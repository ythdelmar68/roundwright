"""Concrete, opt-in bridge to the reviewed native Worker and Recorder APIs.

This module deliberately keeps the SDK and the external retention store on the
operational side of the boundary.  Its public return types are the redacted
types in :mod:`roundwright.worker_shadow`; neither an SDK event nor a store
path is ever returned or serialized by this module.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .codex_worker import (
    BoundedWorkerToolSurface,
    CodexWorkerRequest,
    NativeCodexWorkerBackend,
    NativeWorkerResponse,
    NativeWorkerTurnStep,
    NativeWorkerSession,
    NativeWorkerTurn,
    WorkerResultKind,
    WorkerAction,
    WorkerParserDiagnostic,
    WorkerOutcomeSource,
    WorkerSdkTurnErrorCategory,
    WorkerTool,
    NativeWorkerToolRequest,
    NativeWorkerToolResult,
)
from .coding_tools import BoundedCodingTools, CodingToolError
from .coding_worker_state import (
    CodingAmbiguityState,
    CodingCancellationState,
    CodingProcessState,
    CodingToolEventRecord,
    CodingToolEventStore,
    CodingWorkerStateError,
)
from .configuration import ProviderProfile
from .provider_health import CodexAdapterError, CodexFailure, ProviderHealthAuditIdentity
from .shadow import RecorderBinding
from .worker_shadow import (
    ExternalCapturePlanReceipt,
    ExternalRecorderReceipt,
    ExternalWorkerRecorder,
    WorkerQualificationBinding,
    WorkerQualificationResult,
    WorkerShadowCaptureReadiness,
    WorkerShadowError,
    qualify_worker_adapter,
    require_worker_shadow_capture_readiness,
)
from .codex_worker import CodexWorkerAdapter


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_NO_TOOL_INSTRUCTIONS = "One bounded planning observation only. No provider tools or repository inspection are declared or required. Decide only from the normalized public turn input. Return only the requested schema."
_CODING_TOOL_INSTRUCTIONS = "Execute only bounded workspace-read, workspace-write, and validation-execute requests declared by the host. Never invoke a shell, repository command, network, credential, or undeclared tool. Return only the requested structured schema."
@dataclass(frozen=True)
class CompletionDeadline:
    """Explicit bounded completion contract, always inside the host deadline."""

    application_timeout_ms: int
    host_timeout_ms: int
    headroom_ms: int = 500

    def __post_init__(self) -> None:
        if any(type(value) is not int for value in (self.application_timeout_ms, self.host_timeout_ms, self.headroom_ms)) or self.application_timeout_ms <= 0 or self.headroom_ms < 250 or self.host_timeout_ms < self.application_timeout_ms + self.headroom_ms:
            raise WorkerShadowError("Worker completion deadline lacks host-timeout headroom")

    def receipt(self) -> dict[str, object]:
        return {"schema": "roundwright-worker-completion-timeout/v1", "application_timeout_ms": self.application_timeout_ms, "host_timeout_ms": self.host_timeout_ms, "headroom_ms": self.host_timeout_ms - self.application_timeout_ms}


@dataclass(frozen=True)
class CodingDispatchReceipt:
    """Sealed authority tuple for one executable coding Worker attempt.

    The receipt carries public-safe identifiers only.  Its candidate probe is
    deliberately supplied by the product host and read before dispatch and
    before each local effect, preventing a moved fixture from borrowing a
    still-valid capability.
    """

    task_id: str
    attempt_id: str
    candidate_sha: str
    candidate_fingerprint: str
    policy_fingerprint: str
    configuration_digest: str
    worktree_fingerprint: str
    validation_toolchain_receipt: str
    sandbox_identity: str
    capability_digest: str
    receipt_digest: str

    @classmethod
    def seal(cls, *, task_id: str, attempt_id: str, candidate_sha: str, candidate_fingerprint: str, policy_fingerprint: str, configuration_digest: str, worktree_fingerprint: str, validation_toolchain_receipt: str, sandbox_identity: str, capability_digest: str) -> "CodingDispatchReceipt":
        core = {
            "schema": "roundwright-coding-dispatch-receipt/v1", "task_id": task_id,
            "attempt_id": attempt_id, "candidate_sha": candidate_sha,
            "candidate_fingerprint": candidate_fingerprint,
            "policy_fingerprint": policy_fingerprint,
            "configuration_digest": configuration_digest,
            "worktree_fingerprint": worktree_fingerprint,
            "validation_toolchain_receipt": validation_toolchain_receipt,
            "sandbox_identity": sandbox_identity,
            "capability_digest": capability_digest,
        }
        return cls(task_id, attempt_id, candidate_sha, candidate_fingerprint, policy_fingerprint, configuration_digest, worktree_fingerprint, validation_toolchain_receipt, sandbox_identity, capability_digest, _digest(core))

    def __post_init__(self) -> None:
        values = (self.candidate_fingerprint, self.policy_fingerprint, self.configuration_digest, self.worktree_fingerprint, self.validation_toolchain_receipt, self.sandbox_identity, self.capability_digest)
        core = {
            "schema": "roundwright-coding-dispatch-receipt/v1", "task_id": self.task_id,
            "attempt_id": self.attempt_id, "candidate_sha": self.candidate_sha,
            "candidate_fingerprint": self.candidate_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "configuration_digest": self.configuration_digest,
            "worktree_fingerprint": self.worktree_fingerprint,
            "validation_toolchain_receipt": self.validation_toolchain_receipt,
            "sandbox_identity": self.sandbox_identity,
            "capability_digest": self.capability_digest,
        }
        if (not _TOKEN.fullmatch(self.task_id) or not _TOKEN.fullmatch(self.attempt_id)
                or not re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha)
                or any(type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in values)
                or self.receipt_digest != _digest(core)):
            raise WorkerShadowError("coding dispatch receipt is invalid")

    def validate_for(self, request: CodexWorkerRequest, observed_candidate_sha: str, observed_toolchain_receipt: str) -> None:
        if (type(request) is not CodexWorkerRequest or type(observed_candidate_sha) is not str
                or observed_candidate_sha != self.candidate_sha
                or observed_toolchain_receipt != self.validation_toolchain_receipt
                or request.context.task_id != self.task_id or request.attempt_id != self.attempt_id
                or request.context.candidate_fingerprint != self.candidate_fingerprint
                or request.context.policy_fingerprint != self.policy_fingerprint
                or request.context.configuration_digest != self.configuration_digest
                or request.context.worktree_fingerprint != self.worktree_fingerprint):
            raise WorkerShadowError("coding dispatch receipt drifted")


def _result_schema(action: str) -> dict[str, object]:
    """0.144.4 wire-safe JSON Schema: enum, not unsupported ``const``.

    The locked client passes this object through as ``Any`` and does not
    validate it locally.  Its constrained-output dialect accepts JSON Schema
    enum values; deterministic parser validation below remains authoritative.
    """
    # The reviewed Harness path proves this strict, flat root-object form.
    # Cross-field semantics remain local: composed/conditional schemas have
    # not been qualified against the locked Structured Outputs dialect.
    return {"type": "object", "properties": {
        "status": {"type": "string", "enum": ["complete", "blocked"]},
        "action": {"type": "string", "enum": [action]},
        "blocker": {"type": ["string", "null"], "enum": [None, "provider-blocked"]},
    }, "required": ["status", "action", "blocker"], "additionalProperties": False}


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ReviewedToolboxIdentity:
    """Exact identity of the independently reviewed Harness surface."""

    recorder: RecorderBinding
    native_channel_producer_identity: str
    store_identity: str


class HarnessExternalWorkerRecorder(ExternalWorkerRecorder):
    """Adapter over Harness ``record_document`` and ``verify_recording``.

    ``store_root`` is deliberately private operational state.  The externally
    bound digest is all that crosses the candidate's public evidence boundary.
    """

    def __init__(
        self,
        *,
        store_root: Path,
        store_identity: str,
        recorder: RecorderBinding,
        prepare_capture: Callable[[Mapping[str, Any]], object],
        record_capture: Callable[[Mapping[str, Any], Mapping[str, Any], Path], object],
        verify_capture: Callable[[Mapping[str, Any], Path, str], object],
    ) -> None:
        if not isinstance(store_root, Path) or type(store_identity) is not str or type(recorder) is not RecorderBinding or not callable(prepare_capture) or not callable(record_capture) or not callable(verify_capture):
            raise WorkerShadowError("reviewed external Recorder binding is invalid")
        self._store_root = store_root
        self._store_identity = store_identity
        self._recorder = recorder
        self._prepare_capture = prepare_capture
        self._record_capture = record_capture
        self._verify_capture = verify_capture

    @classmethod
    def from_reviewed_toolbox(cls, *, store_root: Path, store_identity: str, recorder: RecorderBinding, module_name: str = "roundwright_harness.capture") -> "HarnessExternalWorkerRecorder":
        """Load the reviewed Harness module only at the operational boundary."""

        try:
            module = importlib.import_module(module_name)
            prepare_capture = getattr(module, "prepare_capture")
            record_capture = getattr(module, "record_capture")
            verify_capture = getattr(module, "verify_capture")
        except Exception as error:
            raise WorkerShadowError("reviewed external Recorder is unavailable") from error
        return cls(store_root=store_root, store_identity=store_identity, recorder=recorder, prepare_capture=prepare_capture, record_capture=record_capture, verify_capture=verify_capture)

    def seal(self, plan: Mapping[str, object], document: Mapping[str, object], *, store_identity: str) -> ExternalRecorderReceipt:
        self._require_store(store_identity)
        try:
            return self._receipt(self._record_capture(plan, document, self._store_root))
        except WorkerShadowError:
            raise
        except Exception as error:
            raise WorkerShadowError("reviewed external Recorder rejected the public evidence") from error

    def prepare(self, plan: Mapping[str, object], *, store_identity: str) -> ExternalCapturePlanReceipt:
        """Prove the selected external retention target is usable without sealing."""
        self._require_store(store_identity)
        try:
            public = self._prepare_capture(plan).as_dict()
            receipt = ExternalCapturePlanReceipt(public["plan_digest"], public["profile"], public["case_id"], public["candidate_sha"], public["ready_at"], public["receipt_digest"])
            parent = self._store_root.parent
            if not parent.is_dir() or (self._store_root.exists() and (self._store_root.is_symlink() or not self._store_root.is_dir())):
                raise WorkerShadowError("external Recorder store is unavailable")
            return receipt
        except OSError as error:
            raise WorkerShadowError("external Recorder store is unavailable") from error

    def verify(self, plan: Mapping[str, object], bundle_digest: str, *, store_identity: str) -> ExternalRecorderReceipt:
        self._require_store(store_identity)
        try:
            return self._receipt(self._verify_capture(plan, self._store_root, bundle_digest))
        except WorkerShadowError:
            raise
        except Exception as error:
            raise WorkerShadowError("reviewed external Recorder read-back failed") from error

    def _require_store(self, store_identity: str) -> None:
        if store_identity != self._store_identity:
            raise WorkerShadowError("external Recorder store identity drifted")

    @staticmethod
    def _receipt(value: object) -> ExternalRecorderReceipt:
        try:
            public = value.as_dict()  # type: ignore[union-attr]
            receipt = ExternalRecorderReceipt(
                profile=public["profile"], case_id=public["case_id"], candidate_sha=public["candidate_sha"],
                ready_at=public["ready_at"], capture_plan_digest=public["capture_plan_digest"], evidence_digest=public["evidence_digest"], manifest_digest=public["manifest_digest"],
                bundle_digest=public["bundle_digest"], retention_identity=public["retention_identity"], receipt_digest=public["receipt_digest"],
            )
        except (AttributeError, KeyError, TypeError, WorkerShadowError) as error:
            raise WorkerShadowError("reviewed external Recorder receipt is invalid") from error
        core = {
            "schema": "roundwright-harness-bound-capture-receipt/v1", "status": "sealed", "capture_plan_digest": receipt.capture_plan_digest,
            "profile": receipt.profile, "case_id": receipt.case_id, "candidate_sha": receipt.candidate_sha, "ready_at": receipt.ready_at,
            "evidence_digest": receipt.evidence_digest, "manifest_digest": receipt.manifest_digest, "bundle_digest": receipt.bundle_digest,
            "retention_identity": receipt.retention_identity, "recording_receipt_digest": public["recording_receipt_digest"],
        }
        if receipt.receipt_digest != _digest(core):
            raise WorkerShadowError("reviewed external Recorder receipt digest is invalid")
        return receipt


class HarnessNativeCodexWorkerBackend(NativeCodexWorkerBackend):
    """Executable deny-all/read-only bridge over the reviewed native SDK API."""

    def __init__(self, *, cwd: Path, completion: CompletionDeadline, codex_factory: Callable[[], object] | None = None, approval_mode: object | None = None, sandbox: object | None = None, effort_factory: Callable[[str], object] | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(cwd, Path):
            raise WorkerShadowError("native Worker working directory is invalid")
        if codex_factory is None:
            try:
                sdk = importlib.import_module("openai_codex")
                generated = importlib.import_module("openai_codex.generated.v2_all")
                codex_factory, approval_mode, sandbox, effort_factory = sdk.Codex, sdk.ApprovalMode.deny_all, sdk.Sandbox.read_only, generated.ReasoningEffort
            except Exception as error:
                raise WorkerShadowError("reviewed native Worker SDK is unavailable") from error
        if type(completion) is not CompletionDeadline or not callable(codex_factory) or approval_mode is None or sandbox is None or not callable(effort_factory) or not callable(clock):
            raise WorkerShadowError("reviewed native Worker SDK binding is invalid")
        self._cwd, self._completion, self._codex_factory, self._approval_mode, self._sandbox, self._effort_factory, self._clock = cwd, completion, codex_factory, approval_mode, sandbox, effort_factory, clock

    def open_session(self, profile: ProviderProfile, *, resume_session_identity: str | None, action: WorkerAction) -> NativeWorkerSession:
        if type(profile) is not ProviderProfile or type(action) is not WorkerAction:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        instructions = _NO_TOOL_INSTRUCTIONS if action is WorkerAction.PLANNING else _CODING_TOOL_INSTRUCTIONS
        codex = self._codex_factory()
        try:
            client = codex.__enter__() if hasattr(codex, "__enter__") else codex
            if resume_session_identity is None:
                thread = client.thread_start(approval_mode=self._approval_mode, cwd=str(self._cwd), developer_instructions=instructions, ephemeral=False, model=profile.model, sandbox=self._sandbox)
            else:
                resume = getattr(client, "thread_resume", None)
                if not callable(resume):
                    raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
                thread = resume(resume_session_identity, approval_mode=self._approval_mode, cwd=str(self._cwd), developer_instructions=instructions, model=profile.model, sandbox=self._sandbox)
            return _HarnessWorkerSession(thread, codex, self._approval_mode, self._cwd, profile.model, self._sandbox, self._effort_factory, profile.reasoning_effort.value, self._completion, self._clock)
        except CodexAdapterError:
            _close(codex)
            raise
        except Exception as error:
            _close(codex)
            raise CodexAdapterError(CodexFailure.UNKNOWN) from error


class _HarnessCleanupOwner:
    """Own the one interrupt/close sequence for a native Worker session."""

    def __init__(self, codex: object) -> None:
        self._codex = codex
        self._aborted = False
        self._closed = False

    def abort(self, handle: object) -> None:
        """Best-effort, exact-turn interruption; duplicate requests are inert."""
        if self._aborted:
            return
        self._aborted = True
        try:
            interrupt = getattr(handle, "interrupt", None)
            if callable(interrupt):
                interrupt()
        except Exception:
            # Cleanup diagnostics intentionally remain closed and text-free.
            pass

    def close(self) -> None:
        """Close the underlying client at most once after any interruption."""
        if self._closed:
            return
        self._closed = True
        try:
            _close(self._codex)
        except Exception:
            # A cleanup failure cannot make the turn Recorder-eligible.
            pass


class _HarnessWorkerSession(NativeWorkerSession):
    def __init__(self, thread: object, codex: object, approval_mode: object, cwd: Path, model: str, sandbox: object, effort_factory: Callable[[str], object], effort: str, completion: CompletionDeadline, clock: Callable[[], float]) -> None:
        self._thread, self._approval_mode, self._cwd, self._model, self._sandbox, self._effort_factory, self._effort, self._completion, self._clock, self._started = thread, approval_mode, cwd, model, sandbox, effort_factory, effort, completion, clock, False
        self._cleanup = _HarnessCleanupOwner(codex)

    def identity(self) -> str:
        value = getattr(self._thread, "id", None)
        if type(value) is not str:
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def close(self) -> None:
        self._cleanup.close()

    def start_turn(self, request: CodexWorkerRequest, tools: BoundedWorkerToolSurface) -> NativeWorkerTurn:
        if self._started or type(request) is not CodexWorkerRequest or type(tools) is not BoundedWorkerToolSurface:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._started = True
        if request.action is not WorkerAction.PLANNING:
            required = {WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE}
            if set(tools.tools) != required:
                raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
            return _HarnessCodingWorkerTurn(self._thread, self._cleanup, request, tools, self._approval_mode, self._cwd, self._model, self._sandbox, self._effort_factory, self._effort, self._completion, self._clock)
        if tools.capability_contract.value != "no-tools-self-contained/v1":
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        # The full canonical request is transient. Only the validated structured
        # lifecycle projection below can cross the SDK boundary.
        prompt = json.dumps(_native_payload(request, tools), sort_keys=True, separators=(",", ":"))
        try:
            handle = self._thread.turn(prompt, approval_mode=self._approval_mode, cwd=str(self._cwd), model=self._model, effort=self._effort_factory(self._effort), output_schema=_result_schema(request.action.value), sandbox=self._sandbox)
            return _HarnessWorkerTurn(handle, self._cleanup, request.action, self._completion, self._clock)
        except Exception as error:
            self._cleanup.close()
            raise CodexAdapterError(CodexFailure.UNKNOWN) from error


class _HarnessWorkerTurn(NativeWorkerTurn):
    def __init__(self, handle: object, cleanup: _HarnessCleanupOwner, action: WorkerAction, completion: CompletionDeadline, clock: Callable[[], float]) -> None:
        self._handle, self._cleanup, self._action, self._completion, self._clock, self._read = handle, cleanup, action, completion, clock, False

    def identity(self) -> str:
        value = getattr(self._handle, "id", None)
        if type(value) is not str:
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def abort(self) -> None:
        self._cleanup.abort(self._handle)

    def read_response(self) -> NativeWorkerResponse:
        if self._read:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._read = True
        try:
            response = _consume_public_result(self._handle, self._action, completion=self._completion, clock=self._clock, cancel=self.abort)
            if response.kind is WorkerResultKind.AMBIGUOUS:
                self.abort()
            return response
        except Exception:
            self.abort()
            raise
        finally:
            self._cleanup.close()


class _HarnessCodingWorkerTurn(NativeWorkerTurn):
    """Repeated constrained SDK turns over one persistent native thread."""

    def __init__(self, thread: object, cleanup: _HarnessCleanupOwner, request: CodexWorkerRequest, tools: BoundedWorkerToolSurface, approval: object, cwd: Path, model: str, sandbox: object, effort_factory: Callable[[str], object], effort: str, completion: CompletionDeadline, clock: Callable[[], float]) -> None:
        self._thread, self._cleanup, self._request, self._tools = thread, cleanup, request, tools
        self._approval, self._cwd, self._model, self._sandbox, self._effort_factory, self._effort, self._completion, self._clock = approval, cwd, model, sandbox, effort_factory, effort, completion, clock
        self._handle: object | None = None
        self._start({"schema": "roundwright-coding-turn/v1", "request": _native_coding_payload(request, tools), "previous_result": None})

    def identity(self) -> str:
        value = getattr(self._handle, "id", None)
        if type(value) is not str: raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def abort(self) -> None:
        if self._handle is not None: self._cleanup.abort(self._handle)

    def read_response(self) -> NativeWorkerResponse:
        raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)

    def read_step(self) -> NativeWorkerTurnStep:
        if self._handle is None: raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        step = _consume_coding_step(self._handle, self._request.action, self._completion, self._clock, self.abort)
        if step.response is not None:
            self._cleanup.close()
        return step

    def submit_tool_result(self, result: NativeWorkerToolResult) -> None:
        if type(result) is not NativeWorkerToolResult: raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        # Result feedback is deliberately present only in this next prompt.
        self._start({"schema": "roundwright-coding-turn/v1", "request": None, "previous_result": {"sequence": result.sequence, "tool": result.tool.value, "outcome": result.outcome, "before_digest": result.before_digest, "after_digest": result.after_digest, "exit_code": result.exit_code, "output_digest": result.output_digest, "feedback": result.feedback}})

    def _start(self, payload: Mapping[str, object]) -> None:
        try:
            self._handle = self._thread.turn(json.dumps(payload, sort_keys=True, separators=(",", ":")), approval_mode=self._approval, cwd=str(self._cwd), model=self._model, effort=self._effort_factory(self._effort), output_schema=_coding_schema(self._request.action), sandbox=self._sandbox)
        except Exception as error:
            self._cleanup.close(); raise CodexAdapterError(CodexFailure.UNKNOWN) from error


def _consume_public_result(handle: object, action: WorkerAction, *, completion: CompletionDeadline | None = None, clock: Callable[[], float] = time.monotonic, cancel: Callable[[], None] | None = None) -> NativeWorkerResponse:
    """Consume the SDK stream without propagating SDK text or payloads."""
    try:
        stream = handle.stream()
        response: str | None = None
        completed = False
        saw_non_final = False
        try:
            for event in _bounded_events(stream, completion=completion, clock=clock, cancel=cancel):
                method = _field(event, "method")
                payload = _field(event, "payload") or event
                turn = _field(payload, "turn")
                if method == "turn/completed":
                    if turn is None or _field(turn, "id") != _field(handle, "id"):
                        return _invalid(WorkerParserDiagnostic.EXACT_TURN)
                    status = _value(_field(turn, "status"))
                    if status == "failed":
                        failure, category = _turn_failure(_field(turn, "error"))
                        return NativeWorkerResponse(WorkerResultKind.BLOCKED, failure=failure, blocker="provider-failed", outcome_source=WorkerOutcomeSource.SDK_TURN_FAILED, sdk_error_category=category)
                    if status != "completed":
                        # A checkpointed exact turn without a verified terminal
                        # completion may only be reconciled, never recaptured.
                        return NativeWorkerResponse(WorkerResultKind.AMBIGUOUS)
                    completed = True
                    continue
                if method != "item/completed":
                    continue
                if _field(payload, "turn_id", "turnId") != _field(handle, "id"):
                    return _invalid(WorkerParserDiagnostic.EXACT_TURN)
                item = _field(payload, "item")
                item = _field(item, "root") or item
                text = _field(item, "text")
                phase = _value(_field(item, "phase"))
                if _field(item, "type") != "agentMessage":
                    continue
                if phase != "final_answer":
                    saw_non_final = True
                    continue
                if type(text) is not str or response is not None:
                    return _invalid(WorkerParserDiagnostic.SHAPE)
                response = text
        finally:
            close = getattr(stream, "close", None)
            if callable(close): close()
        if not completed:
            # EOF supplies no proof that this exact dispatched turn terminated.
            return NativeWorkerResponse(WorkerResultKind.AMBIGUOUS)
        if response is None:
            return _invalid(WorkerParserDiagnostic.NON_FINAL if saw_non_final else WorkerParserDiagnostic.SHAPE)
        try:
            parsed = json.loads(response)
        except (TypeError, ValueError):
            return _invalid(WorkerParserDiagnostic.SYNTAX)
        if type(parsed) is not dict:
            return _invalid(WorkerParserDiagnostic.SHAPE)
        if type(parsed.get("action")) is not str or parsed["action"] != action.value:
            return _invalid(WorkerParserDiagnostic.ACTION)
        if type(parsed.get("status")) is not str or parsed["status"] not in {"complete", "blocked"}:
            return _invalid(WorkerParserDiagnostic.STATUS)
        if parsed["status"] == "complete":
            if set(parsed) != {"status", "action", "blocker"} or parsed["blocker"] is not None:
                return _invalid(WorkerParserDiagnostic.SHAPE)
            # The provider never manufactures a result digest. Canonical JSON
            # normalization in CodexWorkerAdapter binds this validated content.
            return NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "complete", "action": action.value})
        if set(parsed) != {"status", "action", "blocker"} or parsed["blocker"] != "provider-blocked":
            return _invalid(WorkerParserDiagnostic.BLOCKER)
        return NativeWorkerResponse(WorkerResultKind.BLOCKED, failure=CodexFailure.UNKNOWN, blocker="provider-blocked", outcome_source=WorkerOutcomeSource.PROVIDER_STRUCTURED_BLOCKED)
    except TimeoutError:
        return NativeWorkerResponse(WorkerResultKind.AMBIGUOUS)
    except Exception:
        # Iterator and transport failure leave terminal completion unknown;
        # retain no stream details and require exact-turn recovery.
        return NativeWorkerResponse(WorkerResultKind.AMBIGUOUS)


def _coding_schema(action: WorkerAction) -> dict[str, object]:
    return {"type": "object", "properties": {
        "status": {"type": "string", "enum": ["tool", "complete", "blocked"]},
        "action": {"type": "string", "enum": [action.value]},
        "sequence": {"type": ["integer", "null"]},
        "tool": {"type": ["string", "null"], "enum": [None, *(tool.value for tool in WorkerTool)]},
        "path": {"type": ["string", "null"]}, "content": {"type": ["string", "null"]},
        "command": {"type": ["array", "null"], "items": {"type": "string"}},
        "blocker": {"type": ["string", "null"], "enum": [None, "provider-blocked"]},
    }, "required": ["status", "action", "blocker"], "additionalProperties": False}


def _native_coding_payload(request: CodexWorkerRequest, tools: BoundedWorkerToolSurface) -> dict[str, object]:
    return {"schema": "roundwright-coding-worker-native/v1", "capability_contract": "executable-bounded-coding/v1", "action": request.action.value, "request_digest": request.input_digest, "context_digest": request.context.digest, "objective": request.objective, "constraints": list(request.constraints), "acceptance_criteria": list(request.acceptance_criteria), "tools": [tool.value for tool in tools.tools], "instruction": "Return exactly one bounded tool request or terminal result. Never invoke a shell or name an undeclared tool."}


def _consume_coding_step(handle: object, action: WorkerAction, completion: CompletionDeadline, clock: Callable[[], float], cancel: Callable[[], None]) -> NativeWorkerTurnStep:
    try:
        text = None; completed = False; failed = None
        stream = handle.stream()
        try:
            for event in _bounded_events(stream, completion=completion, clock=clock, cancel=cancel):
                payload = _field(event, "payload") or event
                if _field(event, "method") == "turn/completed":
                    turn = _field(payload, "turn")
                    if turn is None or _field(turn, "id") != _field(handle, "id"):
                        raise ValueError
                    status = _value(_field(turn, "status"))
                    if status == "failed": failed = _field(turn, "error")
                    elif status == "completed": completed = True
                    else: return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.AMBIGUOUS))
                if _field(event, "method") == "item/completed" and _field(payload, "turn_id", "turnId") == _field(handle, "id"):
                    item = _field(_field(payload, "item"), "root") or _field(payload, "item")
                    if _field(item, "type") == "agentMessage" and _value(_field(item, "phase")) == "final_answer":
                        if text is not None: raise ValueError
                        text = _field(item, "text")
        finally:
            close = getattr(stream, "close", None)
            if callable(close): close()
        if failed is not None:
            failure, category = _turn_failure(failed)
            return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.BLOCKED, failure=failure, blocker="provider-failed", outcome_source=WorkerOutcomeSource.SDK_TURN_FAILED, sdk_error_category=category))
        value = json.loads(text) if completed and type(text) is str else None
        if type(value) is not dict or value.get("action") != action.value: raise ValueError
        if value.get("status") == "complete" and set(value) == {"status", "action", "blocker"} and value.get("blocker") is None:
            return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "complete", "action": action.value}))
        if value.get("status") == "blocked" and set(value) == {"status", "action", "blocker"} and value.get("blocker") == "provider-blocked":
            return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.BLOCKED, failure=CodexFailure.UNKNOWN, blocker="provider-blocked", outcome_source=WorkerOutcomeSource.PROVIDER_STRUCTURED_BLOCKED))
        if value.get("status") != "tool": raise ValueError
        request = NativeWorkerToolRequest(int(value["sequence"]), WorkerTool(value["tool"]), value.get("path"), value.get("content"), tuple(value["command"]) if type(value.get("command")) is list else None)
        return NativeWorkerTurnStep(request=request)
    except TimeoutError:
        cancel()
        return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.AMBIGUOUS))
    except Exception:
        # A coding stream can have produced an unobserved terminal result.  Do
        # not recast that transport uncertainty as malformed provider output.
        cancel()
        return NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.AMBIGUOUS))


def _invalid(diagnostic: WorkerParserDiagnostic) -> NativeWorkerResponse:
    return NativeWorkerResponse(WorkerResultKind.INVALID, diagnostic=diagnostic)


def _field(value: object, name: str, alias: str | None = None) -> object | None:
    """Read the SDK's model fields or its serialized camel-case mapping."""
    if isinstance(value, Mapping):
        return value.get(name, value.get(alias) if alias is not None else None)
    return getattr(value, name, None)


def _value(value: object) -> object:
    return getattr(value, "value", value)


def _turn_failure(error: object) -> tuple[CodexFailure, WorkerSdkTurnErrorCategory]:
    """Project only typed SDK ``codexErrorInfo`` values, never error text."""
    detail = _field(error, "codex_error_info", "codexErrorInfo")
    root = _field(detail, "root")
    if root is not None:
        detail = root
    value = _value(detail)
    if type(value) is not str:
        value = None
    if value == "badRequest":
        return CodexFailure.UNKNOWN, WorkerSdkTurnErrorCategory.BAD_REQUEST
    if value == "unauthorized":
        # A turn-level unauthorized code does not prove a credential state.
        return CodexFailure.UNKNOWN, WorkerSdkTurnErrorCategory.UNAUTHORIZED
    if value in {"sandboxError", "cyberPolicy"}:
        return CodexFailure.SANDBOX_OR_APPROVAL_DENIED, WorkerSdkTurnErrorCategory.SANDBOX
    if value in {"serverOverloaded", "internalServerError"}:
        return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.OVERLOAD
    if isinstance(detail, Mapping):
        if "httpConnectionFailed" in detail:
            return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.HTTP
        if "responseStreamConnectionFailed" in detail:
            return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.CONNECTION
        if "responseStreamDisconnected" in detail or "responseTooManyFailedAttempts" in detail:
            return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.STREAM
    name = type(detail).__name__
    if name == "HttpConnectionFailedCodexErrorInfo":
        return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.HTTP
    if name == "ResponseStreamConnectionFailedCodexErrorInfo":
        return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.CONNECTION
    if name in {"ResponseStreamDisconnectedCodexErrorInfo", "ResponseTooManyFailedAttemptsCodexErrorInfo"}:
        return CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, WorkerSdkTurnErrorCategory.STREAM
    return CodexFailure.UNKNOWN, WorkerSdkTurnErrorCategory.MISSING_OR_UNKNOWN


def _bounded_events(stream: object, *, completion: CompletionDeadline | None, clock: Callable[[], float], cancel: Callable[[], None] | None):
    """Do not let ``next_turn_notification`` outlive the application deadline."""
    if completion is None:
        yield from stream  # type: ignore[misc]
        return
    events: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)
    iterator = iter(stream)
    def next_event() -> None:
        try: events.put(("event", next(iterator)))
        except StopIteration: events.put(("end", None))
        except BaseException: events.put(("error", None))
    deadline = clock() + completion.application_timeout_ms / 1000
    while True:
        worker = threading.Thread(target=next_event, daemon=True)
        worker.start()
        remaining = deadline - clock()
        if remaining <= 0:
            if cancel is not None: cancel()
            raise TimeoutError
        try: kind, value = events.get(timeout=remaining)
        except queue.Empty:
            if cancel is not None: cancel()
            raise TimeoutError
        if kind == "event": yield value
        elif kind == "end": return
        else: raise RuntimeError("native stream failed")


def _close(value: object) -> None:
    exit_method = getattr(value, "__exit__", None)
    if callable(exit_method):
        exit_method(None, None, None)
    else:
        close = getattr(value, "close", None)
        if callable(close): close()


def _native_payload(request: CodexWorkerRequest, tools: BoundedWorkerToolSurface) -> dict[str, object]:
    """Action-specific, immutable provider payload; never retained verbatim."""
    if type(request) is not CodexWorkerRequest or type(tools) is not BoundedWorkerToolSurface or request.action is not WorkerAction.PLANNING or tools.capability_contract.value != "no-tools-self-contained/v1":
        raise WorkerShadowError("native Worker capability contract is invalid")
    return {"schema": "roundwright-worker-native/v1", "capability_contract": "no-tools-self-contained/v1", "provider_instruction": "No provider tools or repository inspection are declared or required; decide only from this normalized public input.", "action": request.action.value, "attempt_id": request.attempt_id, "request_digest": request.input_digest, "context": {"task_id": request.context.task_id, "source_digest": request.context.source_digest, "repository_fingerprint": request.context.repository_fingerprint, "worktree_fingerprint": request.context.worktree_fingerprint, "branch_fingerprint": request.context.branch_fingerprint, "base_fingerprint": request.context.base_fingerprint, "candidate_fingerprint": request.context.candidate_fingerprint, "policy_fingerprint": request.context.policy_fingerprint, "configuration_digest": request.context.configuration_digest}, "objective": request.objective, "constraints": list(request.constraints), "acceptance_criteria": list(request.acceptance_criteria), "resume_session_identity": request.resume_session_identity, "tools": []}


def run_bounded_worker_adapter_qualification(*, backend: NativeCodexWorkerBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity, tools: BoundedWorkerToolSurface, request: CodexWorkerRequest, readiness: WorkerShadowCaptureReadiness, binding: WorkerQualificationBinding, recorder: ExternalWorkerRecorder, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None], checkpoint_result: Callable[[str, str, WorkerResultKind, WorkerParserDiagnostic | None, WorkerOutcomeSource | None, WorkerSdkTurnErrorCategory | None], None]) -> WorkerQualificationResult:
    """Operational composition point; all readiness checks occur before SDK dispatch."""
    return qualify_worker_adapter(CodexWorkerAdapter(backend, profile, audit, tools), request, readiness, binding, recorder, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn, checkpoint_result=checkpoint_result)


class ProductionCodingWorkerRuntime:
    """Candidate-bound production coding seam; CLI activation remains blocked."""
    def __init__(self, *, backend: NativeCodexWorkerBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity, local_tools: BoundedCodingTools, dispatch_receipt: CodingDispatchReceipt, event_store: CodingToolEventStore, candidate_probe: Callable[[], str], toolchain_receipt_probe: Callable[[], str]) -> None:
        if (type(dispatch_receipt) is not CodingDispatchReceipt or type(event_store) is not CodingToolEventStore
                or not callable(candidate_probe) or not callable(toolchain_receipt_probe) or local_tools.reviewed_sandbox_identity != dispatch_receipt.sandbox_identity
                or local_tools.capability_digest != dispatch_receipt.capability_digest):
            raise WorkerShadowError("production coding runtime requires a sealed dispatch receipt")
        self._adapter = CodexWorkerAdapter(backend, profile, audit, BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE)))
        self._local_tools = local_tools
        self._dispatch_receipt = dispatch_receipt
        self._event_store = event_store
        self._candidate_probe = candidate_probe
        self._toolchain_receipt_probe = toolchain_receipt_probe

    @property
    def capability_contract(self):
        """Executable only because this binding owns a real local executor."""
        from .codex_worker import WorkerCapabilityContract
        return WorkerCapabilityContract.EXECUTABLE_BOUNDED_CODING

    def dispatch(self, request: CodexWorkerRequest, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]):
        if request.action is WorkerAction.PLANNING:
            raise WorkerShadowError("planning requests require the separate no-tools entrypoint")
        self._dispatch_receipt.validate_for(request, self._candidate_probe(), self._toolchain_receipt_probe())
        checkpoint: dict[str, str] = {}
        submission_turns: dict[int, str] = {}

        def record_session(session_identity: str) -> None:
            checkpoint["session_identity"] = session_identity
            checkpoint_session(session_identity)

        def record_turn(session_identity: str, turn_identity: str) -> None:
            if checkpoint.get("session_identity") != session_identity:
                raise WorkerShadowError("coding turn checkpoint is not session-bound")
            checkpoint["turn_identity"] = turn_identity
            checkpoint_turn(session_identity, turn_identity)

        def execute(item: NativeWorkerToolRequest) -> NativeWorkerToolResult:
            return self._execute_request(request, checkpoint, item)

        def submission(item: NativeWorkerToolRequest, result: NativeWorkerToolResult, state: str) -> None:
            session_identity = checkpoint.get("session_identity"); turn_identity = checkpoint.get("turn_identity") if state == "intent" else submission_turns.get(item.sequence)
            if session_identity is None or turn_identity is None: raise WorkerShadowError("coding submission lacks durable turn checkpoint")
            if state == "intent": submission_turns[item.sequence] = turn_identity
            try:
                self._event_store.record_submission(request.context.task_id, request.attempt_id, session_identity, turn_identity, item.sequence, state, checkpoint.get("turn_identity") if state == "submitted" else None)
            except CodingWorkerStateError as error: raise WorkerShadowError("coding submission checkpoint failed") from error

        callback = execute if request.action is not WorkerAction.PLANNING else None
        return self._adapter.dispatch(request, checkpoint_session=record_session, checkpoint_turn=record_turn, execute_tool_request=callback, checkpoint_submission=submission if callback is not None else None)

    def _execute_request(self, worker_request: CodexWorkerRequest, checkpoint: Mapping[str, str], request: NativeWorkerToolRequest) -> NativeWorkerToolResult:
        self._dispatch_receipt.validate_for(worker_request, self._candidate_probe(), self._toolchain_receipt_probe())
        if self._local_tools.capability_digest != self._dispatch_receipt.capability_digest:
            raise WorkerShadowError("coding capability receipt drifted")
        session_identity = checkpoint.get("session_identity")
        turn_identity = checkpoint.get("turn_identity")
        if session_identity is None or turn_identity is None:
            raise WorkerShadowError("coding tool effect lacks durable turn checkpoint")
        request_digest = _digest({"sequence": request.sequence, "tool": request.tool.value, "path": request.path, "content_digest": _digest(request.content) if request.content is not None else None, "command": request.command})
        if not self._event_store.claim_effect(
            worker_request.context.task_id, worker_request.attempt_id, session_identity,
            turn_identity, request.sequence, request_digest,
        ):
            result = NativeWorkerToolResult(request.sequence, request.tool, "ambiguous")
            self._persist_tool_event(worker_request, session_identity, turn_identity, request, result)
            return result
        try:
            lifecycle = (CodingProcessState.STARTED, CodingCancellationState.NOT_REQUESTED, CodingAmbiguityState.SUBMISSION_UNCERTAIN)
            feedback = None
            if request.tool is WorkerTool.WORKSPACE_READ:
                feedback, event = self._local_tools.read(request.path)
            elif request.tool is WorkerTool.WORKSPACE_WRITE:
                event = self._local_tools.write(request.path, request.content)
            elif request.tool is WorkerTool.VALIDATION_EXECUTE:
                feedback, event = self._local_tools.validate_with_feedback(request.command)
            else: raise CodingToolError("tool denied")
            if feedback is not None and len(json.dumps({"feedback": feedback}, ensure_ascii=True, separators=(",", ":")).encode("utf-8")) > 65_536:
                raise CodingToolError("coding feedback exceeded serialized SDK budget", outcome="failed")
            result = NativeWorkerToolResult(request.sequence, request.tool, event.outcome, event.before_digest, event.after_digest, event.exit_code, event.output_digest, feedback)
        except CodingToolError as error:
            result = NativeWorkerToolResult(request.sequence, request.tool, error.outcome)
            try:
                lifecycle = (CodingProcessState(error.process_state), CodingCancellationState(error.cancellation_state), CodingAmbiguityState(error.ambiguity_state))
            except ValueError as state_error:
                raise WorkerShadowError("coding tool returned invalid lifecycle evidence") from state_error
        self._persist_tool_event(worker_request, session_identity, turn_identity, request, result, lifecycle=lifecycle)
        return result

    def _persist_tool_event(self, worker_request: CodexWorkerRequest, session_identity: str, turn_identity: str, request: NativeWorkerToolRequest, result: NativeWorkerToolResult, *, lifecycle: tuple[CodingProcessState, CodingCancellationState, CodingAmbiguityState] | None = None) -> None:
        outcome = result.outcome
        if lifecycle is None:
            lifecycle = (CodingProcessState.FAILED, CodingCancellationState.NOT_REQUESTED, CodingAmbiguityState.TERMINAL_UNCERTAIN)
        process_state, cancellation_state, ambiguity_state = lifecycle
        request_digest = _digest({"sequence": request.sequence, "tool": request.tool.value, "path": request.path, "content_digest": _digest(request.content) if request.content is not None else None, "command": request.command})
        result_digest = _digest({"sequence": result.sequence, "tool": result.tool.value, "outcome": result.outcome, "before_digest": result.before_digest, "after_digest": result.after_digest, "exit_code": result.exit_code, "output_digest": result.output_digest})
        record = CodingToolEventRecord(
            "roundwright-coding-tool-event/v1", worker_request.context.task_id,
            worker_request.input_digest, worker_request.action, worker_request.attempt_id,
            session_identity, turn_identity, self._dispatch_receipt.candidate_sha,
            request.sequence, request.tool, request_digest, result_digest, outcome,
            result.before_digest, result.after_digest, result.exit_code, result.output_digest,
            process_state, cancellation_state, ambiguity_state,
        )
        try:
            self._event_store.append(record)
        except CodingWorkerStateError as error:
            raise WorkerShadowError("coding tool event checkpoint failed") from error


@dataclass(frozen=True)
class ProductionCodingWorkerEntrypointInputs:
    """Closed, host-owned dependencies for the public coding entrypoint.

    This is deliberately a process-local object rather than CLI arguments:
    none of its capability, provider, sandbox, store, or candidate-probe
    dependencies can be reconstructed from ambient input.
    """

    backend: NativeCodexWorkerBackend
    profile: ProviderProfile
    audit: ProviderHealthAuditIdentity
    local_tools: BoundedCodingTools
    dispatch_receipt: CodingDispatchReceipt
    event_store: CodingToolEventStore
    candidate_probe: Callable[[], str]
    toolchain_receipt_probe: Callable[[], str]

    def __post_init__(self) -> None:
        if (type(self.profile) is not ProviderProfile or type(self.audit) is not ProviderHealthAuditIdentity
                or type(self.local_tools) is not BoundedCodingTools or type(self.dispatch_receipt) is not CodingDispatchReceipt
                or type(self.event_store) is not CodingToolEventStore or not callable(self.candidate_probe) or not callable(self.toolchain_receipt_probe)
                or not callable(getattr(self.backend, "open_session", None))):
            raise WorkerShadowError("production coding entrypoint inputs are invalid")


def run_production_coding_worker(*, inputs: ProductionCodingWorkerEntrypointInputs, request: CodexWorkerRequest, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]):
    """Public production task-lifecycle entrypoint for executable coding.

    Planning remains separately routed through
    :func:`run_bounded_worker_adapter_qualification` with its no-tools
    capability; this entrypoint accepts only implementation or repair work.
    """
    if type(inputs) is not ProductionCodingWorkerEntrypointInputs or type(request) is not CodexWorkerRequest or request.action is WorkerAction.PLANNING:
        raise WorkerShadowError("production coding entrypoint is invalid")
    return ProductionCodingWorkerRuntime(
        backend=inputs.backend, profile=inputs.profile, audit=inputs.audit,
        local_tools=inputs.local_tools, dispatch_receipt=inputs.dispatch_receipt,
        event_store=inputs.event_store, candidate_probe=inputs.candidate_probe, toolchain_receipt_probe=inputs.toolchain_receipt_probe,
    ).dispatch(request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)


@dataclass(frozen=True)
class CodingWorkerRuntimeDescriptor:
    """Closed public identity for one installed production coding resource."""

    resource_id: str
    task_id: str
    attempt_id: str
    candidate_sha: str
    capability_digest: str
    dispatch_receipt_digest: str

    @classmethod
    def parse(cls, value: object) -> "CodingWorkerRuntimeDescriptor":
        required = {"schema", "resource_id", "task_id", "attempt_id", "candidate_sha", "capability_digest", "dispatch_receipt_digest"}
        if type(value) is not dict or set(value) != required or value.get("schema") != "roundwright-coding-runtime-descriptor/v1":
            raise WorkerShadowError("coding runtime descriptor is invalid")
        try:
            return cls(**{key: value[key] for key in required - {"schema"}})
        except TypeError as error:
            raise WorkerShadowError("coding runtime descriptor is invalid") from error

    def __post_init__(self) -> None:
        if (not _TOKEN.fullmatch(self.resource_id) or not _TOKEN.fullmatch(self.task_id) or not _TOKEN.fullmatch(self.attempt_id)
                or not re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha)
                or any(type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in (self.capability_digest, self.dispatch_receipt_digest))):
            raise WorkerShadowError("coding runtime descriptor is invalid")

    def payload(self) -> dict[str, str]:
        return {"schema": "roundwright-coding-runtime-descriptor/v1", "resource_id": self.resource_id,
                "task_id": self.task_id, "attempt_id": self.attempt_id, "candidate_sha": self.candidate_sha,
                "capability_digest": self.capability_digest, "dispatch_receipt_digest": self.dispatch_receipt_digest}


class CodingWorkerRuntimeRegistry:
    """Process-local trusted capability registry for the public lifecycle seam."""

    def __init__(self) -> None:
        self._resources: dict[str, ProductionCodingWorkerEntrypointInputs] = {}

    def install(self, resource_id: str, inputs: ProductionCodingWorkerEntrypointInputs) -> None:
        if not _TOKEN.fullmatch(resource_id) or type(inputs) is not ProductionCodingWorkerEntrypointInputs:
            raise WorkerShadowError("coding runtime resource is invalid")
        existing = self._resources.get(resource_id)
        if existing is not None and existing != inputs:
            raise WorkerShadowError("coding runtime resource conflicts")
        self._resources[resource_id] = inputs

    def materialize(self, descriptor: CodingWorkerRuntimeDescriptor) -> ProductionCodingWorkerEntrypointInputs:
        if type(descriptor) is not CodingWorkerRuntimeDescriptor:
            raise WorkerShadowError("coding runtime descriptor is invalid")
        inputs = self._resources.get(descriptor.resource_id)
        if inputs is None:
            raise WorkerShadowError("coding runtime resource is unavailable")
        receipt = inputs.dispatch_receipt
        if (receipt.task_id != descriptor.task_id or receipt.attempt_id != descriptor.attempt_id
                or receipt.candidate_sha != descriptor.candidate_sha or receipt.capability_digest != descriptor.capability_digest
                or receipt.receipt_digest != descriptor.dispatch_receipt_digest
                or inputs.local_tools.capability_digest != descriptor.capability_digest):
            raise WorkerShadowError("coding runtime resource drifted")
        return inputs


CODING_RUNTIME_REGISTRY = CodingWorkerRuntimeRegistry()


def run_registered_production_coding_worker(*, descriptor_value: object, request: CodexWorkerRequest, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]):
    """Public task-lifecycle seam consuming only a closed resource descriptor."""
    descriptor = CodingWorkerRuntimeDescriptor.parse(descriptor_value)
    inputs = CODING_RUNTIME_REGISTRY.materialize(descriptor)
    return run_production_coding_worker(
        inputs=inputs, request=request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn,
    )


def main() -> int:
    """Explicitly opt-in command shell; orchestration supplies exact typed inputs.

    The live command is intentionally disabled by default.  A separate
    orchestrator invokes :func:`run_bounded_worker_adapter_qualification` after
    constructing its sealed task binding; this CLI never invents a timestamp,
    candidate, or external store identity from ambient state.
    """
    if os.environ.get("ROUNDWRIGHT_RUN_LIVE_WORKER_ADAPTER") != "1":
        print('{"schema":"roundwright-live-worker-adapter/v1","status":"disabled"}')
        return 2
    try:
        completion = CompletionDeadline(int(os.environ["ROUNDWRIGHT_APPLICATION_TIMEOUT_MS"]), int(os.environ["ROUNDWRIGHT_HOST_TIMEOUT_MS"]))
    except (KeyError, ValueError, WorkerShadowError):
        print('{"schema":"roundwright-live-worker-adapter/v1","status":"blocked","reason":"explicit-host-timeout-with-headroom-required"}')
        return 2
    print(json.dumps({"schema": "roundwright-live-worker-adapter/v1", "status": "blocked", "reason": "typed-orchestrator-binding-required", "completion": completion.receipt()}, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
