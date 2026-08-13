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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .codex_worker import (
    BoundedWorkerToolSurface,
    CodexWorkerContext,
    CodexWorkerRequest,
    NativeCodexWorkerBackend,
    NativeWorkerResponse,
    NativeWorkerSession,
    NativeWorkerTurn,
    WorkerResultKind,
)
from .configuration import ProviderProfile, ReasoningEffort
from .provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity
from .shadow import RecorderBinding
from .worker_shadow import (
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


_RESULT_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {"status": {"type": "string", "enum": ["complete", "blocked"]}},
    "required": ["status"],
    "additionalProperties": False,
}


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
        record_document: Callable[[Mapping[str, Any], Path], object],
        verify_recording: Callable[[Path, str], object],
    ) -> None:
        if not isinstance(store_root, Path) or type(store_identity) is not str or type(recorder) is not RecorderBinding or not callable(record_document) or not callable(verify_recording):
            raise WorkerShadowError("reviewed external Recorder binding is invalid")
        self._store_root = store_root
        self._store_identity = store_identity
        self._recorder = recorder
        self._record_document = record_document
        self._verify_recording = verify_recording

    @classmethod
    def from_reviewed_toolbox(cls, *, store_root: Path, store_identity: str, recorder: RecorderBinding, module_name: str = "roundwright_harness.recording") -> "HarnessExternalWorkerRecorder":
        """Load the reviewed Harness module only at the operational boundary."""

        try:
            module = importlib.import_module(module_name)
            record_document = getattr(module, "record_document")
            verify_recording = getattr(module, "verify_recording")
        except Exception as error:
            raise WorkerShadowError("reviewed external Recorder is unavailable") from error
        return cls(store_root=store_root, store_identity=store_identity, recorder=recorder, record_document=record_document, verify_recording=verify_recording)

    def seal(self, document: Mapping[str, object], *, store_identity: str) -> ExternalRecorderReceipt:
        self._require_store(store_identity)
        try:
            return self._receipt(self._record_document(document, self._store_root))
        except WorkerShadowError:
            raise
        except Exception as error:
            raise WorkerShadowError("reviewed external Recorder rejected the public evidence") from error

    def prepare(self, *, store_identity: str) -> None:
        """Prove the selected external retention target is usable without sealing."""
        self._require_store(store_identity)
        try:
            parent = self._store_root.parent
            if not parent.is_dir() or (self._store_root.exists() and (self._store_root.is_symlink() or not self._store_root.is_dir())):
                raise WorkerShadowError("external Recorder store is unavailable")
        except OSError as error:
            raise WorkerShadowError("external Recorder store is unavailable") from error

    def verify(self, bundle_digest: str, *, store_identity: str) -> ExternalRecorderReceipt:
        self._require_store(store_identity)
        try:
            return self._receipt(self._verify_recording(self._store_root, bundle_digest))
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
                ready_at=public["ready_at"], evidence_digest=public["evidence_digest"], manifest_digest=public["manifest_digest"],
                bundle_digest=public["bundle_digest"], retention_identity=public["retention_identity"], receipt_digest=public["receipt_digest"],
            )
        except (AttributeError, KeyError, TypeError, WorkerShadowError) as error:
            raise WorkerShadowError("reviewed external Recorder receipt is invalid") from error
        core = {
            "schema": "roundwright-harness-recording-receipt/v1", "status": "sealed", "evidence_schema": "roundwright-shadow-case/v2",
            "profile": receipt.profile, "case_id": receipt.case_id, "candidate_sha": receipt.candidate_sha, "ready_at": receipt.ready_at,
            "evidence_digest": receipt.evidence_digest, "manifest_digest": receipt.manifest_digest, "bundle_digest": receipt.bundle_digest,
            "retention_identity": receipt.retention_identity,
        }
        if receipt.receipt_digest != _digest(core):
            raise WorkerShadowError("reviewed external Recorder receipt digest is invalid")
        return receipt


class HarnessNativeCodexWorkerBackend(NativeCodexWorkerBackend):
    """Executable deny-all/read-only bridge over the reviewed native SDK API."""

    def __init__(self, *, cwd: Path, codex_factory: Callable[[], object] | None = None, approval_mode: object | None = None, sandbox: object | None = None, effort_factory: Callable[[str], object] | None = None) -> None:
        if not isinstance(cwd, Path):
            raise WorkerShadowError("native Worker working directory is invalid")
        if codex_factory is None:
            try:
                sdk = importlib.import_module("openai_codex")
                generated = importlib.import_module("openai_codex.generated.v2_all")
                codex_factory, approval_mode, sandbox, effort_factory = sdk.Codex, sdk.ApprovalMode.deny_all, sdk.Sandbox.read_only, generated.ReasoningEffort
            except Exception as error:
                raise WorkerShadowError("reviewed native Worker SDK is unavailable") from error
        if not callable(codex_factory) or approval_mode is None or sandbox is None or not callable(effort_factory):
            raise WorkerShadowError("reviewed native Worker SDK binding is invalid")
        self._cwd, self._codex_factory, self._approval_mode, self._sandbox, self._effort_factory = cwd, codex_factory, approval_mode, sandbox, effort_factory

    def open_session(self, profile: ProviderProfile, *, resume_session_identity: str | None) -> NativeWorkerSession:
        if type(profile) is not ProviderProfile:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        codex = self._codex_factory()
        try:
            client = codex.__enter__() if hasattr(codex, "__enter__") else codex
            if resume_session_identity is None:
                thread = client.thread_start(approval_mode=self._approval_mode, cwd=str(self._cwd), developer_instructions="One bounded qualification turn only. Do not call tools or mutate any target. Return only the requested schema.", ephemeral=True, model=profile.model, sandbox=self._sandbox)
            else:
                resume = getattr(client, "thread_resume", None)
                if not callable(resume):
                    raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
                thread = resume(resume_session_identity)
            return _HarnessWorkerSession(thread, codex, self._sandbox, self._effort_factory, profile.reasoning_effort.value)
        except CodexAdapterError:
            _close(codex)
            raise
        except Exception as error:
            _close(codex)
            raise CodexAdapterError(CodexFailure.UNKNOWN) from error


class _HarnessWorkerSession(NativeWorkerSession):
    def __init__(self, thread: object, codex: object, sandbox: object, effort_factory: Callable[[str], object], effort: str) -> None:
        self._thread, self._codex, self._sandbox, self._effort_factory, self._effort, self._started = thread, codex, sandbox, effort_factory, effort, False

    def identity(self) -> str:
        value = getattr(self._thread, "id", None)
        if type(value) is not str:
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def start_turn(self, request: CodexWorkerRequest, tools: BoundedWorkerToolSurface) -> NativeWorkerTurn:
        if self._started or type(request) is not CodexWorkerRequest or type(tools) is not BoundedWorkerToolSurface:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._started = True
        # Input is transient only; no objective or provider output is retained.
        prompt = "Perform the bound, read-only qualification request and return only the response schema. request-digest=" + request.input_digest
        try:
            handle = self._thread.turn(prompt, effort=self._effort_factory(self._effort), output_schema=_RESULT_SCHEMA, sandbox=self._sandbox)
            return _HarnessWorkerTurn(handle, self._codex)
        except Exception as error:
            _close(self._codex)
            raise CodexAdapterError(CodexFailure.UNKNOWN) from error


class _HarnessWorkerTurn(NativeWorkerTurn):
    def __init__(self, handle: object, codex: object) -> None:
        self._handle, self._codex, self._read = handle, codex, False

    def identity(self) -> str:
        value = getattr(self._handle, "id", None)
        if type(value) is not str:
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def read_response(self) -> NativeWorkerResponse:
        if self._read:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._read = True
        try:
            return _consume_public_result(self._handle)
        finally:
            _close(self._codex)


def _consume_public_result(handle: object) -> NativeWorkerResponse:
    """Consume the SDK stream without propagating SDK text or payloads."""
    try:
        stream = handle.stream()
        response: str | None = None
        completed = False
        try:
            for event in stream:
                payload = getattr(event, "payload", event)
                turn = getattr(payload, "turn", None)
                if turn is not None and getattr(turn, "id", None) == getattr(handle, "id", None):
                    status = getattr(getattr(turn, "status", None), "value", getattr(turn, "status", None))
                    if status == "failed":
                        return NativeWorkerResponse(WorkerResultKind.BLOCKED, failure=CodexFailure.UNKNOWN)
                    completed = status == "completed"
                item = getattr(payload, "item", None)
                item = getattr(item, "root", item)
                text = getattr(item, "text", None)
                if type(text) is str:
                    response = text
        finally:
            close = getattr(stream, "close", None)
            if callable(close): close()
        if not completed or response is None:
            return NativeWorkerResponse(WorkerResultKind.INCOMPLETE)
        parsed = json.loads(response)
        if type(parsed) is not dict or set(parsed) != {"status"} or parsed["status"] not in {"complete", "blocked"}:
            return NativeWorkerResponse(WorkerResultKind.INVALID)
        return NativeWorkerResponse(WorkerResultKind.ACCEPTED, parsed)
    except Exception:
        return NativeWorkerResponse(WorkerResultKind.INVALID)


def _close(value: object) -> None:
    exit_method = getattr(value, "__exit__", None)
    if callable(exit_method):
        exit_method(None, None, None)
    else:
        close = getattr(value, "close", None)
        if callable(close): close()


def run_bounded_worker_adapter_qualification(*, backend: NativeCodexWorkerBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity, tools: BoundedWorkerToolSurface, request: CodexWorkerRequest, readiness: WorkerShadowCaptureReadiness, binding: WorkerQualificationBinding, recorder: ExternalWorkerRecorder, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> WorkerQualificationResult:
    """Operational composition point; all readiness checks occur before SDK dispatch."""
    return qualify_worker_adapter(CodexWorkerAdapter(backend, profile, audit, tools), request, readiness, binding, recorder, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)


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
    print('{"schema":"roundwright-live-worker-adapter/v1","status":"blocked","reason":"typed-orchestrator-binding-required"}')
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
