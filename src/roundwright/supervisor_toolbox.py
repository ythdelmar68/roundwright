"""Operational deny-all/read-only bridge for a fresh Codex Supervisor turn.

The surrounding lifecycle owns retries and state transitions.  This bridge
only converts one native SDK turn into the narrow structured response consumed
by :mod:`roundwright.codex_supervisor`; it retains neither provider prose nor
SDK error text.
"""

from __future__ import annotations

import importlib
import json
import time
from pathlib import Path
from typing import Callable, Mapping

from .codex_supervisor import (
    CodexSupervisorError, CodexSupervisorRequest, NativeCodexSupervisorBackend, canonical_supervisor_review_material,
    NativeSupervisorResponse, NativeSupervisorSession, NativeSupervisorTurn,
    SupervisorDiagnostic, SupervisorOutcomeSource, SupervisorResultKind, SupervisorSdkTurnErrorCategory,
)
from .configuration import ProviderProfile
from .provider_health import CodexAdapterError, CodexFailure
from .worker_toolbox import CompletionDeadline, _bounded_events, _close, _field, _turn_failure, _value


def _schema() -> dict[str, object]:
    return {"type": "object", "properties": {"verdict": {"type": "string", "enum": ["pass", "findings"]}, "findings": {"type": "array", "items": {"type": "string"}, "maxItems": 32}, "binding": {"type": "object", "properties": {"input_digest": {"type": "string"}, "candidate_sha": {"type": "string"}, "within_round_attempt": {"type": "integer"}, "profile_identity": {"type": "string"}}, "required": ["input_digest", "candidate_sha", "within_round_attempt", "profile_identity"], "additionalProperties": False}}, "required": ["verdict", "findings", "binding"], "additionalProperties": False}


class HarnessNativeCodexSupervisorBackend(NativeCodexSupervisorBackend):
    """Fresh native Codex sessions with no tool, approval, or write authority."""

    def __init__(self, *, cwd: Path, completion: CompletionDeadline, codex_factory: Callable[[], object] | None = None, approval_mode: object | None = None, sandbox: object | None = None, effort_factory: Callable[[str], object] | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(cwd, Path):
            raise CodexSupervisorError("native Supervisor working directory is invalid")
        if (
            type(completion) is not CompletionDeadline
            or not callable(clock)
            or (
                codex_factory is not None
                and (not callable(codex_factory) or approval_mode is None or sandbox is None or not callable(effort_factory))
            )
            or (
                codex_factory is None
                and any(item is not None for item in (approval_mode, sandbox, effort_factory))
            )
        ):
            raise CodexSupervisorError("reviewed native Supervisor SDK binding is invalid")
        self._cwd, self._completion, self._factory, self._approval, self._sandbox, self._effort, self._clock = cwd, completion, codex_factory, approval_mode, sandbox, effort_factory, clock

    def open_fresh_session(self, profile: ProviderProfile) -> NativeSupervisorSession:
        if type(profile) is not ProviderProfile:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        try:
            factory, approval, sandbox, effort = self._native_binding()
            codex = factory()
            client = codex.__enter__() if hasattr(codex, "__enter__") else codex
            thread = client.thread_start()
            if not isinstance(getattr(thread, "id", None), str):
                raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
            return _Session(thread, codex, self._cwd, profile, approval, sandbox, effort, self._completion, self._clock)
        except CodexAdapterError:
            _close(locals().get("codex"))
            raise
        except Exception:
            _close(locals().get("codex"))
            raise CodexAdapterError(CodexFailure.UNKNOWN) from None

    def _native_binding(self) -> tuple[Callable[[], object], object, object, Callable[[str], object]]:
        """Resolve the SDK only while its failures are classified at dispatch."""

        if self._factory is not None:
            return self._factory, self._approval, self._sandbox, self._effort  # type: ignore[return-value]
        try:
            sdk = importlib.import_module("openai_codex")
            generated = importlib.import_module("openai_codex.generated.v2_all")
            factory, approval, sandbox, effort = sdk.Codex, sdk.ApprovalMode.deny_all, sdk.Sandbox.read_only, generated.ReasoningEffort
        except Exception:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE) from None
        if not callable(factory) or approval is None or sandbox is None or not callable(effort):
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        return factory, approval, sandbox, effort

    @property
    def completion(self) -> CompletionDeadline:
        """Typed deadline supplied by the product host; never provider data."""

        return self._completion


class _Session(NativeSupervisorSession):
    def __init__(self, thread: object, codex: object, cwd: Path, profile: ProviderProfile, approval: object, sandbox: object, effort: Callable[[str], object], completion: CompletionDeadline, clock: Callable[[], float]) -> None:
        self._thread, self._codex, self._cwd, self._profile, self._approval, self._sandbox, self._effort, self._completion, self._clock, self._started, self._closed = thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, False, False

    def identity(self) -> str:
        value = getattr(self._thread, "id", None)
        if not isinstance(value, str): raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            _close(self._codex)

    def start_turn(self, request: CodexSupervisorRequest) -> NativeSupervisorTurn:
        if self._started or type(request) is not CodexSupervisorRequest:
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._started = True
        payload = {"schema": "roundwright-supervisor-native/v1", "capability_contract": "no-tools-self-contained/v1", "instruction": "Review only this canonical immutable material. Do not use tools, inspect repositories, or request credentials. Return only the schema and copy its binding exactly.", "review_material": canonical_supervisor_review_material(request), "tools": []}
        try:
            handle = self._thread.turn(json.dumps(payload, sort_keys=True, separators=(",", ":")), approval_mode=self._approval, cwd=str(self._cwd), model=self._profile.model, effort=self._effort(self._profile.reasoning_effort.value), output_schema=_schema(), sandbox=self._sandbox)
            return _Turn(handle, self, self._completion, self._clock)
        except Exception as error:
            self.close()
            raise CodexAdapterError(CodexFailure.UNKNOWN) from error


class _Turn(NativeSupervisorTurn):
    def __init__(self, handle: object, session: _Session, completion: CompletionDeadline, clock: Callable[[], float]) -> None:
        self._handle, self._session, self._completion, self._clock, self._read, self._aborted = handle, session, completion, clock, False, False

    def identity(self) -> str:
        value = getattr(self._handle, "id", None)
        if not isinstance(value, str): raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        return value

    def abort(self) -> None:
        if not self._aborted:
            self._aborted = True
            interrupt = getattr(self._handle, "interrupt", None)
            if callable(interrupt):
                try: interrupt()
                except Exception: pass

    def read_response(self) -> NativeSupervisorResponse:
        if self._read: raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self._read = True
        try:
            return _consume(self._handle, self._completion, self._clock, self.abort)
        finally:
            self._session.close()


def _consume(handle: object, completion: CompletionDeadline, clock: Callable[[], float], cancel: Callable[[], None]) -> NativeSupervisorResponse:
    try:
        response: str | None = None
        completed = False
        non_final = False
        stream = handle.stream()
        try:
            for event in _bounded_events(stream, completion=completion, clock=clock, cancel=cancel):
                payload = _field(event, "payload") or event
                if _field(event, "method") == "turn/completed":
                    turn = _field(payload, "turn")
                    if turn is None or _field(turn, "id") != _field(handle, "id"):
                        return NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.CONTEXT)
                    status = _value(_field(turn, "status"))
                    if status == "failed":
                        failure, category = _turn_failure(_field(turn, "error"))
                        return NativeSupervisorResponse(
                            SupervisorResultKind.BLOCKED, failure=failure,
                            outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
                            sdk_error_category=SupervisorSdkTurnErrorCategory(category.value),
                        )
                    if status != "completed":
                        return NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)
                    completed = True
                    continue
                if _field(event, "method") != "item/completed" or _field(payload, "turn_id", "turnId") != _field(handle, "id"):
                    continue
                item = _field(_field(payload, "item"), "root") or _field(payload, "item")
                if _field(item, "type") != "agentMessage": continue
                if _value(_field(item, "phase")) != "final_answer":
                    non_final = True; continue
                text = _field(item, "text")
                if not isinstance(text, str) or response is not None:
                    return NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE)
                response = text
        finally:
            close = getattr(stream, "close", None)
            if callable(close): close()
        if not completed: return NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)
        if response is None: return NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.NON_FINAL if non_final else SupervisorDiagnostic.SHAPE)
        try: parsed = json.loads(response)
        except (TypeError, ValueError): return NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX)
        binding = parsed.get("binding") if type(parsed) is dict else None
        if type(parsed) is not dict or set(parsed) != {"verdict", "findings", "binding"} or parsed.get("verdict") not in {"pass", "findings"} or type(parsed.get("findings")) is not list or type(binding) is not dict or set(binding) != {"input_digest", "candidate_sha", "within_round_attempt", "profile_identity"} or type(binding["input_digest"]) is not str or type(binding["candidate_sha"]) is not str or type(binding["within_round_attempt"]) is not int or type(binding["profile_identity"]) is not str:
            return NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE)
        return NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, parsed)
    except TimeoutError:
        return NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)
    except Exception:
        return NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)
