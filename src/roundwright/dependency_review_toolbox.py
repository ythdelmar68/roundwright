"""Reviewed native Codex bridge for one no-tools dependency-review turn."""
from __future__ import annotations

import importlib
import json
import time
from pathlib import Path
from typing import Callable

from .codex_dependency_review import (
    DependencyReviewRequest, DependencyReviewResultKind, NativeCodexDependencyReviewBackend,
    NativeDependencyReviewResponse, NativeDependencyReviewSession, NativeDependencyReviewTurn,
)
from .configuration import ProviderProfile
from .provider_health import CodexAdapterError, CodexFailure
from .worker_toolbox import CompletionDeadline, _bounded_events, _close, _field, _turn_failure, _value


def _schema() -> dict[str, object]:
    return {"type": "object", "properties": {
        "schema": {"type": "string", "const": "roundwright-dependency-review-proposal/v2"},
        "proposal_id": {"type": "string"}, "attempt_id": {"type": "string"},
        "requested_disposition": {"type": "string", "enum": ["auto-activate", "owner-review", "reject"]},
        "owner_route": {"type": "string"}, "edges": {"type": "array", "minItems": 1},
    }, "required": ["schema", "proposal_id", "attempt_id", "requested_disposition", "owner_route", "edges"], "additionalProperties": False}


class HarnessNativeCodexDependencyReviewBackend(NativeCodexDependencyReviewBackend):
    """Fresh deny-all/read-only native sessions; no credential crosses this API."""
    def __init__(self, *, cwd: Path, completion: CompletionDeadline, codex_factory: Callable[[], object] | None = None, approval_mode: object | None = None, sandbox: object | None = None, effort_factory: Callable[[str], object] | None = None, clock: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(cwd, Path) or type(completion) is not CompletionDeadline or not callable(clock) or (codex_factory is not None and (not callable(codex_factory) or approval_mode is None or sandbox is None or not callable(effort_factory))):
            raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self.cwd, self.completion, self.factory, self.approval, self.sandbox, self.effort, self.clock = cwd, completion, codex_factory, approval_mode, sandbox, effort_factory, clock

    def open_fresh_session(self, profile: ProviderProfile) -> NativeDependencyReviewSession:
        if type(profile) is not ProviderProfile or (profile.model, profile.reasoning_effort.value) != ("gpt-5.6-terra", "high"):
            raise CodexAdapterError(CodexFailure.UNSUPPORTED_CAPABILITY)
        try:
            if self.factory is None:
                sdk = importlib.import_module("openai_codex"); generated = importlib.import_module("openai_codex.generated.v2_all")
                factory, approval, sandbox, effort = sdk.Codex, sdk.ApprovalMode.deny_all, sdk.Sandbox.read_only, generated.ReasoningEffort
            else: factory, approval, sandbox, effort = self.factory, self.approval, self.sandbox, self.effort
            codex = factory(); client = codex.__enter__() if hasattr(codex, "__enter__") else codex; thread = client.thread_start()
            if not isinstance(getattr(thread, "id", None), str): raise ValueError
            return _Session(thread, codex, self.cwd, profile, approval, sandbox, effort, self.completion, self.clock)
        except CodexAdapterError: raise
        except Exception: raise CodexAdapterError(CodexFailure.UNKNOWN) from None


class _Session(NativeDependencyReviewSession):
    def __init__(self, thread, codex, cwd, profile, approval, sandbox, effort, completion, clock): self.thread, self.codex, self.cwd, self.profile, self.approval, self.sandbox, self.effort, self.completion, self.clock, self.started = thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, False
    def identity(self) -> str: return self.thread.id
    def close(self) -> None: _close(self.codex)
    def start_turn(self, request: DependencyReviewRequest) -> NativeDependencyReviewTurn:
        if self.started or type(request) is not DependencyReviewRequest: raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self.started = True
        payload = {"schema": "roundwright-dependency-review-native/v1", "capability_contract": "no-tools-self-contained/v1", "instruction": "Return only one dependency proposal for this normalized subset. Do not use tools, inspect repositories, request credentials, or emit prose.", "input": request.input_material, "tools": []}
        try: return _Turn(self.thread.turn(json.dumps(payload, sort_keys=True, separators=(",", ":")), approval_mode=self.approval, cwd=str(self.cwd), model=self.profile.model, effort=self.effort(self.profile.reasoning_effort.value), output_schema=_schema(), sandbox=self.sandbox), self)
        except Exception: self.close(); raise CodexAdapterError(CodexFailure.UNKNOWN) from None


class _Turn(NativeDependencyReviewTurn):
    def __init__(self, handle, session): self.handle, self.session, self.read = handle, session, False
    def identity(self) -> str: return self.handle.id
    def abort(self) -> None:
        interrupt = getattr(self.handle, "interrupt", None)
        if callable(interrupt):
            try: interrupt()
            except Exception: pass
    def read_response(self) -> NativeDependencyReviewResponse:
        if self.read: raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self.read = True; answer = None; complete = False
        try:
            for event in _bounded_events(self.handle.stream(), completion=self.session.completion, clock=self.session.clock, cancel=self.abort):
                payload = _field(event, "payload") or event
                if _field(event, "method") == "turn/completed":
                    turn = _field(payload, "turn"); status = _value(_field(turn, "status")); complete = status == "completed"
                    if status == "failed": return NativeDependencyReviewResponse(DependencyReviewResultKind.BLOCKED, failure=_turn_failure(_field(turn, "error"))[0])
                if _field(event, "method") == "item/completed" and _field(payload, "turn_id", "turnId") == _field(self.handle, "id"):
                    item = _field(_field(payload, "item"), "root") or _field(payload, "item")
                    if _field(item, "type") == "agentMessage" and _value(_field(item, "phase")) == "final_answer": answer = _field(item, "text")
            if not complete: return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
            try: value = json.loads(answer)
            except Exception: return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
            return NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, value) if type(value) is dict else NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
        except Exception: return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
        finally: self.session.close()
