"""Reviewed native Codex bridge for one no-tools dependency-review turn."""
from __future__ import annotations

import importlib
import inspect
import json
import tempfile
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


_NO_TOOL_INSTRUCTIONS = "Deny all tools, filesystem access, network access, credential access, and repository inspection. Use only the supplied normalized input."
_NO_TOOLS = ()


def _schema() -> dict[str, object]:
    return {"type": "object", "properties": {
        "schema": {"type": "string", "enum": ["roundwright-dependency-review-proposal/v2"]},
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
        codex = workspace = None
        try:
            if self.factory is None:
                sdk = importlib.import_module("openai_codex"); generated = importlib.import_module("openai_codex.generated.v2_all")
                factory, approval, sandbox, effort = sdk.Codex, sdk.ApprovalMode.deny_all, sdk.Sandbox.read_only, generated.ReasoningEffort
            else: factory, approval, sandbox, effort = self.factory, self.approval, self.sandbox, self.effort
            codex = factory(); client = codex.__enter__() if hasattr(codex, "__enter__") else codex
            thread_start = _require_empty_tool_surface_control(client)
            workspace = tempfile.TemporaryDirectory(prefix="roundwright-dependency-review-")
            thread = thread_start(
                approval_mode=approval, cwd=workspace.name, developer_instructions=_NO_TOOL_INSTRUCTIONS,
                ephemeral=True, model=profile.model, sandbox=sandbox, tools=_NO_TOOLS,
            )
            if not isinstance(getattr(thread, "id", None), str): raise ValueError
            return _Session(thread, codex, Path(workspace.name), profile, approval, sandbox, effort, self.completion, self.clock, workspace)
        except CodexAdapterError:
            if workspace is not None: workspace.cleanup()
            if codex is not None: _close(codex)
            raise
        except Exception:
            if workspace is not None: workspace.cleanup()
            if codex is not None: _close(codex)
            raise CodexAdapterError(CodexFailure.UNKNOWN) from None


def _require_empty_tool_surface_control(client: object) -> Callable[..., object]:
    """Return only an SDK endpoint with an explicit, empty-tools control.

    A permissive ``**kwargs`` test double or an opaque ``config`` override is
    not evidence that the native endpoint withheld its tool surface.
    """

    thread_start = getattr(client, "thread_start", None)
    if not callable(thread_start):
        raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
    try:
        tools = inspect.signature(thread_start).parameters.get("tools")
    except (TypeError, ValueError):
        raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE) from None
    if tools is None or tools.kind not in {inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY}:
        raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
    return thread_start


class _Session(NativeDependencyReviewSession):
    def __init__(self, thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, workspace): self.thread, self.codex, self.cwd, self.profile, self.approval, self.sandbox, self.effort, self.completion, self.clock, self.workspace, self.started = thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, workspace, False
    def identity(self) -> str: return self.thread.id
    def close(self) -> None: _close(self.codex); self.workspace.cleanup()
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
                    turn = _field(payload, "turn")
                    if turn is None or _field(turn, "id") != _field(self.handle, "id") or complete:
                        return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
                    status = _value(_field(turn, "status")); complete = status == "completed"
                    if status == "failed": return NativeDependencyReviewResponse(DependencyReviewResultKind.BLOCKED, failure=_turn_failure(_field(turn, "error"))[0])
                    if status != "completed": return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
                if _field(event, "method") == "item/completed" and _field(payload, "turn_id", "turnId") == _field(self.handle, "id"):
                    item = _field(_field(payload, "item"), "root") or _field(payload, "item")
                    if _field(item, "type") not in {"agentMessage", "reasoning"}:
                        return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
                    if _field(item, "type") == "agentMessage" and _value(_field(item, "phase")) == "final_answer":
                        text = _field(item, "text")
                        if answer is not None or not isinstance(text, str): return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
                        answer = text
            if not complete: return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
            if answer is None: return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
            try: value = json.loads(answer)
            except Exception: return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
            return NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, value) if type(value) is dict else NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
        except Exception: return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
        finally: self.session.close()
