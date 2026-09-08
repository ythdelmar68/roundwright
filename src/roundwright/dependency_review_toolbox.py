"""Reviewed native Codex bridge for one behaviorally tool-silent review turn."""
from __future__ import annotations

import hashlib
import importlib
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
_SAFE_ITEM_TYPES = frozenset({"agentMessage", "reasoning"})
_TOOL_EVENT_TOKENS = ("tool", "command", "exec", "mcp", "filechange", "websearch")


def dependency_review_native_control_contract() -> dict[str, object]:
    """Return the public-safe native controls bound into every attempt."""

    return {
        "schema": "roundwright-dependency-review-native-controls/v1",
        "session_freshness": "fresh-job-session",
        "input_scope": "immutable-normalized-minimal-subset",
        "workspace": "isolated-ephemeral",
        "sandbox": "read-only",
        "approval_policy": "deny-all",
        "credential_handling": "sanitized-no-credential-material",
        "mutation_authority": False,
        "tool_configuration_override": "none",
        "tool_use_policy": "behavioral-zero-tool-use",
        "tool_event_disposition": "terminal-invalid-ineligible",
    }


def dependency_review_native_control_digest() -> str:
    value = json.dumps(
        dependency_review_native_control_contract(),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(value).hexdigest()


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
            thread_start = getattr(client, "thread_start", None)
            if not callable(thread_start):
                raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
            workspace = tempfile.TemporaryDirectory(prefix="roundwright-dependency-review-")
            thread = thread_start(
                approval_mode=approval, cwd=workspace.name, developer_instructions=_NO_TOOL_INSTRUCTIONS,
                ephemeral=True, model=profile.model, sandbox=sandbox,
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
class _Session(NativeDependencyReviewSession):
    def __init__(self, thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, workspace): self.thread, self.codex, self.cwd, self.profile, self.approval, self.sandbox, self.effort, self.completion, self.clock, self.workspace, self.started = thread, codex, cwd, profile, approval, sandbox, effort, completion, clock, workspace, False
    def identity(self) -> str: return self.thread.id
    def close(self) -> None: _close(self.codex); self.workspace.cleanup()
    def start_turn(self, request: DependencyReviewRequest) -> NativeDependencyReviewTurn:
        if self.started or type(request) is not DependencyReviewRequest: raise CodexAdapterError(CodexFailure.SDK_INCOMPATIBLE)
        self.started = True
        payload = {"schema": "roundwright-dependency-review-native/v1", "capability_contract": "behavioral-zero-tool-use/v1", "instruction": "Return only one dependency proposal for this normalized subset. Do not request or use tools, inspect repositories, request credentials, or emit prose.", "input": request.input_material}
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
                if _is_tool_event(event, payload):
                    return NativeDependencyReviewResponse(
                        DependencyReviewResultKind.INVALID, reason_code="tool-event-observed",
                    )
                if (
                    _field(event, "method") in {"item/started", "item/completed"}
                    and _field(payload, "turn_id", "turnId") != _field(self.handle, "id")
                ):
                    return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
                if _field(event, "method") == "turn/completed":
                    turn = _field(payload, "turn")
                    if turn is None or _field(turn, "id") != _field(self.handle, "id") or complete:
                        return NativeDependencyReviewResponse(DependencyReviewResultKind.INVALID)
                    status = _value(_field(turn, "status")); complete = status == "completed"
                    if status == "failed": return NativeDependencyReviewResponse(DependencyReviewResultKind.BLOCKED, failure=_turn_failure(_field(turn, "error"))[0])
                    if status != "completed": return NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS)
                if _field(event, "method") == "item/completed" and _field(payload, "turn_id", "turnId") == _field(self.handle, "id"):
                    item = _field(_field(payload, "item"), "root") or _field(payload, "item")
                    if _field(item, "type") not in _SAFE_ITEM_TYPES:
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


def _is_tool_event(event: object, payload: object) -> bool:
    """Fail closed on every native event that can represent tool activity."""

    method = _value(_field(event, "method"))
    if isinstance(method, str):
        normalized = "".join(character for character in method.casefold() if character.isalnum())
        if any(token in normalized for token in _TOOL_EVENT_TOKENS):
            return True
        if method in {"item/started", "item/completed"}:
            item = _field(_field(payload, "item"), "root") or _field(payload, "item")
            if _field(item, "type") not in _SAFE_ITEM_TYPES:
                return True
    return False
