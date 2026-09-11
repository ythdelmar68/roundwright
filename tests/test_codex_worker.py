"""Hermetic coverage for the bounded native Codex Worker adapter."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import (
    BoundedWorkerToolSurface,
    CodexWorkerAdapter,
    CodexWorkerContext,
    CodexWorkerError,
    CodexWorkerRequest,
    NativeWorkerResponse,
    WorkerAction,
    WorkerResultKind,
    WorkerTool,
    NativeWorkerToolRequest,
    NativeWorkerToolResult,
    NativeWorkerTurnStep,
    worker_request_digest,
)
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class FakeTurn:
    def __init__(self, identity: str, response: object, events: list[str], steps=()) -> None:
        self._identity, self._response, self._events, self._steps = identity, response, events, iter(steps)
    def identity(self) -> str: return self._identity
    def abort(self): self._events.append("abort")
    def read_response(self):
        self._events.append("read")
        if isinstance(self._response, Exception): raise self._response
        return self._response
    def read_step(self): self._events.append("step"); return next(self._steps)
    def submit_tool_result(self, result): self._events.append(f"submit:{result.sequence}")


class FakeSession:
    def __init__(self, identity: str, turn: FakeTurn, events: list[str]) -> None:
        self._identity, self._turn, self._events = identity, turn, events
    def identity(self) -> str: return self._identity
    def close(self): self._events.append("close")
    def start_turn(self, request, tools):
        self._events.append(f"start:{request.action.value}:{','.join(item.value for item in tools.tools)}")
        return self._turn


class FakeBackend:
    def __init__(self, session: object) -> None: self.session, self.resumes = session, []
    def open_session(self, profile, *, resume_session_identity):
        self.resumes.append(resume_session_identity)
        if isinstance(self.session, Exception): raise self.session
        return self.session


class CodexWorkerAdapterTests(unittest.TestCase):
    def profile(self) -> ProviderProfile:
        return ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)

    def adapter(self, backend, events: list[str]) -> CodexWorkerAdapter:
        profile = self.profile()
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        return CodexWorkerAdapter(backend, profile, audit, BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE)))

    def request(self, *, resume: str | None = None) -> CodexWorkerRequest:
        context = CodexWorkerContext("task-43", *(digest(name) for name in ("source", "repository", "worktree", "branch", "base", "candidate", "policy", "configuration")))
        return CodexWorkerRequest("attempt-43", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-43", action=WorkerAction.IMPLEMENTATION, context=context, objective="Implement only issue 43.", constraints=("No GitHub",), acceptance_criteria=("Use only bounded tools",), resume_session_identity=resume), context, "Implement only issue 43.", ("No GitHub",), ("Use only bounded tools",), resume)

    def dispatch(self, adapter, request, events):
        return adapter.dispatch(request, checkpoint_session=lambda session: events.append(f"session:{session}"), checkpoint_turn=lambda session, turn: events.append(f"turn:{session}:{turn}"))

    def test_checkpoints_precede_provider_result_consumption(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"}), events)
        adapter = self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events)
        result = self.dispatch(adapter, self.request(), events)
        self.assertEqual(events, ["session:thread-43", "start:implementation:workspace-read,workspace-write,validation-execute", "turn:thread-43:turn-43", "read"])
        self.assertEqual((result.kind, result.session_identity, result.turn_identity, result.output), (WorkerResultKind.ACCEPTED, "thread-43", "turn-43", {"status": "done"}))
        self.assertTrue(result.output_fingerprint.startswith("sha256:"))

    def test_each_post_tool_sdk_turn_is_checkpointed_before_consumption(self) -> None:
        events: list[str] = []
        class ReplacingTurn(FakeTurn):
            def __init__(self):
                super().__init__("turn-1", None, events, (
                    NativeWorkerTurnStep(request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_READ, path="a.txt")),
                    NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"})),
                ))
            def submit_tool_result(self, result):
                super().submit_tool_result(result); self._identity = "turn-2"
        turn = ReplacingTurn()
        adapter = self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events)
        result = adapter.dispatch(
            self.request(), checkpoint_session=lambda session: events.append(f"session:{session}"),
            checkpoint_turn=lambda session, identity: events.append(f"turn:{session}:{identity}"),
            execute_tool_request=lambda request: NativeWorkerToolResult(request.sequence, request.tool, "allowed", after_digest=digest("read")),
        )
        self.assertEqual(result.kind, WorkerResultKind.ACCEPTED)
        self.assertLess(events.index("turn:thread-43:turn-2"), events.index("step", events.index("submit:1")))

    def test_resume_must_preserve_the_persisted_worker_thread(self) -> None:
        events: list[str] = []
        backend = FakeBackend(FakeSession("other-thread", FakeTurn("turn-43", NativeWorkerResponse(WorkerResultKind.INCOMPLETE), events), events))
        result = self.dispatch(self.adapter(backend, events), self.request(resume="thread-43"), events)
        self.assertEqual((result.kind, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, "other-thread", None))
        self.assertEqual(events, ["close"])
        self.assertEqual(backend.resumes, ["thread-43"])

    def test_checkpoint_failure_never_consumes_output(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"}), events)
        adapter = self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events)
        result = adapter.dispatch(self.request(), checkpoint_session=lambda _session: None, checkpoint_turn=lambda _session, _turn: (_ for _ in ()).throw(RuntimeError("storage unavailable")))
        self.assertEqual(result.kind, WorkerResultKind.AMBIGUOUS)
        self.assertNotIn("read", events)
        self.assertEqual(events, ["start:implementation:workspace-read,workspace-write,validation-execute", "abort", "close"])

    def test_session_checkpoint_failure_closes_without_starting_a_turn(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"}), events)
        result = self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events).dispatch(self.request(), checkpoint_session=lambda _session: (_ for _ in ()).throw(RuntimeError("storage unavailable")), checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.kind, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, "thread-43", None))
        self.assertEqual(events, ["close"])

    def test_invalid_output_is_never_accepted(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", NativeWorkerResponse(WorkerResultKind.ACCEPTED, {}), events)
        result = self.dispatch(self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events), self.request(), events)
        self.assertEqual((result.kind, result.output, result.failure), (WorkerResultKind.INVALID, None, None))

    def test_typed_denial_and_transport_failure_remain_typed(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", CodexAdapterError(CodexFailure.SANDBOX_OR_APPROVAL_DENIED), events)
        result = self.dispatch(self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events), self.request(), events)
        self.assertEqual((result.kind, result.failure, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, None, "thread-43", "turn-43"))
        self.assertEqual(events, ["session:thread-43", "start:implementation:workspace-read,workspace-write,validation-execute", "turn:thread-43:turn-43", "read", "abort", "close"])

    def test_generic_read_failure_aborts_then_closes_once_without_a_second_turn(self) -> None:
        events: list[str] = []
        turn = FakeTurn("turn-43", RuntimeError("private transport detail"), events)
        backend = FakeBackend(FakeSession("thread-43", turn, events))
        result = self.dispatch(self.adapter(backend, events), self.request(), events)
        self.assertEqual((result.kind, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, "thread-43", "turn-43"))
        self.assertEqual(events, ["session:thread-43", "start:implementation:workspace-read,workspace-write,validation-execute", "turn:thread-43:turn-43", "read", "abort", "close"])
        self.assertEqual(backend.resumes, [None])

    def test_cleanup_failures_preserve_the_ambiguous_exact_turn(self) -> None:
        events: list[str] = []
        class FailingTurn(FakeTurn):
            def abort(self):
                self._events.append("abort")
                raise RuntimeError("private cleanup detail")
        class FailingSession(FakeSession):
            def close(self):
                self._events.append("close")
                raise RuntimeError("private cleanup detail")
        turn = FailingTurn("turn-43", RuntimeError("private provider detail"), events)
        result = self.dispatch(self.adapter(FakeBackend(FailingSession("thread-43", turn, events)), events), self.request(), events)
        self.assertEqual((result.kind, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, "thread-43", "turn-43"))
        self.assertEqual(events, ["session:thread-43", "start:implementation:workspace-read,workspace-write,validation-execute", "turn:thread-43:turn-43", "read", "abort", "close"])

    def test_pre_session_failure_has_no_fabricated_turn_identity(self) -> None:
        events: list[str] = []
        result = self.dispatch(self.adapter(FakeBackend(CodexAdapterError(CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE)), events), self.request(), events)
        self.assertEqual((result.kind, result.session_identity, result.turn_identity), (WorkerResultKind.AMBIGUOUS, None, None))
        events = []
        backend = FakeBackend(CodexAdapterError(CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE))
        result = self.dispatch(self.adapter(backend, events), self.request(resume="thread-43"), events)
        self.assertEqual((result.kind, result.failure), (WorkerResultKind.AMBIGUOUS, None))

    def test_request_digest_binds_every_immutable_request_field(self) -> None:
        request = self.request()
        with self.assertRaises(CodexWorkerError):
            CodexWorkerRequest(request.attempt_id, request.action, request.input_digest, request.context, "different objective", request.constraints, request.acceptance_criteria)

    def test_adapter_rejects_unqualified_profile_or_empty_tools(self) -> None:
        profile = self.profile()
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        self.assertEqual(BoundedWorkerToolSurface(()).capability_contract.value, "no-tools-self-contained/v1")
        with self.assertRaises(CodexWorkerError):
            CodexWorkerAdapter(FakeBackend(None), ProviderProfile("gpt-5.6-sol", ReasoningEffort.HIGH), audit, BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)))

    def test_executable_coding_contract_requires_the_complete_bounded_surface(self) -> None:
        self.assertEqual(BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE)).capability_contract.value, "orchestration-declared-only/v1")
        self.assertEqual(BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)).capability_contract.value, "orchestration-declared-only/v1")

    def test_closed_tool_step_roundtrip_and_cross_tool_rejection(self) -> None:
        request = NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="src/a.py", content="x")
        result = NativeWorkerToolResult(1, WorkerTool.WORKSPACE_WRITE, "allowed", after_digest=digest("x"))
        self.assertEqual((NativeWorkerTurnStep(request=request).request, result.sequence), (request, 1))
        with self.assertRaises(CodexWorkerError):
            NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_READ, path="a", content="x")
        with self.assertRaises(CodexWorkerError):
            NativeWorkerToolRequest(0, WorkerTool.VALIDATION_EXECUTE, command=("python",))

    def test_adapter_routes_ordered_tool_step_before_terminal_response(self) -> None:
        events = []
        request = self.request()
        step = NativeWorkerTurnStep(request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="src/a.py", content="x"))
        terminal = NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"}))
        turn = FakeTurn("turn-43", None, events, (step, terminal))
        adapter = self.adapter(FakeBackend(FakeSession("thread-43", turn, events)), events)
        result = adapter.dispatch(request, checkpoint_session=lambda value: events.append("session:" + value), checkpoint_turn=lambda _a, value: events.append("turn:" + value), execute_tool_request=lambda item: NativeWorkerToolResult(item.sequence, item.tool, "allowed"))
        self.assertEqual(result.kind, WorkerResultKind.ACCEPTED)
        self.assertEqual(events, ["session:thread-43", "start:implementation:workspace-read,workspace-write,validation-execute", "turn:turn-43", "step", "submit:1", "turn:turn-43", "step"])

    def test_out_of_order_step_is_ambiguous_without_callback(self) -> None:
        events=[]; request=self.request(); turn=FakeTurn("turn-43", None, events, (NativeWorkerTurnStep(request=NativeWorkerToolRequest(2, WorkerTool.WORKSPACE_READ, path="a")),))
        result=self.adapter(FakeBackend(FakeSession("thread-43",turn,events)),events).dispatch(request, checkpoint_session=lambda _:None, checkpoint_turn=lambda *_:None, execute_tool_request=lambda _: self.fail("callback"))
        self.assertEqual(result.kind,WorkerResultKind.AMBIGUOUS); self.assertIn("abort",events); self.assertIn("close",events); self.assertNotIn("submit:2",events)

    def test_mismatched_tool_reply_is_ambiguous_without_submission(self) -> None:
        events=[]; request=self.request(); item=NativeWorkerToolRequest(1,WorkerTool.WORKSPACE_READ,path="a"); turn=FakeTurn("turn-43",None,events,(NativeWorkerTurnStep(request=item),))
        result=self.adapter(FakeBackend(FakeSession("thread-43",turn,events)),events).dispatch(request,checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None,execute_tool_request=lambda _:NativeWorkerToolResult(2,WorkerTool.WORKSPACE_READ,"allowed"))
        self.assertEqual(result.kind,WorkerResultKind.AMBIGUOUS); self.assertNotIn("submit:2",events)

    def test_legacy_path_uses_terminal_response_only(self) -> None:
        events=[]; turn=FakeTurn("turn-43",NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}),events)
        result=self.dispatch(self.adapter(FakeBackend(FakeSession("thread-43",turn,events)),events),self.request(),events)
        self.assertEqual(result.kind,WorkerResultKind.ACCEPTED); self.assertIn("read",events); self.assertNotIn("step",events)


if __name__ == "__main__":
    unittest.main()
