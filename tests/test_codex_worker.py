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
    worker_request_digest,
)
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class FakeTurn:
    def __init__(self, identity: str, response: object, events: list[str]) -> None:
        self._identity, self._response, self._events = identity, response, events
    def identity(self) -> str: return self._identity
    def abort(self): self._events.append("abort")
    def read_response(self):
        self._events.append("read")
        if isinstance(self._response, Exception): raise self._response
        return self._response


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


if __name__ == "__main__":
    unittest.main()
