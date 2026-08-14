"""Hermetic contracts for fresh Codex Supervisor review failover."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_supervisor import (
    CodexSupervisorAdapter, CodexSupervisorContext, CodexSupervisorRequest,
    NativeSupervisorResponse, SupervisorDiagnostic, SupervisorResultKind,
    dispatch_ordered_supervisor_attempts, supervisor_request_digest,
)
from roundwright.configuration import ProviderProfile, ReasoningEffort, ReviewMode
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.supervisor_toolbox import HarnessNativeCodexSupervisorBackend
from roundwright.worker_toolbox import CompletionDeadline


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Turn:
    def __init__(self, identity, response, events): self._identity, self._response, self._events = identity, response, events
    def identity(self): return self._identity
    def abort(self): self._events.append(("abort", self._identity))
    def read_response(self): self._events.append(("read", self._identity)); return self._response


class Session:
    def __init__(self, identity, turn, events): self._identity, self._turn, self._events = identity, turn, events
    def identity(self): return self._identity
    def close(self): self._events.append(("close", self._identity))
    def start_turn(self, request): self._events.append(("start", self._identity, request.within_round_attempt)); return self._turn


class Backend:
    def __init__(self, identity, response, events): self.identity, self.response, self.events, self.calls = identity, response, events, 0
    def open_fresh_session(self, _profile):
        self.calls += 1
        return Session(f"session-{self.identity}", Turn(f"turn-{self.identity}", self.response, self.events), self.events)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.context = CodexSupervisorContext("task-44", *(digest(item) for item in ("source", "repo", "worktree", "branch")), "a" * 40, "b" * 40, digest("policy"), digest("config"), 2, 4, ReviewMode.CONVERGING)
        self.profiles = (
            ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH, "primary"),
            ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback"),
            ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback-retry"),
        )

    def adapter(self, profile, identity, response):
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        return CodexSupervisorAdapter(Backend(identity, response, self.events), profile, audit)

    def request(self, ordinal, adapter):
        values = dict(review_attempt_id=f"review-{ordinal}", provider_attempt_id=f"provider-{ordinal}", selected_profile_identity=adapter.profile_identity, within_round_attempt=ordinal, context=self.context, objective="Review the immutable candidate.", acceptance_criteria=("Return a strict verdict.",))
        return CodexSupervisorRequest(input_digest=supervisor_request_digest(**values), **values)

    def test_later_schema_valid_fallback_is_accepted_after_invalid_primary(self):
        primary = self.adapter(self.profiles[0], "one", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX))
        fallback = self.adapter(self.profiles[1], "two", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "findings", "findings": ["missing-evidence"]}))
        result = dispatch_ordered_supervisor_attempts((self.request(1, primary), self.request(2, fallback)), (primary, fallback), checkpoint_session=lambda identity: self.events.append(("session", identity)), checkpoint_turn=lambda session, turn: self.events.append(("turn", session, turn)))
        self.assertFalse(result.exhausted)
        self.assertEqual((result.attempted_profile_identities, result.result.verdict, result.result.findings), ((primary.profile_identity, fallback.profile_identity), "findings", ("missing-evidence",)))
        self.assertEqual([event[0] for event in self.events if event[0] == "start"], ["start", "start"])

    def test_exhaustion_is_availability_only_and_never_fabricates_a_verdict(self):
        adapters = tuple(self.adapter(profile, str(index), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)) for index, profile in enumerate(self.profiles, start=1))
        result = dispatch_ordered_supervisor_attempts(tuple(self.request(index, adapter) for index, adapter in enumerate(adapters, start=1)), adapters, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.result, result.exhausted, len(result.attempted_profile_identities)), (None, True, 3))

    def test_concrete_sdk_bridge_uses_fresh_deny_all_read_only_turn(self):
        events = []
        class Handle:
            id = "turn-native"
            def stream(self):
                return iter((
                    {"method": "item/completed", "payload": {"turn_id": self.id, "item": {"type": "agentMessage", "phase": "final_answer", "text": '{"verdict":"pass","findings":[]}'}}},
                    {"method": "turn/completed", "payload": {"turn": {"id": self.id, "status": "completed"}}},
                ))
        class Thread:
            id = "session-native"
            def turn(self, _prompt, **kwargs): events.append(kwargs); return Handle()
        class Codex:
            def __enter__(self): return self
            def __exit__(self, *_args): events.append("closed")
            def thread_start(self): return Thread()
        profile = self.profiles[0]
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        backend = HarnessNativeCodexSupervisorBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        adapter = CodexSupervisorAdapter(backend, profile, audit)
        result = adapter.dispatch(self.request(1, adapter), checkpoint_session=lambda identity: events.append(("session", identity)), checkpoint_turn=lambda session, turn: events.append(("turn", session, turn)))
        self.assertEqual((result.kind, result.verdict), ("accepted", "pass"))
        self.assertEqual(events[0], ("session", "session-native"))
        self.assertEqual(events[1]["approval_mode"], "deny-all")
        self.assertEqual(events[1]["sandbox"], "read-only")
        self.assertEqual(events[2], ("turn", "session-native", "turn-native"))
        self.assertIn("closed", events)

if __name__ == "__main__":
    unittest.main()
