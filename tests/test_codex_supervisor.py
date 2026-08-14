"""Hermetic contracts for fresh Codex Supervisor review failover."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_supervisor import (
    CodexSupervisorAdapter, CodexSupervisorContext, CodexSupervisorRequest,
    NativeSupervisorResponse, SupervisorDiagnostic, SupervisorResultKind,
    dispatch_ordered_supervisor_attempts, supervisor_request_digest,
)
from roundwright.configuration import ConfigurationError, ConfigurationSource, FinalFindingsPolicy, ProviderProfile, ReasoningEffort, ResolvedConfigurationBinding, ReviewMode, ReviewPolicy, load_configuration
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.runtime_binding import InMemorySupervisorRuntimeStore, RuntimeBindingError
from roundwright.supervisor_toolbox import HarnessNativeCodexSupervisorBackend
from roundwright.worker_toolbox import CompletionDeadline
from roundwright.shadow import RecorderBinding
from roundwright.supervisor_shadow import (
    SUPERVISOR_FAILOVER_PROFILE, SupervisorCapturePlanReceipt,
    SupervisorQualificationBinding, SupervisorRecorderReceipt,
    ResolvedSupervisorSequencePolicy, SupervisorExpectedLifecycleReceipt, SupervisorSequenceBinding, SupervisorSequenceTerminal,
    SupervisorAttemptEvent, SupervisorTerminalRecord, LifecycleChainReceipt, CompleteSupervisorLifecycleRecord,
    FileSupervisorLifecycle, InMemorySupervisorLifecycle,
    SupervisorLifecycleChainBinding,
    SupervisorShadowError,
    qualify_supervisor_attempt, qualify_supervisor_sequence,
    require_supervisor_capture_readiness, supervisor_sequence_lifecycle_identity, supervisor_sequence_observation_identity,
)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Turn:
    def __init__(self, identity, response, events): self._identity, self._response, self._events = identity, response, events
    def identity(self): return self._identity
    def abort(self): self._events.append(("abort", self._identity))
    def read_response(self):
        self._events.append(("read", self._identity))
        if self._response.kind is SupervisorResultKind.ACCEPTED and "binding" not in self._response.structured_output:
            request = self._request
            value = dict(self._response.structured_output)
            value["binding"] = {"input_digest": request.input_digest, "candidate_sha": request.context.candidate_sha, "within_round_attempt": request.within_round_attempt, "profile_identity": request.selected_profile_identity}
            return NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, value)
        return self._response


class Session:
    def __init__(self, identity, turn, events): self._identity, self._turn, self._events = identity, turn, events
    def identity(self): return self._identity
    def close(self): self._events.append(("close", self._identity))
    def start_turn(self, request): self._events.append(("start", self._identity, request.within_round_attempt)); self._turn._request = request; return self._turn


class Backend:
    def __init__(self, identity, response, events): self.identity, self.response, self.events, self.calls = identity, response, events, 0
    def open_fresh_session(self, _profile):
        self.calls += 1
        return Session(f"session-{self.identity}", Turn(f"turn-{self.identity}", self.response, self.events), self.events)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.configuration = load_configuration(cwd=ROOT, environment={}, home=ROOT).pin()
        self.context = CodexSupervisorContext("task-44", *(digest(item) for item in ("source", "repo", "worktree", "branch")), "a" * 40, "b" * 40, "sha256:" + self.configuration.runtime_binding().review_policy_digest, self.configuration.digest, 2, 4, ReviewMode.CONVERGING)
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
            def __init__(self, binding): self.binding = binding
            def stream(self):
                return iter((
                    {"method": "item/completed", "payload": {"turn_id": self.id, "item": {"type": "agentMessage", "phase": "final_answer", "text": json.dumps({"verdict": "pass", "findings": [], "binding": self.binding})}}},
                    {"method": "turn/completed", "payload": {"turn": {"id": self.id, "status": "completed"}}},
                ))
        class Thread:
            id = "session-native"
            def turn(self, prompt, **kwargs):
                events.append(kwargs); material = json.loads(prompt)["review_material"]
                return Handle({key: material[key] for key in ("input_digest", "candidate_sha", "within_round_attempt", "profile_identity")})
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

    def test_armed_capture_uses_one_plan_for_prepare_seal_and_readback(self):
        adapter = self.adapter(self.profiles[0], "one", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}))
        request = self.request(1, adapter)
        readiness = require_supervisor_capture_readiness(candidate_sha=self.context.candidate_sha, ready_at=101, case_id="case-44", observation_identity=request.input_digest, producer_identity=digest("native"), exporter_identity=digest("export"), comparator_identity=digest("compare"), recorder=RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"), store_identity=digest("store"))
        binding = SupervisorQualificationBinding("case-44", self.context.candidate_sha, self.context.base_sha, self.context.task_id, request.input_digest, adapter.profile_identity, adapter.runtime_fingerprint, self.context.review_epoch, self.context.review_round, self.context.review_mode.value, readiness.capture_plan_digest)
        class Recorder:
            def __init__(self): self.receipt = None; self.plans = []
            def prepare(inner, plan, *, store_identity):
                inner.plans.append(("prepare", readiness.capture_plan_digest, store_identity)); return SupervisorCapturePlanReceipt(readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, "case-44", self.context.candidate_sha, 101, digest("prepared"))
            def seal(inner, plan, document, *, store_identity):
                inner.plans.append(("seal", readiness.capture_plan_digest, store_identity)); inner.receipt = SupervisorRecorderReceipt(SUPERVISOR_FAILOVER_PROFILE, "case-44", self.context.candidate_sha, 101, readiness.capture_plan_digest, "sha256:" + hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(), digest("manifest"), digest("bundle"), digest(store_identity), digest("receipt")); return inner.receipt
            def verify(inner, plan, bundle_digest, *, store_identity):
                inner.plans.append(("verify", readiness.capture_plan_digest, store_identity)); return inner.receipt
        recorder = Recorder()
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_attempt(adapter, request, readiness, binding, recorder, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual(recorder.plans, [])

    def sequence_fixture(self, responses):
        adapters = tuple(self.adapter(profile, str(index), response) for index, (profile, response) in enumerate(zip(self.profiles, responses, strict=True), start=1))
        requests = tuple(self.request(index, adapter) for index, adapter in enumerate(adapters, start=1))
        readiness = require_supervisor_capture_readiness(candidate_sha=self.context.candidate_sha, ready_at=101, case_id="case-44-sequence", observation_identity=supervisor_sequence_observation_identity(requests), producer_identity=digest("native"), exporter_identity=digest("export"), comparator_identity=digest("compare"), recorder=RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"), store_identity=digest("sequence-store"))
        binding = SupervisorSequenceBinding("case-44-sequence", self.context.candidate_sha, self.context.base_sha, self.context.task_id, tuple(item.input_digest for item in requests), tuple(item.profile_identity for item in adapters), tuple(item.runtime_fingerprint for item in adapters), self.context.review_epoch, self.context.review_round, self.context.review_mode.value, readiness.capture_plan_digest)
        class Recorder:
            def __init__(inner): inner.receipt = None; inner.calls = []
            def prepare(inner, plan, *, store_identity):
                inner.calls.append("prepare"); return SupervisorCapturePlanReceipt(readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, "case-44-sequence", self.context.candidate_sha, 101, digest("sequence-prepared"))
            def seal(inner, plan, document, *, store_identity):
                inner.calls.append("seal"); evidence = "sha256:" + hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(); inner.receipt = SupervisorRecorderReceipt(SUPERVISOR_FAILOVER_PROFILE, "case-44-sequence", self.context.candidate_sha, 101, readiness.capture_plan_digest, evidence, digest("sequence-manifest"), digest("sequence-bundle"), digest(store_identity), digest("sequence-receipt")); return inner.receipt
            def verify(inner, plan, bundle_digest, *, store_identity):
                inner.calls.append("verify"); return inner.receipt
        configuration = self.configuration
        policy = ResolvedSupervisorSequencePolicy(configuration, configuration.runtime_binding())
        return adapters, requests, readiness, binding, policy, InMemorySupervisorLifecycle(digest("sequence-lifecycle-source")), Recorder()

    def test_sequence_advances_ambiguous_primary_to_valid_fallback(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.envelope.terminal, tuple(item.result_kind for item in result.envelope.attempts), result.envelope.accepted_ordinal, result.comparison.disposition, recorder.calls), (SupervisorSequenceTerminal.ACCEPTED, ("ambiguous", "accepted"), 2, "match", ["prepare", "seal", "verify"]))
        payload = result.envelope.payload()
        self.assertEqual((type(payload["attempts"]), type(payload["request_identities"]), type(payload["profile_identities"]), type(payload["runtime_fingerprints"])), (list, list, list, list))

    def test_sequence_advances_invalid_primary_to_valid_fallback(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX), NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "findings", "findings": ["missing-evidence"]}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((tuple(item.result_kind for item in result.envelope.attempts), result.envelope.accepted_verdict, recorder.calls), (("invalid", "accepted"), "findings", ["prepare", "seal", "verify"]))

    def test_sequence_exhaustion_is_typed_and_unsealed(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture(tuple(NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS) for _profile in self.profiles))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.failover.exhausted, result.envelope.terminal, result.envelope.blocker, result.receipt, recorder.calls), (True, SupervisorSequenceTerminal.EXHAUSTED, "attempt-budget-exhausted", None, ["prepare"]))

    def test_sequence_rejects_binding_order_and_profile_drift(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        drifted = SupervisorSequenceBinding(binding.case_id, binding.candidate_sha, binding.base_sha, binding.task_id, binding.request_identities, (binding.profile_identities[1], binding.profile_identities[0], binding.profile_identities[2]), binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest)
        with self.assertRaises(Exception):
            qualify_supervisor_sequence(adapters, requests, readiness, drifted, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual(recorder.calls, [])

    def test_sequence_candidate_movement_invalidates_armed_plan(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        with self.assertRaises(Exception):
            type(readiness)("c" * 40, readiness.ready_at, readiness.case_id, readiness.observation_identity, readiness.producer_identity, readiness.exporter_identity, readiness.comparator_identity, readiness.recorder_identity, readiness.store_identity, readiness.capture_plan_digest)
        self.assertEqual(binding.candidate_sha, self.context.candidate_sha)

    def test_sequence_fails_closed_when_durable_lifecycle_disagrees_with_provider_events(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        lifecycle.read = lambda *_args, **_kwargs: (_ for _ in ()).throw(SupervisorShadowError("durable drift"))
        with self.assertRaisesRegex(Exception, "read-back failed"):
            qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual(recorder.calls, ["prepare"])

    def test_sequence_rejects_complete_runtime_binding_drift_before_provider_dispatch(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        with self.assertRaisesRegex(Exception, "Resolved Supervisor sequence policy"):
            ResolvedSupervisorSequencePolicy(policy.configuration, replace(policy.runtime, supervisor_profile_identities=tuple(reversed(policy.runtime.supervisor_profile_identities))))
        self.assertEqual(recorder.calls, [])

    def test_sequence_rejects_expected_plan_observation_drift_before_provider_dispatch(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        original = lifecycle.read_plan
        lifecycle.read_plan = lambda *args, **kwargs: (replace(original(*args, **kwargs)[0], observation_identity=digest("wrong-observation")), original(*args, **kwargs)[1])
        with self.assertRaisesRegex(Exception, "pre-dispatch drifted"):
            qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((self.events, recorder.calls), ([], []))

    def test_sequence_lifecycle_failures_prevent_recorder_sealing(self):
        responses = (NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS))
        for seam in ("read_plan", "append", "finalize", "read"):
            with self.subTest(seam=seam):
                adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture(responses)
                setattr(lifecycle, seam, lambda *_args, **_kwargs: (_ for _ in ()).throw(SupervisorShadowError(f"{seam} drift")))
                with self.assertRaises(SupervisorShadowError):
                    qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertNotIn("seal", recorder.calls)
                if seam == "read_plan": self.assertEqual((self.events, recorder.calls), ([], []))

    def test_lifecycle_chain_values_are_immutable_and_reject_bad_order(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        expected = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        chain = SupervisorLifecycleChainBinding(digest("record"), digest("source"), readiness.observation_identity, binding.candidate_sha, expected.context_identity, expected.plan_identity, binding.capture_plan_digest, 10, 20)
        plan = LifecycleChainReceipt(chain, digest("plan-content"), digest("genesis"), 0)
        event = SupervisorAttemptEvent(chain.record_identity, chain.source_identity, chain.observation_identity, chain.candidate_sha, chain.context_identity, chain.plan_identity, chain.capture_plan_digest, 1, plan.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.AMBIGUOUS.value, digest("result"), None, None, 10, 20)
        event_receipt = LifecycleChainReceipt(chain, event.content_digest, event.prior_digest, 1)
        terminal = SupervisorTerminalRecord(chain.record_identity, chain.source_identity, chain.observation_identity, chain.candidate_sha, chain.context_identity, chain.plan_identity, chain.capture_plan_digest, event_receipt.receipt_digest, 1, "exhausted", None, "attempt-budget-exhausted", "retain-terminal-product-block", 10)
        receipt = LifecycleChainReceipt(chain, digest("terminal-content"), terminal.prior_digest, 2)
        self.assertEqual(CompleteSupervisorLifecycleRecord(expected, plan, (event,), terminal, receipt).events, (event,))
        with self.assertRaises(Exception): SupervisorAttemptEvent(chain.record_identity, chain.source_identity, chain.observation_identity, chain.candidate_sha, chain.context_identity, chain.plan_identity, chain.capture_plan_digest, 0, plan.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.AMBIGUOUS.value, digest("result"), None, None, 10, 20)

    def test_lifecycle_store_rejects_read_before_terminal(self):
        lifecycle = InMemorySupervisorLifecycle(digest("lifecycle-source"))
        adapters, requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        plan = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        receipt = lifecycle.prepare(plan, freshness_until=20)
        with self.assertRaises(Exception): lifecycle.read(receipt.record_identity, evidence_time=10)

    def test_lifecycle_store_valid_round_trip_returns_fresh_record(self):
        lifecycle = InMemorySupervisorLifecycle(digest("lifecycle-source")); adapters, requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        plan = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        prepared = lifecycle.prepare(plan, freshness_until=20)
        event = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, 1, prepared.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.ACCEPTED.value, digest("accepted"), digest("accepted"), "pass", 10, 20)
        event_receipt = lifecycle.append(prepared.record_identity, event, evidence_time=10)
        terminal = SupervisorTerminalRecord(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, event_receipt.receipt_digest, 1, "accepted", digest("accepted"), None, "apply-bound-review-result", 10)
        lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)
        value = lifecycle.read(prepared.record_identity, evidence_time=10)
        self.assertEqual((value.expected_plan, value.plan_receipt, value.events, value.terminal), (plan, prepared, (event,), terminal))
        self.assertIsNot(value.expected_plan, plan)
        self.assertIsNot(value.events[0], event)
        self.assertIsNot(value.terminal, terminal)

    def test_lifecycle_store_state_guards(self):
        lifecycle = InMemorySupervisorLifecycle(digest("lifecycle-source")); adapters, requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        plan = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        event = SupervisorAttemptEvent(digest("missing"), digest("source"), readiness.observation_identity, binding.candidate_sha, digest("context"), digest("plan"), binding.capture_plan_digest, 1, digest("prior"), binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.ACCEPTED.value, digest("accepted"), digest("accepted"), "pass", 10, 20)
        with self.assertRaises(Exception): lifecycle.append(event.record_identity, event, evidence_time=10)
        receipt = lifecycle.prepare(plan, freshness_until=20)
        event = SupervisorAttemptEvent(receipt.record_identity, receipt.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, 1, receipt.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.ACCEPTED.value, digest("accepted"), digest("accepted"), "pass", 10, 20)
        event_receipt = lifecycle.append(receipt.record_identity, event, evidence_time=10)
        terminal = SupervisorTerminalRecord(receipt.record_identity, receipt.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, event_receipt.receipt_digest, 1, "accepted", digest("accepted"), None, "apply-bound-review-result", 10)
        lifecycle.finalize(receipt.record_identity, terminal, evidence_time=10)
        with self.assertRaises(Exception): lifecycle.append(receipt.record_identity, event, evidence_time=10)
        with self.assertRaises(Exception): lifecycle.finalize(receipt.record_identity, terminal, evidence_time=10)

    def test_file_lifecycle_plan_persists_and_fails_closed(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        expected_type = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle
        plan = expected_type(binding, policy.policy_digest, policy.configuration_digest, digest("file-runtime"), 10, readiness.observation_identity)
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "durable"
            source = digest("file-lifecycle-source")
            lifecycle = FileSupervisorLifecycle(root, source)
            receipt = lifecycle.prepare(plan, freshness_until=20)
            returned_plan, returned_receipt = FileSupervisorLifecycle(root, source).read_plan(receipt.record_identity, evidence_time=10)
            self.assertEqual((returned_plan, returned_receipt), (plan, receipt))
            self.assertIsNot(returned_plan, plan)
            self.assertIsNot(returned_receipt, receipt)
            with self.assertRaises(SupervisorShadowError): lifecycle.prepare(plan, freshness_until=20)
            record = root / ("record-" + receipt.record_identity.removeprefix("sha256:"))
            for filename, replacement in (("plan.json", "{}"), ("plan-receipt.json", "{}")):
                original = (record / filename).read_text(encoding="utf-8")
                (record / filename).write_text(replacement, encoding="utf-8")
                with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).read_plan(receipt.record_identity, evidence_time=10)
                (record / filename).write_text(original, encoding="utf-8")
            (record / "unexpected").write_text("x", encoding="utf-8")
            with self.assertRaises(SupervisorShadowError): lifecycle.read_plan(receipt.record_identity, evidence_time=10)
            (record / "unexpected").unlink()
            (record / "plan.json.tmp").write_text("partial", encoding="utf-8")
            with self.assertRaises(SupervisorShadowError): lifecycle.read_plan(receipt.record_identity, evidence_time=10)
            (record / "plan.json.tmp").unlink()
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, digest("wrong-source")).read_plan(receipt.record_identity, evidence_time=10)
            with self.assertRaises(SupervisorShadowError): lifecycle.read_plan(receipt.record_identity, evidence_time=9)
            with self.assertRaises(SupervisorShadowError): lifecycle._record_dir("not-a-digest")

    def _fresh_lifecycle_chain(self):
        lifecycle = InMemorySupervisorLifecycle(digest("tamper-lifecycle-source"))
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        cls = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle
        plan = cls(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        prepared = lifecycle.prepare(plan, freshness_until=20)
        first = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, prepared.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, 1, prepared.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.AMBIGUOUS.value, digest("ambiguous"), None, None, 10, 20)
        first_receipt = lifecycle.append(prepared.record_identity, first, evidence_time=10)
        second = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, prepared.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, 2, first_receipt.receipt_digest, binding.request_identities[1], binding.profile_identities[1], binding.runtime_fingerprints[1], SupervisorResultKind.ACCEPTED.value, digest("accepted-two"), digest("accepted-two"), "pass", 10, 20)
        second_receipt = lifecycle.append(prepared.record_identity, second, evidence_time=10)
        terminal = SupervisorTerminalRecord(prepared.record_identity, prepared.source_identity, prepared.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, second_receipt.receipt_digest, 2, "accepted", digest("accepted-two"), None, "apply-bound-review-result", 10)
        lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)
        return lifecycle, prepared.record_identity

    def test_lifecycle_authenticated_read_rejects_canonical_tampering(self):
        def rewrite(material, mutate):
            value = json.loads(material); mutate(value)
            return json.dumps(value, sort_keys=True, separators=(",", ":"))
        def plan(path, value):
            return lambda record: record.__setitem__("plan", rewrite(record["plan"], lambda item: item.__setitem__(path, value)))
        def plan_binding(path, value):
            return lambda record: record.__setitem__("plan", rewrite(record["plan"], lambda item: item["binding"].__setitem__(path, value)))
        def plan_receipt(path, value):
            return lambda record: record.__setitem__("receipt", rewrite(record["receipt"], lambda item: item["binding"].__setitem__(path, value)))
        def event(path, value):
            return lambda record: record["events"].__setitem__(0, (rewrite(record["events"][0][0], lambda item: item.__setitem__(path, value)), record["events"][0][1]))
        def accepted_event(path, value):
            return lambda record: record["events"].__setitem__(1, (rewrite(record["events"][1][0], lambda item: item.__setitem__(path, value)), record["events"][1][1]))
        def event_receipt(path, value):
            return lambda record: record["events"].__setitem__(0, (record["events"][0][0], rewrite(record["events"][0][1], lambda item: item.__setitem__(path, value))))
        def terminal(path, value):
            return lambda record: record.__setitem__("terminal", (rewrite(record["terminal"][0], lambda item: item.__setitem__(path, value)), record["terminal"][1]))
        def terminal_receipt(path, value):
            return lambda record: record.__setitem__("terminal", (record["terminal"][0], rewrite(record["terminal"][1], lambda item: item.__setitem__(path, value))))
        changed = digest("changed")
        cases = [
            ("plan-candidate", plan_binding("candidate_sha", "d" * 40)), ("plan-request-order", plan_binding("request_identities", [changed] * 3)), ("plan-profile-order", plan_binding("profile_identities", [changed] * 3)), ("plan-runtime-order", plan_binding("runtime_fingerprints", [changed] * 3)),
            ("plan-policy", plan("policy_digest", changed)), ("plan-configuration", plan("configuration_digest", changed)), ("plan-runtime", plan("runtime_identity", changed)), ("plan-observation", plan("observation_identity", changed)), ("plan-ready", plan("ready_at", 11)),
            ("receipt-source", plan_receipt("source_identity", changed)), ("receipt-record", plan_receipt("record_identity", changed)), ("receipt-candidate", plan_receipt("candidate_sha", "d" * 40)), ("receipt-context", plan_receipt("context_identity", changed)), ("receipt-plan", plan_receipt("plan_identity", changed)), ("receipt-capture", plan_receipt("capture_plan_digest", changed)), ("receipt-observation", plan_receipt("observation_identity", changed)), ("receipt-ready", plan_receipt("ready_at", 11)), ("receipt-freshness", plan_receipt("freshness_until", 21)),
            ("missing-event", lambda record: record.__setitem__("events", [])), ("duplicate-event", lambda record: record["events"].append(record["events"][0])), ("reordered-events", lambda record: record["events"].reverse()),
            ("event-ordinal", event("ordinal", 3)), ("event-prior", event("prior_digest", changed)), ("event-request", event("request_identity", changed)), ("event-profile", event("profile_identity", changed)), ("event-runtime", event("runtime_fingerprint", changed)), ("event-result", event("result_identity", changed)), ("event-verdict", event("verdict", "findings")), ("event-accepted-presence", event("accepted_result_identity", changed)), ("event-accepted-absence", accepted_event("accepted_result_identity", None)), ("event-freshness", event("freshness_until", 19)),
            ("event-receipt-content", event_receipt("content_digest", changed)), ("event-receipt-prior", event_receipt("prior_digest", changed)), ("event-receipt-ordinal", event_receipt("ordinal", 3)),
            ("terminal-prior", terminal("prior_digest", changed)), ("terminal-count", terminal("attempt_count", 1)), ("terminal-accepted", terminal("accepted_result_identity", changed)), ("terminal-state", terminal("terminal", "exhausted")), ("terminal-blocker", terminal("blocker", "attempt-budget-exhausted")), ("terminal-action", terminal("next_action", "retain-terminal-product-block")), ("terminal-binding", terminal("plan_identity", changed)),
            ("terminal-receipt-content", terminal_receipt("content_digest", changed)), ("terminal-receipt-prior", terminal_receipt("prior_digest", changed)), ("terminal-receipt-ordinal", terminal_receipt("ordinal", 9)),
        ]
        binding_fields = ("record_identity", "source_identity", "observation_identity", "candidate_sha", "context_identity", "plan_identity", "capture_plan_digest", "ready_at", "freshness_until")
        for field in binding_fields:
            value = "d" * 40 if field == "candidate_sha" else (11 if field == "ready_at" else (21 if field == "freshness_until" else changed))
            def receipt_binding(field=field, value=value):
                return lambda record: record["events"].__setitem__(0, (record["events"][0][0], rewrite(record["events"][0][1], lambda item: item["binding"].__setitem__(field, value))))
            def final_binding(field=field, value=value):
                return lambda record: record.__setitem__("terminal", (record["terminal"][0], rewrite(record["terminal"][1], lambda item: item["binding"].__setitem__(field, value))))
            cases.extend(((f"event-receipt-binding-{field}", receipt_binding()), (f"terminal-receipt-binding-{field}", final_binding())))
        for field in ("record_identity", "source_identity", "observation_identity", "candidate_sha", "context_identity", "plan_identity", "capture_plan_digest"):
            value = "d" * 40 if field == "candidate_sha" else changed
            cases.append((f"terminal-binding-{field}", terminal(field, value)))
        for name, mutate in cases:
            with self.subTest(name=name):
                lifecycle, identity = self._fresh_lifecycle_chain(); mutate(lifecycle._records[identity])
                with self.assertRaises(SupervisorShadowError): lifecycle.read(identity, evidence_time=10)
                self.assertEqual(self.events, [])
        lifecycle, identity = self._fresh_lifecycle_chain()
        with self.assertRaises(SupervisorShadowError): lifecycle.read(identity, evidence_time=9)
        with self.assertRaises(SupervisorShadowError): lifecycle.read(identity, evidence_time=21)

    def test_expected_lifecycle_identities_are_stable_and_context_bound(self):
        adapters, requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        cls = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle
        one = cls(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        two = cls(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        self.assertEqual((one.context_identity, one.plan_identity), (two.context_identity, two.plan_identity))
        moved = replace(binding, candidate_sha="d" * 40)
        changed = cls(moved, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        self.assertNotEqual(one.context_identity, changed.context_identity)

    def test_lifecycle_chain_binding_is_canonical_and_fail_closed(self):
        values = [digest("record"), digest("source"), digest("observation"), "c" * 40, digest("context"), digest("plan"), digest("capture"), 10, 20]
        binding = SupervisorLifecycleChainBinding(*values)
        self.assertEqual((binding.payload(), binding.binding_digest), (SupervisorLifecycleChainBinding(*values).payload(), SupervisorLifecycleChainBinding(*values).binding_digest))
        for index, value in enumerate(values):
            changed = list(values); changed[index] = ("d" * 40 if index == 3 else (11 if index == 7 else (21 if index == 8 else digest(f"drift-{index}"))))
            self.assertNotEqual(binding.binding_digest, SupervisorLifecycleChainBinding(*changed).binding_digest)
        with self.assertRaises(Exception): SupervisorLifecycleChainBinding(*values[:7], 20, 10)
        with self.assertRaises(Exception): SupervisorLifecycleChainBinding("bad", *values[1:])
        with self.assertRaises(Exception): binding.record_identity = digest("replacement")

    def test_resolved_configuration_binding_authenticates_complete_policy_material(self):
        pinned = self.configuration
        material = json.loads(pinned.canonical_material)
        self.assertEqual((pinned.repository_root_identity, pinned.cache_directory_identity), (material["paths"]["repository_root"], material["paths"]["cache_directory"]))
        self.assertEqual(material["trusted_review_floor"], {"complete_rounds": pinned.trusted_review_floor.complete_rounds, "max_rounds": pinned.trusted_review_floor.max_rounds, "max_supervisor_attempts_per_round": pinned.trusted_review_floor.max_supervisor_attempts_per_round, "on_final_findings": pinned.trusted_review_floor.on_final_findings.value})
        for key in ("sources", "paths", "review", "trusted_review_floor"):
            altered = json.loads(pinned.canonical_material); altered.pop(key)
            with self.assertRaises(ConfigurationError): replace(pinned, canonical_material=json.dumps(altered, sort_keys=True, separators=(",", ":")))
        with self.assertRaises(ConfigurationError): replace(pinned, supervisor_profile_identities=tuple(reversed(pinned.supervisor_profile_identities)))
        with self.assertRaises(ConfigurationError): replace(pinned, review_policy=ReviewPolicy(0, pinned.review_policy.max_rounds, pinned.review_policy.max_supervisor_attempts_per_round, pinned.review_policy.on_final_findings))
        mutable = dict(pinned.sources); stable = pinned.sources
        mutable["review.max_rounds"] = mutable["roles.worker"]
        self.assertEqual(pinned.sources, stable)

    def test_resolved_configuration_binding_rejects_internally_digested_adversarial_material(self):
        pinned = self.configuration; baseline = json.loads(pinned.canonical_material)
        def canonical(material): return json.dumps(material, sort_keys=True, separators=(",", ":"))
        def construct(material, **typed):
            return ResolvedConfigurationBinding(
                typed.get("schema_version", pinned.schema_version), "sha256:" + hashlib.sha256(canonical(material).encode()).hexdigest(), typed.get("sources", dict(pinned.sources)), typed.get("worker_profile_identity", pinned.worker_profile_identity), typed.get("supervisor_profile_identities", pinned.supervisor_profile_identities), typed.get("review_policy", pinned.review_policy), typed.get("repository_root_identity", pinned.repository_root_identity), typed.get("cache_directory_identity", pinned.cache_directory_identity), typed.get("trusted_review_floor", pinned.trusted_review_floor), canonical(material),
            )
        changed = digest("crafted-drift")
        cases = []
        for key in tuple(baseline):
            cases.append((f"missing-{key}", lambda value, key=key: value.pop(key)))
        cases.append(("extra-top-level", lambda value: value.__setitem__("unexpected", changed)))
        for key in tuple(baseline["sources"]):
            cases.append((f"missing-source-{key}", lambda value, key=key: value["sources"].pop(key)))
        cases.extend((
            ("extra-source", lambda value: value["sources"].__setitem__("review.unknown", ConfigurationSource.DEFAULT.value)),
            ("wrong-source-key", lambda value: value["sources"].__setitem__("roles.unknown", value["sources"].pop("roles.worker"))),
            ("repository-path", lambda value: value["paths"].__setitem__("repository_root", changed)),
            ("cache-path", lambda value: value["paths"].__setitem__("cache_directory", changed)),
            ("worker", lambda value: value.__setitem__("worker", {"model": "changed", "reasoning_effort": "high", "name": "changed"})),
            ("profile-substitution", lambda value: value["supervisor_attempt_profiles"].__setitem__(0, {"model": "changed", "reasoning_effort": "high", "name": "changed"})),
            ("profile-order", lambda value: value.__setitem__("supervisor_attempt_profiles", list(reversed(value["supervisor_attempt_profiles"])))),
            ("profile-duplicate", lambda value: value["supervisor_attempt_profiles"].__setitem__(1, value["supervisor_attempt_profiles"][0])),
            ("complete-rounds", lambda value: value["review"].__setitem__("complete_rounds", value["review"]["complete_rounds"] + 1)),
            ("max-rounds", lambda value: value["review"].__setitem__("max_rounds", value["review"]["max_rounds"] + 1)),
            ("budget", lambda value: value["review"].__setitem__("max_supervisor_attempts_per_round", 1)),
            ("terminal", lambda value: value["review"].__setitem__("on_final_findings", "block")),
            ("floor-complete", lambda value: value["trusted_review_floor"].__setitem__("complete_rounds", value["trusted_review_floor"]["complete_rounds"] + 1)),
            ("floor-max", lambda value: value["trusted_review_floor"].__setitem__("max_rounds", value["trusted_review_floor"]["max_rounds"] + 1)),
            ("floor-budget", lambda value: value["trusted_review_floor"].__setitem__("max_supervisor_attempts_per_round", value["trusted_review_floor"]["max_supervisor_attempts_per_round"] + 1)),
            ("floor-terminal", lambda value: value["trusted_review_floor"].__setitem__("on_final_findings", "block")),
            ("schema", lambda value: value.__setitem__("schema_version", "roundwright-runtime/v0")),
        ))
        for source in ConfigurationSource:
            if source.value != baseline["sources"]["roles.worker"]:
                cases.append((f"source-{source.name}", lambda value, source=source: value["sources"].__setitem__("roles.worker", source.value)))
        for name, mutate in cases:
            with self.subTest(name=name):
                material = json.loads(pinned.canonical_material); mutate(material)
                with self.assertRaises(ConfigurationError): construct(material)
        duplicate = list(pinned.supervisor_profile_identities); duplicate[1] = duplicate[0]
        with self.assertRaises(ConfigurationError): construct(baseline, supervisor_profile_identities=tuple(duplicate))
        self.assertEqual(tuple(pinned.review_policy.mode_for_round(round_number) for round_number in (1, 2, 3, 4)), (ReviewMode.COMPLETE, ReviewMode.COMPLETE, ReviewMode.COMPLETE, ReviewMode.CONVERGING))

    def test_runtime_store_round_trip_and_tamper_fail_closed(self):
        def fresh():
            store = InMemorySupervisorRuntimeStore(digest("runtime-source")); runtime = self.configuration.runtime_binding()
            receipt = store.persist(runtime, candidate_sha=self.context.candidate_sha, context_identity=digest("runtime-context"), ready_at=10, freshness_until=20)
            return store, runtime, receipt
        store, runtime, receipt = fresh(); value = store.read(receipt, evidence_time=10)
        self.assertEqual(value, runtime); self.assertIsNot(value, runtime)
        for field, replacement in (("source_identity", digest("wrong-source")), ("record_identity", digest("wrong-record")), ("candidate_sha", "d" * 40), ("context_identity", digest("wrong-context")), ("resolved_configuration_digest", digest("wrong-configuration")), ("runtime_content_digest", digest("wrong-content")), ("ready_at", 11), ("freshness_until", 21)):
            with self.subTest(field=field):
                store, _runtime, receipt = fresh()
                with self.assertRaises(RuntimeBindingError): store.read(replace(receipt, **{field: replacement}), evidence_time=10)
        store, _runtime, receipt = fresh(); store._records[receipt.record_identity] = "{}"
        with self.assertRaises(RuntimeBindingError): store.read(receipt, evidence_time=10)
        store, _runtime, receipt = fresh()
        with self.assertRaises(RuntimeBindingError): store.read(receipt, evidence_time=9)
        with self.assertRaises(RuntimeBindingError): store.read(receipt, evidence_time=21)

    def test_sequence_runtime_preflight_failures_make_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        counts = {name: 0 for name in ("prepare", "read_plan", "append", "finalize", "read", "recorder_prepare", "seal", "verify")}
        for name in ("prepare", "read_plan", "append", "finalize", "read"):
            original = getattr(lifecycle, name)
            setattr(lifecycle, name, lambda *args, _name=name, _original=original, **kwargs: (counts.__setitem__(_name, counts[_name] + 1), _original(*args, **kwargs))[1])
        for name, key in (("prepare", "recorder_prepare"), ("seal", "seal"), ("verify", "verify")):
            original = getattr(recorder, name)
            setattr(recorder, name, lambda *args, _key=key, _original=original, **kwargs: (counts.__setitem__(_key, counts[_key] + 1), _original(*args, **kwargs))[1])
        class FailingStore:
            def persist(self, *_args, **_kwargs): raise RuntimeBindingError("runtime preflight failure")
            def read(self, *_args, **_kwargs): raise RuntimeBindingError("runtime preflight failure")
        for store in (None, object(), FailingStore()):
            with self.subTest(store=type(store).__name__):
                with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=store, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual(tuple(counts.values()), (0,) * len(counts))

    def test_sequence_runtime_read_preflight_failure_has_zero_adapter_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class ReadFailingStore:
            def persist(self, runtime, **kwargs): return InMemorySupervisorRuntimeStore(digest("unused")).persist(runtime, **kwargs)
            def read(self, *_args, **_kwargs): raise RuntimeBindingError("read failure")
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=ReadFailingStore(), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_sequence_runtime_read_wrong_type_has_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class WrongTypeStore:
            def persist(self, runtime, **kwargs): return InMemorySupervisorRuntimeStore(digest("wrong-type")).persist(runtime, **kwargs)
            def read(self, *_args, **_kwargs): return object()
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=WrongTypeStore(), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_sequence_runtime_candidate_receipt_drift_has_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class CandidateDriftStore:
            def __init__(self): self.store = InMemorySupervisorRuntimeStore(digest("candidate-drift"))
            def persist(self, runtime, **kwargs): return replace(self.store.persist(runtime, **kwargs), candidate_sha="d" * 40)
            def read(self, receipt, **kwargs): return self.store.read(receipt, **kwargs)
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=CandidateDriftStore(), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_runtime_binding_canonical_parser_rejects_adversarial_material(self):
        runtime = self.configuration.runtime_binding(); material = json.loads(runtime.canonical_material())
        def encode(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        cases = [("missing", lambda value: value.pop("resolved_digest")), ("extra", lambda value: value.__setitem__("unknown", "x")), ("duplicate", lambda value: value["supervisor_profile_identities"].__setitem__(1, value["supervisor_profile_identities"][0])), ("budget", lambda value: value.__setitem__("review_max_supervisor_attempts_per_round", 1)), ("complete", lambda value: value.__setitem__("review_complete_rounds", value["review_complete_rounds"] + 1)), ("max", lambda value: value.__setitem__("review_max_rounds", value["review_max_rounds"] + 1)), ("terminal", lambda value: value.__setitem__("review_on_final_findings", "block")), ("policy", lambda value: value.__setitem__("review_policy_digest", "0" * 64))]
        for name, mutate in cases:
            with self.subTest(name=name):
                value = json.loads(runtime.canonical_material()); mutate(value)
                with self.assertRaises(RuntimeBindingError): type(runtime).from_canonical(encode(value))
        with self.assertRaises(RuntimeBindingError): type(runtime).from_canonical(json.dumps(material, sort_keys=True))

if __name__ == "__main__":
    unittest.main()
