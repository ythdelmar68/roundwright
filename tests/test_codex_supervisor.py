"""Hermetic contracts for fresh Codex Supervisor review failover."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_supervisor import (
    CodexSupervisorAdapter, CodexSupervisorContext, CodexSupervisorError, CodexSupervisorRequest,
    NativeSupervisorResponse, SupervisorDiagnostic, SupervisorOutcomeSource,
    ACCOUNTING_TRANSITION_CRITERIA, ACCOUNTING_TRANSITION_OBJECTIVE, SupervisorAccountingDecisionSemantic,
    SupervisorResponseContract, SupervisorResultKind, SupervisorSdkTurnErrorCategory,
    dispatch_ordered_supervisor_attempts, supervisor_request_digest,
)
from roundwright.provider_recovery import AttemptState, SupervisorAccountingAttemptSnapshot, SupervisorAccountingSnapshot, SupervisorDispatchClaimState
from roundwright.configuration import ConfigurationError, ConfigurationSource, FileReviewAuthorityStore, FinalFindingsPolicy, ProviderProfile, ReasoningEffort, ResolvedConfigurationBinding, ReviewAuthorityExpectation, ReviewMode, ReviewPolicy, TrustedReviewAuthorityReceipt, load_configuration, resolve_dispatch_configuration
from roundwright.policy import PolicyDocument, TrustedControlSource, TrustedPolicySnapshot
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.runtime_binding import FileSupervisorRuntimeStore, InMemorySupervisorRuntimeStore, RuntimeBindingError, SupervisorRuntimeBindingReceipt
from roundwright.supervisor_toolbox import HarnessNativeCodexSupervisorBackend, _consume
from roundwright.worker_toolbox import CompletionDeadline
from roundwright.shadow import RecorderBinding
from roundwright.supervisor_shadow import (
    SUPERVISOR_FAILOVER_PROFILE, SupervisorCapturePlanReceipt,
    SupervisorQualificationBinding, SupervisorRecorderReceipt,
    ResolvedSupervisorSequencePolicy, SupervisorExpectedLifecycle, SupervisorExpectedLifecycleReceipt, SupervisorSequenceBinding, SupervisorSequenceTerminal,
    SupervisorAttemptEvent, SupervisorTerminalRecord, LifecycleChainReceipt, CompleteSupervisorLifecycleRecord,
    FileSupervisorLifecycle, InMemorySupervisorLifecycle,
    SupervisorLifecycleChainBinding,
    SupervisorShadowError, TrustedReviewPolicyReceipt,
    qualify_supervisor_attempt, qualify_supervisor_sequence,
    require_supervisor_capture_readiness, supervisor_sequence_lifecycle_identity, supervisor_sequence_observation_identity,
    _sequence_attempt,
)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class Turn:
    def __init__(self, identity, response, events): self._identity, self._response, self._events = identity, response, events
    def identity(self): return self._identity
    def abort(self): self._events.append(("abort", self._identity))
    def read_response(self):
        self._events.append(("read", self._identity))
        if self._request.response_contract is SupervisorResponseContract.PROVIDER_ATTEMPT_ACCOUNTING and self._response.kind is SupervisorResultKind.ACCEPTED:
            # Runtime tests inject only the native backend seam.  Mirror the
            # selected product schema rather than caller-prescribing a result.
            return NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"status": "complete", "action": "accept-formal-review", "blocker": None})
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
        self.authority_temporary = TemporaryDirectory()
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        anchor = load_configuration(cwd=ROOT, environment={}, home=ROOT, trusted_review_floor=floor).resolved_digest
        authority_root = Path(self.authority_temporary.name)
        self.authority_expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, FileReviewAuthorityStore.identity_for_root(authority_root), authority.receipt_digest, authority.policy_snapshot_digest, floor, "b" * 40, anchor, 101, 120)
        self.authority_store = FileReviewAuthorityStore(authority_root, expectation=self.authority_expectation)
        self.authority_evidence = self.authority_store.persist(authority, candidate_sha="b" * 40, configuration_anchor_digest=anchor, ready_at=101, freshness_until=120)
        self.configuration = resolve_dispatch_configuration(cwd=ROOT, environment={}, home=ROOT, trusted_policy_snapshot=snapshot, trusted_review_floor=floor, trusted_review_authority_receipt=authority, review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, candidate_sha="b" * 40, evidence_time=101).pin()
        self.context = CodexSupervisorContext("task-44", *(digest(item) for item in ("source", "repo", "worktree", "branch")), "a" * 40, "b" * 40, "sha256:" + self.configuration.runtime_binding().review_policy_digest, self.configuration.digest, 2, 4, ReviewMode.CONVERGING)
        self.profiles = (
            ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH, "primary"),
            ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback"),
            ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback-retry"),
        )

    def tearDown(self):
        self.authority_temporary.cleanup()

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

    def test_exact_terminal_failure_advances_to_the_next_prebound_profile(self):
        primary = self.adapter(self.profiles[0], "failed-primary", NativeSupervisorResponse(
            SupervisorResultKind.BLOCKED, failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
            outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
            sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD,
        ))
        fallback = self.adapter(self.profiles[1], "failed-fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}))
        result = dispatch_ordered_supervisor_attempts((self.request(1, primary), self.request(2, fallback)), (primary, fallback), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.result.kind, result.attempted_profile_identities, primary._backend.calls, fallback._backend.calls), (SupervisorResultKind.ACCEPTED, (primary.profile_identity, fallback.profile_identity), 1, 1))

    def test_exhaustion_is_only_for_all_retryable_results_and_never_fabricates_a_verdict(self):
        adapters = tuple(self.adapter(profile, str(index), NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX)) for index, profile in enumerate(self.profiles, start=1))
        result = dispatch_ordered_supervisor_attempts(tuple(self.request(index, adapter) for index, adapter in enumerate(adapters, start=1)), adapters, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.result, result.exhausted, len(result.attempted_profile_identities)), (None, True, 3))

    def test_ambiguous_and_incomplete_results_stop_before_fallback(self):
        for kind in (SupervisorResultKind.AMBIGUOUS, SupervisorResultKind.INCOMPLETE):
            with self.subTest(kind=kind.value):
                primary = self.adapter(self.profiles[0], f"{kind.value}-primary", NativeSupervisorResponse(kind))
                fallback = self.adapter(self.profiles[1], f"{kind.value}-fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}))
                result = dispatch_ordered_supervisor_attempts((self.request(1, primary), self.request(2, fallback)), (primary, fallback), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual((result.result.kind, result.exhausted, result.attempted_profile_identities, fallback._backend.calls), (kind, False, (primary.profile_identity,), 0))

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

    def test_concrete_native_accounting_prompt_is_prospective_and_bound(self):
        captured = []
        profile = self.profiles[0]
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        snapshot = SupervisorAccountingSnapshot(
            "repo-44", "task-44", digest("source"), "a" * 40, "b" * 40, "case-44", 101,
            "state-44", ("a" * 64,), (("test", "pass"),), digest("configuration"), "b" * 64,
            1, 4, 2, 2, 4, "CONVERGING", 0, 0, SupervisorDispatchClaimState.CLAIMED,
            SupervisorAccountingAttemptSnapshot("provider-accounting", 1, audit.profile_identity, AttemptState.PREPARED, False, False, False, False, None, None, False), (),
        )
        values = dict(review_attempt_id="review-accounting", provider_attempt_id="provider-accounting", selected_profile_identity=audit.profile_identity, within_round_attempt=1, context=self.context, objective=ACCOUNTING_TRANSITION_OBJECTIVE, acceptance_criteria=ACCOUNTING_TRANSITION_CRITERIA, response_contract=SupervisorResponseContract.PROVIDER_ATTEMPT_ACCOUNTING, decision_material=snapshot, decision_semantic=SupervisorAccountingDecisionSemantic.PRE_DISPATCH_ELIGIBILITY_V2)
        request = CodexSupervisorRequest(input_digest=supervisor_request_digest(**values), **values)
        class Handle:
            id = "turn-accounting"
            def stream(self): return iter(({"method": "item/completed", "payload": {"turn_id": self.id, "item": {"type": "agentMessage", "phase": "final_answer", "text": json.dumps({"status": "complete", "action": "accept-formal-review", "blocker": None})}}}, {"method": "turn/completed", "payload": {"turn": {"id": self.id, "status": "completed"}}}))
        class Thread:
            id = "session-accounting"
            def turn(self, prompt, **_kwargs): captured.append(json.loads(prompt)); return Handle()
        class Codex:
            def __enter__(self): return self
            def __exit__(self, *_args): return None
            def thread_start(self): return Thread()
        adapter = CodexSupervisorAdapter(HarnessNativeCodexSupervisorBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value), profile, audit)
        self.assertEqual(adapter.dispatch(request, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None).kind, SupervisorResultKind.ACCEPTED)
        prompt = captured[0]
        self.assertIn("prospective pre-dispatch", prompt["instruction"])
        self.assertIn("not that either already exists", prompt["instruction"])
        self.assertEqual(prompt["review_material"]["decision_semantic"], "pre-dispatch-transition-eligibility/v2")
        self.assertNotIn("PASS", json.dumps(prompt, sort_keys=True))
        self.assertNotIn("FINDINGS", json.dumps(prompt, sort_keys=True))
        unclaimed = replace(snapshot, dispatch_claim=SupervisorDispatchClaimState.UNCLAIMED)
        values["decision_material"] = unclaimed
        with self.assertRaises(CodexSupervisorError):
            CodexSupervisorRequest(input_digest=supervisor_request_digest(**values), **values)

    def test_native_factory_failure_is_classified_before_any_session_identity(self):
        profile = self.profiles[0]
        backend = HarnessNativeCodexSupervisorBackend(
            cwd=ROOT, completion=CompletionDeadline(100, 600),
            codex_factory=lambda: (_ for _ in ()).throw(RuntimeError("private factory detail")),
            approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value,
        )
        with self.assertRaises(CodexAdapterError) as raised:
            backend.open_fresh_session(profile)
        self.assertIs(raised.exception.failure, CodexFailure.UNKNOWN)
        self.assertNotIn("private", str(raised.exception))

    def test_exact_failed_turn_projects_only_safe_terminal_failure_metadata(self):
        class Handle:
            id = "turn-terminal-failure"
            def stream(self):
                return iter(({
                    "method": "turn/completed",
                    "payload": {"turn": {
                        "id": self.id, "status": "failed",
                        "error": {"codexErrorInfo": "serverOverloaded", "message": "private failure"},
                    }},
                },))
        response = _consume(Handle(), CompletionDeadline(100, 600), __import__("time").monotonic, lambda: None)
        self.assertEqual(
            (response.kind, response.failure, response.outcome_source, response.sdk_error_category),
            (SupervisorResultKind.BLOCKED, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
             SupervisorOutcomeSource.SDK_TURN_FAILED, SupervisorSdkTurnErrorCategory.OVERLOAD),
        )

    def test_failed_turn_category_projection_matches_the_closed_worker_categories(self):
        cases = (
            ("badRequest", CodexFailure.UNKNOWN, SupervisorSdkTurnErrorCategory.BAD_REQUEST),
            ("unauthorized", CodexFailure.UNKNOWN, SupervisorSdkTurnErrorCategory.UNAUTHORIZED),
            ("sandboxError", CodexFailure.SANDBOX_OR_APPROVAL_DENIED, SupervisorSdkTurnErrorCategory.SANDBOX),
            ("serverOverloaded", CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorSdkTurnErrorCategory.OVERLOAD),
            ({"httpConnectionFailed": {}}, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorSdkTurnErrorCategory.HTTP),
            ({"responseStreamConnectionFailed": {}}, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorSdkTurnErrorCategory.CONNECTION),
            ({"responseStreamDisconnected": {}}, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorSdkTurnErrorCategory.STREAM),
            ({}, CodexFailure.UNKNOWN, SupervisorSdkTurnErrorCategory.MISSING_OR_UNKNOWN),
        )
        for detail, failure, category in cases:
            with self.subTest(category=category.value):
                class Handle:
                    id = "turn-safe-category"
                    def stream(self):
                        return iter(({"method": "turn/completed", "payload": {"turn": {"id": self.id, "status": "failed", "error": {"codexErrorInfo": detail, "message": "C:/private/provider-detail"}}}},))
                response = _consume(Handle(), CompletionDeadline(100, 600), __import__("time").monotonic, lambda: None)
                self.assertEqual((response.kind, response.failure, response.outcome_source, response.sdk_error_category), (SupervisorResultKind.BLOCKED, failure, SupervisorOutcomeSource.SDK_TURN_FAILED, category))
                self.assertNotIn("private", repr(response))

    def test_terminal_failure_category_is_bound_into_the_public_result_identity(self):
        identities = []
        for category in (SupervisorSdkTurnErrorCategory.OVERLOAD, SupervisorSdkTurnErrorCategory.CONNECTION):
            adapter = self.adapter(self.profiles[0], category.value, NativeSupervisorResponse(
                SupervisorResultKind.BLOCKED, failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED, sdk_error_category=category,
            ))
            request = self.request(1, adapter)
            result = adapter.dispatch(request, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
            identities.append(_sequence_attempt(1, request, result).result_identity)
        self.assertNotEqual(*identities)

    def test_eof_timeout_and_stream_failures_stop_before_fallback(self):
        class EofHandle:
            id = "turn-eof"
            def stream(self): return iter(())
        class TimeoutHandle:
            id = "turn-timeout"
            def stream(self): raise TimeoutError("C:/private/timeout")
        class StreamHandle:
            id = "turn-stream"
            def stream(self):
                def broken():
                    raise RuntimeError("C:/private/stream")
                    yield None
                return broken()
        for handle in (EofHandle(), TimeoutHandle(), StreamHandle()):
            with self.subTest(handle=type(handle).__name__):
                native = _consume(handle, CompletionDeadline(100, 600), __import__("time").monotonic, lambda: None)
                self.assertIs(native.kind, SupervisorResultKind.AMBIGUOUS)
                primary = self.adapter(self.profiles[0], type(handle).__name__, native)
                fallback = self.adapter(self.profiles[1], f"{type(handle).__name__}-fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}))
                result = dispatch_ordered_supervisor_attempts((self.request(1, primary), self.request(2, fallback)), (primary, fallback), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual((result.result.kind, result.attempted_profile_identities, fallback._backend.calls), (SupervisorResultKind.AMBIGUOUS, (primary.profile_identity,), 0))

    def test_native_stream_rejections_only_advance_typed_invalid_output(self):
        """Native stream/parser failures are typed, bounded, and never sealed."""
        def native_adapter(events, *, completed="completed", binding=None, text=None):
            class Handle:
                id = "turn-native-rejected"
                def stream(self):
                    stream = []
                    response_text = getattr(self, "stream_text", text)
                    if response_text is not None:
                        stream.append({"method": "item/completed", "payload": {"turn_id": self.id, "item": {"type": "agentMessage", "phase": "final_answer", "text": response_text}}})
                    stream.append({"method": "turn/completed", "payload": {"turn": {"id": binding if binding is not None else self.id, "status": completed}}})
                    return iter(stream)
            class Thread:
                id = "session-native-rejected"
                def turn(self, prompt, **kwargs):
                    events.append(kwargs)
                    if text == "__stale_candidate__":
                        material = json.loads(prompt)["review_material"]
                        Handle.stream_text = json.dumps({"verdict": "pass", "findings": [], "binding": {key: material[key] for key in ("input_digest", "within_round_attempt", "profile_identity")} | {"candidate_sha": "f" * 40}})
                    return Handle()
            class Codex:
                def __enter__(self): return self
                def __exit__(self, *_args): return None
                def thread_start(self): return Thread()
            profile = self.profiles[0]
            audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
            return CodexSupervisorAdapter(HarnessNativeCodexSupervisorBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value), profile, audit)

        cases = (
            ("cancelled", {"completed": "cancelled"}, SupervisorResultKind.AMBIGUOUS, None, 0),
            ("interrupted", {"completed": "interrupted"}, SupervisorResultKind.AMBIGUOUS, None, 0),
            ("unknown", {"completed": "unknown"}, SupervisorResultKind.AMBIGUOUS, None, 0),
            ("invalid-context", {"binding": "wrong-turn"}, SupervisorResultKind.INVALID, SupervisorDiagnostic.CONTEXT),
            ("stale-candidate", {"text": "__stale_candidate__"}, SupervisorResultKind.INVALID, SupervisorDiagnostic.CANDIDATE),
            ("malformed-output", {"text": "not-json"}, SupervisorResultKind.INVALID, SupervisorDiagnostic.SYNTAX),
            ("missing-result", {}, SupervisorResultKind.INVALID, SupervisorDiagnostic.SHAPE),
        )
        cases = tuple(item if len(item) == 5 else (*item, 1) for item in cases)
        for name, values, kind, diagnostic, fallback_calls in cases:
            with self.subTest(name=name):
                events = []
                primary = native_adapter(events, **values)
                first = self.request(1, primary)
                rejected = primary.dispatch(first, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual((rejected.kind, rejected.diagnostic), (kind, diagnostic))
                fallback = self.adapter(self.profiles[1], "native-fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}))
                ordered = dispatch_ordered_supervisor_attempts((first, self.request(2, fallback)), (primary, fallback), checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                expected_profiles = (primary.profile_identity, fallback.profile_identity) if fallback_calls else (primary.profile_identity,)
                expected_kind = SupervisorResultKind.ACCEPTED if fallback_calls else SupervisorResultKind.AMBIGUOUS
                self.assertEqual((ordered.attempted_profile_identities, ordered.result.kind, fallback._backend.calls, first.context.review_epoch, first.context.review_round, first.context.review_mode), (expected_profiles, expected_kind, fallback_calls, self.context.review_epoch, self.context.review_round, ReviewMode.CONVERGING))

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
        configuration = self.configuration
        readiness = require_supervisor_capture_readiness(candidate_sha=self.context.candidate_sha, ready_at=101, case_id="case-44-sequence", observation_identity=supervisor_sequence_observation_identity(requests), producer_identity=configuration.trusted_floor_source_identity, exporter_identity=configuration.trusted_floor_authority_identity, comparator_identity=configuration.runtime_store_authority_identity, recorder=RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"), store_identity=digest("sequence-store"))
        binding = SupervisorSequenceBinding("case-44-sequence", self.context.candidate_sha, self.context.base_sha, self.context.task_id, tuple(item.input_digest for item in requests), tuple(item.profile_identity for item in adapters), tuple(item.runtime_fingerprint for item in adapters), self.context.review_epoch, self.context.review_round, self.context.review_mode.value, readiness.capture_plan_digest)
        class Recorder:
            def __init__(inner): inner.receipt = None; inner.calls = []
            def prepare(inner, plan, *, store_identity):
                inner.calls.append("prepare"); return SupervisorCapturePlanReceipt(readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, "case-44-sequence", self.context.candidate_sha, 101, digest("sequence-prepared"))
            def seal(inner, plan, document, *, store_identity):
                inner.calls.append("seal"); evidence = "sha256:" + hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest(); inner.receipt = SupervisorRecorderReceipt(SUPERVISOR_FAILOVER_PROFILE, "case-44-sequence", self.context.candidate_sha, 101, readiness.capture_plan_digest, evidence, digest("sequence-manifest"), digest("sequence-bundle"), digest(store_identity), digest("sequence-receipt")); return inner.receipt
            def verify(inner, plan, bundle_digest, *, store_identity):
                inner.calls.append("verify"); return inner.receipt
        policy = ResolvedSupervisorSequencePolicy(configuration, configuration.runtime_binding())
        return adapters, requests, readiness, binding, policy, InMemorySupervisorLifecycle(digest("sequence-lifecycle-source")), Recorder()

    def trusted_receipt(self, binding, policy, readiness, *, ready_at=101, freshness_until=120):
        value = policy.policy
        return TrustedReviewPolicyReceipt(readiness.producer_identity, readiness.exporter_identity, binding.candidate_sha, policy.configuration_digest, policy.policy_digest, policy.profile_identities, value.complete_rounds, value.max_rounds, value.max_supervisor_attempts_per_round, value.on_final_findings.value, ready_at, freshness_until, policy.configuration.trusted_floor_authority_receipt_digest)

    def runtime_store(self):
        return InMemorySupervisorRuntimeStore(self.configuration.runtime_store_authority_identity)

    def test_sequence_ambiguous_primary_is_terminal_and_unsealed(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.envelope.terminal, tuple(item.result_kind for item in result.envelope.attempts), result.envelope.accepted_ordinal, result.envelope.blocker, result.comparison.disposition, recorder.calls, adapters[1]._backend.calls), (SupervisorSequenceTerminal.AMBIGUOUS, ("ambiguous",), None, "provider-outcome-ambiguous", "match", ["prepare"], 0))
        payload = result.envelope.payload()
        self.assertEqual((type(payload["attempts"]), type(payload["request_identities"]), type(payload["profile_identities"]), type(payload["runtime_fingerprints"])), (list, list, list, list))

    def test_sequence_terminal_outcome_on_final_configured_profile_round_trips_unsealed(self):
        for kind in (SupervisorResultKind.AMBIGUOUS, SupervisorResultKind.INCOMPLETE):
            with self.subTest(kind=kind.value):
                responses = (
                    NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX),
                    NativeSupervisorResponse(SupervisorResultKind.BLOCKED, failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED, sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD),
                    NativeSupervisorResponse(kind),
                )
                adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture(responses)
                result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                durable = lifecycle.read(next(iter(lifecycle._records)), evidence_time=101)
                self.assertEqual((result.envelope.terminal, len(result.envelope.attempts), result.envelope.blocker, result.receipt, recorder.calls, durable.terminal.terminal, durable.terminal.blocker), (SupervisorSequenceTerminal(kind.value), 3, f"provider-outcome-{kind.value}", None, ["prepare"], kind.value, f"provider-outcome-{kind.value}"))

    def test_sequence_advances_invalid_primary_to_valid_fallback(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX), NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "findings", "findings": ["missing-evidence"]}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((tuple(item.result_kind for item in result.envelope.attempts), result.envelope.accepted_verdict, recorder.calls), (("invalid", "accepted"), "findings", ["prepare", "seal", "verify"]))

    def test_sequence_exhaustion_is_typed_and_unsealed(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture(tuple(NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX) for _profile in self.profiles))
        result = qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((result.failover.exhausted, result.envelope.terminal, result.envelope.blocker, result.receipt, recorder.calls), (True, SupervisorSequenceTerminal.EXHAUSTED, "attempt-budget-exhausted", None, ["prepare"]))

    def test_sequence_rejects_binding_order_and_profile_drift(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        drifted = SupervisorSequenceBinding(binding.case_id, binding.candidate_sha, binding.base_sha, binding.task_id, binding.request_identities, (binding.profile_identities[1], binding.profile_identities[0], binding.profile_identities[2]), binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest)
        with self.assertRaises(Exception):
            qualify_supervisor_sequence(adapters, requests, readiness, drifted, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(drifted, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
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
            qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
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
            qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((self.events, recorder.calls), ([], []))

    def test_sequence_lifecycle_failures_prevent_recorder_sealing(self):
        responses = (NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS))
        for seam in ("read_plan", "append", "finalize", "read"):
            with self.subTest(seam=seam):
                adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture(responses)
                setattr(lifecycle, seam, lambda *_args, **_kwargs: (_ for _ in ()).throw(SupervisorShadowError(f"{seam} drift")))
                with self.assertRaises(SupervisorShadowError):
                    qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=InMemorySupervisorRuntimeStore(digest("sequence-runtime")), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertNotIn("seal", recorder.calls)
                if seam == "read_plan": self.assertEqual((self.events, recorder.calls), ([], []))

    def test_sequence_rejects_self_minted_readiness_pins_before_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),) + (NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 2)
        minted = require_supervisor_capture_readiness(candidate_sha=readiness.candidate_sha, ready_at=readiness.ready_at, case_id=readiness.case_id, observation_identity=readiness.observation_identity, producer_identity=digest("self-minted-source"), exporter_identity=digest("self-minted-authority"), comparator_identity=digest("self-minted-runtime"), recorder=RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"), store_identity=readiness.store_identity)
        minted_binding = SupervisorSequenceBinding(binding.case_id, binding.candidate_sha, binding.base_sha, binding.task_id, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, minted.capture_plan_digest)
        with self.assertRaises(SupervisorShadowError):
            qualify_supervisor_sequence(adapters, requests, minted, minted_binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(minted_binding, policy, minted), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((self.events, recorder.calls), ([], []))

    def test_file_store_reparse_test_double_fails_closed_before_material_publication(self):
        _adapters, _requests, readiness, binding, policy, _lifecycle, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        expected = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        with TemporaryDirectory() as directory:
            with patch("roundwright.supervisor_shadow._reparse", side_effect=lambda path: path.name.startswith("record-")):
                with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(Path(directory) / "lifecycle", digest("source")).prepare(expected, freshness_until=20)
            with patch("roundwright.runtime_binding._reparse", side_effect=lambda path: path.name.startswith("record-")):
                with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(Path(directory) / "runtime", digest("source")).persist(policy.runtime, candidate_sha=binding.candidate_sha, context_identity=expected.context_identity, ready_at=10, freshness_until=20)

    def test_file_store_reparse_boundaries_and_downstream_calls_fail_closed(self):
        adapters, requests, readiness, binding, policy, _lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),) + (NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 2)
        expected = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        with TemporaryDirectory() as directory:
            root = Path(directory) / "lifecycle"; source = digest("reparse-source")
            lifecycle = FileSupervisorLifecycle(root, source); prepared = lifecycle.prepare(expected, freshness_until=20)
            event = SupervisorAttemptEvent(prepared.record_identity, source, readiness.observation_identity, binding.candidate_sha, expected.context_identity, expected.plan_identity, binding.capture_plan_digest, 1, prepared.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.AMBIGUOUS.value, digest("reparse-event"), None, None, 10, 20)
            for operation in (
                lambda: lifecycle.read_plan(prepared.record_identity, evidence_time=10),
                lambda: lifecycle.append(prepared.record_identity, event, evidence_time=10),
                lambda: lifecycle.finalize(prepared.record_identity, SupervisorTerminalRecord(prepared.record_identity, source, readiness.observation_identity, binding.candidate_sha, expected.context_identity, expected.plan_identity, binding.capture_plan_digest, prepared.receipt_digest, 1, "exhausted", None, "attempt-budget-exhausted", "retain-terminal-product-block", 10), evidence_time=10),
                lambda: lifecycle.read(prepared.record_identity, evidence_time=10),
            ):
                with patch("roundwright.supervisor_shadow._reparse", side_effect=lambda path: path.name.startswith("record-")):
                    with self.assertRaises(SupervisorShadowError): operation()
            with patch("roundwright.supervisor_shadow._reparse", side_effect=lambda path: path.name.startswith("record-")):
                with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, FileSupervisorLifecycle(Path(directory) / "qualifier", source), recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
            self.assertEqual((self.events, recorder.calls), ([], []))

    @unittest.skipUnless(
        os.name == "nt" and hasattr(Path(), "is_junction") and shutil.which("cmd.exe"),
        "Windows cmd.exe junction creation is unavailable",
    )
    def test_file_lifecycle_rejects_a_real_junction_record_leaf_when_supported(self):
        _adapters, _requests, readiness, binding, policy, _lifecycle, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        plan = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("runtime"), 10, readiness.observation_identity)
        with TemporaryDirectory() as directory:
            root = Path(directory) / "lifecycle"; source = digest("junction-source")
            receipt = FileSupervisorLifecycle(root, source).prepare(plan, freshness_until=20)
            record = root / ("record-" + receipt.record_identity.removeprefix("sha256:")); target = Path(directory) / "junction-target"
            shutil.rmtree(record); target.mkdir()
            result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(record), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode != 0:
                self.skipTest("host cannot create a Windows junction")
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).read_plan(receipt.record_identity, evidence_time=10)

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

    def test_legacy_v1_accepted_and_exhausted_records_retain_original_identities(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        for terminal_kind in ("accepted", "exhausted"):
            with self.subTest(terminal=terminal_kind):
                lifecycle = InMemorySupervisorLifecycle(digest("legacy-" + terminal_kind))
                plan = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("legacy-runtime-" + terminal_kind), 10, readiness.observation_identity, "roundwright-supervisor-expected-lifecycle/v1")
                self.assertEqual(plan.payload()["schema"], "roundwright-supervisor-expected-lifecycle/v1")
                self.assertEqual(plan.payload()["allowed_terminal"], ("accepted", "exhausted"))
                prepared = lifecycle.prepare(plan, freshness_until=20)
                prior = prepared
                count = 1 if terminal_kind == "accepted" else len(binding.profile_identities)
                for ordinal in range(1, count + 1):
                    accepted = terminal_kind == "accepted"
                    event = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, ordinal, prior.receipt_digest, binding.request_identities[ordinal - 1], binding.profile_identities[ordinal - 1], binding.runtime_fingerprints[ordinal - 1], SupervisorResultKind.ACCEPTED.value if accepted else SupervisorResultKind.INVALID.value, digest(f"legacy-{terminal_kind}-{ordinal}"), digest(f"legacy-{terminal_kind}-{ordinal}") if accepted else None, "pass" if accepted else None, 10, 20)
                    prior = lifecycle.append(prepared.record_identity, event, evidence_time=10)
                terminal = SupervisorTerminalRecord(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, prior.receipt_digest, count, terminal_kind, digest("legacy-accepted-1") if terminal_kind == "accepted" else None, None if terminal_kind == "accepted" else "attempt-budget-exhausted", "apply-bound-review-result" if terminal_kind == "accepted" else "retain-terminal-product-block", 10)
                if terminal_kind == "accepted":
                    terminal = replace(terminal, accepted_result_identity=digest("legacy-accepted-1"))
                terminal_receipt = lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)
                read = lifecycle.read(prepared.record_identity, evidence_time=10)
                self.assertEqual((read.expected_plan.payload(), read.expected_plan.source_identity, read.expected_plan.plan_identity, read.plan_receipt, read.terminal_receipt), (plan.payload(), plan.source_identity, plan.plan_identity, prepared, terminal_receipt))

    def test_legacy_v1_plan_identity_matches_literal_pre_blocked_compatibility_vector(self):
        binding = SupervisorSequenceBinding(
            "legacy-case", "b" * 40, "a" * 40, "task-legacy",
            ("sha256:e8a251387e54f7f70d4c4294378b3bcacda3ff10b8d872a9b050d32b0ce142ff", "sha256:c3833b1998943ac5635c4d37800813a7ba8c971442481cde2fb531e025c77256"),
            ("sha256:c6655fb15fcbdcbb36513c28889afadaa3f55d2efea183e244a770e0bab3b63c", "sha256:2852219181564429832c3e28502adbc22475c266bdb6f2ca238914fac6f7cc47"),
            ("sha256:1bd3233d6da7420c090d11fd663357b5b16106540debc5c88c7f53d74fa8d696", "sha256:a826abecdadb70c429e71a3c3032d9282838eb22bdfd9ef1230069ec915e5bc6"),
            2, 4, "CONVERGING", "sha256:f19f1897f8abd7f59b420a51a42aff1b67cc632a9a7f2ac3152d29792f789e47",
        )
        plan = SupervisorExpectedLifecycle(binding, "sha256:17ad92e63c962393c0329c658937d16eccaea13036412a3d1d0a5b6b8f29d738", "sha256:0e57ae90f420d845c9bc973dea8fcbab9baa3809be286830eaca40dc94266a2c", "sha256:2d52cd9073053426a522ce4fb85745902ca2f9482e61774b7c1fa6c44a68931d", 17, "sha256:6bdb95cbfd647dc56d6b1d241787c6a3aafffe36896105fbb416fa8c1e6711ff", "roundwright-supervisor-expected-lifecycle/v1")
        expected_payload = {"schema": "roundwright-supervisor-expected-lifecycle/v1", "binding": {"case_id": "legacy-case", "candidate_sha": "b" * 40, "base_sha": "a" * 40, "task_id": "task-legacy", "request_identities": ["sha256:e8a251387e54f7f70d4c4294378b3bcacda3ff10b8d872a9b050d32b0ce142ff", "sha256:c3833b1998943ac5635c4d37800813a7ba8c971442481cde2fb531e025c77256"], "profile_identities": ["sha256:c6655fb15fcbdcbb36513c28889afadaa3f55d2efea183e244a770e0bab3b63c", "sha256:2852219181564429832c3e28502adbc22475c266bdb6f2ca238914fac6f7cc47"], "runtime_fingerprints": ["sha256:1bd3233d6da7420c090d11fd663357b5b16106540debc5c88c7f53d74fa8d696", "sha256:a826abecdadb70c429e71a3c3032d9282838eb22bdfd9ef1230069ec915e5bc6"], "review_epoch": 2, "review_round": 4, "review_mode": "CONVERGING", "capture_plan_digest": "sha256:f19f1897f8abd7f59b420a51a42aff1b67cc632a9a7f2ac3152d29792f789e47"}, "policy_digest": "sha256:17ad92e63c962393c0329c658937d16eccaea13036412a3d1d0a5b6b8f29d738", "configuration_digest": "sha256:0e57ae90f420d845c9bc973dea8fcbab9baa3809be286830eaca40dc94266a2c", "runtime_identity": "sha256:2d52cd9073053426a522ce4fb85745902ca2f9482e61774b7c1fa6c44a68931d", "ready_at": 17, "observation_identity": "sha256:6bdb95cbfd647dc56d6b1d241787c6a3aafffe36896105fbb416fa8c1e6711ff", "allowed_terminal": ["accepted", "exhausted"], "accepted_next_action": "apply-bound-review-result", "exhausted_blocker": "attempt-budget-exhausted", "exhausted_next_action": "retain-terminal-product-block"}
        self.assertEqual(json.loads(json.dumps(plan.payload())), expected_payload)
        self.assertEqual((plan.context_identity, plan.plan_identity, plan.source_identity), ("sha256:155b232c92cb3aee7b57551fe59444545ef78efb95cc8c2044392cec958e0f9d", "sha256:1a3715e444896e33016a2f8914b7c1a7828cb390880fb4a96ce920279bd4ac43", "sha256:a3b62fdae8fa96198f92467430c488e1ff1c55bbd2a6700de15438931e2662cf"))
        source = "sha256:dddb9d06056750e136eff66f10f8a25484b2db32811d8c72935a6a9d391839e1"
        memory = InMemorySupervisorLifecycle(source)
        memory_receipt = memory.prepare(plan, freshness_until=29)
        self.assertEqual((memory_receipt.record_identity, memory_receipt.receipt_digest), ("sha256:1879df50838884831786253f593d6c49d771b982b8ec3d3ec9d45207d6773c62", "sha256:d8d3497add0f87cb93231aceca3e05163d9610b90690d8adb24cd4989cb2737d"))
        self.assertEqual(memory.read_plan(memory_receipt.record_identity, evidence_time=17), (plan, memory_receipt))
        with TemporaryDirectory() as temporary:
            file = FileSupervisorLifecycle(Path(temporary) / "legacy", source)
            file_receipt = file.prepare(plan, freshness_until=29)
            self.assertEqual(file_receipt, memory_receipt)
            self.assertEqual(FileSupervisorLifecycle(Path(temporary) / "legacy", source).read_plan(file_receipt.record_identity, evidence_time=17), (plan, file_receipt))

    def test_v1_rejects_new_terminal_kinds_while_v2_allows_them(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        for schema, allowed in (("roundwright-supervisor-expected-lifecycle/v1", False), ("roundwright-supervisor-expected-lifecycle/v2", True)):
            with self.subTest(schema=schema):
                lifecycle = InMemorySupervisorLifecycle(digest("schema-" + schema[-2:]))
                plan = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("schema-runtime-" + schema[-2:]), 10, readiness.observation_identity, schema)
                prepared = lifecycle.prepare(plan, freshness_until=20)
                event = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, 1, prepared.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.AMBIGUOUS.value, digest("schema-ambiguous"), None, None, 10, 20)
                receipt = lifecycle.append(prepared.record_identity, event, evidence_time=10)
                terminal = SupervisorTerminalRecord(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, receipt.receipt_digest, 1, "ambiguous", None, "provider-outcome-ambiguous", "retain-terminal-product-block", 10)
                if allowed:
                    lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)
                    self.assertEqual(lifecycle.read(prepared.record_identity, evidence_time=10).terminal, terminal)
                else:
                    with self.assertRaises(SupervisorShadowError):
                        lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)

    def test_file_lifecycle_reads_canonical_legacy_v1_terminal_records_unchanged(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        with TemporaryDirectory() as temporary:
            for terminal_kind in ("accepted", "exhausted"):
                with self.subTest(terminal=terminal_kind):
                    plan = SupervisorExpectedLifecycle(binding, policy.policy_digest, policy.configuration_digest, digest("legacy-file-runtime-" + terminal_kind), 10, readiness.observation_identity, "roundwright-supervisor-expected-lifecycle/v1")
                    lifecycle = FileSupervisorLifecycle(Path(temporary) / terminal_kind, digest("legacy-file-" + terminal_kind))
                    prepared = lifecycle.prepare(plan, freshness_until=20)
                    prior = prepared
                    count = 1 if terminal_kind == "accepted" else len(binding.profile_identities)
                    for ordinal in range(1, count + 1):
                        accepted = terminal_kind == "accepted"
                        result_identity = digest(f"legacy-file-{terminal_kind}-{ordinal}")
                        event = SupervisorAttemptEvent(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, ordinal, prior.receipt_digest, binding.request_identities[ordinal - 1], binding.profile_identities[ordinal - 1], binding.runtime_fingerprints[ordinal - 1], SupervisorResultKind.ACCEPTED.value if accepted else SupervisorResultKind.INVALID.value, result_identity, result_identity if accepted else None, "pass" if accepted else None, 10, 20)
                        prior = lifecycle.append(prepared.record_identity, event, evidence_time=10)
                    terminal = SupervisorTerminalRecord(prepared.record_identity, prepared.source_identity, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, prior.receipt_digest, count, terminal_kind, digest("legacy-file-accepted-1") if terminal_kind == "accepted" else None, None if terminal_kind == "accepted" else "attempt-budget-exhausted", "apply-bound-review-result" if terminal_kind == "accepted" else "retain-terminal-product-block", 10)
                    terminal_receipt = lifecycle.finalize(prepared.record_identity, terminal, evidence_time=10)
                    read = FileSupervisorLifecycle(Path(temporary) / terminal_kind, digest("legacy-file-" + terminal_kind)).read(prepared.record_identity, evidence_time=10)
                    self.assertEqual((read.expected_plan.payload(), read.expected_plan.source_identity, read.expected_plan.plan_identity, read.plan_receipt, read.terminal_receipt), (plan.payload(), plan.source_identity, plan.plan_identity, prepared, terminal_receipt))

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
            root = Path(temporary) / "anchor" / ".." / "durable"
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

    def test_file_lifecycle_rehydrates_complete_append_only_chain(self):
        _adapters, _requests, readiness, binding, policy, _old, _recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 3)
        expected_type = __import__("roundwright.supervisor_shadow", fromlist=["SupervisorExpectedLifecycle"]).SupervisorExpectedLifecycle
        plan = expected_type(binding, policy.policy_digest, policy.configuration_digest, digest("file-runtime-complete"), 10, readiness.observation_identity)
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "anchor" / ".." / "durable"; source = digest("file-chain-source")
            prepared = FileSupervisorLifecycle(root, source).prepare(plan, freshness_until=20)
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).read(prepared.record_identity, evidence_time=10)
            prior = prepared
            for ordinal in range(1, 4):
                event = SupervisorAttemptEvent(prepared.record_identity, source, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, ordinal, prior.receipt_digest, binding.request_identities[ordinal - 1], binding.profile_identities[ordinal - 1], binding.runtime_fingerprints[ordinal - 1], SupervisorResultKind.AMBIGUOUS.value, digest(f"file-result-{ordinal}"), None, None, 10, 20)
                prior = FileSupervisorLifecycle(root, source).append(prepared.record_identity, event, evidence_time=10)
            terminal = SupervisorTerminalRecord(prepared.record_identity, source, readiness.observation_identity, binding.candidate_sha, plan.context_identity, plan.plan_identity, binding.capture_plan_digest, prior.receipt_digest, 3, "exhausted", None, "attempt-budget-exhausted", "retain-terminal-product-block", 10)
            terminal_receipt = FileSupervisorLifecycle(root, source).finalize(prepared.record_identity, terminal, evidence_time=10)
            record = FileSupervisorLifecycle(root, source).read(prepared.record_identity, evidence_time=10)
            self.assertEqual((record.expected_plan, record.plan_receipt, record.terminal, record.terminal_receipt), (plan, prepared, terminal, terminal_receipt))
            self.assertEqual(tuple(item.ordinal for item in record.events), (1, 2, 3))
            self.assertIsNot(record.events[0], event)
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).append(prepared.record_identity, event, evidence_time=10)
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).finalize(prepared.record_identity, terminal, evidence_time=10)
            directory = root / ("record-" + prepared.record_identity.removeprefix("sha256:"))
            (directory / "event-0002.json").unlink()
            with self.assertRaises(SupervisorShadowError): FileSupervisorLifecycle(root, source).read(prepared.record_identity, evidence_time=10)
            accepted_plan = replace(plan, observation_identity=digest("file-accepted-observation"))
            accepted = FileSupervisorLifecycle(root, source).prepare(accepted_plan, freshness_until=20)
            accepted_event = SupervisorAttemptEvent(accepted.record_identity, source, accepted_plan.observation_identity, binding.candidate_sha, accepted_plan.context_identity, accepted_plan.plan_identity, binding.capture_plan_digest, 1, accepted.receipt_digest, binding.request_identities[0], binding.profile_identities[0], binding.runtime_fingerprints[0], SupervisorResultKind.ACCEPTED.value, digest("file-accepted"), digest("file-accepted"), "pass", 10, 20)
            accepted_event_receipt = FileSupervisorLifecycle(root, source).append(accepted.record_identity, accepted_event, evidence_time=10)
            accepted_terminal = SupervisorTerminalRecord(accepted.record_identity, source, accepted_plan.observation_identity, binding.candidate_sha, accepted_plan.context_identity, accepted_plan.plan_identity, binding.capture_plan_digest, accepted_event_receipt.receipt_digest, 1, "accepted", accepted_event.result_identity, None, "apply-bound-review-result", 10)
            FileSupervisorLifecycle(root, source).finalize(accepted.record_identity, accepted_terminal, evidence_time=10)
            self.assertEqual(FileSupervisorLifecycle(root, source).read(accepted.record_identity, evidence_time=10).terminal, accepted_terminal)

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
                schema_version=typed.get("schema_version", pinned.schema_version), digest="sha256:" + hashlib.sha256(canonical(material).encode()).hexdigest(), sources=typed.get("sources", dict(pinned.sources)), worker_profile_identity=typed.get("worker_profile_identity", pinned.worker_profile_identity), dependency_review_profile_identity=typed.get("dependency_review_profile_identity", pinned.dependency_review_profile_identity), supervisor_profile_identities=typed.get("supervisor_profile_identities", pinned.supervisor_profile_identities), review_policy=typed.get("review_policy", pinned.review_policy), repository_root_identity=typed.get("repository_root_identity", pinned.repository_root_identity), cache_directory_identity=typed.get("cache_directory_identity", pinned.cache_directory_identity), trusted_review_floor=typed.get("trusted_review_floor", pinned.trusted_review_floor), canonical_material=canonical(material), trusted_floor_evidence_required=pinned.trusted_floor_evidence_required,
            )
        self.assertEqual(construct(baseline), pinned)
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
            ("dependency-review-profile", lambda value: value.__setitem__("dependency_review", {"model": "changed", "reasoning_effort": "high"})),
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
        with self.assertRaises(ConfigurationError): construct(baseline, dependency_review_profile_identity=digest("dependency-review-substitution"))
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

    def test_file_runtime_store_rehydrates_canonical_receipts(self):
        runtime = self.configuration.runtime_binding(); candidate = self.context.candidate_sha; context = digest("file-runtime-context")
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "anchor" / ".." / "runtime"; source = digest("file-runtime-source")
            receipt = FileSupervisorRuntimeStore(root, source).persist(runtime, candidate_sha=candidate, context_identity=context, ready_at=10, freshness_until=20)
            value = FileSupervisorRuntimeStore(root, source).read(receipt, evidence_time=10)
            self.assertEqual(value, runtime); self.assertIsNot(value, runtime)
            material = json.dumps(receipt.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            self.assertEqual(SupervisorRuntimeBindingReceipt.from_canonical(material), receipt)
            with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, source).persist(runtime, candidate_sha=candidate, context_identity=context, ready_at=10, freshness_until=20)
            record = root / ("record-" + receipt.record_identity.removeprefix("sha256:"))
            for filename, replacement in (("runtime.json", "{}"), ("receipt.json", "{}")):
                original = (record / filename).read_text(encoding="utf-8")
                (record / filename).write_text(replacement, encoding="utf-8")
                with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, source).read(receipt, evidence_time=10)
                (record / filename).write_text(original, encoding="utf-8")
            (record / "runtime.json.tmp").write_text("partial", encoding="utf-8")
            with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, source).read(receipt, evidence_time=10)
            (record / "runtime.json.tmp").unlink()
            with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, digest("wrong-file-runtime-source")).read(receipt, evidence_time=10)
            with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, source).read(receipt, evidence_time=9)
            with self.assertRaises(RuntimeBindingError): FileSupervisorRuntimeStore(root, source).read(receipt, evidence_time=21)

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
                with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=store, trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual(tuple(counts.values()), (0,) * len(counts))

    def test_sequence_requires_independent_trusted_policy_receipt_before_runtime(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class NeverStore:
            def persist(self, *_args, **_kwargs): raise AssertionError("runtime persist must not run")
            def read(self, *_args, **_kwargs): raise AssertionError("runtime read must not run")
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=NeverStore(), trusted_policy_receipt=None, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_sequence_rejects_joint_authority_and_clone_echo_before_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),) + (NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 2)
        counts = {name: 0 for name in ("prepare", "read_plan", "append", "finalize", "read")}
        for name in counts:
            original = getattr(lifecycle, name)
            setattr(lifecycle, name, lambda *args, _name=name, _original=original, **kwargs: (counts.__setitem__(_name, counts[_name] + 1), _original(*args, **kwargs))[1])
        class CloneEchoStore:
            source_identity = policy.configuration.runtime_store_authority_identity
            def persist(self, *_args, **_kwargs): raise AssertionError("must not persist")
            def read(self, *_args, **_kwargs): raise AssertionError("must not read")
        receipt = replace(self.trusted_receipt(binding, policy, readiness), authority_receipt_digest=digest("jointly-minted-authority"))
        with self.assertRaises(SupervisorShadowError):
            qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=CloneEchoStore(), trusted_policy_receipt=receipt, review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((tuple(counts.values()), recorder.calls, self.events), ((0,) * len(counts), [], []))
        receipt = self.trusted_receipt(binding, policy, readiness)
        for field, value in (("source_identity", digest("self-minted-source")), ("authority_identity", digest("self-minted-authority")), ("authority_receipt_digest", digest("self-minted-receipt")), ("candidate_sha", "d" * 40), ("freshness_until", 100)):
            with self.subTest(field=field):
                with self.assertRaises(SupervisorShadowError):
                    qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=replace(receipt, **{field: value}), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual((tuple(counts.values()), recorder.calls, self.events), ((0,) * len(counts), [], []))

    def test_sequence_rejects_jointly_minted_reduced_authority_store_before_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),) + (NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 2)
        counts = {name: 0 for name in ("prepare", "read_plan", "append", "finalize", "read")}
        for name in counts:
            original = getattr(lifecycle, name)
            setattr(lifecycle, name, lambda *args, _name=name, _original=original, **kwargs: (counts.__setitem__(_name, counts[_name] + 1), _original(*args, **kwargs))[1])
        reduced = ReviewPolicy(1, 8, 1, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("c" * 64, "d" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, reduced)
        anchor = load_configuration(cwd=ROOT, environment={}, home=ROOT, trusted_review_floor=reduced).resolved_digest
        with TemporaryDirectory() as directory:
            forged_root = Path(directory)
            expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, FileReviewAuthorityStore.identity_for_root(forged_root), authority.receipt_digest, authority.policy_snapshot_digest, reduced, binding.candidate_sha, anchor, 101, 120)
            forged_store = FileReviewAuthorityStore(forged_root, expectation=expectation)
            forged_evidence = forged_store.persist(authority, candidate_sha=binding.candidate_sha, configuration_anchor_digest=anchor, ready_at=101, freshness_until=120)
            with self.assertRaises(SupervisorShadowError):
                qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=self.runtime_store(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_expectation=self.authority_expectation, review_authority_store=forged_store, review_authority_evidence=forged_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((tuple(counts.values()), recorder.calls, self.events), ((0,) * len(counts), [], []))

    def test_sequence_same_expectation_clone_authority_store_has_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),) + (NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS),) * 2)
        counts = {name: 0 for name in ("prepare", "read_plan", "append", "finalize", "read")}
        for name in counts:
            original = getattr(lifecycle, name)
            setattr(lifecycle, name, lambda *args, _name=name, _original=original, **kwargs: (counts.__setitem__(_name, counts[_name] + 1), _original(*args, **kwargs))[1])
        with TemporaryDirectory() as directory:
            with self.assertRaises(ConfigurationError):
                FileReviewAuthorityStore(Path(directory) / "candidate-controlled-clone", expectation=self.authority_expectation)
        self.assertEqual((tuple(counts.values()), recorder.calls, self.events), ((0,) * len(counts), [], []))
    def test_sequence_runtime_read_preflight_failure_has_zero_adapter_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class ReadFailingStore:
            def persist(self, runtime, **kwargs): return InMemorySupervisorRuntimeStore(digest("unused")).persist(runtime, **kwargs)
            def read(self, *_args, **_kwargs): raise RuntimeBindingError("read failure")
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=ReadFailingStore(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_sequence_runtime_read_wrong_type_has_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class WrongTypeStore:
            def persist(self, runtime, **kwargs): return InMemorySupervisorRuntimeStore(digest("wrong-type")).persist(runtime, **kwargs)
            def read(self, *_args, **_kwargs): return object()
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=WrongTypeStore(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
        self.assertEqual((recorder.calls, self.events), ([], []))

    def test_sequence_runtime_candidate_receipt_drift_has_zero_downstream_calls(self):
        adapters, requests, readiness, binding, policy, lifecycle, recorder = self.sequence_fixture((NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS), NativeSupervisorResponse(SupervisorResultKind.AMBIGUOUS)))
        class CandidateDriftStore:
            def __init__(self): self.store = InMemorySupervisorRuntimeStore(digest("candidate-drift"))
            def persist(self, runtime, **kwargs): return replace(self.store.persist(runtime, **kwargs), candidate_sha="d" * 40)
            def read(self, receipt, **kwargs): return self.store.read(receipt, **kwargs)
        with self.assertRaises(SupervisorShadowError): qualify_supervisor_sequence(adapters, requests, readiness, binding, policy, lifecycle, recorder, evidence_time=101, freshness_until=120, runtime_store=CandidateDriftStore(), trusted_policy_receipt=self.trusted_receipt(binding, policy, readiness), review_authority_store=self.authority_store, review_authority_evidence=self.authority_evidence, checkpoint_session=lambda _identity: None, checkpoint_turn=lambda _session, _turn: None)
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
