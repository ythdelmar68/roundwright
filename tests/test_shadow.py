"""Phase 3 immutable Shadow replay and comparison proof."""

from __future__ import annotations

import unittest
import json
from dataclasses import replace

from roundwright.shadow import (
    Applicability,
    AttemptDisposition,
    ComparisonField,
    ComparisonOutcome,
    EvidenceRole,
    MutationKind,
    NoMutationCapabilities,
    ForbiddenMutationError,
    ReplayClassification,
    ShadowCase,
    ShadowExecutor,
    ShadowIdentity,
    ShadowObservation,
    compare_provider_health_receipt,
    rehydrate_live_provider_health_evidence,
)
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.runtime_binding import RuntimeBinding
from roundwright.provider_health import CodexCapability, CodexHealthContract, CodexRuntimeAudit, HealthState, ProviderHealthAuditIdentity, ProviderHealthObservation, ProviderHealthReceipt, profile_fingerprint
from roundwright.provider_recovery import ProviderRole
import hashlib


BASE = "a" * 40
CANDIDATE = "b" * 40
STATES = ("queued", "planning", "plan-review", "implementing", "diff-review", "ready-for-owner")


class ShadowTests(unittest.TestCase):
    def receipt(self, *, commit="a" * 40, candidate=None, case="case-42", ordinal=0, state=HealthState.READY, fresh_until=200):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        profile_id = profile_fingerprint(profile)
        binding = RuntimeBinding("roundwright-runtime/v1", "sha256:" + "a" * 64, profile_id, (profile_id,))
        audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),))
        observation = ProviderHealthObservation(ProviderRole.WORKER, profile_id, CodexHealthContract(audit.sdk_version, audit.runtime_version, commit).fingerprint, audit.fingerprint, state, None if state is HealthState.READY else __import__("roundwright.provider_health", fromlist=["CodexFailure"]).CodexFailure.UNKNOWN, 100, fresh_until, 1)
        return ProviderHealthReceipt(commit, candidate, case, ordinal, binding, ProviderRole.WORKER, profile_id, observation, ProviderHealthAuditIdentity(audit, profile))

    def test_provider_health_receipt_comparator_is_safe_and_deterministic(self):
        receipt = self.receipt(candidate="b" * 40)
        matched = compare_provider_health_receipt(receipt.evidence(), receipt.evidence(), now=101)
        self.assertEqual((matched.outcome, matched.differing_fields), (ComparisonOutcome.MATCH, ()))
        self.assertEqual(matched.curated_summary()["contract_commit"], "a" * 40)
        changed = self.receipt(commit="c" * 40)
        mismatch = compare_provider_health_receipt(receipt.evidence(), changed.evidence(), now=101)
        self.assertEqual(mismatch.outcome, ComparisonOutcome.MISMATCH)
        self.assertIn("contract_commit", mismatch.differing_fields)
        self.assertEqual(compare_provider_health_receipt(receipt.evidence(), self.receipt(fresh_until=101).evidence(), now=101).differing_fields, ("invalid-evidence",))
        tampered = receipt.evidence(); tampered.pop("case_id")
        self.assertEqual(compare_provider_health_receipt(receipt.evidence(), tampered, now=101).outcome, ComparisonOutcome.INVALID)

    def test_live_json_receipt_evidence_rehydrates_before_typed_shadow_comparison(self):
        worker = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        supervisor = ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH)
        worker_id, supervisor_id = profile_fingerprint(worker), profile_fingerprint(supervisor)
        binding = RuntimeBinding("roundwright-runtime/v1", "sha256:" + "a" * 64, worker_id, (supervisor_id,))
        audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(worker.model, "high"), CodexCapability(supervisor.model, "xhigh")))
        receipts = []
        for ordinal, (role, profile, profile_id) in enumerate(((ProviderRole.PLANNING, worker, worker_id), (ProviderRole.WORKER, worker, worker_id), (ProviderRole.SUPERVISOR, supervisor, supervisor_id))):
            observation = ProviderHealthObservation(role, profile_id, CodexHealthContract(audit.sdk_version, audit.runtime_version, "a" * 40).fingerprint, audit.fingerprint, HealthState.READY, None, 100, 200, 1)
            receipts.append(ProviderHealthReceipt("a" * 40, "b" * 40, "case-42", ordinal, binding, role, profile_id, observation, ProviderHealthAuditIdentity(audit, profile)))
        receipt = receipts[0]
        emitted = {
            "schema": "roundwright-live-provider-health/v1", "ready_at": 101, "ready": True,
            "contract_commit": receipt.contract_commit, "candidate_sha": receipt.candidate_sha, "case_id": receipt.case_id,
            "report": {"health_contract_identity": receipt.observation.health_contract_identity,
                       "configuration": receipt.configuration.complete_columns(),
                       "selections": tuple((item.selection_ordinal, item.role.value, item.profile_identity) for item in receipts),
                       "observations": tuple(item.observation.evidence() for item in receipts)},
            "receipts": tuple(item.evidence() for item in receipts), "receipt_digests": tuple(item.receipt_digest for item in receipts),
        }
        replayed = rehydrate_live_provider_health_evidence(json.loads(json.dumps(emitted)))
        self.assertEqual(len(replayed), 3)
        self.assertEqual(compare_provider_health_receipt(receipt.evidence(), replayed[0].evidence(), now=101).outcome, ComparisonOutcome.MATCH)
        for mutate in (lambda value: value["receipts"][0].__setitem__("receipt_digest", "sha256:" + "0" * 64), lambda value: value.__setitem__("extra", True)):
            tampered = json.loads(json.dumps(emitted)); mutate(tampered)
            with self.assertRaises(Exception):
                rehydrate_live_provider_health_evidence(tampered)
    def identity(self) -> ShadowIdentity:
        return ShadowIdentity(
            "source-38", "task-38", BASE, CANDIDATE, "policy-38", "provider-38", "review-38", "gate-38", "owner-review", "worktree-38",
            "reference-38", (hashlib.sha256(b"input-38").hexdigest(),), "rules-38", "fixture-38", "2030-01-01T00:00:00Z", "phase-3", "retention-38", "normalizer-v1", "comparator-v1", ("input-38",), hashlib.sha256(b"reference-38").hexdigest(), (b"input-38",), b"reference-38", "sha256:" + "c" * 64, "roundwright-runtime/v1", "sha256:" + "d" * 64, ("sha256:" + "e" * 64, "sha256:" + "f" * 64, "sha256:" + "0" * 64), "sha256:" + "e" * 64,
        )

    def observations(self, **last_changes: object) -> tuple[ShadowObservation, ...]:
        roles = (EvidenceRole.WORKER, EvidenceRole.WORKER, EvidenceRole.SUPERVISOR, EvidenceRole.WORKER, EvidenceRole.SUPERVISOR, EvidenceRole.SUPERVISOR)
        items = []
        for index, (state, role) in enumerate(zip(STATES, roles, strict=True), start=1):
            items.append(ShadowObservation(
                f"event-{index}", role, "provider-38", AttemptDisposition.ACCEPTED,
                state, CANDIDATE, source_id="source-38", task_id="task-38", base_sha=BASE, policy_identity="policy-38",
                gate_identity="gate-38", applicability=Applicability.APPLICABLE, blocker=None, next_action="owner-review",
                accepted_review_identity="review-38", worktree_identity="worktree-38",
                input_identities=("input-38",), input_digests=(hashlib.sha256(b"input-38").hexdigest(),), reference_result_digest=hashlib.sha256(b"reference-38").hexdigest(), input_payloads=(b"input-38",), reference_result_payload=b"reference-38", configuration_digest="sha256:" + "c" * 64, configuration_schema_version="roundwright-runtime/v1", worker_profile_identity="sha256:" + "d" * 64, supervisor_profile_identities=("sha256:" + "e" * 64, "sha256:" + "f" * 64, "sha256:" + "0" * 64), selected_supervisor_profile_identity="sha256:" + "e" * 64,
            ))
        items[-1] = replace(items[-1], **last_changes, evidence_digest="")
        return tuple(items)

    def case(self, observations: tuple[ShadowObservation, ...] | None = None, **changes: object) -> ShadowCase:
        return ShadowCase.build("case-38", self.identity(), self.observations() if observations is None else observations, expected_states=STATES, **changes)

    def test_phase_two_trace_replays_exactly_without_mutation(self):
        report = ShadowExecutor().replay(self.case())
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH))
        self.assertEqual(report.replayed_states, STATES)
        self.assertEqual(report.curated_summary()["comparison_fields"], ())

    def test_exact_duplicate_event_is_idempotent(self):
        observations = self.observations()
        case = self.case((observations[0], observations[0], *observations[1:]))
        report = ShadowExecutor().replay(case)
        self.assertEqual(report.classification, ReplayClassification.EXACT_MATCH)
        self.assertEqual(report.replayed_states, STATES)

    def test_ambiguous_restart_is_not_reclassified(self):
        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], attempt_disposition=AttemptDisposition.AMBIGUOUS, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_candidate_movement_invalidates_all_bound_evidence(self):
        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], candidate_sha="c" * 40, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual(report.classification, ReplayClassification.STALE_EVIDENCE)

    def test_resolved_configuration_digest_is_pinned_to_shadow_evidence(self):
        digest = "sha256:" + "c" * 64
        identity = replace(self.identity(), configuration_digest=digest)
        observations = tuple(replace(item, configuration_digest=digest, evidence_digest="") for item in self.observations())
        case = ShadowCase.build("case-config", identity, observations, expected_states=STATES)
        self.assertEqual(ShadowExecutor().replay(case).classification, ReplayClassification.EXACT_MATCH)
        stale = tuple(replace(item, configuration_digest="sha256:" + "d" * 64, evidence_digest="") for item in observations)
        self.assertEqual(ShadowExecutor().replay(ShadowCase.build("case-config", identity, stale, expected_states=STATES)).classification, ReplayClassification.STALE_EVIDENCE)
        with self.assertRaisesRegex(Exception, "configuration digest"):
            ShadowCase.build("case-missing-config", replace(self.identity(), configuration_digest=""), self.observations(), expected_states=STATES)

    def test_resolved_configuration_profile_identity_drift_is_stale_evidence(self):
        observations = self.observations(
            worker_profile_identity="sha256:" + "0" * 64,
        )
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.STALE_EVIDENCE))

    def test_selected_supervisor_profile_drift_is_stale_evidence(self):
        report = ShadowExecutor().replay(self.case(self.observations(selected_supervisor_profile_identity="sha256:" + "f" * 64)))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.STALE_EVIDENCE))

    def test_dirty_worktree_evidence_fails_closed(self):
        observations = self.observations(worktree_clean=False)
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_unaccepted_or_mismatched_review_evidence_fails_closed(self):
        recorded = self.observations(attempt_disposition=AttemptDisposition.RECORDED)
        stale = self.observations(accepted_review_identity="review-37")
        self.assertEqual(ShadowExecutor().replay(self.case(recorded)).classification, ReplayClassification.INCOMPLETE_EVIDENCE)
        stale_report = ShadowExecutor().replay(self.case(stale))
        self.assertEqual((stale_report.outcome, stale_report.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))

    def test_missing_gate_evidence_is_incomplete_not_a_comparison_mismatch(self):
        observations = self.observations(gate_identity=None)
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_observed_identity_is_derived_from_every_persisted_observation(self):
        observations = list(self.observations())
        observations[0] = replace(observations[0], gate_identity="gate-wrong", evidence_digest="")
        report = ShadowExecutor().replay(self.case(tuple(observations)))
        identity = next(item for item in report.comparisons if item.field is ComparisonField.IDENTITY)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))
        self.assertFalse(identity.matches)

    def test_missing_or_mismatched_bound_identity_fails_closed(self):
        missing = ShadowExecutor().replay(self.case(self.observations(source_id=None)))
        mismatched = ShadowExecutor().replay(self.case(self.observations(attempt_id="provider-37")))
        self.assertEqual((missing.outcome, missing.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))
        identity = next(item for item in mismatched.comparisons if item.field is ComparisonField.IDENTITY)
        self.assertEqual((mismatched.outcome, mismatched.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))
        self.assertFalse(identity.matches)

    def test_skipped_phase_two_states_are_incomplete_evidence(self):
        observations = self.observations()
        report = ShadowExecutor().replay(self.case((observations[0], observations[-1])))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_multi_source_not_applicable_evidence_fails_closed(self):
        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], applicability=Applicability.NOT_APPLICABLE, source_count=2, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations, expected_applicability=Applicability.NOT_APPLICABLE))
        self.assertEqual(report.classification, ReplayClassification.INCOMPLETE_EVIDENCE)

    def test_declared_nondeterminism_is_never_an_exact_match(self):
        observations = self.observations(next_action="wait-for-owner")
        report = ShadowExecutor().replay(self.case(observations, expected_nondeterminism=(ComparisonField.NEXT_ACTION,)))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MISMATCH, ReplayClassification.EXPECTED_NONDETERMINISM))

    def test_identity_nondeterminism_is_rejected_before_it_can_mask_drift(self):
        with self.assertRaisesRegex(Exception, "expected nondeterminism"):
            self.case(self.observations(attempt_id="provider-37"), expected_nondeterminism=(ComparisonField.IDENTITY,))

    def test_every_mutation_capability_denies_before_its_callback(self):
        adapter = NoMutationCapabilities()
        capability_names = {
            MutationKind.GIT: "git", MutationKind.GITHUB: "github", MutationKind.REPOSITORY: "repository",
            MutationKind.QUEUE: "queue", MutationKind.BRANCH: "branch", MutationKind.WORKTREE: "worktree",
            MutationKind.PULL_REQUEST: "pull_request", MutationKind.ISSUE: "issue", MutationKind.MERGE: "merge",
            MutationKind.CLOSE: "close", MutationKind.CLEANUP: "cleanup", MutationKind.LIFECYCLE: "lifecycle",
        }
        self.assertEqual(set(capability_names), set(MutationKind))
        for kind, name in capability_names.items():
            with self.subTest(kind=kind):
                called = False

                def side_effect() -> None:
                    nonlocal called
                    called = True

                with self.assertRaises(ForbiddenMutationError) as raised:
                    getattr(adapter, name)(side_effect)
                self.assertEqual(raised.exception.kind, kind)
                self.assertFalse(called)

        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], requested_mutation=MutationKind.GITHUB, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual(report.classification, ReplayClassification.FORBIDDEN_MUTATION)

    def test_executor_rejects_capability_injection(self):
        calls = []

        class Bypass(NoMutationCapabilities):
            def execute(self, kind, action=None):
                calls.append(kind)

        with self.assertRaises(TypeError):
            ShadowExecutor(Bypass())
        observations = self.observations(requested_mutation=MutationKind.GITHUB)
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual(report.classification, ReplayClassification.FORBIDDEN_MUTATION)
        self.assertEqual(calls, [])

    def test_subclass_evidence_hooks_are_rejected_without_attribute_access(self):
        accesses = []

        class AdversarialCase(ShadowCase):
            def __getattribute__(self, name):
                accesses.append(name)
                return super().__getattribute__(name)

        safe_case = self.case()
        adversarial = object.__new__(AdversarialCase)
        for field in safe_case.__dataclass_fields__:
            object.__setattr__(adversarial, field, object.__getattribute__(safe_case, field))
        report = ShadowExecutor().replay(adversarial)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))
        self.assertEqual(accesses, [])

    def test_scalar_subclasses_are_rejected_before_hash_or_comparison(self):
        calls = []

        class HookedString(str):
            def __hash__(self):
                calls.append("hash")
                return super().__hash__()

        class HookedInt(int):
            def __lt__(self, other):
                calls.append("compare")
                return super().__lt__(other)

        with self.assertRaisesRegex(Exception, "event identity"):
            self.observations(event_id=HookedString("event-hook"))
        with self.assertRaisesRegex(Exception, "applicability"):
            self.observations(source_count=HookedInt(1))
        self.assertEqual(calls, [])

    def test_builder_rejects_iterables_before_traversal(self):
        calls = []

        class HookedIterable:
            def __iter__(self):
                calls.append("iter")
                return iter(())

        with self.assertRaisesRegex(Exception, "observations"):
            ShadowCase.build("case-38", self.identity(), HookedIterable(), expected_states=STATES)
        self.assertEqual(calls, [])

    def test_uninitialized_exact_evidence_returns_generic_invalid_report(self):
        case = object.__new__(ShadowCase)
        report = ShadowExecutor().replay(case)
        self.assertEqual((report.case_id, report.case_digest), ("invalid-case", "none"))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))

    def test_partial_exact_nested_evidence_returns_generic_invalid_report(self):
        safe = self.case()
        partial_identity = object.__new__(ShadowIdentity)
        partial_observation = object.__new__(ShadowObservation)
        identity_case = object.__new__(ShadowCase)
        observation_case = object.__new__(ShadowCase)
        for field in safe.__dataclass_fields__:
            object.__setattr__(identity_case, field, object.__getattribute__(safe, field))
            object.__setattr__(observation_case, field, object.__getattribute__(safe, field))
        object.__setattr__(identity_case, "identity", partial_identity)
        object.__setattr__(observation_case, "observations", (partial_observation,))
        for case in (identity_case, observation_case):
            report = ShadowExecutor().replay(case)
            self.assertEqual((report.case_id, report.case_digest), ("invalid-case", "none"))
            self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))

    def test_safe_invalid_reports_retain_curated_evidence(self):
        stale = ShadowExecutor().replay(self.case(self.observations(candidate_sha="c" * 40)))
        incomplete = ShadowExecutor().replay(self.case(self.observations(gate_identity=None)))
        forbidden = ShadowExecutor().replay(self.case(self.observations(requested_mutation=MutationKind.GITHUB)))
        for report in (stale, incomplete, forbidden):
            summary = report.curated_summary()
            self.assertNotEqual(summary["case_digest"], "none")
            self.assertTrue(summary["case_id"].startswith("sha256:"))
            self.assertTrue(summary["identities"])
            self.assertTrue(summary["retention_reference"].startswith("sha256:"))
            self.assertTrue(summary["read_only"])

    def test_protocol_manifest_is_required_immutable_and_curated(self):
        with self.assertRaisesRegex(Exception, "input digests"):
            ShadowCase.build("case-38", replace(self.identity(), input_digests=()), self.observations(), expected_states=STATES)
        case = self.case()
        object.__setattr__(case.identity, "fixture_environment_identity", "fixture-drift")
        drift = ShadowExecutor().replay(case)
        self.assertEqual((drift.outcome, drift.classification), (ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH))
        private_observations = tuple(replace(item, source_id="C:/private/token", evidence_digest="") for item in self.observations())
        private = ShadowCase.build(
            "C:/private/token", replace(self.identity(), source_id="C:/private/token"), private_observations, expected_states=STATES,
        )
        summary = ShadowExecutor().replay(private).curated_summary()
        self.assertTrue(summary["case_id"].startswith("sha256:"))
        self.assertTrue(summary["identities"]["source"].startswith("sha256:"))
        self.assertTrue(summary["read_only"])
        self.assertTrue(summary["retention_reference"].startswith("sha256:"))

    def test_replay_inputs_and_opaque_identifiers_fail_closed_or_redact(self):
        with self.assertRaisesRegex(Exception, "input digest"):
            self.observations(input_digests=("0" * 64,))
        observations = tuple(replace(item, source_id="ghp_not-a-public-identity", task_id="person@example.invalid", evidence_digest="") for item in self.observations())
        case = ShadowCase.build("ghp_case", replace(self.identity(), source_id="ghp_not-a-public-identity", task_id="person@example.invalid"), observations, expected_states=STATES)
        summary = ShadowExecutor().replay(case).curated_summary()
        self.assertTrue(summary["case_id"].startswith("sha256:"))
        self.assertTrue(summary["identities"]["source"].startswith("sha256:"))
        self.assertTrue(summary["identities"]["task"].startswith("sha256:"))

    def test_conflicting_replayed_event_is_a_contract_mismatch(self):
        observations = self.observations()
        conflict = replace(observations[0], state="planning", evidence_digest="")
        report = ShadowExecutor().replay(self.case((observations[0], conflict, *observations[1:])))
        self.assertEqual(report.classification, ReplayClassification.CONTRACT_MISMATCH)


if __name__ == "__main__":
    unittest.main()
