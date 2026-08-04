"""Phase 3 immutable Shadow replay and comparison proof."""

from __future__ import annotations

import unittest
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
)


BASE = "a" * 40
CANDIDATE = "b" * 40
STATES = ("queued", "planning", "plan-review", "implementing", "diff-review", "ready-for-owner")


class ShadowTests(unittest.TestCase):
    def identity(self) -> ShadowIdentity:
        return ShadowIdentity(
            "source-38", "task-38", BASE, CANDIDATE, "policy-38", "provider-38", "review-38", "gate-38", "owner-review", "worktree-38"
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

    def test_dirty_worktree_evidence_fails_closed(self):
        observations = self.observations(worktree_clean=False)
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_unaccepted_or_mismatched_review_evidence_fails_closed(self):
        recorded = self.observations(attempt_disposition=AttemptDisposition.RECORDED)
        stale = self.observations(accepted_review_identity="review-37")
        self.assertEqual(ShadowExecutor().replay(self.case(recorded)).classification, ReplayClassification.INCOMPLETE_EVIDENCE)
        self.assertEqual(ShadowExecutor().replay(self.case(stale)).classification, ReplayClassification.CONTRACT_MISMATCH)

    def test_missing_gate_evidence_is_incomplete_not_a_comparison_mismatch(self):
        observations = self.observations(gate_identity=None)
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))

    def test_observed_identity_is_derived_from_every_persisted_observation(self):
        observations = list(self.observations())
        observations[0] = replace(observations[0], gate_identity="gate-wrong", evidence_digest="")
        report = ShadowExecutor().replay(self.case(tuple(observations)))
        identity = next(item for item in report.comparisons if item.field is ComparisonField.IDENTITY)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MISMATCH, ReplayClassification.CONTRACT_MISMATCH))
        self.assertFalse(identity.matches)

    def test_missing_or_mismatched_bound_identity_fails_closed(self):
        missing = ShadowExecutor().replay(self.case(self.observations(source_id=None)))
        mismatched = ShadowExecutor().replay(self.case(self.observations(attempt_id="provider-37")))
        self.assertEqual((missing.outcome, missing.classification), (ComparisonOutcome.INVALID, ReplayClassification.INCOMPLETE_EVIDENCE))
        identity = next(item for item in mismatched.comparisons if item.field is ComparisonField.IDENTITY)
        self.assertEqual((mismatched.outcome, mismatched.classification), (ComparisonOutcome.MISMATCH, ReplayClassification.CONTRACT_MISMATCH))
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

    def test_conflicting_replayed_event_is_a_contract_mismatch(self):
        observations = self.observations()
        conflict = replace(observations[0], state="planning", evidence_digest="")
        report = ShadowExecutor().replay(self.case((observations[0], conflict, *observations[1:])))
        self.assertEqual(report.classification, ReplayClassification.CONTRACT_MISMATCH)


if __name__ == "__main__":
    unittest.main()
