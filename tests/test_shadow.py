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
            "source-38", "task-38", BASE, CANDIDATE, "policy-38", "worker-attempt", "review-38", "gate-38", "owner-review"
        )

    def observations(self, **last_changes: object) -> tuple[ShadowObservation, ...]:
        roles = (EvidenceRole.WORKER, EvidenceRole.WORKER, EvidenceRole.SUPERVISOR, EvidenceRole.WORKER, EvidenceRole.SUPERVISOR, EvidenceRole.SUPERVISOR)
        items = []
        for index, (state, role) in enumerate(zip(STATES, roles, strict=True), start=1):
            items.append(ShadowObservation(
                f"event-{index}", role, f"attempt-{index}", AttemptDisposition.ACCEPTED,
                state, CANDIDATE, "gate-38", Applicability.APPLICABLE, None, "owner-review",
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

    def test_multi_source_not_applicable_evidence_fails_closed(self):
        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], applicability=Applicability.NOT_APPLICABLE, source_count=2, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations, expected_applicability=Applicability.NOT_APPLICABLE))
        self.assertEqual(report.classification, ReplayClassification.INCOMPLETE_EVIDENCE)

    def test_declared_nondeterminism_is_never_an_exact_match(self):
        observations = self.observations(next_action="wait-for-owner")
        report = ShadowExecutor().replay(self.case(observations, expected_nondeterminism=(ComparisonField.NEXT_ACTION,)))
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MISMATCH, ReplayClassification.EXPECTED_NONDETERMINISM))

    def test_forced_capability_denial_happens_before_callback(self):
        called = False

        def side_effect() -> None:
            nonlocal called
            called = True

        with self.assertRaisesRegex(Exception, "forbids git mutation"):
            NoMutationCapabilities().git(side_effect)
        self.assertFalse(called)

        observations = self.observations()
        observations = (*observations[:-1], replace(observations[-1], requested_mutation=MutationKind.GITHUB, evidence_digest=""))
        report = ShadowExecutor().replay(self.case(observations))
        self.assertEqual(report.classification, ReplayClassification.FORBIDDEN_MUTATION)

    def test_conflicting_replayed_event_is_a_contract_mismatch(self):
        observations = self.observations()
        conflict = replace(observations[0], state="planning", evidence_digest="")
        report = ShadowExecutor().replay(self.case((observations[0], conflict, *observations[1:])))
        self.assertEqual(report.classification, ReplayClassification.CONTRACT_MISMATCH)


if __name__ == "__main__":
    unittest.main()
