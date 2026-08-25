from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.external_validation import EvidenceLaneReceipt
from roundwright.integrated_boundary import IntegratedBoundaryInputs, RetainedEvidenceExpectation, RetainedEvidenceSource, RetainedSourceKind, compose_retained_evidence
from roundwright.qualification_gate import (
    PROMOTION_READY_FOR_CANARY_DECISION,
    QUALIFICATION_BLOCKED,
    Phase3QualificationInputs,
    QualificationGateError,
    RetainedEvidenceBinding,
    RetainedEvidenceObservations,
    RetainedEvidencePins,
    TemporaryResourceDisposition,
    TemporaryResourceEntry,
    TemporaryResourceInventory,
    TemporaryResourceKind,
    assess_phase_3_qualification,
)
from roundwright.shadow import LIVE_LIFECYCLE_SHADOW_PROFILE, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE


def digest(value: int) -> str:
    return f"sha256:{value:064x}"


class Phase3QualificationGateTests(unittest.TestCase):
    issue_49_candidate = "a" * 40
    issue_50_candidate = "b" * 40
    qualification_candidate = "c" * 40

    def source(self, kind: RetainedSourceKind, value: int) -> RetainedEvidenceSource:
        profile = {
            RetainedSourceKind.LANE_A: READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
            RetainedSourceKind.LANE_B: LIVE_LIFECYCLE_SHADOW_PROFILE,
            RetainedSourceKind.HISTORICAL_REFERENCE: "roundwright-shadow-profile/provider-attempt-accounting/v1",
            RetainedSourceKind.SYNTHETIC_REFERENCE: "roundwright-shadow-profile/executor-contract-synthetic/v1",
        }[kind]
        return RetainedEvidenceSource(kind, profile, self.issue_49_candidate, f"case-{value}", value, *(digest(value + offset) for offset in (0, 10, 20, 30, 40, 50)))

    def inputs(self, **changes: object) -> Phase3QualificationInputs:
        lane_a_source = self.source(RetainedSourceKind.LANE_A, 1)
        lane_b_source = replace(self.source(RetainedSourceKind.LANE_B, 2), bundle_digest=self.source(RetainedSourceKind.LANE_B, 2).result_digest)
        historical = self.source(RetainedSourceKind.HISTORICAL_REFERENCE, 3)
        synthetic = self.source(RetainedSourceKind.SYNTHETIC_REFERENCE, 4)
        expectation = RetainedEvidenceExpectation(
            digest(90), lane_a_source.result_digest, lane_a_source.bundle_digest,
            lane_b_source.result_digest, lane_b_source.receipt_digest, lane_b_source.retention_identity,
            digest(91), historical.source_digest, synthetic.source_digest,
        )
        retained = IntegratedBoundaryInputs(self.issue_50_candidate, "issue-50", digest(80), expectation, lane_a_source, lane_b_source, historical, synthetic)
        manifest, result = compose_retained_evidence(retained)
        pins = RetainedEvidencePins(expectation.retention_manifest_digest, digest(92), digest(93))
        resources = TemporaryResourceInventory((
            TemporaryResourceEntry(digest(94), TemporaryResourceKind.REPLAYABLE, TemporaryResourceDisposition.REMOVED),
            TemporaryResourceEntry(digest(95), TemporaryResourceKind.UNIQUE, TemporaryResourceDisposition.PRESERVED),
            TemporaryResourceEntry(digest(96), TemporaryResourceKind.AMBIGUOUS, TemporaryResourceDisposition.PRESERVED),
        ))
        values = {
            "base_sha": "d" * 40, "qualification_candidate_sha": self.qualification_candidate,
            "qualification_case_id": "issue-51-qualification", "qualification_ready_at": 23,
            "qualification_capture_plan_digest": digest(79),
            "qualification_recorder_identity": digest(78), "qualification_store_identity": digest(77),
            "issue_49_candidate_sha": self.issue_49_candidate, "issue_50_candidate_sha": self.issue_50_candidate,
            "roundlet_commit": "d" * 40, "harness_commit": "e" * 40, "forward_target_commit": "f" * 40,
            "rollback_proposal_digest": digest(97), "kill_switch_proposal_digest": digest(98),
            "retained_evidence": RetainedEvidenceBinding(pins, RetainedEvidenceObservations(*pins.payload().values())),
            "temporary_resources": resources, "integrated_inputs": retained, "composed_manifest": manifest, "composed_result": result,
            "lane_a": EvidenceLaneReceipt(READ_ONLY_EXTERNAL_OBSERVATION_PROFILE, self.issue_49_candidate, "verified", "pass"),
            "lane_b": EvidenceLaneReceipt(LIVE_LIFECYCLE_SHADOW_PROFILE, self.issue_49_candidate, "verified", "pass"),
            "supervisor_pass": True, "ci_pass": True, "policy_pass": True, "provenance_pass": True,
        }
        values.update(changes)
        return Phase3QualificationInputs(**values)

    def test_distinct_generations_produce_only_owner_decision(self) -> None:
        decision = assess_phase_3_qualification(self.inputs())
        self.assertEqual(decision.disposition, PROMOTION_READY_FOR_CANARY_DECISION)
        payload = decision.public_payload()
        self.assertEqual(
            (payload["issue_49_candidate_sha"], payload["issue_50_candidate_sha"], payload["qualification_candidate_sha"]),
            (self.issue_49_candidate, self.issue_50_candidate, self.qualification_candidate),
        )
        self.assertFalse(payload["canary_action_authorized"])
        self.assertEqual((payload["new_provider_calls"], payload["new_target_actions"]), (0, 0))
        self.assertEqual(payload["qualification"]["roundlet_commit"], "d" * 40)
        self.assertEqual(payload["qualification"]["rollback_proposal_digest"], digest(97))
        self.assertEqual(len(payload["qualification"]["retained_sources"]), 4)

    def test_cross_generation_substitution_and_current_gate_failure_fail_closed(self) -> None:
        with self.assertRaises(QualificationGateError):
            self.inputs(issue_50_candidate_sha=self.issue_49_candidate)
        with self.assertRaises(QualificationGateError):
            self.inputs(lane_b=EvidenceLaneReceipt(LIVE_LIFECYCLE_SHADOW_PROFILE, self.issue_50_candidate, "verified", "pass"))
        self.assertEqual(assess_phase_3_qualification(self.inputs(ci_pass=False)).disposition, QUALIFICATION_BLOCKED)

    def test_retained_expected_and_observed_pins_reject_substitution(self) -> None:
        inputs = self.inputs()
        with self.assertRaises(QualificationGateError):
            RetainedEvidenceBinding(inputs.retained_evidence.expected, RetainedEvidenceObservations(digest(77), digest(92), digest(93)))
        object.__setattr__(inputs.retained_evidence.observed, "issue_50_result_bundle_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)
        inputs = self.inputs()
        object.__setattr__(inputs.retained_evidence, "binding_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)

    def test_inventory_reconciles_replayable_and_preserves_unique_or_ambiguous_work(self) -> None:
        inputs = self.inputs()
        self.assertTrue(inputs.temporary_resources.fully_reconciled)
        self.assertEqual(tuple(entry.disposition.value for entry in inputs.temporary_resources.entries), ("removed", "preserved", "preserved"))
        with self.assertRaises(QualificationGateError):
            TemporaryResourceEntry(digest(97), TemporaryResourceKind.UNIQUE, TemporaryResourceDisposition.REMOVED)
        object.__setattr__(inputs.temporary_resources, "inventory_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)
        inputs = self.inputs()
        object.__setattr__(inputs.temporary_resources.entries[1], "disposition", TemporaryResourceDisposition.REMOVED)
        with self.assertRaises(QualificationGateError):
            replace(inputs)
