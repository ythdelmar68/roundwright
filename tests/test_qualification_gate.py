from __future__ import annotations

import unittest
from dataclasses import replace

from roundwright.external_validation import EvidenceLaneReceipt
from roundwright.integrated_boundary import (
    IntegratedBoundaryInputs,
    RetainedEvidenceExpectation,
    RetainedEvidenceSource,
    RetainedSourceKind,
    compose_retained_evidence,
)
from roundwright.qualification_gate import (
    PROMOTION_READY_FOR_CANARY_DECISION,
    QUALIFICATION_BLOCKED,
    CanaryEntryDecisionPackage,
    Phase3QualificationInputs,
    QualificationGateError,
    assess_phase_3_qualification,
)
from roundwright.shadow import LIVE_LIFECYCLE_SHADOW_PROFILE, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE


def digest(value: int) -> str:
    return f"sha256:{value:064x}"


class Phase3QualificationGateTests(unittest.TestCase):
    candidate = "a" * 40

    def source(self, kind: RetainedSourceKind, value: int) -> RetainedEvidenceSource:
        profiles = {
            RetainedSourceKind.LANE_A: READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
            RetainedSourceKind.LANE_B: LIVE_LIFECYCLE_SHADOW_PROFILE,
            RetainedSourceKind.HISTORICAL_REFERENCE: "roundwright-shadow-profile/provider-attempt-accounting/v1",
            RetainedSourceKind.SYNTHETIC_REFERENCE: "roundwright-shadow-profile/executor-contract-synthetic/v1",
        }
        return RetainedEvidenceSource(
            kind, profiles[kind], self.candidate, f"case-{value}", value,
            digest(value), digest(value + 10), digest(value + 20), digest(value + 30),
            digest(value + 40), digest(value + 50),
        )

    def inputs(self, **changes: object) -> Phase3QualificationInputs:
        lane_a_source = self.source(RetainedSourceKind.LANE_A, 1)
        lane_b_source = self.source(RetainedSourceKind.LANE_B, 2)
        historical = self.source(RetainedSourceKind.HISTORICAL_REFERENCE, 3)
        synthetic = self.source(RetainedSourceKind.SYNTHETIC_REFERENCE, 4)
        expected = RetainedEvidenceExpectation(
            digest(90), lane_a_source.result_digest, lane_a_source.bundle_digest,
            lane_b_source.result_digest, lane_b_source.receipt_digest, lane_b_source.retention_identity,
            digest(91), historical.source_digest, synthetic.source_digest,
        )
        retained = IntegratedBoundaryInputs(
            self.candidate, "issue-51", digest(80), expected,
            lane_a_source, lane_b_source, historical, synthetic,
        )
        manifest, result = compose_retained_evidence(retained)
        values = {
            "base_sha": "b" * 40,
            "candidate_sha": self.candidate,
            "harness_commit": "c" * 40,
            "forward_target_commit": "d" * 40,
            "issue_49_retention_manifest_digest": expected.retention_manifest_digest,
            "issue_50_retention_manifest_digest": digest(92),
            "issue_50_result_bundle_digest": digest(93),
            "temporary_resource_inventory_digest": digest(94),
            "integrated_inputs": retained,
            "composed_manifest": manifest,
            "composed_result": result,
            "lane_a": EvidenceLaneReceipt(READ_ONLY_EXTERNAL_OBSERVATION_PROFILE, self.candidate, "verified", "pass"),
            "lane_b": EvidenceLaneReceipt(LIVE_LIFECYCLE_SHADOW_PROFILE, self.candidate, "verified", "pass"),
            "supervisor_pass": True,
            "ci_pass": True,
            "policy_pass": True,
            "provenance_pass": True,
            "temporary_resources_reconciled": True,
        }
        values.update(changes)
        return Phase3QualificationInputs(**values)

    def test_complete_current_evidence_emits_only_owner_decision(self) -> None:
        decision = assess_phase_3_qualification(self.inputs())
        self.assertIsInstance(decision, CanaryEntryDecisionPackage)
        self.assertEqual(decision.disposition, PROMOTION_READY_FOR_CANARY_DECISION)
        payload = decision.public_payload()
        self.assertFalse(payload["canary_action_authorized"])
        self.assertFalse(payload["runtime_activation_authorized"])
        self.assertFalse(payload["roundlet_retirement_authorized"])
        self.assertEqual(payload["new_provider_calls"], 0)
        self.assertEqual(payload["new_target_actions"], 0)
        self.assertEqual(payload["lifecycle_observation_sink"], "NOT_SELECTED")

    def test_current_gate_failure_or_unresolved_blocker_fails_closed(self) -> None:
        self.assertEqual(
            assess_phase_3_qualification(self.inputs(ci_pass=False)).disposition,
            QUALIFICATION_BLOCKED,
        )
        self.assertEqual(
            assess_phase_3_qualification(self.inputs(unresolved_blockers=("unexplained-difference",))).disposition,
            QUALIFICATION_BLOCKED,
        )
        self.assertEqual(
            assess_phase_3_qualification(self.inputs(temporary_resources_reconciled=False)).disposition,
            QUALIFICATION_BLOCKED,
        )

    def test_mixed_candidate_or_altered_retained_evidence_is_rejected(self) -> None:
        with self.assertRaises(QualificationGateError):
            self.inputs(lane_b=EvidenceLaneReceipt(LIVE_LIFECYCLE_SHADOW_PROFILE, "e" * 40, "verified", "pass"))
        inputs = self.inputs()
        object.__setattr__(inputs.composed_result, "result_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)
