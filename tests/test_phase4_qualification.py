"""Hermetic tests for the consumer-only Issue #98 Phase 4 gate."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.cross_environment import (
    CROSS_ENVIRONMENT_LANE_ORDER, ComparisonResult, CrossEnvironmentEvidence, CrossEnvironmentEvidenceError,
    EnvironmentKind, EnvironmentLane, OperationMode, ReceiptState,
    SEALED_CANARY_EXECUTION_LEDGER_DIGEST, SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST,
    SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST, SEALED_CANARY_READY_AT,
    SEALED_CANARY_RECEIPT_DIGEST, SEALED_CANARY_SOURCE_CANDIDATE_SHA,
    SEALED_CANARY_TARGET_MERGE_SHA, SealedCanaryReceipt, compare_cross_environment_evidence,
)
from roundwright.phase4_qualification import (
    ConsumerTopology, EvidenceConfidence, ExitEvidenceArea, ExitEvidenceReceipt,
    PHASE_4_QUALIFICATION_BLOCKED, PHASE_5_OWNER_DECISION_REQUIRED,
    Phase4QualificationError, Phase4QualificationInputs, assess_phase_4_qualification,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class Phase4QualificationTests(unittest.TestCase):
    candidate = "a" * 40

    def evidence(self) -> CrossEnvironmentEvidence:
        lanes = tuple(
            EnvironmentLane(
                environment, environment.value + "-runner",
                OperationMode.AUTHORITATIVE if environment is EnvironmentKind.WINDOWS_HOST_PARITY else OperationMode.READ_ONLY,
                self.candidate, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"),
                ReceiptState.VERIFIED, SEALED_CANARY_RECEIPT_DIGEST, 100, ComparisonResult.PASS,
                parity_digest=None if environment is EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER else digest("6"),
                sealed_canary_receipt_digest=SEALED_CANARY_RECEIPT_DIGEST,
            )
            for environment in CROSS_ENVIRONMENT_LANE_ORDER
        )
        sealed = SealedCanaryReceipt(
            SEALED_CANARY_SOURCE_CANDIDATE_SHA, SEALED_CANARY_RECEIPT_DIGEST,
            SEALED_CANARY_EXECUTION_LEDGER_DIGEST, SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST,
            SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST, "ythdelmar68/roundlet-forward-test",
            SEALED_CANARY_TARGET_MERGE_SHA, SEALED_CANARY_READY_AT,
        )
        return CrossEnvironmentEvidence(self.candidate, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), lanes, sealed)

    def inputs(self, **changes: object) -> Phase4QualificationInputs:
        evidence = self.evidence()
        matrix_areas = {
            ExitEvidenceArea.CANCELLATION, ExitEvidenceArea.STALE_RECOVERY,
            ExitEvidenceArea.LOCKS, ExitEvidenceArea.PATHS, ExitEvidenceArea.WORKTREES,
            ExitEvidenceArea.SQLITE, ExitEvidenceArea.CLI_WRAPPERS,
        }
        defaults: dict[str, object] = {
            "candidate_sha": self.candidate,
            "package_artifact_digest": digest("b"),
            "phase_3_entry_decision_digest": digest("7"),
            "cross_environment_evidence": evidence,
            "cross_environment_comparison": compare_cross_environment_evidence(evidence, evidence),
            "retained_cross_environment_payload": evidence.public_payload(),
            "consumer_topology": ConsumerTopology(digest("b"), digest("b"), 0, 0),
            "exit_evidence": tuple(
                ExitEvidenceReceipt(area, evidence.evidence_digest if area in matrix_areas else digest("89abc"[index - 7]))
                for index, area in enumerate(ExitEvidenceArea)
            ),
        }
        defaults.update(changes)
        return Phase4QualificationInputs(**defaults)  # type: ignore[arg-type]

    def test_passes_only_as_a_non_mutating_phase_5_owner_decision_input(self) -> None:
        decision = assess_phase_4_qualification(self.inputs())
        self.assertEqual(decision.disposition, PHASE_5_OWNER_DECISION_REQUIRED)
        payload = decision.public_payload()
        self.assertEqual((payload["authority"], payload["mutation_count"]), ("owner-decision-required", 0))
        self.assertEqual(payload["historical_ready_at"], SEALED_CANARY_READY_AT)
        self.assertNotIn("roundlet-forward-test", str(payload))

    def test_requires_exact_evidence_candidate_artifact_and_semantic_read_back(self) -> None:
        evidence = self.evidence()
        for changes in (
            {"candidate_sha": "c" * 40},
            {"package_artifact_digest": digest("0")},
            {"cross_environment_comparison": replace(compare_cross_environment_evidence(evidence, evidence), observed_digest=digest("0"))},
            {"retained_cross_environment_payload": {"drift": "value"}},
        ):
            with self.subTest(changes=changes), self.assertRaises(Phase4QualificationError):
                self.inputs(**changes)

    def test_rejects_duplicate_authority_non_artifact_consumers_and_exit_coverage_drift(self) -> None:
        evidence = self.evidence()
        duplicate = tuple(
            replace(lane, mode=OperationMode.AUTHORITATIVE) if lane.environment is EnvironmentKind.LINUX_HOST_PARITY else lane
            for lane in evidence.lanes
        )
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=duplicate)
        with self.assertRaises(Phase4QualificationError):
            self.inputs(consumer_topology=ConsumerTopology(digest("b"), digest("0"), 0, 0))
        with self.assertRaises(Phase4QualificationError):
            self.inputs(exit_evidence=self.inputs().exit_evidence[:-1])

    def test_low_confidence_or_residual_risk_blocks_without_claiming_a_pass(self) -> None:
        self.assertEqual(
            assess_phase_4_qualification(self.inputs(confidence=EvidenceConfidence.LOW)).disposition,
            PHASE_4_QUALIFICATION_BLOCKED,
        )
        decision = assess_phase_4_qualification(self.inputs(residual_risks=("retention-review-needed",)))
        self.assertEqual(decision.disposition, PHASE_4_QUALIFICATION_BLOCKED)
        self.assertEqual(decision.public_payload()["residual_risks"], ["retention-review-needed"])
        self.assertEqual(
            assess_phase_4_qualification(self.inputs(confidence=EvidenceConfidence.CONFLICTING)).public_payload()["confidence"],
            "conflicting",
        )

    def test_public_output_rejects_credential_shaped_residual_risks(self) -> None:
        with self.assertRaises(Phase4QualificationError):
            self.inputs(residual_risks=("github_pat_secret",))

    def test_owner_packet_rechecks_post_construction_drift(self) -> None:
        decision = assess_phase_4_qualification(self.inputs())
        object.__setattr__(decision, "historical_ready_at", SEALED_CANARY_READY_AT + 1)
        with self.assertRaises(Phase4QualificationError):
            decision.public_payload()


if __name__ == "__main__":
    unittest.main()
