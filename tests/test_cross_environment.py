"""Hermetic coverage for the Phase 4 cross-environment evidence contract."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.cross_environment import (
    CROSS_ENVIRONMENT_CANARY_PROFILE,
    CROSS_ENVIRONMENT_EVIDENCE_SCHEMA,
    CROSS_ENVIRONMENT_LANE_ORDER,
    ComparisonResult,
    CrossEnvironmentComparison,
    CrossEnvironmentEvidence,
    CrossEnvironmentEvidenceError,
    EnvironmentKind,
    EnvironmentLane,
    OperationMode,
    ReceiptState,
    SealedCanaryReceipt,
    compare_cross_environment_evidence,
    semantic_read_back,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class CrossEnvironmentEvidenceTests(unittest.TestCase):
    def lane(self, environment: EnvironmentKind, *, mode: OperationMode = OperationMode.READ_ONLY) -> EnvironmentLane:
        parity_digest = None if environment is EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER else digest("6")
        return EnvironmentLane(
            environment, environment.value + "-runner", mode, "a" * 40,
            digest("b"), digest("c"), digest("d"), digest("e"), digest("f"),
            ReceiptState.VERIFIED, digest("1"), 100, ComparisonResult.PASS,
            parity_digest=parity_digest, sealed_canary_receipt_digest=digest("1"),
        )

    def evidence(self) -> CrossEnvironmentEvidence:
        lanes = tuple(
            self.lane(environment, mode=OperationMode.AUTHORITATIVE if environment is EnvironmentKind.NATIVE_WINDOWS else OperationMode.READ_ONLY)
            for environment in CROSS_ENVIRONMENT_LANE_ORDER
        )
        sealed = SealedCanaryReceipt(
            "a" * 40, digest("b"), digest("1"), digest("7"), digest("8"),
            digest("9"), "ythdelmar68/roundlet-forward-test", "d" * 40, 100,
        )
        return CrossEnvironmentEvidence("a" * 40, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), lanes, sealed)

    def test_schema_uses_one_exact_artifact_across_the_closed_environment_matrix(self) -> None:
        evidence = self.evidence()
        self.assertEqual(evidence.schema, CROSS_ENVIRONMENT_EVIDENCE_SCHEMA)
        self.assertEqual(tuple(lane.environment for lane in evidence.lanes), CROSS_ENVIRONMENT_LANE_ORDER)
        self.assertEqual({lane.artifact_digest for lane in evidence.lanes}, {digest("b")})
        self.assertEqual(CROSS_ENVIRONMENT_CANARY_PROFILE, "roundwright-shadow-profile/cross-environment-canary/v1")
        self.assertEqual(evidence.result, ComparisonResult.PASS)

    def test_rejects_floating_candidates_inconsistent_artifacts_and_duplicate_lanes(self) -> None:
        evidence = self.evidence()
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence.lanes[0], candidate_sha="main")
        bad_artifact = replace(evidence.lanes[0], artifact_digest=digest("0"))
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=(bad_artifact, *evidence.lanes[1:]))
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=(evidence.lanes[0], evidence.lanes[0], *evidence.lanes[2:]))

    def test_authoritative_mode_requires_verified_receipt_and_nonpassing_lanes_are_bounded(self) -> None:
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(self.lane(EnvironmentKind.CI, mode=OperationMode.AUTHORITATIVE), receipt_state=ReceiptState.BLOCKED, receipt_digest=None, result=ComparisonResult.BLOCKED, reason="receipt-missing")
        blocked = replace(
            self.lane(EnvironmentKind.CI), receipt_state=ReceiptState.BLOCKED,
            receipt_digest=None, result=ComparisonResult.BLOCKED, reason="environment-unavailable",
        )
        self.assertEqual(blocked.result, ComparisonResult.BLOCKED)
        self.assertNotIn("C:\\", str(blocked.public_payload()))

    def test_rejects_duplicate_authority_across_distinct_environment_lanes(self) -> None:
        evidence = self.evidence()
        duplicate_authority = tuple(
            replace(lane, mode=OperationMode.AUTHORITATIVE)
            if lane.environment is EnvironmentKind.NATIVE_MACOS else lane
            for lane in evidence.lanes
        )
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=duplicate_authority)

    def test_requires_the_sealed_canary_for_every_lane_and_a_read_only_consumer(self) -> None:
        evidence = self.evidence()
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=(replace(evidence.lanes[0], sealed_canary_receipt_digest=digest("0")), *evidence.lanes[1:]))
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=(*evidence.lanes[:-1], replace(evidence.lanes[-1], mode=OperationMode.TEST_ONLY)))
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=(replace(evidence.lanes[0], parity_digest=digest("0")), *evidence.lanes[1:]))

    def test_revalidates_a_mutated_sealed_receipt_before_public_rendering(self) -> None:
        evidence = self.evidence()
        object.__setattr__(evidence.sealed_canary, "target_repository", "other/target")
        with self.assertRaises(CrossEnvironmentEvidenceError):
            evidence.public_payload()

    def test_rejects_secret_shaped_values_in_every_emitted_free_text_field(self) -> None:
        evidence = self.evidence()
        values = (
            "ghp_abc123", "gho_abc123", "ghu_abc123", "ghs_abc123", "ghr_abc123",
            "github_pat_abc123", "sk-live-abc123", "sk-proj-abc123",
            "safe-github_pat_abc123", "safe-sk-proj-abc123",
        )
        for value in values:
            with self.subTest(field="environment_identity", value=value), self.assertRaises(CrossEnvironmentEvidenceError):
                replace(evidence.lanes[0], environment_identity=value)
            with self.subTest(field="reason", value=value), self.assertRaises(CrossEnvironmentEvidenceError):
                replace(
                    evidence.lanes[0], receipt_state=ReceiptState.BLOCKED, receipt_digest=None,
                    result=ComparisonResult.BLOCKED, reason=value,
                )
            with self.subTest(field="differences", value=value), self.assertRaises(CrossEnvironmentEvidenceError):
                CrossEnvironmentComparison(ComparisonResult.BLOCKED, "a" * 40, digest("1"), digest("2"), (value,))

    def test_revalidates_mutated_nested_lanes_before_projection_or_retention(self) -> None:
        evidence = self.evidence()
        retained = evidence.public_payload()
        lane = evidence.lanes[0]
        object.__setattr__(lane, "environment_identity", "ghp_bypassed")
        with self.assertRaises(CrossEnvironmentEvidenceError):
            evidence.public_payload()

        evidence = self.evidence()
        lane = evidence.lanes[0]
        object.__setattr__(lane, "receipt_state", ReceiptState.BLOCKED)
        object.__setattr__(lane, "receipt_digest", None)
        object.__setattr__(lane, "result", ComparisonResult.BLOCKED)
        object.__setattr__(lane, "reason", "github_pat_bypassed")
        with self.assertRaises(CrossEnvironmentEvidenceError):
            semantic_read_back(retained, evidence)

    def test_rejects_a_non_enum_comparison_result_before_public_rendering(self) -> None:
        with self.assertRaises(CrossEnvironmentEvidenceError):
            CrossEnvironmentComparison("blocked", "a" * 40, digest("1"), digest("2"), ("lane-mismatch",))  # type: ignore[arg-type]

    def test_comparison_and_retention_read_back_are_deterministic_and_public_safe(self) -> None:
        evidence = self.evidence()
        comparison = compare_cross_environment_evidence(evidence, evidence)
        self.assertEqual(comparison.result, ComparisonResult.PASS)
        self.assertEqual(comparison.differences, ())
        self.assertEqual(semantic_read_back(evidence.public_payload(), evidence), comparison)
        retained = evidence.public_payload()
        retained["artifact_digest"] = digest("0")
        read_back = semantic_read_back(retained, evidence)
        self.assertEqual((read_back.result, read_back.differences), (ComparisonResult.BLOCKED, ("retention-readback-mismatch",)))

    def test_comparison_rejects_lane_substitution_without_exposing_lane_contents(self) -> None:
        evidence = self.evidence()
        changed = replace(evidence.lanes[0], result=ComparisonResult.REJECTED, reason="unsupported-environment")
        observed = replace(evidence, lanes=(changed, *evidence.lanes[1:]))
        comparison = compare_cross_environment_evidence(evidence, observed)
        self.assertEqual(comparison.result, ComparisonResult.REJECTED)
        self.assertEqual(comparison.differences, ("lane-mismatch", "observed-rejected"))


if __name__ == "__main__":
    unittest.main()
