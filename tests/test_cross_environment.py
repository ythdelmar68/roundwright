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
    ComparisonResult,
    CrossEnvironmentComparison,
    CrossEnvironmentEvidence,
    CrossEnvironmentEvidenceError,
    EnvironmentKind,
    EnvironmentLane,
    OperationMode,
    ReceiptState,
    compare_cross_environment_evidence,
    semantic_read_back,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class CrossEnvironmentEvidenceTests(unittest.TestCase):
    def lane(self, environment: EnvironmentKind, *, mode: OperationMode = OperationMode.READ_ONLY) -> EnvironmentLane:
        return EnvironmentLane(
            environment, environment.value + "-runner", mode, "a" * 40,
            digest("b"), digest("c"), digest("d"), digest("e"), digest("f"),
            ReceiptState.VERIFIED, digest("1"), 100, ComparisonResult.PASS,
        )

    def evidence(self) -> CrossEnvironmentEvidence:
        lanes = tuple(
            self.lane(environment, mode=OperationMode.AUTHORITATIVE if environment is EnvironmentKind.NATIVE_WINDOWS else OperationMode.READ_ONLY)
            for environment in sorted(EnvironmentKind, key=lambda item: item.value)
        )
        return CrossEnvironmentEvidence("a" * 40, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), lanes)

    def test_schema_uses_one_exact_artifact_across_the_closed_environment_matrix(self) -> None:
        evidence = self.evidence()
        self.assertEqual(evidence.schema, CROSS_ENVIRONMENT_EVIDENCE_SCHEMA)
        self.assertEqual({lane.environment for lane in evidence.lanes}, set(EnvironmentKind))
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
        self.assertNotIn("path", str(blocked.public_payload()))

    def test_rejects_duplicate_authority_across_distinct_environment_lanes(self) -> None:
        evidence = self.evidence()
        duplicate_authority = tuple(
            replace(lane, mode=OperationMode.AUTHORITATIVE)
            if lane.environment is EnvironmentKind.NATIVE_MACOS else lane
            for lane in evidence.lanes
        )
        with self.assertRaises(CrossEnvironmentEvidenceError):
            replace(evidence, lanes=duplicate_authority)

    def test_rejects_secret_shaped_values_in_every_emitted_free_text_field(self) -> None:
        evidence = self.evidence()
        values = ("ghp_abc123", "sk-secret", "github_pat_abc123")
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
