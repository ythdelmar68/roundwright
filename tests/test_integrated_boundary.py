"""Composed-evidence boundary coverage for issue #50."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.integrated_boundary import (
    IntegratedBoundaryError,
    IntegratedBoundaryInputs,
    RetainedEvidenceSource,
    RetainedSourceKind,
    compose_retained_evidence,
    phase_3_capability_report,
    verify_composed_evidence,
)
from roundwright.shadow import INTEGRATED_BOUNDARY_PROFILE, CaptureMode, shadow_evidence_profile


def digest(character: str) -> str:
    return "sha256:" + character * 64


class IntegratedBoundaryTests(unittest.TestCase):
    candidate = "a" * 40

    def source(self, kind: RetainedSourceKind) -> RetainedEvidenceSource:
        profile = {
            RetainedSourceKind.LANE_A: "roundwright-shadow-profile/read-only-external-observation/v1",
            RetainedSourceKind.LANE_B: "roundwright-shadow-profile/live-lifecycle-shadow/v1",
            RetainedSourceKind.HISTORICAL_REFERENCE: "roundwright-shadow-profile/provider-attempt-accounting/v1",
            RetainedSourceKind.SYNTHETIC_REFERENCE: "roundwright-shadow-profile/executor-contract-synthetic/v1",
        }[kind]
        digests = {
            RetainedSourceKind.LANE_A: ("0", "1", "2", "3", "4", "5"),
            RetainedSourceKind.LANE_B: ("6", "7", "8", "9", "a", "b"),
            RetainedSourceKind.HISTORICAL_REFERENCE: ("c", "d", "e", "f", "0", "1"),
            RetainedSourceKind.SYNTHETIC_REFERENCE: ("2", "3", "4", "5", "6", "7"),
        }[kind]
        return RetainedEvidenceSource(
            kind, profile, self.candidate, f"case-{kind.value}", 17,
            *(digest(character) for character in digests),
        )

    def inputs(self, **changes: object) -> IntegratedBoundaryInputs:
        values: dict[str, object] = {
            "candidate_sha": "b" * 40, "case_id": "integrated-boundary-50", "capture_plan_digest": digest("a"),
            "lane_a": self.source(RetainedSourceKind.LANE_A),
            "lane_b": self.source(RetainedSourceKind.LANE_B),
            "historical_reference": self.source(RetainedSourceKind.HISTORICAL_REFERENCE),
            "synthetic_reference": self.source(RetainedSourceKind.SYNTHETIC_REFERENCE),
        }
        values.update(changes)
        return IntegratedBoundaryInputs(**values)  # type: ignore[arg-type]

    def test_composes_four_distinct_retained_sources_without_live_actions(self) -> None:
        manifest, result = compose_retained_evidence(self.inputs())
        self.assertTrue(verify_composed_evidence(manifest, result))
        payload = manifest.public_payload()
        self.assertEqual(payload["profile"], INTEGRATED_BOUNDARY_PROFILE)
        self.assertEqual(tuple(item["kind"] for item in payload["sources"]), tuple(kind.value for kind in RetainedSourceKind))
        self.assertEqual((payload["new_provider_calls"], payload["new_target_actions"], payload["lifecycle_observation_sink"]), (0, 0, "NOT_SELECTED"))
        self.assertEqual(result.public_payload()["status"], "pass")

    def test_duplicate_or_mixed_lane_evidence_fails_closed(self) -> None:
        baseline = self.inputs()
        for changes in (
            {"lane_b": baseline.lane_a},
            {"historical_reference": replace(baseline.historical_reference, candidate_sha="c" * 40)},
            {"synthetic_reference": replace(baseline.synthetic_reference, receipt_digest=baseline.lane_b.receipt_digest)},
        ):
            with self.subTest(changes=changes), self.assertRaises(IntegratedBoundaryError):
                self.inputs(**changes)

    def test_lane_profile_substitution_and_nonzero_mutation_are_rejected(self) -> None:
        with self.assertRaises(IntegratedBoundaryError):
            self.source(RetainedSourceKind.LANE_A).__class__(
                RetainedSourceKind.LANE_A, "roundwright-shadow-profile/live-lifecycle-shadow/v1", self.candidate,
                "case-lane-a", 17, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), digest("0"), mutation_count=1,
            )

    def test_profile_and_public_capability_report_are_narrow(self) -> None:
        profile = shadow_evidence_profile(INTEGRATED_BOUNDARY_PROFILE)
        self.assertEqual(profile.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(profile.event_kinds, ("composed-evidence-manifest",))
        self.assertEqual(dict(phase_3_capability_report()), {
            "codex-provider-runtime": "supported", "github-mutation-fakes": "test-only",
            "forward-target-observation": "read-only", "deployment-and-daemon": "deferred",
            "merge-release-publication": "prohibited",
        })


if __name__ == "__main__":
    unittest.main()
