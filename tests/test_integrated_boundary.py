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
    RetainedEvidenceExpectation,
    RetainedEvidenceSource,
    RetainedSourceKind,
    bind_issue_49_retained_evidence,
    compose_retained_evidence,
    phase_3_capability_report,
    source_from_public_payload,
    verify_composed_evidence,
)
from roundwright.configuration import (
    FinalFindingsPolicy, ReviewDisposition, ReviewMode, ReviewOutcome, ReviewPolicy,
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
            "lane_b": replace(self.source(RetainedSourceKind.LANE_B), bundle_digest=self.source(RetainedSourceKind.LANE_B).result_digest),
            "historical_reference": self.source(RetainedSourceKind.HISTORICAL_REFERENCE),
            "synthetic_reference": self.source(RetainedSourceKind.SYNTHETIC_REFERENCE),
        }
        values["expectation"] = RetainedEvidenceExpectation(
            digest("a"), values["lane_a"].result_digest, values["lane_a"].bundle_digest,
            values["lane_b"].result_digest, values["lane_b"].receipt_digest, values["lane_b"].retention_identity,
            values["historical_reference"].source_digest, values["synthetic_reference"].source_digest,
        )
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

    def test_reference_profile_substitution_is_rejected_during_rehydration(self) -> None:
        baseline = self.inputs()
        for source, substituted_profile in (
            (baseline.historical_reference, "roundwright-shadow-profile/executor-contract-synthetic/v1"),
            (baseline.synthetic_reference, "roundwright-shadow-profile/provider-attempt-accounting/v1"),
        ):
            payload = source.public_payload() | {"profile": substituted_profile}
            with self.subTest(kind=source.kind), self.assertRaises(IntegratedBoundaryError):
                source_from_public_payload(payload)

    def test_profile_and_public_capability_report_are_narrow(self) -> None:
        profile = shadow_evidence_profile(INTEGRATED_BOUNDARY_PROFILE)
        self.assertEqual(profile.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(profile.event_kinds, ("composed-evidence-manifest",))
        self.assertEqual(dict(phase_3_capability_report()), {
            "codex-provider-runtime": "supported", "github-mutation-fakes": "test-only",
            "forward-target-observation": "read-only", "deployment-and-daemon": "deferred",
            "merge-release-publication": "prohibited",
        })

    def test_concrete_retained_issue_49_lanes_are_bound_without_source_discovery(self) -> None:
        source_candidate = "57183ea8ed2ee1cd91748b0caa899222f898b3be"
        lane_a_result = {
            "schema": "roundwright-harness-profile-executor-result/v2", "profile": "roundwright-shadow-profile/read-only-external-observation/v1",
            "candidate_sha": source_candidate, "case_id": "issue-49-pr85-lane-a-57183ea-e2-r1-a2-retry-1", "ready_at": 1787551215,
            "plan_digest": "sha256:366ef9deae351370943231d6b581ceeb53961e4a0f3f7a23c926845fff9ffa48",
            "receipt_digest": "sha256:645462107032cc30becc19c67c2d1e05990cb462a4d0598449faf884dcccf028",
            "bundle_digest": "sha256:92386f75f4a39886de6c087e03eb2e7c14bacaa89d74b50e778dde34fcc571bd",
            "retention_identity": "sha256:974b8ad2ec4d79eecb9e6458c24295b537b1ed11bdc19e62a8571e7c9e2eb8a6",
            "recording_receipt_digest": "sha256:7d6871df1cffe486251fcc9a0aabce0ed184f5e46345e4654329fd49fc5efa42",
            "result_identity": digest("1"), "status": "pass", "state": "VERIFIED", "mutation_count": 0,
        }
        lane_a_recording = {
            "schema": "roundwright-harness-recording-receipt/v1", "profile": lane_a_result["profile"],
            "candidate_sha": source_candidate, "case_id": lane_a_result["case_id"], "ready_at": 1787551215,
            "bundle_digest": lane_a_result["bundle_digest"], "receipt_digest": lane_a_result["recording_receipt_digest"],
            "retention_identity": lane_a_result["retention_identity"], "manifest_digest": "sha256:83bde279b1129f134957f859515b317de9de672a4808f4191284df5a753903e2",
            "evidence_digest": digest("2"), "evidence_schema": "roundwright-shadow-case/v2", "status": "sealed",
        }
        lane_b_seal = {
            "schema": "roundwright-harness-lifecycle-seal-receipt/v1", "candidate_sha": source_candidate,
            "ready_at": 1787552443, "plan_digest": "sha256:0ef36d978850e9bdcbbc8ee5a37394f5d25a0c39da9af45bf1ff6d1866e59887",
            "ledger_digest": "sha256:15392e2069f342ff8207a1a886346bd4b5d1f7c59ba8041251524cf073a59c6f",
            "manifest_digest": "sha256:6c0f88dba08a4f420750ad08284a7bffba4b860ba535aba8e85a58d1176d3db9",
            "receipt_digest": "sha256:c157388ca674eaeace6963f14b302cef8270fd280fe725743cf99375c3c43457",
            "retention_identity": "sha256:16363b4efd227c22086743e9b9341de85263e32c1289fc9df0e75d0eda54a118", "status": "sealed",
        }
        historical = replace(self.source(RetainedSourceKind.HISTORICAL_REFERENCE), candidate_sha="c" * 40)
        synthetic = replace(self.source(RetainedSourceKind.SYNTHETIC_REFERENCE), candidate_sha="d" * 40)
        expectation = RetainedEvidenceExpectation(
            "sha256:9ac20eb13933909e5689bd1e843abc61b7485d79659c1b40a17aaccad3675c91",
            lane_a_result["receipt_digest"], lane_a_result["bundle_digest"], lane_b_seal["ledger_digest"],
            lane_b_seal["receipt_digest"], lane_b_seal["retention_identity"], historical.source_digest, synthetic.source_digest,
        )
        inputs = bind_issue_49_retained_evidence(
            candidate_sha="b" * 40, case_id="issue-50-composition", capture_plan_digest=digest("a"),
            expectation=expectation,
            lane_a_result=lane_a_result, lane_a_recording=lane_a_recording, lane_b_seal=lane_b_seal,
            historical_reference=historical.public_payload(), synthetic_reference=synthetic.public_payload(),
        )
        self.assertEqual(inputs.lane_a.result_digest, lane_a_result["receipt_digest"])
        self.assertEqual(inputs.lane_a.bundle_digest, lane_a_result["bundle_digest"])
        self.assertEqual(inputs.lane_b.result_digest, lane_b_seal["ledger_digest"])
        self.assertEqual((inputs.historical_reference.candidate_sha, inputs.synthetic_reference.candidate_sha), ("c" * 40, "d" * 40))
        with self.assertRaises(IntegratedBoundaryError):
            bind_issue_49_retained_evidence(
                candidate_sha="b" * 40, case_id="issue-50-composition", capture_plan_digest=digest("a"),
                expectation=expectation,
                lane_a_result={**lane_a_result, "mutation_count": 1}, lane_a_recording=lane_a_recording,
                lane_b_seal=lane_b_seal, historical_reference=historical.public_payload(), synthetic_reference=synthetic.public_payload(),
            )

    def test_review_policy_keeps_failover_separate_from_complete_and_converging_rounds(self) -> None:
        policy = ReviewPolicy(complete_rounds=1, max_rounds=2, max_supervisor_attempts_per_round=3,
                              on_final_findings=FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        self.assertEqual((policy.mode_for_round(1), policy.mode_for_round(2)), (ReviewMode.COMPLETE, ReviewMode.CONVERGING))
        self.assertEqual(policy.disposition(1, ReviewOutcome.PASS), ReviewDisposition.EARLY_PASS)
        self.assertEqual(policy.disposition(2, ReviewOutcome.FINDINGS), ReviewDisposition.WORKER_FINAL_REPAIR)
        self.assertEqual(
            policy.disposition(2, ReviewOutcome.FINDINGS, worker_finalized=True),
            ReviewDisposition.REVIEW_LIMIT_REACHED_WORKER_FINALIZED,
        )


if __name__ == "__main__":
    unittest.main()
