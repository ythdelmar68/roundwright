from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.external_validation import EvidenceLaneReceipt
from roundwright.integrated_boundary import IntegratedBoundaryInputs, RetainedEvidenceExpectation, RetainedEvidenceSource, RetainedSourceKind, compose_retained_evidence, source_from_public_payload
from roundwright.qualification_gate import (
    PROMOTION_READY_FOR_CANARY_DECISION,
    QUALIFICATION_BLOCKED,
    Phase3QualificationInputs,
    QualificationGateKind,
    QualificationGateAuthority,
    QualificationGateReceipt,
    QualificationGateReceiptSet,
    QualificationGateError,
    RetainedEvidenceBinding,
    RetainedEvidenceObservations,
    RetainedEvidencePins,
    RetainedIssue50BundleReceipt,
    TemporaryResourceDisposition,
    TemporaryResourceEntry,
    TemporaryResourceInventory,
    TemporaryResourceKind,
    assess_phase_3_qualification,
    issue_51_selection_trace_correction,
    VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST,
    VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST,
    VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST,
)
from roundwright.shadow import LIVE_LIFECYCLE_SHADOW_PROFILE, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE


def digest(value: int) -> str:
    return f"sha256:{value:064x}"


def canonical(value: dict[str, object]) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def gate_source(kind: QualificationGateKind, candidate_sha: str, case_id: str, epoch: int, round_: int, identity: str) -> dict[str, object]:
    value: dict[str, object] = {
        "candidate_sha": candidate_sha, "case_id": case_id, "review_epoch": epoch,
        "review_round": round_, "review_mode": "COMPLETE" if 1 <= round_ <= 3 else "CONVERGING",
    }
    if kind is QualificationGateKind.FORMAL_REVIEW:
        value |= {"schema": "roundwright-formal-review-receipt/v1", "formal_result": "accepted", "supervisor_verdict": "PASS", "supervisor_result_identity": identity}
    elif kind is QualificationGateKind.HOSTED_CHECKS:
        value |= {"schema": "roundwright-exact-head-check-receipt/v1", "head_sha": candidate_sha, "check_run_identity": identity, "conclusion": "success"}
    elif kind is QualificationGateKind.POLICY:
        value |= {"schema": "roundwright-policy-receipt/v1", "policy_snapshot_digest": identity, "policy_outcome": "pass"}
    else:
        value |= {"schema": "roundwright-provenance-receipt/v1", "source_sha": candidate_sha, "provenance_manifest_digest": identity, "verification": "pass"}
    return value | {"receipt_digest": canonical(value)}


def final_repair_source(candidate_sha: str, supervisor_candidate_sha: str, case_id: str, identity: int) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "roundwright-formal-review-final-repair-receipt/v1",
        "candidate_sha": candidate_sha, "resulting_candidate_sha": candidate_sha,
        "supervisor_candidate_sha": supervisor_candidate_sha, "case_id": case_id,
        "review_epoch": 1, "review_round": 10, "review_mode": "CONVERGING",
        "formal_result": "accepted", "supervisor_verdict": "FINDINGS",
        "supervisor_result_identity": digest(identity), "final_repair_handoff_identity": digest(identity + 1),
        "terminal_receipt_identity": digest(identity + 2), "worker_identity": digest(identity + 3),
        "configuration_identity": digest(identity + 4), "review_policy_identity": digest(identity + 5),
        "candidate_lineage_identity": digest(identity + 6),
        "terminal_state": "REVIEW_LIMIT_REACHED_WORKER_FINALIZED",
    }
    return value | {"receipt_digest": canonical(value)}


_FIXTURES = Path(__file__).with_name("fixtures")


def issue_50_bundle_receipt() -> RetainedIssue50BundleReceipt:
    return RetainedIssue50BundleReceipt(
        json.loads((_FIXTURES / "issue_50_result_receipt.json").read_text()),
        json.loads((_FIXTURES / "issue_50_recording_receipt.json").read_text()),
        (_FIXTURES / "issue_50_retained_bundle.json").read_bytes(),
    )


def retained_issue_50_inputs() -> tuple[IntegratedBoundaryInputs, object, object]:
    bundle = json.loads((_FIXTURES / "issue_50_retained_bundle.json").read_text())
    integrated = bundle["evidence"]["integrated_boundary"]
    manifest = integrated["manifest"]
    sources = {item["kind"]: source_from_public_payload(item) for item in manifest["sources"]}
    expected = manifest["expected_source_digests"]
    expectation = RetainedEvidenceExpectation(
        manifest["retention_manifest_digest"], expected["lane_a_result_digest"], expected["lane_a_bundle_digest"],
        expected["lane_b_ledger_digest"], expected["lane_b_seal_digest"], expected["lane_b_retention_identity"],
        expected["lane_b_qualification_digest"], expected["historical_reference_digest"], expected["synthetic_reference_digest"],
    )
    inputs = IntegratedBoundaryInputs(manifest["candidate_sha"], manifest["case_id"], manifest["capture_plan_digest"], expectation, sources["lane-a"], sources["lane-b"], sources["historical-reference"], sources["synthetic-reference"])
    return (inputs, *compose_retained_evidence(inputs))


class Phase3QualificationGateTests(unittest.TestCase):
    issue_49_candidate = "57183ea8ed2ee1cd91748b0caa899222f898b3be"
    issue_50_candidate = "649039e39dc1481b1683f822dd9f33ce1a5c4839"
    qualification_candidate = "c" * 40

    def source(self, kind: RetainedSourceKind, value: int) -> RetainedEvidenceSource:
        profile = {
            RetainedSourceKind.LANE_A: READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
            RetainedSourceKind.LANE_B: LIVE_LIFECYCLE_SHADOW_PROFILE,
            RetainedSourceKind.HISTORICAL_REFERENCE: "roundwright-shadow-profile/provider-attempt-accounting/v1",
            RetainedSourceKind.SYNTHETIC_REFERENCE: "roundwright-shadow-profile/executor-contract-synthetic/v1",
        }[kind]
        return RetainedEvidenceSource(kind, profile, self.issue_49_candidate, f"case-{value}", value, *(digest(value + offset) for offset in (0, 10, 20, 30, 40, 50)))

    def gate_authority(self) -> QualificationGateAuthority:
        return QualificationGateAuthority(tuple(
            gate_source(kind, self.qualification_candidate, "issue-51-qualification", 1, 1, authority_identity)
            for kind, authority_identity in zip(QualificationGateKind, (digest(78), digest(79), digest(97), digest(98)), strict=True)
        ))

    def inputs(self, **changes: object) -> Phase3QualificationInputs:
        retained, manifest, result = retained_issue_50_inputs()
        bundle_receipt = issue_50_bundle_receipt()
        pins = RetainedEvidencePins(
            retained.expectation.retention_manifest_digest,
            bundle_receipt.issue_50_retention_manifest_digest,
            VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST,
        )
        resources = TemporaryResourceInventory((
            TemporaryResourceEntry(digest(94), TemporaryResourceKind.REPLAYABLE, TemporaryResourceDisposition.REMOVED),
        ))
        authorities = self.gate_authority()
        values = {
            "base_sha": "d" * 40, "qualification_candidate_sha": self.qualification_candidate,
            "qualification_case_id": "issue-51-qualification", "qualification_ready_at": 23,
            "qualification_review_epoch": 1, "qualification_review_round": 1, "qualification_review_mode": "COMPLETE",
            "qualification_capture_plan_digest": digest(79),
            "qualification_recorder_identity": digest(78), "qualification_store_identity": digest(77),
            "issue_49_candidate_sha": self.issue_49_candidate, "issue_50_candidate_sha": self.issue_50_candidate,
            "roundlet_commit": "d" * 40, "harness_commit": "e" * 40, "forward_target_commit": "f" * 40,
            "rollback_proposal_digest": digest(97), "kill_switch_proposal_digest": digest(98),
            "retained_evidence": RetainedEvidenceBinding(pins, RetainedEvidenceObservations(*pins.payload().values())),
            "issue_50_bundle_receipt": bundle_receipt,
            "temporary_resources": resources, "integrated_inputs": retained, "composed_manifest": manifest, "composed_result": result,
            "lane_a": EvidenceLaneReceipt(READ_ONLY_EXTERNAL_OBSERVATION_PROFILE, self.issue_49_candidate, "verified", "pass"),
            "lane_b": EvidenceLaneReceipt(LIVE_LIFECYCLE_SHADOW_PROFILE, self.issue_49_candidate, "verified", "pass"),
            "current_gate_receipts": QualificationGateReceiptSet(tuple(
                QualificationGateReceipt(kind, self.qualification_candidate, "issue-51-qualification", 1, 1, "COMPLETE", "pass", receipt)
                for kind, receipt in zip(QualificationGateKind, authorities.receipts, strict=True)
            )),
        }
        values.update(changes)
        return Phase3QualificationInputs(**values)

    def test_distinct_generations_produce_only_owner_decision(self) -> None:
        decision = assess_phase_3_qualification(self.inputs(), self.gate_authority())
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
        resources = TemporaryResourceInventory((
            TemporaryResourceEntry(digest(95), TemporaryResourceKind.UNIQUE, TemporaryResourceDisposition.PRESERVED),
        ))
        self.assertEqual(assess_phase_3_qualification(self.inputs(temporary_resources=resources), self.gate_authority()).disposition, QUALIFICATION_BLOCKED)

    def test_retained_expected_and_observed_pins_reject_substitution(self) -> None:
        inputs = self.inputs()
        with self.assertRaises(QualificationGateError):
            RetainedEvidenceBinding(inputs.retained_evidence.expected, RetainedEvidenceObservations(digest(77), digest(92), digest(93)))
        object.__setattr__(inputs.retained_evidence.observed, "issue_50_result_bundle_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)

    def test_retained_manifest_generations_are_distinct_and_closed(self) -> None:
        inputs = self.inputs()
        expected = inputs.retained_evidence.expected
        self.assertEqual(
            (expected.issue_49_retention_manifest_digest, expected.issue_50_retention_manifest_digest),
            (VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST, VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST),
        )
        self.assertEqual(
            (inputs.issue_50_bundle_receipt.issue_49_retention_manifest_digest,
             inputs.issue_50_bundle_receipt.issue_50_retention_manifest_digest),
            (VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST, VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST),
        )
        for issue_49, issue_50 in (
            (expected.issue_50_retention_manifest_digest, expected.issue_49_retention_manifest_digest),
            (expected.issue_49_retention_manifest_digest, expected.issue_49_retention_manifest_digest),
            (expected.issue_50_retention_manifest_digest, expected.issue_50_retention_manifest_digest),
        ):
            with self.subTest(issue_49=issue_49, issue_50=issue_50):
                pins = RetainedEvidencePins(issue_49, issue_50, expected.issue_50_result_bundle_digest)
                binding = RetainedEvidenceBinding(pins, RetainedEvidenceObservations(*pins.payload().values()))
                with self.assertRaises(QualificationGateError):
                    self.inputs(retained_evidence=binding)

    def test_gate_receipts_reject_digest_only_and_duplicated_source_assertions(self) -> None:
        with self.assertRaises(QualificationGateError):
            QualificationGateReceipt(
                QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                "issue-51-qualification", 1, 1, "COMPLETE", "pass", digest(100),  # type: ignore[arg-type]
            )
        source = gate_source(QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate, "issue-51-qualification", 1, 1, digest(100))
        with self.assertRaises(QualificationGateError):
            QualificationGateReceipt(
                QualificationGateKind.HOSTED_CHECKS, self.qualification_candidate,
                "issue-51-qualification", 1, 1, "COMPLETE", "pass", source,
            )
        fabricated = QualificationGateReceiptSet(tuple(
            QualificationGateReceipt(kind, self.qualification_candidate, "issue-51-qualification", 1, 1, "COMPLETE", "pass", gate_source(kind, self.qualification_candidate, "issue-51-qualification", 1, 1, digest(110 + index)))
            for index, kind in enumerate(QualificationGateKind)
        ))
        inputs = self.inputs(current_gate_receipts=fabricated)
        self.assertFalse(hasattr(inputs, "gate_authorities"))
        with self.assertRaises(QualificationGateError):
            assess_phase_3_qualification(inputs, self.gate_authority())

    def test_formal_review_gate_derives_pass_only_from_supervisor_pass(self) -> None:
        source = gate_source(
            QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
            "issue-51-qualification", 1, 1, digest(100),
        )
        accepted_findings = {**source, "supervisor_verdict": "FINDINGS"}
        accepted_findings["receipt_digest"] = canonical({
            key: value for key, value in accepted_findings.items() if key != "receipt_digest"
        })
        with self.assertRaises(QualificationGateError):
            QualificationGateReceipt(
                QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                "issue-51-qualification", 1, 1, "COMPLETE", "pass", accepted_findings,
            )
        missing_verdict = {key: value for key, value in source.items() if key != "supervisor_verdict"}
        missing_verdict["receipt_digest"] = canonical({
            key: value for key, value in missing_verdict.items() if key != "receipt_digest"
        })
        with self.assertRaises(QualificationGateError):
            QualificationGateReceipt(
                QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                "issue-51-qualification", 1, 1, "COMPLETE", "pass", missing_verdict,
            )

    def test_round_ten_final_repair_source_is_a_distinct_valid_formal_path(self) -> None:
        supervisor_candidate = "b" * 40
        formal = final_repair_source(self.qualification_candidate, supervisor_candidate, "issue-51-qualification", 150)
        authority = QualificationGateAuthority((
            formal,
            *(gate_source(kind, self.qualification_candidate, "issue-51-qualification", 1, 10, digest(160 + index))
              for index, kind in enumerate(tuple(QualificationGateKind)[1:])),
        ))
        current_gates = QualificationGateReceiptSet(tuple(
            QualificationGateReceipt(kind, self.qualification_candidate, "issue-51-qualification", 1, 10, "CONVERGING", "pass", source)
            for kind, source in zip(QualificationGateKind, authority.receipts, strict=True)
        ))
        inputs = self.inputs(
            qualification_review_round=10, qualification_review_mode="CONVERGING", current_gate_receipts=current_gates,
        )
        self.assertEqual(assess_phase_3_qualification(inputs, authority).disposition, PROMOTION_READY_FOR_CANARY_DECISION)

    def test_round_ten_final_repair_source_rejects_ambiguous_or_drifted_bindings(self) -> None:
        source = final_repair_source(self.qualification_candidate, "b" * 40, "issue-51-qualification", 180)

        def rebuilt(**changes: object) -> dict[str, object]:
            value = {key: item for key, item in source.items() if key != "receipt_digest"}
            value.update(changes)
            return value | {"receipt_digest": canonical(value)}

        def missing(field: str) -> dict[str, object]:
            value = {key: item for key, item in source.items() if key not in {"receipt_digest", field}}
            return value | {"receipt_digest": canonical(value)}

        invalid = (
            *(missing(field) for field in (
                "candidate_sha", "resulting_candidate_sha", "supervisor_candidate_sha", "case_id",
                "review_epoch", "review_round", "review_mode", "formal_result", "supervisor_verdict",
                "supervisor_result_identity", "final_repair_handoff_identity", "terminal_receipt_identity",
                "worker_identity", "configuration_identity", "review_policy_identity", "candidate_lineage_identity",
                "terminal_state",
            )),
            rebuilt(candidate_sha="d" * 40),
            rebuilt(resulting_candidate_sha="d" * 40),
            rebuilt(supervisor_candidate_sha=self.qualification_candidate),
            rebuilt(review_epoch=2),
            rebuilt(review_round=9, review_mode="CONVERGING"),
            rebuilt(review_mode="COMPLETE"),
            rebuilt(supervisor_result_identity="sha256:" + "z" * 64),
            rebuilt(final_repair_handoff_identity="sha256:" + "z" * 64),
            rebuilt(supervisor_verdict="PASS"),
            {"schema": source["schema"], "candidate_sha": self.qualification_candidate,
             "review_epoch": 1, "review_round": 10, "review_mode": "CONVERGING",
             "terminal_state": "REVIEW_LIMIT_REACHED_WORKER_FINALIZED", "receipt_digest": digest(199)},
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(QualificationGateError):
                    QualificationGateReceipt(
                        QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                        "issue-51-qualification", 1, 10, "CONVERGING", "pass", value,
                    )

        authority = QualificationGateAuthority((
            source,
            *(gate_source(kind, self.qualification_candidate, "issue-51-qualification", 1, 10, digest(220 + index))
              for index, kind in enumerate(tuple(QualificationGateKind)[1:])),
        ))
        for field, value in (
            ("supervisor_candidate_sha", "e" * 40),
            ("supervisor_result_identity", digest(230)),
            ("final_repair_handoff_identity", digest(231)),
            ("terminal_receipt_identity", digest(232)),
            ("worker_identity", digest(233)),
            ("configuration_identity", digest(234)),
            ("review_policy_identity", digest(235)),
            ("candidate_lineage_identity", digest(236)),
        ):
            with self.subTest(substituted_field=field):
                substituted = rebuilt(**{field: value})
                receipts = QualificationGateReceiptSet((
                    QualificationGateReceipt(
                        QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                        "issue-51-qualification", 1, 10, "CONVERGING", "pass", substituted,
                    ),
                    *(QualificationGateReceipt(
                        kind, self.qualification_candidate, "issue-51-qualification", 1, 10, "CONVERGING", "pass", receipt,
                    ) for kind, receipt in zip(tuple(QualificationGateKind)[1:], authority.receipts[1:], strict=True)),
                ))
                with self.assertRaises(QualificationGateError):
                    receipts.validate_for(self.qualification_candidate, "issue-51-qualification", authority)

    def test_review_epoch_round_modes_are_bounded_and_exact(self) -> None:
        for round_, mode in ((1, "COMPLETE"), (3, "COMPLETE"), (4, "CONVERGING"), (10, "CONVERGING")):
            with self.subTest(round=round_):
                source = gate_source(
                    QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                    "issue-51-qualification", 1, round_, digest(100 + round_),
                )
                receipt = QualificationGateReceipt(
                    QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                    "issue-51-qualification", 1, round_, mode, "pass", source,
                )
                self.assertEqual(receipt.review_mode, mode)
        for epoch, round_, mode in ((0, 1, "COMPLETE"), (1, 0, "COMPLETE"), (1, 11, "CONVERGING"), (1, 4, "COMPLETE")):
            with self.subTest(epoch=epoch, round=round_, mode=mode), self.assertRaises(QualificationGateError):
                QualificationGateReceipt(
                    QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                    "issue-51-qualification", epoch, round_, mode, "pass",
                    gate_source(QualificationGateKind.FORMAL_REVIEW, self.qualification_candidate,
                                "issue-51-qualification", epoch, round_, digest(120 + max(round_, 0))),
                )
        authority = QualificationGateAuthority(tuple(
            gate_source(kind, self.qualification_candidate, "issue-51-qualification", 1, 10, digest(140 + index))
            for index, kind in enumerate(QualificationGateKind)
        ))
        current_gates = QualificationGateReceiptSet(tuple(
            QualificationGateReceipt(kind, self.qualification_candidate, "issue-51-qualification", 1, 10, "CONVERGING", "pass", source)
            for kind, source in zip(QualificationGateKind, authority.receipts, strict=True)
        ))
        inputs = self.inputs(
            qualification_review_round=10, qualification_review_mode="CONVERGING", current_gate_receipts=current_gates,
        )
        self.assertEqual(assess_phase_3_qualification(inputs, authority).disposition, PROMOTION_READY_FOR_CANARY_DECISION)
        with self.assertRaises(QualificationGateError):
            self.inputs(qualification_review_round=4, qualification_review_mode="COMPLETE")

    def test_trace_correction_uses_only_verified_issue_50_digest(self) -> None:
        correction = issue_51_selection_trace_correction()
        self.assertEqual(correction["verified_digest"], "sha256:5046fd4eed52db54f6b797464bf4faf4082290ec9cf12d3de194f624f8ca8d8a")
        self.assertNotEqual(correction["recorded_digest"], correction["verified_digest"])
        inputs = self.inputs()
        object.__setattr__(inputs.retained_evidence, "binding_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            replace(inputs)

    def test_retained_issue_50_bundle_and_blockers_are_closed(self) -> None:
        inputs = self.inputs()
        with self.assertRaises(QualificationGateError):
            RetainedIssue50BundleReceipt(
                inputs.issue_50_bundle_receipt.harness_result,
                inputs.issue_50_bundle_receipt.recording_receipt,
                inputs.issue_50_bundle_receipt.bundle_bytes.replace(
                    b'"schema":"roundwright-harness-recording-bundle/v1"',
                    b'"schema":"roundwright-harness-recording-bundle/x1"',
                ),
            )
        with self.assertRaises(QualificationGateError):
            RetainedIssue50BundleReceipt(
                {**inputs.issue_50_bundle_receipt.harness_result, "recording_receipt_digest": digest(72)},
                inputs.issue_50_bundle_receipt.recording_receipt,
                inputs.issue_50_bundle_receipt.bundle_bytes,
            )
        changed_result = {**inputs.issue_50_bundle_receipt.harness_result, "dispatch_count": 2}
        changed_result["receipt_digest"] = canonical({key: value for key, value in changed_result.items() if key != "receipt_digest"})
        with self.assertRaises(QualificationGateError):
            RetainedIssue50BundleReceipt(
                changed_result, inputs.issue_50_bundle_receipt.recording_receipt,
                inputs.issue_50_bundle_receipt.bundle_bytes,
            )
        for index, field in enumerate((
            "plan_digest", "readiness_receipt_digest", "result_identity",
            "execution_context_input_digest", "execution_context_identity",
        ), start=201):
            with self.subTest(retained_result_identity=field):
                changed_result = {**inputs.issue_50_bundle_receipt.harness_result, field: digest(index)}
                changed_result["receipt_digest"] = canonical({
                    key: value for key, value in changed_result.items() if key != "receipt_digest"
                })
                with self.assertRaises(QualificationGateError):
                    RetainedIssue50BundleReceipt(
                        changed_result, inputs.issue_50_bundle_receipt.recording_receipt,
                        inputs.issue_50_bundle_receipt.bundle_bytes,
                    )
        with self.assertRaises(QualificationGateError):
            self.inputs(unresolved_blockers=("C:\\secret\nvalue",))  # type: ignore[arg-type]
        first = inputs.current_gate_receipts.receipts[0]
        stale_first = QualificationGateReceipt(
            first.kind, first.candidate_sha, first.case_id, first.review_epoch,
            2, first.review_mode, first.result,
            gate_source(first.kind, first.candidate_sha, first.case_id, first.review_epoch, 2, digest(78)),
        )
        stale_receipts = QualificationGateReceiptSet((
            stale_first, *inputs.current_gate_receipts.receipts[1:],
        ))
        with self.assertRaises(QualificationGateError):
            self.inputs(current_gate_receipts=stale_receipts)

    def test_inventory_reconciles_replayable_and_preserves_unique_or_ambiguous_work(self) -> None:
        resources = TemporaryResourceInventory((
            TemporaryResourceEntry(digest(94), TemporaryResourceKind.REPLAYABLE, TemporaryResourceDisposition.REMOVED),
            TemporaryResourceEntry(digest(95), TemporaryResourceKind.UNIQUE, TemporaryResourceDisposition.PRESERVED),
            TemporaryResourceEntry(digest(96), TemporaryResourceKind.AMBIGUOUS, TemporaryResourceDisposition.PRESERVED),
        ))
        self.assertTrue(resources.fully_reconciled)
        self.assertFalse(resources.promotion_eligible)
        self.assertEqual(tuple(entry.disposition.value for entry in resources.entries), ("removed", "preserved", "preserved"))
        self.assertEqual(assess_phase_3_qualification(self.inputs(temporary_resources=resources), self.gate_authority()).disposition, QUALIFICATION_BLOCKED)
        with self.assertRaises(QualificationGateError):
            TemporaryResourceEntry(digest(97), TemporaryResourceKind.UNIQUE, TemporaryResourceDisposition.REMOVED)
        object.__setattr__(resources, "inventory_digest", digest(77))
        with self.assertRaises(QualificationGateError):
            resources.validate()
        object.__setattr__(resources.entries[1], "disposition", TemporaryResourceDisposition.REMOVED)
        with self.assertRaises(QualificationGateError):
            resources.validate()
