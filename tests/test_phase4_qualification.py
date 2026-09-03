"""Hermetic adversarial coverage for the Issue #98 retained-evidence gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.cross_environment import (
    CROSS_ENVIRONMENT_CANARY_PROFILE, CROSS_ENVIRONMENT_LANE_ORDER, ComparisonResult,
    CrossEnvironmentEvidence, EnvironmentKind, EnvironmentLane, OperationMode, ReceiptState,
    SEALED_CANARY_EXECUTION_LEDGER_DIGEST, SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST,
    SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST, SEALED_CANARY_READY_AT,
    SEALED_CANARY_RECEIPT_DIGEST, SEALED_CANARY_SOURCE_CANDIDATE_SHA,
    SEALED_CANARY_TARGET_MERGE_SHA, SealedCanaryReceipt, compare_cross_environment_evidence,
)
from roundwright.phase4_qualification import (
    ISSUE_97_EVIDENCE_CANDIDATE_SHA, PHASE_3_DECISION_SCHEMA, PHASE_3_QUALIFICATION_PROFILE,
    PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA, PHASE_4_EXIT_RECEIPT_SCHEMA,
    PHASE_4_QUALIFICATION_BLOCKED, PHASE_4_RETAINED_EVIDENCE_SCHEMA,
    PHASE_5_OWNER_DECISION_REQUIRED, EvidenceConfidence, ExitEvidenceArea,
    Phase4QualificationError, Phase4QualificationInputs, Phase4SelectionPins,
    assess_phase_4_qualification,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def canonical(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class Phase4QualificationTests(unittest.TestCase):
    qualification_candidate = "b" * 40

    def evidence(self, candidate: str = ISSUE_97_EVIDENCE_CANDIDATE_SHA) -> CrossEnvironmentEvidence:
        lanes = tuple(
            EnvironmentLane(
                environment, environment.value + "-runner",
                OperationMode.AUTHORITATIVE if environment is EnvironmentKind.WINDOWS_HOST_PARITY else OperationMode.READ_ONLY,
                candidate, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"),
                ReceiptState.VERIFIED, SEALED_CANARY_RECEIPT_DIGEST, 100, ComparisonResult.PASS,
                parity_digest=None if environment is EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER else digest("6"),
                sealed_canary_receipt_digest=SEALED_CANARY_RECEIPT_DIGEST,
            ) for environment in CROSS_ENVIRONMENT_LANE_ORDER
        )
        sealed = SealedCanaryReceipt(
            SEALED_CANARY_SOURCE_CANDIDATE_SHA, SEALED_CANARY_RECEIPT_DIGEST,
            SEALED_CANARY_EXECUTION_LEDGER_DIGEST, SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST,
            SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST, "ythdelmar68/roundlet-forward-test",
            SEALED_CANARY_TARGET_MERGE_SHA, SEALED_CANARY_READY_AT,
        )
        return CrossEnvironmentEvidence(candidate, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), lanes, sealed)

    def retained_bundle(self, *, confidence: str = "high", risks: list[str] | None = None) -> tuple[bytes, Phase4SelectionPins]:
        evidence = self.evidence()
        comparison = compare_cross_environment_evidence(evidence, evidence)
        phase_3_core = {
            "schema": PHASE_3_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE,
            "candidate_sha": "c" * 40, "decision_digest": digest("7"),
            "result": "PROMOTION_READY_FOR_CANARY_DECISION",
        }
        phase_3 = phase_3_core | {"receipt_digest": canonical(phase_3_core)}
        cross_core = {
            "schema": PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA,
            "profile": CROSS_ENVIRONMENT_CANARY_PROFILE, "candidate_sha": evidence.candidate_sha,
            "ready_at": evidence.sealed_canary.ready_at, "evidence_digest": evidence.evidence_digest,
            "result_digest": canonical(comparison.public_payload()),
        }
        cross = cross_core | {"receipt_digest": canonical(cross_core)}
        lineage_core = {
            "schema": "roundwright-phase-4-candidate-lineage/v1",
            "source_candidate_sha": evidence.candidate_sha,
            "qualification_candidate_sha": self.qualification_candidate,
            "relation": "descendant",
        }
        lineage = lineage_core | {"receipt_digest": canonical(lineage_core)}
        exits = []
        for area in ExitEvidenceArea:
            core = {
                "schema": PHASE_4_EXIT_RECEIPT_SCHEMA, "area": area.value,
                "source_candidate_sha": evidence.candidate_sha, "source_digest": evidence.evidence_digest,
                "result": "pass",
            }
            exits.append(core | {"receipt_digest": canonical(core)})
        payload = {
            "schema": PHASE_4_RETAINED_EVIDENCE_SCHEMA, "phase_3": phase_3,
            "cross_environment": {"evidence": evidence.public_payload(), "comparison": comparison.public_payload(), "receipt": cross},
            "lineage": lineage,
            "consumer_topology": {
                "docker_artifact_digest": evidence.artifact_digest,
                "devcontainer_artifact_digest": evidence.artifact_digest,
                "devcontainer_feature_count": 0, "devcontainer_template_count": 0,
            },
            "exit_evidence": exits, "confidence": confidence, "residual_risks": [] if risks is None else risks,
        }
        pins = Phase4SelectionPins(
            evidence.artifact_digest, phase_3["decision_digest"], phase_3["receipt_digest"],
            evidence.evidence_digest, canonical(comparison.public_payload()), cross["receipt_digest"],
            evidence.profile_digest, evidence.schema_digest,
            evidence.candidate_sha, CROSS_ENVIRONMENT_CANARY_PROFILE, evidence.schema,
            evidence.sealed_canary.ready_at, tuple(item["receipt_digest"] for item in exits),
        )
        return encoded(payload), pins

    def inputs(self, **changes: object) -> Phase4QualificationInputs:
        bundle, pins = self.retained_bundle()
        values: dict[str, object] = {
            "qualification_candidate_sha": self.qualification_candidate,
            "selection_pins": pins, "retained_bundle_bytes": bundle,
        }
        values.update(changes)
        return Phase4QualificationInputs(**values)  # type: ignore[arg-type]

    def test_distinct_qualification_and_retained_evidence_candidates_are_preserved(self) -> None:
        decision = assess_phase_4_qualification(self.inputs())
        self.assertEqual(decision.disposition, PHASE_5_OWNER_DECISION_REQUIRED)
        payload = decision.public_payload()
        self.assertEqual(payload["qualification_candidate_sha"], self.qualification_candidate)
        self.assertEqual(payload["retained_evidence_candidate_sha"], ISSUE_97_EVIDENCE_CANDIDATE_SHA)
        self.assertEqual(payload["historical_ready_at"], SEALED_CANARY_READY_AT)
        self.assertEqual(payload["mutation_count"], 0)

    def test_requires_the_historical_issue_97_candidate_and_selection_time_pins(self) -> None:
        bundle, pins = self.retained_bundle()
        with self.assertRaises(Phase4QualificationError):
            Phase4SelectionPins(
                pins.package_artifact_digest, pins.phase_3_decision_digest, pins.phase_3_receipt_digest,
                pins.issue_97_evidence_digest, pins.issue_97_result_digest, pins.issue_97_receipt_digest,
                pins.issue_97_profile_digest, pins.issue_97_schema_digest,
                "a" * 40, pins.cross_environment_profile, pins.cross_environment_schema,
                pins.historical_ready_at, pins.exit_receipt_digests,
            )
        altered = json.loads(bundle)
        altered["phase_3"]["decision_digest"] = digest("0")
        with self.assertRaises(Phase4QualificationError):
            self.inputs(retained_bundle_bytes=encoded(altered), selection_pins=pins)

    def test_reconstructs_retained_bytes_and_rejects_result_receipt_or_topology_drift(self) -> None:
        bundle, pins = self.retained_bundle()
        for mutate in (
            lambda value: value["cross_environment"]["comparison"].update({"observed_digest": digest("0")}),
            lambda value: value["cross_environment"]["receipt"].update({"ready_at": SEALED_CANARY_READY_AT + 1}),
            lambda value: value["consumer_topology"].update({"devcontainer_feature_count": 1}),
            lambda value: value["lineage"].update({"qualification_candidate_sha": "d" * 40}),
        ):
            value = json.loads(bundle)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(Phase4QualificationError):
                self.inputs(retained_bundle_bytes=encoded(value), selection_pins=pins)

    def test_sealed_input_rejects_post_construction_confidence_risk_and_topology_bypasses(self) -> None:
        inputs = self.inputs()
        object.__setattr__(inputs, "qualification_candidate_sha", "d" * 40)
        with self.assertRaises(Phase4QualificationError):
            assess_phase_4_qualification(inputs)

        bundle, pins = self.retained_bundle(confidence="low", risks=["retention-review-needed"])
        low = Phase4QualificationInputs(self.qualification_candidate, pins, bundle)
        object.__setattr__(low, "retained_bundle_bytes", self.retained_bundle()[0])
        with self.assertRaises(Phase4QualificationError):
            assess_phase_4_qualification(low)

    def test_each_exit_area_requires_its_pinned_distinct_semantic_receipt(self) -> None:
        bundle, pins = self.retained_bundle()
        changed = json.loads(bundle)
        receipt = changed["exit_evidence"][7]
        receipt["source_digest"] = digest("0")
        core = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        receipt["receipt_digest"] = canonical(core)
        with self.assertRaises(Phase4QualificationError):
            self.inputs(retained_bundle_bytes=encoded(changed), selection_pins=pins)

        duplicate = json.loads(bundle)
        duplicate["exit_evidence"][8]["receipt_digest"] = duplicate["exit_evidence"][7]["receipt_digest"]
        with self.assertRaises(Phase4QualificationError):
            self.inputs(retained_bundle_bytes=encoded(duplicate), selection_pins=pins)

    def test_low_or_conflicting_retained_evidence_is_blocked_and_owner_packet_rechecks_drift(self) -> None:
        low_bytes, low_pins = self.retained_bundle(confidence="low")
        self.assertEqual(
            assess_phase_4_qualification(Phase4QualificationInputs(self.qualification_candidate, low_pins, low_bytes)).disposition,
            PHASE_4_QUALIFICATION_BLOCKED,
        )
        conflicting_bytes, conflicting_pins = self.retained_bundle(confidence="conflicting", risks=["retention-review-needed"])
        decision = assess_phase_4_qualification(Phase4QualificationInputs(self.qualification_candidate, conflicting_pins, conflicting_bytes))
        self.assertEqual((decision.disposition, decision.public_payload()["confidence"]), (PHASE_4_QUALIFICATION_BLOCKED, "conflicting"))
        object.__setattr__(decision, "historical_ready_at", SEALED_CANARY_READY_AT + 1)
        with self.assertRaises(Phase4QualificationError):
            decision.public_payload()


if __name__ == "__main__":
    unittest.main()
