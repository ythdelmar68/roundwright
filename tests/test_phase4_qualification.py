"""Hermetic adversarial coverage for the Issue #98 retained-evidence gate."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
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
    PHASE_4_LINEAGE_SCHEMA, PHASE_4_QUALIFICATION_BLOCKED, PHASE_4_RETAINED_EVIDENCE_SCHEMA,
    PHASE_5_OWNER_DECISION_REQUIRED, ExitEvidenceArea, Phase4ExitEvidencePin,
    Phase4OwnerDecision, Phase4QualificationError, Phase4QualificationInputs, Phase4SelectionPins,
    assess_phase_4_qualification,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def canonical(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def byte_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class Phase4QualificationTests(unittest.TestCase):
    qualification_candidate = "b" * 40

    def evidence(self) -> CrossEnvironmentEvidence:
        lanes = tuple(
            EnvironmentLane(
                environment, environment.value + "-runner",
                OperationMode.AUTHORITATIVE if environment is EnvironmentKind.WINDOWS_HOST_PARITY else OperationMode.READ_ONLY,
                ISSUE_97_EVIDENCE_CANDIDATE_SHA, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"),
                ReceiptState.VERIFIED, SEALED_CANARY_RECEIPT_DIGEST, 100, ComparisonResult.PASS,
                parity_digest=None if environment is EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER else digest("6"),
                sealed_canary_receipt_digest=SEALED_CANARY_RECEIPT_DIGEST,
            ) for environment in CROSS_ENVIRONMENT_LANE_ORDER
        )
        return CrossEnvironmentEvidence(
            ISSUE_97_EVIDENCE_CANDIDATE_SHA, digest("b"), digest("c"), digest("d"), digest("e"), digest("f"), lanes,
            SealedCanaryReceipt(
                SEALED_CANARY_SOURCE_CANDIDATE_SHA, SEALED_CANARY_RECEIPT_DIGEST,
                SEALED_CANARY_EXECUTION_LEDGER_DIGEST, SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST,
                SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST, "ythdelmar68/roundlet-forward-test",
                SEALED_CANARY_TARGET_MERGE_SHA, SEALED_CANARY_READY_AT,
            ),
        )

    def retained_bundle(self, *, confidence: str = "high", risks: list[str] | None = None) -> tuple[bytes, bytes, Phase4SelectionPins]:
        evidence = self.evidence()
        comparison = compare_cross_environment_evidence(evidence, evidence)
        phase_core = {
            "schema": PHASE_3_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE,
            "candidate_sha": "c" * 40, "decision_digest": digest("7"), "result": "PROMOTION_READY_FOR_CANARY_DECISION",
        }
        phase = phase_core | {"receipt_digest": canonical(phase_core)}
        cross_core = {
            "schema": PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA, "profile": CROSS_ENVIRONMENT_CANARY_PROFILE,
            "candidate_sha": evidence.candidate_sha, "ready_at": evidence.sealed_canary.ready_at,
            "evidence_digest": evidence.evidence_digest, "result_digest": canonical(comparison.public_payload()),
        }
        cross = cross_core | {"receipt_digest": canonical(cross_core)}
        proof_core = {
            "schema": "roundwright-phase-4-authoritative-lineage-proof/v1",
            "issuer_identity": "roundwright-authoritative-git-object-db/v1",
            "repository_identity": "ythdelmar68/roundwright", "object_database_identity": digest("a"),
            "source_candidate_sha": evidence.candidate_sha, "qualification_candidate_sha": self.qualification_candidate,
            "relation": "ancestor", "semantic_result": "verified",
        }
        proof = proof_core | {"proof_digest": canonical(proof_core)}
        proof_bytes = encoded(proof)
        lineage_core = {
            "schema": PHASE_4_LINEAGE_SCHEMA, "source_candidate_sha": evidence.candidate_sha,
            "qualification_candidate_sha": self.qualification_candidate, "relation": "ancestor",
            "observed_source_candidate_sha": evidence.candidate_sha,
            "observed_qualification_candidate_sha": self.qualification_candidate,
            "observed_relation": "ancestor", "semantic_result": "verified",
            "authoritative_proof_digest": proof["proof_digest"],
        }
        lineage = lineage_core | {"receipt_digest": canonical(lineage_core)}
        exits = []
        for index, area in enumerate(ExitEvidenceArea):
            source_identity = digest("0123456789ab"[index])
            core = {
                "schema": PHASE_4_EXIT_RECEIPT_SCHEMA, "area": area.value,
                "source_candidate_sha": evidence.candidate_sha, "source_evidence_digest": evidence.evidence_digest,
                "expected_source_identity": source_identity, "observed_source_identity": source_identity,
                "semantic_result": "verified", "result": "pass",
            }
            exits.append(core | {"receipt_digest": canonical(core)})
        payload = {
            "schema": PHASE_4_RETAINED_EVIDENCE_SCHEMA, "phase_3": phase,
            "cross_environment": {"evidence": evidence.public_payload(), "comparison": comparison.public_payload(), "receipt": cross},
            "lineage": lineage,
            "consumer_topology": {
                "docker_artifact_digest": evidence.artifact_digest, "devcontainer_artifact_digest": evidence.artifact_digest,
                "devcontainer_feature_count": 0, "devcontainer_template_count": 0,
            },
            "exit_evidence": exits, "confidence": confidence, "residual_risks": [] if risks is None else risks,
        }
        bundle = encoded(payload)
        pins = Phase4SelectionPins(
            self.qualification_candidate, evidence.artifact_digest, phase["candidate_sha"], phase["decision_digest"], phase["receipt_digest"],
            evidence.evidence_digest, canonical(comparison.public_payload()), cross["receipt_digest"], evidence.profile_digest,
            evidence.schema_digest, evidence.candidate_sha, CROSS_ENVIRONMENT_CANARY_PROFILE, evidence.schema,
            evidence.sealed_canary.ready_at, byte_digest(bundle), lineage["receipt_digest"],
            proof["proof_digest"],
            tuple(Phase4ExitEvidencePin(
                area, evidence.candidate_sha, evidence.evidence_digest, item["expected_source_identity"],
                item["observed_source_identity"], item["receipt_digest"],
            ) for area, item in zip(ExitEvidenceArea, exits, strict=True)),
        )
        return bundle, proof_bytes, pins

    def inputs(self, **changes: object) -> Phase4QualificationInputs:
        bundle, proof, pins = self.retained_bundle()
        values: dict[str, object] = {
            "qualification_candidate_sha": self.qualification_candidate,
            "selection_pins": pins, "retained_bundle_bytes": bundle, "authoritative_lineage_proof_bytes": proof,
        }
        values.update(changes)
        return Phase4QualificationInputs(**values)  # type: ignore[arg-type]

    def repin(self, pins: Phase4SelectionPins, bundle: bytes) -> Phase4SelectionPins:
        return replace(pins, retained_bundle_digest=byte_digest(bundle))

    def test_preserves_distinct_candidates_and_closed_phase_5_prerequisites(self) -> None:
        decision = assess_phase_4_qualification(self.inputs())
        payload = decision.public_payload()
        self.assertEqual((payload["disposition"], payload["qualification_candidate_sha"], payload["retained_evidence_candidate_sha"]), (
            PHASE_5_OWNER_DECISION_REQUIRED, self.qualification_candidate, ISSUE_97_EVIDENCE_CANDIDATE_SHA,
        ))
        self.assertEqual(payload["phase_5_prerequisites"], [
            "owner-phase-5-decision", "no-automatic-activation", "no-roundlet-retirement", "no-promotion-or-release",
        ])

    def test_selection_pins_exact_canonical_bytes_and_rejects_nested_shape_drift(self) -> None:
        bundle, _, pins = self.retained_bundle()
        with self.assertRaises(Phase4QualificationError):
            self.inputs(retained_bundle_bytes=bundle + b"\n", selection_pins=self.repin(pins, bundle + b"\n"))
        for mutate in (
            lambda value: value["cross_environment"]["evidence"]["lanes"][0].update({"unexpected": "field"}),
            lambda value: value["consumer_topology"].update({"devcontainer_feature_count": False}),
            lambda value: value["cross_environment"]["comparison"].update({"differences": ""}),
        ):
            value = json.loads(bundle)
            mutate(value)
            changed = encoded(value)
            with self.subTest(mutate=mutate), self.assertRaises(Phase4QualificationError):
                self.inputs(retained_bundle_bytes=changed, selection_pins=self.repin(pins, changed))

    def test_selection_pins_exact_ancestry_read_back_and_non_descendant_blocks(self) -> None:
        bundle, proof, pins = self.retained_bundle()
        altered = json.loads(bundle)
        lineage = altered["lineage"]
        lineage["qualification_candidate_sha"] = SEALED_CANARY_SOURCE_CANDIDATE_SHA
        lineage["observed_qualification_candidate_sha"] = SEALED_CANARY_SOURCE_CANDIDATE_SHA
        altered_proof = json.loads(proof)
        altered_proof["qualification_candidate_sha"] = SEALED_CANARY_SOURCE_CANDIDATE_SHA
        altered_proof["relation"] = "not-ancestor"
        altered_proof["proof_digest"] = canonical({key: value for key, value in altered_proof.items() if key != "proof_digest"})
        changed_proof = encoded(altered_proof)
        lineage["authoritative_proof_digest"] = altered_proof["proof_digest"]
        lineage["receipt_digest"] = canonical({key: value for key, value in lineage.items() if key != "receipt_digest"})
        changed = encoded(altered)
        altered_pins = replace(
            pins, qualification_candidate_sha=SEALED_CANARY_SOURCE_CANDIDATE_SHA,
            retained_bundle_digest=byte_digest(changed), lineage_receipt_digest=lineage["receipt_digest"],
            lineage_proof_digest=altered_proof["proof_digest"],
        )
        with self.assertRaises(Phase4QualificationError):
            Phase4QualificationInputs(SEALED_CANARY_SOURCE_CANDIDATE_SHA, altered_pins, changed, changed_proof)
        with self.assertRaises(Phase4QualificationError):
            self.inputs(qualification_candidate_sha="0" * 40)

    def test_exit_receipts_require_pinned_area_specific_expected_and_observed_identity(self) -> None:
        bundle, _, pins = self.retained_bundle()
        for mutate in (
            lambda value: value["exit_evidence"][0].update({"observed_source_identity": digest("f")}),
            lambda value: value["exit_evidence"].__setitem__(1, dict(value["exit_evidence"][0])),
        ):
            value = json.loads(bundle)
            mutate(value)
            for item in value["exit_evidence"]:
                item["receipt_digest"] = canonical({key: raw for key, raw in item.items() if key != "receipt_digest"})
            changed = encoded(value)
            with self.subTest(mutate=mutate), self.assertRaises(Phase4QualificationError):
                self.inputs(retained_bundle_bytes=changed, selection_pins=self.repin(pins, changed))

    def test_owner_decision_is_reconstructed_and_low_confidence_cannot_be_ready(self) -> None:
        low_bundle, low_proof, low_pins = self.retained_bundle(confidence="low", risks=["retention-review-needed"])
        low = Phase4QualificationInputs(self.qualification_candidate, low_pins, low_bundle, low_proof)
        decision = Phase4OwnerDecision(low)
        self.assertEqual(decision.public_payload()["disposition"], PHASE_4_QUALIFICATION_BLOCKED)
        self.assertEqual(replace(decision, qualification_inputs=low).public_payload()["disposition"], PHASE_4_QUALIFICATION_BLOCKED)
        with self.assertRaises(TypeError):
            Phase4OwnerDecision(low, disposition=PHASE_5_OWNER_DECISION_REQUIRED)  # type: ignore[call-arg]

    def test_owner_output_rechecks_mutated_exit_receipts_and_inputs(self) -> None:
        decision = assess_phase_4_qualification(self.inputs())
        object.__setattr__(decision.exit_evidence[0], "observed_source_identity", digest("f"))
        with self.assertRaises(Phase4QualificationError):
            decision.public_payload()
        rebuilt = assess_phase_4_qualification(self.inputs())
        object.__setattr__(rebuilt.qualification_inputs, "retained_bundle_bytes", self.retained_bundle(confidence="low")[0])
        with self.assertRaises(Phase4QualificationError):
            rebuilt.public_payload()

    def test_authoritative_proof_needs_no_ambient_history_or_path(self) -> None:
        bundle, proof, pins = self.retained_bundle()
        previous = os.environ.get("PATH")
        try:
            os.environ["PATH"] = ""
            self.assertEqual(
                assess_phase_4_qualification(Phase4QualificationInputs(self.qualification_candidate, pins, bundle, proof)).disposition,
                PHASE_5_OWNER_DECISION_REQUIRED,
            )
        finally:
            if previous is None:
                del os.environ["PATH"]
            else:
                os.environ["PATH"] = previous


if __name__ == "__main__":
    unittest.main()
