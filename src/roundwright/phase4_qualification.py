"""Fail-closed, consumer-only Phase 4 qualification for Issue #98."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .cross_environment import (
    CROSS_ENVIRONMENT_CANARY_PROFILE, CROSS_ENVIRONMENT_EVIDENCE_SCHEMA,
    CROSS_ENVIRONMENT_RESULT_SCHEMA, ComparisonResult, CrossEnvironmentComparison,
    CrossEnvironmentEvidence, CrossEnvironmentEvidenceError, EnvironmentKind,
    EnvironmentLane, OperationMode, ParityDimension, ReceiptState, SealedCanaryReceipt,
    is_safe_cross_environment_public_string,
)

PHASE_4_QUALIFICATION_SCHEMA = "roundwright-phase-4-qualification-decision/v2"
PHASE_4_RETAINED_EVIDENCE_SCHEMA = "roundwright-phase-4-retained-evidence/v1"
PHASE_4_EXIT_RECEIPT_SCHEMA = "roundwright-phase-4-exit-evidence/v1"
PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA = "roundwright-phase-4-cross-environment-receipt/v1"
PHASE_3_DECISION_SCHEMA = "roundwright-phase-3-qualification-decision/v1"
PHASE_3_QUALIFICATION_PROFILE = "roundwright-shadow-profile/phase-3-qualification/v1"
PHASE_4_LINEAGE_SCHEMA = "roundwright-phase-4-candidate-lineage/v1"
PHASE_4_LINEAGE_PROOF_SCHEMA = "roundwright-phase-4-authoritative-lineage-proof/v1"
_LINEAGE_PROOF_ISSUER = "roundwright-authoritative-git-object-db/v1"
_LINEAGE_PROOF_REPOSITORY = "ythdelmar68/roundwright"
_LINEAGE_PROOF_KEY_ID = "roundwright-phase4-authority-2026-09"
_LINEAGE_PROOF_RSA_N = int.from_bytes(base64.urlsafe_b64decode(
    "sFwBme8IMzNjdxUlNlP65WHlhWOMCqPKpELVLgPGx7tI6ozFAF62TqgQSBf3oa75"
    "vA0NQ0DBGdfCXNgJcAZSloJ3qwijo_eob_KelMurrlQIPvAAGjrt9TcWql_HK0f-fS"
    "PuOAVnUXLf3F8yqEyic47AUzY2Iyuh174_-9ynWyiAiQ3LGDj-Ly2wwWL2JzhfHnkn"
    "5sdaEWMqsoPsUlBKae8KP5MVGselCUj4Zoh0apn5P3AoQp2Eq2TeBet65qZI_uI0u_"
    "FnJAH_wHvvED1Fy5tXm2-qHalQbEFMWs1tCb5VR-Sc01HCHEwQAA2zJuwZhRo1sNlU"
    "2llXYSmycEwx5w" + "=="
), "big")
_LINEAGE_PROOF_RSA_E = 65537
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
ISSUE_97_EVIDENCE_CANDIDATE_SHA = "fe1da4ffa4ee29df21aa62cc5a995fb4075e075d"
PHASE_5_OWNER_DECISION_REQUIRED = "PHASE_5_OWNER_DECISION_REQUIRED"
PHASE_4_QUALIFICATION_BLOCKED = "PHASE_4_QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PHASE_5_PREREQUISITES = (
    "owner-phase-5-decision", "no-automatic-activation", "no-roundlet-retirement", "no-promotion-or-release",
)


class Phase4QualificationError(ValueError):
    """Raised when retained Phase 4 evidence is stale, malformed, or mixed."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_authoritative_lineage_proof(contents: bytes) -> dict[str, str]:
    """Parse a separately issued immutable ancestry proof without local Git access."""

    try:
        if type(contents) is not bytes:
            raise ValueError
        proof = json.loads(contents, object_pairs_hook=_no_duplicate_object)
        if contents != _canonical_bytes(proof):
            raise ValueError
        proof = _require_keys(proof, {
            "schema", "issuer_identity", "repository_identity", "object_database_identity",
            "issuer_key_id", "source_candidate_sha", "qualification_candidate_sha", "relation", "semantic_result",
            "proof_digest", "issuer_signature",
        }, "authoritative lineage proof")
        unsigned = {key: value for key, value in proof.items() if key not in {"proof_digest", "issuer_signature"}}
        signed = {key: value for key, value in proof.items() if key != "issuer_signature"}
        if (
            any(type(value) is not str for value in proof.values())
            or proof["schema"] != PHASE_4_LINEAGE_PROOF_SCHEMA
            or proof["issuer_identity"] != _LINEAGE_PROOF_ISSUER
            or proof["issuer_key_id"] != _LINEAGE_PROOF_KEY_ID
            or proof["repository_identity"] != _LINEAGE_PROOF_REPOSITORY
            or _DIGEST.fullmatch(proof["object_database_identity"]) is None
            or _SHA.fullmatch(proof["source_candidate_sha"]) is None
            or _SHA.fullmatch(proof["qualification_candidate_sha"]) is None
            or proof["source_candidate_sha"] == proof["qualification_candidate_sha"]
            or proof["relation"] != "ancestor" or proof["semantic_result"] != "verified"
            or proof["proof_digest"] != _digest(unsigned)
            or not _verify_lineage_issuer_signature(_canonical_bytes(signed), proof["issuer_signature"])
        ):
            raise ValueError
        return proof  # type: ignore[return-value]
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError, Phase4QualificationError) as error:
        if isinstance(error, Phase4QualificationError):
            raise
        raise Phase4QualificationError("authoritative lineage proof is invalid") from error


def _verify_lineage_issuer_signature(signed: bytes, signature: str) -> bool:
    """Verify the fixed issuer's canonical RSA-SHA256 attestation without ambient tools."""

    try:
        value = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        return False
    representative = int.from_bytes(value, "big")
    if (
        len(value) != 256
        or base64.b64encode(value).decode("ascii") != signature
        or not 0 <= representative < _LINEAGE_PROOF_RSA_N
    ):
        return False
    encoded = pow(representative, _LINEAGE_PROOF_RSA_E, _LINEAGE_PROOF_RSA_N).to_bytes(256, "big")
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(signed).digest()
    padding_length = len(encoded) - len(digest_info) - 3
    return padding_length >= 8 and encoded == b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info


def _no_duplicate_object(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise Phase4QualificationError("retained Phase 4 JSON is not canonical")
        result[key] = value
    return result


def _require_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise Phase4QualificationError(f"{label} is invalid")
    return value


class EvidenceConfidence(StrEnum):
    HIGH = "high"
    LOW = "low"
    CONFLICTING = "conflicting"


class ExitEvidenceArea(StrEnum):
    CANCELLATION = "cancellation"
    STALE_RECOVERY = "stale-recovery"
    LOCKS = "locks"
    PATHS = "paths"
    WORKTREES = "worktrees"
    SQLITE = "sqlite"
    CLI_WRAPPERS = "cli-wrappers"
    OPERATOR_AUTH_RECOVERY = "operator-auth-recovery"
    HANDOFF = "handoff"
    ROLLBACK = "rollback"
    CLEANUP = "cleanup"
    SEMANTIC_READ_BACK = "semantic-read-back"


REQUIRED_EXIT_EVIDENCE = tuple(ExitEvidenceArea)


@dataclass(frozen=True)
class Phase4ExitEvidencePin:
    area: ExitEvidenceArea
    source_candidate_sha: str
    source_evidence_digest: str
    expected_source_identity: str
    observed_source_identity: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.area) is not ExitEvidenceArea or _SHA.fullmatch(self.source_candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.source_evidence_digest, self.expected_source_identity, self.observed_source_identity, self.receipt_digest,
            )) or self.expected_source_identity != self.observed_source_identity
        ):
            raise Phase4QualificationError("Phase 4 exit evidence pin is invalid")

    def public_payload(self) -> dict[str, str]:
        return {
            "area": self.area.value, "source_candidate_sha": self.source_candidate_sha,
            "source_evidence_digest": self.source_evidence_digest,
            "expected_source_identity": self.expected_source_identity,
            "observed_source_identity": self.observed_source_identity, "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class Phase4SelectionPins:
    """Selection-time identities, separated from independently retained bytes."""

    qualification_candidate_sha: str
    package_artifact_digest: str
    phase_3_candidate_sha: str
    phase_3_decision_digest: str
    phase_3_receipt_digest: str
    issue_97_evidence_digest: str
    issue_97_result_digest: str
    issue_97_receipt_digest: str
    issue_97_profile_digest: str
    issue_97_schema_digest: str
    source_candidate_sha: str
    cross_environment_profile: str
    cross_environment_schema: str
    historical_ready_at: int
    retained_bundle_digest: str
    lineage_receipt_digest: str
    lineage_proof_digest: str
    exit_evidence: tuple[Phase4ExitEvidencePin, ...]
    selection_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.qualification_candidate_sha) is None
            or self.qualification_candidate_sha == ISSUE_97_EVIDENCE_CANDIDATE_SHA
            or _SHA.fullmatch(self.phase_3_candidate_sha) is None
            or self.source_candidate_sha != ISSUE_97_EVIDENCE_CANDIDATE_SHA
            or self.cross_environment_profile != CROSS_ENVIRONMENT_CANARY_PROFILE
            or self.cross_environment_schema != CROSS_ENVIRONMENT_EVIDENCE_SCHEMA
            or type(self.historical_ready_at) is not int or self.historical_ready_at < 0
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.package_artifact_digest, self.phase_3_decision_digest, self.phase_3_receipt_digest,
                self.issue_97_evidence_digest, self.issue_97_result_digest, self.issue_97_receipt_digest,
                self.issue_97_profile_digest, self.issue_97_schema_digest, self.retained_bundle_digest,
                self.lineage_receipt_digest, self.lineage_proof_digest,
            )) or type(self.exit_evidence) is not tuple
            or tuple(item.area for item in self.exit_evidence) != REQUIRED_EXIT_EVIDENCE
            or any(type(item) is not Phase4ExitEvidencePin for item in self.exit_evidence)
            or any(item.source_candidate_sha != self.source_candidate_sha for item in self.exit_evidence)
            or len({item.receipt_digest for item in self.exit_evidence}) != len(self.exit_evidence)
        ):
            raise Phase4QualificationError("Phase 4 selection pins are invalid")
        object.__setattr__(self, "selection_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        try:
            rebuilt = Phase4SelectionPins(
                self.qualification_candidate_sha, self.package_artifact_digest, self.phase_3_candidate_sha,
                self.phase_3_decision_digest, self.phase_3_receipt_digest, self.issue_97_evidence_digest,
                self.issue_97_result_digest, self.issue_97_receipt_digest, self.issue_97_profile_digest,
                self.issue_97_schema_digest, self.source_candidate_sha, self.cross_environment_profile,
                self.cross_environment_schema, self.historical_ready_at, self.retained_bundle_digest,
                self.lineage_receipt_digest, self.lineage_proof_digest, self.exit_evidence,
            )
            if rebuilt.selection_digest != self.selection_digest:
                raise ValueError
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 selection pins have drifted") from error

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        if include_digest:
            self.validate()
        value: dict[str, object] = {
            "qualification_candidate_sha": self.qualification_candidate_sha,
            "package_artifact_digest": self.package_artifact_digest,
            "phase_3_candidate_sha": self.phase_3_candidate_sha,
            "phase_3_decision_digest": self.phase_3_decision_digest,
            "phase_3_receipt_digest": self.phase_3_receipt_digest,
            "issue_97_evidence_digest": self.issue_97_evidence_digest,
            "issue_97_result_digest": self.issue_97_result_digest,
            "issue_97_receipt_digest": self.issue_97_receipt_digest,
            "issue_97_profile_digest": self.issue_97_profile_digest,
            "issue_97_schema_digest": self.issue_97_schema_digest,
            "source_candidate_sha": self.source_candidate_sha,
            "cross_environment_profile": self.cross_environment_profile,
            "cross_environment_schema": self.cross_environment_schema,
            "historical_ready_at": self.historical_ready_at,
            "retained_bundle_digest": self.retained_bundle_digest,
            "lineage_receipt_digest": self.lineage_receipt_digest,
            "lineage_proof_digest": self.lineage_proof_digest,
            "exit_evidence": [item.public_payload() for item in self.exit_evidence],
        }
        return value | ({"selection_digest": self.selection_digest} if include_digest else {})


@dataclass(frozen=True)
class _RetainedExitReceipt:
    area: ExitEvidenceArea
    source_candidate_sha: str
    source_evidence_digest: str
    expected_source_identity: str
    observed_source_identity: str
    semantic_result: str
    receipt_digest: str

    def validate(self) -> None:
        core = {
            "schema": PHASE_4_EXIT_RECEIPT_SCHEMA, "area": self.area.value,
            "source_candidate_sha": self.source_candidate_sha, "source_evidence_digest": self.source_evidence_digest,
            "expected_source_identity": self.expected_source_identity,
            "observed_source_identity": self.observed_source_identity,
            "semantic_result": self.semantic_result, "result": "pass",
        }
        if (
            type(self.area) is not ExitEvidenceArea or _SHA.fullmatch(self.source_candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.source_evidence_digest, self.expected_source_identity, self.observed_source_identity, self.receipt_digest,
            )) or self.expected_source_identity != self.observed_source_identity
            or self.semantic_result != "verified" or self.receipt_digest != _digest(core)
        ):
            raise Phase4QualificationError("retained exit receipt is invalid")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, str]:
        if include_digest:
            self.validate()
        return {
            "area": self.area.value, "source_candidate_sha": self.source_candidate_sha,
            "source_evidence_digest": self.source_evidence_digest,
            "expected_source_identity": self.expected_source_identity,
            "observed_source_identity": self.observed_source_identity,
            "semantic_result": self.semantic_result, "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class _RetainedEvidence:
    phase_3_candidate_sha: str
    phase_3_decision_digest: str
    phase_3_receipt_digest: str
    lineage_qualification_candidate_sha: str
    lineage_receipt_digest: str
    lineage_proof_digest: str
    evidence: CrossEnvironmentEvidence
    comparison: CrossEnvironmentComparison
    cross_environment_receipt_digest: str
    exit_receipts: tuple[_RetainedExitReceipt, ...]
    confidence: EvidenceConfidence
    residual_risks: tuple[str, ...]


def _parse_lane(value: object) -> EnvironmentLane:
    payload = _require_keys(value, {
        "environment", "environment_identity", "mode", "candidate_sha", "artifact_digest", "policy_digest",
        "profile_digest", "schema_digest", "producer_identity", "receipt_state", "receipt_digest", "observed_at",
        "result", "reason", "parity_dimensions", "parity_digest", "sealed_canary_receipt_digest",
    }, "retained #97 lane")
    if (
        any(type(payload[key]) is not str for key in (
            "environment", "environment_identity", "mode", "candidate_sha", "artifact_digest", "policy_digest",
            "profile_digest", "schema_digest", "producer_identity", "receipt_state", "result",
        )) or payload["receipt_digest"] is not None and type(payload["receipt_digest"]) is not str
        or type(payload["observed_at"]) is not int or payload["reason"] is not None and type(payload["reason"]) is not str
        or type(payload["parity_dimensions"]) is not list or any(type(item) is not str for item in payload["parity_dimensions"])
        or payload["parity_digest"] is not None and type(payload["parity_digest"]) is not str
        or payload["sealed_canary_receipt_digest"] is not None and type(payload["sealed_canary_receipt_digest"]) is not str
    ):
        raise Phase4QualificationError("retained #97 lane is invalid")
    return EnvironmentLane(
        EnvironmentKind(payload["environment"]), payload["environment_identity"], OperationMode(payload["mode"]),
        payload["candidate_sha"], payload["artifact_digest"], payload["policy_digest"], payload["profile_digest"],
        payload["schema_digest"], payload["producer_identity"], ReceiptState(payload["receipt_state"]),
        payload["receipt_digest"], payload["observed_at"], ComparisonResult(payload["result"]), payload["reason"],
        tuple(ParityDimension(item) for item in payload["parity_dimensions"]), payload["parity_digest"],
        payload["sealed_canary_receipt_digest"],
    )


def _parse_evidence(value: object) -> CrossEnvironmentEvidence:
    payload = _require_keys(value, {
        "schema", "candidate_sha", "artifact_digest", "policy_digest", "profile_digest",
        "schema_digest", "producer_identity", "lanes", "sealed_canary", "result",
    }, "retained #97 evidence")
    try:
        if any(type(payload[key]) is not str for key in (
            "schema", "candidate_sha", "artifact_digest", "policy_digest", "profile_digest", "schema_digest",
            "producer_identity", "result",
        )) or type(payload["lanes"]) is not list:
            raise ValueError
        sealed = _require_keys(payload["sealed_canary"], {
            "source_candidate_sha", "receipt_digest", "execution_ledger_digest", "lifecycle_ledger_digest",
            "lifecycle_comparison_digest", "target_repository", "target_merge_sha", "ready_at",
        }, "retained #96 receipt")
        if any(type(sealed[key]) is not str for key in sealed if key != "ready_at") or type(sealed["ready_at"]) is not int:
            raise ValueError
        evidence = CrossEnvironmentEvidence(
            payload["candidate_sha"], payload["artifact_digest"], payload["policy_digest"], payload["profile_digest"],
            payload["schema_digest"], payload["producer_identity"], tuple(_parse_lane(item) for item in payload["lanes"]),
            SealedCanaryReceipt(
                sealed["source_candidate_sha"], sealed["receipt_digest"], sealed["execution_ledger_digest"],
                sealed["lifecycle_ledger_digest"], sealed["lifecycle_comparison_digest"], sealed["target_repository"],
                sealed["target_merge_sha"], sealed["ready_at"],
            ), payload["schema"],
        )
        if payload != evidence.public_payload():
            raise ValueError
        return evidence
    except (AttributeError, KeyError, TypeError, ValueError, CrossEnvironmentEvidenceError) as error:
        raise Phase4QualificationError("retained #97 evidence is invalid") from error


def _parse_retained_bundle(contents: bytes) -> _RetainedEvidence:
    try:
        if type(contents) is not bytes:
            raise ValueError
        payload = json.loads(contents, object_pairs_hook=_no_duplicate_object)
        if contents != _canonical_bytes(payload):
            raise ValueError
        payload = _require_keys(payload, {
            "schema", "phase_3", "cross_environment", "lineage", "consumer_topology", "exit_evidence",
            "confidence", "residual_risks",
        }, "retained Phase 4 bundle")
        if type(payload["schema"]) is not str or payload["schema"] != PHASE_4_RETAINED_EVIDENCE_SCHEMA:
            raise ValueError
        phase_3 = _require_keys(payload["phase_3"], {
            "schema", "profile", "candidate_sha", "decision_digest", "result", "receipt_digest",
        }, "retained #51 decision")
        phase_core = {key: value for key, value in phase_3.items() if key != "receipt_digest"}
        if (
            any(type(value) is not str for value in phase_3.values()) or phase_3["schema"] != PHASE_3_DECISION_SCHEMA
            or phase_3["profile"] != PHASE_3_QUALIFICATION_PROFILE or _SHA.fullmatch(phase_3["candidate_sha"]) is None
            or phase_3["result"] != "PROMOTION_READY_FOR_CANARY_DECISION"
            or any(_DIGEST.fullmatch(phase_3[key]) is None for key in ("decision_digest", "receipt_digest"))
            or phase_3["receipt_digest"] != _digest(phase_core)
        ):
            raise ValueError
        cross = _require_keys(payload["cross_environment"], {"evidence", "comparison", "receipt"}, "retained #97 bundle")
        evidence = _parse_evidence(cross["evidence"])
        comparison_payload = _require_keys(cross["comparison"], {
            "schema", "result", "candidate_sha", "expected_digest", "observed_digest", "differences",
        }, "retained #97 result")
        if any(type(comparison_payload[key]) is not str for key in (
            "schema", "result", "candidate_sha", "expected_digest", "observed_digest",
        )) or type(comparison_payload["differences"]) is not list or any(type(item) is not str for item in comparison_payload["differences"]):
            raise ValueError
        comparison = CrossEnvironmentComparison(
            ComparisonResult(comparison_payload["result"]), comparison_payload["candidate_sha"],
            comparison_payload["expected_digest"], comparison_payload["observed_digest"],
            tuple(comparison_payload["differences"]), comparison_payload["schema"],
        )
        if comparison_payload != comparison.public_payload():
            raise ValueError
        receipt = _require_keys(cross["receipt"], {
            "schema", "profile", "candidate_sha", "ready_at", "evidence_digest", "result_digest", "receipt_digest",
        }, "retained #97 receipt")
        receipt_core = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        if (
            any(type(receipt[key]) is not str for key in receipt if key != "ready_at") or type(receipt["ready_at"]) is not int
            or receipt["schema"] != PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA
            or receipt["profile"] != CROSS_ENVIRONMENT_CANARY_PROFILE or receipt["candidate_sha"] != evidence.candidate_sha
            or receipt["ready_at"] != evidence.sealed_canary.ready_at or receipt["evidence_digest"] != evidence.evidence_digest
            or receipt["result_digest"] != _digest(comparison.public_payload()) or receipt["receipt_digest"] != _digest(receipt_core)
        ):
            raise ValueError
        lineage = _require_keys(payload["lineage"], {
            "schema", "source_candidate_sha", "qualification_candidate_sha", "relation",
            "observed_source_candidate_sha", "observed_qualification_candidate_sha", "observed_relation",
            "semantic_result", "authoritative_proof_digest", "receipt_digest",
        }, "retained candidate lineage")
        lineage_core = {key: value for key, value in lineage.items() if key != "receipt_digest"}
        if (
            any(type(value) is not str for value in lineage.values()) or lineage["schema"] != PHASE_4_LINEAGE_SCHEMA
            or _SHA.fullmatch(lineage["source_candidate_sha"]) is None or _SHA.fullmatch(lineage["qualification_candidate_sha"]) is None
            or lineage["source_candidate_sha"] == lineage["qualification_candidate_sha"] or lineage["relation"] != "ancestor"
            or (lineage["observed_source_candidate_sha"], lineage["observed_qualification_candidate_sha"], lineage["observed_relation"])
            != (lineage["source_candidate_sha"], lineage["qualification_candidate_sha"], "ancestor")
            or lineage["semantic_result"] != "verified"
            or type(lineage["authoritative_proof_digest"]) is not str
            or _DIGEST.fullmatch(lineage["authoritative_proof_digest"]) is None
            or lineage["receipt_digest"] != _digest(lineage_core)
        ):
            raise ValueError
        topology = _require_keys(payload["consumer_topology"], {
            "docker_artifact_digest", "devcontainer_artifact_digest", "devcontainer_feature_count", "devcontainer_template_count",
        }, "retained consumer topology")
        if (
            type(topology["docker_artifact_digest"]) is not str or type(topology["devcontainer_artifact_digest"]) is not str
            or type(topology["devcontainer_feature_count"]) is not int or type(topology["devcontainer_template_count"]) is not int
            or topology["docker_artifact_digest"] != evidence.artifact_digest or topology["devcontainer_artifact_digest"] != evidence.artifact_digest
            or topology["devcontainer_feature_count"] != 0 or topology["devcontainer_template_count"] != 0
        ):
            raise ValueError
        if type(payload["exit_evidence"]) is not list or len(payload["exit_evidence"]) != len(REQUIRED_EXIT_EVIDENCE):
            raise ValueError
        exits: list[_RetainedExitReceipt] = []
        for area, item in zip(REQUIRED_EXIT_EVIDENCE, payload["exit_evidence"], strict=True):
            receipt_value = _require_keys(item, {
                "schema", "area", "source_candidate_sha", "source_evidence_digest", "expected_source_identity",
                "observed_source_identity", "semantic_result", "result", "receipt_digest",
            }, "retained exit receipt")
            core = {key: value for key, value in receipt_value.items() if key != "receipt_digest"}
            if any(type(value) is not str for value in receipt_value.values()):
                raise ValueError
            exit_receipt = _RetainedExitReceipt(
                area, receipt_value["source_candidate_sha"], receipt_value["source_evidence_digest"],
                receipt_value["expected_source_identity"], receipt_value["observed_source_identity"],
                receipt_value["semantic_result"], receipt_value["receipt_digest"],
            )
            if (
                receipt_value["schema"] != PHASE_4_EXIT_RECEIPT_SCHEMA or receipt_value["area"] != area.value
                or receipt_value["source_candidate_sha"] != evidence.candidate_sha
                or receipt_value["source_evidence_digest"] != evidence.evidence_digest or receipt_value["result"] != "pass"
                or receipt_value["receipt_digest"] != _digest(core)
            ):
                raise ValueError
            exit_receipt.validate()
            exits.append(exit_receipt)
        if len({item.receipt_digest for item in exits}) != len(exits):
            raise ValueError
        if type(payload["confidence"]) is not str or type(payload["residual_risks"]) is not list:
            raise ValueError
        confidence = EvidenceConfidence(payload["confidence"])
        risks = tuple(payload["residual_risks"])
        if any(not is_safe_cross_environment_public_string(item) for item in risks) or tuple(sorted(set(risks))) != risks:
            raise ValueError
        return _RetainedEvidence(
            phase_3["candidate_sha"], phase_3["decision_digest"], phase_3["receipt_digest"],
            lineage["qualification_candidate_sha"], lineage["receipt_digest"], lineage["authoritative_proof_digest"], evidence, comparison,
            receipt["receipt_digest"], tuple(exits), confidence, risks,
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError, CrossEnvironmentEvidenceError, Phase4QualificationError) as error:
        if isinstance(error, Phase4QualificationError):
            raise
        raise Phase4QualificationError("retained Phase 4 bundle is invalid") from error


@dataclass(frozen=True)
class Phase4QualificationInputs:
    qualification_candidate_sha: str
    selection_pins: Phase4SelectionPins
    retained_bundle_bytes: bytes
    authoritative_lineage_proof_bytes: bytes
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if _SHA.fullmatch(self.qualification_candidate_sha) is None or type(self.selection_pins) is not Phase4SelectionPins or type(self.retained_bundle_bytes) is not bytes or type(self.authoritative_lineage_proof_bytes) is not bytes:
            raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
        object.__setattr__(self, "input_digest", _digest(self._identity_payload()))
        self.validate()

    def _identity_payload(self) -> dict[str, str]:
        return {
            "qualification_candidate_sha": self.qualification_candidate_sha,
            "selection_digest": self.selection_pins.selection_digest,
            "retained_bundle_digest": _bytes_digest(self.retained_bundle_bytes),
            "authoritative_lineage_proof_digest": _bytes_digest(self.authoritative_lineage_proof_bytes),
        }

    def validate(self) -> _RetainedEvidence:
        try:
            self.selection_pins.validate()
            if self.input_digest != _digest(self._identity_payload()):
                raise ValueError
            observed, proof, pins = _parse_retained_bundle(self.retained_bundle_bytes), _parse_authoritative_lineage_proof(self.authoritative_lineage_proof_bytes), self.selection_pins
            if (
                self.qualification_candidate_sha != pins.qualification_candidate_sha
                or _bytes_digest(self.retained_bundle_bytes) != pins.retained_bundle_digest
                or observed.lineage_qualification_candidate_sha != self.qualification_candidate_sha
                or observed.lineage_receipt_digest != pins.lineage_receipt_digest
                or observed.lineage_proof_digest != pins.lineage_proof_digest
                or proof["proof_digest"] != pins.lineage_proof_digest
                or (proof["source_candidate_sha"], proof["qualification_candidate_sha"])
                != (pins.source_candidate_sha, self.qualification_candidate_sha)
                or observed.evidence.candidate_sha != pins.source_candidate_sha
                or observed.evidence.artifact_digest != pins.package_artifact_digest
                or observed.evidence.schema != pins.cross_environment_schema
                or observed.evidence.sealed_canary.ready_at != pins.historical_ready_at
                or observed.evidence.evidence_digest != pins.issue_97_evidence_digest
                or observed.evidence.profile_digest != pins.issue_97_profile_digest
                or observed.evidence.schema_digest != pins.issue_97_schema_digest
                or observed.comparison.schema != CROSS_ENVIRONMENT_RESULT_SCHEMA
                or observed.comparison.result is not ComparisonResult.PASS
                or observed.comparison.candidate_sha != observed.evidence.candidate_sha
                or observed.comparison.expected_digest != observed.evidence.evidence_digest
                or observed.comparison.observed_digest != observed.evidence.evidence_digest
                or observed.comparison.differences != ()
                or _digest(observed.comparison.public_payload()) != pins.issue_97_result_digest
                or observed.cross_environment_receipt_digest != pins.issue_97_receipt_digest
                or (observed.phase_3_candidate_sha, observed.phase_3_decision_digest, observed.phase_3_receipt_digest)
                != (pins.phase_3_candidate_sha, pins.phase_3_decision_digest, pins.phase_3_receipt_digest)
                or tuple((item.area, item.source_candidate_sha, item.source_evidence_digest, item.expected_source_identity, item.observed_source_identity, item.receipt_digest) for item in observed.exit_receipts)
                != tuple((item.area, item.source_candidate_sha, item.source_evidence_digest, item.expected_source_identity, item.observed_source_identity, item.receipt_digest) for item in pins.exit_evidence)
            ):
                raise ValueError
            return observed
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 qualification evidence is invalid or stale") from error


@dataclass(frozen=True)
class Phase4OwnerDecision:
    """Public-safe owner input reconstructed from sealed qualification inputs."""

    qualification_inputs: Phase4QualificationInputs
    schema: str = PHASE_4_QUALIFICATION_SCHEMA
    disposition: str = field(init=False)
    qualification_candidate_sha: str = field(init=False)
    retained_evidence_candidate_sha: str = field(init=False)
    package_artifact_digest: str = field(init=False)
    phase_3_receipt_digest: str = field(init=False)
    cross_environment_evidence_digest: str = field(init=False)
    cross_environment_result_digest: str = field(init=False)
    cross_environment_receipt_digest: str = field(init=False)
    sealed_canary_receipt_digest: str = field(init=False)
    historical_ready_at: int = field(init=False)
    exit_evidence: tuple[_RetainedExitReceipt, ...] = field(init=False)
    confidence: EvidenceConfidence = field(init=False)
    residual_risks: tuple[str, ...] = field(init=False)
    phase_5_prerequisites: tuple[str, ...] = field(init=False)
    input_digest: str = field(init=False)
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.qualification_inputs) is not Phase4QualificationInputs or self.schema != PHASE_4_QUALIFICATION_SCHEMA:
            raise Phase4QualificationError("Phase 4 owner decision is invalid")
        observed = self.qualification_inputs.validate()
        evidence = observed.evidence
        values: dict[str, object] = {
            "disposition": PHASE_4_QUALIFICATION_BLOCKED if observed.confidence is not EvidenceConfidence.HIGH or observed.residual_risks else PHASE_5_OWNER_DECISION_REQUIRED,
            "qualification_candidate_sha": self.qualification_inputs.qualification_candidate_sha,
            "retained_evidence_candidate_sha": evidence.candidate_sha, "package_artifact_digest": evidence.artifact_digest,
            "phase_3_receipt_digest": observed.phase_3_receipt_digest, "cross_environment_evidence_digest": evidence.evidence_digest,
            "cross_environment_result_digest": _digest(observed.comparison.public_payload()),
            "cross_environment_receipt_digest": observed.cross_environment_receipt_digest,
            "sealed_canary_receipt_digest": evidence.sealed_canary.receipt_digest,
            "historical_ready_at": evidence.sealed_canary.ready_at, "exit_evidence": observed.exit_receipts,
            "confidence": observed.confidence, "residual_risks": observed.residual_risks,
            "phase_5_prerequisites": _PHASE_5_PREREQUISITES, "input_digest": self.qualification_inputs.input_digest,
        }
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        try:
            rebuilt = Phase4OwnerDecision(self.qualification_inputs, self.schema)
            names = (
                "disposition", "qualification_candidate_sha", "retained_evidence_candidate_sha", "package_artifact_digest",
                "phase_3_receipt_digest", "cross_environment_evidence_digest", "cross_environment_result_digest",
                "cross_environment_receipt_digest", "sealed_canary_receipt_digest", "historical_ready_at", "exit_evidence",
                "confidence", "residual_risks", "phase_5_prerequisites", "input_digest", "decision_digest",
            )
            if any(getattr(rebuilt, name) != getattr(self, name) for name in names):
                raise ValueError
            for receipt in self.exit_evidence:
                receipt.validate()
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 owner decision has drifted") from error

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        if include_digest:
            self.validate()
        value: dict[str, object] = {
            "schema": self.schema, "disposition": self.disposition,
            "qualification_candidate_sha": self.qualification_candidate_sha,
            "retained_evidence_candidate_sha": self.retained_evidence_candidate_sha,
            "package_artifact_digest": self.package_artifact_digest, "phase_3_receipt_digest": self.phase_3_receipt_digest,
            "cross_environment_evidence_digest": self.cross_environment_evidence_digest,
            "cross_environment_result_digest": self.cross_environment_result_digest,
            "cross_environment_receipt_digest": self.cross_environment_receipt_digest,
            "sealed_canary_receipt_digest": self.sealed_canary_receipt_digest,
            "historical_ready_at": self.historical_ready_at,
            "exit_evidence": [item.public_payload() for item in self.exit_evidence],
            "confidence": self.confidence.value, "residual_risks": list(self.residual_risks),
            "phase_5_prerequisites": list(self.phase_5_prerequisites),
            "authority": "owner-decision-required", "mutation_count": 0,
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_4_qualification(inputs: Phase4QualificationInputs) -> Phase4OwnerDecision:
    """Return a Phase 5 owner input only after full pin/read-back reconciliation."""

    if type(inputs) is not Phase4QualificationInputs:
        raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
    return Phase4OwnerDecision(inputs)
