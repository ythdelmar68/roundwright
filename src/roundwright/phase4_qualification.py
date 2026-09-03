"""Fail-closed, consumer-only Phase 4 qualification for Issue #98.

The gate consumes selection-time pins and independently retained public-safe
bytes. It does not invoke a Harness, provider, scheduler, target, GitHub, or
lifecycle sink. A pass only produces a Phase 5 owner-decision input.
"""

from __future__ import annotations

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
ISSUE_97_EVIDENCE_CANDIDATE_SHA = "fe1da4ffa4ee29df21aa62cc5a995fb4075e075d"
PHASE_5_OWNER_DECISION_REQUIRED = "PHASE_5_OWNER_DECISION_REQUIRED"
PHASE_4_QUALIFICATION_BLOCKED = "PHASE_4_QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Phase4QualificationError(ValueError):
    """Raised when a retained Phase 4 evidence binding is stale or mixed."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


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
class Phase4SelectionPins:
    """Selection-time identities, separated from observed retained bytes."""

    package_artifact_digest: str
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
    exit_receipt_digests: tuple[str, ...]
    selection_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            any(_DIGEST.fullmatch(value) is None for value in (
                self.package_artifact_digest, self.phase_3_decision_digest,
                self.phase_3_receipt_digest, self.issue_97_evidence_digest,
                self.issue_97_result_digest, self.issue_97_receipt_digest,
                self.issue_97_profile_digest, self.issue_97_schema_digest,
            ))
            or self.source_candidate_sha != ISSUE_97_EVIDENCE_CANDIDATE_SHA
            or self.cross_environment_profile != CROSS_ENVIRONMENT_CANARY_PROFILE
            or self.cross_environment_schema != CROSS_ENVIRONMENT_EVIDENCE_SCHEMA
            or type(self.historical_ready_at) is not int or self.historical_ready_at < 0
            or type(self.exit_receipt_digests) is not tuple
            or len(self.exit_receipt_digests) != len(REQUIRED_EXIT_EVIDENCE)
            or any(_DIGEST.fullmatch(value) is None for value in self.exit_receipt_digests)
            or len(set(self.exit_receipt_digests)) != len(self.exit_receipt_digests)
        ):
            raise Phase4QualificationError("Phase 4 selection pins are invalid")
        object.__setattr__(self, "selection_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        try:
            rebuilt = Phase4SelectionPins(
                self.package_artifact_digest, self.phase_3_decision_digest,
                self.phase_3_receipt_digest, self.issue_97_evidence_digest,
                self.issue_97_result_digest, self.issue_97_receipt_digest,
                self.issue_97_profile_digest, self.issue_97_schema_digest,
                self.source_candidate_sha, self.cross_environment_profile,
                self.cross_environment_schema, self.historical_ready_at,
                self.exit_receipt_digests,
            )
            if rebuilt.selection_digest != self.selection_digest:
                raise ValueError
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 selection pins have drifted") from error

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        if include_digest:
            self.validate()
        value: dict[str, object] = {
            "package_artifact_digest": self.package_artifact_digest,
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
            "exit_receipt_digests": list(self.exit_receipt_digests),
        }
        return value | ({"selection_digest": self.selection_digest} if include_digest else {})


@dataclass(frozen=True)
class _RetainedExitReceipt:
    area: ExitEvidenceArea
    source_candidate_sha: str
    source_digest: str
    receipt_digest: str

    def public_payload(self) -> dict[str, str]:
        return {
            "area": self.area.value, "source_candidate_sha": self.source_candidate_sha,
            "source_digest": self.source_digest, "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class _RetainedEvidence:
    phase_3_candidate_sha: str
    phase_3_decision_digest: str
    phase_3_receipt_digest: str
    lineage_qualification_candidate_sha: str
    evidence: CrossEnvironmentEvidence
    comparison: CrossEnvironmentComparison
    cross_environment_receipt_digest: str
    topology: dict[str, object]
    exit_receipts: tuple[_RetainedExitReceipt, ...]
    confidence: EvidenceConfidence
    residual_risks: tuple[str, ...]


def _parse_evidence(value: object) -> CrossEnvironmentEvidence:
    payload = _require_keys(value, {
        "schema", "candidate_sha", "artifact_digest", "policy_digest", "profile_digest",
        "schema_digest", "producer_identity", "lanes", "sealed_canary", "result",
    }, "retained #97 evidence")
    try:
        if type(payload["lanes"]) is not list:
            raise ValueError
        lanes = tuple(EnvironmentLane(
            EnvironmentKind(item["environment"]), item["environment_identity"], OperationMode(item["mode"]),
            item["candidate_sha"], item["artifact_digest"], item["policy_digest"], item["profile_digest"],
            item["schema_digest"], item["producer_identity"], ReceiptState(item["receipt_state"]),
            item["receipt_digest"], item["observed_at"], ComparisonResult(item["result"]), item["reason"],
            tuple(ParityDimension(dimension) for dimension in item["parity_dimensions"]),
            item["parity_digest"], item["sealed_canary_receipt_digest"],
        ) for item in payload["lanes"])
        sealed_payload = _require_keys(payload["sealed_canary"], {
            "source_candidate_sha", "receipt_digest", "execution_ledger_digest", "lifecycle_ledger_digest",
            "lifecycle_comparison_digest", "target_repository", "target_merge_sha", "ready_at",
        }, "retained #96 receipt")
        evidence = CrossEnvironmentEvidence(
            payload["candidate_sha"], payload["artifact_digest"], payload["policy_digest"],
            payload["profile_digest"], payload["schema_digest"], payload["producer_identity"], lanes,
            SealedCanaryReceipt(
                sealed_payload["source_candidate_sha"], sealed_payload["receipt_digest"],
                sealed_payload["execution_ledger_digest"], sealed_payload["lifecycle_ledger_digest"],
                sealed_payload["lifecycle_comparison_digest"], sealed_payload["target_repository"],
                sealed_payload["target_merge_sha"], sealed_payload["ready_at"],
            ), payload["schema"],
        )
        if payload["result"] != evidence.result.value:
            raise ValueError
        return evidence
    except (AttributeError, KeyError, TypeError, ValueError, CrossEnvironmentEvidenceError) as error:
        raise Phase4QualificationError("retained #97 evidence is invalid") from error


def _parse_retained_bundle(contents: bytes) -> _RetainedEvidence:
    try:
        if type(contents) is not bytes:
            raise ValueError
        payload = _require_keys(json.loads(contents), {
            "schema", "phase_3", "cross_environment", "lineage", "consumer_topology", "exit_evidence",
            "confidence", "residual_risks",
        }, "retained Phase 4 bundle")
        if payload["schema"] != PHASE_4_RETAINED_EVIDENCE_SCHEMA:
            raise ValueError
        phase_3 = _require_keys(payload["phase_3"], {
            "schema", "profile", "candidate_sha", "decision_digest", "result", "receipt_digest",
        }, "retained #51 decision")
        phase_3_core = {key: value for key, value in phase_3.items() if key != "receipt_digest"}
        if (
            phase_3["schema"] != PHASE_3_DECISION_SCHEMA or phase_3["profile"] != PHASE_3_QUALIFICATION_PROFILE
            or _SHA.fullmatch(str(phase_3["candidate_sha"])) is None
            or phase_3["result"] != "PROMOTION_READY_FOR_CANARY_DECISION"
            or any(_DIGEST.fullmatch(str(phase_3[key])) is None for key in ("decision_digest", "receipt_digest"))
            or phase_3["receipt_digest"] != _digest(phase_3_core)
        ):
            raise ValueError
        cross = _require_keys(payload["cross_environment"], {"evidence", "comparison", "receipt"}, "retained #97 bundle")
        evidence = _parse_evidence(cross["evidence"])
        comparison_payload = _require_keys(cross["comparison"], {
            "schema", "result", "candidate_sha", "expected_digest", "observed_digest", "differences",
        }, "retained #97 result")
        comparison = CrossEnvironmentComparison(
            ComparisonResult(comparison_payload["result"]), comparison_payload["candidate_sha"],
            comparison_payload["expected_digest"], comparison_payload["observed_digest"],
            tuple(comparison_payload["differences"]), comparison_payload["schema"],
        )
        receipt = _require_keys(cross["receipt"], {
            "schema", "profile", "candidate_sha", "ready_at", "evidence_digest", "result_digest", "receipt_digest",
        }, "retained #97 receipt")
        receipt_core = {key: value for key, value in receipt.items() if key != "receipt_digest"}
        if (
            receipt["schema"] != PHASE_4_CROSS_ENVIRONMENT_RECEIPT_SCHEMA
            or receipt["profile"] != CROSS_ENVIRONMENT_CANARY_PROFILE
            or receipt["candidate_sha"] != evidence.candidate_sha
            or receipt["ready_at"] != evidence.sealed_canary.ready_at
            or receipt["evidence_digest"] != evidence.evidence_digest
            or receipt["result_digest"] != _digest(comparison.public_payload())
            or receipt["receipt_digest"] != _digest(receipt_core)
        ):
            raise ValueError
        lineage = _require_keys(payload["lineage"], {
            "schema", "source_candidate_sha", "qualification_candidate_sha", "relation", "receipt_digest",
        }, "retained candidate lineage")
        lineage_core = {key: value for key, value in lineage.items() if key != "receipt_digest"}
        if (
            lineage["schema"] != "roundwright-phase-4-candidate-lineage/v1"
            or lineage["source_candidate_sha"] != evidence.candidate_sha
            or _SHA.fullmatch(str(lineage["qualification_candidate_sha"])) is None
            or lineage["qualification_candidate_sha"] == evidence.candidate_sha
            or lineage["relation"] != "descendant"
            or lineage["receipt_digest"] != _digest(lineage_core)
        ):
            raise ValueError
        topology = _require_keys(payload["consumer_topology"], {
            "docker_artifact_digest", "devcontainer_artifact_digest", "devcontainer_feature_count", "devcontainer_template_count",
        }, "retained consumer topology")
        if (
            topology["docker_artifact_digest"] != evidence.artifact_digest
            or topology["devcontainer_artifact_digest"] != evidence.artifact_digest
            or topology["devcontainer_feature_count"] != 0 or topology["devcontainer_template_count"] != 0
        ):
            raise ValueError
        if type(payload["exit_evidence"]) is not list or len(payload["exit_evidence"]) != len(REQUIRED_EXIT_EVIDENCE):
            raise ValueError
        exits: list[_RetainedExitReceipt] = []
        for area, item in zip(REQUIRED_EXIT_EVIDENCE, payload["exit_evidence"], strict=True):
            receipt_value = _require_keys(item, {
                "schema", "area", "source_candidate_sha", "source_digest", "result", "receipt_digest",
            }, "retained exit receipt")
            core = {key: value for key, value in receipt_value.items() if key != "receipt_digest"}
            if (
                receipt_value["schema"] != PHASE_4_EXIT_RECEIPT_SCHEMA or receipt_value["area"] != area.value
                or receipt_value["source_candidate_sha"] != evidence.candidate_sha
                or receipt_value["source_digest"] != evidence.evidence_digest or receipt_value["result"] != "pass"
                or receipt_value["receipt_digest"] != _digest(core)
            ):
                raise ValueError
            exits.append(_RetainedExitReceipt(area, receipt_value["source_candidate_sha"], receipt_value["source_digest"], receipt_value["receipt_digest"]))
        if len({item.receipt_digest for item in exits}) != len(exits):
            raise ValueError
        confidence = EvidenceConfidence(payload["confidence"])
        risks = tuple(payload["residual_risks"])
        if type(payload["residual_risks"]) is not list or any(not is_safe_cross_environment_public_string(item) for item in risks) or tuple(sorted(set(risks))) != risks:
            raise ValueError
        return _RetainedEvidence(
            phase_3["candidate_sha"], phase_3["decision_digest"], phase_3["receipt_digest"], lineage["qualification_candidate_sha"],
            evidence, comparison, receipt["receipt_digest"], dict(topology), tuple(exits), confidence, risks,
        )
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError, CrossEnvironmentEvidenceError, Phase4QualificationError) as error:
        if isinstance(error, Phase4QualificationError):
            raise
        raise Phase4QualificationError("retained Phase 4 bundle is invalid") from error


@dataclass(frozen=True)
class Phase4QualificationInputs:
    """Selection pins plus independently retained #51/#96/#97 bytes."""

    qualification_candidate_sha: str
    selection_pins: Phase4SelectionPins
    retained_bundle_bytes: bytes
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.qualification_candidate_sha) is None
            or type(self.selection_pins) is not Phase4SelectionPins or type(self.retained_bundle_bytes) is not bytes
        ):
            raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
        object.__setattr__(self, "input_digest", _digest(self._identity_payload()))
        self.validate()

    def _identity_payload(self) -> dict[str, str]:
        return {
            "qualification_candidate_sha": self.qualification_candidate_sha,
            "selection_digest": self.selection_pins.selection_digest,
            "retained_bundle_digest": "sha256:" + hashlib.sha256(self.retained_bundle_bytes).hexdigest(),
        }

    def validate(self) -> _RetainedEvidence:
        try:
            self.selection_pins.validate()
            if self.input_digest != _digest(self._identity_payload()):
                raise ValueError
            observed = _parse_retained_bundle(self.retained_bundle_bytes)
            pins = self.selection_pins
            if (
                self.qualification_candidate_sha == observed.evidence.candidate_sha
                or observed.lineage_qualification_candidate_sha != self.qualification_candidate_sha
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
                or observed.phase_3_decision_digest != pins.phase_3_decision_digest
                or observed.phase_3_receipt_digest != pins.phase_3_receipt_digest
                or tuple(item.receipt_digest for item in observed.exit_receipts) != pins.exit_receipt_digests
            ):
                raise ValueError
            return observed
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 qualification evidence is invalid or stale") from error


@dataclass(frozen=True)
class Phase4OwnerDecision:
    """Public-safe owner input; it carries no activation or mutation authority."""

    disposition: str
    qualification_candidate_sha: str
    retained_evidence_candidate_sha: str
    package_artifact_digest: str
    phase_3_receipt_digest: str
    cross_environment_evidence_digest: str
    cross_environment_result_digest: str
    cross_environment_receipt_digest: str
    sealed_canary_receipt_digest: str
    historical_ready_at: int
    exit_evidence: tuple[_RetainedExitReceipt, ...]
    confidence: EvidenceConfidence
    residual_risks: tuple[str, ...]
    input_digest: str
    schema: str = PHASE_4_QUALIFICATION_SCHEMA
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            self.schema != PHASE_4_QUALIFICATION_SCHEMA
            or self.disposition not in {PHASE_5_OWNER_DECISION_REQUIRED, PHASE_4_QUALIFICATION_BLOCKED}
            or any(_SHA.fullmatch(value) is None for value in (self.qualification_candidate_sha, self.retained_evidence_candidate_sha))
            or self.qualification_candidate_sha == self.retained_evidence_candidate_sha
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.package_artifact_digest, self.phase_3_receipt_digest, self.cross_environment_evidence_digest,
                self.cross_environment_result_digest, self.cross_environment_receipt_digest,
                self.sealed_canary_receipt_digest, self.input_digest,
            ))
            or type(self.historical_ready_at) is not int or self.historical_ready_at < 0
            or type(self.exit_evidence) is not tuple or tuple(item.area for item in self.exit_evidence) != REQUIRED_EXIT_EVIDENCE
            or any(type(item) is not _RetainedExitReceipt for item in self.exit_evidence)
            or type(self.confidence) is not EvidenceConfidence
            or type(self.residual_risks) is not tuple or any(not is_safe_cross_environment_public_string(item) for item in self.residual_risks)
        ):
            raise Phase4QualificationError("Phase 4 owner decision is invalid")
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        try:
            rebuilt = Phase4OwnerDecision(
                self.disposition, self.qualification_candidate_sha, self.retained_evidence_candidate_sha,
                self.package_artifact_digest, self.phase_3_receipt_digest, self.cross_environment_evidence_digest,
                self.cross_environment_result_digest, self.cross_environment_receipt_digest,
                self.sealed_canary_receipt_digest, self.historical_ready_at, self.exit_evidence,
                self.confidence, self.residual_risks, self.input_digest, self.schema,
            )
            if rebuilt.decision_digest != self.decision_digest:
                raise ValueError
        except (AttributeError, TypeError, ValueError, Phase4QualificationError) as error:
            raise Phase4QualificationError("Phase 4 owner decision has drifted") from error

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        if include_digest:
            self.validate()
        value: dict[str, object] = {
            "schema": self.schema, "disposition": self.disposition,
            "qualification_candidate_sha": self.qualification_candidate_sha,
            "retained_evidence_candidate_sha": self.retained_evidence_candidate_sha,
            "package_artifact_digest": self.package_artifact_digest,
            "phase_3_receipt_digest": self.phase_3_receipt_digest,
            "cross_environment_evidence_digest": self.cross_environment_evidence_digest,
            "cross_environment_result_digest": self.cross_environment_result_digest,
            "cross_environment_receipt_digest": self.cross_environment_receipt_digest,
            "sealed_canary_receipt_digest": self.sealed_canary_receipt_digest,
            "historical_ready_at": self.historical_ready_at,
            "exit_evidence": [item.public_payload() for item in self.exit_evidence],
            "confidence": self.confidence.value, "residual_risks": list(self.residual_risks),
            "input_digest": self.input_digest, "authority": "owner-decision-required", "mutation_count": 0,
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_4_qualification(inputs: Phase4QualificationInputs) -> Phase4OwnerDecision:
    """Return a Phase 5 owner input only after full pin/read-back reconciliation."""

    if type(inputs) is not Phase4QualificationInputs:
        raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
    observed = inputs.validate()
    evidence = observed.evidence
    blocked = observed.confidence is not EvidenceConfidence.HIGH or bool(observed.residual_risks)
    return Phase4OwnerDecision(
        PHASE_4_QUALIFICATION_BLOCKED if blocked else PHASE_5_OWNER_DECISION_REQUIRED,
        inputs.qualification_candidate_sha, evidence.candidate_sha, evidence.artifact_digest,
        observed.phase_3_receipt_digest, evidence.evidence_digest, _digest(observed.comparison.public_payload()),
        observed.cross_environment_receipt_digest, evidence.sealed_canary.receipt_digest,
        evidence.sealed_canary.ready_at, observed.exit_receipts, observed.confidence,
        observed.residual_risks, inputs.input_digest,
    )
