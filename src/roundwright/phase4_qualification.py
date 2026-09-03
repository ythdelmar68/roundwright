"""Pure, fail-closed Phase 4 evidence consumer for Issue #98.

This module consumes the already-sealed #96 Canary receipt and #97
cross-environment comparison. It never invokes a provider, scheduler, target,
GitHub, lifecycle, or recorder. A passing result is only a public-safe owner
decision input for Phase 5; it is not promotion or mutation authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .cross_environment import (
    CROSS_ENVIRONMENT_EVIDENCE_SCHEMA,
    CROSS_ENVIRONMENT_LANE_ORDER,
    CROSS_ENVIRONMENT_RESULT_SCHEMA,
    PARITY_DIMENSIONS,
    ComparisonResult,
    CrossEnvironmentComparison,
    CrossEnvironmentEvidence,
    CrossEnvironmentEvidenceError,
    EnvironmentKind,
    OperationMode,
    is_safe_cross_environment_public_string,
    semantic_read_back,
)


PHASE_4_QUALIFICATION_SCHEMA = "roundwright-phase-4-qualification-decision/v1"
PHASE_5_OWNER_DECISION_REQUIRED = "PHASE_5_OWNER_DECISION_REQUIRED"
PHASE_4_QUALIFICATION_BLOCKED = "PHASE_4_QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class Phase4QualificationError(ValueError):
    """Raised when retained Phase 4 evidence is malformed, mixed, or stale."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


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
_MATRIX_AREAS = {
    ExitEvidenceArea.CANCELLATION, ExitEvidenceArea.STALE_RECOVERY,
    ExitEvidenceArea.LOCKS, ExitEvidenceArea.PATHS, ExitEvidenceArea.WORKTREES,
    ExitEvidenceArea.SQLITE, ExitEvidenceArea.CLI_WRAPPERS,
}


@dataclass(frozen=True)
class ExitEvidenceReceipt:
    """One public-safe retained digest for a required Phase 4 exit concern."""

    area: ExitEvidenceArea
    receipt_digest: str

    def __post_init__(self) -> None:
        if type(self.area) is not ExitEvidenceArea or _DIGEST.fullmatch(self.receipt_digest) is None:
            raise Phase4QualificationError("Phase 4 exit evidence receipt is invalid")

    def public_payload(self) -> dict[str, str]:
        return {"area": self.area.value, "receipt_digest": self.receipt_digest}


@dataclass(frozen=True)
class ConsumerTopology:
    """Artifact-only Docker and Dev Container bindings consumed by the gate."""

    docker_artifact_digest: str
    devcontainer_artifact_digest: str
    devcontainer_feature_count: int
    devcontainer_template_count: int

    def __post_init__(self) -> None:
        if (
            any(_DIGEST.fullmatch(value) is None for value in (
                self.docker_artifact_digest, self.devcontainer_artifact_digest,
            ))
            or type(self.devcontainer_feature_count) is not int
            or type(self.devcontainer_template_count) is not int
            or self.devcontainer_feature_count != 0
            or self.devcontainer_template_count != 0
        ):
            raise Phase4QualificationError("Phase 4 consumer topology is invalid")

    def public_payload(self) -> dict[str, object]:
        return {
            "docker_artifact_digest": self.docker_artifact_digest,
            "devcontainer_artifact_digest": self.devcontainer_artifact_digest,
            "devcontainer_feature_count": self.devcontainer_feature_count,
            "devcontainer_template_count": self.devcontainer_template_count,
        }


@dataclass(frozen=True)
class Phase4QualificationInputs:
    """The exact, immutable #51/#96/#97 inputs consumed by this gate."""

    candidate_sha: str
    package_artifact_digest: str
    phase_3_entry_decision_digest: str
    cross_environment_evidence: CrossEnvironmentEvidence
    cross_environment_comparison: CrossEnvironmentComparison
    retained_cross_environment_payload: dict[str, object]
    consumer_topology: ConsumerTopology
    exit_evidence: tuple[ExitEvidenceReceipt, ...]
    confidence: EvidenceConfidence = EvidenceConfidence.HIGH
    residual_risks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.package_artifact_digest, self.phase_3_entry_decision_digest,
            ))
            or type(self.cross_environment_evidence) is not CrossEnvironmentEvidence
            or type(self.cross_environment_comparison) is not CrossEnvironmentComparison
            or type(self.retained_cross_environment_payload) is not dict
            or type(self.consumer_topology) is not ConsumerTopology
            or type(self.exit_evidence) is not tuple
            or type(self.confidence) is not EvidenceConfidence
            or type(self.residual_risks) is not tuple
            or any(not is_safe_cross_environment_public_string(item) for item in self.residual_risks)
            or tuple(sorted(set(self.residual_risks))) != self.residual_risks
        ):
            raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
        self.validate()

    def validate(self) -> None:
        """Reconstruct every nested input before a decision is emitted."""

        try:
            evidence = self.cross_environment_evidence
            comparison = self.cross_environment_comparison
            payload = evidence.public_payload()
            retained_read_back = semantic_read_back(self.retained_cross_environment_payload, evidence)
            expected_areas = tuple(receipt.area for receipt in self.exit_evidence)
            if (
                evidence.schema != CROSS_ENVIRONMENT_EVIDENCE_SCHEMA
                or evidence.candidate_sha != self.candidate_sha
                or evidence.artifact_digest != self.package_artifact_digest
                or evidence.result is not ComparisonResult.PASS
                or comparison.schema != CROSS_ENVIRONMENT_RESULT_SCHEMA
                or comparison.result is not ComparisonResult.PASS
                or comparison.candidate_sha != self.candidate_sha
                or comparison.expected_digest != evidence.evidence_digest
                or comparison.observed_digest != evidence.evidence_digest
                or comparison.differences != ()
                or retained_read_back.result is not ComparisonResult.PASS
                or retained_read_back.expected_digest != evidence.evidence_digest
                or retained_read_back.observed_digest != evidence.evidence_digest
                or tuple(lane.environment for lane in evidence.lanes) != CROSS_ENVIRONMENT_LANE_ORDER
                or tuple(lane.parity_dimensions for lane in evidence.lanes[:-1]) != (PARITY_DIMENSIONS,) * 6
                or sum(lane.mode is OperationMode.AUTHORITATIVE for lane in evidence.lanes) != 1
                or any(lane.mode is OperationMode.AUTHORITATIVE for lane in evidence.lanes[1:])
                or evidence.lanes[-1].environment is not EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER
                or evidence.lanes[-1].mode is not OperationMode.READ_ONLY
                or self.consumer_topology.docker_artifact_digest != evidence.artifact_digest
                or self.consumer_topology.devcontainer_artifact_digest != evidence.artifact_digest
                or expected_areas != REQUIRED_EXIT_EVIDENCE
                or any(receipt.area in _MATRIX_AREAS and receipt.receipt_digest != evidence.evidence_digest for receipt in self.exit_evidence)
                or payload != self.retained_cross_environment_payload
            ):
                raise ValueError
        except (AttributeError, TypeError, ValueError, CrossEnvironmentEvidenceError) as error:
            raise Phase4QualificationError("Phase 4 qualification evidence is invalid or stale") from error

    @property
    def evidence_digest_set(self) -> tuple[str, ...]:
        self.validate()
        evidence = self.cross_environment_evidence
        values = (
            self.phase_3_entry_decision_digest, self.package_artifact_digest,
            evidence.evidence_digest, evidence.sealed_canary.receipt_digest,
            evidence.sealed_canary.execution_ledger_digest, evidence.sealed_canary.lifecycle_ledger_digest,
            evidence.sealed_canary.lifecycle_comparison_digest,
            _digest(self.cross_environment_comparison.public_payload()),
            *(receipt.receipt_digest for receipt in self.exit_evidence),
        )
        return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class Phase4OwnerDecision:
    """The public-safe Phase 5 owner-decision input and nothing more."""

    disposition: str
    candidate_sha: str
    package_artifact_digest: str
    cross_environment_evidence_digest: str
    sealed_canary_receipt_digest: str
    historical_ready_at: int
    evidence_digests: tuple[str, ...]
    confidence: EvidenceConfidence
    residual_risks: tuple[str, ...]
    phase_5_prerequisites: tuple[str, ...]
    schema: str = PHASE_4_QUALIFICATION_SCHEMA
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            self.schema != PHASE_4_QUALIFICATION_SCHEMA
            or self.disposition not in {PHASE_5_OWNER_DECISION_REQUIRED, PHASE_4_QUALIFICATION_BLOCKED}
            or _SHA.fullmatch(self.candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.package_artifact_digest, self.cross_environment_evidence_digest,
                self.sealed_canary_receipt_digest,
            ))
            or type(self.historical_ready_at) is not int or self.historical_ready_at < 0
            or type(self.evidence_digests) is not tuple or any(_DIGEST.fullmatch(item) is None for item in self.evidence_digests)
            or len(set(self.evidence_digests)) != len(self.evidence_digests)
            or type(self.confidence) is not EvidenceConfidence
            or type(self.residual_risks) is not tuple or any(not is_safe_cross_environment_public_string(item) for item in self.residual_risks)
            or type(self.phase_5_prerequisites) is not tuple or not self.phase_5_prerequisites
            or any(not is_safe_cross_environment_public_string(item) for item in self.phase_5_prerequisites)
        ):
            raise Phase4QualificationError("Phase 4 owner decision is invalid")
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        """Reject post-construction mutation before an owner sees a decision."""

        try:
            rebuilt = Phase4OwnerDecision(
                self.disposition, self.candidate_sha, self.package_artifact_digest,
                self.cross_environment_evidence_digest, self.sealed_canary_receipt_digest,
                self.historical_ready_at, self.evidence_digests, self.confidence, self.residual_risks,
                self.phase_5_prerequisites, self.schema,
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
            "candidate_sha": self.candidate_sha, "package_artifact_digest": self.package_artifact_digest,
            "cross_environment_evidence_digest": self.cross_environment_evidence_digest,
            "sealed_canary_receipt_digest": self.sealed_canary_receipt_digest,
            "historical_ready_at": self.historical_ready_at,
            "evidence_digests": list(self.evidence_digests), "confidence": self.confidence.value,
            "residual_risks": list(self.residual_risks),
            "phase_5_prerequisites": list(self.phase_5_prerequisites),
            "authority": "owner-decision-required", "mutation_count": 0,
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


_PHASE_5_PREREQUISITES = (
    "owner-phase-5-decision", "no-automatic-activation", "no-roundlet-retirement", "no-promotion-or-release",
)


def assess_phase_4_qualification(inputs: Phase4QualificationInputs) -> Phase4OwnerDecision:
    """Consume sealed evidence and produce a bounded Phase 5 owner input."""

    if type(inputs) is not Phase4QualificationInputs:
        raise Phase4QualificationError("Phase 4 qualification inputs are invalid")
    inputs.validate()
    evidence = inputs.cross_environment_evidence
    blocked = inputs.confidence is not EvidenceConfidence.HIGH or bool(inputs.residual_risks)
    return Phase4OwnerDecision(
        PHASE_4_QUALIFICATION_BLOCKED if blocked else PHASE_5_OWNER_DECISION_REQUIRED,
        inputs.candidate_sha, inputs.package_artifact_digest, evidence.evidence_digest,
        evidence.sealed_canary.receipt_digest, evidence.sealed_canary.ready_at,
        inputs.evidence_digest_set, inputs.confidence, inputs.residual_risks, _PHASE_5_PREREQUISITES,
    )
