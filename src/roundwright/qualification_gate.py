"""Pure Phase 3 qualification consumer for the owner-facing Canary decision.

The #51 gate consumes sealed #49 and #50 evidence without pretending that
their historical candidates are the new qualification candidate. It performs
no Harness, provider, forward-target, lifecycle, or cleanup action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from .external_validation import EvidenceLaneReceipt
from .integrated_boundary import ComposedEvidenceManifest, ComposedEvidenceResult, IntegratedBoundaryInputs, verify_composed_evidence
from .shadow import LIVE_LIFECYCLE_SHADOW_PROFILE, PHASE_3_QUALIFICATION_PROFILE, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE


QUALIFICATION_DECISION_SCHEMA = "roundwright-phase-3-qualification-decision/v1"
PROMOTION_READY_FOR_CANARY_DECISION = "PROMOTION_READY_FOR_CANARY_DECISION"
QUALIFICATION_BLOCKED = "QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class QualificationGateError(ValueError):
    """Raised when a retained qualification package has drifted or mixed data."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


class TemporaryResourceKind(StrEnum):
    REPLAYABLE = "replayable"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


class TemporaryResourceDisposition(StrEnum):
    REMOVED = "removed"
    PRESERVED = "preserved"


@dataclass(frozen=True, slots=True)
class RetainedEvidencePins:
    """Selection-time expected identities from the immutable Roundlet contract."""

    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str
    issue_50_result_bundle_digest: str
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if any(_DIGEST.fullmatch(value) is None for value in self.payload().values()):
            raise QualificationGateError("retained evidence pins are invalid")
        object.__setattr__(self, "integrity_digest", _digest(self.payload()))

    def payload(self) -> dict[str, str]:
        return {
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
            "issue_50_result_bundle_digest": self.issue_50_result_bundle_digest,
        }

    def validate(self) -> None:
        if type(self) is not RetainedEvidencePins or self.integrity_digest != _digest(self.payload()):
            raise QualificationGateError("retained evidence pins have drifted")


@dataclass(frozen=True, slots=True)
class RetainedEvidenceObservations:
    """Read-back identities for the same three retained artifacts."""

    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str
    issue_50_result_bundle_digest: str
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if any(_DIGEST.fullmatch(value) is None for value in self.payload().values()):
            raise QualificationGateError("retained evidence observations are invalid")
        object.__setattr__(self, "integrity_digest", _digest(self.payload()))

    def payload(self) -> dict[str, str]:
        return {
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
            "issue_50_result_bundle_digest": self.issue_50_result_bundle_digest,
        }

    def validate(self) -> None:
        if type(self) is not RetainedEvidenceObservations or self.integrity_digest != _digest(self.payload()):
            raise QualificationGateError("retained evidence observations have drifted")


@dataclass(frozen=True, slots=True)
class RetainedEvidenceBinding:
    """Closed expected-versus-observed binding; neither side may be substituted."""

    expected: RetainedEvidencePins
    observed: RetainedEvidenceObservations
    binding_digest: str = field(init=False)

    def __post_init__(self) -> None:
        self.validate()
        object.__setattr__(self, "binding_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        if type(self) is not RetainedEvidenceBinding or type(self.expected) is not RetainedEvidencePins or type(self.observed) is not RetainedEvidenceObservations:
            raise QualificationGateError("retained evidence binding is invalid")
        self.expected.validate(); self.observed.validate()
        if self.expected.payload() != self.observed.payload():
            raise QualificationGateError("retained evidence read-back does not match selection")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "expected": self.expected.payload(), "expected_integrity_digest": self.expected.integrity_digest,
            "observed": self.observed.payload(), "observed_integrity_digest": self.observed.integrity_digest,
        }
        return value | ({"binding_digest": self.binding_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class TemporaryResourceEntry:
    """A path-free cleanup disposition; unique or ambiguous work is preserved."""

    resource_identity: str
    kind: TemporaryResourceKind
    disposition: TemporaryResourceDisposition

    def __post_init__(self) -> None:
        if (
            _DIGEST.fullmatch(self.resource_identity) is None
            or type(self.kind) is not TemporaryResourceKind
            or type(self.disposition) is not TemporaryResourceDisposition
            or (self.kind is TemporaryResourceKind.REPLAYABLE) != (self.disposition is TemporaryResourceDisposition.REMOVED)
        ):
            raise QualificationGateError("temporary resource disposition is invalid")

    def public_payload(self) -> dict[str, str]:
        return {"resource_identity": self.resource_identity, "kind": self.kind.value, "disposition": self.disposition.value}


@dataclass(frozen=True, slots=True)
class TemporaryResourceInventory:
    """Recomputed inventory identity, never an arbitrary digest or Boolean."""

    entries: tuple[TemporaryResourceEntry, ...]
    inventory_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(type(entry) is not TemporaryResourceEntry for entry in self.entries) or len({entry.resource_identity for entry in self.entries}) != len(self.entries):
            raise QualificationGateError("temporary resource inventory is invalid")
        object.__setattr__(self, "inventory_digest", _digest(self.public_payload(include_digest=False)))

    @property
    def fully_reconciled(self) -> bool:
        return all(
            (entry.kind is TemporaryResourceKind.REPLAYABLE and entry.disposition is TemporaryResourceDisposition.REMOVED)
            or (entry.kind in {TemporaryResourceKind.UNIQUE, TemporaryResourceKind.AMBIGUOUS} and entry.disposition is TemporaryResourceDisposition.PRESERVED)
            for entry in self.entries
        )

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"entries": [entry.public_payload() for entry in self.entries]}
        return value | ({"inventory_digest": self.inventory_digest} if include_digest else {})

    def validate(self) -> None:
        if type(self) is not TemporaryResourceInventory or self.inventory_digest != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("temporary resource inventory has drifted")


@dataclass(frozen=True, slots=True)
class Phase3QualificationInputs:
    """Closed #51 consumer inputs with distinct #49, #50, and #51 lineages."""

    base_sha: str
    qualification_candidate_sha: str
    issue_49_candidate_sha: str
    issue_50_candidate_sha: str
    harness_commit: str
    forward_target_commit: str
    retained_evidence: RetainedEvidenceBinding
    temporary_resources: TemporaryResourceInventory
    integrated_inputs: IntegratedBoundaryInputs
    composed_manifest: ComposedEvidenceManifest
    composed_result: ComposedEvidenceResult
    lane_a: EvidenceLaneReceipt
    lane_b: EvidenceLaneReceipt
    supervisor_pass: bool
    ci_pass: bool
    policy_pass: bool
    provenance_pass: bool
    unresolved_blockers: tuple[str, ...] = ()
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            any(_SHA.fullmatch(value) is None for value in (self.base_sha, self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha, self.harness_commit, self.forward_target_commit))
            or len({self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha}) != 3
            or type(self.retained_evidence) is not RetainedEvidenceBinding or type(self.temporary_resources) is not TemporaryResourceInventory
            or type(self.integrated_inputs) is not IntegratedBoundaryInputs or type(self.composed_manifest) is not ComposedEvidenceManifest or type(self.composed_result) is not ComposedEvidenceResult
            or type(self.lane_a) is not EvidenceLaneReceipt or type(self.lane_b) is not EvidenceLaneReceipt
            or any(type(value) is not bool for value in (self.supervisor_pass, self.ci_pass, self.policy_pass, self.provenance_pass))
            or type(self.unresolved_blockers) is not tuple or any(type(value) is not str or not value for value in self.unresolved_blockers) or len(set(self.unresolved_blockers)) != len(self.unresolved_blockers)
        ):
            raise QualificationGateError("phase-3 qualification evidence is invalid")
        self.retained_evidence.validate(); self.temporary_resources.validate()
        if (
            not verify_composed_evidence(self.composed_manifest, self.composed_result)
            or self.composed_manifest.inputs != self.integrated_inputs or self.composed_result.manifest != self.composed_manifest
            or self.integrated_inputs.expectation.retention_manifest_digest != self.retained_evidence.expected.issue_49_retention_manifest_digest
            or self.composed_result.result != "pass"
            or self.composed_manifest.inputs.candidate_sha != self.issue_50_candidate_sha or self.composed_result.manifest.inputs.candidate_sha != self.issue_50_candidate_sha
            or self.integrated_inputs.lane_a.candidate_sha != self.issue_49_candidate_sha or self.integrated_inputs.lane_b.candidate_sha != self.issue_49_candidate_sha
            or self.lane_a.candidate_sha != self.issue_49_candidate_sha or self.lane_b.candidate_sha != self.issue_49_candidate_sha
            or self.lane_a.profile_id != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE or self.lane_b.profile_id != LIVE_LIFECYCLE_SHADOW_PROFILE
        ):
            raise QualificationGateError("phase-3 qualification lineage is invalid")
        composed = self.composed_manifest.public_payload()
        if composed["new_provider_calls"] != 0 or composed["new_target_actions"] != 0 or composed["lifecycle_observation_sink"] != "NOT_SELECTED":
            raise QualificationGateError("phase-3 qualification evidence is not consumer-only")
        object.__setattr__(self, "input_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE,
            "base_sha": self.base_sha, "qualification_candidate_sha": self.qualification_candidate_sha,
            "issue_49_candidate_sha": self.issue_49_candidate_sha, "issue_50_candidate_sha": self.issue_50_candidate_sha,
            "harness_commit": self.harness_commit, "forward_target_commit": self.forward_target_commit,
            "retained_evidence": self.retained_evidence.public_payload(), "temporary_resources": self.temporary_resources.public_payload(),
            "capture_plan_digest": self.integrated_inputs.capture_plan_digest, "composed_manifest_digest": self.composed_manifest.manifest_digest,
            "composed_result_digest": self.composed_result.result_digest,
            "lane_a": {"state": self.lane_a.state, "result": self.lane_a.result}, "lane_b": {"state": self.lane_b.state, "result": self.lane_b.result},
            "supervisor_pass": self.supervisor_pass, "ci_pass": self.ci_pass, "policy_pass": self.policy_pass, "provenance_pass": self.provenance_pass,
            "unresolved_blockers": list(self.unresolved_blockers), "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"input_digest": self.input_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class CanaryEntryDecisionPackage:
    """Public-safe owner decision package; never an authority or action receipt."""

    inputs: Phase3QualificationInputs
    disposition: Literal["PROMOTION_READY_FOR_CANARY_DECISION", "QUALIFICATION_BLOCKED"]
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.inputs) is not Phase3QualificationInputs or self.disposition not in {PROMOTION_READY_FOR_CANARY_DECISION, QUALIFICATION_BLOCKED}:
            raise QualificationGateError("Canary-entry decision package is invalid")
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE, "disposition": self.disposition,
            "input_digest": self.inputs.input_digest, "base_sha": self.inputs.base_sha,
            "qualification_candidate_sha": self.inputs.qualification_candidate_sha, "issue_49_candidate_sha": self.inputs.issue_49_candidate_sha,
            "issue_50_candidate_sha": self.inputs.issue_50_candidate_sha, "composed_manifest_digest": self.inputs.composed_manifest.manifest_digest,
            "composed_result_digest": self.inputs.composed_result.result_digest, "canary_action_authorized": False,
            "runtime_activation_authorized": False, "roundlet_retirement_authorized": False,
            "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_3_qualification(inputs: Phase3QualificationInputs) -> CanaryEntryDecisionPackage:
    """Evaluate retained evidence without external calls, storage, or cleanup."""

    if type(inputs) is not Phase3QualificationInputs:
        raise QualificationGateError("phase-3 qualification inputs are invalid")
    lanes_pass = (inputs.lane_a.state, inputs.lane_a.result, inputs.lane_b.state, inputs.lane_b.result, inputs.supervisor_pass) == ("verified", "pass", "verified", "pass", True)
    ready = lanes_pass and inputs.ci_pass and inputs.policy_pass and inputs.provenance_pass and inputs.temporary_resources.fully_reconciled and not inputs.unresolved_blockers
    return CanaryEntryDecisionPackage(inputs, PROMOTION_READY_FOR_CANARY_DECISION if ready else QUALIFICATION_BLOCKED)
