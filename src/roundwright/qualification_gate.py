"""Pure Phase 3 qualification consumer for the owner-facing Canary decision.

The #51 gate consumes sealed #49 and #50 evidence without pretending that
their historical candidates are the new qualification candidate. It performs
no Harness, provider, forward-target, lifecycle, or cleanup action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
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
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class QualificationGateError(ValueError):
    """Raised when a retained qualification package has drifted or mixed data."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST = "sha256:5046fd4eed52db54f6b797464bf4faf4082290ec9cf12d3de194f624f8ca8d8a"
STALE_ISSUE_50_TRACE_DIGEST = "sha256:5046fd4e0c805cefacbe92dd28f72c95be164baad0caa35e7414cab198478d8a"


def issue_51_selection_trace_correction() -> dict[str, str]:
    """Curated non-mutating disposition for the known #51 selection-trace drift."""

    return {
        "disposition": "ORCHESTRATOR_TRACE_CORRECTION_REQUIRED",
        "recorded_digest": STALE_ISSUE_50_TRACE_DIGEST,
        "verified_digest": VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST,
        "required_action": "publish-and-semantic-read-back-curated-trace-correction",
    }


class QualificationGateKind(StrEnum):
    FORMAL_REVIEW = "formal-review"
    HOSTED_CHECKS = "hosted-checks"
    POLICY = "policy"
    PROVENANCE = "provenance"


@dataclass(frozen=True, slots=True)
class QualificationGateReceipt:
    """One independently read-back, candidate-bound normal-gate receipt."""

    kind: QualificationGateKind
    candidate_sha: str
    case_id: str
    review_epoch: int
    review_round: int
    review_mode: str
    result: Literal["pass"]
    source_identity: str
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.kind) is not QualificationGateKind or _SHA.fullmatch(self.candidate_sha) is None
            or _TOKEN.fullmatch(self.case_id) is None or type(self.review_epoch) is not int or self.review_epoch < 0
            or type(self.review_round) is not int or self.review_round < 0 or self.review_mode != "COMPLETE"
            or self.result != "pass" or _DIGEST.fullmatch(self.source_identity) is None):
            raise QualificationGateError("qualification gate receipt is invalid")
        object.__setattr__(self, "receipt_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"kind": self.kind.value, "candidate_sha": self.candidate_sha, "case_id": self.case_id,
            "review_epoch": self.review_epoch, "review_round": self.review_round, "review_mode": self.review_mode,
            "result": self.result, "source_identity": self.source_identity}
        return value | ({"receipt_digest": self.receipt_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class QualificationGateReceiptSet:
    """Exact four-gate read-back set; no caller booleans cross this boundary."""

    receipts: tuple[QualificationGateReceipt, ...]
    binding_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.receipts) is not tuple or any(type(item) is not QualificationGateReceipt for item in self.receipts)
            or tuple(item.kind for item in self.receipts) != tuple(QualificationGateKind)
            or len({item.receipt_digest for item in self.receipts}) != len(self.receipts)):
            raise QualificationGateError("qualification gate receipt set is invalid")
        object.__setattr__(self, "binding_digest", _digest(self.public_payload(include_digest=False)))

    def validate_for(self, candidate_sha: str, case_id: str) -> None:
        if (type(self) is not QualificationGateReceiptSet or self.binding_digest != _digest(self.public_payload(include_digest=False))
            or any((item.candidate_sha, item.case_id) != (candidate_sha, case_id) or item.receipt_digest != _digest(item.public_payload(include_digest=False)) for item in self.receipts)):
            raise QualificationGateError("qualification gate receipts have drifted")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"receipts": [item.public_payload() for item in self.receipts]}
        return value | ({"binding_digest": self.binding_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class RetainedIssue50BundleReceipt:
    """Public-safe verified Harness bundle binding for retained #50 composition."""

    candidate_sha: str
    retention_manifest_digest: str
    composed_manifest_digest: str
    composed_result_digest: str
    bundle_digest: str
    receipt_identity: str = field(init=False)

    def __post_init__(self) -> None:
        if _SHA.fullmatch(self.candidate_sha) is None or any(_DIGEST.fullmatch(value) is None for value in (self.retention_manifest_digest, self.composed_manifest_digest, self.composed_result_digest, self.bundle_digest)):
            raise QualificationGateError("retained issue-50 bundle receipt is invalid")
        object.__setattr__(self, "receipt_identity", _digest(self.public_payload(include_identity=False)))

    def public_payload(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"candidate_sha": self.candidate_sha, "retention_manifest_digest": self.retention_manifest_digest,
            "composed_manifest_digest": self.composed_manifest_digest, "composed_result_digest": self.composed_result_digest,
            "bundle_digest": self.bundle_digest}
        return value | ({"receipt_identity": self.receipt_identity} if include_identity else {})

    def validate(self) -> None:
        if type(self) is not RetainedIssue50BundleReceipt or self.receipt_identity != _digest(self.public_payload(include_identity=False)):
            raise QualificationGateError("retained issue-50 bundle receipt has drifted")


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
        current = getattr(self, "binding_digest", None)
        if current is not None and current != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("retained evidence binding has drifted")

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

    @property
    def promotion_eligible(self) -> bool:
        """Preserved unique/ambiguous work is safe, but blocks promotion."""

        return self.fully_reconciled and not any(
            entry.kind in {TemporaryResourceKind.UNIQUE, TemporaryResourceKind.AMBIGUOUS}
            for entry in self.entries
        )

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"entries": [entry.public_payload() for entry in self.entries]}
        return value | ({"inventory_digest": self.inventory_digest} if include_digest else {})

    def validate(self) -> None:
        if type(self) is not TemporaryResourceInventory:
            raise QualificationGateError("temporary resource inventory has drifted")
        try:
            for entry in self.entries:
                TemporaryResourceEntry(entry.resource_identity, entry.kind, entry.disposition)
        except (AttributeError, TypeError, QualificationGateError) as error:
            raise QualificationGateError("temporary resource inventory has drifted") from error
        if self.inventory_digest != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("temporary resource inventory has drifted")


@dataclass(frozen=True, slots=True)
class Phase3QualificationInputs:
    """Closed #51 consumer inputs with distinct #49, #50, and #51 lineages."""

    base_sha: str
    qualification_candidate_sha: str
    qualification_case_id: str
    qualification_ready_at: int
    qualification_review_epoch: int
    qualification_review_round: int
    qualification_review_mode: str
    qualification_capture_plan_digest: str
    qualification_recorder_identity: str
    qualification_store_identity: str
    issue_49_candidate_sha: str
    issue_50_candidate_sha: str
    roundlet_commit: str
    harness_commit: str
    forward_target_commit: str
    rollback_proposal_digest: str
    kill_switch_proposal_digest: str
    retained_evidence: RetainedEvidenceBinding
    issue_50_bundle_receipt: RetainedIssue50BundleReceipt
    temporary_resources: TemporaryResourceInventory
    integrated_inputs: IntegratedBoundaryInputs
    composed_manifest: ComposedEvidenceManifest
    composed_result: ComposedEvidenceResult
    lane_a: EvidenceLaneReceipt
    lane_b: EvidenceLaneReceipt
    current_gate_receipts: QualificationGateReceiptSet
    unresolved_blockers: tuple[QualificationGateKind, ...] = ()
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            any(_SHA.fullmatch(value) is None for value in (self.base_sha, self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha, self.roundlet_commit, self.harness_commit, self.forward_target_commit))
            or _TOKEN.fullmatch(self.qualification_case_id) is None or type(self.qualification_ready_at) is not int or self.qualification_ready_at < 0
            or type(self.qualification_review_epoch) is not int or self.qualification_review_epoch < 0 or type(self.qualification_review_round) is not int or self.qualification_review_round < 0 or self.qualification_review_mode != "COMPLETE"
            or any(_DIGEST.fullmatch(value) is None for value in (self.qualification_capture_plan_digest, self.qualification_recorder_identity, self.qualification_store_identity, self.rollback_proposal_digest, self.kill_switch_proposal_digest))
            or len({self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha}) != 3
            or type(self.retained_evidence) is not RetainedEvidenceBinding or type(self.issue_50_bundle_receipt) is not RetainedIssue50BundleReceipt or type(self.temporary_resources) is not TemporaryResourceInventory
            or type(self.integrated_inputs) is not IntegratedBoundaryInputs or type(self.composed_manifest) is not ComposedEvidenceManifest or type(self.composed_result) is not ComposedEvidenceResult
            or type(self.lane_a) is not EvidenceLaneReceipt or type(self.lane_b) is not EvidenceLaneReceipt or type(self.current_gate_receipts) is not QualificationGateReceiptSet
            or type(self.unresolved_blockers) is not tuple or any(type(value) is not QualificationGateKind for value in self.unresolved_blockers) or len(set(self.unresolved_blockers)) != len(self.unresolved_blockers)
        ):
            raise QualificationGateError("phase-3 qualification evidence is invalid")
        self.retained_evidence.validate(); self.issue_50_bundle_receipt.validate(); self.temporary_resources.validate()
        self.current_gate_receipts.validate_for(self.qualification_candidate_sha, self.qualification_case_id)
        if any((item.review_epoch, item.review_round, item.review_mode) != (self.qualification_review_epoch, self.qualification_review_round, self.qualification_review_mode) for item in self.current_gate_receipts.receipts):
            raise QualificationGateError("qualification gate receipts have a stale formal review binding")
        if (
            not verify_composed_evidence(self.composed_manifest, self.composed_result)
            or self.composed_manifest.inputs != self.integrated_inputs or self.composed_result.manifest != self.composed_manifest
            or self.integrated_inputs.expectation.retention_manifest_digest != self.retained_evidence.expected.issue_49_retention_manifest_digest
            or (self.issue_50_bundle_receipt.candidate_sha, self.issue_50_bundle_receipt.retention_manifest_digest, self.issue_50_bundle_receipt.composed_manifest_digest, self.issue_50_bundle_receipt.composed_result_digest, self.issue_50_bundle_receipt.bundle_digest)
            != (self.issue_50_candidate_sha, self.composed_manifest.inputs.expectation.retention_manifest_digest, self.composed_manifest.manifest_digest, self.composed_result.result_digest, self.retained_evidence.expected.issue_50_result_bundle_digest)
            or self.retained_evidence.expected.issue_50_retention_manifest_digest != self.issue_50_bundle_receipt.retention_manifest_digest
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

    def validate(self) -> None:
        """Reconstruct this closed input tuple to detect post-build drift."""

        try:
            rebuilt = replace(self)
        except (AttributeError, TypeError, ValueError, QualificationGateError) as error:
            raise QualificationGateError("phase-3 qualification evidence has drifted") from error
        if rebuilt.input_digest != self.input_digest:
            raise QualificationGateError("phase-3 qualification evidence has drifted")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE,
            "base_sha": self.base_sha, "qualification_candidate_sha": self.qualification_candidate_sha,
            "qualification_case_id": self.qualification_case_id, "qualification_ready_at": self.qualification_ready_at,
            "qualification_review_epoch": self.qualification_review_epoch, "qualification_review_round": self.qualification_review_round, "qualification_review_mode": self.qualification_review_mode,
            "qualification_capture_plan_digest": self.qualification_capture_plan_digest,
            "qualification_recorder_identity": self.qualification_recorder_identity,
            "qualification_store_identity": self.qualification_store_identity,
            "issue_49_candidate_sha": self.issue_49_candidate_sha, "issue_50_candidate_sha": self.issue_50_candidate_sha,
            "roundlet_commit": self.roundlet_commit, "harness_commit": self.harness_commit, "forward_target_commit": self.forward_target_commit,
            "rollback_proposal_digest": self.rollback_proposal_digest, "kill_switch_proposal_digest": self.kill_switch_proposal_digest,
            "retained_evidence": self.retained_evidence.public_payload(), "temporary_resources": self.temporary_resources.public_payload(),
            "issue_50_bundle_receipt": self.issue_50_bundle_receipt.public_payload(), "current_gate_receipts": self.current_gate_receipts.public_payload(),
            "retained_issue_50_capture_plan_digest": self.integrated_inputs.capture_plan_digest,
            "composed_manifest_digest": self.composed_manifest.manifest_digest,
            "composed_result_digest": self.composed_result.result_digest,
            "retained_sources": [source.public_payload() | {"source_digest": source.source_digest} for source in (self.integrated_inputs.lane_a, self.integrated_inputs.lane_b, self.integrated_inputs.historical_reference, self.integrated_inputs.synthetic_reference)],
            "composed_manifest": self.composed_manifest.public_payload(), "composed_result": self.composed_result.public_payload(),
            "lane_a": {"state": self.lane_a.state, "result": self.lane_a.result}, "lane_b": {"state": self.lane_b.state, "result": self.lane_b.result},
            "unresolved_blockers": [item.value for item in self.unresolved_blockers], "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
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
            "qualification": self.inputs.public_payload(),
            "runtime_activation_authorized": False, "roundlet_retirement_authorized": False,
            "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_3_qualification(inputs: Phase3QualificationInputs) -> CanaryEntryDecisionPackage:
    """Evaluate retained evidence without external calls, storage, or cleanup."""

    if type(inputs) is not Phase3QualificationInputs:
        raise QualificationGateError("phase-3 qualification inputs are invalid")
    inputs.validate()
    lanes_pass = (inputs.lane_a.state, inputs.lane_a.result, inputs.lane_b.state, inputs.lane_b.result) == ("verified", "pass", "verified", "pass")
    ready = lanes_pass and inputs.temporary_resources.promotion_eligible and not inputs.unresolved_blockers
    return CanaryEntryDecisionPackage(inputs, PROMOTION_READY_FOR_CANARY_DECISION if ready else QUALIFICATION_BLOCKED)
