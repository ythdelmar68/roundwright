"""Pure Phase 3 qualification consumer for the owner-facing Canary decision.

The #51 gate consumes previously sealed public-safe evidence.  It deliberately
does not load Harness, contact a provider or forward target, allocate a
lifecycle store, or clean resources.  Cleanup stays an explicit orchestrator
operation and must preserve ambiguous or unique work.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Literal

from .external_validation import EvidenceLaneReceipt, TwoStageQualification
from .integrated_boundary import (
    ComposedEvidenceManifest,
    ComposedEvidenceResult,
    IntegratedBoundaryInputs,
    verify_composed_evidence,
)
from .shadow import PHASE_3_QUALIFICATION_PROFILE


QUALIFICATION_DECISION_SCHEMA = "roundwright-phase-3-qualification-decision/v1"
PROMOTION_READY_FOR_CANARY_DECISION = "PROMOTION_READY_FOR_CANARY_DECISION"
QUALIFICATION_BLOCKED = "QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class QualificationGateError(ValueError):
    """Raised when a retained qualification package has drifted or mixed data."""


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class Phase3QualificationInputs:
    """Closed #51 consumer inputs, all public-safe and candidate-bound.

    The explicit retained manifests/bundle bind the immutable #49/#50
    inventories.  ``integrated_inputs`` and the composed result independently
    check every retained lower-level source, receipt, capture time, and #72
    capture-plan binding before this gate can assess current qualification.
    """

    base_sha: str
    candidate_sha: str
    harness_commit: str
    forward_target_commit: str
    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str
    issue_50_result_bundle_digest: str
    temporary_resource_inventory_digest: str
    integrated_inputs: IntegratedBoundaryInputs
    composed_manifest: ComposedEvidenceManifest
    composed_result: ComposedEvidenceResult
    lane_a: EvidenceLaneReceipt
    lane_b: EvidenceLaneReceipt
    supervisor_pass: bool
    ci_pass: bool
    policy_pass: bool
    provenance_pass: bool
    temporary_resources_reconciled: bool
    unresolved_blockers: tuple[str, ...] = ()
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            any(_SHA.fullmatch(value) is None for value in (
                self.base_sha, self.candidate_sha, self.harness_commit, self.forward_target_commit,
            ))
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.issue_49_retention_manifest_digest,
                self.issue_50_retention_manifest_digest,
                self.issue_50_result_bundle_digest,
                self.temporary_resource_inventory_digest,
            ))
            or type(self.integrated_inputs) is not IntegratedBoundaryInputs
            or type(self.composed_manifest) is not ComposedEvidenceManifest
            or type(self.composed_result) is not ComposedEvidenceResult
            or type(self.lane_a) is not EvidenceLaneReceipt
            or type(self.lane_b) is not EvidenceLaneReceipt
            or any(type(value) is not bool for value in (
                self.supervisor_pass, self.ci_pass, self.policy_pass, self.provenance_pass,
                self.temporary_resources_reconciled,
            ))
            or type(self.unresolved_blockers) is not tuple
            or any(type(value) is not str or not value for value in self.unresolved_blockers)
            or len(set(self.unresolved_blockers)) != len(self.unresolved_blockers)
            or not verify_composed_evidence(self.composed_manifest, self.composed_result)
            or self.composed_manifest.inputs != self.integrated_inputs
            or self.composed_result.manifest != self.composed_manifest
            or self.integrated_inputs.expectation.retention_manifest_digest != self.issue_49_retention_manifest_digest
            or self.composed_result.result != "pass"
            or any(value != self.candidate_sha for value in (
                self.integrated_inputs.candidate_sha,
                self.composed_manifest.inputs.candidate_sha,
                self.composed_result.manifest.inputs.candidate_sha,
                self.lane_a.candidate_sha,
                self.lane_b.candidate_sha,
            ))
        ):
            raise QualificationGateError("phase-3 qualification evidence is invalid")
        composed = self.composed_manifest.public_payload()
        if (
            composed["new_provider_calls"] != 0
            or composed["new_target_actions"] != 0
            or composed["lifecycle_observation_sink"] != "NOT_SELECTED"
        ):
            raise QualificationGateError("phase-3 qualification evidence is not consumer-only")
        object.__setattr__(self, "input_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA,
            "profile": PHASE_3_QUALIFICATION_PROFILE,
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "harness_commit": self.harness_commit,
            "forward_target_commit": self.forward_target_commit,
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
            "issue_50_result_bundle_digest": self.issue_50_result_bundle_digest,
            "temporary_resource_inventory_digest": self.temporary_resource_inventory_digest,
            "capture_plan_digest": self.integrated_inputs.capture_plan_digest,
            "composed_manifest_digest": self.composed_manifest.manifest_digest,
            "composed_result_digest": self.composed_result.result_digest,
            "lane_a": {"state": self.lane_a.state, "result": self.lane_a.result},
            "lane_b": {"state": self.lane_b.state, "result": self.lane_b.result},
            "supervisor_pass": self.supervisor_pass,
            "ci_pass": self.ci_pass,
            "policy_pass": self.policy_pass,
            "provenance_pass": self.provenance_pass,
            "temporary_resources_reconciled": self.temporary_resources_reconciled,
            "unresolved_blockers": list(self.unresolved_blockers),
            "new_provider_calls": 0,
            "new_target_actions": 0,
            "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"input_digest": self.input_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class CanaryEntryDecisionPackage:
    """Public-safe owner decision package; never an authority or action receipt."""

    inputs: Phase3QualificationInputs
    disposition: Literal["PROMOTION_READY_FOR_CANARY_DECISION", "QUALIFICATION_BLOCKED"]
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.inputs) is not Phase3QualificationInputs or self.disposition not in {
            PROMOTION_READY_FOR_CANARY_DECISION, QUALIFICATION_BLOCKED,
        }:
            raise QualificationGateError("Canary-entry decision package is invalid")
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA,
            "profile": PHASE_3_QUALIFICATION_PROFILE,
            "disposition": self.disposition,
            "input_digest": self.inputs.input_digest,
            "base_sha": self.inputs.base_sha,
            "candidate_sha": self.inputs.candidate_sha,
            "composed_manifest_digest": self.inputs.composed_manifest.manifest_digest,
            "composed_result_digest": self.inputs.composed_result.result_digest,
            "canary_action_authorized": False,
            "runtime_activation_authorized": False,
            "roundlet_retirement_authorized": False,
            "new_provider_calls": 0,
            "new_target_actions": 0,
            "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_3_qualification(inputs: Phase3QualificationInputs) -> CanaryEntryDecisionPackage:
    """Evaluate retained evidence without external calls, storage, or cleanup."""

    if type(inputs) is not Phase3QualificationInputs:
        raise QualificationGateError("phase-3 qualification inputs are invalid")
    qualification = TwoStageQualification(
        inputs.candidate_sha, inputs.lane_a, inputs.lane_b, inputs.supervisor_pass,
    )
    ready = (
        not inputs.unresolved_blockers
        and inputs.temporary_resources_reconciled
        and qualification.merge_qualified(
            ci_pass=inputs.ci_pass, policy_pass=inputs.policy_pass, provenance_pass=inputs.provenance_pass,
        )
    )
    return CanaryEntryDecisionPackage(
        inputs,
        PROMOTION_READY_FOR_CANARY_DECISION if ready else QUALIFICATION_BLOCKED,
    )
