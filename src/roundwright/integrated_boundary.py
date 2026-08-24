"""Pure composition of retained Phase-3 evidence.

The integrated boundary does not reopen a lower-level observation window.  It
only accepts two independently sealed #49 lanes and their distinct historical
and synthetic references, then emits a path-free manifest for a Recorder to
retain.  In particular, it has no provider, GitHub, Harness, or filesystem
capability.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .shadow import (
    INTEGRATED_BOUNDARY_PROFILE,
    LIVE_LIFECYCLE_SHADOW_PROFILE,
    READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
)


INTEGRATED_BOUNDARY_SCHEMA = "roundwright-integrated-boundary-composition/v1"
COMPOSED_MANIFEST_SCHEMA = "roundwright-composed-evidence-manifest/v1"
COMPOSED_RESULT_SCHEMA = "roundwright-composed-evidence-result/v1"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class IntegratedBoundaryError(ValueError):
    """Raised when a composed manifest would mix, replace, or invent evidence."""


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class RetainedSourceKind(StrEnum):
    LANE_A = "lane-a"
    LANE_B = "lane-b"
    HISTORICAL_REFERENCE = "historical-reference"
    SYNTHETIC_REFERENCE = "synthetic-reference"


@dataclass(frozen=True)
class RetainedEvidenceExpectation:
    """Immutable selection-time identities for the four retained sources."""

    retention_manifest_digest: str
    lane_a_result_digest: str
    lane_a_bundle_digest: str
    lane_b_ledger_digest: str
    lane_b_seal_digest: str
    lane_b_retention_identity: str
    historical_reference_digest: str
    synthetic_reference_digest: str

    def __post_init__(self) -> None:
        if any(not _DIGEST.fullmatch(value) for value in self.__dict__.values()):
            raise IntegratedBoundaryError("retained evidence expectation is invalid")

    def public_payload(self) -> dict[str, str]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class RetainedEvidenceSource:
    """A sealed, public-safe immutable source consumed by composition once."""

    kind: RetainedSourceKind
    profile_id: str
    candidate_sha: str
    case_id: str
    ready_at: int
    capture_plan_digest: str
    result_digest: str
    bundle_digest: str
    manifest_digest: str
    receipt_digest: str
    retention_identity: str
    status: str = "verified"
    result: str = "pass"
    mutation_count: int = 0
    source_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not RetainedSourceKind
            or not isinstance(self.profile_id, str)
            or not _SHA.fullmatch(self.candidate_sha)
            or not _TOKEN.fullmatch(self.case_id)
            or type(self.ready_at) is not int or self.ready_at < 0
            or any(not _DIGEST.fullmatch(value) for value in (
                self.capture_plan_digest, self.result_digest, self.bundle_digest,
                self.manifest_digest, self.receipt_digest, self.retention_identity,
            ))
            or self.status != "verified" or self.result != "pass"
            or type(self.mutation_count) is not int or self.mutation_count != 0
        ):
            raise IntegratedBoundaryError("retained evidence source is invalid")
        expected_profile = {
            RetainedSourceKind.LANE_A: READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
            RetainedSourceKind.LANE_B: LIVE_LIFECYCLE_SHADOW_PROFILE,
        }.get(self.kind)
        if expected_profile is not None and self.profile_id != expected_profile:
            raise IntegratedBoundaryError("retained evidence lane profile is invalid")
        if self.kind in {RetainedSourceKind.HISTORICAL_REFERENCE, RetainedSourceKind.SYNTHETIC_REFERENCE} and self.profile_id == INTEGRATED_BOUNDARY_PROFILE:
            raise IntegratedBoundaryError("reference may not substitute for composed evidence")
        object.__setattr__(self, "source_digest", _digest(self.public_payload()))

    def public_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value, "profile": self.profile_id,
            "candidate_sha": self.candidate_sha, "case_id": self.case_id,
            "ready_at": self.ready_at, "capture_plan_digest": self.capture_plan_digest,
            "result_digest": self.result_digest, "bundle_digest": self.bundle_digest,
            "manifest_digest": self.manifest_digest, "receipt_digest": self.receipt_digest,
            "retention_identity": self.retention_identity, "status": self.status,
            "result": self.result, "mutation_count": self.mutation_count,
        }


def source_from_public_payload(value: object) -> RetainedEvidenceSource:
    """Rehydrate one path-free retained source without accepting extra fields."""

    try:
        if type(value) is not dict:
            raise ValueError
        raw = dict(value)
        supplied_digest = raw.pop("source_digest", None)
        if set(raw) != {
            "kind", "profile", "candidate_sha", "case_id", "ready_at",
            "capture_plan_digest", "result_digest", "bundle_digest",
            "manifest_digest", "receipt_digest", "retention_identity", "status",
            "result", "mutation_count",
        }:
            raise ValueError
        source = RetainedEvidenceSource(
            RetainedSourceKind(raw["kind"]), raw["profile"], raw["candidate_sha"], raw["case_id"], raw["ready_at"],
            raw["capture_plan_digest"], raw["result_digest"], raw["bundle_digest"],
            raw["manifest_digest"], raw["receipt_digest"], raw["retention_identity"],
            raw["status"], raw["result"], raw["mutation_count"],
        )
        if supplied_digest is not None and supplied_digest != source.source_digest:
            raise ValueError
        return source
    except (KeyError, TypeError, ValueError) as error:
        raise IntegratedBoundaryError("retained evidence payload is invalid") from error


def bind_issue_49_retained_evidence(
    *, candidate_sha: str, case_id: str, capture_plan_digest: str, expectation: RetainedEvidenceExpectation,
    lane_a_result: object, lane_a_recording: object, lane_b_seal: object,
    historical_reference: object, synthetic_reference: object,
) -> IntegratedBoundaryInputs:
    """Bind the concrete #49 receipt shapes into one #50 composition request.

    The host supplies already-read public-safe JSON values.  This parser makes
    their cross-receipt identities explicit; it never discovers a path, reads
    a store, or substitutes a newer lower-level receipt.
    """

    try:
        lane_a, recording, lane_b = (dict(value) for value in (lane_a_result, lane_a_recording, lane_b_seal))
        result_required = {
            "candidate_sha", "case_id", "mutation_count", "plan_digest", "profile",
            "ready_at", "receipt_digest", "retention_identity", "schema", "state", "status",
            "bundle_digest", "recording_receipt_digest", "result_identity",
        }
        recording_required = {
            "bundle_digest", "candidate_sha", "case_id", "evidence_digest", "evidence_schema",
            "manifest_digest", "profile", "ready_at", "receipt_digest", "retention_identity", "schema", "status",
        }
        seal_required = {
            "candidate_sha", "ledger_digest", "manifest_digest", "plan_digest", "ready_at",
            "receipt_digest", "retention_identity", "schema", "status",
        }
        if (
            not result_required.issubset(lane_a) or not recording_required.issubset(recording) or not seal_required.issubset(lane_b)
            or lane_a["schema"] != "roundwright-harness-profile-executor-result/v2"
            or recording["schema"] != "roundwright-harness-recording-receipt/v1"
            or lane_b["schema"] != "roundwright-harness-lifecycle-seal-receipt/v1"
            or lane_a["profile"] != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
            or lane_a["status"] != "pass" or lane_a["state"] != "VERIFIED" or lane_a["mutation_count"] != 0
            or recording["status"] != "sealed" or lane_b["status"] != "sealed"
            or any(lane_a[key] != recording[key] for key in ("candidate_sha", "case_id", "ready_at", "profile", "bundle_digest", "retention_identity"))
            or lane_a["recording_receipt_digest"] != recording["receipt_digest"]
            or lane_a["candidate_sha"] != lane_b["candidate_sha"]
        ):
            raise ValueError
        historical = source_from_public_payload(historical_reference)
        synthetic = source_from_public_payload(synthetic_reference)
        lane_a_source = RetainedEvidenceSource(
            RetainedSourceKind.LANE_A, lane_a["profile"], lane_a["candidate_sha"], lane_a["case_id"], lane_a["ready_at"],
            lane_a["plan_digest"], lane_a["receipt_digest"], lane_a["bundle_digest"], recording["manifest_digest"],
            recording["receipt_digest"], lane_a["retention_identity"],
        )
        lane_b_source = RetainedEvidenceSource(
            RetainedSourceKind.LANE_B, LIVE_LIFECYCLE_SHADOW_PROFILE, lane_b["candidate_sha"], "issue-49-lane-b", lane_b["ready_at"],
            lane_b["plan_digest"], lane_b["ledger_digest"], lane_b["ledger_digest"], lane_b["manifest_digest"],
            lane_b["receipt_digest"], lane_b["retention_identity"],
        )
        return IntegratedBoundaryInputs(candidate_sha, case_id, capture_plan_digest, expectation, lane_a_source, lane_b_source, historical, synthetic)
    except (KeyError, TypeError, ValueError, IntegratedBoundaryError) as error:
        raise IntegratedBoundaryError("issue-49 retained evidence is invalid") from error


@dataclass(frozen=True)
class IntegratedBoundaryInputs:
    """The closed source tuple required to create one composed manifest."""

    candidate_sha: str
    case_id: str
    capture_plan_digest: str
    expectation: RetainedEvidenceExpectation
    lane_a: RetainedEvidenceSource
    lane_b: RetainedEvidenceSource
    historical_reference: RetainedEvidenceSource
    synthetic_reference: RetainedEvidenceSource

    def __post_init__(self) -> None:
        sources = (self.lane_a, self.lane_b, self.historical_reference, self.synthetic_reference)
        if (
            not _SHA.fullmatch(self.candidate_sha) or not _TOKEN.fullmatch(self.case_id)
            or not _DIGEST.fullmatch(self.capture_plan_digest)
            or type(self.expectation) is not RetainedEvidenceExpectation
            or any(type(source) is not RetainedEvidenceSource for source in sources)
            or tuple(source.kind for source in sources) != tuple(RetainedSourceKind)
            or len({source.source_digest for source in sources}) != len(sources)
            or len({source.receipt_digest for source in sources}) != len(sources)
            or len({source.bundle_digest for source in sources}) != len(sources)
            or self.lane_a.result_digest != self.expectation.lane_a_result_digest
            or self.lane_a.bundle_digest != self.expectation.lane_a_bundle_digest
            or self.lane_b.result_digest != self.expectation.lane_b_ledger_digest
            or self.lane_b.bundle_digest != self.expectation.lane_b_ledger_digest
            or self.lane_b.receipt_digest != self.expectation.lane_b_seal_digest
            or self.lane_b.retention_identity != self.expectation.lane_b_retention_identity
            or self.historical_reference.source_digest != self.expectation.historical_reference_digest
            or self.synthetic_reference.source_digest != self.expectation.synthetic_reference_digest
        ):
            raise IntegratedBoundaryError("integrated evidence inputs are missing, stale, or mixed")


@dataclass(frozen=True)
class ComposedEvidenceManifest:
    """Path-free output for independent append-only retention and read-back."""

    inputs: IntegratedBoundaryInputs
    manifest_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.inputs) is not IntegratedBoundaryInputs:
            raise IntegratedBoundaryError("composed manifest inputs are invalid")
        object.__setattr__(self, "manifest_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        sources = (self.inputs.lane_a, self.inputs.lane_b, self.inputs.historical_reference, self.inputs.synthetic_reference)
        value: dict[str, object] = {
            "schema": COMPOSED_MANIFEST_SCHEMA,
            "profile": INTEGRATED_BOUNDARY_PROFILE,
            "candidate_sha": self.inputs.candidate_sha,
            "case_id": self.inputs.case_id,
            "capture_plan_digest": self.inputs.capture_plan_digest,
            "retention_manifest_digest": self.inputs.expectation.retention_manifest_digest,
            "expected_source_digests": self.inputs.expectation.public_payload(),
            "sources": tuple({"source_digest": source.source_digest} | source.public_payload() for source in sources),
            "new_provider_calls": 0,
            "new_target_actions": 0,
            "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"manifest_digest": self.manifest_digest} if include_digest else {})


@dataclass(frozen=True)
class ComposedEvidenceResult:
    """Comparison result; successful composition is never an authority receipt."""

    manifest: ComposedEvidenceManifest
    result: str = "pass"
    result_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.manifest) is not ComposedEvidenceManifest or self.result != "pass":
            raise IntegratedBoundaryError("composed evidence result is invalid")
        object.__setattr__(self, "result_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": COMPOSED_RESULT_SCHEMA, "status": self.result,
            "manifest_digest": self.manifest.manifest_digest,
            "candidate_sha": self.manifest.inputs.candidate_sha,
            "new_provider_calls": 0, "new_target_actions": 0,
        }
        return value | ({"result_digest": self.result_digest} if include_digest else {})


def compose_retained_evidence(inputs: IntegratedBoundaryInputs) -> tuple[ComposedEvidenceManifest, ComposedEvidenceResult]:
    """Compose already-verified evidence only; this function performs no I/O."""

    if type(inputs) is not IntegratedBoundaryInputs:
        raise IntegratedBoundaryError("integrated evidence inputs are invalid")
    manifest = ComposedEvidenceManifest(inputs)
    return manifest, ComposedEvidenceResult(manifest)


def integrated_boundary_execution_context(inputs: IntegratedBoundaryInputs) -> dict[str, object]:
    """The exact request context bound before Harness validate/execute."""

    if type(inputs) is not IntegratedBoundaryInputs:
        raise IntegratedBoundaryError("integrated evidence inputs are invalid")
    return {
        "schema": "roundwright-integrated-boundary-context/v1",
        "candidate_sha": inputs.candidate_sha, "case_id": inputs.case_id,
        "capture_plan_digest": inputs.capture_plan_digest,
        "retention_manifest_digest": inputs.expectation.retention_manifest_digest,
        "expected_source_digests": inputs.expectation.public_payload(),
    }


def verify_composed_evidence(manifest: ComposedEvidenceManifest, result: ComposedEvidenceResult) -> bool:
    """Independently recheck the two content-addressed composition outputs."""

    try:
        if type(manifest) is not ComposedEvidenceManifest or type(result) is not ComposedEvidenceResult:
            return False
        return (
            manifest.manifest_digest == _digest(manifest.public_payload(include_digest=False))
            and result.manifest == manifest
            and result.result_digest == _digest(result.public_payload(include_digest=False))
        )
    except (AttributeError, TypeError, IntegratedBoundaryError):
        return False


def phase_3_capability_report() -> tuple[tuple[str, str], ...]:
    """Render the public Phase-3 boundary without claiming future authority."""

    return (
        ("codex-provider-runtime", "supported"),
        ("github-mutation-fakes", "test-only"),
        ("forward-target-observation", "read-only"),
        ("deployment-and-daemon", "deferred"),
        ("merge-release-publication", "prohibited"),
    )
