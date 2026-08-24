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


@dataclass(frozen=True)
class IntegratedBoundaryInputs:
    """The closed source tuple required to create one composed manifest."""

    candidate_sha: str
    case_id: str
    capture_plan_digest: str
    lane_a: RetainedEvidenceSource
    lane_b: RetainedEvidenceSource
    historical_reference: RetainedEvidenceSource
    synthetic_reference: RetainedEvidenceSource

    def __post_init__(self) -> None:
        sources = (self.lane_a, self.lane_b, self.historical_reference, self.synthetic_reference)
        if (
            not _SHA.fullmatch(self.candidate_sha) or not _TOKEN.fullmatch(self.case_id)
            or not _DIGEST.fullmatch(self.capture_plan_digest)
            or any(type(source) is not RetainedEvidenceSource for source in sources)
            or tuple(source.kind for source in sources) != tuple(RetainedSourceKind)
            or len({source.source_digest for source in sources}) != len(sources)
            or len({source.receipt_digest for source in sources}) != len(sources)
            or len({source.bundle_digest for source in sources}) != len(sources)
            or any(source.candidate_sha != self.lane_a.candidate_sha for source in sources)
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
