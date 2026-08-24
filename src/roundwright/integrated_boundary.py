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
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    INTEGRATED_BOUNDARY_PROFILE,
    LIVE_LIFECYCLE_SHADOW_PROFILE,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
)
from .lifecycle_observation import (
    LIFECYCLE_PROJECTION_SCHEMA,
    LifecycleObservationError,
    LifecycleProjectionComparison,
    LifecycleShadowProjection,
    ProjectedLifecycleEvent,
)


INTEGRATED_BOUNDARY_SCHEMA = "roundwright-integrated-boundary-composition/v1"
COMPOSED_MANIFEST_SCHEMA = "roundwright-composed-evidence-manifest/v1"
COMPOSED_RESULT_SCHEMA = "roundwright-composed-evidence-result/v1"
RETAINED_EVIDENCE_EXPECTATION_SCHEMA = "roundwright-retained-evidence-expectation/v1"
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


@dataclass(frozen=True, slots=True)
class RetainedEvidenceExpectation:
    """Immutable selection-time identities for the four retained sources."""

    retention_manifest_digest: str
    lane_a_result_digest: str
    lane_a_bundle_digest: str
    lane_b_ledger_digest: str
    lane_b_seal_digest: str
    lane_b_retention_identity: str
    lane_b_qualification_digest: str
    historical_reference_digest: str
    synthetic_reference_digest: str
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if any(not _DIGEST.fullmatch(value) for value in self._pins_payload().values()):
            raise IntegratedBoundaryError("retained evidence expectation is invalid")
        object.__setattr__(self, "integrity_digest", self._expected_integrity_digest())

    def _pins_payload(self) -> dict[str, str]:
        """Return exactly the selection-time identities, never instance state."""

        return {
            "retention_manifest_digest": self.retention_manifest_digest,
            "lane_a_result_digest": self.lane_a_result_digest,
            "lane_a_bundle_digest": self.lane_a_bundle_digest,
            "lane_b_ledger_digest": self.lane_b_ledger_digest,
            "lane_b_seal_digest": self.lane_b_seal_digest,
            "lane_b_retention_identity": self.lane_b_retention_identity,
            "lane_b_qualification_digest": self.lane_b_qualification_digest,
            "historical_reference_digest": self.historical_reference_digest,
            "synthetic_reference_digest": self.synthetic_reference_digest,
        }

    def _expected_integrity_digest(self) -> str:
        return _digest({"schema": RETAINED_EVIDENCE_EXPECTATION_SCHEMA, "pins": self._pins_payload()})

    def validate_integrity(self) -> None:
        """Reject post-construction selection-pin drift before any execution."""

        if (
            type(self) is not RetainedEvidenceExpectation
            or any(not _DIGEST.fullmatch(value) for value in self._pins_payload().values())
            or not _DIGEST.fullmatch(self.integrity_digest)
            or self.integrity_digest != self._expected_integrity_digest()
        ):
            raise IntegratedBoundaryError("retained evidence expectation has drifted")

    def public_payload(self) -> dict[str, str]:
        self.validate_integrity()
        return {
            "schema": RETAINED_EVIDENCE_EXPECTATION_SCHEMA,
            **self._pins_payload(),
            "integrity_digest": self.integrity_digest,
        }


@dataclass(frozen=True, slots=True)
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
            RetainedSourceKind.HISTORICAL_REFERENCE: PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
            RetainedSourceKind.SYNTHETIC_REFERENCE: EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
        }.get(self.kind)
        if expected_profile is not None and self.profile_id != expected_profile:
            raise IntegratedBoundaryError("retained evidence source profile is invalid")
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


def _projection_from_semantic_payload(value: object) -> LifecycleShadowProjection:
    """Rehydrate an already-verified projection without reading its store.

    The generic lifecycle projector owns event-sequence validation.  #50 only
    accepts its closed semantic projection and the comparison it produced;
    it never opens or replays the retained lifecycle window.
    """

    try:
        if type(value) is not dict or set(value) != {
            "schema", "profile", "candidate_sha", "ready_at", "window_identity",
            "repository_identity", "producer_identity", "store_identity",
            "capture_plan_digest", "plan_digest", "review_epoch", "review_round",
            "review_mode", "events", "accepted_attempt_identity", "ledger_digest",
            "manifest_digest", "retention_identity", "head_event_digest",
            "head_entry_digest", "classified_differences",
        }:
            raise ValueError
        events = value["events"]
        if type(events) is not list:
            raise ValueError
        projected = tuple(
            ProjectedLifecycleEvent(
                item["sequence"], item["occurred_at"], item["role"], item["task_identity"],
                item["attempt_identity"], item["review_attempt"], item["transition"],
                item["disposition"], item["accepted_result"], item["successor_candidate_sha"],
                item["predecessor_event_digest"], tuple(item["artifact_references"]), item["event_digest"],
            )
            for item in events
            if type(item) is dict and set(item) == {
                "sequence", "occurred_at", "role", "task_identity", "attempt_identity",
                "review_attempt", "transition", "disposition", "accepted_result",
                "successor_candidate_sha", "predecessor_event_digest", "artifact_references", "event_digest",
            }
        )
        if len(projected) != len(events) or type(value["classified_differences"]) is not list:
            raise ValueError
        return LifecycleShadowProjection(
            value["candidate_sha"], value["ready_at"], value["window_identity"], value["repository_identity"],
            value["producer_identity"], value["store_identity"], value["capture_plan_digest"], value["plan_digest"],
            value["review_epoch"], value["review_round"], value["review_mode"], projected,
            value["accepted_attempt_identity"], value["ledger_digest"], value["manifest_digest"],
            value["retention_identity"], value["head_event_digest"], value["head_entry_digest"],
            tuple(value["classified_differences"]), value["schema"], value["profile"],
        )
    except (KeyError, TypeError, ValueError, LifecycleObservationError) as error:
        raise IntegratedBoundaryError("lane-b lifecycle projection is invalid") from error


def bind_issue_49_retained_evidence(
    *, candidate_sha: str, case_id: str, capture_plan_digest: str, expectation: RetainedEvidenceExpectation,
    lane_a_result: object, lane_a_recording: object, lane_b_seal: object, lane_b_qualification: object,
    historical_reference: object, synthetic_reference: object,
) -> IntegratedBoundaryInputs:
    """Bind the concrete #49 receipt shapes into one #50 composition request.

    The host supplies already-read public-safe JSON values.  This parser makes
    their cross-receipt identities explicit; it never discovers a path, reads
    a store, or substitutes a newer lower-level receipt.
    """

    try:
        lane_a, recording, lane_b, qualification = (
            dict(value) for value in (lane_a_result, lane_a_recording, lane_b_seal, lane_b_qualification)
        )
        result_required = {
            "schema", "status", "state", "readiness_receipt_digest", "plan_digest", "profile",
            "case_id", "candidate_sha", "ready_at", "result_identity", "bundle_digest",
            "recording_receipt_digest", "retention_identity", "dispatch_count", "record_count",
            "verify_count", "mutation_count", "execution_context_input_digest",
            "execution_context_identity", "receipt_digest",
        }
        recording_required = {
            "bundle_digest", "candidate_sha", "case_id", "evidence_digest", "evidence_schema",
            "manifest_digest", "profile", "ready_at", "receipt_digest", "retention_identity", "schema", "status",
        }
        seal_required = {
            "candidate_sha", "ledger_digest", "manifest_digest", "plan_digest", "ready_at",
            "receipt_digest", "retention_identity", "schema", "status", "event_schema",
            "window_identity", "repository_identity", "event_count", "head_event_digest", "head_entry_digest",
        }
        qualification_required = {
            "schema", "status", "state", "candidate_sha", "ready_at", "plan_digest",
            "ledger_digest", "seal_receipt_digest", "manifest_digest", "retention_identity",
            "mutation_count", "classified_differences", "projection", "projection_identity",
            "comparison", "result_digest",
        }
        def receipt_is_canonical(value: dict[str, object], digest_key: str) -> bool:
            supplied = value.get(digest_key)
            return isinstance(supplied, str) and supplied == _digest({key: item for key, item in value.items() if key != digest_key})
        if (
            set(lane_a) != result_required or set(recording) != recording_required or set(lane_b) != seal_required
            or set(qualification) != qualification_required
            or lane_a["schema"] != "roundwright-harness-profile-executor-result/v2"
            or recording["schema"] != "roundwright-harness-recording-receipt/v1"
            or lane_b["schema"] != "roundwright-harness-lifecycle-seal-receipt/v1"
            or qualification["schema"] != "roundwright-integrated-lane-b-qualification/v1"
            or lane_a["profile"] != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
            or lane_a["status"] != "pass" or lane_a["state"] != "VERIFIED"
            or (lane_a["dispatch_count"], lane_a["record_count"], lane_a["verify_count"], lane_a["mutation_count"]) != (1, 1, 1, 0)
            or recording["status"] != "sealed" or lane_b["status"] != "sealed"
            or qualification["status"] != "pass" or qualification["state"] != "VERIFIED"
            or qualification["mutation_count"] != 0 or qualification["classified_differences"] != []
            or any(lane_a[key] != recording[key] for key in ("candidate_sha", "case_id", "ready_at", "profile", "bundle_digest", "retention_identity"))
            or lane_a["recording_receipt_digest"] != recording["receipt_digest"]
            or lane_a["candidate_sha"] != lane_b["candidate_sha"]
            or any(qualification[key] != lane_b[value] for key, value in (
                ("candidate_sha", "candidate_sha"), ("ready_at", "ready_at"), ("plan_digest", "plan_digest"),
                ("ledger_digest", "ledger_digest"), ("seal_receipt_digest", "receipt_digest"),
                ("manifest_digest", "manifest_digest"), ("retention_identity", "retention_identity"),
            ))
            or not receipt_is_canonical(lane_a, "receipt_digest")
            or not receipt_is_canonical(recording, "receipt_digest")
            or not receipt_is_canonical(lane_b, "receipt_digest")
            or not receipt_is_canonical(qualification, "result_digest")
            or qualification["result_digest"] != expectation.lane_b_qualification_digest
        ):
            raise ValueError
        projection = _projection_from_semantic_payload(qualification["projection"])
        projection_identity = _digest(projection.semantic_payload())
        comparison = qualification["comparison"]
        if (
            type(comparison) is not dict
            or set(comparison) != {
                "schema", "status", "classified_differences", "expected_identity",
                "observed_identity", "result_identity",
            }
            or projection.schema != LIFECYCLE_PROJECTION_SCHEMA
            or projection.profile != LIVE_LIFECYCLE_SHADOW_PROFILE
            or projection.candidate_sha != lane_b["candidate_sha"]
            or projection.ready_at != lane_b["ready_at"]
            or projection.window_identity != lane_b["window_identity"]
            or projection.repository_identity != lane_b["repository_identity"]
            or projection.plan_digest != lane_b["plan_digest"]
            or projection.ledger_digest != lane_b["ledger_digest"]
            or projection.manifest_digest != lane_b["manifest_digest"]
            or projection.retention_identity != lane_b["retention_identity"]
            or len(projection.events) != lane_b["event_count"]
            or projection.head_event_digest != lane_b["head_event_digest"]
            or projection.head_entry_digest != lane_b["head_entry_digest"]
            or projection.classified_differences != ()
            or qualification["projection_identity"] != projection_identity
            or type(comparison["classified_differences"]) is not list
        ):
            raise ValueError
        expected_comparison = LifecycleProjectionComparison(
            "pass", (), projection_identity, projection_identity,
        )
        if comparison != expected_comparison.public_payload():
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
        if type(self.expectation) is not RetainedEvidenceExpectation:
            raise IntegratedBoundaryError("integrated evidence inputs are missing, stale, or mixed")
        self.expectation.validate_integrity()
        if (
            not _SHA.fullmatch(self.candidate_sha) or not _TOKEN.fullmatch(self.case_id)
            or not _DIGEST.fullmatch(self.capture_plan_digest)
            or any(type(source) is not RetainedEvidenceSource for source in sources)
            or any(source.source_digest != _digest(source.public_payload()) for source in sources)
            or tuple(source.kind for source in sources) != tuple(RetainedSourceKind)
            or len({source.source_digest for source in sources}) != len(sources)
            or len({source.receipt_digest for source in sources}) != len(sources)
            or len({source.bundle_digest for source in sources}) != len(sources)
            or self.lane_a.candidate_sha != self.lane_b.candidate_sha
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
            "sources": [{"source_digest": source.source_digest} | source.public_payload() for source in sources],
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
