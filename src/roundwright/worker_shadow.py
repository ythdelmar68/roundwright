"""Public-safe Shadow evidence for the native Codex Worker adapter.

This module intentionally exports identities and digests, never a prompt,
provider response, transcript, credential, local path, or hidden reasoning.
It is pure apart from the supplied append-only test/store boundary; opening a
provider session or invoking the external Recorder is not part of this API.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from .codex_worker import CodexWorkerContext, CodexWorkerRequest, CodexWorkerResult, WorkerResultKind
from .shadow import AppendOnlyEvidenceStore, CaptureMode, RecorderBinding, ShadowEvidenceProfile, ShadowProducer


WORKER_ADAPTER_PROFILE = "roundwright-shadow-profile/worker-adapter/v1"
WORKER_ADAPTER_SCHEMA = "roundwright-shadow-case/v2"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


class WorkerShadowError(ValueError):
    pass


class WorkerShadowDisposition(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INVALID = "invalid"


@dataclass(frozen=True)
class WorkerShadowEnvelope:
    """Durable request/result projection for one already-checkpointed SDK turn."""

    task_id: str
    worker_thread_identity: str
    provider_attempt_id: str
    external_turn_identity: str
    base_sha: str
    candidate_sha: str
    profile_identity: str
    configuration_digest: str
    runtime_fingerprint: str
    request_digest: str
    result_kind: WorkerResultKind
    accepted_result_digest: str | None
    deterministic_state: str
    blocker: str | None
    next_action: str
    ready_at: int
    schema: str = WORKER_ADAPTER_SCHEMA
    profile_id: str = WORKER_ADAPTER_PROFILE
    envelope_digest: str = ""

    def __post_init__(self) -> None:
        if (
            self.schema != WORKER_ADAPTER_SCHEMA
            or self.profile_id != WORKER_ADAPTER_PROFILE
            or not all(_token(value) for value in (
                self.task_id, self.worker_thread_identity, self.provider_attempt_id,
                self.external_turn_identity, self.deterministic_state, self.next_action,
            ))
            or not _SHA.fullmatch(self.base_sha)
            or not _SHA.fullmatch(self.candidate_sha)
            or not all(_digest(value) for value in (
                self.profile_identity, self.configuration_digest, self.runtime_fingerprint, self.request_digest,
            ))
            or type(self.result_kind) is not WorkerResultKind
            or (self.accepted_result_digest is not None and not _digest(self.accepted_result_digest))
            or (self.blocker is not None and not _token(self.blocker))
            or type(self.ready_at) is not int
            or self.ready_at < 0
        ):
            raise WorkerShadowError("Worker Shadow envelope is invalid")
        accepted = self.result_kind is WorkerResultKind.ACCEPTED
        if accepted != (self.accepted_result_digest is not None):
            raise WorkerShadowError("Worker Shadow accepted-result binding is invalid")
        digest = _hash(self.payload())
        if self.envelope_digest and self.envelope_digest != digest:
            raise WorkerShadowError("Worker Shadow envelope digest is invalid")
        object.__setattr__(self, "envelope_digest", digest)

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "profile_id": self.profile_id, "task_id": self.task_id,
            "worker_thread_identity": self.worker_thread_identity, "provider_attempt_id": self.provider_attempt_id,
            "external_turn_identity": self.external_turn_identity, "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha, "profile_identity": self.profile_identity,
            "configuration_digest": self.configuration_digest, "runtime_fingerprint": self.runtime_fingerprint,
            "request_digest": self.request_digest, "result_kind": self.result_kind.value,
            "accepted_result_digest": self.accepted_result_digest, "deterministic_state": self.deterministic_state,
            "blocker": self.blocker, "next_action": self.next_action, "ready_at": self.ready_at,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True)
class WorkerShadowCaptureReadiness:
    """Sealed preflight that must exist before a qualifying provider attempt."""

    candidate_sha: str
    ready_at: int
    native_channel_producer_identity: str
    exporter_identity: str
    comparator_identity: str
    recorder_binding_digest: str
    store_identity: str
    schema: str = WORKER_ADAPTER_SCHEMA
    profile_id: str = WORKER_ADAPTER_PROFILE
    retention_contract: str = "append-only-content-addressed-readback"
    missing_history_action: str = "fresh-bounded-attempt-recapture"
    readiness_digest: str = ""

    def __post_init__(self) -> None:
        if (
            self.schema != WORKER_ADAPTER_SCHEMA or self.profile_id != WORKER_ADAPTER_PROFILE
            or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0
            or not all(_digest(value) for value in (self.native_channel_producer_identity, self.exporter_identity, self.comparator_identity, self.recorder_binding_digest, self.store_identity))
            or self.retention_contract != "append-only-content-addressed-readback"
            or self.missing_history_action != "fresh-bounded-attempt-recapture"
        ):
            raise WorkerShadowError("Worker Shadow capture readiness is invalid")
        digest = _hash(self.payload())
        if self.readiness_digest and self.readiness_digest != digest:
            raise WorkerShadowError("Worker Shadow capture readiness digest is invalid")
        object.__setattr__(self, "readiness_digest", digest)

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "profile_id": self.profile_id, "candidate_sha": self.candidate_sha,
            "ready_at": self.ready_at, "native_channel_producer_identity": self.native_channel_producer_identity,
            "exporter_identity": self.exporter_identity, "comparator_identity": self.comparator_identity,
            "recorder_binding_digest": self.recorder_binding_digest, "store_identity": self.store_identity,
            "retention_contract": self.retention_contract, "missing_history_action": self.missing_history_action,
        }


@dataclass(frozen=True)
class WorkerShadowRecord:
    readiness_digest: str
    envelope_digest: str
    retention_digest: str
    candidate_sha: str
    ready_at: int

    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.readiness_digest, self.envelope_digest, self.retention_digest)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0:
            raise WorkerShadowError("Worker Shadow record is invalid")


@dataclass(frozen=True)
class WorkerShadowComparison:
    disposition: WorkerShadowDisposition
    expected_digest: str
    observed_digest: str
    differing_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.disposition) is not WorkerShadowDisposition or not _digest(self.expected_digest) or not _digest(self.observed_digest) or type(self.differing_fields) is not tuple or any(not _token(value) for value in self.differing_fields):
            raise WorkerShadowError("Worker Shadow comparison is invalid")


def worker_adapter_shadow_profile() -> ShadowEvidenceProfile:
    """Return the closed profile declaration used by capture preflight."""

    return ShadowEvidenceProfile(
        WORKER_ADAPTER_PROFILE, CaptureMode.LIFECYCLE_GRAPH, ShadowProducer.PROFILE_DEFINED,
        "v2-native-channel-exporter-comparator-recorder-store-readback-bound",
        "before-first-selected-live-worker-provider-attempt",
        "append-only-content-addressed-readback", "fresh-bounded-attempt-recapture",
        ("worker-request-response-envelope",), 0, 0, False,
    )


def export_worker_shadow_envelope(
    request: CodexWorkerRequest, result: CodexWorkerResult, *, provider_attempt_id: str,
    external_turn_identity: str, base_sha: str, candidate_sha: str, profile_identity: str,
    runtime_fingerprint: str, deterministic_state: str, blocker: str | None, next_action: str, ready_at: int,
) -> WorkerShadowEnvelope:
    """Export only identities and a canonical accepted-output digest after a turn."""

    if type(request) is not CodexWorkerRequest or type(result) is not CodexWorkerResult or not _token(provider_attempt_id) or not _token(external_turn_identity) or result.turn_identity != external_turn_identity:
        raise WorkerShadowError("Worker Shadow turn identity is invalid")
    accepted = None if result.output is None else _hash(result.output)
    if accepted is not None and accepted != result.output_fingerprint:
        raise WorkerShadowError("Worker Shadow accepted result is not bound to the adapter output")
    return WorkerShadowEnvelope(
        request.context.task_id, result.session_identity, provider_attempt_id, external_turn_identity,
        base_sha, candidate_sha, profile_identity, request.context.configuration_digest, runtime_fingerprint,
        request.input_digest, result.kind, accepted, deterministic_state, blocker, next_action, ready_at,
    )


def require_worker_shadow_capture_readiness(
    *, candidate_sha: str, ready_at: int, native_channel_producer_identity: str,
    exporter_identity: str, comparator_identity: str, recorder: RecorderBinding,
    store: AppendOnlyEvidenceStore,
) -> WorkerShadowCaptureReadiness:
    """Arm capture before provider work; no Worker request is accepted here."""

    profile = worker_adapter_shadow_profile()
    if type(recorder) is not RecorderBinding or type(store) is not AppendOnlyEvidenceStore or candidate_sha is None or type(ready_at) is not int:
        raise WorkerShadowError("Worker Shadow capture preflight is incomplete")
    recorder_digest = _hash({"harness_merge": recorder.harness_merge, "recorder_content": recorder.recorder_content, "harness_tree": recorder.harness_tree})
    store_identity = _hash({"retention_identity": store.retention_identity})
    return WorkerShadowCaptureReadiness(candidate_sha, ready_at, native_channel_producer_identity, exporter_identity, comparator_identity, recorder_digest, store_identity, profile_id=profile.profile_id)


def record_worker_shadow_envelope(
    readiness: WorkerShadowCaptureReadiness, envelope: WorkerShadowEnvelope, store: AppendOnlyEvidenceStore,
) -> WorkerShadowRecord:
    """Append and independently read back an armed envelope without Recorder I/O."""

    if type(readiness) is not WorkerShadowCaptureReadiness or type(envelope) is not WorkerShadowEnvelope or type(store) is not AppendOnlyEvidenceStore:
        raise WorkerShadowError("Worker Shadow capture record is invalid")
    current_store = _hash({"retention_identity": store.retention_identity})
    if (readiness.candidate_sha, readiness.ready_at, readiness.store_identity) != (envelope.candidate_sha, envelope.ready_at, current_store):
        raise WorkerShadowError("Worker Shadow capture is unarmed or stale; recapture is required")
    try:
        receipt = store.append(envelope.canonical_bytes())
        read_back = store.read_back(receipt)
    except Exception as error:
        raise WorkerShadowError("Worker Shadow append-only read-back is invalid") from error
    if read_back != envelope.canonical_bytes():
        raise WorkerShadowError("Worker Shadow append-only read-back is invalid")
    return WorkerShadowRecord(readiness.readiness_digest, envelope.envelope_digest, receipt.content_digest, envelope.candidate_sha, envelope.ready_at)


def compare_worker_shadow_envelopes(expected: WorkerShadowEnvelope, observed: WorkerShadowEnvelope) -> WorkerShadowComparison:
    """Compare deterministic public-safe fields; never inspect provider prose."""

    if type(expected) is not WorkerShadowEnvelope or type(observed) is not WorkerShadowEnvelope:
        raise WorkerShadowError("Worker Shadow comparison input is invalid")
    fields = tuple(key for key in expected.payload() if expected.payload()[key] != observed.payload()[key])
    disposition = WorkerShadowDisposition.MATCH if not fields else WorkerShadowDisposition.MISMATCH
    return WorkerShadowComparison(disposition, expected.envelope_digest, observed.envelope_digest, fields)


def _token(value: object) -> bool:
    return type(value) is str and bool(_TOKEN.fullmatch(value))


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
