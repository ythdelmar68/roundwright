"""Operational public-safe Shadow evidence for the native Codex Worker.

The live entry point is deliberately dependency-injected: the reviewed Harness
owns the Recorder process and the external retained store, while Roundwright
owns Worker semantics.  No SDK, credential, path, provider prose, or Recorder
implementation is imported here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .codex_worker import CodexWorkerAdapter, CodexWorkerRequest, CodexWorkerResult, WorkerCapabilityContract, WorkerOutcomeSource, WorkerParserDiagnostic, WorkerResultKind, WorkerSdkTurnErrorCategory, expected_lifecycle
from .shadow import CaptureMode, RecorderBinding, ShadowEvidenceProfile, ShadowProducer

WORKER_ADAPTER_PROFILE = "roundwright-shadow-profile/worker-adapter/v1"
WORKER_ADAPTER_SCHEMA = "roundwright-shadow-case/v2"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


class WorkerShadowError(ValueError): pass


class WorkerShadowMismatchError(WorkerShadowError):
    """Safe diagnostic for a live mismatch; it never carries provider text."""

    def __init__(self, comparison: "WorkerShadowComparison") -> None:
        self.comparison = comparison
        super().__init__("Worker Shadow observed lifecycle state differs: " + ",".join(comparison.differing_fields))


class WorkerShadowDisposition(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INVALID = "invalid"


@dataclass(frozen=True)
class WorkerShadowEnvelope:
    """One redacted durable request/result projection, not raw provider output."""
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
            self.schema != WORKER_ADAPTER_SCHEMA or self.profile_id != WORKER_ADAPTER_PROFILE
            or not all(_token(value) for value in (self.task_id, self.worker_thread_identity, self.provider_attempt_id, self.external_turn_identity, self.deterministic_state, self.next_action))
            or not _SHA.fullmatch(self.base_sha) or not _SHA.fullmatch(self.candidate_sha)
            or not all(_digest(value) for value in (self.profile_identity, self.configuration_digest, self.runtime_fingerprint, self.request_digest))
            or type(self.result_kind) is not WorkerResultKind
            or (self.accepted_result_digest is not None and not _digest(self.accepted_result_digest))
            or (self.blocker is not None and not _token(self.blocker)) or type(self.ready_at) is not int or self.ready_at < 0
        ): raise WorkerShadowError("Worker Shadow envelope is invalid")
        if (self.result_kind is WorkerResultKind.ACCEPTED) != (self.accepted_result_digest is not None):
            raise WorkerShadowError("Worker Shadow accepted-result binding is invalid")
        digest = _hash(self.payload())
        if self.envelope_digest and self.envelope_digest != digest: raise WorkerShadowError("Worker Shadow envelope digest is invalid")
        object.__setattr__(self, "envelope_digest", digest)

    def payload(self) -> dict[str, object]:
        return {"schema": self.schema, "profile_id": self.profile_id, "task_id": self.task_id, "worker_thread_identity": self.worker_thread_identity, "provider_attempt_id": self.provider_attempt_id, "external_turn_identity": self.external_turn_identity, "base_sha": self.base_sha, "candidate_sha": self.candidate_sha, "profile_identity": self.profile_identity, "configuration_digest": self.configuration_digest, "runtime_fingerprint": self.runtime_fingerprint, "request_digest": self.request_digest, "result_kind": self.result_kind.value, "accepted_result_digest": self.accepted_result_digest, "deterministic_state": self.deterministic_state, "blocker": self.blocker, "next_action": self.next_action, "ready_at": self.ready_at}


@dataclass(frozen=True)
class ExternalRecorderReceipt:
    """The reviewed Harness's path-free sealed/re-read receipt projection."""
    profile: str
    case_id: str
    candidate_sha: str
    ready_at: int
    evidence_digest: str
    manifest_digest: str
    bundle_digest: str
    retention_identity: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if self.profile != WORKER_ADAPTER_PROFILE or not _token(self.case_id) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not all(_digest(value) for value in (self.evidence_digest, self.manifest_digest, self.bundle_digest, self.retention_identity, self.receipt_digest)):
            raise WorkerShadowError("external Recorder receipt is invalid")


class ExternalWorkerRecorder(Protocol):
    """Harness CLI bridge; store identity is external to product Git."""
    def prepare(self, *, store_identity: str) -> None: ...
    def seal(self, document: Mapping[str, object], *, store_identity: str) -> ExternalRecorderReceipt: ...
    def verify(self, bundle_digest: str, *, store_identity: str) -> ExternalRecorderReceipt: ...


@dataclass(frozen=True)
class WorkerShadowCaptureReadiness:
    """Armed pre-dispatch binding. It never claims an observation was recorded."""
    candidate_sha: str
    ready_at: int
    native_channel_producer_identity: str
    exporter_identity: str
    comparator_identity: str
    recorder_binding_digest: str
    store_identity: str
    capability_contract: str = WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED.value
    schema: str = WORKER_ADAPTER_SCHEMA
    profile_id: str = WORKER_ADAPTER_PROFILE
    retention_contract: str = "append-only-content-addressed-readback"
    missing_history_action: str = "fresh-bounded-attempt-recapture"
    readiness_digest: str = ""

    def __post_init__(self) -> None:
        if self.schema != WORKER_ADAPTER_SCHEMA or self.profile_id != WORKER_ADAPTER_PROFILE or self.capability_contract != WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED.value or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not all(_digest(value) for value in (self.native_channel_producer_identity, self.exporter_identity, self.comparator_identity, self.recorder_binding_digest, self.store_identity)) or self.retention_contract != "append-only-content-addressed-readback" or self.missing_history_action != "fresh-bounded-attempt-recapture":
            raise WorkerShadowError("Worker Shadow capture readiness is invalid")
        digest = _hash(self.payload())
        if self.readiness_digest and self.readiness_digest != digest: raise WorkerShadowError("Worker Shadow capture readiness digest is invalid")
        object.__setattr__(self, "readiness_digest", digest)

    def payload(self) -> dict[str, object]:
        return {"schema": self.schema, "profile_id": self.profile_id, "candidate_sha": self.candidate_sha, "ready_at": self.ready_at, "native_channel_producer_identity": self.native_channel_producer_identity, "exporter_identity": self.exporter_identity, "comparator_identity": self.comparator_identity, "recorder_binding_digest": self.recorder_binding_digest, "store_identity": self.store_identity, "capability_contract": self.capability_contract, "retention_contract": self.retention_contract, "missing_history_action": self.missing_history_action}


@dataclass(frozen=True)
class WorkerQualificationBinding:
    """Exact candidate/runtime identities required before an SDK call."""
    case_id: str
    task_id: str
    attempt_id: str
    input_digest: str
    resume_session_identity: str | None
    source_digest: str
    repository_fingerprint: str
    worktree_fingerprint: str
    branch_fingerprint: str
    policy_fingerprint: str
    base_sha: str
    candidate_sha: str
    base_fingerprint: str
    candidate_fingerprint: str
    profile_identity: str
    configuration_digest: str
    runtime_fingerprint: str
    native_channel_producer_identity: str
    exporter_identity: str
    comparator_identity: str
    recorder_binding_digest: str
    store_identity: str
    deterministic_state: str
    blocker: str | None
    next_action: str
    capability_contract: str = WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED.value

    def __post_init__(self) -> None:
        if not _token(self.case_id) or not _token(self.task_id) or not _token(self.attempt_id) or (self.resume_session_identity is not None and not _token(self.resume_session_identity)) or not _SHA.fullmatch(self.base_sha) or not _SHA.fullmatch(self.candidate_sha) or self.capability_contract != WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED.value or not all(_digest(value) for value in (self.input_digest, self.source_digest, self.repository_fingerprint, self.worktree_fingerprint, self.branch_fingerprint, self.policy_fingerprint, self.base_fingerprint, self.candidate_fingerprint, self.profile_identity, self.configuration_digest, self.runtime_fingerprint, self.native_channel_producer_identity, self.exporter_identity, self.comparator_identity, self.recorder_binding_digest, self.store_identity)) or not _token(self.deterministic_state) or not _token(self.next_action) or (self.blocker is not None and not _token(self.blocker)):
            raise WorkerShadowError("Worker qualification binding is invalid")


@dataclass(frozen=True)
class WorkerShadowRecord:
    readiness_digest: str
    envelope_digest: str
    receipt: ExternalRecorderReceipt

    def __post_init__(self) -> None:
        if not _digest(self.readiness_digest) or not _digest(self.envelope_digest) or type(self.receipt) is not ExternalRecorderReceipt: raise WorkerShadowError("Worker Shadow record is invalid")


@dataclass(frozen=True)
class WorkerShadowComparison:
    disposition: WorkerShadowDisposition
    expected_digest: str
    observed_digest: str
    differing_fields: tuple[str, ...] = ()
    def __post_init__(self) -> None:
        if type(self.disposition) is not WorkerShadowDisposition or not _digest(self.expected_digest) or not _digest(self.observed_digest) or type(self.differing_fields) is not tuple or any(not _token(value) for value in self.differing_fields): raise WorkerShadowError("Worker Shadow comparison is invalid")

    def diagnostic(self) -> dict[str, object]:
        """Public-safe mismatch result: field names and typed disposition only."""
        return {"disposition": self.disposition.value, "differing_fields": self.differing_fields}


@dataclass(frozen=True)
class WorkerQualificationResult:
    result: CodexWorkerResult
    envelope: WorkerShadowEnvelope | None
    record: WorkerShadowRecord | None
    comparison: WorkerShadowComparison | None


def worker_adapter_shadow_profile() -> ShadowEvidenceProfile:
    return ShadowEvidenceProfile(WORKER_ADAPTER_PROFILE, CaptureMode.LIFECYCLE_GRAPH, ShadowProducer.PROFILE_DEFINED, "v2-native-channel-exporter-comparator-recorder-store-readback-bound", "before-first-selected-live-worker-provider-attempt", "append-only-content-addressed-readback", "fresh-bounded-attempt-recapture", ("worker-request-response-envelope",), 0, 0, False)


def require_worker_shadow_capture_readiness(*, candidate_sha: str, ready_at: int, native_channel_producer_identity: str, exporter_identity: str, comparator_identity: str, recorder: RecorderBinding, store_identity: str, capability_contract: str = WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED.value) -> WorkerShadowCaptureReadiness:
    """Bind external retention before dispatch, without creating a recording."""
    if type(recorder) is not RecorderBinding: raise WorkerShadowError("Worker Shadow capture preflight is incomplete")
    recorder_digest = _hash({"harness_merge": recorder.harness_merge, "recorder_content": recorder.recorder_content, "harness_tree": recorder.harness_tree})
    return WorkerShadowCaptureReadiness(candidate_sha, ready_at, native_channel_producer_identity, exporter_identity, comparator_identity, recorder_digest, store_identity, capability_contract)


def export_worker_shadow_envelope(request: CodexWorkerRequest, result: CodexWorkerResult, *, provider_attempt_id: str, external_turn_identity: str, binding: WorkerQualificationBinding, ready_at: int, expected: bool = False) -> WorkerShadowEnvelope:
    if type(request) is not CodexWorkerRequest or type(result) is not CodexWorkerResult or not _token(provider_attempt_id) or not _token(external_turn_identity) or result.session_identity is None or result.turn_identity != external_turn_identity or request.context.task_id == "": raise WorkerShadowError("Worker Shadow turn identity is invalid")
    accepted = None if result.output is None else _hash(result.output)
    if accepted is not None and accepted != result.output_fingerprint: raise WorkerShadowError("Worker Shadow accepted result is not bound to the adapter output")
    if expected:
        state, blocker, next_action = _expected_worker_transition(request.action, result, binding)
    else:
        state, blocker, next_action = _observed_worker_transition(request.action, result)
    return WorkerShadowEnvelope(request.context.task_id, result.session_identity, provider_attempt_id, external_turn_identity, binding.base_sha, binding.candidate_sha, binding.profile_identity, request.context.configuration_digest, binding.runtime_fingerprint, request.input_digest, result.kind, accepted, state, blocker, next_action, ready_at)


def record_worker_shadow_envelope(readiness: WorkerShadowCaptureReadiness, envelope: WorkerShadowEnvelope, recorder: ExternalWorkerRecorder, *, case_id: str) -> WorkerShadowRecord:
    """Seal via Harness then independently verify retained bytes/receipt."""
    if type(readiness) is not WorkerShadowCaptureReadiness or type(envelope) is not WorkerShadowEnvelope or not callable(getattr(recorder, "seal", None)) or not callable(getattr(recorder, "verify", None)) or not _token(case_id): raise WorkerShadowError("Worker Shadow capture record is invalid")
    if (readiness.candidate_sha, readiness.ready_at) != (envelope.candidate_sha, envelope.ready_at): raise WorkerShadowError("Worker Shadow capture is unarmed or stale; recapture is required")
    document = {"schema": WORKER_ADAPTER_SCHEMA, "profile": WORKER_ADAPTER_PROFILE, "ready_at": envelope.ready_at, "case_id": case_id, "candidate_sha": envelope.candidate_sha, "worker_envelope": envelope.payload(), "readiness_digest": readiness.readiness_digest}
    try:
        sealed = recorder.seal(document, store_identity=readiness.store_identity)
        verified = recorder.verify(sealed.bundle_digest, store_identity=readiness.store_identity)
    except Exception as error:
        raise WorkerShadowError("external Recorder seal or read-back is invalid") from error
    if sealed != verified or (sealed.profile, sealed.case_id, sealed.candidate_sha, sealed.ready_at, sealed.evidence_digest) != (WORKER_ADAPTER_PROFILE, case_id, envelope.candidate_sha, envelope.ready_at, _hash(document)):
        raise WorkerShadowError("external Recorder retained identity is invalid")
    return WorkerShadowRecord(readiness.readiness_digest, envelope.envelope_digest, sealed)


def qualify_worker_adapter(adapter: CodexWorkerAdapter, request: CodexWorkerRequest, readiness: WorkerShadowCaptureReadiness, binding: WorkerQualificationBinding, recorder: ExternalWorkerRecorder, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None], checkpoint_result: Callable[[str, str, WorkerResultKind, WorkerParserDiagnostic | None, WorkerOutcomeSource | None, WorkerSdkTurnErrorCategory | None], None]) -> WorkerQualificationResult:
    """One armed, bounded turn; never retries or starts a second Worker."""
    if type(adapter) is not CodexWorkerAdapter or type(request) is not CodexWorkerRequest or type(readiness) is not WorkerShadowCaptureReadiness or type(binding) is not WorkerQualificationBinding or not callable(getattr(recorder, "prepare", None)) or (readiness.candidate_sha, readiness.ready_at, readiness.native_channel_producer_identity, readiness.exporter_identity, readiness.comparator_identity, readiness.recorder_binding_digest, readiness.store_identity, readiness.capability_contract) != (binding.candidate_sha, readiness.ready_at, binding.native_channel_producer_identity, binding.exporter_identity, binding.comparator_identity, binding.recorder_binding_digest, binding.store_identity, binding.capability_contract) or (request.attempt_id, request.input_digest, request.resume_session_identity, request.context.task_id, request.context.source_digest, request.context.repository_fingerprint, request.context.worktree_fingerprint, request.context.branch_fingerprint, request.context.policy_fingerprint, request.context.base_fingerprint, request.context.candidate_fingerprint, request.context.configuration_digest) != (binding.attempt_id, binding.input_digest, binding.resume_session_identity, binding.task_id, binding.source_digest, binding.repository_fingerprint, binding.worktree_fingerprint, binding.branch_fingerprint, binding.policy_fingerprint, binding.base_fingerprint, binding.candidate_fingerprint, binding.configuration_digest) or adapter.capability_contract.value != readiness.capability_contract: raise WorkerShadowError("Worker qualification pre-dispatch binding is invalid")
    if (adapter.profile_identity, adapter.runtime_fingerprint) != (binding.profile_identity, binding.runtime_fingerprint): raise WorkerShadowError("Worker qualification runtime identity has drifted")
    if (binding.deterministic_state, binding.blocker, binding.next_action) != expected_lifecycle(request.action):
        raise WorkerShadowError("Worker qualification deterministic lifecycle binding is invalid")
    try:
        recorder.prepare(store_identity=readiness.store_identity)
    except Exception as error:
        raise WorkerShadowError("external Recorder pre-dispatch readiness is invalid") from error
    # The adapter does not receive a clock; every outward artifact consumes the pre-bound ready_at.
    result = adapter.dispatch(request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)
    if result.turn_identity is None: return WorkerQualificationResult(result, None, None, None)
    try:
        checkpoint_result(result.session_identity, result.turn_identity, result.kind, result.diagnostic, result.outcome_source, result.sdk_error_category)  # type: ignore[arg-type]
    except Exception as error:
        raise WorkerShadowError("Worker response-stage checkpoint is invalid") from error
    observed = export_worker_shadow_envelope(request, result, provider_attempt_id=request.attempt_id, external_turn_identity=result.turn_identity, binding=binding, ready_at=readiness.ready_at)
    expected = export_worker_shadow_envelope(request, result, provider_attempt_id=request.attempt_id, external_turn_identity=result.turn_identity, binding=binding, ready_at=readiness.ready_at, expected=True)
    comparison = compare_worker_shadow_envelopes(expected, observed)
    if comparison.disposition is not WorkerShadowDisposition.MATCH:
        raise WorkerShadowMismatchError(comparison)
    if result.kind is not WorkerResultKind.ACCEPTED:
        # A checked failure projection is diagnostic only. It is never a
        # qualifying capture and therefore cannot reach the Recorder.
        return WorkerQualificationResult(result, observed, None, comparison)
    record = record_worker_shadow_envelope(readiness, observed, recorder, case_id=binding.case_id)
    return WorkerQualificationResult(result, observed, record, comparison)


def compare_worker_shadow_envelopes(expected: WorkerShadowEnvelope, observed: WorkerShadowEnvelope) -> WorkerShadowComparison:
    if type(expected) is not WorkerShadowEnvelope or type(observed) is not WorkerShadowEnvelope: raise WorkerShadowError("Worker Shadow comparison input is invalid")
    fields = tuple(key for key in expected.payload() if expected.payload()[key] != observed.payload()[key])
    return WorkerShadowComparison(WorkerShadowDisposition.MATCH if not fields else WorkerShadowDisposition.MISMATCH, expected.envelope_digest, observed.envelope_digest, fields)


def _observed_worker_transition(action, result: CodexWorkerResult) -> tuple[str, str | None, str]:
    """State-machine projection from a checkpointed typed result, never provider prose.

    This intentionally does not reuse ``expected_lifecycle``: it models the
    observed local state transition independently, so a mapping defect remains
    visible to the comparison gate before any Recorder call.
    """
    if result.kind is WorkerResultKind.BLOCKED:
        return "blocked", result.blocker, "owner-input"
    if result.kind is WorkerResultKind.INVALID:
        return "invalid", None, "fresh-bounded-attempt-recapture"
    if result.kind is WorkerResultKind.INCOMPLETE:
        return "incomplete", None, "fresh-bounded-attempt-recapture"
    if result.kind is WorkerResultKind.AMBIGUOUS:
        return "blocked", "exact-turn-recovery", "blocked-ambiguous-turn"
    accepted = {
        "planning": ("planning-complete", None, "supervisor-review"),
        "implementation": ("implementation-complete", None, "supervisor-review"),
        "repair": ("qualification-complete", None, "supervisor-review"),
    }
    try:
        return accepted[action.value]
    except (AttributeError, KeyError) as error:
        raise WorkerShadowError("Worker observed lifecycle action is invalid") from error


def _expected_worker_transition(action, result: CodexWorkerResult, binding: WorkerQualificationBinding) -> tuple[str, str | None, str]:
    """Independent deterministic expectation for either success or failure."""
    if result.kind is WorkerResultKind.ACCEPTED:
        return binding.deterministic_state, binding.blocker, binding.next_action
    failure = {
        WorkerResultKind.BLOCKED: ("blocked", result.blocker, "owner-input"),
        WorkerResultKind.INVALID: ("invalid", None, "fresh-bounded-attempt-recapture"),
        WorkerResultKind.INCOMPLETE: ("incomplete", None, "fresh-bounded-attempt-recapture"),
        WorkerResultKind.AMBIGUOUS: ("blocked", "exact-turn-recovery", "blocked-ambiguous-turn"),
    }
    try:
        return failure[result.kind]
    except KeyError as error:
        raise WorkerShadowError("Worker expected lifecycle result is invalid") from error


def _token(value: object) -> bool: return type(value) is str and bool(_TOKEN.fullmatch(value))
def _digest(value: object) -> bool: return type(value) is str and bool(_DIGEST.fullmatch(value))
def _hash(value: object) -> str: return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
