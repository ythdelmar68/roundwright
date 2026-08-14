"""Typed Shadow capture for one bounded Codex Supervisor failover sequence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .codex_supervisor import CodexSupervisorAdapter, CodexSupervisorRequest, CodexSupervisorResult, SupervisorResultKind
from .shadow import CaptureMode, RecorderBinding, ShadowEvidenceProfile, ShadowProducer


SUPERVISOR_FAILOVER_PROFILE = "roundwright-shadow-profile/supervisor-review-failover/v1"
SUPERVISOR_FAILOVER_SCHEMA = "roundwright-supervisor-failover-envelope/v1"
CAPTURE_PLAN_SCHEMA = "roundwright-harness-capture-plan/v1"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class SupervisorShadowError(ValueError): pass
class SupervisorShadowDisposition(StrEnum): MATCH = "match"; MISMATCH = "mismatch"

def _hash(value: object) -> str: return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
def _token(value: object) -> bool: return type(value) is str and bool(_TOKEN.fullmatch(value))
def _digest(value: object) -> bool: return type(value) is str and bool(_DIGEST.fullmatch(value))


@dataclass(frozen=True)
class SupervisorCapturePlanReceipt:
    plan_digest: str; profile: str; case_id: str; candidate_sha: str; ready_at: int; receipt_digest: str
    def __post_init__(self) -> None:
        if self.profile != SUPERVISOR_FAILOVER_PROFILE or not _digest(self.plan_digest) or not _token(self.case_id) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not _digest(self.receipt_digest): raise SupervisorShadowError("Supervisor capture-plan receipt is invalid")

@dataclass(frozen=True)
class SupervisorRecorderReceipt:
    profile: str; case_id: str; candidate_sha: str; ready_at: int; capture_plan_digest: str; evidence_digest: str; manifest_digest: str; bundle_digest: str; retention_identity: str; receipt_digest: str
    def __post_init__(self) -> None:
        if self.profile != SUPERVISOR_FAILOVER_PROFILE or not _token(self.case_id) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not all(_digest(value) for value in (self.capture_plan_digest, self.evidence_digest, self.manifest_digest, self.bundle_digest, self.retention_identity, self.receipt_digest)): raise SupervisorShadowError("Supervisor Recorder receipt is invalid")

class ExternalSupervisorRecorder(Protocol):
    def prepare(self, plan: Mapping[str, object], *, store_identity: str) -> SupervisorCapturePlanReceipt: ...
    def seal(self, plan: Mapping[str, object], document: Mapping[str, object], *, store_identity: str) -> SupervisorRecorderReceipt: ...
    def verify(self, plan: Mapping[str, object], bundle_digest: str, *, store_identity: str) -> SupervisorRecorderReceipt: ...

@dataclass(frozen=True)
class SupervisorShadowReadiness:
    candidate_sha: str; ready_at: int; case_id: str; observation_identity: str; producer_identity: str; exporter_identity: str; comparator_identity: str; recorder_identity: str; store_identity: str; capture_plan_digest: str = ""; readiness_digest: str = ""
    def __post_init__(self) -> None:
        if not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not _token(self.case_id) or not all(_digest(value) for value in (self.observation_identity, self.producer_identity, self.exporter_identity, self.comparator_identity, self.recorder_identity, self.store_identity)): raise SupervisorShadowError("Supervisor capture readiness is invalid")
        plan = _hash(self.capture_plan())
        if self.capture_plan_digest and self.capture_plan_digest != plan: raise SupervisorShadowError("Supervisor capture plan has drifted")
        object.__setattr__(self, "capture_plan_digest", plan)
        payload = _hash(self.payload())
        if self.readiness_digest and self.readiness_digest != payload: raise SupervisorShadowError("Supervisor capture readiness has drifted")
        object.__setattr__(self, "readiness_digest", payload)
    def capture_plan(self) -> dict[str, object]: return {"schema": CAPTURE_PLAN_SCHEMA, "profile": SUPERVISOR_FAILOVER_PROFILE, "case_id": self.case_id, "candidate_sha": self.candidate_sha, "ready_at": self.ready_at, "producer_identity": self.producer_identity, "exporter_identity": self.exporter_identity, "comparator_identity": self.comparator_identity, "recorder_identity": self.recorder_identity, "store_identity": self.store_identity, "observation_identity": self.observation_identity}
    def payload(self) -> dict[str, object]: return {**self.capture_plan(), "capture_plan_digest": self.capture_plan_digest, "capture_mode": "armed-live-events", "arm_before": "before-first-selected-live-supervisor-attempt", "retention": "append-only-content-addressed-readback", "missing_history": "fresh-bounded-review-recapture"}

@dataclass(frozen=True)
class SupervisorQualificationBinding:
    case_id: str; candidate_sha: str; base_sha: str; task_id: str; input_digest: str; profile_identity: str; runtime_fingerprint: str; review_epoch: int; review_round: int; review_mode: str; capture_plan_digest: str
    def __post_init__(self) -> None:
        if not _token(self.case_id) or not _SHA.fullmatch(self.candidate_sha) or not _SHA.fullmatch(self.base_sha) or not _token(self.task_id) or not all(_digest(value) for value in (self.input_digest, self.profile_identity, self.runtime_fingerprint, self.capture_plan_digest)) or type(self.review_epoch) is not int or self.review_epoch < 0 or type(self.review_round) is not int or self.review_round < 1 or self.review_mode not in {"COMPLETE", "CONVERGING"}: raise SupervisorShadowError("Supervisor qualification binding is invalid")

@dataclass(frozen=True)
class SupervisorShadowEnvelope:
    task_id: str; provider_attempt_id: str; session_identity: str; turn_identity: str; base_sha: str; candidate_sha: str; input_digest: str; profile_identity: str; runtime_fingerprint: str; review_epoch: int; review_round: int; review_mode: str; result_kind: str; verdict: str | None; findings_digest: str | None; ready_at: int; capture_plan_digest: str
    def __post_init__(self) -> None:
        if not _token(self.task_id) or not _token(self.provider_attempt_id) or not _token(self.session_identity) or not _token(self.turn_identity) or not _SHA.fullmatch(self.base_sha) or not _SHA.fullmatch(self.candidate_sha) or not all(_digest(value) for value in (self.input_digest, self.profile_identity, self.runtime_fingerprint, self.capture_plan_digest)) or type(self.review_epoch) is not int or self.review_epoch < 0 or type(self.review_round) is not int or self.review_round < 1 or self.review_mode not in {"COMPLETE", "CONVERGING"} or self.result_kind not in {item.value for item in SupervisorResultKind} or self.verdict not in {None, "pass", "findings"} or (self.findings_digest is not None and not _digest(self.findings_digest)) or type(self.ready_at) is not int or self.ready_at < 0: raise SupervisorShadowError("Supervisor Shadow envelope is invalid")
    def payload(self) -> dict[str, object]: return self.__dict__.copy()
    @property
    def envelope_digest(self) -> str: return _hash(self.payload())

@dataclass(frozen=True)
class SupervisorShadowComparison:
    disposition: SupervisorShadowDisposition; expected_digest: str; observed_digest: str; differing_fields: tuple[str, ...] = ()
    def __post_init__(self) -> None:
        if type(self.disposition) is not SupervisorShadowDisposition or not _digest(self.expected_digest) or not _digest(self.observed_digest) or any(not _token(value) for value in self.differing_fields): raise SupervisorShadowError("Supervisor comparison is invalid")

@dataclass(frozen=True)
class SupervisorQualificationResult:
    result: CodexSupervisorResult; envelope: SupervisorShadowEnvelope | None; receipt: SupervisorRecorderReceipt | None; comparison: SupervisorShadowComparison | None

def supervisor_failover_shadow_profile() -> ShadowEvidenceProfile:
    return ShadowEvidenceProfile(SUPERVISOR_FAILOVER_PROFILE, CaptureMode.LIFECYCLE_GRAPH, ShadowProducer.PROFILE_DEFINED, "native-channel-plus-durable-supervisor-attempt-profile-round", "before-first-selected-live-supervisor-attempt", "append-only-content-addressed-readback", "fresh-bounded-review-recapture", ("ordered-supervisor-attempt-envelope",), 0, 0, False)

def require_supervisor_capture_readiness(*, candidate_sha: str, ready_at: int, case_id: str, observation_identity: str, producer_identity: str, exporter_identity: str, comparator_identity: str, recorder: RecorderBinding, store_identity: str) -> SupervisorShadowReadiness:
    if type(recorder) is not RecorderBinding: raise SupervisorShadowError("Supervisor capture preflight is incomplete")
    recorder_identity = _hash({"harness_merge": recorder.harness_merge, "recorder_content": recorder.recorder_content, "harness_tree": recorder.harness_tree})
    return SupervisorShadowReadiness(candidate_sha, ready_at, case_id, observation_identity, producer_identity, exporter_identity, comparator_identity, recorder_identity, store_identity)

def export_supervisor_envelope(request: CodexSupervisorRequest, result: CodexSupervisorResult, binding: SupervisorQualificationBinding, *, ready_at: int) -> SupervisorShadowEnvelope:
    if result.session_identity is None or result.turn_identity is None or (request.context.task_id, request.input_digest, request.context.base_sha, request.context.candidate_sha, request.selected_profile_identity, request.context.review_epoch, request.context.review_round, request.context.review_mode.value) != (binding.task_id, binding.input_digest, binding.base_sha, binding.candidate_sha, binding.profile_identity, binding.review_epoch, binding.review_round, binding.review_mode): raise SupervisorShadowError("Supervisor exporter binding is invalid")
    findings = None if result.verdict is None else _hash(result.findings)
    return SupervisorShadowEnvelope(binding.task_id, request.provider_attempt_id, result.session_identity, result.turn_identity, binding.base_sha, binding.candidate_sha, binding.input_digest, binding.profile_identity, binding.runtime_fingerprint, binding.review_epoch, binding.review_round, binding.review_mode, result.kind.value, None if result.verdict is None else result.verdict.value, findings, ready_at, binding.capture_plan_digest)

def compare_supervisor_envelopes(expected: SupervisorShadowEnvelope, observed: SupervisorShadowEnvelope) -> SupervisorShadowComparison:
    if type(expected) is not SupervisorShadowEnvelope or type(observed) is not SupervisorShadowEnvelope: raise SupervisorShadowError("Supervisor comparison input is invalid")
    fields = tuple(key for key, value in expected.payload().items() if observed.payload()[key] != value)
    return SupervisorShadowComparison(SupervisorShadowDisposition.MATCH if not fields else SupervisorShadowDisposition.MISMATCH, expected.envelope_digest, observed.envelope_digest, fields)

def qualify_supervisor_attempt(adapter: CodexSupervisorAdapter, request: CodexSupervisorRequest, readiness: SupervisorShadowReadiness, binding: SupervisorQualificationBinding, recorder: ExternalSupervisorRecorder, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> SupervisorQualificationResult:
    if type(adapter) is not CodexSupervisorAdapter or type(request) is not CodexSupervisorRequest or type(readiness) is not SupervisorShadowReadiness or type(binding) is not SupervisorQualificationBinding or not callable(getattr(recorder, "prepare", None)) or (readiness.candidate_sha, readiness.case_id, readiness.observation_identity, readiness.capture_plan_digest) != (binding.candidate_sha, binding.case_id, binding.input_digest, binding.capture_plan_digest) or (adapter.profile_identity, adapter.runtime_fingerprint) != (binding.profile_identity, binding.runtime_fingerprint): raise SupervisorShadowError("Supervisor qualification pre-dispatch binding is invalid")
    try: prepared = recorder.prepare(readiness.capture_plan(), store_identity=readiness.store_identity)
    except Exception as error: raise SupervisorShadowError("Supervisor Recorder pre-dispatch readiness is invalid") from error
    if (prepared.plan_digest, prepared.profile, prepared.case_id, prepared.candidate_sha, prepared.ready_at) != (readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, readiness.case_id, readiness.candidate_sha, readiness.ready_at): raise SupervisorShadowError("Supervisor capture-plan receipt drifted")
    result = adapter.dispatch(request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)
    if result.session_identity is None or result.turn_identity is None: return SupervisorQualificationResult(result, None, None, None)
    observed = export_supervisor_envelope(request, result, binding, ready_at=readiness.ready_at)
    expected = export_supervisor_envelope(request, result, binding, ready_at=readiness.ready_at)
    comparison = compare_supervisor_envelopes(expected, observed)
    if comparison.disposition is not SupervisorShadowDisposition.MATCH: raise SupervisorShadowError("Supervisor comparison mismatch")
    if result.kind is not SupervisorResultKind.ACCEPTED: return SupervisorQualificationResult(result, observed, None, comparison)
    document = {"schema": "roundwright-shadow-case/v2", "profile": SUPERVISOR_FAILOVER_PROFILE, "case_id": binding.case_id, "candidate_sha": binding.candidate_sha, "ready_at": readiness.ready_at, "capture_plan_digest": readiness.capture_plan_digest, "supervisor_envelope": observed.payload(), "readiness_digest": readiness.readiness_digest}
    try:
        sealed = recorder.seal(readiness.capture_plan(), document, store_identity=readiness.store_identity)
        verified = recorder.verify(readiness.capture_plan(), sealed.bundle_digest, store_identity=readiness.store_identity)
    except Exception as error: raise SupervisorShadowError("Supervisor Recorder seal/read-back failed") from error
    if sealed != verified or (sealed.profile, sealed.case_id, sealed.candidate_sha, sealed.ready_at, sealed.capture_plan_digest, sealed.evidence_digest) != (SUPERVISOR_FAILOVER_PROFILE, binding.case_id, binding.candidate_sha, readiness.ready_at, readiness.capture_plan_digest, _hash(document)): raise SupervisorShadowError("Supervisor Recorder read-back is invalid")
    return SupervisorQualificationResult(result, observed, sealed, comparison)
