"""Typed Shadow capture for one bounded Codex Supervisor failover sequence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .codex_supervisor import CodexSupervisorAdapter, CodexSupervisorRequest, CodexSupervisorResult, SupervisorFailoverResult, SupervisorResultKind, dispatch_ordered_supervisor_attempts
from .shadow import CaptureMode, RecorderBinding, ShadowEvidenceProfile, ShadowProducer
from .configuration import ResolvedConfigurationBinding, ReviewPolicy
from .runtime_binding import RuntimeBinding


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


class SupervisorSequenceTerminal(StrEnum):
    ACCEPTED = "accepted"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class SupervisorSequenceAttempt:
    ordinal: int; profile_identity: str; request_identity: str; result_kind: str; result_identity: str; verdict: str | None
    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal < 1 or not _digest(self.profile_identity) or not _digest(self.request_identity) or self.result_kind not in {item.value for item in SupervisorResultKind} or not _digest(self.result_identity) or self.verdict not in {None, "pass", "findings"} or ((self.result_kind == SupervisorResultKind.ACCEPTED.value) != (self.verdict is not None)):
            raise SupervisorShadowError("Supervisor sequence attempt is invalid")


@dataclass(frozen=True)
class SupervisorSequenceBinding:
    case_id: str; candidate_sha: str; base_sha: str; task_id: str; request_identities: tuple[str, ...]; profile_identities: tuple[str, ...]; runtime_fingerprints: tuple[str, ...]; review_epoch: int; review_round: int; review_mode: str; capture_plan_digest: str
    def __post_init__(self) -> None:
        if not _token(self.case_id) or not _SHA.fullmatch(self.candidate_sha) or not _SHA.fullmatch(self.base_sha) or not _token(self.task_id) or type(self.request_identities) is not tuple or type(self.profile_identities) is not tuple or type(self.runtime_fingerprints) is not tuple or not self.request_identities or len(self.request_identities) != len(self.profile_identities) or len(self.profile_identities) != len(self.runtime_fingerprints) or any(not _digest(value) for value in (*self.request_identities, *self.profile_identities, *self.runtime_fingerprints, self.capture_plan_digest)) or len(set(self.profile_identities)) != len(self.profile_identities) or type(self.review_epoch) is not int or self.review_epoch < 0 or type(self.review_round) is not int or self.review_round < 1 or self.review_mode not in {"COMPLETE", "CONVERGING"}:
            raise SupervisorShadowError("Supervisor sequence binding is invalid")


@dataclass(frozen=True)
class ResolvedSupervisorSequencePolicy:
    """Complete pinned configuration and its independently verified runtime form."""

    configuration: ResolvedConfigurationBinding; runtime: RuntimeBinding
    def __post_init__(self) -> None:
        if type(self.configuration) is not ResolvedConfigurationBinding or type(self.runtime) is not RuntimeBinding:
            raise SupervisorShadowError("Resolved Supervisor sequence policy is invalid")
        try:
            self.configuration.runtime_binding().require_matches(self.runtime)
        except Exception as error:
            raise SupervisorShadowError("Resolved Supervisor sequence policy is invalid") from error
        policy = self.configuration.review_policy
        if type(policy) is not ReviewPolicy or self.runtime.review_policy_digest != _hash({"complete_rounds": policy.complete_rounds, "max_rounds": policy.max_rounds, "max_supervisor_attempts_per_round": policy.max_supervisor_attempts_per_round, "on_final_findings": policy.on_final_findings.value}).removeprefix("sha256:"):
            raise SupervisorShadowError("Resolved Supervisor sequence policy is invalid")
    @property
    def policy(self) -> ReviewPolicy: return self.configuration.review_policy
    @property
    def policy_digest(self) -> str: return "sha256:" + self.runtime.review_policy_digest
    @property
    def configuration_digest(self) -> str: return self.configuration.digest
    @property
    def profile_identities(self) -> tuple[str, ...]: return self.configuration.supervisor_profile_identities


@dataclass(frozen=True)
class SupervisorExpectedLifecycle:
    """Policy-only envelope armed before provider events can exist."""

    binding: SupervisorSequenceBinding; policy_digest: str; configuration_digest: str; runtime_identity: str; ready_at: int; observation_identity: str
    def __post_init__(self) -> None:
        if type(self.binding) is not SupervisorSequenceBinding or not all(_digest(value) for value in (self.policy_digest, self.configuration_digest, self.runtime_identity, self.observation_identity)) or type(self.ready_at) is not int or self.ready_at < 0:
            raise SupervisorShadowError("Supervisor expected lifecycle is invalid")
    def payload(self) -> dict[str, object]:
        return {"schema": "roundwright-supervisor-expected-lifecycle/v1", "binding": self.binding.__dict__.copy(), "policy_digest": self.policy_digest, "configuration_digest": self.configuration_digest, "runtime_identity": self.runtime_identity, "ready_at": self.ready_at, "observation_identity": self.observation_identity, "allowed_terminal": ("accepted", "exhausted"), "accepted_next_action": "apply-bound-review-result", "exhausted_blocker": "attempt-budget-exhausted", "exhausted_next_action": "retain-terminal-product-block"}
    @property
    def source_identity(self) -> str: return _hash(self.payload())


@dataclass(frozen=True)
class SupervisorExpectedLifecycleReceipt:
    record_digest: str; source_identity: str; candidate_sha: str; capture_plan_digest: str; observation_identity: str; ready_at: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.record_digest, self.source_identity, self.observation_identity)) or not _SHA.fullmatch(self.candidate_sha) or not _digest(self.capture_plan_digest) or type(self.ready_at) is not int or self.ready_at < 0:
            raise SupervisorShadowError("Supervisor expected lifecycle receipt is invalid")

@dataclass(frozen=True)
class SupervisorAttemptEvent:
    record_identity: str; source_identity: str; observation_identity: str; candidate_sha: str; context_identity: str; capture_plan_digest: str; ordinal: int; prior_digest: str; result_kind: str; result_identity: str; ready_at: int; freshness_until: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.context_identity, self.capture_plan_digest, self.prior_digest, self.result_identity)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ordinal) is not int or self.ordinal < 1 or self.result_kind not in {item.value for item in SupervisorResultKind} or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.freshness_until < self.ready_at: raise SupervisorShadowError("Supervisor attempt event is invalid")
    def payload(self) -> dict[str, object]: return self.__dict__.copy()
    @property
    def content_digest(self) -> str: return _hash(self.payload())

@dataclass(frozen=True)
class SupervisorTerminalRecord:
    record_identity: str; source_identity: str; observation_identity: str; candidate_sha: str; context_identity: str; capture_plan_digest: str; prior_digest: str; terminal: str; blocker: str | None; next_action: str; ready_at: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.context_identity, self.capture_plan_digest, self.prior_digest)) or not _SHA.fullmatch(self.candidate_sha) or self.terminal not in {"accepted", "exhausted"} or not _token(self.next_action) or type(self.ready_at) is not int or self.ready_at < 0 or (self.terminal == "exhausted") != (self.blocker == "attempt-budget-exhausted"): raise SupervisorShadowError("Supervisor terminal record is invalid")

@dataclass(frozen=True)
class LifecycleChainReceipt:
    record_identity: str; source_identity: str; observation_identity: str; content_digest: str; prior_digest: str; ordinal: int; ready_at: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.content_digest, self.prior_digest)) or type(self.ordinal) is not int or self.ordinal < 0 or type(self.ready_at) is not int or self.ready_at < 0: raise SupervisorShadowError("Supervisor lifecycle receipt is invalid")

@dataclass(frozen=True)
class CompleteSupervisorLifecycleRecord:
    plan_receipt: LifecycleChainReceipt; events: tuple[SupervisorAttemptEvent, ...]; terminal: SupervisorTerminalRecord; terminal_receipt: LifecycleChainReceipt
    def __post_init__(self) -> None:
        if type(self.plan_receipt) is not LifecycleChainReceipt or type(self.events) is not tuple or any(type(item) is not SupervisorAttemptEvent for item in self.events) or type(self.terminal) is not SupervisorTerminalRecord or type(self.terminal_receipt) is not LifecycleChainReceipt or tuple(item.ordinal for item in self.events) != tuple(range(1, len(self.events) + 1)): raise SupervisorShadowError("Complete supervisor lifecycle record is invalid")


class ExternalSupervisorLifecycle(Protocol):
    """Append/read an immutable expected contract before provider events."""

    def prepare_expected(self, expected: SupervisorExpectedLifecycle) -> SupervisorExpectedLifecycleReceipt: ...
    def read_expected(self, receipt: SupervisorExpectedLifecycleReceipt) -> SupervisorExpectedLifecycle: ...
    def persist(self, record_identity: str, observation_identity: str, attempts: tuple["SupervisorSequenceAttempt", ...], result: SupervisorFailoverResult) -> None: ...
    def read(self, record_identity: str) -> tuple[str, tuple["SupervisorSequenceAttempt", ...], SupervisorFailoverResult]: ...


@dataclass(frozen=True)
class SupervisorSequenceEnvelope:
    task_id: str; base_sha: str; candidate_sha: str; request_identities: tuple[str, ...]; profile_identities: tuple[str, ...]; runtime_fingerprints: tuple[str, ...]; review_epoch: int; review_round: int; review_mode: str; capture_plan_digest: str; terminal: SupervisorSequenceTerminal; attempts: tuple[SupervisorSequenceAttempt, ...]; accepted_ordinal: int | None; accepted_result_identity: str | None; accepted_verdict: str | None; blocker: str | None; next_action: str
    def __post_init__(self) -> None:
        accepted = self.terminal is SupervisorSequenceTerminal.ACCEPTED
        if not _token(self.task_id) or not _SHA.fullmatch(self.base_sha) or not _SHA.fullmatch(self.candidate_sha) or type(self.request_identities) is not tuple or type(self.profile_identities) is not tuple or type(self.runtime_fingerprints) is not tuple or not self.request_identities or len(self.request_identities) != len(self.profile_identities) or len(self.profile_identities) != len(self.runtime_fingerprints) or any(not _digest(value) for value in (*self.request_identities, *self.profile_identities, *self.runtime_fingerprints, self.capture_plan_digest)) or type(self.review_epoch) is not int or self.review_epoch < 0 or type(self.review_round) is not int or self.review_round < 1 or self.review_mode not in {"COMPLETE", "CONVERGING"} or type(self.terminal) is not SupervisorSequenceTerminal or type(self.attempts) is not tuple or not self.attempts or any(type(item) is not SupervisorSequenceAttempt for item in self.attempts) or tuple(item.ordinal for item in self.attempts) != tuple(range(1, len(self.attempts) + 1)) or tuple(item.profile_identity for item in self.attempts) != self.profile_identities[:len(self.attempts)] or tuple(item.request_identity for item in self.attempts) != self.request_identities[:len(self.attempts)] or not _token(self.next_action):
            raise SupervisorShadowError("Supervisor sequence envelope is invalid")
        accepted_attempts = tuple(item for item in self.attempts if item.result_kind == SupervisorResultKind.ACCEPTED.value)
        if accepted:
            if len(accepted_attempts) != 1 or self.accepted_ordinal != accepted_attempts[0].ordinal or self.accepted_result_identity != accepted_attempts[0].result_identity or self.accepted_verdict != accepted_attempts[0].verdict or self.blocker is not None or self.attempts[-1] != accepted_attempts[0]:
                raise SupervisorShadowError("Supervisor accepted sequence is invalid")
        elif self.terminal is SupervisorSequenceTerminal.EXHAUSTED:
            if len(self.attempts) != len(self.profile_identities) or accepted_attempts or self.accepted_ordinal is not None or self.accepted_result_identity is not None or self.accepted_verdict is not None or self.blocker != "attempt-budget-exhausted":
                raise SupervisorShadowError("Supervisor exhausted sequence is invalid")
        else:
            raise SupervisorShadowError("Supervisor sequence terminal is invalid")
    def payload(self) -> dict[str, object]:
        return {"task_id": self.task_id, "base_sha": self.base_sha, "candidate_sha": self.candidate_sha, "request_identities": list(self.request_identities), "profile_identities": list(self.profile_identities), "runtime_fingerprints": list(self.runtime_fingerprints), "review_epoch": self.review_epoch, "review_round": self.review_round, "review_mode": self.review_mode, "capture_plan_digest": self.capture_plan_digest, "terminal": self.terminal.value, "attempts": [item.__dict__.copy() for item in self.attempts], "accepted_ordinal": self.accepted_ordinal, "accepted_result_identity": self.accepted_result_identity, "accepted_verdict": self.accepted_verdict, "blocker": self.blocker, "next_action": self.next_action}
    @property
    def envelope_digest(self) -> str: return _hash(self.payload())


@dataclass(frozen=True)
class SupervisorSequenceQualificationResult:
    failover: SupervisorFailoverResult; envelope: SupervisorSequenceEnvelope; receipt: SupervisorRecorderReceipt | None; comparison: SupervisorShadowComparison | None


def supervisor_sequence_observation_identity(requests: tuple[CodexSupervisorRequest, ...]) -> str:
    if type(requests) is not tuple or not requests or any(type(item) is not CodexSupervisorRequest for item in requests):
        raise SupervisorShadowError("Supervisor sequence requests are invalid")
    return _hash({"schema": "roundwright-supervisor-sequence-observation/v1", "requests": tuple({"ordinal": item.within_round_attempt, "profile_identity": item.selected_profile_identity, "request_identity": item.input_digest} for item in requests)})


def supervisor_sequence_lifecycle_identity(binding: SupervisorSequenceBinding) -> str:
    if type(binding) is not SupervisorSequenceBinding:
        raise SupervisorShadowError("Supervisor lifecycle binding is invalid")
    return _hash({"schema": "roundwright-supervisor-sequence-lifecycle/v1", "case_id": binding.case_id, "candidate_sha": binding.candidate_sha, "capture_plan_digest": binding.capture_plan_digest, "request_identities": binding.request_identities, "review_epoch": binding.review_epoch, "review_round": binding.review_round, "review_mode": binding.review_mode})


def _sequence_attempt(ordinal: int, request: CodexSupervisorRequest, result: CodexSupervisorResult) -> SupervisorSequenceAttempt:
    if type(ordinal) is not int or type(request) is not CodexSupervisorRequest or type(result) is not CodexSupervisorResult:
        raise SupervisorShadowError("Supervisor sequence result is invalid")
    identity = _hash({"ordinal": ordinal, "profile_identity": request.selected_profile_identity, "request_identity": request.input_digest, "result_kind": result.kind.value, "output_fingerprint": result.output_fingerprint, "diagnostic": None if result.diagnostic is None else result.diagnostic.value, "session_identity": result.session_identity, "turn_identity": result.turn_identity})
    return SupervisorSequenceAttempt(ordinal, request.selected_profile_identity, request.input_digest, result.kind.value, identity, None if result.verdict is None else result.verdict.value)


def export_supervisor_sequence(binding: SupervisorSequenceBinding, attempts: tuple[SupervisorSequenceAttempt, ...], failover: SupervisorFailoverResult) -> SupervisorSequenceEnvelope:
    if type(binding) is not SupervisorSequenceBinding or type(attempts) is not tuple or not attempts or any(type(item) is not SupervisorSequenceAttempt for item in attempts) or type(failover) is not SupervisorFailoverResult or tuple(item.profile_identity for item in attempts) != failover.attempted_profile_identities:
        raise SupervisorShadowError("Supervisor sequence exporter binding is invalid")
    if failover.result is None:
        return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.EXHAUSTED, attempts, None, None, None, "attempt-budget-exhausted", "retain-terminal-product-block")
    result = failover.result
    if result.kind is not SupervisorResultKind.ACCEPTED or result.verdict is None or len(attempts) > len(binding.profile_identities) or attempts[-1].result_kind != SupervisorResultKind.ACCEPTED.value or attempts[-1].verdict != result.verdict.value:
        raise SupervisorShadowError("Supervisor sequence accepted result is invalid")
    accepted = attempts[-1]
    return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.ACCEPTED, attempts, accepted.ordinal, accepted.result_identity, accepted.verdict, None, "apply-bound-review-result")


def derive_expected_supervisor_sequence(binding: SupervisorSequenceBinding, policy: ResolvedSupervisorSequencePolicy, lifecycle_attempts: tuple[SupervisorSequenceAttempt, ...], lifecycle_result: SupervisorFailoverResult, lifecycle_identity: str) -> SupervisorSequenceEnvelope:
    """Derive expected terminal state from durable sequence accounting, not export."""
    if type(binding) is not SupervisorSequenceBinding or type(policy) is not ResolvedSupervisorSequencePolicy or lifecycle_identity != supervisor_sequence_lifecycle_identity(binding) or type(lifecycle_attempts) is not tuple or not lifecycle_attempts or any(type(item) is not SupervisorSequenceAttempt for item in lifecycle_attempts) or type(lifecycle_result) is not SupervisorFailoverResult or tuple(item.ordinal for item in lifecycle_attempts) != tuple(range(1, len(lifecycle_attempts) + 1)) or tuple(item.profile_identity for item in lifecycle_attempts) != binding.profile_identities[:len(lifecycle_attempts)] or tuple(item.request_identity for item in lifecycle_attempts) != binding.request_identities[:len(lifecycle_attempts)]:
        raise SupervisorShadowError("Supervisor expected lifecycle state is invalid")
    if lifecycle_result.result is None:
        if len(lifecycle_attempts) != policy.policy.max_supervisor_attempts_per_round or any(item.result_kind == SupervisorResultKind.ACCEPTED.value for item in lifecycle_attempts):
            raise SupervisorShadowError("Supervisor expected exhaustion is invalid")
        return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.EXHAUSTED, lifecycle_attempts, None, None, None, "attempt-budget-exhausted", "retain-terminal-product-block")
    accepted = lifecycle_attempts[-1]
    if lifecycle_result.result.kind is not SupervisorResultKind.ACCEPTED or lifecycle_result.result.verdict is None or accepted.result_kind != SupervisorResultKind.ACCEPTED.value or accepted.verdict != lifecycle_result.result.verdict.value:
        raise SupervisorShadowError("Supervisor expected accepted lifecycle is invalid")
    return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.ACCEPTED, lifecycle_attempts, accepted.ordinal, accepted.result_identity, accepted.verdict, None, "apply-bound-review-result")


def compare_supervisor_sequences(expected: SupervisorSequenceEnvelope, observed: SupervisorSequenceEnvelope) -> SupervisorShadowComparison:
    if type(expected) is not SupervisorSequenceEnvelope or type(observed) is not SupervisorSequenceEnvelope:
        raise SupervisorShadowError("Supervisor sequence comparison input is invalid")
    fields = tuple(key for key, value in expected.payload().items() if observed.payload()[key] != value)
    return SupervisorShadowComparison(SupervisorShadowDisposition.MATCH if not fields else SupervisorShadowDisposition.MISMATCH, expected.envelope_digest, observed.envelope_digest, fields)


def qualify_supervisor_sequence(adapters: tuple[CodexSupervisorAdapter, ...], requests: tuple[CodexSupervisorRequest, ...], readiness: SupervisorShadowReadiness, binding: SupervisorSequenceBinding, resolved_policy: ResolvedSupervisorSequencePolicy, lifecycle: ExternalSupervisorLifecycle, recorder: ExternalSupervisorRecorder, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> SupervisorSequenceQualificationResult:
    """Capture exactly one terminal product failover sequence under one plan."""
    if type(adapters) is not tuple or type(requests) is not tuple or not adapters or len(adapters) != len(requests) or any(type(item) is not CodexSupervisorAdapter for item in adapters) or any(type(item) is not CodexSupervisorRequest for item in requests) or type(readiness) is not SupervisorShadowReadiness or type(binding) is not SupervisorSequenceBinding or type(resolved_policy) is not ResolvedSupervisorSequencePolicy or not callable(getattr(lifecycle, "prepare_expected", None)) or not callable(getattr(lifecycle, "read_expected", None)) or not callable(getattr(lifecycle, "persist", None)) or not callable(getattr(lifecycle, "read", None)) or not callable(getattr(recorder, "prepare", None)) or not callable(getattr(recorder, "seal", None)) or not callable(getattr(recorder, "verify", None)) or not callable(checkpoint_session) or not callable(checkpoint_turn):
        raise SupervisorShadowError("Supervisor sequence pre-dispatch binding is invalid")
    context = requests[0].context
    if any(request.context != context or request.within_round_attempt != ordinal for ordinal, request in enumerate(requests, start=1)) or (context.task_id, context.base_sha, context.candidate_sha, context.review_epoch, context.review_round, context.review_mode.value) != (binding.task_id, binding.base_sha, binding.candidate_sha, binding.review_epoch, binding.review_round, binding.review_mode) or tuple(request.input_digest for request in requests) != binding.request_identities or tuple(request.selected_profile_identity for request in requests) != binding.profile_identities or tuple(adapter.profile_identity for adapter in adapters) != binding.profile_identities or tuple(adapter.runtime_fingerprint for adapter in adapters) != binding.runtime_fingerprints or (context.policy_digest, context.configuration_digest, binding.profile_identities, len(requests), context.review_mode) != (resolved_policy.policy_digest, resolved_policy.configuration_digest, resolved_policy.profile_identities, resolved_policy.policy.max_supervisor_attempts_per_round, resolved_policy.policy.mode_for_round(context.review_round)) or (readiness.candidate_sha, readiness.case_id, readiness.capture_plan_digest, readiness.observation_identity) != (binding.candidate_sha, binding.case_id, binding.capture_plan_digest, supervisor_sequence_observation_identity(requests)):
        raise SupervisorShadowError("Supervisor sequence context has drifted")
    expected_plan = SupervisorExpectedLifecycle(binding, resolved_policy.policy_digest, resolved_policy.configuration_digest, _hash(resolved_policy.runtime.complete_columns()), readiness.ready_at, readiness.observation_identity)
    try:
        expected_receipt = lifecycle.prepare_expected(expected_plan)
        expected_readback = lifecycle.read_expected(expected_receipt)
    except Exception as error:
        raise SupervisorShadowError("Supervisor expected lifecycle pre-dispatch read-back failed") from error
    if expected_readback != expected_plan or (expected_receipt.source_identity, expected_receipt.candidate_sha, expected_receipt.capture_plan_digest, expected_receipt.observation_identity, expected_receipt.ready_at) != (expected_plan.source_identity, binding.candidate_sha, binding.capture_plan_digest, readiness.observation_identity, readiness.ready_at) or expected_receipt.record_digest != _hash(expected_plan.payload()):
        raise SupervisorShadowError("Supervisor expected lifecycle pre-dispatch drifted")
    try:
        prepared = recorder.prepare(readiness.capture_plan(), store_identity=readiness.store_identity)
    except Exception as error:
        raise SupervisorShadowError("Supervisor sequence Recorder pre-dispatch readiness is invalid") from error
    if (prepared.plan_digest, prepared.profile, prepared.case_id, prepared.candidate_sha, prepared.ready_at) != (readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, readiness.case_id, readiness.candidate_sha, readiness.ready_at):
        raise SupervisorShadowError("Supervisor sequence capture-plan receipt drifted")
    observed_attempts: list[SupervisorSequenceAttempt] = []
    failover = dispatch_ordered_supervisor_attempts(requests, adapters, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn, checkpoint_result=lambda ordinal, request, result: observed_attempts.append(_sequence_attempt(ordinal, request, result)))
    attempts = tuple(observed_attempts)
    lifecycle_identity = supervisor_sequence_lifecycle_identity(binding)
    try:
        lifecycle.persist(lifecycle_identity, readiness.observation_identity, attempts, failover)
        read_identity, lifecycle_attempts, lifecycle_failover = lifecycle.read(lifecycle_identity)
    except Exception as error:
        raise SupervisorShadowError("Supervisor durable lifecycle read-back failed") from error
    expected = derive_expected_supervisor_sequence(binding, resolved_policy, lifecycle_attempts, lifecycle_failover, read_identity)
    observed = export_supervisor_sequence(binding, attempts, failover)
    comparison = compare_supervisor_sequences(expected, observed)
    if comparison.disposition is not SupervisorShadowDisposition.MATCH:
        raise SupervisorShadowError("Supervisor sequence comparison mismatch")
    if expected.terminal is SupervisorSequenceTerminal.EXHAUSTED:
        return SupervisorSequenceQualificationResult(failover, observed, None, comparison)
    document = {"schema": "roundwright-shadow-case/v2", "profile": SUPERVISOR_FAILOVER_PROFILE, "case_id": binding.case_id, "candidate_sha": binding.candidate_sha, "ready_at": readiness.ready_at, "capture_plan_digest": readiness.capture_plan_digest, "supervisor_sequence": observed.payload(), "readiness_digest": readiness.readiness_digest}
    try:
        sealed = recorder.seal(readiness.capture_plan(), document, store_identity=readiness.store_identity)
        verified = recorder.verify(readiness.capture_plan(), sealed.bundle_digest, store_identity=readiness.store_identity)
    except Exception as error:
        raise SupervisorShadowError("Supervisor sequence Recorder seal/read-back failed") from error
    if sealed != verified or (sealed.profile, sealed.case_id, sealed.candidate_sha, sealed.ready_at, sealed.capture_plan_digest, sealed.evidence_digest) != (SUPERVISOR_FAILOVER_PROFILE, binding.case_id, binding.candidate_sha, readiness.ready_at, readiness.capture_plan_digest, _hash(document)):
        raise SupervisorShadowError("Supervisor sequence Recorder read-back is invalid")
    return SupervisorSequenceQualificationResult(failover, observed, sealed, comparison)
