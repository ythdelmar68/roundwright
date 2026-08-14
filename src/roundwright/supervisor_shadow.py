"""Typed Shadow capture for one bounded Codex Supervisor failover sequence."""

from __future__ import annotations

import hashlib
import json
import re
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .codex_supervisor import CodexSupervisorAdapter, CodexSupervisorRequest, CodexSupervisorResult, SupervisorFailoverResult, SupervisorResultKind, dispatch_ordered_supervisor_attempts
from .shadow import CaptureMode, RecorderBinding, ShadowEvidenceProfile, ShadowProducer
from .configuration import ResolvedConfigurationBinding, ReviewPolicy
from .runtime_binding import ExternalSupervisorRuntimeStore, RuntimeBinding, SupervisorRuntimeBindingReceipt


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
    raise SupervisorShadowError("Supervisor single-attempt qualification is disabled; use qualify_supervisor_sequence")
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
    def context_identity(self) -> str: return _hash({"task_id": self.binding.task_id, "base_sha": self.binding.base_sha, "candidate_sha": self.binding.candidate_sha, "requests": self.binding.request_identities, "profiles": self.binding.profile_identities, "runtime": self.binding.runtime_fingerprints, "epoch": self.binding.review_epoch, "round": self.binding.review_round, "mode": self.binding.review_mode, "capture_plan": self.binding.capture_plan_digest})
    @property
    def plan_identity(self) -> str: return _hash({**self.payload(), "context_identity": self.context_identity, "allowed_result_kinds": tuple(item.value for item in SupervisorResultKind), "attempt_budget": len(self.binding.profile_identities)})
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
    record_identity: str; source_identity: str; observation_identity: str; candidate_sha: str; context_identity: str; plan_identity: str; capture_plan_digest: str; ordinal: int; prior_digest: str; request_identity: str; profile_identity: str; runtime_fingerprint: str; result_kind: str; result_identity: str; accepted_result_identity: str | None; verdict: str | None; ready_at: int; freshness_until: int
    def __post_init__(self) -> None:
        accepted = self.result_kind == SupervisorResultKind.ACCEPTED.value
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.context_identity, self.plan_identity, self.capture_plan_digest, self.prior_digest, self.request_identity, self.profile_identity, self.runtime_fingerprint, self.result_identity)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ordinal) is not int or self.ordinal < 1 or self.result_kind not in {item.value for item in SupervisorResultKind} or self.verdict not in {None, "pass", "findings"} or (accepted != (self.verdict is not None)) or (accepted != (self.accepted_result_identity == self.result_identity)) or (not accepted and self.accepted_result_identity is not None) or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.freshness_until < self.ready_at: raise SupervisorShadowError("Supervisor attempt event is invalid")
    def payload(self) -> dict[str, object]: return self.__dict__.copy()
    @property
    def content_digest(self) -> str: return _hash(self.payload())

@dataclass(frozen=True)
class SupervisorTerminalRecord:
    record_identity: str; source_identity: str; observation_identity: str; candidate_sha: str; context_identity: str; plan_identity: str; capture_plan_digest: str; prior_digest: str; attempt_count: int; terminal: str; accepted_result_identity: str | None; blocker: str | None; next_action: str; ready_at: int
    def __post_init__(self) -> None:
        accepted = self.terminal == "accepted"
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.context_identity, self.plan_identity, self.capture_plan_digest, self.prior_digest)) or not _SHA.fullmatch(self.candidate_sha) or self.terminal not in {"accepted", "exhausted"} or type(self.attempt_count) is not int or self.attempt_count < 1 or type(self.ready_at) is not int or self.ready_at < 0 or (accepted and (not _digest(self.accepted_result_identity) or self.blocker is not None or self.next_action != "apply-bound-review-result")) or (not accepted and (self.accepted_result_identity is not None or self.blocker != "attempt-budget-exhausted" or self.next_action != "retain-terminal-product-block")): raise SupervisorShadowError("Supervisor terminal record is invalid")

@dataclass(frozen=True)
class LifecycleChainReceipt:
    binding: SupervisorLifecycleChainBinding; content_digest: str; prior_digest: str; ordinal: int
    def __post_init__(self) -> None:
        if type(self.binding) is not SupervisorLifecycleChainBinding or not all(_digest(value) for value in (self.content_digest, self.prior_digest)) or type(self.ordinal) is not int or self.ordinal < 0: raise SupervisorShadowError("Supervisor lifecycle receipt is invalid")
    def payload(self) -> dict[str, object]: return {"binding": self.binding.payload(), "content_digest": self.content_digest, "prior_digest": self.prior_digest, "ordinal": self.ordinal}
    @property
    def receipt_digest(self) -> str: return _hash(self.payload())
    @property
    def record_identity(self) -> str: return self.binding.record_identity
    @property
    def source_identity(self) -> str: return self.binding.source_identity
    @property
    def observation_identity(self) -> str: return self.binding.observation_identity
    @property
    def candidate_sha(self) -> str: return self.binding.candidate_sha
    @property
    def context_identity(self) -> str: return self.binding.context_identity
    @property
    def plan_identity(self) -> str: return self.binding.plan_identity
    @property
    def capture_plan_digest(self) -> str: return self.binding.capture_plan_digest
    @property
    def ready_at(self) -> int: return self.binding.ready_at
    @property
    def freshness_until(self) -> int: return self.binding.freshness_until

@dataclass(frozen=True)
class SupervisorLifecycleChainBinding:
    record_identity: str; source_identity: str; observation_identity: str; candidate_sha: str; context_identity: str; plan_identity: str; capture_plan_digest: str; ready_at: int; freshness_until: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.record_identity, self.source_identity, self.observation_identity, self.context_identity, self.plan_identity, self.capture_plan_digest)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.ready_at < 0 or self.freshness_until < self.ready_at: raise SupervisorShadowError("Supervisor lifecycle chain binding is invalid")
    def payload(self) -> dict[str, object]: return self.__dict__.copy()
    @property
    def binding_digest(self) -> str: return _hash(self.payload())


@dataclass(frozen=True)
class TrustedReviewPolicyReceipt:
    """Independent, canonical policy-floor evidence required for Supervisor work."""
    source_identity: str; authority_identity: str; candidate_sha: str; configuration_digest: str; policy_digest: str; supervisor_profile_identities: tuple[str, ...]; complete_rounds: int; max_rounds: int; attempt_budget: int; on_final_findings: str; ready_at: int; freshness_until: int
    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.source_identity, self.authority_identity, self.configuration_digest, self.policy_digest)) or not _SHA.fullmatch(self.candidate_sha) or type(self.supervisor_profile_identities) is not tuple or not self.supervisor_profile_identities or len(set(self.supervisor_profile_identities)) != len(self.supervisor_profile_identities) or any(not _digest(value) for value in self.supervisor_profile_identities) or type(self.complete_rounds) is not int or type(self.max_rounds) is not int or type(self.attempt_budget) is not int or self.complete_rounds < 1 or self.max_rounds < self.complete_rounds or self.attempt_budget != len(self.supervisor_profile_identities) or self.on_final_findings != "worker-final-repair-then-merge" or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.ready_at < 0 or self.freshness_until < self.ready_at:
            raise SupervisorShadowError("Trusted review policy receipt is invalid")
    def payload(self) -> dict[str, object]: return {"schema": "roundwright-trusted-review-policy-receipt/v1", "source_identity": self.source_identity, "authority_identity": self.authority_identity, "candidate_sha": self.candidate_sha, "configuration_digest": self.configuration_digest, "policy_digest": self.policy_digest, "supervisor_profile_identities": list(self.supervisor_profile_identities), "complete_rounds": self.complete_rounds, "max_rounds": self.max_rounds, "attempt_budget": self.attempt_budget, "on_final_findings": self.on_final_findings, "ready_at": self.ready_at, "freshness_until": self.freshness_until}
    @property
    def receipt_digest(self) -> str: return _hash(self.payload())
    @classmethod
    def from_canonical(cls, material: object) -> "TrustedReviewPolicyReceipt":
        if type(material) is not str: raise SupervisorShadowError("Trusted review policy receipt material is invalid")
        try:
            payload = json.loads(material); expected = {"schema", "source_identity", "authority_identity", "candidate_sha", "configuration_digest", "policy_digest", "supervisor_profile_identities", "complete_rounds", "max_rounds", "attempt_budget", "on_final_findings", "ready_at", "freshness_until"}
            if type(payload) is not dict or set(payload) != expected or payload["schema"] != "roundwright-trusted-review-policy-receipt/v1" or json.dumps(payload, sort_keys=True, separators=(",", ":")) != material: raise ValueError
            return cls(payload["source_identity"], payload["authority_identity"], payload["candidate_sha"], payload["configuration_digest"], payload["policy_digest"], tuple(payload["supervisor_profile_identities"]), payload["complete_rounds"], payload["max_rounds"], payload["attempt_budget"], payload["on_final_findings"], payload["ready_at"], payload["freshness_until"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error: raise SupervisorShadowError("Trusted review policy receipt material is invalid") from error

@dataclass(frozen=True)
class CompleteSupervisorLifecycleRecord:
    expected_plan: SupervisorExpectedLifecycle; plan_receipt: LifecycleChainReceipt; events: tuple[SupervisorAttemptEvent, ...]; terminal: SupervisorTerminalRecord; terminal_receipt: LifecycleChainReceipt
    def __post_init__(self) -> None:
        if type(self.expected_plan) is not SupervisorExpectedLifecycle or type(self.plan_receipt) is not LifecycleChainReceipt or type(self.events) is not tuple or not self.events or any(type(item) is not SupervisorAttemptEvent for item in self.events) or type(self.terminal) is not SupervisorTerminalRecord or type(self.terminal_receipt) is not LifecycleChainReceipt or tuple(item.ordinal for item in self.events) != tuple(range(1, len(self.events) + 1)): raise SupervisorShadowError("Complete supervisor lifecycle record is invalid")
        binding = self.plan_receipt.binding
        if any(receipt.binding != binding for receipt in (*(), self.terminal_receipt)) or any((event.record_identity, event.source_identity, event.observation_identity, event.candidate_sha, event.context_identity, event.plan_identity, event.capture_plan_digest) != (binding.record_identity, binding.source_identity, binding.observation_identity, binding.candidate_sha, binding.context_identity, binding.plan_identity, binding.capture_plan_digest) for event in self.events) or (self.expected_plan.context_identity, self.expected_plan.plan_identity, self.expected_plan.observation_identity, self.expected_plan.binding.candidate_sha, self.expected_plan.binding.capture_plan_digest) != (binding.context_identity, binding.plan_identity, binding.observation_identity, binding.candidate_sha, binding.capture_plan_digest) or (self.terminal.record_identity, self.terminal.source_identity, self.terminal.observation_identity, self.terminal.candidate_sha, self.terminal.context_identity, self.terminal.plan_identity, self.terminal.capture_plan_digest, self.terminal.attempt_count) != (binding.record_identity, binding.source_identity, binding.observation_identity, binding.candidate_sha, binding.context_identity, binding.plan_identity, binding.capture_plan_digest, len(self.events)):
            raise SupervisorShadowError("Complete supervisor lifecycle binding is invalid")
        receipts = (self.plan_receipt, *tuple(LifecycleChainReceipt(binding, event.content_digest, event.prior_digest, event.ordinal) for event in self.events), self.terminal_receipt)
        if tuple(receipt.ordinal for receipt in receipts) != tuple(range(len(receipts))) or any(receipt.prior_digest != previous.receipt_digest for previous, receipt in zip(receipts, receipts[1:])) or self.terminal.prior_digest != receipts[-2].receipt_digest:
            raise SupervisorShadowError("Complete supervisor lifecycle chain is invalid")
        accepted = tuple(event for event in self.events if event.result_kind == SupervisorResultKind.ACCEPTED.value)
        if (self.terminal.terminal == "accepted" and (len(accepted) != 1 or accepted[-1].ordinal != len(self.events) or self.terminal.accepted_result_identity != accepted[-1].result_identity)) or (self.terminal.terminal == "exhausted" and accepted):
            raise SupervisorShadowError("Complete supervisor lifecycle terminal is invalid")


class ExternalSupervisorLifecycle(Protocol):
    """Receipt-bound durable lifecycle protocol used by ordered qualification."""
    def prepare(self, plan: SupervisorExpectedLifecycle, *, freshness_until: int) -> LifecycleChainReceipt: ...
    def append(self, record_identity: str, event: SupervisorAttemptEvent, *, evidence_time: int) -> LifecycleChainReceipt: ...
    def finalize(self, record_identity: str, terminal: SupervisorTerminalRecord, *, evidence_time: int) -> LifecycleChainReceipt: ...
    def read_plan(self, record_identity: str, *, evidence_time: int) -> tuple[SupervisorExpectedLifecycle, LifecycleChainReceipt]: ...
    def read(self, record_identity: str, *, evidence_time: int) -> CompleteSupervisorLifecycleRecord: ...


class FileSupervisorLifecycle:
    """Append-only canonical disk lifecycle with authenticated restart read-back."""

    _PLAN_FILE = "plan.json"
    _RECEIPT_FILE = "plan-receipt.json"

    def __init__(self, root: str | Path, source_identity: str) -> None:
        if not _digest(source_identity) or not isinstance(root, (str, os.PathLike)):
            raise SupervisorShadowError("Supervisor file lifecycle source is invalid")
        candidate = Path(root)
        if candidate.is_symlink():
            raise SupervisorShadowError("Supervisor file lifecycle root is invalid")
        candidate.mkdir(parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        if candidate.is_symlink() or not resolved.is_dir():
            raise SupervisorShadowError("Supervisor file lifecycle root is invalid")
        self._root = resolved
        self._source_identity = source_identity

    @staticmethod
    def _material(value: object) -> str:
        return InMemorySupervisorLifecycle._material(value)

    @staticmethod
    def _receipt(material: object) -> LifecycleChainReceipt:
        return InMemorySupervisorLifecycle._receipt(material)

    @staticmethod
    def _plan(material: object) -> SupervisorExpectedLifecycle:
        return InMemorySupervisorLifecycle._plan(material)

    @staticmethod
    def _evidence_time(binding: SupervisorLifecycleChainBinding, evidence_time: int) -> None:
        InMemorySupervisorLifecycle._evidence_time(binding, evidence_time)

    def _binding(self, plan: SupervisorExpectedLifecycle, freshness_until: int) -> SupervisorLifecycleChainBinding:
        record_identity = _hash({"source_identity": self._source_identity, "plan_identity": plan.plan_identity, "observation_identity": plan.observation_identity, "candidate_sha": plan.binding.candidate_sha, "context_identity": plan.context_identity, "capture_plan_digest": plan.binding.capture_plan_digest})
        return SupervisorLifecycleChainBinding(record_identity, self._source_identity, plan.observation_identity, plan.binding.candidate_sha, plan.context_identity, plan.plan_identity, plan.binding.capture_plan_digest, plan.ready_at, freshness_until)

    def _record_dir(self, record_identity: str) -> Path:
        if not _digest(record_identity):
            raise SupervisorShadowError("Supervisor file lifecycle record is invalid")
        path = self._root / ("record-" + record_identity.removeprefix("sha256:"))
        try:
            path.resolve(strict=False).relative_to(self._root)
        except ValueError as error:
            raise SupervisorShadowError("Supervisor file lifecycle path escaped root") from error
        if path.exists() and path.is_symlink():
            raise SupervisorShadowError("Supervisor file lifecycle record is invalid")
        return path

    def _record_entries(self, record_identity: str) -> dict[str, Path]:
        directory = self._record_dir(record_identity)
        if not directory.exists() or directory.is_symlink() or not directory.is_dir():
            raise SupervisorShadowError("Supervisor file lifecycle plan is missing")
        entries = {item.name: item for item in directory.iterdir()}
        if any(item.is_symlink() or not item.is_file() for item in entries.values()):
            raise SupervisorShadowError("Supervisor file lifecycle record is incomplete")
        return entries

    def _chain(self, record_identity: str, *, evidence_time: int, require_terminal: bool) -> tuple[SupervisorExpectedLifecycle, LifecycleChainReceipt, tuple[SupervisorAttemptEvent, ...], tuple[LifecycleChainReceipt, ...], SupervisorTerminalRecord | None, LifecycleChainReceipt | None]:
        entries = self._record_entries(record_identity)
        names = {self._PLAN_FILE, self._RECEIPT_FILE, "terminal.json", "terminal-receipt.json"}
        if not {self._PLAN_FILE, self._RECEIPT_FILE} <= set(entries) or any(name not in names and not re.fullmatch(r"event-[0-9]{4}(?:-receipt)?\.json", name) for name in entries):
            raise SupervisorShadowError("Supervisor file lifecycle record is incomplete")
        plan = self._plan(self._read_canonical(entries[self._PLAN_FILE]))
        stored_plan = self._receipt(self._read_canonical(entries[self._RECEIPT_FILE]))
        binding = self._binding(plan, stored_plan.freshness_until)
        self._evidence_time(binding, evidence_time)
        plan_receipt = LifecycleChainReceipt(binding, _hash(plan.payload()), _hash({"genesis": binding.binding_digest}), 0)
        if binding.record_identity != record_identity or stored_plan != plan_receipt:
            raise SupervisorShadowError("Supervisor file lifecycle plan receipt was tampered")
        event_indexes = sorted(int(name[6:10]) for name in entries if re.fullmatch(r"event-[0-9]{4}\.json", name))
        if event_indexes != list(range(1, len(event_indexes) + 1)) or any(f"event-{ordinal:04d}-receipt.json" not in entries for ordinal in event_indexes):
            raise SupervisorShadowError("Supervisor file lifecycle event order is invalid")
        if any(re.fullmatch(r"event-[0-9]{4}-receipt\.json", name) and int(name[6:10]) not in event_indexes for name in entries):
            raise SupervisorShadowError("Supervisor file lifecycle event receipt is invalid")
        events: list[SupervisorAttemptEvent] = []; receipts: list[LifecycleChainReceipt] = []; previous = plan_receipt
        for ordinal in event_indexes:
            try:
                event = SupervisorAttemptEvent(**json.loads(self._read_canonical(entries[f"event-{ordinal:04d}.json"])))
            except (TypeError, ValueError) as error:
                raise SupervisorShadowError("Supervisor file lifecycle event material is invalid") from error
            expected = ordinal - 1
            if expected >= len(plan.binding.request_identities) or (event.record_identity, event.source_identity, event.observation_identity, event.candidate_sha, event.context_identity, event.plan_identity, event.capture_plan_digest, event.ordinal, event.prior_digest, event.request_identity, event.profile_identity, event.runtime_fingerprint, event.ready_at, event.freshness_until) != (binding.record_identity, binding.source_identity, binding.observation_identity, binding.candidate_sha, binding.context_identity, binding.plan_identity, binding.capture_plan_digest, ordinal, previous.receipt_digest, plan.binding.request_identities[expected], plan.binding.profile_identities[expected], plan.binding.runtime_fingerprints[expected], binding.ready_at, binding.freshness_until):
                raise SupervisorShadowError("Supervisor file lifecycle event binding is invalid")
            if events and events[-1].result_kind == SupervisorResultKind.ACCEPTED.value:
                raise SupervisorShadowError("Supervisor file lifecycle advance is invalid")
            receipt = LifecycleChainReceipt(binding, event.content_digest, event.prior_digest, ordinal)
            if self._receipt(self._read_canonical(entries[f"event-{ordinal:04d}-receipt.json"])) != receipt:
                raise SupervisorShadowError("Supervisor file lifecycle event receipt was tampered")
            events.append(event); receipts.append(receipt); previous = receipt
        terminal_names = {"terminal.json", "terminal-receipt.json"} & set(entries)
        if terminal_names not in (set(), {"terminal.json", "terminal-receipt.json"}) or (require_terminal and not terminal_names):
            raise SupervisorShadowError("Supervisor file lifecycle record is incomplete")
        if not terminal_names:
            return plan, plan_receipt, tuple(events), tuple(receipts), None, None
        try:
            terminal = SupervisorTerminalRecord(**json.loads(self._read_canonical(entries["terminal.json"])))
        except (TypeError, ValueError) as error:
            raise SupervisorShadowError("Supervisor file lifecycle terminal material is invalid") from error
        terminal_receipt = LifecycleChainReceipt(binding, _hash(terminal.__dict__), terminal.prior_digest, len(events) + 1)
        if terminal.prior_digest != previous.receipt_digest or self._receipt(self._read_canonical(entries["terminal-receipt.json"])) != terminal_receipt:
            raise SupervisorShadowError("Supervisor file lifecycle terminal receipt was tampered")
        return plan, plan_receipt, tuple(events), tuple(receipts), terminal, terminal_receipt

    @staticmethod
    def _read_canonical(path: Path) -> str:
        try:
            material = path.read_bytes().decode("utf-8")
            parsed = json.loads(material)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SupervisorShadowError("Supervisor file lifecycle material is invalid") from error
        if json.dumps(parsed, sort_keys=True, separators=(",", ":")) != material:
            raise SupervisorShadowError("Supervisor file lifecycle material is noncanonical")
        return material

    @staticmethod
    def _publish(path: Path, material: str) -> None:
        temporary = path.with_name(path.name + ".tmp")
        if path.parent.is_symlink() or path.exists() or temporary.exists():
            raise SupervisorShadowError("Supervisor file lifecycle collision")
        try:
            descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(material.encode("utf-8")); handle.flush(); os.fsync(handle.fileno())
            if path.exists():
                raise SupervisorShadowError("Supervisor file lifecycle collision")
            os.replace(temporary, path)
        except SupervisorShadowError:
            raise
        except OSError as error:
            raise SupervisorShadowError("Supervisor file lifecycle publication failed") from error

    def prepare(self, plan: SupervisorExpectedLifecycle, *, freshness_until: int) -> LifecycleChainReceipt:
        if type(plan) is not SupervisorExpectedLifecycle or type(freshness_until) is not int or freshness_until < plan.ready_at:
            raise SupervisorShadowError("Supervisor file lifecycle prepare is invalid")
        binding = self._binding(plan, freshness_until)
        directory = self._record_dir(binding.record_identity)
        try:
            directory.mkdir()
        except FileExistsError as error:
            raise SupervisorShadowError("Supervisor file lifecycle collision") from error
        except OSError as error:
            raise SupervisorShadowError("Supervisor file lifecycle publication failed") from error
        if directory.is_symlink():
            raise SupervisorShadowError("Supervisor file lifecycle record is invalid")
        receipt = LifecycleChainReceipt(binding, _hash(plan.payload()), _hash({"genesis": binding.binding_digest}), 0)
        self._publish(directory / self._PLAN_FILE, self._material(plan.payload()))
        self._publish(directory / self._RECEIPT_FILE, self._material(receipt.payload()))
        return receipt

    def read_plan(self, record_identity: str, *, evidence_time: int) -> tuple[SupervisorExpectedLifecycle, LifecycleChainReceipt]:
        plan, receipt, _events, _event_receipts, _terminal, _terminal_receipt = self._chain(record_identity, evidence_time=evidence_time, require_terminal=False)
        return plan, receipt

    def append(self, record_identity: str, event: SupervisorAttemptEvent, *, evidence_time: int) -> LifecycleChainReceipt:
        plan, plan_receipt, events, receipts, terminal, _terminal_receipt = self._chain(record_identity, evidence_time=evidence_time, require_terminal=False)
        if terminal is not None or type(event) is not SupervisorAttemptEvent or event.record_identity != record_identity:
            raise SupervisorShadowError("Supervisor file lifecycle append is invalid")
        expected = event.ordinal - 1
        if expected >= len(plan.binding.request_identities) or (event.source_identity, event.observation_identity, event.candidate_sha, event.context_identity, event.plan_identity, event.capture_plan_digest, event.request_identity, event.profile_identity, event.runtime_fingerprint, event.ready_at, event.freshness_until) != (plan_receipt.source_identity, plan_receipt.observation_identity, plan_receipt.candidate_sha, plan_receipt.context_identity, plan_receipt.plan_identity, plan_receipt.capture_plan_digest, plan.binding.request_identities[expected], plan.binding.profile_identities[expected], plan.binding.runtime_fingerprints[expected], plan_receipt.ready_at, plan_receipt.freshness_until):
            raise SupervisorShadowError("Supervisor file lifecycle append is invalid")
        previous = plan_receipt if not receipts else receipts[-1]
        if event.ordinal != len(events) + 1 or event.prior_digest != previous.receipt_digest or (events and events[-1].result_kind == SupervisorResultKind.ACCEPTED.value):
            raise SupervisorShadowError("Supervisor file lifecycle append is invalid")
        receipt = LifecycleChainReceipt(plan_receipt.binding, event.content_digest, event.prior_digest, event.ordinal)
        directory = self._record_dir(record_identity)
        self._publish(directory / f"event-{event.ordinal:04d}.json", self._material(event.payload()))
        self._publish(directory / f"event-{event.ordinal:04d}-receipt.json", self._material(receipt.payload()))
        return receipt

    def finalize(self, record_identity: str, terminal: SupervisorTerminalRecord, *, evidence_time: int) -> LifecycleChainReceipt:
        plan, plan_receipt, events, receipts, existing, _terminal_receipt = self._chain(record_identity, evidence_time=evidence_time, require_terminal=False)
        if existing is not None or not events or type(terminal) is not SupervisorTerminalRecord or terminal.record_identity != record_identity or terminal.prior_digest != receipts[-1].receipt_digest or terminal.attempt_count != len(events):
            raise SupervisorShadowError("Supervisor file lifecycle finalize is invalid")
        if (terminal.source_identity, terminal.observation_identity, terminal.candidate_sha, terminal.context_identity, terminal.plan_identity, terminal.capture_plan_digest, terminal.ready_at) != (plan_receipt.source_identity, plan_receipt.observation_identity, plan_receipt.candidate_sha, plan_receipt.context_identity, plan_receipt.plan_identity, plan_receipt.capture_plan_digest, plan_receipt.ready_at):
            raise SupervisorShadowError("Supervisor file lifecycle finalize is invalid")
        accepted = tuple(item for item in events if item.result_kind == SupervisorResultKind.ACCEPTED.value)
        if (terminal.terminal == "accepted" and (len(accepted) != 1 or accepted[-1].ordinal != len(events) or terminal.accepted_result_identity != accepted[-1].result_identity)) or (terminal.terminal == "exhausted" and accepted):
            raise SupervisorShadowError("Supervisor file lifecycle finalize is invalid")
        receipt = LifecycleChainReceipt(plan_receipt.binding, _hash(terminal.__dict__), terminal.prior_digest, len(events) + 1)
        directory = self._record_dir(record_identity)
        self._publish(directory / "terminal.json", self._material(terminal.__dict__))
        self._publish(directory / "terminal-receipt.json", self._material(receipt.payload()))
        return receipt

    def read(self, record_identity: str, *, evidence_time: int) -> CompleteSupervisorLifecycleRecord:
        plan, plan_receipt, events, _receipts, terminal, terminal_receipt = self._chain(record_identity, evidence_time=evidence_time, require_terminal=True)
        if terminal is None or terminal_receipt is None:
            raise SupervisorShadowError("Supervisor file lifecycle record is incomplete")
        return CompleteSupervisorLifecycleRecord(plan, plan_receipt, events, terminal, terminal_receipt)


class InMemorySupervisorLifecycle:
    """Provider-free append-only canonical lifecycle chain for qualification tests."""
    def __init__(self, source_identity: str) -> None:
        if not _digest(source_identity): raise SupervisorShadowError("Supervisor lifecycle source is invalid")
        self._source_identity = source_identity; self._records: dict[str, dict[str, object]] = {}
    @staticmethod
    def _evidence_time(binding: SupervisorLifecycleChainBinding, evidence_time: int) -> None:
        if type(evidence_time) is not int or not binding.ready_at <= evidence_time <= binding.freshness_until: raise SupervisorShadowError("Supervisor lifecycle evidence time is invalid")
    @staticmethod
    def _material(value: object) -> str: return json.dumps(value, sort_keys=True, separators=(",", ":"))
    @staticmethod
    def _receipt(material: object) -> LifecycleChainReceipt:
        if type(material) is not str: raise SupervisorShadowError("Supervisor lifecycle receipt material is invalid")
        try:
            payload = json.loads(material); binding = SupervisorLifecycleChainBinding(**payload["binding"])
            return LifecycleChainReceipt(binding, payload["content_digest"], payload["prior_digest"], payload["ordinal"])
        except (KeyError, TypeError, ValueError) as error: raise SupervisorShadowError("Supervisor lifecycle receipt material is invalid") from error
    @staticmethod
    def _plan(material: object) -> SupervisorExpectedLifecycle:
        if type(material) is not str: raise SupervisorShadowError("Supervisor lifecycle plan material is invalid")
        try:
            payload = json.loads(material); raw_binding = payload["binding"]
            binding = SupervisorSequenceBinding(raw_binding["case_id"], raw_binding["candidate_sha"], raw_binding["base_sha"], raw_binding["task_id"], tuple(raw_binding["request_identities"]), tuple(raw_binding["profile_identities"]), tuple(raw_binding["runtime_fingerprints"]), raw_binding["review_epoch"], raw_binding["review_round"], raw_binding["review_mode"], raw_binding["capture_plan_digest"])
            return SupervisorExpectedLifecycle(binding, payload["policy_digest"], payload["configuration_digest"], payload["runtime_identity"], payload["ready_at"], payload["observation_identity"])
        except (KeyError, TypeError, ValueError) as error: raise SupervisorShadowError("Supervisor lifecycle plan material is invalid") from error
    def _binding(self, plan: SupervisorExpectedLifecycle, freshness_until: int) -> SupervisorLifecycleChainBinding:
        record_identity = _hash({"source_identity": self._source_identity, "plan_identity": plan.plan_identity, "observation_identity": plan.observation_identity, "candidate_sha": plan.binding.candidate_sha, "context_identity": plan.context_identity, "capture_plan_digest": plan.binding.capture_plan_digest})
        return SupervisorLifecycleChainBinding(record_identity, self._source_identity, plan.observation_identity, plan.binding.candidate_sha, plan.context_identity, plan.plan_identity, plan.binding.capture_plan_digest, plan.ready_at, freshness_until)
    def prepare(self, plan: SupervisorExpectedLifecycle, *, freshness_until: int) -> LifecycleChainReceipt:
        if type(plan) is not SupervisorExpectedLifecycle or type(freshness_until) is not int or freshness_until < plan.ready_at: raise SupervisorShadowError("Supervisor lifecycle prepare is invalid")
        record_identity = self._binding(plan, freshness_until).record_identity
        if record_identity in self._records: raise SupervisorShadowError("Supervisor lifecycle prepare is invalid")
        binding = self._binding(plan, freshness_until)
        content = _hash(plan.payload()); receipt = LifecycleChainReceipt(binding, content, _hash({"genesis": binding.binding_digest}), 0)
        self._records[record_identity] = {"plan": self._material(plan.payload()), "receipt": self._material(receipt.payload()), "events": [], "terminal": None}
        return receipt
    def read_plan(self, record_identity: str, *, evidence_time: int) -> tuple[SupervisorExpectedLifecycle, LifecycleChainReceipt]:
        record = self._records.get(record_identity)
        if record is None: raise SupervisorShadowError("Supervisor lifecycle plan is missing")
        plan = self._plan(record["plan"]); stored_receipt = self._receipt(record["receipt"])
        binding = self._binding(plan, stored_receipt.freshness_until); self._evidence_time(binding, evidence_time)
        receipt = LifecycleChainReceipt(binding, _hash(plan.payload()), _hash({"genesis": binding.binding_digest}), 0)
        if stored_receipt != receipt or binding.record_identity != record_identity: raise SupervisorShadowError("Supervisor lifecycle plan receipt was tampered")
        return plan, receipt
    def append(self, record_identity: str, event: SupervisorAttemptEvent, *, evidence_time: int) -> LifecycleChainReceipt:
        record = self._records.get(record_identity)
        if record is None or record["terminal"] is not None or type(event) is not SupervisorAttemptEvent or event.record_identity != record_identity: raise SupervisorShadowError("Supervisor lifecycle append is invalid")
        receipt = self._receipt(record["receipt"])
        self._evidence_time(receipt.binding, evidence_time)
        plan = self._plan(record["plan"]); binding = plan.binding.__dict__.copy()
        expected_ordinal = event.ordinal - 1
        if expected_ordinal >= len(binding["request_identities"]) or (event.source_identity, event.observation_identity, event.candidate_sha, event.context_identity, event.plan_identity, event.capture_plan_digest, event.request_identity, event.profile_identity, event.runtime_fingerprint, event.ready_at, event.freshness_until) != (receipt.source_identity, receipt.observation_identity, receipt.candidate_sha, receipt.context_identity, receipt.plan_identity, receipt.capture_plan_digest, binding["request_identities"][expected_ordinal], binding["profile_identities"][expected_ordinal], binding["runtime_fingerprints"][expected_ordinal], receipt.ready_at, receipt.freshness_until): raise SupervisorShadowError("Supervisor lifecycle append is invalid")
        events = record["events"]
        assert type(events) is list
        prior = receipt if not events else self._receipt(events[-1][1])
        if event.ordinal != len(events) + 1 or event.prior_digest != prior.receipt_digest: raise SupervisorShadowError("Supervisor lifecycle append is invalid")
        event_receipt = LifecycleChainReceipt(receipt.binding, event.content_digest, event.prior_digest, event.ordinal)
        events.append((self._material(event.payload()), self._material(event_receipt.payload()))); return event_receipt
    def finalize(self, record_identity: str, terminal: SupervisorTerminalRecord, *, evidence_time: int) -> LifecycleChainReceipt:
        record = self._records.get(record_identity); events = None if record is None else record["events"]
        plan_receipt = None if record is None else self._receipt(record["receipt"])
        if record is None or record["terminal"] is not None or type(events) is not list or not events or type(terminal) is not SupervisorTerminalRecord or terminal.record_identity != record_identity or terminal.prior_digest != self._receipt(events[-1][1]).receipt_digest or terminal.source_identity != plan_receipt.source_identity or terminal.attempt_count != len(events): raise SupervisorShadowError("Supervisor lifecycle finalize is invalid")
        self._evidence_time(plan_receipt.binding, evidence_time)
        if (terminal.observation_identity, terminal.candidate_sha, terminal.context_identity, terminal.plan_identity, terminal.capture_plan_digest, terminal.ready_at) != (plan_receipt.observation_identity, plan_receipt.candidate_sha, plan_receipt.context_identity, plan_receipt.plan_identity, plan_receipt.capture_plan_digest, plan_receipt.ready_at): raise SupervisorShadowError("Supervisor lifecycle finalize is invalid")
        accepted = tuple(event for material, _receipt in events for event in (SupervisorAttemptEvent(**json.loads(material)),) if event.result_kind == SupervisorResultKind.ACCEPTED.value)
        if (terminal.terminal == "accepted" and (len(accepted) != 1 or accepted[-1].ordinal != len(events) or terminal.accepted_result_identity != accepted[-1].result_identity)) or (terminal.terminal == "exhausted" and accepted): raise SupervisorShadowError("Supervisor lifecycle finalize is invalid")
        terminal_receipt = LifecycleChainReceipt(plan_receipt.binding, _hash(terminal.__dict__), terminal.prior_digest, len(events) + 1); record["terminal"] = (self._material(terminal.__dict__), self._material(terminal_receipt.payload())); return terminal_receipt
    def read_chain(self, record_identity: str, *, evidence_time: int) -> tuple[SupervisorExpectedLifecycle, LifecycleChainReceipt, tuple[SupervisorAttemptEvent, ...], SupervisorTerminalRecord, LifecycleChainReceipt]:
        record = self._records.get(record_identity)
        if record is None or record["terminal"] is None: raise SupervisorShadowError("Supervisor lifecycle read is incomplete")
        plan, plan_receipt = self.read_plan(record_identity, evidence_time=evidence_time); binding = plan_receipt.binding
        events = record["events"]; terminal = record["terminal"]
        if type(events) is not list or type(terminal) is not tuple or len(terminal) != 2: raise SupervisorShadowError("Supervisor lifecycle read is invalid")
        rebuilt: list[SupervisorAttemptEvent] = []; previous = plan_receipt
        for ordinal, entry in enumerate(events, start=1):
            if type(entry) is not tuple or len(entry) != 2: raise SupervisorShadowError("Supervisor lifecycle read is invalid")
            try: event = SupervisorAttemptEvent(**json.loads(entry[0]))
            except (TypeError, ValueError) as error: raise SupervisorShadowError("Supervisor lifecycle event material is invalid") from error
            expected = ordinal - 1
            if expected >= len(plan.binding.request_identities) or (event.record_identity, event.source_identity, event.observation_identity, event.candidate_sha, event.context_identity, event.plan_identity, event.capture_plan_digest, event.ordinal, event.prior_digest, event.request_identity, event.profile_identity, event.runtime_fingerprint, event.ready_at, event.freshness_until) != (binding.record_identity, binding.source_identity, binding.observation_identity, binding.candidate_sha, binding.context_identity, binding.plan_identity, binding.capture_plan_digest, ordinal, previous.receipt_digest, plan.binding.request_identities[expected], plan.binding.profile_identities[expected], plan.binding.runtime_fingerprints[expected], binding.ready_at, binding.freshness_until): raise SupervisorShadowError("Supervisor lifecycle event binding is invalid")
            if rebuilt and rebuilt[-1].result_kind == SupervisorResultKind.ACCEPTED.value: raise SupervisorShadowError("Supervisor lifecycle advance is invalid")
            receipt = LifecycleChainReceipt(binding, event.content_digest, event.prior_digest, ordinal)
            if self._receipt(entry[1]) != receipt: raise SupervisorShadowError("Supervisor lifecycle event receipt was tampered")
            rebuilt.append(event); previous = receipt
        try: final = SupervisorTerminalRecord(**json.loads(terminal[0]))
        except (TypeError, ValueError) as error: raise SupervisorShadowError("Supervisor lifecycle terminal material is invalid") from error
        terminal_receipt = LifecycleChainReceipt(binding, _hash(final.__dict__), final.prior_digest, len(rebuilt) + 1)
        if final.prior_digest != previous.receipt_digest or self._receipt(terminal[1]) != terminal_receipt: raise SupervisorShadowError("Supervisor lifecycle terminal receipt was tampered")
        return plan, plan_receipt, tuple(rebuilt), final, terminal_receipt
    def read(self, record_identity: str, *, evidence_time: int) -> CompleteSupervisorLifecycleRecord:
        plan, plan_receipt, events, terminal, terminal_receipt = self.read_chain(record_identity, evidence_time=evidence_time)
        return CompleteSupervisorLifecycleRecord(plan, plan_receipt, events, terminal, terminal_receipt)


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


def _durable_sequence_envelope(record: CompleteSupervisorLifecycleRecord) -> SupervisorSequenceEnvelope:
    plan = record.expected_plan; binding = plan.binding
    attempts = tuple(SupervisorSequenceAttempt(event.ordinal, event.profile_identity, event.request_identity, event.result_kind, event.result_identity, event.verdict) for event in record.events)
    if record.terminal.terminal == "accepted":
        accepted = attempts[-1]
        return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.ACCEPTED, attempts, accepted.ordinal, record.terminal.accepted_result_identity, accepted.verdict, None, "apply-bound-review-result")
    return SupervisorSequenceEnvelope(binding.task_id, binding.base_sha, binding.candidate_sha, binding.request_identities, binding.profile_identities, binding.runtime_fingerprints, binding.review_epoch, binding.review_round, binding.review_mode, binding.capture_plan_digest, SupervisorSequenceTerminal.EXHAUSTED, attempts, None, None, None, "attempt-budget-exhausted", "retain-terminal-product-block")


def qualify_supervisor_sequence(adapters: tuple[CodexSupervisorAdapter, ...], requests: tuple[CodexSupervisorRequest, ...], readiness: SupervisorShadowReadiness, binding: SupervisorSequenceBinding, resolved_policy: ResolvedSupervisorSequencePolicy, lifecycle: ExternalSupervisorLifecycle, recorder: ExternalSupervisorRecorder, *, evidence_time: int, freshness_until: int, runtime_store: ExternalSupervisorRuntimeStore, trusted_policy_receipt: TrustedReviewPolicyReceipt, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> SupervisorSequenceQualificationResult:
    """Capture exactly one terminal product failover sequence under one plan."""
    if type(adapters) is not tuple or type(requests) is not tuple or not adapters or len(adapters) != len(requests) or any(type(item) is not CodexSupervisorAdapter for item in adapters) or any(type(item) is not CodexSupervisorRequest for item in requests) or type(readiness) is not SupervisorShadowReadiness or type(binding) is not SupervisorSequenceBinding or type(resolved_policy) is not ResolvedSupervisorSequencePolicy or not all(callable(getattr(lifecycle, name, None)) for name in ("prepare", "append", "finalize", "read_plan", "read")) or not callable(getattr(recorder, "prepare", None)) or not callable(getattr(recorder, "seal", None)) or not callable(getattr(recorder, "verify", None)) or not callable(checkpoint_session) or not callable(checkpoint_turn) or type(evidence_time) is not int or type(freshness_until) is not int or freshness_until < evidence_time:
        raise SupervisorShadowError("Supervisor sequence pre-dispatch binding is invalid")
    context = requests[0].context
    if any(request.context != context or request.within_round_attempt != ordinal for ordinal, request in enumerate(requests, start=1)) or (context.task_id, context.base_sha, context.candidate_sha, context.review_epoch, context.review_round, context.review_mode.value) != (binding.task_id, binding.base_sha, binding.candidate_sha, binding.review_epoch, binding.review_round, binding.review_mode) or tuple(request.input_digest for request in requests) != binding.request_identities or tuple(request.selected_profile_identity for request in requests) != binding.profile_identities or tuple(adapter.profile_identity for adapter in adapters) != binding.profile_identities or tuple(adapter.runtime_fingerprint for adapter in adapters) != binding.runtime_fingerprints or (context.policy_digest, context.configuration_digest, binding.profile_identities, len(requests), context.review_mode) != (resolved_policy.policy_digest, resolved_policy.configuration_digest, resolved_policy.profile_identities, resolved_policy.policy.max_supervisor_attempts_per_round, resolved_policy.policy.mode_for_round(context.review_round)) or (readiness.candidate_sha, readiness.case_id, readiness.capture_plan_digest, readiness.observation_identity) != (binding.candidate_sha, binding.case_id, binding.capture_plan_digest, supervisor_sequence_observation_identity(requests)):
        raise SupervisorShadowError("Supervisor sequence context has drifted")
    if not callable(getattr(runtime_store, "persist", None)) or not callable(getattr(runtime_store, "read", None)):
        raise SupervisorShadowError("Supervisor runtime preflight is invalid")
    try:
        if type(trusted_policy_receipt) is not TrustedReviewPolicyReceipt or (trusted_policy_receipt.source_identity, trusted_policy_receipt.authority_identity) != (readiness.producer_identity, readiness.exporter_identity) or not trusted_policy_receipt.ready_at <= evidence_time <= trusted_policy_receipt.freshness_until or (trusted_policy_receipt.candidate_sha, trusted_policy_receipt.configuration_digest, trusted_policy_receipt.policy_digest, trusted_policy_receipt.supervisor_profile_identities, trusted_policy_receipt.complete_rounds, trusted_policy_receipt.max_rounds, trusted_policy_receipt.attempt_budget, trusted_policy_receipt.on_final_findings) != (binding.candidate_sha, resolved_policy.configuration_digest, resolved_policy.policy_digest, resolved_policy.profile_identities, resolved_policy.policy.complete_rounds, resolved_policy.policy.max_rounds, resolved_policy.policy.max_supervisor_attempts_per_round, resolved_policy.policy.on_final_findings.value):
            raise SupervisorShadowError("Trusted review policy receipt is invalid")
        material = json.dumps(trusted_policy_receipt.payload(), sort_keys=True, separators=(",", ":"))
        if TrustedReviewPolicyReceipt.from_canonical(material) != trusted_policy_receipt:
            raise SupervisorShadowError("Trusted review policy receipt drifted")
        context_identity = _hash({"task_id": binding.task_id, "base_sha": binding.base_sha, "candidate_sha": binding.candidate_sha, "requests": binding.request_identities, "profiles": binding.profile_identities, "runtime": binding.runtime_fingerprints, "epoch": binding.review_epoch, "round": binding.review_round, "mode": binding.review_mode, "capture_plan": binding.capture_plan_digest})
        if getattr(runtime_store, "source_identity", None) != readiness.comparator_identity:
            raise SupervisorShadowError("Supervisor runtime source pin is invalid")
        runtime_receipt = runtime_store.persist(resolved_policy.runtime, candidate_sha=binding.candidate_sha, context_identity=context_identity, ready_at=readiness.ready_at, freshness_until=freshness_until)
        if type(runtime_receipt) is not SupervisorRuntimeBindingReceipt or runtime_receipt.source_identity != readiness.comparator_identity or (runtime_receipt.candidate_sha, runtime_receipt.context_identity, runtime_receipt.resolved_configuration_digest, runtime_receipt.ready_at, runtime_receipt.freshness_until) != (binding.candidate_sha, context_identity, resolved_policy.configuration_digest, readiness.ready_at, freshness_until):
            raise SupervisorShadowError("Supervisor runtime receipt is invalid")
        runtime = runtime_store.read(runtime_receipt, evidence_time=evidence_time)
        if type(runtime) is not RuntimeBinding or runtime is resolved_policy.runtime:
            raise SupervisorShadowError("Supervisor runtime read-back is invalid")
        material_digest = "sha256:" + hashlib.sha256(runtime.canonical_material().encode()).hexdigest()
        expected_record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": runtime_receipt.source_identity, "candidate_sha": binding.candidate_sha, "context_identity": context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": material_digest, "canonical_material_digest": material_digest, "ready_at": readiness.ready_at, "freshness_until": freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (runtime_receipt.record_identity, runtime_receipt.runtime_content_digest, runtime_receipt.canonical_material_digest) != (expected_record, material_digest, material_digest):
            raise SupervisorShadowError("Supervisor runtime receipt drifted")
        reconstructed_policy = ResolvedSupervisorSequencePolicy(resolved_policy.configuration, runtime)
    except Exception as error:
        raise SupervisorShadowError("Supervisor runtime preflight failed") from error
    if reconstructed_policy != resolved_policy:
        raise SupervisorShadowError("Supervisor runtime preflight drifted")
    resolved_policy = reconstructed_policy
    expected_plan = SupervisorExpectedLifecycle(binding, resolved_policy.policy_digest, resolved_policy.configuration_digest, _hash(resolved_policy.runtime.complete_columns()), readiness.ready_at, readiness.observation_identity)
    try:
        expected_receipt = lifecycle.prepare(expected_plan, freshness_until=freshness_until)
        expected_readback, authenticated_receipt = lifecycle.read_plan(expected_receipt.record_identity, evidence_time=evidence_time)
    except Exception as error:
        raise SupervisorShadowError("Supervisor expected lifecycle pre-dispatch read-back failed") from error
    if expected_readback != expected_plan or authenticated_receipt != expected_receipt or (expected_receipt.candidate_sha, expected_receipt.capture_plan_digest, expected_receipt.observation_identity, expected_receipt.ready_at) != (binding.candidate_sha, binding.capture_plan_digest, readiness.observation_identity, readiness.ready_at):
        raise SupervisorShadowError("Supervisor expected lifecycle pre-dispatch drifted")
    try:
        prepared = recorder.prepare(readiness.capture_plan(), store_identity=readiness.store_identity)
    except Exception as error:
        raise SupervisorShadowError("Supervisor sequence Recorder pre-dispatch readiness is invalid") from error
    if (prepared.plan_digest, prepared.profile, prepared.case_id, prepared.candidate_sha, prepared.ready_at) != (readiness.capture_plan_digest, SUPERVISOR_FAILOVER_PROFILE, readiness.case_id, readiness.candidate_sha, readiness.ready_at):
        raise SupervisorShadowError("Supervisor sequence capture-plan receipt drifted")
    observed_attempts: list[SupervisorSequenceAttempt] = []; prior = expected_receipt
    def checkpoint_result(ordinal: int, request: CodexSupervisorRequest, result: CodexSupervisorResult) -> None:
        nonlocal prior
        observed = _sequence_attempt(ordinal, request, result); observed_attempts.append(observed)
        event = SupervisorAttemptEvent(expected_receipt.record_identity, expected_receipt.source_identity, expected_receipt.observation_identity, expected_receipt.candidate_sha, expected_receipt.context_identity, expected_receipt.plan_identity, expected_receipt.capture_plan_digest, ordinal, prior.receipt_digest, request.input_digest, request.selected_profile_identity, adapters[ordinal - 1].runtime_fingerprint, result.kind.value, observed.result_identity, observed.result_identity if result.kind is SupervisorResultKind.ACCEPTED else None, observed.verdict, expected_receipt.ready_at, expected_receipt.freshness_until)
        try: prior = lifecycle.append(expected_receipt.record_identity, event, evidence_time=evidence_time)
        except Exception as error: raise SupervisorShadowError("Supervisor durable lifecycle append failed") from error
    failover = dispatch_ordered_supervisor_attempts(requests, adapters, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn, checkpoint_result=checkpoint_result)
    attempts = tuple(observed_attempts)
    try:
        accepted = failover.result is not None
        terminal = SupervisorTerminalRecord(expected_receipt.record_identity, expected_receipt.source_identity, expected_receipt.observation_identity, expected_receipt.candidate_sha, expected_receipt.context_identity, expected_receipt.plan_identity, expected_receipt.capture_plan_digest, prior.receipt_digest, len(attempts), "accepted" if accepted else "exhausted", attempts[-1].result_identity if accepted else None, None if accepted else "attempt-budget-exhausted", "apply-bound-review-result" if accepted else "retain-terminal-product-block", expected_receipt.ready_at)
        lifecycle.finalize(expected_receipt.record_identity, terminal, evidence_time=evidence_time)
        durable_record = lifecycle.read(expected_receipt.record_identity, evidence_time=evidence_time)
    except Exception as error:
        raise SupervisorShadowError("Supervisor durable lifecycle read-back failed") from error
    expected = _durable_sequence_envelope(durable_record)
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
