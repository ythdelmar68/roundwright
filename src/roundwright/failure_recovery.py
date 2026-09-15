"""Closed, provider-neutral failure decisions for future effect entrypoints.

This boundary deliberately consumes typed observations, never provider display
text.  It is shared by Worker, Supervisor and dependency-review callers before
they select a retry or fallback.  It does not activate any provider.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from enum import StrEnum


class FailureRecoveryError(ValueError):
    """A failure decision or its clearance is malformed or unsafe."""


class FailureRole(StrEnum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    DEPENDENCY_REVIEW = "dependency-review"


class FailureClass(StrEnum):
    PARTIAL_INCREMENT = "partial-increment"
    ORDINARY_REVIEW_HANDOFF = "ordinary-review-handoff"
    VALIDATION_RUNNING = "validation-running"
    NO_PROGRESS = "no-progress"
    SESSION_TERMINATED = "session-terminated"
    MISSING_OUTPUT = "missing-output"
    TOPOLOGY_VIOLATION = "topology-violation"
    HOST_SECURITY_DENIAL = "host-security-denial"
    TRANSIENT_SERVICE = "transient-service"
    CREDENTIAL_FAILURE = "credential-failure"
    BUDGET_EXHAUSTED = "budget-exhausted"
    AMBIGUOUS_EFFECT = "ambiguous-effect"
    UNKNOWN = "unknown"


class EvidenceSource(StrEnum):
    VERIFIED_OUTPUT = "verified-output"
    VERIFIED_HOST = "verified-host"
    VERIFIED_LIFECYCLE = "verified-lifecycle"
    VERIFIED_TOPOLOGY = "verified-topology"
    VERIFIED_SERVICE = "verified-service"
    MODEL_SELF_REPORT = "model-self-report"
    UNAVAILABLE = "unavailable"


class EvidenceConfidence(StrEnum):
    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class FailureEvidence:
    """Closed provenance: prose is never an authority-bearing observation."""

    source: EvidenceSource
    confidence: EvidenceConfidence

    def __post_init__(self) -> None:
        if type(self.source) is not EvidenceSource or type(self.confidence) is not EvidenceConfidence:
            raise FailureRecoveryError("failure evidence is invalid")
        if self.source in {EvidenceSource.MODEL_SELF_REPORT, EvidenceSource.UNAVAILABLE} and self.confidence is not EvidenceConfidence.UNAVAILABLE:
            raise FailureRecoveryError("untrusted evidence cannot be verified")


class RecoveryAction(StrEnum):
    CONTINUE_SAME_SESSION = "continue-same-session"
    RECONCILE = "reconcile"
    STOP_SCOPE = "stop-scope"
    PREBOUND_FALLBACK = "prebound-fallback"


@dataclass(frozen=True)
class FailureBinding:
    """Immutable identity shared with the #136 role-admission receipt."""

    candidate_sha: str
    policy_digest: str
    configuration_digest: str
    authority_scope: str
    role: FailureRole
    profile_identity: str
    session_identity: str
    attempt_identity: str

    def __post_init__(self) -> None:
        if (not all(isinstance(value, str) and value for value in self.__dict__.values())
                or len(self.candidate_sha) != 40
                or not all(character in "0123456789abcdef" for character in self.candidate_sha)):
            raise FailureRecoveryError("failure binding is invalid")


@dataclass(frozen=True)
class FailureRecord:
    """Versioned public-safe decision; prose is intentionally not retained."""

    binding: FailureBinding
    failure: FailureClass
    evidence: EvidenceSource
    retryable: bool
    action: RecoveryAction
    clearance_required: bool

    def __post_init__(self) -> None:
        if type(self.binding) is not FailureBinding or type(self.failure) is not FailureClass or type(self.evidence) is not EvidenceSource or type(self.retryable) is not bool or type(self.action) is not RecoveryAction or type(self.clearance_required) is not bool:
            raise FailureRecoveryError("failure record is invalid")
        if self.failure is FailureClass.HOST_SECURITY_DENIAL and (self.retryable or self.action is not RecoveryAction.STOP_SCOPE or not self.clearance_required):
            raise FailureRecoveryError("security denial must stop its scope")
        if self.failure in {FailureClass.UNKNOWN, FailureClass.MISSING_OUTPUT, FailureClass.AMBIGUOUS_EFFECT} and (self.retryable or self.action is not RecoveryAction.RECONCILE):
            raise FailureRecoveryError("unverified outcome must reconcile")

    @property
    def digest(self) -> str:
        material = {"schema": "roundwright-failure-recovery/v1", "binding": self.binding.__dict__, "failure": self.failure.value, "evidence": self.evidence.value, "retryable": self.retryable, "action": self.action.value, "clearance_required": self.clearance_required}
        return "sha256:" + hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Clearance:
    """A later durable host decision; it cannot erase the original denial."""

    record_digest: str
    binding: FailureBinding
    evidence: EvidenceSource

    def __post_init__(self) -> None:
        if not self.record_digest.startswith("sha256:") or len(self.record_digest) != 71 or type(self.binding) is not FailureBinding or self.evidence is not EvidenceSource.VERIFIED_HOST:
            raise FailureRecoveryError("clearance is invalid")


@dataclass(frozen=True)
class RecoveryRouteAdmission:
    """Product-issued, exact route identity; callers cannot assert equivalence."""

    binding: FailureBinding
    capability_digest: str
    target_identity: str

    def __post_init__(self) -> None:
        if type(self.binding) is not FailureBinding or not self.capability_digest.startswith("sha256:") or len(self.capability_digest) != 71 or not isinstance(self.target_identity, str) or not self.target_identity:
            raise FailureRecoveryError("recovery route admission is invalid")


@dataclass(frozen=True)
class RecoveryAdvice:
    """A digest-only recommendation for #140; it cannot authorize an effect."""

    record_digest: str
    recommendation_digest: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 for value in (self.record_digest, self.recommendation_digest)):
            raise FailureRecoveryError("recovery advice is invalid")


def _payload(record: FailureRecord) -> dict[str, object]:
    return {"schema": "roundwright-failure-recovery/v1", "binding": {**record.binding.__dict__, "role": record.binding.role.value}, "failure": record.failure.value, "evidence": record.evidence.value, "retryable": record.retryable, "action": record.action.value, "clearance_required": record.clearance_required}


def record_durable_failure(repository, identity, record: FailureRecord, *, now: int | None = None, connection=None) -> str:
    """Append an idempotent public-safe failure record to the product ledger."""
    from .state import _open_writable_connection, _require_matching_task
    if type(record) is not FailureRecord:
        raise FailureRecoveryError("failure record binding is unavailable")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0:
        raise FailureRecoveryError("failure record time is invalid")
    encoded = json.dumps(_payload(record), sort_keys=True, separators=(",", ":"))
    owned_connection = connection is None
    connection = _open_writable_connection(repository) if owned_connection else connection
    try:
        _require_matching_task(connection, identity)
        current = connection.execute("SELECT task_id, record_json FROM failure_recovery_records WHERE record_digest=?", (record.digest,)).fetchone()
        expected = (identity.task_id, encoded)
        if current is None:
            connection.execute("INSERT INTO failure_recovery_records(record_digest, task_id, record_json, recorded_at) VALUES (?, ?, ?, ?)", (record.digest, *expected, observed))
        elif current != expected:
            raise FailureRecoveryError("durable failure record conflicts")
        if owned_connection:
            connection.commit()
    except Exception:
        if owned_connection:
            connection.rollback()
        raise
    finally:
        if owned_connection:
            connection.close()
    return record.digest


def read_durable_failure(repository, identity, record_digest: str) -> dict[str, object]:
    """Return the closed record only when it remains task-bound and canonical."""
    from .state import _open_writable_connection, _require_matching_task
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute("SELECT record_json FROM failure_recovery_records WHERE record_digest=? AND task_id=?", (record_digest, identity.task_id)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise FailureRecoveryError("durable failure record is unavailable")
    try:
        payload = json.loads(row[0])
    except (TypeError, json.JSONDecodeError) as error:
        raise FailureRecoveryError("durable failure record is malformed") from error
    if type(payload) is not dict or payload.get("schema") != "roundwright-failure-recovery/v1":
        raise FailureRecoveryError("durable failure record is malformed")
    return payload


def classify(binding: FailureBinding, failure: FailureClass, evidence: EvidenceSource | FailureEvidence) -> FailureRecord:
    """Map one typed observation to the only permitted recovery action."""
    if type(evidence) is FailureEvidence:
        evidence = evidence.source if evidence.confidence is EvidenceConfidence.VERIFIED else EvidenceSource.UNAVAILABLE
    if type(binding) is not FailureBinding or type(failure) is not FailureClass or type(evidence) is not EvidenceSource:
        raise FailureRecoveryError("failure classification inputs are invalid")
    # Provider prose and unavailable telemetry never establish capacity, death,
    # denial, or an eligible retry.
    if evidence in {EvidenceSource.MODEL_SELF_REPORT, EvidenceSource.UNAVAILABLE}:
        failure = FailureClass.UNKNOWN
    if failure is FailureClass.HOST_SECURITY_DENIAL:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.STOP_SCOPE, True)
    if failure in {FailureClass.UNKNOWN, FailureClass.MISSING_OUTPUT, FailureClass.AMBIGUOUS_EFFECT, FailureClass.TOPOLOGY_VIOLATION, FailureClass.CREDENTIAL_FAILURE, FailureClass.BUDGET_EXHAUSTED}:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.RECONCILE, failure in {FailureClass.CREDENTIAL_FAILURE, FailureClass.BUDGET_EXHAUSTED})
    if failure in {FailureClass.PARTIAL_INCREMENT, FailureClass.ORDINARY_REVIEW_HANDOFF, FailureClass.VALIDATION_RUNNING, FailureClass.NO_PROGRESS}:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.CONTINUE_SAME_SESSION, False)
    if failure is FailureClass.SESSION_TERMINATED:
        if evidence is not EvidenceSource.VERIFIED_LIFECYCLE:
            return FailureRecord(binding, FailureClass.UNKNOWN, evidence, False, RecoveryAction.RECONCILE, False)
        return FailureRecord(binding, failure, evidence, True, RecoveryAction.PREBOUND_FALLBACK, False)
    if failure is FailureClass.TRANSIENT_SERVICE and evidence is EvidenceSource.VERIFIED_SERVICE:
        return FailureRecord(binding, failure, evidence, True, RecoveryAction.PREBOUND_FALLBACK, False)
    return FailureRecord(binding, FailureClass.UNKNOWN, evidence, False, RecoveryAction.RECONCILE, False)


def classify_for_role(role: FailureRole, binding: FailureBinding, failure: FailureClass, evidence: EvidenceSource) -> FailureRecord:
    """Production adapters use this typed seam before selecting any route."""
    if type(role) is not FailureRole or type(binding) is not FailureBinding or binding.role is not role:
        raise FailureRecoveryError("failure role binding is invalid")
    return classify(binding, failure, evidence)


def admit_recovery(record: FailureRecord, current: FailureBinding, *, route: RecoveryRouteAdmission, clearance: Clearance | None = None) -> RecoveryAction:
    """Recheck immutable context before a retry; denial survives restarts."""
    if type(record) is not FailureRecord or type(current) is not FailureBinding or record.binding != current or type(route) is not RecoveryRouteAdmission or route.binding != current:
        raise FailureRecoveryError("recovery context has drifted")
    if record.clearance_required:
        if clearance is None or clearance.record_digest != record.digest or clearance.binding != current:
            return RecoveryAction.STOP_SCOPE
        # A clearance is a new, exact host decision.  It does not mutate the
        # old record or permit a changed role/session/scope to inherit it.
        return RecoveryAction.PREBOUND_FALLBACK
    if record.action is RecoveryAction.PREBOUND_FALLBACK:
        return RecoveryAction.PREBOUND_FALLBACK if record.retryable else RecoveryAction.RECONCILE
    return record.action
