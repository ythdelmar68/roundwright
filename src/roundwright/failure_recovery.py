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
import re


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


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
        if (
            not _COMMIT.fullmatch(self.candidate_sha)
            or not _DIGEST.fullmatch(self.policy_digest)
            or not _DIGEST.fullmatch(self.configuration_digest)
            or not _TOKEN.fullmatch(self.authority_scope)
            or not _DIGEST.fullmatch(self.profile_identity)
            or not _TOKEN.fullmatch(self.session_identity)
            or not _TOKEN.fullmatch(self.attempt_identity)
            or type(self.role) is not FailureRole
        ):
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

    @property
    def digest(self) -> str:
        return "sha256:" + _digest_json(_clearance_payload(self))


@dataclass(frozen=True)
class ClearanceRevocation:
    clearance_digest: str
    binding: FailureBinding
    evidence: EvidenceSource

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.clearance_digest) or type(self.binding) is not FailureBinding or self.evidence is not EvidenceSource.VERIFIED_HOST:
            raise FailureRecoveryError("clearance revocation is invalid")

    @property
    def digest(self) -> str:
        return "sha256:" + _digest_json(_revocation_payload(self))


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


def _binding_payload(binding: FailureBinding) -> dict[str, object]:
    return {**binding.__dict__, "role": binding.role.value}


def _clearance_payload(clearance: Clearance) -> dict[str, object]:
    return {"schema": "roundwright-failure-clearance/v1", "record_digest": clearance.record_digest, "binding": _binding_payload(clearance.binding), "evidence": clearance.evidence.value}


def _revocation_payload(revocation: ClearanceRevocation) -> dict[str, object]:
    return {"schema": "roundwright-failure-clearance-revocation/v1", "clearance_digest": revocation.clearance_digest, "binding": _binding_payload(revocation.binding), "evidence": revocation.evidence.value}


def _digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_failure_record(value: object) -> FailureRecord:
    if type(value) is not dict or set(value) != {"schema", "binding", "failure", "evidence", "retryable", "action", "clearance_required"} or value.get("schema") != "roundwright-failure-recovery/v1" or type(value.get("binding")) is not dict:
        raise FailureRecoveryError("durable failure record is malformed")
    binding = value["binding"]
    if set(binding) != {"candidate_sha", "policy_digest", "configuration_digest", "authority_scope", "role", "profile_identity", "session_identity", "attempt_identity"}:
        raise FailureRecoveryError("durable failure record is malformed")
    try:
        record = FailureRecord(FailureBinding(binding["candidate_sha"], binding["policy_digest"], binding["configuration_digest"], binding["authority_scope"], FailureRole(binding["role"]), binding["profile_identity"], binding["session_identity"], binding["attempt_identity"]), FailureClass(value["failure"]), EvidenceSource(value["evidence"]), value["retryable"], RecoveryAction(value["action"]), value["clearance_required"])
    except (KeyError, TypeError, ValueError) as error:
        raise FailureRecoveryError("durable failure record is malformed") from error
    if _payload(record) != value:
        raise FailureRecoveryError("durable failure record is non-canonical")
    return record


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
        _require_attempt_admission(connection, identity, record.binding)
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


def _require_attempt_admission(connection, identity, binding: FailureBinding) -> None:
    """Reconcile failure identity with the trusted, session-bound admission.

    Legacy attempts deliberately have no row in this forward-only table.  They
    cannot mint a durable recovery record because fingerprints alone cannot be
    reversed into the raw candidate or configuration identities.
    """

    row = connection.execute(
        "SELECT admissions.task_id, admissions.candidate_sha, admissions.policy_digest, admissions.configuration_digest, admissions.authority_scope, admissions.provider_role, admissions.profile_identity, admissions.session_identity, admissions.attempt_identity, attempts.task_id, attempts.provider_role, attempts.selected_profile_identity, attempts.session_identity, contexts.task_id, contexts.candidate_fingerprint, contexts.policy_fingerprint, contexts.configuration_digest FROM provider_failure_admissions AS admissions JOIN provider_attempts AS attempts ON attempts.attempt_id = admissions.attempt_id JOIN provider_attempt_contexts AS contexts ON contexts.attempt_id = admissions.attempt_id WHERE admissions.attempt_id = ?",
        (binding.attempt_identity,),
    ).fetchone()
    expected = (
        identity.task_id, binding.candidate_sha, binding.policy_digest,
        binding.configuration_digest, binding.authority_scope, binding.role.value,
        binding.profile_identity, binding.session_identity, binding.attempt_identity,
    )
    if row is None or tuple(row[:9]) != expected:
        raise FailureRecoveryError("durable failure admission is unavailable or has drifted")
    if (
        row[9] != identity.task_id or row[10] != binding.role.value
        or row[11] != binding.profile_identity or row[12] != binding.session_identity
        or row[13] != identity.task_id
        or row[14] != hashlib.sha256(binding.candidate_sha.encode()).hexdigest()
        or row[15] != binding.policy_digest.removeprefix("sha256:")
        or row[16] != binding.configuration_digest
    ):
        raise FailureRecoveryError("durable failure admission is unavailable or has drifted")


def read_durable_failure(repository, identity, record_digest: str) -> FailureRecord:
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
    record = parse_failure_record(payload)
    if record.digest != record_digest:
        raise FailureRecoveryError("durable failure record digest has drifted")
    return record


def record_durable_clearance(repository, identity, clearance: Clearance, *, now: int | None = None) -> str:
    """Append an exact clearance for one admitted STOP_SCOPE denial."""
    from .state import _open_writable_connection, _require_matching_task
    if type(clearance) is not Clearance:
        raise FailureRecoveryError("durable clearance is invalid")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0: raise FailureRecoveryError("clearance time is invalid")
    encoded = json.dumps(_clearance_payload(clearance), sort_keys=True, separators=(",", ":"))
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity); _require_attempt_admission(connection, identity, clearance.binding)
        original = connection.execute("SELECT record_json FROM failure_recovery_records WHERE task_id=? AND record_digest=?", (identity.task_id, clearance.record_digest)).fetchone()
        if original is None: raise FailureRecoveryError("durable clearance denial is unavailable")
        record = parse_failure_record(json.loads(original[0]))
        if record.digest != clearance.record_digest or record.binding != clearance.binding or record.action is not RecoveryAction.STOP_SCOPE or not record.clearance_required: raise FailureRecoveryError("durable clearance denial has drifted")
        existing = connection.execute("SELECT task_id,record_digest,clearance_json FROM failure_recovery_clearances WHERE clearance_digest=?", (clearance.digest,)).fetchone()
        expected = (identity.task_id, clearance.record_digest, encoded)
        if existing is None:
            sequence = connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM failure_recovery_clearances WHERE task_id=?", (identity.task_id,)).fetchone()[0]
            connection.execute("INSERT INTO failure_recovery_clearances(clearance_digest,task_id,record_digest,clearance_json,sequence,recorded_at) VALUES (?,?,?,?,?,?)", (clearance.digest, *expected, sequence, observed))
        elif existing != expected: raise FailureRecoveryError("durable clearance conflicts")
        connection.commit()
    except Exception:
        connection.rollback(); raise
    finally: connection.close()
    return clearance.digest


def record_durable_clearance_revocation(repository, identity, revocation: ClearanceRevocation, *, now: int | None = None) -> str:
    """Append a revocation without deleting its clearance or original denial."""
    from .state import _open_writable_connection, _require_matching_task
    if type(revocation) is not ClearanceRevocation: raise FailureRecoveryError("clearance revocation is invalid")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0: raise FailureRecoveryError("clearance revocation time is invalid")
    encoded = json.dumps(_revocation_payload(revocation), sort_keys=True, separators=(",", ":")); connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity); _require_attempt_admission(connection, identity, revocation.binding)
        row = connection.execute("SELECT task_id,record_digest,clearance_json FROM failure_recovery_clearances WHERE clearance_digest=?", (revocation.clearance_digest,)).fetchone()
        if row is None or row[0] != identity.task_id: raise FailureRecoveryError("clearance revocation clearance is unavailable")
        clearance = _parse_clearance(json.loads(row[2]))
        if clearance.digest != revocation.clearance_digest or clearance.binding != revocation.binding: raise FailureRecoveryError("clearance revocation clearance has drifted")
        existing = connection.execute("SELECT task_id,clearance_digest,revocation_json FROM failure_recovery_clearance_revocations WHERE revocation_digest=?", (revocation.digest,)).fetchone(); expected=(identity.task_id,revocation.clearance_digest,encoded)
        if existing is None:
            sequence=connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM failure_recovery_clearance_revocations WHERE task_id=?",(identity.task_id,)).fetchone()[0]
            connection.execute("INSERT INTO failure_recovery_clearance_revocations(revocation_digest,task_id,clearance_digest,revocation_json,sequence,recorded_at) VALUES (?,?,?,?,?,?)",(revocation.digest,*expected,sequence,observed))
        elif existing != expected: raise FailureRecoveryError("clearance revocation conflicts")
        connection.commit()
    except Exception:
        connection.rollback(); raise
    finally: connection.close()
    return revocation.digest


def _parse_binding(value: object) -> FailureBinding:
    if type(value) is not dict or set(value) != {"candidate_sha","policy_digest","configuration_digest","authority_scope","role","profile_identity","session_identity","attempt_identity"}: raise FailureRecoveryError("durable clearance is malformed")
    try: return FailureBinding(value["candidate_sha"],value["policy_digest"],value["configuration_digest"],value["authority_scope"],FailureRole(value["role"]),value["profile_identity"],value["session_identity"],value["attempt_identity"])
    except (KeyError, TypeError, ValueError) as error: raise FailureRecoveryError("durable clearance is malformed") from error


def _parse_clearance(value: object) -> Clearance:
    if type(value) is not dict or set(value) != {"schema","record_digest","binding","evidence"} or value.get("schema") != "roundwright-failure-clearance/v1": raise FailureRecoveryError("durable clearance is malformed")
    try: clearance=Clearance(value["record_digest"],_parse_binding(value["binding"]),EvidenceSource(value["evidence"]))
    except (KeyError,TypeError,ValueError) as error: raise FailureRecoveryError("durable clearance is malformed") from error
    if _clearance_payload(clearance) != value: raise FailureRecoveryError("durable clearance is non-canonical")
    return clearance


def _parse_revocation(value: object) -> ClearanceRevocation:
    if type(value) is not dict or set(value) != {"schema","clearance_digest","binding","evidence"} or value.get("schema") != "roundwright-failure-clearance-revocation/v1": raise FailureRecoveryError("clearance revocation is malformed")
    try: revocation=ClearanceRevocation(value["clearance_digest"],_parse_binding(value["binding"]),EvidenceSource(value["evidence"]))
    except (KeyError,TypeError,ValueError) as error: raise FailureRecoveryError("clearance revocation is malformed") from error
    if _revocation_payload(revocation) != value: raise FailureRecoveryError("clearance revocation is non-canonical")
    return revocation


def require_scope_open(connection, task_id: str, scope: str) -> None:
    """Fail before an effect when an exact durable scope has an uncleared stop."""
    if not isinstance(task_id, str) or not isinstance(scope, str):
        raise FailureRecoveryError("failure scope is invalid")
    for digest, encoded in connection.execute("SELECT record_digest, record_json FROM failure_recovery_records WHERE task_id=?", (task_id,)):
        try:
            value = json.loads(encoded)
        except (TypeError, json.JSONDecodeError) as error:
            raise FailureRecoveryError("durable failure record is malformed") from error
        record = parse_failure_record(value)
        if record.digest != digest: raise FailureRecoveryError("durable failure record digest has drifted")
        if record.action is not RecoveryAction.STOP_SCOPE or record.binding.authority_scope != scope: continue
        row = connection.execute("SELECT clearance_digest,clearance_json FROM failure_recovery_clearances WHERE task_id=? AND record_digest=?", (task_id,digest)).fetchone()
        if row is None: raise FailureRecoveryError("failure scope remains stopped")
        clearance = _parse_clearance(json.loads(row[1]))
        if clearance.digest != row[0] or clearance.record_digest != digest or clearance.binding != record.binding: raise FailureRecoveryError("durable clearance has drifted")
        revocation = connection.execute("SELECT revocation_digest,revocation_json FROM failure_recovery_clearance_revocations WHERE task_id=? AND clearance_digest=?", (task_id,row[0])).fetchone()
        if revocation is not None:
            value = _parse_revocation(json.loads(revocation[1]))
            if value.digest != revocation[0] or value.clearance_digest != row[0] or value.binding != record.binding: raise FailureRecoveryError("clearance revocation has drifted")
            raise FailureRecoveryError("failure scope remains stopped")


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
