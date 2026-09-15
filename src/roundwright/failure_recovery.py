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
import weakref


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
    MISSING_OWNER_SCOPE = "missing-owner-scope"
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


def native_failure_class(value: object) -> tuple[FailureClass, EvidenceSource]:
    """Project one closed native error category onto recovery evidence.

    Adapters retain their native enum independently; this boundary accepts
    only its public ``value`` so it does not import a provider implementation
    or create a recovery/provider import cycle.
    """

    native = getattr(value, "value", value)
    if type(native) is not str:
        return FailureClass.UNKNOWN, EvidenceSource.UNAVAILABLE
    if native == "sandbox-or-approval-denied":
        return FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST
    if native in {"provider-outage", "transport-or-provider-outage"}:
        return FailureClass.TRANSIENT_SERVICE, EvidenceSource.VERIFIED_SERVICE
    if native in {"auth-missing", "auth-expired", "auth-rejected"}:
        return FailureClass.CREDENTIAL_FAILURE, EvidenceSource.VERIFIED_HOST
    if native == "missing-owner-scope":
        return FailureClass.MISSING_OWNER_SCOPE, EvidenceSource.VERIFIED_LIFECYCLE
    if native in {"rate-limited", "quota-limited", "quota-or-rate-limit"}:
        return FailureClass.BUDGET_EXHAUSTED, EvidenceSource.VERIFIED_SERVICE
    return FailureClass.UNKNOWN, EvidenceSource.UNAVAILABLE


def classify_native_failure(
    role: FailureRole, binding: "FailureBinding", native_failure: object,
) -> "FailureRecord":
    """Classify a typed SDK terminal result without reading provider prose."""

    failure, evidence = native_failure_class(native_failure)
    return classify_for_role(role, binding, failure, evidence)


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
    evidence_confidence: EvidenceConfidence = EvidenceConfidence.VERIFIED
    record_schema: str = "roundwright-failure-recovery/v2"

    def __post_init__(self) -> None:
        if type(self.binding) is not FailureBinding or type(self.failure) is not FailureClass or type(self.evidence) is not EvidenceSource or type(self.retryable) is not bool or type(self.action) is not RecoveryAction or type(self.clearance_required) is not bool or type(self.evidence_confidence) is not EvidenceConfidence or self.record_schema not in {"roundwright-failure-recovery/v1", "roundwright-failure-recovery/v2"}:
            raise FailureRecoveryError("failure record is invalid")
        if self.record_schema == "roundwright-failure-recovery/v1" and self.evidence_confidence is not EvidenceConfidence.UNAVAILABLE:
            raise FailureRecoveryError("legacy failure evidence confidence is unavailable")
        if self.evidence in {EvidenceSource.MODEL_SELF_REPORT, EvidenceSource.UNAVAILABLE} and self.evidence_confidence is not EvidenceConfidence.UNAVAILABLE:
            raise FailureRecoveryError("untrusted failure evidence cannot be verified")
        if self.failure is FailureClass.HOST_SECURITY_DENIAL and (self.retryable or self.action is not RecoveryAction.STOP_SCOPE or not self.clearance_required):
            raise FailureRecoveryError("security denial must stop its scope")
        if self.failure in {FailureClass.UNKNOWN, FailureClass.MISSING_OUTPUT, FailureClass.AMBIGUOUS_EFFECT} and (self.retryable or self.action is not RecoveryAction.RECONCILE):
            raise FailureRecoveryError("unverified outcome must reconcile")

    @property
    def digest(self) -> str:
        return "sha256:" + _digest_json(_payload(self))


@dataclass(frozen=True)
class Clearance:
    """A request to append one authenticated owner clearance decision.

    ``command_id`` names an already-consumed #115 owner command.  It is not
    enough to label a caller-supplied value ``verified-host``: the recorder
    re-derives the host receipt and current authority from durable state.
    """

    record_digest: str
    binding: FailureBinding
    command_id: str

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.record_digest) or type(self.binding) is not FailureBinding or not _TOKEN.fullmatch(self.command_id):
            raise FailureRecoveryError("clearance is invalid")


@dataclass(frozen=True)
class ClearanceRevocation:
    clearance_digest: str
    binding: FailureBinding
    command_id: str

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.clearance_digest) or type(self.binding) is not FailureBinding or not _TOKEN.fullmatch(self.command_id):
            raise FailureRecoveryError("clearance revocation is invalid")


_ROUTE_ADMISSION_SEAL = object()
_ROUTE_AUTHORITIES: "weakref.WeakKeyDictionary[RecoveryRouteAdmission, tuple[object, object, object]]" = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class RecoveryRouteAdmission:
    """Product-issued, exact route identity; callers cannot assert equivalence.

    The source and target authority objects stay in a module-owned anchor so
    a replay after process reconstruction fails closed unless a trusted host
    reissues the route from current #136 authority and its exact reservation.
    """

    binding: FailureBinding
    source_capability_digest: str
    target_capability_digest: str
    target_identity: str
    reservation_identity: str
    _seal: object | None = None

    def __post_init__(self) -> None:
        if (
            self._seal is not _ROUTE_ADMISSION_SEAL
            or type(self.binding) is not FailureBinding
            or any(type(value) is not str or not _DIGEST.fullmatch(value) for value in (
                self.source_capability_digest, self.target_capability_digest,
                self.target_identity, self.reservation_identity,
            ))
        ):
            raise FailureRecoveryError("recovery route admission is invalid")


def issue_recovery_route_admission(
    binding: FailureBinding, *, source_execution: object, target_execution: object,
    target_reservation: object,
) -> RecoveryRouteAdmission:
    """Issue one route only from live #136 authority plus a reserved target.

    The caller cannot supply a digest, target identity, or budget claim.  Each
    is derived from sealed execution capsules and revalidated before every
    admitted recovery decision.
    """

    from .role_capability_policy import (
        AdvisoryRole, SealedRoleExecution, TrustedRoleEffectReservation,
    )

    if (
        type(binding) is not FailureBinding
        or type(source_execution) is not SealedRoleExecution
        or type(target_execution) is not SealedRoleExecution
        or type(target_reservation) is not TrustedRoleEffectReservation
    ):
        raise FailureRecoveryError("recovery route authority is unavailable")
    source = source_execution.execution_binding
    target = target_reservation.require_recovery_route(target_execution)
    expected_role = AdvisoryRole(binding.role.value)
    task_scope = f"{binding.role.value}:{source.task_identity}"
    if (
        source_execution.seam.value != binding.role.value
        or target_execution.seam.value != binding.role.value
        or source.role is not expected_role or target.role is not expected_role
        or source.candidate_sha != binding.candidate_sha
        or target.candidate_sha != binding.candidate_sha
        or source.task_identity != target.task_identity
        or binding.authority_scope != task_scope
        or target_reservation.execution_binding.digest != target.digest
    ):
        raise FailureRecoveryError("recovery route authority has drifted")
    source_receipt = source_execution.require_before_effect(expected_execution=source)
    target_receipt = target_execution.require_before_effect(expected_execution=target)
    route = RecoveryRouteAdmission(
        binding,
        "sha256:" + _digest_json({"execution": source.digest, "admission": source_receipt}),
        "sha256:" + _digest_json({"execution": target.digest, "admission": target_receipt}),
        target.digest,
        "sha256:" + _digest_json({"reservation": target_reservation.execution_binding.digest}),
        _seal=_ROUTE_ADMISSION_SEAL,
    )
    _ROUTE_AUTHORITIES[route] = (source_execution, target_execution, target_reservation)
    return route


def _require_live_recovery_route(route: RecoveryRouteAdmission, current: FailureBinding) -> None:
    try:
        source_execution, target_execution, target_reservation = _ROUTE_AUTHORITIES[route]
    except (KeyError, TypeError) as error:
        raise FailureRecoveryError("recovery route authority is unavailable") from error
    refreshed = issue_recovery_route_admission(
        current, source_execution=source_execution, target_execution=target_execution,
        target_reservation=target_reservation,
    )
    if (
        refreshed.source_capability_digest != route.source_capability_digest
        or refreshed.target_capability_digest != route.target_capability_digest
        or refreshed.target_identity != route.target_identity
        or refreshed.reservation_identity != route.reservation_identity
    ):
        raise FailureRecoveryError("recovery route authority has drifted")


@dataclass(frozen=True)
class RecoveryAdvice:
    """A digest-only recommendation for #140; it cannot authorize an effect."""

    record_digest: str
    recommendation_digest: str

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 for value in (self.record_digest, self.recommendation_digest)):
            raise FailureRecoveryError("recovery advice is invalid")


def _payload(record: FailureRecord) -> dict[str, object]:
    payload = {"schema": record.record_schema, "binding": _binding_payload(record.binding), "failure": record.failure.value, "evidence": record.evidence.value, "retryable": record.retryable, "action": record.action.value, "clearance_required": record.clearance_required}
    if record.record_schema == "roundwright-failure-recovery/v2":
        payload["evidence_confidence"] = record.evidence_confidence.value
    return payload


def _binding_payload(binding: FailureBinding) -> dict[str, object]:
    return {**binding.__dict__, "role": binding.role.value}


_CLEARANCE_CONDITIONS = (
    "authenticated-owner-command",
    "consumed-owner-command",
    "current-candidate-seal",
    "verified-host-receipt",
)


def _decision_payload(
    *, kind: str, record_digest: str, binding: FailureBinding, command: dict[str, str],
    predecessor_digest: str | None, sequence: int,
) -> dict[str, object]:
    """Canonical, sequenced decision receipt written only after DB verification."""
    if kind not in {"clear", "revoke"} or type(sequence) is not int or sequence <= 0:
        raise FailureRecoveryError("durable clearance decision is invalid")
    return {
        "schema": "roundwright-failure-clearance-decision/v2",
        "kind": kind,
        "record_digest": record_digest,
        "binding": _binding_payload(binding),
        "conditions": list(_CLEARANCE_CONDITIONS),
        "host_receipt": command,
        "predecessor_digest": predecessor_digest,
        "sequence": sequence,
    }


def _digest_json(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_failure_record(value: object) -> FailureRecord:
    if type(value) is not dict or type(value.get("binding")) is not dict:
        raise FailureRecoveryError("durable failure record is malformed")
    schema = value.get("schema")
    expected = {"schema", "binding", "failure", "evidence", "retryable", "action", "clearance_required"}
    if schema == "roundwright-failure-recovery/v2":
        expected = expected | {"evidence_confidence"}
    if schema not in {"roundwright-failure-recovery/v1", "roundwright-failure-recovery/v2"} or set(value) != expected:
        raise FailureRecoveryError("durable failure record is malformed")
    binding = value["binding"]
    if set(binding) != {"candidate_sha", "policy_digest", "configuration_digest", "authority_scope", "role", "profile_identity", "session_identity", "attempt_identity"}:
        raise FailureRecoveryError("durable failure record is malformed")
    try:
        record = FailureRecord(
            FailureBinding(binding["candidate_sha"], binding["policy_digest"], binding["configuration_digest"], binding["authority_scope"], FailureRole(binding["role"]), binding["profile_identity"], binding["session_identity"], binding["attempt_identity"]),
            FailureClass(value["failure"]), EvidenceSource(value["evidence"]), value["retryable"],
            RecoveryAction(value["action"]), value["clearance_required"],
            EvidenceConfidence(value["evidence_confidence"]) if schema.endswith("/v2") else EvidenceConfidence.UNAVAILABLE,
            schema,
        )
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
    _require_current_admission_authority(connection, identity, binding)


def _require_current_admission_authority(connection, identity, binding: FailureBinding) -> None:
    """Read the current task authority in the same snapshot as its admission.

    The failure record's binding is evidence to be checked, never an authority
    input.  A restart must therefore reject a removed admission, a moved
    candidate seal, stale policy/configuration/runtime rows, or a substituted
    session checkpoint even when the old JSON remains canonical.
    """

    row = connection.execute(
        "SELECT seals.base_sha, seals.candidate_sha, seals.state_identity, "
        "current_context.candidate_fingerprint, current_context.policy_fingerprint, "
        "current_context.configuration_digest, current_context.worker_profile_identity, "
        "current_context.supervisor_profile_identities, runtime.schema_version, "
        "runtime.resolved_digest, runtime.worker_profile_identity, "
        "runtime.supervisor_profile_identities, checkpoints.task_id, "
        "checkpoints.attempt_id, checkpoints.session_identity "
        "FROM candidate_seals AS seals "
        "JOIN provider_attempt_contexts AS current_context "
        "ON current_context.attempt_id = ? AND current_context.task_id = seals.task_id "
        "JOIN runtime_configuration_bindings AS runtime "
        "ON runtime.task_id = seals.task_id "
        "JOIN provider_session_checkpoints AS checkpoints "
        "ON checkpoints.attempt_id = ? "
        "WHERE seals.task_id = ?",
        (binding.attempt_identity, binding.attempt_identity, identity.task_id),
    ).fetchone()
    if row is None:
        raise FailureRecoveryError("durable failure authority is unavailable or has drifted")
    (
        base_sha, candidate_sha, state_identity, candidate_fingerprint,
        policy_fingerprint, configuration_digest, context_worker_profile,
        context_supervisor_profiles, runtime_schema, runtime_configuration,
        runtime_worker_profile, runtime_supervisor_profiles, checkpoint_task,
        checkpoint_attempt, checkpoint_session,
    ) = row
    expected_fingerprint = hashlib.sha256(binding.candidate_sha.encode()).hexdigest()
    expected_policy = binding.policy_digest.removeprefix("sha256:")
    try:
        context_supervisors = tuple(json.loads(context_supervisor_profiles))
        runtime_supervisors = tuple(json.loads(runtime_supervisor_profiles))
    except (TypeError, json.JSONDecodeError):
        raise FailureRecoveryError("durable failure authority is unavailable or has drifted") from None
    expected_profile = (
        runtime_worker_profile if binding.role is FailureRole.WORKER
        else binding.profile_identity if binding.role is FailureRole.SUPERVISOR else None
    )
    if (
        base_sha != identity.base_sha
        or candidate_sha != binding.candidate_sha
        or type(state_identity) is not str or not state_identity
        or candidate_fingerprint != expected_fingerprint
        or policy_fingerprint != expected_policy
        or configuration_digest != binding.configuration_digest
        or context_worker_profile != runtime_worker_profile
        or context_supervisors != runtime_supervisors
        or runtime_schema != "roundwright-runtime/v1"
        or runtime_configuration != binding.configuration_digest
        or expected_profile != binding.profile_identity
        or (binding.role is FailureRole.SUPERVISOR and binding.profile_identity not in runtime_supervisors)
        or checkpoint_task != identity.task_id
        or checkpoint_attempt != binding.attempt_identity
        or checkpoint_session != binding.session_identity
    ):
        raise FailureRecoveryError("durable failure authority is unavailable or has drifted")


def read_durable_failure(repository, identity, record_digest: str) -> FailureRecord:
    """Return a record only from one current, authoritative state snapshot."""
    from .state import _open_writable_connection, _require_matching_task
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN")
        _require_matching_task(connection, identity)
        row = connection.execute("SELECT record_json FROM failure_recovery_records WHERE record_digest=? AND task_id=?", (record_digest, identity.task_id)).fetchone()
        if row is None:
            raise FailureRecoveryError("durable failure record is unavailable")
        try:
            payload = json.loads(row[0])
        except (TypeError, json.JSONDecodeError) as error:
            raise FailureRecoveryError("durable failure record is malformed") from error
        record = parse_failure_record(payload)
        if record.digest != record_digest:
            raise FailureRecoveryError("durable failure record digest has drifted")
        _require_attempt_admission(connection, identity, record.binding)
        connection.execute("COMMIT")
        return record
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _owner_command_receipt(connection, task_id: str, binding: FailureBinding, command_id: str) -> dict[str, str]:
    """Rebuild the authenticated #115 receipt; a caller enum is never proof."""
    from .review_lifecycle import _valid_owner_grant
    row = connection.execute(
        "SELECT commands.task_id, commands.candidate_sha, commands.command_kind, commands.owner_identity, commands.authority_grant_id, commands.command_digest, commands.scope_digest, commands.state, commands.result_digest, grants.owner_identity, grants.command_scope, grants.task_id, grants.candidate_sha, grants.authority_digest, grants.state, seals.candidate_sha FROM owner_command_records AS commands JOIN owner_authority_grants AS grants ON grants.grant_id = commands.authority_grant_id JOIN candidate_seals AS seals ON seals.task_id = commands.task_id WHERE commands.command_id = ?",
        (command_id,),
    ).fetchone()
    if row is None:
        raise FailureRecoveryError("authenticated owner command is unavailable")
    task, candidate, kind, owner, grant_id, command_digest, scope_digest, state, result_digest, *grant, sealed_candidate = row
    if (
        not all(type(value) is str for value in (task, candidate, kind, owner, grant_id, command_digest, scope_digest, state, result_digest, sealed_candidate))
        or task != task_id or candidate != binding.candidate_sha or sealed_candidate != binding.candidate_sha
        or state != "consumed" or not _valid_owner_grant(tuple(grant), owner, kind, task_id, candidate)
        or not _DIGEST.fullmatch("sha256:" + command_digest)
        or not _DIGEST.fullmatch("sha256:" + result_digest)
        or not re.fullmatch(r"^[0-9a-f]{64}$", scope_digest)
    ):
        raise FailureRecoveryError("authenticated owner command has drifted")
    return {"schema": "roundwright-owner-command-receipt/v1", "command_id": command_id, "command_digest": "sha256:" + command_digest, "result_digest": "sha256:" + result_digest, "owner_identity": owner, "authority_grant_id": grant_id, "authority_digest": "sha256:" + grant[4]}


def _decision_history(connection, task_id: str, record_digest: str, binding: FailureBinding) -> list[tuple[str, dict[str, object]]]:
    rows = connection.execute("SELECT decision_digest, decision_json, sequence FROM failure_recovery_clearance_decisions WHERE task_id = ? AND record_digest = ? ORDER BY sequence", (task_id, record_digest)).fetchall()
    history: list[tuple[str, dict[str, object]]] = []
    predecessor: str | None = None
    state = "stopped"
    for expected_sequence, (digest, encoded, sequence) in enumerate(rows, start=1):
        if sequence != expected_sequence:
            raise FailureRecoveryError("clearance decision sequence is stale or out of order")
        try:
            payload = json.loads(encoded)
        except (TypeError, json.JSONDecodeError) as error:
            raise FailureRecoveryError("durable clearance decision is malformed") from error
        if type(payload) is not dict or set(payload) != {"schema", "kind", "record_digest", "binding", "conditions", "host_receipt", "predecessor_digest", "sequence"}:
            raise FailureRecoveryError("durable clearance decision is malformed")
        if (payload.get("schema") != "roundwright-failure-clearance-decision/v2" or payload.get("record_digest") != record_digest or payload.get("binding") != _binding_payload(binding) or payload.get("conditions") != list(_CLEARANCE_CONDITIONS) or payload.get("sequence") != sequence or payload.get("predecessor_digest") != predecessor or not _DIGEST.fullmatch(digest) or digest != "sha256:" + _digest_json(payload)):
            raise FailureRecoveryError("durable clearance decision has drifted")
        receipt = payload.get("host_receipt")
        if type(receipt) is not dict or set(receipt) != {"schema", "command_id", "command_digest", "result_digest", "owner_identity", "authority_grant_id", "authority_digest"} or receipt != _owner_command_receipt(connection, task_id, binding, receipt["command_id"]):
            raise FailureRecoveryError("durable clearance receipt has drifted")
        kind = payload.get("kind")
        if kind not in {"clear", "revoke"} or (kind == "clear" and state != "stopped") or (kind == "revoke" and state != "clear"):
            raise FailureRecoveryError("clearance decision is stale or out of order")
        state = "clear" if kind == "clear" else "stopped"
        predecessor = digest
        history.append((digest, payload))
    return history


def _require_clearance_record(connection, identity, record_digest: str, binding: FailureBinding) -> None:
    _require_attempt_admission(connection, identity, binding)
    original = connection.execute("SELECT record_json FROM failure_recovery_records WHERE task_id=? AND record_digest=?", (identity.task_id, record_digest)).fetchone()
    if original is None:
        raise FailureRecoveryError("durable clearance denial is unavailable")
    try:
        record = parse_failure_record(json.loads(original[0]))
    except (TypeError, json.JSONDecodeError) as error:
        raise FailureRecoveryError("durable clearance denial is malformed") from error
    if record.digest != record_digest or record.binding != binding or record.action is not RecoveryAction.STOP_SCOPE or not record.clearance_required:
        raise FailureRecoveryError("durable clearance denial has drifted")


def _append_clearance_decision(connection, identity, *, kind: str, record_digest: str, binding: FailureBinding, command_id: str, observed: int) -> str:
    history = _decision_history(connection, identity.task_id, record_digest, binding)
    predecessor = history[-1][0] if history else None
    prior_kind = history[-1][1]["kind"] if history else None
    if (kind == "clear" and prior_kind not in {None, "revoke"}) or (kind == "revoke" and prior_kind != "clear"):
        raise FailureRecoveryError("clearance decision is stale or out of order")
    receipt = _owner_command_receipt(connection, identity.task_id, binding, command_id)
    payload = _decision_payload(kind=kind, record_digest=record_digest, binding=binding, command=receipt, predecessor_digest=predecessor, sequence=len(history) + 1)
    digest = "sha256:" + _digest_json(payload)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    existing = connection.execute("SELECT task_id, record_digest, decision_json FROM failure_recovery_clearance_decisions WHERE decision_digest = ?", (digest,)).fetchone()
    expected = (identity.task_id, record_digest, encoded)
    if existing is None:
        connection.execute("INSERT INTO failure_recovery_clearance_decisions(decision_digest, task_id, record_digest, command_id, decision_json, sequence, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)", (digest, identity.task_id, record_digest, command_id, encoded, len(history) + 1, observed))
    elif existing != expected:
        raise FailureRecoveryError("durable clearance decision conflicts")
    return digest


def record_durable_clearance(repository, identity, clearance: Clearance, *, now: int | None = None) -> str:
    """Append an authenticated clearance; a later clearance may follow revocation."""
    from .state import _open_writable_connection, _require_matching_task
    if type(clearance) is not Clearance:
        raise FailureRecoveryError("durable clearance is invalid")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0:
        raise FailureRecoveryError("clearance time is invalid")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_matching_task(connection, identity)
        _require_clearance_record(connection, identity, clearance.record_digest, clearance.binding)
        digest = _append_clearance_decision(connection, identity, kind="clear", record_digest=clearance.record_digest, binding=clearance.binding, command_id=clearance.command_id, observed=observed)
        connection.commit()
        return digest
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def record_durable_clearance_revocation(repository, identity, revocation: ClearanceRevocation, *, now: int | None = None) -> str:
    """Append an authenticated revocation without erasing any earlier decision."""
    from .state import _open_writable_connection, _require_matching_task
    if type(revocation) is not ClearanceRevocation:
        raise FailureRecoveryError("clearance revocation is invalid")
    observed = int(time.time()) if now is None else now
    if type(observed) is not int or observed <= 0:
        raise FailureRecoveryError("clearance revocation time is invalid")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_matching_task(connection, identity)
        row = connection.execute("SELECT record_digest FROM failure_recovery_clearance_decisions WHERE task_id=? AND decision_digest=?", (identity.task_id, revocation.clearance_digest)).fetchone()
        if row is None:
            raise FailureRecoveryError("clearance revocation clearance is unavailable")
        _require_clearance_record(connection, identity, row[0], revocation.binding)
        digest = _append_clearance_decision(connection, identity, kind="revoke", record_digest=row[0], binding=revocation.binding, command_id=revocation.command_id, observed=observed)
        connection.commit()
        return digest
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def require_scope_open(connection, task_id: str, scope: str) -> None:
    """Fail closed unless the latest authenticated decision clears every stop."""
    if not isinstance(task_id, str) or not isinstance(scope, str):
        raise FailureRecoveryError("failure scope is invalid")
    for digest, encoded in connection.execute("SELECT record_digest, record_json FROM failure_recovery_records WHERE task_id=?", (task_id,)):
        try:
            record = parse_failure_record(json.loads(encoded))
        except (TypeError, json.JSONDecodeError) as error:
            raise FailureRecoveryError("durable failure record is malformed") from error
        if record.digest != digest:
            raise FailureRecoveryError("durable failure record digest has drifted")
        if record.action is not RecoveryAction.STOP_SCOPE or record.binding.authority_scope != scope:
            continue
        history = _decision_history(connection, task_id, digest, record.binding)
        if not history or history[-1][1]["kind"] != "clear":
            raise FailureRecoveryError("failure scope remains stopped")


def classify(binding: FailureBinding, failure: FailureClass, evidence: EvidenceSource | FailureEvidence) -> FailureRecord:
    """Map one typed observation to the only permitted recovery action."""
    if type(evidence) is FailureEvidence:
        confidence = evidence.confidence
        evidence = evidence.source
    else:
        confidence = EvidenceConfidence.UNAVAILABLE if evidence in {EvidenceSource.MODEL_SELF_REPORT, EvidenceSource.UNAVAILABLE} else EvidenceConfidence.VERIFIED
    if type(binding) is not FailureBinding or type(failure) is not FailureClass or type(evidence) is not EvidenceSource:
        raise FailureRecoveryError("failure classification inputs are invalid")
    # Provider prose and unavailable telemetry never establish capacity, death,
    # denial, or an eligible retry.
    if confidence is not EvidenceConfidence.VERIFIED or evidence in {EvidenceSource.MODEL_SELF_REPORT, EvidenceSource.UNAVAILABLE}:
        failure = FailureClass.UNKNOWN
    if failure is FailureClass.HOST_SECURITY_DENIAL:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.STOP_SCOPE, True, confidence)
    if failure is FailureClass.MISSING_OWNER_SCOPE:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.STOP_SCOPE, True, confidence)
    if failure in {FailureClass.UNKNOWN, FailureClass.MISSING_OUTPUT, FailureClass.AMBIGUOUS_EFFECT, FailureClass.TOPOLOGY_VIOLATION, FailureClass.CREDENTIAL_FAILURE, FailureClass.BUDGET_EXHAUSTED}:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.RECONCILE, failure in {FailureClass.CREDENTIAL_FAILURE, FailureClass.BUDGET_EXHAUSTED}, confidence)
    if failure in {FailureClass.PARTIAL_INCREMENT, FailureClass.ORDINARY_REVIEW_HANDOFF, FailureClass.VALIDATION_RUNNING, FailureClass.NO_PROGRESS}:
        return FailureRecord(binding, failure, evidence, False, RecoveryAction.CONTINUE_SAME_SESSION, False, confidence)
    if failure is FailureClass.SESSION_TERMINATED:
        if evidence is not EvidenceSource.VERIFIED_LIFECYCLE:
            return FailureRecord(binding, FailureClass.UNKNOWN, evidence, False, RecoveryAction.RECONCILE, False, confidence)
        return FailureRecord(binding, failure, evidence, True, RecoveryAction.PREBOUND_FALLBACK, False, confidence)
    if failure is FailureClass.TRANSIENT_SERVICE and evidence is EvidenceSource.VERIFIED_SERVICE:
        return FailureRecord(binding, failure, evidence, True, RecoveryAction.PREBOUND_FALLBACK, False, confidence)
    return FailureRecord(binding, FailureClass.UNKNOWN, evidence, False, RecoveryAction.RECONCILE, False, confidence)


def classify_for_role(role: FailureRole, binding: FailureBinding, failure: FailureClass, evidence: EvidenceSource) -> FailureRecord:
    """Production adapters use this typed seam before selecting any route."""
    if type(role) is not FailureRole or type(binding) is not FailureBinding or binding.role is not role:
        raise FailureRecoveryError("failure role binding is invalid")
    return classify(binding, failure, evidence)


def admit_recovery(record: FailureRecord, current: FailureBinding, *, route: RecoveryRouteAdmission, clearance: Clearance | None = None) -> RecoveryAction:
    """Recheck immutable context before a retry; denial survives restarts."""
    if type(record) is not FailureRecord or type(current) is not FailureBinding or record.binding != current or type(route) is not RecoveryRouteAdmission or route.binding != current:
        raise FailureRecoveryError("recovery context has drifted")
    _require_live_recovery_route(route, current)
    if record.clearance_required:
        # Durable scope admission is the only clearance authority.  A caller
        # cannot construct a host enum (or a ``Clearance`` request) and bypass
        # the authenticated, sequenced receipt checked at dispatch.
        return RecoveryAction.STOP_SCOPE
    if record.action is RecoveryAction.PREBOUND_FALLBACK:
        return RecoveryAction.PREBOUND_FALLBACK if record.retryable else RecoveryAction.RECONCILE
    return record.action
