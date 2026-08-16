"""Provider-neutral attempt persistence and fail-closed restart recovery.

This module deliberately models provider turns as opaque identities.  It does
not start processes, call an SDK, read provider output, or expose private
output locations.  A later adapter can use these records to make dispatch and
resume decisions without ever guessing whether an external turn was created.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass, replace
from enum import StrEnum

from .configuration import RepositoryIdentity
from .git_identity import TransitionLease, _require_current_lease
from .runtime_binding import RuntimeBinding
from .state import StateError, TaskIdentity, _open_writable_connection, _require_matching_task, database_path, record_runtime_binding, require_runtime_binding


class ProviderRecoveryError(StateError):
    """Raised when a provider turn cannot be persisted or recovered safely."""


class ProviderRole(StrEnum):
    PLANNING = "planning"
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    AGGREGATION = "aggregation"


class AttemptState(StrEnum):
    PREPARED = "prepared"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    ACCEPTED = "accepted"
    AMBIGUOUS = "ambiguous"
    BLOCKED = "blocked"
    INVALIDATED = "invalidated"


class RecoveryAction(StrEnum):
    RETRY = "retry"
    RESUME_SAME_SESSION = "resume-same-session"
    CONSUME_VERIFIED_OUTPUT = "consume-verified-output"
    ACCEPTED_REVIEW = "accepted-review"
    BLOCKED_AMBIGUOUS_TURN = "blocked-ambiguous-turn"
    BLOCKED_STALE_WORKER = "blocked-stale-worker"
    FRESH_SUPERVISOR_SESSION = "fresh-supervisor-session"
    BLOCKED_RETRY_LIMIT = "blocked-retry-limit"
    BLOCKED_IDENTITY_DRIFT = "blocked-identity-drift"
    # Existing durable storage already reserves this no-followup action.  The
    # closed blocker below distinguishes a schema-valid accounting conclusion
    # from an uncertain external turn without changing historical rows.
    BLOCKED_PROVIDER_ACCOUNTING = "blocked-ambiguous-turn"


class SupervisorTerminalFailureClass(StrEnum):
    AUTH_MISSING = "auth-missing"
    AUTH_EXPIRED = "auth-expired"
    QUOTA_OR_RATE_LIMIT = "quota-or-rate-limit"
    MODEL_UNAVAILABLE = "model-unavailable"
    SDK_INCOMPATIBLE = "sdk-incompatible"
    SANDBOX_OR_APPROVAL_DENIED = "sandbox-or-approval-denied"
    TRANSPORT_OR_PROVIDER_OUTAGE = "transport-or-provider-outage"
    MALFORMED_RESPONSE = "malformed-response"
    UNKNOWN = "unknown"


class SupervisorTerminalFailureSource(StrEnum):
    SDK_TURN_FAILED = "sdk-turn-failed"


class SupervisorTerminalFailureSdkCategory(StrEnum):
    BAD_REQUEST = "bad-request"
    UNAUTHORIZED = "unauthorized"
    SANDBOX = "sandbox"
    OVERLOAD = "overload"
    HTTP = "http"
    STREAM = "stream"
    CONNECTION = "connection"
    MISSING_OR_UNKNOWN = "missing-or-unknown"


class SupervisorAccountingBlocker(StrEnum):
    INCOMPLETE_ACCOUNTING = "provider-accounting-incomplete"


class SupervisorDispatchClaimState(StrEnum):
    UNCLAIMED = "unclaimed"
    CLAIMED = "claimed"


@dataclass(frozen=True)
class SupervisorAccountingAttemptSnapshot:
    attempt_id: str; within_round_attempt: int; profile_identity: str; state: AttemptState
    session_present: bool; turn_present: bool; completion_present: bool; invalid_output_present: bool
    recovery_action: RecoveryAction | None; terminal_failure: SupervisorTerminalFailure | None; accepted: bool
    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.attempt_id) or type(self.within_round_attempt) is not int or self.within_round_attempt < 1 or not _DIGEST.fullmatch(self.profile_identity) or type(self.state) is not AttemptState or any(type(value) is not bool for value in (self.session_present, self.turn_present, self.completion_present, self.invalid_output_present, self.accepted)) or (self.recovery_action is not None and type(self.recovery_action) is not RecoveryAction) or (self.terminal_failure is not None and type(self.terminal_failure) is not SupervisorTerminalFailure):
            raise ProviderRecoveryError("accounting attempt snapshot is invalid")
        if self.accepted != (self.state is AttemptState.ACCEPTED) or self.accepted and (not self.session_present or not self.turn_present or not self.completion_present or self.invalid_output_present):
            raise ProviderRecoveryError("accounting attempt snapshot is inconsistent")
        if self.state is AttemptState.PREPARED and (self.session_present or self.turn_present or self.completion_present or self.invalid_output_present or self.recovery_action is not None or self.terminal_failure is not None or self.accepted):
            raise ProviderRecoveryError("accounting prepared snapshot is inconsistent")
        if self.turn_present and not self.session_present:
            raise ProviderRecoveryError("accounting turn snapshot is inconsistent")
        if self.invalid_output_present and self.state is not AttemptState.INVALIDATED:
            raise ProviderRecoveryError("accounting invalid snapshot is inconsistent")
        if self.terminal_failure is not None and (self.state is not AttemptState.INVALIDATED or not self.session_present or not self.turn_present or self.completion_present or self.invalid_output_present or self.recovery_action is not RecoveryAction.FRESH_SUPERVISOR_SESSION):
            raise ProviderRecoveryError("accounting terminal failure snapshot is inconsistent")
        if self.state is AttemptState.INVALIDATED and ((self.invalid_output_present == (self.terminal_failure is not None)) or self.recovery_action is not RecoveryAction.FRESH_SUPERVISOR_SESSION):
            raise ProviderRecoveryError("accounting recovery snapshot is inconsistent")
    def canonical_material(self) -> dict[str, object]: return {"attempt_id":self.attempt_id,"within_round_attempt":self.within_round_attempt,"profile_identity":self.profile_identity,"state":self.state.value,"session_present":self.session_present,"turn_present":self.turn_present,"completion_present":self.completion_present,"invalid_output_present":self.invalid_output_present,"recovery_action":None if self.recovery_action is None else self.recovery_action.value,"terminal_failure":None if self.terminal_failure is None else {"failure_class":self.terminal_failure.failure_class.value,"outcome_source":self.terminal_failure.outcome_source.value,"sdk_error_category":self.terminal_failure.sdk_error_category.value},"accepted":self.accepted}


@dataclass(frozen=True)
class SupervisorAccountingSnapshot:
    repository_id: str; task_id: str; source_digest: str; base_sha: str; candidate_sha: str; case_id: str; ready_at: int
    seal_state_identity: str; evidence: tuple[str, ...]; verifications: tuple[tuple[str, str], ...]
    configuration_digest: str; policy_digest: str; complete_rounds: int; max_rounds: int; max_attempts: int; review_epoch: int; review_round: int; review_mode: str
    formal_record_count: int; formal_accepted_count: int; dispatch_claim: SupervisorDispatchClaimState; current: SupervisorAccountingAttemptSnapshot; prior: tuple[SupervisorAccountingAttemptSnapshot, ...]
    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.repository_id) or not _TOKEN.fullmatch(self.task_id) or not _TOKEN.fullmatch(self.case_id) or not _DIGEST.fullmatch(self.source_digest) or not _COMMIT.fullmatch(self.base_sha) or not _COMMIT.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or self.ready_at < 0 or not _TOKEN.fullmatch(self.seal_state_identity) or type(self.evidence) is not tuple or type(self.verifications) is not tuple or any(type(item) is not str or not _FINGERPRINT.fullmatch(item) for item in self.evidence) or len(set(self.evidence)) != len(self.evidence) or any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not str or type(item[1]) is not str or item[0] not in {"test","build"} or item[1] not in {"pass","not-applicable"} for item in self.verifications) or len(set(self.verifications)) != len(self.verifications):
            raise ProviderRecoveryError("accounting snapshot is invalid")
        if not _DIGEST.fullmatch(self.configuration_digest) or not _FINGERPRINT.fullmatch(self.policy_digest) or self.review_mode not in {"COMPLETE", "CONVERGING"} or any(type(value) is not int or value < 0 for value in (self.complete_rounds,self.max_rounds,self.max_attempts,self.review_epoch,self.formal_record_count,self.formal_accepted_count)) or type(self.review_round) is not int or self.review_round < 1 or self.complete_rounds < 1 or self.max_rounds < self.complete_rounds or self.max_attempts < 1 or self.review_round > self.max_rounds or self.formal_accepted_count not in {0,1} or self.formal_accepted_count > self.formal_record_count or type(self.dispatch_claim) is not SupervisorDispatchClaimState or type(self.current) is not SupervisorAccountingAttemptSnapshot or type(self.prior) is not tuple or any(type(item) is not SupervisorAccountingAttemptSnapshot for item in self.prior):
            raise ProviderRecoveryError("accounting snapshot is invalid")
        if self.current.state is not AttemptState.PREPARED or self.current.within_round_attempt != len(self.prior)+1 or any((self.current.session_present,self.current.turn_present,self.current.completion_present,self.current.invalid_output_present,self.current.accepted)) or self.current.recovery_action is not None or tuple(item.within_round_attempt for item in self.prior) != tuple(range(1,len(self.prior)+1)) or len({item.attempt_id for item in self.prior + (self.current,)}) != len(self.prior) + 1 or len({item.profile_identity for item in self.prior + (self.current,)}) != len(self.prior) + 1:
            raise ProviderRecoveryError("accounting snapshot attempt ordering is invalid")
    def canonical_material(self) -> dict[str, object]: return {"schema":"roundwright-provider-attempt-accounting-decision/v3","binding":{"repository_id":self.repository_id,"task_id":self.task_id,"source_digest":self.source_digest,"base_sha":self.base_sha,"candidate_sha":self.candidate_sha,"case_id":self.case_id,"ready_at":self.ready_at},"candidate":{"seal_state_identity":self.seal_state_identity,"evidence_count":len(self.evidence),"evidence_digest":"sha256:"+hashlib.sha256("|".join(self.evidence).encode()).hexdigest(),"verification_count":len(self.verifications),"verification_kinds":[{"kind":a,"outcome":b} for a,b in self.verifications]},"review_policy":{"configuration_digest":self.configuration_digest,"policy_digest":self.policy_digest,"complete_rounds":self.complete_rounds,"max_rounds":self.max_rounds,"max_supervisor_attempts_per_round":self.max_attempts,"review_epoch":self.review_epoch,"review_round":self.review_round,"review_mode":self.review_mode},"formal_review":{"review_epoch":self.review_epoch,"review_round":self.review_round,"record_count":self.formal_record_count,"accepted_count":self.formal_accepted_count,"accepted_result_present":bool(self.formal_accepted_count)},"dispatch_claim":self.dispatch_claim.value,"current_attempt":self.current.canonical_material(),"prior_attempts":[item.canonical_material() for item in self.prior]}


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class RecoveryContext:
    """Opaque identity evidence that must still agree before recovery resumes."""

    task_id: str
    repository_fingerprint: str
    worktree_fingerprint: str
    branch_fingerprint: str
    base_fingerprint: str
    candidate_fingerprint: str | None
    candidate_sha: str | None
    policy_fingerprint: str
    deployment_fingerprint: str
    runtime_binding: RuntimeBinding
    health_contract_commit: str | None = None
    shadow_case_id: str | None = None
    health_receipt: object | None = None

    @classmethod
    def for_task(
        cls,
        identity: TaskIdentity,
        *,
        candidate_sha: str | None,
        policy_fingerprint: str,
        deployment_fingerprint: str,
        runtime_binding: RuntimeBinding,
        health_contract_commit: str | None = None,
        shadow_case_id: str | None = None,
        health_receipt: object | None = None,
    ) -> "RecoveryContext":
        """Build context without retaining a worktree path in owner projections."""

        _validate_task(identity)
        if candidate_sha is not None and not _COMMIT.fullmatch(candidate_sha):
            raise ProviderRecoveryError("candidate identity is invalid")
        _require_fingerprint(policy_fingerprint, "policy fingerprint")
        _require_fingerprint(deployment_fingerprint, "deployment fingerprint")
        if type(runtime_binding) is not RuntimeBinding:
            raise ProviderRecoveryError("resolved configuration binding is invalid")
        return cls(
            identity.task_id,
            _fingerprint(identity.repository_id),
            _fingerprint(identity.worktree),
            _fingerprint(identity.branch),
            _fingerprint(identity.base_sha),
            None if candidate_sha is None else _fingerprint(candidate_sha),
            candidate_sha,
            policy_fingerprint,
            deployment_fingerprint,
            runtime_binding,
            health_contract_commit,
            shadow_case_id,
            health_receipt,
        )


@dataclass(frozen=True)
class ProviderAttempt:
    """Provider-neutral durable identity for exactly one attempted turn."""

    attempt_id: str
    task_id: str
    role: ProviderRole
    attempt_number: int
    process_lease_id: str
    process_lease_expires_at: int
    session_identity: str | None
    external_turn_identity: str | None
    input_fingerprint: str
    output_pointer: str | None
    completion_evidence_fingerprint: str | None
    accepted_review_identity: str | None
    state: AttemptState
    selected_profile_identity: str


@dataclass(frozen=True)
class RecoveryProjection:
    """Owner-safe view: opaque identities, never raw output or local paths."""

    attempt_id: str
    role: ProviderRole
    state: AttemptState
    process_lease_id: str
    session_identity: str | None
    external_turn_identity: str | None
    output_available: bool
    accepted_review_identity: str | None
    blocker: str | None
    next_action: RecoveryAction


@dataclass(frozen=True)
class SupervisorTerminalFailure:
    """Durable public-safe SDK terminal failure, never provider prose."""

    failure_class: SupervisorTerminalFailureClass
    outcome_source: SupervisorTerminalFailureSource
    sdk_error_category: SupervisorTerminalFailureSdkCategory

    def __post_init__(self) -> None:
        if type(self.failure_class) is not SupervisorTerminalFailureClass or self.outcome_source is not SupervisorTerminalFailureSource.SDK_TURN_FAILED or type(self.sdk_error_category) is not SupervisorTerminalFailureSdkCategory:
            raise ProviderRecoveryError("terminal failure projection is invalid")


@dataclass(frozen=True)
class _PersistedRecoveryOutcome:
    action: RecoveryAction
    blocker: str | None


def read_supervisor_accounting_snapshot(
    repository: RepositoryIdentity, identity: TaskIdentity, context: RecoveryContext, *,
    source_digest: str, base_sha: str, candidate_sha: str, case_id: str, ready_at: int,
    review_epoch: int, review_round: int, review_mode: str,
    current_attempt_id: str, current_within_round_attempt: int, current_profile_identity: str,
    prior_attempts: tuple[tuple[str, int, str], ...],
    seal_state_identity: str,
) -> SupervisorAccountingSnapshot:
    """Read the closed accounting decision input from durable product state."""
    _validate_task(identity); _validate_context(identity, context)
    if not _DIGEST.fullmatch(source_digest) or base_sha != identity.base_sha or candidate_sha != context.candidate_sha or not _TOKEN.fullmatch(case_id) or type(ready_at) is not int or ready_at < 0 or type(review_epoch) is not int or review_epoch < 0 or type(review_round) is not int or review_round < 1 or review_mode not in {"COMPLETE", "CONVERGING"} or not _TOKEN.fullmatch(current_attempt_id) or current_within_round_attempt < 1 or not _DIGEST.fullmatch(current_profile_identity) or tuple(item[1] for item in prior_attempts) != tuple(range(1, len(prior_attempts)+1)):
        raise ProviderRecoveryError("accounting snapshot inputs are invalid")
    path = database_path(repository)
    if not path.exists():
        raise ProviderRecoveryError("accounting snapshot state is unavailable")
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    except (OSError, sqlite3.DatabaseError) as error:
        raise ProviderRecoveryError("accounting snapshot state is unavailable") from error
    try:
        _require_matching_task(connection, identity)
        seal = connection.execute("SELECT base_sha,candidate_sha,state_identity FROM candidate_seals WHERE task_id=?", (identity.task_id,)).fetchone()
        if seal != (base_sha, candidate_sha, seal_state_identity): raise ProviderRecoveryError("accounting snapshot seal has drifted")
        evidence = tuple(row[0] for row in connection.execute("SELECT evidence_fingerprint FROM candidate_evidence WHERE task_id=? AND candidate_sha=? ORDER BY evidence_fingerprint", (identity.task_id,candidate_sha)))
        verifications = tuple((row[0],row[1]) for row in connection.execute("SELECT verification_kind,outcome FROM candidate_verifications WHERE task_id=? AND candidate_sha=? ORDER BY verification_kind,verification_id", (identity.task_id,candidate_sha)))
        formal = connection.execute("SELECT COUNT(*),SUM(CASE WHEN state='accepted' THEN 1 ELSE 0 END) FROM diff_review_attempts WHERE task_id=? AND review_epoch=? AND review_round=?", (identity.task_id,review_epoch,review_round)).fetchone()
        def attempt(attempt_id: str, ordinal: int, profile: str) -> SupervisorAccountingAttemptSnapshot:
            row = connection.execute("SELECT state,session_identity,external_turn_identity,output_pointer,completion_evidence_fingerprint,accepted_review_identity,selected_profile_identity FROM provider_attempts WHERE task_id=? AND attempt_id=?", (identity.task_id,attempt_id)).fetchone()
            outcome = connection.execute("SELECT recovery_action,blocker FROM provider_recovery_outcomes WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None or row[6] != profile: raise ProviderRecoveryError("accounting snapshot attempt is unavailable")
            persisted = None if outcome is None else _PersistedRecoveryOutcome(RecoveryAction(outcome[0]), outcome[1])
            return SupervisorAccountingAttemptSnapshot(attempt_id,ordinal,profile,AttemptState(row[0]),row[1] is not None,row[2] is not None,row[4] is not None,(row[3] or "").startswith("supervisor-invalid-"),None if outcome is None else RecoveryAction(outcome[0]),_terminal_failure_from_outcome(AttemptState(row[0]), persisted),row[5] is not None)
        current = attempt(current_attempt_id,current_within_round_attempt,current_profile_identity)
        prior = tuple(attempt(*item) for item in prior_attempts)
        binding = context.runtime_binding
        claim = _dispatch_claim_state(connection, identity, _attempt_row(connection, identity.task_id, current_attempt_id))
        return SupervisorAccountingSnapshot(identity.repository_id,identity.task_id,source_digest,base_sha,candidate_sha,case_id,ready_at,seal_state_identity,evidence,verifications,binding.resolved_digest,binding.review_policy_digest,binding.review_complete_rounds,binding.review_max_rounds,binding.review_max_supervisor_attempts_per_round,review_epoch,review_round,review_mode,formal[0],0 if formal[1] is None else formal[1],claim,current,prior)
    finally:
        connection.close()


def preflight_attempt_preparation(
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    role: ProviderRole,
    process_lease_id: str,
    process_lease_expires_at: int,
    input_fingerprint: str,
    selected_profile_identity: str | None = None,
    now: int | None = None,
) -> None:
    """Validate a future attempt's identity and health without durable writes."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_role(role)
    _require_token(process_lease_id, "process lease identity")
    _require_future_time(process_lease_expires_at, now)
    _require_fingerprint(input_fingerprint, "input fingerprint")
    selected = _selected_profile_identity(context, role, selected_profile_identity)
    _require_health_authorization(context, role, selected, _clock(now))


def prepare_attempt(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    role: ProviderRole,
    process_lease_id: str,
    process_lease_expires_at: int,
    input_fingerprint: str,
    selected_profile_identity: str | None = None,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Checkpoint before dispatch and persist a turn that has no external ID yet."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_role(role)
    _require_token(process_lease_id, "process lease identity")
    _require_future_time(process_lease_expires_at, now)
    _require_fingerprint(input_fingerprint, "input fingerprint")
    observed = _clock(now)
    selected_profile = _selected_profile_identity(context, role, selected_profile_identity)
    receipt = _require_health_authorization(context, role, selected_profile, observed)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        if role is ProviderRole.SUPERVISOR and connection.execute("SELECT 1 FROM review_limit_finalizations WHERE task_id = ?", (identity.task_id,)).fetchone() is not None:
            raise ProviderRecoveryError("review limit has consumed the final Worker repair")
        # The binding is first persisted only after lease and task validation,
        # inside the same transaction that creates the dispatch checkpoint.
        record_runtime_binding(repository, identity, context.runtime_binding, connection=connection)
        require_runtime_binding(repository, identity, context.runtime_binding, connection=connection)
        existing = connection.execute(
            "SELECT attempt_id FROM provider_attempts WHERE task_id = ? AND attempt_id = ?",
            (identity.task_id, attempt_id),
        ).fetchone()
        if existing is not None:
            row = _attempt_row(connection, identity.task_id, attempt_id)
            _require_persisted_context(connection, attempt_id, context)
            _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
            if (
                row.role is not role
                or row.process_lease_id != process_lease_id
                or row.process_lease_expires_at != process_lease_expires_at
                or row.input_fingerprint != input_fingerprint
                or row.selected_profile_identity != selected_profile
                or row.state not in {AttemptState.PREPARED, AttemptState.DISPATCHED}
            ):
                raise ProviderRecoveryError("provider attempt replay conflicts with committed state")
            connection.commit()
            return row
        number = connection.execute(
            "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM provider_attempts WHERE task_id = ? AND provider_role = ?",
            (identity.task_id, role.value),
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO provider_attempts(attempt_id, task_id, provider_role, attempt_number, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint, accepted_review_identity, state, selected_profile_identity) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL, NULL, NULL, ?, ?)",
            (attempt_id, identity.task_id, role.value, number, process_lease_id, process_lease_expires_at, input_fingerprint, AttemptState.PREPARED.value, selected_profile),
        )
        _persist_context(connection, attempt_id, context)
        authorization_fingerprint = _persist_health_authorization(connection, attempt_id, receipt, role, selected_profile)
        _checkpoint(connection, identity.task_id, role, "before-dispatch", attempt_id, context, authorization_fingerprint, observed)
        connection.commit()
    except sqlite3.IntegrityError as error:
        connection.rollback()
        raise ProviderRecoveryError("provider attempt identity conflicts with committed state") from error
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id)


def claim_supervisor_dispatch(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Atomically consume one prepared Supervisor dispatch authorization.

    A claim deliberately precedes native session construction.  It makes a
    prepared attempt one-shot even when a provider cannot return a session or
    a local checkpoint callback fails before a durable turn exists.
    """

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.role is not ProviderRole.SUPERVISOR or row.state is not AttemptState.PREPARED or row.session_identity is not None or row.external_turn_identity is not None or row.output_pointer is not None or row.accepted_review_identity is not None:
            raise ProviderRecoveryError("Supervisor dispatch claim requires an unclaimed prepared attempt")
        existing = connection.execute("SELECT task_id,claim_fingerprint FROM provider_dispatch_claims WHERE attempt_id=?", (attempt_id,)).fetchone()
        if existing is not None:
            raise ProviderRecoveryError("Supervisor dispatch claim is already consumed")
        connection.execute(
            "INSERT INTO provider_dispatch_claims(attempt_id,task_id,claim_fingerprint,claimed_at) VALUES (?,?,?,?)",
            (attempt_id, identity.task_id, row.input_fingerprint, observed),
        )
        connection.commit()
    except sqlite3.IntegrityError as error:
        connection.rollback()
        raise ProviderRecoveryError("Supervisor dispatch claim is already consumed") from error
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id, context=context, now=now)


def read_supervisor_dispatch_claim(
    repository: RepositoryIdentity, identity: TaskIdentity, context: RecoveryContext, *, attempt_id: str,
) -> SupervisorDispatchClaimState:
    """Read the closed one-shot dispatch disposition without state mutation."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    path = database_path(repository)
    if not path.exists():
        raise ProviderRecoveryError("Supervisor dispatch claim is unavailable")
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    except (OSError, sqlite3.DatabaseError) as error:
        raise ProviderRecoveryError("Supervisor dispatch claim is unavailable") from error
    try:
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        if row.role is not ProviderRole.SUPERVISOR:
            raise ProviderRecoveryError("Supervisor dispatch claim has drifted")
        return _dispatch_claim_state(connection, identity, row)
    finally:
        connection.close()


def _dispatch_claim_state(connection, identity: TaskIdentity, row: ProviderAttempt) -> SupervisorDispatchClaimState:
    claim = connection.execute("SELECT task_id,claim_fingerprint FROM provider_dispatch_claims WHERE attempt_id=?", (row.attempt_id,)).fetchone()
    if claim is None:
        return SupervisorDispatchClaimState.UNCLAIMED
    if tuple(claim) != (identity.task_id, row.input_fingerprint):
        raise ProviderRecoveryError("Supervisor dispatch claim has drifted")
    return SupervisorDispatchClaimState.CLAIMED


def record_external_turn(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    session_identity: str,
    external_turn_identity: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Record an external turn only after its session checkpoint is durable."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_token(session_identity, "session identity")
    _require_token(external_turn_identity, "external turn identity")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        authorization_fingerprint = _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.state is AttemptState.DISPATCHED and (row.session_identity, row.external_turn_identity) == (session_identity, external_turn_identity):
            _require_session_checkpoint(connection, identity.task_id, attempt_id, session_identity, context, authorization_fingerprint)
            connection.commit()
            return row
        if row.state is not AttemptState.PREPARED or row.session_identity != session_identity:
            raise ProviderRecoveryError("external turn identity cannot be replayed for this attempt")
        _require_session_checkpoint(connection, identity.task_id, attempt_id, session_identity, context, authorization_fingerprint)
        connection.execute(
            "UPDATE provider_attempts SET external_turn_identity = ?, state = ? WHERE attempt_id = ?",
            (external_turn_identity, AttemptState.DISPATCHED.value, attempt_id),
        )
        _checkpoint(connection, identity.task_id, row.role, "after-dispatch", attempt_id, context, authorization_fingerprint, observed)
        connection.commit()
    except sqlite3.IntegrityError as error:
        connection.rollback()
        raise ProviderRecoveryError("external turn identity conflicts with committed state") from error
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id)


def record_session_identity(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    session_identity: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Checkpoint a provider thread/session before creating an external turn."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_token(session_identity, "session identity")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        authorization_fingerprint = _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.state is not AttemptState.PREPARED:
            raise ProviderRecoveryError("session identity cannot be recorded for this attempt")
        if row.session_identity is not None and row.session_identity != session_identity:
            raise ProviderRecoveryError("session identity replay conflicts with committed state")
        _require_session_reuse_allowed(connection, row, session_identity)
        if row.session_identity is None:
            connection.execute("UPDATE provider_attempts SET session_identity = ? WHERE attempt_id = ?", (session_identity, attempt_id))
        checkpoint = connection.execute(
            "SELECT task_id, session_identity, identity_fingerprint FROM provider_session_checkpoints WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        expected = (identity.task_id, session_identity, _checkpoint_fingerprint(context, authorization_fingerprint))
        if checkpoint is None:
            connection.execute(
                "INSERT INTO provider_session_checkpoints(attempt_id, task_id, session_identity, identity_fingerprint, created_at) VALUES (?, ?, ?, ?, ?)",
                (attempt_id, *expected, observed),
            )
        elif checkpoint != expected:
            raise ProviderRecoveryError("session checkpoint replay conflicts with committed state")
        connection.commit()
    except sqlite3.IntegrityError as error:
        connection.rollback()
        raise ProviderRecoveryError("session identity conflicts with committed state") from error
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id)


def record_completed_output(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    output_pointer: str,
    completion_evidence_fingerprint: str,
    output_fingerprint: str = "",
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Persist a completed-output pointer, evidence, and immutable output binding."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_token(output_pointer, "output pointer")
    _require_fingerprint(completion_evidence_fingerprint, "completion evidence fingerprint")
    if output_fingerprint:
        _require_fingerprint(output_fingerprint, "output fingerprint")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        expected = (output_pointer, completion_evidence_fingerprint)
        binding = connection.execute(
            "SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row.state is AttemptState.COMPLETED:
            if (row.output_pointer, row.completion_evidence_fingerprint) != expected:
                raise ProviderRecoveryError("completed output replay conflicts with committed state")
            if binding is None:
                connection.execute(
                    "INSERT INTO provider_completion_outputs(attempt_id, output_fingerprint) VALUES (?, ?)",
                    (attempt_id, output_fingerprint),
                )
            elif binding[0] != output_fingerprint:
                raise ProviderRecoveryError("completed output replay conflicts with committed content")
        elif row.state is AttemptState.DISPATCHED:
            if binding is not None and binding[0] != output_fingerprint:
                raise ProviderRecoveryError("completed output conflicts with committed content")
            connection.execute(
                "UPDATE provider_attempts SET output_pointer = ?, completion_evidence_fingerprint = ?, state = ? WHERE attempt_id = ?",
                (*expected, AttemptState.COMPLETED.value, attempt_id),
            )
            if binding is None:
                connection.execute(
                    "INSERT INTO provider_completion_outputs(attempt_id, output_fingerprint) VALUES (?, ?)",
                    (attempt_id, output_fingerprint),
                )
        else:
            raise ProviderRecoveryError("completed output requires a dispatched provider turn")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id)


def record_invalid_output(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    output_pointer: str,
    output_fingerprint: str,
    reason_fingerprint: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Persist a rejected output separately and make the turn fail closed."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_token(output_pointer, "output pointer")
    _require_fingerprint(output_fingerprint, "output fingerprint")
    _require_fingerprint(reason_fingerprint, "invalid output reason fingerprint")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        existing = connection.execute(
            "SELECT output_fingerprint, reason_fingerprint FROM provider_invalid_outputs WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchall()
        expected = (output_fingerprint, reason_fingerprint)
        if expected in existing and row.state is AttemptState.AMBIGUOUS and row.output_pointer == output_pointer:
            connection.commit()
            return row
        if existing:
            raise ProviderRecoveryError("invalid output replay conflicts with committed state")
        if row.state is not AttemptState.DISPATCHED:
            raise ProviderRecoveryError("invalid output requires a dispatched provider turn")
        connection.execute(
            "UPDATE provider_attempts SET output_pointer = ?, state = ? WHERE attempt_id = ?",
            (output_pointer, AttemptState.AMBIGUOUS.value, attempt_id),
        )
        connection.execute(
            "INSERT INTO provider_invalid_outputs(task_id, attempt_id, output_fingerprint, reason_fingerprint, recorded_at) VALUES (?, ?, ?, ?, ?)",
            (identity.task_id, attempt_id, output_fingerprint, reason_fingerprint, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id)


def accept_supervisor_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    accepted_review_identity: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Record acceptance separately from the provider attempt and output evidence."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    _require_token(accepted_review_identity, "accepted review identity")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if _accepted_review_kind(connection, identity, row) != "generic":
            raise ProviderRecoveryError("generic supervisor acceptance requires generic review evidence")
        if row.role is ProviderRole.SUPERVISOR and row.state is AttemptState.ACCEPTED and row.accepted_review_identity == accepted_review_identity:
            _require_accepted_supervisor_review(connection, identity, row, context)
            connection.commit()
            return row
        if row.role is not ProviderRole.SUPERVISOR or row.state is not AttemptState.COMPLETED:
            raise ProviderRecoveryError("only a completed supervisor attempt can be accepted")
        selected = connection.execute("SELECT selected_profile_identity FROM provider_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
        if selected is None or selected[0] not in context.runtime_binding.supervisor_profile_identities:
            raise ProviderRecoveryError("accepted supervisor profile binding has drifted")
        connection.execute(
            "UPDATE provider_attempts SET accepted_review_identity = ?, state = ? WHERE attempt_id = ?",
            (accepted_review_identity, AttemptState.ACCEPTED.value, attempt_id),
        )
        connection.execute(
            "INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity, within_round_attempt, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest, review_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (accepted_review_identity, *_accepted_supervisor_review_values(identity, row, context)),
        )
        connection.commit()
    except sqlite3.IntegrityError as error:
        connection.rollback()
        raise ProviderRecoveryError("accepted review identity conflicts with committed state") from error
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return read_attempt(repository, identity, attempt_id, context=context, now=observed)


def invalidate_supervisor_attempt(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Invalidate an incomplete Supervisor result; recovery must use a fresh session."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.role is not ProviderRole.SUPERVISOR:
            raise ProviderRecoveryError("only a Supervisor attempt can be invalidated")
        if row.state is AttemptState.ACCEPTED:
            connection.commit()
            return row
        if row.state is not AttemptState.INVALIDATED:
            connection.execute("UPDATE provider_attempts SET state = ? WHERE attempt_id = ?", (AttemptState.INVALIDATED.value, attempt_id))
            row = replace(row, state=AttemptState.INVALIDATED)
        _persist_recovery_outcome(connection, attempt_id, RecoveryAction.FRESH_SUPERVISOR_SESSION, "partial-supervisor-review", observed)
        connection.execute(
            "INSERT INTO provider_recovery_events(task_id, attempt_id, recovery_action, observed_at) VALUES (?, ?, ?, ?)",
            (identity.task_id, attempt_id, RecoveryAction.FRESH_SUPERVISOR_SESSION.value, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return row


def record_supervisor_terminal_failure(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    failure_class: SupervisorTerminalFailureClass,
    outcome_source: SupervisorTerminalFailureSource,
    sdk_error_category: SupervisorTerminalFailureSdkCategory,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Durably invalidate one failed Supervisor SDK turn for failover.

    This intentionally does not create ``provider_invalid_outputs``: the
    terminal failure is an operational turn result, not rejected provider text.
    """

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    if type(failure_class) is not SupervisorTerminalFailureClass or outcome_source is not SupervisorTerminalFailureSource.SDK_TURN_FAILED or type(sdk_error_category) is not SupervisorTerminalFailureSdkCategory:
        raise ProviderRecoveryError("terminal failure projection is invalid")
    observed = _clock(now)
    blocker = f"terminal-failure:{outcome_source.value}:{failure_class.value}:{sdk_error_category.value}"
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.role is not ProviderRole.SUPERVISOR or row.external_turn_identity is None:
            raise ProviderRecoveryError("terminal failure requires a dispatched Supervisor turn")
        if row.state is AttemptState.INVALIDATED:
            outcome = _read_recovery_outcome(connection, attempt_id)
            if outcome != _PersistedRecoveryOutcome(RecoveryAction.FRESH_SUPERVISOR_SESSION, blocker):
                raise ProviderRecoveryError("terminal failure conflicts with committed state")
            connection.commit()
            return row
        if row.state is not AttemptState.DISPATCHED:
            raise ProviderRecoveryError("terminal failure requires an unsettled Supervisor turn")
        if connection.execute("SELECT 1 FROM provider_invalid_outputs WHERE attempt_id = ?", (attempt_id,)).fetchone() is not None:
            raise ProviderRecoveryError("terminal failure conflicts with invalid output")
        connection.execute("UPDATE provider_attempts SET state = ? WHERE attempt_id = ?", (AttemptState.INVALIDATED.value, attempt_id))
        row = replace(row, state=AttemptState.INVALIDATED)
        _persist_recovery_outcome(connection, attempt_id, RecoveryAction.FRESH_SUPERVISOR_SESSION, blocker, observed)
        connection.execute(
            "INSERT INTO provider_recovery_events(task_id, attempt_id, recovery_action, observed_at) VALUES (?, ?, ?, ?)",
            (identity.task_id, attempt_id, RecoveryAction.FRESH_SUPERVISOR_SESSION.value, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return row


def read_supervisor_terminal_failure(
    repository: RepositoryIdentity, identity: TaskIdentity, attempt_id: str,
) -> SupervisorTerminalFailure | None:
    """Read only the fixed public-safe failure projection for one attempt."""

    _validate_task(identity)
    _require_token(attempt_id, "attempt identity")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        outcome = _read_recovery_outcome(connection, attempt_id)
        return _terminal_failure_from_outcome(row.state, outcome)
    except ValueError:
        raise ProviderRecoveryError("terminal failure projection is invalid") from None
    finally:
        connection.close()


def _terminal_failure_from_outcome(
    state: AttemptState, outcome: _PersistedRecoveryOutcome | None,
) -> SupervisorTerminalFailure | None:
    """Decode only the fixed, durable terminal-failure projection."""

    if state is not AttemptState.INVALIDATED or outcome is None or outcome.action is not RecoveryAction.FRESH_SUPERVISOR_SESSION or outcome.blocker is None:
        return None
    parts = outcome.blocker.split(":")
    if len(parts) != 4 or parts[0] != "terminal-failure":
        return None
    _, source, failure, category = parts
    try:
        return SupervisorTerminalFailure(
            SupervisorTerminalFailureClass(failure),
            SupervisorTerminalFailureSource(source),
            SupervisorTerminalFailureSdkCategory(category),
        )
    except ValueError:
        raise ProviderRecoveryError("terminal failure projection is invalid") from None


def record_supervisor_accounting_blocker(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    blocker: SupervisorAccountingBlocker,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> RecoveryProjection:
    """Terminally retain a schema-valid accounting decision without failover."""

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    if type(blocker) is not SupervisorAccountingBlocker:
        raise ProviderRecoveryError("accounting blocker is invalid")
    observed = _clock(now)
    action = RecoveryAction.BLOCKED_PROVIDER_ACCOUNTING
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if row.role is not ProviderRole.SUPERVISOR or row.external_turn_identity is None:
            raise ProviderRecoveryError("accounting blocker requires a dispatched Supervisor turn")
        if row.state is AttemptState.BLOCKED:
            outcome = _read_recovery_outcome(connection, attempt_id)
            if outcome != _PersistedRecoveryOutcome(action, blocker.value):
                raise ProviderRecoveryError("accounting blocker conflicts with committed state")
            connection.commit()
            return _projection(row, action, blocker.value)
        if row.state is not AttemptState.DISPATCHED:
            raise ProviderRecoveryError("accounting blocker requires an unsettled Supervisor turn")
        if connection.execute("SELECT 1 FROM provider_invalid_outputs WHERE attempt_id = ?", (attempt_id,)).fetchone() is not None:
            raise ProviderRecoveryError("accounting blocker conflicts with invalid output")
        connection.execute("UPDATE provider_attempts SET state = ? WHERE attempt_id = ?", (AttemptState.BLOCKED.value, attempt_id))
        row = replace(row, state=AttemptState.BLOCKED)
        _persist_recovery_outcome(connection, attempt_id, action, blocker.value, observed)
        connection.execute(
            "INSERT INTO provider_recovery_events(task_id, attempt_id, recovery_action, observed_at) VALUES (?, ?, ?, ?)",
            (identity.task_id, attempt_id, action.value, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return _projection(row, action, blocker.value)


def block_session_without_turn(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> RecoveryProjection:
    """Terminally reconcile a real session that never reached a turn.

    A persisted session proves that an external boundary was entered, but it
    must not make the bounded sequence resumable when no external turn was
    ever checkpointed.  The terminal record deliberately retains the real
    session identity while retaining a null turn identity and no output.
    """

    _validate_task(identity)
    _validate_context(identity, context)
    _require_token(attempt_id, "attempt identity")
    observed = _clock(now)
    action = RecoveryAction.BLOCKED_AMBIGUOUS_TURN
    blocker = "session-without-turn"
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        authorization_fingerprint = _require_persisted_health_authorization(
            connection, attempt_id, context, row.role, row.selected_profile_identity, observed,
        )
        if row.role is not ProviderRole.SUPERVISOR:
            raise ProviderRecoveryError("only a Supervisor session can be blocked before a turn")
        if row.session_identity is None or row.external_turn_identity is not None:
            raise ProviderRecoveryError("session-without-turn reconciliation requires exactly one session checkpoint")
        _require_session_checkpoint(
            connection, identity.task_id, attempt_id, row.session_identity, context, authorization_fingerprint,
        )
        if row.state is AttemptState.BLOCKED:
            outcome = _read_recovery_outcome(connection, attempt_id)
            if outcome != _PersistedRecoveryOutcome(action, blocker):
                raise ProviderRecoveryError("session-without-turn reconciliation conflicts with committed state")
            connection.commit()
            return _projection(row, action, blocker)
        if row.state is not AttemptState.PREPARED:
            raise ProviderRecoveryError("session-without-turn reconciliation requires a prepared attempt")
        connection.execute(
            "UPDATE provider_attempts SET state = ? WHERE attempt_id = ?",
            (AttemptState.BLOCKED.value, attempt_id),
        )
        row = replace(row, state=AttemptState.BLOCKED)
        _persist_recovery_outcome(connection, attempt_id, action, blocker, observed)
        connection.execute(
            "INSERT INTO provider_recovery_events(task_id, attempt_id, recovery_action, observed_at) VALUES (?, ?, ?, ?)",
            (identity.task_id, attempt_id, action.value, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return _projection(row, action, blocker)


def recover_attempt(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    attempt_id: str,
    verified_completion_evidence: str | None = None,
    max_attempts: int,
    lease: TransitionLease | None = None,
    now: int | None = None,
) -> RecoveryProjection:
    """Return one idempotent recovery decision without dispatching a provider turn.

    A persisted external turn without independently verified completion is
    always ambiguous.  The only exception is a stale Supervisor lease, which
    invalidates partial output and requires a fresh review session; a stale
    Worker lease remains local to its task and blocks that task alone.
    """

    _validate_task(identity)
    _require_token(attempt_id, "attempt identity")
    if not isinstance(max_attempts, int) or max_attempts < 1:
        raise ProviderRecoveryError("attempt limit is invalid")
    if verified_completion_evidence is not None:
        _require_fingerprint(verified_completion_evidence, "verified completion evidence")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        if not _context_matches(connection, identity, attempt_id, context):
            connection.rollback()
            return _projection(row, RecoveryAction.BLOCKED_IDENTITY_DRIFT, "identity-drift")
        _validate_context(identity, context)
        authorization_fingerprint = _require_persisted_health_authorization(connection, attempt_id, context, row.role, row.selected_profile_identity, observed)
        if _accepted_review_kind(connection, identity, row) == "invalid":
            raise ProviderRecoveryError("accepted supervisor review is invalid")
        if _accepted_review_kind(connection, identity, row) == "generic" and row.state is AttemptState.ACCEPTED:
            _require_accepted_supervisor_review(connection, identity, row, context)
        if row.state is AttemptState.PREPARED and row.session_identity is not None:
            try:
                _require_session_checkpoint(connection, identity.task_id, attempt_id, row.session_identity, context, authorization_fingerprint)
            except ProviderRecoveryError:
                connection.rollback()
                return _projection(row, RecoveryAction.BLOCKED_AMBIGUOUS_TURN, "session-checkpoint-unavailable")
        action, blocker, next_state = _recovery_outcome(
            connection,
            row,
            verified_completion_evidence=verified_completion_evidence,
            max_attempts=max_attempts,
            observed=observed,
        )
        if row.state is AttemptState.ACCEPTED and row.output_pointer is not None and row.output_pointer.startswith("diff-review:"):
            _stale_unvalidated_diff_review(connection, identity, row)
            row = replace(row, state=AttemptState.INVALIDATED, accepted_review_identity=None)
        if next_state is not None and next_state is not row.state:
            connection.execute("UPDATE provider_attempts SET state = ? WHERE attempt_id = ?", (next_state.value, attempt_id))
            row = replace(row, state=next_state)
        if blocker is not None:
            _persist_recovery_outcome(connection, attempt_id, action, blocker, observed)
        connection.execute(
            "INSERT INTO provider_recovery_events(task_id, attempt_id, recovery_action, observed_at) VALUES (?, ?, ?, ?)",
            (identity.task_id, attempt_id, action.value, observed),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return _projection(row, action, blocker)


def read_attempt(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    attempt_id: str,
    *,
    context: RecoveryContext | None = None,
    now: int | None = None,
) -> ProviderAttempt:
    """Read a persisted attempt without exposing it through an owner report."""

    _validate_task(identity)
    _require_token(attempt_id, "attempt identity")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        kind = _accepted_review_kind(connection, identity, row)
        if kind == "invalid":
            raise ProviderRecoveryError("accepted supervisor review is invalid")
        if kind == "generic" and row.state is AttemptState.ACCEPTED:
            if not isinstance(context, RecoveryContext) or not _context_matches(connection, identity, attempt_id, context):
                raise ProviderRecoveryError("accepted supervisor review requires exact recovery context")
            _validate_context(identity, context)
            _require_persisted_health_authorization(
                connection, attempt_id, context, row.role, row.selected_profile_identity, _clock(now),
            )
            _require_accepted_supervisor_review(connection, identity, row, context)
        return row
    finally:
        connection.close()


def _accepted_supervisor_review_values(
    identity: TaskIdentity,
    row: ProviderAttempt,
    context: RecoveryContext,
) -> tuple[object, ...]:
    return (
        identity.task_id,
        row.attempt_id,
        row.completion_evidence_fingerprint,
        *context.runtime_binding.columns(),
        row.selected_profile_identity,
        0,
        *context.runtime_binding.complete_columns()[4:],
        0,
    )


def _accepted_review_kind(connection, identity: TaskIdentity, row: ProviderAttempt) -> str:
    """Classify an accepted Supervisor from immutable review relationships only."""

    if row.role is not ProviderRole.SUPERVISOR:
        return "generic"
    plan = connection.execute(
        "SELECT review_attempt_id FROM plan_review_attempts WHERE provider_attempt_id = ? AND task_id = ?",
        (row.attempt_id, identity.task_id),
    ).fetchone()
    diff = connection.execute(
        "SELECT diff_review_attempt_id FROM diff_review_attempts WHERE provider_attempt_id = ? AND task_id = ?",
        (row.attempt_id, identity.task_id),
    ).fetchone()
    if plan is not None and diff is not None:
        return "invalid"
    if plan is not None:
        if row.state is not AttemptState.ACCEPTED:
            return "plan"
        return "plan" if (
            row.accepted_review_identity == plan[0]
            and row.output_pointer == f"plan-review:{plan[0]}"
        ) else "invalid"
    if diff is not None:
        if row.state is not AttemptState.ACCEPTED:
            return "diff"
        return "diff" if (
            row.accepted_review_identity == diff[0]
            and row.output_pointer == f"diff-review:{diff[0]}"
        ) else "invalid"
    if (row.output_pointer or "").startswith(("plan-review:", "diff-review:")):
        return "invalid"
    return "generic"


def _require_accepted_supervisor_review(
    connection,
    identity: TaskIdentity,
    row: ProviderAttempt,
    context: RecoveryContext,
) -> None:
    if (
        row.role is not ProviderRole.SUPERVISOR
        or row.state is not AttemptState.ACCEPTED
        or row.accepted_review_identity is None
        or row.completion_evidence_fingerprint is None
    ):
        raise ProviderRecoveryError("accepted supervisor review is invalid")
    persisted = connection.execute(
        "SELECT task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity, within_round_attempt, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest, review_epoch FROM accepted_provider_reviews WHERE accepted_review_identity = ?",
        (row.accepted_review_identity,),
    ).fetchone()
    if persisted != _accepted_supervisor_review_values(identity, row, context):
        raise ProviderRecoveryError("accepted supervisor review has drifted")


def _recovery_outcome(connection, row: ProviderAttempt, *, verified_completion_evidence: str | None, max_attempts: int, observed: int):
    if row.state is AttemptState.ACCEPTED:
        if row.output_pointer is not None and row.output_pointer.startswith("diff-review:"):
            return RecoveryAction.FRESH_SUPERVISOR_SESSION, "candidate-review-revalidation-required", AttemptState.INVALIDATED
        return RecoveryAction.ACCEPTED_REVIEW, None, None
    if row.state in {AttemptState.COMPLETED, AttemptState.AMBIGUOUS} and row.completion_evidence_fingerprint is not None:
        if verified_completion_evidence == row.completion_evidence_fingerprint:
            return RecoveryAction.CONSUME_VERIFIED_OUTPUT, None, (
                AttemptState.COMPLETED if row.state is AttemptState.AMBIGUOUS else None
            )
        return RecoveryAction.BLOCKED_AMBIGUOUS_TURN, "completion-evidence-unverified", (
            AttemptState.AMBIGUOUS if row.state is AttemptState.COMPLETED else None
        )
    outcome = _read_recovery_outcome(connection, row.attempt_id)
    if row.state is AttemptState.BLOCKED and outcome is not None:
        return outcome.action, outcome.blocker, None
    if row.state is AttemptState.AMBIGUOUS:
        if outcome is not None:
            return outcome.action, outcome.blocker, None
        return RecoveryAction.BLOCKED_AMBIGUOUS_TURN, "external-turn-ambiguous", None
    if row.state is AttemptState.INVALIDATED:
        return (RecoveryAction.FRESH_SUPERVISOR_SESSION, "supervisor-session-invalidated", None) if outcome is None else (outcome.action, outcome.blocker, None)
    if row.state is AttemptState.PREPARED:
        if row.session_identity is not None:
            if row.process_lease_expires_at <= observed:
                if row.role is ProviderRole.WORKER:
                    return RecoveryAction.BLOCKED_STALE_WORKER, "stale-worker-process-lease", AttemptState.BLOCKED
                if row.role is ProviderRole.SUPERVISOR:
                    return RecoveryAction.FRESH_SUPERVISOR_SESSION, "stale-supervisor-process-lease", AttemptState.INVALIDATED
            return RecoveryAction.RESUME_SAME_SESSION, None, None
        count = connection.execute(
            "SELECT COUNT(*) FROM provider_attempts WHERE task_id = ? AND provider_role = ?",
            (row.task_id, row.role.value),
        ).fetchone()[0]
        if count >= max_attempts:
            return RecoveryAction.BLOCKED_RETRY_LIMIT, "retry-limit-reached", AttemptState.BLOCKED
        return RecoveryAction.RETRY, None, None
    if row.state is not AttemptState.DISPATCHED:
        raise ProviderRecoveryError("provider attempt state is invalid")
    if row.process_lease_expires_at <= observed:
        if row.role is ProviderRole.WORKER:
            return RecoveryAction.BLOCKED_STALE_WORKER, "stale-worker-process-lease", AttemptState.BLOCKED
        if row.role is ProviderRole.SUPERVISOR:
            return RecoveryAction.FRESH_SUPERVISOR_SESSION, "stale-supervisor-process-lease", AttemptState.INVALIDATED
    return RecoveryAction.BLOCKED_AMBIGUOUS_TURN, "external-turn-ambiguous", AttemptState.AMBIGUOUS


def _stale_unvalidated_diff_review(connection, identity: TaskIdentity, row: ProviderAttempt) -> None:
    """Prevent generic recovery from reviving a candidate-bound review unaudited."""

    connection.execute("DELETE FROM accepted_provider_reviews WHERE attempt_id = ?", (row.attempt_id,))
    connection.execute("UPDATE provider_attempts SET state = ?, accepted_review_identity = NULL WHERE attempt_id = ? AND state = ?", (AttemptState.INVALIDATED.value, row.attempt_id, AttemptState.ACCEPTED.value))
    connection.execute("UPDATE diff_review_attempts SET state = 'recorded', accepted_review_identity = NULL WHERE task_id = ? AND provider_attempt_id = ? AND state = 'accepted'", (identity.task_id, row.attempt_id))


def _projection(row: ProviderAttempt, action: RecoveryAction, blocker: str | None) -> RecoveryProjection:
    return RecoveryProjection(
        row.attempt_id,
        row.role,
        row.state,
        row.process_lease_id,
        row.session_identity,
        row.external_turn_identity,
        row.output_pointer is not None and row.completion_evidence_fingerprint is not None,
        row.accepted_review_identity,
        blocker,
        action,
    )


def _read_recovery_outcome(connection, attempt_id: str) -> _PersistedRecoveryOutcome | None:
    row = connection.execute(
        "SELECT recovery_action, blocker FROM provider_recovery_outcomes WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        return _PersistedRecoveryOutcome(RecoveryAction(row[0]), row[1])
    except (TypeError, ValueError) as error:
        raise ProviderRecoveryError("persisted recovery outcome is malformed") from error


def _persist_recovery_outcome(
    connection, attempt_id: str, action: RecoveryAction, blocker: str, observed: int
) -> None:
    existing = connection.execute(
        "SELECT recovery_action, blocker FROM provider_recovery_outcomes WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    expected = (action.value, blocker)
    if existing is None:
        connection.execute(
            "INSERT INTO provider_recovery_outcomes(attempt_id, recovery_action, blocker, recorded_at) VALUES (?, ?, ?, ?)",
            (attempt_id, *expected, observed),
        )
    elif existing != expected:
        raise ProviderRecoveryError("recovery outcome conflicts with committed state")


def _attempt_row(connection, task_id: str, attempt_id: str) -> ProviderAttempt:
    row = connection.execute(
        "SELECT attempt_id, task_id, provider_role, attempt_number, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint, accepted_review_identity, state, selected_profile_identity FROM provider_attempts WHERE task_id = ? AND attempt_id = ?",
        (task_id, attempt_id),
    ).fetchone()
    if row is None:
        raise ProviderRecoveryError("provider attempt is unavailable")
    try:
        return ProviderAttempt(row[0], row[1], ProviderRole(row[2]), *row[3:12], AttemptState(row[12]), row[13])
    except (TypeError, ValueError) as error:
        raise ProviderRecoveryError("provider attempt is malformed") from error


def _checkpoint(connection, task_id: str, role: ProviderRole, phase: str, attempt_id: str, context: RecoveryContext, authorization_fingerprint: str, observed: int) -> None:
    checkpoint_id = f"{attempt_id}:{phase}"
    connection.execute(
        "INSERT INTO provider_checkpoints(checkpoint_id, task_id, provider_role, checkpoint_phase, attempt_id, identity_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (checkpoint_id, task_id, role.value, phase, attempt_id, _checkpoint_fingerprint(context, authorization_fingerprint), observed),
    )


def _persist_context(connection, attempt_id: str, context: RecoveryContext) -> None:
    existing = connection.execute(
        "SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest FROM provider_attempt_contexts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    expected = (context.task_id, *_context_values(context))
    if existing is None:
        connection.execute(
        "INSERT INTO provider_attempt_contexts(attempt_id, task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (attempt_id, *expected),
        )
    elif existing != expected:
        raise ProviderRecoveryError("recovery identity context has drifted")


def _context_matches(connection, identity: TaskIdentity, attempt_id: str, context: object) -> bool:
    """Compare all resume identities without exposing their raw values."""

    if not isinstance(context, RecoveryContext) or context.task_id != identity.task_id:
        return False
    existing = connection.execute(
        "SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest FROM provider_attempt_contexts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    expected = (identity.task_id, *_context_values(context))
    return existing == expected


def _context_values(context: RecoveryContext) -> tuple[object, ...]:
    return (
        context.repository_fingerprint,
        context.worktree_fingerprint,
        context.branch_fingerprint,
        context.base_fingerprint,
        context.candidate_fingerprint,
        context.policy_fingerprint,
        context.deployment_fingerprint,
        *context.runtime_binding.complete_columns(),
    )


def _selected_profile_identity(context: RecoveryContext, role: ProviderRole, requested: str | None = None) -> str:
    """Persist the one exact configured profile selected for this role's turn."""

    selected = context.runtime_binding.worker_profile_identity if role is not ProviderRole.SUPERVISOR else context.runtime_binding.supervisor_profile_identities[0]
    if requested is not None:
        selected = requested
    allowed = (context.runtime_binding.worker_profile_identity,) if role is not ProviderRole.SUPERVISOR else context.runtime_binding.supervisor_profile_identities
    if type(selected) is not str or selected not in allowed:
        raise ProviderRecoveryError("selected provider profile identity is invalid")
    return selected


def _require_health_authorization(context: RecoveryContext, role: ProviderRole, profile_identity: str, observed: int):
    """Fail before SQLite is opened whenever dispatch is health-bound."""

    values = (context.health_contract_commit, context.shadow_case_id, context.health_receipt)
    if context.health_contract_commit is None or context.shadow_case_id is None or context.health_receipt is None:
        raise ProviderRecoveryError("provider health authorization is incomplete")
    try:
        from .provider_health import ProviderHealthReceipt, required_provider_selections
        receipt = context.health_receipt
        if type(receipt) is not ProviderHealthReceipt:
            raise ProviderRecoveryError("provider health authorization is invalid")
        receipt.authorize(
            context.runtime_binding, role, profile_identity,
            contract_commit=context.health_contract_commit,
            candidate_sha=context.candidate_sha, case_id=context.shadow_case_id, now=observed,
        )
        if receipt.selection_ordinal >= len(required_provider_selections(context.runtime_binding)) or required_provider_selections(context.runtime_binding)[receipt.selection_ordinal] != (receipt.selection_ordinal, role, profile_identity):
            raise ProviderRecoveryError("provider health authorization is invalid")
        return receipt
    except ProviderRecoveryError:
        raise
    except Exception as error:
        raise ProviderRecoveryError("provider health authorization is invalid") from error


def _require_persisted_context(connection, attempt_id: str, context: RecoveryContext) -> None:
    _persist_context(connection, attempt_id, context)


def _health_authorization_values(receipt, role: ProviderRole, profile_identity: str) -> tuple[object, ...]:
    return (
        receipt.contract_commit, receipt.candidate_sha, receipt.case_id,
        receipt.receipt_digest, receipt.selection_ordinal,
        receipt.observation.fresh_until, receipt.observation.health_contract_identity,
        role.value, profile_identity,
    )


def _health_authorization_fingerprint(attempt_id: str, values: tuple[object, ...]) -> str:
    if type(attempt_id) is not str or any(type(value) not in {str, int, type(None)} for value in values):
        raise ProviderRecoveryError("provider health authorization is invalid")
    return _fingerprint("\x00".join((attempt_id, *("" if value is None else str(value) for value in values))))


def _persist_health_authorization(connection, attempt_id: str, receipt, role: ProviderRole, profile_identity: str) -> str:
    expected = _health_authorization_values(receipt, role, profile_identity)
    existing = connection.execute(
        "SELECT contract_commit, candidate_sha, case_id, receipt_digest, selection_ordinal, fresh_until, health_contract_identity, provider_role, profile_identity FROM provider_attempt_health_authorizations WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if existing is not None:
        raise ProviderRecoveryError("provider health authorization already exists")
    connection.execute(
        "INSERT INTO provider_attempt_health_authorizations(attempt_id, contract_commit, candidate_sha, case_id, receipt_digest, selection_ordinal, fresh_until, health_contract_identity, provider_role, profile_identity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (attempt_id, *expected),
    )
    fingerprint = _health_authorization_fingerprint(attempt_id, expected)
    connection.execute(
        "INSERT INTO provider_attempt_health_seals(attempt_id, authorization_fingerprint) VALUES (?, ?)",
        (attempt_id, fingerprint),
    )
    return fingerprint


def _require_persisted_health_authorization(connection, attempt_id: str, context: RecoveryContext, role: ProviderRole, profile_identity: str, observed: int) -> str:
    existing = connection.execute(
        "SELECT authorization.contract_commit, authorization.candidate_sha, authorization.case_id, authorization.receipt_digest, authorization.selection_ordinal, authorization.fresh_until, authorization.health_contract_identity, authorization.provider_role, authorization.profile_identity, seals.authorization_fingerprint FROM provider_attempt_health_authorizations AS authorization LEFT JOIN provider_attempt_health_seals AS seals ON seals.attempt_id = authorization.attempt_id WHERE authorization.attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if (
        type(existing) is not tuple or len(existing) != 10
        or type(existing[0]) is not str or not _COMMIT.fullmatch(existing[0])
        or (existing[1] is not None and (type(existing[1]) is not str or not _COMMIT.fullmatch(existing[1])))
        or type(existing[2]) is not str or not _TOKEN.fullmatch(existing[2])
        or type(existing[3]) is not str or not _DIGEST.fullmatch(existing[3])
        or type(existing[4]) is not int or existing[4] < 0
        or type(existing[5]) is not int or existing[5] <= observed
        or type(existing[6]) is not str or not _DIGEST.fullmatch(existing[6])
        or existing[7] != role.value or existing[8] != profile_identity
        or existing[1] != context.candidate_sha
        or type(existing[9]) is not str or not _FINGERPRINT.fullmatch(existing[9])
        or existing[9] != _health_authorization_fingerprint(attempt_id, existing[:9])
    ):
        raise ProviderRecoveryError("provider health authorization is unavailable or has drifted")
    checkpoint = connection.execute(
        "SELECT task_id, provider_role, checkpoint_phase, identity_fingerprint FROM provider_checkpoints WHERE checkpoint_id = ?",
        (f"{attempt_id}:before-dispatch",),
    ).fetchone()
    if checkpoint != (context.task_id, role.value, "before-dispatch", _checkpoint_fingerprint(context, existing[9])):
        raise ProviderRecoveryError("provider health authorization is unavailable or has drifted")
    return existing[9]


def _require_session_checkpoint(
    connection, task_id: str, attempt_id: str, session_identity: str, context: RecoveryContext, authorization_fingerprint: str
) -> None:
    row = connection.execute(
        "SELECT task_id, session_identity, identity_fingerprint FROM provider_session_checkpoints WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row != (task_id, session_identity, _checkpoint_fingerprint(context, authorization_fingerprint)):
        raise ProviderRecoveryError("session checkpoint is unavailable or has drifted")


def _require_session_reuse_allowed(connection, row: ProviderAttempt, session_identity: str) -> None:
    """Permit cross-attempt reuse only for persistent Worker planning/execution sessions."""

    existing_roles = connection.execute(
        "SELECT provider_role FROM provider_attempts WHERE task_id = ? AND session_identity = ? AND attempt_id != ?",
        (row.task_id, session_identity, row.attempt_id),
    ).fetchall()
    reusable_roles = {ProviderRole.PLANNING.value, ProviderRole.WORKER.value}
    if existing_roles and (
        row.role.value not in reusable_roles or any(role[0] not in reusable_roles for role in existing_roles)
    ):
        raise ProviderRecoveryError("session identity cannot be reused across provider attempts")


def _validate_context(identity: TaskIdentity, context: RecoveryContext) -> None:
    if not isinstance(context, RecoveryContext) or context.task_id != identity.task_id:
        raise ProviderRecoveryError("recovery context does not match the task")
    for value, name in (
        (context.repository_fingerprint, "repository fingerprint"),
        (context.worktree_fingerprint, "worktree fingerprint"),
        (context.branch_fingerprint, "branch fingerprint"),
        (context.base_fingerprint, "base fingerprint"),
        (context.policy_fingerprint, "policy fingerprint"),
        (context.deployment_fingerprint, "deployment fingerprint"),
    ):
        _require_fingerprint(value, name)
    if context.candidate_fingerprint is not None:
        _require_fingerprint(context.candidate_fingerprint, "candidate fingerprint")
    if type(context.runtime_binding) is not RuntimeBinding:
        raise ProviderRecoveryError("resolved configuration binding is invalid")


def _validate_task(identity: object) -> None:
    if type(identity) is not TaskIdentity:
        raise ProviderRecoveryError("task identity is invalid")


def _require_role(value: object) -> None:
    if not isinstance(value, ProviderRole):
        raise ProviderRecoveryError("provider role is invalid")


def _require_token(value: object, name: str) -> None:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ProviderRecoveryError(f"{name} is invalid")


def _require_fingerprint(value: object, name: str) -> None:
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise ProviderRecoveryError(f"{name} is invalid")


def _require_future_time(value: object, now: int | None) -> None:
    if type(value) is not int or value <= _clock(now):
        raise ProviderRecoveryError("process lease expiry is invalid")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _context_fingerprint(context: RecoveryContext) -> str:
    return _fingerprint("\x00".join("" if value is None else str(value) for value in _context_values(context)))


def _checkpoint_fingerprint(context: RecoveryContext, authorization_fingerprint: str) -> str:
    if type(authorization_fingerprint) is not str or not _FINGERPRINT.fullmatch(authorization_fingerprint):
        raise ProviderRecoveryError("provider health authorization is invalid")
    return _fingerprint(f"{_context_fingerprint(context)}\x00{authorization_fingerprint}")


def _clock(now: int | None) -> int:
    if now is not None and type(now) is not int:
        raise ProviderRecoveryError("recovery clock is invalid")
    return int(time.time()) if now is None else now
