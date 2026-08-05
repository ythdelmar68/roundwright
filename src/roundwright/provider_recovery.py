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
from .state import StateError, TaskIdentity, _open_writable_connection, _require_matching_task, record_runtime_binding, require_runtime_binding


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


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class RecoveryContext:
    """Opaque identity evidence that must still agree before recovery resumes."""

    task_id: str
    repository_fingerprint: str
    worktree_fingerprint: str
    branch_fingerprint: str
    base_fingerprint: str
    candidate_fingerprint: str | None
    policy_fingerprint: str
    deployment_fingerprint: str
    runtime_binding: RuntimeBinding

    @classmethod
    def for_task(
        cls,
        identity: TaskIdentity,
        *,
        candidate_sha: str | None,
        policy_fingerprint: str,
        deployment_fingerprint: str,
        runtime_binding: RuntimeBinding,
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
            policy_fingerprint,
            deployment_fingerprint,
            runtime_binding,
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
class _PersistedRecoveryOutcome:
    action: RecoveryAction
    blocker: str | None


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
            if (
                row.role is not role
                or row.process_lease_id != process_lease_id
                or row.process_lease_expires_at != process_lease_expires_at
                or row.input_fingerprint != input_fingerprint
                or row.selected_profile_identity != _selected_profile_identity(context, role, selected_profile_identity)
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
            (attempt_id, identity.task_id, role.value, number, process_lease_id, process_lease_expires_at, input_fingerprint, AttemptState.PREPARED.value, _selected_profile_identity(context, role, selected_profile_identity)),
        )
        _persist_context(connection, attempt_id, context)
        _checkpoint(connection, identity.task_id, role, "before-dispatch", attempt_id, context, observed)
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
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        if row.state is AttemptState.DISPATCHED and (row.session_identity, row.external_turn_identity) == (session_identity, external_turn_identity):
            _require_session_checkpoint(connection, identity.task_id, attempt_id, session_identity, context)
            connection.commit()
            return row
        if row.state is not AttemptState.PREPARED or row.session_identity != session_identity:
            raise ProviderRecoveryError("external turn identity cannot be replayed for this attempt")
        _require_session_checkpoint(connection, identity.task_id, attempt_id, session_identity, context)
        connection.execute(
            "UPDATE provider_attempts SET external_turn_identity = ?, state = ? WHERE attempt_id = ?",
            (external_turn_identity, AttemptState.DISPATCHED.value, attempt_id),
        )
        _checkpoint(connection, identity.task_id, row.role, "after-dispatch", attempt_id, context, _clock(now))
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
        expected = (identity.task_id, session_identity, _context_fingerprint(context))
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
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
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
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        _require_matching_task(connection, identity)
        _require_persisted_context(connection, attempt_id, context)
        row = _attempt_row(connection, identity.task_id, attempt_id)
        if row.role is ProviderRole.SUPERVISOR and row.state is AttemptState.ACCEPTED and row.accepted_review_identity == accepted_review_identity:
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
            "INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (accepted_review_identity, identity.task_id, attempt_id, row.completion_evidence_fingerprint, *context.runtime_binding.columns(), row.selected_profile_identity),
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
    return read_attempt(repository, identity, attempt_id)


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
        if row.state is AttemptState.PREPARED and row.session_identity is not None:
            try:
                _require_session_checkpoint(connection, identity.task_id, attempt_id, row.session_identity, context)
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


def read_attempt(repository: RepositoryIdentity, identity: TaskIdentity, attempt_id: str) -> ProviderAttempt:
    """Read a persisted attempt without exposing it through an owner report."""

    _validate_task(identity)
    _require_token(attempt_id, "attempt identity")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        return _attempt_row(connection, identity.task_id, attempt_id)
    finally:
        connection.close()


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


def _checkpoint(connection, task_id: str, role: ProviderRole, phase: str, attempt_id: str, context: RecoveryContext, observed: int) -> None:
    checkpoint_id = f"{attempt_id}:{phase}"
    connection.execute(
        "INSERT INTO provider_checkpoints(checkpoint_id, task_id, provider_role, checkpoint_phase, attempt_id, identity_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (checkpoint_id, task_id, role.value, phase, attempt_id, _context_fingerprint(context), observed),
    )


def _persist_context(connection, attempt_id: str, context: RecoveryContext) -> None:
    existing = connection.execute(
        "SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities FROM provider_attempt_contexts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    expected = (context.task_id, *_context_values(context))
    if existing is None:
        connection.execute(
        "INSERT INTO provider_attempt_contexts(attempt_id, task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (attempt_id, *expected),
        )
    elif existing != expected:
        raise ProviderRecoveryError("recovery identity context has drifted")


def _context_matches(connection, identity: TaskIdentity, attempt_id: str, context: object) -> bool:
    """Compare all resume identities without exposing their raw values."""

    if not isinstance(context, RecoveryContext) or context.task_id != identity.task_id:
        return False
    existing = connection.execute(
        "SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities FROM provider_attempt_contexts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    expected = (identity.task_id, *_context_values(context))
    return existing == expected


def _context_values(context: RecoveryContext) -> tuple[str | None, ...]:
    return (
        context.repository_fingerprint,
        context.worktree_fingerprint,
        context.branch_fingerprint,
        context.base_fingerprint,
        context.candidate_fingerprint,
        context.policy_fingerprint,
        context.deployment_fingerprint,
        *context.runtime_binding.columns(),
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


def _require_persisted_context(connection, attempt_id: str, context: RecoveryContext) -> None:
    _persist_context(connection, attempt_id, context)


def _require_session_checkpoint(
    connection, task_id: str, attempt_id: str, session_identity: str, context: RecoveryContext
) -> None:
    row = connection.execute(
        "SELECT task_id, session_identity, identity_fingerprint FROM provider_session_checkpoints WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row != (task_id, session_identity, _context_fingerprint(context)):
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
    return _fingerprint("\x00".join("" if value is None else value for value in _context_values(context)))


def _clock(now: int | None) -> int:
    if now is not None and type(now) is not int:
        raise ProviderRecoveryError("recovery clock is invalid")
    return int(time.time()) if now is None else now
