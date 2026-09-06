"""Lease-bound durable Phase 5 review, objective, and owner-control state."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .state import StateError, TaskIdentity, _open_writable_connection, _require_current_transition_lease, _require_matching_task

_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OWNER_ALLOWLIST = frozenset({"ythdelmar68"})


class ReviewLifecycleError(ValueError):
    """Raised when review lifecycle authority or durable state is invalid."""


class ReviewItemKind(StrEnum):
    PASS_FOLLOW_UP = "pass-follow-up"
    FINDING = "finding"


class ReviewItemSource(StrEnum):
    ACCEPTED_REVIEW = "accepted-review"
    SUPERVISOR_FINDING = "supervisor-finding"


class ReviewItemDisposition(StrEnum):
    PENDING = "pending"
    RESOLVED = "resolved"
    WAIVED = "waived"


class VerificationState(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    WAIVED = "waived"


class OwnerCommandKind(StrEnum):
    RESOLVE_REVIEW_ITEM = "resolve-review-item"
    WAIVE_REVIEW_ITEM = "waive-review-item"


class ObjectiveState(StrEnum):
    ACTIVE = "active"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


@dataclass(frozen=True)
class ReviewItem:
    item_id: str
    task_id: str
    review_identity: str
    candidate_sha: str
    source_attempt_id: str
    kind: ReviewItemKind
    source: ReviewItemSource
    content_digest: str
    destination: str
    blocking: bool
    created_at: int

    def __post_init__(self) -> None:
        if (not all(_token(v) for v in (self.item_id, self.task_id, self.review_identity, self.source_attempt_id, self.destination))
                or not _sha(self.candidate_sha) or not _digest(self.content_digest) or type(self.blocking) is not bool
                or type(self.created_at) is not int or self.created_at <= 0
                or type(self.kind) is not ReviewItemKind or type(self.source) is not ReviewItemSource):
            raise ReviewLifecycleError("review item is invalid")
        if (self.kind, self.source) not in {(ReviewItemKind.PASS_FOLLOW_UP, ReviewItemSource.ACCEPTED_REVIEW), (ReviewItemKind.FINDING, ReviewItemSource.SUPERVISOR_FINDING)}:
            raise ReviewLifecycleError("review item kind/source pairing is invalid")


@dataclass(frozen=True)
class WorkerObjective:
    objective_id: str
    task_id: str
    dispatch_sha: str
    provider_attempt_id: str
    retry_identity: str
    objective_digest: str
    state: ObjectiveState = ObjectiveState.ACTIVE
    result: "WorkerObjectiveResult | None" = None
    cancellation_reason_digest: str | None = None

    def __post_init__(self) -> None:
        if not all(_token(v) for v in (self.objective_id, self.task_id, self.provider_attempt_id, self.retry_identity)) or not _sha(self.dispatch_sha) or not _digest(self.objective_digest) or type(self.state) is not ObjectiveState:
            raise ReviewLifecycleError("Worker objective is invalid")
        if ((self.state is ObjectiveState.ACTIVE and (self.result is not None or self.cancellation_reason_digest is not None))
                or (self.state is ObjectiveState.COMPLETED and (type(self.result) is not WorkerObjectiveResult or self.cancellation_reason_digest is not None))
                or (self.state is ObjectiveState.CANCELLED and (self.result is not None or not _digest(self.cancellation_reason_digest)))):
            raise ReviewLifecycleError("Worker objective terminal state is invalid")

    @property
    def candidate_sha(self) -> str:
        """Compatibility alias for the SHA that was current at Worker dispatch."""

        return self.dispatch_sha


@dataclass(frozen=True)
class WorkerObjectiveResult:
    """The independently persisted output accepted for one Worker objective."""

    candidate_sha: str
    completion_evidence_fingerprint: str
    accepted_result_identity: str

    def __post_init__(self) -> None:
        if not all(_digest(value) for value in (self.completion_evidence_fingerprint, self.accepted_result_identity)) or not _sha(self.candidate_sha):
            raise ReviewLifecycleError("Worker objective result is invalid")


@dataclass(frozen=True)
class OwnerCommand:
    command_id: str
    task_id: str
    kind: OwnerCommandKind
    target_item_id: str
    candidate_sha: str
    command_digest: str
    idempotency_key: str
    owner_identity: str
    authority_grant_id: str

    def __post_init__(self) -> None:
        if (not all(_token(v) for v in (self.command_id, self.task_id, self.target_item_id, self.idempotency_key, self.owner_identity, self.authority_grant_id))
                or not _sha(self.candidate_sha) or not _digest(self.command_digest) or type(self.kind) is not OwnerCommandKind):
            raise ReviewLifecycleError("owner command is invalid")


@dataclass(frozen=True)
class ReviewItemProjection:
    item_id: str
    kind: ReviewItemKind
    disposition: ReviewItemDisposition
    verification: VerificationState
    blocking: bool
    destination: str


class ReviewLifecycleStore:
    """Phase 5 authority surface: each write requires exact task and lease state."""

    def record_review_item(self, repository: RepositoryIdentity, identity: TaskIdentity, item: ReviewItem, *, lease: object) -> ReviewItemProjection:
        if item.task_id != identity.task_id:
            raise ReviewLifecycleError("review item task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            _require_current_candidate(connection, identity, item.candidate_sha, lease)
            result = _record_review_item_connection(connection, identity, item)
            connection.commit()
            return result
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ReviewLifecycleError("review item conflicts with committed state") from error
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def start_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, *, lease: object) -> WorkerObjective:
        if objective.task_id != identity.task_id:
            raise ReviewLifecycleError("Worker objective task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            retry = _require_worker_dispatch(connection, identity, objective.provider_attempt_id, objective.dispatch_sha)
            if objective.retry_identity != retry:
                raise ReviewLifecycleError("Worker objective retry identity is not the durable attempt identity")
            expected = (objective.task_id, objective.dispatch_sha, objective.provider_attempt_id, retry, objective.objective_digest)
            row = connection.execute("SELECT task_id, dispatch_sha, provider_attempt_id, retry_identity, objective_digest, state, candidate_sha, completion_evidence_fingerprint, accepted_result_identity, terminal_reason_digest FROM worker_objective_records WHERE objective_id = ?", (objective.objective_id,)).fetchone()
            if row is None:
                connection.execute("INSERT INTO worker_objective_records(objective_id, task_id, dispatch_sha, provider_attempt_id, retry_identity, objective_digest, state, candidate_sha, completion_evidence_fingerprint, accepted_result_identity, terminal_reason_digest) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, NULL, NULL, NULL)", (objective.objective_id, *expected))
            elif tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective identity conflicts with committed state")
            connection.commit()
            return _objective_projection(objective.objective_id, *expected, *(row[5:] if row is not None else (ObjectiveState.ACTIVE.value, None, None, None, None)))
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ReviewLifecycleError("Worker objective conflicts with an existing attempt") from error
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, *, lease: object, result: WorkerObjectiveResult) -> WorkerObjective:
        if type(result) is not WorkerObjectiveResult:
            raise ReviewLifecycleError("objective completion is invalid")
        return self._terminal_objective(repository, identity, objective, lease, ObjectiveState.COMPLETED, result)

    def cancel_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, *, lease: object, reason_digest: str) -> WorkerObjective:
        if not _digest(reason_digest):
            raise ReviewLifecycleError("objective cancellation is invalid")
        return self._terminal_objective(repository, identity, objective, lease, ObjectiveState.CANCELLED, reason_digest)

    def cancel_objective_for_provider_attempt(self, repository: RepositoryIdentity, identity: TaskIdentity, *, provider_attempt_id: str, reason_digest: str, lease: object) -> WorkerObjective | None:
        """Terminalize the active objective attached to one recovered Worker turn."""

        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            objective = _cancel_objective_for_recovery_connection(connection, identity, provider_attempt_id, reason_digest)
            connection.commit()
            return objective
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def read_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, *, objective_id: str) -> WorkerObjective:
        """Reconstruct one durable objective and reject incomplete terminal evidence."""
        if not _token(objective_id):
            raise ReviewLifecycleError("Worker objective identity is invalid")
        connection = _open_writable_connection(repository)
        try:
            _require_matching_task(connection, identity)
            row = connection.execute("SELECT task_id, dispatch_sha, provider_attempt_id, retry_identity, objective_digest, state, candidate_sha, completion_evidence_fingerprint, accepted_result_identity, terminal_reason_digest FROM worker_objective_records WHERE objective_id = ?", (objective_id,)).fetchone()
            if row is None:
                raise ReviewLifecycleError("Worker objective is unavailable")
            objective = _objective_projection(objective_id, *row)
            if objective.state is ObjectiveState.COMPLETED:
                _require_worker_objective_result(connection, identity, objective.provider_attempt_id, objective.dispatch_sha, objective.result)
            elif objective.state is ObjectiveState.ACTIVE:
                _require_worker_objective_attempt(connection, identity, objective.provider_attempt_id, objective.dispatch_sha)
            return objective
        finally:
            connection.close()

    def queue_owner_command(self, repository: RepositoryIdentity, identity: TaskIdentity, command: OwnerCommand, *, lease: object) -> OwnerCommand:
        if command.task_id != identity.task_id:
            raise ReviewLifecycleError("owner command task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            _require_current_candidate(connection, identity, command.candidate_sha, lease)
            if not _owner_command_target(connection, identity, command.target_item_id, command.candidate_sha):
                raise ReviewLifecycleError("owner command target is stale or outside its scope")
            scope = _owner_scope_digest(command)
            grant = connection.execute("SELECT owner_identity, command_scope, task_id, candidate_sha, authority_digest, state FROM owner_authority_grants WHERE grant_id = ?", (command.authority_grant_id,)).fetchone()
            if not _valid_owner_grant(grant, command.owner_identity, command.kind.value, identity.task_id, command.candidate_sha):
                raise ReviewLifecycleError("owner command lacks a current allowlisted authority grant")
            expected = (command.task_id, command.kind.value, command.owner_identity, command.authority_grant_id, command.target_item_id, command.candidate_sha, command.command_digest, scope, command.idempotency_key)
            row = connection.execute("SELECT task_id, command_kind, owner_identity, authority_grant_id, target_item_id, candidate_sha, command_digest, scope_digest, idempotency_key FROM owner_command_records WHERE command_id = ?", (command.command_id,)).fetchone()
            if row is None:
                same = connection.execute("SELECT command_id, task_id, command_kind, owner_identity, authority_grant_id, target_item_id, candidate_sha, command_digest, scope_digest FROM owner_command_records WHERE idempotency_key = ?", (command.idempotency_key,)).fetchone()
                if same is not None and (same[0] != command.command_id or tuple(same[1:]) != expected[:-1]):
                    raise ReviewLifecycleError("owner command idempotency key conflicts with committed state")
                if same is None:
                    connection.execute("INSERT INTO owner_command_records(command_id, task_id, command_kind, owner_identity, authority_grant_id, target_item_id, candidate_sha, command_digest, scope_digest, idempotency_key, state, result_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL)", (command.command_id, *expected))
            elif tuple(row) != expected:
                raise ReviewLifecycleError("owner command identity conflicts with committed state")
            connection.commit()
            return command
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def consume_owner_command(self, repository: RepositoryIdentity, identity: TaskIdentity, *, command_id: str, lease: object, result_digest: str) -> ReviewItemProjection:
        if not _token(command_id) or not _digest(result_digest):
            raise ReviewLifecycleError("owner command consumption is invalid")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            row = connection.execute("SELECT commands.command_kind, commands.target_item_id, commands.candidate_sha, commands.state, commands.result_digest, commands.owner_identity, grants.command_scope, grants.task_id, grants.candidate_sha, grants.authority_digest, grants.state FROM owner_command_records AS commands JOIN owner_authority_grants AS grants ON grants.grant_id = commands.authority_grant_id WHERE commands.command_id = ? AND commands.task_id = ?", (command_id, identity.task_id)).fetchone()
            if row is None:
                raise ReviewLifecycleError("owner command is missing or outside its exact task")
            if not _valid_owner_grant(row[5:], row[5], row[0], identity.task_id, row[2]):
                raise ReviewLifecycleError("owner command authority is stale or no longer allowlisted")
            _require_current_candidate(connection, identity, row[2], lease)
            item = connection.execute("SELECT item_kind, blocker_state, disposition, verification_state, destination, resolved_command_id FROM review_item_records WHERE item_id = ? AND task_id = ?", (row[1], identity.task_id)).fetchone()
            if item is None:
                raise ReviewLifecycleError("owner command target is stale or outside its scope")
            if row[3] == "consumed":
                if row[4] != result_digest or item[5] != command_id:
                    raise ReviewLifecycleError("owner command terminal replay conflicts with committed state")
                connection.commit()
                return _projection(row[1], item[0], item[1], item[3], item[2], item[4])
            if row[3] != "pending" or item[2] != ReviewItemDisposition.PENDING.value:
                raise ReviewLifecycleError("owner command conflicts with an already terminal item")
            disposition = ReviewItemDisposition.RESOLVED if row[0] == OwnerCommandKind.RESOLVE_REVIEW_ITEM.value else ReviewItemDisposition.WAIVED
            verification = VerificationState.VERIFIED if disposition is ReviewItemDisposition.RESOLVED else VerificationState.WAIVED
            if connection.execute("UPDATE review_item_records SET disposition = ?, verification_state = ?, resolved_command_id = ? WHERE item_id = ? AND disposition = 'pending'", (disposition.value, verification.value, command_id, row[1])).rowcount != 1:
                raise ReviewLifecycleError("owner command could not claim the pending item")
            if connection.execute("UPDATE owner_command_records SET state = 'consumed', result_digest = ? WHERE command_id = ? AND state = 'pending'", (result_digest, command_id)).rowcount != 1:
                raise ReviewLifecycleError("owner command could not atomically consume its stored row")
            connection.commit()
            return _projection(row[1], item[0], item[1], verification.value, disposition.value, item[4])
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def render_owner_view(self, repository: RepositoryIdentity, *, task_id: str, candidate_sha: str) -> str:
        if not _token(task_id) or not _sha(candidate_sha):
            raise ReviewLifecycleError("owner rendering scope is invalid")
        connection = _open_writable_connection(repository)
        try:
            rows = connection.execute("SELECT item_id, item_kind, disposition, verification_state, blocker_state, destination FROM review_item_records WHERE task_id = ? AND (candidate_sha = ? OR (item_kind = 'pass-follow-up' AND source_kind = 'accepted-review')) ORDER BY item_id", (task_id, candidate_sha)).fetchall()
            commands = connection.execute("SELECT command_id, command_kind, target_item_id, state FROM owner_command_records WHERE task_id = ? AND candidate_sha = ? ORDER BY command_id", (task_id, candidate_sha)).fetchall()
        finally:
            connection.close()
        return "\n".join(["review-items", *(f"item={a} kind={b} disposition={c} verification={d} blocking={e} destination={f}" for a, b, c, d, e, f in rows), "owner-commands", *(f"command={a} kind={b} target={c} state={d}" for a, b, c, d in commands)])

    def _terminal_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, lease: object, state: ObjectiveState, terminal: WorkerObjectiveResult | str) -> WorkerObjective:
        if objective.task_id != identity.task_id:
            raise ReviewLifecycleError("Worker objective task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            retry = _require_worker_objective_attempt(connection, identity, objective.provider_attempt_id, objective.dispatch_sha)
            expected = (objective.task_id, objective.dispatch_sha, objective.provider_attempt_id, retry, objective.objective_digest)
            row = connection.execute("SELECT task_id, dispatch_sha, provider_attempt_id, retry_identity, objective_digest, state, candidate_sha, completion_evidence_fingerprint, accepted_result_identity, terminal_reason_digest FROM worker_objective_records WHERE objective_id = ?", (objective.objective_id,)).fetchone()
            if row is None or tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective is missing or has drifted")
            if row[5] == state.value:
                if state is ObjectiveState.COMPLETED:
                    if not isinstance(terminal, WorkerObjectiveResult) or tuple(row[6:9]) != (terminal.candidate_sha, terminal.completion_evidence_fingerprint, terminal.accepted_result_identity):
                        raise ReviewLifecycleError("Worker objective terminal replay conflicts with committed state")
                    _require_current_candidate(connection, identity, terminal.candidate_sha, lease)
                    _require_worker_objective_result(connection, identity, objective.provider_attempt_id, objective.dispatch_sha, terminal)
                if state is ObjectiveState.CANCELLED and (not isinstance(terminal, str) or row[9] != terminal):
                    raise ReviewLifecycleError("Worker objective terminal replay conflicts with committed state")
            elif row[5] != ObjectiveState.ACTIVE.value:
                raise ReviewLifecycleError("Worker objective is already terminal")
            elif state is ObjectiveState.COMPLETED:
                if not isinstance(terminal, WorkerObjectiveResult):
                    raise ReviewLifecycleError("Worker objective completion is invalid")
                _require_current_candidate(connection, identity, terminal.candidate_sha, lease)
                _require_worker_objective_result(connection, identity, objective.provider_attempt_id, objective.dispatch_sha, terminal)
                connection.execute("UPDATE worker_objective_records SET state = 'completed', candidate_sha = ?, completion_evidence_fingerprint = ?, accepted_result_identity = ? WHERE objective_id = ?", (terminal.candidate_sha, terminal.completion_evidence_fingerprint, terminal.accepted_result_identity, objective.objective_id))
            else:
                if not isinstance(terminal, str):
                    raise ReviewLifecycleError("Worker objective cancellation is invalid")
                connection.execute("UPDATE worker_objective_records SET state = 'cancelled', terminal_reason_digest = ? WHERE objective_id = ?", (terminal, objective.objective_id))
            connection.commit()
            return _objective_projection(objective.objective_id, *expected, state.value, terminal.candidate_sha if state is ObjectiveState.COMPLETED and isinstance(terminal, WorkerObjectiveResult) else None, terminal.completion_evidence_fingerprint if state is ObjectiveState.COMPLETED and isinstance(terminal, WorkerObjectiveResult) else None, terminal.accepted_result_identity if state is ObjectiveState.COMPLETED and isinstance(terminal, WorkerObjectiveResult) else None, terminal if state is ObjectiveState.CANCELLED and isinstance(terminal, str) else None)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def unresolved_final_gate_blockers(connection: sqlite3.Connection, task_id: str, candidate_sha: str) -> bool:
    # A plan PASS is bound to the task base before a later implementation
    # candidate exists.  It remains an owner obligation across that candidate
    # transition, so readiness deliberately scopes these terminal blockers to
    # the task rather than only to the current seal.
    return connection.execute("SELECT 1 FROM review_item_records WHERE task_id = ? AND item_kind = 'pass-follow-up' AND blocker_state = 'blocking' AND disposition = 'pending' LIMIT 1", (task_id,)).fetchone() is not None


def _owner_command_target(connection: sqlite3.Connection, identity: TaskIdentity, item_id: str, current_candidate_sha: str) -> bool:
    """Allow current-seal commands to resolve immutable plan-base obligations.

    Plan PASS records predate implementation candidate sealing.  Their stored
    SHA is therefore provenance, while an owner command is always authorized
    at the current seal.  Candidate-created items remain exact-seal scoped.
    """

    row = connection.execute(
        "SELECT candidate_sha, item_kind, source_kind FROM review_item_records WHERE item_id = ? AND task_id = ?",
        (item_id, identity.task_id),
    ).fetchone()
    return row is not None and (
        row[0] == current_candidate_sha
        or row[1:] == (ReviewItemKind.PASS_FOLLOW_UP.value, ReviewItemSource.ACCEPTED_REVIEW.value)
    )


def _cancel_objective_for_recovery_connection(
    connection: sqlite3.Connection,
    identity: TaskIdentity,
    provider_attempt_id: str,
    reason_digest: str,
) -> WorkerObjective | None:
    """Cancel only after an exact persisted Worker abandonment outcome."""

    if not _token(provider_attempt_id) or not _digest(reason_digest):
        raise ReviewLifecycleError("Worker recovery cancellation is invalid")
    recovery = connection.execute(
        "SELECT attempts.provider_role, attempts.state, outcomes.recovery_action, outcomes.blocker "
        "FROM provider_attempts AS attempts JOIN provider_recovery_outcomes AS outcomes "
        "ON outcomes.attempt_id = attempts.attempt_id WHERE attempts.task_id = ? AND attempts.attempt_id = ?",
        (identity.task_id, provider_attempt_id),
    ).fetchone()
    allowed = {"blocked-stale-worker", "blocked-ambiguous-turn", "blocked-identity-drift", "blocked-retry-limit"}
    if recovery is None or recovery[0] != "worker" or recovery[1] not in {"blocked", "ambiguous"} or recovery[2] not in allowed or not _token(recovery[3]):
        raise ReviewLifecycleError("Worker recovery cancellation lacks terminal abandonment evidence")
    row = connection.execute(
        "SELECT objective_id, task_id, dispatch_sha, provider_attempt_id, retry_identity, objective_digest, state, candidate_sha, completion_evidence_fingerprint, accepted_result_identity, terminal_reason_digest "
        "FROM worker_objective_records WHERE task_id = ? AND provider_attempt_id = ?",
        (identity.task_id, provider_attempt_id),
    ).fetchone()
    if row is None:
        return None
    objective = _objective_projection(*row)
    if objective.state is ObjectiveState.COMPLETED:
        return objective
    if objective.state is ObjectiveState.CANCELLED:
        if objective.cancellation_reason_digest != reason_digest:
            raise ReviewLifecycleError("Worker objective terminal replay conflicts with committed state")
        return objective
    connection.execute(
        "UPDATE worker_objective_records SET state = 'cancelled', terminal_reason_digest = ? WHERE objective_id = ? AND state = 'active'",
        (reason_digest, objective.objective_id),
    )
    return WorkerObjective(
        objective.objective_id, objective.task_id, objective.dispatch_sha, objective.provider_attempt_id,
        objective.retry_identity, objective.objective_digest, ObjectiveState.CANCELLED,
        cancellation_reason_digest=reason_digest,
    )


def _record_review_item_connection(connection: sqlite3.Connection, identity: TaskIdentity, item: ReviewItem) -> ReviewItemProjection:
    """Insert one canonical item and its exact source provenance in the caller's transaction."""
    source_owner = _require_accepted_review(connection, identity, item)
    blocker = "blocking" if item.blocking else "non-blocking"
    expected = (item.task_id, item.candidate_sha, item.kind.value, item.source.value,
                item.source_attempt_id, source_owner, item.content_digest, item.destination, blocker)
    row = connection.execute("SELECT task_id, review_identity, candidate_sha, item_kind, source_kind, source_attempt_id, source_owner_identity, content_digest, destination, blocker_state, created_at, disposition, verification_state FROM review_item_records WHERE item_id = ?", (item.item_id,)).fetchone()
    if row is not None:
        # The canonical record is semantic; each accepted review supplies an
        # additional provenance row.  A replay must therefore not compare its
        # distinct review identity or timestamp against the first producer.
        if (row[0], row[2], row[3], row[4], row[7], row[8], row[9]) != (
            expected[0], expected[1], expected[2], expected[3], expected[6], expected[7], expected[8]
        ):
            raise ReviewLifecycleError("review item identity conflicts with committed state")
        connection.execute("INSERT INTO review_item_provenance(item_id, task_id, candidate_sha, review_identity, source_kind, source_attempt_id, source_owner_identity) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(item_id, review_identity, source_kind, source_attempt_id) DO NOTHING", (item.item_id, item.task_id, item.candidate_sha, item.review_identity, item.source.value, item.source_attempt_id, source_owner))
        return _projection(item.item_id, row[3], row[9], row[12], row[11], row[8])
    semantic = connection.execute("SELECT item_id, destination, blocker_state, item_kind, verification_state, disposition FROM review_item_records WHERE task_id = ? AND candidate_sha = ? AND item_kind = ? AND content_digest = ?", (item.task_id, item.candidate_sha, item.kind.value, item.content_digest)).fetchone()
    if semantic is not None:
        if semantic[1:3] != (item.destination, blocker):
            raise ReviewLifecycleError("review item semantic identity has materially conflicting state")
        connection.execute("INSERT INTO review_item_provenance(item_id, task_id, candidate_sha, review_identity, source_kind, source_attempt_id, source_owner_identity) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(item_id, review_identity, source_kind, source_attempt_id) DO NOTHING", (semantic[0], item.task_id, item.candidate_sha, item.review_identity, item.source.value, item.source_attempt_id, source_owner))
        return _projection(semantic[0], semantic[3], semantic[2], semantic[4], semantic[5], semantic[1])
    connection.execute("INSERT INTO review_item_records(item_id, task_id, review_identity, candidate_sha, item_kind, source_kind, source_attempt_id, source_owner_identity, content_digest, destination, blocker_state, verification_state, disposition, created_at, resolved_command_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', ?, NULL)", (item.item_id, item.task_id, item.review_identity, item.candidate_sha, item.kind.value, item.source.value, item.source_attempt_id, source_owner, item.content_digest, item.destination, blocker, item.created_at))
    connection.execute("INSERT INTO review_item_provenance(item_id, task_id, candidate_sha, review_identity, source_kind, source_attempt_id, source_owner_identity) VALUES (?, ?, ?, ?, ?, ?, ?)", (item.item_id, item.task_id, item.candidate_sha, item.review_identity, item.source.value, item.source_attempt_id, source_owner))
    return ReviewItemProjection(item.item_id, item.kind, ReviewItemDisposition.PENDING, VerificationState.PENDING, item.blocking, item.destination)


def _require_lifecycle_authority(connection: sqlite3.Connection, identity: TaskIdentity, lease: object) -> None:
    try:
        _require_current_transition_lease(connection, lease, identity.repository_id)
        _require_matching_task(connection, identity)
    except StateError as error:
        raise ReviewLifecycleError("review lifecycle mutation lacks a current exact transition lease") from error


def _require_current_candidate(connection: sqlite3.Connection, identity: TaskIdentity, candidate_sha: str, lease: object) -> None:
    if connection.execute("SELECT candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (identity.task_id,)).fetchone() != (candidate_sha, getattr(lease, "state_identity", None)):
        raise ReviewLifecycleError("review lifecycle candidate is stale or not bound to the current lease state")


def _require_accepted_review(connection: sqlite3.Connection, identity: TaskIdentity, item: ReviewItem) -> str:
    row = connection.execute("SELECT attempts.task_id, attempts.attempt_id, attempts.provider_role, attempts.state, attempts.accepted_review_identity, COALESCE(NULLIF(attempts.selected_profile_identity, ''), accepted.selected_profile_identity) FROM provider_attempts AS attempts LEFT JOIN accepted_provider_reviews AS accepted ON accepted.attempt_id = attempts.attempt_id WHERE attempts.attempt_id = ?", (item.source_attempt_id,)).fetchone()
    if row is None or row[:3] != (identity.task_id, item.source_attempt_id, "supervisor") or not _durable_identity(row[5]):
        raise ReviewLifecycleError("review item provenance is missing, stale, or not an accepted supervisor review")
    diff = connection.execute("SELECT task_id, candidate_sha, provider_attempt_id, state, accepted_review_identity FROM diff_review_attempts WHERE diff_review_attempt_id = ?", (item.review_identity,)).fetchone()
    plan = connection.execute("SELECT task_id, provider_attempt_id, state FROM plan_review_attempts WHERE review_attempt_id = ?", (item.review_identity,)).fetchone()
    if item.source is ReviewItemSource.ACCEPTED_REVIEW:
        accepted_diff = diff == (identity.task_id, item.candidate_sha, item.source_attempt_id, "accepted", item.review_identity)
        accepted_plan = plan == (identity.task_id, item.source_attempt_id, "recorded") and item.candidate_sha == identity.base_sha
        if row[3:5] != ("accepted", item.review_identity) or not (accepted_diff or accepted_plan):
            raise ReviewLifecycleError("review item accepted review is not bound to the current candidate")
    if item.source is ReviewItemSource.SUPERVISOR_FINDING:
        output = connection.execute("SELECT 1 FROM provider_completion_outputs WHERE attempt_id = ?", (item.source_attempt_id,)).fetchone()
        if row[3] not in {"completed", "accepted"} or diff is None or diff[:4] != (identity.task_id, item.candidate_sha, item.source_attempt_id, "recorded") or output is None:
            raise ReviewLifecycleError("review finding provenance is not bound to a recorded supervisor output")
    return row[5]


def _require_worker_dispatch(connection: sqlite3.Connection, identity: TaskIdentity, attempt_id: str, dispatch_sha: str) -> str:
    row = connection.execute("SELECT attempts.task_id, attempts.provider_role, attempts.attempt_number, attempts.state, attempts.session_identity, attempts.external_turn_identity, implementation.task_id, implementation.worker_thread_identity, implementation.external_turn_identity, implementation.state, implementation.repair_candidate_sha FROM provider_attempts AS attempts JOIN implementation_attempts AS implementation ON implementation.provider_attempt_id = attempts.attempt_id WHERE attempts.attempt_id = ?", (attempt_id,)).fetchone()
    expected_dispatch_sha = row[10] or identity.base_sha if row is not None else None
    if row is None or row[:2] != (identity.task_id, "worker") or row[3] != "dispatched" or not _token(row[4]) or not _token(row[5]) or row[4] != row[7] or row[6] != identity.task_id or row[5] != row[8] or row[9] != "dispatched" or dispatch_sha != expected_dispatch_sha:
        raise ReviewLifecycleError("Worker objective provider dispatch is unavailable or stale")
    return f"worker-{row[2]}-{attempt_id}"


def _require_worker_objective_attempt(connection: sqlite3.Connection, identity: TaskIdentity, attempt_id: str, dispatch_sha: str) -> str:
    row = connection.execute("SELECT attempts.task_id, attempts.provider_role, attempts.attempt_number, attempts.state, attempts.completion_evidence_fingerprint, outcomes.recovery_action, outcomes.blocker, implementation.task_id, implementation.state, implementation.repair_candidate_sha FROM provider_attempts AS attempts JOIN implementation_attempts AS implementation ON implementation.provider_attempt_id = attempts.attempt_id LEFT JOIN provider_recovery_outcomes AS outcomes ON outcomes.attempt_id = attempts.attempt_id WHERE attempts.attempt_id = ?", (attempt_id,)).fetchone()
    expected_dispatch_sha = row[9] or identity.base_sha if row is not None else None
    recoverable_ambiguity = row is not None and row[3] == "ambiguous" and _digest(row[4]) and row[5:7] == ("blocked-ambiguous-turn", "completion-evidence-unverified")
    if row is None or row[:2] != (identity.task_id, "worker") or (row[3] not in {"dispatched", "completed"} and not recoverable_ambiguity) or row[7] != identity.task_id or row[8] not in {"dispatched", "recorded"} or dispatch_sha != expected_dispatch_sha:
        raise ReviewLifecycleError("Worker objective provider attempt is unavailable or stale")
    return f"worker-{row[2]}-{attempt_id}"


def _require_worker_objective_result(connection: sqlite3.Connection, identity: TaskIdentity, attempt_id: str, dispatch_sha: str, result: WorkerObjectiveResult) -> None:
    row = connection.execute("SELECT attempts.task_id, attempts.provider_role, attempts.state, attempts.session_identity, attempts.external_turn_identity, attempts.output_pointer, attempts.completion_evidence_fingerprint, outputs.output_fingerprint, implementation.task_id, implementation.state, implementation.worker_thread_identity, implementation.external_turn_identity, candidates.base_sha, candidates.candidate_sha, candidates.completion_evidence_fingerprint, candidates.content_digest FROM provider_attempts AS attempts JOIN implementation_attempts AS implementation ON implementation.provider_attempt_id = attempts.attempt_id JOIN implementation_candidates AS candidates ON candidates.implementation_attempt_id = implementation.implementation_attempt_id LEFT JOIN provider_completion_outputs AS outputs ON outputs.attempt_id = attempts.attempt_id WHERE attempts.attempt_id = ?", (attempt_id,)).fetchone()
    expected = (identity.task_id, "worker", "completed", identity.task_id, "recorded", identity.base_sha, result.candidate_sha, result.completion_evidence_fingerprint, result.accepted_result_identity)
    if row is None or row[0:3] != expected[0:3] or not _token(row[3]) or not _token(row[4]) or row[3] != row[10] or row[4] != row[11] or type(row[5]) is not str or not row[5] or row[6:8] != (result.completion_evidence_fingerprint, result.accepted_result_identity) or row[8:10] != expected[3:5] or row[12:16] != expected[5:]:
        raise ReviewLifecycleError("Worker objective result is missing, stale, or mismatched")


def _owner_scope_digest(command: OwnerCommand) -> str:
    return hashlib.sha256("\x1f".join((command.kind.value, command.task_id, command.candidate_sha, command.target_item_id, command.owner_identity, command.authority_grant_id)).encode("ascii")).hexdigest()


def _owner_authority_digest(owner_identity: str, command_scope: str, task_id: str, candidate_sha: str) -> str:
    return hashlib.sha256("\x1f".join(("review-owner-authority/v1", owner_identity, command_scope, task_id, candidate_sha, *sorted(_OWNER_ALLOWLIST))).encode("ascii")).hexdigest()


def _valid_owner_grant(grant: object, owner_identity: str, command_scope: str, task_id: str, candidate_sha: str) -> bool:
    return (type(grant) is tuple and len(grant) == 6 and grant[:4] == (owner_identity, command_scope, task_id, candidate_sha)
            and grant[5] == "active" and owner_identity in _OWNER_ALLOWLIST
            and grant[4] == _owner_authority_digest(owner_identity, command_scope, task_id, candidate_sha))


def _objective_projection(objective_id: str, task_id: str, dispatch_sha: str, attempt_id: str, retry_identity: str, objective_digest: str, state: str, candidate_sha: str | None, completion_evidence_fingerprint: str | None, accepted_result_identity: str | None, reason_digest: str | None) -> WorkerObjective:
    objective_state = ObjectiveState(state)
    result = WorkerObjectiveResult(candidate_sha, completion_evidence_fingerprint, accepted_result_identity) if objective_state is ObjectiveState.COMPLETED and candidate_sha is not None and completion_evidence_fingerprint is not None and accepted_result_identity is not None else None
    return WorkerObjective(objective_id, task_id, dispatch_sha, attempt_id, retry_identity, objective_digest, objective_state, result, reason_digest if objective_state is ObjectiveState.CANCELLED else None)


def _projection(item_id: object, kind: object, blocker: object, verification: object, disposition: object, destination: object) -> ReviewItemProjection:
    try:
        return ReviewItemProjection(str(item_id), ReviewItemKind(kind), ReviewItemDisposition(disposition), VerificationState(verification), blocker == "blocking", str(destination))
    except (TypeError, ValueError) as error:
        raise ReviewLifecycleError("committed review item is invalid") from error


def _token(value: object) -> bool:
    return type(value) is str and bool(_TOKEN.fullmatch(value))


def _sha(value: object) -> bool:
    return type(value) is str and bool(_SHA.fullmatch(value))


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _durable_identity(value: object) -> bool:
    return _token(value) or (type(value) is str and value.startswith("sha256:") and _digest(value[7:]))
