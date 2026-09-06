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
    candidate_sha: str
    provider_attempt_id: str
    retry_identity: str
    objective_digest: str
    state: ObjectiveState = ObjectiveState.ACTIVE
    terminal_digest: str | None = None

    def __post_init__(self) -> None:
        if not all(_token(v) for v in (self.objective_id, self.task_id, self.provider_attempt_id, self.retry_identity)) or not _sha(self.candidate_sha) or not _digest(self.objective_digest) or type(self.state) is not ObjectiveState:
            raise ReviewLifecycleError("Worker objective is invalid")
        if (self.state is ObjectiveState.ACTIVE) != (self.terminal_digest is None) or (self.terminal_digest is not None and not _digest(self.terminal_digest)):
            raise ReviewLifecycleError("Worker objective terminal state is invalid")


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
            source_owner = _require_accepted_review(connection, identity, item)
            expected = (item.task_id, item.review_identity, item.candidate_sha, item.kind.value, item.source.value, item.source_attempt_id, source_owner, item.content_digest, item.destination, "blocking" if item.blocking else "non-blocking", item.created_at)
            row = connection.execute("SELECT task_id, review_identity, candidate_sha, item_kind, source_kind, source_attempt_id, source_owner_identity, content_digest, destination, blocker_state, created_at, disposition, verification_state FROM review_item_records WHERE item_id = ?", (item.item_id,)).fetchone()
            if row is None:
                semantic = connection.execute("SELECT item_id, source_kind, source_attempt_id, source_owner_identity, destination, blocker_state, item_kind, verification_state, disposition FROM review_item_records WHERE task_id = ? AND candidate_sha = ? AND review_identity = ? AND item_kind = ? AND content_digest = ?", (item.task_id, item.candidate_sha, item.review_identity, item.kind.value, item.content_digest)).fetchone()
                if semantic is not None:
                    if tuple(semantic[1:6]) != (item.source.value, item.source_attempt_id, source_owner, item.destination, "blocking" if item.blocking else "non-blocking"):
                        raise ReviewLifecycleError("review item semantic identity has materially conflicting state")
                    connection.commit()
                    return _projection(semantic[0], semantic[6], semantic[5], semantic[7], semantic[8], semantic[4])
                connection.execute("INSERT INTO review_item_records(item_id, task_id, review_identity, candidate_sha, item_kind, source_kind, source_attempt_id, source_owner_identity, content_digest, destination, blocker_state, verification_state, disposition, created_at, resolved_command_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', ?, NULL)", (item.item_id, *expected))
                connection.execute("INSERT INTO review_item_provenance(item_id, task_id, candidate_sha, review_identity, source_kind, source_attempt_id, source_owner_identity) VALUES (?, ?, ?, ?, ?, ?, ?)", (item.item_id, item.task_id, item.candidate_sha, item.review_identity, item.source.value, item.source_attempt_id, source_owner))
                result = ReviewItemProjection(item.item_id, item.kind, ReviewItemDisposition.PENDING, VerificationState.PENDING, item.blocking, item.destination)
            elif tuple(row[:11]) == expected:
                result = _projection(item.item_id, row[3], row[9], row[12], row[11], row[8])
            else:
                raise ReviewLifecycleError("review item identity conflicts with committed state")
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
            _require_current_candidate(connection, identity, objective.candidate_sha, lease)
            retry = _require_worker_attempt(connection, identity, objective.provider_attempt_id, objective.candidate_sha)
            if objective.retry_identity != retry:
                raise ReviewLifecycleError("Worker objective retry identity is not the durable attempt identity")
            expected = (objective.task_id, objective.candidate_sha, objective.provider_attempt_id, retry, objective.objective_digest)
            row = connection.execute("SELECT task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest FROM worker_objective_records WHERE objective_id = ?", (objective.objective_id,)).fetchone()
            if row is None:
                connection.execute("INSERT INTO worker_objective_records(objective_id, task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, NULL)", (objective.objective_id, *expected))
            elif tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective identity conflicts with committed state")
            connection.commit()
            return _objective_projection(objective.objective_id, *expected, *(row[5:] if row is not None else (ObjectiveState.ACTIVE.value, None, None)))
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ReviewLifecycleError("Worker objective conflicts with an existing attempt") from error
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, *, lease: object, completion_digest: str) -> WorkerObjective:
        if not _digest(completion_digest):
            raise ReviewLifecycleError("objective completion is invalid")
        return self._terminal_objective(repository, identity, objective, lease, ObjectiveState.COMPLETED, completion_digest)

    def cancel_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, *, lease: object, reason_digest: str) -> WorkerObjective:
        if not _digest(reason_digest):
            raise ReviewLifecycleError("objective cancellation is invalid")
        return self._terminal_objective(repository, identity, objective, lease, ObjectiveState.CANCELLED, reason_digest)

    def queue_owner_command(self, repository: RepositoryIdentity, identity: TaskIdentity, command: OwnerCommand, *, lease: object) -> OwnerCommand:
        if command.task_id != identity.task_id:
            raise ReviewLifecycleError("owner command task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            _require_current_candidate(connection, identity, command.candidate_sha, lease)
            if connection.execute("SELECT task_id, candidate_sha FROM review_item_records WHERE item_id = ?", (command.target_item_id,)).fetchone() != (command.task_id, command.candidate_sha):
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
            item = connection.execute("SELECT item_kind, blocker_state, disposition, verification_state, destination, resolved_command_id FROM review_item_records WHERE item_id = ? AND task_id = ? AND candidate_sha = ?", (row[1], identity.task_id, row[2])).fetchone()
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
            rows = connection.execute("SELECT item_id, item_kind, disposition, verification_state, blocker_state, destination FROM review_item_records WHERE task_id = ? AND candidate_sha = ? ORDER BY item_id", (task_id, candidate_sha)).fetchall()
            commands = connection.execute("SELECT command_id, command_kind, target_item_id, state FROM owner_command_records WHERE task_id = ? AND candidate_sha = ? ORDER BY command_id", (task_id, candidate_sha)).fetchall()
        finally:
            connection.close()
        return "\n".join(["review-items", *(f"item={a} kind={b} disposition={c} verification={d} blocking={e} destination={f}" for a, b, c, d, e, f in rows), "owner-commands", *(f"command={a} kind={b} target={c} state={d}" for a, b, c, d in commands)])

    def _terminal_objective(self, repository: RepositoryIdentity, identity: TaskIdentity, objective: WorkerObjective, lease: object, state: ObjectiveState, digest: str) -> WorkerObjective:
        if objective.task_id != identity.task_id:
            raise ReviewLifecycleError("Worker objective task does not match its exact identity")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lifecycle_authority(connection, identity, lease)
            _require_current_candidate(connection, identity, objective.candidate_sha, lease)
            retry = _require_worker_attempt(connection, identity, objective.provider_attempt_id, objective.candidate_sha)
            expected = (objective.task_id, objective.candidate_sha, objective.provider_attempt_id, retry, objective.objective_digest)
            row = connection.execute("SELECT task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest FROM worker_objective_records WHERE objective_id = ?", (objective.objective_id,)).fetchone()
            if row is None or tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective is missing or has drifted")
            if row[5] == state.value:
                if (row[6] if state is ObjectiveState.COMPLETED else row[7]) != digest:
                    raise ReviewLifecycleError("Worker objective terminal replay conflicts with committed state")
            elif row[5] != ObjectiveState.ACTIVE.value:
                raise ReviewLifecycleError("Worker objective is already terminal")
            elif state is ObjectiveState.COMPLETED:
                connection.execute("UPDATE worker_objective_records SET state = 'completed', completion_digest = ? WHERE objective_id = ?", (digest, objective.objective_id))
            else:
                connection.execute("UPDATE worker_objective_records SET state = 'cancelled', terminal_reason_digest = ? WHERE objective_id = ?", (digest, objective.objective_id))
            connection.commit()
            return _objective_projection(objective.objective_id, *expected, state.value, digest if state is ObjectiveState.COMPLETED else None, digest if state is ObjectiveState.CANCELLED else None)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def unresolved_final_gate_blockers(connection: sqlite3.Connection, task_id: str, candidate_sha: str) -> bool:
    return connection.execute("SELECT 1 FROM review_item_records WHERE task_id = ? AND candidate_sha = ? AND item_kind = 'pass-follow-up' AND blocker_state = 'blocking' AND disposition = 'pending' LIMIT 1", (task_id, candidate_sha)).fetchone() is not None


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
    row = connection.execute("SELECT accepted.task_id, accepted.attempt_id, attempts.provider_role, attempts.state, attempts.accepted_review_identity, accepted.selected_profile_identity FROM accepted_provider_reviews AS accepted JOIN provider_attempts AS attempts ON attempts.attempt_id = accepted.attempt_id WHERE accepted.accepted_review_identity = ?", (item.review_identity,)).fetchone()
    if row is None or row[:5] != (identity.task_id, item.source_attempt_id, "supervisor", "accepted", item.review_identity) or not _durable_identity(row[5]):
        raise ReviewLifecycleError("review item provenance is missing, stale, or not an accepted supervisor review")
    diff = connection.execute("SELECT task_id, candidate_sha, provider_attempt_id, state, accepted_review_identity FROM diff_review_attempts WHERE diff_review_attempt_id = ?", (item.review_identity,)).fetchone()
    if diff != (identity.task_id, item.candidate_sha, item.source_attempt_id, "accepted", item.review_identity):
        raise ReviewLifecycleError("review item accepted review is not bound to the current candidate")
    return row[5]


def _require_worker_attempt(connection: sqlite3.Connection, identity: TaskIdentity, attempt_id: str, candidate_sha: str) -> str:
    row = connection.execute("SELECT attempts.task_id, attempts.provider_role, attempts.attempt_number, attempts.state, candidates.candidate_sha FROM provider_attempts AS attempts JOIN implementation_attempts AS implementation ON implementation.provider_attempt_id = attempts.attempt_id JOIN implementation_candidates AS candidates ON candidates.implementation_attempt_id = implementation.implementation_attempt_id WHERE attempts.attempt_id = ?", (attempt_id,)).fetchone()
    if row is None or row[0] != identity.task_id or row[1] != "worker" or row[3] not in {"dispatched", "completed", "accepted"} or row[4] != candidate_sha:
        raise ReviewLifecycleError("Worker objective provider attempt is unavailable or stale")
    return f"worker-{row[2]}-{attempt_id}"


def _owner_scope_digest(command: OwnerCommand) -> str:
    return hashlib.sha256("\x1f".join((command.kind.value, command.task_id, command.candidate_sha, command.target_item_id, command.owner_identity, command.authority_grant_id)).encode("ascii")).hexdigest()


def _owner_authority_digest(owner_identity: str, command_scope: str, task_id: str, candidate_sha: str) -> str:
    return hashlib.sha256("\x1f".join(("review-owner-authority/v1", owner_identity, command_scope, task_id, candidate_sha, *sorted(_OWNER_ALLOWLIST))).encode("ascii")).hexdigest()


def _valid_owner_grant(grant: object, owner_identity: str, command_scope: str, task_id: str, candidate_sha: str) -> bool:
    return (type(grant) is tuple and len(grant) == 6 and grant[:4] == (owner_identity, command_scope, task_id, candidate_sha)
            and grant[5] == "active" and owner_identity in _OWNER_ALLOWLIST
            and grant[4] == _owner_authority_digest(owner_identity, command_scope, task_id, candidate_sha))


def _objective_projection(objective_id: str, task_id: str, candidate_sha: str, attempt_id: str, retry_identity: str, objective_digest: str, state: str, completion_digest: str | None, reason_digest: str | None) -> WorkerObjective:
    objective_state = ObjectiveState(state)
    return WorkerObjective(objective_id, task_id, candidate_sha, attempt_id, retry_identity, objective_digest, objective_state, completion_digest if objective_state is ObjectiveState.COMPLETED else reason_digest)


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
