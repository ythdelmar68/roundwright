"""Durable, public-safe Phase 5 review, objective, and owner-command state.

The module deliberately stores opaque identifiers and digests only.  Model
output, Markdown, command prose, and private context are not authority inputs.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .state import _open_writable_connection


_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ReviewLifecycleError(ValueError):
    """Raised when durable review lifecycle state is malformed or conflicts."""


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
    kind: ReviewItemKind
    source: ReviewItemSource
    content_digest: str
    destination: str
    blocking: bool
    created_at: int

    def __post_init__(self) -> None:
        if (not _token(self.item_id) or not _token(self.task_id) or not _token(self.review_identity)
                or not _sha(self.candidate_sha) or not _digest(self.content_digest)
                or not _token(self.destination) or type(self.blocking) is not bool
                or type(self.created_at) is not int or self.created_at <= 0):
            raise ReviewLifecycleError("review item is invalid")
        if type(self.kind) is not ReviewItemKind or type(self.source) is not ReviewItemSource:
            raise ReviewLifecycleError("review item is invalid")
        if self.kind is ReviewItemKind.PASS_FOLLOW_UP and self.source is not ReviewItemSource.ACCEPTED_REVIEW:
            raise ReviewLifecycleError("PASS follow-up source is invalid")


@dataclass(frozen=True)
class WorkerObjective:
    objective_id: str
    task_id: str
    candidate_sha: str
    provider_attempt_id: str
    retry_identity: str
    objective_digest: str

    def __post_init__(self) -> None:
        if not all(_token(value) for value in (self.objective_id, self.task_id, self.provider_attempt_id, self.retry_identity)):
            raise ReviewLifecycleError("Worker objective is invalid")
        if not _sha(self.candidate_sha) or not _digest(self.objective_digest):
            raise ReviewLifecycleError("Worker objective is invalid")


@dataclass(frozen=True)
class OwnerCommand:
    command_id: str
    task_id: str
    kind: OwnerCommandKind
    target_item_id: str
    candidate_sha: str
    command_digest: str
    idempotency_key: str
    owner_source: str = "allowlisted-owner"

    def __post_init__(self) -> None:
        if (not all(_token(value) for value in (self.command_id, self.task_id, self.target_item_id, self.idempotency_key))
                or self.owner_source != "allowlisted-owner" or not _sha(self.candidate_sha)
                or not _digest(self.command_digest) or type(self.kind) is not OwnerCommandKind):
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
    """One SQLite authority surface for review items, objectives, and commands."""

    def record_review_item(self, repository: RepositoryIdentity, item: ReviewItem) -> ReviewItemProjection:
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_task(connection, item.task_id)
            expected = (item.task_id, item.review_identity, item.candidate_sha, item.kind.value, item.source.value,
                        item.content_digest, item.destination, "blocking" if item.blocking else "non-blocking", item.created_at)
            row = connection.execute(
                "SELECT task_id, review_identity, candidate_sha, item_kind, source_kind, content_digest, destination, blocker_state, created_at, disposition, verification_state FROM structured_review_items WHERE item_id = ?",
                (item.item_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO structured_review_items(item_id, task_id, review_identity, candidate_sha, item_kind, source_kind, content_digest, destination, blocker_state, verification_state, disposition, created_at, resolved_command_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', ?, NULL)",
                    (item.item_id, *expected),
                )
                result = ReviewItemProjection(item.item_id, item.kind, ReviewItemDisposition.PENDING, VerificationState.PENDING, item.blocking, item.destination)
            elif tuple(row[:9]) == expected:
                result = _projection(item.item_id, row[3], row[7], row[9], row[10], row[6])
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

    def start_objective(self, repository: RepositoryIdentity, objective: WorkerObjective) -> WorkerObjective:
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_task(connection, objective.task_id)
            expected = (objective.task_id, objective.candidate_sha, objective.provider_attempt_id, objective.retry_identity, objective.objective_digest)
            row = connection.execute(
                "SELECT task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest FROM worker_objectives WHERE objective_id = ?",
                (objective.objective_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO worker_objectives(objective_id, task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, NULL)",
                    (objective.objective_id, *expected),
                )
            elif tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective identity conflicts with committed state")
            connection.commit()
            return objective
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise ReviewLifecycleError("Worker objective conflicts with an existing attempt") from error
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_objective(self, repository: RepositoryIdentity, objective: WorkerObjective, *, completion_digest: str) -> None:
        if not _digest(completion_digest):
            raise ReviewLifecycleError("objective completion is invalid")
        self._terminal_objective(repository, objective, ObjectiveState.COMPLETED, completion_digest)

    def cancel_objective(self, repository: RepositoryIdentity, objective: WorkerObjective, *, reason_digest: str) -> None:
        if not _digest(reason_digest):
            raise ReviewLifecycleError("objective cancellation is invalid")
        self._terminal_objective(repository, objective, ObjectiveState.CANCELLED, reason_digest)

    def queue_owner_command(self, repository: RepositoryIdentity, command: OwnerCommand) -> OwnerCommand:
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_task(connection, command.task_id)
            item = connection.execute(
                "SELECT task_id, candidate_sha FROM structured_review_items WHERE item_id = ?", (command.target_item_id,)
            ).fetchone()
            if item != (command.task_id, command.candidate_sha):
                raise ReviewLifecycleError("owner command target is stale or outside its scope")
            expected = (command.task_id, command.kind.value, command.owner_source, command.target_item_id, command.candidate_sha, command.command_digest, command.idempotency_key)
            row = connection.execute(
                "SELECT task_id, command_kind, owner_source, target_item_id, candidate_sha, command_digest, idempotency_key FROM owner_commands WHERE command_id = ?",
                (command.command_id,),
            ).fetchone()
            if row is None:
                same_key = connection.execute(
                    "SELECT command_id, task_id, command_kind, owner_source, target_item_id, candidate_sha, command_digest FROM owner_commands WHERE idempotency_key = ?",
                    (command.idempotency_key,),
                ).fetchone()
                if same_key is not None:
                    if same_key[0] != command.command_id or tuple(same_key[1:]) != expected[:-1]:
                        raise ReviewLifecycleError("owner command idempotency key conflicts with committed state")
                else:
                    connection.execute(
                        "INSERT INTO owner_commands(command_id, task_id, command_kind, owner_source, target_item_id, candidate_sha, command_digest, idempotency_key, state, result_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL)",
                        (command.command_id, *expected),
                    )
            elif tuple(row) != expected:
                raise ReviewLifecycleError("owner command identity conflicts with committed state")
            connection.commit()
            return command
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def consume_owner_command(self, repository: RepositoryIdentity, command: OwnerCommand, *, result_digest: str) -> ReviewItemProjection:
        if not _digest(result_digest):
            raise ReviewLifecycleError("owner command result is invalid")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT task_id, command_kind, owner_source, target_item_id, candidate_sha, command_digest, idempotency_key, state, result_digest FROM owner_commands WHERE command_id = ?",
                (command.command_id,),
            ).fetchone()
            expected = (command.task_id, command.kind.value, command.owner_source, command.target_item_id, command.candidate_sha, command.command_digest, command.idempotency_key)
            if row is None or tuple(row[:7]) != expected:
                raise ReviewLifecycleError("owner command is missing, stale, or unauthorized")
            item = connection.execute(
                "SELECT task_id, candidate_sha, item_kind, blocker_state, disposition, verification_state, destination, resolved_command_id FROM structured_review_items WHERE item_id = ?",
                (command.target_item_id,),
            ).fetchone()
            if item is None or item[:2] != (command.task_id, command.candidate_sha):
                raise ReviewLifecycleError("owner command target is stale or outside its scope")
            if row[7] == "consumed":
                if row[8] != result_digest or item[7] != command.command_id:
                    raise ReviewLifecycleError("owner command terminal replay conflicts with committed state")
                connection.commit()
                return _projection(command.target_item_id, item[2], item[3], item[5], item[4], item[6])
            if row[7] != "pending" or item[4] != ReviewItemDisposition.PENDING.value:
                raise ReviewLifecycleError("owner command conflicts with an already terminal item")
            disposition = ReviewItemDisposition.RESOLVED if command.kind is OwnerCommandKind.RESOLVE_REVIEW_ITEM else ReviewItemDisposition.WAIVED
            verification = VerificationState.VERIFIED if disposition is ReviewItemDisposition.RESOLVED else VerificationState.WAIVED
            connection.execute(
                "UPDATE structured_review_items SET disposition = ?, verification_state = ?, resolved_command_id = ? WHERE item_id = ?",
                (disposition.value, verification.value, command.command_id, command.target_item_id),
            )
            connection.execute(
                "UPDATE owner_commands SET state = 'consumed', result_digest = ? WHERE command_id = ?",
                (result_digest, command.command_id),
            )
            connection.commit()
            return _projection(command.target_item_id, item[2], item[3], verification.value, disposition.value, item[6])
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
            rows = connection.execute(
                "SELECT item_id, item_kind, disposition, verification_state, blocker_state, destination FROM structured_review_items WHERE task_id = ? AND candidate_sha = ? ORDER BY item_id",
                (task_id, candidate_sha),
            ).fetchall()
            commands = connection.execute(
                "SELECT command_id, command_kind, target_item_id, state FROM owner_commands WHERE task_id = ? AND candidate_sha = ? ORDER BY command_id",
                (task_id, candidate_sha),
            ).fetchall()
        finally:
            connection.close()
        lines = ["review-items"]
        lines.extend(
            f"item={item_id} kind={kind} disposition={disposition} verification={verification} blocking={blocking} destination={destination}"
            for item_id, kind, disposition, verification, blocking, destination in rows
        )
        lines.append("owner-commands")
        lines.extend(f"command={command_id} kind={kind} target={target} state={state}" for command_id, kind, target, state in commands)
        return "\n".join(lines)

    def _terminal_objective(self, repository: RepositoryIdentity, objective: WorkerObjective, state: ObjectiveState, digest: str) -> None:
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT task_id, candidate_sha, provider_attempt_id, retry_identity, objective_digest, state, completion_digest, terminal_reason_digest FROM worker_objectives WHERE objective_id = ?",
                (objective.objective_id,),
            ).fetchone()
            expected = (objective.task_id, objective.candidate_sha, objective.provider_attempt_id, objective.retry_identity, objective.objective_digest)
            if row is None or tuple(row[:5]) != expected:
                raise ReviewLifecycleError("Worker objective is missing or has drifted")
            if row[5] == state.value:
                persisted = row[6] if state is ObjectiveState.COMPLETED else row[7]
                if persisted != digest:
                    raise ReviewLifecycleError("Worker objective terminal replay conflicts with committed state")
            elif row[5] != ObjectiveState.ACTIVE.value:
                raise ReviewLifecycleError("Worker objective is already terminal")
            elif state is ObjectiveState.COMPLETED:
                connection.execute("UPDATE worker_objectives SET state = 'completed', completion_digest = ? WHERE objective_id = ?", (digest, objective.objective_id))
            else:
                connection.execute("UPDATE worker_objectives SET state = 'cancelled', terminal_reason_digest = ? WHERE objective_id = ?", (digest, objective.objective_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def unresolved_final_gate_blockers(connection: sqlite3.Connection, task_id: str, candidate_sha: str) -> bool:
    """Return whether the exact candidate has an unresolved blocking PASS follow-up."""

    row = connection.execute(
        "SELECT 1 FROM structured_review_items WHERE task_id = ? AND candidate_sha = ? AND item_kind = 'pass-follow-up' AND blocker_state = 'blocking' AND disposition = 'pending' LIMIT 1",
        (task_id, candidate_sha),
    ).fetchone()
    return row is not None


def _projection(item_id: str, kind: object, blocker: object, verification: object, disposition: object, destination: object) -> ReviewItemProjection:
    try:
        return ReviewItemProjection(item_id, ReviewItemKind(kind), ReviewItemDisposition(disposition), VerificationState(verification), blocker == "blocking", destination)
    except (TypeError, ValueError) as error:
        raise ReviewLifecycleError("committed review item is invalid") from error


def _require_task(connection: sqlite3.Connection, task_id: str) -> None:
    if connection.execute("SELECT 1 FROM tasks WHERE task_id = ?", (task_id,)).fetchone() is None:
        raise ReviewLifecycleError("review lifecycle task is unavailable")


def _token(value: object) -> bool:
    return type(value) is str and bool(_TOKEN.fullmatch(value))


def _sha(value: object) -> bool:
    return type(value) is str and bool(_SHA.fullmatch(value))


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))
