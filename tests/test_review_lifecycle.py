"""Hermetic coverage for Phase 5 durable review and owner-control state."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import acquire_transition_lease
from roundwright.review_lifecycle import (
    ObjectiveState, OwnerCommand, OwnerCommandKind, ReviewItem, ReviewItemKind,
    ReviewItemSource, ReviewLifecycleError, ReviewLifecycleStore, WorkerObjective,
    unresolved_final_gate_blockers,
)
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


class ReviewLifecycleTests(unittest.TestCase):
    candidate = "c" * 40

    def repository(self, root: Path) -> RepositoryIdentity:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", root.resolve())
        return repository

    def setup(self, root: Path) -> tuple[RepositoryIdentity, TaskIdentity]:
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("task-115", "source-115", "repo-115", "codex/115", "C:/review-115", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="review-lifecycle-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        return repository, identity

    def item(self, identity: TaskIdentity, *, item_id: str = "item-115", content: str = "d" * 64) -> ReviewItem:
        return ReviewItem(item_id, identity.task_id, "review-115", self.candidate, ReviewItemKind.PASS_FOLLOW_UP,
                          ReviewItemSource.ACCEPTED_REVIEW, content, "owner-review", True, 1)

    def objective(self, identity: TaskIdentity) -> WorkerObjective:
        return WorkerObjective("objective-115", identity.task_id, self.candidate, "attempt-115", "retry-115", "e" * 64)

    def command(self, identity: TaskIdentity, *, kind: OwnerCommandKind = OwnerCommandKind.RESOLVE_REVIEW_ITEM) -> OwnerCommand:
        return OwnerCommand("command-115", identity.task_id, kind, "item-115", self.candidate, "f" * 64, "key-115")

    def test_review_items_are_idempotent_candidate_bound_and_gate_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            first = store.record_review_item(repository, self.item(identity))
            second = store.record_review_item(repository, self.item(identity))
            self.assertEqual((first.disposition, second.disposition, first.blocking), ("pending", "pending", True))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertTrue(unresolved_final_gate_blockers(connection, identity.task_id, self.candidate))
            with self.assertRaises(ReviewLifecycleError):
                store.record_review_item(repository, self.item(identity, content="0" * 64))
            with self.assertRaises(ReviewLifecycleError):
                store.record_review_item(repository, self.item(identity, item_id="item-116"))

    def test_exact_owner_command_is_idempotent_and_resolves_the_bound_item(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            store.record_review_item(repository, self.item(identity))
            command = self.command(identity)
            self.assertEqual(store.queue_owner_command(repository, command), command)
            resolved = store.consume_owner_command(repository, command, result_digest="1" * 64)
            replay = store.consume_owner_command(repository, command, result_digest="1" * 64)
            self.assertEqual((resolved.disposition, resolved.verification, replay.disposition), ("resolved", "verified", "resolved"))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertFalse(unresolved_final_gate_blockers(connection, identity.task_id, self.candidate))
            rendered = store.render_owner_view(repository, task_id=identity.task_id, candidate_sha=self.candidate)
            self.assertIn("item=item-115 kind=pass-follow-up disposition=resolved", rendered)
            self.assertNotIn("f" * 64, rendered)

    def test_owner_commands_fail_closed_for_wrong_candidate_source_or_terminal_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            store.record_review_item(repository, self.item(identity))
            wrong_candidate = OwnerCommand("command-115", identity.task_id, OwnerCommandKind.RESOLVE_REVIEW_ITEM, "item-115", "0" * 40, "f" * 64, "key-115")
            with self.assertRaises(ReviewLifecycleError):
                store.queue_owner_command(repository, wrong_candidate)
            with self.assertRaises(ReviewLifecycleError):
                OwnerCommand("command-116", identity.task_id, OwnerCommandKind.RESOLVE_REVIEW_ITEM, "item-115", self.candidate, "f" * 64, "key-116", "untrusted-owner")
            command = self.command(identity)
            store.queue_owner_command(repository, command)
            store.consume_owner_command(repository, command, result_digest="1" * 64)
            with self.assertRaises(ReviewLifecycleError):
                store.consume_owner_command(repository, command, result_digest="2" * 64)

    def test_worker_objective_is_separate_from_attempt_and_has_one_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            objective = self.objective(identity)
            self.assertEqual(store.start_objective(repository, objective), objective)
            self.assertEqual(store.start_objective(repository, objective), objective)
            store.complete_objective(repository, objective, completion_digest="1" * 64)
            store.complete_objective(repository, objective, completion_digest="1" * 64)
            with self.assertRaises(ReviewLifecycleError):
                store.cancel_objective(repository, objective, reason_digest="2" * 64)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute("SELECT state FROM worker_objectives WHERE objective_id = 'objective-115'").fetchone(), (ObjectiveState.COMPLETED.value,))
