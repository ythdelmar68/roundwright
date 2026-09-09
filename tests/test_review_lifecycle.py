"""Hermetic coverage for lease-bound Phase 5 review and owner-control state."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import acquire_transition_lease
from roundwright.review_lifecycle import (
    ObjectiveState, OwnerCommand, OwnerCommandKind, ReviewItem, ReviewItemKind,
    ReviewItemSource, ReviewLifecycleError, ReviewLifecycleStore, WorkerObjective, WorkerObjectiveResult,
    _owner_authority_digest, owner_blocker_state_receipt, unresolved_final_gate_blockers,
)
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


class ReviewLifecycleTests(unittest.TestCase):
    candidate = "c" * 40

    def repository(self, root: Path) -> RepositoryIdentity:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", root.resolve())
        return repository

    def setup(self, root: Path):
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("task-115", "source-115", "repo-115", "codex/115", "C:/review-115", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="review-lifecycle-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        with closing(sqlite3.connect(database_path(repository))) as connection:
            connection.execute("INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)", (identity.task_id, identity.base_sha, self.candidate, lease.state_identity))
            now = int(time.time()) + 60
            connection.execute("INSERT INTO provider_attempts(attempt_id, task_id, provider_role, attempt_number, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint, accepted_review_identity, state) VALUES (?, ?, 'supervisor', 1, 'lease-115', ?, 'session-115', 'turn-115', ?, 'pointer-115', ?, 'review-115', 'accepted')", ("attempt-review-115", identity.task_id, now, "d" * 64, "e" * 64))
            connection.execute("INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, selected_profile_identity) VALUES ('review-115', ?, 'attempt-review-115', ?, ?)", (identity.task_id, "e" * 64, "sha256:" + "2" * 64))
            connection.execute("INSERT INTO diff_review_attempts(diff_review_attempt_id, task_id, implementation_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, message_identity, base_sha, candidate_sha, input_digest, state, created_at, accepted_review_identity) VALUES ('review-115', ?, 'implementation-115', 'attempt-review-115', 'review-session-115', 'review-turn-115', 'review-message-115', ?, ?, ?, 'accepted', 1, 'review-115')", (identity.task_id, identity.base_sha, self.candidate, "d" * 64))
            connection.execute("INSERT INTO provider_attempts(attempt_id, task_id, provider_role, attempt_number, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint, accepted_review_identity, state) VALUES ('attempt-115', ?, 'worker', 1, 'worker-lease-115', ?, 'worker-thread-115', 'worker-turn-115', ?, NULL, NULL, NULL, 'dispatched')", (identity.task_id, now, "f" * 64))
            connection.execute("INSERT INTO implementation_attempts(implementation_attempt_id, task_id, plan_attempt_id, accepted_plan_review_identity, provider_attempt_id, worker_thread_identity, external_turn_identity, input_digest, state, created_at) VALUES ('implementation-115', ?, 'plan-115', 'review-plan-115', 'attempt-115', 'worker-thread-115', 'worker-turn-115', ?, 'dispatched', 1)", (identity.task_id, "f" * 64))
            connection.execute("INSERT INTO owner_authority_grants(grant_id, owner_identity, command_scope, task_id, candidate_sha, authority_digest, state) VALUES ('grant-resolve-115', 'ythdelmar68', 'resolve-review-item', ?, ?, ?, 'active')", (identity.task_id, self.candidate, _owner_authority_digest("ythdelmar68", "resolve-review-item", identity.task_id, self.candidate)))
            connection.commit()
        return repository, identity, lease

    def item(self, identity: TaskIdentity, *, item_id: str = "item-115", content: str = "d" * 64) -> ReviewItem:
        return ReviewItem(item_id, identity.task_id, "review-115", self.candidate, "attempt-review-115", ReviewItemKind.PASS_FOLLOW_UP, ReviewItemSource.ACCEPTED_REVIEW, content, "owner-review", True, 1)

    def objective(self, identity: TaskIdentity) -> WorkerObjective:
        return WorkerObjective("objective-115", identity.task_id, identity.base_sha, "attempt-115", "worker-1-attempt-115", "e" * 64)

    def objective_result(self) -> WorkerObjectiveResult:
        return WorkerObjectiveResult(self.candidate, "1" * 64, "2" * 64)

    def persist_objective_result(self, repository: RepositoryIdentity, identity: TaskIdentity, *, evidence: str = "1" * 64, accepted: str = "2" * 64, candidate: str | None = None) -> WorkerObjectiveResult:
        result = WorkerObjectiveResult(candidate or self.candidate, evidence, accepted)
        with closing(sqlite3.connect(database_path(repository))) as connection:
            connection.execute("UPDATE provider_attempts SET state = 'completed', output_pointer = 'implementation-115', completion_evidence_fingerprint = ? WHERE attempt_id = 'attempt-115'", (result.completion_evidence_fingerprint,))
            connection.execute("INSERT INTO provider_completion_outputs(attempt_id, output_fingerprint) VALUES ('attempt-115', ?)", (result.accepted_result_identity,))
            connection.execute("INSERT INTO implementation_candidates(implementation_attempt_id, task_id, base_sha, candidate_sha, completion_evidence_fingerprint, content_digest) VALUES ('implementation-115', ?, ?, ?, ?, ?)", (identity.task_id, identity.base_sha, result.candidate_sha, result.completion_evidence_fingerprint, result.accepted_result_identity))
            connection.execute("UPDATE implementation_attempts SET state = 'recorded' WHERE implementation_attempt_id = 'implementation-115'")
            connection.commit()
        return result

    def command(self, identity: TaskIdentity, *, kind: OwnerCommandKind = OwnerCommandKind.RESOLVE_REVIEW_ITEM) -> OwnerCommand:
        return OwnerCommand("command-115", identity.task_id, kind, "item-115", self.candidate, "f" * 64, "key-115", "ythdelmar68", "grant-resolve-115")

    def test_review_items_are_lease_bound_provenance_bound_and_semantically_deduplicated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            first = store.record_review_item(repository, identity, self.item(identity), lease=lease)
            alias = store.record_review_item(repository, identity, self.item(identity, item_id="item-116"), lease=lease)
            self.assertEqual((first.item_id, alias.item_id, first.blocking), ("item-115", "item-115", True))
            # Distinct accepted Supervisor/provider identities with the same
            # semantic follow-up retain both provenance rows under one item.
            with closing(sqlite3.connect(database_path(repository))) as connection:
                now = int(time.time()) + 60
                connection.execute("INSERT INTO provider_attempts(attempt_id, task_id, provider_role, attempt_number, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint, accepted_review_identity, state) VALUES ('attempt-review-116', ?, 'supervisor', 2, 'lease-116', ?, 'session-116', 'turn-116', ?, 'pointer-116', ?, 'review-116', 'accepted')", (identity.task_id, now, "d" * 64, "e" * 64))
                connection.execute("INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, selected_profile_identity) VALUES ('review-116', ?, 'attempt-review-116', ?, ?)", (identity.task_id, "e" * 64, "sha256:" + "3" * 64))
                connection.execute("INSERT INTO diff_review_attempts(diff_review_attempt_id, task_id, implementation_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, message_identity, base_sha, candidate_sha, input_digest, state, created_at, accepted_review_identity) VALUES ('review-116', ?, 'implementation-115', 'attempt-review-116', 'review-session-116', 'review-turn-116', 'review-message-116', ?, ?, ?, 'accepted', 1, 'review-116')", (identity.task_id, identity.base_sha, self.candidate, "d" * 64))
                connection.commit()
            second = ReviewItem("item-117", identity.task_id, "review-116", self.candidate, "attempt-review-116", ReviewItemKind.PASS_FOLLOW_UP, ReviewItemSource.ACCEPTED_REVIEW, "d" * 64, "owner-review", True, 1)
            self.assertEqual(store.record_review_item(repository, identity, second, lease=lease).item_id, "item-115")
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_item_records").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM review_item_provenance WHERE item_id = 'item-115'").fetchone(), (2,))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertTrue(unresolved_final_gate_blockers(connection, identity.task_id, self.candidate))
            with self.assertRaises(ReviewLifecycleError):
                store.record_review_item(repository, identity, self.item(identity, content="0" * 64), lease=lease)
            with self.assertRaises(ReviewLifecycleError):
                store.record_review_item(repository, identity, ReviewItem("bad-item", identity.task_id, "review-115", self.candidate, "attempt-115", ReviewItemKind.FINDING, ReviewItemSource.SUPERVISOR_FINDING, "2" * 64, "owner-review", True, 1), lease=lease)
            with self.assertRaises(ReviewLifecycleError):
                ReviewItem("bad-source-115", identity.task_id, "review-115", self.candidate, "attempt-review-115", ReviewItemKind.FINDING, ReviewItemSource.ACCEPTED_REVIEW, "2" * 64, "owner-review", True, 1)

    def test_mutations_require_current_lease_and_exact_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            with self.assertRaises(ReviewLifecycleError):
                ReviewLifecycleStore().record_review_item(repository, identity, self.item(identity), lease=object())
            stale = replace(lease, owner="replacement-owner")
            with self.assertRaises(ReviewLifecycleError):
                ReviewLifecycleStore().record_review_item(repository, identity, self.item(identity), lease=stale)
            self.assertEqual(stale.repository_id, identity.repository_id)

    def test_owner_command_uses_authority_grant_and_consumes_stored_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            store.record_review_item(repository, identity, self.item(identity), lease=lease)
            command = self.command(identity)
            self.assertEqual(store.queue_owner_command(repository, identity, command, lease=lease), command)
            resolved = store.consume_owner_command(repository, identity, command_id=command.command_id, lease=lease, result_digest="1" * 64)
            replay = store.consume_owner_command(repository, identity, command_id=command.command_id, lease=lease, result_digest="1" * 64)
            self.assertEqual((resolved.disposition, resolved.verification, replay.disposition), ("resolved", "verified", "resolved"))
            canonical = store.record_review_item(repository, identity, self.item(identity, item_id="item-116"), lease=lease)
            self.assertEqual((canonical.item_id, canonical.disposition), ("item-115", "resolved"))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertFalse(unresolved_final_gate_blockers(connection, identity.task_id, self.candidate))
            self.assertNotIn("f" * 64, store.render_owner_view(repository, task_id=identity.task_id, candidate_sha=self.candidate))
            untrusted = OwnerCommand("command-116", identity.task_id, OwnerCommandKind.RESOLVE_REVIEW_ITEM, "item-115", self.candidate, "f" * 64, "key-116", "untrusted-owner", "grant-resolve-115")
            with self.assertRaises(ReviewLifecycleError):
                store.queue_owner_command(repository, identity, untrusted, lease=lease)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("UPDATE owner_authority_grants SET authority_digest = ? WHERE grant_id = 'grant-resolve-115'", ("0" * 64,))
                connection.commit()
            with self.assertRaises(ReviewLifecycleError):
                store.consume_owner_command(repository, identity, command_id=command.command_id, lease=lease, result_digest="1" * 64)

    def test_plan_base_follow_up_remains_visible_and_resolvable_after_candidate_moves(self) -> None:
        """A current-seal command discharges, but never rewrites, plan provenance."""
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            store.record_review_item(repository, identity, self.item(identity), lease=lease)
            moved = "d" * 40
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("UPDATE candidate_seals SET candidate_sha = ? WHERE task_id = ?", (moved, identity.task_id))
                connection.execute("INSERT INTO owner_authority_grants(grant_id, owner_identity, command_scope, task_id, candidate_sha, authority_digest, state) VALUES ('grant-resolve-moved', 'ythdelmar68', 'resolve-review-item', ?, ?, ?, 'active')", (identity.task_id, moved, _owner_authority_digest("ythdelmar68", "resolve-review-item", identity.task_id, moved)))
                connection.commit()
            command = OwnerCommand("command-moved", identity.task_id, OwnerCommandKind.RESOLVE_REVIEW_ITEM, "item-115", moved, "1" * 64, "key-moved", "ythdelmar68", "grant-resolve-moved")
            self.assertEqual(store.queue_owner_command(repository, identity, command, lease=lease), command)
            self.assertIn("item=item-115", store.render_owner_view(repository, task_id=identity.task_id, candidate_sha=moved))
            self.assertTrue(store.consume_owner_command(repository, identity, command_id=command.command_id, lease=lease, result_digest="2" * 64).disposition is not None)
            self.assertEqual(store.consume_owner_command(repository, identity, command_id=command.command_id, lease=lease, result_digest="2" * 64).disposition.value, "resolved")
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertFalse(unresolved_final_gate_blockers(connection, identity.task_id, moved))
                self.assertEqual(connection.execute("SELECT candidate_sha FROM review_item_records WHERE item_id = 'item-115'").fetchone(), (self.candidate,))

    def test_owner_blocker_receipt_retains_prior_candidate_pass_follow_up_and_requires_current_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            ReviewLifecycleStore().record_review_item(repository, identity, self.item(identity), lease=lease)
            moved = "d" * 40
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("UPDATE candidate_seals SET candidate_sha = ? WHERE task_id = ?", (moved, identity.task_id))
                connection.commit()
                receipt = owner_blocker_state_receipt(connection, identity.task_id, moved)
                self.assertTrue(receipt.blockers_pending)
                self.assertEqual(receipt.candidate_sha, moved)
                self.assertNotEqual(receipt.blocker_state_digest, "0" * 64)
                with self.assertRaises(ReviewLifecycleError):
                    owner_blocker_state_receipt(connection, identity.task_id, self.candidate)
                connection.execute("DELETE FROM candidate_seals WHERE task_id = ?", (identity.task_id,))
                connection.commit()
                with self.assertRaises(ReviewLifecycleError):
                    owner_blocker_state_receipt(connection, identity.task_id, moved)

    def test_worker_objective_starts_from_dispatch_then_completes_only_from_persisted_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            objective = self.objective(identity)
            # No candidate output exists yet: the durable Worker/provider turn is the start boundary.
            self.assertEqual(store.start_objective(repository, identity, objective, lease=lease), objective)
            # A new store models process restart/reconstruction; it reads and preserves the same active objective.
            self.assertEqual(ReviewLifecycleStore().start_objective(repository, identity, objective, lease=lease), objective)
            with self.assertRaises(ReviewLifecycleError):
                store.complete_objective(repository, identity, objective, lease=lease, result=self.objective_result())
            result = self.persist_objective_result(repository, identity)
            completed = store.complete_objective(repository, identity, objective, lease=lease, result=result)
            replay = store.complete_objective(repository, identity, objective, lease=lease, result=result)
            self.assertEqual((completed.state, completed.result, replay.state), (ObjectiveState.COMPLETED, result, ObjectiveState.COMPLETED))
            with self.assertRaises(ReviewLifecycleError):
                store.cancel_objective(repository, identity, objective, lease=lease, reason_digest="2" * 64)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute("SELECT state FROM worker_objective_records WHERE objective_id = 'objective-115'").fetchone(), (ObjectiveState.COMPLETED.value,))
            bad = WorkerObjective("objective-116", identity.task_id, identity.base_sha, "attempt-115", "retry-115", "e" * 64)
            with self.assertRaises(ReviewLifecycleError):
                store.start_objective(repository, identity, bad, lease=lease)

    def test_worker_objective_cancellation_and_terminal_replays_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            objective = self.objective(identity)
            store.start_objective(repository, identity, objective, lease=lease)
            cancelled = store.cancel_objective(repository, identity, objective, lease=lease, reason_digest="3" * 64)
            self.assertEqual((cancelled.state, cancelled.cancellation_reason_digest), (ObjectiveState.CANCELLED, "3" * 64))
            self.assertEqual(store.cancel_objective(repository, identity, objective, lease=lease, reason_digest="3" * 64), cancelled)
            with self.assertRaises(ReviewLifecycleError):
                store.cancel_objective(repository, identity, objective, lease=lease, reason_digest="4" * 64)

    def test_worker_objective_rejects_wrong_stale_or_replayed_result_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease = self.setup(Path(temporary))
            store = ReviewLifecycleStore()
            objective = self.objective(identity)
            store.start_objective(repository, identity, objective, lease=lease)
            result = self.persist_objective_result(repository, identity)
            for bad in (
                WorkerObjectiveResult(result.candidate_sha, "0" * 64, result.accepted_result_identity),
                WorkerObjectiveResult(result.candidate_sha, result.completion_evidence_fingerprint, "0" * 64),
                WorkerObjectiveResult("d" * 40, result.completion_evidence_fingerprint, result.accepted_result_identity),
            ):
                with self.assertRaises(ReviewLifecycleError):
                    store.complete_objective(repository, identity, objective, lease=lease, result=bad)
            completed = store.complete_objective(repository, identity, objective, lease=lease, result=result)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("UPDATE provider_completion_outputs SET output_fingerprint = ? WHERE attempt_id = 'attempt-115'", ("0" * 64,))
                connection.commit()
            with self.assertRaises(ReviewLifecycleError):
                store.complete_objective(repository, identity, objective, lease=lease, result=result)
            self.assertEqual(completed.state, ObjectiveState.COMPLETED)
