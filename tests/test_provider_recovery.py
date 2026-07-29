"""Hermetic recovery coverage for provider-neutral Phase 2 turns."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import acquire_transition_lease
from roundwright.provider_recovery import (
    AttemptState,
    ProviderRecoveryError,
    ProviderRole,
    RecoveryAction,
    RecoveryContext,
    accept_supervisor_review,
    prepare_attempt,
    read_attempt,
    record_completed_output,
    record_external_turn,
    record_invalid_output,
    recover_attempt,
)
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


class ProviderRecoveryTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        identity = object.__new__(RepositoryIdentity)
        object.__setattr__(identity, "root", root.resolve())
        return identity

    def identity(self, suffix: str = "one") -> TaskIdentity:
        return TaskIdentity(
            task_id=f"task-22-{suffix}",
            source_id=f"fixture-{suffix}",
            repository_id="ythdelmar68/roundwright",
            branch=f"codex/issue-22-{suffix}",
            worktree=f"C:/private/worktree-{suffix}",
            base_sha="b" * 40,
        )

    def context(self, identity: TaskIdentity, *, candidate: str | None = None) -> RecoveryContext:
        return RecoveryContext.for_task(
            identity,
            candidate_sha=candidate,
            policy_fingerprint="c" * 64,
            deployment_fingerprint="d" * 64,
        )

    def admit(self, repository: RepositoryIdentity, identity: TaskIdentity, lease: object) -> None:
        admit_task(
            repository,
            identity,
            (SourceSnapshot(identity.source_id, identity.repository_id, hashlib.sha256(identity.source_id.encode()).hexdigest()),),
            lease=lease,
        )

    def lease(self, repository: RepositoryIdentity):
        return acquire_transition_lease(
            repository,
            repository_id="ythdelmar68/roundwright",
            owner="recovery-tests",
            ttl_seconds=1000,
        )

    def prepare(self, repository: RepositoryIdentity, identity: TaskIdentity, lease: object, *, role: ProviderRole, attempt: str):
        return prepare_attempt(
            repository,
            identity,
            self.context(identity),
            attempt_id=attempt,
            role=role,
            process_lease_id=f"lease-{attempt}",
            process_lease_expires_at=int(time.time()) + 10,
            input_fingerprint="a" * 64,
            lease=lease,
        )

    def test_external_turn_without_verified_completion_blocks_without_duplicate_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-one")
            record_external_turn(
                repository, identity, self.context(identity), attempt_id="worker-one", session_identity="thread-one",
                external_turn_identity="turn-one", lease=lease,
            )

            recovery = recover_attempt(
                repository, identity, self.context(identity), attempt_id="worker-one", max_attempts=2, lease=lease,
            )

            self.assertEqual(recovery.next_action, RecoveryAction.BLOCKED_AMBIGUOUS_TURN)
            self.assertEqual(recovery.external_turn_identity, "turn-one")
            self.assertEqual(read_attempt(repository, identity, "worker-one").state, AttemptState.AMBIGUOUS)

    def test_no_external_turn_has_a_bounded_retry_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.PLANNING, attempt="plan-one")
            retry = recover_attempt(repository, identity, self.context(identity), attempt_id="plan-one", max_attempts=2, lease=lease)
            self.assertEqual(retry.next_action, RecoveryAction.RETRY)

            self.prepare(repository, identity, lease, role=ProviderRole.PLANNING, attempt="plan-two")
            exhausted = recover_attempt(repository, identity, self.context(identity), attempt_id="plan-two", max_attempts=2, lease=lease)
            self.assertEqual(exhausted.next_action, RecoveryAction.BLOCKED_RETRY_LIMIT)
            self.assertEqual(read_attempt(repository, identity, "plan-two").state, AttemptState.BLOCKED)

    def test_verified_completed_output_is_consumed_idempotently_and_is_owner_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-output")
            record_external_turn(repository, identity, self.context(identity), attempt_id="worker-output", session_identity="thread-output", external_turn_identity="turn-output", lease=lease)
            record_completed_output(
                repository, identity, self.context(identity), attempt_id="worker-output", output_pointer="private-output-pointer",
                completion_evidence_fingerprint="e" * 64, lease=lease,
            )
            recovery = recover_attempt(
                repository, identity, self.context(identity), attempt_id="worker-output", verified_completion_evidence="e" * 64,
                max_attempts=1, lease=lease,
            )
            self.assertEqual(recovery.next_action, RecoveryAction.CONSUME_VERIFIED_OUTPUT)
            self.assertTrue(recovery.output_available)
            self.assertNotIn("private-output-pointer", repr(recovery))

    def test_stale_worker_blocks_only_that_task_while_stale_supervisor_requires_a_fresh_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            worker = self.identity("worker")
            supervisor = self.identity("supervisor")
            self.admit(repository, worker, lease)
            self.admit(repository, supervisor, lease)
            for identity, role, attempt in ((worker, ProviderRole.WORKER, "worker-stale"), (supervisor, ProviderRole.SUPERVISOR, "supervisor-stale")):
                self.prepare(repository, identity, lease, role=role, attempt=attempt)
                record_external_turn(repository, identity, self.context(identity), attempt_id=attempt, session_identity=f"session-{attempt}", external_turn_identity=f"turn-{attempt}", lease=lease)

            expired = int(time.time()) + 11
            worker_recovery = recover_attempt(repository, worker, self.context(worker), attempt_id="worker-stale", max_attempts=2, lease=lease, now=expired)
            supervisor_recovery = recover_attempt(repository, supervisor, self.context(supervisor), attempt_id="supervisor-stale", max_attempts=2, lease=lease, now=expired)
            self.assertEqual(worker_recovery.next_action, RecoveryAction.BLOCKED_STALE_WORKER)
            self.assertEqual(supervisor_recovery.next_action, RecoveryAction.FRESH_SUPERVISOR_SESSION)
            self.assertEqual(read_attempt(repository, worker, "worker-stale").state, AttemptState.BLOCKED)
            self.assertEqual(read_attempt(repository, supervisor, "supervisor-stale").state, AttemptState.INVALIDATED)
            with self.assertRaises(ProviderRecoveryError):
                accept_supervisor_review(repository, supervisor, self.context(supervisor), attempt_id="supervisor-stale", accepted_review_identity="partial-pass", lease=lease)

    def test_accepted_review_identity_is_separate_from_completion_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="review-one")
            record_external_turn(repository, identity, self.context(identity), attempt_id="review-one", session_identity="review-session", external_turn_identity="review-turn", lease=lease)
            record_completed_output(repository, identity, self.context(identity), attempt_id="review-one", output_pointer="review-output", completion_evidence_fingerprint="e" * 64, lease=lease)
            accepted = accept_supervisor_review(repository, identity, self.context(identity), attempt_id="review-one", accepted_review_identity="accepted-cycle-one", lease=lease)
            self.assertEqual(accepted.state, AttemptState.ACCEPTED)
            self.assertEqual(accepted.accepted_review_identity, "accepted-cycle-one")
            recovery = recover_attempt(repository, identity, self.context(identity), attempt_id="review-one", max_attempts=1, lease=lease)
            self.assertEqual(recovery.next_action, RecoveryAction.ACCEPTED_REVIEW)

    def test_invalid_outputs_and_recovery_attempts_are_counted_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-invalid")
            record_external_turn(repository, identity, self.context(identity), attempt_id="worker-invalid", session_identity="invalid-session", external_turn_identity="invalid-turn", lease=lease)
            record_invalid_output(
                repository, identity, self.context(identity), attempt_id="worker-invalid", output_pointer="invalid-output",
                output_fingerprint="e" * 64, reason_fingerprint="f" * 64, lease=lease,
            )
            recovery = recover_attempt(repository, identity, self.context(identity), attempt_id="worker-invalid", max_attempts=1, lease=lease)
            self.assertEqual(recovery.next_action, RecoveryAction.BLOCKED_AMBIGUOUS_TURN)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_invalid_outputs").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_recovery_events").fetchone(), (1,))
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
