"""Hermetic recovery coverage for provider-neutral Phase 2 turns."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity, ProviderProfile, ReasoningEffort
from roundwright.runtime_binding import RuntimeBinding
from roundwright.git_identity import acquire_transition_lease
from roundwright.provider_recovery import (
    AttemptState,
    ProviderRecoveryError,
    ProviderRole,
    RecoveryAction,
    RecoveryContext,
    accept_supervisor_review,
    invalidate_supervisor_attempt,
    prepare_attempt,
    read_attempt,
    record_completed_output,
    record_external_turn,
    record_invalid_output,
    record_session_identity,
    recover_attempt,
)
from roundwright.provider_health import CodexCapability, CodexHealthContract, CodexRuntimeAudit, HealthState, ProviderHealthAuditIdentity, ProviderHealthObservation, ProviderHealthReceipt, profile_fingerprint
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


class ProviderRecoveryTests(unittest.TestCase):
    def runtime_binding(self) -> RuntimeBinding:
        worker = profile_fingerprint(ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH))
        supervisors = (
            profile_fingerprint(ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH, "primary")),
            profile_fingerprint(ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback")),
            profile_fingerprint(ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH, "fallback-retry")),
        )
        return RuntimeBinding(
            "roundwright-runtime/v1", "sha256:" + "a" * 64, worker, supervisors,
            1, 3, 3, "worker-final-repair-then-merge", "b" * 64,
        )

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

    def context(self, identity: TaskIdentity, *, candidate: str | None = None, role: ProviderRole = ProviderRole.WORKER) -> RecoveryContext:
        binding = self.runtime_binding()
        selected = ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH, "primary") if role is ProviderRole.SUPERVISOR else ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        profile = profile_fingerprint(selected)
        audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(selected.model, selected.reasoning_effort.value),))
        observation = ProviderHealthObservation(role, profile, CodexHealthContract(audit.sdk_version, audit.runtime_version, identity.base_sha).fingerprint, audit.fingerprint, HealthState.READY, None, 0, 2_000_000_000, 1)
        ordinal = 0 if role is ProviderRole.PLANNING else 1 if role is ProviderRole.WORKER else 2
        receipt = ProviderHealthReceipt(identity.base_sha, candidate, "case-22", ordinal, binding, role, profile, observation, ProviderHealthAuditIdentity(audit, selected))
        return RecoveryContext.for_task(
            identity,
            candidate_sha=candidate,
            policy_fingerprint="c" * 64,
            deployment_fingerprint="d" * 64,
            runtime_binding=binding, health_contract_commit=identity.base_sha, shadow_case_id="case-22", health_receipt=receipt,
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
            self.context(identity, role=role),
            attempt_id=attempt,
            role=role,
            process_lease_id=f"lease-{attempt}",
            process_lease_expires_at=int(time.time()) + 10,
            input_fingerprint="a" * 64,
            lease=lease,
        )

    def test_missing_or_role_mismatched_health_blocks_before_attempt_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            valid = self.context(identity, role=ProviderRole.WORKER)
            for name, context in (
                ("missing", replace(valid, health_receipt=None)),
                ("mismatched", self.context(identity, role=ProviderRole.SUPERVISOR)),
            ):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ProviderRecoveryError, "health authorization"):
                        prepare_attempt(
                            repository, identity, context, attempt_id=f"health-{name}", role=ProviderRole.WORKER,
                            process_lease_id=f"lease-health-{name}", process_lease_expires_at=int(time.time()) + 10,
                            input_fingerprint="a" * 64, lease=lease,
                        )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_attempts").fetchone(), (0,))
            finally:
                connection.close()

    def test_prepared_attempt_persists_and_rechecks_the_exact_fresh_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity(); self.admit(repository, identity, lease)
            context = self.context(identity)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="bound-health")
            connection = sqlite3.connect(database_path(repository))
            try:
                row = connection.execute("SELECT contract_commit, candidate_sha, case_id, receipt_digest, selection_ordinal, fresh_until, health_contract_identity FROM provider_attempt_health_authorizations WHERE attempt_id = ?", ("bound-health",)).fetchone()
            finally:
                connection.close()
            receipt = context.health_receipt
            self.assertEqual(row, (receipt.contract_commit, receipt.candidate_sha, receipt.case_id, receipt.receipt_digest, receipt.selection_ordinal, receipt.observation.fresh_until, receipt.observation.health_contract_identity))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_attempt_health_authorizations SET fresh_until = ? WHERE attempt_id = ?", (int(time.time()), "bound-health")); connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ProviderRecoveryError):
                record_session_identity(repository, identity, context, attempt_id="bound-health", session_identity="blocked-session", lease=lease)
            self.assertIsNone(read_attempt(repository, identity, "bound-health").session_identity)

    def test_existing_dispatched_attempt_never_recreates_a_deleted_health_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("deleted-health"); self.admit(repository, identity, lease)
            context = self.context(identity); self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="dispatched-health")
            record_session_identity(repository, identity, context, attempt_id="dispatched-health", session_identity="health-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="dispatched-health", session_identity="health-session", external_turn_identity="health-turn", lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("DELETE FROM provider_attempt_health_authorizations WHERE attempt_id = ?", ("dispatched-health",)); connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ProviderRecoveryError):
                prepare_attempt(repository, identity, context, attempt_id="dispatched-health", role=ProviderRole.WORKER, process_lease_id="lease-dispatched-health", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            with self.assertRaises(ProviderRecoveryError):
                record_external_turn(repository, identity, context, attempt_id="dispatched-health", session_identity="health-session", external_turn_identity="health-turn", lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertIsNone(connection.execute("SELECT 1 FROM provider_attempt_health_authorizations WHERE attempt_id = ?", ("dispatched-health",)).fetchone())
                self.assertIsNotNone(connection.execute("SELECT 1 FROM provider_attempt_health_seals WHERE attempt_id = ?", ("dispatched-health",)).fetchone())
            finally:
                connection.close()

    def test_every_later_transition_fails_when_its_authorization_row_is_deleted(self) -> None:
        for operation in ("complete", "invalid", "accept", "invalidate", "recover"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository(Path(temporary)); initialize(repository)
                lease = self.lease(repository); role = ProviderRole.SUPERVISOR if operation in {"accept", "invalidate"} else ProviderRole.WORKER
                identity = self.identity(operation); self.admit(repository, identity, lease)
                context = self.context(identity, role=role); attempt = f"health-{operation}"
                self.prepare(repository, identity, lease, role=role, attempt=attempt)
                if operation in {"complete", "invalid", "accept"}:
                    record_session_identity(repository, identity, context, attempt_id=attempt, session_identity=f"session-{operation}", lease=lease)
                    record_external_turn(repository, identity, context, attempt_id=attempt, session_identity=f"session-{operation}", external_turn_identity=f"turn-{operation}", lease=lease)
                if operation == "accept":
                    record_completed_output(repository, identity, context, attempt_id=attempt, output_pointer="review-output", completion_evidence_fingerprint="e" * 64, lease=lease)
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute("DELETE FROM provider_attempt_health_authorizations WHERE attempt_id = ?", (attempt,)); connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(ProviderRecoveryError):
                    if operation == "complete": record_completed_output(repository, identity, context, attempt_id=attempt, output_pointer="output", completion_evidence_fingerprint="e" * 64, lease=lease)
                    elif operation == "invalid": record_invalid_output(repository, identity, context, attempt_id=attempt, output_pointer="output", output_fingerprint="f" * 64, reason_fingerprint="e" * 64, lease=lease)
                    elif operation == "accept": accept_supervisor_review(repository, identity, context, attempt_id=attempt, accepted_review_identity="accepted", lease=lease)
                    elif operation == "invalidate": invalidate_supervisor_attempt(repository, identity, context, attempt_id=attempt, lease=lease)
                    else: recover_attempt(repository, identity, context, attempt_id=attempt, max_attempts=2, lease=lease)

    def test_every_authorization_field_is_sealed_against_later_transition_drift(self) -> None:
        mutations = (
            ("contract_commit", "a" * 40, "not-a-commit"), ("candidate_sha", "a" * 40, "not-a-commit"),
            ("case_id", "case-drift", ""), ("receipt_digest", "sha256:" + "f" * 64, "malformed"),
            ("selection_ordinal", 0, -1), ("fresh_until", 2_000_000_001, 0),
            ("health_contract_identity", "sha256:" + "f" * 64, "malformed"),
            ("provider_role", ProviderRole.PLANNING.value, "invalid-role"),
            ("profile_identity", "sha256:" + "f" * 64, "malformed"),
        )
        operations = ("complete", "invalid", "accept", "invalidate", "recover")
        for operation in operations:
            for column, valid_drift, malformed in mutations:
                for variant, replacement in (("drift", valid_drift), ("malformed", malformed)):
                    with self.subTest(operation=operation, column=column, variant=variant), tempfile.TemporaryDirectory() as temporary:
                        repository = self.repository(Path(temporary)); initialize(repository)
                        lease = self.lease(repository)
                        role = ProviderRole.SUPERVISOR if operation in {"accept", "invalidate"} else ProviderRole.WORKER
                        identity = self.identity(f"sealed-{operation}-{column}"); self.admit(repository, identity, lease)
                        context = self.context(identity, role=role); attempt = f"sealed-{operation}"
                        self.prepare(repository, identity, lease, role=role, attempt=attempt)
                        if operation in {"complete", "invalid", "accept"}:
                            record_session_identity(repository, identity, context, attempt_id=attempt, session_identity="sealed-session", lease=lease)
                            record_external_turn(repository, identity, context, attempt_id=attempt, session_identity="sealed-session", external_turn_identity="sealed-turn", lease=lease)
                        if operation == "accept":
                            record_completed_output(repository, identity, context, attempt_id=attempt, output_pointer="sealed-output", completion_evidence_fingerprint="e" * 64, lease=lease)
                        connection = sqlite3.connect(database_path(repository))
                        try:
                            connection.execute(f"UPDATE provider_attempt_health_authorizations SET {column} = ? WHERE attempt_id = ?", (replacement, attempt)); connection.commit()
                        finally:
                            connection.close()
                        with self.assertRaises(ProviderRecoveryError):
                            if operation == "complete": record_completed_output(repository, identity, context, attempt_id=attempt, output_pointer="output", completion_evidence_fingerprint="e" * 64, lease=lease)
                            elif operation == "invalid": record_invalid_output(repository, identity, context, attempt_id=attempt, output_pointer="output", output_fingerprint="f" * 64, reason_fingerprint="e" * 64, lease=lease)
                            elif operation == "accept": accept_supervisor_review(repository, identity, context, attempt_id=attempt, accepted_review_identity="accepted", lease=lease)
                            elif operation == "invalidate": invalidate_supervisor_attempt(repository, identity, context, attempt_id=attempt, lease=lease)
                            else: recover_attempt(repository, identity, context, attempt_id=attempt, max_attempts=2, lease=lease)

    def test_original_checkpoint_rejects_a_recomputed_authorization_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("recomputed-seal"); self.admit(repository, identity, lease)
            context = self.context(identity); self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="sealed-attempt")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_attempt_health_authorizations SET contract_commit = ? WHERE attempt_id = ?", ("a" * 40, "sealed-attempt"))
                values = connection.execute("SELECT contract_commit, candidate_sha, case_id, receipt_digest, selection_ordinal, fresh_until, health_contract_identity, provider_role, profile_identity FROM provider_attempt_health_authorizations WHERE attempt_id = ?", ("sealed-attempt",)).fetchone()
                replacement = hashlib.sha256("\x00".join(("sealed-attempt", *("" if value is None else str(value) for value in values))).encode()).hexdigest()
                connection.execute("UPDATE provider_attempt_health_seals SET authorization_fingerprint = ? WHERE attempt_id = ?", (replacement, "sealed-attempt")); connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ProviderRecoveryError):
                recover_attempt(repository, identity, context, attempt_id="sealed-attempt", max_attempts=1, lease=lease)
    def test_external_turn_without_verified_completion_blocks_without_duplicate_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-one")
            record_session_identity(repository, identity, self.context(identity), attempt_id="worker-one", session_identity="thread-one", lease=lease)
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
            record_session_identity(repository, identity, self.context(identity), attempt_id="worker-output", session_identity="thread-output", lease=lease)
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
                record_session_identity(repository, identity, self.context(identity, role=role), attempt_id=attempt, session_identity=f"session-{attempt}", lease=lease)
                record_external_turn(repository, identity, self.context(identity, role=role), attempt_id=attempt, session_identity=f"session-{attempt}", external_turn_identity=f"turn-{attempt}", lease=lease)

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
            record_session_identity(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="review-one", session_identity="review-session", lease=lease)
            record_external_turn(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="review-one", session_identity="review-session", external_turn_identity="review-turn", lease=lease)
            record_completed_output(repository, identity, self.context(identity), attempt_id="review-one", output_pointer="review-output", completion_evidence_fingerprint="e" * 64, lease=lease)
            accepted = accept_supervisor_review(repository, identity, self.context(identity), attempt_id="review-one", accepted_review_identity="accepted-cycle-one", lease=lease)
            self.assertEqual(accepted.state, AttemptState.ACCEPTED)
            self.assertEqual(accepted.accepted_review_identity, "accepted-cycle-one")
            recovery = recover_attempt(repository, identity, self.context(identity), attempt_id="review-one", max_attempts=1, lease=lease)
            self.assertEqual(recovery.next_action, RecoveryAction.ACCEPTED_REVIEW)
            self.assertEqual(
                read_attempt(repository, identity, "review-one", context=self.context(identity)).state,
                AttemptState.ACCEPTED,
            )
            with self.assertRaisesRegex(ProviderRecoveryError, "exact recovery context"):
                read_attempt(repository, identity, "review-one")
            for column, replacement in (
                ("review_complete_rounds", 2), ("review_max_rounds", 4),
                ("review_max_supervisor_attempts_per_round", 2), ("review_on_final_findings", "block"),
                ("review_policy_digest", "f" * 64),
            ):
                with self.subTest(review_policy_column=column):
                    connection = sqlite3.connect(database_path(repository))
                    try:
                        original = connection.execute(f"SELECT {column} FROM accepted_provider_reviews WHERE attempt_id = ?", ("review-one",)).fetchone()[0]
                        connection.execute(f"UPDATE accepted_provider_reviews SET {column} = ? WHERE attempt_id = ?", (replacement, "review-one")); connection.commit()
                    finally:
                        connection.close()
                    with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review"):
                        accept_supervisor_review(repository, identity, self.context(identity), attempt_id="review-one", accepted_review_identity="accepted-cycle-one", lease=lease)
                    with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review"):
                        recover_attempt(repository, identity, self.context(identity), attempt_id="review-one", max_attempts=1, lease=lease)
                    with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review"):
                        read_attempt(repository, identity, "review-one", context=self.context(identity))
                    connection = sqlite3.connect(database_path(repository))
                    try:
                        connection.execute(f"UPDATE accepted_provider_reviews SET {column} = ? WHERE attempt_id = ?", (original, "review-one")); connection.commit()
                    finally:
                        connection.close()

    def test_generic_supervisor_acceptance_rejects_specialized_pointers_and_pointer_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            context = self.context(identity, role=ProviderRole.SUPERVISOR)
            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="reserved-review")
            record_session_identity(repository, identity, context, attempt_id="reserved-review", session_identity="reserved-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="reserved-review", session_identity="reserved-session", external_turn_identity="reserved-turn", lease=lease)
            record_completed_output(repository, identity, context, attempt_id="reserved-review", output_pointer="reserved-output", completion_evidence_fingerprint="e" * 64, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_attempts SET output_pointer = ? WHERE attempt_id = ?", ("plan-review:forged", "reserved-review")); connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ProviderRecoveryError, "generic review evidence"):
                accept_supervisor_review(repository, identity, context, attempt_id="reserved-review", accepted_review_identity="reserved-accepted", lease=lease)
            with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review is invalid"):
                read_attempt(repository, identity, "reserved-review")

            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="generic-review")
            record_session_identity(repository, identity, context, attempt_id="generic-review", session_identity="generic-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="generic-review", session_identity="generic-session", external_turn_identity="generic-turn", lease=lease)
            record_completed_output(repository, identity, context, attempt_id="generic-review", output_pointer="generic-output", completion_evidence_fingerprint="f" * 64, lease=lease)
            accept_supervisor_review(repository, identity, context, attempt_id="generic-review", accepted_review_identity="generic-accepted", lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_attempts SET output_pointer = ? WHERE attempt_id = ?", ("diff-review:forged", "generic-review")); connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review is invalid"):
                read_attempt(repository, identity, "generic-review", context=context)
            with self.assertRaisesRegex(ProviderRecoveryError, "accepted supervisor review is invalid"):
                recover_attempt(repository, identity, context, attempt_id="generic-review", max_attempts=1, lease=lease)

    def test_invalid_outputs_and_recovery_attempts_are_counted_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-invalid")
            record_session_identity(repository, identity, self.context(identity), attempt_id="worker-invalid", session_identity="invalid-session", lease=lease)
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

    def test_persisted_session_checkpoint_resumes_the_same_thread_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="worker-session")
            recorded = record_session_identity(
                repository, identity, self.context(identity), attempt_id="worker-session", session_identity="thread-session", lease=lease,
            )
            replayed = record_session_identity(
                repository, identity, self.context(identity), attempt_id="worker-session", session_identity="thread-session", lease=lease,
            )
            self.assertEqual(recorded, replayed)
            self.assertEqual(read_attempt(repository, identity, "worker-session").session_identity, "thread-session")
            recovery = recover_attempt(repository, identity, self.context(identity), attempt_id="worker-session", max_attempts=1, lease=lease)
            self.assertEqual(recovery.next_action, RecoveryAction.RESUME_SAME_SESSION)
            self.assertEqual(recovery.session_identity, "thread-session")
            with self.assertRaises(ProviderRecoveryError):
                record_session_identity(repository, identity, self.context(identity), attempt_id="worker-session", session_identity="different-thread", lease=lease)
            record_external_turn(
                repository, identity, self.context(identity), attempt_id="worker-session", session_identity="thread-session",
                external_turn_identity="turn-after-resume", lease=lease,
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_session_checkpoints").fetchone(), (1,))
            finally:
                connection.close()

    def test_identity_drift_returns_an_owner_safe_block_without_mutating_the_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            context = self.context(identity, candidate="a" * 40)
            prepare_attempt(
                repository, identity, context, attempt_id="candidate-drift", role=ProviderRole.WORKER,
                process_lease_id="lease-candidate-drift", process_lease_expires_at=int(time.time()) + 10,
                input_fingerprint="a" * 64, lease=lease,
            )
            changed = hashlib.sha256(b"identity-drift").hexdigest()
            for field in (
                "repository_fingerprint", "worktree_fingerprint", "branch_fingerprint", "base_fingerprint",
                "candidate_fingerprint", "policy_fingerprint", "deployment_fingerprint",
            ):
                with self.subTest(field=field):
                    recovery = recover_attempt(
                        repository, identity, replace(context, **{field: changed}), attempt_id="candidate-drift", max_attempts=1, lease=lease,
                    )
                    self.assertEqual(recovery.next_action, RecoveryAction.BLOCKED_IDENTITY_DRIFT)
                    self.assertEqual(recovery.blocker, "identity-drift")
            for field, value in (
                ("review_complete_rounds", 2), ("review_max_rounds", 4),
                ("review_max_supervisor_attempts_per_round", 2),
                ("review_on_final_findings", "drift"), ("review_policy_digest", "f" * 64),
            ):
                drifted_binding = replace(context.runtime_binding)
                object.__setattr__(drifted_binding, field, value)
                with self.subTest(field=field):
                    recovery = recover_attempt(repository, identity, replace(context, runtime_binding=drifted_binding), attempt_id="candidate-drift", max_attempts=1, lease=lease)
                    self.assertEqual((recovery.next_action, recovery.blocker), (RecoveryAction.BLOCKED_IDENTITY_DRIFT, "identity-drift"))
            self.assertEqual(read_attempt(repository, identity, "candidate-drift").state, AttemptState.PREPARED)
            self.assertNotIn(identity.worktree, repr(recovery))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_recovery_events").fetchone(), (0,))
            finally:
                connection.close()

    def test_context_is_bound_to_each_attempt_after_candidate_and_policy_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            first = self.context(identity, candidate="a" * 40, role=ProviderRole.SUPERVISOR)
            prepare_attempt(repository, identity, first, attempt_id="supervisor-first", role=ProviderRole.SUPERVISOR, process_lease_id="lease-supervisor-first", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            second = replace(
                self.context(identity, candidate="b" * 40, role=ProviderRole.SUPERVISOR), policy_fingerprint="e" * 64, deployment_fingerprint="f" * 64,
            )
            fresh = prepare_attempt(repository, identity, second, attempt_id="supervisor-second", role=ProviderRole.SUPERVISOR, process_lease_id="lease-supervisor-second", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="b" * 64, lease=lease)
            self.assertEqual(fresh.attempt_number, 2)
            self.assertEqual(recover_attempt(repository, identity, first, attempt_id="supervisor-first", max_attempts=3, lease=lease).next_action, RecoveryAction.RETRY)
            self.assertEqual(recover_attempt(repository, identity, second, attempt_id="supervisor-second", max_attempts=3, lease=lease).next_action, RecoveryAction.RETRY)

    def test_late_verified_completion_restores_a_reviewable_ambiguous_supervisor_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="late-completion")
            record_session_identity(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="late-completion", session_identity="late-thread", lease=lease)
            record_external_turn(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="late-completion", session_identity="late-thread", external_turn_identity="late-turn", lease=lease)
            record_completed_output(repository, identity, self.context(identity), attempt_id="late-completion", output_pointer="late-output", completion_evidence_fingerprint="e" * 64, lease=lease)
            self.assertEqual(recover_attempt(repository, identity, self.context(identity), attempt_id="late-completion", max_attempts=1, lease=lease).next_action, RecoveryAction.BLOCKED_AMBIGUOUS_TURN)
            conflicting = recover_attempt(repository, identity, self.context(identity), attempt_id="late-completion", verified_completion_evidence="f" * 64, max_attempts=1, lease=lease)
            self.assertEqual((conflicting.next_action, conflicting.blocker), (RecoveryAction.BLOCKED_AMBIGUOUS_TURN, "completion-evidence-unverified"))
            verified = recover_attempt(repository, identity, self.context(identity), attempt_id="late-completion", verified_completion_evidence="e" * 64, max_attempts=1, lease=lease)
            self.assertEqual(verified.next_action, RecoveryAction.CONSUME_VERIFIED_OUTPUT)
            self.assertEqual(read_attempt(repository, identity, "late-completion").state, AttemptState.COMPLETED)
            self.assertEqual(recover_attempt(repository, identity, self.context(identity), attempt_id="late-completion", verified_completion_evidence="e" * 64, max_attempts=1, lease=lease).next_action, RecoveryAction.CONSUME_VERIFIED_OUTPUT)
            self.assertEqual(
                accept_supervisor_review(repository, identity, self.context(identity), attempt_id="late-completion", accepted_review_identity="late-accepted", lease=lease).state,
                AttemptState.ACCEPTED,
            )

    def test_stale_session_only_supervisor_invalidates_a_delayed_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="session-only-supervisor")
            record_session_identity(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="session-only-supervisor", session_identity="review-thread", lease=lease)
            recovery = recover_attempt(repository, identity, self.context(identity), attempt_id="session-only-supervisor", max_attempts=2, lease=lease, now=int(time.time()) + 11)
            self.assertEqual(recovery.next_action, RecoveryAction.FRESH_SUPERVISOR_SESSION)
            self.assertEqual(read_attempt(repository, identity, "session-only-supervisor").state, AttemptState.INVALIDATED)
            with self.assertRaises(ProviderRecoveryError):
                record_external_turn(repository, identity, self.context(identity), attempt_id="session-only-supervisor", session_identity="review-thread", external_turn_identity="delayed-turn", lease=lease)
            with self.assertRaises(ProviderRecoveryError):
                record_completed_output(repository, identity, self.context(identity), attempt_id="session-only-supervisor", output_pointer="delayed-output", completion_evidence_fingerprint="e" * 64, lease=lease)
            with self.assertRaises(ProviderRecoveryError):
                accept_supervisor_review(repository, identity, self.context(identity), attempt_id="session-only-supervisor", accepted_review_identity="delayed-review", lease=lease)
            self.prepare(repository, identity, lease, role=ProviderRole.SUPERVISOR, attempt="fresh-supervisor")
            with self.assertRaises(ProviderRecoveryError):
                record_session_identity(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="fresh-supervisor", session_identity="review-thread", lease=lease)
            self.assertEqual(
                record_session_identity(repository, identity, self.context(identity, role=ProviderRole.SUPERVISOR), attempt_id="fresh-supervisor", session_identity="fresh-review-thread", lease=lease).session_identity,
                "fresh-review-thread",
            )

    def test_multiple_attempts_can_continue_one_persistent_worker_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            for attempt, turn in (("persistent-one", "persistent-turn-one"), ("persistent-two", "persistent-turn-two")):
                self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt=attempt)
                record_session_identity(repository, identity, self.context(identity), attempt_id=attempt, session_identity="persistent-thread", lease=lease)
                record_external_turn(repository, identity, self.context(identity), attempt_id=attempt, session_identity="persistent-thread", external_turn_identity=turn, lease=lease)
            self.assertEqual(read_attempt(repository, identity, "persistent-two").attempt_number, 2)

    def test_terminal_block_and_invalid_output_replays_keep_their_original_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            lease = self.lease(repository)
            identity = self.identity()
            self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.PLANNING, attempt="retry-block")
            first = recover_attempt(repository, identity, self.context(identity), attempt_id="retry-block", max_attempts=1, lease=lease)
            replay = recover_attempt(repository, identity, self.context(identity), attempt_id="retry-block", max_attempts=1, lease=lease)
            self.assertEqual((replay.next_action, replay.blocker), (first.next_action, first.blocker))

            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="invalid-replay")
            record_session_identity(repository, identity, self.context(identity), attempt_id="invalid-replay", session_identity="invalid-replay-thread", lease=lease)
            record_external_turn(repository, identity, self.context(identity), attempt_id="invalid-replay", session_identity="invalid-replay-thread", external_turn_identity="invalid-replay-turn", lease=lease)
            first_invalid = record_invalid_output(repository, identity, self.context(identity), attempt_id="invalid-replay", output_pointer="invalid-replay-output", output_fingerprint="e" * 64, reason_fingerprint="f" * 64, lease=lease)
            self.assertEqual(record_invalid_output(repository, identity, self.context(identity), attempt_id="invalid-replay", output_pointer="invalid-replay-output", output_fingerprint="e" * 64, reason_fingerprint="f" * 64, lease=lease), first_invalid)
            with self.assertRaises(ProviderRecoveryError):
                record_invalid_output(repository, identity, self.context(identity), attempt_id="invalid-replay", output_pointer="invalid-replay-output", output_fingerprint="e" * 64, reason_fingerprint="a" * 64, lease=lease)


if __name__ == "__main__":
    unittest.main()
