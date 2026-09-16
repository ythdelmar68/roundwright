"""Hermetic recovery coverage for provider-neutral Phase 2 turns."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing
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
    record_supervisor_terminal_failure,
    SupervisorTerminalFailureClass,
    SupervisorTerminalFailureSource,
    SupervisorTerminalFailureSdkCategory,
)
from roundwright.review_lifecycle import ObjectiveState, ReviewLifecycleError, ReviewLifecycleStore, WorkerObjective, WorkerObjectiveResult, _owner_authority_digest
from roundwright.provider_health import CodexCapability, CodexHealthContract, CodexRuntimeAudit, HealthState, ProviderHealthAuditIdentity, ProviderHealthObservation, ProviderHealthReceipt, profile_fingerprint
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize
from roundwright.failure_recovery import Clearance, ClearanceRevocation, DurableRecoveryRouteAuthorization, EvidenceSource, FailureBinding, FailureClass, FailureRole, _denial_authority_digest, abandon_durable_recovery_route_reservation, begin_durable_recovery_route_reservation, classify, commit_durable_recovery_route_successor_admission, consume_durable_recovery_route_authorization, issue_durable_recovery_route_authorization, read_durable_recovery_route_authorization, read_durable_failure, record_durable_clearance, record_durable_clearance_revocation, record_durable_failure, release_durable_recovery_route_authorization, require_scope_open


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

    def seal_candidate(self, repository: RepositoryIdentity, identity: TaskIdentity, lease: object, candidate: str) -> None:
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute(
                "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                (identity.task_id, identity.base_sha, candidate, lease.state_identity),
            )
            connection.commit()
        finally:
            connection.close()

    def denial_command(self, repository: RepositoryIdentity, identity: TaskIdentity, record, command_id: str, *, kind: str) -> None:
        """Seed one consumed command in the dedicated denial namespace."""
        connection = sqlite3.connect(database_path(repository))
        grant_id = f"{kind}-grant-{identity.task_id}"
        candidate = record.binding.candidate_sha
        seal = connection.execute("SELECT state_identity FROM candidate_seals WHERE task_id = ?", (identity.task_id,)).fetchone()[0]
        scope = record.binding.authority_scope
        denial = record.digest
        command_kind = "clear-denial" if kind == "clear" else "revoke-denial-clearance"
        grants = "denial_clearance_authority_grants" if kind == "clear" else "denial_revocation_authority_grants"
        commands = "denial_clearance_commands" if kind == "clear" else "denial_revocation_commands"
        authority = _denial_authority_digest(kind=command_kind, owner="ythdelmar68", task_id=identity.task_id, repository_id=identity.repository_id, candidate_sha=candidate, candidate_seal=seal, authority_scope=scope, target_digest=denial)
        try:
            connection.execute(
                f"INSERT OR IGNORE INTO {grants}(grant_id, owner_identity, task_id, repository_id, candidate_sha, candidate_seal, authority_scope, target_digest, authority_digest, state) VALUES (?, 'ythdelmar68', ?, ?, ?, ?, ?, ?, ?, 'active')",
                (grant_id, identity.task_id, identity.repository_id, candidate, seal, scope, denial, authority),
            )
            if kind == "clear":
                connection.execute(
                    f"INSERT INTO {commands}(command_id, task_id, repository_id, denial_digest, authority_grant_id, candidate_sha, candidate_seal, authority_scope, target_digest, command_kind, command_digest, host_result_digest, result_digest, idempotency_key, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'clear-denial', ?, ?, ?, ?, 'consumed')",
                    (command_id, identity.task_id, identity.repository_id, denial, grant_id, candidate, seal, scope, denial, "a" * 64, "b" * 64, "c" * 64, f"key-{command_id}"),
                )
            else:
                clearance = connection.execute("SELECT decision_digest FROM denial_clearance_decisions WHERE task_id = ? AND record_digest = ? AND command_kind = 'clear-denial' ORDER BY sequence DESC LIMIT 1", (identity.task_id, denial)).fetchone()[0]
                connection.execute(
                    f"INSERT INTO {commands}(command_id, task_id, repository_id, denial_digest, clearance_digest, authority_grant_id, candidate_sha, candidate_seal, authority_scope, target_digest, command_kind, command_digest, host_result_digest, result_digest, idempotency_key, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'revoke-denial-clearance', ?, ?, ?, ?, 'consumed')",
                    (command_id, identity.task_id, identity.repository_id, denial, clearance, grant_id, candidate, seal, scope, denial, "a" * 64, "b" * 64, "c" * 64, f"key-{command_id}"),
                )
            connection.commit()
        finally:
            connection.close()

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

    def test_identity_drift_terminalizes_a_worker_objective_with_its_recovery_evidence(self) -> None:
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
            record_session_identity(repository, identity, context, attempt_id="candidate-drift", session_identity="drift-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="candidate-drift", session_identity="drift-session", external_turn_identity="drift-turn", lease=lease)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("INSERT INTO implementation_attempts(implementation_attempt_id, task_id, plan_attempt_id, accepted_plan_review_identity, provider_attempt_id, worker_thread_identity, external_turn_identity, input_digest, state, created_at) VALUES ('drift-implementation', ?, 'plan-drift', 'review-drift', 'candidate-drift', 'drift-session', 'drift-turn', ?, 'dispatched', 1)", (identity.task_id, "a" * 64))
                connection.commit()
            objective = WorkerObjective("drift-objective", identity.task_id, identity.base_sha, "candidate-drift", "worker-1-candidate-drift", "e" * 64)
            ReviewLifecycleStore().start_objective(repository, identity, objective, lease=lease)
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
            self.assertEqual(read_attempt(repository, identity, "candidate-drift").state, AttemptState.AMBIGUOUS)
            self.assertNotIn(identity.worktree, repr(recovery))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_recovery_events").fetchone(), (12,))
                self.assertEqual(connection.execute("SELECT state FROM worker_objective_records WHERE objective_id = 'drift-objective'").fetchone(), (ObjectiveState.CANCELLED.value,))
            finally:
                connection.close()

    def test_stale_worker_recovery_cancels_the_objective_atomically_and_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("objective-recovery"); self.admit(repository, identity, lease)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="objective-worker")
            context = self.context(identity)
            record_session_identity(repository, identity, context, attempt_id="objective-worker", session_identity="objective-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="objective-worker", session_identity="objective-session", external_turn_identity="objective-turn", lease=lease)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("INSERT INTO implementation_attempts(implementation_attempt_id, task_id, plan_attempt_id, accepted_plan_review_identity, provider_attempt_id, worker_thread_identity, external_turn_identity, input_digest, state, created_at) VALUES ('objective-implementation', ?, 'plan-objective', 'review-objective', 'objective-worker', 'objective-session', 'objective-turn', ?, 'dispatched', 1)", (identity.task_id, "a" * 64))
                connection.commit()
            objective = WorkerObjective("objective-recovery", identity.task_id, identity.base_sha, "objective-worker", "worker-1-objective-worker", "e" * 64)
            ReviewLifecycleStore().start_objective(repository, identity, objective, lease=lease)
            first = recover_attempt(repository, identity, context, attempt_id="objective-worker", max_attempts=1, lease=lease, now=int(time.time()) + 11)
            replay = recover_attempt(repository, identity, context, attempt_id="objective-worker", max_attempts=1, lease=lease, now=int(time.time()) + 11)
            self.assertEqual((first.next_action, replay.next_action), (RecoveryAction.BLOCKED_STALE_WORKER, RecoveryAction.BLOCKED_STALE_WORKER))
            self.assertEqual(ReviewLifecycleStore().read_objective(repository, identity, objective_id=objective.objective_id).state, ObjectiveState.CANCELLED)

    def test_late_verified_worker_completion_keeps_the_objective_active_until_it_completes(self) -> None:
        """A crash after output persistence remains recoverable by its exact receipt."""
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("late-objective"); self.admit(repository, identity, lease)
            context = self.context(identity)
            self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="late-worker")
            record_session_identity(repository, identity, context, attempt_id="late-worker", session_identity="late-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="late-worker", session_identity="late-session", external_turn_identity="late-turn", lease=lease)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("INSERT INTO implementation_attempts(implementation_attempt_id, task_id, plan_attempt_id, accepted_plan_review_identity, provider_attempt_id, worker_thread_identity, external_turn_identity, input_digest, state, created_at) VALUES ('late-implementation', ?, 'plan-late', 'review-late', 'late-worker', 'late-session', 'late-turn', ?, 'dispatched', 1)", (identity.task_id, "a" * 64))
                connection.commit()
            objective = WorkerObjective("late-objective", identity.task_id, identity.base_sha, "late-worker", "worker-1-late-worker", "e" * 64)
            store = ReviewLifecycleStore(); store.start_objective(repository, identity, objective, lease=lease)
            evidence, accepted, candidate = "1" * 64, "2" * 64, "c" * 40
            record_completed_output(repository, identity, context, attempt_id="late-worker", output_pointer="implementation:late-implementation", completion_evidence_fingerprint=evidence, output_fingerprint=accepted, lease=lease)
            ambiguous = recover_attempt(repository, identity, context, attempt_id="late-worker", max_attempts=1, lease=lease)
            self.assertEqual((ambiguous.next_action, ambiguous.state), (RecoveryAction.BLOCKED_AMBIGUOUS_TURN, AttemptState.AMBIGUOUS))
            with self.assertRaisesRegex(ReviewLifecycleError, "completion evidence remains recoverable"):
                store.cancel_objective_for_provider_attempt(repository, identity, provider_attempt_id="late-worker", reason_digest="3" * 64, lease=lease)
            self.assertEqual(store.read_objective(repository, identity, objective_id=objective.objective_id).state, ObjectiveState.ACTIVE)
            restored = recover_attempt(repository, identity, context, attempt_id="late-worker", verified_completion_evidence=evidence, max_attempts=1, lease=lease)
            self.assertEqual((restored.next_action, restored.state), (RecoveryAction.CONSUME_VERIFIED_OUTPUT, AttemptState.COMPLETED))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                connection.execute("UPDATE implementation_attempts SET state = 'recorded' WHERE implementation_attempt_id = 'late-implementation'")
                connection.execute("INSERT INTO implementation_candidates(implementation_attempt_id, task_id, base_sha, candidate_sha, completion_evidence_fingerprint, content_digest) VALUES ('late-implementation', ?, ?, ?, ?, ?)", (identity.task_id, identity.base_sha, candidate, evidence, accepted))
                connection.execute("INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)", (identity.task_id, identity.base_sha, candidate, lease.state_identity))
                connection.commit()
            result = store.complete_objective(repository, identity, objective, lease=lease, result=WorkerObjectiveResult(candidate, evidence, accepted))
            self.assertEqual(result.state, ObjectiveState.COMPLETED)
            self.assertEqual(store.complete_objective(repository, identity, objective, lease=lease, result=WorkerObjectiveResult(candidate, evidence, accepted)), result)

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

    def test_restart_rejects_changed_worker_attempt_after_durable_scope_denial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("denied")
            self.admit(repository, identity, lease)
            candidate = "c" * 40
            context = self.context(identity, candidate=candidate, role=ProviderRole.WORKER)
            self.seal_candidate(repository, identity, lease, candidate)
            prepare_attempt(repository, identity, context, attempt_id="denial-attempt", role=ProviderRole.WORKER, process_lease_id="lease-denial", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            record_session_identity(repository, identity, context, attempt_id="denial-attempt", session_identity="session-before-denial", lease=lease)
            binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "worker:" + identity.task_id, FailureRole.WORKER, context.runtime_binding.worker_profile_identity, "session-before-denial", "denial-attempt")
            record_durable_failure(repository, identity, classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST))
            with self.assertRaisesRegex(ProviderRecoveryError, "scope is stopped"):
                self.prepare(repository, identity, lease, role=ProviderRole.WORKER, attempt="changed-session-attempt")

    def test_failure_admission_is_raw_bound_and_legacy_contexts_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("admission")
            self.admit(repository, identity, lease)
            candidate = "c" * 40
            context = self.context(identity, candidate=candidate, role=ProviderRole.SUPERVISOR)
            prepare_attempt(repository, identity, context, attempt_id="admitted", role=ProviderRole.SUPERVISOR, process_lease_id="lease-admitted", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            record_session_identity(repository, identity, context, attempt_id="admitted", session_identity="admitted-session", lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT task_id, candidate_sha, policy_digest, configuration_digest, authority_scope, provider_role, profile_identity, session_identity, attempt_identity FROM provider_failure_admissions WHERE attempt_id = ?", ("admitted",)).fetchone(), (identity.task_id, candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "supervisor:" + identity.task_id, "supervisor", context.runtime_binding.supervisor_profile_identities[0], "admitted-session", "admitted"))
            finally:
                connection.close()
            legacy = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "supervisor:" + identity.task_id, FailureRole.SUPERVISOR, context.runtime_binding.supervisor_profile_identities[0], "legacy-session", "legacy-attempt")
            with self.assertRaisesRegex(Exception, "admission"):
                record_durable_failure(repository, identity, classify(legacy, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST))

    def test_failure_admission_rejects_tamper_cross_task_and_stale_candidate_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("tamper")
            self.admit(repository, identity, lease)
            candidate = "c" * 40
            context = self.context(identity, candidate=candidate, role=ProviderRole.SUPERVISOR)
            prepare_attempt(repository, identity, context, attempt_id="tamper-attempt", role=ProviderRole.SUPERVISOR, process_lease_id="lease-tamper", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            record_session_identity(repository, identity, context, attempt_id="tamper-attempt", session_identity="tamper-session", lease=lease)
            record_external_turn(repository, identity, context, attempt_id="tamper-attempt", session_identity="tamper-session", external_turn_identity="tamper-turn", lease=lease)
            binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "supervisor:" + identity.task_id, FailureRole.SUPERVISOR, context.runtime_binding.supervisor_profile_identities[0], "tamper-session", "tamper-attempt")
            other_identity = self.identity("other-task")
            self.admit(repository, other_identity, lease)
            with self.assertRaisesRegex(Exception, "admission"):
                record_durable_failure(repository, other_identity, classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_failure_admissions SET configuration_digest = ? WHERE attempt_id = ?", ("sha256:" + "d" * 64, "tamper-attempt")); connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(Exception, "admission"):
                record_durable_failure(repository, identity, classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST))
            self.assertEqual(read_attempt(repository, identity, "tamper-attempt").state, AttemptState.DISPATCHED)
            replacement = self.context(identity, candidate="d" * 40, role=ProviderRole.SUPERVISOR)
            with self.assertRaisesRegex(ProviderRecoveryError, "drifted"):
                record_supervisor_terminal_failure(repository, identity, replacement, attempt_id="tamper-attempt", failure_class=SupervisorTerminalFailureClass.SANDBOX_OR_APPROVAL_DENIED, outcome_source=SupervisorTerminalFailureSource.SDK_TURN_FAILED, sdk_error_category=SupervisorTerminalFailureSdkCategory.SANDBOX, lease=lease)

    def test_durable_failure_readback_revalidates_current_admission_authority(self) -> None:
        mutations = {
            "missing-admission": "DELETE FROM provider_failure_admissions WHERE attempt_id = 'readback-attempt'",
            "tampered-admission": "UPDATE provider_failure_admissions SET configuration_digest = 'sha256:" + "d" * 64 + "' WHERE attempt_id = 'readback-attempt'",
            "moved-candidate": "UPDATE candidate_seals SET candidate_sha = '" + "d" * 40 + "' WHERE task_id = 'task-22-readback'",
            "superseded-policy": "UPDATE provider_attempt_contexts SET policy_fingerprint = '" + "d" * 64 + "' WHERE attempt_id = 'readback-attempt'",
            "superseded-runtime": "UPDATE runtime_configuration_bindings SET resolved_digest = 'sha256:" + "d" * 64 + "' WHERE task_id = 'task-22-readback'",
            "substituted-profile": "UPDATE provider_attempts SET selected_profile_identity = 'sha256:" + "d" * 64 + "' WHERE attempt_id = 'readback-attempt'",
            "substituted-session": "UPDATE provider_session_checkpoints SET session_identity = 'replacement-session' WHERE attempt_id = 'readback-attempt'",
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository(Path(temporary)); initialize(repository)
                lease = self.lease(repository); identity = self.identity("readback"); self.admit(repository, identity, lease)
                candidate = "c" * 40; self.seal_candidate(repository, identity, lease, candidate)
                context = self.context(identity, candidate=candidate, role=ProviderRole.SUPERVISOR)
                prepare_attempt(repository, identity, context, attempt_id="readback-attempt", role=ProviderRole.SUPERVISOR, process_lease_id="lease-readback", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
                record_session_identity(repository, identity, context, attempt_id="readback-attempt", session_identity="readback-session", lease=lease)
                binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "supervisor:" + identity.task_id, FailureRole.SUPERVISOR, context.runtime_binding.supervisor_profile_identities[0], "readback-session", "readback-attempt")
                record = classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
                record_durable_failure(repository, identity, record)
                self.assertEqual(read_durable_failure(repository, identity, record.digest), record)
                connection = sqlite3.connect(database_path(repository))
                try:
                    canonical = connection.execute("SELECT record_json FROM failure_recovery_records WHERE record_digest = ?", (record.digest,)).fetchone()[0]
                    tampered = json.loads(canonical); tampered["evidence"] = EvidenceSource.VERIFIED_SERVICE.value
                    connection.execute("UPDATE failure_recovery_records SET record_json = ? WHERE record_digest = ?", (json.dumps(tampered, sort_keys=True, separators=(",", ":")), record.digest)); connection.commit()
                    with self.assertRaisesRegex(Exception, "malformed"):
                        read_durable_failure(repository, identity, record.digest)
                    connection.execute("UPDATE failure_recovery_records SET record_json = ? WHERE record_digest = ?", (canonical, record.digest))
                    connection.execute(mutation); connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(Exception, "authority|admission"):
                    read_durable_failure(repository, identity, record.digest)
                other = self.identity("readback-other"); self.admit(repository, other, lease)
                with self.assertRaises(Exception):
                    read_durable_failure(repository, other, record.digest)

    def test_supervisor_coordinates_are_unique_and_strictly_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("coordinate")
            self.admit(repository, identity, lease)
            context = self.context(identity, role=ProviderRole.SUPERVISOR)
            profile = context.runtime_binding.supervisor_profile_identities[0]
            # Coordinate replay is an identity check, not a clock-race test.
            # Keep the lease input fixed across the adversarial sequence.
            lease_expires_at = 2_000_000_000

            def reserve(attempt: str, *, epoch: int, review_round: int, physical: int):
                return prepare_attempt(
                    repository, identity, context, attempt_id=attempt,
                    role=ProviderRole.SUPERVISOR, process_lease_id=f"lease-{attempt}",
                    process_lease_expires_at=lease_expires_at,
                    input_fingerprint="a" * 64, selected_profile_identity=profile,
                    logical_profile_position=1, physical_format_output_ordinal=physical,
                    review_epoch=epoch, review_round=review_round, lease=lease,
                )

            first = reserve("coordinate-zero", epoch=1, review_round=1, physical=0)
            self.assertEqual(first, reserve("coordinate-zero", epoch=1, review_round=1, physical=0))
            reserve("coordinate-one", epoch=1, review_round=1, physical=1)
            reserve("coordinate-two", epoch=1, review_round=1, physical=2)
            reserve("coordinate-round-two", epoch=1, review_round=2, physical=0)
            with self.assertRaisesRegex(ProviderRecoveryError, "conflicts"):
                reserve("coordinate-duplicate", epoch=1, review_round=2, physical=0)
            with self.assertRaisesRegex(ProviderRecoveryError, "stale, regressive, or gapped"):
                reserve("coordinate-gap", epoch=1, review_round=4, physical=0)
            with self.assertRaisesRegex(ProviderRecoveryError, "stale, regressive, or gapped"):
                reserve("coordinate-regression", epoch=0, review_round=1, physical=0)
            connection = sqlite3.connect(database_path(repository))
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO supervisor_attempt_coordinates("
                        "attempt_id, task_id, review_epoch, review_round, logical_profile_position, "
                        "physical_format_output_ordinal, profile_identity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ("database-coordinate-duplicate", identity.task_id, 1, 2, 1, 0, profile),
                    )
            finally:
                connection.close()

    def test_durable_clearance_and_revocation_are_append_only_and_restart_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("clearance"); self.admit(repository, identity, lease)
            candidate = "c" * 40; context = self.context(identity, candidate=candidate, role=ProviderRole.WORKER)
            self.seal_candidate(repository, identity, lease, candidate)
            prepare_attempt(repository, identity, context, attempt_id="clearance-attempt", role=ProviderRole.WORKER, process_lease_id="lease-clearance", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            record_session_identity(repository, identity, context, attempt_id="clearance-attempt", session_identity="clearance-session", lease=lease)
            binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "worker:" + identity.task_id, FailureRole.WORKER, context.runtime_binding.worker_profile_identity, "clearance-session", "clearance-attempt")
            record = classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST); record_durable_failure(repository, identity, record)
            # A consumed generic review command has a deliberately disjoint
            # namespace.  It cannot become a denial-clearance receipt.
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("INSERT INTO owner_authority_grants(grant_id, owner_identity, command_scope, task_id, candidate_sha, authority_digest, state) VALUES ('generic-denial-grant', 'ythdelmar68', 'resolve-review-item', ?, ?, ?, 'active')", (identity.task_id, candidate, _owner_authority_digest("ythdelmar68", "resolve-review-item", identity.task_id, candidate)))
                connection.execute("INSERT INTO owner_command_records(command_id, task_id, command_kind, owner_identity, authority_grant_id, target_item_id, candidate_sha, command_digest, scope_digest, idempotency_key, state, result_digest) VALUES ('generic-denial-command', ?, 'resolve-review-item', 'ythdelmar68', 'generic-denial-grant', 'generic-target', ?, ?, ?, 'generic-denial-key', 'consumed', ?)", (identity.task_id, candidate, "a" * 64, "b" * 64, "c" * 64))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(Exception, "dedicated denial command"):
                record_durable_clearance(repository, identity, Clearance(record.digest, binding, "generic-denial-command"))
            with self.assertRaisesRegex(Exception, "dedicated denial command"):
                record_durable_clearance(repository, identity, Clearance(record.digest, binding, "fabricated-host-proof"))
            other = self.identity("clearance-other"); self.admit(repository, other, lease)
            self.seal_candidate(repository, other, lease, candidate)
            self.denial_command(repository, other, record, "owner-cross-task", kind="clear")
            with self.assertRaisesRegex(Exception, "dedicated denial command"):
                record_durable_clearance(repository, identity, Clearance(record.digest, binding, "owner-cross-task"))
            self.denial_command(repository, identity, record, "owner-clear-1", kind="clear")
            clearance = Clearance(record.digest, binding, "owner-clear-1")
            clearance_digest = record_durable_clearance(repository, identity, clearance)
            with self.assertRaisesRegex(Exception, "stale|out of order"):
                record_durable_clearance(repository, identity, clearance)
            connection = sqlite3.connect(database_path(repository))
            try: require_scope_open(connection, identity.task_id, binding.authority_scope)
            finally: connection.close()
            # The revocation request names the current clearance, but the
            # consumed command is independently authenticated against that
            # same predecessor.  A substituted command column must not revoke
            # the scope by borrowing this request's digest.
            self.denial_command(repository, identity, record, "owner-revoke-wrong-clearance", kind="revoke")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "UPDATE denial_revocation_commands SET clearance_digest = ? WHERE command_id = ?",
                    ("sha256:" + "0" * 64, "owner-revoke-wrong-clearance"),
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(Exception, "dedicated denial command"):
                record_durable_clearance_revocation(
                    repository, identity,
                    ClearanceRevocation(clearance_digest, binding, "owner-revoke-wrong-clearance"),
                )
            self.denial_command(repository, identity, record, "revoke-first", kind="revoke")
            first_revocation = ClearanceRevocation(clearance_digest, binding, "revoke-first")
            record_durable_clearance_revocation(repository, identity, first_revocation)
            self.denial_command(repository, identity, record, "clear-second", kind="clear")
            second = record_durable_clearance(repository, identity, Clearance(record.digest, binding, "clear-second"))
            self.denial_command(repository, identity, record, "revoke-second", kind="revoke")
            for request in (ClearanceRevocation(clearance_digest, binding, "revoke-second"),
                            ClearanceRevocation(second, binding, "revoke-first"), first_revocation):
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    before = connection.execute("SELECT * FROM denial_clearance_decisions").fetchall()
                with self.assertRaises(Exception):
                    record_durable_clearance_revocation(repository, identity, request)
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    self.assertEqual(connection.execute("SELECT * FROM denial_clearance_decisions").fetchall(), before)
                    require_scope_open(connection, identity.task_id, binding.authority_scope)
            exact = ClearanceRevocation(second, binding, "revoke-second")
            record_durable_clearance_revocation(repository, identity, exact)
            with self.assertRaises(Exception):
                record_durable_clearance_revocation(repository, identity, exact)

    def test_durable_routes_reject_legacy_and_unavailable_sources_before_any_effect(self) -> None:
        from roundwright.failure_recovery import EvidenceConfidence, FailureRecoveryError, _payload
        for variant in ("v1-unavailable", "v2-verified", "v3-unknown"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository(Path(temporary)); initialize(repository)
                lease = self.lease(repository); identity = self.identity("legacy-route"); self.admit(repository, identity, lease)
                candidate = "c" * 40; self.seal_candidate(repository, identity, lease, candidate)
                context = self.context(identity, candidate=candidate, role=ProviderRole.SUPERVISOR)
                prepare_attempt(repository, identity, context, attempt_id="legacy-source", role=ProviderRole.SUPERVISOR,
                                process_lease_id="legacy-lease", process_lease_expires_at=int(time.time()) + 100, input_fingerprint="a" * 64, lease=lease)
                record_session_identity(repository, identity, context, attempt_id="legacy-source", session_identity="legacy-session", lease=lease)
                binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest,
                                         "supervisor:" + identity.task_id, FailureRole.SUPERVISOR, context.runtime_binding.supervisor_profile_identities[0],
                                         "legacy-session", "legacy-source")
                record = classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.VERIFIED_LIFECYCLE)
                if variant == "v1-unavailable":
                    record = replace(record, record_schema="roundwright-failure-recovery/v1", evidence_confidence=EvidenceConfidence.UNAVAILABLE)
                elif variant == "v2-verified":
                    record = replace(record, record_schema="roundwright-failure-recovery/v2")
                else:
                    record = classify(binding, FailureClass.UNKNOWN, EvidenceSource.UNAVAILABLE)
                values = dict(record_digest=record.digest, binding=binding, target_role=FailureRole.SUPERVISOR,
                              target_profile_digest=context.runtime_binding.supervisor_profile_identities[1], target_route_digest="sha256:" + "d" * 64,
                              coordinate_digest="sha256:" + "e" * 64, remaining_budget_digest="sha256:" + "f" * 64)
                canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    connection.execute("INSERT INTO failure_recovery_records(record_digest,task_id,record_json,recorded_at) VALUES (?,?,?,?)",
                                       (record.digest, identity.task_id, canonical(_payload(record)), 100))
                    connection.commit()
                with self.assertRaises(FailureRecoveryError):
                    issue_durable_recovery_route_authorization(repository, identity, **values)
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM recovery_route_authorizations").fetchone(), (0,))
                    # Retained pre-repair route fixture: coherent identity, no
                    # implementation bypass used to issue it during the test.
                    route_payload = {"schema": "roundwright-durable-recovery-route/v1", **values,
                                     "binding": _payload(record)["binding"], "target_role": "supervisor"}
                    route_id = "sha256:" + hashlib.sha256(canonical(route_payload).encode()).hexdigest()
                    connection.execute("INSERT INTO recovery_route_authorizations(route_digest,task_id,repository_id,record_digest,binding_json,target_role,target_profile_digest,target_route_digest,coordinate_digest,remaining_budget_digest,state,reservation_digest,issued_at,consumed_at) VALUES (?,?,?,?,?,?,?,?,?,?,'issued',NULL,100,NULL)",
                                       (route_id, identity.task_id, identity.repository_id, record.digest, canonical(route_payload["binding"]), "supervisor", values["target_profile_digest"], values["target_route_digest"], values["coordinate_digest"], values["remaining_budget_digest"]))
                    connection.commit()
                    before = tuple(connection.execute("SELECT * FROM " + table).fetchall() for table in
                                   ("recovery_route_authorizations", "provider_attempts", "provider_dispatch_claims", "recovery_route_successor_admissions"))
                authorization = DurableRecoveryRouteAuthorization(route_id, **values)
                with self.assertRaises(FailureRecoveryError):
                    read_durable_recovery_route_authorization(repository, identity, route_id)
                target = {key: values[key] for key in ("target_role", "target_profile_digest", "target_route_digest", "coordinate_digest", "remaining_budget_digest")}
                for operation in (begin_durable_recovery_route_reservation, consume_durable_recovery_route_authorization):
                    with self.assertRaises(FailureRecoveryError):
                        operation(repository, identity, authorization, reservation_digest="sha256:" + "2" * 64, **target)
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    after = tuple(connection.execute("SELECT * FROM " + table).fetchall() for table in
                                  ("recovery_route_authorizations", "provider_attempts", "provider_dispatch_claims", "recovery_route_successor_admissions"))
                self.assertEqual(before, after)

    def test_durable_recovery_route_is_exact_single_use_and_restart_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary)); initialize(repository)
            lease = self.lease(repository); identity = self.identity("route-ledger"); self.admit(repository, identity, lease)
            candidate = "c" * 40; self.seal_candidate(repository, identity, lease, candidate)
            context = self.context(identity, candidate=candidate, role=ProviderRole.SUPERVISOR)
            prepare_attempt(repository, identity, context, attempt_id="route-source", role=ProviderRole.SUPERVISOR, process_lease_id="lease-route", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="a" * 64, lease=lease)
            record_session_identity(repository, identity, context, attempt_id="route-source", session_identity="route-session", lease=lease)
            binding = FailureBinding(candidate, "sha256:" + context.policy_fingerprint, context.runtime_binding.resolved_digest, "supervisor:" + identity.task_id, FailureRole.SUPERVISOR, context.runtime_binding.supervisor_profile_identities[0], "route-session", "route-source")
            record = classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.VERIFIED_LIFECYCLE)
            record_durable_failure(repository, identity, record)
            values = dict(record_digest=record.digest, binding=binding, target_role=FailureRole.SUPERVISOR, target_profile_digest=context.runtime_binding.supervisor_profile_identities[1], target_route_digest="sha256:" + "d" * 64, coordinate_digest="sha256:" + "e" * 64, remaining_budget_digest="sha256:" + "f" * 64)
            issued = issue_durable_recovery_route_authorization(repository, identity, **values)
            self.assertEqual(read_durable_recovery_route_authorization(repository, identity, issued.route_digest), issued)
            self.assertEqual(issue_durable_recovery_route_authorization(repository, identity, **values), issued)
            with self.assertRaises(Exception):
                issue_durable_recovery_route_authorization(repository, identity, **{**values, "coordinate_digest": "sha256:" + "1" * 64})
            with self.assertRaises(Exception):
                consume_durable_recovery_route_authorization(repository, identity, issued, reservation_digest="sha256:" + "2" * 64, target_role=FailureRole.WORKER, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"])
            consume_durable_recovery_route_authorization(repository, identity, issued, reservation_digest="sha256:" + "2" * 64, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"])
            release_durable_recovery_route_authorization(
                repository, identity, issued, reservation_digest="sha256:" + "2" * 64,
            )
            self.assertEqual(
                read_durable_recovery_route_authorization(repository, identity, issued.route_digest), issued,
            )
            consume_durable_recovery_route_authorization(repository, identity, issued, reservation_digest="sha256:" + "2" * 64, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"])
            with self.assertRaises(Exception):
                consume_durable_recovery_route_authorization(repository, identity, issued, reservation_digest="sha256:" + "2" * 64, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"])
            with self.assertRaises(Exception):
                issue_durable_recovery_route_authorization(repository, identity, **{**values, "record_digest": "sha256:" + "0" * 64})
            release_durable_recovery_route_authorization(repository, identity, issued, reservation_digest="sha256:" + "2" * 64)
            reservation = "sha256:" + "3" * 64
            self.assertTrue(begin_durable_recovery_route_reservation(repository, identity, issued, reservation_digest=reservation, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"]))
            self.assertFalse(begin_durable_recovery_route_reservation(repository, identity, issued, reservation_digest=reservation, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"]))
            abandon_durable_recovery_route_reservation(repository, identity, issued, reservation_digest=reservation)
            self.assertTrue(begin_durable_recovery_route_reservation(repository, identity, issued, reservation_digest=reservation, target_role=FailureRole.SUPERVISOR, target_profile_digest=values["target_profile_digest"], target_route_digest=values["target_route_digest"], coordinate_digest=values["coordinate_digest"], remaining_budget_digest=values["remaining_budget_digest"]))
            commit_durable_recovery_route_successor_admission(
                repository, identity, issued, reservation_digest=reservation,
                target_attempt_id="route-successor",
                target_request_digest="sha256:" + "4" * 64,
            )
            with self.assertRaisesRegex(Exception, "already admitted"):
                release_durable_recovery_route_authorization(
                    repository, identity, issued, reservation_digest=reservation,
                )
            # Exact restart replay is idempotent, but an admission cannot be
            # borrowed by a different supervisor request.
            commit_durable_recovery_route_successor_admission(
                repository, identity, issued, reservation_digest=reservation,
                target_attempt_id="route-successor",
                target_request_digest="sha256:" + "4" * 64,
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT target_attempt_id, target_request_digest FROM recovery_route_successor_admissions"
                ).fetchall(), [("route-successor", "sha256:" + "4" * 64)])
            finally:
                connection.close()
            # Also reject a product successor row without relying on the
            # generic qualification admission table.
            prepare_attempt(repository, identity, context, attempt_id="route-product-successor", role=ProviderRole.SUPERVISOR, process_lease_id="lease-product-successor", process_lease_expires_at=int(time.time()) + 10, input_fingerprint="b" * 64, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("DELETE FROM recovery_route_successor_admissions WHERE route_digest=?", (issued.route_digest,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(Exception, "already admitted"):
                release_durable_recovery_route_authorization(repository, identity, issued, reservation_digest=reservation)
            with self.assertRaisesRegex(Exception, "has drifted"):
                release_durable_recovery_route_authorization(repository, identity, replace(issued, binding=replace(binding, attempt_identity="unrelated-source")), reservation_digest=reservation)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state, reservation_digest FROM recovery_route_authorizations WHERE route_digest=?", (issued.route_digest,)).fetchone(), ("consumed", reservation))
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
