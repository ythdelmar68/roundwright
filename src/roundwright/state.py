"""Repository-local SQLite state with fail-closed migration verification."""

from __future__ import annotations

import hashlib
import ntpath
import os
import posixpath
import stat
import sqlite3
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .configuration import RepositoryIdentity


class StateError(RuntimeError):
    """Raised when local state is absent, unsafe, or incompatible."""


@dataclass(frozen=True)
class Migration:
    version: int
    statements: tuple[str, ...]
    schema: tuple[tuple[str, str], ...]

    @property
    def checksum(self) -> str:
        content = "\n".join((str(self.version), *self.statements)).encode("utf-8")
        return hashlib.sha256(content).hexdigest()


MIGRATIONS = (
    Migration(
        1,
        (
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, checksum TEXT NOT NULL)",
            "CREATE TABLE state_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        ),
        (
            ("schema_migrations", "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, checksum TEXT NOT NULL)"),
            ("state_metadata", "CREATE TABLE state_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
        ),
    ),
    Migration(
        2,
        (
            "CREATE TABLE source_snapshots (source_id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, source_digest TEXT NOT NULL, UNIQUE(repository_id, source_digest))",
            "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_snapshots(source_id), repository_id TEXT NOT NULL, branch TEXT NOT NULL, worktree TEXT NOT NULL, base_sha TEXT NOT NULL, state TEXT NOT NULL, blocked_from_state TEXT, CHECK(state IN ('queued', 'planning', 'plan-review', 'implementing', 'diff-review', 'ready-for-owner', 'blocked')), CHECK((state = 'blocked' AND blocked_from_state IS NOT NULL) OR (state != 'blocked' AND blocked_from_state IS NULL)))",
            "CREATE TABLE transition_events (task_id TEXT NOT NULL REFERENCES tasks(task_id), sequence INTEGER NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, sequence), UNIQUE(task_id, evidence_fingerprint), CHECK(from_state != to_state))",
            "CREATE TABLE artifact_references (task_id TEXT NOT NULL REFERENCES tasks(task_id), artifact_kind TEXT NOT NULL, artifact_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, artifact_kind, artifact_fingerprint))",
            "CREATE TABLE blockers (task_id TEXT NOT NULL REFERENCES tasks(task_id), blocker_class TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, resolution_fingerprint TEXT, PRIMARY KEY(task_id, blocker_class))",
            "CREATE TABLE next_actions (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), action_kind TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, resolution_fingerprint TEXT)",
        ),
        (
            ("source_snapshots", "CREATE TABLE source_snapshots (source_id TEXT PRIMARY KEY, repository_id TEXT NOT NULL, source_digest TEXT NOT NULL, UNIQUE(repository_id, source_digest))"),
            ("tasks", "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_snapshots(source_id), repository_id TEXT NOT NULL, branch TEXT NOT NULL, worktree TEXT NOT NULL, base_sha TEXT NOT NULL, state TEXT NOT NULL, blocked_from_state TEXT, CHECK(state IN ('queued', 'planning', 'plan-review', 'implementing', 'diff-review', 'ready-for-owner', 'blocked')), CHECK((state = 'blocked' AND blocked_from_state IS NOT NULL) OR (state != 'blocked' AND blocked_from_state IS NULL)))"),
            ("transition_events", "CREATE TABLE transition_events (task_id TEXT NOT NULL REFERENCES tasks(task_id), sequence INTEGER NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, sequence), UNIQUE(task_id, evidence_fingerprint), CHECK(from_state != to_state))"),
            ("artifact_references", "CREATE TABLE artifact_references (task_id TEXT NOT NULL REFERENCES tasks(task_id), artifact_kind TEXT NOT NULL, artifact_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, artifact_kind, artifact_fingerprint))"),
            ("blockers", "CREATE TABLE blockers (task_id TEXT NOT NULL REFERENCES tasks(task_id), blocker_class TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, resolution_fingerprint TEXT, PRIMARY KEY(task_id, blocker_class))"),
            ("next_actions", "CREATE TABLE next_actions (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), action_kind TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, resolution_fingerprint TEXT)"),
        ),
    ),
    Migration(
        3,
        (
            "CREATE TABLE transition_leases (lease_scope TEXT PRIMARY KEY CHECK(lease_scope = 'repository-state'), repository_id TEXT NOT NULL, state_identity TEXT NOT NULL, owner TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0), expires_at INTEGER NOT NULL CHECK(expires_at >= 0))",
            "CREATE TABLE candidate_seals (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL)",
            "CREATE TABLE candidate_evidence (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha, evidence_fingerprint))",
        ),
        (
            ("transition_leases", "CREATE TABLE transition_leases (lease_scope TEXT PRIMARY KEY CHECK(lease_scope = 'repository-state'), repository_id TEXT NOT NULL, state_identity TEXT NOT NULL, owner TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation > 0), expires_at INTEGER NOT NULL CHECK(expires_at >= 0))"),
            ("candidate_seals", "CREATE TABLE candidate_seals (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL)"),
            ("candidate_evidence", "CREATE TABLE candidate_evidence (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha, evidence_fingerprint))"),
        ),
    ),
    Migration(
        4,
        (
            "CREATE TABLE transition_lease_generations (lease_scope TEXT PRIMARY KEY CHECK(lease_scope = 'repository-state'), generation INTEGER NOT NULL CHECK(generation > 0))",
            "ALTER TABLE candidate_seals ADD COLUMN state_identity TEXT NOT NULL DEFAULT ''",
        ),
        (
            ("transition_lease_generations", "CREATE TABLE transition_lease_generations (lease_scope TEXT PRIMARY KEY CHECK(lease_scope = 'repository-state'), generation INTEGER NOT NULL CHECK(generation > 0))"),
            ("candidate_seals", "CREATE TABLE candidate_seals (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, state_identity TEXT NOT NULL DEFAULT '')"),
        ),
    ),
    Migration(
        5,
        (
            "ALTER TABLE tasks ADD COLUMN worktree_key TEXT NOT NULL DEFAULT ''",
            "CREATE TABLE task_worktree_ownership (worktree_key TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id))",
        ),
        (
            ("tasks", "CREATE TABLE tasks (task_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_snapshots(source_id), repository_id TEXT NOT NULL, branch TEXT NOT NULL, worktree TEXT NOT NULL, base_sha TEXT NOT NULL, state TEXT NOT NULL, blocked_from_state TEXT, worktree_key TEXT NOT NULL DEFAULT '', CHECK(state IN ('queued', 'planning', 'plan-review', 'implementing', 'diff-review', 'ready-for-owner', 'blocked')), CHECK((state = 'blocked' AND blocked_from_state IS NOT NULL) OR (state != 'blocked' AND blocked_from_state IS NULL)))"),
            ("task_worktree_ownership", "CREATE TABLE task_worktree_ownership (worktree_key TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id))"),
        ),
    ),
    Migration(
        6,
        (
            "CREATE TABLE task_branch_ownership (branch TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id))",
        ),
        (
            ("task_branch_ownership", "CREATE TABLE task_branch_ownership (branch TEXT PRIMARY KEY, task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id))"),
        ),
    ),
    Migration(
        7,
        (
            "INSERT INTO transition_lease_generations(lease_scope, generation) "
            "SELECT 'repository-state', CASE "
            "WHEN COALESCE((SELECT MAX(generation) FROM transition_leases WHERE lease_scope = 'repository-state'), 0) >= 2 "
            "THEN (SELECT MAX(generation) + 1 FROM transition_leases WHERE lease_scope = 'repository-state') "
            "ELSE 2 END "
            "ON CONFLICT(lease_scope) DO UPDATE SET generation = MAX(transition_lease_generations.generation, excluded.generation)",
        ),
        (),
    ),
    Migration(
        8,
        (
            "CREATE TABLE gate_evidence (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, gate_key TEXT NOT NULL, outcome TEXT NOT NULL, evaluator_id TEXT NOT NULL, evaluated_at INTEGER NOT NULL CHECK(evaluated_at > 0), evidence_fingerprint TEXT NOT NULL, changed_boundary TEXT, reason TEXT, PRIMARY KEY(task_id, candidate_sha, gate_key, evaluator_id, evidence_fingerprint))",
        ),
        (
            ("gate_evidence", "CREATE TABLE gate_evidence (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, gate_key TEXT NOT NULL, outcome TEXT NOT NULL, evaluator_id TEXT NOT NULL, evaluated_at INTEGER NOT NULL CHECK(evaluated_at > 0), evidence_fingerprint TEXT NOT NULL, changed_boundary TEXT, reason TEXT, PRIMARY KEY(task_id, candidate_sha, gate_key, evaluator_id, evidence_fingerprint))"),
        ),
    ),
    Migration(
        9,
        (
            "CREATE TABLE gate_contexts (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)))",
        ),
        (
            ("gate_contexts", "CREATE TABLE gate_contexts (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)))"),
        ),
    ),
    Migration(
        10,
        (
            "ALTER TABLE gate_contexts ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE gate_contexts ADD COLUMN receipt_fingerprint TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE gate_evidence ADD COLUMN follow_ups TEXT NOT NULL DEFAULT '[]'",
        ),
        (
            ("gate_contexts", "CREATE TABLE gate_contexts (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)), policy_digest TEXT NOT NULL DEFAULT '', receipt_fingerprint TEXT NOT NULL DEFAULT '')"),
            ("gate_evidence", "CREATE TABLE gate_evidence (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, gate_key TEXT NOT NULL, outcome TEXT NOT NULL, evaluator_id TEXT NOT NULL, evaluated_at INTEGER NOT NULL CHECK(evaluated_at > 0), evidence_fingerprint TEXT NOT NULL, changed_boundary TEXT, reason TEXT, follow_ups TEXT NOT NULL DEFAULT '[]', PRIMARY KEY(task_id, candidate_sha, gate_key, evaluator_id, evidence_fingerprint))"),
        ),
    ),
    Migration(
        11,
        (
            "CREATE TABLE gate_contexts_v2 (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)), policy_digest TEXT NOT NULL, receipt_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha))",
            "INSERT INTO gate_contexts_v2(task_id, candidate_sha, source_count, isolated_local_task, policy_digest, receipt_fingerprint) SELECT contexts.task_id, seals.candidate_sha, contexts.source_count, contexts.isolated_local_task, contexts.policy_digest, contexts.receipt_fingerprint FROM gate_contexts AS contexts JOIN candidate_seals AS seals ON seals.task_id = contexts.task_id",
            "DROP TABLE gate_contexts",
            "ALTER TABLE gate_contexts_v2 RENAME TO gate_contexts",
        ),
        (
            ("gate_contexts", "CREATE TABLE \"gate_contexts\" (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)), policy_digest TEXT NOT NULL, receipt_fingerprint TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha))"),
        ),
    ),
    Migration(
        12,
        (
            "ALTER TABLE gate_contexts ADD COLUMN policy_activated_at TEXT NOT NULL DEFAULT ''",
        ),
        (
            ("gate_contexts", "CREATE TABLE \"gate_contexts\" (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, source_count INTEGER NOT NULL CHECK(source_count > 0), isolated_local_task INTEGER NOT NULL CHECK(isolated_local_task IN (0, 1)), policy_digest TEXT NOT NULL, receipt_fingerprint TEXT NOT NULL, policy_activated_at TEXT NOT NULL DEFAULT '', PRIMARY KEY(task_id, candidate_sha))"),
        ),
    ),
    Migration(
        13,
        (
            "CREATE TABLE provider_attempts (attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), attempt_number INTEGER NOT NULL CHECK(attempt_number > 0), process_lease_id TEXT NOT NULL, process_lease_expires_at INTEGER NOT NULL CHECK(process_lease_expires_at > 0), session_identity TEXT, external_turn_identity TEXT, input_fingerprint TEXT NOT NULL, output_pointer TEXT, completion_evidence_fingerprint TEXT, accepted_review_identity TEXT, state TEXT NOT NULL CHECK(state IN ('prepared', 'dispatched', 'completed', 'accepted', 'ambiguous', 'blocked', 'invalidated')), UNIQUE(task_id, provider_role, attempt_number), UNIQUE(task_id, provider_role, external_turn_identity), UNIQUE(task_id, accepted_review_identity), CHECK((external_turn_identity IS NULL AND state IN ('prepared', 'blocked')) OR (external_turn_identity IS NOT NULL AND state != 'prepared')), CHECK((state IN ('completed', 'accepted') AND output_pointer IS NOT NULL AND completion_evidence_fingerprint IS NOT NULL) OR state NOT IN ('completed', 'accepted')), CHECK((accepted_review_identity IS NOT NULL AND provider_role = 'supervisor' AND state = 'accepted') OR accepted_review_identity IS NULL))",
            "CREATE TABLE provider_checkpoints (checkpoint_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), checkpoint_phase TEXT NOT NULL CHECK(checkpoint_phase IN ('before-dispatch', 'after-dispatch')), attempt_id TEXT REFERENCES provider_attempts(attempt_id), identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0), UNIQUE(task_id, provider_role, checkpoint_phase, attempt_id))",
            "CREATE TABLE provider_recovery_contexts (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), repository_fingerprint TEXT NOT NULL, worktree_fingerprint TEXT NOT NULL, branch_fingerprint TEXT NOT NULL, base_fingerprint TEXT NOT NULL, candidate_fingerprint TEXT, policy_fingerprint TEXT NOT NULL, deployment_fingerprint TEXT NOT NULL)",
        ),
        (
            ("provider_attempts", "CREATE TABLE provider_attempts (attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), attempt_number INTEGER NOT NULL CHECK(attempt_number > 0), process_lease_id TEXT NOT NULL, process_lease_expires_at INTEGER NOT NULL CHECK(process_lease_expires_at > 0), session_identity TEXT, external_turn_identity TEXT, input_fingerprint TEXT NOT NULL, output_pointer TEXT, completion_evidence_fingerprint TEXT, accepted_review_identity TEXT, state TEXT NOT NULL CHECK(state IN ('prepared', 'dispatched', 'completed', 'accepted', 'ambiguous', 'blocked', 'invalidated')), UNIQUE(task_id, provider_role, attempt_number), UNIQUE(task_id, provider_role, external_turn_identity), UNIQUE(task_id, accepted_review_identity), CHECK((external_turn_identity IS NULL AND state IN ('prepared', 'blocked')) OR (external_turn_identity IS NOT NULL AND state != 'prepared')), CHECK((state IN ('completed', 'accepted') AND output_pointer IS NOT NULL AND completion_evidence_fingerprint IS NOT NULL) OR state NOT IN ('completed', 'accepted')), CHECK((accepted_review_identity IS NOT NULL AND provider_role = 'supervisor' AND state = 'accepted') OR accepted_review_identity IS NULL))"),
            ("provider_checkpoints", "CREATE TABLE provider_checkpoints (checkpoint_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), checkpoint_phase TEXT NOT NULL CHECK(checkpoint_phase IN ('before-dispatch', 'after-dispatch')), attempt_id TEXT REFERENCES provider_attempts(attempt_id), identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0), UNIQUE(task_id, provider_role, checkpoint_phase, attempt_id))"),
            ("provider_recovery_contexts", "CREATE TABLE provider_recovery_contexts (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), repository_fingerprint TEXT NOT NULL, worktree_fingerprint TEXT NOT NULL, branch_fingerprint TEXT NOT NULL, base_fingerprint TEXT NOT NULL, candidate_fingerprint TEXT, policy_fingerprint TEXT NOT NULL, deployment_fingerprint TEXT NOT NULL)"),
        ),
    ),
    Migration(
        14,
        (
            "CREATE TABLE provider_invalid_outputs (invalid_output_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL, reason_fingerprint TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0))",
            "CREATE TABLE provider_recovery_events (recovery_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL CHECK(recovery_action IN ('retry', 'resume-same-session', 'consume-verified-output', 'accepted-review', 'blocked-ambiguous-turn', 'blocked-stale-worker', 'fresh-supervisor-session', 'blocked-retry-limit', 'blocked-identity-drift')), observed_at INTEGER NOT NULL CHECK(observed_at > 0))",
            "CREATE TABLE accepted_provider_reviews (accepted_review_identity TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), completion_evidence_fingerprint TEXT NOT NULL)",
        ),
        (
            ("provider_invalid_outputs", "CREATE TABLE provider_invalid_outputs (invalid_output_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL, reason_fingerprint TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0))"),
            ("provider_recovery_events", "CREATE TABLE provider_recovery_events (recovery_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL CHECK(recovery_action IN ('retry', 'resume-same-session', 'consume-verified-output', 'accepted-review', 'blocked-ambiguous-turn', 'blocked-stale-worker', 'fresh-supervisor-session', 'blocked-retry-limit', 'blocked-identity-drift')), observed_at INTEGER NOT NULL CHECK(observed_at > 0))"),
            ("accepted_provider_reviews", "CREATE TABLE accepted_provider_reviews (accepted_review_identity TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), completion_evidence_fingerprint TEXT NOT NULL)"),
        ),
    ),
    Migration(
        15,
        (
            "CREATE TABLE provider_session_checkpoints (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), session_identity TEXT NOT NULL, identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0), UNIQUE(task_id, session_identity))",
        ),
        (
            ("provider_session_checkpoints", "CREATE TABLE provider_session_checkpoints (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), session_identity TEXT NOT NULL, identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0), UNIQUE(task_id, session_identity))"),
        ),
    ),
    Migration(
        16,
        (
            "CREATE TABLE provider_attempt_contexts (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), repository_fingerprint TEXT NOT NULL, worktree_fingerprint TEXT NOT NULL, branch_fingerprint TEXT NOT NULL, base_fingerprint TEXT NOT NULL, candidate_fingerprint TEXT, policy_fingerprint TEXT NOT NULL, deployment_fingerprint TEXT NOT NULL)",
            "INSERT INTO provider_attempt_contexts(attempt_id, task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint) SELECT attempts.attempt_id, attempts.task_id, contexts.repository_fingerprint, contexts.worktree_fingerprint, contexts.branch_fingerprint, contexts.base_fingerprint, contexts.candidate_fingerprint, contexts.policy_fingerprint, contexts.deployment_fingerprint FROM provider_attempts AS attempts JOIN provider_recovery_contexts AS contexts ON contexts.task_id = attempts.task_id",
            "ALTER TABLE provider_session_checkpoints RENAME TO provider_session_checkpoints_v1",
            "CREATE TABLE provider_session_checkpoints (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), session_identity TEXT NOT NULL, identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "INSERT INTO provider_session_checkpoints(attempt_id, task_id, session_identity, identity_fingerprint, created_at) SELECT attempt_id, task_id, session_identity, identity_fingerprint, created_at FROM provider_session_checkpoints_v1",
            "DROP TABLE provider_session_checkpoints_v1",
            "CREATE TABLE provider_recovery_outcomes (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL, blocker TEXT, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0))",
            "ALTER TABLE provider_invalid_outputs RENAME TO provider_invalid_outputs_v1",
            "CREATE TABLE provider_invalid_outputs (invalid_output_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL, reason_fingerprint TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0), UNIQUE(attempt_id, output_fingerprint, reason_fingerprint))",
            "INSERT INTO provider_invalid_outputs(invalid_output_id, task_id, attempt_id, output_fingerprint, reason_fingerprint, recorded_at) SELECT invalid_output_id, task_id, attempt_id, output_fingerprint, reason_fingerprint, recorded_at FROM provider_invalid_outputs_v1",
            "DROP TABLE provider_invalid_outputs_v1",
        ),
        (
            ("provider_attempt_contexts", "CREATE TABLE provider_attempt_contexts (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), repository_fingerprint TEXT NOT NULL, worktree_fingerprint TEXT NOT NULL, branch_fingerprint TEXT NOT NULL, base_fingerprint TEXT NOT NULL, candidate_fingerprint TEXT, policy_fingerprint TEXT NOT NULL, deployment_fingerprint TEXT NOT NULL)"),
            ("provider_session_checkpoints", "CREATE TABLE provider_session_checkpoints (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), session_identity TEXT NOT NULL, identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("provider_recovery_outcomes", "CREATE TABLE provider_recovery_outcomes (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL, blocker TEXT, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0))"),
            ("provider_invalid_outputs", "CREATE TABLE provider_invalid_outputs (invalid_output_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL, reason_fingerprint TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0), UNIQUE(attempt_id, output_fingerprint, reason_fingerprint))"),
        ),
    ),
    Migration(
        17,
        (
            "CREATE TABLE provider_attempts_v2 (attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), attempt_number INTEGER NOT NULL CHECK(attempt_number > 0), process_lease_id TEXT NOT NULL, process_lease_expires_at INTEGER NOT NULL CHECK(process_lease_expires_at > 0), session_identity TEXT, external_turn_identity TEXT, input_fingerprint TEXT NOT NULL, output_pointer TEXT, completion_evidence_fingerprint TEXT, accepted_review_identity TEXT, state TEXT NOT NULL CHECK(state IN ('prepared', 'dispatched', 'completed', 'accepted', 'ambiguous', 'blocked', 'invalidated')), UNIQUE(task_id, provider_role, attempt_number), UNIQUE(task_id, provider_role, external_turn_identity), UNIQUE(task_id, accepted_review_identity), CHECK((external_turn_identity IS NULL AND state IN ('prepared', 'blocked', 'invalidated')) OR (external_turn_identity IS NOT NULL AND state != 'prepared')), CHECK((state IN ('completed', 'accepted') AND output_pointer IS NOT NULL AND completion_evidence_fingerprint IS NOT NULL) OR state NOT IN ('completed', 'accepted')), CHECK((accepted_review_identity IS NOT NULL AND provider_role = 'supervisor' AND state = 'accepted') OR accepted_review_identity IS NULL))",
            "INSERT INTO provider_attempts_v2 SELECT * FROM provider_attempts",
            "CREATE TABLE provider_checkpoints_v2 AS SELECT * FROM provider_checkpoints",
            "CREATE TABLE provider_invalid_outputs_v2 AS SELECT * FROM provider_invalid_outputs",
            "CREATE TABLE provider_recovery_events_v2 AS SELECT * FROM provider_recovery_events",
            "CREATE TABLE accepted_provider_reviews_v2 AS SELECT * FROM accepted_provider_reviews",
            "CREATE TABLE provider_session_checkpoints_v2 AS SELECT * FROM provider_session_checkpoints",
            "CREATE TABLE provider_attempt_contexts_v2 AS SELECT * FROM provider_attempt_contexts",
            "CREATE TABLE provider_recovery_outcomes_v2 AS SELECT * FROM provider_recovery_outcomes",
            "DROP TABLE provider_checkpoints",
            "DROP TABLE provider_invalid_outputs",
            "DROP TABLE provider_recovery_events",
            "DROP TABLE accepted_provider_reviews",
            "DROP TABLE provider_session_checkpoints",
            "DROP TABLE provider_attempt_contexts",
            "DROP TABLE provider_recovery_outcomes",
            "DROP TABLE provider_attempts",
            "ALTER TABLE provider_attempts_v2 RENAME TO provider_attempts",
            "CREATE TABLE provider_checkpoints (checkpoint_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), checkpoint_phase TEXT NOT NULL CHECK(checkpoint_phase IN ('before-dispatch', 'after-dispatch')), attempt_id TEXT REFERENCES provider_attempts(attempt_id), identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0), UNIQUE(task_id, provider_role, checkpoint_phase, attempt_id))",
            "CREATE TABLE provider_invalid_outputs (invalid_output_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL, reason_fingerprint TEXT NOT NULL, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0), UNIQUE(attempt_id, output_fingerprint, reason_fingerprint))",
            "CREATE TABLE provider_recovery_events (recovery_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL CHECK(recovery_action IN ('retry', 'resume-same-session', 'consume-verified-output', 'accepted-review', 'blocked-ambiguous-turn', 'blocked-stale-worker', 'fresh-supervisor-session', 'blocked-retry-limit', 'blocked-identity-drift')), observed_at INTEGER NOT NULL CHECK(observed_at > 0))",
            "CREATE TABLE accepted_provider_reviews (accepted_review_identity TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), completion_evidence_fingerprint TEXT NOT NULL)",
            "CREATE TABLE provider_session_checkpoints (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), session_identity TEXT NOT NULL, identity_fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE provider_attempt_contexts (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), repository_fingerprint TEXT NOT NULL, worktree_fingerprint TEXT NOT NULL, branch_fingerprint TEXT NOT NULL, base_fingerprint TEXT NOT NULL, candidate_fingerprint TEXT, policy_fingerprint TEXT NOT NULL, deployment_fingerprint TEXT NOT NULL)",
            "CREATE TABLE provider_recovery_outcomes (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), recovery_action TEXT NOT NULL, blocker TEXT, recorded_at INTEGER NOT NULL CHECK(recorded_at > 0))",
            "INSERT INTO provider_checkpoints SELECT * FROM provider_checkpoints_v2",
            "INSERT INTO provider_invalid_outputs SELECT * FROM provider_invalid_outputs_v2",
            "INSERT INTO provider_recovery_events SELECT * FROM provider_recovery_events_v2",
            "INSERT INTO accepted_provider_reviews SELECT * FROM accepted_provider_reviews_v2",
            "INSERT INTO provider_session_checkpoints SELECT * FROM provider_session_checkpoints_v2",
            "INSERT INTO provider_attempt_contexts SELECT * FROM provider_attempt_contexts_v2",
            "INSERT INTO provider_recovery_outcomes SELECT * FROM provider_recovery_outcomes_v2",
            "DROP TABLE provider_checkpoints_v2",
            "DROP TABLE provider_invalid_outputs_v2",
            "DROP TABLE provider_recovery_events_v2",
            "DROP TABLE accepted_provider_reviews_v2",
            "DROP TABLE provider_session_checkpoints_v2",
            "DROP TABLE provider_attempt_contexts_v2",
            "DROP TABLE provider_recovery_outcomes_v2",
        ),
        (
            ("provider_attempts", "CREATE TABLE \"provider_attempts\" (attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_role TEXT NOT NULL CHECK(provider_role IN ('planning', 'worker', 'supervisor', 'aggregation')), attempt_number INTEGER NOT NULL CHECK(attempt_number > 0), process_lease_id TEXT NOT NULL, process_lease_expires_at INTEGER NOT NULL CHECK(process_lease_expires_at > 0), session_identity TEXT, external_turn_identity TEXT, input_fingerprint TEXT NOT NULL, output_pointer TEXT, completion_evidence_fingerprint TEXT, accepted_review_identity TEXT, state TEXT NOT NULL CHECK(state IN ('prepared', 'dispatched', 'completed', 'accepted', 'ambiguous', 'blocked', 'invalidated')), UNIQUE(task_id, provider_role, attempt_number), UNIQUE(task_id, provider_role, external_turn_identity), UNIQUE(task_id, accepted_review_identity), CHECK((external_turn_identity IS NULL AND state IN ('prepared', 'blocked', 'invalidated')) OR (external_turn_identity IS NOT NULL AND state != 'prepared')), CHECK((state IN ('completed', 'accepted') AND output_pointer IS NOT NULL AND completion_evidence_fingerprint IS NOT NULL) OR state NOT IN ('completed', 'accepted')), CHECK((accepted_review_identity IS NOT NULL AND provider_role = 'supervisor' AND state = 'accepted') OR accepted_review_identity IS NULL))"),
        ),
    ),
    Migration(
        18,
        (
            "CREATE TABLE worker_plan_attempts (plan_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, source_digest TEXT NOT NULL, input_digest TEXT NOT NULL, task_summary TEXT NOT NULL, parent_plan_attempt_id TEXT REFERENCES worker_plan_attempts(plan_attempt_id), attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('initial', 'revision')), state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'owner-blocked')), created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE worker_plan_artifacts (plan_attempt_id TEXT PRIMARY KEY REFERENCES worker_plan_attempts(plan_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), content_json TEXT NOT NULL, content_digest TEXT NOT NULL)",
            "CREATE TABLE worker_plan_findings (finding_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), finding_digest TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE accepted_plan_reviews (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), review_identity TEXT NOT NULL UNIQUE, review_digest TEXT NOT NULL)",
            "CREATE TABLE deterministic_done_criteria (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), criteria_json TEXT NOT NULL, criteria_digest TEXT NOT NULL)",
        ),
        (
            ("worker_plan_attempts", "CREATE TABLE worker_plan_attempts (plan_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, source_digest TEXT NOT NULL, input_digest TEXT NOT NULL, task_summary TEXT NOT NULL, parent_plan_attempt_id TEXT REFERENCES worker_plan_attempts(plan_attempt_id), attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('initial', 'revision')), state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'owner-blocked')), created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("worker_plan_artifacts", "CREATE TABLE worker_plan_artifacts (plan_attempt_id TEXT PRIMARY KEY REFERENCES worker_plan_attempts(plan_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), content_json TEXT NOT NULL, content_digest TEXT NOT NULL)"),
            ("worker_plan_findings", "CREATE TABLE worker_plan_findings (finding_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), finding_digest TEXT NOT NULL, created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("accepted_plan_reviews", "CREATE TABLE accepted_plan_reviews (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), review_identity TEXT NOT NULL UNIQUE, review_digest TEXT NOT NULL)"),
            ("deterministic_done_criteria", "CREATE TABLE deterministic_done_criteria (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), criteria_json TEXT NOT NULL, criteria_digest TEXT NOT NULL)"),
        ),
    ),
    Migration(
        19,
        (
            "ALTER TABLE worker_plan_attempts ADD COLUMN revision_findings_digest TEXT NOT NULL DEFAULT ''",
            "CREATE TABLE submitted_plan_reviews (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), plan_digest TEXT NOT NULL)",
        ),
        (
            ("worker_plan_attempts", "CREATE TABLE worker_plan_attempts (plan_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, source_digest TEXT NOT NULL, input_digest TEXT NOT NULL, task_summary TEXT NOT NULL, parent_plan_attempt_id TEXT REFERENCES worker_plan_attempts(plan_attempt_id), attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('initial', 'revision')), state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'owner-blocked')), created_at INTEGER NOT NULL CHECK(created_at > 0), revision_findings_digest TEXT NOT NULL DEFAULT '')"),
            ("submitted_plan_reviews", "CREATE TABLE submitted_plan_reviews (task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL UNIQUE REFERENCES worker_plan_attempts(plan_attempt_id), plan_digest TEXT NOT NULL)"),
        ),
    ),
    Migration(
        20,
        (
            "ALTER TABLE worker_plan_attempts ADD COLUMN process_lease_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE worker_plan_attempts ADD COLUMN process_lease_expires_at INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE worker_plan_attempts ADD COLUMN external_turn_identity TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE worker_plan_attempts ADD COLUMN context_digest TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE worker_plan_attempts ADD COLUMN owner_blocker_digest TEXT NOT NULL DEFAULT ''",
        ),
        (
            ("worker_plan_attempts", "CREATE TABLE worker_plan_attempts (plan_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, source_digest TEXT NOT NULL, input_digest TEXT NOT NULL, task_summary TEXT NOT NULL, parent_plan_attempt_id TEXT REFERENCES worker_plan_attempts(plan_attempt_id), attempt_kind TEXT NOT NULL CHECK(attempt_kind IN ('initial', 'revision')), state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'owner-blocked')), created_at INTEGER NOT NULL CHECK(created_at > 0), revision_findings_digest TEXT NOT NULL DEFAULT '', process_lease_id TEXT NOT NULL DEFAULT '', process_lease_expires_at INTEGER NOT NULL DEFAULT 0, external_turn_identity TEXT NOT NULL DEFAULT '', context_digest TEXT NOT NULL DEFAULT '', owner_blocker_digest TEXT NOT NULL DEFAULT '')"),
        ),
    ),
    Migration(
        21,
        (
            "CREATE TABLE provider_completion_outputs (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL)",
        ),
        (
            ("provider_completion_outputs", "CREATE TABLE provider_completion_outputs (attempt_id TEXT PRIMARY KEY REFERENCES provider_attempts(attempt_id), output_fingerprint TEXT NOT NULL)"),
        ),
    ),
    Migration(
        22,
        (
            "CREATE TABLE plan_review_attempts (review_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), supervisor_session_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, source_digest TEXT NOT NULL, plan_digest TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'invalidated')), created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE plan_review_artifacts (review_attempt_id TEXT PRIMARY KEY REFERENCES plan_review_attempts(review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'findings')), findings_json TEXT NOT NULL, missing_tests_json TEXT NOT NULL, ambiguous_criteria_json TEXT NOT NULL, residual_risks_json TEXT NOT NULL, content_digest TEXT NOT NULL)",
            "CREATE TABLE plan_review_routes (review_attempt_id TEXT PRIMARY KEY REFERENCES plan_review_attempts(review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), worker_thread_identity TEXT NOT NULL, finding_ids_json TEXT NOT NULL)",
        ),
        (
            ("plan_review_attempts", "CREATE TABLE plan_review_attempts (review_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), supervisor_session_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, source_digest TEXT NOT NULL, plan_digest TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'invalidated')), created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("plan_review_artifacts", "CREATE TABLE plan_review_artifacts (review_attempt_id TEXT PRIMARY KEY REFERENCES plan_review_attempts(review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'findings')), findings_json TEXT NOT NULL, missing_tests_json TEXT NOT NULL, ambiguous_criteria_json TEXT NOT NULL, residual_risks_json TEXT NOT NULL, content_digest TEXT NOT NULL)"),
            ("plan_review_routes", "CREATE TABLE plan_review_routes (review_attempt_id TEXT PRIMARY KEY REFERENCES plan_review_attempts(review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), worker_thread_identity TEXT NOT NULL, finding_ids_json TEXT NOT NULL)"),
        ),
    ),
    Migration(
        23,
        (
            "CREATE TABLE implementation_attempts (implementation_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), accepted_plan_review_identity TEXT NOT NULL REFERENCES accepted_plan_reviews(review_identity), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded')), created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE implementation_candidates (implementation_attempt_id TEXT PRIMARY KEY REFERENCES implementation_attempts(implementation_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, completion_evidence_fingerprint TEXT NOT NULL, content_digest TEXT NOT NULL, UNIQUE(task_id, candidate_sha))",
            "CREATE TABLE candidate_verifications (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, verification_id TEXT NOT NULL, verification_kind TEXT NOT NULL CHECK(verification_kind IN ('test', 'build')), outcome TEXT NOT NULL CHECK(outcome IN ('pass', 'not-applicable')), evidence_fingerprint TEXT NOT NULL, justification TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha, verification_id))",
            "CREATE TABLE diff_review_attempts (diff_review_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), implementation_attempt_id TEXT NOT NULL REFERENCES implementation_attempts(implementation_attempt_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), supervisor_session_identity TEXT NOT NULL UNIQUE, external_turn_identity TEXT NOT NULL, message_identity TEXT NOT NULL, base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'accepted')), created_at INTEGER NOT NULL CHECK(created_at > 0))",
            "CREATE TABLE diff_review_artifacts (diff_review_attempt_id TEXT PRIMARY KEY REFERENCES diff_review_attempts(diff_review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'findings')), findings_json TEXT NOT NULL, content_digest TEXT NOT NULL)",
            "CREATE TABLE diff_review_routes (diff_review_attempt_id TEXT PRIMARY KEY REFERENCES diff_review_attempts(diff_review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), worker_thread_identity TEXT NOT NULL, finding_ids_json TEXT NOT NULL)",
        ),
        (
            ("implementation_attempts", "CREATE TABLE implementation_attempts (implementation_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), plan_attempt_id TEXT NOT NULL REFERENCES worker_plan_attempts(plan_attempt_id), accepted_plan_review_identity TEXT NOT NULL REFERENCES accepted_plan_reviews(review_identity), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), worker_thread_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded')), created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("implementation_candidates", "CREATE TABLE implementation_candidates (implementation_attempt_id TEXT PRIMARY KEY REFERENCES implementation_attempts(implementation_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, completion_evidence_fingerprint TEXT NOT NULL, content_digest TEXT NOT NULL, UNIQUE(task_id, candidate_sha))"),
            ("candidate_verifications", "CREATE TABLE candidate_verifications (task_id TEXT NOT NULL REFERENCES tasks(task_id), candidate_sha TEXT NOT NULL, verification_id TEXT NOT NULL, verification_kind TEXT NOT NULL CHECK(verification_kind IN ('test', 'build')), outcome TEXT NOT NULL CHECK(outcome IN ('pass', 'not-applicable')), evidence_fingerprint TEXT NOT NULL, justification TEXT NOT NULL, PRIMARY KEY(task_id, candidate_sha, verification_id))"),
            ("diff_review_attempts", "CREATE TABLE diff_review_attempts (diff_review_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), implementation_attempt_id TEXT NOT NULL REFERENCES implementation_attempts(implementation_attempt_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), supervisor_session_identity TEXT NOT NULL UNIQUE, external_turn_identity TEXT NOT NULL, message_identity TEXT NOT NULL, base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'accepted')), created_at INTEGER NOT NULL CHECK(created_at > 0))"),
            ("diff_review_artifacts", "CREATE TABLE diff_review_artifacts (diff_review_attempt_id TEXT PRIMARY KEY REFERENCES diff_review_attempts(diff_review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), verdict TEXT NOT NULL CHECK(verdict IN ('pass', 'findings')), findings_json TEXT NOT NULL, content_digest TEXT NOT NULL)"),
            ("diff_review_routes", "CREATE TABLE diff_review_routes (diff_review_attempt_id TEXT PRIMARY KEY REFERENCES diff_review_attempts(diff_review_attempt_id), task_id TEXT NOT NULL REFERENCES tasks(task_id), worker_thread_identity TEXT NOT NULL, finding_ids_json TEXT NOT NULL)"),
        ),
    ),
    Migration(
        24,
        (
            "ALTER TABLE diff_review_attempts ADD COLUMN verification_digest TEXT NOT NULL DEFAULT ''",
        ),
        (
            ("diff_review_attempts", "CREATE TABLE diff_review_attempts (diff_review_attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id), implementation_attempt_id TEXT NOT NULL REFERENCES implementation_attempts(implementation_attempt_id), provider_attempt_id TEXT NOT NULL UNIQUE REFERENCES provider_attempts(attempt_id), supervisor_session_identity TEXT NOT NULL UNIQUE, external_turn_identity TEXT NOT NULL, message_identity TEXT NOT NULL, base_sha TEXT NOT NULL, candidate_sha TEXT NOT NULL, input_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('dispatched', 'recorded', 'accepted')), created_at INTEGER NOT NULL CHECK(created_at > 0), verification_digest TEXT NOT NULL DEFAULT '')"),
        ),
    ),
)


LIFECYCLE_STATES = frozenset(
    {"queued", "planning", "plan-review", "implementing", "diff-review", "ready-for-owner", "blocked"}
)
_ALLOWED_TRANSITIONS = {
    "queued": frozenset({"planning", "blocked"}),
    "planning": frozenset({"plan-review", "blocked"}),
    "plan-review": frozenset({"planning", "implementing", "blocked"}),
    "implementing": frozenset({"diff-review", "blocked"}),
    "diff-review": frozenset({"implementing", "ready-for-owner", "blocked"}),
    "ready-for-owner": frozenset(),
    "blocked": frozenset({"queued", "planning", "plan-review", "implementing", "diff-review"}),
}
BLOCKER_CLASSES = frozenset({"evidence-ambiguous", "evidence-incomplete", "identity-mismatch", "policy-denied"})
NEXT_ACTION_KINDS = frozenset({"provide-evidence", "reconcile-identity", "resolve-policy", "review-plan"})
ARTIFACT_KINDS = frozenset({"diff", "plan", "review", "status"})


@dataclass(frozen=True)
class SourceSnapshot:
    """One immutable local source snapshot eligible for a Phase 2 task."""

    source_id: str
    repository_id: str
    source_digest: str


@dataclass(frozen=True)
class TaskIdentity:
    """Exact durable identity that binds a task to its sole source snapshot."""

    task_id: str
    source_id: str
    repository_id: str
    branch: str
    worktree: str
    base_sha: str


@dataclass(frozen=True)
class ArtifactReference:
    """Path-free artifact projection bound to a committed opaque fingerprint."""

    kind: str
    fingerprint: str


@dataclass(frozen=True)
class TaskProjection:
    """Owner-safe projection of committed task state; it deliberately omits paths."""

    task_id: str
    repository_id: str
    state: str
    base_sha: str
    source_fingerprint: str
    artifacts: tuple[ArtifactReference, ...]
    blockers: tuple[str, ...]
    next_action: str | None


@dataclass(frozen=True)
class DatabaseStatus:
    state: str
    version: int | None
    detail: str
    identity: str | None = None

    @property
    def healthy(self) -> bool:
        return self.state == "healthy"


def database_path(repository: RepositoryIdentity) -> Path:
    """Return the sole repository-local database path without creating it."""
    state_directory = repository.state_directory
    if state_directory.exists() and not state_directory.is_dir():
        raise StateError("state directory is unavailable")
    path = state_directory / "state.sqlite3"
    if os.path.lexists(path):
        if _is_reparse_point(path) or not path.is_file():
            raise StateError("state database path is unsafe")
        try:
            path.resolve(strict=True).relative_to(repository.root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise StateError("state database path escapes the repository") from error
    return path


def initialize(repository: RepositoryIdentity) -> DatabaseStatus:
    """Create or migrate the local database transactionally and idempotently."""

    path = database_path(repository)
    path_was_absent = not os.path.lexists(path)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise StateError("state directory is unavailable") from error
    try:
        connection = sqlite3.connect(path)
        try:
            _apply_migrations(connection, MIGRATIONS, allow_new_identity=path_was_absent)
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise StateError("local database is corrupt or unreadable") from error
    return check_database(repository)


def check_database(repository: RepositoryIdentity) -> DatabaseStatus:
    """Inspect local state without creating, repairing, or modifying it."""

    try:
        path = database_path(repository)
    except StateError as error:
        return DatabaseStatus("incompatible", None, str(error))
    if not path.exists():
        return DatabaseStatus("missing", None, "run roundwright init")
    if not path.is_file():
        return DatabaseStatus("incompatible", None, "state path is not a regular file")
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            version, identity = _verify_migrations(connection, MIGRATIONS)
        finally:
            connection.close()
    except StateError as error:
        return DatabaseStatus("incompatible", None, str(error))
    except sqlite3.DatabaseError:
        return DatabaseStatus("corrupt", None, "local database is corrupt or unreadable")
    return DatabaseStatus("healthy", version, "migration checksums verified", identity)


def admit_task(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    snapshots: tuple[SourceSnapshot, ...],
    *,
    lease: object | None = None,
) -> TaskProjection:
    """Durably admit exactly one immutable local source into the runnable pool."""

    _validate_task_identity(identity)
    if len(snapshots) != 1:
        raise StateError("a runnable task must have exactly one source snapshot")
    snapshot = snapshots[0]
    _validate_source_snapshot(snapshot)
    if snapshot.source_id != identity.source_id or snapshot.repository_id != identity.repository_id:
        raise StateError("task identity does not match its source snapshot")
    return _mutate_task(repository, identity, snapshot, lease)


def transition_task(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    expected_state: str,
    next_state: str,
    evidence_fingerprint: str,
    lease: object | None = None,
) -> TaskProjection:
    """Advance a non-final task transition through the explicit Phase 2 state sequence."""

    _validate_task_identity(identity)
    _require_state(expected_state)
    _require_state(next_state)
    _require_fingerprint(evidence_fingerprint)
    if expected_state == "diff-review" and next_state == "ready-for-owner":
        raise StateError("ready-for-owner requires the candidate-bound final transition")
    return _commit_transition(repository, identity, expected_state, next_state, evidence_fingerprint, lease=lease)


def _transition_ready_for_owner(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    binding: object,
    seal: object,
    *,
    evidence_fingerprint: str,
    lease: object | None = None,
) -> TaskProjection:
    """Perform the sole final transition after live candidate validation under the lease."""

    from .git_identity import CandidateSeal, WorktreeBinding, candidate_evidence

    _validate_task_identity(identity)
    _require_fingerprint(evidence_fingerprint)
    if not isinstance(binding, WorktreeBinding) or not isinstance(seal, CandidateSeal):
        raise StateError("ready-for-owner requires an exact live candidate binding")
    if binding.task_id != identity.task_id or binding.repository_id != identity.repository_id:
        raise StateError("ready-for-owner candidate binding does not match the task")
    if seal.task_id != identity.task_id or seal.base_sha != identity.base_sha:
        raise StateError("ready-for-owner candidate seal does not match the task")
    candidate_evidence(repository, binding, seal, lease=lease)
    return _commit_transition(
        repository,
        identity,
        "diff-review",
        "ready-for-owner",
        evidence_fingerprint,
        lease=lease,
        candidate_validated=True,
    )


def _commit_transition(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    expected_state: str,
    next_state: str,
    evidence_fingerprint: str,
    *,
    lease: object | None,
    candidate_validated: bool = False,
) -> TaskProjection:
    """Commit an already-authorized state transition in one SQLite transaction."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, identity.repository_id)
        _require_matching_task(connection, identity, expected_state)
        if expected_state == "diff-review" and next_state == "ready-for-owner":
            if not candidate_validated:
                raise StateError("ready-for-owner requires live candidate validation")
            from .gates import GateOutcome, _decision_from_connection

            if _decision_from_connection(connection, identity).outcome is not GateOutcome.PASS:
                raise StateError("ready-for-owner requires persisted aggregate PASS gate evidence")
        blocked_from = connection.execute(
            "SELECT blocked_from_state FROM tasks WHERE task_id = ?", (identity.task_id,)
        ).fetchone()[0]
        if not _transition_is_allowed(expected_state, next_state, blocked_from):
            raise StateError("task transition is invalid, regressive, or skips blocked recovery")
        if connection.execute(
            "SELECT 1 FROM transition_events WHERE task_id = ? AND evidence_fingerprint = ?",
            (identity.task_id, evidence_fingerprint),
        ).fetchone() is not None:
            raise StateError("task transition evidence has already been committed")
        sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM transition_events WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()[0]
        if next_state == "blocked":
            connection.execute(
                "UPDATE tasks SET state = ?, blocked_from_state = ? WHERE task_id = ? AND state = ?",
                (next_state, expected_state, identity.task_id, expected_state),
            )
        else:
            connection.execute(
                "UPDATE tasks SET state = ?, blocked_from_state = NULL WHERE task_id = ? AND state = ?",
                (next_state, identity.task_id, expected_state),
            )
        if expected_state == "blocked":
            connection.execute(
                "UPDATE blockers SET resolution_fingerprint = ? WHERE task_id = ? AND resolution_fingerprint IS NULL",
                (evidence_fingerprint, identity.task_id),
            )
            connection.execute(
                "UPDATE next_actions SET resolution_fingerprint = ? WHERE task_id = ? AND resolution_fingerprint IS NULL",
                (evidence_fingerprint, identity.task_id),
            )
        connection.execute(
            "INSERT INTO transition_events(task_id, sequence, from_state, to_state, evidence_fingerprint) VALUES (?, ?, ?, ?, ?)",
            (identity.task_id, sequence, expected_state, next_state, evidence_fingerprint),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return task_projection(repository, identity)


def record_artifact(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    artifact_kind: str,
    artifact_fingerprint: str,
    lease: object | None = None,
) -> TaskProjection:
    """Persist an opaque artifact reference without making it the source of truth."""

    _validate_task_identity(identity)
    _require_classification(artifact_kind, ARTIFACT_KINDS, "artifact kind")
    _require_fingerprint(artifact_fingerprint)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, identity.repository_id)
        _require_matching_task(connection, identity)
        connection.execute(
            "INSERT OR IGNORE INTO artifact_references(task_id, artifact_kind, artifact_fingerprint) VALUES (?, ?, ?)",
            (identity.task_id, artifact_kind, artifact_fingerprint),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return task_projection(repository, identity)


def set_blocker(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    blocker_class: str,
    evidence_fingerprint: str,
    lease: object | None = None,
) -> TaskProjection:
    """Store a bounded blocker classification while retaining raw evidence outside owner views."""

    _validate_task_identity(identity)
    _require_classification(blocker_class, BLOCKER_CLASSES, "blocker class")
    _require_fingerprint(evidence_fingerprint)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, identity.repository_id)
        _require_matching_task(connection, identity)
        connection.execute(
            "INSERT INTO blockers(task_id, blocker_class, evidence_fingerprint, resolution_fingerprint) VALUES (?, ?, ?, NULL) "
            "ON CONFLICT(task_id, blocker_class) DO UPDATE SET evidence_fingerprint = excluded.evidence_fingerprint, resolution_fingerprint = NULL",
            (identity.task_id, blocker_class, evidence_fingerprint),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return task_projection(repository, identity)


def set_next_action(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    action_kind: str,
    evidence_fingerprint: str,
    lease: object | None = None,
) -> TaskProjection:
    """Persist the one bounded next action associated with committed task state."""

    _validate_task_identity(identity)
    _require_classification(action_kind, NEXT_ACTION_KINDS, "next action")
    _require_fingerprint(evidence_fingerprint)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, identity.repository_id)
        _require_matching_task(connection, identity)
        connection.execute(
            "INSERT INTO next_actions(task_id, action_kind, evidence_fingerprint, resolution_fingerprint) VALUES (?, ?, ?, NULL) "
            "ON CONFLICT(task_id) DO UPDATE SET action_kind = excluded.action_kind, evidence_fingerprint = excluded.evidence_fingerprint, resolution_fingerprint = NULL",
            (identity.task_id, action_kind, evidence_fingerprint),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return task_projection(repository, identity)


def task_projection(repository: RepositoryIdentity, identity: TaskIdentity) -> TaskProjection:
    """Read a path-free rendering projection derived only from committed SQLite state."""

    _validate_task_identity(identity)
    path = database_path(repository)
    if not path.exists():
        raise StateError("local database is missing")
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            _verify_migrations(connection, MIGRATIONS)
            row = _require_matching_task(connection, identity)
            source = connection.execute(
                "SELECT source_digest FROM source_snapshots WHERE source_id = ?", (identity.source_id,)
            ).fetchone()
            artifacts = tuple(
                ArtifactReference(kind=row[0], fingerprint=row[1])
                for row in connection.execute(
                    "SELECT artifact_kind, artifact_fingerprint FROM artifact_references WHERE task_id = ? ORDER BY artifact_kind, artifact_fingerprint",
                    (identity.task_id,),
                )
            )
            blockers = tuple(row[0] for row in connection.execute(
                "SELECT blocker_class FROM blockers WHERE task_id = ? AND resolution_fingerprint IS NULL ORDER BY blocker_class", (identity.task_id,)
            ))
            next_action = connection.execute(
                "SELECT action_kind FROM next_actions WHERE task_id = ? AND resolution_fingerprint IS NULL", (identity.task_id,)
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise StateError("local database is corrupt or unreadable") from error
    if source is None:
        raise StateError("task source snapshot is missing")
    return TaskProjection(
        task_id=identity.task_id,
        repository_id=identity.repository_id,
        state=row[0],
        base_sha=identity.base_sha,
        source_fingerprint=hashlib.sha256(source[0].encode("ascii")).hexdigest()[:16],
        artifacts=artifacts,
        blockers=blockers,
        next_action=None if next_action is None else next_action[0],
    )


def _mutate_task(
    repository: RepositoryIdentity, identity: TaskIdentity, snapshot: SourceSnapshot, lease: object | None
) -> TaskProjection:
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, identity.repository_id)
        existing_source = connection.execute(
            "SELECT repository_id, source_digest FROM source_snapshots WHERE source_id = ?", (snapshot.source_id,)
        ).fetchone()
        if existing_source is None:
            connection.execute(
                "INSERT INTO source_snapshots(source_id, repository_id, source_digest) VALUES (?, ?, ?)",
                (snapshot.source_id, snapshot.repository_id, snapshot.source_digest),
            )
        elif existing_source != (snapshot.repository_id, snapshot.source_digest):
            raise StateError("source snapshot identity does not match replayed input")
        worktree_key = _canonical_worktree_key(identity.worktree)
        existing_task = connection.execute(
            "SELECT source_id, repository_id, branch, worktree, base_sha FROM tasks WHERE task_id = ?", (identity.task_id,)
        ).fetchone()
        expected = (identity.source_id, identity.repository_id, identity.branch, identity.worktree, identity.base_sha)
        branch_owner = connection.execute(
            "SELECT task_id FROM task_branch_ownership WHERE branch = ?", (identity.branch,)
        ).fetchone()
        collision = connection.execute(
            "SELECT task_id FROM tasks WHERE branch = ? AND task_id != ?",
            (identity.branch, identity.task_id),
        ).fetchone()
        owner = connection.execute(
            "SELECT task_id FROM task_worktree_ownership WHERE worktree_key = ?", (worktree_key,)
        ).fetchone()
        if (
            collision is not None
            or (branch_owner is not None and branch_owner[0] != identity.task_id)
            or (owner is not None and owner[0] != identity.task_id)
        ):
            raise StateError("an active task already owns the branch or worktree")
        if existing_task is None:
            connection.execute(
                "INSERT INTO tasks(task_id, source_id, repository_id, branch, worktree, base_sha, state, worktree_key) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)",
                (identity.task_id, *expected, worktree_key),
            )
            connection.execute(
                "INSERT INTO task_worktree_ownership(worktree_key, task_id) VALUES (?, ?)",
                (worktree_key, identity.task_id),
            )
            connection.execute(
                "INSERT INTO task_branch_ownership(branch, task_id) VALUES (?, ?)",
                (identity.branch, identity.task_id),
            )
        elif existing_task != expected:
            raise StateError("task identity does not match replayed input")
        else:
            raise StateError("task has already been admitted")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return task_projection(repository, identity)


def _open_writable_connection(repository: RepositoryIdentity) -> sqlite3.Connection:
    path = database_path(repository)
    if not path.exists():
        raise StateError("local database is missing")
    try:
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys = ON")
        _verify_migrations(connection, MIGRATIONS)
        return connection
    except Exception:
        connection.close() if "connection" in locals() else None
        raise


def _require_matching_task(
    connection: sqlite3.Connection, identity: TaskIdentity, expected_state: str | None = None
) -> tuple[str]:
    row = connection.execute(
        "SELECT state, source_id, repository_id, branch, worktree, base_sha, worktree_key FROM tasks WHERE task_id = ?",
        (identity.task_id,),
    ).fetchone()
    expected = (identity.source_id, identity.repository_id, identity.branch, identity.worktree, identity.base_sha)
    if row is None or tuple(row[1:6]) != expected:
        raise StateError("task identity does not match committed state")
    if row[6] != _canonical_worktree_key(identity.worktree):
        raise StateError("task worktree ownership is not current")
    branch_owner = connection.execute(
        "SELECT task_id FROM task_branch_ownership WHERE branch = ?", (identity.branch,)
    ).fetchone()
    worktree_owner = connection.execute(
        "SELECT task_id FROM task_worktree_ownership WHERE worktree_key = ?", (row[6],)
    ).fetchone()
    if branch_owner != (identity.task_id,) or worktree_owner != (identity.task_id,):
        raise StateError("task ownership is not current")
    if expected_state is not None and row[0] != expected_state:
        raise StateError("task state does not match the requested transition")
    return (row[0],)


def _require_current_transition_lease(connection: sqlite3.Connection, lease: object | None, repository_id: str) -> None:
    """Require the exact unexpired lease row for every state transition."""

    required = ("repository_id", "state_identity", "owner", "generation", "expires_at")
    if lease is None or any(not hasattr(lease, attribute) for attribute in required):
        raise StateError("a current transition lease is required")
    row = connection.execute(
        "SELECT repository_id, state_identity, owner, generation, expires_at FROM transition_leases WHERE lease_scope = 'repository-state'"
    ).fetchone()
    if row is None or tuple(getattr(lease, attribute) for attribute in required) != tuple(row):
        raise StateError("transition lease ownership has drifted")
    if getattr(lease, "repository_id") != repository_id:
        raise StateError("transition lease does not match the task repository")
    state = connection.execute("SELECT value FROM state_metadata WHERE key = 'state_id'").fetchone()
    if state is None or state[0] != getattr(lease, "state_identity"):
        raise StateError("transition lease state identity has drifted")
    if not isinstance(getattr(lease, "expires_at"), int) or getattr(lease, "expires_at") <= int(time.time()):
        raise StateError("transition lease is stale and requires owner recovery")


def _validate_source_snapshot(snapshot: SourceSnapshot) -> None:
    _require_token(snapshot.source_id, "source identity")
    _require_token(snapshot.repository_id, "repository identity")
    if len(snapshot.source_digest) != 64 or any(character not in "0123456789abcdef" for character in snapshot.source_digest):
        raise StateError("source digest is not a lowercase SHA-256 value")


def _validate_task_identity(identity: TaskIdentity) -> None:
    _require_token(identity.task_id, "task identity")
    _require_token(identity.source_id, "source identity")
    _require_token(identity.repository_id, "repository identity")
    _require_token(identity.branch, "task branch")
    _require_worktree(identity.worktree)
    _canonical_worktree_key(identity.worktree)
    if len(identity.base_sha) != 40 or any(character not in "0123456789abcdef" for character in identity.base_sha):
        raise StateError("base commit is not a full lowercase SHA")


def _require_token(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or any(character.isspace() or ord(character) < 32 for character in value):
        raise StateError(f"{name} is invalid")


def _require_worktree(value: str) -> None:
    if not isinstance(value, str) or not value or any(unicodedata.category(character) == "Cc" for character in value):
        raise StateError("task worktree is invalid")


def _canonical_worktree_key(value: str) -> str:
    """Return one platform-aware, absolute ownership key without exposing it."""

    _require_worktree(value)
    if (
        len(value) >= 3
        and value[0].isalpha()
        and value[1] == ":"
        and value[2] in ("/", "\\")
    ):
        return ntpath.normcase(ntpath.normpath(value)).replace("\\", "/")
    if value.startswith(("\\\\", "//")):
        return ntpath.normcase(ntpath.normpath(value)).replace("\\", "/")
    if value.startswith("/"):
        return posixpath.normpath(value)
    raise StateError("task worktree must be an absolute path")


def _require_fingerprint(value: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise StateError("evidence fingerprint is not a lowercase SHA-256 value")


def _require_state(value: str) -> None:
    if value not in LIFECYCLE_STATES:
        raise StateError("task state is invalid")


def _transition_is_allowed(current: str, next_state: str, blocked_from: object) -> bool:
    if next_state not in _ALLOWED_TRANSITIONS[current]:
        return False
    if current != "blocked":
        return True
    return isinstance(blocked_from, str) and blocked_from == next_state


def _require_classification(value: str, allowed: frozenset[str], name: str) -> None:
    if value not in allowed:
        raise StateError(f"{name} is not an owner-safe classification")


def _apply_migrations(connection: sqlite3.Connection, migrations: Iterable[Migration], *, allow_new_identity: bool = True) -> None:
    ordered = _validate_definitions(migrations)
    try:
        connection.execute("BEGIN IMMEDIATE")
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if not exists:
            if not allow_new_identity:
                raise StateError("existing database is unrecognized")
            unmanaged = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table'"
            ).fetchone()
            if unmanaged:
                raise StateError("database contains unmanaged partial schema")
            applied: dict[int, str] = {}
        else:
            applied = _read_applied(connection)
        _validate_applied(applied, ordered)
        _validate_schema(connection, ordered[:len(applied)])
        for migration in ordered[len(applied):]:
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations(version, checksum) VALUES (?, ?)",
                (migration.version, migration.checksum),
            )
        _backfill_task_ownership(connection)
        _validate_task_ownership(connection)
        _ensure_state_identity(connection, allow_create=allow_new_identity and not exists)
        _validate_schema(connection, ordered)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _verify_migrations(connection: sqlite3.Connection, migrations: Iterable[Migration]) -> tuple[int, str]:
    ordered = _validate_definitions(migrations)
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if not exists:
        raise StateError("migration history is missing")
    applied = _read_applied(connection)
    _validate_applied(applied, ordered)
    if len(applied) != len(ordered):
        raise StateError("database schema is not fully migrated")
    _validate_schema(connection, ordered)
    _validate_task_ownership(connection)
    return ordered[-1].version if ordered else 0, _read_state_identity(connection)


def _backfill_task_ownership(connection: sqlite3.Connection) -> None:
    """Establish all durable task ownership invariants during migration."""

    has_worktree_ownership = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_worktree_ownership'"
    ).fetchone()
    has_branch_ownership = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_branch_ownership'"
    ).fetchone()
    if not has_worktree_ownership and not has_branch_ownership:
        return
    for task_id, branch, worktree in connection.execute("SELECT task_id, branch, worktree FROM tasks ORDER BY task_id"):
        if has_branch_ownership:
            branch_owner = connection.execute(
                "SELECT task_id FROM task_branch_ownership WHERE branch = ?", (branch,)
            ).fetchone()
            if branch_owner is not None and branch_owner[0] != task_id:
                raise StateError("active task branch ownership is ambiguous")
            connection.execute(
                "INSERT INTO task_branch_ownership(branch, task_id) VALUES (?, ?) "
                "ON CONFLICT(branch) DO UPDATE SET task_id = excluded.task_id",
                (branch, task_id),
            )
        if not has_worktree_ownership:
            continue
        key = _canonical_worktree_key(worktree)
        existing = connection.execute(
            "SELECT task_id FROM task_worktree_ownership WHERE worktree_key = ?", (key,)
        ).fetchone()
        if existing is not None and existing[0] != task_id:
            raise StateError("active task worktree ownership is ambiguous")
        connection.execute("UPDATE tasks SET worktree_key = ? WHERE task_id = ?", (key, task_id))
        reservation = connection.execute(
            "SELECT worktree_key FROM task_worktree_ownership WHERE task_id = ?", (task_id,)
        ).fetchone()
        if reservation is None:
            connection.execute(
                "INSERT INTO task_worktree_ownership(worktree_key, task_id) VALUES (?, ?)",
                (key, task_id),
            )
        elif reservation[0] != key:
            connection.execute(
                "UPDATE task_worktree_ownership SET worktree_key = ? WHERE task_id = ?", (key, task_id)
            )


def _validate_task_ownership(connection: sqlite3.Connection) -> None:
    """Fail closed if a fully migrated ledger no longer has one owner per task."""

    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if "tasks" not in tables:
        return
    for table in ("task_branch_ownership", "task_worktree_ownership"):
        if table not in tables:
            return
    tasks = tuple(connection.execute("SELECT task_id, branch, worktree, worktree_key FROM tasks ORDER BY task_id"))
    if connection.execute("SELECT COUNT(*) FROM task_branch_ownership").fetchone()[0] != len(tasks):
        raise StateError("task branch ownership is incomplete")
    if connection.execute("SELECT COUNT(*) FROM task_worktree_ownership").fetchone()[0] != len(tasks):
        raise StateError("task worktree ownership is incomplete")
    for task_id, branch, worktree, worktree_key in tasks:
        if worktree_key != _canonical_worktree_key(worktree):
            raise StateError("task worktree ownership is invalid")
        if connection.execute(
            "SELECT task_id FROM task_branch_ownership WHERE branch = ?", (branch,)
        ).fetchone() != (task_id,):
            raise StateError("task branch ownership is invalid")
        if connection.execute(
            "SELECT task_id FROM task_worktree_ownership WHERE worktree_key = ?", (worktree_key,)
        ).fetchone() != (task_id,):
            raise StateError("task worktree ownership is invalid")


def _validate_definitions(migrations: Iterable[Migration]) -> tuple[Migration, ...]:
    ordered = tuple(migrations)
    versions = tuple(migration.version for migration in ordered)
    if not ordered or any(version < 1 for version in versions) or versions != tuple(range(1, len(ordered) + 1)):
        raise StateError("migration definitions are invalid or duplicate")
    return ordered


def _validate_schema(connection: sqlite3.Connection, migrations: Iterable[Migration]) -> None:
    expected = {name: statement for migration in migrations for name, statement in migration.schema}
    observed = connection.execute(
        "SELECT type, name FROM sqlite_master "
        "WHERE type IN ('table', 'view', 'index', 'trigger') AND name NOT GLOB 'sqlite_*'"
    ).fetchall()
    if set(observed) != {('table', name) for name in expected}:
        raise StateError("database contains unmanaged or missing application schema")
    for name, statement in expected.items():
        row = connection.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        if row != ("table", statement):
            raise StateError("database schema does not match recorded migration")


def _ensure_state_identity(connection: sqlite3.Connection, *, allow_create: bool) -> None:
    row = connection.execute("SELECT value FROM state_metadata WHERE key = 'state_id'").fetchone()
    if row is None:
        if not allow_create:
            raise StateError("state identity is missing")
        connection.execute("INSERT INTO state_metadata(key, value) VALUES ('state_id', ?)", (str(uuid.uuid4()),))
        return
    _state_identity_fingerprint(row[0])


def _read_state_identity(connection: sqlite3.Connection) -> str:
    row = connection.execute("SELECT value FROM state_metadata WHERE key = 'state_id'").fetchone()
    if row is None:
        raise StateError("state identity is missing")
    return _state_identity_fingerprint(row[0])


def _state_identity_fingerprint(value: object) -> str:
    if not isinstance(value, str):
        raise StateError("state identity is malformed")
    try:
        state_id = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise StateError("state identity is malformed") from error
    return hashlib.sha256(state_id.bytes).hexdigest()[:16]


def _is_reparse_point(path: Path) -> bool:
    try:
        entry = path.lstat()
    except OSError as error:
        raise StateError("state database path is unsafe") from error
    if stat.S_ISLNK(entry.st_mode):
        return True
    attributes = getattr(entry, "st_file_attributes", None)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes is not None and reparse_flag and attributes & reparse_flag)


def _read_applied(connection: sqlite3.Connection) -> dict[int, str]:
    rows = connection.execute("SELECT version, checksum FROM schema_migrations ORDER BY version").fetchall()
    if any(not isinstance(version, int) or not isinstance(checksum, str) for version, checksum in rows):
        raise StateError("migration history is malformed")
    return dict(rows)


def _validate_applied(applied: dict[int, str], ordered: tuple[Migration, ...]) -> None:
    expected = {migration.version: migration.checksum for migration in ordered}
    versions = tuple(applied)
    if len(versions) != len(applied) or versions != tuple(range(1, len(versions) + 1)):
        raise StateError("migration history has a missing or duplicate version")
    if any(version not in expected for version in versions):
        raise StateError("database schema is from a future version")
    for version, checksum in applied.items():
        if checksum != expected[version]:
            raise StateError("migration checksum does not match canonical content")
