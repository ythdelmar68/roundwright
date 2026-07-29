"""Table-driven contracts for the centralized Phase 2 gate decision."""

from __future__ import annotations

import sys
import tempfile
import unittest
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.gates import (
    EvidenceOutcome,
    FollowUp,
    GATE_REGISTRY,
    GateContext,
    GateDecision,
    GateEvidence,
    GateError,
    GateKey,
    GateOutcome,
    TrustedGatePolicyEvidence,
    decide_gates,
    evaluate_gates,
    render_gate_decision,
    read_gate_evidence,
    record_gate_evidence,
    task_identity_fingerprint,
    transition_ready_for_owner,
)
from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import CandidateSeal, GitIdentityError, WorktreeBinding, acquire_transition_lease
from roundwright.policy import ActivationReceipt, PolicyAction, PolicyDocument, ReceiptStatus, StandingAuthority, TrustedControlSource, TrustedPolicySnapshot
from roundwright.state import SourceSnapshot, StateError, TaskIdentity, admit_task, database_path, initialize, transition_task


class GateDecisionTests(unittest.TestCase):
    task_id = "issue-21"
    candidate = "a" * 40
    policy_digest = "c" * 64
    receipt_fingerprint = "d" * 64

    def context(self, *, sources: int = 1, isolated: bool = True) -> GateContext:
        return GateContext(self.task_id, self.candidate, sources, isolated, self.policy_digest, self.receipt_fingerprint)

    def evidence(
        self,
        key: GateKey,
        outcome: EvidenceOutcome = EvidenceOutcome.PASS,
        *,
        fingerprint: str = "1" * 64,
        candidate: str | None = None,
        boundary: str | None = None,
        reason: str | None = None,
        follow_ups: object = (),
    ) -> GateEvidence:
        return GateEvidence(
            self.task_id,
            self.candidate if candidate is None else candidate,
            key,
            outcome,
            "deterministic-validator",
            1,
            fingerprint,
            boundary,
            reason,
            follow_ups,
        )

    def accepted_evidence(self) -> tuple[GateEvidence, ...]:
        entries = []
        for index, requirement in enumerate(GATE_REGISTRY, 1):
            fingerprint = f"{index:064x}"
            if requirement.permits_phase_two_local_na:
                entries.append(
                    self.evidence(
                        requirement.key,
                        EvidenceOutcome.NOT_APPLICABLE,
                        fingerprint=fingerprint,
                        boundary="phase-2 isolated local task",
                        reason="the provider-neutral local slice has no external adapter",
                    )
                )
            else:
                entries.append(self.evidence(requirement.key, fingerprint=fingerprint))
        return tuple(entries)

    def test_every_registered_gate_accepts_structured_evidence(self) -> None:
        decision = decide_gates(self.context(), self.accepted_evidence())
        self.assertEqual(decision.outcome, GateOutcome.PASS)
        self.assertEqual(tuple(result.gate_key for result in decision.results), tuple(item.key.value for item in GATE_REGISTRY))
        self.assertEqual(render_gate_decision(decision).splitlines()[0], "decision=PASS")

    def test_each_registered_gate_is_required(self) -> None:
        accepted = self.accepted_evidence()
        for omitted in GATE_REGISTRY:
            with self.subTest(gate=omitted.key):
                decision = decide_gates(self.context(), tuple(item for item in accepted if item.gate_key != omitted.key))
                self.assertEqual(decision.outcome, GateOutcome.PENDING)
                result = next(item for item in decision.results if item.gate_key == omitted.key.value)
                self.assertEqual(result.outcome, GateOutcome.PENDING)

    def test_unjustified_or_multi_source_not_applicable_fails_closed(self) -> None:
        accepted = list(self.accepted_evidence())
        external = next(item for item in GATE_REGISTRY if item.permits_phase_two_local_na).key
        accepted = [item for item in accepted if item.gate_key != external]
        accepted.append(self.evidence(external, EvidenceOutcome.NOT_APPLICABLE, boundary=None, reason=None))
        self.assertEqual(decide_gates(self.context(), tuple(accepted)).outcome, GateOutcome.BLOCKED)
        accepted[-1] = self.evidence(
            external,
            EvidenceOutcome.NOT_APPLICABLE,
            boundary="isolated local boundary",
            reason="no adapter in Phase 2",
        )
        self.assertEqual(decide_gates(self.context(sources=2), tuple(accepted)).outcome, GateOutcome.BLOCKED)

    def test_findings_unknown_invalid_conflict_and_candidate_mismatch_never_pass(self) -> None:
        cases = (
            (self.evidence(GateKey.BUILD, EvidenceOutcome.FINDINGS), GateOutcome.BLOCKED),
            (self.evidence(GateKey.BUILD, EvidenceOutcome.UNKNOWN), GateOutcome.BLOCKED),
            (self.evidence(GateKey.BUILD, EvidenceOutcome.PASS, fingerprint=""), GateOutcome.BLOCKED),
            (
                self.evidence(GateKey.BUILD, EvidenceOutcome.PASS, candidate="b" * 40),
                GateOutcome.BLOCKED,
            ),
        )
        for replacement, expected in cases:
            with self.subTest(replacement=replacement):
                evidence = [item for item in self.accepted_evidence() if item.gate_key != GateKey.BUILD]
                evidence.append(replacement)
                self.assertEqual(decide_gates(self.context(), tuple(evidence)).outcome, expected)

        conflict = list(self.accepted_evidence())
        conflict.append(self.evidence(GateKey.BUILD, EvidenceOutcome.FINDINGS, fingerprint="f" * 64))
        self.assertEqual(decide_gates(self.context(), tuple(conflict)).outcome, GateOutcome.BLOCKED)

    def test_candidate_movement_requires_fresh_evidence(self) -> None:
        moved = GateContext(self.task_id, "b" * 40, 1, True, self.policy_digest, self.receipt_fingerprint)
        self.assertEqual(decide_gates(moved, self.accepted_evidence()).outcome, GateOutcome.BLOCKED)
        self.assertEqual(decide_gates(moved, ()).outcome, GateOutcome.PENDING)

    def test_status_rendering_is_deterministic_for_all_decisions(self) -> None:
        pass_render = render_gate_decision(decide_gates(self.context(), self.accepted_evidence()))
        pending_render = render_gate_decision(decide_gates(self.context(), ()))
        blocked_render = render_gate_decision(
            GateDecision(GateOutcome.BLOCKED, decide_gates(self.context(), ()).results)
        )
        self.assertTrue(pass_render.startswith("decision=PASS\n"))
        self.assertTrue(pending_render.startswith("decision=PENDING\n"))
        self.assertTrue(blocked_render.startswith("decision=BLOCKED\n"))

    def test_boolean_context_and_timestamp_values_are_invalid(self) -> None:
        accepted = list(self.accepted_evidence())
        accepted[-1] = GateEvidence(
            accepted[-1].task_id,
            accepted[-1].candidate_sha,
            accepted[-1].gate_key,
            accepted[-1].outcome,
            accepted[-1].evaluator_id,
            True,
            accepted[-1].evidence_fingerprint,
            accepted[-1].changed_boundary,
            accepted[-1].reason,
        )
        self.assertEqual(decide_gates(self.context(), tuple(accepted)).outcome, GateOutcome.BLOCKED)
        self.assertEqual(decide_gates(GateContext(self.task_id, self.candidate, True, "yes", self.policy_digest, self.receipt_fingerprint), self.accepted_evidence()).outcome, GateOutcome.BLOCKED)

    def test_unresolved_follow_ups_and_malformed_shapes_fail_closed(self) -> None:
        evidence = [item for item in self.accepted_evidence() if item.gate_key != GateKey.SUPERVISOR_DIFF_REVIEW]
        evidence.append(self.evidence(GateKey.SUPERVISOR_DIFF_REVIEW, follow_ups=(FollowUp("follow-up-1", False),)))
        self.assertEqual(decide_gates(self.context(), tuple(evidence)).outcome, GateOutcome.BLOCKED)
        for requirement in (item for item in GATE_REGISTRY if item.permits_phase_two_local_na):
            with self.subTest(gate=requirement.key):
                evidence = [item for item in self.accepted_evidence() if item.gate_key != requirement.key]
                evidence.append(
                    self.evidence(
                        requirement.key,
                        EvidenceOutcome.NOT_APPLICABLE,
                        boundary="phase-2 isolated local task",
                        reason="the provider-neutral local slice has no external adapter",
                        follow_ups=(FollowUp(f"{requirement.key.value}-follow-up", False),),
                    )
                )
                self.assertEqual(decide_gates(self.context(), tuple(evidence)).outcome, GateOutcome.BLOCKED)
        malformed = GateEvidence(self.task_id, self.candidate, [], EvidenceOutcome.PASS, "validator", 1, "1" * 64)
        self.assertEqual(decide_gates(self.context(), (malformed,)).outcome, GateOutcome.BLOCKED)
        self.assertEqual(decide_gates(self.context(), list(self.accepted_evidence())).outcome, GateOutcome.BLOCKED)


class SQLiteGateEvidenceTests(unittest.TestCase):
    def policy_snapshot(self) -> TrustedPolicySnapshot:
        return TrustedPolicySnapshot(
            TrustedControlSource("a" * 64, "b" * 64),
            PolicyDocument(1, frozenset({PolicyAction.ISSUE_COMMENT})),
        )

    def policy_evidence(
        self,
        context: GateContext,
        *,
        task_fingerprint: str | None = None,
        activated_at: datetime | None = None,
        status: ReceiptStatus = ReceiptStatus.FRESH,
    ) -> TrustedGatePolicyEvidence:
        snapshot = self.policy_snapshot()
        activated_at = datetime(2026, 7, 29, tzinfo=timezone.utc) if activated_at is None else activated_at
        now = activated_at + timedelta(minutes=1)
        receipt = ActivationReceipt(
            "c" * 64,
            context.receipt_fingerprint,
            snapshot.source.source_fingerprint,
            snapshot.source.revision_fingerprint,
            snapshot.policy_digest,
            1,
            self.expected_task_fingerprint(context) if task_fingerprint is None else task_fingerprint,
            context.candidate_sha,
            activated_at,
            now + timedelta(minutes=1),
        )
        return TrustedGatePolicyEvidence(
            snapshot,
            receipt,
            StandingAuthority(frozenset(PolicyAction)),
            now,
            status,
        )

    def expected_task_fingerprint(self, context: GateContext) -> str:
        return task_identity_fingerprint(
            TaskIdentity(context.task_id, "source-21", "ythdelmar68/roundwright", "codex/issue-21", "C:/private/issue-21", "a" * 40)
        )

    def repository(self, root: Path) -> RepositoryIdentity:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", root.resolve())
        return repository

    def complete_persisted_pass(self, root: Path, *, receipt_fingerprint: str = "d" * 64):
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("issue-21", "source-21", "ythdelmar68/roundwright", "codex/issue-21", "C:/private/issue-21", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="gate-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "1" * 64),), lease=lease)
        binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, Path(identity.worktree), identity.base_sha, lease.state_identity)
        seal = CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity)
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)", (seal.task_id, seal.base_sha, seal.candidate_sha, seal.state_identity))
            connection.commit()
        finally:
            connection.close()
        context = GateContext(identity.task_id, seal.candidate_sha, 1, True, self.policy_snapshot().policy_digest, receipt_fingerprint)
        policy_evidence = self.policy_evidence(context)
        evidence = []
        for number, requirement in enumerate(GATE_REGISTRY, 1):
            outcome = EvidenceOutcome.NOT_APPLICABLE if requirement.permits_phase_two_local_na else EvidenceOutcome.PASS
            evidence.append(GateEvidence(identity.task_id, seal.candidate_sha, requirement.key, outcome, "validator", number, f"{number:064x}", "isolated local boundary" if outcome is EvidenceOutcome.NOT_APPLICABLE else None, "no external adapter in Phase 2" if outcome is EvidenceOutcome.NOT_APPLICABLE else None))
        with mock.patch("roundwright.gates.bind_candidate_evidence"):
            for item in evidence:
                record_gate_evidence(repository, binding, seal, context, item, policy_evidence=policy_evidence, lease=lease)
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.executemany("INSERT OR IGNORE INTO candidate_evidence(task_id, candidate_sha, evidence_fingerprint) VALUES (?, ?, ?)", [(identity.task_id, seal.candidate_sha, item.evidence_fingerprint) for item in evidence])
            connection.commit()
        finally:
            connection.close()
        for before, after, fingerprint in (("queued", "planning", "3"), ("planning", "plan-review", "4"), ("plan-review", "implementing", "5"), ("implementing", "diff-review", "6")):
            transition_task(repository, identity, expected_state=before, next_state=after, evidence_fingerprint=fingerprint * 64, lease=lease)
        return repository, identity, binding, seal, context, lease, tuple(item.evidence_fingerprint for item in evidence)

    def test_sqlite_evidence_is_candidate_bound_and_uses_the_current_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = TaskIdentity("issue-21", "source-21", "ythdelmar68/roundwright", "codex/issue-21", "C:/private/issue-21", "a" * 40)
            lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="gate-tests", ttl_seconds=60)
            admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "1" * 64),), lease=lease)
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, Path(identity.worktree), identity.base_sha, lease.state_identity)
            seal = CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                    (seal.task_id, seal.base_sha, seal.candidate_sha, seal.state_identity),
                )
                connection.commit()
            finally:
                connection.close()
            context = GateContext(identity.task_id, seal.candidate_sha, 1, True, self.policy_snapshot().policy_digest, "d" * 64)
            policy_evidence = self.policy_evidence(context)
            evidence = GateEvidence(identity.task_id, seal.candidate_sha, GateKey.BUILD, EvidenceOutcome.PASS, "validator", 1, "2" * 64)
            with mock.patch("roundwright.gates.bind_candidate_evidence") as bind:
                record_gate_evidence(repository, binding, seal, context, evidence, policy_evidence=policy_evidence, lease=lease)
            bind.assert_called_once()
            with mock.patch("roundwright.gates.candidate_evidence", return_value=(evidence.evidence_fingerprint,)):
                self.assertEqual(read_gate_evidence(repository, binding, seal, lease=lease), (evidence,))
            moved = CandidateSeal(identity.task_id, identity.base_sha, "c" * 40, lease.state_identity)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=(evidence.evidence_fingerprint,)):
                self.assertEqual(read_gate_evidence(repository, binding, moved, lease=lease), ())

    def test_conflicting_replay_is_durable_and_detached_decisions_cannot_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = TaskIdentity("issue-21", "source-21", "ythdelmar68/roundwright", "codex/issue-21", "C:/private/issue-21", "a" * 40)
            lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="gate-tests", ttl_seconds=60)
            admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "1" * 64),), lease=lease)
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, Path(identity.worktree), identity.base_sha, lease.state_identity)
            seal = CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)", (seal.task_id, seal.base_sha, seal.candidate_sha, seal.state_identity))
                connection.commit()
            finally:
                connection.close()
            context = GateContext(identity.task_id, seal.candidate_sha, 1, True, self.policy_snapshot().policy_digest, "d" * 64)
            policy_evidence = self.policy_evidence(context)
            passed = GateEvidence(identity.task_id, seal.candidate_sha, GateKey.BUILD, EvidenceOutcome.PASS, "validator", 1, "2" * 64)
            findings = GateEvidence(identity.task_id, seal.candidate_sha, GateKey.BUILD, EvidenceOutcome.FINDINGS, "validator", 1, "2" * 64)
            with mock.patch("roundwright.gates.bind_candidate_evidence"):
                record_gate_evidence(repository, binding, seal, context, passed, policy_evidence=policy_evidence, lease=lease)
                with self.assertRaisesRegex(Exception, "conflicting gate evidence"):
                    record_gate_evidence(repository, binding, seal, context, findings, policy_evidence=policy_evidence, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT outcome FROM gate_evidence").fetchone(), ("CONFLICT",))
            finally:
                connection.close()
            for before, after, fingerprint in (("queued", "planning", "3"), ("planning", "plan-review", "4"), ("plan-review", "implementing", "5"), ("implementing", "diff-review", "6")):
                transition_task(repository, identity, expected_state=before, next_state=after, evidence_fingerprint=fingerprint * 64, lease=lease)
            with self.assertRaises(StateError):
                transition_task(repository, identity, expected_state="diff-review", next_state="ready-for-owner", evidence_fingerprint="7" * 64, lease=lease)

    def test_persisted_all_gates_pass_decodes_context_and_allows_final_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, binding, seal, context, lease, fingerprints = self.complete_persisted_pass(Path(temporary))
            policy_evidence = self.policy_evidence(context)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                self.assertEqual(evaluate_gates(repository, binding, seal, context, policy_evidence=policy_evidence, lease=lease).outcome, GateOutcome.PASS)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints), mock.patch("roundwright.git_identity.candidate_evidence", return_value=fingerprints):
                transition_ready_for_owner(repository, binding, seal, context, evidence_fingerprint="7" * 64, policy_evidence=policy_evidence, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM tasks WHERE task_id = ?", (identity.task_id,)).fetchone(), ("ready-for-owner",))
            finally:
                connection.close()

    def test_live_head_and_dirty_drift_block_the_only_final_transition_path(self) -> None:
        for message in ("candidate head moved and candidate sealing is required", "candidate worktree is dirty"):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                repository, identity, binding, seal, context, lease, _ = self.complete_persisted_pass(Path(temporary))
                with self.assertRaisesRegex(GitIdentityError, message), mock.patch("roundwright.gates.candidate_evidence", side_effect=GitIdentityError(message)):
                    transition_ready_for_owner(repository, binding, seal, context, evidence_fingerprint="7" * 64, policy_evidence=self.policy_evidence(context), lease=lease)
                with self.assertRaises(StateError):
                    transition_task(repository, identity, expected_state="diff-review", next_state="ready-for-owner", evidence_fingerprint="8" * 64, lease=lease)

    def test_persisted_follow_up_and_policy_movement_block_without_candidate_movement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, binding, seal, context, lease, fingerprints = self.complete_persisted_pass(Path(temporary))
            policy_evidence = self.policy_evidence(context)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "UPDATE gate_evidence SET follow_ups = ? WHERE task_id = ? AND gate_key = ?",
                    ('[{"identifier":"follow-up-1","resolution_fingerprint":null,"resolved":false}]', identity.task_id, GateKey.SUPERVISOR_DIFF_REVIEW.value),
                )
                connection.commit()
            finally:
                connection.close()
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                self.assertEqual(evaluate_gates(repository, binding, seal, context, policy_evidence=policy_evidence, lease=lease).outcome, GateOutcome.BLOCKED)
            moved_policy = GateContext(context.task_id, context.candidate_sha, context.source_count, context.isolated_local_task, "e" * 64, context.receipt_fingerprint)
            moved_receipt = GateContext(context.task_id, context.candidate_sha, context.source_count, context.isolated_local_task, context.policy_digest, "f" * 64)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                self.assertEqual(evaluate_gates(repository, binding, seal, moved_policy, policy_evidence=policy_evidence, lease=lease).outcome, GateOutcome.BLOCKED)
                self.assertEqual(evaluate_gates(repository, binding, seal, moved_receipt, policy_evidence=policy_evidence, lease=lease).outcome, GateOutcome.BLOCKED)
                with self.assertRaises(GateError):
                    transition_ready_for_owner(repository, binding, seal, moved_policy, evidence_fingerprint="7" * 64, policy_evidence=policy_evidence, lease=lease)

    def test_superseded_receipt_replay_cannot_replace_current_context_or_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, binding, seal, old_context, lease, _ = self.complete_persisted_pass(Path(temporary))
            fresh_context = GateContext(
                old_context.task_id,
                old_context.candidate_sha,
                old_context.source_count,
                old_context.isolated_local_task,
                old_context.policy_digest,
                "f" * 64,
            )
            fresh_policy = self.policy_evidence(
                fresh_context,
                activated_at=datetime(2026, 7, 29, 1, tzinfo=timezone.utc),
            )
            fresh_evidence = []
            for number, requirement in enumerate(GATE_REGISTRY, 1):
                outcome = EvidenceOutcome.NOT_APPLICABLE if requirement.permits_phase_two_local_na else EvidenceOutcome.PASS
                fresh_evidence.append(
                    GateEvidence(
                        identity.task_id,
                        seal.candidate_sha,
                        requirement.key,
                        outcome,
                        "validator",
                        number,
                        f"{number + 64:064x}",
                        "isolated local boundary" if outcome is EvidenceOutcome.NOT_APPLICABLE else None,
                        "no external adapter in Phase 2" if outcome is EvidenceOutcome.NOT_APPLICABLE else None,
                    )
                )
            with mock.patch("roundwright.gates.bind_candidate_evidence"):
                for entry in fresh_evidence:
                    record_gate_evidence(
                        repository,
                        binding,
                        seal,
                        fresh_context,
                        entry,
                        policy_evidence=fresh_policy,
                        lease=lease,
                    )
            fingerprints = tuple(entry.evidence_fingerprint for entry in fresh_evidence)
            stale_context = GateContext(
                fresh_context.task_id,
                fresh_context.candidate_sha,
                fresh_context.source_count,
                fresh_context.isolated_local_task,
                fresh_context.policy_digest,
                "d" * 64,
            )
            stale_evidence = GateEvidence(
                identity.task_id,
                seal.candidate_sha,
                GateKey.BUILD,
                EvidenceOutcome.PASS,
                "validator",
                99,
                "f" * 64,
            )
            with mock.patch("roundwright.gates.bind_candidate_evidence"):
                with self.assertRaisesRegex(GateError, "gate context conflicts"):
                    record_gate_evidence(
                        repository,
                        binding,
                        seal,
                        stale_context,
                        stale_evidence,
                        policy_evidence=self.policy_evidence(stale_context),
                        lease=lease,
                    )
                with self.assertRaisesRegex(GateError, "current trusted policy evidence"):
                    record_gate_evidence(
                        repository,
                        binding,
                        seal,
                        stale_context,
                        stale_evidence,
                        policy_evidence=self.policy_evidence(stale_context, status=ReceiptStatus.CONSUMED),
                        lease=lease,
                    )
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                self.assertEqual(
                    evaluate_gates(
                        repository,
                        binding,
                        seal,
                        stale_context,
                        policy_evidence=self.policy_evidence(stale_context, status=ReceiptStatus.CONSUMED),
                        lease=lease,
                    ).outcome,
                    GateOutcome.BLOCKED,
                )
                self.assertEqual(
                    evaluate_gates(
                        repository,
                        binding,
                        seal,
                        fresh_context,
                        policy_evidence=fresh_policy,
                        lease=lease,
                    ).outcome,
                    GateOutcome.PASS,
                )
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                with self.assertRaises(GateError):
                    transition_ready_for_owner(
                        repository,
                        binding,
                        seal,
                        stale_context,
                        evidence_fingerprint="7" * 64,
                        policy_evidence=self.policy_evidence(stale_context, status=ReceiptStatus.CONSUMED),
                        lease=lease,
                    )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute("SELECT state FROM tasks WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    ("diff-review",),
                )
                self.assertEqual(
                    connection.execute("SELECT receipt_fingerprint FROM gate_contexts WHERE task_id = ? AND candidate_sha = ?", (identity.task_id, seal.candidate_sha)).fetchone(),
                    (fresh_context.receipt_fingerprint,),
                )
            finally:
                connection.close()

    def test_foreign_task_receipt_with_the_same_candidate_cannot_complete_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, binding, seal, context, lease, fingerprints = self.complete_persisted_pass(Path(temporary))
            foreign = TaskIdentity(
                "issue-22",
                "source-22",
                identity.repository_id,
                "codex/issue-22",
                "C:/private/issue-22",
                identity.base_sha,
            )
            admit_task(
                repository,
                foreign,
                (SourceSnapshot(foreign.source_id, foreign.repository_id, "2" * 64),),
                lease=lease,
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                    (foreign.task_id, foreign.base_sha, seal.candidate_sha, lease.state_identity),
                )
                connection.commit()
            finally:
                connection.close()
            foreign_policy = self.policy_evidence(
                context,
                task_fingerprint=task_identity_fingerprint(foreign),
            )
            foreign_evidence = GateEvidence(
                identity.task_id,
                seal.candidate_sha,
                GateKey.BUILD,
                EvidenceOutcome.PASS,
                "validator",
                99,
                "f" * 64,
            )
            with mock.patch("roundwright.gates.bind_candidate_evidence"):
                with self.assertRaises(GateError):
                    record_gate_evidence(
                        repository,
                        binding,
                        seal,
                        context,
                        foreign_evidence,
                        policy_evidence=foreign_policy,
                        lease=lease,
                    )
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints):
                self.assertEqual(
                    evaluate_gates(repository, binding, seal, context, policy_evidence=foreign_policy, lease=lease).outcome,
                    GateOutcome.BLOCKED,
                )
                with self.assertRaises(GateError):
                    transition_ready_for_owner(
                        repository,
                        binding,
                        seal,
                        context,
                        evidence_fingerprint="7" * 64,
                        policy_evidence=foreign_policy,
                        lease=lease,
                    )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute("SELECT state FROM tasks WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    ("diff-review",),
                )
                self.assertEqual(
                    connection.execute("SELECT candidate_sha FROM candidate_seals WHERE task_id = ?", (foreign.task_id,)).fetchone(),
                    (seal.candidate_sha,),
                )
            finally:
                connection.close()

    def test_every_na_gate_with_an_unresolved_follow_up_cannot_complete_final_transition(self) -> None:
        for requirement in (item for item in GATE_REGISTRY if item.permits_phase_two_local_na):
            with self.subTest(gate=requirement.key), tempfile.TemporaryDirectory() as temporary:
                repository, _, binding, seal, context, lease, fingerprints = self.complete_persisted_pass(Path(temporary))
                policy_evidence = self.policy_evidence(context)
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute(
                        "UPDATE gate_evidence SET follow_ups = ? WHERE task_id = ? AND candidate_sha = ? AND gate_key = ?",
                        (
                            f'[{{"identifier":"{requirement.key.value}-follow-up","resolution_fingerprint":null,"resolved":false}}]',
                            binding.task_id,
                            seal.candidate_sha,
                            requirement.key.value,
                        ),
                    )
                    connection.commit()
                finally:
                    connection.close()
                with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints), mock.patch("roundwright.git_identity.candidate_evidence", return_value=fingerprints):
                    with self.assertRaises(StateError):
                        transition_ready_for_owner(repository, binding, seal, context, evidence_fingerprint="7" * 64, policy_evidence=policy_evidence, lease=lease)

    def test_receipt_context_is_rebound_for_each_candidate_and_rejects_stale_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, binding, seal_a, context_a, lease, _ = self.complete_persisted_pass(Path(temporary))

            def reseal(candidate_sha: str) -> CandidateSeal:
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute("UPDATE candidate_seals SET candidate_sha = ? WHERE task_id = ?", (candidate_sha, identity.task_id))
                    connection.execute("DELETE FROM candidate_evidence WHERE task_id = ?", (identity.task_id,))
                    connection.execute("DELETE FROM gate_evidence WHERE task_id = ?", (identity.task_id,))
                    connection.execute("DELETE FROM gate_contexts WHERE task_id = ?", (identity.task_id,))
                    connection.commit()
                finally:
                    connection.close()
                return CandidateSeal(identity.task_id, identity.base_sha, candidate_sha, lease.state_identity)

            def record_complete(candidate_seal: CandidateSeal, context: GateContext) -> tuple[str, ...]:
                entries = []
                for number, requirement in enumerate(GATE_REGISTRY, 1):
                    outcome = EvidenceOutcome.NOT_APPLICABLE if requirement.permits_phase_two_local_na else EvidenceOutcome.PASS
                    entries.append(
                        GateEvidence(
                            identity.task_id,
                            candidate_seal.candidate_sha,
                            requirement.key,
                            outcome,
                            "validator",
                            number,
                            f"{number + 32:064x}",
                            "isolated local boundary" if outcome is EvidenceOutcome.NOT_APPLICABLE else None,
                            "no external adapter in Phase 2" if outcome is EvidenceOutcome.NOT_APPLICABLE else None,
                        )
                    )
                with mock.patch("roundwright.gates.bind_candidate_evidence"):
                    for entry in entries:
                        record_gate_evidence(repository, binding, candidate_seal, context, entry, policy_evidence=self.policy_evidence(context), lease=lease)
                return tuple(entry.evidence_fingerprint for entry in entries)

            seal_b = reseal("e" * 40)
            context_b = GateContext(identity.task_id, seal_b.candidate_sha, 1, True, context_a.policy_digest, "f" * 64)
            stale_receipt_b = GateContext(identity.task_id, seal_b.candidate_sha, 1, True, context_a.policy_digest, context_a.receipt_fingerprint)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=()):
                self.assertEqual(evaluate_gates(repository, binding, seal_b, stale_receipt_b, policy_evidence=self.policy_evidence(stale_receipt_b, status=ReceiptStatus.CONSUMED), lease=lease).outcome, GateOutcome.BLOCKED)
            fingerprints_b = record_complete(seal_b, context_b)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=fingerprints_b):
                self.assertEqual(evaluate_gates(repository, binding, seal_b, stale_receipt_b, policy_evidence=self.policy_evidence(stale_receipt_b, status=ReceiptStatus.CONSUMED), lease=lease).outcome, GateOutcome.BLOCKED)
                self.assertEqual(evaluate_gates(repository, binding, seal_b, context_b, policy_evidence=self.policy_evidence(context_b), lease=lease).outcome, GateOutcome.PASS)

            restored_a = reseal(seal_a.candidate_sha)
            restored_fingerprints = record_complete(restored_a, context_a)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=restored_fingerprints):
                self.assertEqual(evaluate_gates(repository, binding, restored_a, context_a, policy_evidence=self.policy_evidence(context_a), lease=lease).outcome, GateOutcome.PASS)


if __name__ == "__main__":
    unittest.main()
