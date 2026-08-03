"""Hermetic contracts for the Phase 2 immutable implementation candidate."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.candidate_review import (
    CandidateReviewError, CandidateVerification, DiffReviewOutput, DiffReviewVerdict,
    VerificationKind, VerificationOutcome, begin_implementation, dispatch_diff_review,
    read_diff_review, record_candidate_verification, record_diff_review, record_implementation_candidate,
    recover_diff_review,
)
from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import CandidateSeal, GitIdentityError, WorktreeBinding, acquire_transition_lease, provision_worktree
from roundwright.plan_review import PlanReviewOutput, PlanReviewVerdict, dispatch_plan_review, record_plan_review
from roundwright.provider_recovery import AttemptState, RecoveryAction, RecoveryContext, read_attempt, recover_attempt
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize, task_projection
from roundwright.worker_planning import (
    PlanReviewReceipt, PlanningInput, WorkerPlan, WorkerPlanOutput,
    accept_plan_review_and_begin_implementation, begin_planning, dispatch_plan,
    record_plan, submit_plan_for_review,
)


class CandidateReviewTests(unittest.TestCase):
    def git(self, directory: Path, *arguments: str) -> str:
        return subprocess.run(["git", "-C", str(directory), *arguments], check=True, text=True, capture_output=True).stdout.strip()

    def repository(self, root: Path) -> RepositoryIdentity:
        remote = root.parent / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, text=True, capture_output=True)
        subprocess.run(["git", "init", "-b", "main", str(root)], check=True, text=True, capture_output=True)
        self.git(root, "config", "user.email", "test@example.invalid")
        self.git(root, "config", "user.name", "Roundwright Tests")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "test: base")
        self.git(root, "remote", "add", "origin", str(remote))
        self.git(root, "push", "-u", "origin", "main")
        return RepositoryIdentity.from_root(root)

    def ready_task(self, root: Path, *, commit: bool = True):
        repository = self.repository(root)
        initialize(repository)
        base = self.git(root, "rev-parse", "HEAD")
        worktree = root.parent / "worker"
        identity = TaskIdentity("task-25", "source-25", "ythdelmar68/roundwright", "codex/issue-25", str(worktree), base)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="test-owner", ttl_seconds=120)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, hashlib.sha256(b"source-25").hexdigest()),), lease=lease)
        begin_planning(repository, identity, evidence_fingerprint="a" * 64, lease=lease)
        context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="b" * 64, deployment_fingerprint="c" * 64)
        now = int(time.time())
        input_value = PlanningInput("Implement candidate", (), ("Commit locally",), (), ("Unit tests",), (), ())
        plan = WorkerPlan("Implement candidate", (), (), ("Commit locally",), ("Unit tests",), (), (), ())
        dispatch = dispatch_plan(repository, identity, context, input_value, plan_attempt_id="plan-25", provider_attempt_id="worker-plan", worker_thread_identity="worker-thread-25", external_turn_identity="worker-plan-turn", process_lease_id="plan-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        persisted = record_plan(repository, identity, context, plan_attempt_id=dispatch.plan_attempt_id, output=WorkerPlanOutput("plan-25", "worker-plan", "worker-thread-25", "worker-plan-turn", input_value.digest, dispatch.source_digest, plan), completion_evidence_fingerprint="e" * 64, lease=lease, now=now)
        submit_plan_for_review(repository, identity, plan_attempt_id="plan-25", evidence_fingerprint="f" * 64, lease=lease)
        review = dispatch_plan_review(repository, identity, context, review_attempt_id="plan-review-25", provider_attempt_id="plan-supervisor", supervisor_session_identity="plan-session-25", external_turn_identity="plan-review-turn", plan_attempt_id="plan-25", process_lease_id="review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        record_plan_review(repository, identity, context, review_attempt_id=review.review_attempt_id, output=PlanReviewOutput(review.review_attempt_id, review.provider_attempt_id, review.supervisor_session_identity, review.external_turn_identity, review.plan_attempt_id, review.source_digest, review.plan_digest, PlanReviewVerdict.PASS, (), (), (), ()), completion_evidence_fingerprint="1" * 64, lease=lease, now=now)
        accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-25", receipt=PlanReviewReceipt("plan-review-25", persisted.content_digest, True), evidence_fingerprint="2" * 64, lease=lease)
        binding = provision_worktree(repository, identity, default_branch="main", worktree=worktree, lease=lease)
        if commit:
            (worktree / "candidate.txt").write_text("candidate\n", encoding="utf-8")
            self.git(worktree, "add", "candidate.txt")
            self.git(worktree, "commit", "-m", "feat(candidate): seal local implementation")
        return repository, identity, lease, context, binding, now

    def implement(self, values):
        repository, identity, lease, context, binding, now = values
        dispatch = begin_implementation(repository, identity, context, implementation_attempt_id="implementation-25", provider_attempt_id="worker-implementation", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", external_turn_identity="implementation-turn", process_lease_id="implementation-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        seal = record_implementation_candidate(repository, identity, context, binding, implementation_attempt_id=dispatch.implementation_attempt_id, completion_evidence_fingerprint="3" * 64, lease=lease, now=now)
        return dispatch, seal

    def review_context(self, identity, initial_context, seal):
        return RecoveryContext.for_task(identity, candidate_sha=seal.candidate_sha, policy_fingerprint=initial_context.policy_fingerprint, deployment_fingerprint=initial_context.deployment_fingerprint)

    def accepted_diff_review(self, values, *, review_id="diff-accepted", provider_id="accepted-supervisor"):
        repository, identity, lease, context, binding, now = values
        dispatch, seal = self.implement(values)
        review_context = self.review_context(identity, context, seal)
        for verification in (
            CandidateVerification(f"{review_id}-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
            CandidateVerification(f"{review_id}-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
        ):
            record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
        review = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review_id, implementation_attempt_id=dispatch.implementation_attempt_id, provider_attempt_id=provider_id, supervisor_session_identity=f"{review_id}-session", external_turn_identity=f"{review_id}-turn", message_identity=f"{review_id}-message", process_lease_id=f"{review_id}-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        result = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=DiffReviewOutput(review_id, provider_id, f"{review_id}-session", f"{review_id}-turn", f"{review_id}-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="c" * 64, lease=lease, now=now)
        self.assertTrue(result.accepted)
        return seal, review_context, review

    def test_clean_candidate_requires_test_and_build_then_binds_a_fresh_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            with self.assertRaisesRegex(CandidateReviewError, "test and build"):
                dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("targeted-tests", VerificationKind.TEST, VerificationOutcome.PASS, "4" * 64), lease=lease)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("build", VerificationKind.BUILD, VerificationOutcome.NOT_APPLICABLE, "5" * 64, "no build target"), lease=lease)
            with self.assertRaisesRegex(CandidateReviewError, "sealed candidate"):
                dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="context-drift", implementation_attempt_id="implementation-25", provider_attempt_id="context-supervisor", supervisor_session_identity="context-session", external_turn_identity="context-turn", message_identity="context-message", process_lease_id="context-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "distinct from plan review"):
                dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="plan-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            dispatch = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("later-targeted-test", VerificationKind.TEST, VerificationOutcome.PASS, "6" * 64), lease=lease)
            with self.assertRaisesRegex(CandidateReviewError, "verification evidence has changed"):
                record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-25", "diff-supervisor", "diff-session-25", "diff-turn", "diff-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="7" * 64, lease=lease, now=now)
            dispatch = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-26", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor-2", supervisor_session_identity="diff-session-26", external_turn_identity="diff-turn-2", message_identity="diff-message-2", process_lease_id="diff-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            result = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-26", "diff-supervisor-2", "diff-session-26", "diff-turn-2", "diff-message-2", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="8" * 64, lease=lease, now=now)
            self.assertTrue(result.accepted)
            self.assertEqual(result.accepted_review_identity, dispatch.diff_review_attempt_id)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.ACCEPTED)
            self.assertEqual(
                recover_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, max_attempts=1, lease=lease).next_action,
                RecoveryAction.ACCEPTED_REVIEW,
            )
            replay = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-26", "diff-supervisor-2", "diff-session-26", "diff-turn-2", "diff-message-2", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="8" * 64, lease=lease, now=now)
            self.assertEqual(replay.accepted_review_identity, dispatch.diff_review_attempt_id)
            self.assertEqual((result.base_sha, result.candidate_sha), (seal.base_sha, seal.candidate_sha))
            self.assertEqual(task_projection(repository, identity).state, "diff-review")
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("post-pass-test", VerificationKind.TEST, VerificationOutcome.PASS, "9" * 64), lease=lease)
            self.assertFalse(read_diff_review(repository, identity, dispatch.diff_review_attempt_id, binding=binding, seal=seal, context=review_context, lease=lease).accepted)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.INVALIDATED)

    def test_findings_route_to_the_same_worker_and_require_a_new_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("tests", VerificationKind.TEST, VerificationOutcome.PASS, "7" * 64),
                CandidateVerification("build", VerificationKind.BUILD, VerificationOutcome.PASS, "8" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            dispatch = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-findings", implementation_attempt_id="implementation-25", provider_attempt_id="findings-supervisor", supervisor_session_identity="findings-session", external_turn_identity="findings-turn", message_identity="findings-message", process_lease_id="findings-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            result = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-findings", "findings-supervisor", "findings-session", "findings-turn", "findings-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("repair boundary",)), completion_evidence_fingerprint="9" * 64, lease=lease, now=now)
            self.assertFalse(result.accepted)
            self.assertEqual(len(result.routed_finding_ids), 1)
            self.assertEqual(task_projection(repository, identity).state, "implementing")
            with self.assertRaisesRegex(CandidateReviewError, "accepted Worker thread"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="wrong-worker", external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "routed diff-review parent"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            repair = begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=dispatch.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=result.routed_finding_ids, external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            self.assertNotEqual(repair.input_digest, dispatch.input_digest)
            self.assertEqual(repair.repair_diff_review_id, dispatch.diff_review_attempt_id)
            self.assertEqual(repair.repair_candidate_sha, seal.candidate_sha)
            self.assertEqual(repair.routed_finding_ids, result.routed_finding_ids)
            (Path(identity.worktree) / "candidate.txt").write_text("repaired candidate\n", encoding="utf-8")
            self.git(Path(identity.worktree), "add", "candidate.txt")
            self.git(Path(identity.worktree), "commit", "-m", "fix(candidate): repair routed finding")
            repaired_seal = record_implementation_candidate(repository, identity, context, binding, implementation_attempt_id=repair.implementation_attempt_id, completion_evidence_fingerprint="a" * 64, lease=lease, now=now)
            self.assertNotEqual(repaired_seal.candidate_sha, seal.candidate_sha)
            repaired_context = self.review_context(identity, context, repaired_seal)
            for verification in (
                CandidateVerification("repair-tests", VerificationKind.TEST, VerificationOutcome.PASS, "b" * 64),
                CandidateVerification("repair-build", VerificationKind.BUILD, VerificationOutcome.PASS, "c" * 64),
            ):
                record_candidate_verification(repository, identity, binding, repaired_seal, verification, lease=lease)
            fresh = dispatch_diff_review(repository, identity, repaired_context, binding, repaired_seal, diff_review_attempt_id="diff-repaired", implementation_attempt_id=repair.implementation_attempt_id, provider_attempt_id="repair-supervisor", supervisor_session_identity="repair-session", external_turn_identity="repair-review-turn", message_identity="repair-message", process_lease_id="repair-review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            second_findings = record_diff_review(repository, identity, repaired_context, binding, repaired_seal, diff_review_attempt_id=fresh.diff_review_attempt_id, output=DiffReviewOutput("diff-repaired", "repair-supervisor", "repair-session", "repair-review-turn", "repair-message", repaired_seal.base_sha, repaired_seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("second repair boundary",)), completion_evidence_fingerprint="d" * 64, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "routed diff-review parent"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-26", provider_attempt_id="repair-worker-2", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", external_turn_identity="repair-turn-2", process_lease_id="repair-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "latest outstanding"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-26", provider_attempt_id="repair-worker-2", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=dispatch.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=result.routed_finding_ids, external_turn_identity="repair-turn-2", process_lease_id="repair-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "latest outstanding"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-26", provider_attempt_id="repair-worker-2", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=fresh.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=second_findings.routed_finding_ids, external_turn_identity="repair-turn-2", process_lease_id="repair-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            repair_two = begin_implementation(repository, identity, context, implementation_attempt_id="repair-26", provider_attempt_id="repair-worker-2", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=fresh.diff_review_attempt_id, repair_candidate_sha=repaired_seal.candidate_sha, routed_finding_ids=second_findings.routed_finding_ids, external_turn_identity="repair-turn-2", process_lease_id="repair-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            candidate = Path(identity.worktree) / "candidate.txt"
            candidate.write_text("second repaired candidate\n", encoding="utf-8")
            self.git(Path(identity.worktree), "add", "candidate.txt")
            self.git(Path(identity.worktree), "commit", "-m", "fix(candidate): repair latest routed finding")
            final_seal = record_implementation_candidate(repository, identity, context, binding, implementation_attempt_id=repair_two.implementation_attempt_id, completion_evidence_fingerprint="e" * 64, lease=lease, now=now)
            final_context = self.review_context(identity, context, final_seal)
            for verification in (
                CandidateVerification("final-repair-tests", VerificationKind.TEST, VerificationOutcome.PASS, "f" * 64),
                CandidateVerification("final-repair-build", VerificationKind.BUILD, VerificationOutcome.PASS, "0" * 64),
            ):
                record_candidate_verification(repository, identity, binding, final_seal, verification, lease=lease)
            final_review = dispatch_diff_review(repository, identity, final_context, binding, final_seal, diff_review_attempt_id="diff-final", implementation_attempt_id=repair_two.implementation_attempt_id, provider_attempt_id="final-supervisor", supervisor_session_identity="final-session", external_turn_identity="final-review-turn", message_identity="final-message", process_lease_id="final-review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            accepted = record_diff_review(repository, identity, final_context, binding, final_seal, diff_review_attempt_id=final_review.diff_review_attempt_id, output=DiffReviewOutput("diff-final", "final-supervisor", "final-session", "final-review-turn", "final-message", final_seal.base_sha, final_seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="1" * 64, lease=lease, now=now)
            self.assertTrue(accepted.accepted)
            self.assertNotEqual(fresh.supervisor_session_identity, dispatch.supervisor_session_identity)

    def test_dirty_or_moved_candidate_stales_both_accepted_review_layers(self):
        for mutation in ("dirty", "moved"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                values = self.ready_task(Path(temporary) / "repository")
                repository, identity, lease, context, binding, now = values
                seal, review_context, review = self.accepted_diff_review(values, review_id=f"diff-{mutation}", provider_id=f"supervisor-{mutation}")
                candidate = Path(identity.worktree) / "candidate.txt"
                if mutation == "dirty":
                    (Path(identity.worktree) / "untracked.txt").write_text("dirty\n", encoding="utf-8")
                    expected = "dirty"
                else:
                    candidate.write_text("moved candidate\n", encoding="utf-8")
                    self.git(Path(identity.worktree), "add", "candidate.txt")
                    self.git(Path(identity.worktree), "commit", "-m", "test: move candidate")
                    expected = "head moved"
                with self.assertRaisesRegex(GitIdentityError, expected):
                    recover_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, max_attempts=1, lease=lease)
                self.assertEqual(read_attempt(repository, identity, review.provider_attempt_id).state, AttemptState.INVALIDATED)
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertEqual(connection.execute("SELECT state, accepted_review_identity FROM diff_review_attempts WHERE diff_review_attempt_id = ?", (review.diff_review_attempt_id,)).fetchone(), ("recorded", None))
                    self.assertIsNone(connection.execute("SELECT 1 FROM accepted_provider_reviews WHERE attempt_id = ?", (review.provider_attempt_id,)).fetchone())
                finally:
                    connection.close()

    def test_preaccepted_provider_output_must_match_structured_review_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            seal, review_context, review = self.accepted_diff_review(values, review_id="diff-output", provider_id="supervisor-output")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_completion_outputs SET output_fingerprint = ? WHERE attempt_id = ?", ("f" * 64, review.provider_attempt_id))
                connection.commit()
            finally:
                connection.close()
            recovered = recover_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, max_attempts=1, lease=lease)
            self.assertEqual(recovered.next_action, RecoveryAction.FRESH_SUPERVISOR_SESSION)
            self.assertEqual(read_attempt(repository, identity, review.provider_attempt_id).state, AttemptState.INVALIDATED)
            self.assertFalse(read_diff_review(repository, identity, review.diff_review_attempt_id, binding=binding, seal=seal, context=review_context, lease=lease).accepted)
            self.assertEqual(
                recover_attempt(repository, identity, review_context, attempt_id=review.provider_attempt_id, max_attempts=1, lease=lease).next_action,
                RecoveryAction.FRESH_SUPERVISOR_SESSION,
            )

    def test_generic_recovery_cannot_reuse_an_accepted_diff_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            seal, review_context, review = self.accepted_diff_review(values, review_id="diff-generic", provider_id="supervisor-generic")
            recovery = recover_attempt(repository, identity, review_context, attempt_id=review.provider_attempt_id, max_attempts=1, lease=lease)
            self.assertEqual(recovery.next_action, RecoveryAction.FRESH_SUPERVISOR_SESSION)
            self.assertEqual(read_attempt(repository, identity, review.provider_attempt_id).state, AttemptState.INVALIDATED)
            self.assertFalse(read_diff_review(repository, identity, review.diff_review_attempt_id, binding=binding, seal=seal, context=review_context, lease=lease).accepted)

    def test_generic_recovery_has_no_candidate_acceptance_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            seal, review_context, review = self.accepted_diff_review(values, review_id="diff-no-bypass", provider_id="supervisor-no-bypass")
            with self.assertRaises(TypeError):
                recover_attempt(repository, identity, review_context, attempt_id=review.provider_attempt_id, max_attempts=1, lease=lease, _allow_accepted_diff_review=True)
            (Path(identity.worktree) / "untracked.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(GitIdentityError, "dirty"):
                recover_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, max_attempts=1, lease=lease)
            self.assertEqual(read_attempt(repository, identity, review.provider_attempt_id).state, AttemptState.INVALIDATED)

    def test_base_head_cannot_authorize_a_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository", commit=False)
            repository, identity, lease, context, binding, now = values
            dispatch = begin_implementation(repository, identity, context, implementation_attempt_id="implementation-base", provider_attempt_id="worker-base", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", external_turn_identity="base-turn", process_lease_id="base-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaisesRegex(CandidateReviewError, "new local commit"):
                record_implementation_candidate(repository, identity, context, binding, implementation_attempt_id=dispatch.implementation_attempt_id, completion_evidence_fingerprint="a" * 64, lease=lease, now=now)
            self.assertEqual(task_projection(repository, identity).state, "implementing")

    def test_second_clean_task_at_the_same_sha_cannot_alias_candidate_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            other_worktree = Path(identity.worktree).parent / "other-worker"
            other = TaskIdentity("task-26", "source-26", identity.repository_id, "codex/issue-26", str(other_worktree), identity.base_sha)
            admit_task(repository, other, (SourceSnapshot(other.source_id, other.repository_id, hashlib.sha256(b"source-26").hexdigest()),), lease=lease)
            self.git(repository.root, "branch", other.branch, seal.candidate_sha)
            self.git(repository.root, "worktree", "add", str(other_worktree), other.branch)
            other_binding = WorktreeBinding(other.task_id, other.repository_id, other.branch, other_worktree, other.base_sha, binding.state_identity)
            other_seal = CandidateSeal(other.task_id, other.base_sha, seal.candidate_sha, binding.state_identity)
            with self.assertRaisesRegex(CandidateReviewError, "worktree binding does not match"):
                record_candidate_verification(repository, identity, other_binding, other_seal, CandidateVerification("other-test", VerificationKind.TEST, VerificationOutcome.PASS, "b" * 64), lease=lease)


if __name__ == "__main__":
    unittest.main()
