"""Hermetic contracts for the Phase 2 immutable implementation candidate."""

from __future__ import annotations

import hashlib
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
    record_candidate_verification, record_diff_review, record_implementation_candidate,
)
from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import CandidateSeal, WorktreeBinding, acquire_transition_lease, provision_worktree
from roundwright.plan_review import PlanReviewOutput, PlanReviewVerdict, dispatch_plan_review, record_plan_review
from roundwright.provider_recovery import RecoveryContext
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize, task_projection
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

    def test_clean_candidate_requires_test_and_build_then_binds_a_fresh_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            with self.assertRaisesRegex(CandidateReviewError, "test and build"):
                dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("targeted-tests", VerificationKind.TEST, VerificationOutcome.PASS, "4" * 64), lease=lease)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("build", VerificationKind.BUILD, VerificationOutcome.NOT_APPLICABLE, "5" * 64, "no build target"), lease=lease)
            with self.assertRaisesRegex(CandidateReviewError, "distinct from plan review"):
                dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="plan-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            dispatch = dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="diff-25", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-session-25", external_turn_identity="diff-turn", message_identity="diff-message", process_lease_id="diff-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            record_candidate_verification(repository, identity, binding, seal, CandidateVerification("later-targeted-test", VerificationKind.TEST, VerificationOutcome.PASS, "6" * 64), lease=lease)
            with self.assertRaisesRegex(CandidateReviewError, "verification evidence has changed"):
                record_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-25", "diff-supervisor", "diff-session-25", "diff-turn", "diff-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="7" * 64, lease=lease, now=now)
            dispatch = dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="diff-26", implementation_attempt_id="implementation-25", provider_attempt_id="diff-supervisor-2", supervisor_session_identity="diff-session-26", external_turn_identity="diff-turn-2", message_identity="diff-message-2", process_lease_id="diff-lease-2", process_lease_expires_at=now + 60, lease=lease, now=now)
            result = record_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-26", "diff-supervisor-2", "diff-session-26", "diff-turn-2", "diff-message-2", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS), completion_evidence_fingerprint="8" * 64, lease=lease, now=now)
            self.assertTrue(result.accepted)
            self.assertEqual((result.base_sha, result.candidate_sha), (seal.base_sha, seal.candidate_sha))
            self.assertEqual(task_projection(repository, identity).state, "diff-review")

    def test_findings_route_to_the_same_worker_and_require_a_new_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            for verification in (
                CandidateVerification("tests", VerificationKind.TEST, VerificationOutcome.PASS, "7" * 64),
                CandidateVerification("build", VerificationKind.BUILD, VerificationOutcome.PASS, "8" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            dispatch = dispatch_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id="diff-findings", implementation_attempt_id="implementation-25", provider_attempt_id="findings-supervisor", supervisor_session_identity="findings-session", external_turn_identity="findings-turn", message_identity="findings-message", process_lease_id="findings-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            result = record_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id, output=DiffReviewOutput("diff-findings", "findings-supervisor", "findings-session", "findings-turn", "findings-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("repair boundary",)), completion_evidence_fingerprint="9" * 64, lease=lease, now=now)
            self.assertFalse(result.accepted)
            self.assertEqual(len(result.routed_finding_ids), 1)
            self.assertEqual(task_projection(repository, identity).state, "implementing")
            with self.assertRaisesRegex(CandidateReviewError, "accepted Worker thread"):
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="wrong-worker", external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now)

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
