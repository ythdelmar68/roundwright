"""Hermetic contracts for the Phase 2 immutable implementation candidate."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.candidate_review import (
    CandidateReviewError, CandidateVerification, DiffReviewOutput, DiffReviewVerdict, ImplementationDispatch,
    VerificationKind, VerificationOutcome, begin_implementation as _begin_implementation, dispatch_diff_review as _native_dispatch_diff_review,
    finalize_review_limit_repair, read_diff_review, record_candidate_verification, record_diff_review, record_implementation_candidate,
    recover_diff_review,
)
import roundwright.candidate_review as candidate_review
from roundwright.configuration import RepositoryIdentity
from roundwright.gates import _valid_review_limit_finalization
from roundwright.runtime_binding import RuntimeBinding
from roundwright.dependency_policy import BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent, DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition, PolicyTransitionKind, TrustedDependencyAdmission, VersionRange
from roundwright.git_identity import CandidateSeal, GitEntrypointControl, GitIdentityError, WorktreeBinding, acquire_transition_lease, provision_worktree
from roundwright.plan_review import PlanReviewOutput, PlanReviewVerdict, dispatch_plan_review as _native_dispatch_plan_review, record_plan_review
from roundwright.provider_recovery import AttemptState, ProviderRecoveryError, ProviderRole, RecoveryAction, RecoveryContext, prepare_attempt, read_attempt, recover_attempt
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize, task_projection
from roundwright.worker_planning import (
    PlanReviewReceipt, PlanningInput, ProviderDispatchControl, WorkerPlan, WorkerPlanOutput,
    accept_plan_review_and_begin_implementation, begin_planning, dispatch_plan as _native_dispatch_plan,
    record_plan, submit_plan_for_review,
)
from tests.provider_health_fixture import provider_context, runtime_binding as health_runtime_binding


def _dispatch_control(identity, context, now, candidate=None):
    digest=lambda value: "sha256:" + value * 64; binding=CandidateBinding(identity.repository_id, identity.task_id, candidate or context.candidate_sha or identity.base_sha); components=(ComponentPolicy(DependencyComponent.PACKAGE,"roundwright",VersionRange("0.0.0","3.0.0"),"pypi/roundwright",digest("1"),digest("2")),ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME,"codex-sdk",VersionRange("1.0.0","2.0.0"),"registry/codex-sdk",digest("3"),digest("4")),ComponentPolicy(DependencyComponent.GITHUB_CLI,"gh",VersionRange("2.0.0","3.0.0"),"github/gh",digest("5"),digest("6")),ComponentPolicy(DependencyComponent.BUILD_BACKEND,"setuptools",VersionRange("69.0.0","70.0.0"),"pypi/setuptools",digest("7"),digest("8"))); policy=DependencyPolicy(binding,digest("9"),now,60,components,PolicyTransition(PolicyTransitionKind.BOOTSTRAP)); receipt=BootstrapPolicyReceipt.create(policy,reviewer_identity=digest("a"),authority_digest=digest("b")); policy=replace(policy,transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP,receipt)); observations=tuple(ObservedDependency(binding,item.component,item.identifier,item.versions.minimum,item.source_identity,item.artifact_digest,item.executable_digest,now,policy.policy_digest) for item in components); return binding,ProviderDispatchControl(binding,DependencyExecutionControl(policy,observations,TrustedDependencyAdmission(binding,policy.core_fingerprint,receipt.receipt_digest,digest("a"),digest("b"))),now)

def dispatch_plan(repository, identity, context, *args, **kwargs):
    binding, control = _dispatch_control(identity, context, kwargs["now"]); kwargs.update(binding=binding, control=control)
    return _native_dispatch_plan(repository, identity, provider_context(context, identity, ProviderRole.PLANNING), *args, **kwargs)


def dispatch_plan_review(repository, identity, context, *args, **kwargs):
    return _native_dispatch_plan_review(repository, identity, provider_context(context, identity, ProviderRole.SUPERVISOR), *args, **kwargs)


def begin_implementation(repository, identity, context, *args, **kwargs):
    binding, control = _dispatch_control(identity, context, kwargs["now"], kwargs.get("repair_candidate_sha")); kwargs.update(binding=binding, control=control)
    return _begin_implementation(repository, identity, provider_context(context, identity, ProviderRole.WORKER), *args, **kwargs)


def _dispatch_diff_review(repository, identity, context, binding, seal, **kwargs):
    selected = kwargs.get("selected_profile_identity")
    if selected not in context.runtime_binding.supervisor_profile_identities:
        selected = None
    return _native_dispatch_diff_review(
        repository, identity, provider_context(context, identity, ProviderRole.SUPERVISOR, selected_profile_identity=selected), binding, seal, **kwargs
    )


def dispatch_diff_review(repository, identity, context, binding, seal, **kwargs):
    """Fixture boundary: every existing scenario names the pinned primary attempt."""

    kwargs.setdefault("selected_profile_identity", context.runtime_binding.supervisor_profile_identities[0])
    kwargs.setdefault("within_round_attempt", 1)
    kwargs.setdefault("review_round", 4)
    return _dispatch_diff_review(repository, identity, context, binding, seal, **kwargs)


class CandidateReviewTests(unittest.TestCase):
    def runtime_binding(self, supervisor_count: int = 3, *, include_policy: bool = True) -> RuntimeBinding:
        values = "cdefgh"
        policy_digest = candidate_review._digest({"complete_rounds": 3, "max_rounds": 10, "max_supervisor_attempts_per_round": supervisor_count, "on_final_findings": "worker-final-repair-then-merge"})
        return health_runtime_binding(
            supervisor_count,
            complete_rounds=3 if include_policy else None,
            max_rounds=10 if include_policy else None,
            final_policy="worker-final-repair-then-merge" if include_policy else None,
            policy_digest=policy_digest if include_policy else None,
        )

    def test_sealed_context_projection_excludes_only_per_attempt_health_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, _, context, _, _ = values
            dispatch, seal = self.implement(values)
            authorized = provider_context(self.review_context(identity, context, seal), identity, ProviderRole.SUPERVISOR)
            candidate_review._require_diff_review_context(repository, identity, authorized, seal, dispatch.implementation_attempt_id)
            replacement = "f" * 64
            for field, value in (
                ("task_id", "other-task"), ("repository_fingerprint", replacement),
                ("worktree_fingerprint", replacement), ("branch_fingerprint", replacement),
                ("base_fingerprint", replacement), ("candidate_fingerprint", replacement),
                ("candidate_sha", "c" * 40), ("policy_fingerprint", replacement),
                ("deployment_fingerprint", replacement), ("runtime_binding", self.runtime_binding(2)),
            ):
                with self.subTest(field=field):
                    with self.assertRaisesRegex(CandidateReviewError, "recovery context"):
                        candidate_review._require_diff_review_context(repository, identity, replace(authorized, **{field: value}), seal, dispatch.implementation_attempt_id)

    def git(self, directory: Path, *arguments: str) -> str:
        return subprocess.run(["git", "-C", str(directory), *arguments], check=True, text=True, capture_output=True).stdout.strip()

    def git_control(self, identity: TaskIdentity, *, now: int) -> GitEntrypointControl:
        digest = lambda value: "sha256:" + value * 64
        binding = CandidateBinding(identity.repository_id, identity.task_id, identity.base_sha)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-scm/git", digest("3"), digest("4")),
        )
        policy = DependencyPolicy(binding, digest("5"), now, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("6"), authority_digest=digest("7"))
        policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(
            ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, now, policy.policy_digest)
            for item in components
        )
        admission = TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, digest("6"), digest("7"))
        return GitEntrypointControl(binding, DependencyExecutionControl(policy, observations, admission), now)

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

    def ready_task(self, root: Path, *, commit: bool = True, supervisor_count: int = 3, include_policy: bool = True):
        repository = self.repository(root)
        initialize(repository)
        base = self.git(root, "rev-parse", "HEAD")
        worktree = root.parent / "worker"
        identity = TaskIdentity("task-25", "source-25", "ythdelmar68/roundwright", "codex/issue-25", str(worktree), base)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="test-owner", ttl_seconds=120)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, hashlib.sha256(b"source-25").hexdigest()),), lease=lease)
        begin_planning(repository, identity, evidence_fingerprint="a" * 64, lease=lease)
        context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="b" * 64, deployment_fingerprint="c" * 64, runtime_binding=self.runtime_binding(supervisor_count, include_policy=include_policy))
        now = int(time.time())
        input_value = PlanningInput("Implement candidate", (), ("Commit locally",), (), ("Unit tests",), (), ())
        plan = WorkerPlan("Implement candidate", (), (), ("Commit locally",), ("Unit tests",), (), (), ())
        dispatch = dispatch_plan(repository, identity, context, input_value, plan_attempt_id="plan-25", provider_attempt_id="worker-plan", worker_thread_identity="worker-thread-25", external_turn_identity="worker-plan-turn", process_lease_id="plan-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        persisted = record_plan(repository, identity, context, plan_attempt_id=dispatch.plan_attempt_id, output=WorkerPlanOutput("plan-25", "worker-plan", "worker-thread-25", "worker-plan-turn", input_value.digest, dispatch.source_digest, plan), completion_evidence_fingerprint="e" * 64, lease=lease, now=now)
        submit_plan_for_review(repository, identity, plan_attempt_id="plan-25", evidence_fingerprint="f" * 64, lease=lease)
        review = dispatch_plan_review(repository, identity, context, review_attempt_id="plan-review-25", provider_attempt_id="plan-supervisor", supervisor_session_identity="plan-session-25", external_turn_identity="plan-review-turn", plan_attempt_id="plan-25", process_lease_id="review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        record_plan_review(repository, identity, context, review_attempt_id=review.review_attempt_id, output=PlanReviewOutput(review.review_attempt_id, review.provider_attempt_id, review.supervisor_session_identity, review.external_turn_identity, review.plan_attempt_id, review.source_digest, review.plan_digest, PlanReviewVerdict.PASS, (), (), (), ()), completion_evidence_fingerprint="1" * 64, lease=lease, now=now)
        accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-25", receipt=PlanReviewReceipt("plan-review-25", persisted.content_digest, True), evidence_fingerprint="2" * 64, lease=lease)
        binding = provision_worktree(repository, identity, default_branch="main", worktree=worktree, control=self.git_control(identity, now=now), lease=lease)
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
        return RecoveryContext.for_task(identity, candidate_sha=seal.candidate_sha, policy_fingerprint=initial_context.policy_fingerprint, deployment_fingerprint=initial_context.deployment_fingerprint, runtime_binding=initial_context.runtime_binding)

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

    def final_review_limit_repair(self, root: Path):
        """Produce the one routed FINDINGS repair through the public orchestration APIs."""

        values = self.ready_task(root)
        repository, identity, lease, context, binding, now = values
        initial, initial_seal = self.implement(values)
        review_context = self.review_context(identity, context, initial_seal)
        for verification in (
            CandidateVerification("final-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
            CandidateVerification("final-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
        ):
            record_candidate_verification(repository, identity, binding, initial_seal, verification, lease=lease)
        review = dispatch_diff_review(
            repository, identity, review_context, binding, initial_seal,
            diff_review_attempt_id="final-findings", implementation_attempt_id=initial.implementation_attempt_id,
            provider_attempt_id="final-supervisor", supervisor_session_identity="final-supervisor-session",
            external_turn_identity="final-supervisor-turn", message_identity="final-supervisor-message",
            process_lease_id="final-supervisor-lease", process_lease_expires_at=now + 60, review_round=10, lease=lease, now=now,
        )
        findings = DiffReviewOutput(
            review.diff_review_attempt_id, "final-supervisor", "final-supervisor-session",
            "final-supervisor-turn", "final-supervisor-message", initial_seal.base_sha,
            initial_seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("final repair required",),
        )
        routed = record_diff_review(
            repository, identity, review_context, binding, initial_seal,
            diff_review_attempt_id=review.diff_review_attempt_id, output=findings,
            completion_evidence_fingerprint="c" * 64, lease=lease, now=now,
        )
        (binding.worktree / "final-repair.txt").write_text("repair\n", encoding="utf-8")
        self.git(binding.worktree, "add", "final-repair.txt")
        self.git(binding.worktree, "commit", "-m", "fix(candidate): final findings repair")
        repair = begin_implementation(
            repository, identity, context, implementation_attempt_id="final-repair", provider_attempt_id="final-worker",
            plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25",
            repair_diff_review_id=routed.diff_review_attempt_id, repair_candidate_sha=initial_seal.candidate_sha,
            routed_finding_ids=routed.routed_finding_ids, external_turn_identity="final-worker-turn",
            process_lease_id="final-worker-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
        )
        repair_seal = record_implementation_candidate(
            repository, identity, context, binding, implementation_attempt_id=repair.implementation_attempt_id,
            completion_evidence_fingerprint="d" * 64, lease=lease, now=now,
        )
        return repository, identity, lease, context, binding, now, routed.content_digest, repair_seal

    def test_diff_dispatch_requires_the_exact_within_round_profile(self):
        cases = (
            (2, 1, 0, True), (2, 2, 1, True), (2, 3, 0, False),
            (4, 1, 0, True), (4, 2, 1, True), (4, 3, 2, True), (4, 4, 3, True), (4, 5, 3, False),
            (4, 1, 1, False), (4, 2, 0, False), (4, 3, 1, False), (4, 4, 2, False),
        )
        for profile_count, ordinal, profile_index, accepted in cases:
            with self.subTest(profiles=profile_count, ordinal=ordinal, profile=profile_index), tempfile.TemporaryDirectory() as temporary:
                values = self.ready_task(Path(temporary) / "repository", supervisor_count=profile_count)
                repository, identity, lease, context, binding, now = values
                implementation, seal = self.implement(values)
                review_context = self.review_context(identity, context, seal)
                for verification in (CandidateVerification("map-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64), CandidateVerification("map-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64)):
                    record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
                arguments = dict(diff_review_attempt_id="mapping-review", implementation_attempt_id=implementation.implementation_attempt_id, provider_attempt_id="mapping-supervisor", supervisor_session_identity="mapping-session", external_turn_identity="mapping-turn", message_identity="mapping-message", process_lease_id="mapping-lease", process_lease_expires_at=now + 60, selected_profile_identity=context.runtime_binding.supervisor_profile_identities[profile_index], within_round_attempt=ordinal, review_round=4, lease=lease, now=now)
                if not accepted:
                    with self.assertRaises(CandidateReviewError):
                        _dispatch_diff_review(repository, identity, review_context, binding, seal, **arguments)
                    continue
                dispatch = _dispatch_diff_review(repository, identity, review_context, binding, seal, **arguments)
                self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).selected_profile_identity, arguments["selected_profile_identity"])
                self.assertEqual((dispatch.within_round_attempt, dispatch.selected_profile_identity), (ordinal, arguments["selected_profile_identity"]))
                self.assertEqual(candidate_review._read_diff_dispatch(repository, identity, dispatch.diff_review_attempt_id), dispatch)
                for column, replacement in (("within_round_attempt", 0), ("selected_profile_identity", ""), ("selected_profile_identity", context.runtime_binding.supervisor_profile_identities[(ordinal % profile_count)]), ("input_digest", "f" * 64)):
                    connection = sqlite3.connect(database_path(repository))
                    try:
                        connection.execute(f"UPDATE diff_review_attempts SET {column} = ? WHERE diff_review_attempt_id = ?", (replacement, dispatch.diff_review_attempt_id))
                        connection.commit()
                    finally:
                        connection.close()
                    with self.assertRaises(CandidateReviewError):
                        candidate_review._read_diff_dispatch(repository, identity, dispatch.diff_review_attempt_id)

    def test_final_review_limit_repair_is_candidate_bound_idempotent_and_blocks_later_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, now, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
            receipt = finalize_review_limit_repair(
                repository, identity, binding, repair_seal,
                findings_fingerprint=findings, worker_repair_fingerprint="d" * 64,
                worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease,
            )
            self.assertEqual(receipt.candidate_sha, repair_seal.candidate_sha)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT disposition, candidate_sha, worker_thread_identity FROM review_limit_finalizations WHERE task_id = ?",
                        (identity.task_id,),
                    ).fetchone(),
                    ("REVIEW_LIMIT_REACHED_WORKER_FINALIZED", repair_seal.candidate_sha, "worker-thread-25"),
                )
            finally:
                connection.close()
            self.assertEqual(
                finalize_review_limit_repair(
                    repository, identity, binding, repair_seal,
                    findings_fingerprint=findings, worker_repair_fingerprint="d" * 64,
                    worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease,
                ),
                receipt,
            )
            with self.assertRaisesRegex(ProviderRecoveryError, "review limit"):
                prepare_attempt(
                    repository, identity, provider_context(context, identity, ProviderRole.SUPERVISOR), attempt_id="later-supervisor", role=ProviderRole.SUPERVISOR,
                    process_lease_id="later-supervisor-lease", process_lease_expires_at=now + 60,
                    input_fingerprint="e" * 64, lease=lease, now=now,
                )

    def test_accepted_diff_review_persists_a_profile_bound_output_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, _, _, _, _ = values
            seal, _, review = self.accepted_diff_review(values, review_id="bound-review", provider_id="bound-provider")
            raw_digest = DiffReviewOutput("bound-review", "bound-provider", "bound-review-session", "bound-review-turn", "bound-review-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS).normalized().digest
            connection = sqlite3.connect(database_path(repository))
            try:
                provider_digest = connection.execute("SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?", (review.provider_attempt_id,)).fetchone()[0]
                artifact_digest = connection.execute("SELECT content_digest FROM diff_review_artifacts WHERE diff_review_attempt_id = ?", (review.diff_review_attempt_id,)).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(provider_digest, artifact_digest)
            self.assertNotEqual(provider_digest, raw_digest)

    def test_public_diff_lifecycle_requires_sealed_authorization_and_complete_policy(self):
        def recorded_review(root):
            values = self.ready_task(root)
            repository, identity, lease, context, binding, now = values
            implementation, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("sealed-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
                CandidateVerification("sealed-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            review = dispatch_diff_review(
                repository, identity, review_context, binding, seal,
                diff_review_attempt_id="sealed-review", implementation_attempt_id=implementation.implementation_attempt_id,
                provider_attempt_id="sealed-supervisor", supervisor_session_identity="sealed-session",
                external_turn_identity="sealed-turn", message_identity="sealed-message",
                process_lease_id="sealed-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
            )
            output = DiffReviewOutput(
                review.diff_review_attempt_id, review.provider_attempt_id, review.supervisor_session_identity,
                review.external_turn_identity, review.message_identity, seal.base_sha, seal.candidate_sha,
                DiffReviewVerdict.PASS,
            )
            with patch.object(candidate_review, "_accept_diff_pass"):
                record_diff_review(
                    repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id,
                    output=output, completion_evidence_fingerprint="c" * 64, lease=lease, now=now,
                )
            return repository, identity, lease, review_context, binding, seal, now, review, output

        authorization_columns = (
            ("contract_commit", "b" * 40), ("candidate_sha", "b" * 40), ("case_id", "case-drift"),
            ("receipt_digest", "sha256:" + "e" * 64), ("selection_ordinal", 0),
            ("fresh_until", 2_000_000_001), ("health_contract_identity", "sha256:" + "e" * 64),
            ("provider_role", ProviderRole.WORKER.value), ("profile_identity", "sha256:" + "e" * 64),
        )
        for column, replacement in authorization_columns:
            with self.subTest(authorization_column=column), tempfile.TemporaryDirectory() as temporary:
                repository, identity, lease, context, binding, seal, now, review, output = recorded_review(Path(temporary) / "repository")
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute(f"UPDATE provider_attempt_health_authorizations SET {column} = ? WHERE attempt_id = ?", (replacement, review.provider_attempt_id)); connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(CandidateReviewError, "authorization"):
                    with patch.object(candidate_review, "record_completed_output"):
                        record_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=output, completion_evidence_fingerprint="c" * 64, lease=lease, now=now)

        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, seal, now, review, output = recorded_review(Path(temporary) / "repository")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_attempt_health_authorizations SET contract_commit = ? WHERE attempt_id = ?", ("b" * 40, review.provider_attempt_id))
                values = connection.execute("SELECT contract_commit, candidate_sha, case_id, receipt_digest, selection_ordinal, fresh_until, health_contract_identity, provider_role, profile_identity FROM provider_attempt_health_authorizations WHERE attempt_id = ?", (review.provider_attempt_id,)).fetchone()
                seal_value = hashlib.sha256("\x00".join((review.provider_attempt_id, *("" if value is None else str(value) for value in values))).encode()).hexdigest()
                connection.execute("UPDATE provider_attempt_health_seals SET authorization_fingerprint = ? WHERE attempt_id = ?", (seal_value, review.provider_attempt_id)); connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(CandidateReviewError, "authorization"):
                with patch.object(candidate_review, "record_completed_output"):
                    record_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=output, completion_evidence_fingerprint="c" * 64, lease=lease, now=now)

        for column, replacement in (
            ("review_complete_rounds", 2), ("review_max_rounds", 3),
            ("review_max_supervisor_attempts_per_round", 2), ("review_on_final_findings", "block"),
            ("review_policy_digest", "sha256:" + "e" * 64),
        ):
            with self.subTest(review_policy_column=column), tempfile.TemporaryDirectory() as temporary:
                values = self.ready_task(Path(temporary) / "repository")
                repository, identity, lease, _, binding, now = values
                seal, context, review = self.accepted_diff_review(values, review_id=f"policy-{column}", provider_id=f"provider-{column}")
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute(f"UPDATE accepted_provider_reviews SET {column} = ? WHERE attempt_id = ?", (replacement, review.provider_attempt_id)); connection.commit()
                finally:
                    connection.close()
                persisted = read_diff_review(repository, identity, review.diff_review_attempt_id, binding=binding, seal=seal, context=context, lease=lease)
                self.assertFalse(persisted.accepted)

        for lifecycle in ("read", "recover"):
            with self.subTest(authorization_deleted_lifecycle=lifecycle), tempfile.TemporaryDirectory() as temporary:
                values = self.ready_task(Path(temporary) / "repository")
                repository, identity, lease, _, binding, now = values
                seal, context, review = self.accepted_diff_review(values, review_id=f"deleted-{lifecycle}", provider_id=f"deleted-provider-{lifecycle}")
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute("DELETE FROM provider_attempt_health_authorizations WHERE attempt_id = ?", (review.provider_attempt_id,)); connection.commit()
                finally:
                    connection.close()
                if lifecycle == "read":
                    with self.assertRaisesRegex(CandidateReviewError, "authorization"):
                        read_diff_review(repository, identity, review.diff_review_attempt_id, binding=binding, seal=seal, context=context, lease=lease)
                else:
                    with self.assertRaisesRegex(CandidateReviewError, "authorization"):
                        recover_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, max_attempts=1, lease=lease, now=now)

    def test_diff_review_rejects_provider_profile_or_input_drift_before_findings_route(self):
        for column, replacement in (("selected_profile_identity", "sha256:" + "d" * 64), ("input_fingerprint", "f" * 64)):
            with self.subTest(column=column), tempfile.TemporaryDirectory() as temporary:
                values = self.ready_task(Path(temporary) / "repository")
                repository, identity, lease, context, binding, now = values
                implementation, seal = self.implement(values)
                review_context = self.review_context(identity, context, seal)
                for verification in (
                    CandidateVerification("provider-drift-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
                    CandidateVerification("provider-drift-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
                ):
                    record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
                dispatch = dispatch_diff_review(
                    repository, identity, review_context, binding, seal,
                    diff_review_attempt_id="provider-drift", implementation_attempt_id=implementation.implementation_attempt_id,
                    provider_attempt_id="provider-drift-supervisor", supervisor_session_identity="provider-drift-session",
                    external_turn_identity="provider-drift-turn", message_identity="provider-drift-message",
                    process_lease_id="provider-drift-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
                )
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute(f"UPDATE provider_attempts SET {column} = ? WHERE attempt_id = ?", (replacement, dispatch.provider_attempt_id))
                    connection.commit()
                finally:
                    connection.close()
                output = DiffReviewOutput(
                    dispatch.diff_review_attempt_id, dispatch.provider_attempt_id, dispatch.supervisor_session_identity,
                    dispatch.external_turn_identity, dispatch.message_identity, seal.base_sha, seal.candidate_sha,
                    DiffReviewVerdict.FINDINGS, ("provider evidence drift",),
                )
                with self.assertRaisesRegex(CandidateReviewError, "provider attempt"):
                    record_diff_review(
                        repository, identity, review_context, binding, seal, diff_review_attempt_id=dispatch.diff_review_attempt_id,
                        output=output, completion_evidence_fingerprint="c" * 64, lease=lease, now=now,
                    )
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertIsNone(
                        connection.execute(
                            "SELECT 1 FROM diff_review_routes WHERE diff_review_attempt_id = ?", (dispatch.diff_review_attempt_id,)
                        ).fetchone()
                    )
                finally:
                    connection.close()

    def test_final_review_limit_repair_rejects_wrong_bound_identity(self):
        cases = (
            ("wrong Worker", {"worker_thread_identity": "other-worker"}),
            ("wrong candidate", {"seal_candidate": "f" * 40}),
            ("wrong findings", {"findings_fingerprint": "e" * 64}),
            ("wrong repair", {"worker_repair_fingerprint": "e" * 64}),
        )
        for label, replacement in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
                seal = repair_seal if "seal_candidate" not in replacement else CandidateSeal(
                    repair_seal.task_id, repair_seal.base_sha, replacement["seal_candidate"], repair_seal.state_identity,
                )
                arguments = {
                    "findings_fingerprint": findings,
                    "worker_repair_fingerprint": "d" * 64, "worker_thread_identity": "worker-thread-25", "runtime_binding": context.runtime_binding,
                }
                arguments.update({key: value for key, value in replacement.items() if key != "seal_candidate"})
                with self.assertRaises(Exception):
                    finalize_review_limit_repair(repository, identity, binding, seal, lease=lease, **arguments)

    def test_final_review_limit_repair_rejects_a_conflicting_second_finalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
            finalize_review_limit_repair(
                repository, identity, binding, repair_seal,
                findings_fingerprint=findings, worker_repair_fingerprint="d" * 64,
                worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease,
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE review_limit_finalizations SET receipt_fingerprint = ? WHERE task_id = ?", ("e" * 64, identity.task_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(Exception, "already been consumed"):
                finalize_review_limit_repair(
                    repository, identity, binding, repair_seal,
                    findings_fingerprint=findings, worker_repair_fingerprint="d" * 64,
                    worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease,
                )

    def test_final_review_limit_repair_rejects_obsolete_caller_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
            with self.assertRaises(TypeError):
                finalize_review_limit_repair(
                    repository, identity, binding, repair_seal, findings_fingerprint=findings,
                    worker_repair_fingerprint="d" * 64, worker_thread_identity="worker-thread-25",
                    runtime_binding=context.runtime_binding, review_round=1, max_rounds=1, lease=lease,
                )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertIsNone(connection.execute("SELECT 1 FROM review_limit_finalizations WHERE task_id = ?", (identity.task_id,)).fetchone())
            finally:
                connection.close()

    def test_final_review_limit_repair_rejects_tampered_persisted_round(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE diff_review_attempts SET review_round = ? WHERE task_id = ?", (9, identity.task_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(Exception):
                finalize_review_limit_repair(repository, identity, binding, repair_seal, findings_fingerprint=findings, worker_repair_fingerprint="d" * 64, worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertIsNone(connection.execute("SELECT 1 FROM review_limit_finalizations WHERE task_id = ?", (identity.task_id,)).fetchone())
            finally:
                connection.close()

    def test_diff_review_requires_the_pinned_runtime_policy_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository", include_policy=False)
            repository, identity, lease, context, binding, now = values
            implementation, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("policy-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
                CandidateVerification("policy-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            with self.assertRaisesRegex(CandidateReviewError, "review policy projection"):
                dispatch_diff_review(
                    repository, identity, review_context, binding, seal,
                    diff_review_attempt_id="unbound-policy", implementation_attempt_id=implementation.implementation_attempt_id,
                    provider_attempt_id="unbound-policy-supervisor", supervisor_session_identity="unbound-policy-session",
                    external_turn_identity="unbound-policy-turn", message_identity="unbound-policy-message",
                    process_lease_id="unbound-policy-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
                )

    def test_final_review_limit_repair_rejects_detached_or_coherently_tampered_policy(self):
        cases = ("detached", "coherent")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
                connection = sqlite3.connect(database_path(repository))
                try:
                    if case == "detached":
                        connection.execute("UPDATE runtime_review_policies SET configuration_digest = ? WHERE task_id = ?", ("sha256:" + "f" * 64, identity.task_id))
                    else:
                        digest = candidate_review._digest({"complete_rounds": 2, "max_rounds": 10, "max_supervisor_attempts_per_round": 3, "on_final_findings": "worker-final-repair-then-merge"})
                        connection.execute("UPDATE diff_review_attempts SET review_complete_rounds = ?, review_max_rounds = ?, review_max_supervisor_attempts_per_round = ?, review_on_final_findings = ?, review_policy_digest = ? WHERE task_id = ?", (2, 10, 3, "worker-final-repair-then-merge", digest, identity.task_id))
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(Exception):
                    finalize_review_limit_repair(repository, identity, binding, repair_seal, findings_fingerprint=findings, worker_repair_fingerprint="d" * 64, worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease)
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertIsNone(connection.execute("SELECT 1 FROM review_limit_finalizations WHERE task_id = ?", (identity.task_id,)).fetchone())
                finally:
                    connection.close()

    def test_final_review_limit_repair_rejects_a_coherent_persisted_policy_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, binding, _, findings, repair_seal = self.final_review_limit_repair(Path(temporary) / "repository")
            substituted_digest = candidate_review._digest({"complete_rounds": 3, "max_rounds": 4, "max_supervisor_attempts_per_round": 3, "on_final_findings": "worker-final-repair-then-merge"})
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE runtime_review_policies SET complete_rounds = ?, max_rounds = ?, max_supervisor_attempts_per_round = ?, on_final_findings = ?, policy_digest = ? WHERE task_id = ?", (3, 4, 3, "worker-final-repair-then-merge", substituted_digest, identity.task_id))
                connection.execute("UPDATE diff_review_attempts SET review_round = ?, review_complete_rounds = ?, review_max_rounds = ?, review_max_supervisor_attempts_per_round = ?, review_on_final_findings = ?, review_policy_digest = ? WHERE task_id = ?", (4, 3, 4, 3, "worker-final-repair-then-merge", substituted_digest, identity.task_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(Exception):
                finalize_review_limit_repair(repository, identity, binding, repair_seal, findings_fingerprint=findings, worker_repair_fingerprint="d" * 64, worker_thread_identity="worker-thread-25", runtime_binding=context.runtime_binding, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertIsNone(connection.execute("SELECT 1 FROM review_limit_finalizations WHERE task_id = ?", (identity.task_id,)).fetchone())
            finally:
                connection.close()
            self.assertFalse(_valid_review_limit_finalization(repository, binding, repair_seal, context.runtime_binding, None))

    def test_implementation_replays_the_persisted_worker_turn_after_a_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, _, now = values
            original = candidate_review.record_external_turn

            def crash_after_turn(*args, **kwargs):
                original(*args, **kwargs)
                raise RuntimeError("crash after implementation turn")

            with patch.object(candidate_review, "record_external_turn", side_effect=crash_after_turn):
                with self.assertRaisesRegex(RuntimeError, "implementation turn"):
                    begin_implementation(
                        repository, identity, context,
                        implementation_attempt_id="implementation-25", provider_attempt_id="worker-implementation",
                        plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25",
                        external_turn_identity="implementation-turn", process_lease_id="implementation-lease",
                        process_lease_expires_at=now + 60, lease=lease, now=now,
                    )
            self.assertEqual(task_projection(repository, identity).state, "implementing")
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT state, external_turn_identity FROM provider_attempts WHERE attempt_id = ?",
                        ("worker-implementation",),
                    ).fetchone(),
                    ("dispatched", "implementation-turn"),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM implementation_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (0,),
                )
            finally:
                connection.close()

            replay = begin_implementation(
                repository, identity, context,
                implementation_attempt_id="implementation-25", provider_attempt_id="worker-implementation",
                plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25",
                external_turn_identity="implementation-turn", process_lease_id="implementation-lease",
                process_lease_expires_at=now + 60, lease=lease, now=now,
            )
            self.assertEqual(replay.external_turn_identity, "implementation-turn")
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE attempt_id = ?", ("worker-implementation",)).fetchone(),
                    (1,),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM implementation_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (1,),
                )
            finally:
                connection.close()

    def test_diff_review_replays_the_persisted_supervisor_turn_after_a_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            implementation, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("restart-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
                CandidateVerification("restart-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            original = candidate_review.record_external_turn

            def crash_after_turn(*args, **kwargs):
                original(*args, **kwargs)
                raise RuntimeError("crash after diff-review turn")

            with patch.object(candidate_review, "record_external_turn", side_effect=crash_after_turn):
                with self.assertRaisesRegex(RuntimeError, "diff-review turn"):
                    dispatch_diff_review(
                        repository, identity, review_context, binding, seal,
                        diff_review_attempt_id="diff-restart", implementation_attempt_id=implementation.implementation_attempt_id,
                        provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-restart-session",
                        external_turn_identity="diff-restart-turn", message_identity="diff-restart-message",
                        process_lease_id="diff-restart-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
                    )
            self.assertEqual(task_projection(repository, identity).state, "diff-review")
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT state, external_turn_identity FROM provider_attempts WHERE attempt_id = ?",
                        ("diff-supervisor",),
                    ).fetchone(),
                    ("dispatched", "diff-restart-turn"),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM diff_review_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (0,),
                )
            finally:
                connection.close()

            replay = dispatch_diff_review(
                repository, identity, review_context, binding, seal,
                diff_review_attempt_id="diff-restart", implementation_attempt_id=implementation.implementation_attempt_id,
                provider_attempt_id="diff-supervisor", supervisor_session_identity="diff-restart-session",
                external_turn_identity="diff-restart-turn", message_identity="diff-restart-message",
                process_lease_id="diff-restart-lease", process_lease_expires_at=now + 60, lease=lease, now=now,
            )
            self.assertEqual(replay.external_turn_identity, "diff-restart-turn")
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE attempt_id = ?", ("diff-supervisor",)).fetchone(),
                    (1,),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM diff_review_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (1,),
                )
            finally:
                connection.close()

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
                begin_implementation(repository, identity, context, implementation_attempt_id="repair-rejected", provider_attempt_id="rejected-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", external_turn_identity="rejected-turn", process_lease_id="rejected-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            with self.assertRaises(ProviderRecoveryError):
                read_attempt(repository, identity, "rejected-worker")
            repair = begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=dispatch.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=result.routed_finding_ids, external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            self.assertEqual(repair, begin_implementation(repository, identity, context, implementation_attempt_id="repair-25", provider_attempt_id="repair-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=dispatch.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=result.routed_finding_ids, external_turn_identity="repair-turn", process_lease_id="repair-lease", process_lease_expires_at=now + 60, lease=lease, now=now))
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

    def test_concurrent_repair_dispatch_claims_only_one_provider_turn(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("race-tests", VerificationKind.TEST, VerificationOutcome.PASS, "2" * 64),
                CandidateVerification("race-build", VerificationKind.BUILD, VerificationOutcome.PASS, "3" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            review = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-race", implementation_attempt_id="implementation-25", provider_attempt_id="race-supervisor", supervisor_session_identity="race-session", external_turn_identity="race-review-turn", message_identity="race-message", process_lease_id="race-review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            findings = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=DiffReviewOutput("diff-race", "race-supervisor", "race-session", "race-review-turn", "race-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("race repair",)), completion_evidence_fingerprint="4" * 64, lease=lease, now=now)
            barrier = threading.Barrier(2)
            original_claim = candidate_review._claim_repair_parent

            def synchronized_claim(*arguments):
                barrier.wait(timeout=10)
                return original_claim(*arguments)

            def dispatch(index):
                try:
                    return index, begin_implementation(repository, identity, context, implementation_attempt_id=f"repair-race-{index}", provider_attempt_id=f"race-worker-{index}", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=review.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=findings.routed_finding_ids, external_turn_identity=f"race-turn-{index}", process_lease_id=f"race-lease-{index}", process_lease_expires_at=now + 60, lease=lease, now=now)
                except Exception as error:
                    return index, error

            with patch.object(candidate_review, "_claim_repair_parent", side_effect=synchronized_claim):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(pool.map(dispatch, (1, 2)))
            winners = [(index, value) for index, value in outcomes if isinstance(value, ImplementationDispatch)]
            failures = [(index, value) for index, value in outcomes if isinstance(value, Exception)]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0][1], CandidateReviewError)
            self.assertEqual(read_attempt(repository, identity, winners[0][1].provider_attempt_id).state, AttemptState.DISPATCHED)
            with self.assertRaises(ProviderRecoveryError):
                read_attempt(repository, identity, f"race-worker-{failures[0][0]}")

    def test_concurrent_same_implementation_alias_leaves_no_loser_provider_turn(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("alias-tests", VerificationKind.TEST, VerificationOutcome.PASS, "5" * 64),
                CandidateVerification("alias-build", VerificationKind.BUILD, VerificationOutcome.PASS, "6" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            review = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-alias", implementation_attempt_id="implementation-25", provider_attempt_id="alias-supervisor", supervisor_session_identity="alias-session", external_turn_identity="alias-review-turn", message_identity="alias-message", process_lease_id="alias-review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            findings = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=DiffReviewOutput("diff-alias", "alias-supervisor", "alias-session", "alias-review-turn", "alias-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("alias repair",)), completion_evidence_fingerprint="7" * 64, lease=lease, now=now)
            barrier = threading.Barrier(2)
            original_claim = candidate_review._claim_repair_parent

            def synchronized_claim(*arguments):
                barrier.wait(timeout=10)
                return original_claim(*arguments)

            def dispatch(index):
                try:
                    return index, begin_implementation(repository, identity, context, implementation_attempt_id="repair-alias", provider_attempt_id=f"alias-worker-{index}", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=review.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=findings.routed_finding_ids, external_turn_identity=f"alias-turn-{index}", process_lease_id=f"alias-lease-{index}", process_lease_expires_at=now + 60, lease=lease, now=now)
                except Exception as error:
                    return index, error

            with patch.object(candidate_review, "_claim_repair_parent", side_effect=synchronized_claim):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(pool.map(dispatch, (1, 2)))
            winners = [(index, value) for index, value in outcomes if isinstance(value, ImplementationDispatch)]
            failures = [(index, value) for index, value in outcomes if isinstance(value, Exception)]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0][1], CandidateReviewError)
            self.assertEqual(read_attempt(repository, identity, winners[0][1].provider_attempt_id).state, AttemptState.DISPATCHED)
            with self.assertRaises(ProviderRecoveryError):
                read_attempt(repository, identity, f"alias-worker-{failures[0][0]}")

    def test_concurrent_provider_replay_alias_cannot_release_the_claimant(self):
        with tempfile.TemporaryDirectory() as temporary:
            values = self.ready_task(Path(temporary) / "repository")
            repository, identity, lease, context, binding, now = values
            _, seal = self.implement(values)
            review_context = self.review_context(identity, context, seal)
            for verification in (
                CandidateVerification("lease-tests", VerificationKind.TEST, VerificationOutcome.PASS, "8" * 64),
                CandidateVerification("lease-build", VerificationKind.BUILD, VerificationOutcome.PASS, "9" * 64),
            ):
                record_candidate_verification(repository, identity, binding, seal, verification, lease=lease)
            review = dispatch_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id="diff-lease", implementation_attempt_id="implementation-25", provider_attempt_id="lease-supervisor", supervisor_session_identity="lease-session", external_turn_identity="lease-review-turn", message_identity="lease-message", process_lease_id="lease-review-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
            findings = record_diff_review(repository, identity, review_context, binding, seal, diff_review_attempt_id=review.diff_review_attempt_id, output=DiffReviewOutput("diff-lease", "lease-supervisor", "lease-session", "lease-review-turn", "lease-message", seal.base_sha, seal.candidate_sha, DiffReviewVerdict.FINDINGS, ("lease repair",)), completion_evidence_fingerprint="a" * 64, lease=lease, now=now)
            alternate_context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="b" * 64, deployment_fingerprint=context.deployment_fingerprint, runtime_binding=context.runtime_binding)
            barrier = threading.Barrier(2)
            original_claim = candidate_review._claim_repair_parent

            def synchronized_claim(*arguments):
                barrier.wait(timeout=10)
                return original_claim(*arguments)

            def dispatch(index):
                try:
                    replay_context = context if index == 1 else alternate_context
                    return index, begin_implementation(repository, identity, replay_context, implementation_attempt_id="repair-lease-alias", provider_attempt_id="lease-worker", plan_attempt_id="plan-25", worker_thread_identity="worker-thread-25", repair_diff_review_id=review.diff_review_attempt_id, repair_candidate_sha=seal.candidate_sha, routed_finding_ids=findings.routed_finding_ids, external_turn_identity="lease-turn", process_lease_id=f"lease-worker-{index}", process_lease_expires_at=now + 60, lease=lease, now=now)
                except Exception as error:
                    return index, error

            with patch.object(candidate_review, "_claim_repair_parent", side_effect=synchronized_claim):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    outcomes = list(pool.map(dispatch, (1, 2)))
            winners = [(index, value) for index, value in outcomes if isinstance(value, ImplementationDispatch)]
            failures = [(index, value) for index, value in outcomes if isinstance(value, Exception)]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0][1], CandidateReviewError)
            self.assertEqual(read_attempt(repository, identity, "lease-worker").state, AttemptState.DISPATCHED)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM implementation_attempts WHERE implementation_attempt_id = 'repair-lease-alias'").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE task_id = ? AND provider_role = 'worker'", (identity.task_id,)).fetchone(), (2,))
            finally:
                connection.close()

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
