"""Hermetic Git and transition-lease contracts for Phase 2 task identity."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import (
    GitEntrypointControl,
    GitIdentityError,
    TransitionLease,
    WorktreeBinding,
    acquire_transition_lease,
    bind_candidate_evidence,
    candidate_evidence,
    provision_worktree,
    revalidate_worktree,
    release_transition_lease,
    renew_transition_lease,
    resolve_canonical_base,
    seal_candidate,
)
from roundwright.dependency_policy import BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent, DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition, PolicyTransitionKind, TrustedDependencyAdmission, VersionRange
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize
from roundwright.state import database_path


class GitIdentityTests(unittest.TestCase):
    def control(self, repository: RepositoryIdentity) -> GitEntrypointControl:
        base = self.run_git(repository.root, "rev-parse", "refs/remotes/origin/main")
        digest = lambda value: "sha256:" + value * 64
        binding = CandidateBinding("ythdelmar68/roundwright", "issue-20", base)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-scm/git", digest("3"), digest("4")),
        )
        policy = DependencyPolicy(binding, digest("5"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("6"), authority_digest=digest("7"))
        policy = __import__("dataclasses").replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 100, policy.policy_digest) for item in components)
        return GitEntrypointControl(binding, DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, digest("6"), digest("7"))), 100)
    def run_git(self, directory: Path, *arguments: str) -> str:
        result = subprocess.run(["git", "-C", str(directory), *arguments], check=True, text=True, capture_output=True)
        return result.stdout.strip()

    def repository(self, root: Path) -> RepositoryIdentity:
        remote = root.parent / f"{root.name}-remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, text=True, capture_output=True)
        subprocess.run(["git", "init", "-b", "main", str(root)], check=True, text=True, capture_output=True)
        self.run_git(root, "config", "user.email", "test@example.invalid")
        self.run_git(root, "config", "user.name", "Roundwright Tests")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.run_git(root, "add", "README.md")
        self.run_git(root, "commit", "-m", "test: establish canonical base")
        self.run_git(root, "remote", "add", "origin", str(remote))
        self.run_git(root, "push", "-u", "origin", "main")
        return RepositoryIdentity.from_root(root)

    def identity(self, base_sha: str, *, branch: str = "codex/issue-20", worktree: Path | None = None) -> TaskIdentity:
        return TaskIdentity(
            task_id="issue-20",
            source_id="fixture-source",
            repository_id="ythdelmar68/roundwright",
            branch=branch,
            worktree=str(worktree if worktree is not None else Path("private-worktree")),
            base_sha=base_sha,
        )

    def admit(self, repository: RepositoryIdentity, identity: TaskIdentity) -> None:
        initialize(repository)
        digest = hashlib.sha256(identity.source_id.encode("utf-8")).hexdigest()
        admit_task(
            repository,
            identity,
            (SourceSnapshot(identity.source_id, identity.repository_id, digest),),
            lease=self.lease(repository),
        )

    def lease(self, repository: RepositoryIdentity):
        return acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-a", ttl_seconds=60)

    def test_transition_lease_is_atomic_owner_scoped_and_stale_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary) / "repository")
            initialize(repository)
            first = acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-a", ttl_seconds=10, now=100)
            self.assertGreaterEqual(first.generation, 3)
            with self.assertRaises(GitIdentityError):
                acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-b", ttl_seconds=10, now=101)
            renewed = renew_transition_lease(repository, first, ttl_seconds=20, now=105)
            self.assertEqual(renewed.expires_at, 125)
            with self.assertRaises(GitIdentityError):
                release_transition_lease(repository, first, now=106)
            release_transition_lease(repository, renewed, now=106)
            reacquired = acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-a", ttl_seconds=10, now=200)
            self.assertGreater(reacquired.generation, renewed.generation)
            with self.assertRaises(GitIdentityError):
                release_transition_lease(repository, renewed, now=201)
            stale = renew_transition_lease(repository, reacquired, ttl_seconds=1, now=205)
            with self.assertRaises(GitIdentityError):
                renew_transition_lease(repository, stale, ttl_seconds=10, now=206)

    def test_base_comes_from_origin_default_branch_not_current_checkout_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary) / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            self.run_git(repository.root, "checkout", "-b", "local-only")
            (repository.root / "README.md").write_text("local-only\n", encoding="utf-8")
            self.run_git(repository.root, "commit", "-am", "test: diverge local checkout")
            self.assertNotEqual(self.run_git(repository.root, "rev-parse", "HEAD"), base)
            self.assertEqual(resolve_canonical_base(repository, "main", control=self.control(repository)), base)

    def test_provision_revalidates_exact_registered_worktree_and_rejects_detached_or_dirty_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository))
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=lease)
            wrong_owner = TransitionLease(lease.repository_id, lease.state_identity, "orchestrator-b", lease.generation, lease.expires_at)
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, control=self.control(repository), lease=wrong_owner)
            self.assertEqual(provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=lease), binding)
            self.run_git(location, "checkout", "--detach")
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, control=self.control(repository), lease=lease)

    def test_provision_and_revalidation_preserve_unicode_worktree_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            location = parent / "isolated" / "任務"
            identity = self.identity(base, branch="codex/unicode-worktree", worktree=location)
            self.admit(repository, identity)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=self.lease(repository))
            self.assertTrue(location.is_dir())
            self.assertEqual(revalidate_worktree(repository, binding, control=self.control(repository)), binding)

    def test_provision_rejects_unsealed_or_mismatched_control_before_git_or_state_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = self.run_git(repository.root, "rev-parse", "refs/remotes/origin/main")
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            state_before = database_path(repository).read_bytes()
            valid = self.control(repository)

            def forged(binding, now):
                value = object.__new__(GitEntrypointControl)
                object.__setattr__(value, "binding", binding)
                object.__setattr__(value, "dependency_control", valid.dependency_control)
                object.__setattr__(value, "now", now)
                return value

            invalid = (
                None,
                object(),
                forged(valid.binding, 1_000),
                forged(CandidateBinding("other/repository", identity.task_id, base), valid.now),
                forged(CandidateBinding(identity.repository_id, "other-task", base), valid.now),
                valid,
            )
            identities = (*((identity,) * 5), self.identity("f" * 40, worktree=parent / "isolated" / "wrong-candidate"))
            with patch("roundwright.git_identity._resolve_canonical_base_unchecked") as resolve:
                for control, attempted_identity in zip(invalid, identities, strict=True):
                    with self.subTest(control=type(control).__name__, task=attempted_identity.task_id):
                        with self.assertRaises((GitIdentityError, TypeError)):
                            provision_worktree(
                                repository, attempted_identity, default_branch="main", worktree=Path(attempted_identity.worktree), control=control, lease=lease
                            )
            resolve.assert_not_called()
            self.assertFalse(location.exists())
            self.assertFalse((parent / "isolated" / "wrong-candidate").exists())
            self.assertEqual(database_path(repository).read_bytes(), state_before)

    def test_provision_rejects_base_drift_before_worktree_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = self.run_git(repository.root, "rev-parse", "refs/remotes/origin/main")
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            state_before = database_path(repository).read_bytes()
            with patch("roundwright.git_identity._resolve_canonical_base_unchecked", return_value="f" * 40) as resolve:
                with self.assertRaises(GitIdentityError):
                    provision_worktree(
                        repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=lease
                    )
            resolve.assert_called_once()
            self.assertFalse(location.exists())
            self.assertEqual(database_path(repository).read_bytes(), state_before)

    def test_repository_bound_lease_and_metadata_descendant_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            initialize(repository)
            normal = parent / "isolated" / "wrong-repository"
            normal_identity = self.identity(base, branch="codex/wrong-repository", worktree=normal)
            self.admit(repository, normal_identity)
            current = self.lease(repository)
            wrong_lease = TransitionLease("other/repository", current.state_identity, current.owner, current.generation, current.expires_at)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, normal_identity, default_branch="main", worktree=normal, control=self.control(repository), lease=wrong_lease)
            for name in (".git/nested-worktree", ".roundwright/nested-worktree"):
                location = repository.root / name
                identity = TaskIdentity(
                    task_id=f"issue-20-{name.replace('/', '-')}",
                    source_id=f"fixture-{name.replace('/', '-')}",
                    repository_id="ythdelmar68/roundwright",
                    branch=f"codex/{name.replace('/', '-')}",
                    worktree=str(location),
                    base_sha=base,
                )
                self.admit(repository, identity)
                with self.subTest(path=name), self.assertRaises(GitIdentityError):
                    provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=wrong_lease)

    def test_revalidate_rejects_registered_path_prefix_collisions_and_copied_gitfiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            requested = parent / "isolated" / "task"
            registered = parent / "isolated" / "task-copy"
            identity = self.identity(base, worktree=requested)
            self.admit(repository, identity)
            self.run_git(repository.root, "worktree", "add", "-b", identity.branch, str(registered), base)
            shutil.copytree(registered, requested)
            binding = WorktreeBinding(
                identity.task_id,
                identity.repository_id,
                identity.branch,
                requested,
                identity.base_sha,
                self.lease(repository).state_identity,
            )
            with self.assertRaises(GitIdentityError):
                revalidate_worktree(repository, binding, control=self.control(repository))

    def test_revalidation_and_candidate_sealing_reject_controls_before_git_or_state_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            identity = self.identity(base, worktree=parent / "isolated" / "task-20")
            self.admit(repository, identity)
            lease = self.lease(repository)
            binding = provision_worktree(
                repository, identity, default_branch="main", worktree=Path(identity.worktree),
                control=self.control(repository), lease=lease,
            )
            valid = self.control(repository)

            def forged(candidate_binding, now):
                value = object.__new__(GitEntrypointControl)
                object.__setattr__(value, "binding", candidate_binding)
                object.__setattr__(value, "dependency_control", valid.dependency_control)
                object.__setattr__(value, "now", now)
                return value

            invalid_controls = (
                None,
                object(),
                forged(valid.binding, 1_000),
                forged(CandidateBinding(identity.repository_id, "other-task", base), valid.now),
                forged(CandidateBinding(identity.repository_id, identity.task_id, "f" * 40), valid.now),
            )
            state_before = database_path(repository).read_bytes()
            with patch("roundwright.git_identity._common_git_directory") as git_helper, patch(
                "roundwright.git_identity._open_writable_connection"
            ) as state_helper:
                for control in invalid_controls:
                    with self.subTest(control=type(control).__name__):
                        with self.assertRaises(GitIdentityError):
                            revalidate_worktree(repository, binding, control=control)
                        with self.assertRaises(GitIdentityError):
                            seal_candidate(repository, binding, control=control, lease=lease)
            git_helper.assert_not_called()
            state_helper.assert_not_called()
            self.assertEqual(database_path(repository).read_bytes(), state_before)

    def test_candidate_seal_is_idempotent_and_movement_invalidates_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=lease)
            seal = seal_candidate(repository, binding, control=self.control(repository), lease=lease)
            bind_candidate_evidence(repository, binding, seal, evidence_fingerprint="b" * 64, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "INSERT INTO gate_evidence(task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason, follow_ups) VALUES (?, ?, 'build', 'PASS', 'validator', 1, ?, NULL, NULL, '[]')",
                    (identity.task_id, seal.candidate_sha, "b" * 64),
                )
                connection.execute(
                    "INSERT INTO gate_contexts(task_id, candidate_sha, source_count, isolated_local_task, policy_digest, receipt_fingerprint) VALUES (?, ?, 1, 1, ?, ?)",
                    (identity.task_id, seal.candidate_sha, "c" * 64, "d" * 64),
                )
                connection.commit()
            finally:
                connection.close()
            self.assertEqual(candidate_evidence(repository, binding, seal, lease=lease), ("b" * 64,))
            self.assertEqual(seal_candidate(repository, binding, control=self.control(repository), lease=lease), seal)
            self.assertEqual(candidate_evidence(repository, binding, seal, lease=lease), ("b" * 64,))
            (binding.worktree / "candidate.txt").write_text("moved\n", encoding="utf-8")
            self.run_git(binding.worktree, "add", "candidate.txt")
            self.run_git(binding.worktree, "commit", "-m", "test: move candidate")
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, seal, lease=lease)
            moved = seal_candidate(repository, binding, control=self.control(repository), lease=lease)
            self.assertNotEqual(moved.candidate_sha, seal.candidate_sha)
            self.assertEqual(candidate_evidence(repository, binding, moved, lease=lease), ())
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_evidence WHERE task_id = ?", (identity.task_id,)).fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_contexts WHERE task_id = ?", (identity.task_id,)).fetchone(), (0,))
            finally:
                connection.close()
            bind_candidate_evidence(repository, binding, moved, evidence_fingerprint="c" * 64, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "INSERT INTO gate_evidence(task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason, follow_ups) VALUES (?, ?, 'build', 'PASS', 'validator', 1, ?, NULL, NULL, '[]')",
                    (identity.task_id, moved.candidate_sha, "c" * 64),
                )
                connection.execute(
                    "INSERT INTO gate_contexts(task_id, candidate_sha, source_count, isolated_local_task, policy_digest, receipt_fingerprint) VALUES (?, ?, 1, 1, ?, ?)",
                    (identity.task_id, moved.candidate_sha, "c" * 64, "e" * 64),
                )
                connection.commit()
            finally:
                connection.close()
            self.run_git(binding.worktree, "reset", "--hard", base)
            restored = seal_candidate(repository, binding, control=self.control(repository), lease=lease)
            self.assertEqual(restored.candidate_sha, seal.candidate_sha)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_evidence WHERE task_id = ?", (identity.task_id,)).fetchone(), (0,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM gate_contexts WHERE task_id = ?", (identity.task_id,)).fetchone(), (0,))
            finally:
                connection.close()
            self.assertEqual(candidate_evidence(repository, binding, restored, lease=lease), ())
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE state_metadata SET value = ? WHERE key = 'state_id'", ("87654321-4321-8765-4321-876543218765",))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, moved, lease=lease)

    def test_detached_candidate_drift_cannot_restore_prior_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, control=self.control(repository), lease=lease)
            seal = seal_candidate(repository, binding, control=self.control(repository), lease=lease)
            bind_candidate_evidence(repository, binding, seal, evidence_fingerprint="b" * 64, lease=lease)
            self.run_git(location, "checkout", "--detach", base)
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, seal, lease=lease)
            self.run_git(location, "checkout", identity.branch)
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, seal, lease=lease)
            refreshed = seal_candidate(repository, binding, control=self.control(repository), lease=lease)
            bind_candidate_evidence(repository, binding, refreshed, evidence_fingerprint="c" * 64, lease=lease)
            self.assertEqual(candidate_evidence(repository, binding, refreshed, lease=lease), ("c" * 64,))

    def test_wrong_base_foreign_repository_and_path_collision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main", control=self.control(repository))
            collision = parent / "isolated" / "collision"
            identity = self.identity(base, worktree=collision)
            self.admit(repository, identity)
            lease = self.lease(repository)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, self.identity("f" * 40, worktree=parent / "isolated" / "wrong-base"), default_branch="main", worktree=parent / "isolated" / "wrong-base", control=self.control(repository), lease=lease)
            collision.mkdir(parents=True)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, identity, default_branch="main", worktree=collision, control=self.control(repository), lease=lease)
            foreign = self.repository(parent / "foreign")
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, foreign.root, base, lease.state_identity)
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, control=self.control(repository), lease=lease)
