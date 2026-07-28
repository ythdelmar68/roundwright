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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import (
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
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize
from roundwright.state import database_path


class GitIdentityTests(unittest.TestCase):
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
            self.assertEqual(first.generation, 1)
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
            base = resolve_canonical_base(repository, "main")
            self.run_git(repository.root, "checkout", "-b", "local-only")
            (repository.root / "README.md").write_text("local-only\n", encoding="utf-8")
            self.run_git(repository.root, "commit", "-am", "test: diverge local checkout")
            self.assertNotEqual(self.run_git(repository.root, "rev-parse", "HEAD"), base)
            self.assertEqual(resolve_canonical_base(repository, "main"), base)

    def test_provision_revalidates_exact_registered_worktree_and_rejects_detached_or_dirty_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, identity, default_branch="main", worktree=location)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, lease=lease)
            wrong_owner = TransitionLease(lease.repository_id, lease.state_identity, "orchestrator-b", lease.generation, lease.expires_at)
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, lease=wrong_owner)
            self.assertEqual(provision_worktree(repository, identity, default_branch="main", worktree=location, lease=lease), binding)
            self.run_git(location, "checkout", "--detach")
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, lease=lease)

    def test_repository_bound_lease_and_metadata_descendant_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            initialize(repository)
            normal = parent / "isolated" / "wrong-repository"
            normal_identity = self.identity(base, branch="codex/wrong-repository", worktree=normal)
            self.admit(repository, normal_identity)
            current = self.lease(repository)
            wrong_lease = TransitionLease("other/repository", current.state_identity, current.owner, current.generation, current.expires_at)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, normal_identity, default_branch="main", worktree=normal, lease=wrong_lease)
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
                    provision_worktree(repository, identity, default_branch="main", worktree=location, lease=wrong_lease)

    def test_revalidate_rejects_registered_path_prefix_collisions_and_copied_gitfiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
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
                revalidate_worktree(repository, binding)

    def test_candidate_seal_is_idempotent_and_movement_invalidates_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            lease = self.lease(repository)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location, lease=lease)
            seal = seal_candidate(repository, binding, lease=lease)
            bind_candidate_evidence(repository, binding, seal, evidence_fingerprint="b" * 64, lease=lease)
            self.assertEqual(candidate_evidence(repository, binding, seal, lease=lease), ("b" * 64,))
            self.assertEqual(seal_candidate(repository, binding, lease=lease), seal)
            self.assertEqual(candidate_evidence(repository, binding, seal, lease=lease), ("b" * 64,))
            (binding.worktree / "candidate.txt").write_text("moved\n", encoding="utf-8")
            self.run_git(binding.worktree, "add", "candidate.txt")
            self.run_git(binding.worktree, "commit", "-m", "test: move candidate")
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, seal, lease=lease)
            moved = seal_candidate(repository, binding, lease=lease)
            self.assertNotEqual(moved.candidate_sha, seal.candidate_sha)
            self.assertEqual(candidate_evidence(repository, binding, moved, lease=lease), ())
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, seal, lease=lease)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE state_metadata SET value = ? WHERE key = 'state_id'", ("87654321-4321-8765-4321-876543218765",))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, binding, moved, lease=lease)

    def test_wrong_base_foreign_repository_and_path_collision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            collision = parent / "isolated" / "collision"
            identity = self.identity(base, worktree=collision)
            self.admit(repository, identity)
            lease = self.lease(repository)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, self.identity("f" * 40, worktree=parent / "isolated" / "wrong-base"), default_branch="main", worktree=parent / "isolated" / "wrong-base", lease=lease)
            collision.mkdir(parents=True)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, identity, default_branch="main", worktree=collision, lease=lease)
            foreign = self.repository(parent / "foreign")
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, foreign.root, base, lease.state_identity)
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding, lease=lease)
