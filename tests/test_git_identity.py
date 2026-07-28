"""Hermetic Git and transition-lease contracts for Phase 2 task identity."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import (
    GitIdentityError,
    WorktreeBinding,
    acquire_transition_lease,
    bind_candidate_evidence,
    candidate_evidence,
    provision_worktree,
    release_transition_lease,
    renew_transition_lease,
    resolve_canonical_base,
    seal_candidate,
)
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize


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
        admit_task(repository, identity, (SourceSnapshot("fixture-source", identity.repository_id, "a" * 64),))

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
            stale = acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-a", ttl_seconds=1, now=200)
            with self.assertRaises(GitIdentityError):
                acquire_transition_lease(repository, repository_id="ythdelmar68/roundwright", owner="orchestrator-b", ttl_seconds=10, now=201)
            with self.assertRaises(GitIdentityError):
                renew_transition_lease(repository, stale, ttl_seconds=10, now=201)

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
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location)
            self.assertEqual(provision_worktree(repository, identity, default_branch="main", worktree=location), binding)
            self.run_git(location, "checkout", "--detach")
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding)

    def test_candidate_seal_is_idempotent_and_movement_invalidates_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            location = parent / "isolated" / "task-20"
            identity = self.identity(base, worktree=location)
            self.admit(repository, identity)
            binding = provision_worktree(repository, identity, default_branch="main", worktree=location)
            seal = seal_candidate(repository, binding)
            bind_candidate_evidence(repository, seal, evidence_fingerprint="b" * 64)
            self.assertEqual(candidate_evidence(repository, seal), ("b" * 64,))
            self.assertEqual(seal_candidate(repository, binding), seal)
            self.assertEqual(candidate_evidence(repository, seal), ("b" * 64,))
            (binding.worktree / "candidate.txt").write_text("moved\n", encoding="utf-8")
            self.run_git(binding.worktree, "add", "candidate.txt")
            self.run_git(binding.worktree, "commit", "-m", "test: move candidate")
            moved = seal_candidate(repository, binding)
            self.assertNotEqual(moved.candidate_sha, seal.candidate_sha)
            self.assertEqual(candidate_evidence(repository, moved), ())
            with self.assertRaises(GitIdentityError):
                candidate_evidence(repository, seal)

    def test_wrong_base_foreign_repository_and_path_collision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            repository = self.repository(parent / "repository")
            base = resolve_canonical_base(repository, "main")
            collision = parent / "isolated" / "collision"
            identity = self.identity(base, worktree=collision)
            self.admit(repository, identity)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, self.identity("f" * 40, worktree=parent / "isolated" / "wrong-base"), default_branch="main", worktree=parent / "isolated" / "wrong-base")
            collision.mkdir(parents=True)
            with self.assertRaises(GitIdentityError):
                provision_worktree(repository, identity, default_branch="main", worktree=collision)
            foreign = self.repository(parent / "foreign")
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, foreign.root, base)
            with self.assertRaises(GitIdentityError):
                seal_candidate(repository, binding)
