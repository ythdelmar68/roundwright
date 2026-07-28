"""Fail-closed, local Git identity contracts for one Phase 2 task.

This module deliberately has no network, provider, or cleanup operations.  It
only establishes the local identity facts a later lifecycle may rely on.
"""

from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .configuration import RepositoryIdentity
from .state import StateError, TaskIdentity, _open_writable_connection


class GitIdentityError(StateError):
    """Raised when a local Git identity fact cannot be proved safely."""


_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


@dataclass(frozen=True)
class TransitionLease:
    """One short-lived owner binding for deterministic state transitions."""

    repository_id: str
    state_identity: str
    owner: str
    generation: int
    expires_at: int


@dataclass(frozen=True)
class WorktreeBinding:
    """The path-sensitive identity retained only in local machine state."""

    task_id: str
    repository_id: str
    branch: str
    worktree: Path
    base_sha: str
    state_identity: str


@dataclass(frozen=True)
class CandidateSeal:
    """A clean readable worktree HEAD bound to the task's immutable base."""

    task_id: str
    base_sha: str
    candidate_sha: str
    state_identity: str


def acquire_transition_lease(
    repository: RepositoryIdentity,
    *,
    repository_id: str,
    owner: str,
    ttl_seconds: int,
    now: int | None = None,
) -> TransitionLease:
    """Acquire one repository/state lease; conflicting or stale rows fail closed."""

    _require_token(repository_id, "repository identity")
    _require_token(owner, "lease owner")
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise GitIdentityError("lease duration is invalid")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        state_identity = _state_identity(connection)
        row = connection.execute(
            "SELECT repository_id, state_identity, owner, generation, expires_at FROM transition_leases WHERE lease_scope = 'repository-state'"
        ).fetchone()
        if row is None:
            generation = connection.execute(
                "SELECT generation FROM transition_lease_generations WHERE lease_scope = 'repository-state'"
            ).fetchone()
            next_generation = 1 if generation is None else generation[0] + 1
            lease = TransitionLease(repository_id, state_identity, owner, next_generation, observed + ttl_seconds)
            connection.execute(
                "INSERT INTO transition_lease_generations(lease_scope, generation) VALUES ('repository-state', ?) "
                "ON CONFLICT(lease_scope) DO UPDATE SET generation = excluded.generation",
                (next_generation,),
            )
            connection.execute(
                "INSERT INTO transition_leases(lease_scope, repository_id, state_identity, owner, generation, expires_at) VALUES ('repository-state', ?, ?, ?, ?, ?)",
                (lease.repository_id, lease.state_identity, lease.owner, lease.generation, lease.expires_at),
            )
        else:
            existing = TransitionLease(*row)
            if existing.repository_id != repository_id or existing.state_identity != state_identity:
                raise GitIdentityError("transition lease identity is unverifiable")
            if existing.expires_at <= observed:
                raise GitIdentityError("transition lease is stale and requires owner recovery")
            if existing.owner != owner:
                raise GitIdentityError("a conflicting transition lease is active")
            lease = TransitionLease(repository_id, state_identity, owner, existing.generation, observed + ttl_seconds)
            connection.execute(
                "UPDATE transition_leases SET expires_at = ? WHERE lease_scope = 'repository-state' AND owner = ? AND generation = ?",
                (lease.expires_at, owner, existing.generation),
            )
        connection.commit()
        return lease
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def renew_transition_lease(
    repository: RepositoryIdentity, lease: TransitionLease, *, ttl_seconds: int, now: int | None = None
) -> TransitionLease:
    """Renew only the exact unexpired owner binding."""

    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise GitIdentityError("lease duration is invalid")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, lease.repository_id, observed)
        renewed = TransitionLease(lease.repository_id, lease.state_identity, lease.owner, lease.generation, observed + ttl_seconds)
        connection.execute(
            "UPDATE transition_leases SET expires_at = ? WHERE lease_scope = 'repository-state'",
            (renewed.expires_at,),
        )
        connection.commit()
        return renewed
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def release_transition_lease(repository: RepositoryIdentity, lease: TransitionLease, *, now: int | None = None) -> None:
    """Atomically release only the exact current, unexpired owner binding."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, lease.repository_id, _clock(now))
        connection.execute("DELETE FROM transition_leases WHERE lease_scope = 'repository-state'")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@contextmanager
def transition_lease(
    repository: RepositoryIdentity, *, repository_id: str, owner: str, ttl_seconds: int, now: int | None = None
) -> Iterator[TransitionLease]:
    """Scope one deterministic transition to a verified local lease."""

    lease = acquire_transition_lease(repository, repository_id=repository_id, owner=owner, ttl_seconds=ttl_seconds, now=now)
    try:
        yield lease
    finally:
        release_transition_lease(repository, lease, now=now)


def resolve_canonical_base(repository: RepositoryIdentity, default_branch: str) -> str:
    """Resolve a full base commit from ``origin/<default_branch>``, never local HEAD."""

    _require_branch(default_branch)
    return _git_commit(repository.root, "rev-parse", "--verify", f"refs/remotes/origin/{default_branch}^{{commit}}")


def provision_worktree(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    default_branch: str,
    worktree: Path,
    lease: TransitionLease | None = None,
) -> WorktreeBinding:
    """Create or revalidate one task-owned branch/worktree at the canonical base.

    No reset, clean, rebase, deletion, or force operation is used.  Existing
    paths are revalidated rather than repaired.
    """

    base_sha = resolve_canonical_base(repository, default_branch)
    if base_sha != identity.base_sha:
        raise GitIdentityError("task base does not match the canonical default branch")
    _require_branch(identity.branch)
    requested = _validated_worktree_path(repository.root, worktree)
    if Path(identity.worktree).resolve(strict=False) != requested:
        raise GitIdentityError("task worktree path does not match committed task identity")
    _verify_lease(repository, lease, identity.repository_id)
    binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, requested, identity.base_sha, _read_state_identity(repository))
    if requested.exists():
        return revalidate_worktree(repository, binding)
    _git(repository.root, "worktree", "add", "-b", identity.branch, os.fspath(requested), base_sha)
    return revalidate_worktree(repository, binding)


def revalidate_worktree(repository: RepositoryIdentity, binding: WorktreeBinding) -> WorktreeBinding:
    """Prove one existing linked worktree belongs to its exact task identity."""

    root = repository.root.resolve(strict=True)
    worktree = _validated_worktree_path(root, binding.worktree)
    _require_task_binding(repository, binding, worktree)
    if binding.state_identity != _read_state_identity(repository):
        raise GitIdentityError("task worktree state identity has drifted")
    if not worktree.exists() or not worktree.is_dir():
        raise GitIdentityError("task worktree is unavailable")
    if _common_git_directory(worktree) != _common_git_directory(root):
        raise GitIdentityError("task worktree belongs to a foreign repository")
    branch = _git(worktree, "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch != binding.branch:
        raise GitIdentityError("task worktree branch does not match its identity")
    head = _git_commit(worktree, "rev-parse", "--verify", "HEAD^{commit}")
    if head != binding.base_sha and not _is_ancestor(worktree, binding.base_sha, head):
        raise GitIdentityError("task worktree does not descend from its base")
    if _local_path_key(worktree) not in _registered_worktree_paths(root):
        raise GitIdentityError("task worktree is not an active registered worktree")
    _require_worktree_backlink(worktree)
    return WorktreeBinding(binding.task_id, binding.repository_id, binding.branch, worktree, binding.base_sha, binding.state_identity)


def seal_candidate(repository: RepositoryIdentity, binding: WorktreeBinding, *, lease: TransitionLease | None = None) -> CandidateSeal:
    """Seal a clean full commit HEAD and invalidate evidence for a moved candidate."""

    verified = _revalidate_live_candidate_binding(repository, binding, lease)
    if _git(verified.worktree, "status", "--porcelain=v1", "--untracked-files=all"):
        _invalidate_candidate(repository, verified, lease)
        raise GitIdentityError("candidate worktree is dirty")
    candidate = _git_commit(verified.worktree, "rev-parse", "--verify", "HEAD^{commit}")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, binding.repository_id, None)
        row = connection.execute(
            "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (verified.task_id,)
        ).fetchone()
        if row is not None and tuple(row) != (verified.base_sha, candidate, verified.state_identity):
            connection.execute("DELETE FROM candidate_evidence WHERE task_id = ?", (verified.task_id,))
        connection.execute(
            "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(task_id) DO UPDATE SET base_sha = excluded.base_sha, candidate_sha = excluded.candidate_sha, state_identity = excluded.state_identity",
            (verified.task_id, verified.base_sha, candidate, verified.state_identity),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return CandidateSeal(verified.task_id, verified.base_sha, candidate, verified.state_identity)


def bind_candidate_evidence(repository: RepositoryIdentity, binding: WorktreeBinding, seal: CandidateSeal, *, evidence_fingerprint: str, lease: TransitionLease | None = None) -> None:
    """Bind opaque evidence only to the currently sealed exact candidate."""

    if not isinstance(evidence_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_fingerprint):
        raise GitIdentityError("candidate evidence fingerprint is invalid")
    _require_live_candidate(repository, binding, seal, lease)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, binding.repository_id, None)
        row = connection.execute(
            "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (seal.task_id,)
        ).fetchone()
        if row != (seal.base_sha, seal.candidate_sha, seal.state_identity):
            raise GitIdentityError("candidate seal is no longer current")
        connection.execute(
            "INSERT OR IGNORE INTO candidate_evidence(task_id, candidate_sha, evidence_fingerprint) VALUES (?, ?, ?)",
            (seal.task_id, seal.candidate_sha, evidence_fingerprint),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def candidate_evidence(repository: RepositoryIdentity, binding: WorktreeBinding, seal: CandidateSeal, *, lease: TransitionLease | None = None) -> tuple[str, ...]:
    """Return evidence only if the caller still holds the current candidate seal."""

    _require_live_candidate(repository, binding, seal, lease)
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (seal.task_id,)
        ).fetchone()
        if row != (seal.base_sha, seal.candidate_sha, seal.state_identity):
            raise GitIdentityError("candidate seal is no longer current")
        return tuple(
            entry[0] for entry in connection.execute(
                "SELECT evidence_fingerprint FROM candidate_evidence WHERE task_id = ? AND candidate_sha = ? ORDER BY evidence_fingerprint",
                (seal.task_id, seal.candidate_sha),
            )
        )
    finally:
        connection.close()


def _state_identity(connection: sqlite3.Connection) -> str:
    row = connection.execute("SELECT value FROM state_metadata WHERE key = 'state_id'").fetchone()
    if row is None or not isinstance(row[0], str):
        raise GitIdentityError("repository state identity is unavailable")
    return row[0]


def _read_state_identity(repository: RepositoryIdentity) -> str:
    connection = _open_writable_connection(repository)
    try:
        return _state_identity(connection)
    finally:
        connection.close()


def _verify_lease(repository: RepositoryIdentity, lease: TransitionLease | None, repository_id: str, now: int | None = None) -> None:
    if not isinstance(lease, TransitionLease):
        raise GitIdentityError("a current transition lease is required")
    connection = _open_writable_connection(repository)
    try:
        _require_current_lease(connection, lease, repository_id, _clock(now))
    finally:
        connection.close()


def _require_live_candidate(
    repository: RepositoryIdentity, binding: WorktreeBinding, seal: CandidateSeal, lease: TransitionLease | None
) -> None:
    """Invalidate evidence on live head/state drift before it can be consumed."""

    verified = _revalidate_live_candidate_binding(repository, binding, lease)
    if verified.task_id != seal.task_id or verified.base_sha != seal.base_sha or verified.state_identity != seal.state_identity:
        raise GitIdentityError("candidate seal identity has drifted")
    if _git(verified.worktree, "status", "--porcelain=v1", "--untracked-files=all"):
        _invalidate_candidate(repository, verified, lease)
        raise GitIdentityError("candidate worktree is dirty")
    head = _git_commit(verified.worktree, "rev-parse", "--verify", "HEAD^{commit}")
    if head != seal.candidate_sha:
        _invalidate_candidate(repository, verified, lease)
        raise GitIdentityError("candidate head moved and candidate sealing is required")


def _revalidate_live_candidate_binding(
    repository: RepositoryIdentity, binding: WorktreeBinding, lease: TransitionLease | None
) -> WorktreeBinding:
    """Invalidate candidate state after leased, exact task worktree drift."""

    _verify_lease(repository, lease, binding.repository_id)
    root = repository.root.resolve(strict=True)
    worktree = _validated_worktree_path(root, binding.worktree)
    _require_task_binding(repository, binding, worktree)
    if not isinstance(lease, TransitionLease) or binding.state_identity != lease.state_identity:
        raise GitIdentityError("candidate state identity has drifted")
    try:
        return revalidate_worktree(repository, binding)
    except GitIdentityError:
        _invalidate_candidate(repository, binding, lease)
        raise


def _invalidate_candidate(repository: RepositoryIdentity, binding: WorktreeBinding, lease: TransitionLease | None) -> None:
    """Atomically remove evidence that can no longer prove the live candidate."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, binding.repository_id, None)
        if not isinstance(lease, TransitionLease) or binding.state_identity != lease.state_identity:
            raise GitIdentityError("candidate state identity has drifted")
        connection.execute("DELETE FROM candidate_evidence WHERE task_id = ?", (binding.task_id,))
        connection.execute("DELETE FROM candidate_seals WHERE task_id = ?", (binding.task_id,))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _require_task_binding(repository: RepositoryIdentity, binding: WorktreeBinding, worktree: Path) -> None:
    """Require the durable task ledger to own the exact branch/path/base tuple."""

    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT repository_id, branch, worktree, base_sha FROM tasks WHERE task_id = ?", (binding.task_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or row[0] != binding.repository_id or row[1] != binding.branch or row[3] != binding.base_sha:
        raise GitIdentityError("task worktree ownership does not match committed state")
    try:
        recorded = Path(row[2]).resolve(strict=False)
    except (TypeError, OSError) as error:
        raise GitIdentityError("task worktree ownership is invalid") from error
    if recorded != worktree:
        raise GitIdentityError("task worktree path does not match committed task identity")


def _require_current_lease(connection: sqlite3.Connection, lease: TransitionLease, repository_id: str, observed: int | None) -> None:
    if not isinstance(lease, TransitionLease):
        raise GitIdentityError("a current transition lease is required")
    row = connection.execute(
        "SELECT repository_id, state_identity, owner, generation, expires_at FROM transition_leases WHERE lease_scope = 'repository-state'"
    ).fetchone()
    if row is None or TransitionLease(*row) != lease:
        raise GitIdentityError("transition lease ownership has drifted")
    if lease.repository_id != repository_id:
        raise GitIdentityError("transition lease does not match the task repository")
    if _state_identity(connection) != lease.state_identity:
        raise GitIdentityError("transition lease state identity has drifted")
    if lease.expires_at <= _clock(observed):
        raise GitIdentityError("transition lease is stale and requires owner recovery")


def _clock(now: int | None) -> int:
    value = int(time.time()) if now is None else now
    if not isinstance(value, int) or value < 0:
        raise GitIdentityError("lease clock is invalid")
    return value


def _validated_worktree_path(root: Path, worktree: Path) -> Path:
    try:
        normalized = worktree.resolve(strict=False)
    except OSError as error:
        raise GitIdentityError("task worktree path is unavailable") from error
    protected = (root, root / ".git", root / ".roundwright")
    if any(_is_within(normalized, directory) for directory in protected):
        raise GitIdentityError("task worktree path is unsafe")
    return normalized


def _is_within(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _is_ancestor(worktree: Path, base: str, candidate: str) -> bool:
    result = _git_result(worktree, "merge-base", "--is-ancestor", base, candidate)
    return result.returncode == 0


def _common_git_directory(worktree: Path) -> Path:
    raw = _git_path(worktree, "rev-parse", "--git-common-dir")
    if not raw.is_absolute():
        raw = worktree / raw
    try:
        return raw.resolve(strict=True)
    except OSError as error:
        raise GitIdentityError("Git common directory is unavailable") from error


def _registered_worktree_paths(root: Path) -> frozenset[str]:
    """Parse Git's porcelain records into exact local path identities."""

    paths: set[str] = set()
    for entry in _git_bytes(root, "worktree", "list", "--porcelain", "-z").split(b"\0"):
        if entry.startswith(b"worktree "):
            paths.add(_local_path_key(Path(os.fsdecode(entry[len(b"worktree ") :]))))
    return frozenset(paths)


def _require_worktree_backlink(worktree: Path) -> None:
    """Prove the linked-worktree Git directory points back to this exact path."""

    common = _common_git_directory(worktree)
    git_directory = _git_path(worktree, "rev-parse", "--absolute-git-dir")
    try:
        git_directory = git_directory.resolve(strict=True)
        expected_parent = (common / "worktrees").resolve(strict=True)
        if git_directory.parent != expected_parent:
            raise GitIdentityError("task worktree metadata is not a linked worktree")
        backlink = git_directory / "gitdir"
        target = Path(backlink.read_text(encoding="utf-8").strip()).resolve(strict=True)
        expected = (worktree / ".git").resolve(strict=True)
    except (OSError, ValueError) as error:
        raise GitIdentityError("task worktree metadata is unavailable") from error
    if target != expected:
        raise GitIdentityError("task worktree metadata does not bind its exact path")


def _local_path_key(path: Path) -> str:
    try:
        resolved = path.resolve(strict=False)
    except OSError as error:
        raise GitIdentityError("task worktree path is unavailable") from error
    return os.path.normcase(os.path.normpath(os.fspath(resolved)))


def _git_commit(worktree: Path, *arguments: str) -> str:
    value = _git(worktree, *arguments)
    if not _COMMIT.fullmatch(value):
        raise GitIdentityError("Git did not return a full readable commit")
    return value


def _git_path(worktree: Path, *arguments: str) -> Path:
    """Read Git path output as bytes so locale cannot alter a valid filename."""

    output = _git_bytes(worktree, *arguments)
    if not output.endswith(b"\n"):
        raise GitIdentityError("Git did not return a readable path")
    return Path(os.fsdecode(output[:-1]))


def _git(worktree: Path, *arguments: str) -> str:
    result = _git_result(worktree, *arguments)
    if result.returncode != 0:
        raise GitIdentityError("Git identity verification failed")
    return result.stdout.strip()


def _git_bytes(worktree: Path, *arguments: str) -> bytes:
    result = _git_bytes_result(worktree, *arguments)
    if result.returncode != 0:
        raise GitIdentityError("Git identity verification failed")
    return result.stdout


def _git_result(worktree: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        return subprocess.run(
            ["git", "-C", os.fspath(worktree), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GitIdentityError("Git identity verification is unavailable") from error


def _git_bytes_result(worktree: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        return subprocess.run(
            ["git", "-C", os.fspath(worktree), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GitIdentityError("Git identity verification is unavailable") from error


def _require_branch(value: str) -> None:
    if not isinstance(value, str) or not _BRANCH.fullmatch(value) or ".." in value or value.endswith("/"):
        raise GitIdentityError("Git branch identity is invalid")


def _require_token(value: str, name: str) -> None:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise GitIdentityError(f"{name} is invalid")
