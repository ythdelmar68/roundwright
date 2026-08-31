"""Hermetic native-host lifecycle parity for receipt-bound deployments.

The native host does not install software, start a scheduler, or run a child
process. It models the small product-owned boundary those integrations must
obey: installation admits only an already-claimed authority, a scheduler wake
uses the same one-shot admission path as a direct invocation, and one host
cannot have two active process lifecycles. Credential, provider, repository,
and GitHub capabilities remain outside this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from contextlib import closing
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
import sqlite3
from threading import RLock
from typing import Callable

from .deployment_handoff import (
    DeploymentAuthorityHandoffCoordinator,
    DeploymentAuthorityHandoffReceipt,
    DeploymentAuthorityIdentity,
)
from .runtime_binding import RuntimeBinding


class NativeHostError(ValueError):
    """Raised when a native-host value cannot be safely represented."""


class NativeHostState(str, Enum):
    """The complete process-local lifecycle of one installed host."""

    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"


class InvocationSource(str, Enum):
    """The two equivalent admission routes exposed to a native host."""

    ONE_SHOT = "one-shot"
    SCHEDULER_WAKE = "scheduler-wake"


_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_BRANCH_COMPONENT = re.compile(r"^[^ ~^:?*\\[\]\x00-\x1f\x7f]+$")
_DEFAULT_PROCESS_LEASE = timedelta(minutes=1)
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def _require_fingerprint(value: object, description: str) -> str:
    if type(value) is not str or not _FINGERPRINT.fullmatch(value):
        raise NativeHostError(f"{description} fingerprint is invalid")
    return value


def _require_process_id(value: object) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise NativeHostError("native host process identity is invalid")
    return value


@dataclass(frozen=True)
class NativeHostInstallation:
    """An opaque installed-host identity bound to one authority receipt."""

    installation_fingerprint: str
    identity: DeploymentAuthorityIdentity
    receipt: DeploymentAuthorityHandoffReceipt

    def __post_init__(self) -> None:
        _require_fingerprint(self.installation_fingerprint, "native host installation")
        if (
            type(self.identity) is not DeploymentAuthorityIdentity
            or type(self.receipt) is not DeploymentAuthorityHandoffReceipt
            or self.receipt.identity != self.identity
        ):
            raise NativeHostError("native host installation is not bound to its authority")


@dataclass(frozen=True)
class NativeHostDecision:
    """A public-safe installation, admission, or lifecycle disposition."""

    accepted: bool
    reason: str
    installation_fingerprint: str | None = None
    receipt_fingerprint: str | None = None
    process_id: str | None = None


@dataclass(frozen=True)
class NativeHostObservation:
    """Read-only, public-safe metadata observed from a mounted control store."""

    installation_fingerprint: str
    receipt_fingerprint: str
    candidate_sha: str

    def __post_init__(self) -> None:
        _require_fingerprint(self.installation_fingerprint, "observed native host installation")
        _require_fingerprint(self.receipt_fingerprint, "observed native host receipt")
        if type(self.candidate_sha) is not str or not _COMMIT.fullmatch(self.candidate_sha):
            raise NativeHostError("observed native host candidate SHA is invalid")


@dataclass(frozen=True)
class NativeHostMountedRuntimeEvidence:
    """Read-only Docker adapter binding persisted beside native-host truth.

    This deliberately contains identities, never configuration or
    authentication material.  It lets a non-authoritative consumer compare
    its mounted inputs with host-created SQLite evidence without granting that
    consumer any ability to create or refresh the evidence.
    """

    installation_fingerprint: str
    receipt_fingerprint: str
    candidate_sha: str
    runtime_binding: RuntimeBinding
    authentication_identity: str
    environment_fingerprint: str

    def __post_init__(self) -> None:
        for value, description in (
            (self.installation_fingerprint, "mounted native host installation"),
            (self.receipt_fingerprint, "mounted native host receipt"),
            (self.authentication_identity, "mounted authentication"),
            (self.environment_fingerprint, "mounted environment"),
        ):
            _require_fingerprint(value, description)
        if type(self.candidate_sha) is not str or not _COMMIT.fullmatch(self.candidate_sha):
            raise NativeHostError("mounted native host candidate SHA is invalid")
        if type(self.runtime_binding) is not RuntimeBinding:
            raise NativeHostError("mounted native host runtime binding is invalid")


@dataclass(frozen=True)
class NativeHostLifecycleObservation:
    """Read-only lifecycle facts for a mounted native-host control store."""

    installation: NativeHostObservation
    active_lock: bool
    completed_count: int
    cancelled_count: int
    recovered_count: int

    def __post_init__(self) -> None:
        if type(self.installation) is not NativeHostObservation or any(type(value) is not int or value < 0 for value in (self.completed_count, self.cancelled_count, self.recovered_count)):
            raise NativeHostError("native host lifecycle observation is invalid")


@dataclass(frozen=True)
class NativeHostPaths:
    """Platform-aware, public-safe locations used by a native-host wrapper.

    Resolving paths does not create them.  In particular, the authentication
    path is only a location for a later credential adapter; this module never
    reads it or accepts a credential value.
    """

    platform: str
    configuration: PurePath
    authentication: PurePath
    cache: PurePath
    state_directory: PurePath
    state_database: PurePath
    worktree: PurePath

    def __post_init__(self) -> None:
        if type(self.platform) is not str or not self.platform:
            raise NativeHostError("native host platform is invalid")
        path_type = _declared_path_type(self.platform)
        values = (
            self.configuration, self.authentication, self.cache, self.state_directory,
            self.state_database, self.worktree,
        )
        if not all(isinstance(value, PurePath) for value in values):
            raise NativeHostError("native host paths are invalid")
        configuration, authentication, cache, state_directory, state_database, worktree = (
            _coerce_declared_path(path_type, value) for value in values
        )
        if not all(value.is_absolute() for value in (
            configuration, authentication, cache, state_directory, state_database, worktree,
        )):
            raise NativeHostError("native host paths are not absolute for the declared platform")
        if any(".." in value.parts for value in (
            configuration, authentication, cache, state_directory, state_database, worktree,
        )):
            raise NativeHostError("native host paths must not contain parent segments")
        if authentication != configuration.parent / "auth.toml":
            raise NativeHostError("native host authentication path is not derived from configuration")
        if _paths_overlap(cache, state_directory) or _paths_overlap(cache, state_database):
            raise NativeHostError("native host cache and durable state paths must not overlap")
        if state_database != state_directory / "native-host.sqlite3":
            raise NativeHostError("native host state database is outside the declared state directory")

    @classmethod
    def resolve(
        cls,
        *,
        platform: str,
        environment: dict[str, str],
        home: PurePath,
        worktree: PurePath,
    ) -> "NativeHostPaths":
        if type(platform) is not str or not platform:
            raise NativeHostError("native host platform is invalid")
        if type(environment) is not dict or not all(type(key) is str and type(value) is str for key, value in environment.items()):
            raise NativeHostError("native host environment is invalid")
        if not isinstance(home, PurePath) or not isinstance(worktree, PurePath):
            raise NativeHostError("native host paths are invalid")
        path_type = _declared_path_type(platform)
        declared_home = _coerce_declared_path(path_type, home)
        if not declared_home.is_absolute():
            raise NativeHostError("native host home path is not absolute for the declared platform")
        declared_worktree = _coerce_declared_path(path_type, worktree)
        if not declared_worktree.is_absolute():
            raise NativeHostError("native host worktree path is not absolute for the declared platform")
        configuration, cache, state_directory = _declared_host_paths(platform, path_type, declared_home, environment)
        return cls(
            platform,
            _native_path_if_compatible(platform, configuration),
            _native_path_if_compatible(platform, configuration.parent / "auth.toml"),
            _native_path_if_compatible(platform, cache),
            _native_path_if_compatible(platform, state_directory),
            _native_path_if_compatible(platform, state_directory / "native-host.sqlite3"),
            _native_path_if_compatible(platform, declared_worktree),
        )

    def require_authoritative_worktree(self, candidate_sha: str) -> None:
        """Reject unavailable and detached Git worktrees before state mutation."""

        if not _COMMIT.fullmatch(candidate_sha):
            raise NativeHostError("native host candidate SHA is invalid")
        if not isinstance(self.worktree, Path):
            raise NativeHostError("native host worktree targets a different platform")
        if not self.worktree.is_dir():
            raise NativeHostError("native host worktree is unavailable")
        marker = self.worktree / ".git"
        if marker.is_dir():
            git_directory = marker
            head = marker / "HEAD"
        elif marker.is_file():
            try:
                line = marker.read_text(encoding="utf-8").strip()
            except OSError as error:
                raise NativeHostError("native host worktree marker is unreadable") from error
            if not line.startswith("gitdir: "):
                raise NativeHostError("native host worktree marker is invalid")
            git_directory = Path(line.removeprefix("gitdir: "))
            if not git_directory.is_absolute():
                try:
                    git_directory = (self.worktree / git_directory).resolve()
                except (OSError, RuntimeError, ValueError) as error:
                    raise NativeHostError("native host worktree Git directory resolution is unavailable") from error
            head = git_directory / "HEAD"
        else:
            raise NativeHostError("native host worktree is not a Git worktree")
        try:
            value = head.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise NativeHostError("native host worktree HEAD is unavailable") from error
        if not value.startswith("ref: refs/heads/"):
            raise NativeHostError("native host worktree is detached; select a bound branch before installation")
        reference = value.removeprefix("ref: ")
        _require_canonical_branch_reference(reference)
        resolved = _resolve_worktree_reference(_common_git_directory(git_directory), reference)
        if resolved is None:
            raise NativeHostError("native host worktree HEAD cannot resolve to a full SHA")
        if resolved != candidate_sha:
            raise NativeHostError("native host worktree HEAD does not match the installation candidate SHA")


class NativeHostControlStore:
    """SQLite-backed host lifecycle truth for one platform installation.

    The store owns only local process bookkeeping.  It cannot issue, refresh,
    or inspect deployment authority; callers must pass authority through the
    handoff coordinator before every state transition.
    """

    def __init__(self, database: Path) -> None:
        if not isinstance(database, Path) or database.name != "native-host.sqlite3":
            raise NativeHostError("native host state database path is invalid")
        self._database = database

    def install(self, installation: NativeHostInstallation) -> NativeHostDecision:
        try:
            self._database.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    expected = {
                        "installation_fingerprint": installation.installation_fingerprint,
                        "receipt_fingerprint": installation.receipt.receipt_fingerprint,
                        "candidate_sha": installation.identity.candidate_sha,
                    }
                    current = dict(connection.execute("SELECT key, value FROM native_host_metadata"))
                    if current and current != expected:
                        return self._denied(installation, "native host state belongs to a different receipt or candidate")
                    if not current:
                        connection.executemany(
                            "INSERT INTO native_host_metadata(key, value) VALUES (?, ?)", expected.items()
                        )
        except (OSError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable")
        return self._accepted(installation, "native host installation recorded")

    def verify(self, installation: NativeHostInstallation) -> NativeHostDecision:
        """Read a mounted installation without creating or repairing state.

        Docker consumers use this to prove that their host-owned SQLite input
        already belongs to the typed handoff installation.  Unlike ``install``
        it never creates a database or schema, which keeps read-only and
        test-only consumers incapable of manufacturing lifecycle evidence.
        """

        try:
            uri = self._database.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                if not self._matches(connection, installation):
                    return self._denied(installation, "native host state is not authoritative for this candidate")
        except (OSError, ValueError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable")
        return self._accepted(installation, "native host installation verified")

    def observe(self) -> NativeHostObservation:
        """Read mounted installation metadata without manufacturing lifecycle state."""

        try:
            uri = self._database.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                metadata = dict(connection.execute("SELECT key, value FROM native_host_metadata"))
            if set(metadata) != {"installation_fingerprint", "receipt_fingerprint", "candidate_sha"}:
                raise NativeHostError("native host state metadata is invalid")
            return NativeHostObservation(
                metadata["installation_fingerprint"], metadata["receipt_fingerprint"], metadata["candidate_sha"],
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            raise NativeHostError("native host state database is unavailable") from error

    def record_mounted_runtime_evidence(self, evidence: NativeHostMountedRuntimeEvidence) -> NativeHostDecision:
        """Persist host-created Docker mount identities after installation.

        Qualification setup is the only caller permitted to create this row.
        Consumer preflight uses :meth:`verify_mounted_runtime_evidence`, which
        opens the database read-only and therefore cannot manufacture it.
        """

        if type(evidence) is not NativeHostMountedRuntimeEvidence:
            raise NativeHostError("mounted runtime evidence is invalid")
        try:
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    metadata = dict(connection.execute("SELECT key, value FROM native_host_metadata"))
                    if metadata != {
                        "installation_fingerprint": evidence.installation_fingerprint,
                        "receipt_fingerprint": evidence.receipt_fingerprint,
                        "candidate_sha": evidence.candidate_sha,
                    }:
                        return NativeHostDecision(False, "native host state is not authoritative for mounted evidence")
                    expected = self._mounted_runtime_values(evidence)
                    current = dict(connection.execute("SELECT key, value FROM native_host_mounted_runtime"))
                    if current and current != expected:
                        return NativeHostDecision(False, "native host mounted evidence conflicts")
                    if not current:
                        connection.executemany(
                            "INSERT INTO native_host_mounted_runtime(key, value) VALUES (?, ?)", expected.items()
                        )
        except (OSError, sqlite3.Error):
            return NativeHostDecision(False, "native host state database is unavailable")
        return NativeHostDecision(True, "native host mounted evidence recorded")

    def verify_mounted_runtime_evidence(self, evidence: NativeHostMountedRuntimeEvidence) -> NativeHostDecision:
        """Read and compare complete mounted identities without state mutation."""

        if type(evidence) is not NativeHostMountedRuntimeEvidence:
            raise NativeHostError("mounted runtime evidence is invalid")
        try:
            uri = self._database.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                metadata = dict(connection.execute("SELECT key, value FROM native_host_metadata"))
                current = dict(connection.execute("SELECT key, value FROM native_host_mounted_runtime"))
            if metadata != {
                "installation_fingerprint": evidence.installation_fingerprint,
                "receipt_fingerprint": evidence.receipt_fingerprint,
                "candidate_sha": evidence.candidate_sha,
            } or current != self._mounted_runtime_values(evidence):
                return NativeHostDecision(False, "native host mounted evidence is mismatched")
        except (OSError, ValueError, sqlite3.Error):
            return NativeHostDecision(False, "native host state database is unavailable")
        return NativeHostDecision(True, "native host mounted evidence verified")

    def observe_lifecycle(self) -> NativeHostLifecycleObservation:
        """Return persisted lifecycle facts without acquiring a lock or mutating state."""

        try:
            uri = self._database.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                metadata = dict(connection.execute("SELECT key, value FROM native_host_metadata"))
                if set(metadata) != {"installation_fingerprint", "receipt_fingerprint", "candidate_sha"}:
                    raise NativeHostError("native host state metadata is invalid")
                states = dict(connection.execute("SELECT state, COUNT(*) FROM native_host_process GROUP BY state"))
            if set(states).difference({"running", "completed", "cancelled", "recovered"}):
                raise NativeHostError("native host process state is invalid")
            return NativeHostLifecycleObservation(
                NativeHostObservation(metadata["installation_fingerprint"], metadata["receipt_fingerprint"], metadata["candidate_sha"]),
                states.get("running", 0) > 0, states.get("completed", 0), states.get("cancelled", 0), states.get("recovered", 0),
            )
        except (OSError, ValueError, sqlite3.Error) as error:
            raise NativeHostError("native host state database is unavailable") from error

    def admit(self, installation: NativeHostInstallation, process_id: str, source: InvocationSource, *, now: datetime, lease_for: timedelta = _DEFAULT_PROCESS_LEASE) -> NativeHostDecision:
        if type(lease_for) is not timedelta or lease_for <= timedelta():
            raise NativeHostError("native host process lease is invalid")
        try:
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    if not self._matches(connection, installation):
                        return self._denied(installation, "native host state is not authoritative for this candidate", process_id)
                    active = connection.execute(
                        "SELECT process_id FROM native_host_process WHERE state = 'running'"
                    ).fetchone()
                    if active is not None:
                        return self._denied(installation, "native host lock has an active process", process_id)
                    previous = connection.execute(
                        "SELECT process_id FROM native_host_process WHERE process_id = ?", (process_id,)
                    ).fetchone()
                    if previous is not None:
                        return self._denied(installation, "native host process identity was already consumed", process_id)
                    connection.execute(
                        "INSERT INTO native_host_process(process_id, receipt_fingerprint, candidate_sha, source, state, started_at, lease_expires_at, updated_at) VALUES (?, ?, ?, ?, 'running', ?, ?, ?)",
                        (process_id, installation.receipt.receipt_fingerprint, installation.identity.candidate_sha, source.value, _timestamp(now), _timestamp(now) + _timedelta_microseconds(lease_for), _timestamp(now)),
                    )
        except (OSError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable", process_id)
        return self._accepted(installation, f"native host {source.value} process admitted", process_id)

    def renew_lease(self, installation: NativeHostInstallation, process_id: str, *, now: datetime, lease_for: timedelta) -> NativeHostDecision:
        if type(lease_for) is not timedelta or lease_for <= timedelta():
            raise NativeHostError("native host process lease is invalid")
        try:
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    if not self._matches(connection, installation):
                        return self._denied(installation, "native host state is not authoritative for this candidate", process_id)
                    result = connection.execute(
                        "UPDATE native_host_process SET lease_expires_at = ?, updated_at = ? WHERE process_id = ? AND state = 'running'",
                        (_timestamp(now) + _timedelta_microseconds(lease_for), _timestamp(now), process_id),
                    )
                    if result.rowcount != 1:
                        return self._denied(installation, "native host process is not active", process_id)
        except (OSError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable", process_id)
        return self._accepted(installation, "native host process lease renewed", process_id)

    def finish(self, installation: NativeHostInstallation, process_id: str, state: str, *, now: datetime) -> NativeHostDecision:
        if state not in {"completed", "cancelled", "recovered"}:
            raise NativeHostError("native host terminal state is invalid")
        try:
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    if not self._matches(connection, installation):
                        return self._denied(installation, "native host state is not authoritative for this candidate", process_id)
                    row = connection.execute(
                        "SELECT state FROM native_host_process WHERE process_id = ?", (process_id,)
                    ).fetchone()
                    if row is None:
                        return self._denied(installation, "native host process is not active", process_id)
                    if row[0] != "running":
                        if state == "cancelled" and row[0] == "cancelled":
                            return self._accepted(installation, "native host process is already cancelled", process_id)
                        return self._denied(installation, "native host process is not active", process_id)
                    connection.execute(
                        "UPDATE native_host_process SET state = ?, updated_at = ? WHERE process_id = ?",
                        (state, _timestamp(now), process_id),
                    )
        except (OSError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable", process_id)
        return self._accepted(installation, f"native host process {state}", process_id)

    def recover_stale(self, installation: NativeHostInstallation, process_id: str, *, now: datetime, stale_after: timedelta) -> NativeHostDecision:
        if type(stale_after) is not timedelta or stale_after <= timedelta():
            raise NativeHostError("native host stale-child interval is invalid")
        try:
            with closing(self._connection()) as connection:
                with connection:
                    self._prepare(connection)
                    if not self._matches(connection, installation):
                        return self._denied(installation, "native host state is not authoritative for this candidate", process_id)
                    row = connection.execute(
                        "SELECT state, started_at, lease_expires_at FROM native_host_process WHERE process_id = ?", (process_id,)
                    ).fetchone()
                    if row is None or row[0] != "running":
                        return self._denied(installation, "native host process is not an active stale child", process_id)
                    if _timestamp(now) < row[1] + _timedelta_microseconds(stale_after) or _timestamp(now) < row[2]:
                        return self._denied(installation, "native host child has a live lease or is not stale", process_id)
                    connection.execute(
                        "UPDATE native_host_process SET state = 'recovered', updated_at = ? WHERE process_id = ?",
                        (_timestamp(now), process_id),
                    )
        except (OSError, sqlite3.Error):
            return self._denied(installation, "native host state database is unavailable", process_id)
        return self._accepted(installation, "native host stale child recovered", process_id)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database, isolation_level=None)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 1000")
        connection.execute("BEGIN IMMEDIATE")
        return connection

    @staticmethod
    def _prepare(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE IF NOT EXISTS native_host_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS native_host_mounted_runtime (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("CREATE TABLE IF NOT EXISTS native_host_process (process_id TEXT PRIMARY KEY, receipt_fingerprint TEXT NOT NULL, candidate_sha TEXT NOT NULL, source TEXT NOT NULL, state TEXT NOT NULL, started_at INTEGER NOT NULL, lease_expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)")

    @staticmethod
    def _mounted_runtime_values(evidence: NativeHostMountedRuntimeEvidence) -> dict[str, str]:
        return {
            "authentication_identity": evidence.authentication_identity,
            "environment_fingerprint": evidence.environment_fingerprint,
            "runtime_binding": evidence.runtime_binding.canonical_material(),
        }

    @staticmethod
    def _matches(connection: sqlite3.Connection, installation: NativeHostInstallation) -> bool:
        return dict(connection.execute("SELECT key, value FROM native_host_metadata")) == {
            "installation_fingerprint": installation.installation_fingerprint,
            "receipt_fingerprint": installation.receipt.receipt_fingerprint,
            "candidate_sha": installation.identity.candidate_sha,
        }

    @staticmethod
    def _accepted(installation: NativeHostInstallation, reason: str, process_id: str | None = None) -> NativeHostDecision:
        return NativeHostDecision(True, reason, installation.installation_fingerprint, installation.receipt.receipt_fingerprint, process_id)

    @staticmethod
    def _denied(installation: NativeHostInstallation, reason: str, process_id: str | None = None) -> NativeHostDecision:
        return NativeHostDecision(False, reason, installation.installation_fingerprint, installation.receipt.receipt_fingerprint, process_id)


def _timestamp(value: object) -> int:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise NativeHostError("native host timestamp must be an aware UTC datetime")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return _timedelta_microseconds(value - epoch)


def _timedelta_microseconds(value: timedelta) -> int:
    return value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds


def _declared_path_type(platform: str) -> type[PureWindowsPath] | type[PurePosixPath]:
    if platform.startswith("win"):
        return PureWindowsPath
    if platform == "darwin" or platform.startswith("linux"):
        return PurePosixPath
    raise NativeHostError("native host platform is unsupported")


def _declared_host_paths(
    platform: str,
    path_type: type[PureWindowsPath] | type[PurePosixPath],
    home: PurePath,
    environment: dict[str, str],
) -> tuple[PurePath, PurePath, PurePath]:
    if platform.startswith("win"):
        configuration_root = _declared_environment_directory(
            environment, "APPDATA", home / "AppData" / "Roaming", path_type
        )
        cache_root = _declared_environment_directory(
            environment, "LOCALAPPDATA", home / "AppData" / "Local", path_type
        )
        return configuration_root / "Roundwright" / "config.toml", cache_root / "Roundwright" / "Cache", cache_root / "Roundwright" / "State"
    if platform == "darwin":
        return home / "Library" / "Application Support" / "roundwright" / "config.toml", home / "Library" / "Caches" / "roundwright", home / "Library" / "Application Support" / "roundwright" / "state"
    configuration_root = _declared_environment_directory(environment, "XDG_CONFIG_HOME", home / ".config", path_type)
    cache_root = _declared_environment_directory(environment, "XDG_CACHE_HOME", home / ".cache", path_type)
    state_root = _declared_environment_directory(environment, "XDG_STATE_HOME", home / ".local" / "state", path_type)
    return configuration_root / "roundwright" / "config.toml", cache_root / "roundwright", state_root / "roundwright"


def _coerce_declared_path(path_type: type[PureWindowsPath] | type[PurePosixPath], value: PurePath) -> PurePath:
    text = str(value)
    return path_type(text.replace("\\", "/") if path_type is PurePosixPath else text)


def _paths_overlap(left: PurePath, right: PurePath) -> bool:
    """Return whether either declared-platform path contains the other."""

    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _declared_environment_directory(
    environment: dict[str, str], key: str, default: PurePath, path_type: type[PureWindowsPath] | type[PurePosixPath]
) -> PurePath:
    value = path_type(environment[key]) if key in environment else default
    if not value.is_absolute():
        raise NativeHostError(f"native host {key} path is not absolute for the declared platform")
    return value


def _native_path_if_compatible(platform: str, value: PurePath) -> PurePath:
    host_is_windows = Path("C:/").is_absolute()
    declared_is_windows = platform.startswith("win")
    return Path(str(value)) if host_is_windows == declared_is_windows else value


def _common_git_directory(git_directory: Path) -> Path:
    marker = git_directory / "commondir"
    if not marker.is_file():
        return git_directory
    try:
        value = marker.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise NativeHostError("native host linked worktree common directory is unavailable") from error
    if not value:
        raise NativeHostError("native host linked worktree common directory is invalid")
    common = Path(value)
    if common.is_absolute():
        return common
    try:
        return (git_directory / common).resolve()
    except (OSError, RuntimeError, ValueError) as error:
        raise NativeHostError("native host linked worktree common directory resolution is unavailable") from error


def _resolve_worktree_reference(git_directory: Path, reference: str) -> str | None:
    _require_canonical_branch_reference(reference)
    try:
        root = git_directory.resolve()
        loose_path = root.joinpath(*reference.split("/"))
        resolved_loose_path = loose_path.resolve()
        resolved_loose_path.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise NativeHostError("native host worktree reference resolution is unavailable or escapes the Git directory") from error
    try:
        value = resolved_loose_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        value = None
    except OSError as error:
        raise NativeHostError("native host loose worktree reference is unreadable") from error
    if value is not None and not _COMMIT.fullmatch(value):
        raise NativeHostError("native host loose worktree reference is malformed")
    if value is not None:
        return value
    try:
        packed = (git_directory / "packed-refs").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in packed:
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1] == reference and _COMMIT.fullmatch(parts[0]):
            return parts[0]
    return None


def _require_canonical_branch_reference(reference: object) -> str:
    if type(reference) is not str or not reference.startswith("refs/heads/"):
        raise NativeHostError("native host worktree reference is not a branch reference")
    parts = reference.split("/")
    if len(parts) < 3 or "@{" in reference or any(part in {"", ".", ".."} or part.startswith(".") or ".." in part or part.endswith(".") or part.endswith(".lock") or not _BRANCH_COMPONENT.fullmatch(part) for part in parts):
        raise NativeHostError("native host worktree reference is malformed")
    return reference


class NativeHost:
    """Serialize one host's installation and process lifecycle in memory.

    A production native host may persist equivalent machine truth, but it must
    not use this process-local object as a source of authority. Each action
    revalidates the already-claimed receipt through the handoff coordinator.
    """

    def __init__(
        self,
        coordinator: DeploymentAuthorityHandoffCoordinator,
        installation: NativeHostInstallation,
        control_store: NativeHostControlStore | None = None,
    ) -> None:
        if type(coordinator) is not DeploymentAuthorityHandoffCoordinator or type(installation) is not NativeHostInstallation:
            raise NativeHostError("native host installation is invalid")
        if control_store is not None and type(control_store) is not NativeHostControlStore:
            raise NativeHostError("native host control store is invalid")
        self._coordinator = coordinator
        self._installation = installation
        self._control_store = control_store
        self._lock = RLock()
        self._state = NativeHostState.IDLE
        self._active_process_id: str | None = None
        self._consumed_process_ids: set[str] = set()

    @property
    def state(self) -> NativeHostState:
        with self._lock:
            return self._state

    @property
    def installation(self) -> NativeHostInstallation:
        return self._installation

    def run_once(self, process_id: str, *, now: object) -> NativeHostDecision:
        """Admit one direct process using the same receipt check as a wake."""

        return self._start(process_id, InvocationSource.ONE_SHOT, now=now)

    def request_scheduler_wake(self, process_id: str, *, now: object) -> NativeHostDecision:
        """Translate an authorized scheduler request into one normal start.

        The scheduler cannot claim, renew, install, or transfer authority; it
        merely supplies the source of an invocation that must pass the exact
        same admission check as :meth:`run_once`.
        """

        process = _require_process_id(process_id)
        wake = self._coordinator.request_scheduler_wakeup(
            self._installation.identity, self._installation.receipt, now=now
        )
        if not wake.requested:
            return self._denied(wake.reason, process)
        return self._start(process, InvocationSource.SCHEDULER_WAKE, now=now)

    def complete(self, process_id: str, *, now: datetime | None = None) -> NativeHostDecision:
        """Finish exactly the active process and return the host to idle."""

        process = _require_process_id(process_id)
        timestamp = _now_utc() if now is None else now
        _timestamp(timestamp)
        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._denied("native host is stopped", process)
            if self._state is not NativeHostState.RUNNING or self._active_process_id != process:
                return self._denied("native host process is not active", process)

            def transition() -> NativeHostDecision:
                if self._control_store is not None:
                    decision = self._control_store.finish(self._installation, process, "completed", now=timestamp)
                    if not decision.accepted:
                        return decision
                self._active_process_id = None
                self._state = NativeHostState.IDLE
                return self._accepted("native host process completed", process)

            return self._run_authorized_transition(process, now=timestamp, transition=transition)

    def cancel(self, process_id: str, *, now: datetime) -> NativeHostDecision:
        """Cancel only the current child; a repeated cancellation is idempotent."""

        process = _require_process_id(process_id)
        _timestamp(now)
        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._denied("native host is stopped", process)
            if self._state is NativeHostState.IDLE and self._control_store is not None and process in self._consumed_process_ids:
                def transition() -> NativeHostDecision:
                    decision = self._control_store.finish(self._installation, process, "cancelled", now=now)
                    if not decision.accepted:
                        return decision
                    return self._accepted("native host process is already cancelled", process)

                return self._run_authorized_transition(process, now=now, transition=transition)
            if self._state is not NativeHostState.RUNNING or self._active_process_id != process:
                return self._denied("native host process is not active", process)

            def transition() -> NativeHostDecision:
                if self._control_store is not None:
                    decision = self._control_store.finish(self._installation, process, "cancelled", now=now)
                    if not decision.accepted:
                        return decision
                self._active_process_id = None
                self._state = NativeHostState.IDLE
                return self._accepted("native host process cancelled", process)

            return self._run_authorized_transition(process, now=now, transition=transition)

    def renew_child_lease(self, process_id: str, *, now: datetime, lease_for: timedelta = _DEFAULT_PROCESS_LEASE) -> NativeHostDecision:
        """Renew only this host's active child lease before stale recovery."""

        process = _require_process_id(process_id)
        _timestamp(now)
        if self._control_store is None:
            return self._denied("native host has no durable child lease", process)
        with self._lock:
            if self._state is not NativeHostState.RUNNING or self._active_process_id != process:
                return self._denied("native host process is not active", process)
            return self._run_authorized_transition(
                process, now=now,
                transition=lambda: self._control_store.renew_lease(
                    self._installation, process, now=now, lease_for=lease_for,
                ),
            )

    def recover_stale_child(self, process_id: str, *, now: datetime, stale_after: timedelta) -> NativeHostDecision:
        """Release a persisted child only after the explicit stale interval."""

        process = _require_process_id(process_id)
        _timestamp(now)
        if self._control_store is None:
            return self._denied("native host has no durable child state to recover", process)
        with self._lock:
            def transition() -> NativeHostDecision:
                decision = self._control_store.recover_stale(self._installation, process, now=now, stale_after=stale_after)
                if not decision.accepted:
                    return decision
                if self._active_process_id == process:
                    self._active_process_id = None
                    self._state = NativeHostState.IDLE
                return decision

            return self._run_authorized_transition(process, now=now, transition=transition)

    def execute_one_shot(self, process_id: str, action: Callable[[], None], *, now: datetime) -> NativeHostDecision:
        """Run an injected native child behind durable admission and cleanup.

        The action is intentionally supplied by the platform wrapper.  This
        boundary never selects an executable, credentials, or a provider.
        """

        if not callable(action):
            raise NativeHostError("native host one-shot action is invalid")
        decision = self.run_once(process_id, now=now)
        if not decision.accepted:
            return decision
        try:
            action()
        except BaseException:
            self.cancel(process_id, now=now)
            raise
        return self.complete(process_id, now=now)

    def stop(self) -> NativeHostDecision:
        """Stop only an idle host; a running process must reconcile first."""

        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._accepted("native host is already stopped", None)
            if self._state is NativeHostState.RUNNING:
                return self._denied("native host has an active process", self._active_process_id)
            self._state = NativeHostState.STOPPED
            return self._accepted("native host stopped", None)

    def _run_authorized_transition(
        self, process_id: str, *, now: datetime, transition: Callable[[], NativeHostDecision],
    ) -> NativeHostDecision:
        authority, decision = self._coordinator.transition_if_authorized(
            self._installation.identity, self._installation.receipt, now=now, transition=transition,
        )
        if not authority.authorized:
            return self._denied(authority.reason, process_id)
        if type(decision) is not NativeHostDecision:
            raise NativeHostError("native host authority transition returned an invalid decision")
        return decision

    def _start(self, process_id: str, source: InvocationSource, *, now: object) -> NativeHostDecision:
        process = _require_process_id(process_id)
        if type(source) is not InvocationSource:
            raise NativeHostError("native host invocation source is invalid")
        with self._lock:
            if self._state is NativeHostState.STOPPED:
                return self._denied("native host is stopped", process)
            if self._state is NativeHostState.RUNNING:
                return self._denied("native host already has an active process", process)
            if process in self._consumed_process_ids:
                return self._denied("native host process identity was already consumed", process)

            def transition() -> NativeHostDecision:
                if self._control_store is not None:
                    durable = self._control_store.admit(self._installation, process, source, now=now)
                    if not durable.accepted:
                        return durable
                self._consumed_process_ids.add(process)
                self._active_process_id = process
                self._state = NativeHostState.RUNNING
                return self._accepted(f"native host {source.value} process admitted", process)

            return self._run_authorized_transition(process, now=now, transition=transition)

    def _accepted(self, reason: str, process_id: str | None) -> NativeHostDecision:
        return NativeHostDecision(
            True, reason, self._installation.installation_fingerprint,
            self._installation.receipt.receipt_fingerprint, process_id,
        )

    def _denied(self, reason: str, process_id: str | None) -> NativeHostDecision:
        return NativeHostDecision(
            False, reason, self._installation.installation_fingerprint,
            self._installation.receipt.receipt_fingerprint, process_id,
        )


def install_native_host(
    coordinator: DeploymentAuthorityHandoffCoordinator,
    installation: NativeHostInstallation,
    *,
    now: object,
    paths: NativeHostPaths | None = None,
) -> tuple[NativeHost | None, NativeHostDecision]:
    """Install a host only after its exact receipt is already authorized.

    When platform paths are supplied, installation records local SQLite
    machine truth only after authority admission and a bound worktree check.
    It does not create a service, read credentials, or start a scheduler.
    """

    if type(coordinator) is not DeploymentAuthorityHandoffCoordinator or type(installation) is not NativeHostInstallation:
        raise NativeHostError("native host installation is invalid")
    if paths is not None and type(paths) is not NativeHostPaths:
        raise NativeHostError("native host paths are invalid")
    def transition() -> tuple[NativeHost | None, NativeHostDecision]:
        admitted = NativeHostDecision(
            True, "native host installation admitted",
            installation.installation_fingerprint, installation.receipt.receipt_fingerprint,
        )
        if paths is None:
            return NativeHost(coordinator, installation), admitted
        try:
            paths.require_authoritative_worktree(installation.identity.candidate_sha)
        except NativeHostError as error:
            return None, NativeHostDecision(
                False, str(error), installation.installation_fingerprint,
                installation.receipt.receipt_fingerprint,
            )
        control_store = NativeHostControlStore(paths.state_database)
        durable = control_store.install(installation)
        if not durable.accepted:
            return None, durable
        return NativeHost(coordinator, installation, control_store), durable

    authority, result = coordinator.transition_if_authorized(
        installation.identity, installation.receipt, now=now, transition=transition,
    )
    if not authority.authorized:
        return None, NativeHostDecision(
            False, authority.reason, installation.installation_fingerprint,
            installation.receipt.receipt_fingerprint,
        )
    if (
        type(result) is not tuple or len(result) != 2
        or (result[0] is not None and type(result[0]) is not NativeHost)
        or type(result[1]) is not NativeHostDecision
    ):
        raise NativeHostError("native host authority transition returned an invalid installation result")
    return result


def _now_utc() -> datetime:
    """Use a UTC timestamp for compatibility-only completion calls."""

    return datetime.now(timezone.utc)
