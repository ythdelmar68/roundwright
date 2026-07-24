"""Repository-local SQLite state with fail-closed migration verification."""

from __future__ import annotations

import hashlib
import sqlite3
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
)


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

    return repository.state_directory / "state.sqlite3"


def initialize(repository: RepositoryIdentity) -> DatabaseStatus:
    """Create or migrate the local database transactionally and idempotently."""

    path = database_path(repository)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(path)
        try:
            _apply_migrations(connection, MIGRATIONS)
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise StateError("local database is corrupt or unreadable") from error
    return check_database(repository)


def check_database(repository: RepositoryIdentity) -> DatabaseStatus:
    """Inspect local state without creating, repairing, or modifying it."""

    path = database_path(repository)
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


def _apply_migrations(connection: sqlite3.Connection, migrations: Iterable[Migration]) -> None:
    ordered = _validate_definitions(migrations)
    try:
        connection.execute("BEGIN IMMEDIATE")
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if not exists:
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
        _ensure_state_identity(connection)
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
    return ordered[-1].version if ordered else 0, _read_state_identity(connection)


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
        "WHERE type IN ('table', 'view', 'index', 'trigger') AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    if set(observed) != {('table', name) for name in expected}:
        raise StateError("database contains unmanaged or missing application schema")
    for name, statement in expected.items():
        row = connection.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        if row != ("table", statement):
            raise StateError("database schema does not match recorded migration")


def _ensure_state_identity(connection: sqlite3.Connection) -> None:
    row = connection.execute("SELECT value FROM state_metadata WHERE key = 'state_id'").fetchone()
    if row is None:
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
