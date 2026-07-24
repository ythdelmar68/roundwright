"""Repository-local SQLite state with fail-closed migration verification."""

from __future__ import annotations

import hashlib
import sqlite3
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
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            version = _verify_migrations(connection, MIGRATIONS)
        finally:
            connection.close()
    except StateError as error:
        return DatabaseStatus("incompatible", None, str(error))
    except sqlite3.DatabaseError:
        return DatabaseStatus("corrupt", None, "local database is corrupt or unreadable")
    return DatabaseStatus("healthy", version, "migration checksums verified")


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
        _validate_schema(connection, ordered)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _verify_migrations(connection: sqlite3.Connection, migrations: Iterable[Migration]) -> int:
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
    return ordered[-1].version if ordered else 0


def _validate_definitions(migrations: Iterable[Migration]) -> tuple[Migration, ...]:
    ordered = tuple(migrations)
    versions = tuple(migration.version for migration in ordered)
    if not ordered or any(version < 1 for version in versions) or versions != tuple(range(1, len(ordered) + 1)):
        raise StateError("migration definitions are invalid or duplicate")
    return ordered


def _validate_schema(connection: sqlite3.Connection, migrations: Iterable[Migration]) -> None:
    expected = {name: statement for migration in migrations for name, statement in migration.schema}
    for name, statement in expected.items():
        row = connection.execute(
            "SELECT type, sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        if row != ("table", statement):
            raise StateError("database schema does not match recorded migration")


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
