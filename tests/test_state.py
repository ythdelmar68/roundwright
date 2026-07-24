"""Hermetic coverage for repository-local SQLite migrations."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright import cli
from roundwright.state import DatabaseStatus, Migration, StateError, _apply_migrations, check_database, database_path, initialize


class StateTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        identity = object.__new__(RepositoryIdentity)
        object.__setattr__(identity, "root", root.resolve())
        return identity

    def test_initialization_is_idempotent_and_check_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            self.assertEqual(initialize(repository).state, "healthy")
            identity = check_database(repository).identity
            before = database_path(repository).read_bytes()
            self.assertEqual(initialize(repository).state, "healthy")
            self.assertEqual(check_database(repository).identity, identity)
            self.assertEqual(before, database_path(repository).read_bytes())

    def test_missing_checksum_and_future_schema_fail_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            path = database_path(repository)
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE schema_migrations SET checksum = 'changed'")
                connection.commit()
            finally:
                connection.close()
            self.assertEqual(check_database(repository).state, "incompatible")
            connection = sqlite3.connect(path)
            try:
                connection.execute("UPDATE schema_migrations SET checksum = 'changed' WHERE version = 1")
                connection.execute("INSERT INTO schema_migrations VALUES (2, 'future')")
                connection.commit()
            finally:
                connection.close()
            self.assertEqual(check_database(repository).state, "incompatible")

    def test_partial_schema_cannot_be_accepted_or_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            path = database_path(repository)
            connection = sqlite3.connect(path)
            try:
                connection.execute("DROP TABLE state_metadata")
                connection.commit()
            finally:
                connection.close()
            before = path.read_bytes()
            self.assertEqual(check_database(repository).state, "incompatible")
            with self.assertRaises(StateError):
                initialize(repository)
            self.assertEqual(before, path.read_bytes())

    def test_unmanaged_schema_fails_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            path = database_path(repository)
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE unexpected_payload (id INTEGER)")
                connection.commit()
            finally:
                connection.close()
            before = path.read_bytes()
            self.assertEqual(check_database(repository).state, "incompatible")
            with self.assertRaises(StateError):
                initialize(repository)
            self.assertEqual(before, path.read_bytes())

    def test_unmanaged_non_table_schema_fails_without_repair(self) -> None:
        statements = (
            "CREATE VIEW unexpected_view AS SELECT 1 AS value",
            "CREATE INDEX unexpected_index ON state_metadata(value)",
            "CREATE TRIGGER unexpected_trigger AFTER INSERT ON state_metadata BEGIN SELECT 1; END",
        )
        for statement in statements:
            with self.subTest(statement=statement), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository(Path(temporary))
                initialize(repository)
                path = database_path(repository)
                connection = sqlite3.connect(path)
                try:
                    connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                before = path.read_bytes()
                self.assertEqual(check_database(repository).state, "incompatible")
                with self.assertRaises(StateError):
                    initialize(repository)
                self.assertEqual(before, path.read_bytes())

    def test_uri_reserved_path_reads_the_exact_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo#fragment"
            root.mkdir()
            repository = self.repository(root)
            self.assertEqual(initialize(repository).state, "healthy")
            self.assertEqual(check_database(repository).state, "healthy")

    def test_init_never_reports_ready_for_unhealthy_status(self) -> None:
        output = io.StringIO()
        configuration = mock.Mock(repository=self.repository(Path.cwd()))
        with mock.patch("roundwright.cli.load_configuration", return_value=configuration), mock.patch("roundwright.cli.preflight"), mock.patch("roundwright.cli.initialize", return_value=DatabaseStatus("corrupt", None, "verification failed")):
            self.assertEqual(cli._initialize(output), 2)
        self.assertIn("result: blocked", output.getvalue())
        self.assertNotIn("result: ready", output.getvalue())

    def test_failed_migration_rolls_back_every_schema_change(self) -> None:
        with sqlite3.connect(":memory:") as connection:
            broken = Migration(1, ("CREATE TABLE transient (id INTEGER)", "not valid SQL"), ())
            with self.assertRaises(sqlite3.DatabaseError):
                _apply_migrations(connection, (broken,))
            self.assertIsNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'transient'").fetchone())

    def test_cli_db_check_and_status_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            before = database_path(repository).read_bytes()
            output = io.StringIO()
            with mock.patch("roundwright.cli._repository", return_value=repository), mock.patch("subprocess.run") as subprocess_run:
                self.assertEqual(cli._check_database(output), 0)
                self.assertEqual(cli._render_status(output), 0)
            self.assertIn("state: healthy", output.getvalue())
            self.assertEqual(before, database_path(repository).read_bytes())
            subprocess_run.assert_not_called()

    def test_corrupt_database_is_reported_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            path = database_path(repository)
            path.parent.mkdir()
            path.write_bytes(b"not sqlite")
            self.assertEqual(check_database(repository).state, "corrupt")
