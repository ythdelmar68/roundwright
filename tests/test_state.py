"""Hermetic coverage for repository-local SQLite migrations."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.state import check_database, database_path, initialize


class StateTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        identity = object.__new__(RepositoryIdentity)
        object.__setattr__(identity, "root", root.resolve())
        return identity

    def test_initialization_is_idempotent_and_check_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            self.assertEqual(initialize(repository).state, "healthy")
            before = database_path(repository).read_bytes()
            self.assertEqual(initialize(repository).state, "healthy")
            self.assertEqual(check_database(repository).state, "healthy")
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

    def test_corrupt_database_is_reported_without_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            path = database_path(repository)
            path.parent.mkdir()
            path.write_bytes(b"not sqlite")
            self.assertEqual(check_database(repository).state, "corrupt")
