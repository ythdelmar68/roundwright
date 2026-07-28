"""Hermetic coverage for repository-local SQLite migrations."""

from __future__ import annotations

import sqlite3
import os
import subprocess
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
from roundwright.state import (
    DatabaseStatus,
    Migration,
    SourceSnapshot,
    StateError,
    TaskIdentity,
    _apply_migrations,
    _is_reparse_point,
    admit_task,
    check_database,
    database_path,
    initialize,
    record_artifact,
    set_blocker,
    set_next_action,
    task_projection,
    transition_task,
)


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
                connection.execute("INSERT INTO schema_migrations VALUES (3, 'future')")
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

    def test_sqliteevil_and_non_table_schema_fail_without_repair(self) -> None:
        statements = (
            "CREATE TABLE sqliteevil (id INTEGER)",
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

    def test_init_refuses_unsafe_entrypoint_before_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            output = io.StringIO()
            configuration = mock.Mock(repository=repository)
            with mock.patch("roundwright.cli.require_safe_entrypoint_identity", side_effect=cli.UnsafeEntrypointIdentityError("more than one command executable was discovered")), mock.patch("roundwright.cli.load_configuration", return_value=configuration):
                self.assertEqual(cli._initialize(output), 2)
            self.assertFalse(database_path(repository).exists())
            self.assertIn("result: blocked", output.getvalue())

    def test_local_state_is_ignored_but_repository_toml_is_trackable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / ".gitignore").write_text(".roundwright/\n", encoding="utf-8")
            repository = self.repository(root)
            initialize(repository)
            (root / ".roundwright.toml").write_text("[roundwright]\n", encoding="utf-8")
            ignored = subprocess.run(["git", "check-ignore", ".roundwright/state.sqlite3"], cwd=root, capture_output=True, text=True)
            tracked = subprocess.run(["git", "check-ignore", ".roundwright.toml"], cwd=root, capture_output=True, text=True)
            self.assertEqual(ignored.returncode, 0)
            self.assertEqual(tracked.returncode, 1)

    def test_missing_or_malformed_identity_never_remints(self) -> None:
        for value in (None, "malformed"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository(Path(temporary))
                initialize(repository)
                path = database_path(repository)
                connection = sqlite3.connect(path)
                try:
                    if value is None:
                        connection.execute("DELETE FROM state_metadata WHERE key = 'state_id'")
                    else:
                        connection.execute("UPDATE state_metadata SET value = ? WHERE key = 'state_id'", (value,))
                    connection.commit()
                finally:
                    connection.close()
                before = path.read_bytes()
                self.assertEqual(check_database(repository).state, "incompatible")
                with self.assertRaises(StateError):
                    initialize(repository)
                self.assertEqual(before, path.read_bytes())

    def test_truncated_existing_database_never_remints_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            path = database_path(repository)
            path.write_bytes(b"")
            before = path.read_bytes()
            self.assertEqual(check_database(repository).state, "incompatible")
            with self.assertRaises(StateError):
                initialize(repository)
            self.assertEqual(before, path.read_bytes())

    def test_state_directory_collision_is_owner_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            repository.state_directory.write_text("collision", encoding="utf-8")
            self.assertEqual(check_database(repository).state, "incompatible")
            configuration = mock.Mock(repository=repository)
            output = io.StringIO()
            with mock.patch("roundwright.cli.load_configuration", return_value=configuration), mock.patch("roundwright.cli.preflight"):
                self.assertEqual(cli._initialize(output), 2)
            self.assertIn("result: blocked", output.getvalue())

    def test_database_symlink_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            repository = self.repository(Path(temporary))
            target = Path(outside) / "outside.sqlite3"
            target.write_bytes(b"outside")
            repository.state_directory.mkdir()
            link = repository.state_directory / "state.sqlite3"
            try:
                os.symlink(target, link)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            self.assertEqual(check_database(repository).state, "incompatible")
            self.assertEqual(target.read_bytes(), b"outside")

    def test_ordinary_database_entry_is_not_a_reparse_point(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.sqlite3"
            path.write_bytes(b"ordinary")
            self.assertFalse(_is_reparse_point(path))

    def test_dangling_database_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            repository.state_directory.mkdir()
            link = repository.state_directory / "state.sqlite3"
            try:
                os.symlink(Path(temporary) / "missing.sqlite3", link)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            self.assertEqual(check_database(repository).state, "incompatible")
            with self.assertRaises(StateError):
                initialize(repository)

    def test_status_renders_schema_identity_and_detail_for_each_state(self) -> None:
        for status, code in (
            (DatabaseStatus("healthy", 1, "verified", "identity"), 0),
            (DatabaseStatus("missing", None, "run roundwright init"), 0),
            (DatabaseStatus("incompatible", None, "schema changed"), 2),
            (DatabaseStatus("corrupt", None, "database unreadable"), 2),
        ):
            with self.subTest(state=status.state):
                output = io.StringIO()
                with mock.patch("roundwright.cli._repository"), mock.patch("roundwright.cli.check_database", return_value=status):
                    self.assertEqual(cli._render_status(output), code)
                rendered = output.getvalue()
                self.assertIn("schema:", rendered)
                self.assertIn("state identity:", rendered)
                self.assertIn("detail:", rendered)

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

    def task_identity(self) -> TaskIdentity:
        return TaskIdentity(
            task_id="task-19",
            source_id="local-fixture",
            repository_id="ythdelmar68/roundwright",
            branch="codex/issue-19",
            worktree="C:/private/worktree",
            base_sha="b" * 40,
        )

    def source_snapshot(self) -> SourceSnapshot:
        return SourceSnapshot(
            source_id="local-fixture",
            repository_id="ythdelmar68/roundwright",
            source_digest="a" * 64,
        )

    def identity_for(self, suffix: str) -> TaskIdentity:
        return TaskIdentity(
            task_id=f"task-19-{suffix}",
            source_id=f"local-fixture-{suffix}",
            repository_id="ythdelmar68/roundwright",
            branch=f"codex/issue-19-{suffix}",
            worktree=f"C:/private/worktree-{suffix}",
            base_sha="b" * 40,
        )

    def source_for(self, suffix: str) -> SourceSnapshot:
        return SourceSnapshot(f"local-fixture-{suffix}", "ythdelmar68/roundwright", (suffix * 64)[:64])

    def test_phase_two_migration_persists_one_source_task_and_owner_safe_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            self.assertEqual(initialize(repository).version, 2)
            projection = admit_task(repository, self.task_identity(), (self.source_snapshot(),))
            self.assertEqual(projection.state, "queued")
            self.assertEqual(projection.base_sha, "b" * 40)
            self.assertNotIn("private", repr(projection))
            self.assertNotIn("worktree", repr(projection))
            self.assertEqual(projection, task_projection(repository, self.task_identity()))

    def test_lifecycle_rejects_invalid_regressive_duplicate_and_mismatched_transitions_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = self.task_identity()
            admit_task(repository, identity, (self.source_snapshot(),))
            with self.assertRaises(StateError):
                transition_task(repository, identity, expected_state="queued", next_state="implementing", evidence_fingerprint="c" * 64)
            self.assertEqual(task_projection(repository, identity).state, "queued")
            transitioned = transition_task(repository, identity, expected_state="queued", next_state="planning", evidence_fingerprint="c" * 64)
            self.assertEqual(transitioned.state, "planning")
            with self.assertRaises(StateError):
                transition_task(repository, identity, expected_state="planning", next_state="plan-review", evidence_fingerprint="c" * 64)
            self.assertEqual(task_projection(repository, identity).state, "planning")
            with self.assertRaises(StateError):
                transition_task(repository, identity, expected_state="planning", next_state="planning", evidence_fingerprint="d" * 64)
            mismatched = TaskIdentity(**{**identity.__dict__, "branch": "codex/other"})
            with self.assertRaises(StateError):
                transition_task(repository, mismatched, expected_state="planning", next_state="plan-review", evidence_fingerprint="e" * 64)
            self.assertEqual(task_projection(repository, identity).state, "planning")

    def test_blocked_recovery_and_committed_projection_references_are_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = self.task_identity()
            admit_task(repository, identity, (self.source_snapshot(),))
            transition_task(repository, identity, expected_state="queued", next_state="planning", evidence_fingerprint="c" * 64)
            transition_task(repository, identity, expected_state="planning", next_state="blocked", evidence_fingerprint="d" * 64)
            blocked = transition_task(repository, identity, expected_state="blocked", next_state="planning", evidence_fingerprint="e" * 64)
            self.assertEqual(blocked.state, "planning")
            record_artifact(repository, identity, artifact_kind="plan", artifact_fingerprint="f" * 64)
            set_blocker(repository, identity, blocker_class="evidence-incomplete", evidence_fingerprint="1" * 64)
            projection = set_next_action(repository, identity, action_kind="review-plan", evidence_fingerprint="2" * 64)
            self.assertEqual(projection.blockers, ("evidence-incomplete",))
            self.assertEqual(projection.next_action, "review-plan")
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM tasks WHERE task_id = 'task-19'").fetchone()[0], projection.state)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM artifact_references WHERE task_id = 'task-19'").fetchone()[0], 1)
            finally:
                connection.close()

    def test_blocked_recovery_returns_only_to_the_interrupted_stage(self) -> None:
        origins = (
            ("queued", ()),
            ("planning", ("planning",)),
            ("plan-review", ("planning", "plan-review")),
            ("implementing", ("planning", "plan-review", "implementing")),
            ("diff-review", ("planning", "plan-review", "implementing", "diff-review")),
        )
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            for index, (origin, path) in enumerate(origins, start=1):
                with self.subTest(origin=origin):
                    suffix = str(index)
                    identity = self.identity_for(suffix)
                    admit_task(repository, identity, (self.source_for(suffix),))
                    current = "queued"
                    for step, next_state in enumerate(path, start=1):
                        transition_task(repository, identity, expected_state=current, next_state=next_state, evidence_fingerprint=(f"{index:x}{step:x}" * 64)[:64])
                        current = next_state
                    transition_task(repository, identity, expected_state=origin, next_state="blocked", evidence_fingerprint=(f"{index:x}a" * 64)[:64])
                    for skipped in {"queued", "planning", "plan-review", "implementing", "diff-review"} - {origin}:
                        with self.assertRaises(StateError):
                            transition_task(repository, identity, expected_state="blocked", next_state=skipped, evidence_fingerprint=(f"{index:x}b" * 64)[:64])
                    recovered = transition_task(repository, identity, expected_state="blocked", next_state=origin, evidence_fingerprint=(f"{index:x}c" * 64)[:64])
                    self.assertEqual(recovered.state, origin)

    def test_owner_visible_classifications_reject_paths_and_raw_provider_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = self.task_identity()
            admit_task(repository, identity, (self.source_snapshot(),))
            with self.assertRaises(StateError):
                set_blocker(repository, identity, blocker_class="C:\\private\\worktree", evidence_fingerprint="1" * 64)
            with self.assertRaises(StateError):
                set_next_action(repository, identity, action_kind="provider-output-" + "x" * 100, evidence_fingerprint="2" * 64)
            projection = task_projection(repository, identity)
            self.assertEqual(projection.blockers, ())
            self.assertIsNone(projection.next_action)

    def test_multi_source_and_replayed_task_admission_are_rejected_without_partial_task_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = self.task_identity()
            alternate = SourceSnapshot("other-fixture", "ythdelmar68/roundwright", "c" * 64)
            with self.assertRaises(StateError):
                admit_task(repository, identity, (self.source_snapshot(), alternate))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)
            finally:
                connection.close()
            admit_task(repository, identity, (self.source_snapshot(),))
            with self.assertRaises(StateError):
                admit_task(repository, identity, (self.source_snapshot(),))
