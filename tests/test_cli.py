"""Unit coverage for the public CLI and read-only diagnostics."""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.cli import main
from roundwright.doctor import collect_diagnostics, render_diagnostics
from roundwright.identity import (
    UnsafeEntrypointIdentityError,
    inspect_entrypoint_identity,
    require_safe_entrypoint_identity,
)


def executable_name() -> str:
    return "roundwright.exe" if os.name == "nt" else "roundwright"


class CliTests(unittest.TestCase):
    def test_help_is_available_without_configuration(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("usage: roundwright", output.getvalue())

    def test_unknown_command_has_argparse_exit_code(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main(["unknown"])
        self.assertEqual(raised.exception.code, 2)

    def test_doctor_reports_ready_capabilities_without_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / executable_name()
            executable.touch()
            report = collect_diagnostics(
                str(executable), version_info=(3, 12), path=str(root)
            )
            output = io.StringIO()
            render_diagnostics(report, output)
        self.assertTrue(report.healthy)
        self.assertEqual(report.exit_code, 0)
        rendered = output.getvalue()
        self.assertIn("result: healthy", rendered)
        self.assertNotIn(str(root), rendered)

    def test_wrong_python_is_a_deterministic_capability_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / executable_name()
            executable.touch()
            report = collect_diagnostics(
                str(executable), version_info=(3, 11), path=str(root)
            )
        self.assertFalse(report.python_ready)
        self.assertEqual(report.exit_code, 2)

    def test_windows_launcher_wrapper_matches_its_console_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "roundwright.exe"
            wrapper = root / "roundwright-script.py"
            executable.touch()
            wrapper.touch()
            identity = inspect_entrypoint_identity(
                str(wrapper), path=str(root), is_windows=True
            )
        self.assertTrue(identity.safe)

    def test_windows_pipx_exposed_copy_matches_its_managed_venv_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "pipx-home"
            bin_directory = root / "pipx-bin"
            managed_directory = home / "venvs" / "roundwright" / "Scripts"
            managed_directory.mkdir(parents=True)
            bin_directory.mkdir()
            managed = managed_directory / "roundwright.exe"
            exposed = bin_directory / "roundwright.exe"
            managed.write_bytes(b"same pipx launcher")
            exposed.write_bytes(b"same pipx launcher")
            with mock.patch.dict(os.environ, {"PIPX_HOME": str(home), "PIPX_BIN_DIR": str(bin_directory)}):
                identity = inspect_entrypoint_identity(
                    str(managed), path=str(bin_directory), is_windows=True
                )
        self.assertTrue(identity.safe)

    def test_windows_pipx_default_paths_match_its_managed_venv_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            home = profile / ".local" / "pipx"
            bin_directory = profile / ".local" / "bin"
            managed_directory = home / "venvs" / "roundwright" / "Scripts"
            managed_directory.mkdir(parents=True)
            bin_directory.mkdir(parents=True)
            managed = managed_directory / "roundwright.exe"
            exposed = bin_directory / "roundwright.exe"
            managed.write_bytes(b"same default pipx launcher")
            exposed.write_bytes(b"same default pipx launcher")
            with mock.patch.object(Path, "home", return_value=profile), mock.patch.dict(
                os.environ, {"LOCALAPPDATA": str(profile / "AppData" / "Local")}, clear=True
            ):
                identity = inspect_entrypoint_identity(
                    str(managed), path=str(bin_directory), is_windows=True
                )
        self.assertTrue(identity.safe)

    def test_windows_pipx_default_paths_reject_a_different_exposed_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "profile"
            home = profile / ".local" / "pipx"
            bin_directory = profile / ".local" / "bin"
            managed_directory = home / "venvs" / "roundwright" / "Scripts"
            managed_directory.mkdir(parents=True)
            bin_directory.mkdir(parents=True)
            managed = managed_directory / "roundwright.exe"
            exposed = bin_directory / "roundwright.exe"
            managed.write_bytes(b"managed default pipx launcher")
            exposed.write_bytes(b"different default pipx launcher")
            with mock.patch.object(Path, "home", return_value=profile), mock.patch.dict(
                os.environ, {"LOCALAPPDATA": str(profile / "AppData" / "Local")}, clear=True
            ):
                identity = inspect_entrypoint_identity(
                    str(managed), path=str(bin_directory), is_windows=True
                )
        self.assertFalse(identity.safe)

    def test_windows_pipx_rejects_a_different_exposed_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "pipx-home"
            bin_directory = root / "pipx-bin"
            managed_directory = home / "venvs" / "roundwright" / "Scripts"
            managed_directory.mkdir(parents=True)
            bin_directory.mkdir()
            managed = managed_directory / "roundwright.exe"
            exposed = bin_directory / "roundwright.exe"
            managed.write_bytes(b"managed launcher")
            exposed.write_bytes(b"different launcher")
            with mock.patch.dict(os.environ, {"PIPX_HOME": str(home), "PIPX_BIN_DIR": str(bin_directory)}):
                identity = inspect_entrypoint_identity(
                    str(managed), path=str(bin_directory), is_windows=True
                )
        self.assertFalse(identity.safe)

    def test_bare_launcher_name_uses_the_current_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "roundwright.exe"
            runtime = root / "python.exe"
            executable.touch()
            runtime.touch()
            identity = inspect_entrypoint_identity(
                "roundwright",
                path=str(root),
                is_windows=True,
                runtime_executable=str(runtime),
            )
        self.assertTrue(identity.safe)

    def test_shadowed_executable_is_rejected_before_future_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            executable = first / executable_name()
            executable.touch()
            (second / executable_name()).touch()
            path = os.pathsep.join((str(first), str(second)))
            identity = inspect_entrypoint_identity(str(executable), path=path)
            self.assertFalse(identity.safe)
            self.assertIn("more than one", identity.reason)
            with self.assertRaises(UnsafeEntrypointIdentityError):
                require_safe_entrypoint_identity(str(executable), path=path)

    def test_stale_executable_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "selected"
            stale = root / "stale"
            selected.mkdir()
            stale.mkdir()
            (selected / executable_name()).touch()
            stale_executable = stale / executable_name()
            stale_executable.touch()
            identity = inspect_entrypoint_identity(
                str(stale_executable), path=str(selected)
            )
        self.assertFalse(identity.safe)
        self.assertIn("does not match", identity.reason)

    def test_doctor_does_not_write_to_its_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / executable_name()
            executable.touch()
            before = {path.name for path in root.iterdir()}
            report = collect_diagnostics(
                str(executable), version_info=(3, 12), path=str(root)
            )
            output = io.StringIO()
            render_diagnostics(report, output)
            after = {path.name for path in root.iterdir()}
        self.assertTrue(report.healthy)
        self.assertEqual(before, after)
