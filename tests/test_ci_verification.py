"""Regression coverage for the workflow's package-tool and pipx boundaries."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_install_verifier() -> object:
    location = ROOT / "ci" / "verify_installs.py"
    specification = importlib.util.spec_from_file_location("verify_installs", location)
    if specification is None or specification.loader is None:
        raise AssertionError("install verifier is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class CiVerificationTests(unittest.TestCase):
    def test_workflow_installs_declared_backend_before_no_isolation_build(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        backend = 'python -m pip install --disable-pip-version-check "setuptools>=69" pipx uv'
        build = "python -m pip wheel --no-build-isolation --no-deps --wheel-dir dist ."
        self.assertIn(backend, workflow)
        self.assertIn(build, workflow)
        self.assertLess(workflow.index(backend), workflow.index(build))

    def test_pipx_route_forces_pip_and_uses_one_offline_no_dependency_pair(self) -> None:
        verifier = load_install_verifier()
        environment = verifier.pipx_environment({"PIP_NO_INDEX": "1", "PIP_NO_DEPS": "1"})
        command = verifier.pipx_install_command(Path("candidate.whl"))
        self.assertNotIn("PIPX_USE_UV", environment)
        self.assertNotIn("PIP_NO_INDEX", environment)
        self.assertNotIn("PIP_NO_DEPS", environment)
        self.assertEqual(command[2:4], ["--backend", "pip"])
        self.assertEqual(command.count("--pip-args=--no-index --no-deps"), 1)
        self.assertEqual(command[-1], "candidate.whl")

    def test_uv_route_uses_the_active_python_without_an_offline_download(self) -> None:
        verifier = load_install_verifier()
        command = verifier.uv_tool_install_command(Path("candidate.whl"))
        self.assertEqual(command[:5], ["uv", "tool", "install", "--python", verifier.sys.executable])
        self.assertIn("--offline", command)
        self.assertEqual(command[-2:], ["candidate.whl", "roundwright"])

    def test_installed_command_environment_precedes_the_inherited_path(self) -> None:
        verifier = load_install_verifier()
        environment = verifier.command_environment({"PATH": "parent"}, Path("isolated-bin"))
        self.assertEqual(environment["PATH"], f"isolated-bin{verifier.os.pathsep}parent")

    def test_pipx_validates_the_exposed_and_managed_launchers(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "pipx-home"
            exposed_directory = root / "pipx-bin"
            scripts = home / "venvs" / "roundwright" / ("Scripts" if verifier.os.name == "nt" else "bin")
            scripts.mkdir(parents=True)
            exposed_directory.mkdir()
            managed = verifier.executable(scripts, "roundwright")
            exposed = verifier.executable(exposed_directory, "roundwright")
            managed.write_bytes(b"managed")
            exposed.write_bytes(b"exposed")
            exposed_command, managed_command = verifier.pipx_commands(home, exposed_directory)
            self.assertEqual(exposed_command, exposed.resolve())
            self.assertEqual(managed_command, managed.resolve())
            self.assertEqual(
                verifier.command_environment({"PATH": "parent"}, managed_command.parent)["PATH"],
                f"{managed_command.parent}{verifier.os.pathsep}parent",
            )

    def test_pipx_managed_command_rejects_absent_and_traversal_paths(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "pipx-home"
            home.mkdir()
            with self.assertRaisesRegex(ValueError, "managed command is unavailable"):
                verifier.pipx_managed_command(home)
            with self.assertRaisesRegex(ValueError, "application path is invalid"):
                verifier.pipx_managed_command(home, "../outside")

    def test_pipx_smoke_runs_every_command_through_the_exposed_launcher(self) -> None:
        verifier = load_install_verifier()
        exposed = Path("pipx-bin") / verifier.executable(Path(), "roundwright").name
        commands: list[list[str]] = []

        def record(command: list[str], **_kwargs: object) -> None:
            commands.append(command)

        with mock.patch.object(verifier, "run", side_effect=record):
            verifier.pipx_smoke(exposed, cwd=Path("isolated"), environment={})
        self.assertEqual(
            commands,
            [
                [str(exposed), "--help"],
                [str(exposed), "doctor"],
                [str(exposed), "status"],
                [str(exposed), "db", "check"],
            ],
        )

    def test_relative_distribution_path_selects_one_absolute_wheel_before_cwd_changes(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            wheel = dist / "roundwright-0.0.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            original = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(verifier.select_wheel(Path("dist")), wheel.resolve())
            finally:
                os.chdir(original)
            (dist / "roundwright-extra.whl").write_bytes(b"wheel")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                verifier.select_wheel(dist)
            with self.assertRaisesRegex(ValueError, "distribution directory is unavailable"):
                verifier.select_wheel(root / "missing")
