"""Hermetic build and installed-wheel checks for the distribution boundary."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackageArtifactTests(unittest.TestCase):
    def run_command(self, command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            self.fail(
                f"command failed with {result.returncode}: {result.stderr or result.stdout}"
            )
        return result

    def test_clean_source_builds_and_installed_wheel_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            source = workspace / "source"
            shutil.copytree(
                ROOT,
                source,
                ignore=shutil.ignore_patterns(
                    ".git", "build", "dist", ".venv", "__pycache__", "*.egg-info"
                ),
            )
            wheels = workspace / "wheels"
            sdists = workspace / "sdists"
            wheels.mkdir()
            sdists.mkdir()
            self.run_command(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    "--no-build-isolation",
                    "--no-deps",
                    "--wheel-dir",
                    str(wheels),
                    ".",
                ],
                cwd=source,
            )
            self.run_command(
                [
                    sys.executable,
                    "-c",
                    "from setuptools.build_meta import build_sdist; build_sdist(r'" + str(sdists) + "')",
                ],
                cwd=source,
            )

            wheel = next(wheels.glob("roundwright-*.whl"))
            sdist = next(sdists.glob("roundwright-*.tar.gz"))
            with zipfile.ZipFile(wheel) as archive:
                self.assertIn("roundwright/cli.py", archive.namelist())
                self.assertIn("roundwright/doctor.py", archive.namelist())
            with tarfile.open(sdist) as archive:
                names = archive.getnames()
                self.assertTrue(any(name.endswith("/pyproject.toml") for name in names))
                self.assertTrue(any(name.endswith("/src/roundwright/cli.py") for name in names))

            environment = workspace / "environment"
            self.run_command([sys.executable, "-m", "venv", str(environment)], cwd=workspace)
            scripts = environment / ("Scripts" if os.name == "nt" else "bin")
            python = scripts / ("python.exe" if os.name == "nt" else "python")
            command = scripts / ("roundwright.exe" if os.name == "nt" else "roundwright")
            self.run_command(
                [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                cwd=workspace,
            )
            environment_variables = os.environ.copy()
            environment_variables["PATH"] = str(scripts) + os.pathsep + environment_variables.get("PATH", "")
            help_result = self.run_command([str(command), "--help"], cwd=workspace, env=environment_variables)
            doctor_result = self.run_command([str(command), "doctor"], cwd=workspace, env=environment_variables)
            self.assertIn("usage: roundwright", help_result.stdout)
            self.assertIn("result: healthy", doctor_result.stdout)
