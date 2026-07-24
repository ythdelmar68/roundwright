"""Regression coverage for the workflow's package-tool and pipx boundaries."""

from __future__ import annotations

import importlib.util
import unittest
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
        self.assertEqual(environment["PIPX_USE_UV"], "0")
        self.assertNotIn("PIP_NO_INDEX", environment)
        self.assertNotIn("PIP_NO_DEPS", environment)
        self.assertEqual(command.count("--pip-args=--no-index --no-deps"), 1)
        self.assertEqual(command[-1], "candidate.whl")
