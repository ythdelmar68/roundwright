"""Regression coverage for the workflow's package-tool and pipx boundaries."""

from __future__ import annotations

import importlib.util
import os
import sys
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


def load_validation_resolver() -> object:
    location = ROOT / "ci" / "resolve_validation_toolchain.py"
    specification = importlib.util.spec_from_file_location("resolve_validation_toolchain", location)
    if specification is None or specification.loader is None:
        raise AssertionError("validation toolchain resolver is unavailable")
    module = importlib.util.module_from_spec(specification)
    with mock.patch.object(sys, "path", [str(location.parent), *sys.path]):
        specification.loader.exec_module(module)
    return module


def load_docker_qualification() -> object:
    location = ROOT / "ci" / "docker_consumer_qualification.py"
    specification = importlib.util.spec_from_file_location("docker_consumer_qualification", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Docker qualification helper is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class CiVerificationTests(unittest.TestCase):
    def test_candidate_route_uses_candidate_lock_and_explicit_shared_cache(self) -> None:
        resolver = load_validation_resolver()
        candidate_lock = Path("candidate") / "ci" / "validation-toolchain.lock.toml"
        authoritative_cache = Path("authoritative") / ".roundlet" / "validation-tools"
        arguments = [
            "resolve_validation_toolchain.py",
            "--lock",
            str(candidate_lock),
            "--cache-root",
            str(authoritative_cache),
            "verify",
        ]
        with mock.patch.object(sys, "argv", arguments):
            parsed = resolver.parse_arguments()
        self.assertEqual(parsed.lock, candidate_lock)
        self.assertEqual(parsed.cache_root, authoritative_cache)
        self.assertEqual(parsed.operation, "verify")

        guide = (ROOT / "docs" / "operations" / "validation-toolchain.md").read_text(encoding="utf-8")
        self.assertIn("run the candidate's resolver and candidate lock", guide)
        self.assertIn("--cache-root <authoritative-checkout>/.roundlet/validation-tools", guide)
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("isolated candidate Worker must execute the resolver and lock", instructions)
        self.assertIn("never validation evidence", instructions)

    def test_workflow_provisions_locked_toolchain_before_no_isolation_build(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        provision = "python ci/resolve_validation_toolchain.py provision"
        build = "python ci/resolve_validation_toolchain.py exec-python -- -m pip wheel --no-build-isolation"
        self.assertIn(provision, workflow)
        self.assertIn(build, workflow)
        self.assertLess(workflow.index(provision), workflow.index(build))
        self.assertNotIn('setuptools>=69" pipx uv', workflow)

    def test_platform_matrix_qualifies_one_uploaded_content_addressed_package(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("build-package:", workflow)
        self.assertIn("needs: build-package", workflow)
        self.assertIn("roundwright-package-${{ github.sha }}", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)
        self.assertIn("ci/verify_package_digest.py verify dist", workflow)
        self.assertIn("ci/verify_package_digest.py qualify dist", workflow)

    def test_docker_consumer_workflow_qualifies_the_uploaded_wheel_without_publication(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("docker-consumer-qualification:", workflow)
        self.assertIn("needs: build-package", workflow)
        self.assertIn("roundwright-package-${{ github.sha }}", workflow)
        self.assertIn("ci/docker_consumer_qualification.py inputs dist --candidate", workflow)
        self.assertIn("docker pull \"${{ steps.docker-inputs.outputs.base_image }}\"", workflow)
        self.assertIn("docker build --network=none --file docker/Dockerfile", workflow)
        self.assertIn("ROUNDWRIGHT_WHEEL_SHA256=${{ steps.docker-inputs.outputs.wheel_sha256 }}", workflow)
        self.assertIn("docker run --rm --network=none --read-only --tmpfs /tmp", workflow)
        self.assertIn("--docker-mode read-only", workflow)
        self.assertIn("--docker-mode test-only", workflow)
        self.assertIn("roundwright-docker-consumer-qualification-${{ github.sha }}", workflow)
        self.assertNotIn("docker push", workflow)

    def test_docker_qualification_binds_artifact_base_and_dockerfile_without_paths(self) -> None:
        qualification = load_docker_qualification()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            wheel = dist / "roundwright-0.0.0-py3-none-any.whl"
            wheel.write_bytes(b"candidate wheel")
            digest = qualification.hashlib.sha256(wheel.read_bytes()).hexdigest()
            (dist / "package-digest.json").write_text(
                qualification.json.dumps({"wheel": wheel.name, "sha256": digest}) + "\n", encoding="utf-8"
            )
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(
                "FROM python:3.12.13-slim-bookworm@sha256:" + "a" * 64
                + "\nCOPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL} /tmp/roundwright.whl\n"
                + "RUN python -m pip install --no-index --no-deps /tmp/roundwright.whl\n",
                encoding="utf-8",
            )
            values = qualification.docker_inputs(dist, "b" * 40, dockerfile=dockerfile)
            self.assertEqual(values["wheel_sha256"], digest)
            self.assertEqual(values["base_image_digest"], "sha256:" + "a" * 64)
            self.assertNotIn(str(root), qualification.json.dumps(values, sort_keys=True))
            receipt = root / "receipt.json"
            with mock.patch.object(qualification, "_DOCKERFILE", dockerfile):
                qualification.record_qualification(dist, "b" * 40, values["base_image"], receipt)
            recorded = qualification.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(recorded["candidate_sha"], "b" * 40)
            self.assertEqual(recorded["wheel_sha256"], digest)
            self.assertEqual(recorded["checks"]["offline_build"], "passed")

    def test_workflow_does_not_restore_nonportable_windows_junctions(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        cache_step = """- name: Restore portable validation toolchain cache
        if: runner.os != 'Windows'
        uses: actions/cache@v4"""
        self.assertIn(cache_step, workflow)
        self.assertIn("path: .roundlet/validation-tools", workflow)

    def test_pipx_route_forces_pip_and_uses_one_offline_no_dependency_pair(self) -> None:
        verifier = load_install_verifier()
        environment = verifier.pipx_environment({"PIP_NO_INDEX": "1", "PIP_NO_DEPS": "1"})
        command = verifier.pipx_install_command(Path("tools/pipx"), Path("python"), Path("candidate.whl"))
        self.assertNotIn("PIPX_USE_UV", environment)
        self.assertNotIn("PIP_NO_INDEX", environment)
        self.assertNotIn("PIP_NO_DEPS", environment)
        self.assertEqual(command[2:4], ["--backend", "pip"])
        self.assertEqual(command[4:6], ["--python", str(Path("python"))])
        self.assertIn("--skip-maintenance", command)
        self.assertEqual(command.count("--pip-args=--no-index --no-deps"), 1)
        self.assertEqual(command[-1], "candidate.whl")

    def test_uv_route_uses_receipt_bound_tools_without_discovery_or_download(self) -> None:
        verifier = load_install_verifier()
        command = verifier.uv_tool_install_command(Path("tools/uv"), Path("python"), Path("candidate.whl"))
        self.assertEqual(command[:5], [str(Path("tools/uv")), "tool", "install", "--python", str(Path("python"))])
        self.assertIn("--no-python-downloads", command)
        self.assertIn("--no-config", command)
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

    def test_pipx_default_environment_clears_overrides_for_a_temporary_profile(self) -> None:
        verifier = load_install_verifier()
        profile = Path("temporary-profile")
        environment = verifier.pipx_default_environment(
            {
                "PIPX_HOME": "override-home",
                "PIPX_BIN_DIR": "override-bin",
                "XDG_BIN_HOME": "override-xdg-bin",
                "XDG_CACHE_HOME": "override-xdg-cache",
                "XDG_DATA_HOME": "override-xdg-data",
            },
            profile,
        )
        home, bin_directory = verifier.pipx_default_paths(profile)
        self.assertNotIn("PIPX_HOME", environment)
        self.assertNotIn("PIPX_BIN_DIR", environment)
        self.assertFalse({"XDG_BIN_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"} & set(environment))
        self.assertEqual(environment["HOME"], str(profile))
        if verifier.os.name == "nt":
            self.assertEqual(home, profile / "AppData" / "Local" / "pipx" / "pipx")
        self.assertEqual(bin_directory, profile / ".local" / "bin")
        self.assertNotEqual(home, Path("override-home"))

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
