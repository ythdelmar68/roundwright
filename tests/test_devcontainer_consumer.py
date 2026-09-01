"""Hermetic contract checks for the optional Dev Container consumer."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import shutil
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ci"))

import devcontainer_consumer_qualification


_BASE = "sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2"


class DevContainerConsumerTests(unittest.TestCase):
    def test_devcontainer_reuses_the_artifact_only_docker_consumer(self) -> None:
        configuration = json.loads(
            (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        )

        self.assertEqual(configuration["build"]["context"], "..")
        self.assertEqual(configuration["build"]["dockerfile"], "../docker/Dockerfile")
        self.assertEqual(
            configuration["build"]["args"],
            {
                "ROUNDWRIGHT_WHEEL": "${localEnv:ROUNDWRIGHT_WHEEL}",
                "ROUNDWRIGHT_WHEEL_SHA256": "${localEnv:ROUNDWRIGHT_WHEEL_SHA256}",
                "ROUNDWRIGHT_CANDIDATE_SHA": "${localEnv:ROUNDWRIGHT_DOCKER_CANDIDATE_SHA}",
                "ROUNDWRIGHT_BASE_IMAGE_DIGEST": _BASE,
            },
        )
        self.assertEqual(configuration["remoteUser"], "roundwright")
        self.assertFalse(configuration["updateRemoteUserUID"])
        self.assertEqual(configuration["build"]["options"], ["--network=none"])

    def test_default_open_is_read_only_and_has_no_lifecycle_hook(self) -> None:
        configuration = json.loads(
            (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        )

        self.assertTrue(configuration["overrideCommand"])
        self.assertEqual(configuration["workspaceFolder"], "/workspace")
        self.assertEqual(
            configuration["workspaceMount"],
            "source=${localWorkspaceFolder},target=/workspace,type=bind,readonly",
        )
        self.assertEqual(
            configuration["mounts"],
            [
                "type=volume,source=roundwright-devcontainer-home,target=/home/roundwright",
                "type=tmpfs,target=/tmp",
            ],
        )
        self.assertEqual(configuration["runArgs"], ["--read-only"])
        self.assertNotIn("features", configuration)
        self.assertFalse(any(key.lower().endswith("command") for key in configuration if key != "overrideCommand"))

    def test_documentation_requires_the_existing_preflight_contract(self) -> None:
        documentation = (ROOT / "docs" / "operations" / "devcontainer-consumer.md").read_text(encoding="utf-8")
        for value in (
            "docker/Dockerfile",
            "ROUNDWRIGHT_WHEEL=<exact-wheel-name>",
            "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA=<40-lowercase-hex>",
            "ROUNDWRIGHT_DOCKER_MODE",
            "devcontainer up --workspace-folder . --config .devcontainer/read-only/devcontainer.json",
            "docker/compose.yaml",
            "--network=none",
            "exit code 3",
        ):
            self.assertIn(value, documentation)
        for forbidden in ("postCreateCommand", "postStartCommand", "devcontainer-feature.json", "template.json"):
            self.assertNotIn(forbidden, documentation)

    def test_every_mode_uses_the_canonical_runtime_mount_contract(self) -> None:
        expected_common = {
            "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "${localEnv:ROUNDWRIGHT_DOCKER_CANDIDATE_SHA}",
            "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "${localEnv:ROUNDWRIGHT_WHEEL_SHA256}",
            "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": _BASE,
            "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
            "XDG_CONFIG_HOME": "/etc",
            "XDG_STATE_HOME": "/var/lib",
        }
        for mode in ("authoritative", "read-only", "test-only"):
            with self.subTest(mode=mode):
                definition = ROOT / ".devcontainer" / mode / "devcontainer.json"
                self.assertEqual(definition.name, "devcontainer.json")
                configuration = json.loads(definition.read_text(encoding="utf-8"))
                self.assertEqual(configuration["build"]["context"], "../..")
                self.assertEqual(configuration["build"]["dockerfile"], "../../docker/Dockerfile")
                self.assertEqual(configuration["containerEnv"]["ROUNDWRIGHT_DOCKER_MODE"], mode)
                self.assertEqual({name: configuration["containerEnv"][name] for name in expected_common}, expected_common)
                self.assertEqual(configuration["remoteUser"], "roundwright")
                self.assertFalse(configuration["updateRemoteUserUID"])
                self.assertEqual(configuration["runArgs"], ["--read-only"])
                self.assertEqual(configuration["build"]["options"], ["--network=none"])
                self.assertIn("type=bind,source=${localEnv:ROUNDWRIGHT_CONFIGURATION},target=/etc/roundwright/config.toml,readonly", configuration["mounts"])
                self.assertIn("type=bind,source=${localEnv:ROUNDWRIGHT_AUTHENTICATION},target=/run/roundwright/auth.toml,readonly", configuration["mounts"])
                if mode == "authoritative":
                    self.assertIn("ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256", configuration["containerEnv"])
                    self.assertIn("type=bind,source=${localEnv:ROUNDWRIGHT_STATE},target=/var/lib/roundwright", configuration["mounts"])
                    self.assertIn("type=bind,source=${localEnv:ROUNDWRIGHT_AUTHORITY_RECEIPT},target=/run/roundwright/authority-receipt.json,readonly", configuration["mounts"])
                else:
                    self.assertNotIn("ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256", configuration["containerEnv"])
                    self.assertIn("type=bind,source=${localEnv:ROUNDWRIGHT_STATE},target=/var/lib/roundwright,readonly", configuration["mounts"])
                    self.assertFalse(any("authority-receipt" in mount for mount in configuration["mounts"]))
        for mode in ("authoritative", "read-only", "test-only"):
            self.assertFalse((ROOT / ".devcontainer" / f"devcontainer.{mode}.json").exists())

    def test_dockerfile_rejects_a_wrong_base_before_writing_identity(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
        check = f'test "${{ROUNDWRIGHT_BASE_IMAGE_DIGEST}}" = "{_BASE}"'
        self.assertIn(check, dockerfile)
        self.assertLess(dockerfile.index(check), dockerfile.index("consumer-identity.json"))

    def test_reference_cli_qualification_starts_and_execs_all_modes(self) -> None:
        environment = {name: "provided" for name in devcontainer_consumer_qualification._COMMON_ENVIRONMENT | devcontainer_consumer_qualification._AUTHORITATIVE_ENVIRONMENT}
        calls: list[tuple[str, ...]] = []

        def runner(command, **_kwargs):
            calls.append(tuple(command))
            return mock.Mock()

        devcontainer_consumer_qualification.qualify("devcontainer", ROOT, ROOT, environment, runner=runner)
        self.assertEqual(sum(command[1] == "up" for command in calls), 4)
        self.assertEqual(sum(command[1] == "exec" for command in calls), 4)
        self.assertFalse(any("--no-lockfile" in command or "--noLockfile" in command for command in calls))
        self.assertTrue(any(any("authoritative/devcontainer.json" in value.replace("\\", "/") for value in command) for command in calls))
        self.assertTrue(any(any("read-only/devcontainer.json" in value.replace("\\", "/") for value in command) for command in calls))
        self.assertTrue(any(any("test-only/devcontainer.json" in value.replace("\\", "/") for value in command) for command in calls))
        doctor_commands = [command for command in calls if command[1] == "exec" and command[-1].endswith("roundwright.docker_entrypoint doctor")]
        self.assertEqual(len(doctor_commands), 3)

    def test_reference_cli_receipt_requires_real_startup_and_exact_identity(self) -> None:
        environment = {name: "provided" for name in devcontainer_consumer_qualification._COMMON_ENVIRONMENT | devcontainer_consumer_qualification._AUTHORITATIVE_ENVIRONMENT}
        environment.update({"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "b" * 64})
        calls: list[tuple[str, ...]] = []

        def runner(command, **_kwargs):
            calls.append(tuple(command))
            return mock.Mock(stdout="0.82.0\n")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt.json"
            devcontainer_consumer_qualification.qualify_and_record(
                "devcontainer", ROOT, ROOT, environment, "a" * 40, "b" * 64, _BASE,
                "0.82.0", output, runner=runner,
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(receipt["candidate_sha"], "a" * 40)
        self.assertEqual(receipt["wheel_sha256"], "b" * 64)
        self.assertEqual(receipt["reference_cli_version"], "0.82.0")
        self.assertEqual(set(receipt["checks"]), {"default_startup", "authoritative_doctor", "read_only_doctor", "test_only_doctor"})
        definitions = {
            "default": ROOT / ".devcontainer" / "devcontainer.json",
            "authoritative": ROOT / ".devcontainer" / "authoritative" / "devcontainer.json",
            "read-only": ROOT / ".devcontainer" / "read-only" / "devcontainer.json",
            "test-only": ROOT / ".devcontainer" / "test-only" / "devcontainer.json",
        }
        self.assertEqual(
            receipt["configuration_digests"],
            {name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() for name, path in definitions.items()},
        )
        self.assertEqual(calls[0], ("devcontainer", "--version"))

    def test_reference_cli_receipt_is_not_written_after_a_failed_command(self) -> None:
        environment = {name: "provided" for name in devcontainer_consumer_qualification._COMMON_ENVIRONMENT | devcontainer_consumer_qualification._AUTHORITATIVE_ENVIRONMENT}
        environment.update({"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "b" * 64})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "receipt.json"
            with self.assertRaises(RuntimeError):
                devcontainer_consumer_qualification.qualify_and_record(
                    "devcontainer", ROOT, ROOT, environment, "a" * 40, "b" * 64, _BASE,
                    "0.82.0", output, runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("reference CLI failed")),
                )
            self.assertFalse(output.exists())

    def test_identity_drift_blocks_before_any_reference_cli_command(self) -> None:
        environment = {name: "provided" for name in devcontainer_consumer_qualification._COMMON_ENVIRONMENT | devcontainer_consumer_qualification._AUTHORITATIVE_ENVIRONMENT}
        cases = (
            ("candidate", {"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "c" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "b" * 64}, "a" * 40, "b" * 64, _BASE),
            ("wheel", {"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "c" * 64}, "a" * 40, "b" * 64, _BASE),
            ("base", {"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "b" * 64}, "a" * 40, "b" * 64, "sha256:" + "0" * 64),
        )
        for _name, update, candidate, wheel, base in cases:
            with self.subTest(case=_name), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "receipt.json"
                calls = []
                with self.assertRaises(ValueError):
                    devcontainer_consumer_qualification.qualify_and_record("devcontainer", ROOT, ROOT, {**environment, **update}, candidate, wheel, base, "0.82.0", output, runner=lambda *args, **kwargs: calls.append(args))
                self.assertEqual(calls, [])
                self.assertFalse(output.exists())

    def test_committed_definition_and_dockerfile_drift_block_before_runner(self) -> None:
        environment = {name: "provided" for name in devcontainer_consumer_qualification._COMMON_ENVIRONMENT | devcontainer_consumer_qualification._AUTHORITATIVE_ENVIRONMENT}
        environment.update({"ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_WHEEL_SHA256": "b" * 64})
        for target in ("definition", "dockerfile"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                copied = Path(temporary) / "candidate"; shutil.copytree(ROOT, copied)
                path = copied / ".devcontainer" / "authoritative" / "devcontainer.json" if target == "definition" else copied / "docker" / "Dockerfile"
                path.write_text(path.read_text(encoding="utf-8").replace(_BASE, "sha256:" + "0" * 64, 1), encoding="utf-8")
                output = Path(temporary) / "receipt.json"; calls = []
                with self.assertRaises(ValueError):
                    devcontainer_consumer_qualification.qualify_and_record("devcontainer", copied, copied, environment, "a" * 40, "b" * 64, _BASE, "0.82.0", output, runner=lambda *args, **kwargs: calls.append(args))
                self.assertEqual(calls, []); self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
