"""Hermetic contract checks for the optional Dev Container consumer."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


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
                "ROUNDWRIGHT_BASE_IMAGE_DIGEST": "${localEnv:ROUNDWRIGHT_BASE_IMAGE_DIGEST}",
            },
        )
        self.assertEqual(configuration["remoteUser"], "65532")

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
        self.assertEqual(configuration["mounts"], ["type=tmpfs,target=/tmp"])
        self.assertNotIn("features", configuration)
        self.assertFalse(any(key.lower().endswith("command") for key in configuration if key != "overrideCommand"))

    def test_documentation_requires_the_existing_preflight_contract(self) -> None:
        documentation = (ROOT / "docs" / "operations" / "devcontainer-consumer.md").read_text(encoding="utf-8")
        for value in (
            "docker/Dockerfile",
            "ROUNDWRIGHT_WHEEL=<exact-wheel-name>",
            "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA=<40-lowercase-hex>",
            "ROUNDWRIGHT_DOCKER_MODE",
            "python -m roundwright.docker_entrypoint doctor",
            "docker/compose.yaml",
            "--network=none",
            "exit code 3",
        ):
            self.assertIn(value, documentation)
        for forbidden in ("postCreateCommand", "postStartCommand", "devcontainer-feature.json", "template.json"):
            self.assertNotIn(forbidden, documentation)


if __name__ == "__main__":
    unittest.main()
