"""Run offline Dev Container reference-CLI qualification for one wheel.

This helper deliberately delegates image construction and command execution to
the Dev Container reference CLI.  It does not create fixture input, start a
dispatcher, or interpret authority; those remain the existing host-owned
Docker consumer contracts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Mapping


_DEFAULT = Path(".devcontainer/devcontainer.json")
_MODES = {
    "authoritative": Path(".devcontainer/authoritative/devcontainer.json"),
    "read-only": Path(".devcontainer/read-only/devcontainer.json"),
    "test-only": Path(".devcontainer/test-only/devcontainer.json"),
}
_COMMON_ENVIRONMENT = {
    "ROUNDWRIGHT_WHEEL",
    "ROUNDWRIGHT_WHEEL_SHA256",
    "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA",
    "ROUNDWRIGHT_STATE",
    "ROUNDWRIGHT_CONFIGURATION",
    "ROUNDWRIGHT_AUTHENTICATION",
}
_AUTHORITATIVE_ENVIRONMENT = {
    "ROUNDWRIGHT_AUTHORITY_RECEIPT",
    "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256",
}
_CANDIDATE = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _require(environment: Mapping[str, str], names: set[str]) -> None:
    if any(not environment.get(name) for name in names):
        raise ValueError("Dev Container qualification inputs are incomplete")


def _reference_command(
    executable: str,
    operation: str,
    workspace: Path,
    configuration: Path,
    *arguments: str,
) -> tuple[str, ...]:
    return (
        executable,
        operation,
        "--workspace-folder",
        str(workspace),
        "--config",
        str(configuration),
        *arguments,
    )


def qualify(
    executable: str,
    workspace: Path,
    configuration_root: Path,
    environment: Mapping[str, str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Start and exec every opt-in consumer through the reference CLI.

    Callers provide an already-built wheel and the same disposable host inputs
    used by the Docker consumer fixture.  The definitions use no Features or
    generated lockfile inputs; after the pinned base has been made local, each
    command is an offline candidate qualification.
    """

    if not executable or not workspace.is_dir() or not configuration_root.is_dir():
        raise ValueError("Dev Container qualification command is invalid")
    _require(environment, _COMMON_ENVIRONMENT | _AUTHORITATIVE_ENVIRONMENT)
    run = lambda command: runner(command, check=True, env=dict(environment), text=True)
    default = configuration_root / _DEFAULT
    modes = {mode: configuration_root / configuration for mode, configuration in _MODES.items()}
    if not default.is_file() or any(not configuration.is_file() for configuration in modes.values()):
        raise ValueError("Dev Container qualification configuration is unavailable")
    run(_reference_command(executable, "up", workspace, default))
    run(
        _reference_command(
            executable,
            "exec",
            workspace,
            _DEFAULT,
            "sh",
            "-lc",
            "test \"$(id -u)\" = 65532 && test \"$HOME\" = /home/roundwright && test -w /home/roundwright && test -w /tmp && test ! -w /workspace",
        )
    )
    for mode, configuration in modes.items():
        run(_reference_command(executable, "up", workspace, configuration))
        run(
            _reference_command(
                executable,
                "exec",
                workspace,
                configuration,
                "sh",
                "-lc",
                f"test \"$(id -u)\" = 65532 && test \"$HOME\" = /home/roundwright && test -w /home/roundwright && test -w /tmp && test ! -w /workspace && {'test -w /var/lib/roundwright' if mode == 'authoritative' else 'test ! -w /var/lib/roundwright'} && python -m roundwright.docker_entrypoint doctor",
            )
        )


def _receipt(
    candidate_sha: str,
    wheel_sha256: str,
    base_image_digest: str,
    reference_cli_version: str,
    configuration_root: Path,
) -> dict[str, object]:
    if not _CANDIDATE.fullmatch(candidate_sha) or not _SHA256.fullmatch(wheel_sha256) or not re.fullmatch(r"sha256:[0-9a-f]{64}", base_image_digest) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", reference_cli_version):
        raise ValueError("Dev Container qualification identity is invalid")
    configurations = {"default": configuration_root / _DEFAULT, **_MODES}
    digests: dict[str, str] = {}
    for name, relative in configurations.items():
        path = relative if name == "default" else configuration_root / relative
        try:
            digests[name] = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise ValueError("Dev Container qualification configuration is unavailable") from error
    return {
        "schema": "roundwright-devcontainer-consumer-qualification/v1",
        "candidate_sha": candidate_sha,
        "wheel_sha256": wheel_sha256,
        "base_image_digest": base_image_digest,
        "reference_cli_version": reference_cli_version,
        "configuration_digests": digests,
        "checks": {
            "default_startup": "passed",
            "authoritative_doctor": "passed",
            "read_only_doctor": "passed",
            "test_only_doctor": "passed",
        },
    }


def _require_identity_binding(candidate_sha: str, wheel_sha256: str, base_image_digest: str, configuration_root: Path, environment: Mapping[str, str]) -> None:
    """Reject substituted invocation identities before starting any CLI process."""

    if environment.get("ROUNDWRIGHT_DOCKER_CANDIDATE_SHA") != candidate_sha or environment.get("ROUNDWRIGHT_WHEEL_SHA256") != wheel_sha256:
        raise ValueError("Dev Container qualification environment identity is mismatched")
    try:
        dockerfile = (configuration_root / "docker" / "Dockerfile").read_text(encoding="utf-8")
        if f"@{base_image_digest}" not in dockerfile or f'test "${{ROUNDWRIGHT_BASE_IMAGE_DIGEST}}" = "{base_image_digest}"' not in dockerfile:
            raise ValueError("Dev Container qualification base identity is mismatched")
        for path in (configuration_root / _DEFAULT, *(configuration_root / item for item in _MODES.values())):
            configuration = json.loads(path.read_text(encoding="utf-8"))
            if configuration["build"]["args"]["ROUNDWRIGHT_BASE_IMAGE_DIGEST"] != base_image_digest:
                raise ValueError("Dev Container qualification base identity is mismatched")
            runtime = configuration.get("containerEnv", {})
            if runtime and runtime.get("ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST") != base_image_digest:
                raise ValueError("Dev Container qualification base identity is mismatched")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Dev Container qualification base identity is mismatched") from error


def qualify_and_record(
    executable: str,
    workspace: Path,
    configuration_root: Path,
    environment: Mapping[str, str],
    candidate_sha: str,
    wheel_sha256: str,
    base_image_digest: str,
    reference_cli_version: str,
    output: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Record a public-safe receipt only after every real CLI operation passes."""

    if output.exists():
        raise ValueError("Dev Container qualification output already exists")
    _require_identity_binding(candidate_sha, wheel_sha256, base_image_digest, configuration_root, environment)
    version = runner((executable, "--version"), check=True, capture_output=True, text=True)
    if version.stdout.strip() != reference_cli_version:
        raise ValueError("Dev Container reference CLI version is mismatched")
    qualify(executable, workspace, configuration_root, environment, runner=runner)
    receipt = _receipt(candidate_sha, wheel_sha256, base_image_digest, reference_cli_version, configuration_root)
    output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devcontainer", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--configuration-root", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--wheel-sha256", required=True)
    parser.add_argument("--base-image-digest", required=True)
    parser.add_argument("--reference-cli-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    qualify_and_record(
        arguments.devcontainer, arguments.workspace, arguments.configuration_root, os.environ,
        arguments.candidate, arguments.wheel_sha256, arguments.base_image_digest,
        arguments.reference_cli_version, arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
