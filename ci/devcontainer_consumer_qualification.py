"""Run offline Dev Container reference-CLI qualification for one wheel.

This helper deliberately delegates image construction and command execution to
the Dev Container reference CLI.  It does not create fixture input, start a
dispatcher, or interpret authority; those remain the existing host-owned
Docker consumer contracts.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
from typing import Callable, Mapping, Sequence


_DEFAULT = Path(".devcontainer/devcontainer.json")
_MODES = {
    "authoritative": Path(".devcontainer/devcontainer.authoritative.json"),
    "read-only": Path(".devcontainer/devcontainer.read-only.json"),
    "test-only": Path(".devcontainer/devcontainer.test-only.json"),
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
    environment: Mapping[str, str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    """Start and exec every opt-in consumer through the reference CLI.

    Callers provide an already-built wheel and the same disposable host inputs
    used by the Docker consumer fixture.  The reference CLI is run with no
    lockfile generation; after the pinned base has been made local, each
    command is an offline candidate qualification.
    """

    if not executable or not workspace.is_dir():
        raise ValueError("Dev Container qualification command is invalid")
    _require(environment, _COMMON_ENVIRONMENT | _AUTHORITATIVE_ENVIRONMENT)
    run = lambda command: runner(command, check=True, env=dict(environment), text=True)
    run(_reference_command(executable, "up", workspace, _DEFAULT, "--no-lockfile"))
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
    for mode, configuration in _MODES.items():
        run(_reference_command(executable, "up", workspace, configuration, "--no-lockfile"))
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devcontainer", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    qualify(arguments.devcontainer, arguments.workspace, os.environ)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
