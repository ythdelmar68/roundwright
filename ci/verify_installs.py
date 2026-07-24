"""Exercise installed package commands without a source checkout on PATH."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(command: list[str], *, cwd: Path, environment: dict[str, str], allowed: tuple[int, ...] = (0,)) -> None:
    result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=True, check=False)
    if result.returncode not in allowed:
        raise RuntimeError(result.stderr or result.stdout or "installed command failed")


def executable(directory: Path, name: str) -> Path:
    return directory / (f"{name}.exe" if os.name == "nt" else name)


def smoke(command: Path, *, cwd: Path, environment: dict[str, str]) -> None:
    run([str(command), "--help"], cwd=cwd, environment=environment)
    run([str(command), "doctor"], cwd=cwd, environment=environment)
    run([str(command), "status"], cwd=cwd, environment=environment)
    run([str(command), "db", "check"], cwd=cwd, environment=environment, allowed=(0, 2))


def pipx_environment(environment: dict[str, str]) -> dict[str, str]:
    """Keep pipx on pip when uv is installed for its separate smoke test."""

    configured = environment.copy()
    configured.pop("PIP_NO_INDEX", None)
    configured.pop("PIP_NO_DEPS", None)
    configured["PIPX_USE_UV"] = "0"
    return configured


def pipx_install_command(wheel: Path) -> list[str]:
    """Install only the local wheel with pip's offline, no-dependency flags."""

    return ["pipx", "install", "--force", "--pip-args=--no-index --no-deps", str(wheel)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    arguments = parser.parse_args()
    wheel = next(arguments.dist.glob("roundwright-*.whl"))
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        environment["PIP_NO_INDEX"] = "1"
        environment["PIP_NO_DEPS"] = "1"

        venv = root / "pip"
        run([sys.executable, "-m", "venv", str(venv)], cwd=root, environment=environment)
        scripts = venv / ("Scripts" if os.name == "nt" else "bin")
        run([str(executable(scripts, "python")), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], cwd=root, environment=environment)
        smoke(executable(scripts, "roundwright"), cwd=root, environment=environment)

        environment["PIPX_HOME"] = str(root / "pipx-home")
        environment["PIPX_BIN_DIR"] = str(root / "pipx-bin")
        pipx_environment_variables = pipx_environment(environment)
        run(pipx_install_command(wheel), cwd=root, environment=pipx_environment_variables)
        smoke(executable(Path(environment["PIPX_BIN_DIR"]), "roundwright"), cwd=root, environment=pipx_environment_variables)

        environment["UV_TOOL_DIR"] = str(root / "uv-tools")
        environment["UV_TOOL_BIN_DIR"] = str(root / "uv-bin")
        run(["uv", "tool", "install", "--offline", "--no-cache", "--force", "--from", str(wheel), "roundwright"], cwd=root, environment=environment)
        smoke(executable(Path(environment["UV_TOOL_BIN_DIR"]), "roundwright"), cwd=root, environment=environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
