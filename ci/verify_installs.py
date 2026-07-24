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


def command_environment(environment: dict[str, str], directory: Path) -> dict[str, str]:
    """Make one installed console command discoverable without source checkout paths."""

    configured = environment.copy()
    configured["PATH"] = str(directory) + os.pathsep + configured.get("PATH", "")
    return configured


def pipx_environment(environment: dict[str, str]) -> dict[str, str]:
    """Prevent inherited pip flags from duplicating the explicit pipx pair."""

    configured = environment.copy()
    configured.pop("PIP_NO_INDEX", None)
    configured.pop("PIP_NO_DEPS", None)
    return configured


def pipx_install_command(wheel: Path) -> list[str]:
    """Install only the local wheel with pip's offline, no-dependency flags."""

    return ["pipx", "install", "--backend", "pip", "--force", "--pip-args=--no-index --no-deps", str(wheel)]


def uv_tool_install_command(wheel: Path) -> list[str]:
    """Use the active Python 3.12 interpreter without an offline download."""

    return ["uv", "tool", "install", "--python", sys.executable, "--offline", "--no-cache", "--force", "--from", str(wheel), "roundwright"]


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
        pip_environment_variables = command_environment(environment, scripts)
        run([str(executable(scripts, "python")), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], cwd=root, environment=pip_environment_variables)
        smoke(executable(scripts, "roundwright"), cwd=root, environment=pip_environment_variables)

        environment["PIPX_HOME"] = str(root / "pipx-home")
        environment["PIPX_BIN_DIR"] = str(root / "pipx-bin")
        pipx_environment_variables = command_environment(pipx_environment(environment), Path(environment["PIPX_BIN_DIR"]))
        run(pipx_install_command(wheel), cwd=root, environment=pipx_environment_variables)
        smoke(executable(Path(environment["PIPX_BIN_DIR"]), "roundwright"), cwd=root, environment=pipx_environment_variables)

        environment["UV_TOOL_DIR"] = str(root / "uv-tools")
        environment["UV_TOOL_BIN_DIR"] = str(root / "uv-bin")
        uv_environment_variables = command_environment(environment, Path(environment["UV_TOOL_BIN_DIR"]))
        run(uv_tool_install_command(wheel), cwd=root, environment=uv_environment_variables)
        smoke(executable(Path(environment["UV_TOOL_BIN_DIR"]), "roundwright"), cwd=root, environment=uv_environment_variables)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
