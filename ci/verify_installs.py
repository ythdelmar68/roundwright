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


def required_executable(directory: Path, name: str, *, label: str) -> Path:
    """Return an existing launcher without accepting a missing installation."""

    try:
        command = executable(directory, name).resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError(f"{label} is unavailable") from error
    if not command.is_file():
        raise ValueError(f"{label} is unavailable")
    return command


def pipx_managed_command(pipx_home: Path, application: str = "roundwright") -> Path:
    """Find pipx's application launcher inside its isolated managed venv."""

    if Path(application).name != application or application in {".", ".."}:
        raise ValueError("pipx application path is invalid")
    try:
        home = pipx_home.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError("pipx home is unavailable") from error
    if not home.is_dir():
        raise ValueError("pipx home is unavailable")
    scripts = home / "venvs" / application / ("Scripts" if os.name == "nt" else "bin")
    command = required_executable(scripts, application, label="pipx managed command")
    try:
        command.relative_to(home)
    except ValueError as error:
        raise ValueError("pipx managed command escapes its home") from error
    return command


def pipx_commands(pipx_home: Path, pipx_bin_directory: Path) -> tuple[Path, Path]:
    """Keep the exposed application check separate from the managed-venv smoke route."""

    return (
        required_executable(pipx_bin_directory, "roundwright", label="pipx exposed command"),
        pipx_managed_command(pipx_home),
    )


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


def select_wheel(dist: Path) -> Path:
    """Resolve exactly one locally built wheel before changing execution cwd."""

    try:
        directory = dist.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError("distribution directory is unavailable") from error
    if not directory.is_dir():
        raise ValueError("distribution directory is unavailable")
    wheels = tuple(path for path in sorted(directory.glob("roundwright-*.whl")) if path.is_file())
    if len(wheels) != 1:
        raise ValueError("expected exactly one roundwright wheel")
    return wheels[0].resolve(strict=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dist", type=Path)
    arguments = parser.parse_args()
    wheel = select_wheel(arguments.dist)
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

        pipx_home = root / "pipx-home"
        pipx_bin_directory = root / "pipx-bin"
        environment["PIPX_HOME"] = str(pipx_home)
        environment["PIPX_BIN_DIR"] = str(pipx_bin_directory)
        pipx_environment_variables = command_environment(pipx_environment(environment), pipx_bin_directory)
        run(pipx_install_command(wheel), cwd=root, environment=pipx_environment_variables)
        pipx_exposed_command, pipx_managed_command_path = pipx_commands(pipx_home, pipx_bin_directory)
        run([str(pipx_exposed_command), "--help"], cwd=root, environment=pipx_environment_variables)
        pipx_managed_environment = command_environment(pipx_environment(environment), pipx_managed_command_path.parent)
        smoke(pipx_managed_command_path, cwd=root, environment=pipx_managed_environment)

        environment["UV_TOOL_DIR"] = str(root / "uv-tools")
        environment["UV_TOOL_BIN_DIR"] = str(root / "uv-bin")
        uv_environment_variables = command_environment(environment, Path(environment["UV_TOOL_BIN_DIR"]))
        run(uv_tool_install_command(wheel), cwd=root, environment=uv_environment_variables)
        smoke(executable(Path(environment["UV_TOOL_BIN_DIR"]), "roundwright"), cwd=root, environment=uv_environment_variables)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
