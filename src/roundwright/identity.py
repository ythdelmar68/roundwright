"""Read-only executable identity checks for the command boundary."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EntrypointIdentity:
    """A public-safe result of locating the installed console command."""

    safe: bool
    reason: str


class UnsafeEntrypointIdentityError(RuntimeError):
    """Raised when a future mutation-capable command lacks a safe identity."""


def _candidate_names(command: str, *, is_windows: bool) -> tuple[str, ...]:
    """Return command filenames without consulting or executing PATH helpers."""

    if not is_windows or Path(command).suffix:
        return (command,)
    return tuple(f"{command}{suffix}" for suffix in (".exe", ".com", ".bat", ".cmd"))


def _path_candidates(
    command: str,
    path: str,
    *,
    is_windows: bool,
) -> tuple[Path, ...]:
    """Find distinct executable files directly, without invoking a shell helper."""

    discovered: list[Path] = []
    for directory in path.split(os.pathsep):
        if not directory:
            continue
        for filename in _candidate_names(command, is_windows=is_windows):
            candidate = Path(directory) / filename
            if candidate.is_file():
                resolved = candidate.resolve()
                if resolved not in discovered:
                    discovered.append(resolved)
    return tuple(discovered)


def inspect_entrypoint_identity(
    argv0: str,
    *,
    command: str = "roundwright",
    path: str | None = None,
    is_windows: bool | None = None,
    runtime_executable: str | None = None,
) -> EntrypointIdentity:
    """Verify that PATH selects exactly the executable currently running.

    The result deliberately contains no filesystem paths. It can therefore be
    safely shown to operators and later used as a fail-closed guard before any
    mutation-capable command is introduced.
    """

    active_path = os.environ.get("PATH", "") if path is None else path
    windows = os.name == "nt" if is_windows is None else is_windows
    candidates = _path_candidates(command, active_path, is_windows=windows)

    if not candidates:
        return EntrypointIdentity(False, "the command is not discoverable on PATH")
    if len(candidates) != 1:
        return EntrypointIdentity(False, "more than one command executable was discovered")

    requested = Path(argv0)
    if requested.parent == Path(".") and runtime_executable is not None:
        requested = Path(runtime_executable).parent / requested.name
    active = requested.resolve()
    selected = candidates[0]
    if not _same_file(active, selected) and not _is_windows_console_wrapper(
        active, selected, command=command, is_windows=windows
    ) and not _is_windows_pipx_launcher_pair(active, selected, command=command, is_windows=windows):
        return EntrypointIdentity(False, "the selected command does not match this executable")
    return EntrypointIdentity(True, "one matching executable was discovered")


def _same_file(first: Path, second: Path) -> bool:
    """Compare file identity so Windows short-name aliases remain equivalent."""

    try:
        return os.path.samefile(first, second)
    except OSError:
        return first == second


def _is_windows_console_wrapper(
    active: Path,
    selected: Path,
    *,
    command: str,
    is_windows: bool,
) -> bool:
    """Accept only the standard adjacent script used by a Windows launcher."""

    if not is_windows or active.parent != selected.parent:
        return False
    if selected.stem.casefold() != command.casefold():
        return False
    wrapper_names = {command, f"{command}-script.py", f"{command}.py"}
    return active.name.casefold() in {name.casefold() for name in wrapper_names}


def _is_windows_pipx_launcher_pair(
    active: Path,
    selected: Path,
    *,
    command: str,
    is_windows: bool,
) -> bool:
    """Accept only pipx's verified exposed-copy and managed-venv launcher pair."""

    if not is_windows or Path(command).name != command:
        return False
    try:
        home = Path(os.environ["PIPX_HOME"]).resolve(strict=True)
        bin_directory = Path(os.environ["PIPX_BIN_DIR"]).resolve(strict=True)
    except (KeyError, OSError):
        return False
    if not home.is_dir() or not bin_directory.is_dir():
        return False
    launcher_name = f"{command}.exe"
    try:
        exposed = (bin_directory / launcher_name).resolve(strict=True)
        managed = (home / "venvs" / command / "Scripts" / launcher_name).resolve(strict=True)
    except OSError:
        return False
    if not _same_file(selected, exposed):
        return False
    if not (_same_file(active, managed) or _is_windows_console_wrapper(active, managed, command=command, is_windows=True)):
        return False
    return _same_file_content(exposed, managed)


def _same_file_content(first: Path, second: Path) -> bool:
    """Require copied pipx launchers to have the same complete byte content."""

    try:
        if first.stat().st_size != second.stat().st_size:
            return False
        with first.open("rb") as first_file, second.open("rb") as second_file:
            while first_chunk := first_file.read(64 * 1024):
                if first_chunk != second_file.read(64 * 1024):
                    return False
            return second_file.read(1) == b""
    except OSError:
        return False


def require_safe_entrypoint_identity(
    argv0: str,
    *,
    command: str = "roundwright",
    path: str | None = None,
    is_windows: bool | None = None,
    runtime_executable: str | None = None,
) -> None:
    """Fail closed before a future mutation-capable command is allowed to run."""

    identity = inspect_entrypoint_identity(
        argv0,
        command=command,
        path=path,
        is_windows=is_windows,
        runtime_executable=runtime_executable,
    )
    if not identity.safe:
        raise UnsafeEntrypointIdentityError(identity.reason)
