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
    if selected != active and not _is_windows_console_wrapper(
        active, selected, command=command, is_windows=windows
    ):
        return EntrypointIdentity(False, "the selected command does not match this executable")
    return EntrypointIdentity(True, "one matching executable was discovered")


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
