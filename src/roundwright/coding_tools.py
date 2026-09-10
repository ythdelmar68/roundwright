"""Hermetic, capability-scoped filesystem and validation tools for Workers.

The native provider is never given a shell.  A product host translates a
declared Worker tool request into one of the methods below, which resolve it
against the selected worktree and retain a closed, public-safe result record.
This module deliberately has no provider, GitHub, or credential dependency.
"""

from __future__ import annotations

import hashlib
import os
import queue
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path


class CodingToolError(ValueError):
    """A requested operation is outside the sealed local capability."""


@dataclass(frozen=True)
class CodingToolEvent:
    """Closed evidence projection; content and absolute paths never escape."""

    tool: str
    path: str | None
    outcome: str
    before_digest: str | None = None
    after_digest: str | None = None
    exit_code: int | None = None
    output_digest: str | None = None


@dataclass(frozen=True)
class BoundedCodingCapability:
    """Immutable local authority for one selected disposable worktree."""

    root: Path
    readable_paths: tuple[str, ...]
    writable_paths: tuple[str, ...]
    validation_commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 30
    output_limit: int = 65_536

    def __post_init__(self) -> None:
        if (
            not isinstance(self.root, Path)
            or not self.readable_paths
            or not self.writable_paths
            or not self.validation_commands
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
            or type(self.output_limit) is not int
            or not 1 <= self.output_limit <= 1_000_000
            or any(not _relative(path) for path in self.readable_paths + self.writable_paths)
            or any(
                not command
                or any(type(part) is not str or not part for part in command)
                or not Path(command[0]).is_absolute()
                for command in self.validation_commands
            )
        ):
            raise CodingToolError("bounded coding capability is invalid")


class BoundedCodingTools:
    """Execute the only three coding capabilities permitted to a Worker."""

    def __init__(self, capability: BoundedCodingCapability) -> None:
        if type(capability) is not BoundedCodingCapability:
            raise CodingToolError("bounded coding capability is invalid")
        self._capability = capability
        self._root = capability.root.resolve(strict=True)
        if not self._root.is_dir() or _is_link(self._root):
            raise CodingToolError("selected workspace is invalid")

    def read(self, relative_path: str) -> tuple[str, CodingToolEvent]:
        path, display = self._path(relative_path, self._capability.readable_paths)
        try:
            value = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise CodingToolError("workspace read failed") from error
        return value, CodingToolEvent("workspace-read", display, "allowed", after_digest=_digest(value.encode("utf-8")))

    def write(self, relative_path: str, content: str) -> CodingToolEvent:
        if type(content) is not str or len(content.encode("utf-8")) > self._capability.output_limit:
            raise CodingToolError("workspace write content is invalid")
        path, display = self._path(relative_path, self._capability.writable_paths)
        try:
            before = path.read_bytes() if path.exists() else None
            # Do not create an unreviewed parent path as a side effect.
            if not path.parent.is_dir() or _is_link(path.parent):
                raise CodingToolError("workspace write parent is invalid")
            path.write_text(content, encoding="utf-8", newline="")
            after = path.read_bytes()
        except CodingToolError:
            raise
        except OSError as error:
            raise CodingToolError("workspace write failed") from error
        return CodingToolEvent("workspace-write", display, "allowed", _digest(before) if before is not None else None, _digest(after))

    def validate(self, command: tuple[str, ...]) -> CodingToolEvent:
        if type(command) is not tuple or command not in self._capability.validation_commands:
            raise CodingToolError("validation command is not allowlisted")
        executable = Path(command[0])
        if not executable.is_file() or _is_link(executable):
            raise CodingToolError("validation executable is invalid")
        try:
            process = subprocess.Popen(
                list(command), cwd=self._root, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                # A new process group lets the cleanup path own the validation
                # tree rather than merely timing out its immediate parent.
                start_new_session=os.name != "nt",
                creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
                env={"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
            )
        except OSError as error:
            raise CodingToolError("bounded validation could not start") from error
        try:
            output = _bounded_output(process, self._capability.timeout_seconds, self._capability.output_limit)
        except CodingToolError:
            _terminate_tree(process)
            raise
        finally:
            if process.stdout is not None:
                process.stdout.close()
        return CodingToolEvent("validation-execute", None, "allowed" if process.returncode == 0 else "failed", exit_code=process.returncode, output_digest=_digest(output))

    def _path(self, relative_path: str, allowed: tuple[str, ...]) -> tuple[Path, str]:
        if type(relative_path) is not str or relative_path not in allowed or not _relative(relative_path):
            raise CodingToolError("workspace path is not allowlisted")
        candidate = self._root.joinpath(*relative_path.split("/"))
        # Existing symlinks and junctions are never traversed.  Resolve first
        # so a foreign worktree cannot masquerade as an approved relative path.
        if any(_is_link(part) for part in (self._root, *candidate.parents)):
            raise CodingToolError("workspace path crosses a link")
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self._root)
        except ValueError as error:
            raise CodingToolError("workspace path escapes selected root") from error
        if resolved.exists() and _is_link(resolved):
            raise CodingToolError("workspace path crosses a link")
        return resolved, relative_path


def _relative(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value:
        return False
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and all(part not in {"", "."} for part in path.parts)


def _is_link(path: Path) -> bool:
    """Treat Windows junctions/reparse points like symlinks, never as roots."""

    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(junction) and junction())


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_output(process: subprocess.Popen[bytes], timeout_seconds: int, output_limit: int) -> bytes:
    """Read incrementally, so a noisy child cannot first exhaust host memory."""

    if process.stdout is None:
        raise CodingToolError("validation output pipe is unavailable")
    chunks: queue.Queue[bytes | None] = queue.Queue()

    def drain() -> None:
        try:
            while chunk := process.stdout.read(4096):
                chunks.put(chunk)
        finally:
            chunks.put(None)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout_seconds
    output = bytearray()
    closed = False
    while not closed:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CodingToolError("bounded validation timed out")
        try:
            chunk = chunks.get(timeout=remaining)
        except queue.Empty as error:
            raise CodingToolError("bounded validation timed out") from error
        if chunk is None:
            closed = True
            continue
        if len(output) + len(chunk) > output_limit:
            # Preserve a bounded prefix only for the digest; no raw output is
            # retained and the producer is stopped immediately.
            output.extend(chunk[: output_limit - len(output)])
            raise CodingToolError("bounded validation exceeded output budget")
        output.extend(chunk)
    try:
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise CodingToolError("bounded validation timed out") from error
    return bytes(output)


def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort process-tree cleanup for cancellation, cap, and timeout."""

    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False, timeout=5,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
    finally:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
