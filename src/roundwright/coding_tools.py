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
import re
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path


class CodingToolError(ValueError):
    """A requested operation is outside the sealed local capability."""

    def __init__(self, message: str, *, outcome: str = "denied", process_state: str = "failed", cancellation_state: str = "not-requested", ambiguity_state: str = "clear") -> None:
        super().__init__(message)
        if outcome not in {"denied", "failed", "timed-out", "cancelled", "ambiguous"}:
            raise ValueError("coding tool failure outcome is invalid")
        self.outcome = outcome
        self.process_state = process_state
        self.cancellation_state = cancellation_state
        self.ambiguity_state = ambiguity_state


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
class CodingSandboxResult:
    """Bounded result supplied by a reviewed OS-enforced sandbox."""

    exit_code: int
    output: bytes

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int or type(self.output) is not bytes:
            raise CodingToolError("coding sandbox result is invalid", outcome="failed")


_REVIEWED_HARNESS_SANDBOX_PIN = "0154817a6fba345b78af25017eb312a1b2349cd6"


@dataclass(frozen=True)
class ReviewedSandboxReceipt:
    """Public-safe, host-issued assertion for the reviewed OS boundary."""

    identity: str
    filesystem_policy_digest: str
    network_policy_digest: str
    credential_policy_digest: str
    executable_policy_digest: str
    child_cleanup_digest: str
    receipt_digest: str

    @classmethod
    def seal(cls, *, identity: str, filesystem_policy_digest: str, network_policy_digest: str, credential_policy_digest: str, executable_policy_digest: str, child_cleanup_digest: str) -> "ReviewedSandboxReceipt":
        core = {
            "schema": "roundwright-reviewed-sandbox-receipt/v1",
            "infrastructure_pin": _REVIEWED_HARNESS_SANDBOX_PIN,
            "identity": identity, "filesystem_policy_digest": filesystem_policy_digest,
            "network_policy_digest": network_policy_digest,
            "credential_policy_digest": credential_policy_digest,
            "executable_policy_digest": executable_policy_digest,
            "child_cleanup_digest": child_cleanup_digest,
        }
        return cls(identity, filesystem_policy_digest, network_policy_digest, credential_policy_digest, executable_policy_digest, child_cleanup_digest, _object_digest(core))

    def __post_init__(self) -> None:
        values = (self.identity, self.filesystem_policy_digest, self.network_policy_digest, self.credential_policy_digest, self.executable_policy_digest, self.child_cleanup_digest)
        core = {
            "schema": "roundwright-reviewed-sandbox-receipt/v1",
            "infrastructure_pin": _REVIEWED_HARNESS_SANDBOX_PIN,
            "identity": self.identity, "filesystem_policy_digest": self.filesystem_policy_digest,
            "network_policy_digest": self.network_policy_digest,
            "credential_policy_digest": self.credential_policy_digest,
            "executable_policy_digest": self.executable_policy_digest,
            "child_cleanup_digest": self.child_cleanup_digest,
        }
        if (any(type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in values)
                or self.receipt_digest != _object_digest(core)):
            raise CodingToolError("reviewed sandbox receipt is invalid")


class ReviewedValidationSandbox:
    """Operational boundary for an OS-enforced validation sandbox.

    Product hosts must bind a reviewed implementation which seals the mounted
    worktree, denies network and ambient credentials, and owns all children.
    The local direct launcher below is retained only for disposable unit-test
    fixtures and cannot satisfy a production runtime receipt.
    """

    @property
    def identity(self) -> str:
        raise NotImplementedError

    @property
    def receipt(self) -> ReviewedSandboxReceipt:
        raise NotImplementedError

    @property
    def receipt_digest(self) -> str:
        """Digest of the reviewed sandbox implementation and resource seal.

        The reviewed host issues this digest.  It binds its infrastructure
        pin, mounts, network and credential policy, child containment, and
        cleanup protocol; a Worker never derives it from local input.
        """
        receipt = self.receipt
        if type(receipt) is not ReviewedSandboxReceipt or receipt.identity != self.identity:
            raise CodingToolError("reviewed sandbox receipt is invalid")
        return receipt.receipt_digest

    def execute(self, *, command: tuple[str, ...], root: Path, timeout_seconds: int, output_limit: int) -> CodingSandboxResult:
        raise NotImplementedError


@dataclass(frozen=True)
class BoundedCodingCapability:
    """Immutable local authority for one selected disposable worktree."""

    root: Path
    readable_paths: tuple[str, ...]
    writable_paths: tuple[str, ...]
    validation_commands: tuple[tuple[str, ...], ...]
    timeout_seconds: int = 30
    output_limit: int = 65_536
    sandbox_identity: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.root, Path)
            or not self.readable_paths
            or not self.writable_paths
            or not self.validation_commands
            or type(self.timeout_seconds) is not int
            or not 1 <= self.timeout_seconds <= 300
            or type(self.output_limit) is not int
            or not 1 <= self.output_limit <= 65_536
            or any(not _relative(path) for path in self.readable_paths + self.writable_paths)
            or any(
                not command
                or any(type(part) is not str or not part for part in command)
                or not Path(command[0]).is_absolute()
                for command in self.validation_commands
            )
            or (self.sandbox_identity is not None and (type(self.sandbox_identity) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.sandbox_identity)))
        ):
            raise CodingToolError("bounded coding capability is invalid")


class BoundedCodingTools:
    """Execute the only three coding capabilities permitted to a Worker."""

    def __init__(self, capability: BoundedCodingCapability, *, validation_sandbox: ReviewedValidationSandbox | None = None) -> None:
        if type(capability) is not BoundedCodingCapability:
            raise CodingToolError("bounded coding capability is invalid")
        self._capability = capability
        self._root = capability.root.resolve(strict=True)
        if not self._root.is_dir() or _is_link(self._root):
            raise CodingToolError("selected workspace is invalid")
        if validation_sandbox is not None:
            if (not isinstance(validation_sandbox, ReviewedValidationSandbox)
                    or capability.sandbox_identity != validation_sandbox.identity
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", validation_sandbox.receipt_digest)):
                raise CodingToolError("reviewed validation sandbox is invalid")
        elif capability.sandbox_identity is not None:
            raise CodingToolError("reviewed validation sandbox is required")
        self._validation_sandbox = validation_sandbox

    @property
    def capability_root(self) -> Path:
        """Private operational root used only for candidate read-back."""

        return self._root

    @property
    def reviewed_sandbox_identity(self) -> str | None:
        return self._capability.sandbox_identity

    @property
    def capability_digest(self) -> str:
        """Digest every observed path, command, budget, executable, and seal."""
        executables: list[dict[str, str]] = []
        for command in self._capability.validation_commands:
            try:
                executable = Path(command[0]).resolve(strict=True)
                executable_digest = _digest(executable.read_bytes())
            except OSError as error:
                raise CodingToolError("validation executable is invalid") from error
            executables.append({"path": str(executable), "digest": executable_digest})
        return _object_digest({
            "schema": "roundwright-bounded-coding-capability/v1",
            "root_identity": _digest(str(self._root).encode("utf-8")),
            "readable_paths": self._capability.readable_paths,
            "writable_paths": self._capability.writable_paths,
            "validation_commands": self._capability.validation_commands,
            "executables": executables,
            "timeout_seconds": self._capability.timeout_seconds,
            "output_limit": self._capability.output_limit,
            "sandbox_identity": self._capability.sandbox_identity,
            "sandbox_receipt": self._validation_sandbox.receipt_digest if self._validation_sandbox is not None else None,
        })

    def read(self, relative_path: str) -> tuple[str, CodingToolEvent]:
        path, display = self._path(relative_path, self._capability.readable_paths)
        try:
            with path.open("rb") as source:
                raw = source.read(self._capability.output_limit + 1)
            if len(raw) > self._capability.output_limit:
                raise CodingToolError("workspace read exceeded output budget", outcome="failed")
            value = raw.decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise CodingToolError("workspace read failed") from error
        return value, CodingToolEvent("workspace-read", display, "allowed", after_digest=_digest(raw))

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
        _, event = self.validate_with_feedback(command)
        return event

    def validate_with_feedback(self, command: tuple[str, ...]) -> tuple[str, CodingToolEvent]:
        """Run one command and return bounded diagnostics for the active turn.

        Callers retain only the returned event; the text is transient SDK
        feedback and bounded by ``output_limit``.
        """
        if type(command) is not tuple or command not in self._capability.validation_commands:
            raise CodingToolError("validation command is not allowlisted")
        # The command tuple itself is the sealed executable identity.  Hosted
        # CPython installations commonly expose that exact executable through
        # a launcher symlink, so reject only a missing or non-file resolved
        # target rather than treating the platform's managed launcher as an
        # untrusted workspace link.
        try:
            executable = Path(command[0]).resolve(strict=True)
        except OSError as error:
            raise CodingToolError("validation executable is invalid") from error
        if not executable.is_file():
            raise CodingToolError("validation executable is invalid")
        if self._validation_sandbox is not None:
            try:
                sandbox_result = self._validation_sandbox.execute(command=command, root=self._root, timeout_seconds=self._capability.timeout_seconds, output_limit=self._capability.output_limit)
            except CodingToolError:
                raise
            except Exception as error:
                raise CodingToolError("reviewed validation sandbox failed", outcome="failed") from error
            if type(sandbox_result) is not CodingSandboxResult or len(sandbox_result.output) > self._capability.output_limit:
                raise CodingToolError("reviewed validation sandbox returned invalid output", outcome="failed")
            output, exit_code = sandbox_result.output, sandbox_result.exit_code
        else:
            try:
                process = subprocess.Popen(
                    list(command), cwd=self._root, shell=False, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    # This launcher is for disposable test fixtures only.  The
                    # production runtime requires ``ReviewedValidationSandbox``.
                    start_new_session=os.name != "nt",
                    creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
                    env={"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
                )
            except OSError as error:
                raise CodingToolError("bounded validation could not start", outcome="failed") from error
            try:
                output = _bounded_output(process, self._capability.timeout_seconds, self._capability.output_limit)
            except CodingToolError:
                _terminate_tree(process)
                raise
            finally:
                if process.stdout is not None:
                    process.stdout.close()
            exit_code = process.returncode
        event = CodingToolEvent("validation-execute", None, "allowed" if exit_code == 0 else "failed", exit_code=exit_code, output_digest=_digest(output))
        return output.decode("utf-8", errors="replace"), event

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


def _object_digest(value: object) -> str:
    import json
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _bounded_output(process: subprocess.Popen[bytes], timeout_seconds: int, output_limit: int) -> bytes:
    """Read incrementally, so a noisy child cannot first exhaust host memory."""

    if process.stdout is None:
        raise CodingToolError("validation output pipe is unavailable", outcome="failed")
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
            raise CodingToolError("bounded validation timed out", outcome="timed-out", cancellation_state="confirmed")
        try:
            chunk = chunks.get(timeout=remaining)
        except queue.Empty as error:
            raise CodingToolError("bounded validation timed out", outcome="timed-out", cancellation_state="confirmed") from error
        if chunk is None:
            closed = True
            continue
        if len(output) + len(chunk) > output_limit:
            # Preserve a bounded prefix only for the digest; no raw output is
            # retained and the producer is stopped immediately.
            output.extend(chunk[: output_limit - len(output)])
            raise CodingToolError("bounded validation exceeded output budget", outcome="failed", cancellation_state="confirmed")
        output.extend(chunk)
    try:
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as error:
        raise CodingToolError("bounded validation timed out", outcome="timed-out", cancellation_state="confirmed") from error
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
