"""Config-free, read-only package diagnostics."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

from .identity import EntrypointIdentity, inspect_entrypoint_identity


@dataclass(frozen=True)
class DiagnosticReport:
    """Deterministic, path-free capabilities suitable for owner-facing output."""

    python_ready: bool
    entrypoint: EntrypointIdentity

    @property
    def healthy(self) -> bool:
        return self.python_ready and self.entrypoint.safe

    @property
    def exit_code(self) -> int:
        return 0 if self.healthy else 2


def collect_diagnostics(
    argv0: str,
    *,
    version_info: tuple[int, int] | None = None,
    path: str | None = None,
    runtime_executable: str | None = None,
) -> DiagnosticReport:
    """Collect diagnostics using only process information and filesystem reads."""

    version = sys.version_info[:2] if version_info is None else version_info
    return DiagnosticReport(
        python_ready=version == (3, 12),
        entrypoint=inspect_entrypoint_identity(
            argv0,
            path=path,
            runtime_executable=sys.executable if runtime_executable is None else runtime_executable,
        ),
    )


def render_diagnostics(report: DiagnosticReport, output: TextIO) -> None:
    """Render stable diagnostics without exposing paths, settings, or credentials."""

    python_state = "ready" if report.python_ready else "unavailable"
    entrypoint_state = "ready" if report.entrypoint.safe else "unavailable"
    result = "healthy" if report.healthy else "attention required"
    output.write("roundwright doctor\n")
    output.write(f"python: {python_state} (requires Python 3.12)\n")
    output.write(f"entrypoint: {entrypoint_state} ({report.entrypoint.reason})\n")
    output.write("deployment modes:\n")
    output.write("read-only: available (inspection only)\n")
    output.write("test-only: available (no dispatch authority)\n")
    output.write("authoritative: unavailable (requires an exact external receipt)\n")
    output.write("blocked: active for dispatch command shells\n")
    output.write(f"result: {result}\n")
