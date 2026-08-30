"""Config-free, read-only package diagnostics."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

from .docker_consumer import DockerConsumerDiagnosticReport, render_docker_consumer_diagnostics
from .identity import EntrypointIdentity, inspect_entrypoint_identity
from .provider_health import CodexFailure, provider_recovery_guidance


@dataclass(frozen=True)
class DiagnosticReport:
    """Deterministic, path-free capabilities suitable for owner-facing output."""

    python_ready: bool
    entrypoint: EntrypointIdentity
    provider_failure: CodexFailure | None = None
    docker_consumer: DockerConsumerDiagnosticReport | None = None

    @property
    def healthy(self) -> bool:
        return self.python_ready and self.entrypoint.safe and (
            self.docker_consumer is None or self.docker_consumer.ready
        )

    @property
    def exit_code(self) -> int:
        return 0 if self.healthy else 2


def collect_diagnostics(
    argv0: str,
    *,
    version_info: tuple[int, int] | None = None,
    path: str | None = None,
    runtime_executable: str | None = None,
    provider_failure: CodexFailure | None = None,
    docker_consumer: DockerConsumerDiagnosticReport | None = None,
) -> DiagnosticReport:
    """Collect diagnostics using only process information and filesystem reads."""

    version = sys.version_info[:2] if version_info is None else version_info
    if provider_failure is not None and type(provider_failure) is not CodexFailure:
        raise ValueError("provider failure is invalid")
    if docker_consumer is not None and type(docker_consumer) is not DockerConsumerDiagnosticReport:
        raise ValueError("Docker consumer report is invalid")
    return DiagnosticReport(
        python_ready=version == (3, 12),
        entrypoint=inspect_entrypoint_identity(
            argv0,
            path=path,
            runtime_executable=sys.executable if runtime_executable is None else runtime_executable,
        ),
        provider_failure=provider_failure,
        docker_consumer=docker_consumer,
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
    _render_provider_recovery(report.provider_failure, output)
    if report.docker_consumer is not None:
        render_docker_consumer_diagnostics(report.docker_consumer, output)
    output.write(f"result: {result}\n")


def render_provider_recovery_status(failure: CodexFailure | None, output: TextIO) -> None:
    """Render a static recovery status without inspecting credentials or providers."""

    _render_provider_recovery(failure, output)


def _render_provider_recovery(failure: CodexFailure | None, output: TextIO) -> None:
    if failure is None:
        output.write("provider authentication: qualification not requested\n")
        output.write("provider recovery: operator-run only; no login or credential change was attempted\n")
        return
    classification, detail, action = provider_recovery_guidance(failure)
    output.write(f"provider authentication: blocked ({classification})\n")
    output.write(f"provider detail: {detail}\n")
    output.write(f"provider next action: operator must {action}\n")
