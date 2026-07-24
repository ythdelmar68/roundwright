"""The minimal public command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .deployment import blocked_command_shell_preflight
from .doctor import collect_diagnostics, render_diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roundwright",
        description="Roundwright read-only diagnostics and blocked command shells.",
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser("doctor", help="report read-only package diagnostics")
    subcommands.add_parser("status", help="report deployment modes without dispatching")
    subcommands.add_parser("run-once", help="fail-closed dispatch shell; does not dispatch work")
    subcommands.add_parser("run-daemon", help="fail-closed daemon shell; does not start a daemon")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a read-only command and return a deterministic process status."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "doctor":
        report = collect_diagnostics(sys.argv[0])
        render_diagnostics(report, sys.stdout)
        return report.exit_code
    if arguments.command == "status":
        _render_status(sys.stdout)
        return 0
    if arguments.command in {"run-once", "run-daemon"}:
        decision = blocked_command_shell_preflight()
        _render_blocked_shell(arguments.command, decision.reason, sys.stdout)
        return 3
    else:
        parser.print_help()
        return 0


def _render_status(output: object) -> None:
    """Render deployment status without reading state or authority receipts."""

    output.write("roundwright status\n")  # type: ignore[attr-defined]
    output.write("read-only: available (inspection only)\n")  # type: ignore[attr-defined]
    output.write("test-only: available (no dispatch authority)\n")  # type: ignore[attr-defined]
    output.write("authoritative: unavailable (requires an exact external receipt)\n")  # type: ignore[attr-defined]
    output.write("blocked: active for dispatch command shells\n")  # type: ignore[attr-defined]


def _render_blocked_shell(command: str, reason: str, output: object) -> None:
    """Render one owner-safe denial before a dispatch command can begin."""

    output.write(f"roundwright {command}\n")  # type: ignore[attr-defined]
    output.write("mode: blocked\n")  # type: ignore[attr-defined]
    output.write(f"authority: {reason}\n")  # type: ignore[attr-defined]
    output.write("dispatch: not started\n")  # type: ignore[attr-defined]
    output.write("result: blocked\n")  # type: ignore[attr-defined]
