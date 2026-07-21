"""The minimal public command line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from .doctor import collect_diagnostics, render_diagnostics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roundwright",
        description="Read-only Roundwright package diagnostics.",
    )
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser("doctor", help="report read-only package diagnostics")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run a read-only command and return a deterministic process status."""

    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.command != "doctor":
        parser.print_help()
        return 0

    report = collect_diagnostics(sys.argv[0])
    render_diagnostics(report, sys.stdout)
    return report.exit_code
