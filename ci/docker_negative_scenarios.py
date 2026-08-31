"""Canonical, public-safe diagnostics for Docker qualification negatives.

This table deliberately represents the complete observation emitted by the
installed preflight.  It is consumed by hosted qualification and inspected by
the focused contract tests, preventing a scenario label from silently standing
in for unrelated dependent mount observations.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass


_MOUNTS = ("authentication", "authority-receipt", "configuration", "repository", "state")


@dataclass(frozen=True)
class NegativeScenario:
    mode: str
    reason: str
    candidate: str = "match"
    authentication: str = "ready"
    authority_receipt: str | None = None
    authority_mount: str | None = None
    configuration: str = "ready"
    repository: str = "ready"
    state: str = "ready"

    def render(self) -> str:
        authority_mount = self.authority_mount
        authority_receipt = self.authority_receipt
        if authority_mount is None:
            authority_mount = "ready" if self.mode == "authoritative" else "not-applicable"
        if authority_receipt is None:
            authority_receipt = "match" if self.mode == "authoritative" else "not required"
        values = {
            "authentication": self.authentication,
            "authority-receipt": authority_mount,
            "configuration": self.configuration,
            "repository": self.repository,
            "state": self.state,
        }
        return "\n".join((
            "roundwright Docker consumer preflight",
            f"mode: {self.mode}",
            *(f"{name} mount: {values[name]}" for name in _MOUNTS),
            f"candidate: {self.candidate}",
            "package: match",
            "base image: match",
            f"authority receipt: {authority_receipt}",
            f"result: blocked ({self.reason})",
        ))


def _mount(mode: str, expected: str, **values: str) -> NegativeScenario:
    name, status = expected.split(": ", 1)
    key = name.replace(" mount", "").replace("authority-receipt", "authority_mount")
    values[key] = status
    return NegativeScenario(mode, expected.replace("mount: ", "mount is "), **values)


_SCENARIOS = {
    # An omitted state bind leaves both typed identities unparsable because
    # their independently persisted native-host binding cannot be read.
    ("test-only", "state mount: missing"): NegativeScenario("test-only", "state mount is missing", authentication="evidence-mismatch", configuration="evidence-mismatch", state="missing"),
    ("read-only", "state mount: permission-mismatch"): _mount("read-only", "state mount: permission-mismatch"),
    ("authoritative", "authority-receipt mount: missing"): _mount("authoritative", "authority-receipt mount: missing", authority_receipt="missing"),
    ("test-only", "authority-receipt mount: permission-mismatch"): _mount("test-only", "authority-receipt mount: permission-mismatch"),
    ("authoritative", "state mount: ownership-mismatch"): _mount("authoritative", "state mount: ownership-mismatch"),
    # A dirty checkout and the image's empty /workspace both fail the strict
    # verifier before it can observe a detached candidate, so this is
    # deliberately candidate *missing*, not merely a ready identity paired
    # with an unrelated mount error.
    ("test-only", "repository mount: evidence-mismatch"): _mount("test-only", "repository mount: evidence-mismatch", candidate="missing"),
    ("read-only", "configuration mount: evidence-mismatch"): _mount("read-only", "configuration mount: evidence-mismatch"),
    ("test-only", "authentication mount: evidence-mismatch"): _mount("test-only", "authentication mount: evidence-mismatch"),
    ("authoritative", "state mount: evidence-mismatch"): _mount("authoritative", "state mount: evidence-mismatch", authentication="evidence-mismatch", configuration="evidence-mismatch"),
    ("read-only", "configuration mount: missing"): _mount("read-only", "configuration mount: missing"),
    ("test-only", "authentication mount: missing"): _mount("test-only", "authentication mount: missing"),
    ("authoritative", "state mount: permission-mismatch"): _mount("authoritative", "state mount: permission-mismatch"),
    ("test-only", "repository mount: permission-mismatch"): _mount("test-only", "repository mount: permission-mismatch"),
    ("read-only", "configuration mount: permission-mismatch"): _mount("read-only", "configuration mount: permission-mismatch"),
    ("test-only", "authentication mount: permission-mismatch"): _mount("test-only", "authentication mount: permission-mismatch"),
    ("authoritative", "authority-receipt mount: permission-mismatch"): _mount("authoritative", "authority-receipt mount: permission-mismatch"),
    ("authoritative", "authority receipt: mismatch"): NegativeScenario("authoritative", "authority receipt identity is missing or mismatched", authority_receipt="missing"),
}


def scenario(mode: str, expected: str) -> NegativeScenario:
    """Return exactly one reviewed projection or reject the workflow case."""

    try:
        return _SCENARIOS[(mode, expected)]
    except KeyError as error:
        raise ValueError("Docker negative scenario is not declared") from error


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 2:
        return 2
    try:
        print(scenario(*arguments).render())
    except ValueError:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
