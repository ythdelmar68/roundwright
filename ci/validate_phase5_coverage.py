"""Validate and render the public-safe Phase 5 legacy-parity coverage map.

The source ledgers intentionally retain historical, neutral descriptions.  This
tool does not reproduce them: it locks the selected opaque identifiers to their
one Phase 5 owner and produces a candidate-bound read-back artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "docs" / "migration" / "phase5-coverage-map.json"
DEFAULT_LEDGER = ROOT / "docs" / "migration" / "legacy-decision-ledger.md"
DEFAULT_TESTS = ROOT / "docs" / "migration" / "test-disposition.md"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
ITEM_ID = re.compile(r"(?:EV|TS)-[0-9A-F]{12}\Z")
ISSUE = re.compile(r"#1(?:1[2-9]|20)\Z")
DISPOSITIONS = frozenset({"adopt", "reframe", "merge", "defer", "retire"})
STATUSES = frozenset({"proposed", "blocked", "owner-routed"})
CONFIDENCES = frozenset({"low", "medium", "high"})

# This is intentionally independent of the rendered map.  Adding, dropping,
# or reassigning a selected identifier requires a reviewed code change.
EXPECTED_OWNERS = {
    "EV-0F91CDC81DEA": "#120", "EV-11F2ACA46283": "#118", "EV-305347E6CE3A": "#120",
    "EV-312D7F292898": "#119", "EV-346AD74E1323": "#115", "EV-3C97D24C7ECE": "#114",
    "EV-457FC17699F7": "#115", "EV-50613D9E02C5": "#118", "EV-5AAD74DCC184": "#119",
    "EV-6FCE77814A22": "#119", "EV-70980A46DE9E": "#120", "EV-8B3ADA5DCF43": "#115",
    "EV-9C3DC7F9F8A0": "#115", "EV-A66CF4326777": "#115", "EV-AC0B36BE5F29": "#114",
    "EV-B766FE226AE0": "#115", "EV-BC32C3A410F6": "#119", "EV-CA4BBED76303": "#117",
    "EV-F467391FEB1E": "#119",
    "TS-0351A26DBE99": "#118", "TS-06896C06863C": "#114", "TS-126BD58C04F8": "#119",
    "TS-176D0551EC9C": "#114", "TS-28CD3D7A4ECA": "#115", "TS-3135EFA60899": "#120",
    "TS-38B72E44AD2C": "#115", "TS-5ECC2458A2BF": "#118", "TS-617815F1AF67": "#120",
    "TS-658FBA7F941B": "#115", "TS-9C2FE6B21A18": "#115", "TS-A0D00D74FBB0": "#119",
    "TS-A1630BB5E806": "#115", "TS-D5AC3D130518": "#115", "TS-E0FEB594E104": "#114",
    "TS-E5C8F4C6FEA2": "#119", "TS-E739091723AA": "#120", "TS-EABDEABE0FC0": "#119",
    "TS-ECEA91EAD390": "#115", "TS-F6DC3340D9FF": "#114", "TS-F8EA5D587E87": "#115",
    "TS-FCE318E20A2A": "#119",
}

FORBIDDEN_TEXT = re.compile(
    r"(?:https?://|file://|[A-Za-z]:[\\/]|\\\\|\.codex/|private[-_ ]?(?:repo|path|url)|credential|password|token|secret|owner reasoning)",
    re.IGNORECASE,
)


class CoverageError(ValueError):
    """The coverage map is incomplete, stale, or unsafe to publish."""


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError("coverage map is unavailable") from error
    if type(value) is not dict:
        raise CoverageError("coverage map must be an object")
    return value


def _source_identifiers(path: Path, prefix: str) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise CoverageError("source ledger is unavailable") from error
    identifiers = re.findall(rf"\| ({prefix}-[0-9A-F]{{12}}) \|", text)
    return set(identifiers)


def validate(source: Path, ledger: Path, tests: Path) -> dict[str, Any]:
    document = _read_json(source)
    if set(document) != {"schema", "sources", "items"} or document["schema"] != "roundwright-phase5-coverage/v1":
        raise CoverageError("coverage map schema is invalid")
    if type(document["sources"]) is not dict or set(document["sources"]) != {"ledger_sha256", "test_disposition_sha256"}:
        raise CoverageError("coverage source bindings are invalid")
    source_bindings = document["sources"]
    if any(type(value) is not str or not SHA256.fullmatch(value) for value in source_bindings.values()):
        raise CoverageError("coverage source digest is invalid")
    if source_bindings["ledger_sha256"] != _digest(ledger.read_bytes()) or source_bindings["test_disposition_sha256"] != _digest(tests.read_bytes()):
        raise CoverageError("coverage source content has drifted")
    items = document["items"]
    if type(items) is not list or not items:
        raise CoverageError("coverage items are invalid")
    observed: dict[str, str] = {}
    for item in items:
        if type(item) is not dict or set(item) != {"id", "disposition", "destination", "owner_issue", "prerequisites", "verification", "confidence", "status"}:
            raise CoverageError("coverage item fields are invalid")
        identifier = item["id"]
        if type(identifier) is not str or not ITEM_ID.fullmatch(identifier) or identifier in observed:
            raise CoverageError("coverage identifier is invalid or duplicate")
        if item["owner_issue"] != EXPECTED_OWNERS.get(identifier) or not ISSUE.fullmatch(item["owner_issue"]):
            raise CoverageError("coverage owner issue has drifted")
        if item["disposition"] not in DISPOSITIONS or item["status"] not in STATUSES or item["confidence"] not in CONFIDENCES:
            raise CoverageError("coverage disposition metadata is invalid")
        if type(item["destination"]) is not str or type(item["verification"]) is not str or not item["destination"] or not item["verification"]:
            raise CoverageError("coverage destination or verification is invalid")
        prerequisites = item["prerequisites"]
        if type(prerequisites) is not list or not prerequisites or any(type(value) is not str or not ISSUE.fullmatch(value) for value in prerequisites):
            raise CoverageError("coverage prerequisites are invalid")
        if item["status"] in {"blocked", "owner-routed"} and item["confidence"] != "low":
            raise CoverageError("blocked or owner-routed items must remain low confidence")
        if FORBIDDEN_TEXT.search(_canonical(item).decode("ascii")):
            raise CoverageError("coverage map contains unsafe text")
        observed[identifier] = item["owner_issue"]
    if observed != EXPECTED_OWNERS:
        raise CoverageError("coverage inventory is missing, unknown, or unassigned identifiers")
    ledger_ids = _source_identifiers(ledger, "EV")
    test_ids = _source_identifiers(tests, "TS")
    if not set(identifier for identifier in observed if identifier.startswith("EV-")) <= ledger_ids:
        raise CoverageError("coverage ledger identifier is stale")
    if not set(identifier for identifier in observed if identifier.startswith("TS-")) <= test_ids:
        raise CoverageError("coverage test identifier is stale")
    return document


def render(source: Path, ledger: Path, tests: Path, candidate: str, output: Path) -> None:
    if not COMMIT_SHA.fullmatch(candidate):
        raise CoverageError("candidate SHA is invalid")
    document = validate(source, ledger, tests)
    payload = {"schema": "roundwright-phase5-coverage-readback/v1", "candidate_sha": candidate, "source_digest": _digest(_canonical(document)), "items": document["items"]}
    receipt = {**payload, "coverage_digest": _digest(_canonical(payload))}
    output.write_bytes(_canonical(receipt) + b"\n")


def verify(source: Path, ledger: Path, tests: Path, candidate: str, manifest: Path) -> None:
    if not COMMIT_SHA.fullmatch(candidate):
        raise CoverageError("candidate SHA is invalid")
    document = validate(source, ledger, tests)
    actual = _read_json(manifest)
    payload = {"schema": "roundwright-phase5-coverage-readback/v1", "candidate_sha": candidate, "source_digest": _digest(_canonical(document)), "items": document["items"]}
    expected = {**payload, "coverage_digest": _digest(_canonical(payload))}
    if actual != expected:
        raise CoverageError("candidate-bound coverage manifest does not match")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("validate", "render", "verify"))
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--tests", type=Path, default=DEFAULT_TESTS)
    parser.add_argument("--candidate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    arguments = parser.parse_args()
    if arguments.operation == "validate":
        validate(arguments.source, arguments.ledger, arguments.tests)
    elif arguments.operation == "render":
        if not arguments.candidate or arguments.output is None:
            raise CoverageError("render requires a candidate and output")
        render(arguments.source, arguments.ledger, arguments.tests, arguments.candidate, arguments.output)
    else:
        if not arguments.candidate or arguments.manifest is None:
            raise CoverageError("verify requires a candidate and manifest")
        verify(arguments.source, arguments.ledger, arguments.tests, arguments.candidate, arguments.manifest)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CoverageError as error:
        raise SystemExit(f"phase-5 coverage validation failed: {error}")
