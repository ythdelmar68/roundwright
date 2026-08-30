"""Write canonical public-safe Docker authority fixture material for CI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import argparse
import json
from pathlib import Path
import sqlite3
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.docker_authority import canonical_fixture_envelope, load_mounted_authority
from roundwright.native_host import InvocationSource, NativeHostControlStore


def seal_read_only_state(database: Path) -> None:
    """Checkpoint fixture lifecycle state before its read-only image mount.

    ``NativeHostControlStore`` correctly uses WAL for host-side mutations.
    The disposable consumer fixture is different: the first test-only and
    read-only image invocations must observe a self-contained SQLite database
    through a read-only bind mount.  Retaining a WAL journal would require
    SQLite to coordinate sidecars at runtime, which is incompatible with that
    mount contract.
    """

    try:
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if mode != ("delete",):
            raise sqlite3.Error("fixture database did not leave WAL mode")
    except sqlite3.Error as error:
        raise RuntimeError("native-host fixture state could not be sealed") from error
    for suffix in ("-wal", "-shm"):
        if database.with_name(database.name + suffix).exists():
            raise RuntimeError("native-host fixture state retained a journal sidecar")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--configuration", required=True, type=Path)
    parser.add_argument("--authentication", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    now = datetime.now(timezone.utc)
    material = canonical_fixture_envelope(arguments.candidate, now=now)
    # State is not allowed to independently reconstruct a native-host
    # installation from the candidate.  The mounted authority envelope is the
    # typed source that the consumer will parse, so initialize its persisted
    # control store from that exact serialized installation.
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    installation = load_mounted_authority(
        arguments.output, candidate_sha=arguments.candidate
    ).native_host_installation
    arguments.state.mkdir(parents=True, exist_ok=True)
    decision = NativeHostControlStore(arguments.state / "native-host.sqlite3").install(installation)
    if not decision.accepted:
        raise RuntimeError("native-host fixture state could not be initialized")
    # Fixture setup may create deterministic persisted lifecycle history; the
    # mounted image only observes it through the read-only adapter.
    control_store = NativeHostControlStore(arguments.state / "native-host.sqlite3")
    if not control_store.admit(installation, "fixture-restart", InvocationSource.ONE_SHOT, now=now).accepted:
        raise RuntimeError("native-host restart fixture could not be initialized")
    if not control_store.finish(installation, "fixture-restart", "completed", now=now).accepted:
        raise RuntimeError("native-host restart fixture could not be completed")
    if not control_store.admit(installation, "fixture-cancel", InvocationSource.ONE_SHOT, now=now).accepted:
        raise RuntimeError("native-host cancellation fixture could not be initialized")
    if not control_store.finish(installation, "fixture-cancel", "cancelled", now=now).accepted:
        raise RuntimeError("native-host cancellation fixture could not be completed")
    stale_at = now - timedelta(hours=1)
    if not control_store.admit(installation, "fixture-stale", InvocationSource.SCHEDULER_WAKE, now=stale_at, lease_for=timedelta(seconds=1)).accepted:
        raise RuntimeError("native-host stale fixture could not be initialized")
    if not control_store.recover_stale(installation, "fixture-stale", now=now, stale_after=timedelta(minutes=1)).accepted:
        raise RuntimeError("native-host stale fixture could not be recovered")
    if not control_store.admit(installation, "fixture-active", InvocationSource.ONE_SHOT, now=now).accepted:
        raise RuntimeError("native-host active-lock fixture could not be initialized")
    seal_read_only_state(arguments.state / "native-host.sqlite3")
    arguments.configuration.parent.mkdir(parents=True, exist_ok=True)
    binding = material["identity"]["runtime_binding"]
    authentication_identity = material["mounts"]["authentication_identity"]
    arguments.configuration.write_text(
        "[runtime]\n"
        f"candidate_sha = {json.dumps(arguments.candidate)}\n"
        f"binding = {json.dumps(binding)}\n",
        encoding="utf-8",
    )
    arguments.authentication.parent.mkdir(parents=True, exist_ok=True)
    arguments.authentication.write_text(
        "[operator]\n"
        f"candidate_sha = {json.dumps(arguments.candidate)}\n"
        f"identity = {json.dumps(authentication_identity)}\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
