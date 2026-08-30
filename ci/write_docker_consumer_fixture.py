"""Write canonical public-safe Docker authority fixture material for CI."""

from __future__ import annotations

from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.docker_authority import canonical_fixture_envelope, canonical_native_host_installation
from roundwright.native_host import NativeHostControlStore


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
    arguments.state.mkdir(parents=True, exist_ok=True)
    installation = canonical_native_host_installation(arguments.candidate, now=now)
    decision = NativeHostControlStore(arguments.state / "native-host.sqlite3").install(installation)
    if not decision.accepted:
        raise RuntimeError("native-host fixture state could not be initialized")
    arguments.configuration.parent.mkdir(parents=True, exist_ok=True)
    arguments.configuration.write_text("[runtime]\nschema_version = 1\n", encoding="utf-8")
    arguments.authentication.parent.mkdir(parents=True, exist_ok=True)
    arguments.authentication.write_text("# operator-provided authentication fixture; no credential material\n", encoding="utf-8")
    arguments.output.write_text(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
