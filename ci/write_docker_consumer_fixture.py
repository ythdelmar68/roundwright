"""Write canonical public-safe Docker authority fixture material for CI."""

from __future__ import annotations

from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.docker_authority import canonical_fixture_envelope


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    material = canonical_fixture_envelope(arguments.candidate, now=datetime.now(timezone.utc))
    arguments.output.write_text(
        json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
