"""Bind one built package digest to every host qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from pathlib import Path


def _wheel(directory: Path) -> Path:
    wheels = tuple(sorted(path for path in directory.glob("roundwright-*.whl") if path.is_file()))
    if len(wheels) != 1:
        raise ValueError("expected exactly one roundwright wheel")
    return wheels[0]


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(directory: Path) -> dict[str, str]:
    wheel = _wheel(directory)
    return {"wheel": wheel.name, "sha256": _digest(wheel)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("write", "verify", "qualify"))
    parser.add_argument("dist", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    manifest_path = arguments.dist / "package-digest.json"
    if arguments.operation == "write":
        manifest_path.write_text(json.dumps(_manifest(arguments.dist), sort_keys=True) + "\n", encoding="utf-8")
        return 0
    try:
        expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("package digest manifest is unavailable") from error
    actual = _manifest(arguments.dist)
    if expected != actual:
        raise ValueError("downloaded package digest does not match the build artifact")
    if arguments.operation == "qualify":
        if arguments.output is None:
            raise ValueError("qualification output is required")
        receipt = {
            "package": actual,
            "platform": platform.system().lower(),
            "qualification": "pip-pipx-uv-cli-doctor-passed",
        }
        arguments.output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
