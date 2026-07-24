"""Write the exact candidate and artifact identities from one hosted build."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    arguments = parser.parse_args()
    artifacts = sorted(arguments.artifact_dir.glob("roundwright-*"))
    if not artifacts:
        raise SystemExit("no package artifacts were built")
    print(json.dumps({
        "repository": arguments.repository,
        "workflow": arguments.workflow,
        "head_sha": arguments.head,
        "ref": arguments.ref,
        "artifacts": [[path.name, digest(path)] for path in artifacts],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
