"""Fail closed unless one hosted record names the exact build candidate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.hosted_evidence import HostedEvidence, HostedEvidenceError, validate_hosted_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--branch", required=True)
    arguments = parser.parse_args()
    try:
        payload = json.loads(arguments.record.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("record is not an object")
        raw_artifacts = payload.get("artifacts", ())
        if not isinstance(raw_artifacts, list):
            raise ValueError("artifacts are not a list")
        record = HostedEvidence(
            repository=payload.get("repository"),
            workflow=payload.get("workflow"),
            head_sha=payload.get("head_sha"),
            ref=payload.get("ref"),
            artifacts=tuple(tuple(item) if isinstance(item, list) else item for item in raw_artifacts),
        )
        validate_hosted_evidence(
            (record,), repository=arguments.repository, workflow=arguments.workflow,
            head_sha=arguments.head, branch=arguments.branch,
        )
    except (HostedEvidenceError, TypeError, ValueError):
        print("hosted evidence rejected")
        return 2
    print("hosted evidence accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
