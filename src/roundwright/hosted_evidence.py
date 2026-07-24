"""Validate public hosted-build evidence against one exact package candidate."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


class HostedEvidenceError(ValueError):
    """Raised when hosted verification evidence is absent or not exact."""


@dataclass(frozen=True)
class HostedEvidence:
    """The non-secret identity emitted for one hosted package build."""

    repository: str
    workflow: str
    head_sha: str
    ref: str
    artifacts: tuple[tuple[str, str], ...]


def validate_hosted_evidence(
    records: Iterable[HostedEvidence],
    *,
    repository: str,
    workflow: str,
    head_sha: str,
    branch: str,
) -> HostedEvidence:
    """Require exactly one branch build and its digested wheel/sdist evidence."""

    if not _COMMIT.fullmatch(head_sha):
        raise HostedEvidenceError("candidate identity is invalid")
    records = tuple(records)
    if not records:
        raise HostedEvidenceError("hosted evidence is missing")
    if len(records) != 1:
        raise HostedEvidenceError("hosted evidence is duplicate")
    record = records[0]
    if not all(isinstance(value, str) for value in (record.repository, record.workflow, record.head_sha, record.ref)):
        raise HostedEvidenceError("hosted evidence is invalid")
    if record.repository != repository:
        raise HostedEvidenceError("hosted evidence names a different repository")
    if record.workflow != workflow:
        raise HostedEvidenceError("hosted evidence names a different workflow")
    if record.ref != f"refs/heads/{branch}" or record.ref.startswith("refs/pull/"):
        raise HostedEvidenceError("hosted evidence does not name the candidate branch")
    if record.head_sha != head_sha:
        raise HostedEvidenceError("hosted evidence is stale for the candidate")
    if not isinstance(record.artifacts, tuple) or not record.artifacts:
        raise HostedEvidenceError("hosted artifact evidence is invalid")
    names: set[str] = set()
    for artifact in record.artifacts:
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            raise HostedEvidenceError("hosted artifact evidence is invalid")
        name, digest = artifact
        if not isinstance(name, str) or not name or not isinstance(digest, str) or not _SHA256.fullmatch(digest) or name in names:
            raise HostedEvidenceError("hosted artifact evidence is invalid")
        names.add(name)
    return record
