"""Typed, exact-candidate evidence from a hosted CI/check provider.

The module deliberately accepts already-normalized, public-safe values.  It
does not invoke a provider, inspect logs, or use local test/package results as
hosted evidence.  A provider adapter may be disabled, and a fake adapter is
provided for hermetic coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Iterable, Protocol


_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")


class HostedEvidenceError(ValueError):
    """Raised when hosted verification evidence is absent or not exact."""


class HostedCheckState(StrEnum):
    """The public terminal or non-terminal state of one hosted operation."""

    QUEUED = "queued"
    IN_PROGRESS = "in-progress"
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    NEUTRAL = "neutral"


class HostedEvidenceOutcome(StrEnum):
    """A gate result; policy and observation are intentionally separate."""

    PASS = "pass"
    QUEUED = "queued"
    IN_PROGRESS = "in-progress"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    NEUTRAL = "neutral"
    STALE = "stale"
    MISSING = "missing"
    DUPLICATE = "duplicate"
    MALFORMED = "malformed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class HostedCheck:
    """One normalized check run and its suite/checkout attestations."""

    check_id: str
    suite_id: str
    name: str
    state: HostedCheckState
    head_sha: str
    checked_out_sha: str


@dataclass(frozen=True)
class HostedWorkflowJob:
    """One normalized workflow job; it must attest to the candidate checkout."""

    job_id: str
    name: str
    state: HostedCheckState
    checked_out_sha: str


@dataclass(frozen=True)
class HostedWorkflowRun:
    """One normalized workflow run and its jobs."""

    run_id: str
    workflow: str
    state: HostedCheckState
    head_sha: str
    ref: str
    jobs: tuple[HostedWorkflowJob, ...]


@dataclass(frozen=True)
class HostedCheckEvidence:
    """The complete, public-safe observation used to gate one candidate."""

    repository: str
    workflow: str
    candidate_sha: str
    branch: str
    observed_at: int
    checks: tuple[HostedCheck, ...]
    workflow_runs: tuple[HostedWorkflowRun, ...]
    artifacts: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class HostedCheckPolicy:
    """Required hosted checks/artifacts; it never derives policy from results."""

    required_checks: tuple[str, ...]
    required_artifacts: tuple[str, ...] = ()
    max_age_seconds: int = 900


@dataclass(frozen=True)
class HostedCheckEvaluation:
    """Curated hosted result suitable for a Shadow projection or gate."""

    outcome: HostedEvidenceOutcome
    candidate_sha: str
    required_checks: tuple[str, ...]
    observed_checks: tuple[str, ...]
    evidence_digest: str


class HostedCheckSource(Protocol):
    """A narrow real-provider seam; implementations return no raw payloads."""

    def read(self, *, repository: str, workflow: str, candidate_sha: str, branch: str) -> HostedCheckEvidence: ...


class HostedCheckAdapter:
    """Disableable real adapter with an explicit, candidate-bound source."""

    def __init__(self, source: HostedCheckSource | None = None, *, enabled: bool = False) -> None:
        if source is not None and not hasattr(source, "read"):
            raise HostedEvidenceError("hosted adapter source is invalid")
        self._source = source
        self._enabled = enabled

    def read(self, *, repository: str, workflow: str, candidate_sha: str, branch: str) -> HostedCheckEvidence:
        if not self._enabled or self._source is None:
            raise HostedEvidenceError("hosted adapter is disabled")
        evidence = self._source.read(repository=repository, workflow=workflow, candidate_sha=candidate_sha, branch=branch)
        if type(evidence) is not HostedCheckEvidence:
            raise HostedEvidenceError("hosted adapter returned malformed evidence")
        return evidence


class FakeHostedCheckAdapter:
    """Deterministic, network-free adapter for targeted and full test coverage."""

    def __init__(self, evidence: HostedCheckEvidence | None = None) -> None:
        self._evidence = evidence
        self.calls: list[tuple[str, str, str, str]] = []

    def read(self, *, repository: str, workflow: str, candidate_sha: str, branch: str) -> HostedCheckEvidence:
        self.calls.append((repository, workflow, candidate_sha, branch))
        if self._evidence is None:
            raise HostedEvidenceError("hosted evidence is missing")
        return self._evidence


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
    if not any(name.endswith(".whl") for name in names) or not any(name.endswith(".tar.gz") for name in names):
        raise HostedEvidenceError("hosted artifact evidence is incomplete")
    return record


def evaluate_hosted_check_evidence(
    evidence: HostedCheckEvidence,
    *,
    repository: str,
    workflow: str,
    candidate_sha: str,
    branch: str,
    policy: HostedCheckPolicy,
    now: int,
) -> HostedCheckEvaluation:
    """Evaluate one complete hosted observation without inferring policy.

    Identity, freshness, suite/run/job checkout, artifact, and duplication
    defects fail closed with curated exceptions.  A valid observation that is
    merely queued, failed, cancelled, skipped, or neutral returns a distinct
    typed outcome so callers can choose the next action without reparsing a
    provider response.
    """

    _require_candidate(candidate_sha)
    if type(evidence) is not HostedCheckEvidence or type(policy) is not HostedCheckPolicy:
        raise HostedEvidenceError("hosted evidence is malformed")
    if type(now) is not int or now < 0:
        raise HostedEvidenceError("hosted observation time is invalid")
    required_checks = _validate_policy(policy)
    _validate_identity(evidence, repository, workflow, candidate_sha, branch, now, policy.max_age_seconds)
    _validate_artifacts(evidence.artifacts, required=policy.required_artifacts)
    checks = _validate_checks(evidence.checks, candidate_sha)
    runs = _validate_workflows(evidence.workflow_runs, workflow, candidate_sha, branch)
    observed = tuple(sorted(check.name for check in checks))
    missing = tuple(name for name in required_checks if name not in observed)
    digest = _evidence_digest(evidence)
    if missing:
        return HostedCheckEvaluation(HostedEvidenceOutcome.MISSING, candidate_sha, required_checks, observed, digest)
    required = tuple(check for check in checks if check.name in required_checks)
    outcome = _combined_outcome((
        *(check.state for check in required),
        *(run.state for run in runs),
        *(job.state for run in runs for job in run.jobs),
    ))
    return HostedCheckEvaluation(outcome, candidate_sha, required_checks, observed, digest)


def _validate_policy(policy: HostedCheckPolicy) -> tuple[str, ...]:
    if (
        type(policy.required_checks) is not tuple
        or not policy.required_checks
        or any(not _valid_name(value) for value in policy.required_checks)
        or len(set(policy.required_checks)) != len(policy.required_checks)
        or tuple(sorted(policy.required_checks)) != policy.required_checks
        or type(policy.required_artifacts) is not tuple
        or any(not _valid_name(value) for value in policy.required_artifacts)
        or len(set(policy.required_artifacts)) != len(policy.required_artifacts)
        or tuple(sorted(policy.required_artifacts)) != policy.required_artifacts
        or type(policy.max_age_seconds) is not int
        or not 0 <= policy.max_age_seconds <= 86_400
    ):
        raise HostedEvidenceError("hosted check policy is invalid")
    return policy.required_checks


def _validate_identity(
    evidence: HostedCheckEvidence, repository: str, workflow: str, candidate_sha: str,
    branch: str, now: int, max_age_seconds: int,
) -> None:
    if not all(type(value) is str for value in (repository, workflow, branch)) or not _valid_name(repository) or not _valid_name(workflow) or not _valid_branch(branch):
        raise HostedEvidenceError("hosted expected identity is invalid")
    if not all(type(value) is str for value in (evidence.repository, evidence.workflow, evidence.candidate_sha, evidence.branch)):
        raise HostedEvidenceError("hosted evidence is malformed")
    if evidence.repository != repository:
        raise HostedEvidenceError("hosted evidence names a different repository")
    if evidence.workflow != workflow:
        raise HostedEvidenceError("hosted evidence names a different workflow")
    if evidence.candidate_sha != candidate_sha:
        raise HostedEvidenceError("hosted evidence is stale for the candidate")
    if evidence.branch != branch or evidence.branch.startswith("refs/pull/"):
        raise HostedEvidenceError("hosted evidence does not name the candidate branch")
    if type(evidence.observed_at) is not int or evidence.observed_at < 0:
        raise HostedEvidenceError("hosted observation is malformed")
    if evidence.observed_at > now or now - evidence.observed_at > max_age_seconds:
        raise HostedEvidenceError("hosted evidence is stale")


def _validate_checks(checks: object, candidate_sha: str) -> tuple[HostedCheck, ...]:
    if type(checks) is not tuple or not checks:
        raise HostedEvidenceError("hosted checks are missing")
    seen_ids: set[str] = set()
    names: set[str] = set()
    for check in checks:
        if (
            type(check) is not HostedCheck
            or not _valid_token(check.check_id)
            or not _valid_token(check.suite_id)
            or not _valid_name(check.name)
            or type(check.state) is not HostedCheckState
            or check.head_sha != candidate_sha
            or check.checked_out_sha != candidate_sha
        ):
            raise HostedEvidenceError("hosted check evidence is malformed")
        if check.check_id in seen_ids or check.name in names:
            raise HostedEvidenceError("hosted check evidence is duplicate")
        seen_ids.add(check.check_id)
        names.add(check.name)
    return checks


def _validate_workflows(
    runs: object, workflow: str, candidate_sha: str, branch: str,
) -> tuple[HostedWorkflowRun, ...]:
    if type(runs) is not tuple or len(runs) != 1:
        raise HostedEvidenceError("hosted workflow evidence is duplicate" if type(runs) is tuple and len(runs) > 1 else "hosted workflow evidence is missing")
    run = runs[0]
    if (
        type(run) is not HostedWorkflowRun
        or not _valid_token(run.run_id)
        or run.workflow != workflow
        or type(run.state) is not HostedCheckState
        or run.head_sha != candidate_sha
        or run.ref != f"refs/heads/{branch}"
        or not isinstance(run.jobs, tuple)
        or not run.jobs
    ):
        raise HostedEvidenceError("hosted workflow evidence is malformed")
    jobs: set[str] = set()
    names: set[str] = set()
    for job in run.jobs:
        if (
            type(job) is not HostedWorkflowJob
            or not _valid_token(job.job_id)
            or not _valid_name(job.name)
            or type(job.state) is not HostedCheckState
            or job.checked_out_sha != candidate_sha
        ):
            raise HostedEvidenceError("hosted workflow job evidence is malformed")
        if job.job_id in jobs or job.name in names:
            raise HostedEvidenceError("hosted workflow job evidence is duplicate")
        jobs.add(job.job_id)
        names.add(job.name)
    if run.state is HostedCheckState.SUCCESS and any(job.state is not HostedCheckState.SUCCESS for job in run.jobs):
        raise HostedEvidenceError("hosted workflow and job states conflict")
    if run.state not in {HostedCheckState.QUEUED, HostedCheckState.IN_PROGRESS, HostedCheckState.SUCCESS} and all(job.state is HostedCheckState.SUCCESS for job in run.jobs):
        raise HostedEvidenceError("hosted workflow and job states conflict")
    return runs


def _validate_artifacts(artifacts: object, *, required: tuple[str, ...]) -> None:
    if type(artifacts) is not tuple:
        raise HostedEvidenceError("hosted artifact evidence is malformed")
    values: dict[str, str] = {}
    for artifact in artifacts:
        if type(artifact) is tuple and len(artifact) == 2 and type(artifact[0]) is str and artifact[0] in values:
            raise HostedEvidenceError("hosted artifact evidence is duplicate")
        if (
            type(artifact) is not tuple or len(artifact) != 2
            or not _valid_name(artifact[0]) or type(artifact[1]) is not str
            or not _SHA256.fullmatch(artifact[1])
        ):
            raise HostedEvidenceError("hosted artifact evidence is malformed")
        values[artifact[0]] = artifact[1]
    if any(name not in values for name in required):
        raise HostedEvidenceError("hosted artifact evidence is incomplete")


def _combined_outcome(states: Iterable[HostedCheckState]) -> HostedEvidenceOutcome:
    values = tuple(states)
    if not values:
        return HostedEvidenceOutcome.MISSING
    for state, outcome in (
        (HostedCheckState.FAILURE, HostedEvidenceOutcome.FAILURE),
        (HostedCheckState.CANCELLED, HostedEvidenceOutcome.CANCELLED),
        (HostedCheckState.SKIPPED, HostedEvidenceOutcome.SKIPPED),
        (HostedCheckState.NEUTRAL, HostedEvidenceOutcome.NEUTRAL),
        (HostedCheckState.IN_PROGRESS, HostedEvidenceOutcome.IN_PROGRESS),
        (HostedCheckState.QUEUED, HostedEvidenceOutcome.QUEUED),
    ):
        if state in values:
            return outcome
    return HostedEvidenceOutcome.PASS


def _evidence_digest(evidence: HostedCheckEvidence) -> str:
    """Return a deterministic public-safe identity without logs or paths."""

    import hashlib
    import json

    value = {
        "repository": evidence.repository, "workflow": evidence.workflow,
        "candidate_sha": evidence.candidate_sha, "branch": evidence.branch,
        "observed_at": evidence.observed_at,
        "checks": [(item.check_id, item.suite_id, item.name, item.state.value, item.head_sha, item.checked_out_sha) for item in evidence.checks],
        "runs": [(item.run_id, item.workflow, item.state.value, item.head_sha, item.ref, [(job.job_id, job.name, job.state.value, job.checked_out_sha) for job in item.jobs]) for item in evidence.workflow_runs],
        "artifacts": evidence.artifacts,
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _require_candidate(value: object) -> None:
    if type(value) is not str or not _COMMIT.fullmatch(value):
        raise HostedEvidenceError("candidate identity is invalid")


def _valid_token(value: object) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", value))


def _valid_name(value: object) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[^\x00-\x1f\x7f]{1,256}", value))


def _valid_branch(value: object) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", value))
