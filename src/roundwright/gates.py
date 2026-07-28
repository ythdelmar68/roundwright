"""Deterministic, candidate-bound final gates for the Phase 2 local slice."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .git_identity import CandidateSeal, TransitionLease, WorktreeBinding, bind_candidate_evidence, candidate_evidence
from .state import StateError, _open_writable_connection, _require_current_transition_lease, transition_task


class GateError(StateError):
    """Raised when gate evidence cannot be safely committed or read."""


class GateKey(StrEnum):
    PLAN_REVIEW = "plan-review"
    CANDIDATE_SEAL = "candidate-seal"
    SUPERVISOR_DIFF_REVIEW = "supervisor-diff-review"
    TARGETED_TESTS = "targeted-tests"
    FULL_TESTS = "full-tests"
    BUILD = "build"
    POLICY = "policy"
    DEPLOYMENT_AUTHORITY = "deployment-authority"
    DEPENDENCY_GRAPH = "dependency-graph"
    GITHUB_TRACE = "github-trace"
    PUBLIC_IDENTIFIER = "public-identifier"
    LIVE_PROOF = "live-proof"
    EXTERNAL_CI = "external-ci"


class EvidenceOutcome(StrEnum):
    PASS = "PASS"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"
    FINDINGS = "FINDINGS"
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"


class GateOutcome(StrEnum):
    PASS = "PASS"
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class GateRequirement:
    key: GateKey
    permits_phase_two_local_na: bool = False


GATE_REGISTRY = (
    GateRequirement(GateKey.PLAN_REVIEW),
    GateRequirement(GateKey.CANDIDATE_SEAL),
    GateRequirement(GateKey.SUPERVISOR_DIFF_REVIEW),
    GateRequirement(GateKey.TARGETED_TESTS),
    GateRequirement(GateKey.FULL_TESTS),
    GateRequirement(GateKey.BUILD),
    GateRequirement(GateKey.POLICY),
    GateRequirement(GateKey.DEPLOYMENT_AUTHORITY),
    GateRequirement(GateKey.DEPENDENCY_GRAPH, True),
    GateRequirement(GateKey.GITHUB_TRACE, True),
    GateRequirement(GateKey.PUBLIC_IDENTIFIER, True),
    GateRequirement(GateKey.LIVE_PROOF, True),
    GateRequirement(GateKey.EXTERNAL_CI, True),
)

_FINGERPRINT = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}")


@dataclass(frozen=True)
class GateContext:
    task_id: str
    candidate_sha: str
    source_count: int
    isolated_local_task: bool


@dataclass(frozen=True)
class GateEvidence:
    task_id: str
    candidate_sha: str
    gate_key: GateKey | str
    outcome: EvidenceOutcome | str
    evaluator_id: str
    evaluated_at: int
    evidence_fingerprint: str
    changed_boundary: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class GateResult:
    gate_key: str
    outcome: GateOutcome
    reason: str


@dataclass(frozen=True)
class GateDecision:
    outcome: GateOutcome
    results: tuple[GateResult, ...]


def decide_gates(context: GateContext, evidence: tuple[GateEvidence, ...]) -> GateDecision:
    """Purely aggregate structured gate evidence into one fail-closed decision."""

    registry = {requirement.key.value: requirement for requirement in GATE_REGISTRY}
    grouped: dict[str, list[GateEvidence]] = {key: [] for key in registry}
    unsupported = False
    for item in evidence:
        key = _value(item.gate_key)
        if key not in registry:
            unsupported = True
        else:
            grouped[key].append(item)

    results: list[GateResult] = []
    for key, requirement in ((entry.key.value, entry) for entry in GATE_REGISTRY):
        entries = grouped[key]
        if not entries:
            results.append(GateResult(key, GateOutcome.PENDING, "missing evidence"))
            continue
        results.append(_decide_requirement(context, requirement, entries))
    if unsupported:
        results.append(GateResult("unsupported", GateOutcome.BLOCKED, "unsupported gate evidence"))

    outcome = GateOutcome.PASS
    if any(result.outcome is GateOutcome.BLOCKED for result in results):
        outcome = GateOutcome.BLOCKED
    elif any(result.outcome is GateOutcome.PENDING for result in results):
        outcome = GateOutcome.PENDING
    return GateDecision(outcome, tuple(results))


def render_gate_decision(decision: GateDecision) -> str:
    """Render a stable, public-safe status view for owner-facing diagnostics."""

    lines = [f"decision={decision.outcome.value}"]
    lines.extend(f"gate={result.gate_key} outcome={result.outcome.value} reason={result.reason}" for result in decision.results)
    return "\n".join(lines)


def record_gate_evidence(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    evidence: GateEvidence,
    *,
    lease: TransitionLease | None = None,
) -> None:
    """Persist one exact-candidate gate record and bind its fingerprint to that candidate."""

    _validate_evidence(evidence)
    if evidence.task_id != binding.task_id or evidence.candidate_sha != seal.candidate_sha:
        raise GateError("gate evidence does not match the active task candidate")
    bind_candidate_evidence(
        repository, binding, seal, evidence_fingerprint=evidence.evidence_fingerprint, lease=lease
    )
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_transition_lease(connection, lease, binding.repository_id)
        row = connection.execute(
            "SELECT candidate_sha FROM candidate_seals WHERE task_id = ?", (binding.task_id,)
        ).fetchone()
        if row != (seal.candidate_sha,):
            raise GateError("candidate seal is no longer current")
        connection.execute(
            "INSERT OR IGNORE INTO gate_evidence(task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence.task_id,
                evidence.candidate_sha,
                _value(evidence.gate_key),
                _value(evidence.outcome),
                evidence.evaluator_id,
                evidence.evaluated_at,
                evidence.evidence_fingerprint,
                evidence.changed_boundary,
                evidence.reason,
            ),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def read_gate_evidence(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    lease: TransitionLease | None = None,
) -> tuple[GateEvidence, ...]:
    """Read only evidence whose fingerprint remains bound to the live candidate."""

    valid_fingerprints = frozenset(candidate_evidence(repository, binding, seal, lease=lease))
    connection = _open_writable_connection(repository)
    try:
        rows = connection.execute(
            "SELECT task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason FROM gate_evidence WHERE task_id = ? AND candidate_sha = ? ORDER BY gate_key, evaluator_id, evidence_fingerprint",
            (binding.task_id, seal.candidate_sha),
        ).fetchall()
    finally:
        connection.close()
    return tuple(
        GateEvidence(*row)
        for row in rows
        if isinstance(row[6], str) and row[6] in valid_fingerprints
    )


def evaluate_gates(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    context: GateContext,
    *,
    lease: TransitionLease | None = None,
) -> GateDecision:
    """Load SQLite-backed evidence then apply the pure centralized decision API."""

    if context.task_id != binding.task_id or context.candidate_sha != seal.candidate_sha:
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "candidate identity mismatch"),))
    return decide_gates(context, read_gate_evidence(repository, binding, seal, lease=lease))


def transition_ready_for_owner(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    context: GateContext,
    *,
    evidence_fingerprint: str,
    lease: TransitionLease | None = None,
):
    """Permit only an aggregate PASS to perform the final lifecycle transition."""

    decision = evaluate_gates(repository, binding, seal, context, lease=lease)
    if decision.outcome is not GateOutcome.PASS:
        raise GateError("ready-for-owner requires an aggregate PASS gate decision")
    return transition_task(
        repository,
        _task_identity(repository, binding.task_id),
        expected_state="diff-review",
        next_state="ready-for-owner",
        evidence_fingerprint=evidence_fingerprint,
        lease=lease,
        gate_decision=decision,
    )


def _decide_requirement(context: GateContext, requirement: GateRequirement, entries: list[GateEvidence]) -> GateResult:
    key = requirement.key.value
    if any(entry.task_id != context.task_id or entry.candidate_sha != context.candidate_sha for entry in entries):
        return GateResult(key, GateOutcome.BLOCKED, "candidate identity mismatch")
    if any(not _is_well_formed(entry) for entry in entries):
        return GateResult(key, GateOutcome.BLOCKED, "invalid structured evidence")
    outcomes = {_value(entry.outcome) for entry in entries}
    if len(outcomes) != 1:
        return GateResult(key, GateOutcome.BLOCKED, "conflicting evidence")
    outcome = next(iter(outcomes))
    if outcome == EvidenceOutcome.PASS.value:
        return GateResult(key, GateOutcome.PASS, "accepted")
    if outcome == EvidenceOutcome.NOT_APPLICABLE.value:
        if not requirement.permits_phase_two_local_na:
            return GateResult(key, GateOutcome.BLOCKED, "not applicable is unsupported for this gate")
        if context.source_count != 1 or not context.isolated_local_task:
            return GateResult(key, GateOutcome.BLOCKED, "not applicable requires the isolated single-source local boundary")
        if any(not _justified_na(entry) for entry in entries):
            return GateResult(key, GateOutcome.BLOCKED, "not applicable is not auditable")
        return GateResult(key, GateOutcome.PASS, "accepted isolated-local not applicable")
    if outcome in {EvidenceOutcome.PENDING.value, EvidenceOutcome.STALE.value}:
        return GateResult(key, GateOutcome.PENDING, "evidence is pending or stale")
    if outcome == EvidenceOutcome.FINDINGS.value:
        return GateResult(key, GateOutcome.BLOCKED, "findings remain")
    return GateResult(key, GateOutcome.BLOCKED, "unknown or blocked evidence")


def _validate_evidence(evidence: GateEvidence) -> None:
    if _value(evidence.gate_key) not in {entry.key.value for entry in GATE_REGISTRY}:
        raise GateError("gate key is unsupported")
    if not _is_well_formed(evidence):
        raise GateError("gate evidence is invalid")


def _is_well_formed(evidence: GateEvidence) -> bool:
    return (
        isinstance(evidence.task_id, str)
        and bool(_TOKEN.fullmatch(evidence.task_id))
        and isinstance(evidence.candidate_sha, str)
        and bool(_COMMIT.fullmatch(evidence.candidate_sha))
        and _value(evidence.outcome) in {entry.value for entry in EvidenceOutcome}
        and isinstance(evidence.evaluator_id, str)
        and bool(_TOKEN.fullmatch(evidence.evaluator_id))
        and isinstance(evidence.evaluated_at, int)
        and evidence.evaluated_at > 0
        and isinstance(evidence.evidence_fingerprint, str)
        and bool(_FINGERPRINT.fullmatch(evidence.evidence_fingerprint))
    )


def _justified_na(evidence: GateEvidence) -> bool:
    return all(isinstance(value, str) and bool(value.strip()) for value in (evidence.changed_boundary, evidence.reason))


def _task_identity(repository: RepositoryIdentity, task_id: str):
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT task_id, source_id, repository_id, branch, worktree, base_sha FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise GateError("task identity is unavailable")
    from .state import TaskIdentity

    return TaskIdentity(*row)


def _value(value: GateKey | EvidenceOutcome | str) -> str:
    return value.value if isinstance(value, StrEnum) else value
