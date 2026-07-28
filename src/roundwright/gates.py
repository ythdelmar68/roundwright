"""Deterministic, candidate-bound final gates for the Phase 2 local slice."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .git_identity import CandidateSeal, TransitionLease, WorktreeBinding, bind_candidate_evidence, candidate_evidence
from .state import StateError, _open_writable_connection, _require_current_transition_lease, _transition_ready_for_owner


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
    CONFLICT = "CONFLICT"


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

    if not _is_well_formed_context(context):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "invalid gate context"),))
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
    context: GateContext,
    evidence: GateEvidence,
    *,
    lease: TransitionLease | None = None,
) -> None:
    """Persist one exact-candidate gate record and bind its fingerprint to that candidate."""

    _validate_context(context)
    _validate_evidence(evidence)
    if (
        context.task_id != binding.task_id
        or context.candidate_sha != seal.candidate_sha
        or evidence.task_id != binding.task_id
        or evidence.candidate_sha != seal.candidate_sha
    ):
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
        source_count = connection.execute(
            "SELECT COUNT(*) FROM tasks JOIN source_snapshots ON source_snapshots.source_id = tasks.source_id WHERE tasks.task_id = ?",
            (binding.task_id,),
        ).fetchone()[0]
        if context.source_count != source_count:
            raise GateError("gate context source count does not match committed task state")
        persisted_context = connection.execute(
            "SELECT source_count, isolated_local_task FROM gate_contexts WHERE task_id = ?", (binding.task_id,)
        ).fetchone()
        context_values = (context.source_count, int(context.isolated_local_task))
        if persisted_context is None:
            connection.execute(
                "INSERT INTO gate_contexts(task_id, source_count, isolated_local_task) VALUES (?, ?, ?)",
                (binding.task_id, *context_values),
            )
        elif persisted_context != context_values:
            raise GateError("gate context conflicts with committed task state")
        existing = connection.execute(
            "SELECT outcome, evaluated_at, changed_boundary, reason FROM gate_evidence WHERE task_id = ? AND candidate_sha = ? AND gate_key = ? AND evaluator_id = ? AND evidence_fingerprint = ?",
            (evidence.task_id, evidence.candidate_sha, _value(evidence.gate_key), evidence.evaluator_id, evidence.evidence_fingerprint),
        ).fetchone()
        expected = (_value(evidence.outcome), evidence.evaluated_at, evidence.changed_boundary, evidence.reason)
        conflict = existing is not None and existing != expected
        if conflict:
            connection.execute(
                "UPDATE gate_evidence SET outcome = ?, reason = ? WHERE task_id = ? AND candidate_sha = ? AND gate_key = ? AND evaluator_id = ? AND evidence_fingerprint = ?",
                (EvidenceOutcome.CONFLICT.value, "conflicting evidence replay", evidence.task_id, evidence.candidate_sha, _value(evidence.gate_key), evidence.evaluator_id, evidence.evidence_fingerprint),
            )
        elif existing is None:
            connection.execute(
                "INSERT INTO gate_evidence(task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        if conflict:
            raise GateError("conflicting gate evidence was recorded")
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
    context: GateContext | None = None,
    *,
    lease: TransitionLease | None = None,
) -> GateDecision:
    """Load SQLite-backed evidence then apply the pure centralized decision API."""

    decision = _read_persisted_decision(repository, binding, seal, lease=lease)
    if context is not None and context != _persisted_gate_context(repository, binding.task_id, seal.candidate_sha):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "candidate identity mismatch"),))
    return decision


def transition_ready_for_owner(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    context: GateContext | None = None,
    *,
    evidence_fingerprint: str,
    lease: TransitionLease | None = None,
):
    """Permit only an aggregate PASS to perform the final lifecycle transition."""

    candidate_evidence(repository, binding, seal, lease=lease)
    if context is not None and context != _persisted_gate_context(repository, binding.task_id, seal.candidate_sha):
        raise GateError("gate context does not match committed task state")
    return _transition_ready_for_owner(
        repository,
        _task_identity(repository, binding.task_id),
        binding,
        seal,
        evidence_fingerprint=evidence_fingerprint,
        lease=lease,
    )


def _read_persisted_decision(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    lease: TransitionLease | None,
) -> GateDecision:
    candidate_evidence(repository, binding, seal, lease=lease)
    connection = _open_writable_connection(repository)
    try:
        decision = _decision_from_connection(connection, _task_identity(repository, binding.task_id))
    finally:
        connection.close()
    return decision


def _persisted_gate_context(repository: RepositoryIdentity, task_id: str, candidate_sha: str) -> GateContext | None:
    connection = _open_writable_connection(repository)
    try:
        return _read_gate_context(connection, task_id, candidate_sha)
    finally:
        connection.close()


def _decision_from_connection(connection, identity) -> GateDecision:
    """Derive readiness from the exact persisted task, seal, context, and evidence rows."""

    seal = connection.execute(
        "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (identity.task_id,)
    ).fetchone()
    lease = connection.execute(
        "SELECT state_identity FROM transition_leases WHERE lease_scope = 'repository-state'"
    ).fetchone()
    if seal is None or lease is None or seal[0] != identity.base_sha or seal[2] != lease[0]:
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "candidate seal is unavailable or stale"),))
    context = _read_gate_context(connection, identity.task_id, seal[1])
    if context is None:
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "gate context is unavailable"),))
    rows = connection.execute(
        "SELECT gates.task_id, gates.candidate_sha, gates.gate_key, gates.outcome, gates.evaluator_id, gates.evaluated_at, gates.evidence_fingerprint, gates.changed_boundary, gates.reason FROM gate_evidence AS gates JOIN candidate_evidence AS candidate ON candidate.task_id = gates.task_id AND candidate.candidate_sha = gates.candidate_sha AND candidate.evidence_fingerprint = gates.evidence_fingerprint WHERE gates.task_id = ? AND gates.candidate_sha = ? ORDER BY gates.gate_key, gates.evaluator_id, gates.evidence_fingerprint",
        (identity.task_id, seal[1]),
    ).fetchall()
    return decide_gates(context, tuple(GateEvidence(*row) for row in rows))


def _read_gate_context(connection, task_id: str, candidate_sha: str) -> GateContext | None:
    row = connection.execute(
        "SELECT source_count, isolated_local_task FROM gate_contexts WHERE task_id = ?", (task_id,)
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] <= 0 or type(row[1]) is not int or row[1] not in (0, 1):
        return None
    return GateContext(task_id, candidate_sha, row[0], bool(row[1]))


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


def _validate_context(context: GateContext) -> None:
    if not _is_well_formed_context(context):
        raise GateError("gate context is invalid")


def _is_well_formed_context(context: GateContext) -> bool:
    return (
        isinstance(context.task_id, str)
        and bool(_TOKEN.fullmatch(context.task_id))
        and isinstance(context.candidate_sha, str)
        and bool(_COMMIT.fullmatch(context.candidate_sha))
        and type(context.source_count) is int
        and context.source_count > 0
        and type(context.isolated_local_task) is bool
    )


def _is_well_formed(evidence: GateEvidence) -> bool:
    return (
        isinstance(evidence.task_id, str)
        and bool(_TOKEN.fullmatch(evidence.task_id))
        and isinstance(evidence.candidate_sha, str)
        and bool(_COMMIT.fullmatch(evidence.candidate_sha))
        and _value(evidence.outcome) in {entry.value for entry in EvidenceOutcome}
        and isinstance(evidence.evaluator_id, str)
        and bool(_TOKEN.fullmatch(evidence.evaluator_id))
        and type(evidence.evaluated_at) is int
        and evidence.evaluated_at > 0
        and isinstance(evidence.evidence_fingerprint, str)
        and bool(_FINGERPRINT.fullmatch(evidence.evidence_fingerprint))
        and (evidence.changed_boundary is None or isinstance(evidence.changed_boundary, str))
        and (evidence.reason is None or isinstance(evidence.reason, str))
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
