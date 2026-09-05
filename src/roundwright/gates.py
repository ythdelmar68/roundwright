"""Deterministic, candidate-bound final gates for the Phase 2 local slice."""

from __future__ import annotations

import re
import json
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from .configuration import RepositoryIdentity
from .git_identity import CandidateSeal, TransitionLease, WorktreeBinding, bind_candidate_evidence, candidate_evidence
from .policy import ActivationReceipt, ReceiptStatus, StandingAuthority, TrustedPolicySnapshot, evaluate_policy
from .runtime_binding import RuntimeBinding, RuntimeBindingError
from .state import ReviewLimitFinalizationReceipt, StateError, _open_writable_connection, _require_current_transition_lease, _transition_ready_for_owner, require_runtime_binding


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
    policy_digest: str
    receipt_fingerprint: str
    runtime_binding: RuntimeBinding
    selected_supervisor_profile_identity: str
    review_limit_finalization: ReviewLimitFinalizationReceipt | None = field(default=None, compare=False)
    dependency_graph_version_id: str | None = None
    dependency_graph_decision_digest: str | None = None


@dataclass(frozen=True)
class TrustedGatePolicyEvidence:
    """Externally verified policy material for the current gate evaluation."""

    snapshot: TrustedPolicySnapshot
    receipt: ActivationReceipt
    standing_authority: StandingAuthority
    evaluated_at: datetime
    receipt_status: ReceiptStatus


@dataclass(frozen=True)
class FollowUp:
    """One evaluator follow-up and its explicit resolution binding."""

    identifier: str
    resolved: bool
    resolution_fingerprint: str | None = None


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
    follow_ups: object = ()


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

    if type(context) is not GateContext or not _is_well_formed_context(context):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "invalid gate context"),))
    if type(evidence) is not tuple:
        return GateDecision(GateOutcome.BLOCKED, (GateResult("evidence", GateOutcome.BLOCKED, "invalid evidence container"),))
    registry = {requirement.key.value: requirement for requirement in GATE_REGISTRY}
    grouped: dict[str, list[GateEvidence]] = {key: [] for key in registry}
    unsupported = False
    malformed = False
    for item in evidence:
        if type(item) is not GateEvidence or not isinstance(item.gate_key, (GateKey, str)):
            malformed = True
            continue
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
    if malformed:
        results.append(GateResult("malformed", GateOutcome.BLOCKED, "invalid structured evidence"))

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
    policy_evidence: TrustedGatePolicyEvidence,
    lease: TransitionLease | None = None,
) -> None:
    """Persist one exact-candidate gate record and bind its fingerprint to that candidate."""

    _validate_context(context)
    if not _valid_review_limit_finalization(repository, binding, seal, context.runtime_binding, context.review_limit_finalization):
        raise GateError("review-limit finalization receipt is unavailable or stale")
    _validate_evidence(evidence)
    policy_activated_at = _current_trusted_policy_activation(repository, binding, context, policy_evidence)
    if policy_activated_at is None:
        raise GateError("gate context does not match current trusted policy evidence")
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
        require_runtime_binding(repository, _task_identity(repository, binding.task_id), context.runtime_binding, connection=connection)
        row = connection.execute(
            "SELECT candidate_sha FROM candidate_seals WHERE task_id = ?", (binding.task_id,)
        ).fetchone()
        if row != (seal.candidate_sha,):
            raise GateError("candidate seal is no longer current")
        source_count = _affected_source_count(connection, binding.task_id)
        if context.source_count != source_count:
            raise GateError("gate context source count does not match committed task state")
        if _value(evidence.gate_key) == GateKey.DEPENDENCY_GRAPH.value and _value(evidence.outcome) == EvidenceOutcome.PASS.value:
            _require_current_dependency_graph(connection, binding.task_id, seal.candidate_sha, context, evidence)
        persisted_context = connection.execute(
            "SELECT source_count, isolated_local_task, policy_digest, receipt_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest, selected_supervisor_profile_identity, dependency_graph_version_id, dependency_graph_decision_digest, policy_activated_at FROM gate_contexts WHERE task_id = ? AND candidate_sha = ?",
            (binding.task_id, seal.candidate_sha),
        ).fetchone()
        context_values = (context.source_count, int(context.isolated_local_task), context.policy_digest, context.receipt_fingerprint, *context.runtime_binding.complete_columns(), context.selected_supervisor_profile_identity, context.dependency_graph_version_id or "", context.dependency_graph_decision_digest or "")
        if persisted_context is None:
            connection.execute(
                "INSERT INTO gate_contexts(task_id, candidate_sha, source_count, isolated_local_task, policy_digest, receipt_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest, selected_supervisor_profile_identity, dependency_graph_version_id, dependency_graph_decision_digest, policy_activated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (binding.task_id, seal.candidate_sha, *context_values, policy_activated_at),
            )
        elif persisted_context[:16] != context_values:
            graph_moved = persisted_context[:14] == context_values[:14] and persisted_context[16] == policy_activated_at
            if not graph_moved and (type(persisted_context[16]) is not str or policy_activated_at <= persisted_context[16]):
                raise GateError("gate context conflicts with committed task state")
            connection.execute(
                "DELETE FROM gate_evidence WHERE task_id = ? AND candidate_sha = ?",
                (binding.task_id, seal.candidate_sha),
            )
            connection.execute(
                "DELETE FROM candidate_evidence WHERE task_id = ? AND candidate_sha = ?",
                (binding.task_id, seal.candidate_sha),
            )
            connection.execute(
                "UPDATE gate_contexts SET source_count = ?, isolated_local_task = ?, policy_digest = ?, receipt_fingerprint = ?, configuration_schema_version = ?, configuration_digest = ?, worker_profile_identity = ?, supervisor_profile_identities = ?, review_complete_rounds = ?, review_max_rounds = ?, review_max_supervisor_attempts_per_round = ?, review_on_final_findings = ?, review_policy_digest = ?, selected_supervisor_profile_identity = ?, dependency_graph_version_id = ?, dependency_graph_decision_digest = ?, policy_activated_at = ? WHERE task_id = ? AND candidate_sha = ?",
                (*context_values, policy_activated_at, binding.task_id, seal.candidate_sha),
            )
        elif persisted_context[16] != policy_activated_at:
            raise GateError("gate context conflicts with committed task state")
        connection.execute(
            "INSERT OR IGNORE INTO candidate_evidence(task_id, candidate_sha, evidence_fingerprint) VALUES (?, ?, ?)",
            (binding.task_id, seal.candidate_sha, evidence.evidence_fingerprint),
        )
        existing = connection.execute(
            "SELECT outcome, evaluated_at, changed_boundary, reason, follow_ups FROM gate_evidence WHERE task_id = ? AND candidate_sha = ? AND gate_key = ? AND evaluator_id = ? AND evidence_fingerprint = ?",
            (evidence.task_id, evidence.candidate_sha, _value(evidence.gate_key), evidence.evaluator_id, evidence.evidence_fingerprint),
        ).fetchone()
        follow_ups = _encode_follow_ups(evidence.follow_ups)
        expected = (_value(evidence.outcome), evidence.evaluated_at, evidence.changed_boundary, evidence.reason, follow_ups)
        conflict = existing is not None and existing != expected
        if conflict:
            connection.execute(
                "UPDATE gate_evidence SET outcome = ?, reason = ? WHERE task_id = ? AND candidate_sha = ? AND gate_key = ? AND evaluator_id = ? AND evidence_fingerprint = ?",
                (EvidenceOutcome.CONFLICT.value, "conflicting evidence replay", evidence.task_id, evidence.candidate_sha, _value(evidence.gate_key), evidence.evaluator_id, evidence.evidence_fingerprint),
            )
        elif existing is None:
            connection.execute(
                "INSERT INTO gate_evidence(task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason, follow_ups) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    follow_ups,
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
            "SELECT task_id, candidate_sha, gate_key, outcome, evaluator_id, evaluated_at, evidence_fingerprint, changed_boundary, reason, follow_ups FROM gate_evidence WHERE task_id = ? AND candidate_sha = ? ORDER BY gate_key, evaluator_id, evidence_fingerprint",
            (binding.task_id, seal.candidate_sha),
        ).fetchall()
    finally:
        connection.close()
    return tuple(
        GateEvidence(*row[:9], _decode_follow_ups(row[9]))
        for row in rows
        if isinstance(row[6], str) and row[6] in valid_fingerprints
    )


def evaluate_gates(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    context: GateContext,
    *,
    policy_evidence: TrustedGatePolicyEvidence,
    lease: TransitionLease | None = None,
) -> GateDecision:
    """Load SQLite-backed evidence then apply the pure centralized decision API."""

    policy_activated_at = _current_trusted_policy_activation(repository, binding, context, policy_evidence)
    if policy_activated_at is None:
        return GateDecision(GateOutcome.BLOCKED, (GateResult("policy", GateOutcome.BLOCKED, "current trusted policy evidence is unavailable"),))
    if not _valid_review_limit_finalization(repository, binding, seal, context.runtime_binding, context.review_limit_finalization):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("review-limit", GateOutcome.BLOCKED, "review-limit finalization receipt is unavailable or stale"),))
    decision = _read_persisted_decision(repository, binding, seal, lease=lease)
    if not _contexts_match(context, _persisted_gate_context(repository, binding.task_id, seal.candidate_sha)):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("context", GateOutcome.BLOCKED, "candidate identity mismatch"),))
    if policy_activated_at != _persisted_policy_activation(repository, binding.task_id, seal.candidate_sha):
        return GateDecision(GateOutcome.BLOCKED, (GateResult("policy", GateOutcome.BLOCKED, "trusted policy receipt is stale"),))
    return decision


def transition_ready_for_owner(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    context: GateContext,
    *,
    evidence_fingerprint: str,
    policy_evidence: TrustedGatePolicyEvidence,
    lease: TransitionLease | None = None,
):
    """Permit only an aggregate PASS to perform the final lifecycle transition."""

    policy_activated_at = _current_trusted_policy_activation(repository, binding, context, policy_evidence)
    if policy_activated_at is None:
        raise GateError("gate context does not match current trusted policy evidence")
    if not _valid_review_limit_finalization(repository, binding, seal, context.runtime_binding, context.review_limit_finalization):
        raise GateError("review-limit finalization receipt is unavailable or stale")
    candidate_evidence(repository, binding, seal, lease=lease)
    if not _contexts_match(context, _persisted_gate_context(repository, binding.task_id, seal.candidate_sha)):
        raise GateError("gate context does not match committed task state")
    if policy_activated_at != _persisted_policy_activation(repository, binding.task_id, seal.candidate_sha):
        raise GateError("trusted policy receipt is stale")
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


def _persisted_policy_activation(repository: RepositoryIdentity, task_id: str, candidate_sha: str) -> str | None:
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT policy_activated_at FROM gate_contexts WHERE task_id = ? AND candidate_sha = ?",
            (task_id, candidate_sha),
        ).fetchone()
    finally:
        connection.close()
    return row[0] if row is not None and isinstance(row[0], str) and row[0] else None


def _valid_review_limit_finalization(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    runtime_binding: RuntimeBinding,
    receipt: ReviewLimitFinalizationReceipt | None,
) -> bool:
    """Require a receipt exactly when durable state consumed a final Worker repair."""

    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT review_round, findings_fingerprint, worker_repair_fingerprint, candidate_sha, worker_thread_identity, diff_review_attempt_id, configuration_digest, review_policy_digest, receipt_fingerprint FROM review_limit_finalizations WHERE task_id = ?",
            (binding.task_id,),
        ).fetchone()
        routed_review = connection.execute(
            "SELECT reviews.review_round, reviews.review_mode, reviews.review_complete_rounds, reviews.review_max_rounds, reviews.review_max_supervisor_attempts_per_round, reviews.review_on_final_findings, reviews.review_policy_digest "
            "FROM implementation_candidates AS candidates "
            "JOIN implementation_attempts AS implementation ON implementation.implementation_attempt_id = candidates.implementation_attempt_id "
            "JOIN diff_review_attempts AS reviews ON reviews.diff_review_attempt_id = implementation.repair_diff_review_id "
            "JOIN diff_review_artifacts AS artifacts ON artifacts.diff_review_attempt_id = reviews.diff_review_attempt_id "
            "WHERE candidates.task_id = ? AND candidates.candidate_sha = ? AND artifacts.verdict = 'findings'",
            (binding.task_id, seal.candidate_sha),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        if routed_review is None:
            return receipt is None
        if type(runtime_binding) is not RuntimeBinding or not runtime_binding.has_review_policy:
            return False
        expected = (
            runtime_binding.review_complete_rounds,
            runtime_binding.review_max_rounds,
            runtime_binding.review_max_supervisor_attempts_per_round,
            runtime_binding.review_on_final_findings,
            runtime_binding.review_policy_digest,
        )
        if tuple(routed_review[2:]) != expected:
            return False
        return not (
            routed_review[0] == runtime_binding.review_max_rounds
            and routed_review[1] == "CONVERGING"
        ) and receipt is None
    if type(receipt) is not ReviewLimitFinalizationReceipt or type(runtime_binding) is not RuntimeBinding or not runtime_binding.has_review_policy:
        return False
    return (
        receipt.review_round,
        receipt.findings_fingerprint,
        receipt.worker_repair_fingerprint,
        receipt.candidate_sha,
        receipt.worker_thread_identity,
        receipt.diff_review_attempt_id,
        receipt.configuration_digest,
        receipt.review_policy_digest,
        receipt.receipt_fingerprint,
    ) == tuple(row) and receipt.candidate_sha == seal.candidate_sha and (
        receipt.review_round,
        receipt.configuration_digest,
        receipt.review_policy_digest,
    ) == (
        runtime_binding.review_max_rounds,
        runtime_binding.resolved_digest,
        runtime_binding.review_policy_digest,
    )


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
        "SELECT gates.task_id, gates.candidate_sha, gates.gate_key, gates.outcome, gates.evaluator_id, gates.evaluated_at, gates.evidence_fingerprint, gates.changed_boundary, gates.reason, gates.follow_ups FROM gate_evidence AS gates JOIN candidate_evidence AS candidate ON candidate.task_id = gates.task_id AND candidate.candidate_sha = gates.candidate_sha AND candidate.evidence_fingerprint = gates.evidence_fingerprint WHERE gates.task_id = ? AND gates.candidate_sha = ? ORDER BY gates.gate_key, gates.evaluator_id, gates.evidence_fingerprint",
        (identity.task_id, seal[1]),
    ).fetchall()
    return decide_gates(context, tuple(GateEvidence(*row[:9], _decode_follow_ups(row[9])) for row in rows))


def _read_gate_context(connection, task_id: str, candidate_sha: str) -> GateContext | None:
    row = connection.execute(
        "SELECT source_count, isolated_local_task, policy_digest, receipt_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, review_complete_rounds, review_max_rounds, review_max_supervisor_attempts_per_round, review_on_final_findings, review_policy_digest, selected_supervisor_profile_identity, dependency_graph_version_id, dependency_graph_decision_digest FROM gate_contexts WHERE task_id = ? AND candidate_sha = ?",
        (task_id, candidate_sha),
    ).fetchone()
    if row is None or type(row[0]) is not int or row[0] <= 0 or type(row[1]) is not int or row[1] not in (0, 1) or not _is_fingerprint(row[2]) or not _is_fingerprint(row[3]) or type(row[13]) is not str:
        return None
    try:
        runtime_binding = RuntimeBinding(row[4], row[5], row[6], tuple(json.loads(row[7])), row[8], row[9], row[10], row[11], row[12])
    except (RuntimeBindingError, TypeError, ValueError, json.JSONDecodeError):
        return None
    if row[13] not in runtime_binding.supervisor_profile_identities:
        return None
    return GateContext(task_id, candidate_sha, row[0], bool(row[1]), row[2], row[3], runtime_binding, row[13], None, row[14] or None, row[15] or None)


def _decide_requirement(context: GateContext, requirement: GateRequirement, entries: list[GateEvidence]) -> GateResult:
    key = requirement.key.value
    if any(entry.task_id != context.task_id or entry.candidate_sha != context.candidate_sha for entry in entries):
        return GateResult(key, GateOutcome.BLOCKED, "candidate identity mismatch")
    if any(not _is_well_formed(entry) for entry in entries):
        return GateResult(key, GateOutcome.BLOCKED, "invalid structured evidence")
    if any(not follow_up.resolved for entry in entries for follow_up in entry.follow_ups):
        return GateResult(key, GateOutcome.BLOCKED, "unresolved follow-up remains")
    outcomes = {_value(entry.outcome) for entry in entries}
    if len(outcomes) != 1:
        return GateResult(key, GateOutcome.BLOCKED, "conflicting evidence")
    outcome = next(iter(outcomes))
    if outcome == EvidenceOutcome.PASS.value:
        if requirement.key is GateKey.DEPENDENCY_GRAPH and context.source_count > 1 and (not _is_token(context.dependency_graph_version_id) or not _is_fingerprint(context.dependency_graph_decision_digest)):
            return GateResult(key, GateOutcome.BLOCKED, "accepted graph decision is unavailable")
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


def task_identity_fingerprint(identity: object) -> str:
    """Return the opaque activation-receipt binding for one durable task."""

    from .state import TaskIdentity

    if type(identity) is not TaskIdentity or any(type(value) is not str for value in identity.__dict__.values()):
        raise GateError("task identity is invalid")
    return hashlib.sha256("\x00".join(identity.__dict__.values()).encode("utf-8")).hexdigest()


def _current_trusted_policy_activation(
    repository: RepositoryIdentity,
    binding: WorktreeBinding,
    context: GateContext,
    evidence: object,
) -> str | None:
    """Require the policy module to independently validate this exact binding."""

    if type(evidence) is not TrustedGatePolicyEvidence:
        return None
    try:
        identity = _task_identity(repository, context.task_id)
        if (
            identity.task_id != binding.task_id
            or identity.repository_id != binding.repository_id
            or identity.branch != binding.branch
            or Path(identity.worktree) != binding.worktree
            or identity.base_sha != binding.base_sha
        ):
            return None
        require_runtime_binding(repository, identity, context.runtime_binding)
        decision = evaluate_policy(
            evidence.snapshot,
            evidence.receipt,
            task_fingerprint=task_identity_fingerprint(identity),
            candidate_sha=context.candidate_sha,
            standing_authority=evidence.standing_authority,
            now=evidence.evaluated_at,
            receipt_status=evidence.receipt_status,
        )
    except (AttributeError, TypeError, ValueError, StateError):
        return None
    if not (
        decision.authorized
        and decision.policy_digest == context.policy_digest
        and decision.receipt_fingerprint == context.receipt_fingerprint
        and _runtime_bindings_match(context.runtime_binding, evidence.receipt.runtime_binding)
        and evidence.receipt.selected_supervisor_profile_identity == context.selected_supervisor_profile_identity
    ):
        return None
    try:
        activated_at = evidence.receipt.activated_at
        return activated_at.isoformat() if type(activated_at) is datetime else None
    except (AttributeError, TypeError, ValueError):
        return None


def _runtime_bindings_match(expected: RuntimeBinding, actual: object) -> bool:
    try:
        expected.require_matches(actual)
    except (AttributeError, RuntimeBindingError, TypeError, ValueError):
        return False
    return True


def _contexts_match(expected: GateContext, actual: object) -> bool:
    if type(expected) is not GateContext or type(actual) is not GateContext:
        return False
    if (
        expected.task_id, expected.candidate_sha, expected.source_count,
        expected.isolated_local_task, expected.policy_digest, expected.receipt_fingerprint,
        expected.selected_supervisor_profile_identity,
        expected.dependency_graph_version_id, expected.dependency_graph_decision_digest,
    ) != (
        actual.task_id, actual.candidate_sha, actual.source_count,
        actual.isolated_local_task, actual.policy_digest, actual.receipt_fingerprint,
        actual.selected_supervisor_profile_identity,
        actual.dependency_graph_version_id, actual.dependency_graph_decision_digest,
    ):
        return False
    return _runtime_bindings_match(expected.runtime_binding, actual.runtime_binding)


def _is_well_formed_context(context: GateContext) -> bool:
    return (
        isinstance(context.task_id, str)
        and bool(_TOKEN.fullmatch(context.task_id))
        and isinstance(context.candidate_sha, str)
        and bool(_COMMIT.fullmatch(context.candidate_sha))
        and type(context.source_count) is int
        and context.source_count > 0
        and type(context.isolated_local_task) is bool
        and _is_fingerprint(context.policy_digest)
        and _is_fingerprint(context.receipt_fingerprint)
        and type(context.runtime_binding) is RuntimeBinding
        and context.selected_supervisor_profile_identity in context.runtime_binding.supervisor_profile_identities
        and (context.dependency_graph_version_id is None or _is_token(context.dependency_graph_version_id))
        and (context.dependency_graph_decision_digest is None or _is_graph_digest(context.dependency_graph_decision_digest))
    )


def _is_well_formed(evidence: GateEvidence) -> bool:
    return (
        isinstance(evidence.task_id, str)
        and bool(_TOKEN.fullmatch(evidence.task_id))
        and isinstance(evidence.candidate_sha, str)
        and bool(_COMMIT.fullmatch(evidence.candidate_sha))
        and isinstance(evidence.gate_key, (GateKey, str))
        and isinstance(evidence.outcome, (EvidenceOutcome, str))
        and _value(evidence.outcome) in {entry.value for entry in EvidenceOutcome}
        and isinstance(evidence.evaluator_id, str)
        and bool(_TOKEN.fullmatch(evidence.evaluator_id))
        and type(evidence.evaluated_at) is int
        and evidence.evaluated_at > 0
        and isinstance(evidence.evidence_fingerprint, str)
        and bool(_FINGERPRINT.fullmatch(evidence.evidence_fingerprint))
        and (evidence.changed_boundary is None or isinstance(evidence.changed_boundary, str))
        and (evidence.reason is None or isinstance(evidence.reason, str))
        and _follow_ups_are_valid(evidence.follow_ups)
    )


def _justified_na(evidence: GateEvidence) -> bool:
    return all(isinstance(value, str) and bool(value.strip()) for value in (evidence.changed_boundary, evidence.reason))


def _is_fingerprint(value: object) -> bool:
    return isinstance(value, str) and bool(_FINGERPRINT.fullmatch(value))


def _is_graph_digest(value: object) -> bool:
    return _is_fingerprint(value) or (isinstance(value, str) and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)))


def _graph_fingerprint(value: str) -> str:
    return value[7:] if value.startswith("sha256:") else value


def _is_token(value: object) -> bool:
    return isinstance(value, str) and bool(_TOKEN.fullmatch(value))


def _affected_source_count(connection, task_id: str) -> int:
    """Use the terminal immutable affected subset when review evidence exists."""
    row = connection.execute(
        "SELECT subsets.member_count FROM dependency_review_attempts AS attempts JOIN dependency_review_subsets AS subsets ON subsets.snapshot_id = attempts.snapshot_id WHERE attempts.task_id = ? AND NOT EXISTS (SELECT 1 FROM dependency_review_successors AS successors WHERE successors.predecessor_attempt_id = attempts.attempt_id) ORDER BY attempts.attempt_id",
        (task_id,),
    ).fetchone()
    return row[0] if row is not None and type(row[0]) is int and row[0] > 0 else 1


def _require_current_dependency_graph(connection, task_id: str, candidate_sha: str, context: GateContext, evidence: GateEvidence) -> None:
    if context.source_count <= 1:
        raise GateError("dependency graph PASS is not valid for a single-source task")
    if not _is_token(context.dependency_graph_version_id) or not _is_graph_digest(context.dependency_graph_decision_digest):
        raise GateError("dependency graph context is unavailable")
    # Syntax-level rows are insufficient: the graph store reconstructs the
    # accepted proposal, predecessor snapshot, and decision digest on restart.
    from .dependency_graph import DependencyGraphError, DependencyGraphStore
    try:
        current = DependencyGraphStore._read_current(connection)
    except DependencyGraphError as error:
        raise GateError("dependency graph evidence is unavailable or stale") from error
    if current.graph_version_id != context.dependency_graph_version_id or current.binding is None or current.binding.candidate_sha != candidate_sha:
        raise GateError("dependency graph evidence is unavailable or stale")
    row = connection.execute(
        "SELECT versions.candidate_sha, decisions.decision, decisions.decision_digest FROM dependency_graph_current AS current JOIN dependency_graph_versions AS versions ON versions.graph_version_id = current.graph_version_id JOIN dependency_graph_decisions AS decisions ON decisions.graph_version_id = versions.graph_version_id WHERE current.singleton = 1 AND versions.graph_version_id = ?",
        (context.dependency_graph_version_id,),
    ).fetchone()
    if row is None or row[:2] != (candidate_sha, "accepted") or _graph_fingerprint(row[2]) != _graph_fingerprint(context.dependency_graph_decision_digest) or evidence.evidence_fingerprint != _graph_fingerprint(context.dependency_graph_decision_digest):
        raise GateError("dependency graph evidence is unavailable or stale")


def _follow_ups_are_valid(value: object) -> bool:
    if type(value) is not tuple:
        return False
    identifiers: set[str] = set()
    for follow_up in value:
        if type(follow_up) is not FollowUp or not isinstance(follow_up.identifier, str) or not _TOKEN.fullmatch(follow_up.identifier) or type(follow_up.resolved) is not bool:
            return False
        if follow_up.identifier in identifiers:
            return False
        identifiers.add(follow_up.identifier)
        if follow_up.resolved != _is_fingerprint(follow_up.resolution_fingerprint):
            return False
    return True


def _encode_follow_ups(value: object) -> str:
    if not _follow_ups_are_valid(value):
        raise GateError("gate follow-ups are invalid")
    return json.dumps(
        [
            {"identifier": follow_up.identifier, "resolved": follow_up.resolved, "resolution_fingerprint": follow_up.resolution_fingerprint}
            for follow_up in value
        ],
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_follow_ups(value: object) -> object:
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError):
        return None
    if type(decoded) is not list:
        return None
    follow_ups: list[FollowUp] = []
    for item in decoded:
        if type(item) is not dict or set(item) != {"identifier", "resolved", "resolution_fingerprint"}:
            return None
        follow_ups.append(FollowUp(item["identifier"], item["resolved"], item["resolution_fingerprint"]))
    value = tuple(follow_ups)
    return value if _follow_ups_are_valid(value) else None


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
