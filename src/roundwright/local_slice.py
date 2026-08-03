"""Hermetic, single-source Phase 2 run-once fixture.

This module intentionally joins the persisted planning, review, candidate, and
gate contracts without starting a real provider or contacting an external
service.  It is an explicit local-fixture boundary: production command shells
remain fail closed.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .candidate_review import (
    CandidateVerification,
    DiffReviewOutput,
    DiffReviewVerdict,
    VerificationKind,
    VerificationOutcome,
    begin_implementation,
    dispatch_diff_review,
    record_candidate_verification,
    record_diff_review,
    record_implementation_candidate,
)
from .configuration import RepositoryIdentity
from .gates import (
    EvidenceOutcome,
    GATE_REGISTRY,
    GateContext,
    GateEvidence,
    GateOutcome,
    TrustedGatePolicyEvidence,
    evaluate_gates,
    record_gate_evidence,
    task_identity_fingerprint,
    transition_ready_for_owner,
)
from .git_identity import CandidateSeal, acquire_transition_lease, provision_worktree, resolve_canonical_base
from .plan_review import PlanReviewOutput, PlanReviewVerdict, dispatch_plan_review, record_plan_review
from .policy import ActivationReceipt, PolicyAction, PolicyDocument, ReceiptStatus, StandingAuthority, TrustedControlSource, TrustedPolicySnapshot
from .provider_recovery import RecoveryContext
from .state import SourceSnapshot, StateError, TaskIdentity, TaskProjection, admit_task, initialize, record_artifact, set_next_action, task_projection
from .worker_planning import (
    PlanReviewReceipt,
    PlanningInput,
    WorkerPlan,
    WorkerPlanOutput,
    accept_plan_review_and_begin_implementation,
    begin_planning,
    dispatch_plan,
    record_plan,
    submit_plan_for_review,
)


class LocalSliceError(StateError):
    """Raised when a fixture is unsafe, incomplete, or not a bounded replay."""


@dataclass(frozen=True)
class LocalSliceFixture:
    """The one explicit source and local Git destination for a test-only task."""

    task_id: str
    source_id: str
    repository_id: str
    branch: str
    worktree: Path
    source_contents: str


@dataclass(frozen=True)
class LocalSliceResult:
    """Public-safe completion evidence for one exact local candidate."""

    task: TaskProjection
    candidate: CandidateSeal
    gates: GateOutcome
    plan_session: str
    diff_session: str


def run_once_local_slice(
    repository: RepositoryIdentity,
    fixture: LocalSliceFixture,
    *,
    now: datetime | None = None,
) -> LocalSliceResult:
    """Drive one local task to ready-for-owner, or return its exact completed replay.

    The caller must provide a disposable repository with an ``origin/main``
    base and local Git identity.  The function makes one local implementation
    commit in the task worktree; it never reads credentials or uses networked
    APIs.  A second call is intentionally a read-only completion replay.
    """

    if type(fixture) is not LocalSliceFixture or not isinstance(fixture.worktree, Path):
        raise LocalSliceError("local slice fixture is invalid")
    if not isinstance(fixture.source_contents, str) or not fixture.source_contents:
        raise LocalSliceError("local slice source is invalid")

    initialize(repository)
    base_sha = resolve_canonical_base(repository, "main")
    identity = TaskIdentity(
        fixture.task_id,
        fixture.source_id,
        fixture.repository_id,
        fixture.branch,
        str(fixture.worktree.resolve(strict=False)),
        base_sha,
    )
    completed = _completed_result(repository, identity)
    if completed is not None:
        return completed

    instant = datetime.now(timezone.utc) if now is None else now
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise LocalSliceError("local slice clock must be timezone-aware")
    epoch = int(instant.timestamp())
    lease = acquire_transition_lease(
        repository,
        repository_id=identity.repository_id,
        owner="local-slice-fixture",
        ttl_seconds=120,
        now=epoch,
    )
    try:
        return _run_new_slice(repository, identity, fixture, lease, instant, epoch)
    except StateError as error:
        raise LocalSliceError(str(error)) from error


def render_local_slice_status(result: LocalSliceResult) -> str:
    """Render only persisted identity and gate facts for the fixture owner."""

    task = result.task
    return "\n".join(
        (
            "roundwright local-slice",
            f"task={task.task_id}",
            f"state={task.state}",
            f"base={result.candidate.base_sha}",
            f"candidate={result.candidate.candidate_sha}",
            f"gates={result.gates.value}",
            f"plan_session={result.plan_session}",
            f"diff_session={result.diff_session}",
            f"next_action={task.next_action or 'none'}",
            f"blockers={','.join(task.blockers) if task.blockers else 'none'}",
        )
    )


def _run_new_slice(repository, identity, fixture, lease, instant, epoch):
    source = SourceSnapshot(identity.source_id, identity.repository_id, _fingerprint("source", fixture.source_contents))
    admit_task(repository, identity, (source,), lease=lease)
    set_next_action(repository, identity, action_kind="review-plan", evidence_fingerprint=_fingerprint("next", identity.task_id), lease=lease)
    begin_planning(repository, identity, evidence_fingerprint=_fingerprint("transition", "queued", identity.task_id), lease=lease)

    context = RecoveryContext.for_task(
        identity,
        candidate_sha=None,
        policy_fingerprint=_fingerprint("policy", identity.task_id),
        deployment_fingerprint=_fingerprint("deployment", identity.task_id),
    )
    planning_input = PlanningInput(
        "Implement one isolated local task",
        ("No network", "No credential", "No external provider"),
        ("Create one committed local implementation", "Persist a ready-for-owner task"),
        ("implementation.txt",),
        ("Verify the exact local candidate",),
        (),
        ("A completed run is an idempotent replay",),
    )
    plan = WorkerPlan(
        planning_input.task_summary,
        planning_input.non_goals,
        planning_input.expected_files,
        planning_input.acceptance_criteria,
        planning_input.test_plan,
        planning_input.risks,
        planning_input.recovery_notes,
        (),
    )
    plan_dispatch = dispatch_plan(
        repository, identity, context, planning_input,
        plan_attempt_id="local-plan", provider_attempt_id="local-worker-plan",
        worker_thread_identity="local-worker-thread", external_turn_identity="local-plan-turn",
        process_lease_id="local-plan-lease", process_lease_expires_at=epoch + 60,
        lease=lease, now=epoch,
    )
    persisted_plan = record_plan(
        repository, identity, context, plan_attempt_id=plan_dispatch.plan_attempt_id,
        output=WorkerPlanOutput(
            plan_dispatch.plan_attempt_id, plan_dispatch.provider_attempt_id,
            plan_dispatch.worker_thread_identity, plan_dispatch.external_turn_identity,
            planning_input.digest, plan_dispatch.source_digest, plan,
        ),
        completion_evidence_fingerprint=_fingerprint("plan-output", identity.task_id), lease=lease, now=epoch,
    )
    record_artifact(repository, identity, artifact_kind="plan", artifact_fingerprint=persisted_plan.content_digest, lease=lease)
    submit_plan_for_review(repository, identity, plan_attempt_id=persisted_plan.plan_attempt_id, evidence_fingerprint=_fingerprint("submit-plan", identity.task_id), lease=lease)

    plan_review = dispatch_plan_review(
        repository, identity, context,
        review_attempt_id="local-plan-review", provider_attempt_id="local-plan-supervisor",
        supervisor_session_identity="local-plan-supervisor-session", external_turn_identity="local-plan-review-turn",
        plan_attempt_id=persisted_plan.plan_attempt_id, process_lease_id="local-plan-review-lease",
        process_lease_expires_at=epoch + 60, lease=lease, now=epoch,
    )
    record_plan_review(
        repository, identity, context, review_attempt_id=plan_review.review_attempt_id,
        output=PlanReviewOutput(
            plan_review.review_attempt_id, plan_review.provider_attempt_id,
            plan_review.supervisor_session_identity, plan_review.external_turn_identity,
            plan_review.plan_attempt_id, plan_review.source_digest, plan_review.plan_digest,
            PlanReviewVerdict.PASS, (), (), (), (),
        ),
        completion_evidence_fingerprint=_fingerprint("plan-review", identity.task_id), lease=lease, now=epoch,
    )
    record_artifact(repository, identity, artifact_kind="review", artifact_fingerprint=_fingerprint("plan-review-artifact", identity.task_id), lease=lease)
    accept_plan_review_and_begin_implementation(
        repository, identity, plan_attempt_id=persisted_plan.plan_attempt_id,
        receipt=PlanReviewReceipt(plan_review.review_attempt_id, persisted_plan.content_digest, True),
        evidence_fingerprint=_fingerprint("begin-implementation", identity.task_id), lease=lease,
    )

    binding = provision_worktree(repository, identity, default_branch="main", worktree=fixture.worktree, lease=lease)
    implementation = begin_implementation(
        repository, identity, context,
        implementation_attempt_id="local-implementation", provider_attempt_id="local-worker-implementation",
        plan_attempt_id=persisted_plan.plan_attempt_id, worker_thread_identity=plan_dispatch.worker_thread_identity,
        external_turn_identity="local-implementation-turn", process_lease_id="local-implementation-lease",
        process_lease_expires_at=epoch + 60, lease=lease, now=epoch,
    )
    _commit_local_implementation(binding.worktree, fixture.source_contents)
    seal = record_implementation_candidate(
        repository, identity, context, binding, implementation_attempt_id=implementation.implementation_attempt_id,
        completion_evidence_fingerprint=_fingerprint("implementation", identity.task_id), lease=lease, now=epoch,
    )
    for verification_id, kind in (("local-targeted-tests", VerificationKind.TEST), ("local-build", VerificationKind.BUILD)):
        record_candidate_verification(
            repository, identity, binding, seal,
            CandidateVerification(verification_id, kind, VerificationOutcome.PASS, _fingerprint(verification_id, seal.candidate_sha)),
            lease=lease,
        )

    candidate_context = RecoveryContext.for_task(
        identity, candidate_sha=seal.candidate_sha,
        policy_fingerprint=context.policy_fingerprint, deployment_fingerprint=context.deployment_fingerprint,
    )
    diff_review = dispatch_diff_review(
        repository, identity, candidate_context, binding, seal,
        diff_review_attempt_id="local-diff-review", implementation_attempt_id=implementation.implementation_attempt_id,
        provider_attempt_id="local-diff-supervisor", supervisor_session_identity="local-diff-supervisor-session",
        external_turn_identity="local-diff-review-turn", message_identity="local-diff-review-message",
        process_lease_id="local-diff-review-lease", process_lease_expires_at=epoch + 60, lease=lease, now=epoch,
    )
    record_diff_review(
        repository, identity, candidate_context, binding, seal, diff_review_attempt_id=diff_review.diff_review_attempt_id,
        output=DiffReviewOutput(
            diff_review.diff_review_attempt_id, diff_review.provider_attempt_id,
            diff_review.supervisor_session_identity, diff_review.external_turn_identity,
            diff_review.message_identity, seal.base_sha, seal.candidate_sha, DiffReviewVerdict.PASS,
        ),
        completion_evidence_fingerprint=_fingerprint("diff-review", seal.candidate_sha), lease=lease, now=epoch,
    )
    record_artifact(repository, identity, artifact_kind="diff", artifact_fingerprint=_fingerprint("diff-artifact", seal.candidate_sha), lease=lease)

    gate_context, policy_evidence = _gate_evidence(identity, seal, instant)
    for index, requirement in enumerate(GATE_REGISTRY, 1):
        not_applicable = requirement.permits_phase_two_local_na
        record_gate_evidence(
            repository, binding, seal, gate_context,
            GateEvidence(
                identity.task_id, seal.candidate_sha, requirement.key,
                EvidenceOutcome.NOT_APPLICABLE if not_applicable else EvidenceOutcome.PASS,
                "local-fixture", epoch + index, _fingerprint("gate", requirement.key.value, seal.candidate_sha),
                "isolated single-source local fixture" if not_applicable else None,
                "external adapter is outside this isolated local proof" if not_applicable else None,
            ),
            policy_evidence=policy_evidence, lease=lease,
        )
    decision = evaluate_gates(repository, binding, seal, gate_context, policy_evidence=policy_evidence, lease=lease)
    if decision.outcome is not GateOutcome.PASS:
        raise LocalSliceError("local slice gates did not pass")
    transition_ready_for_owner(
        repository, binding, seal, gate_context, evidence_fingerprint=_fingerprint("ready", seal.candidate_sha),
        policy_evidence=policy_evidence, lease=lease,
    )
    set_next_action(repository, identity, action_kind="owner-review", evidence_fingerprint=_fingerprint("owner-review", seal.candidate_sha), lease=lease)
    record_artifact(repository, identity, artifact_kind="status", artifact_fingerprint=_fingerprint("status", seal.candidate_sha), lease=lease)
    return LocalSliceResult(task_projection(repository, identity), seal, decision.outcome, plan_review.supervisor_session_identity, diff_review.supervisor_session_identity)


def _completed_result(repository, identity):
    try:
        task = task_projection(repository, identity)
    except StateError:
        return None
    if task.state != "ready-for-owner":
        raise LocalSliceError("local slice has incomplete persisted state")
    from .state import _open_writable_connection

    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (identity.task_id,)
        ).fetchone()
    finally:
        connection.close()
    if row is None or row[0] != identity.base_sha:
        raise LocalSliceError("completed local slice is missing its candidate seal")
    return LocalSliceResult(task, CandidateSeal(identity.task_id, *row), GateOutcome.PASS, "local-plan-supervisor-session", "local-diff-supervisor-session")


def _gate_evidence(identity, seal, instant):
    source = TrustedControlSource(_fingerprint("control-source", identity.task_id), _fingerprint("control-revision", identity.task_id))
    snapshot = TrustedPolicySnapshot(source, PolicyDocument(1, frozenset({PolicyAction.ISSUE_COMMENT})))
    context = GateContext(identity.task_id, seal.candidate_sha, 1, True, snapshot.policy_digest, _fingerprint("receipt", seal.candidate_sha))
    receipt = ActivationReceipt(
        _fingerprint("owner", identity.task_id), context.receipt_fingerprint,
        source.source_fingerprint, source.revision_fingerprint, snapshot.policy_digest, 1,
        task_identity_fingerprint(identity), seal.candidate_sha, instant, instant + timedelta(minutes=1),
    )
    return context, TrustedGatePolicyEvidence(snapshot, receipt, StandingAuthority(frozenset(PolicyAction)), instant, ReceiptStatus.FRESH)


def _commit_local_implementation(worktree: Path, source_contents: str) -> None:
    target = worktree / "implementation.txt"
    target.write_text(source_contents, encoding="utf-8")
    _git(worktree, "add", target.name)
    _git(worktree, "commit", "-m", "feat(local-slice): record hermetic implementation")


def _git(directory: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(directory), *arguments], check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise LocalSliceError("local Git fixture command failed")
    return result.stdout.strip()


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
