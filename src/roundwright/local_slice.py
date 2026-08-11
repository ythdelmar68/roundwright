"""Hermetic, single-source Phase 2 run-once fixture.

This module intentionally joins the persisted planning, review, candidate, and
gate contracts without starting a real provider or contacting an external
service.  It is an explicit local-fixture boundary: production command shells
remain fail closed.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .candidate_review import (
    CandidateReviewError,
    CandidateValidationControl,
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
from .configuration import RepositoryIdentity, ReviewPolicy, resolve_dispatch_configuration
from .dependency_policy import CandidateBinding, DependencyExecutionControl, DependencyPolicy, DependencyPolicyError, DependencyStage, ObservedDependency, TrustedDependencyAdmission, execute_after_dependency_preflight
from .gates import (
    EvidenceOutcome,
    GATE_REGISTRY,
    GateContext,
    GateEvidence,
    GateOutcome,
    TrustedGatePolicyEvidence,
    decide_gates,
    evaluate_gates,
    record_gate_evidence,
    task_identity_fingerprint,
    transition_ready_for_owner,
)
from .git_identity import CandidateSeal, GitEntrypointControl, GitIdentityError, provision_worktree, resolve_canonical_base, transition_lease
from .plan_review import PlanReviewOutput, PlanReviewVerdict, dispatch_plan_review, record_plan_review
from .policy import ActivationReceipt, PolicyAction, PolicyDocument, ReceiptStatus, StandingAuthority, TrustedControlSource, TrustedPolicySnapshot
from .provider_health import CodexCapability, CodexHealthContract, CodexRuntimeAudit, HealthState, ProviderHealthAuditIdentity, ProviderHealthObservation, ProviderHealthReceipt, profile_fingerprint
from .provider_recovery import ProviderRole, RecoveryContext
from .state import SourceSnapshot, StateError, TaskIdentity, TaskProjection, admit_task, check_database, database_path, initialize, record_artifact, set_next_action, task_projection
from .worker_planning import (
    PlanReviewReceipt,
    PlanningInput,
    WorkerPlan,
    WorkerPlanOutput,
    ProviderDispatchControl,
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
    git_entrypoint_control: GitEntrypointControl,
    trusted_policy_snapshot: TrustedPolicySnapshot | None = None,
    trusted_review_floor: ReviewPolicy | None = None,
    candidate_dependency_evidence: Callable[[CandidateBinding], tuple[DependencyPolicy, Iterable[ObservedDependency]]] | None = None,
    trusted_dependency_admission: Callable[[CandidateBinding], TrustedDependencyAdmission] | None = None,
    candidate_validation: Callable[[CandidateBinding, VerificationKind], str] | None = None,
    now: datetime | None = None,
) -> LocalSliceResult:
    """Drive one local task to ready-for-owner, or return its exact completed replay.

    The caller must provide a disposable repository with an ``origin/main``
    base and local Git identity.  The function makes one local implementation
    commit in the task worktree; it never reads credentials or uses networked
    APIs.  A second call is intentionally a read-only completion replay.
    """

    if type(repository) is not RepositoryIdentity or type(fixture) is not LocalSliceFixture or not isinstance(fixture.worktree, Path):
        raise LocalSliceError("local slice fixture is invalid")
    if not isinstance(fixture.source_contents, str) or not fixture.source_contents:
        raise LocalSliceError("local slice source is invalid")
    if type(git_entrypoint_control) is not GitEntrypointControl:
        raise LocalSliceError("local slice Git entrypoint control is invalid")
    if (
        git_entrypoint_control.binding.repository != fixture.repository_id
        or git_entrypoint_control.binding.task_id != fixture.task_id
    ):
        raise LocalSliceError("local slice Git entrypoint control does not match fixture identity")
    instant = datetime.now(timezone.utc) if now is None else now
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise LocalSliceError("local slice clock must be timezone-aware")
    epoch = int(instant.timestamp())
    if git_entrypoint_control.now != epoch:
        raise LocalSliceError("local slice clock does not match Git entrypoint control")
    try:
        git_entrypoint_control.dependency_control.require(
            git_entrypoint_control.binding, DependencyStage.GIT_ENTRYPOINT, now=git_entrypoint_control.now
        )
        base_sha = resolve_canonical_base(repository, "main", control=git_entrypoint_control)
    except (DependencyPolicyError, GitIdentityError) as error:
        raise LocalSliceError("local slice Git entrypoint preflight blocked execution") from error
    if base_sha != git_entrypoint_control.binding.candidate_sha:
        raise LocalSliceError("local slice canonical base does not match Git entrypoint control")
    base_dependency_binding = CandidateBinding(fixture.repository_id, fixture.task_id, base_sha)
    try:
        git_entrypoint_control.dependency_control.require(base_dependency_binding, DependencyStage.DISPATCH, now=epoch)
    except DependencyPolicyError as error:
        raise LocalSliceError("local slice dispatch preflight blocked execution") from error
    identity = TaskIdentity(
        fixture.task_id,
        fixture.source_id,
        fixture.repository_id,
        fixture.branch,
        str(fixture.worktree.resolve(strict=False)),
        base_sha,
    )
    configuration = _local_configuration(repository, trusted_policy_snapshot, trusted_review_floor)
    runtime_binding = configuration.pin().runtime_binding()
    dispatch_control = _materialize_dispatch_control(candidate_dependency_evidence, trusted_dependency_admission, base_dependency_binding, epoch)
    database = check_database(repository)
    if database.state == "healthy":
        completed = _completed_result(repository, identity, fixture, runtime_binding)
        if completed is not None:
            return completed
    elif database.state == "missing":
        initialize(repository)
    else:
        raise LocalSliceError("local slice database is unavailable")

    try:
        with transition_lease(
            repository,
            repository_id=identity.repository_id,
            owner="local-slice-fixture",
            ttl_seconds=120,
            now=epoch,
        ) as lease:
            return _run_new_slice(repository, identity, fixture, lease, instant, epoch, configuration, runtime_binding, git_entrypoint_control, base_dependency_binding, dispatch_control, candidate_dependency_evidence, trusted_dependency_admission, candidate_validation)
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


def _run_new_slice(repository, identity, fixture, lease, instant, epoch, configuration, runtime_binding, git_entrypoint_control, base_dependency_binding, dispatch_control, candidate_dependency_evidence, trusted_dependency_admission, candidate_validation):
    source_contents = _normalized_source_contents(fixture.source_contents)
    source = SourceSnapshot(identity.source_id, identity.repository_id, _fingerprint("source", source_contents))
    admit_task(repository, identity, (source,), lease=lease)
    set_next_action(repository, identity, action_kind="review-plan", evidence_fingerprint=_fingerprint("next", identity.task_id), lease=lease)
    begin_planning(repository, identity, evidence_fingerprint=_fingerprint("transition", "queued", identity.task_id), lease=lease)

    context = RecoveryContext.for_task(
        identity,
        candidate_sha=None,
        policy_fingerprint=_fingerprint("policy", identity.task_id),
        deployment_fingerprint=_fingerprint("deployment", identity.task_id),
        runtime_binding=runtime_binding,
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
        repository, identity, _health_context(context, identity, ProviderRole.PLANNING, configuration.worker.value, epoch), planning_input,
        plan_attempt_id="local-plan", provider_attempt_id="local-worker-plan",
        worker_thread_identity="local-worker-thread", external_turn_identity="local-plan-turn",
        process_lease_id="local-plan-lease", process_lease_expires_at=epoch + 60,
        binding=base_dependency_binding, control=dispatch_control, lease=lease, now=epoch,
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
        repository, identity, _health_context(context, identity, ProviderRole.SUPERVISOR, configuration.supervisor_attempt_profiles.value[0], epoch),
        review_attempt_id="local-plan-review", provider_attempt_id="local-plan-supervisor",
        supervisor_session_identity="local-plan-supervisor-session", external_turn_identity="local-plan-review-turn",
        plan_attempt_id=persisted_plan.plan_attempt_id, process_lease_id="local-plan-review-lease",
        process_lease_expires_at=epoch + 60, selected_profile_identity=runtime_binding.supervisor_profile_identities[0],
        binding=base_dependency_binding, control=dispatch_control, lease=lease, now=epoch,
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

    binding = provision_worktree(
        repository, identity, default_branch="main", worktree=fixture.worktree,
        control=git_entrypoint_control, lease=lease,
    )
    implementation = begin_implementation(
        repository, identity, _health_context(context, identity, ProviderRole.WORKER, configuration.worker.value, epoch),
        implementation_attempt_id="local-implementation", provider_attempt_id="local-worker-implementation",
        plan_attempt_id=persisted_plan.plan_attempt_id, worker_thread_identity=plan_dispatch.worker_thread_identity,
        external_turn_identity="local-implementation-turn", process_lease_id="local-implementation-lease",
        process_lease_expires_at=epoch + 60, binding=base_dependency_binding, control=dispatch_control, lease=lease, now=epoch,
    )
    _commit_local_implementation(binding.worktree, source_contents, control=git_entrypoint_control)
    seal = record_implementation_candidate(
        repository, identity, context, binding, implementation_attempt_id=implementation.implementation_attempt_id,
        git_entrypoint_control=git_entrypoint_control,
        completion_evidence_fingerprint=_fingerprint("implementation", identity.task_id), lease=lease, now=epoch,
    )
    candidate_binding = CandidateBinding(identity.repository_id, identity.task_id, seal.candidate_sha)
    try:
        dispatch_control.dependency_control.require(base_dependency_binding, DependencyStage.PACKAGE_BUILD, now=epoch)
    except DependencyPolicyError as error:
        raise LocalSliceError("local slice candidate build preflight blocked evidence collection") from error
    candidate_validation_control = _materialize_validation_control(
        candidate_dependency_evidence, trusted_dependency_admission, candidate_binding, epoch,
    )
    for verification_id, kind in (("local-targeted-tests", VerificationKind.TEST), ("local-build", VerificationKind.BUILD)):
        _run_and_record_candidate_validation(
            candidate_validation, candidate_binding, candidate_validation_control,
            repository, identity, binding, seal, verification_id, kind, lease, epoch,
        )

    candidate_context = RecoveryContext.for_task(
        identity, candidate_sha=seal.candidate_sha,
        policy_fingerprint=context.policy_fingerprint, deployment_fingerprint=context.deployment_fingerprint,
        runtime_binding=runtime_binding,
    )
    candidate_binding = CandidateBinding(identity.repository_id, identity.task_id, seal.candidate_sha)
    try:
        dispatch_control.dependency_control.require(base_dependency_binding, DependencyStage.DISPATCH, now=epoch)
    except DependencyPolicyError as error:
        raise LocalSliceError("local slice candidate dispatch preflight blocked evidence collection") from error
    candidate_dispatch_control = _materialize_dispatch_control(
        candidate_dependency_evidence, trusted_dependency_admission, candidate_binding, epoch,
    )
    diff_review = dispatch_diff_review(
        repository, identity, _health_context(candidate_context, identity, ProviderRole.SUPERVISOR, configuration.supervisor_attempt_profiles.value[0], epoch), binding, seal,
        dependency_binding=candidate_binding, control=candidate_dispatch_control,
        diff_review_attempt_id="local-diff-review", implementation_attempt_id=implementation.implementation_attempt_id,
        provider_attempt_id="local-diff-supervisor", supervisor_session_identity="local-diff-supervisor-session",
        external_turn_identity="local-diff-review-turn", message_identity="local-diff-review-message",
        process_lease_id="local-diff-review-lease", process_lease_expires_at=epoch + 60, selected_profile_identity=runtime_binding.supervisor_profile_identities[0], within_round_attempt=1,
        review_round=1, lease=lease, now=epoch,
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

    gate_context, policy_evidence = _gate_evidence(identity, seal, instant, runtime_binding)
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


def _completed_result(repository, identity, fixture, runtime_binding):
    try:
        task = task_projection(repository, identity)
    except StateError:
        return None
    if task.state != "ready-for-owner":
        raise LocalSliceError("local slice has incomplete persisted state")
    expected_source = _fingerprint("source", _normalized_source_contents(fixture.source_contents))
    connection = sqlite3.connect(f"{database_path(repository).resolve().as_uri()}?mode=ro", uri=True)
    try:
        source = connection.execute(
            "SELECT snapshots.source_digest FROM tasks JOIN source_snapshots AS snapshots ON snapshots.source_id = tasks.source_id "
            "WHERE tasks.task_id = ? AND tasks.source_id = ? AND snapshots.repository_id = ?",
            (identity.task_id, identity.source_id, identity.repository_id),
        ).fetchone()
        row = connection.execute(
            "SELECT base_sha, candidate_sha, state_identity FROM candidate_seals WHERE task_id = ?", (identity.task_id,)
        ).fetchone()
        plan = connection.execute(
            "SELECT reviews.supervisor_session_identity, reviews.source_digest, reviews.plan_digest, "
            "plans.source_digest, plan_artifact.content_digest, submitted.plan_digest, accepted_plan.review_digest "
            "FROM plan_review_attempts AS reviews "
            "JOIN plan_review_artifacts AS artifacts ON artifacts.review_attempt_id = reviews.review_attempt_id "
            "JOIN worker_plan_attempts AS plans ON plans.plan_attempt_id = reviews.plan_attempt_id "
            "JOIN worker_plan_artifacts AS plan_artifact ON plan_artifact.plan_attempt_id = plans.plan_attempt_id "
            "JOIN submitted_plan_reviews AS submitted ON submitted.task_id = reviews.task_id "
            "AND submitted.plan_attempt_id = reviews.plan_attempt_id "
            "JOIN accepted_plan_reviews AS accepted_plan ON accepted_plan.task_id = reviews.task_id "
            "AND accepted_plan.plan_attempt_id = reviews.plan_attempt_id "
            "JOIN provider_attempts AS attempts ON attempts.attempt_id = reviews.provider_attempt_id "
            "JOIN accepted_provider_reviews AS accepted ON accepted.accepted_review_identity = reviews.review_attempt_id "
            "AND accepted.attempt_id = attempts.attempt_id WHERE reviews.task_id = ? "
            "AND reviews.review_attempt_id = 'local-plan-review' AND reviews.state = 'recorded' "
            "AND reviews.plan_attempt_id = 'local-plan' "
            "AND artifacts.verdict = 'pass' AND attempts.state = 'accepted' "
            "AND attempts.accepted_review_identity = reviews.review_attempt_id",
            (identity.task_id,),
        ).fetchone()
        diff = connection.execute(
            "SELECT reviews.supervisor_session_identity, reviews.base_sha, reviews.candidate_sha, "
            "candidates.base_sha, candidates.candidate_sha, implementation.plan_attempt_id, "
            "implementation.accepted_plan_review_identity FROM diff_review_attempts AS reviews "
            "JOIN diff_review_artifacts AS artifacts ON artifacts.diff_review_attempt_id = reviews.diff_review_attempt_id "
            "JOIN implementation_candidates AS candidates ON candidates.implementation_attempt_id = reviews.implementation_attempt_id "
            "JOIN implementation_attempts AS implementation ON implementation.implementation_attempt_id = reviews.implementation_attempt_id "
            "JOIN provider_attempts AS attempts ON attempts.attempt_id = reviews.provider_attempt_id "
            "JOIN accepted_provider_reviews AS accepted ON accepted.accepted_review_identity = reviews.diff_review_attempt_id "
            "AND accepted.attempt_id = attempts.attempt_id WHERE reviews.task_id = ? "
            "AND reviews.diff_review_attempt_id = 'local-diff-review' AND reviews.state = 'accepted' "
            "AND reviews.implementation_attempt_id = 'local-implementation' "
            "AND artifacts.verdict = 'pass' AND attempts.state = 'accepted' "
            "AND attempts.accepted_review_identity = reviews.diff_review_attempt_id",
            (identity.task_id,),
        ).fetchone()
        context_row = connection.execute(
            "SELECT source_count, isolated_local_task, policy_digest, receipt_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_supervisor_profile_identity FROM gate_contexts "
            "WHERE task_id = ? AND candidate_sha = ?", (identity.task_id, row[1] if row else None),
        ).fetchone()
        gate_rows = connection.execute(
            "SELECT gates.task_id, gates.candidate_sha, gates.gate_key, gates.outcome, gates.evaluator_id, "
            "gates.evaluated_at, gates.evidence_fingerprint, gates.changed_boundary, gates.reason, gates.follow_ups "
            "FROM gate_evidence AS gates JOIN candidate_evidence AS evidence ON evidence.task_id = gates.task_id "
            "AND evidence.candidate_sha = gates.candidate_sha AND evidence.evidence_fingerprint = gates.evidence_fingerprint "
            "WHERE gates.task_id = ? AND gates.candidate_sha = ? ORDER BY gates.gate_key",
            (identity.task_id, row[1] if row else None),
        ).fetchall()
    finally:
        connection.close()
    if source != (expected_source,) or row is None or row[0] != identity.base_sha:
        raise LocalSliceError("completed local slice does not match its normalized source or candidate seal")
    if plan is None or diff is None or context_row is None:
        raise LocalSliceError("completed local slice is missing accepted review or gate evidence")
    if (
        plan[1:] != (expected_source, plan[2], expected_source, plan[2], plan[2], plan[2])
        or diff[1:] != (row[0], row[1], row[0], row[1], "local-plan", "local-plan-review")
    ):
        raise LocalSliceError("completed local slice review evidence does not match its source, plan, or candidate")
    expected_context, _ = _gate_evidence(
        identity, CandidateSeal(identity.task_id, *row), datetime(2030, 1, 1, tzinfo=timezone.utc), runtime_binding
    )
    if context_row != (
        expected_context.source_count,
        int(expected_context.isolated_local_task),
        expected_context.policy_digest,
        expected_context.receipt_fingerprint,
        *runtime_binding.columns(),
        expected_context.selected_supervisor_profile_identity,
    ):
        raise LocalSliceError("completed local slice gate context does not match the fixture contract")
    if any(record[9] != "[]" for record in gate_rows):
        raise LocalSliceError("completed local slice has malformed gate follow-up evidence")
    context = GateContext(identity.task_id, row[1], context_row[0], bool(context_row[1]), context_row[2], context_row[3], runtime_binding, context_row[8])
    evidence = tuple(GateEvidence(*record[:9], ()) for record in gate_rows)
    decision = decide_gates(context, evidence)
    if decision.outcome is not GateOutcome.PASS or len(evidence) != len(GATE_REGISTRY):
        raise LocalSliceError("completed local slice gate evidence is incomplete or invalid")
    expected_gates = {requirement.key.value for requirement in GATE_REGISTRY}
    if {record.gate_key.value if hasattr(record.gate_key, "value") else record.gate_key for record in evidence} != expected_gates:
        raise LocalSliceError("completed local slice gate evidence does not cover the registry")
    for requirement in GATE_REGISTRY:
        record = next(entry for entry in evidence if entry.gate_key == requirement.key.value)
        expected_na = requirement.permits_phase_two_local_na
        if (
            record.evaluator_id != "local-fixture"
            or record.evidence_fingerprint != _fingerprint("gate", requirement.key.value, row[1])
            or record.outcome != (EvidenceOutcome.NOT_APPLICABLE if expected_na else EvidenceOutcome.PASS)
            or record.changed_boundary != ("isolated single-source local fixture" if expected_na else None)
            or record.reason != ("external adapter is outside this isolated local proof" if expected_na else None)
        ):
            raise LocalSliceError("completed local slice gate evidence does not match the fixture contract")
    return LocalSliceResult(task, CandidateSeal(identity.task_id, *row), decision.outcome, plan[0], diff[0])


def _health_context(context, identity, role, profile, now):
    """Attach fixture-only typed preflight evidence for one local pseudo-turn."""

    audit = CodexRuntimeAudit(
        "1.2.3", "4.5.6",
        (CodexCapability(profile.model, profile.reasoning_effort.value),),
    )
    contract = CodexHealthContract(audit.sdk_version, audit.runtime_version, identity.base_sha)
    profile_identity = profile_fingerprint(profile)
    observation = ProviderHealthObservation(
        role, profile_identity, contract.fingerprint, audit.fingerprint,
        HealthState.READY, None, now, now + 60, 1,
    )
    ordinal = 0 if role is ProviderRole.PLANNING else 1 if role is ProviderRole.WORKER else 2 + context.runtime_binding.supervisor_profile_identities.index(profile_identity)
    receipt = ProviderHealthReceipt(
        identity.base_sha, context.candidate_sha, "local-slice-provider-health", ordinal,
        context.runtime_binding, role, profile_identity, observation,
        ProviderHealthAuditIdentity(audit, profile),
    )
    return replace(
        context,
        health_contract_commit=identity.base_sha,
        shadow_case_id="local-slice-provider-health",
        health_receipt=receipt,
    )


def _local_configuration(repository: RepositoryIdentity, trusted_policy_snapshot: object, trusted_review_floor: object):
    """Resolve the fixture configuration without invoking repository discovery commands."""

    return resolve_dispatch_configuration(
        # A repo-local Python makes os.__file__ a descendant of the checkout.
        # The filesystem root is stable across interpreter installation layouts.
        cwd=Path(repository.root.anchor),
        environment={},
        home=repository.root,
        trusted_policy_snapshot=trusted_policy_snapshot,
        trusted_review_floor=trusted_review_floor,
    )


def _gate_evidence(identity, seal, instant, runtime_binding):
    source = TrustedControlSource(_fingerprint("control-source", identity.task_id), _fingerprint("control-revision", identity.task_id))
    snapshot = TrustedPolicySnapshot(source, PolicyDocument(1, frozenset({PolicyAction.ISSUE_COMMENT})))
    selected_profile_identity = runtime_binding.supervisor_profile_identities[0]
    context = GateContext(identity.task_id, seal.candidate_sha, 1, True, snapshot.policy_digest, _fingerprint("receipt", seal.candidate_sha), runtime_binding, selected_profile_identity)
    receipt = ActivationReceipt(
        _fingerprint("owner", identity.task_id), context.receipt_fingerprint,
        source.source_fingerprint, source.revision_fingerprint, snapshot.policy_digest, 1,
        task_identity_fingerprint(identity), seal.candidate_sha, instant, instant + timedelta(minutes=1),
        runtime_binding, selected_profile_identity,
    )
    return context, TrustedGatePolicyEvidence(snapshot, receipt, StandingAuthority(frozenset(PolicyAction)), instant, ReceiptStatus.FRESH)


def _commit_local_implementation(
    worktree: Path, source_contents: str, *, control: GitEntrypointControl,
) -> None:
    if type(control) is not GitEntrypointControl:
        raise LocalSliceError("local implementation Git entrypoint control is invalid")
    try:
        control.dependency_control.require(control.binding, DependencyStage.GIT_ENTRYPOINT, now=control.now)
    except DependencyPolicyError as error:
        raise LocalSliceError("local implementation Git entrypoint preflight blocked execution") from error
    target = worktree / "implementation.txt"
    target.write_text(source_contents, encoding="utf-8")
    _git(worktree, "add", target.name)
    _git(worktree, "commit", "-m", "feat(local-slice): record hermetic implementation")


def _execute_candidate_diff_helper(
    binding: CandidateBinding,
    policy: DependencyPolicy | None,
    observations: Iterable[ObservedDependency] | None,
    action: Callable[[], object],
    now: int,
) -> object:
    """Canonical candidate-bound provider helper boundary for the local slice."""

    try:
        return execute_after_dependency_preflight(
            binding, policy, observations, DependencyStage.DISPATCH, now=now, action=action,
        )
    except DependencyPolicyError as error:
        raise LocalSliceError("candidate dependency preflight blocked helper execution") from error


def _execute_candidate_helper_from_factory(
    factory: Callable[[CandidateBinding], tuple[DependencyPolicy, Iterable[ObservedDependency]]] | None,
    admission_factory: Callable[[CandidateBinding], TrustedDependencyAdmission] | None,
    binding: CandidateBinding,
    stage: DependencyStage,
    action: Callable[[], object],
    now: int,
) -> object:
    """Require trusted evidence before every local-slice helper execution."""

    if not callable(factory) or not callable(admission_factory):
        raise LocalSliceError("candidate dependency evidence is unavailable")
    try:
        trusted_admission = admission_factory(binding)
        policy, observations = factory(binding)
    except (DependencyPolicyError, TypeError, ValueError) as error:
        raise LocalSliceError("candidate dependency evidence is unavailable") from error
    try:
        return execute_after_dependency_preflight(
            binding, policy, observations, stage, now=now, action=action,
            previous_policy=trusted_admission.previous_policy,
            trusted_admission=trusted_admission,
        )
    except DependencyPolicyError as error:
        raise LocalSliceError("candidate dependency preflight blocked helper execution") from error


def _materialize_dispatch_control(factory, admission_factory, binding, now):
    if not callable(factory) or not callable(admission_factory):
        raise LocalSliceError("candidate dependency evidence is unavailable")
    try:
        trusted_admission = admission_factory(binding)
        policy, observations = factory(binding)
        return execute_after_dependency_preflight(
            binding, policy, observations, DependencyStage.DISPATCH, now=now,
            previous_policy=trusted_admission.previous_policy, trusted_admission=trusted_admission,
            action=lambda: ProviderDispatchControl(binding, DependencyExecutionControl(policy, tuple(observations), trusted_admission), now),
        )
    except DependencyPolicyError as error:
        raise LocalSliceError("candidate dependency preflight blocked helper execution") from error


def _materialize_validation_control(factory, admission_factory, binding, now):
    if not callable(factory) or not callable(admission_factory):
        raise LocalSliceError("candidate dependency evidence is unavailable")
    try:
        trusted_admission = admission_factory(binding)
        policy, observations = factory(binding)
        return execute_after_dependency_preflight(
            binding, policy, observations, DependencyStage.PACKAGE_BUILD, now=now,
            previous_policy=trusted_admission.previous_policy, trusted_admission=trusted_admission,
            action=lambda: CandidateValidationControl(
                binding, DependencyExecutionControl(policy, tuple(observations), trusted_admission), now,
            ),
        )
    except DependencyPolicyError as error:
        raise LocalSliceError("candidate dependency preflight blocked helper execution") from error


def _run_and_record_candidate_validation(validation, candidate_binding, control, repository, identity, worktree_binding, seal, verification_id, kind, lease, now):
    """Run the actual validation callback before durable PASS evidence exists."""

    if not callable(validation):
        raise LocalSliceError("candidate validation is unavailable")
    try:
        control.require(candidate_binding, now=now)
    except (CandidateReviewError, DependencyPolicyError) as error:
        raise LocalSliceError("candidate validation preflight blocked execution") from error
    evidence = validation(candidate_binding, kind)
    if not isinstance(evidence, str) or not evidence:
        raise LocalSliceError("candidate validation is invalid")
    return record_candidate_verification(
        repository, identity, worktree_binding, seal,
        CandidateVerification(verification_id, kind, VerificationOutcome.PASS, _fingerprint(verification_id, seal.candidate_sha, evidence)),
        dependency_binding=candidate_binding, control=control,
        lease=lease,
        now=now,
    )


def _git(directory: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(directory), *arguments], check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, env=_hermetic_git_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LocalSliceError("local Git fixture command failed") from error
    if result.returncode != 0:
        raise LocalSliceError("local Git fixture command failed")
    return result.stdout.strip()


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _normalized_source_contents(value: str) -> str:
    """Canonicalize fixture text before it becomes durable source evidence."""

    if not isinstance(value, str):
        raise LocalSliceError("local slice source is invalid")
    normalized = "\n".join(line.rstrip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n")).strip()
    if not normalized:
        raise LocalSliceError("local slice source is invalid")
    return normalized + "\n"


def _hermetic_git_environment() -> dict[str, str]:
    """Expose only the OS variables needed to invoke the local Git executable."""

    allowed = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}
