"""Hermetic, provider-neutral Worker planning for one admitted local task.

The module accepts evidence from a fake or sandboxed Worker adapter, but does
not start a process, call a model SDK, read GitHub, or grant review authority.
It keeps the plan body local and binds every persisted value to the admitted
task, its source snapshot, the durable provider attempt, and one Worker thread.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from .configuration import RepositoryIdentity
from .git_identity import TransitionLease, _require_current_lease
from .provider_recovery import (
    AttemptState,
    ProviderAttempt,
    ProviderRole,
    RecoveryContext,
    prepare_attempt,
    read_attempt,
    record_completed_output,
    record_external_turn,
    record_session_identity,
)
from .state import StateError, TaskIdentity, _open_writable_connection, _require_matching_task, transition_task


class WorkerPlanningError(StateError):
    """Raised when a planning input, plan, or review receipt is unsafe."""


class PlanAttemptKind(StrEnum):
    INITIAL = "initial"
    REVISION = "revision"


class PlanAttemptState(StrEnum):
    DISPATCHED = "dispatched"
    RECORDED = "recorded"
    OWNER_BLOCKED = "owner-blocked"


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_PID = re.compile(r"^(?:pid[-_:]?)?\d+$", re.IGNORECASE)
_OWNER_BLOCKER = re.compile(r"^owner(?:[-_:].+)?$", re.IGNORECASE)


@dataclass(frozen=True)
class PlanningInput:
    """The immutable, normalized prompt payload for one Worker planning turn."""

    task_summary: str
    non_goals: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    expected_files: tuple[str, ...]
    test_plan: tuple[str, ...]
    risks: tuple[str, ...]
    recovery_notes: tuple[str, ...]

    def normalized(self) -> "PlanningInput":
        return PlanningInput(
            _text(self.task_summary, "task summary"),
            _items(self.non_goals, "non-goals", allow_empty=True),
            _items(self.acceptance_criteria, "acceptance criteria"),
            _items(self.expected_files, "expected files", allow_empty=True),
            _items(self.test_plan, "test plan"),
            _items(self.risks, "risks", allow_empty=True),
            _items(self.recovery_notes, "recovery notes", allow_empty=True),
        )

    @property
    def digest(self) -> str:
        return _digest(_input_payload(self.normalized()))


@dataclass(frozen=True)
class WorkerPlan:
    """Schema-conforming plan returned by a fake or sandboxed Worker turn."""

    task_summary: str
    non_goals: tuple[str, ...]
    expected_files: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    test_plan: tuple[str, ...]
    risks: tuple[str, ...]
    recovery_notes: tuple[str, ...]
    true_blockers: tuple[str, ...]

    def normalized(self) -> "WorkerPlan":
        return WorkerPlan(
            _text(self.task_summary, "task summary"),
            _items(self.non_goals, "non-goals", allow_empty=True),
            _items(self.expected_files, "expected files", allow_empty=True),
            _items(self.acceptance_criteria, "acceptance criteria"),
            _items(self.test_plan, "test plan"),
            _items(self.risks, "risks", allow_empty=True),
            _items(self.recovery_notes, "recovery notes", allow_empty=True),
            _items(self.true_blockers, "true blockers", allow_empty=True),
        )

    @property
    def digest(self) -> str:
        return _digest(_plan_payload(self.normalized()))


@dataclass(frozen=True)
class WorkerPlanOutput:
    """Identity-bearing Worker result accepted only for its exact dispatched turn."""

    plan_attempt_id: str
    provider_attempt_id: str
    worker_thread_identity: str
    external_turn_identity: str
    input_digest: str
    source_digest: str
    plan: WorkerPlan

    def normalized(self) -> "WorkerPlanOutput":
        _require_token(self.plan_attempt_id, "plan attempt identity")
        _require_token(self.provider_attempt_id, "provider attempt identity")
        _require_worker_thread(self.worker_thread_identity)
        _require_token(self.external_turn_identity, "external turn identity")
        _require_fingerprint(self.input_digest, "plan input digest")
        _require_fingerprint(self.source_digest, "plan source digest")
        return WorkerPlanOutput(
            self.plan_attempt_id,
            self.provider_attempt_id,
            self.worker_thread_identity,
            self.external_turn_identity,
            self.input_digest,
            self.source_digest,
            self.plan.normalized(),
        )


@dataclass(frozen=True)
class PlanningDispatch:
    """Durable identity emitted before a Worker turn is allowed to return a plan."""

    plan_attempt_id: str
    provider_attempt_id: str
    worker_thread_identity: str
    input_digest: str
    source_digest: str
    kind: PlanAttemptKind
    external_turn_identity: str
    process_lease_id: str
    process_lease_expires_at: int
    context_digest: str


@dataclass(frozen=True)
class PersistedPlan:
    """Verifiable, path-free projection of one accepted plan body."""

    plan_attempt_id: str
    worker_thread_identity: str
    source_digest: str
    input_digest: str
    content_digest: str
    kind: PlanAttemptKind
    state: PlanAttemptState
    has_true_blockers: bool


@dataclass(frozen=True)
class PlanReviewReceipt:
    """A separate reviewer attests to PASS for one exact persisted plan."""

    review_identity: str
    plan_digest: str
    accepted_pass: bool


@dataclass(frozen=True)
class PlanningCompletion:
    """The only output that permits the task to enter implementation."""

    plan_attempt_id: str
    plan_digest: str
    criteria: tuple[str, ...]
    criteria_digest: str


def begin_planning(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    evidence_fingerprint: str,
    lease: TransitionLease | None,
) -> None:
    """Move a queued admitted task to planning under the current single-writer lease."""

    transition_task(
        repository,
        identity,
        expected_state="queued",
        next_state="planning",
        evidence_fingerprint=evidence_fingerprint,
        lease=lease,
    )


def dispatch_plan(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    planning_input: PlanningInput,
    *,
    plan_attempt_id: str,
    provider_attempt_id: str,
    worker_thread_identity: str,
    external_turn_identity: str,
    process_lease_id: str,
    process_lease_expires_at: int,
    parent_plan_attempt_id: str | None = None,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PlanningDispatch:
    """Persist a normalized input and one stable Worker thread before dispatch.

    The adapter supplies opaque turn identities.  This wrapper forbids process
    IDs and pending placeholders from being treated as a Worker thread.
    """

    _require_token(plan_attempt_id, "plan attempt identity")
    _require_token(provider_attempt_id, "provider attempt identity")
    _require_worker_thread(worker_thread_identity)
    _require_token(external_turn_identity, "external turn identity")
    normalized = planning_input.normalized()
    context_digest = _context_digest(context)
    observed = _clock(now)
    kind = PlanAttemptKind.INITIAL if parent_plan_attempt_id is None else PlanAttemptKind.REVISION
    if parent_plan_attempt_id is not None:
        _require_token(parent_plan_attempt_id, "parent plan attempt identity")

    # Check a replay before creating another provider attempt.  The lease makes
    # this preflight authoritative for this local single-writer slice.
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity, "planning")
        source_digest = _source_digest(connection, identity)
        if kind is PlanAttemptKind.INITIAL:
            previous = connection.execute(
                "SELECT plan_attempt_id FROM worker_plan_attempts WHERE task_id = ? AND attempt_kind = 'initial' AND plan_attempt_id != ?",
                (identity.task_id, plan_attempt_id),
            ).fetchone()
            if previous is not None:
                raise WorkerPlanningError("an initial plan attempt is already recorded")
            revision_findings_digest = ""
        else:
            revision_findings_digest = _revision_scope(
                connection, identity, parent_plan_attempt_id, worker_thread_identity, normalized
            )
        existing = connection.execute(
            "SELECT provider_attempt_id, worker_thread_identity, source_digest, input_digest, task_summary, parent_plan_attempt_id, attempt_kind, revision_findings_digest, external_turn_identity, process_lease_id, process_lease_expires_at, context_digest "
            "FROM worker_plan_attempts WHERE plan_attempt_id = ?",
            (plan_attempt_id,),
        ).fetchone()
        expected = (
            provider_attempt_id,
            worker_thread_identity,
            source_digest,
            normalized.digest,
            normalized.task_summary,
            parent_plan_attempt_id,
            kind.value,
            revision_findings_digest,
            external_turn_identity,
            process_lease_id,
            process_lease_expires_at,
            context_digest,
        )
        if existing is not None:
            if tuple(existing) != expected:
                raise WorkerPlanningError("plan dispatch replay conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    provider = prepare_attempt(
        repository,
        identity,
        context,
        attempt_id=provider_attempt_id,
        role=ProviderRole.PLANNING,
        process_lease_id=process_lease_id,
        process_lease_expires_at=process_lease_expires_at,
        input_fingerprint=normalized.digest,
        lease=lease,
        now=now,
    )
    _require_planning_attempt(provider)
    if provider.state is AttemptState.DISPATCHED:
        if (provider.session_identity, provider.external_turn_identity) != (
            worker_thread_identity,
            external_turn_identity,
        ):
            raise WorkerPlanningError("dispatched provider turn does not match the requested Worker thread")
    else:
        record_session_identity(
            repository,
            identity,
            context,
            attempt_id=provider_attempt_id,
            session_identity=worker_thread_identity,
            lease=lease,
            now=now,
        )
        record_external_turn(
            repository,
            identity,
            context,
            attempt_id=provider_attempt_id,
            session_identity=worker_thread_identity,
            external_turn_identity=external_turn_identity,
            lease=lease,
            now=now,
        )

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity, "planning")
        source_digest = _source_digest(connection, identity)
        if kind is PlanAttemptKind.INITIAL:
            previous = connection.execute(
                "SELECT 1 FROM worker_plan_attempts WHERE task_id = ? AND attempt_kind = 'initial'",
                (identity.task_id,),
            ).fetchone()
            if previous is not None:
                raise WorkerPlanningError("an initial plan attempt is already recorded")
            revision_findings_digest = ""
        else:
            revision_findings_digest = _revision_scope(
                connection, identity, parent_plan_attempt_id, worker_thread_identity, normalized
            )
        existing = connection.execute(
            "SELECT provider_attempt_id, worker_thread_identity, source_digest, input_digest, task_summary, parent_plan_attempt_id, attempt_kind, revision_findings_digest, external_turn_identity, process_lease_id, process_lease_expires_at, context_digest "
            "FROM worker_plan_attempts WHERE plan_attempt_id = ?",
            (plan_attempt_id,),
        ).fetchone()
        expected = (
            provider_attempt_id,
            worker_thread_identity,
            source_digest,
            normalized.digest,
            normalized.task_summary,
            parent_plan_attempt_id,
            kind.value,
            revision_findings_digest,
            external_turn_identity,
            process_lease_id,
            process_lease_expires_at,
            context_digest,
        )
        if existing is None:
            connection.execute(
                "INSERT INTO worker_plan_attempts(plan_attempt_id, task_id, provider_attempt_id, worker_thread_identity, source_digest, input_digest, task_summary, parent_plan_attempt_id, attempt_kind, state, created_at, revision_findings_digest, external_turn_identity, process_lease_id, process_lease_expires_at, context_digest) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    plan_attempt_id,
                    identity.task_id,
                    provider_attempt_id,
                    worker_thread_identity,
                    source_digest,
                    normalized.digest,
                    normalized.task_summary,
                    parent_plan_attempt_id,
                    kind.value,
                    PlanAttemptState.DISPATCHED.value,
                    observed,
                    revision_findings_digest,
                    external_turn_identity,
                    process_lease_id,
                    process_lease_expires_at,
                    context_digest,
                ),
            )
        elif tuple(existing) != expected:
            raise WorkerPlanningError("plan dispatch replay conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return PlanningDispatch(
        plan_attempt_id,
        provider_attempt_id,
        worker_thread_identity,
        normalized.digest,
        source_digest,
        kind,
        external_turn_identity,
        process_lease_id,
        process_lease_expires_at,
        context_digest,
    )


def record_plan(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    plan_attempt_id: str,
    output: WorkerPlanOutput,
    completion_evidence_fingerprint: str,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PersistedPlan:
    """Validate one exact completed Worker output before making its plan reviewable."""

    _require_token(plan_attempt_id, "plan attempt identity")
    _require_fingerprint(completion_evidence_fingerprint, "completion evidence fingerprint")
    normalized_output = output.normalized()
    if normalized_output.plan_attempt_id != plan_attempt_id:
        raise WorkerPlanningError("Worker output plan attempt does not match the requested artifact")
    dispatch = _read_dispatch(repository, identity, plan_attempt_id)
    if (
        normalized_output.provider_attempt_id,
        normalized_output.worker_thread_identity,
        normalized_output.external_turn_identity,
        normalized_output.input_digest,
        normalized_output.source_digest,
    ) != (
        dispatch.provider_attempt_id,
        dispatch.worker_thread_identity,
        dispatch.external_turn_identity,
        dispatch.input_digest,
        dispatch.source_digest,
    ):
        raise WorkerPlanningError("Worker output identity does not match the durable dispatch")
    completed = record_completed_output(
        repository,
        identity,
        context,
        attempt_id=dispatch.provider_attempt_id,
        output_pointer=f"plan:{plan_attempt_id}",
        completion_evidence_fingerprint=completion_evidence_fingerprint,
        lease=lease,
        now=now,
    )
    if completed.state is not AttemptState.COMPLETED:
        raise WorkerPlanningError("Worker plan provider turn is not completed")
    normalized = normalized_output.plan
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity, "planning")
        attempt = _plan_attempt(connection, identity, plan_attempt_id)
        if normalized.task_summary != _input_task_summary(connection, plan_attempt_id):
            raise WorkerPlanningError("plan task summary does not match immutable planning input")
        payload = _canonical_json(_plan_payload(normalized))
        digest = normalized.digest
        existing = connection.execute(
            "SELECT content_json, content_digest FROM worker_plan_artifacts WHERE plan_attempt_id = ?",
            (plan_attempt_id,),
        ).fetchone()
        if existing is not None and existing != (payload, digest):
            raise WorkerPlanningError("plan artifact replay conflicts with committed content")
        if existing is not None:
            if attempt["state"] != PlanAttemptState.RECORDED.value:
                raise WorkerPlanningError("recorded plan artifact has an invalid attempt state")
            connection.commit()
            return _persisted_plan(repository, identity, plan_attempt_id)
        if attempt["state"] == PlanAttemptState.OWNER_BLOCKED.value:
            if attempt["owner_blocker_digest"] != digest:
                raise WorkerPlanningError("owner-blocked plan replay conflicts with committed output")
            connection.commit()
            raise WorkerPlanningError("plan requires owner input")
        if attempt["state"] != PlanAttemptState.DISPATCHED.value:
            raise WorkerPlanningError("plan attempt is not eligible for its first output")
        if _has_owner_blocker(normalized.true_blockers):
            connection.execute(
                "UPDATE worker_plan_attempts SET state = ?, owner_blocker_digest = ? WHERE plan_attempt_id = ?",
                (PlanAttemptState.OWNER_BLOCKED.value, digest, plan_attempt_id),
            )
            connection.commit()
            raise WorkerPlanningError("plan requires owner input")
        if existing is None:
            connection.execute(
                "INSERT INTO worker_plan_artifacts(plan_attempt_id, task_id, content_json, content_digest) VALUES (?, ?, ?, ?)",
                (plan_attempt_id, identity.task_id, payload, digest),
            )
        connection.execute(
            "UPDATE worker_plan_attempts SET state = ? WHERE plan_attempt_id = ?",
            (PlanAttemptState.RECORDED.value, plan_attempt_id),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return _persisted_plan(repository, identity, plan_attempt_id)


def route_plan_findings(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    plan_attempt_id: str,
    findings: Iterable[str],
    lease: TransitionLease | None,
    now: int | None = None,
) -> tuple[str, ...]:
    """Return an exact rejected review target to planning for a same-thread revision."""

    _require_token(plan_attempt_id, "plan attempt identity")
    normalized = _items(tuple(findings), "plan findings")
    observed = _clock(now)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        state = _require_matching_task(connection, identity)[0]
        identifiers, findings_digest = _finding_identifiers(identity, plan_attempt_id, normalized)
        transition_evidence = _digest(
            {"event": "plan-revision-open", "target": plan_attempt_id, "findings": findings_digest}
        )
        if state == "planning":
            _require_routed_findings(connection, identity, plan_attempt_id, identifiers)
            if connection.execute(
                "SELECT 1 FROM transition_events WHERE task_id = ? AND evidence_fingerprint = ?",
                (identity.task_id, transition_evidence),
            ).fetchone() is None:
                raise WorkerPlanningError("planning state is not a committed findings-routing replay")
            connection.commit()
            return identifiers
        if state != "plan-review":
            raise WorkerPlanningError("plan findings require the submitted plan-review state")
        _plan_attempt(connection, identity, plan_attempt_id, required_state=PlanAttemptState.RECORDED)
        target = connection.execute(
            "SELECT plan_attempt_id, plan_digest FROM submitted_plan_reviews WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()
        artifact = connection.execute(
            "SELECT content_digest FROM worker_plan_artifacts WHERE plan_attempt_id = ? AND task_id = ?",
            (plan_attempt_id, identity.task_id),
        ).fetchone()
        if target != (plan_attempt_id, artifact[0] if artifact is not None else None):
            raise WorkerPlanningError("plan findings do not match the submitted review target")
        for finding, finding_id in zip(normalized, identifiers, strict=True):
            digest = _digest({"finding": finding})
            existing = connection.execute(
                "SELECT task_id, plan_attempt_id, finding_digest FROM worker_plan_findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            expected = (identity.task_id, plan_attempt_id, digest)
            if existing is None:
                connection.execute(
                    "INSERT INTO worker_plan_findings(finding_id, task_id, plan_attempt_id, finding_digest, created_at) VALUES (?, ?, ?, ?, ?)",
                    (finding_id, *expected, observed),
                )
            elif existing != expected:
                raise WorkerPlanningError("plan finding identity conflicts with committed state")
        sequence = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM transition_events WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()[0]
        if connection.execute(
            "SELECT 1 FROM transition_events WHERE task_id = ? AND evidence_fingerprint = ?",
            (identity.task_id, transition_evidence),
        ).fetchone() is not None:
            raise WorkerPlanningError("findings-routing evidence has already been committed")
        connection.execute(
            "UPDATE tasks SET state = 'planning', blocked_from_state = NULL WHERE task_id = ? AND state = 'plan-review'",
            (identity.task_id,),
        )
        connection.execute(
            "INSERT INTO transition_events(task_id, sequence, from_state, to_state, evidence_fingerprint) VALUES (?, ?, 'plan-review', 'planning', ?)",
            (identity.task_id, sequence, transition_evidence),
        )
        connection.execute("DELETE FROM submitted_plan_reviews WHERE task_id = ?", (identity.task_id,))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return identifiers


def submit_plan_for_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    plan_attempt_id: str,
    evidence_fingerprint: str,
    lease: TransitionLease | None,
) -> PersistedPlan:
    """Expose an exact recorded plan to a later, separate review implementation."""

    plan = _persisted_plan(repository, identity, plan_attempt_id)
    if plan.state is not PlanAttemptState.RECORDED or plan.has_true_blockers:
        raise WorkerPlanningError("only a complete unblocked plan can be submitted for review")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, None)
        _require_matching_task(connection, identity, "planning")
        _require_completed_dispatch(connection, identity, plan_attempt_id)
        existing = connection.execute(
            "SELECT plan_attempt_id, plan_digest FROM submitted_plan_reviews WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()
        expected = (plan_attempt_id, plan.content_digest)
        if existing is None:
            connection.execute(
                "INSERT INTO submitted_plan_reviews(task_id, plan_attempt_id, plan_digest) VALUES (?, ?, ?)",
                (identity.task_id, *expected),
            )
        elif existing != expected:
            raise WorkerPlanningError("a different plan is already submitted for review")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    transition_task(
        repository,
        identity,
        expected_state="planning",
        next_state="plan-review",
        evidence_fingerprint=evidence_fingerprint,
        lease=lease,
    )
    return plan


def accept_plan_review_and_begin_implementation(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    *,
    plan_attempt_id: str,
    receipt: PlanReviewReceipt,
    evidence_fingerprint: str,
    lease: TransitionLease | None,
) -> PlanningCompletion:
    """Require a separate accepted PASS before persisting done criteria and implementing."""

    _require_token(plan_attempt_id, "plan attempt identity")
    _require_token(receipt.review_identity, "plan review identity")
    _require_fingerprint(receipt.plan_digest, "plan review digest")
    _require_fingerprint(evidence_fingerprint, "transition evidence fingerprint")
    if receipt.accepted_pass is not True:
        raise WorkerPlanningError("implementation requires an accepted plan-review PASS")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, None)
        _require_matching_task(connection, identity, "plan-review")
        _plan_attempt(connection, identity, plan_attempt_id, required_state=PlanAttemptState.RECORDED)
        _require_completed_dispatch(connection, identity, plan_attempt_id)
        submitted = connection.execute(
            "SELECT plan_attempt_id, plan_digest FROM submitted_plan_reviews WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()
        if submitted != (plan_attempt_id, receipt.plan_digest):
            raise WorkerPlanningError("accepted plan review does not match the submitted review target")
        artifact = connection.execute(
            "SELECT content_json, content_digest FROM worker_plan_artifacts WHERE plan_attempt_id = ? AND task_id = ?",
            (plan_attempt_id, identity.task_id),
        ).fetchone()
        if artifact is None or artifact[1] != receipt.plan_digest:
            raise WorkerPlanningError("accepted plan review does not bind the persisted plan digest")
        plan = _plan_from_payload(json.loads(artifact[0]))
        if plan.true_blockers:
            raise WorkerPlanningError("a blocked plan cannot enter implementation")
        criteria = _done_criteria(plan)
        criteria_json = _canonical_json({"criteria": criteria})
        criteria_digest = _digest({"criteria": criteria})
        existing_review = connection.execute(
            "SELECT plan_attempt_id, review_identity, review_digest FROM accepted_plan_reviews WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()
        expected_review = (plan_attempt_id, receipt.review_identity, receipt.plan_digest)
        if existing_review is None:
            connection.execute(
                "INSERT INTO accepted_plan_reviews(task_id, plan_attempt_id, review_identity, review_digest) VALUES (?, ?, ?, ?)",
                (identity.task_id, *expected_review),
            )
        elif existing_review != expected_review:
            raise WorkerPlanningError("accepted plan review conflicts with committed state")
        existing_criteria = connection.execute(
            "SELECT plan_attempt_id, criteria_json, criteria_digest FROM deterministic_done_criteria WHERE task_id = ?",
            (identity.task_id,),
        ).fetchone()
        expected_criteria = (plan_attempt_id, criteria_json, criteria_digest)
        if existing_criteria is None:
            connection.execute(
                "INSERT INTO deterministic_done_criteria(task_id, plan_attempt_id, criteria_json, criteria_digest) VALUES (?, ?, ?, ?)",
                (identity.task_id, *expected_criteria),
            )
        elif existing_criteria != expected_criteria:
            raise WorkerPlanningError("deterministic done criteria conflict with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    transition_task(
        repository,
        identity,
        expected_state="plan-review",
        next_state="implementing",
        evidence_fingerprint=evidence_fingerprint,
        lease=lease,
    )
    return PlanningCompletion(plan_attempt_id, receipt.plan_digest, criteria, criteria_digest)


def read_plan(repository: RepositoryIdentity, identity: TaskIdentity, plan_attempt_id: str) -> PersistedPlan:
    """Read a plan projection without exposing its local serialized body."""

    _require_token(plan_attempt_id, "plan attempt identity")
    return _persisted_plan(repository, identity, plan_attempt_id)


def _persisted_plan(repository: RepositoryIdentity, identity: TaskIdentity, plan_attempt_id: str) -> PersistedPlan:
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute(
            "SELECT attempts.worker_thread_identity, attempts.source_digest, attempts.input_digest, attempts.attempt_kind, attempts.state, artifacts.content_digest, artifacts.content_json "
            "FROM worker_plan_attempts AS attempts LEFT JOIN worker_plan_artifacts AS artifacts ON artifacts.plan_attempt_id = attempts.plan_attempt_id "
            "WHERE attempts.plan_attempt_id = ? AND attempts.task_id = ?",
            (plan_attempt_id, identity.task_id),
        ).fetchone()
        if row is None or row[5] is None:
            raise WorkerPlanningError("plan artifact is unavailable")
        plan = _plan_from_payload(json.loads(row[6]))
        return PersistedPlan(plan_attempt_id, row[0], row[1], row[2], row[5], PlanAttemptKind(row[3]), PlanAttemptState(row[4]), bool(plan.true_blockers))
    finally:
        connection.close()


def _read_dispatch(repository: RepositoryIdentity, identity: TaskIdentity, plan_attempt_id: str) -> PlanningDispatch:
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute(
            "SELECT provider_attempt_id, worker_thread_identity, input_digest, source_digest, attempt_kind, external_turn_identity, process_lease_id, process_lease_expires_at, context_digest FROM worker_plan_attempts WHERE plan_attempt_id = ? AND task_id = ?",
            (plan_attempt_id, identity.task_id),
        ).fetchone()
        if row is None:
            raise WorkerPlanningError("plan attempt is unavailable")
        return PlanningDispatch(plan_attempt_id, row[0], row[1], row[2], row[3], PlanAttemptKind(row[4]), row[5], row[6], row[7], row[8])
    finally:
        connection.close()


def _plan_attempt(connection, identity: TaskIdentity, plan_attempt_id: str, *, required_state: PlanAttemptState | None = None) -> dict[str, str]:
    row = connection.execute(
        "SELECT provider_attempt_id, worker_thread_identity, source_digest, input_digest, parent_plan_attempt_id, attempt_kind, state, revision_findings_digest, external_turn_identity, process_lease_id, process_lease_expires_at, context_digest, owner_blocker_digest FROM worker_plan_attempts WHERE plan_attempt_id = ? AND task_id = ?",
        (plan_attempt_id, identity.task_id),
    ).fetchone()
    if row is None:
        raise WorkerPlanningError("plan attempt does not match the task")
    result = dict(zip(("provider_attempt_id", "worker_thread_identity", "source_digest", "input_digest", "parent_plan_attempt_id", "attempt_kind", "state", "revision_findings_digest", "external_turn_identity", "process_lease_id", "process_lease_expires_at", "context_digest", "owner_blocker_digest"), row, strict=True))
    if required_state is not None and result["state"] != required_state.value:
        raise WorkerPlanningError("plan attempt is not in the required state")
    return result


def _require_completed_dispatch(connection, identity: TaskIdentity, plan_attempt_id: str) -> None:
    """Prove that the stored plan can only be reviewed after its exact turn completed."""

    attempt = _plan_attempt(connection, identity, plan_attempt_id)
    provider = connection.execute(
        "SELECT provider_role, process_lease_id, process_lease_expires_at, session_identity, external_turn_identity, input_fingerprint, state "
        "FROM provider_attempts WHERE attempt_id = ? AND task_id = ?",
        (attempt["provider_attempt_id"], identity.task_id),
    ).fetchone()
    expected = (
        ProviderRole.PLANNING.value,
        attempt["process_lease_id"],
        attempt["process_lease_expires_at"],
        attempt["worker_thread_identity"],
        attempt["external_turn_identity"],
        attempt["input_digest"],
        AttemptState.COMPLETED.value,
    )
    if provider != expected:
        raise WorkerPlanningError("plan artifact is not bound to an exact completed provider turn")


def _context_digest(context: RecoveryContext) -> str:
    return _digest(
        {
            "task": context.task_id,
            "repository": context.repository_fingerprint,
            "worktree": context.worktree_fingerprint,
            "branch": context.branch_fingerprint,
            "base": context.base_fingerprint,
            "candidate": context.candidate_fingerprint,
            "policy": context.policy_fingerprint,
            "deployment": context.deployment_fingerprint,
        }
    )


def _require_parent_attempt(connection, identity: TaskIdentity, parent: str, worker_thread_identity: str) -> None:
    row = _plan_attempt(connection, identity, parent, required_state=PlanAttemptState.RECORDED)
    if row["worker_thread_identity"] != worker_thread_identity:
        raise WorkerPlanningError("plan revision must use the original Worker thread")


def _revision_scope(
    connection,
    identity: TaskIdentity,
    parent: str,
    worker_thread_identity: str,
    planning_input: PlanningInput,
) -> str:
    """Require a recorded review delta and the original immutable task input."""

    _require_parent_attempt(connection, identity, parent, worker_thread_identity)
    initial = connection.execute(
        "SELECT input_digest, task_summary FROM worker_plan_attempts WHERE task_id = ? AND attempt_kind = 'initial'",
        (identity.task_id,),
    ).fetchone()
    if initial is None or initial != (planning_input.digest, planning_input.task_summary):
        raise WorkerPlanningError("plan revision changes immutable task scope")
    findings = connection.execute(
        "SELECT finding_id, finding_digest FROM worker_plan_findings WHERE task_id = ? AND plan_attempt_id = ? ORDER BY finding_id",
        (identity.task_id, parent),
    ).fetchall()
    if not findings:
        raise WorkerPlanningError("plan revision requires routed review findings")
    return _digest({"task": identity.task_id, "parent": parent, "findings": tuple(findings)})


def _finding_identifiers(
    identity: TaskIdentity, plan_attempt_id: str, findings: tuple[str, ...]
) -> tuple[tuple[str, ...], str]:
    identifiers = tuple(
        f"finding-{_digest({'task': identity.task_id, 'plan': plan_attempt_id, 'finding': _digest({'finding': finding})})[:24]}"
        for finding in findings
    )
    return identifiers, _digest({"task": identity.task_id, "plan": plan_attempt_id, "findings": identifiers})


def _require_routed_findings(
    connection, identity: TaskIdentity, plan_attempt_id: str, identifiers: tuple[str, ...]
) -> None:
    rows = connection.execute(
        "SELECT finding_id FROM worker_plan_findings WHERE task_id = ? AND plan_attempt_id = ? ORDER BY finding_id",
        (identity.task_id, plan_attempt_id),
    ).fetchall()
    if tuple(row[0] for row in rows) != tuple(sorted(identifiers)):
        raise WorkerPlanningError("planning state does not retain the exact routed findings")


def _source_digest(connection, identity: TaskIdentity) -> str:
    row = connection.execute(
        "SELECT source_digest FROM source_snapshots WHERE source_id = ? AND repository_id = ?",
        (identity.source_id, identity.repository_id),
    ).fetchone()
    if row is None:
        raise WorkerPlanningError("task source snapshot is unavailable")
    return row[0]


def _input_task_summary(connection, plan_attempt_id: str) -> str:
    row = connection.execute(
        "SELECT task_summary FROM worker_plan_attempts WHERE plan_attempt_id = ?", (plan_attempt_id,)
    ).fetchone()
    if row is None:
        raise WorkerPlanningError("plan input is unavailable")
    return row[0]


def _require_planning_attempt(attempt: ProviderAttempt) -> None:
    if attempt.role is not ProviderRole.PLANNING:
        raise WorkerPlanningError("provider attempt is not a planning attempt")


def _require_worker_thread(value: object) -> None:
    _require_token(value, "Worker thread identity")
    assert isinstance(value, str)
    lowered = value.lower()
    if _PID.fullmatch(value) or lowered in {"pending", "placeholder", "unknown", "none", "null"} or lowered.startswith("pending-"):
        raise WorkerPlanningError("Worker thread identity cannot be a PID or pending placeholder")
    if not any(character.isalpha() for character in value):
        raise WorkerPlanningError("Worker thread identity is invalid")


def _has_owner_blocker(blockers: tuple[str, ...]) -> bool:
    return any(_OWNER_BLOCKER.fullmatch(blocker) is not None for blocker in blockers)


def _done_criteria(plan: WorkerPlan) -> tuple[str, ...]:
    values = tuple(f"acceptance:{item}" for item in plan.acceptance_criteria) + tuple(f"test:{item}" for item in plan.test_plan)
    return tuple(sorted(set(values)))


def _input_payload(value: PlanningInput) -> dict[str, object]:
    return {
        "acceptance_criteria": value.acceptance_criteria,
        "expected_files": value.expected_files,
        "non_goals": value.non_goals,
        "recovery_notes": value.recovery_notes,
        "risks": value.risks,
        "task_summary": value.task_summary,
        "test_plan": value.test_plan,
    }


def _plan_payload(value: WorkerPlan) -> dict[str, object]:
    return {
        "acceptance_criteria": value.acceptance_criteria,
        "expected_files": value.expected_files,
        "non_goals": value.non_goals,
        "recovery_notes": value.recovery_notes,
        "risks": value.risks,
        "task_summary": value.task_summary,
        "test_plan": value.test_plan,
        "true_blockers": value.true_blockers,
    }


def _plan_from_payload(value: object) -> WorkerPlan:
    if not isinstance(value, dict) or set(value) != {"acceptance_criteria", "expected_files", "non_goals", "recovery_notes", "risks", "task_summary", "test_plan", "true_blockers"}:
        raise WorkerPlanningError("persisted plan artifact is malformed")
    return WorkerPlan(
        value["task_summary"], tuple(value["non_goals"]), tuple(value["expected_files"]), tuple(value["acceptance_criteria"]),
        tuple(value["test_plan"]), tuple(value["risks"]), tuple(value["recovery_notes"]), tuple(value["true_blockers"]),
    ).normalized()


def _text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise WorkerPlanningError(f"{name} is invalid")
    normalized = " ".join(value.split())
    if not normalized or len(normalized) > 2000:
        raise WorkerPlanningError(f"{name} is invalid")
    return normalized


def _items(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise WorkerPlanningError(f"{name} must be an immutable tuple")
    normalized = tuple(sorted({_text(item, name) for item in value}))
    if not normalized and not allow_empty:
        raise WorkerPlanningError(f"{name} must not be empty")
    return normalized


def _require_token(value: object, name: str) -> None:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise WorkerPlanningError(f"{name} is invalid")


def _require_fingerprint(value: object, name: str) -> None:
    if not isinstance(value, str) or _FINGERPRINT.fullmatch(value) is None:
        raise WorkerPlanningError(f"{name} is invalid")


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _clock(now: int | None) -> int:
    observed = int(time.time()) if now is None else now
    if not isinstance(observed, int) or observed <= 0:
        raise WorkerPlanningError("planning clock is invalid")
    return observed
