"""Fresh, hermetic Supervisor review for one exact persisted Worker plan.

This module models only the Phase 2 review contract.  Callers supply opaque
fake/sandboxed identities and structured output; it never starts a process,
loads a provider SDK, reads credentials, or grants mutation authority.
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
    ProviderRole,
    RecoveryContext,
    invalidate_supervisor_attempt,
    prepare_attempt,
    read_attempt,
    record_completed_output,
    record_external_turn,
    record_invalid_output,
    record_session_identity,
)
from .state import StateError, TaskIdentity, _open_writable_connection, _require_matching_task
from .worker_planning import (
    PlanAttemptState,
    WorkerPlanningError,
    _items as _canonical_plan_findings,
    read_plan,
    route_plan_findings,
)


class PlanReviewError(StateError):
    """Raised when a Supervisor plan-review attempt is malformed or stale."""


class PlanReviewVerdict(StrEnum):
    PASS = "pass"
    FINDINGS = "findings"


class PlanReviewState(StrEnum):
    DISPATCHED = "dispatched"
    RECORDED = "recorded"
    INVALIDATED = "invalidated"


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class PlanReviewOutput:
    """One complete, identity-bound structured Supervisor response."""

    review_attempt_id: str
    provider_attempt_id: str
    supervisor_session_identity: str
    external_turn_identity: str
    plan_attempt_id: str
    source_digest: str
    plan_digest: str
    verdict: PlanReviewVerdict
    findings: tuple[str, ...]
    missing_tests: tuple[str, ...]
    ambiguous_criteria: tuple[str, ...]
    residual_risks: tuple[str, ...]

    def normalized(self) -> "PlanReviewOutput":
        for value, name in (
            (self.review_attempt_id, "review attempt identity"),
            (self.provider_attempt_id, "provider attempt identity"),
            (self.supervisor_session_identity, "Supervisor session identity"),
            (self.external_turn_identity, "external turn identity"),
            (self.plan_attempt_id, "plan attempt identity"),
        ):
            _require_token(value, name)
        _require_fingerprint(self.source_digest, "source digest")
        _require_fingerprint(self.plan_digest, "plan digest")
        try:
            verdict = PlanReviewVerdict(self.verdict)
        except (TypeError, ValueError) as error:
            raise PlanReviewError("review verdict is unsupported") from error
        result = PlanReviewOutput(
            self.review_attempt_id,
            self.provider_attempt_id,
            self.supervisor_session_identity,
            self.external_turn_identity,
            self.plan_attempt_id,
            self.source_digest,
            self.plan_digest,
            verdict,
            _items(self.findings, "findings"),
            _items(self.missing_tests, "missing tests"),
            _items(self.ambiguous_criteria, "ambiguous criteria"),
            _items(self.residual_risks, "residual risks"),
        )
        details = (*result.findings, *result.missing_tests, *result.ambiguous_criteria, *result.residual_risks)
        if verdict is PlanReviewVerdict.PASS and details:
            raise PlanReviewError("PASS must not include findings or residual review fields")
        if verdict is PlanReviewVerdict.FINDINGS and not details:
            raise PlanReviewError("FINDINGS requires at least one structured detail")
        return result

    @property
    def digest(self) -> str:
        value = self.normalized()
        return _digest(
            {
                "review_attempt": value.review_attempt_id,
                "provider_attempt": value.provider_attempt_id,
                "session": value.supervisor_session_identity,
                "turn": value.external_turn_identity,
                "plan_attempt": value.plan_attempt_id,
                "source": value.source_digest,
                "plan": value.plan_digest,
                "verdict": value.verdict.value,
                "findings": value.findings,
                "missing_tests": value.missing_tests,
                "ambiguous_criteria": value.ambiguous_criteria,
                "residual_risks": value.residual_risks,
            }
        )


@dataclass(frozen=True)
class PlanReviewDispatch:
    review_attempt_id: str
    provider_attempt_id: str
    supervisor_session_identity: str
    external_turn_identity: str
    plan_attempt_id: str
    source_digest: str
    plan_digest: str
    input_digest: str


@dataclass(frozen=True)
class PersistedPlanReview:
    review_attempt_id: str
    plan_attempt_id: str
    supervisor_session_identity: str
    plan_digest: str
    verdict: PlanReviewVerdict
    state: PlanReviewState
    routed_finding_ids: tuple[str, ...]


def dispatch_plan_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    review_attempt_id: str,
    provider_attempt_id: str,
    supervisor_session_identity: str,
    external_turn_identity: str,
    plan_attempt_id: str,
    process_lease_id: str,
    process_lease_expires_at: int,
    selected_profile_identity: str | None = None,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PlanReviewDispatch:
    """Persist a new, non-reusable Supervisor session before review output exists."""

    for value, name in (
        (review_attempt_id, "review attempt identity"),
        (provider_attempt_id, "provider attempt identity"),
        (supervisor_session_identity, "Supervisor session identity"),
        (external_turn_identity, "external turn identity"),
        (plan_attempt_id, "plan attempt identity"),
        (process_lease_id, "process lease identity"),
    ):
        _require_token(value, name)
    plan = read_plan(repository, identity, plan_attempt_id)
    if plan.state is not PlanAttemptState.RECORDED or plan.has_true_blockers:
        raise PlanReviewError("only a complete unblocked plan can be reviewed")
    source_digest, plan_digest = plan.source_digest, plan.content_digest
    input_digest = _digest({"task": identity.task_id, "plan_attempt": plan_attempt_id, "source": source_digest, "plan": plan_digest})
    observed = _clock(now)
    existing = _read_dispatch(repository, identity, review_attempt_id)
    expected = PlanReviewDispatch(review_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, plan_attempt_id, source_digest, plan_digest, input_digest)
    if existing is not None:
        if existing != expected:
            raise PlanReviewError("review dispatch replay conflicts with committed state")
        return existing
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity, "plan-review")
        submitted = connection.execute(
            "SELECT plan_attempt_id, plan_digest FROM submitted_plan_reviews WHERE task_id = ?", (identity.task_id,)
        ).fetchone()
        if submitted != (plan_attempt_id, plan_digest):
            raise PlanReviewError("review dispatch does not match the submitted plan")
    finally:
        connection.close()
    provider = prepare_attempt(
        repository, identity, context, attempt_id=provider_attempt_id, role=ProviderRole.SUPERVISOR,
        process_lease_id=process_lease_id, process_lease_expires_at=process_lease_expires_at,
        input_fingerprint=input_digest, selected_profile_identity=selected_profile_identity, lease=lease, now=now,
    )
    if provider.role is not ProviderRole.SUPERVISOR:
        raise PlanReviewError("review provider attempt has the wrong role")
    if provider.state is AttemptState.PREPARED:
        record_session_identity(repository, identity, context, attempt_id=provider_attempt_id,
                                session_identity=supervisor_session_identity, lease=lease, now=now)
        record_external_turn(repository, identity, context, attempt_id=provider_attempt_id,
                             session_identity=supervisor_session_identity, external_turn_identity=external_turn_identity,
                             lease=lease, now=now)
    elif provider.state is AttemptState.DISPATCHED:
        if (provider.session_identity, provider.external_turn_identity) != (supervisor_session_identity, external_turn_identity):
            raise PlanReviewError("review provider turn conflicts with the requested dispatch")
    else:
        raise PlanReviewError("review provider attempt cannot finish a missing dispatch")
    _persist_dispatch(repository, identity, expected, lease, observed)
    return expected


def _persist_dispatch(repository, identity, expected, lease, observed) -> None:
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, observed)
        _require_matching_task(connection, identity, "plan-review")
        current = _read_dispatch_connection(connection, identity, expected.review_attempt_id)
        if current is None:
            connection.execute(
                "INSERT INTO plan_review_attempts(review_attempt_id, task_id, plan_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, source_digest, plan_digest, input_digest, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    expected.review_attempt_id, identity.task_id, expected.plan_attempt_id, expected.provider_attempt_id,
                    expected.supervisor_session_identity, expected.external_turn_identity, expected.source_digest,
                    expected.plan_digest, expected.input_digest, PlanReviewState.DISPATCHED.value, observed,
                ),
            )
        elif current != expected:
            raise PlanReviewError("review dispatch replay conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def record_plan_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    review_attempt_id: str,
    output: object,
    completion_evidence_fingerprint: str,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PersistedPlanReview:
    """Validate one complete response, accepting PASS or routing FINDINGS exactly once."""

    _require_token(review_attempt_id, "review attempt identity")
    _require_fingerprint(completion_evidence_fingerprint, "completion evidence fingerprint")
    dispatch = _read_dispatch(repository, identity, review_attempt_id)
    if dispatch is None:
        raise PlanReviewError("review dispatch is unavailable")
    try:
        if not isinstance(output, PlanReviewOutput):
            raise PlanReviewError("review output is malformed")
        normalized = output.normalized()
        if (
            normalized.review_attempt_id, normalized.provider_attempt_id, normalized.supervisor_session_identity,
            normalized.external_turn_identity, normalized.plan_attempt_id, normalized.source_digest, normalized.plan_digest,
        ) != (
            dispatch.review_attempt_id, dispatch.provider_attempt_id, dispatch.supervisor_session_identity,
            dispatch.external_turn_identity, dispatch.plan_attempt_id, dispatch.source_digest, dispatch.plan_digest,
        ):
            raise PlanReviewError("review output identity does not match the durable dispatch")
        canonical_details = () if normalized.verdict is PlanReviewVerdict.PASS else _canonical_routed_details(normalized)
    except (PlanReviewError, WorkerPlanningError) as error:
        _record_invalid(repository, identity, context, dispatch, output, str(error), lease, now)
        if isinstance(error, PlanReviewError):
            raise
        raise PlanReviewError("review findings routing data is invalid") from error
    record_completed_output(
        repository, identity, context, attempt_id=dispatch.provider_attempt_id,
        output_pointer=f"plan-review:{review_attempt_id}", completion_evidence_fingerprint=completion_evidence_fingerprint,
        output_fingerprint=normalized.digest, lease=lease, now=now,
    )
    _persist_artifact(repository, identity, dispatch, normalized, lease, now)
    if normalized.verdict is PlanReviewVerdict.FINDINGS:
        finding_ids = route_plan_findings(
            repository, identity, plan_attempt_id=dispatch.plan_attempt_id,
            findings=canonical_details, lease=lease, now=now,
        )
        _persist_route(repository, identity, dispatch, finding_ids, lease)
    else:
        _accept_pass_atomically(repository, identity, context, dispatch, lease, now)
    return read_plan_review(repository, identity, review_attempt_id)


def recover_plan_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    review_attempt_id: str,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PersistedPlanReview:
    """Invalidate an unaccepted partial review so retry requires a fresh session."""

    dispatch = _read_dispatch(repository, identity, review_attempt_id)
    if dispatch is None:
        raise PlanReviewError("review dispatch is unavailable")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        _require_exact_provider_context(connection, identity, dispatch.provider_attempt_id, context)
        artifact = connection.execute(
            "SELECT verdict, findings_json, missing_tests_json, ambiguous_criteria_json, residual_risks_json, content_digest FROM plan_review_artifacts WHERE review_attempt_id = ? AND task_id = ?",
            (review_attempt_id, identity.task_id),
        ).fetchone()
        task_state = connection.execute("SELECT state FROM tasks WHERE task_id = ?", (identity.task_id,)).fetchone()
    finally:
        connection.close()
    attempt = read_attempt(repository, identity, dispatch.provider_attempt_id)
    if artifact is not None and artifact[0] == PlanReviewVerdict.FINDINGS.value:
        _recover_routed_findings(repository, identity, dispatch, artifact, task_state[0] if task_state else None, lease, now)
    elif attempt.state is AttemptState.ACCEPTED:
        _accept_pass_atomically(repository, identity, context, dispatch, lease, now)
    else:
        invalidate_supervisor_attempt(repository, identity, context, attempt_id=attempt.attempt_id, lease=lease, now=now)
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_current_lease(connection, lease, identity.repository_id, _clock(now))
            _require_matching_task(connection, identity, "plan-review")
            connection.execute("UPDATE plan_review_attempts SET state = ? WHERE review_attempt_id = ?", (PlanReviewState.INVALIDATED.value, review_attempt_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    return read_plan_review(repository, identity, review_attempt_id)


def read_plan_review(repository: RepositoryIdentity, identity: TaskIdentity, review_attempt_id: str) -> PersistedPlanReview:
    _require_token(review_attempt_id, "review attempt identity")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute(
            "SELECT attempts.plan_attempt_id, attempts.supervisor_session_identity, attempts.plan_digest, attempts.state, artifacts.verdict, routes.finding_ids_json FROM plan_review_attempts AS attempts LEFT JOIN plan_review_artifacts AS artifacts ON artifacts.review_attempt_id = attempts.review_attempt_id LEFT JOIN plan_review_routes AS routes ON routes.review_attempt_id = attempts.review_attempt_id WHERE attempts.review_attempt_id = ? AND attempts.task_id = ?",
            (review_attempt_id, identity.task_id),
        ).fetchone()
        if row is None or row[4] is None:
            raise PlanReviewError("review result is unavailable")
        return PersistedPlanReview(review_attempt_id, row[0], row[1], row[2], PlanReviewVerdict(row[4]), PlanReviewState(row[3]), tuple(json.loads(row[5] or "[]")))
    finally:
        connection.close()


def _persist_artifact(repository, identity, dispatch, output, lease, now) -> None:
    payload = _canonical_json({
        "findings": output.findings, "missing_tests": output.missing_tests,
        "ambiguous_criteria": output.ambiguous_criteria, "residual_risks": output.residual_risks,
    })
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        _require_matching_task(connection, identity, "plan-review")
        existing = connection.execute(
            "SELECT verdict, findings_json, missing_tests_json, ambiguous_criteria_json, residual_risks_json, content_digest FROM plan_review_artifacts WHERE review_attempt_id = ?",
            (dispatch.review_attempt_id,),
        ).fetchone()
        expected = (output.verdict.value, json.dumps(output.findings), json.dumps(output.missing_tests), json.dumps(output.ambiguous_criteria), json.dumps(output.residual_risks), output.digest)
        if existing is None:
            connection.execute(
                "INSERT INTO plan_review_artifacts(review_attempt_id, task_id, verdict, findings_json, missing_tests_json, ambiguous_criteria_json, residual_risks_json, content_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (dispatch.review_attempt_id, identity.task_id, *expected),
            )
            connection.execute("UPDATE plan_review_attempts SET state = ? WHERE review_attempt_id = ?", (PlanReviewState.RECORDED.value, dispatch.review_attempt_id))
        elif existing != expected:
            raise PlanReviewError("review output conflicts with committed content")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _persist_route(repository, identity, dispatch, finding_ids, lease) -> None:
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, None)
        thread = connection.execute("SELECT worker_thread_identity FROM worker_plan_attempts WHERE plan_attempt_id = ? AND task_id = ?", (dispatch.plan_attempt_id, identity.task_id)).fetchone()
        if thread is None:
            raise PlanReviewError("review target Worker thread is unavailable")
        expected = (identity.task_id, dispatch.plan_attempt_id, thread[0], json.dumps(finding_ids))
        existing = connection.execute("SELECT task_id, plan_attempt_id, worker_thread_identity, finding_ids_json FROM plan_review_routes WHERE review_attempt_id = ?", (dispatch.review_attempt_id,)).fetchone()
        if existing is None:
            connection.execute("INSERT INTO plan_review_routes(review_attempt_id, task_id, plan_attempt_id, worker_thread_identity, finding_ids_json) VALUES (?, ?, ?, ?, ?)", (dispatch.review_attempt_id, *expected))
        elif existing != expected:
            raise PlanReviewError("review findings route conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _accept_pass_atomically(repository, identity, context, dispatch, lease, now) -> None:
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        _require_matching_task(connection, identity, "plan-review")
        _require_exact_provider_context(connection, identity, dispatch.provider_attempt_id, context)
        submitted = connection.execute("SELECT plan_attempt_id, plan_digest FROM submitted_plan_reviews WHERE task_id = ?", (identity.task_id,)).fetchone()
        expected = (dispatch.plan_attempt_id, dispatch.review_attempt_id, dispatch.plan_digest)
        if submitted != (dispatch.plan_attempt_id, dispatch.plan_digest):
            raise PlanReviewError("accepted PASS no longer matches the submitted plan")
        artifact = connection.execute("SELECT verdict FROM plan_review_artifacts WHERE review_attempt_id = ? AND task_id = ?", (dispatch.review_attempt_id, identity.task_id)).fetchone()
        if artifact != (PlanReviewVerdict.PASS.value,):
            raise PlanReviewError("only a recorded PASS can be accepted")
        provider = connection.execute("SELECT provider_role, state, accepted_review_identity, completion_evidence_fingerprint FROM provider_attempts WHERE attempt_id = ? AND task_id = ?", (dispatch.provider_attempt_id, identity.task_id)).fetchone()
        if provider is None or provider[0] != ProviderRole.SUPERVISOR.value or provider[3] is None:
            raise PlanReviewError("accepted PASS provider attempt is incomplete")
        if provider[1] == AttemptState.COMPLETED.value:
            connection.execute("UPDATE provider_attempts SET accepted_review_identity = ?, state = ? WHERE attempt_id = ?", (dispatch.review_attempt_id, AttemptState.ACCEPTED.value, dispatch.provider_attempt_id))
            provider = (provider[0], AttemptState.ACCEPTED.value, dispatch.review_attempt_id, provider[3])
        if provider[1] != AttemptState.ACCEPTED.value or provider[2] != dispatch.review_attempt_id:
            raise PlanReviewError("accepted PASS provider attempt conflicts with committed state")
        provider_review = connection.execute("SELECT task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities FROM accepted_provider_reviews WHERE accepted_review_identity = ?", (dispatch.review_attempt_id,)).fetchone()
        expected_provider_review = (identity.task_id, dispatch.provider_attempt_id, provider[3], *context.runtime_binding.columns())
        if provider_review is None:
            connection.execute("INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (dispatch.review_attempt_id, *expected_provider_review))
        elif provider_review != expected_provider_review:
            raise PlanReviewError("accepted provider review conflicts with committed state")
        existing = connection.execute("SELECT plan_attempt_id, review_identity, review_digest FROM accepted_plan_reviews WHERE task_id = ?", (identity.task_id,)).fetchone()
        if existing is None:
            connection.execute("INSERT INTO accepted_plan_reviews(task_id, plan_attempt_id, review_identity, review_digest) VALUES (?, ?, ?, ?)", (identity.task_id, *expected))
        elif existing != expected:
            raise PlanReviewError("accepted plan review conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _recover_routed_findings(repository, identity, dispatch, artifact, task_state, lease, now) -> None:
    """Finish or verify a committed FINDINGS cycle without opening another review."""

    try:
        findings = tuple(json.loads(artifact[1]))
        missing_tests = tuple(json.loads(artifact[2]))
        ambiguous_criteria = tuple(json.loads(artifact[3]))
        residual_risks = tuple(json.loads(artifact[4]))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise PlanReviewError("persisted findings artifact is malformed") from error
    try:
        output = PlanReviewOutput(
            dispatch.review_attempt_id, dispatch.provider_attempt_id, dispatch.supervisor_session_identity,
            dispatch.external_turn_identity, dispatch.plan_attempt_id, dispatch.source_digest, dispatch.plan_digest,
            PlanReviewVerdict.FINDINGS, findings, missing_tests, ambiguous_criteria, residual_risks,
        ).normalized()
        canonical_details = _canonical_routed_details(output)
    except (PlanReviewError, WorkerPlanningError) as error:
        raise PlanReviewError("persisted findings routing data is invalid") from error
    if output.digest != artifact[5]:
        raise PlanReviewError("persisted findings artifact has drifted")
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        _require_completed_review_provider(connection, identity, dispatch, artifact[5])
        expected_ids = _finding_ids(identity, dispatch.plan_attempt_id, canonical_details)
        route = connection.execute("SELECT task_id, plan_attempt_id, worker_thread_identity, finding_ids_json FROM plan_review_routes WHERE review_attempt_id = ?", (dispatch.review_attempt_id,)).fetchone()
        thread = connection.execute("SELECT worker_thread_identity FROM worker_plan_attempts WHERE plan_attempt_id = ? AND task_id = ?", (dispatch.plan_attempt_id, identity.task_id)).fetchone()
        if thread is None:
            raise PlanReviewError("review target Worker thread is unavailable")
        expected_route = (identity.task_id, dispatch.plan_attempt_id, thread[0], json.dumps(expected_ids))
        rows = connection.execute("SELECT finding_id FROM worker_plan_findings WHERE task_id = ? AND plan_attempt_id = ? ORDER BY finding_id", (identity.task_id, dispatch.plan_attempt_id)).fetchall()
        routed = tuple(row[0] for row in rows)
        if task_state == "planning":
            if routed != tuple(sorted(expected_ids)):
                raise PlanReviewError("planning state does not retain the exact routed findings")
            if route is not None and route != expected_route:
                raise PlanReviewError("review findings route conflicts with committed state")
        elif task_state == "plan-review":
            if route is not None or routed:
                raise PlanReviewError("findings routing checkpoint conflicts with task state")
        else:
            raise PlanReviewError("findings recovery task state is invalid")
    finally:
        connection.close()
    if task_state == "plan-review":
        finding_ids = route_plan_findings(repository, identity, plan_attempt_id=dispatch.plan_attempt_id, findings=canonical_details, lease=lease, now=now)
        _persist_route(repository, identity, dispatch, finding_ids, lease)
    elif route is None:
        _persist_route(repository, identity, dispatch, expected_ids, lease)


def _require_completed_review_provider(connection, identity, dispatch, artifact_digest) -> None:
    row = connection.execute(
        "SELECT provider_role, state, session_identity, external_turn_identity, input_fingerprint, output_pointer, completion_evidence_fingerprint FROM provider_attempts WHERE attempt_id = ? AND task_id = ?",
        (dispatch.provider_attempt_id, identity.task_id),
    ).fetchone()
    expected = (
        ProviderRole.SUPERVISOR.value, AttemptState.COMPLETED.value, dispatch.supervisor_session_identity,
        dispatch.external_turn_identity, dispatch.input_digest, f"plan-review:{dispatch.review_attempt_id}",
    )
    if row is None or tuple(row[:6]) != expected or row[6] is None:
        raise PlanReviewError("findings provider output binding is incomplete")
    binding = connection.execute("SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?", (dispatch.provider_attempt_id,)).fetchone()
    if binding != (artifact_digest,):
        raise PlanReviewError("findings provider output binding has drifted")


def _require_exact_provider_context(connection, identity, provider_attempt_id, context) -> None:
    if not isinstance(context, RecoveryContext) or context.task_id != identity.task_id:
        raise PlanReviewError("review recovery context does not match the task")
    for value, name in (
        (context.repository_fingerprint, "repository fingerprint"), (context.worktree_fingerprint, "worktree fingerprint"),
        (context.branch_fingerprint, "branch fingerprint"), (context.base_fingerprint, "base fingerprint"),
        (context.policy_fingerprint, "policy fingerprint"), (context.deployment_fingerprint, "deployment fingerprint"),
    ):
        _require_fingerprint(value, name)
    if context.candidate_fingerprint is not None:
        _require_fingerprint(context.candidate_fingerprint, "candidate fingerprint")
    expected = (
        identity.task_id, context.repository_fingerprint, context.worktree_fingerprint, context.branch_fingerprint,
        context.base_fingerprint, context.candidate_fingerprint, context.policy_fingerprint, context.deployment_fingerprint,
        *context.runtime_binding.columns(),
    )
    row = connection.execute(
        "SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities FROM provider_attempt_contexts WHERE attempt_id = ?",
        (provider_attempt_id,),
    ).fetchone()
    if row != expected:
        raise PlanReviewError("review recovery context has drifted")


def _finding_ids(identity, plan_attempt_id, findings) -> tuple[str, ...]:
    return tuple(
        f"finding-{_digest({'task': identity.task_id, 'plan': plan_attempt_id, 'finding': _digest({'finding': finding})})[:24]}"
        for finding in findings
    )


def _record_invalid(repository, identity, context, dispatch, output, reason, lease, now) -> None:
    record_invalid_output(
        repository, identity, context, attempt_id=dispatch.provider_attempt_id,
        output_pointer=f"invalid-plan-review:{dispatch.review_attempt_id}", output_fingerprint=_digest({"raw": repr(output)}),
        reason_fingerprint=_digest({"reason": reason}), lease=lease, now=now,
    )
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_current_lease(connection, lease, identity.repository_id, _clock(now))
        connection.execute("UPDATE plan_review_attempts SET state = ? WHERE review_attempt_id = ?", (PlanReviewState.INVALIDATED.value, dispatch.review_attempt_id))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _read_dispatch(repository, identity, review_attempt_id):
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        return _read_dispatch_connection(connection, identity, review_attempt_id)
    finally:
        connection.close()


def _read_dispatch_connection(connection, identity, review_attempt_id):
    row = connection.execute(
        "SELECT provider_attempt_id, supervisor_session_identity, external_turn_identity, plan_attempt_id, source_digest, plan_digest, input_digest FROM plan_review_attempts WHERE review_attempt_id = ? AND task_id = ?",
        (review_attempt_id, identity.task_id),
    ).fetchone()
    return None if row is None else PlanReviewDispatch(review_attempt_id, *row)


def _routed_details(output: PlanReviewOutput) -> tuple[str, ...]:
    tagged: list[str] = []
    for prefix, details, name in (
        ("finding", output.findings, "findings"),
        ("missing-test", output.missing_tests, "missing tests"),
        ("ambiguous-criterion", output.ambiguous_criteria, "ambiguous criteria"),
        ("residual-risk", output.residual_risks, "residual risks"),
    ):
        tagged.extend(f"{prefix}:{detail}" for detail in _canonical_plan_findings(details, name, allow_empty=True))
    return tuple(tagged)


def _canonical_routed_details(output: PlanReviewOutput) -> tuple[str, ...]:
    """Use Worker planning's complete findings normalization without copying it."""

    return _canonical_plan_findings(_routed_details(output), "plan findings")


def _items(value: Iterable[str], name: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise PlanReviewError(f"{name} must be a sequence")
    try:
        result = tuple(value)
    except TypeError as error:
        raise PlanReviewError(f"{name} must be a sequence") from error
    if any(not isinstance(item, str) or not item.strip() for item in result):
        raise PlanReviewError(f"{name} contains an invalid item")
    return result


def _require_token(value: object, name: str) -> None:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise PlanReviewError(f"{name} is invalid")


def _require_fingerprint(value: object, name: str) -> None:
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise PlanReviewError(f"{name} is invalid")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _clock(now: int | None) -> int:
    return int(time.time()) if now is None else now
