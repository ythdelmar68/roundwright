"""Hermetic implementation, candidate sealing, and immutable diff review.

This Phase 2 boundary receives identities and structured evidence from fake or
sandboxed adapters.  It never launches a Worker or Supervisor, reads a
credential, creates a pull request, or makes a network request.  Git identity
is delegated to :mod:`roundwright.git_identity`, which is the sole authority
for proving a clean local commit candidate.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable

from .configuration import FinalFindingsPolicy, RepositoryIdentity, ReviewMode
from .git_identity import CandidateSeal, GitIdentityError, TransitionLease, WorktreeBinding, bind_candidate_evidence, candidate_evidence, seal_candidate
from .provider_recovery import AttemptState, ProviderRole, RecoveryAction, RecoveryContext, RecoveryProjection, prepare_attempt, read_attempt, record_completed_output, record_external_turn, record_session_identity, recover_attempt
from .runtime_binding import RuntimeBinding, RuntimeBindingError
from .state import ReviewLimitFinalizationReceipt, StateError, TaskIdentity, _open_writable_connection, _require_matching_task, database_path, record_review_limit_finalization, transition_task


class CandidateReviewError(StateError):
    """Raised when candidate-bound implementation or diff review is unsafe."""


@dataclass(frozen=True)
class _ReviewPolicyProjection:
    review_round: int
    review_mode: ReviewMode
    complete_rounds: int
    max_rounds: int
    max_supervisor_attempts_per_round: int
    on_final_findings: FinalFindingsPolicy
    policy_digest: str


def _project_review_policy(review_round: int, binding: RuntimeBinding) -> _ReviewPolicyProjection:
    """Derive one typed immutable review policy projection."""

    if type(review_round) is not int or type(binding) is not RuntimeBinding or not binding.has_review_policy:
        raise CandidateReviewError("review policy projection is invalid")
    if not 1 <= review_round <= binding.review_max_rounds:
        raise CandidateReviewError("review policy projection is invalid")
    try:
        final_policy = FinalFindingsPolicy(binding.review_on_final_findings)
    except ValueError as error:
        raise CandidateReviewError("review policy projection is invalid") from error
    mode = ReviewMode.COMPLETE if review_round <= binding.review_complete_rounds else ReviewMode.CONVERGING
    digest = _digest({"complete_rounds": binding.review_complete_rounds, "max_rounds": binding.review_max_rounds, "max_supervisor_attempts_per_round": binding.review_max_supervisor_attempts_per_round, "on_final_findings": final_policy.value})
    if digest != binding.review_policy_digest:
        raise CandidateReviewError("resolved review policy binding has drifted")
    return _ReviewPolicyProjection(review_round, mode, binding.review_complete_rounds, binding.review_max_rounds, binding.review_max_supervisor_attempts_per_round, final_policy, digest)


class VerificationKind(StrEnum):
    TEST = "test"
    BUILD = "build"


class VerificationOutcome(StrEnum):
    PASS = "pass"
    NOT_APPLICABLE = "not-applicable"


class DiffReviewVerdict(StrEnum):
    PASS = "pass"
    FINDINGS = "findings"


def finalize_review_limit_repair(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    findings_fingerprint: str,
    worker_repair_fingerprint: str,
    worker_thread_identity: str,
    runtime_binding: RuntimeBinding,
    lease: TransitionLease | None,
) -> ReviewLimitFinalizationReceipt:
    """Consume the one same-Worker final repair under the active transition lease."""

    _require_candidate_binding(identity, binding, seal)
    return record_review_limit_finalization(
        repository,
        identity,
        findings_fingerprint=findings_fingerprint,
        worker_repair_fingerprint=worker_repair_fingerprint,
        candidate_sha=seal.candidate_sha,
        worker_thread_identity=worker_thread_identity,
        runtime_binding=runtime_binding,
        lease=lease,
    )


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


def _bound_diff_review_output_digest(raw_digest: str, within_round_attempt: int, selected_profile_identity: str) -> str:
    """Bind one normalized review output to its exact configured Supervisor attempt."""

    _fingerprint(raw_digest, "normalized diff review output digest")
    if type(within_round_attempt) is not int or within_round_attempt < 1:
        raise CandidateReviewError("within-round Supervisor attempt is invalid")
    _token(selected_profile_identity, "selected Supervisor profile identity")
    return _digest({"normalized_output_digest": raw_digest, "within_round_attempt": within_round_attempt, "selected_profile_identity": selected_profile_identity})


def _validate_diff_review_profile_mapping(runtime_binding: RuntimeBinding, within_round_attempt: int, selected_profile_identity: str) -> None:
    """Require the exact configured Supervisor profile at one positive attempt ordinal."""

    if type(runtime_binding) is not RuntimeBinding:
        raise CandidateReviewError("resolved configuration binding is invalid")
    profiles = runtime_binding.supervisor_profile_identities
    if type(within_round_attempt) is not int or not 1 <= within_round_attempt <= len(profiles):
        raise CandidateReviewError("within-round Supervisor attempt is invalid")
    if type(selected_profile_identity) is not str or selected_profile_identity != profiles[within_round_attempt - 1]:
        raise CandidateReviewError("selected Supervisor profile does not match the within-round attempt")


def _diff_review_input_digest(
    identity: TaskIdentity,
    implementation_attempt_id: str,
    base_sha: str,
    candidate_sha: str,
    message_identity: str,
    verification_digest: str,
    within_round_attempt: int,
    selected_profile_identity: str,
    policy_projection: _ReviewPolicyProjection,
) -> str:
    return _digest({"task": identity.task_id, "implementation": implementation_attempt_id, "base": base_sha, "candidate": candidate_sha, "message": message_identity, "verifications": verification_digest, "within_round_attempt": within_round_attempt, "selected_profile_identity": selected_profile_identity, "review_round": policy_projection.review_round, "review_mode": policy_projection.review_mode.value, "review_complete_rounds": policy_projection.complete_rounds, "review_max_rounds": policy_projection.max_rounds, "review_max_supervisor_attempts_per_round": policy_projection.max_supervisor_attempts_per_round, "review_on_final_findings": policy_projection.on_final_findings.value, "review_policy_digest": policy_projection.policy_digest})


@dataclass(frozen=True)
class ImplementationDispatch:
    implementation_attempt_id: str
    provider_attempt_id: str
    plan_attempt_id: str
    accepted_plan_review_identity: str
    worker_thread_identity: str
    external_turn_identity: str
    input_digest: str
    repair_diff_review_id: str | None = None
    repair_candidate_sha: str | None = None
    routed_finding_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RepairParent:
    """Durable lineage from a routed finding to its repair attempt."""

    diff_review_attempt_id: str | None
    candidate_sha: str | None
    finding_ids: tuple[str, ...]

    @property
    def digest(self) -> str:
        if self.diff_review_attempt_id is None:
            return ""
        return _digest({"review": self.diff_review_attempt_id, "candidate": self.candidate_sha, "findings": self.finding_ids})


@dataclass(frozen=True)
class CandidateVerification:
    verification_id: str
    kind: VerificationKind
    outcome: VerificationOutcome
    evidence_fingerprint: str
    justification: str = ""

    def normalized(self) -> "CandidateVerification":
        _token(self.verification_id, "verification identity")
        _fingerprint(self.evidence_fingerprint, "verification evidence fingerprint")
        try:
            kind = VerificationKind(self.kind)
            outcome = VerificationOutcome(self.outcome)
        except (TypeError, ValueError) as error:
            raise CandidateReviewError("verification kind or outcome is unsupported") from error
        if not isinstance(self.justification, str):
            raise CandidateReviewError("verification justification is invalid")
        justification = " ".join(self.justification.split())
        if outcome is VerificationOutcome.NOT_APPLICABLE and not justification:
            raise CandidateReviewError("not-applicable verification requires a justification")
        if outcome is VerificationOutcome.PASS and justification:
            raise CandidateReviewError("passing verification must not include a justification")
        return CandidateVerification(self.verification_id, kind, outcome, self.evidence_fingerprint, justification)


@dataclass(frozen=True)
class DiffReviewDispatch:
    diff_review_attempt_id: str
    implementation_attempt_id: str
    provider_attempt_id: str
    supervisor_session_identity: str
    external_turn_identity: str
    message_identity: str
    base_sha: str
    candidate_sha: str
    verification_digest: str
    input_digest: str
    within_round_attempt: int
    selected_profile_identity: str
    review_policy: _ReviewPolicyProjection


@dataclass(frozen=True)
class DiffReviewOutput:
    diff_review_attempt_id: str
    provider_attempt_id: str
    supervisor_session_identity: str
    external_turn_identity: str
    message_identity: str
    base_sha: str
    candidate_sha: str
    verdict: DiffReviewVerdict
    findings: tuple[str, ...] = ()

    def normalized(self) -> "DiffReviewOutput":
        for value, name in (
            (self.diff_review_attempt_id, "diff review identity"),
            (self.provider_attempt_id, "provider attempt identity"),
            (self.supervisor_session_identity, "Supervisor session identity"),
            (self.external_turn_identity, "external turn identity"),
            (self.message_identity, "review message identity"),
        ):
            _token(value, name)
        _commit(self.base_sha, "reviewed base")
        _commit(self.candidate_sha, "reviewed candidate")
        try:
            verdict = DiffReviewVerdict(self.verdict)
        except (TypeError, ValueError) as error:
            raise CandidateReviewError("diff review verdict is unsupported") from error
        findings = _items(self.findings, "diff review findings", allow_empty=True)
        if verdict is DiffReviewVerdict.PASS and findings:
            raise CandidateReviewError("PASS must not include findings")
        if verdict is DiffReviewVerdict.FINDINGS and not findings:
            raise CandidateReviewError("FINDINGS requires at least one finding")
        return DiffReviewOutput(
            self.diff_review_attempt_id, self.provider_attempt_id, self.supervisor_session_identity,
            self.external_turn_identity, self.message_identity, self.base_sha, self.candidate_sha, verdict, findings,
        )

    @property
    def digest(self) -> str:
        value = self.normalized()
        return _digest({
            "review": value.diff_review_attempt_id, "provider": value.provider_attempt_id,
            "session": value.supervisor_session_identity, "turn": value.external_turn_identity,
            "message": value.message_identity, "base": value.base_sha, "candidate": value.candidate_sha,
            "verdict": value.verdict.value, "findings": value.findings,
        })


@dataclass(frozen=True)
class PersistedDiffReview:
    diff_review_attempt_id: str
    implementation_attempt_id: str
    supervisor_session_identity: str
    message_identity: str
    base_sha: str
    candidate_sha: str
    verification_digest: str
    accepted_review_identity: str | None
    verdict: DiffReviewVerdict
    accepted: bool
    routed_finding_ids: tuple[str, ...]
    content_digest: str


def begin_implementation(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    *,
    implementation_attempt_id: str,
    provider_attempt_id: str,
    plan_attempt_id: str,
    worker_thread_identity: str,
    repair_diff_review_id: str | None = None,
    repair_candidate_sha: str | None = None,
    routed_finding_ids: tuple[str, ...] = (),
    external_turn_identity: str,
    process_lease_id: str,
    process_lease_expires_at: int,
    lease: TransitionLease | None,
    now: int | None = None,
) -> ImplementationDispatch:
    """Resume exactly the Worker accepted by plan review for an implementation turn."""

    for value, name in (
        (implementation_attempt_id, "implementation attempt identity"), (provider_attempt_id, "provider attempt identity"),
        (plan_attempt_id, "plan attempt identity"), (worker_thread_identity, "Worker thread identity"),
        (external_turn_identity, "external turn identity"), (process_lease_id, "process lease identity"),
    ):
        _token(value, name)
    accepted = _accepted_plan(repository, identity, plan_attempt_id, worker_thread_identity)
    repair_parent = _specified_repair_parent(repair_diff_review_id, repair_candidate_sha, routed_finding_ids)
    input_digest = _digest({"task": identity.task_id, "plan": plan_attempt_id, "review": accepted, "worker": worker_thread_identity, "repair": repair_parent.digest})
    expected = ImplementationDispatch(
        implementation_attempt_id, provider_attempt_id, plan_attempt_id, accepted, worker_thread_identity,
        external_turn_identity, input_digest, repair_parent.diff_review_attempt_id,
        repair_parent.candidate_sha, repair_parent.finding_ids,
    )
    existing = _read_implementation_dispatch(repository, identity, implementation_attempt_id)
    if existing is not None:
        if existing != expected:
            raise CandidateReviewError("implementation dispatch replay conflicts with committed state")
        _require_replayed_repair_parent(repository, identity, repair_parent, worker_thread_identity, implementation_attempt_id)
        return existing
    repair_parent = _repair_parent(
        repository, identity, repair_diff_review_id, repair_candidate_sha, routed_finding_ids, worker_thread_identity,
    )
    input_digest = _digest({"task": identity.task_id, "plan": plan_attempt_id, "review": accepted, "worker": worker_thread_identity, "repair": repair_parent.digest})
    expected = ImplementationDispatch(
        implementation_attempt_id, provider_attempt_id, plan_attempt_id, accepted, worker_thread_identity,
        external_turn_identity, input_digest, repair_parent.diff_review_attempt_id,
        repair_parent.candidate_sha, repair_parent.finding_ids,
    )
    claim_token = _claim_repair_parent(repository, identity, repair_parent, worker_thread_identity, implementation_attempt_id, provider_attempt_id, external_turn_identity, lease, now)
    try:
        provider = prepare_attempt(repository, identity, context, attempt_id=provider_attempt_id, role=ProviderRole.WORKER,
                                   process_lease_id=process_lease_id, process_lease_expires_at=process_lease_expires_at,
                                   input_fingerprint=input_digest, lease=lease, now=now)
        if provider.role is not ProviderRole.WORKER:
            raise CandidateReviewError("implementation provider attempt has the wrong role")
        if provider.state is AttemptState.PREPARED:
            record_session_identity(repository, identity, context, attempt_id=provider_attempt_id,
                                    session_identity=worker_thread_identity, lease=lease, now=now)
            record_external_turn(repository, identity, context, attempt_id=provider_attempt_id,
                                 session_identity=worker_thread_identity, external_turn_identity=external_turn_identity,
                                 lease=lease, now=now)
        elif provider.state is not AttemptState.DISPATCHED or (provider.session_identity, provider.external_turn_identity) != (worker_thread_identity, external_turn_identity):
            raise CandidateReviewError("implementation provider turn conflicts with the requested dispatch")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            _require_lease(connection, lease, identity, now)
            _require_matching_task(connection, identity, "implementing")
            current = _read_implementation_dispatch_connection(connection, identity, implementation_attempt_id)
            if current is None:
                connection.execute(
                    "INSERT INTO implementation_attempts(implementation_attempt_id, task_id, plan_attempt_id, accepted_plan_review_identity, provider_attempt_id, worker_thread_identity, external_turn_identity, input_digest, state, created_at, repair_diff_review_id, repair_candidate_sha, routed_finding_ids_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'dispatched', ?, ?, ?, ?)",
                    (
                        implementation_attempt_id, identity.task_id, plan_attempt_id, accepted,
                        provider_attempt_id, worker_thread_identity, external_turn_identity,
                        input_digest, _clock(now), repair_parent.diff_review_attempt_id,
                        repair_parent.candidate_sha, json.dumps(repair_parent.finding_ids),
                    ),
                )
                _consume_repair_parent(connection, identity, repair_parent, worker_thread_identity, implementation_attempt_id, provider_attempt_id, external_turn_identity, claim_token)
            elif current != expected:
                raise CandidateReviewError("implementation dispatch replay conflicts with committed state")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
    except Exception:
        if claim_token is not None:
            _release_repair_claim(repository, identity, repair_parent, claim_token, lease, now)
        raise
    return expected


def record_implementation_candidate(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    binding: WorktreeBinding,
    *,
    implementation_attempt_id: str,
    completion_evidence_fingerprint: str,
    lease: TransitionLease | None,
    now: int | None = None,
) -> CandidateSeal:
    """Seal a clean local commit, bind it to the exact Worker output, and enter diff review."""

    _fingerprint(completion_evidence_fingerprint, "implementation completion evidence fingerprint")
    dispatch = _read_implementation_dispatch(repository, identity, implementation_attempt_id)
    if dispatch is None:
        raise CandidateReviewError("implementation dispatch is unavailable")
    _require_candidate_binding(identity, binding, None)
    seal = seal_candidate(repository, binding, lease=lease)
    _require_candidate_binding(identity, binding, seal)
    if seal.candidate_sha == identity.base_sha:
        raise CandidateReviewError("implementation candidate requires a new local commit")
    candidate_evidence(repository, binding, seal, lease=lease)
    output_digest = _digest({"implementation": implementation_attempt_id, "base": seal.base_sha, "candidate": seal.candidate_sha})
    record_completed_output(repository, identity, context, attempt_id=dispatch.provider_attempt_id,
                            output_pointer=f"implementation:{implementation_attempt_id}",
                            completion_evidence_fingerprint=completion_evidence_fingerprint,
                            output_fingerprint=output_digest, lease=lease, now=now)
    bind_candidate_evidence(repository, binding, seal, evidence_fingerprint=completion_evidence_fingerprint, lease=lease)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        _require_matching_task(connection, identity, "implementing")
        existing = connection.execute(
            "SELECT task_id, base_sha, candidate_sha, completion_evidence_fingerprint, content_digest FROM implementation_candidates WHERE implementation_attempt_id = ?",
            (implementation_attempt_id,),
        ).fetchone()
        expected = (identity.task_id, seal.base_sha, seal.candidate_sha, completion_evidence_fingerprint, output_digest)
        if existing is None:
            connection.execute("INSERT INTO implementation_candidates(implementation_attempt_id, task_id, base_sha, candidate_sha, completion_evidence_fingerprint, content_digest) VALUES (?, ?, ?, ?, ?, ?)", (implementation_attempt_id, *expected))
            connection.execute("UPDATE implementation_attempts SET state = 'recorded' WHERE implementation_attempt_id = ?", (implementation_attempt_id,))
        elif existing != expected:
            raise CandidateReviewError("implementation candidate conflicts with committed content")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    transition_task(repository, identity, expected_state="implementing", next_state="diff-review", evidence_fingerprint=output_digest, lease=lease)
    return seal


def record_candidate_verification(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    verification: CandidateVerification,
    *,
    lease: TransitionLease | None,
) -> None:
    """Persist a structured test/build result only for the currently clean candidate."""

    value = verification.normalized()
    _require_candidate_binding(identity, binding, seal)
    candidate_evidence(repository, binding, seal, lease=lease)
    _require_current_candidate(repository, identity, seal)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, None)
        _require_matching_task(connection, identity, "diff-review")
        existing = connection.execute(
            "SELECT verification_kind, outcome, evidence_fingerprint, justification FROM candidate_verifications WHERE task_id = ? AND candidate_sha = ? AND verification_id = ?",
            (identity.task_id, seal.candidate_sha, value.verification_id),
        ).fetchone()
        expected = (value.kind.value, value.outcome.value, value.evidence_fingerprint, value.justification)
        if existing is None:
            connection.execute("INSERT INTO candidate_verifications(task_id, candidate_sha, verification_id, verification_kind, outcome, evidence_fingerprint, justification) VALUES (?, ?, ?, ?, ?, ?, ?)", (identity.task_id, seal.candidate_sha, value.verification_id, *expected))
        elif existing != expected:
            raise CandidateReviewError("candidate verification conflicts with committed evidence")
        kinds = {row[0] for row in connection.execute("SELECT verification_kind FROM candidate_verifications WHERE task_id = ? AND candidate_sha = ?", (identity.task_id, seal.candidate_sha))}
        if kinds == {VerificationKind.TEST.value, VerificationKind.BUILD.value}:
            snapshot = _verification_snapshot_connection(connection, identity, seal.candidate_sha)
            stale_attempts = tuple(
                row[0] for row in connection.execute(
                    "SELECT provider_attempt_id FROM diff_review_attempts WHERE task_id = ? AND candidate_sha = ? AND state = 'accepted' AND verification_digest != ?",
                    (identity.task_id, seal.candidate_sha, snapshot),
                )
            )
            for attempt_id in stale_attempts:
                connection.execute("DELETE FROM accepted_provider_reviews WHERE attempt_id = ?", (attempt_id,))
                connection.execute("UPDATE provider_attempts SET state = 'invalidated', accepted_review_identity = NULL WHERE attempt_id = ? AND state = 'accepted'", (attempt_id,))
            connection.execute(
                "UPDATE diff_review_attempts SET state = 'recorded', accepted_review_identity = NULL "
                "WHERE task_id = ? AND candidate_sha = ? AND state = 'accepted' AND verification_digest != ?",
                (identity.task_id, seal.candidate_sha, snapshot),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    bind_candidate_evidence(repository, binding, seal, evidence_fingerprint=value.evidence_fingerprint, lease=lease)


def dispatch_diff_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    diff_review_attempt_id: str,
    implementation_attempt_id: str,
    provider_attempt_id: str,
    supervisor_session_identity: str,
    external_turn_identity: str,
    message_identity: str,
    process_lease_id: str,
    process_lease_expires_at: int,
    selected_profile_identity: str,
    within_round_attempt: int,
    review_round: int,
    lease: TransitionLease | None,
    now: int | None = None,
) -> DiffReviewDispatch:
    """Dispatch one fresh read-only review of exactly ``base...candidate``."""

    for value, name in (
        (diff_review_attempt_id, "diff review identity"), (implementation_attempt_id, "implementation attempt identity"),
        (provider_attempt_id, "provider attempt identity"), (supervisor_session_identity, "Supervisor session identity"),
        (external_turn_identity, "external turn identity"), (message_identity, "review message identity"),
        (process_lease_id, "process lease identity"),
    ):
        _token(value, name)
    _require_candidate_binding(identity, binding, seal)
    candidate_evidence(repository, binding, seal, lease=lease)
    _require_current_candidate(repository, identity, seal, implementation_attempt_id)
    _require_diff_review_context(repository, identity, context, seal, implementation_attempt_id)
    verification_digest = _verification_snapshot(repository, identity, seal.candidate_sha)
    policy_projection = _project_review_policy(review_round, context.runtime_binding)
    _validate_diff_review_profile_mapping(context.runtime_binding, within_round_attempt, selected_profile_identity)
    if _session_is_plan_review(repository, identity, supervisor_session_identity):
        raise CandidateReviewError("diff review must use a session distinct from plan review")
    input_digest = _diff_review_input_digest(identity, implementation_attempt_id, seal.base_sha, seal.candidate_sha, message_identity, verification_digest, within_round_attempt, selected_profile_identity, policy_projection)
    expected = DiffReviewDispatch(diff_review_attempt_id, implementation_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, message_identity, seal.base_sha, seal.candidate_sha, verification_digest, input_digest, within_round_attempt, selected_profile_identity, policy_projection)
    existing = _read_diff_dispatch(repository, identity, diff_review_attempt_id)
    if existing is not None:
        if existing != expected:
            raise CandidateReviewError("diff review dispatch replay conflicts with committed state")
        return existing
    provider = prepare_attempt(repository, identity, context, attempt_id=provider_attempt_id, role=ProviderRole.SUPERVISOR,
                               process_lease_id=process_lease_id, process_lease_expires_at=process_lease_expires_at,
                               input_fingerprint=input_digest, selected_profile_identity=selected_profile_identity, lease=lease, now=now)
    if provider.state is AttemptState.PREPARED:
        record_session_identity(repository, identity, context, attempt_id=provider_attempt_id, session_identity=supervisor_session_identity, lease=lease, now=now)
        record_external_turn(repository, identity, context, attempt_id=provider_attempt_id, session_identity=supervisor_session_identity, external_turn_identity=external_turn_identity, lease=lease, now=now)
    elif provider.state is not AttemptState.DISPATCHED or (provider.session_identity, provider.external_turn_identity) != (supervisor_session_identity, external_turn_identity):
        raise CandidateReviewError("diff review provider turn conflicts with the requested dispatch")
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        _require_matching_task(connection, identity, "diff-review")
        current = _read_diff_dispatch_connection(connection, identity, diff_review_attempt_id)
        if current is None:
            connection.execute(
                "INSERT INTO diff_review_attempts(diff_review_attempt_id, task_id, implementation_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, message_identity, base_sha, candidate_sha, input_digest, state, created_at, verification_digest, within_round_attempt, selected_profile_identity, review_round, review_mode, review_max_rounds, review_on_final_findings, review_policy_digest, review_complete_rounds, review_max_supervisor_attempts_per_round) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'dispatched', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    diff_review_attempt_id, identity.task_id, implementation_attempt_id,
                    provider_attempt_id, supervisor_session_identity, external_turn_identity,
                    message_identity, seal.base_sha, seal.candidate_sha, input_digest, _clock(now), verification_digest, within_round_attempt, selected_profile_identity, policy_projection.review_round, policy_projection.review_mode.value, policy_projection.max_rounds, policy_projection.on_final_findings.value, policy_projection.policy_digest, policy_projection.complete_rounds, policy_projection.max_supervisor_attempts_per_round,
                ),
            )
        elif current != expected:
            raise CandidateReviewError("diff review dispatch replay conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    return expected


def record_diff_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    diff_review_attempt_id: str,
    output: object,
    completion_evidence_fingerprint: str,
    lease: TransitionLease | None,
    now: int | None = None,
) -> PersistedDiffReview:
    """Record PASS only for the current candidate, or route FINDINGS to its Worker."""

    _fingerprint(completion_evidence_fingerprint, "diff review completion evidence fingerprint")
    dispatch = _read_diff_dispatch(repository, identity, diff_review_attempt_id)
    if dispatch is None:
        raise CandidateReviewError("diff review dispatch is unavailable")
    if not isinstance(output, DiffReviewOutput):
        raise CandidateReviewError("diff review output is malformed")
    normalized = output.normalized()
    bound_output_digest = _bound_diff_review_output_digest(
        normalized.digest, dispatch.within_round_attempt, dispatch.selected_profile_identity,
    )
    if tuple(normalized.__dict__[field] for field in ("diff_review_attempt_id", "provider_attempt_id", "supervisor_session_identity", "external_turn_identity", "message_identity", "base_sha", "candidate_sha")) != tuple(dispatch.__dict__[field] for field in ("diff_review_attempt_id", "provider_attempt_id", "supervisor_session_identity", "external_turn_identity", "message_identity", "base_sha", "candidate_sha")):
        raise CandidateReviewError("diff review output identity does not match the durable dispatch")
    _require_live_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id, dispatch.implementation_attempt_id, lease)
    if _verification_snapshot(repository, identity, seal.candidate_sha) != dispatch.verification_digest:
        raise CandidateReviewError("diff review verification evidence has changed")
    provider = read_attempt(repository, identity, dispatch.provider_attempt_id)
    if (
        provider.role is not ProviderRole.SUPERVISOR
        or provider.selected_profile_identity != dispatch.selected_profile_identity
        or provider.input_fingerprint != dispatch.input_digest
    ):
        raise CandidateReviewError("diff review provider attempt does not match the durable dispatch")
    if provider.state is AttemptState.ACCEPTED:
        if (
            provider.accepted_review_identity != dispatch.diff_review_attempt_id
            or provider.output_pointer != f"diff-review:{diff_review_attempt_id}"
            or provider.completion_evidence_fingerprint != completion_evidence_fingerprint
            or _provider_output_fingerprint(repository, identity, dispatch.provider_attempt_id) != bound_output_digest
        ):
            _stale_diff_review_acceptance(repository, identity, diff_review_attempt_id, lease)
            raise CandidateReviewError("accepted diff review replay conflicts with provider evidence")
    else:
        record_completed_output(repository, identity, context, attempt_id=dispatch.provider_attempt_id,
                                output_pointer=f"diff-review:{diff_review_attempt_id}", completion_evidence_fingerprint=completion_evidence_fingerprint,
                                output_fingerprint=bound_output_digest, lease=lease, now=now)
    findings = normalized.findings
    finding_ids = tuple(f"diff-finding-{_digest({'task': identity.task_id, 'candidate': seal.candidate_sha, 'finding': finding})[:24]}" for finding in findings)
    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        _require_matching_task(connection, identity, "diff-review")
        artifact = connection.execute("SELECT verdict, findings_json, content_digest FROM diff_review_artifacts WHERE diff_review_attempt_id = ?", (diff_review_attempt_id,)).fetchone()
        expected_artifact = (normalized.verdict.value, json.dumps(findings), bound_output_digest)
        if artifact is None:
            connection.execute("INSERT INTO diff_review_artifacts(diff_review_attempt_id, task_id, verdict, findings_json, content_digest) VALUES (?, ?, ?, ?, ?)", (diff_review_attempt_id, identity.task_id, *expected_artifact))
            connection.execute("UPDATE diff_review_attempts SET state = 'recorded' WHERE diff_review_attempt_id = ?", (diff_review_attempt_id,))
        elif artifact != expected_artifact:
            raise CandidateReviewError("diff review output conflicts with committed content")
        if normalized.verdict is DiffReviewVerdict.FINDINGS:
            thread = connection.execute("SELECT worker_thread_identity FROM implementation_attempts WHERE implementation_attempt_id = ?", (dispatch.implementation_attempt_id,)).fetchone()
            if thread is None:
                raise CandidateReviewError("review target Worker thread is unavailable")
            route = connection.execute("SELECT worker_thread_identity, finding_ids_json FROM diff_review_routes WHERE diff_review_attempt_id = ?", (diff_review_attempt_id,)).fetchone()
            expected_route = (thread[0], json.dumps(finding_ids))
            if route is None:
                connection.execute("INSERT INTO diff_review_routes(diff_review_attempt_id, task_id, worker_thread_identity, finding_ids_json) VALUES (?, ?, ?, ?)", (diff_review_attempt_id, identity.task_id, *expected_route))
            elif route != expected_route:
                raise CandidateReviewError("diff review findings route conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    bind_candidate_evidence(repository, binding, seal, evidence_fingerprint=completion_evidence_fingerprint, lease=lease)
    if normalized.verdict is DiffReviewVerdict.FINDINGS:
        transition_task(repository, identity, expected_state="diff-review", next_state="implementing", evidence_fingerprint=bound_output_digest, lease=lease)
    else:
        _require_live_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id, dispatch.implementation_attempt_id, lease)
        _accept_diff_pass(repository, identity, context, dispatch, lease, now)
    return read_diff_review(repository, identity, diff_review_attempt_id, binding=binding, seal=seal, context=context, lease=lease)


def read_diff_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    diff_review_attempt_id: str,
    *,
    binding: WorktreeBinding | None = None,
    seal: CandidateSeal | None = None,
    context: RecoveryContext | None = None,
    lease: TransitionLease | None = None,
) -> PersistedDiffReview:
    _token(diff_review_attempt_id, "diff review identity")
    if binding is None or seal is None or context is None:
        raise CandidateReviewError("reading diff review acceptance requires live candidate evidence")
    _require_live_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id, None, lease)
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute("SELECT attempts.implementation_attempt_id, attempts.supervisor_session_identity, attempts.message_identity, attempts.base_sha, attempts.candidate_sha, attempts.verification_digest, attempts.state, attempts.accepted_review_identity, attempts.provider_attempt_id, artifacts.verdict, routes.finding_ids_json, artifacts.content_digest FROM diff_review_attempts AS attempts LEFT JOIN diff_review_artifacts AS artifacts ON artifacts.diff_review_attempt_id = attempts.diff_review_attempt_id LEFT JOIN diff_review_routes AS routes ON routes.diff_review_attempt_id = attempts.diff_review_attempt_id WHERE attempts.diff_review_attempt_id = ? AND attempts.task_id = ?", (diff_review_attempt_id, identity.task_id)).fetchone()
        if row is None or row[9] is None:
            raise CandidateReviewError("diff review result is unavailable")
        dispatch = _read_diff_dispatch_connection(connection, identity, diff_review_attempt_id)
        if dispatch is None:
            raise CandidateReviewError("diff review dispatch is unavailable")
        provider = connection.execute("SELECT state, accepted_review_identity, output_pointer, completion_evidence_fingerprint, selected_profile_identity, input_fingerprint FROM provider_attempts WHERE attempt_id = ? AND task_id = ?", (row[8], identity.task_id)).fetchone()
        output = connection.execute("SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?", (row[8],)).fetchone()
        accepted_provider = connection.execute("SELECT task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity, within_round_attempt FROM accepted_provider_reviews WHERE accepted_review_identity = ?", (row[7],)).fetchone() if row[7] is not None else None
        _require_exact_provider_context(connection, identity, row[8], context)
    finally:
        connection.close()
    current_snapshot = _verification_snapshot(repository, identity, row[4])
    accepted = (
        row[6] == "accepted"
        and row[7] == diff_review_attempt_id
        and provider is not None
        and provider[0] == AttemptState.ACCEPTED.value
        and provider[1] == row[7]
        and provider[2] == f"diff-review:{diff_review_attempt_id}"
        and provider[3] is not None
        and output == (row[11],)
        and provider[4] == dispatch.selected_profile_identity
        and provider[5] == dispatch.input_digest
        and accepted_provider == (identity.task_id, row[8], provider[3], *context.runtime_binding.columns(), dispatch.selected_profile_identity, dispatch.within_round_attempt)
        and current_snapshot == row[5]
    )
    if not accepted and row[6] == "accepted":
        _stale_diff_review_acceptance(repository, identity, diff_review_attempt_id, lease)
    return PersistedDiffReview(diff_review_attempt_id, row[0], row[1], row[2], row[3], row[4], row[5], row[7] if accepted else None, DiffReviewVerdict(row[9]), accepted, tuple(json.loads(row[10] or "[]")), row[11])


def recover_diff_review(
    repository: RepositoryIdentity,
    identity: TaskIdentity,
    context: RecoveryContext,
    binding: WorktreeBinding,
    seal: CandidateSeal,
    *,
    diff_review_attempt_id: str,
    verified_completion_evidence: str | None = None,
    max_attempts: int,
    lease: TransitionLease | None,
    now: int | None = None,
) -> RecoveryProjection:
    """Recover a diff review only after revalidating its live candidate binding."""

    _token(diff_review_attempt_id, "diff review identity")
    dispatch = _read_diff_dispatch(repository, identity, diff_review_attempt_id)
    if dispatch is None:
        raise CandidateReviewError("diff review dispatch is unavailable")
    _require_live_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id, dispatch.implementation_attempt_id, lease)
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT state FROM diff_review_attempts WHERE diff_review_attempt_id = ? AND task_id = ?",
            (diff_review_attempt_id, identity.task_id),
        ).fetchone()
    finally:
        connection.close()
    if row == ("accepted",):
        accepted = read_diff_review(repository, identity, diff_review_attempt_id, binding=binding, seal=seal, context=context, lease=lease)
        if not accepted.accepted:
            return recover_attempt(repository, identity, context, attempt_id=dispatch.provider_attempt_id,
                                   verified_completion_evidence=verified_completion_evidence, max_attempts=max_attempts,
                                   lease=lease, now=now)
        provider = read_attempt(repository, identity, dispatch.provider_attempt_id)
        if provider.state is AttemptState.ACCEPTED and provider.accepted_review_identity == diff_review_attempt_id:
            return RecoveryProjection(
                provider.attempt_id, provider.role, provider.state, provider.process_lease_id,
                provider.session_identity, provider.external_turn_identity,
                provider.output_pointer is not None and provider.completion_evidence_fingerprint is not None,
                provider.accepted_review_identity, None, RecoveryAction.ACCEPTED_REVIEW,
            )
        _stale_diff_review_acceptance(repository, identity, diff_review_attempt_id, lease)
        return recover_attempt(repository, identity, context, attempt_id=dispatch.provider_attempt_id,
                               verified_completion_evidence=verified_completion_evidence, max_attempts=max_attempts,
                               lease=lease, now=now)
    return recover_attempt(repository, identity, context, attempt_id=dispatch.provider_attempt_id,
                           verified_completion_evidence=verified_completion_evidence, max_attempts=max_attempts,
                           lease=lease, now=now)


def _require_live_diff_review(repository, identity, context, binding, seal, diff_review_attempt_id, implementation_attempt_id, lease):
    """Revalidate the candidate before any acceptance read, replay, or recovery."""

    try:
        _require_candidate_binding(identity, binding, seal)
        candidate_evidence(repository, binding, seal, lease=lease)
        _require_current_candidate(repository, identity, seal, implementation_attempt_id)
        connection = _open_writable_connection(repository)
        try:
            row = connection.execute(
                "SELECT provider_attempt_id, implementation_attempt_id FROM diff_review_attempts WHERE diff_review_attempt_id = ? AND task_id = ?",
                (diff_review_attempt_id, identity.task_id),
            ).fetchone()
            if row is None:
                raise CandidateReviewError("diff review recovery context is unavailable")
            bound_implementation = implementation_attempt_id if implementation_attempt_id is not None else row[1]
            _require_diff_review_context(repository, identity, context, seal, bound_implementation)
            if row is not None:
                _require_exact_provider_context(connection, identity, row[0], context)
        finally:
            connection.close()
    except (CandidateReviewError, GitIdentityError):
        _stale_diff_review_acceptance(repository, identity, diff_review_attempt_id, lease)
        raise


def _provider_output_fingerprint(repository, identity, attempt_id):
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute("SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?", (attempt_id,)).fetchone()
        return None if row is None else row[0]
    finally:
        connection.close()


def _stale_diff_review_acceptance(repository, identity, diff_review_attempt_id, lease):
    """Atomically stale the diff-review and provider acceptance layers together."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, None)
        row = connection.execute(
            "SELECT provider_attempt_id FROM diff_review_attempts WHERE diff_review_attempt_id = ? AND task_id = ?",
            (diff_review_attempt_id, identity.task_id),
        ).fetchone()
        if row is not None:
            _stale_diff_review_acceptance_connection(connection, identity, diff_review_attempt_id, row[0])
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _stale_diff_review_acceptance_connection(connection, identity, diff_review_attempt_id, provider_attempt_id):
    connection.execute("DELETE FROM accepted_provider_reviews WHERE attempt_id = ?", (provider_attempt_id,))
    connection.execute("UPDATE provider_attempts SET state = 'invalidated', accepted_review_identity = NULL WHERE attempt_id = ? AND state = 'accepted'", (provider_attempt_id,))
    connection.execute("UPDATE diff_review_attempts SET state = 'recorded', accepted_review_identity = NULL WHERE diff_review_attempt_id = ? AND task_id = ? AND state = 'accepted'", (diff_review_attempt_id, identity.task_id))


def _accepted_plan(repository, identity, plan_attempt_id, worker_thread_identity) -> str:
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        row = connection.execute("SELECT accepted.review_identity, attempts.worker_thread_identity FROM accepted_plan_reviews AS accepted JOIN worker_plan_attempts AS attempts ON attempts.plan_attempt_id = accepted.plan_attempt_id WHERE accepted.task_id = ? AND accepted.plan_attempt_id = ?", (identity.task_id, plan_attempt_id)).fetchone()
        if row is None or row[1] != worker_thread_identity:
            raise CandidateReviewError("implementation must resume the accepted Worker thread")
        return row[0]
    finally:
        connection.close()


def _repair_parent(repository, identity, review_id, candidate_sha, finding_ids, worker_thread_identity):
    """Bind a repair to the latest outstanding findings route for this task."""

    parent = _specified_repair_parent(review_id, candidate_sha, finding_ids)
    current = _current_repair_route(repository, identity)
    if parent.diff_review_attempt_id is None:
        if current is not None:
            raise CandidateReviewError("repair dispatch requires a routed diff-review parent")
        return parent
    if current != (parent.diff_review_attempt_id, parent.candidate_sha, worker_thread_identity, parent.finding_ids):
        raise CandidateReviewError("repair dispatch does not match the latest outstanding diff findings")
    return parent


def _specified_repair_parent(review_id, candidate_sha, finding_ids):
    """Normalize a caller's repair-parent tuple without consulting live routes."""

    values = (review_id, candidate_sha)
    if values == (None, None) and not finding_ids:
        return RepairParent(None, None, ())
    if not isinstance(review_id, str) or not isinstance(candidate_sha, str):
        raise CandidateReviewError("repair dispatch requires a complete parent identity")
    _token(review_id, "repair diff review identity")
    _commit(candidate_sha, "repair candidate")
    if not isinstance(finding_ids, tuple) or not finding_ids:
        raise CandidateReviewError("repair dispatch requires routed findings")
    for finding_id in finding_ids:
        _token(finding_id, "routed finding identity")
    return RepairParent(review_id, candidate_sha, finding_ids)


def _current_repair_route(repository, identity):
    """Return the one newest findings route that has not yet begun a repair."""

    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT routes.diff_review_attempt_id, attempts.candidate_sha, routes.worker_thread_identity, routes.finding_ids_json FROM diff_review_routes AS routes JOIN diff_review_attempts AS attempts ON attempts.diff_review_attempt_id = routes.diff_review_attempt_id WHERE routes.task_id = ? AND routes.consumed_by_implementation_attempt_id IS NULL ORDER BY attempts.created_at DESC, attempts.rowid DESC LIMIT 1",
            (identity.task_id,),
        ).fetchone()
        return None if row is None else (row[0], row[1], row[2], tuple(json.loads(row[3])))
    finally:
        connection.close()


def _consume_repair_parent(connection, identity, parent, worker_thread_identity, implementation_attempt_id, provider_attempt_id, external_turn_identity, claim_token):
    """Consume only the still-current route in the same transaction as dispatch."""

    row = connection.execute(
        "SELECT routes.diff_review_attempt_id, attempts.candidate_sha, routes.worker_thread_identity, routes.finding_ids_json, routes.claimed_by_implementation_attempt_id, routes.claimed_provider_attempt_id, routes.claimed_external_turn_identity, routes.claim_owner_token FROM diff_review_routes AS routes JOIN diff_review_attempts AS attempts ON attempts.diff_review_attempt_id = routes.diff_review_attempt_id WHERE routes.task_id = ? AND routes.consumed_by_implementation_attempt_id IS NULL ORDER BY attempts.created_at DESC, attempts.rowid DESC LIMIT 1",
        (identity.task_id,),
    ).fetchone()
    current = None if row is None else (row[0], row[1], row[2], tuple(json.loads(row[3])))
    expected = (parent.diff_review_attempt_id, parent.candidate_sha, worker_thread_identity, parent.finding_ids)
    if parent.diff_review_attempt_id is None:
        if current is not None:
            raise CandidateReviewError("repair dispatch requires a routed diff-review parent")
        return
    if current != expected or row[4:] != (implementation_attempt_id, provider_attempt_id, external_turn_identity, claim_token):
        raise CandidateReviewError("repair dispatch does not own the latest outstanding diff findings")
    updated = connection.execute(
        "UPDATE diff_review_routes SET consumed_by_implementation_attempt_id = ?, claimed_by_implementation_attempt_id = NULL, claimed_provider_attempt_id = NULL, claimed_external_turn_identity = NULL, claim_owner_token = NULL WHERE diff_review_attempt_id = ? AND consumed_by_implementation_attempt_id IS NULL AND claimed_by_implementation_attempt_id = ? AND claimed_provider_attempt_id = ? AND claimed_external_turn_identity = ? AND claim_owner_token = ?",
        (implementation_attempt_id, parent.diff_review_attempt_id, implementation_attempt_id, provider_attempt_id, external_turn_identity, claim_token),
    ).rowcount
    if updated != 1:
        raise CandidateReviewError("repair findings route was already consumed")


def _claim_repair_parent(repository, identity, parent, worker_thread_identity, implementation_attempt_id, provider_attempt_id, external_turn_identity, lease, now):
    """Reserve a new repair's current route before any provider turn is persisted."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        _require_matching_task(connection, identity, "implementing")
        row = connection.execute(
            "SELECT routes.diff_review_attempt_id, attempts.candidate_sha, routes.worker_thread_identity, routes.finding_ids_json, routes.claimed_by_implementation_attempt_id, routes.claimed_provider_attempt_id, routes.claimed_external_turn_identity, routes.claim_owner_token FROM diff_review_routes AS routes JOIN diff_review_attempts AS attempts ON attempts.diff_review_attempt_id = routes.diff_review_attempt_id WHERE routes.task_id = ? AND routes.consumed_by_implementation_attempt_id IS NULL ORDER BY attempts.created_at DESC, attempts.rowid DESC LIMIT 1",
            (identity.task_id,),
        ).fetchone()
        current = None if row is None else (row[0], row[1], row[2], tuple(json.loads(row[3])))
        expected = (parent.diff_review_attempt_id, parent.candidate_sha, worker_thread_identity, parent.finding_ids)
        if parent.diff_review_attempt_id is None:
            if current is not None:
                raise CandidateReviewError("repair dispatch requires a routed diff-review parent")
            connection.commit()
            return None
        if current != expected or row[4:] != (None, None, None, None):
            raise CandidateReviewError("repair dispatch does not match the latest outstanding diff findings")
        claim_token = uuid.uuid4().hex
        updated = connection.execute(
            "UPDATE diff_review_routes SET claimed_by_implementation_attempt_id = ?, claimed_provider_attempt_id = ?, claimed_external_turn_identity = ?, claim_owner_token = ? WHERE diff_review_attempt_id = ? AND consumed_by_implementation_attempt_id IS NULL AND claimed_by_implementation_attempt_id IS NULL AND claimed_provider_attempt_id IS NULL AND claimed_external_turn_identity IS NULL AND claim_owner_token IS NULL",
            (implementation_attempt_id, provider_attempt_id, external_turn_identity, claim_token, parent.diff_review_attempt_id),
        ).rowcount
        if updated != 1:
            raise CandidateReviewError("repair findings route is already claimed")
        connection.commit()
        return claim_token
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _release_repair_claim(repository, identity, parent, claim_token, lease, now):
    """Release a reservation when setup fails before its dispatch can commit."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        connection.execute(
            "UPDATE diff_review_routes SET claimed_by_implementation_attempt_id = NULL, claimed_provider_attempt_id = NULL, claimed_external_turn_identity = NULL, claim_owner_token = NULL WHERE diff_review_attempt_id = ? AND task_id = ? AND consumed_by_implementation_attempt_id IS NULL AND claim_owner_token = ?",
            (parent.diff_review_attempt_id, identity.task_id, claim_token),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _require_replayed_repair_parent(repository, identity, parent, worker_thread_identity, implementation_attempt_id):
    """Permit an exact retry only when the same dispatch consumed its parent."""

    if parent.diff_review_attempt_id is None:
        return
    connection = _open_writable_connection(repository)
    try:
        row = connection.execute(
            "SELECT attempts.candidate_sha, routes.worker_thread_identity, routes.finding_ids_json, routes.consumed_by_implementation_attempt_id FROM diff_review_routes AS routes JOIN diff_review_attempts AS attempts ON attempts.diff_review_attempt_id = routes.diff_review_attempt_id WHERE routes.diff_review_attempt_id = ? AND routes.task_id = ?",
            (parent.diff_review_attempt_id, identity.task_id),
        ).fetchone()
    finally:
        connection.close()
    expected = (parent.candidate_sha, worker_thread_identity, json.dumps(parent.finding_ids), implementation_attempt_id)
    if row != expected:
        raise CandidateReviewError("repair dispatch replay does not own its routed diff findings")


def _read_implementation_dispatch(repository, identity, implementation_attempt_id):
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        return _read_implementation_dispatch_connection(connection, identity, implementation_attempt_id)
    finally:
        connection.close()


def _read_implementation_dispatch_connection(connection, identity, implementation_attempt_id):
    row = connection.execute("SELECT provider_attempt_id, plan_attempt_id, accepted_plan_review_identity, worker_thread_identity, external_turn_identity, input_digest, repair_diff_review_id, repair_candidate_sha, routed_finding_ids_json FROM implementation_attempts WHERE implementation_attempt_id = ? AND task_id = ?", (implementation_attempt_id, identity.task_id)).fetchone()
    return None if row is None else ImplementationDispatch(implementation_attempt_id, *row[:6], row[6], row[7], tuple(json.loads(row[8])))


def _read_diff_dispatch(repository, identity, diff_review_attempt_id):
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        return _read_diff_dispatch_connection(connection, identity, diff_review_attempt_id)
    finally:
        connection.close()


def _read_diff_dispatch_connection(connection, identity, diff_review_attempt_id):
    row = connection.execute("SELECT implementation_attempt_id, provider_attempt_id, supervisor_session_identity, external_turn_identity, message_identity, base_sha, candidate_sha, verification_digest, input_digest, within_round_attempt, selected_profile_identity, review_round, review_mode, review_max_rounds, review_on_final_findings, review_policy_digest, review_complete_rounds, review_max_supervisor_attempts_per_round FROM diff_review_attempts WHERE diff_review_attempt_id = ? AND task_id = ?", (diff_review_attempt_id, identity.task_id)).fetchone()
    if row is None:
        return None
    if type(row[11]) is not int or row[11] < 1 or type(row[13]) is not int or type(row[16]) is not int or type(row[17]) is not int or row[11] > row[13] or type(row[15]) is not str or not _FINGERPRINT.fullmatch(row[15]):
        raise CandidateReviewError("persisted diff review profile mapping is invalid")
    try:
        projection = _ReviewPolicyProjection(row[11], ReviewMode(row[12]), row[16], row[13], row[17], FinalFindingsPolicy(row[14]), row[15])
    except (TypeError, ValueError) as error:
        raise CandidateReviewError("persisted review policy projection is invalid") from error
    binding_row = connection.execute(
        "SELECT schema_version, resolved_digest, worker_profile_identity, supervisor_profile_identities FROM runtime_configuration_bindings WHERE task_id = ?",
        (identity.task_id,),
    ).fetchone()
    try:
        runtime_binding = RuntimeBinding(*binding_row[:3], tuple(json.loads(binding_row[3]))) if binding_row is not None else None
    except (TypeError, ValueError, json.JSONDecodeError, RuntimeBindingError) as error:
        raise CandidateReviewError("persisted resolved configuration binding is invalid") from error
    _validate_diff_review_profile_mapping(runtime_binding, row[9], row[10])
    policy_row = connection.execute("SELECT configuration_digest, complete_rounds, max_rounds, max_supervisor_attempts_per_round, on_final_findings, policy_digest FROM runtime_review_policies WHERE task_id = ?", (identity.task_id,)).fetchone()
    expected_policy = (runtime_binding.resolved_digest, projection.complete_rounds, projection.max_rounds, projection.max_supervisor_attempts_per_round, projection.on_final_findings.value, projection.policy_digest)
    if policy_row != expected_policy or projection.max_supervisor_attempts_per_round != len(runtime_binding.supervisor_profile_identities):
        raise CandidateReviewError("persisted review policy binding has drifted")
    if type(row[7]) is not str or not _FINGERPRINT.fullmatch(row[7]):
        raise CandidateReviewError("persisted diff review verification digest is invalid")
    expected_input_digest = _diff_review_input_digest(identity, row[0], row[5], row[6], row[4], row[7], row[9], row[10], projection)
    if row[8] != expected_input_digest:
        raise CandidateReviewError("persisted diff review input digest has drifted")
    return DiffReviewDispatch(diff_review_attempt_id, *row[:11], projection)


def _require_current_candidate(repository, identity, seal, implementation_attempt_id=None):
    connection = _open_writable_connection(repository)
    try:
        _require_matching_task(connection, identity)
        sql = "SELECT attempts.implementation_attempt_id, candidates.base_sha, candidates.candidate_sha FROM implementation_candidates AS candidates JOIN implementation_attempts AS attempts ON attempts.implementation_attempt_id = candidates.implementation_attempt_id WHERE candidates.task_id = ? AND candidates.candidate_sha = ?"
        row = connection.execute(sql, (identity.task_id, seal.candidate_sha)).fetchone()
        if row is None or row[1:] != (seal.base_sha, seal.candidate_sha) or (implementation_attempt_id is not None and row[0] != implementation_attempt_id):
            raise CandidateReviewError("candidate seal is not the current implementation candidate")
    finally:
        connection.close()


def _verification_snapshot(repository, identity, candidate_sha):
    connection = _open_writable_connection(repository)
    try:
        rows = tuple(connection.execute("SELECT verification_id, verification_kind, outcome, evidence_fingerprint, justification FROM candidate_verifications WHERE task_id = ? AND candidate_sha = ? ORDER BY verification_id", (identity.task_id, candidate_sha)))
    finally:
        connection.close()
    kinds = {row[1] for row in rows}
    if kinds != {VerificationKind.TEST.value, VerificationKind.BUILD.value}:
        raise CandidateReviewError("candidate requires targeted test and build verification")
    return _digest({"task": identity.task_id, "candidate": candidate_sha, "verifications": rows})


def _accept_diff_pass(repository, identity, context, dispatch, lease, now):
    """Atomically couple a recorded PASS to provider-level acceptance evidence."""

    connection = _open_writable_connection(repository)
    try:
        connection.execute("BEGIN IMMEDIATE")
        _require_lease(connection, lease, identity, now)
        _require_matching_task(connection, identity, "diff-review")
        _require_exact_provider_context(connection, identity, dispatch.provider_attempt_id, context)
        row = connection.execute("SELECT state, accepted_review_identity, verification_digest FROM diff_review_attempts WHERE diff_review_attempt_id = ? AND task_id = ?", (dispatch.diff_review_attempt_id, identity.task_id)).fetchone()
        if row is None or row[2] != dispatch.verification_digest:
            raise CandidateReviewError("diff review acceptance does not match its dispatch")
        if _verification_snapshot_connection(connection, identity, dispatch.candidate_sha) != dispatch.verification_digest:
            raise CandidateReviewError("diff review verification evidence has changed")
        artifact = connection.execute("SELECT verdict, content_digest FROM diff_review_artifacts WHERE diff_review_attempt_id = ? AND task_id = ?", (dispatch.diff_review_attempt_id, identity.task_id)).fetchone()
        if artifact is None or artifact[0] != DiffReviewVerdict.PASS.value:
            raise CandidateReviewError("only a recorded PASS can be accepted")
        provider = connection.execute("SELECT provider_role, state, accepted_review_identity, output_pointer, completion_evidence_fingerprint, selected_profile_identity, input_fingerprint FROM provider_attempts WHERE attempt_id = ? AND task_id = ?", (dispatch.provider_attempt_id, identity.task_id)).fetchone()
        output = connection.execute("SELECT output_fingerprint FROM provider_completion_outputs WHERE attempt_id = ?", (dispatch.provider_attempt_id,)).fetchone()
        if provider is None or provider[0] != ProviderRole.SUPERVISOR.value or provider[4] is None or provider[5] != dispatch.selected_profile_identity or provider[6] != dispatch.input_digest:
            raise CandidateReviewError("accepted PASS provider attempt is incomplete")
        if provider[3] != f"diff-review:{dispatch.diff_review_attempt_id}" or output != (artifact[1],):
            _stale_diff_review_acceptance_connection(connection, identity, dispatch.diff_review_attempt_id, dispatch.provider_attempt_id)
            connection.commit()
            raise CandidateReviewError("accepted PASS provider output does not match the structured diff review")
        accepted_identity = dispatch.diff_review_attempt_id
        if provider[1] == AttemptState.COMPLETED.value:
            connection.execute("UPDATE provider_attempts SET accepted_review_identity = ?, state = ? WHERE attempt_id = ?", (accepted_identity, AttemptState.ACCEPTED.value, dispatch.provider_attempt_id))
            provider = (provider[0], AttemptState.ACCEPTED.value, accepted_identity, provider[3], provider[4], provider[5], provider[6])
        if provider[1] != AttemptState.ACCEPTED.value or provider[2] != accepted_identity:
            raise CandidateReviewError("accepted PASS provider attempt conflicts with committed state")
        accepted_provider = connection.execute("SELECT task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity, within_round_attempt FROM accepted_provider_reviews WHERE accepted_review_identity = ?", (accepted_identity,)).fetchone()
        expected_provider = (identity.task_id, dispatch.provider_attempt_id, provider[4], *context.runtime_binding.columns(), dispatch.selected_profile_identity, dispatch.within_round_attempt)
        if accepted_provider is None:
            connection.execute("INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities, selected_profile_identity, within_round_attempt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (accepted_identity, *expected_provider))
        elif accepted_provider != expected_provider:
            raise CandidateReviewError("accepted provider review conflicts with committed state")
        if row[0] in ("recorded", "accepted") and row[1] in (None, accepted_identity):
            connection.execute("UPDATE diff_review_attempts SET state = 'accepted', accepted_review_identity = ? WHERE diff_review_attempt_id = ?", (accepted_identity, dispatch.diff_review_attempt_id))
        else:
            raise CandidateReviewError("diff review acceptance conflicts with committed state")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _require_diff_review_context(repository, identity, context, seal, implementation_attempt_id):
    """Require the sealed recovery projection, excluding per-attempt health evidence."""

    if not isinstance(context, RecoveryContext):
        raise CandidateReviewError("diff review recovery context is invalid")
    expected = RecoveryContext.for_task(
        identity,
        candidate_sha=seal.candidate_sha,
        policy_fingerprint=context.policy_fingerprint,
        deployment_fingerprint=context.deployment_fingerprint,
        runtime_binding=context.runtime_binding,
    )
    if _sealed_recovery_context_projection(context) != _sealed_recovery_context_projection(expected):
        raise CandidateReviewError("diff review recovery context does not match the sealed candidate")
    try:
        connection = sqlite3.connect(f"{database_path(repository).as_uri()}?mode=ro", uri=True)
        try:
            row = connection.execute(
                "SELECT contexts.task_id, contexts.repository_fingerprint, contexts.worktree_fingerprint, contexts.branch_fingerprint, contexts.base_fingerprint, contexts.policy_fingerprint, contexts.deployment_fingerprint, contexts.configuration_schema_version, contexts.configuration_digest, contexts.worker_profile_identity, contexts.supervisor_profile_identities FROM implementation_attempts AS implementations JOIN provider_attempt_contexts AS contexts ON contexts.attempt_id = implementations.provider_attempt_id WHERE implementations.implementation_attempt_id = ? AND implementations.task_id = ?",
                (implementation_attempt_id, identity.task_id),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise CandidateReviewError("diff review recovery context is unavailable") from error
    if row != _implementation_context_projection(context):
        raise CandidateReviewError("diff review recovery context does not match the sealed candidate")


def _sealed_recovery_context_projection(context):
    """The immutable candidate-review identity; receipts authorize only prepare_attempt."""

    return (
        context.task_id,
        context.repository_fingerprint,
        context.worktree_fingerprint,
        context.branch_fingerprint,
        context.base_fingerprint,
        context.candidate_fingerprint,
        context.candidate_sha,
    )


def _implementation_context_projection(context):
    """Immutable predecessor context, excluding the candidate and health receipt."""

    return (
        context.task_id,
        context.repository_fingerprint,
        context.worktree_fingerprint,
        context.branch_fingerprint,
        context.base_fingerprint,
        context.policy_fingerprint,
        context.deployment_fingerprint,
        *context.runtime_binding.columns(),
    )


def _require_exact_provider_context(connection, identity, attempt_id, context):
    expected = (
        identity.task_id, context.repository_fingerprint, context.worktree_fingerprint,
        context.branch_fingerprint, context.base_fingerprint, context.candidate_fingerprint,
        context.policy_fingerprint, context.deployment_fingerprint,
        *context.runtime_binding.columns(),
    )
    row = connection.execute("SELECT task_id, repository_fingerprint, worktree_fingerprint, branch_fingerprint, base_fingerprint, candidate_fingerprint, policy_fingerprint, deployment_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities FROM provider_attempt_contexts WHERE attempt_id = ?", (attempt_id,)).fetchone()
    if row != expected:
        raise CandidateReviewError("diff review recovery context has drifted")


def _verification_snapshot_connection(connection, identity, candidate_sha):
    rows = tuple(connection.execute("SELECT verification_id, verification_kind, outcome, evidence_fingerprint, justification FROM candidate_verifications WHERE task_id = ? AND candidate_sha = ? ORDER BY verification_id", (identity.task_id, candidate_sha)))
    kinds = {row[1] for row in rows}
    if kinds != {VerificationKind.TEST.value, VerificationKind.BUILD.value}:
        raise CandidateReviewError("candidate requires targeted test and build verification")
    return _digest({"task": identity.task_id, "candidate": candidate_sha, "verifications": rows})


def _require_candidate_binding(identity, binding, seal):
    """Reject aliases before any Git, provider, or durable candidate operation."""

    if not isinstance(binding, WorktreeBinding):
        raise CandidateReviewError("candidate worktree binding is invalid")
    if (
        binding.task_id != identity.task_id
        or binding.repository_id != identity.repository_id
        or binding.branch != identity.branch
        or binding.base_sha != identity.base_sha
        or binding.worktree.resolve(strict=False) != Path(identity.worktree).resolve(strict=False)
    ):
        raise CandidateReviewError("candidate worktree binding does not match the task")
    if seal is not None and (
        not isinstance(seal, CandidateSeal)
        or seal.task_id != identity.task_id
        or seal.base_sha != identity.base_sha
        or seal.state_identity != binding.state_identity
    ):
        raise CandidateReviewError("candidate seal does not match the task binding")


def _session_is_plan_review(repository, identity, session):
    connection = _open_writable_connection(repository)
    try:
        return connection.execute("SELECT 1 FROM plan_review_attempts WHERE task_id = ? AND supervisor_session_identity = ?", (identity.task_id, session)).fetchone() is not None
    finally:
        connection.close()


def _require_lease(connection, lease, identity, now):
    from .git_identity import _require_current_lease
    _require_current_lease(connection, lease, identity.repository_id, _clock(now))


def _items(value: Iterable[str], name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise CandidateReviewError(f"{name} must be a sequence")
    try:
        values = tuple(" ".join(item.split()) if isinstance(item, str) else item for item in value)
    except TypeError as error:
        raise CandidateReviewError(f"{name} must be a sequence") from error
    if (not allow_empty and not values) or any(not isinstance(item, str) or not item for item in values):
        raise CandidateReviewError(f"{name} contains an invalid item")
    return tuple(sorted(set(values)))


def _token(value, name):
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise CandidateReviewError(f"{name} is invalid")


def _fingerprint(value, name):
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise CandidateReviewError(f"{name} is invalid")


def _commit(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise CandidateReviewError(f"{name} is invalid")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _clock(now):
    return int(time.time()) if now is None else now
