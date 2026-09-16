"""Fresh, deny-all Codex adapter for one dependency-review attempt.

The model-facing request contains only the normalized, digest-only subset from
``dependency_review``.  This adapter owns no repository, GitHub, scheduler,
or credential capability and deliberately has no session-resume API.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .configuration import ProviderProfile, RepositoryIdentity
from .dependency_review import (
    AffectedSubset, DependencyProposal, DependencyReviewBinding,
    DependencyReviewError, DependencyReviewStore, SourceOwnedRelation,
)
from .provider_health import CodexAdapterError, CodexFailure, ProviderHealthAuditIdentity
from .failure_recovery import (
    DurableRecoveryRouteAuthorization, EvidenceSource, FailureBinding,
    FailureClass, FailureRole, FailureRecord, RecoveryAction,
    abandon_durable_recovery_route_reservation,
    begin_durable_recovery_route_reservation,
    commit_durable_recovery_route_reservation,
    classify_native_failure,
    issue_durable_recovery_route_authorization, parse_failure_record,
    read_durable_failure, read_durable_recovery_route_authorization,
    record_durable_failure,
)
from .state import TaskIdentity, _open_writable_connection
from .role_capability_policy import RoleCapabilityError, RoleExecutionSeam, SealedRoleExecution, TrustedExecutionHostInputs, TrustedRoleEffectReservation, recovery_reservation_digest, recover_role_effect_reservation, require_external_production_activation, reserve_role_effect, trusted_provider_launch_context


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class DependencyReviewDispatchError(ValueError):
    """A dependency-review dispatch violates the narrow role contract."""


class DependencyReviewResultKind(StrEnum):
    ACCEPTED = "accepted"
    INVALID = "invalid"
    BLOCKED = "blocked"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class DependencyReviewRequest:
    """One immutable request for a fresh behaviorally tool-silent session."""

    attempt_id: str
    input_material: Mapping[str, object]
    input_digest: str
    profile_identity: str

    def __post_init__(self) -> None:
        if (
            not _TOKEN.fullmatch(self.attempt_id)
            or type(self.input_material) is not dict
            or not _DIGEST.fullmatch(self.input_digest)
            or not _DIGEST.fullmatch(self.profile_identity)
            or self.input_digest != _digest(self.input_material)
        ):
            raise DependencyReviewDispatchError("dependency review request is invalid")


@dataclass(frozen=True)
class NativeDependencyReviewResponse:
    kind: DependencyReviewResultKind
    proposal: Mapping[str, object] | None = None
    failure: CodexFailure | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not DependencyReviewResultKind
            or (self.proposal is not None and type(self.proposal) is not dict)
            or (self.failure is not None and type(self.failure) is not CodexFailure)
            or (self.kind is DependencyReviewResultKind.ACCEPTED and (self.proposal is None or self.failure is not None))
            or (self.kind is DependencyReviewResultKind.BLOCKED and (self.proposal is not None or self.failure is None))
            or (self.kind in {DependencyReviewResultKind.INVALID, DependencyReviewResultKind.AMBIGUOUS} and (self.proposal is not None or self.failure is not None))
            or (self.reason_code is not None and (self.kind is not DependencyReviewResultKind.INVALID or self.reason_code != "tool-event-observed"))
        ):
            raise DependencyReviewDispatchError("dependency review response is invalid")


class NativeDependencyReviewTurn(Protocol):
    def identity(self) -> str: ...
    def abort(self) -> None: ...
    def read_response(self) -> NativeDependencyReviewResponse: ...


class NativeDependencyReviewSession(Protocol):
    def identity(self) -> str: ...
    def close(self) -> None: ...
    def start_turn(self, request: DependencyReviewRequest) -> NativeDependencyReviewTurn: ...


class NativeCodexDependencyReviewBackend(Protocol):
    def open_fresh_session(self, profile: ProviderProfile) -> NativeDependencyReviewSession: ...


@dataclass(frozen=True)
class DependencyReviewDispatchResult:
    kind: DependencyReviewResultKind
    session_identity: str | None
    turn_identity: str | None
    proposal: DependencyProposal | None
    output_digest: str
    reason_code: str
    failure: CodexFailure | None = None

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not DependencyReviewResultKind
            or (self.session_identity is not None and not _TOKEN.fullmatch(self.session_identity))
            or (self.turn_identity is not None and not _TOKEN.fullmatch(self.turn_identity))
            or (self.proposal is not None and type(self.proposal) is not DependencyProposal)
            or not _DIGEST.fullmatch(self.output_digest)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.reason_code)
            or (self.kind is DependencyReviewResultKind.ACCEPTED) != (self.proposal is not None)
            or ((self.kind is DependencyReviewResultKind.BLOCKED) != (type(self.failure) is CodexFailure))
        ):
            raise DependencyReviewDispatchError("dependency review result is invalid")


class CodexDependencyReviewAdapter:
    """Open exactly one fresh, behaviorally tool-silent configured session."""

    def __init__(self, backend: NativeCodexDependencyReviewBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity) -> None:
        if (
            not callable(getattr(backend, "open_fresh_session", None))
            or type(profile) is not ProviderProfile
            or type(audit) is not ProviderHealthAuditIdentity
            or audit.profile != profile
            or not audit.audit.supports(profile)
        ):
            raise DependencyReviewDispatchError("dependency review adapter is not bound to its qualified profile")
        self._backend, self._profile, self._audit = backend, profile, audit

    @property
    def profile_identity(self) -> str:
        return self._audit.profile_identity

    def effect_material(self, request: DependencyReviewRequest) -> tuple[dict[str, object], dict[str, object]]:
        """Return the exact request and adapter facts reserved by the host."""

        if type(request) is not DependencyReviewRequest:
            raise DependencyReviewDispatchError("dependency review dispatch is invalid")
        return (
            {"input_digest": request.input_digest, "input_material": request.input_material},
            {"adapter_profile": self.profile_identity, "audit": self._audit.profile_identity},
        )

    def dispatch(
        self, request: DependencyReviewRequest, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None], advisory_execution: SealedRoleExecution, effect_reservation: TrustedRoleEffectReservation,
    ) -> DependencyReviewDispatchResult:
        if type(request) is not DependencyReviewRequest or request.profile_identity != self.profile_identity or not callable(checkpoint_session) or not callable(checkpoint_turn):
            raise DependencyReviewDispatchError("dependency review dispatch is invalid")
        if (type(advisory_execution) is not SealedRoleExecution
                or advisory_execution.seam is not RoleExecutionSeam.DEPENDENCY_REVIEW
                or type(effect_reservation) is not TrustedRoleEffectReservation):
            raise DependencyReviewDispatchError("dependency review advisory admission is unavailable")
        try:
            request_material, preflight_material = self.effect_material(request)

            def admit() -> dict[str, object]:
                return effect_reservation.require_before_effect(
                    advisory_execution, profile=self._profile,
                    request_or_attempt_identity=request.attempt_id,
                    request_material=request_material,
                    preflight_material=preflight_material,
                )

            admit()
        except RoleCapabilityError as error:
            raise DependencyReviewDispatchError("dependency review advisory admission is denied") from error
        session = None
        turn = None
        session_id = None
        turn_id = None
        try:
            admit()
            session = self._backend.open_fresh_session(self._profile)
            session_id = _identity(session, "session")
            admit()
            checkpoint_session(session_id)
            admit()
            turn = session.start_turn(request)
            turn_id = _identity(turn, "turn")
            admit()
            checkpoint_turn(session_id, turn_id)
            admit()
            response = turn.read_response()
        except CodexAdapterError as error:
            _abort(turn)
            if session_id is not None and turn_id is not None:
                return DependencyReviewDispatchResult(
                    DependencyReviewResultKind.BLOCKED, session_id, turn_id, None,
                    _digest({"attempt_id": request.attempt_id, "status": "sdk-turn-failed", "failure": error.failure.value}),
                    "sdk-turn-failed", error.failure,
                )
            return DependencyReviewDispatchResult(DependencyReviewResultKind.AMBIGUOUS, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "session": session_id, "turn": turn_id, "status": "ambiguous"}), "uncertain-provider-turn")
        except Exception:
            _abort(turn)
            return DependencyReviewDispatchResult(DependencyReviewResultKind.AMBIGUOUS, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "session": session_id, "turn": turn_id, "status": "ambiguous"}), "uncertain-provider-turn")
        finally:
            _close(session)
        if type(response) is not NativeDependencyReviewResponse:
            return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "status": "malformed-response"}), "malformed-response")
        if response.kind is DependencyReviewResultKind.ACCEPTED:
            try:
                proposal = DependencyProposal.parse(response.proposal)
                if proposal.attempt_id != request.attempt_id:
                    raise DependencyReviewError
            except (DependencyReviewError, TypeError, ValueError):
                return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, session_id, turn_id, None, _digest(response.proposal), "malformed-response")
            return DependencyReviewDispatchResult(response.kind, session_id, turn_id, proposal, proposal.proposal_digest, "schema-valid")
        reason = response.reason_code or (
            "provider-blocked" if response.kind is DependencyReviewResultKind.BLOCKED
            else "uncertain-provider-turn" if response.kind is DependencyReviewResultKind.AMBIGUOUS
            else "malformed-response"
        )
        return DependencyReviewDispatchResult(response.kind, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "status": response.kind.value, "failure": None if response.failure is None else response.failure.value, "reason_code": reason}), reason, response.failure)


class DependencyReviewService:
    """Persist one new attempt before dispatch and retain every terminal outcome."""

    def run(
        self, repository: RepositoryIdentity, subset: AffectedSubset, *, attempt_id: str,
        binding: DependencyReviewBinding, adapter: CodexDependencyReviewAdapter,
        checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None], advisory_execution: SealedRoleExecution,
        execution_host: TrustedExecutionHostInputs, budget_ledger_path: Path,
        source_owned_relations: tuple[SourceOwnedRelation, ...] = (), supersedes_attempt_id: str | None = None,
        task_identity: TaskIdentity | None = None,
    ) -> DependencyReviewDispatchResult:
        if task_identity is not None and type(task_identity) is not TaskIdentity:
            raise DependencyReviewDispatchError("dependency review task identity is unavailable")
        if type(adapter) is not CodexDependencyReviewAdapter or adapter.profile_identity != binding.profile_identity:
            raise DependencyReviewDispatchError("dependency review adapter profile has drifted")
        if type(advisory_execution) is not SealedRoleExecution or advisory_execution.seam is not RoleExecutionSeam.DEPENDENCY_REVIEW:
            raise DependencyReviewDispatchError("dependency review advisory admission is unavailable")
        store = DependencyReviewStore()
        input_material = store.model_input(
            subset, attempt_id=attempt_id,
            profile_identity=binding.profile_identity,
            source_owned_relations=source_owned_relations,
        )
        request = DependencyReviewRequest(
            attempt_id, input_material, _digest(input_material), binding.profile_identity,
        )
        if task_identity is not None:
            store.require_current_authority(repository, task_identity, subset, binding)
        # A previously checkpointed session is already ambiguous.  Detect it
        # before deriving a recovery route or reserving a successor budget so
        # restart reconciliation cannot create any later durable effect.
        recovery_digest = _digest({"attempt_id": attempt_id, "status": "recovered-in-flight-dispatch"})
        connection = _open_writable_connection(repository)
        try:
            existing_attempt = connection.execute(
                "SELECT state FROM dependency_review_attempts WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
        finally:
            connection.close()
        if existing_attempt is not None and store.recover_dispatch_claim(
            repository, attempt_id=attempt_id, output_digest=recovery_digest,
            subset=subset, binding=binding, input_digest=request.input_digest,
            supersedes_attempt_id=supersedes_attempt_id, task_identity=task_identity,
        ):
            return DependencyReviewDispatchResult(
                DependencyReviewResultKind.AMBIGUOUS, None, None, None,
                recovery_digest, "uncertain-provider-turn",
            )
        recovery_route = self._successor_recovery_route(
            repository, task_identity, binding, request, supersedes_attempt_id,
            advisory_execution, execution_host, adapter,
        )
        request_material, preflight_material = adapter.effect_material(request)
        route_reserved = False
        if recovery_route is not None:
            route, coordinate, remaining, reservation_digest = self._recovery_route_material(
                request, binding, supersedes_attempt_id, advisory_execution,
                execution_host, adapter,
            )
            try:
                # ``prepared`` is the successor admission.  On restart keep
                # its exact reservation and only complete the route commit;
                # never release/re-reserve a durable successor merely because
                # the process stopped between preparation and commit.
                existing_prepared = existing_attempt == ("prepared",)
                if not existing_prepared:
                    route_reserved = begin_durable_recovery_route_reservation(
                        repository, task_identity, recovery_route,
                        reservation_digest=reservation_digest,
                        target_role=FailureRole.DEPENDENCY_REVIEW,
                        target_profile_digest=binding.profile_identity,
                        target_route_digest=route, coordinate_digest=coordinate,
                        remaining_budget_digest=remaining,
                    )
                if not route_reserved and not existing_prepared:
                    try:
                        recovered = recover_role_effect_reservation(
                            advisory_execution, host_inputs=execution_host,
                            ledger_path=budget_ledger_path,
                            profile=advisory_execution.execution_binding.provider_profile,
                            request_or_attempt_identity=attempt_id,
                            request_material=request_material,
                            preflight_material=preflight_material,
                        )
                        recovered.reject_recovery_route()
                    except RoleCapabilityError:
                        pass
                    abandon_durable_recovery_route_reservation(
                        repository, task_identity, recovery_route,
                        reservation_digest=reservation_digest,
                    )
                    route_reserved = begin_durable_recovery_route_reservation(
                        repository, task_identity, recovery_route,
                        reservation_digest=reservation_digest,
                        target_role=FailureRole.DEPENDENCY_REVIEW,
                        target_profile_digest=binding.profile_identity,
                        target_route_digest=route, coordinate_digest=coordinate,
                        remaining_budget_digest=remaining,
                    )
            except Exception as error:
                raise DependencyReviewDispatchError("dependency review transient recovery route is unavailable") from error
        reservation = None
        try:
            reservation = (
                recover_role_effect_reservation(
                    advisory_execution, host_inputs=execution_host,
                    ledger_path=budget_ledger_path,
                    profile=advisory_execution.execution_binding.provider_profile,
                    request_or_attempt_identity=attempt_id,
                    request_material=request_material,
                    preflight_material=preflight_material,
                )
                if recovery_route is not None and existing_attempt == ("prepared",)
                else reserve_role_effect(
                    advisory_execution, host_inputs=execution_host,
                    ledger_path=budget_ledger_path,
                    profile=advisory_execution.execution_binding.provider_profile,
                    request_or_attempt_identity=attempt_id,
                    request_material=request_material,
                    preflight_material=preflight_material,
                )
            )
            if recovery_route is not None:
                if reservation.recovery_digest != reservation_digest:
                    raise DependencyReviewDispatchError("dependency review recovery reservation has drifted")
                try:
                    reservation.require_recovery_route(advisory_execution)
                except RoleCapabilityError:
                    raise DependencyReviewDispatchError("dependency review recovery reservation has drifted") from None

            def admit() -> dict[str, object]:
                return reservation.require_before_effect(
                    advisory_execution,
                    profile=advisory_execution.execution_binding.provider_profile,
                    request_or_attempt_identity=attempt_id,
                    request_material=request_material,
                    preflight_material=preflight_material,
                )
        except (RoleCapabilityError, DependencyReviewDispatchError) as error:
            if recovery_route is not None and route_reserved:
                try:
                    if reservation is not None:
                        reservation.reject_recovery_route()
                    abandon_durable_recovery_route_reservation(
                        repository, task_identity, recovery_route,
                        reservation_digest=reservation_digest,
                    )
                except Exception:
                    pass
            raise DependencyReviewDispatchError("dependency review advisory admission is denied") from error
        # Do not materialize a successor lineage row before its exact recovery
        # route and sealed budget reservation agree.  In particular, a route
        # replay or tamper rejection must leave no prepared successor that a
        # later restart could mistake for an admitted provider turn.
        try:
            attempt = store.start_attempt(
                repository, subset, attempt_id=attempt_id, binding=binding,
                source_owned_relations=source_owned_relations,
                supersedes_attempt_id=supersedes_attempt_id,
            )
        except Exception:
            if recovery_route is not None and route_reserved:
                try:
                    reservation.reject_recovery_route()
                    abandon_durable_recovery_route_reservation(
                        repository, task_identity, recovery_route,
                        reservation_digest=reservation_digest,
                    )
                except Exception:
                    pass
            raise
        if attempt.input_digest != request.input_digest:
            raise DependencyReviewDispatchError("dependency review prepared request has drifted")
        if recovery_route is not None:
            try:
                commit_durable_recovery_route_reservation(
                    repository, task_identity, recovery_route,
                    reservation_digest=reservation_digest,
                )
            except Exception as error:
                raise DependencyReviewDispatchError("dependency review transient recovery route is unavailable") from error
        recovery_digest = _digest({"attempt_id": attempt.attempt_id, "status": "recovered-in-flight-dispatch"})
        if store.recover_dispatch_claim(repository, attempt_id=attempt.attempt_id, output_digest=recovery_digest,
                                        subset=subset, binding=binding, input_digest=request.input_digest,
                                        supersedes_attempt_id=supersedes_attempt_id, task_identity=task_identity):
            return DependencyReviewDispatchResult(DependencyReviewResultKind.AMBIGUOUS, None, None, None, recovery_digest, "uncertain-provider-turn")
        admit()
        # This claim deliberately precedes ``open_fresh_session``.  There is
        # no provider supplied session identity at this point, so a restart
        # treats the one-shot pre-dispatch marker as ambiguous rather than
        # opening a duplicate native session.
        store.claim_pre_dispatch(
            repository, attempt_id=attempt.attempt_id, task_identity=task_identity,
            binding=binding if task_identity is not None else None,
        )

        def claimed_session(session_identity: str) -> None:
            admit()
            store.claim_session(
                repository, attempt_id=attempt.attempt_id, session_identity=session_identity,
                task_identity=task_identity, binding=binding if task_identity is not None else None,
            )
            admit()
            checkpoint_session(session_identity)

        def claimed_turn(session_identity: str, turn_identity: str) -> None:
            admit()
            store.claim_turn(repository, attempt_id=attempt.attempt_id, session_identity=session_identity, turn_identity=turn_identity)
            admit()
            checkpoint_turn(session_identity, turn_identity)

        result = adapter.dispatch(
            request, checkpoint_session=claimed_session, checkpoint_turn=claimed_turn,
            advisory_execution=advisory_execution, effect_reservation=reservation,
        )
        if result.kind is DependencyReviewResultKind.ACCEPTED:
            assert result.proposal is not None
            try:
                admit()
                store.accept_proposal(repository, result.proposal, binding=binding)
            except DependencyReviewError:
                admit()
                store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code="proposal-rejected")
                return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, result.session_identity, result.turn_identity, None, result.output_digest, "proposal-rejected")
        elif result.kind is DependencyReviewResultKind.BLOCKED:
            if task_identity is not None and (result.session_identity is None or result.failure is None):
                raise DependencyReviewDispatchError("dependency review typed terminal failure is incomplete")
            if task_identity is not None:
                assert result.session_identity is not None and result.failure is not None
                failure_binding = FailureBinding(
                    binding.candidate_sha, binding.policy_digest, binding.configuration_digest,
                    "dependency-review:" + task_identity.task_id, FailureRole.DEPENDENCY_REVIEW,
                    binding.profile_identity, result.session_identity, attempt.attempt_id,
                )
                record_durable_failure(
                    repository, task_identity,
                    classify_native_failure(FailureRole.DEPENDENCY_REVIEW, failure_binding, result.failure),
                )
            admit()
            store.record_blocked(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code=result.reason_code, owner_route="prebound-transient-route")
        elif result.kind is DependencyReviewResultKind.AMBIGUOUS:
            admit()
            # UNKNOWN is a durable reconciliation decision, never an ordinary
            # blocked predecessor that a successor can consume as a retry.
            store.record_blocked(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code=result.reason_code, owner_route="reconcile-required")
        else:
            admit()
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code=result.reason_code)
        return result

    @staticmethod
    def _recovery_route_material(
        request: DependencyReviewRequest, binding: DependencyReviewBinding,
        predecessor_attempt_id: str | None, execution: SealedRoleExecution,
        execution_host: TrustedExecutionHostInputs, adapter: CodexDependencyReviewAdapter,
    ) -> tuple[str, str, str, str]:
        if predecessor_attempt_id is None:
            raise DependencyReviewDispatchError("dependency review recovery predecessor is unavailable")
        route = _digest({
            "schema": "roundwright-dependency-review-recovery-target/v1",
            "attempt_id": request.attempt_id, "input_digest": request.input_digest,
            "profile_identity": binding.profile_identity,
        })
        coordinate = _digest({
            "schema": "roundwright-dependency-review-recovery-coordinate/v1",
            "predecessor_attempt_id": predecessor_attempt_id,
            "successor_attempt_id": request.attempt_id,
        })
        remaining = _digest({
            "schema": "roundwright-dependency-review-recovery-budget/v1",
            "execution_binding": execution.execution_binding.digest,
            "profile_identity": binding.profile_identity,
        })
        request_material, preflight_material = adapter.effect_material(request)
        reservation = recovery_reservation_digest(
            execution, host_inputs=execution_host,
            profile=execution.execution_binding.provider_profile,
            request_or_attempt_identity=request.attempt_id,
            request_material=request_material, preflight_material=preflight_material,
        )
        return route, coordinate, remaining, reservation

    def _successor_recovery_route(
        self, repository: RepositoryIdentity, task_identity: TaskIdentity | None,
        binding: DependencyReviewBinding, request: DependencyReviewRequest,
        predecessor_attempt_id: str | None, execution: SealedRoleExecution,
        execution_host: TrustedExecutionHostInputs, adapter: CodexDependencyReviewAdapter,
    ) -> DurableRecoveryRouteAuthorization | None:
        """Return the one permitted transient successor route, if any.

        A persisted UNKNOWN is deliberately not recoverable here.  It needs a
        separately completed reconciliation and cannot spend a successor
        budget, construct a session, or reach a provider merely by naming it
        as a blocked predecessor.
        """

        if predecessor_attempt_id is None:
            return None
        if task_identity is None:
            raise DependencyReviewDispatchError("dependency review recovery authority is unavailable")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN")
            DependencyReviewStore._verify_task_lineage(connection, task_identity.task_id)
            DependencyReviewStore._read_attempt(connection, predecessor_attempt_id)
            row = connection.execute(
                "SELECT attempts.state, outcomes.reason_code, outcomes.owner_route, "
                "admissions.candidate_sha, admissions.policy_digest, admissions.configuration_digest, "
                "admissions.authority_scope, admissions.profile_identity, admissions.session_identity "
                "FROM dependency_review_attempts AS attempts "
                "LEFT JOIN dependency_review_validation_outcomes AS outcomes "
                "ON outcomes.attempt_id = attempts.attempt_id "
                "LEFT JOIN dependency_review_failure_admissions AS admissions "
                "ON admissions.attempt_id = attempts.attempt_id "
                "WHERE attempts.attempt_id = ? AND attempts.task_id = ?",
                (predecessor_attempt_id, task_identity.task_id),
            ).fetchone()
            connection.commit()
        except Exception:
            connection.rollback()
            raise DependencyReviewDispatchError("dependency review recovery predecessor is unavailable") from None
        finally:
            connection.close()
        # Naming a predecessor is itself a recovery request.  It must never
        # quietly degrade into an ordinary fresh attempt: an ACCEPTED or
        # INVALID predecessor has no transient route to spend, and a missing
        # record is indistinguishable from a changed lineage.
        if row is None or row[0] != "blocked":
            raise DependencyReviewDispatchError("dependency review supersession is not recovery-eligible")
        if row[1] == "uncertain-provider-turn" or row[2] == "reconcile-required":
            raise DependencyReviewDispatchError("dependency review reconciliation is incomplete")
        if row[1] != "sdk-turn-failed" or row[2] != "prebound-transient-route" or any(type(value) is not str for value in row[3:]):
            raise DependencyReviewDispatchError("dependency review blocked predecessor is not retryable")
        source_binding = FailureBinding(
            row[3], row[4], row[5], row[6], FailureRole.DEPENDENCY_REVIEW,
            row[7], row[8], predecessor_attempt_id,
        )
        # Locate only a canonical exact source decision; the durable readback
        # below revalidates the still-current admission and candidate authority.
        connection = _open_writable_connection(repository)
        try:
            records = connection.execute(
                "SELECT record_digest, record_json FROM failure_recovery_records WHERE task_id = ?",
                (task_identity.task_id,),
            ).fetchall()
        finally:
            connection.close()
        source_digests = []
        for digest, encoded in records:
            try:
                record = parse_failure_record(json.loads(encoded))
            except Exception:
                continue
            if record.digest == digest and record.binding == source_binding:
                source_digests.append(digest)
        if len(source_digests) != 1:
            raise DependencyReviewDispatchError("dependency review transient recovery source is unavailable")
        source_digest = source_digests[0]
        try:
            source = read_durable_failure(repository, task_identity, source_digest)
            if (source.binding != source_binding or source.failure is not FailureClass.TRANSIENT_SERVICE
                    or source.evidence is not EvidenceSource.VERIFIED_SERVICE
                    or source.action is not RecoveryAction.PREBOUND_FALLBACK or not source.retryable):
                raise DependencyReviewDispatchError("dependency review transient recovery source is not eligible")
            route, coordinate, remaining, _reservation = self._recovery_route_material(
                request, binding, predecessor_attempt_id, execution, execution_host, adapter,
            )
            issued = issue_durable_recovery_route_authorization(
                repository, task_identity, record_digest=source_digest,
                binding=source_binding, target_role=FailureRole.DEPENDENCY_REVIEW,
                target_profile_digest=binding.profile_identity, target_route_digest=route,
                coordinate_digest=coordinate, remaining_budget_digest=remaining,
            )
            return read_durable_recovery_route_authorization(
                repository, task_identity, issued.route_digest,
            )
        except DependencyReviewDispatchError:
            raise
        except Exception:
            raise DependencyReviewDispatchError("dependency review transient recovery route is unavailable") from None


@dataclass(frozen=True)
class DependencyReviewHostInputs:
    """Trusted product inputs for one hosted V2 dependency-review attempt.

    The Harness receives this value only through the product entrypoint.  It
    contains no credential, repository mutation, or tool capability; the
    injected adapter can open exactly one fresh behaviorally tool-silent model
    session under read-only sandbox and deny-all approval controls.
    """

    repository: RepositoryIdentity
    task_identity: TaskIdentity | None
    subset: AffectedSubset
    binding: DependencyReviewBinding
    adapter: CodexDependencyReviewAdapter
    checkpoint_session: Callable[[str], None]
    checkpoint_turn: Callable[[str, str], None]
    advisory_execution: SealedRoleExecution
    execution_host: TrustedExecutionHostInputs
    budget_ledger_path: Path
    source_owned_relations: tuple[SourceOwnedRelation, ...] = ()
    supersedes_attempt_id: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.repository) is not RepositoryIdentity
            or (self.task_identity is not None and type(self.task_identity) is not TaskIdentity)
            or type(self.subset) is not AffectedSubset
            or type(self.binding) is not DependencyReviewBinding
            or type(self.adapter) is not CodexDependencyReviewAdapter
            or not callable(self.checkpoint_session)
            or not callable(self.checkpoint_turn)
            or type(self.advisory_execution) is not SealedRoleExecution
            or self.advisory_execution.seam is not RoleExecutionSeam.DEPENDENCY_REVIEW
            or type(self.execution_host) is not TrustedExecutionHostInputs
            or not isinstance(self.budget_ledger_path, Path)
            or type(self.source_owned_relations) is not tuple
            or any(type(item) is not SourceOwnedRelation for item in self.source_owned_relations)
            or (self.supersedes_attempt_id is not None and not _TOKEN.fullmatch(self.supersedes_attempt_id))
            or self.adapter.profile_identity != self.binding.profile_identity
            or (self.task_identity is not None and self.task_identity.task_id != self.subset.task_id)
        ):
            raise DependencyReviewDispatchError("dependency review host inputs are invalid")
        self.binding.require_subset(self.subset)


def prepare_dependency_review_host(
    repository: RepositoryIdentity, task_identity: TaskIdentity, subset: AffectedSubset, binding: DependencyReviewBinding,
    audit: ProviderHealthAuditIdentity, *, backend: NativeCodexDependencyReviewBackend | None = None,
    advisory_execution: SealedRoleExecution, execution_host: TrustedExecutionHostInputs,
    budget_ledger_path: Path,
    source_owned_relations: tuple[SourceOwnedRelation, ...] = (),
    supersedes_attempt_id: str | None = None,
) -> DependencyReviewHostInputs:
    """Construct the closed product host from exact durable identities only."""

    # No local flag or supplied backend can turn this product entrypoint into
    # a production authority.  The external-validation harness owns its
    # separate, test-only fixture path and cannot opt this one in.
    try:
        require_external_production_activation()
    except RoleCapabilityError as error:
        raise DependencyReviewDispatchError("dependency review production activation is unavailable") from error

    if type(repository) is not RepositoryIdentity or type(task_identity) is not TaskIdentity or type(subset) is not AffectedSubset or type(binding) is not DependencyReviewBinding or type(audit) is not ProviderHealthAuditIdentity or type(advisory_execution) is not SealedRoleExecution or advisory_execution.seam is not RoleExecutionSeam.DEPENDENCY_REVIEW or type(execution_host) is not TrustedExecutionHostInputs or not isinstance(budget_ledger_path, Path):
        raise DependencyReviewDispatchError("dependency review preparation inputs are invalid")
    binding.require_subset(subset)
    if audit.profile_identity != binding.profile_identity or (audit.profile.model, audit.profile.reasoning_effort.value) != ("gpt-5.6-terra", "high"):
        raise DependencyReviewDispatchError("dependency review profile is unavailable")
    if backend is None:
        from .dependency_review_toolbox import HarnessNativeCodexDependencyReviewBackend
        from .worker_toolbox import CompletionDeadline
        backend = HarnessNativeCodexDependencyReviewBackend(
            cwd=repository.root, completion=CompletionDeadline(100, 600),
            launch_context=trusted_provider_launch_context(
                advisory_execution, cwd=repository.root,
            ),
        )
    return DependencyReviewHostInputs(
        repository, task_identity, subset, binding, CodexDependencyReviewAdapter(backend, audit.profile, audit),
        lambda _session: None, lambda _session, _turn: None, advisory_execution,
        execution_host, budget_ledger_path,
        source_owned_relations, supersedes_attempt_id,
    )


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _identity(value: object, name: str) -> str:
    identity = getattr(value, "identity", None)
    result = identity() if callable(identity) else None
    if not _TOKEN.fullmatch(result or ""):
        raise DependencyReviewDispatchError(f"dependency review {name} identity is invalid")
    return result


def _abort(turn: object) -> None:
    try:
        if turn is not None:
            turn.abort()
    except Exception:
        pass


def _close(session: object) -> None:
    try:
        if session is not None:
            session.close()
    except Exception:
        pass
