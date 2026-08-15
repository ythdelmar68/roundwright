"""Product-owned V2 runtime materialization for provider-attempt evidence.

The Harness request carries only a public descriptor.  The descriptor names a
previously installed, process-local capability; it cannot carry provider
responses, lifecycle events, credentials, paths, or a requested outcome.  The
opaque capability is deliberately installed by the product host before the
executor is armed, and all evidence is subsequently read from Roundwright's
durable state APIs.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from .configuration import RepositoryIdentity, ReviewMode
from .candidate_review import DiffReviewOutput, DiffReviewVerdict, dispatch_diff_review, record_diff_review
from .codex_supervisor import (
    CodexSupervisorAdapter, CodexSupervisorContext, CodexSupervisorRequest,
    NativeCodexSupervisorBackend, SupervisorResultKind, SupervisorVerdict,
    supervisor_request_digest,
)
from .dependency_policy import CandidateBinding
from .git_identity import CandidateSeal, TransitionLease, WorktreeBinding
from .provider_health import ProviderHealthAuditIdentity
from .provider_recovery import (
    AttemptState, RecoveryContext, read_attempt, record_invalid_output,
    recover_attempt,
)
from .runtime_binding import RuntimeBinding, RuntimeBindingError
from .state import TaskIdentity, check_database, require_runtime_binding, task_projection
from .worker_planning import ProviderDispatchControl
from .shadow import (
    AcceptedResultReference, EvidenceRole, FormalReviewRoundReference,
    LifecycleAttempt, LifecycleAttemptKind, ProviderAttemptManifest,
    ShadowV2Event, ShadowV2EventGraph, shadow_evidence_profile,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
SCHEMA = "roundwright-provider-attempt-runtime/v2"


class ProviderAttemptRuntimeError(ValueError):
    """The descriptor or its opaque product resource is unavailable."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class ProviderAttemptRuntimeDescriptor:
    """Public JSON-safe identity material accepted from the V2 executor.

    ``resource_id`` is an opaque local capability handle.  It is intentionally
    not a file path, import string, provider payload, or event source.
    """

    resource_id: str
    repository_id: str
    task_id: str
    source_digest: str
    base_sha: str
    candidate_sha: str
    case_id: str
    ready_at: int
    capture_plan_digest: str
    runtime_binding: str
    provider_profile_identity: str
    review_epoch: int
    review_round: int

    @classmethod
    def parse(cls, value: object) -> "ProviderAttemptRuntimeDescriptor":
        required = {
            "schema", "resource_id", "repository_id", "task_id", "source_digest", "base_sha",
            "candidate_sha", "case_id", "ready_at", "capture_plan_digest", "runtime_binding",
            "provider_profile_identity", "review_epoch", "review_round",
        }
        if type(value) is not dict or set(value) != required or value.get("schema") != SCHEMA:
            raise ProviderAttemptRuntimeError("provider attempt runtime descriptor is invalid")
        try:
            parsed = cls(**{name: value[name] for name in required if name != "schema"})
        except TypeError as error:
            raise ProviderAttemptRuntimeError("provider attempt runtime descriptor is invalid") from error
        parsed._validate()
        return parsed

    def _validate(self) -> None:
        if (
            not all(_TOKEN.fullmatch(item) for item in (self.resource_id, self.repository_id, self.task_id, self.case_id))
            or not all(_DIGEST.fullmatch(item) for item in (self.source_digest, self.capture_plan_digest, self.provider_profile_identity))
            or not all(_SHA.fullmatch(item) for item in (self.base_sha, self.candidate_sha))
            or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.runtime_binding) is not str
            or type(self.review_epoch) is not int or self.review_epoch < 0
            or type(self.review_round) is not int or self.review_round < 1
        ):
            raise ProviderAttemptRuntimeError("provider attempt runtime descriptor is invalid")
        # The descriptor is intentionally closed: no outcome/history, provider
        # prose, credentials, arbitrary import/factory, or path fields exist.
        if any(word in self.runtime_binding.lower() for word in ("token", "secret", "credential", "password")):
            raise ProviderAttemptRuntimeError("provider attempt runtime descriptor is unsafe")
        try:
            binding = RuntimeBinding.from_canonical(self.runtime_binding)
        except RuntimeBindingError as error:
            raise ProviderAttemptRuntimeError("provider attempt runtime binding is invalid") from error
        if self.provider_profile_identity not in binding.supervisor_profile_identities:
            raise ProviderAttemptRuntimeError("provider attempt runtime profile is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": SCHEMA, "resource_id": self.resource_id, "repository_id": self.repository_id,
            "task_id": self.task_id, "source_digest": self.source_digest, "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha, "case_id": self.case_id, "ready_at": self.ready_at,
            "capture_plan_digest": self.capture_plan_digest, "runtime_binding": self.runtime_binding,
            "provider_profile_identity": self.provider_profile_identity, "review_epoch": self.review_epoch,
            "review_round": self.review_round,
        }


class ProviderAttemptRunner(Protocol):
    """One bounded product operation; implementations must persist via APIs."""

    def execute(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class DiffReviewSelection:
    """Non-outcome identifiers selected before the first provider dispatch."""

    diff_review_attempt_id: str
    implementation_attempt_id: str
    provider_attempt_id: str
    message_identity: str
    process_lease_id: str
    process_lease_expires_at: int
    objective: str
    acceptance_criteria: tuple[str, ...]
    within_round_attempt: int = 1

    def __post_init__(self) -> None:
        if (
            not all(_TOKEN.fullmatch(value) for value in (
                self.diff_review_attempt_id, self.implementation_attempt_id, self.provider_attempt_id,
                self.message_identity, self.process_lease_id,
            ))
            or type(self.process_lease_expires_at) is not int
            or type(self.objective) is not str or not self.objective.strip()
            or type(self.acceptance_criteria) is not tuple
            or not self.acceptance_criteria or any(type(item) is not str or not item.strip() for item in self.acceptance_criteria)
            or type(self.within_round_attempt) is not int or self.within_round_attempt < 1
        ):
            raise ProviderAttemptRuntimeError("provider attempt selection is invalid")


@dataclass(frozen=True)
class DurableDiffReviewRunner:
    """One real read-only Supervisor attempt through the durable product APIs.

    The runner creates no result or event itself.  It lets the native adapter
    observe the provider, checkpoints the native session/turn through
    ``candidate_review.dispatch_diff_review``, and persists the resulting
    typed verdict with ``record_diff_review``.  An invalid/ambiguous native
    outcome is persisted as such and cannot become qualifying evidence.
    """

    repository: RepositoryIdentity
    identity: TaskIdentity
    recovery: RecoveryContext
    binding: WorktreeBinding
    seal: CandidateSeal
    lease: TransitionLease
    dependency_binding: CandidateBinding
    dispatch_control: ProviderDispatchControl
    audit: ProviderHealthAuditIdentity
    backend: NativeCodexSupervisorBackend
    source_digest: str
    review_epoch: int
    review_round: int
    selection: DiffReviewSelection

    def execute(self) -> tuple[str, ...]:
        runtime = self.recovery.runtime_binding
        if (
            self.dependency_binding != CandidateBinding(self.identity.repository_id, self.identity.task_id, self.seal.candidate_sha)
            or self.audit.profile_identity not in runtime.supervisor_profile_identities
            or self.selection.within_round_attempt != 1
        ):
            raise ProviderAttemptRuntimeError("provider attempt runner context has drifted")
        context = CodexSupervisorContext(
            self.identity.task_id, self.source_digest, self.recovery.repository_fingerprint,
            self.recovery.worktree_fingerprint, self.recovery.branch_fingerprint,
            self.identity.base_sha, self.seal.candidate_sha,
            "sha256:" + self.recovery.policy_fingerprint, runtime.resolved_digest,
            self.review_epoch, self.review_round,
            ReviewMode.COMPLETE
            if self.review_round <= runtime.review_complete_rounds
            else ReviewMode.CONVERGING,
        )
        selected = self.audit.profile_identity
        request = CodexSupervisorRequest(
            self.selection.diff_review_attempt_id, self.selection.provider_attempt_id, selected,
            self.selection.within_round_attempt,
            supervisor_request_digest(
                review_attempt_id=self.selection.diff_review_attempt_id,
                provider_attempt_id=self.selection.provider_attempt_id,
                selected_profile_identity=selected,
                within_round_attempt=self.selection.within_round_attempt,
                context=context, objective=self.selection.objective,
                acceptance_criteria=self.selection.acceptance_criteria,
            ),
            context, self.selection.objective, self.selection.acceptance_criteria,
        )
        dispatched = False

        def checkpoint_session(_: str) -> None:
            return None

        def checkpoint_turn(session_identity: str, turn_identity: str) -> None:
            nonlocal dispatched
            dispatch_diff_review(
                self.repository, self.identity, self.recovery, self.binding, self.seal,
                dependency_binding=self.dependency_binding, control=self.dispatch_control,
                diff_review_attempt_id=self.selection.diff_review_attempt_id,
                implementation_attempt_id=self.selection.implementation_attempt_id,
                provider_attempt_id=self.selection.provider_attempt_id,
                supervisor_session_identity=session_identity, external_turn_identity=turn_identity,
                message_identity=self.selection.message_identity,
                process_lease_id=self.selection.process_lease_id,
                process_lease_expires_at=self.selection.process_lease_expires_at,
                selected_profile_identity=selected, within_round_attempt=self.selection.within_round_attempt,
                review_round=self.review_round, lease=self.lease, now=self.dispatch_control.now,
            )
            dispatched = True

        result = CodexSupervisorAdapter(self.backend, self.audit.profile, self.audit).dispatch(
            request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn,
        )
        if not dispatched:
            raise ProviderAttemptRuntimeError("native Supervisor did not reach a durable dispatch checkpoint")
        if result.kind is not SupervisorResultKind.ACCEPTED:
            # This is an observed typed adapter outcome, not caller-supplied
            # provider text.  It preserves the durable invalid/recovery path.
            marker = hashlib.sha256((result.kind.value + ":" + (result.diagnostic.value if result.diagnostic else "none")).encode()).hexdigest()
            record_invalid_output(
                self.repository, self.identity, self.recovery,
                attempt_id=self.selection.provider_attempt_id,
                output_pointer="supervisor-invalid-" + self.selection.provider_attempt_id,
                output_fingerprint=marker, reason_fingerprint=marker,
                lease=self.lease, now=self.dispatch_control.now,
            )
            recover_attempt(
                self.repository, self.identity, self.recovery,
                attempt_id=self.selection.provider_attempt_id,
                max_attempts=runtime.review_max_supervisor_attempts_per_round,
                lease=self.lease, now=self.dispatch_control.now,
            )
            return (self.selection.provider_attempt_id,)
        if result.session_identity is None or result.turn_identity is None or result.output_fingerprint is None or result.verdict is None:
            raise ProviderAttemptRuntimeError("native Supervisor result is incomplete")
        output = DiffReviewOutput(
            self.selection.diff_review_attempt_id, self.selection.provider_attempt_id,
            result.session_identity, result.turn_identity, self.selection.message_identity,
            self.identity.base_sha, self.seal.candidate_sha,
            DiffReviewVerdict.PASS if result.verdict is SupervisorVerdict.PASS else DiffReviewVerdict.FINDINGS,
            result.findings,
        )
        record_diff_review(
            self.repository, self.identity, self.recovery, self.binding, self.seal,
            diff_review_attempt_id=self.selection.diff_review_attempt_id, output=output,
            completion_evidence_fingerprint=result.output_fingerprint.removeprefix("sha256:"),
            lease=self.lease, now=self.dispatch_control.now,
        )
        return (self.selection.provider_attempt_id,)


@dataclass(frozen=True)
class ProviderAttemptRuntimeResources:
    """Opaque product objects held in memory, never emitted by Harness."""

    repository: RepositoryIdentity
    identity: TaskIdentity
    recovery: RecoveryContext
    lease: TransitionLease
    seal: CandidateSeal
    worktree: WorktreeBinding
    source_digest: str
    case_id: str
    ready_at: int
    capture_plan_digest: str
    provider_profile_identity: str
    review_epoch: int
    review_round: int
    runner: ProviderAttemptRunner

    def validate(self, descriptor: ProviderAttemptRuntimeDescriptor) -> None:
        if (
            self.identity.repository_id != descriptor.repository_id
            or self.worktree.repository_id != descriptor.repository_id
            or self.identity.task_id != descriptor.task_id
            or self.identity.base_sha != descriptor.base_sha
            or self.recovery.candidate_sha != descriptor.candidate_sha
            or self.source_digest != descriptor.source_digest
            or self.case_id != descriptor.case_id
            or self.ready_at != descriptor.ready_at
            or self.capture_plan_digest != descriptor.capture_plan_digest
            or self.provider_profile_identity != descriptor.provider_profile_identity
            or self.review_epoch != descriptor.review_epoch
            or self.review_round != descriptor.review_round
            or self.seal != CandidateSeal(descriptor.task_id, descriptor.base_sha, descriptor.candidate_sha, self.lease.state_identity)
            or self.worktree.task_id != descriptor.task_id
            or self.worktree.base_sha != descriptor.base_sha
            or self.worktree.state_identity != self.lease.state_identity
            or self.recovery.runtime_binding.canonical_material() != descriptor.runtime_binding
            or self.recovery.runtime_binding.resolved_digest != descriptor.provider_profile_identity and descriptor.provider_profile_identity not in self.recovery.runtime_binding.supervisor_profile_identities
            or not callable(getattr(self.runner, "execute", None))
        ):
            raise ProviderAttemptRuntimeError("provider attempt runtime context has drifted")
        # Provider-free preflight confirms the local durable identity and the
        # exact binding without calling a provider or creating a lifecycle row.
        check_database(self.repository)
        task_projection(self.repository, self.identity)
        require_runtime_binding(self.repository, self.identity, self.recovery.runtime_binding)


class ProviderAttemptRuntimeRegistry:
    """Closed in-memory product capability registry for the Harness V2 seam."""

    def __init__(self) -> None:
        self._resources: dict[str, ProviderAttemptRuntimeResources] = {}

    def install(self, resource_id: str, resources: ProviderAttemptRuntimeResources) -> None:
        if not _TOKEN.fullmatch(resource_id) or type(resources) is not ProviderAttemptRuntimeResources:
            raise ProviderAttemptRuntimeError("provider attempt runtime resource is invalid")
        if resource_id in self._resources and self._resources[resource_id] != resources:
            raise ProviderAttemptRuntimeError("provider attempt runtime resource conflicts")
        self._resources[resource_id] = resources

    def materialize(self, descriptor: ProviderAttemptRuntimeDescriptor) -> ProviderAttemptRuntimeResources:
        resources = self._resources.get(descriptor.resource_id)
        if resources is None:
            raise ProviderAttemptRuntimeError("provider attempt runtime resource is unavailable")
        resources.validate(descriptor)
        return resources


RUNTIME_REGISTRY = ProviderAttemptRuntimeRegistry()


@dataclass(frozen=True)
class MaterializedProviderAttemptContext:
    """The single opaque value flowing through V2 validate/execute/project."""

    descriptor: ProviderAttemptRuntimeDescriptor
    resources: ProviderAttemptRuntimeResources

    @property
    def identity(self) -> str:
        return _digest({"descriptor": self.descriptor.payload(), "runtime_binding": self.resources.recovery.runtime_binding.fingerprint, "state_identity": self.resources.lease.state_identity})

    def read_back(self, attempt_ids: tuple[str, ...]) -> tuple[object, ...]:
        # Evidence can only be formed from persisted provider rows.  A runner
        # returns identities it actually dispatched; the projection reads every
        # one back with its exact recovery context.
        if type(attempt_ids) is not tuple or not attempt_ids or any(not _TOKEN.fullmatch(item) for item in attempt_ids):
            raise ProviderAttemptRuntimeError("provider attempt execution returned no durable records")
        return tuple(read_attempt(self.resources.repository, self.resources.identity, item, context=self.resources.recovery) for item in attempt_ids)

    def snapshot(self, attempt_ids: tuple[str, ...]) -> dict[str, object]:
        """Project durable rows only; no descriptor value prescribes an outcome."""

        attempts = self.read_back(attempt_ids)
        projection = task_projection(self.resources.repository, self.resources.identity)
        accepted = tuple(item for item in attempts if item.state is AttemptState.ACCEPTED)
        graph: ShadowV2EventGraph | None = None
        # A profile is qualifying only after one actual accepted formal review.
        # Other persisted states remain visible as a typed non-qualifying
        # read-back, never as inferred recovery or acceptance facts.
        if len(accepted) == 1:
            review_id = "formal-" + accepted[0].accepted_review_identity
            records = tuple(
                LifecycleAttempt(item.attempt_id, ordinal, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, review_round_id=review_id if item is accepted[0] else None)
                for ordinal, item in enumerate(attempts, start=1)
            )
            manifests = tuple(
                ProviderAttemptManifest(
                    item.attempt_id, item.attempt_id, ordinal, item.selected_profile_identity,
                    "accepted" if item.state is AttemptState.ACCEPTED else item.state.value,
                )
                for ordinal, item in enumerate(attempts, start=1)
            )
            events: list[ShadowV2Event] = []
            ordinal = 1
            for item in attempts:
                events.append(ShadowV2Event(
                    "provider-" + item.attempt_id, ordinal, item.attempt_id, "provider-attempt", item.attempt_id, True,
                    review_id if item is accepted[0] else None,
                ))
                ordinal += 1
                if item.state is AttemptState.AMBIGUOUS:
                    events.append(ShadowV2Event("invalid-" + item.attempt_id, ordinal, item.attempt_id, "invalid-output", None, False))
                    ordinal += 1
                if item.state is AttemptState.INVALIDATED:
                    events.append(ShadowV2Event("recovery-" + item.attempt_id, ordinal, item.attempt_id, "recovery-attempt", None, False))
                    ordinal += 1
            result_id = accepted[0].accepted_review_identity
            events.append(ShadowV2Event("accepted-" + result_id, ordinal, accepted[0].attempt_id, "formal-review-accepted", None, False, review_id, accepted_result_id=result_id))
            graph = ShadowV2EventGraph(
                records, manifests,
                (FormalReviewRoundReference(review_id, 1, self.descriptor.candidate_sha, result_id),),
                (), (AcceptedResultReference(result_id, review_id, "accepted-" + result_id, self.descriptor.candidate_sha),),
                tuple(events),
            )
            graph.validate(shadow_evidence_profile("roundwright-shadow-profile/provider-attempt-accounting/v1"), self.descriptor.candidate_sha)
        return {
            "task_id": self.descriptor.task_id,
            "source_digest": self.descriptor.source_digest,
            "base_sha": self.descriptor.base_sha,
            "candidate_sha": self.descriptor.candidate_sha,
            "capture_plan_digest": self.descriptor.capture_plan_digest,
            "ready_at": self.descriptor.ready_at,
            "review_epoch": self.descriptor.review_epoch,
            "review_round": self.descriptor.review_round,
            "review_mode": "COMPLETE" if self.descriptor.review_round <= self.resources.recovery.runtime_binding.review_complete_rounds else "CONVERGING",
            "complete_rounds": self.resources.recovery.runtime_binding.review_complete_rounds,
            "max_rounds": self.resources.recovery.runtime_binding.review_max_rounds,
            "max_supervisor_attempts": self.resources.recovery.runtime_binding.review_max_supervisor_attempts_per_round,
            "review_policy_digest": "sha256:" + self.resources.recovery.runtime_binding.review_policy_digest,
            "configuration_digest": self.resources.recovery.runtime_binding.resolved_digest,
            "provider_identity": self.descriptor.provider_profile_identity,
            "provider_context_digest": self.identity,
            "lifecycle_state": projection.state,
            "blocker": None if graph is not None else "provider-attempt-history-incomplete",
            "next_action": projection.next_action or "provider-attempt-recapture-required",
            "history_complete": graph is not None,
            "event_graph": graph,
        }


def prepare_context(descriptor_value: object, *, plan_digest: str, candidate_sha: str, case_id: str, ready_at: int) -> MaterializedProviderAttemptContext:
    descriptor = ProviderAttemptRuntimeDescriptor.parse(descriptor_value)
    if (descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at) != (plan_digest, candidate_sha, case_id, ready_at):
        raise ProviderAttemptRuntimeError("provider attempt runtime descriptor does not match capture plan")
    return MaterializedProviderAttemptContext(descriptor, RUNTIME_REGISTRY.materialize(descriptor))
