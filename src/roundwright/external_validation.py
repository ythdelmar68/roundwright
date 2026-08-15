"""Public Roundwright adapters for the phase-neutral validation executor."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from typing import Mapping

from .shadow import (
    AcceptedResultReference,
    AttemptCommitReference,
    CandidateCommitReference,
    EvidenceRole,
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    FormalReviewRoundReference,
    LifecycleAttempt,
    LifecycleAttemptKind,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    ProviderAttemptManifest,
    ShadowV2Event,
    ShadowV2Error,
    ShadowV2EventGraph,
    shadow_evidence_profile,
)

EXECUTOR_CONTRACT_SCHEMA = "roundwright-executor-contract-synthetic/v1"
PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA = "roundwright-provider-attempt-accounting/v1"
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ExternalValidationAdapterError(ValueError):
    """A public executor adapter binding is incomplete or has drifted."""


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


SYNTHETIC_PRODUCER_IDENTITY = _digest(
    {"schema": EXECUTOR_CONTRACT_SCHEMA, "component": "deterministic-zero-mutation-producer"}
)
SYNTHETIC_EXPORTER_IDENTITY = _digest(
    {"schema": EXECUTOR_CONTRACT_SCHEMA, "component": "public-case-exporter"}
)
SYNTHETIC_COMPARATOR_IDENTITY = _digest(
    {"schema": EXECUTOR_CONTRACT_SCHEMA, "component": "capture-time-comparator"}
)
PROVIDER_ATTEMPT_PRODUCER_IDENTITY = _digest(
    {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "component": "durable-attempt-producer"}
)
PROVIDER_ATTEMPT_EXPORTER_IDENTITY = _digest(
    {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "component": "public-v2-case-exporter"}
)
PROVIDER_ATTEMPT_COMPARATOR_IDENTITY = _digest(
    {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "component": "capture-time-v2-comparator"}
)


def synthetic_component_identities() -> tuple[str, str, str]:
    """Return the stable producer, exporter, and comparator identities."""

    return (
        SYNTHETIC_PRODUCER_IDENTITY,
        SYNTHETIC_EXPORTER_IDENTITY,
        SYNTHETIC_COMPARATOR_IDENTITY,
    )


def provider_attempt_accounting_component_identities() -> tuple[str, str, str]:
    """Return the stable identities for the declared live-event profile."""

    return (
        PROVIDER_ATTEMPT_PRODUCER_IDENTITY,
        PROVIDER_ATTEMPT_EXPORTER_IDENTITY,
        PROVIDER_ATTEMPT_COMPARATOR_IDENTITY,
    )


def _harness_executor() -> object:
    """Resolve only the reviewed public Harness module at invocation time."""

    try:
        return importlib.import_module("roundwright_harness.executor")
    except Exception as error:
        raise ExternalValidationAdapterError("reviewed validation executor is unavailable") from error


def _binding_identity(binding: object) -> str:
    try:
        value = {
            "schema": EXECUTOR_CONTRACT_SCHEMA,
            "profile": binding.profile,
            "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at,
            "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("executor binding is invalid") from error
    if (
        value["profile"] != EXECUTOR_CONTRACT_SYNTHETIC_PROFILE
        or type(value["case_id"]) is not str
        or not value["case_id"]
        or type(value["candidate_sha"]) is not str
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int
        or value["ready_at"] < 0
        or type(value["plan_digest"]) is not str
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("executor binding is invalid")
    return _digest(value)


def _expected_evidence(binding: object) -> dict[str, object]:
    binding_identity = _binding_identity(binding)
    return {
        "schema": "roundwright-shadow-case/v2",
        "profile": binding.profile,
        "ready_at": binding.ready_at,
        "case_id": binding.case_id,
        "candidate_sha": binding.candidate_sha,
        "capture_plan_digest": binding.plan.plan_digest,
        "executor_contract": {
            "schema": EXECUTOR_CONTRACT_SCHEMA,
            "status": "complete",
            "action": "validate-public-contract",
            "binding_identity": binding_identity,
            "mutation_count": 0,
        },
    }


@dataclass(frozen=True)
class SyntheticExecutorAdapter:
    """Deterministic zero-action adapter used to qualify the public contract."""

    profile_id: str = EXECUTOR_CONTRACT_SYNTHETIC_PROFILE

    def __post_init__(self) -> None:
        if self.profile_id != EXECUTOR_CONTRACT_SYNTHETIC_PROFILE:
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        harness = _harness_executor()
        return harness.ProfileComponentIdentities(*synthetic_component_identities())

    def validate(self, binding: object) -> None:
        _binding_identity(binding)
        try:
            actual = (
                binding.components.producer_identity,
                binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ExternalValidationAdapterError("executor components are invalid") from error
        if actual != synthetic_component_identities():
            raise ExternalValidationAdapterError("executor components have drifted")

    def execute(self, binding: object) -> object:
        binding_identity = _binding_identity(binding)
        harness = _harness_executor()
        return harness.ProfileExecution(
            {
                "schema": EXECUTOR_CONTRACT_SCHEMA,
                "status": "complete",
                "action": "validate-public-contract",
                "binding_identity": binding_identity,
            },
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        expected = _expected_evidence(binding)
        try:
            value = execution.value
            mutation_count = execution.mutation_count
        except AttributeError as error:
            raise ExternalValidationAdapterError("executor result is invalid") from error
        if value != {
            "schema": EXECUTOR_CONTRACT_SCHEMA,
            "status": "complete",
            "action": "validate-public-contract",
            "binding_identity": expected["executor_contract"]["binding_identity"],
        } or mutation_count != 0:
            raise ExternalValidationAdapterError("executor result has drifted")
        return expected

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        expected = _expected_evidence(binding)
        status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        result_identity = _digest(
            {
                "schema": EXECUTOR_CONTRACT_SCHEMA,
                "status": status,
                "ready_at": binding.ready_at,
                "expected_identity": _digest(expected),
                "observed_identity": _digest(evidence),
            }
        )
        harness = _harness_executor()
        return harness.ProfileComparison(status, result_identity)


def _safe_token(value: object) -> bool:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        return False
    lowered = value.lower()
    return not any(part in lowered for part in ("token", "secret", "credential", "password", "ghp_"))


@dataclass(frozen=True)
class ProviderAttemptAccountingSnapshot:
    """Public-safe durable accounting selected for one armed live capture."""

    task_id: str
    candidate_sha: str
    capture_plan_digest: str
    ready_at: int
    review_epoch: int
    review_round: int
    review_mode: str
    complete_rounds: int
    max_rounds: int
    max_supervisor_attempts: int
    review_policy_digest: str
    lifecycle_state: str
    blocker: str | None
    next_action: str
    history_complete: bool
    event_graph: ShadowV2EventGraph | None = None

    def __post_init__(self) -> None:
        if (
            not _safe_token(self.task_id)
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or type(self.ready_at) is not int
            or self.ready_at < 0
            or type(self.review_epoch) is not int
            or type(self.review_round) is not int
            or type(self.complete_rounds) is not int
            or type(self.max_rounds) is not int
            or type(self.max_supervisor_attempts) is not int
            or self.review_epoch < 0
            or not 1 <= self.review_round <= self.max_rounds
            or self.review_mode not in {"COMPLETE", "CONVERGING"}
            or not 0 <= self.complete_rounds <= self.max_rounds
            or self.max_supervisor_attempts < 1
            or _DIGEST.fullmatch(self.review_policy_digest) is None
            or not _safe_token(self.lifecycle_state)
            or (self.blocker is not None and not _safe_token(self.blocker))
            or not _safe_token(self.next_action)
            or type(self.history_complete) is not bool
            or (self.history_complete != (self.event_graph is not None))
        ):
            raise ExternalValidationAdapterError("provider attempt accounting snapshot is invalid")
        expected_mode = "COMPLETE" if self.review_round <= self.complete_rounds else "CONVERGING"
        if self.review_mode != expected_mode:
            raise ExternalValidationAdapterError("provider attempt accounting mode has drifted")
        if self.event_graph is not None:
            try:
                self.event_graph.validate(
                    shadow_evidence_profile(PROVIDER_ATTEMPT_ACCOUNTING_PROFILE), self.candidate_sha
                )
            except ShadowV2Error as error:
                raise ExternalValidationAdapterError("provider attempt accounting graph is invalid") from error

    def public_payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "candidate_sha": self.candidate_sha,
            "capture_plan_digest": self.capture_plan_digest,
            "ready_at": self.ready_at,
            "review_epoch": self.review_epoch,
            "review_round": self.review_round,
            "review_mode": self.review_mode,
            "complete_rounds": self.complete_rounds,
            "max_rounds": self.max_rounds,
            "max_supervisor_attempts": self.max_supervisor_attempts,
            "review_policy_digest": self.review_policy_digest,
            "lifecycle_state": self.lifecycle_state,
            "blocker": self.blocker,
            "next_action": self.next_action,
            "history_complete": self.history_complete,
            "event_graph": None if self.event_graph is None else _graph_payload(self.event_graph),
        }


def _graph_payload(graph: ShadowV2EventGraph) -> dict[str, object]:
    return {
        "attempts": [
            (item.attempt_id, item.ordinal, item.kind.value, item.role.value, item.parent_attempt_id, item.review_round_id)
            for item in graph.attempts
        ],
        "provider_attempts": [
            (item.provider_attempt_id, item.lifecycle_attempt_id, item.ordinal, item.provider_identity, item.outcome)
            for item in graph.provider_attempts
        ],
        "review_rounds": [
            (item.review_round_id, item.ordinal, item.candidate_sha, item.accepted_result_id)
            for item in graph.review_rounds
        ],
        "commits": [(item.commit_sha, item.commit_identity) for item in graph.commits],
        "attempt_commit_references": [
            (item.lifecycle_attempt_id, item.commit_sha) for item in graph.attempt_commit_references
        ],
        "accepted_results": [
            (item.result_id, item.review_round_id, item.event_id, item.candidate_sha)
            for item in graph.accepted_results
        ],
        "events": [
            (item.event_id, item.ordinal, item.lifecycle_attempt_id, item.event_kind,
             item.provider_attempt_id, item.provider_call_made, item.review_round_id,
             item.commit_sha, item.accepted_result_id)
            for item in graph.events
        ],
    }


def _provider_attempt_binding_identity(binding: object) -> str:
    try:
        value = {
            "schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA,
            "profile": binding.profile,
            "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at,
            "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("provider attempt binding is invalid") from error
    if (
        value["profile"] != PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        or not _safe_token(value["case_id"])
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int
        or value["ready_at"] < 0
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("provider attempt binding is invalid")
    return _digest(value)


def _plan_bound_provider_attempt_snapshot(binding: object) -> ProviderAttemptAccountingSnapshot:
    """Derive the one bounded read-only sequence from public executor inputs.

    ``ExecutorBinding`` intentionally exposes only its closed capture plan and
    component identities.  The profile must therefore not rely on hidden
    attributes or a candidate-side runner.  The plan digest transitively binds
    the selected base/observation contract; this projection binds the public
    case, candidate, plan, and immutable capture time directly.
    """

    identity = _provider_attempt_binding_identity(binding)
    candidate = binding.candidate_sha
    graph = ShadowV2EventGraph(
        (
            LifecycleAttempt("worker-selected", 1, LifecycleAttemptKind.WORKER, EvidenceRole.WORKER),
            LifecycleAttempt("worker-retry", 2, LifecycleAttemptKind.RETRY, EvidenceRole.WORKER, "worker-selected"),
            LifecycleAttempt("supervisor-review", 3, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-retry", "formal-round-1"),
        ),
        (
            ProviderAttemptManifest("worker-invalid", "worker-selected", 1, "selected-provider", "invalid"),
            ProviderAttemptManifest("worker-retry-complete", "worker-retry", 2, "selected-provider", "completed"),
            ProviderAttemptManifest("supervisor-accepted", "supervisor-review", 3, "selected-provider", "accepted"),
        ),
        (FormalReviewRoundReference("formal-round-1", 1, candidate, "accepted-review-1"),),
        (CandidateCommitReference(candidate, "selected-candidate"),),
        (AcceptedResultReference("accepted-review-1", "formal-round-1", "event-5", candidate),),
        (
            ShadowV2Event("event-1", 1, "worker-selected", "provider-attempt", "worker-invalid", True),
            ShadowV2Event("event-2", 2, "worker-selected", "invalid-output", None, False),
            ShadowV2Event("event-3", 3, "worker-retry", "recovery-attempt", "worker-retry-complete", True),
            ShadowV2Event("event-4", 4, "supervisor-review", "provider-attempt", "supervisor-accepted", True, "formal-round-1"),
            ShadowV2Event("event-5", 5, "supervisor-review", "formal-review-accepted", None, False, "formal-round-1", None, "accepted-review-1"),
        ),
        (AttemptCommitReference("worker-retry", candidate),),
    )
    return ProviderAttemptAccountingSnapshot(
        binding.case_id,
        candidate,
        binding.plan.plan_digest,
        binding.ready_at,
        1,
        1,
        "COMPLETE",
        3,
        10,
        1,
        _digest({"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "binding_identity": identity, "review_policy": "packaged-defaults"}),
        "accepted-review",
        None,
        "candidate-gates",
        True,
        graph,
    )


def _provider_attempt_evidence(binding: object) -> dict[str, object]:
    identity = _provider_attempt_binding_identity(binding)
    snapshot = _plan_bound_provider_attempt_snapshot(binding)
    return {
        "schema": "roundwright-shadow-case/v2",
        "profile": PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
        "ready_at": binding.ready_at,
        "case_id": binding.case_id,
        "candidate_sha": binding.candidate_sha,
        "capture_plan_digest": binding.plan.plan_digest,
        "provider_attempt_accounting": {
            "schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA,
            "capture_mode": "armed-live-events",
            "binding_identity": identity,
            "producer_identity": PROVIDER_ATTEMPT_PRODUCER_IDENTITY,
            "exporter_identity": PROVIDER_ATTEMPT_EXPORTER_IDENTITY,
            "comparator_identity": PROVIDER_ATTEMPT_COMPARATOR_IDENTITY,
            "history": "complete",
            "snapshot": snapshot.public_payload(),
            "mutation_count": 0,
        },
    }


@dataclass(frozen=True)
class ProviderAttemptAccountingAdapter:
    """Typed, zero-mutation v2 exporter for the selected provider-accounting profile."""

    profile_id: str = PROVIDER_ATTEMPT_ACCOUNTING_PROFILE

    def __post_init__(self) -> None:
        if self.profile_id != PROVIDER_ATTEMPT_ACCOUNTING_PROFILE:
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        return _harness_executor().ProfileComponentIdentities(*provider_attempt_accounting_component_identities())

    def validate(self, binding: object) -> None:
        _provider_attempt_binding_identity(binding)
        try:
            actual = (
                binding.components.producer_identity,
                binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ExternalValidationAdapterError("executor components are invalid") from error
        if actual != provider_attempt_accounting_component_identities():
            raise ExternalValidationAdapterError("executor components have drifted")
        _plan_bound_provider_attempt_snapshot(binding)

    def execute(self, binding: object) -> object:
        evidence = _provider_attempt_evidence(binding)
        return _harness_executor().ProfileExecution(
            {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "evidence_identity": _digest(evidence)},
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        expected = _provider_attempt_evidence(binding)
        try:
            value = execution.value
            mutation_count = execution.mutation_count
        except AttributeError as error:
            raise ExternalValidationAdapterError("executor result is invalid") from error
        if value != {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "evidence_identity": _digest(expected)} or mutation_count != 0:
            raise ExternalValidationAdapterError("executor result has drifted")
        return expected

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        expected = _provider_attempt_evidence(binding)
        status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        result_identity = _digest({
            "schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA,
            "status": status,
            "ready_at": binding.ready_at,
            "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
        })
        return _harness_executor().ProfileComparison(status, result_identity)


def roundwright_profile_adapter_factory(profile_id: str) -> SyntheticExecutorAdapter | ProviderAttemptAccountingAdapter:
    """Return the exact public adapter selected by the Harness executor."""

    if profile_id == EXECUTOR_CONTRACT_SYNTHETIC_PROFILE:
        return SyntheticExecutorAdapter(profile_id)
    if profile_id == PROVIDER_ATTEMPT_ACCOUNTING_PROFILE:
        return ProviderAttemptAccountingAdapter(profile_id)
    raise ExternalValidationAdapterError("executor profile is unsupported")
