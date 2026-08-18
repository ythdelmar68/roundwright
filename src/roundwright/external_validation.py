"""Public Roundwright adapters for the phase-neutral validation executor."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

from .shadow import (
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    HOSTED_CHECK_PROFILE,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    ShadowV2Error,
    ShadowV2EventGraph,
    shadow_evidence_profile,
)
from .provider_attempt_runtime import (
    MaterializedProviderAttemptContext,
    ProviderAttemptHostInputs,
    ProviderAttemptRuntimeError,
    install_host_runtime,
    prepare_context as prepare_provider_attempt_context,
)

EXECUTOR_CONTRACT_SCHEMA = "roundwright-executor-contract-synthetic/v1"
PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA = "roundwright-provider-attempt-accounting/v2"
HOSTED_CHECK_SCHEMA = "roundwright-hosted-check-evidence/v1"
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
PROVIDER_ATTEMPT_HISTORY_BLOCKER = "provider-attempt-runtime-unavailable"
HOSTED_CHECK_OBSERVATION_BLOCKER = "hosted-check-observation-unavailable"


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


HOSTED_CHECK_PRODUCER_IDENTITY = _digest(
    {"schema": HOSTED_CHECK_SCHEMA, "component": "typed-hosted-check-reader"}
)
HOSTED_CHECK_EXPORTER_IDENTITY = _digest(
    {"schema": HOSTED_CHECK_SCHEMA, "component": "public-terminal-case-exporter"}
)
HOSTED_CHECK_COMPARATOR_IDENTITY = _digest(
    {"schema": HOSTED_CHECK_SCHEMA, "component": "exact-candidate-hosted-check-comparator"}
)


def hosted_check_component_identities() -> tuple[str, str, str]:
    """Return the fixed component identities for the hosted-check profile."""

    return (
        HOSTED_CHECK_PRODUCER_IDENTITY,
        HOSTED_CHECK_EXPORTER_IDENTITY,
        HOSTED_CHECK_COMPARATOR_IDENTITY,
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
    """Public-safe durable records required by the provider-accounting profile.

    The reviewed Harness ``ExecutorBinding`` does not currently carry this
    value.  This type therefore documents and validates the product-owned
    records a future public executor contract must make available; it must not
    be reconstructed from a capture plan.
    """

    task_id: str
    source_digest: str
    base_sha: str
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
    configuration_digest: str
    provider_identity: str
    provider_context_digest: str
    lifecycle_state: str
    blocker: str | None
    next_action: str
    history_complete: bool
    event_graph: ShadowV2EventGraph | None = None

    def __post_init__(self) -> None:
        if (
            not _safe_token(self.task_id)
            or _DIGEST.fullmatch(self.source_digest) is None
            or _SHA.fullmatch(self.base_sha) is None
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
            or _DIGEST.fullmatch(self.configuration_digest) is None
            or not _safe_token(self.provider_identity)
            or _DIGEST.fullmatch(self.provider_context_digest) is None
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
            "source_digest": self.source_digest,
            "base_sha": self.base_sha,
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
            "configuration_digest": self.configuration_digest,
            "provider_identity": self.provider_identity,
            "provider_context_digest": self.provider_context_digest,
            "lifecycle_state": self.lifecycle_state,
            "blocker": self.blocker,
            "next_action": self.next_action,
            "history_complete": self.history_complete,
            "event_graph": None if self.event_graph is None else _graph_payload(self.event_graph),
        }


def _graph_payload(graph: ShadowV2EventGraph) -> dict[str, object]:
    return {
        "attempts": [
            [item.attempt_id, item.ordinal, item.kind.value, item.role.value, item.parent_attempt_id, item.review_round_id]
            for item in graph.attempts
        ],
        "provider_attempts": [
            [item.provider_attempt_id, item.lifecycle_attempt_id, item.ordinal, item.provider_identity, item.outcome]
            for item in graph.provider_attempts
        ],
        "review_rounds": [
            [item.review_round_id, item.ordinal, item.candidate_sha, item.accepted_result_id]
            for item in graph.review_rounds
        ],
        "commits": [[item.commit_sha, item.commit_identity] for item in graph.commits],
        "attempt_commit_references": [
            [item.lifecycle_attempt_id, item.commit_sha] for item in graph.attempt_commit_references
        ],
        "accepted_results": [
            [item.result_id, item.review_round_id, item.event_id, item.candidate_sha]
            for item in graph.accepted_results
        ],
        "events": [
            [item.event_id, item.ordinal, item.lifecycle_attempt_id, item.event_kind,
             item.provider_attempt_id, item.provider_call_made, item.review_round_id,
             item.commit_sha, item.accepted_result_id]
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


def _provider_attempt_history_blocker(binding: object) -> dict[str, object]:
    """Describe why a bare public executor binding cannot qualify this profile."""

    return {
        "code": PROVIDER_ATTEMPT_HISTORY_BLOCKER,
        "binding_identity": _provider_attempt_binding_identity(binding),
        "required_public_contract": "roundwright-harness-profile-executor-request/v2",
        "required_records": [
            "base-candidate-policy-configuration-provider-context",
            "provider-attempt-invalid-recovery-acceptance-events",
            "review-policy-mode-round-and-lifecycle-state",
        ],
        "missing_runtime_capabilities": [
            "repository-and-task-identity",
            "transition-lease-and-candidate-seal",
            "pinned-runtime-policy-and-provider-profile",
            "bounded-provider-backend-and-durable-lifecycle-store",
        ],
    }


def _require_provider_attempt_history(binding: object) -> None:
    """Fail before dispatch until the reviewed executor exposes real records."""

    _provider_attempt_history_blocker(binding)
    raise ExternalValidationAdapterError(
        f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: execution context is unavailable"
    )


def _provider_attempt_context(binding: object) -> MaterializedProviderAttemptContext:
    try:
        context = binding.execution_context
        descriptor_digest = binding.execution_context_input_digest
        value = context.value
    except AttributeError as error:
        raise ExternalValidationAdapterError(
            f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: reviewed ExecutorBinding lacks a V2 execution context"
        ) from error
    if (
        type(value) is not MaterializedProviderAttemptContext
        or type(descriptor_digest) is not str
        or not descriptor_digest.startswith("sha256:")
    ):
        raise ExternalValidationAdapterError(f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: execution context has drifted")
    return value


def _provider_attempt_evidence(binding: object, snapshot: ProviderAttemptAccountingSnapshot | None = None) -> dict[str, object]:
    identity = _provider_attempt_binding_identity(binding)
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
            "history": "complete" if snapshot is not None else "unavailable-public-binding",
            "snapshot": None if snapshot is None else snapshot.public_payload(),
            "blocker": _provider_attempt_history_blocker(binding) if snapshot is None else None,
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

    def prepare_execution_context(self, preparation: object) -> object:
        """Materialize the V2 descriptor into one opaque product context."""

        try:
            context = prepare_provider_attempt_context(
                dict(preparation.descriptor),
                plan_digest=preparation.plan.plan_digest,
                candidate_sha=preparation.plan.candidate_sha,
                case_id=preparation.plan.case_id,
                ready_at=preparation.plan.ready_at,
            )
            return _harness_executor().ProfileExecutionContext(context.identity, context)
        except (AttributeError, ProviderAttemptRuntimeError) as error:
            raise ExternalValidationAdapterError(f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: {error}") from error

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
        context = _provider_attempt_context(binding)
        try:
            context.resources.validate(context.descriptor)
            # Host construction is intentionally non-mutating.  This formal
            # boundary creates one fresh PREPARED checkpoint or validates an
            # exact persisted terminal/accepted sequence read-only.
            context.resources.runner.validate_accounting_checkpoint()
        except ProviderAttemptRuntimeError as error:
            raise ExternalValidationAdapterError(f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: {error}") from error

    def execute(self, binding: object) -> object:
        context = _provider_attempt_context(binding)
        try:
            attempt_ids = context.resources.runner.execute()
            snapshot = ProviderAttemptAccountingSnapshot(**context.snapshot(attempt_ids))
        except (ProviderAttemptRuntimeError, ValueError) as error:
            raise ExternalValidationAdapterError(f"{PROVIDER_ATTEMPT_HISTORY_BLOCKER}: {error}") from error
        if not snapshot.history_complete:
            raise ExternalValidationAdapterError("provider-attempt-history-incomplete")
        evidence = _provider_attempt_evidence(binding, snapshot)
        return _harness_executor().ProfileExecution(
            {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "evidence_identity": _digest(evidence), "snapshot": snapshot},
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        context = _provider_attempt_context(binding)
        try:
            value = execution.value
            mutation_count = execution.mutation_count
        except AttributeError as error:
            raise ExternalValidationAdapterError("executor result is invalid") from error
        if type(value) is not dict or set(value) != {"schema", "evidence_identity", "snapshot"} or type(value.get("snapshot")) is not ProviderAttemptAccountingSnapshot or mutation_count != 0:
            raise ExternalValidationAdapterError("executor result has drifted")
        expected = _provider_attempt_evidence(binding, value["snapshot"])
        if value != {"schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA, "evidence_identity": _digest(expected), "snapshot": value["snapshot"]}:
            raise ExternalValidationAdapterError("executor result has drifted")
        # Re-read durable state after execution; a restart, plan, candidate, or
        # context change cannot reuse a previously projected graph.
        try:
            refreshed = ProviderAttemptAccountingSnapshot(**context.snapshot(tuple(item.provider_attempt_id for item in value["snapshot"].event_graph.provider_attempts)))
        except (AttributeError, ProviderAttemptRuntimeError, ValueError) as error:
            raise ExternalValidationAdapterError("durable provider attempt read-back has drifted") from error
        if refreshed != value["snapshot"]:
            raise ExternalValidationAdapterError("durable provider attempt read-back has drifted")
        return expected

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        status = "fail"
        try:
            snapshot = evidence["provider_attempt_accounting"]["snapshot"]
            # Public evidence is JSON, so compare the canonical projection,
            # rather than accepting an opaque execution object.
            context = _provider_attempt_context(binding)
            current = ProviderAttemptAccountingSnapshot(**context.snapshot(tuple(item[0] for item in snapshot["event_graph"]["provider_attempts"])))
            expected = _provider_attempt_evidence(binding, current)
            status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        except (KeyError, TypeError, ProviderAttemptRuntimeError, ExternalValidationAdapterError, ValueError):
            expected = _provider_attempt_evidence(binding)
        result_identity = _digest({
            "schema": PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA,
            "status": status,
            "ready_at": binding.ready_at,
            "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
        })
        return _harness_executor().ProfileComparison(status, result_identity)


@dataclass(frozen=True)
class HostedCheckSnapshot:
    """One public-safe, already-normalized terminal hosted observation.

    The Worker never constructs this from a provider response.  A credentialed
    owner-side reader must supply this typed value after the exact plan is
    armed; tests use it directly as a deterministic fake.
    """

    repository: str
    workflow: str
    ref: str
    branch: str
    candidate_sha: str
    check_suite_ids: tuple[str, ...]
    job_ids: tuple[str, ...]
    artifact_digests: tuple[str, ...]
    freshness_seconds: int
    outcome: str

    def __post_init__(self) -> None:
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}", self.repository)
            or not _safe_token(self.workflow)
            or not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.ref)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.branch)
            or self.ref != f"refs/heads/{self.branch}"
            or _SHA.fullmatch(self.candidate_sha) is None
            or type(self.check_suite_ids) is not tuple
            or type(self.job_ids) is not tuple
            or type(self.artifact_digests) is not tuple
            or not self.check_suite_ids
            or not self.job_ids
            or any(not _safe_token(value) for value in (*self.check_suite_ids, *self.job_ids))
            or len(set(self.check_suite_ids)) != len(self.check_suite_ids)
            or len(set(self.job_ids)) != len(self.job_ids)
            or any(_DIGEST.fullmatch(value) is None for value in self.artifact_digests)
            or len(set(self.artifact_digests)) != len(self.artifact_digests)
            or type(self.freshness_seconds) is not int
            or not 0 <= self.freshness_seconds <= 86_400
            or self.outcome not in {"pass", "queued", "in-progress", "failure", "cancelled", "skipped", "neutral"}
        ):
            raise ExternalValidationAdapterError("hosted check snapshot is invalid")

    def public_payload(self) -> dict[str, object]:
        return {
            "repository": self.repository, "workflow": self.workflow,
            "ref": self.ref, "branch": self.branch,
            "candidate_sha": self.candidate_sha,
            # Internal tuples make the typed snapshot immutable.  The
            # Recorder boundary is strict JSON, so project canonical arrays.
            "check_suite_ids": list(self.check_suite_ids), "job_ids": list(self.job_ids),
            "artifact_digests": list(self.artifact_digests),
            "freshness_seconds": self.freshness_seconds, "outcome": self.outcome,
        }


@dataclass(frozen=True)
class HostedCheckRuntimeDescriptor:
    """Closed V2 public context; it carries identities, never provider output."""

    repository: str
    workflow: str
    ref: str
    branch: str
    base_sha: str
    candidate_sha: str
    capture_plan_digest: str
    case_id: str
    ready_at: int
    pull_request: int
    schema: str = "roundwright-hosted-check-runtime/v1"

    @classmethod
    def parse(cls, value: object) -> "HostedCheckRuntimeDescriptor":
        if type(value) not in (dict, MappingProxyType):
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")
        raw = dict(value)
        expected = {
            "schema", "repository", "workflow", "ref", "branch", "base_sha",
            "candidate_sha", "capture_plan_digest", "case_id", "ready_at", "pull_request",
        }
        if set(raw) != expected:
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")
        try:
            return cls(**raw)
        except (TypeError, ValueError) as error:
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid") from error

    def __post_init__(self) -> None:
        if (
            self.schema != "roundwright-hosted-check-runtime/v1"
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}", self.repository)
            or not _safe_token(self.workflow)
            or not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.ref)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.branch)
            or self.ref != f"refs/heads/{self.branch}"
            or _SHA.fullmatch(self.base_sha) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or not _safe_token(self.case_id)
            or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.pull_request) is not int or self.pull_request <= 0
        ):
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "repository": self.repository, "workflow": self.workflow,
            "ref": self.ref, "branch": self.branch, "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "capture_plan_digest": self.capture_plan_digest, "case_id": self.case_id,
            "ready_at": self.ready_at, "pull_request": self.pull_request,
        }


@dataclass(frozen=True)
class MaterializedHostedCheckContext:
    """Opaque V2 value retained unchanged across validate, execute, and replay."""

    descriptor: HostedCheckRuntimeDescriptor

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-hosted-check-context/v1", "descriptor": self.descriptor.payload()})


def prepare_hosted_check_context(
    descriptor_value: object, *, plan_digest: str, candidate_sha: str, case_id: str, ready_at: int,
) -> MaterializedHostedCheckContext:
    descriptor = HostedCheckRuntimeDescriptor.parse(descriptor_value)
    if (
        descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at,
    ) != (plan_digest, candidate_sha, case_id, ready_at):
        raise ExternalValidationAdapterError("hosted check runtime descriptor does not match capture plan")
    return MaterializedHostedCheckContext(descriptor)


def _hosted_check_binding_identity(binding: object) -> str:
    try:
        value = {
            "schema": HOSTED_CHECK_SCHEMA, "profile": binding.profile,
            "case_id": binding.case_id, "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at, "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("hosted check binding is invalid") from error
    if (
        value["profile"] != HOSTED_CHECK_PROFILE
        or not _safe_token(value["case_id"])
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int or value["ready_at"] < 0
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("hosted check binding is invalid")
    return _digest(value)


def _hosted_check_context(binding: object) -> MaterializedHostedCheckContext:
    try:
        context = binding.execution_context
        descriptor_digest = binding.execution_context_input_digest
        value = context.value
    except AttributeError as error:
        raise ExternalValidationAdapterError("hosted check V2 execution context is unavailable") from error
    if type(value) is not MaterializedHostedCheckContext or type(descriptor_digest) is not str or _DIGEST.fullmatch(descriptor_digest) is None:
        raise ExternalValidationAdapterError("hosted check V2 execution context has drifted")
    descriptor = value.descriptor
    if (
        descriptor.candidate_sha != binding.candidate_sha
        or descriptor.capture_plan_digest != binding.plan.plan_digest
        or descriptor.case_id != binding.case_id
        or descriptor.ready_at != binding.ready_at
    ):
        raise ExternalValidationAdapterError("hosted check V2 execution context has drifted")
    return value


@dataclass(frozen=True)
class HostedCheckProfileAdapter:
    """Context-free hosted-check profile with no default provider capability."""

    snapshot: HostedCheckSnapshot | None = None
    profile_id: str = HOSTED_CHECK_PROFILE

    def __post_init__(self) -> None:
        if self.profile_id != HOSTED_CHECK_PROFILE or (self.snapshot is not None and type(self.snapshot) is not HostedCheckSnapshot):
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        return _harness_executor().ProfileComponentIdentities(*hosted_check_component_identities())

    def prepare_execution_context(self, preparation: object) -> object:
        """Materialize the one closed public V2 descriptor without provider access."""

        try:
            context = prepare_hosted_check_context(
                preparation.descriptor, plan_digest=preparation.plan.plan_digest,
                candidate_sha=preparation.plan.candidate_sha, case_id=preparation.plan.case_id,
                ready_at=preparation.plan.ready_at,
            )
            return _harness_executor().ProfileExecutionContext(context.identity, context)
        except (AttributeError, ExternalValidationAdapterError) as error:
            raise ExternalValidationAdapterError("hosted check V2 execution context is invalid") from error

    def validate(self, binding: object) -> None:
        _hosted_check_binding_identity(binding)
        _hosted_check_context(binding)
        try:
            actual = (
                binding.components.producer_identity, binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ExternalValidationAdapterError("hosted check components are invalid") from error
        if actual != hosted_check_component_identities():
            raise ExternalValidationAdapterError("hosted check components have drifted")
        try:
            profile = shadow_evidence_profile(HOSTED_CHECK_PROFILE)
        except ShadowV2Error as error:
            raise ExternalValidationAdapterError("hosted check profile is unavailable") from error
        if profile.capture_mode.value != "terminal-snapshot":
            raise ExternalValidationAdapterError("hosted check profile capture mode has drifted")

    def execute(self, binding: object) -> object:
        identity = _hosted_check_binding_identity(binding)
        context = _hosted_check_context(binding)
        snapshot = self.snapshot
        if snapshot is None:
            raise ExternalValidationAdapterError(HOSTED_CHECK_OBSERVATION_BLOCKER)
        if (
            snapshot.candidate_sha != binding.candidate_sha
            or (snapshot.repository, snapshot.workflow, snapshot.ref, snapshot.branch)
            != (context.descriptor.repository, context.descriptor.workflow, context.descriptor.ref, context.descriptor.branch)
        ):
            raise ExternalValidationAdapterError("hosted check snapshot candidate has drifted")
        return _harness_executor().ProfileExecution(
            {"schema": HOSTED_CHECK_SCHEMA, "binding_identity": identity, "snapshot": snapshot},
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        identity = _hosted_check_binding_identity(binding)
        _hosted_check_context(binding)
        try:
            value, mutation_count = execution.value, execution.mutation_count
            snapshot = value["snapshot"]
        except (AttributeError, KeyError, TypeError) as error:
            raise ExternalValidationAdapterError("hosted check result is invalid") from error
        if (
            type(value) is not dict or value.get("schema") != HOSTED_CHECK_SCHEMA
            or value.get("binding_identity") != identity or type(snapshot) is not HostedCheckSnapshot
            or mutation_count != 0 or snapshot.candidate_sha != binding.candidate_sha
        ):
            raise ExternalValidationAdapterError("hosted check result has drifted")
        return {
            "schema": "roundwright-shadow-case/v2", "profile": HOSTED_CHECK_PROFILE,
            "ready_at": binding.ready_at, "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha,
            "capture_plan_digest": binding.plan.plan_digest,
            "hosted_check": {
                "schema": HOSTED_CHECK_SCHEMA, "binding_identity": identity,
                "producer_identity": HOSTED_CHECK_PRODUCER_IDENTITY,
                "exporter_identity": HOSTED_CHECK_EXPORTER_IDENTITY,
                "comparator_identity": HOSTED_CHECK_COMPARATOR_IDENTITY,
                "snapshot": snapshot.public_payload(), "mutation_count": 0,
            },
        }

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        _hosted_check_context(binding)
        snapshot = self.snapshot
        if snapshot is None:
            raise ExternalValidationAdapterError(HOSTED_CHECK_OBSERVATION_BLOCKER)
        expected = self.project(binding, _harness_executor().ProfileExecution(
            {"schema": HOSTED_CHECK_SCHEMA, "binding_identity": _hosted_check_binding_identity(binding), "snapshot": snapshot},
            mutation_count=0,
        ))
        status = "pass" if type(evidence) is dict and evidence == expected and snapshot.outcome == "pass" else "fail"
        return _harness_executor().ProfileComparison(status, _digest({
            "schema": HOSTED_CHECK_SCHEMA, "status": status,
            "ready_at": binding.ready_at, "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
        }))


def roundwright_profile_adapter_factory(profile_id: str) -> SyntheticExecutorAdapter | ProviderAttemptAccountingAdapter | HostedCheckProfileAdapter:
    """Return the exact public adapter selected by the Harness executor."""

    if profile_id == EXECUTOR_CONTRACT_SYNTHETIC_PROFILE:
        return SyntheticExecutorAdapter(profile_id)
    if profile_id == PROVIDER_ATTEMPT_ACCOUNTING_PROFILE:
        return ProviderAttemptAccountingAdapter(profile_id)
    if profile_id == HOSTED_CHECK_PROFILE:
        return HostedCheckProfileAdapter(profile_id=profile_id)
    raise ExternalValidationAdapterError("executor profile is unsupported")


def run_hosted_check_profile(
    mode: Literal["validate", "execute"], request_value: Mapping[str, Any], store_root: Path,
    snapshot: HostedCheckSnapshot | None = None, *, expected_readiness_digest: str | None = None,
) -> object:
    """Run the one V2 hosted-check flow with an explicit typed observation.

    Validate has no provider capability.  Execute requires a caller-supplied
    normalized snapshot bound to the same request/context; it never receives
    credentials, raw provider output, paths, or an inferred latest run.
    """

    harness = _harness_executor()
    try:
        request = harness.ExecutorRequest.parse(request_value)
        if (
            request.schema != "roundwright-harness-profile-executor-request/v2"
            or request.capture_plan["profile"] != HOSTED_CHECK_PROFILE
            or request.execution_context is None
            or not isinstance(store_root, Path)
            or (mode == "execute" and type(snapshot) is not HostedCheckSnapshot)
            or (mode == "validate" and snapshot is not None)
        ):
            raise ValueError
        plan = harness.prepare_capture(request.capture_plan)
        prepare_hosted_check_context(
            request.execution_context, plan_digest=plan.plan_digest, candidate_sha=plan.candidate_sha,
            case_id=plan.case_id, ready_at=plan.ready_at,
        )
        return harness.run_profile_executor(
            mode, request_value, HostedCheckProfileAdapter(snapshot), store_root,
            expected_readiness_digest=expected_readiness_digest,
        )
    except ExternalValidationAdapterError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("hosted check hosted entrypoint binding is invalid") from error


def run_provider_attempt_accounting_profile(
    mode: Literal["validate", "execute"],
    request_value: Mapping[str, Any],
    store_root: Path,
    host_inputs: ProviderAttemptHostInputs,
    *,
    expected_readiness_digest: str | None = None,
) -> object:
    """Run the V2 live profile through one hosted product/Harness process.

    Context-free profiles may use the generic Harness CLI/factory.  This
    profile requires product-owned host inputs, so this entrypoint installs the
    exact opaque runtime before delegating exactly once to Harness's reviewed
    ``run_profile_executor`` library API.
    """

    harness = _harness_executor()
    try:
        request = harness.ExecutorRequest.parse(request_value)
        if (
            request.schema != "roundwright-harness-profile-executor-request/v2"
            or request.capture_plan["profile"] != PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
            or request.execution_context is None
            or not isinstance(store_root, Path)
        ):
            raise ValueError
        plan = harness.prepare_capture(request.capture_plan)
        context = install_host_runtime(dict(request.execution_context), host_inputs)
        if (
            context.descriptor.capture_plan_digest != plan.plan_digest
            or context.descriptor.candidate_sha != plan.candidate_sha
            or context.descriptor.case_id != plan.case_id
            or context.descriptor.ready_at != plan.ready_at
        ):
            raise ValueError
        adapter = ProviderAttemptAccountingAdapter()
        return harness.run_profile_executor(
            mode, request_value, adapter, store_root,
            expected_readiness_digest=expected_readiness_digest,
        )
    except ExternalValidationAdapterError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError, ProviderAttemptRuntimeError) as error:
        raise ExternalValidationAdapterError("provider attempt hosted entrypoint binding is invalid") from error
