"""Public Roundwright adapters for the phase-neutral validation executor."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import base64
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol

from .shadow import (
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    HOSTED_CHECK_PROFILE,
    LIVE_LIFECYCLE_SHADOW_PROFILE,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
    INTEGRATED_BOUNDARY_PROFILE,
    EvidenceRole,
    FormalReviewRoundReference,
    LifecycleAttempt,
    LifecycleAttemptKind,
    ShadowV2Event,
    ShadowV2Error,
    ShadowV2EventGraph,
    shadow_evidence_profile,
)
from .integrated_boundary import (
    ComposedEvidenceManifest, ComposedEvidenceResult, IntegratedBoundaryInputs,
    IntegratedBoundaryError, compose_retained_evidence, integrated_boundary_execution_context,
)
from .github import (
    GitHubReadOperation,
    GitHubReadRequest,
    GitHubReadResult,
    CommentsSnapshot,
    PullRequestSnapshot,
    RepositoryRef,
    RepositoryInventorySection,
    RepositoryInventorySnapshot,
)
from .github_runtime import (
    GitHubRuntimeError,
    ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED,
    RepositoryInventoryFailureStage,
    RepositoryInventoryReadFailureCode,
    RepositoryInventoryTransportSubcategory,
    credentialed_repository_inventory_failure,
    project_repository_fixture_outcomes,
)
from .provider_attempt_runtime import (
    MaterializedProviderAttemptContext,
    ProviderAttemptHostInputs,
    ProviderAttemptRuntimeError,
    install_host_runtime,
    prepare_context as prepare_provider_attempt_context,
)
from . import lifecycle_observation

EXECUTOR_CONTRACT_SCHEMA = "roundwright-executor-contract-synthetic/v1"
PROVIDER_ATTEMPT_ACCOUNTING_SCHEMA = "roundwright-provider-attempt-accounting/v2"
HOSTED_CHECK_SCHEMA = "roundwright-hosted-check-evidence/v1"
LIVE_LIFECYCLE_SHADOW_SCHEMA = "roundwright-live-lifecycle-shadow/v1"
READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA = "roundwright-read-only-external-observation/v1"
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ExternalValidationAdapterError(ValueError):
    """A public executor adapter binding is incomplete or has drifted."""


class RepositoryInventoryFirstReadBoundaryError(ExternalValidationAdapterError):
    """Typed, public-safe inventory failure at the lifecycle adapter boundary."""

    def __init__(
        self,
        code: RepositoryInventoryReadFailureCode,
        stage: RepositoryInventoryFailureStage = RepositoryInventoryFailureStage.UNKNOWN,
        transport_subcategory: RepositoryInventoryTransportSubcategory = RepositoryInventoryTransportSubcategory.UNKNOWN,
    ) -> None:
        if (
            type(code) is not RepositoryInventoryReadFailureCode
            or type(stage) is not RepositoryInventoryFailureStage
            or type(transport_subcategory) is not RepositoryInventoryTransportSubcategory
            or (
                stage is not RepositoryInventoryFailureStage.TRANSPORT
                and transport_subcategory is not RepositoryInventoryTransportSubcategory.UNKNOWN
            )
        ):
            raise TypeError("repository inventory failure is invalid")
        self.code = code
        self.stage = stage
        self.transport_subcategory = transport_subcategory
        reason = f"{ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED}:{code.value}"
        if stage is not RepositoryInventoryFailureStage.UNKNOWN:
            reason += f":{stage.value}"
        if (
            stage is RepositoryInventoryFailureStage.TRANSPORT
            and transport_subcategory is not RepositoryInventoryTransportSubcategory.UNKNOWN
        ):
            reason += f":{transport_subcategory.value}"
        super().__init__(
            reason
        )


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
LIVE_LIFECYCLE_OBSERVATION_BLOCKER = "live-lifecycle-shadow-observation-unavailable"
INTEGRATED_BOUNDARY_SCHEMA = "roundwright-integrated-boundary-composition/v1"


def synthetic_component_identities() -> tuple[str, str, str]:
    """Return the stable producer, exporter, and comparator identities."""

    return (
        SYNTHETIC_PRODUCER_IDENTITY,
        SYNTHETIC_EXPORTER_IDENTITY,
        SYNTHETIC_COMPARATOR_IDENTITY,
    )


READ_ONLY_EXTERNAL_OBSERVATION_PRODUCER_IDENTITY = _digest(
    {"schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA, "component": "typed-read-only-observer"}
)
READ_ONLY_EXTERNAL_OBSERVATION_EXPORTER_IDENTITY = _digest(
    {"schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA, "component": "public-safe-observation-exporter"}
)
READ_ONLY_EXTERNAL_OBSERVATION_COMPARATOR_IDENTITY = _digest(
    {"schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA, "component": "exact-candidate-read-only-comparator"}
)


def read_only_external_observation_component_identities() -> tuple[str, str, str]:
    """Return the stable Lane A component identities."""

    return (
        READ_ONLY_EXTERNAL_OBSERVATION_PRODUCER_IDENTITY,
        READ_ONLY_EXTERNAL_OBSERVATION_EXPORTER_IDENTITY,
        READ_ONLY_EXTERNAL_OBSERVATION_COMPARATOR_IDENTITY,
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
from .hosted_evidence import (
    HostedCheckEvidence,
    HostedCheckEvaluation,
    HostedCheckPolicy,
    HostedEvidenceOutcome,
    evaluate_hosted_check_evidence,
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


LIVE_LIFECYCLE_PRODUCER_IDENTITY = _digest(
    {"schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "component": "normalized-live-lifecycle-reader"}
)
LIVE_LIFECYCLE_EXPORTER_IDENTITY = _digest(
    {"schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "component": "public-safe-lifecycle-exporter"}
)
LIVE_LIFECYCLE_COMPARATOR_IDENTITY = _digest(
    {"schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "component": "zero-mutation-lifecycle-comparator"}
)


def live_lifecycle_shadow_component_identities() -> tuple[str, str, str]:
    """Return the fixed identities for the armed live-lifecycle profile."""

    return (
        LIVE_LIFECYCLE_PRODUCER_IDENTITY,
        LIVE_LIFECYCLE_EXPORTER_IDENTITY,
        LIVE_LIFECYCLE_COMPARATOR_IDENTITY,
    )


INTEGRATED_BOUNDARY_PRODUCER_IDENTITY = _digest({"schema": INTEGRATED_BOUNDARY_SCHEMA, "component": "retained-source-verifier"})
INTEGRATED_BOUNDARY_EXPORTER_IDENTITY = _digest({"schema": INTEGRATED_BOUNDARY_SCHEMA, "component": "composed-manifest-exporter"})
INTEGRATED_BOUNDARY_COMPARATOR_IDENTITY = _digest({"schema": INTEGRATED_BOUNDARY_SCHEMA, "component": "exact-composed-result-comparator"})


def integrated_boundary_component_identities() -> tuple[str, str, str]:
    return (INTEGRATED_BOUNDARY_PRODUCER_IDENTITY, INTEGRATED_BOUNDARY_EXPORTER_IDENTITY, INTEGRATED_BOUNDARY_COMPARATOR_IDENTITY)


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


def _read_only_external_observation_binding_identity(binding: object) -> str:
    """Bind Lane A to the same candidate-bound V2 plan used by its executor."""

    try:
        value = {
            "schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA,
            "profile": binding.profile,
            "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at,
            "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("read-only external observation binding is invalid") from error
    if (
        value["profile"] != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
        or type(value["case_id"]) is not str
        or not value["case_id"]
        or type(value["candidate_sha"]) is not str
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int
        or value["ready_at"] < 0
        or type(value["plan_digest"]) is not str
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("read-only external observation binding is invalid")
    return _digest(value)


@dataclass(frozen=True)
class ReadOnlyExternalObservationAdapter:
    """Lane A adapter installed only by the product-hosted V2 entrypoint."""

    provider: ReadOnlyExternalObservationProvider | None = None
    profile_id: str = READ_ONLY_EXTERNAL_OBSERVATION_PROFILE

    def __post_init__(self) -> None:
        if (
            self.profile_id != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
            or (self.provider is not None and type(self.provider) is not ReadOnlyExternalObservationProvider)
        ):
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        return _harness_executor().ProfileComponentIdentities(
            *read_only_external_observation_component_identities(),
        )

    def prepare_execution_context(self, preparation: object) -> object:
        try:
            context = prepare_read_only_external_observation_context(
                preparation.descriptor, plan_digest=preparation.plan.plan_digest,
                candidate_sha=preparation.plan.candidate_sha, case_id=preparation.plan.case_id,
                ready_at=preparation.plan.ready_at,
            )
            return _harness_executor().ProfileExecutionContext(context.identity, context)
        except (AttributeError, ExternalValidationAdapterError) as error:
            raise ExternalValidationAdapterError("read-only external observation V2 execution context is invalid") from error

    def validate(self, binding: object) -> None:
        _read_only_external_observation_binding_identity(binding)
        _read_only_external_observation_context(binding)
        try:
            components = (
                binding.components.producer_identity,
                binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ExternalValidationAdapterError("read-only external observation components are invalid") from error
        if components != read_only_external_observation_component_identities():
            raise ExternalValidationAdapterError("read-only external observation components have drifted")

    def execute(self, binding: object) -> object:
        identity = _read_only_external_observation_binding_identity(binding)
        _read_only_external_observation_context(binding)
        provider = self.provider
        if provider is None:
            raise ExternalValidationAdapterError("read-only external observation is unavailable")
        snapshot = provider.observe()
        if (snapshot.candidate_sha, snapshot.capture_plan_digest, snapshot.ready_at) != (
            binding.candidate_sha, binding.plan.plan_digest, binding.ready_at,
        ):
            raise ExternalValidationAdapterError("read-only external observation has drifted")
        return _harness_executor().ProfileExecution(
            {
                "schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA,
                "status": "complete",
                "action": "read-only-external-observation",
                "binding_identity": identity,
                "snapshot": snapshot,
            },
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        identity = _read_only_external_observation_binding_identity(binding)
        try:
            value, mutation_count, snapshot = execution.value, execution.mutation_count, execution.value["snapshot"]
        except AttributeError as error:
            raise ExternalValidationAdapterError("read-only external observation result is invalid") from error
        if value != {
            "schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA,
            "status": "complete",
            "action": "read-only-external-observation",
            "binding_identity": identity,
            "snapshot": snapshot,
        } or mutation_count != 0 or type(snapshot) is not ReadOnlyExternalObservationSnapshot:
            raise ExternalValidationAdapterError("read-only external observation result has drifted")
        if (snapshot.candidate_sha, snapshot.capture_plan_digest, snapshot.ready_at) != (
            binding.candidate_sha, binding.plan.plan_digest, binding.ready_at,
        ):
            raise ExternalValidationAdapterError("read-only external observation has drifted")
        return {
            "schema": "roundwright-shadow-case/v2",
            "profile": READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
            "ready_at": binding.ready_at,
            "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha,
            "capture_plan_digest": binding.plan.plan_digest,
            "read_only_external_observation": {
                "schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA,
                "binding_identity": identity,
                "producer_identity": READ_ONLY_EXTERNAL_OBSERVATION_PRODUCER_IDENTITY,
                "exporter_identity": READ_ONLY_EXTERNAL_OBSERVATION_EXPORTER_IDENTITY,
                "comparator_identity": READ_ONLY_EXTERNAL_OBSERVATION_COMPARATOR_IDENTITY,
                "target_state_digest": snapshot.target_state_digest,
                "trace_receipt_digest": snapshot.trace_receipt_digest,
                "fixture_receipt_digest": snapshot.fixture_receipt_digest,
                "mutation_count": 0,
            },
        }

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        expected = self.project(binding, self.execute(binding))
        status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        return _harness_executor().ProfileComparison(status, _digest({
            "schema": READ_ONLY_EXTERNAL_OBSERVATION_SCHEMA,
            "status": status,
            "ready_at": binding.ready_at,
            "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
        }))


def _safe_token(value: object) -> bool:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        return False
    lowered = value.lower()
    return not any(part in lowered for part in ("token", "secret", "credential", "password", "ghp_"))


def _safe_repository(value: object) -> bool:
    return type(value) is str and re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}", value,
    ) is not None


def _trace_publisher_identity(value: object) -> bool:
    return type(value) is str and re.fullmatch(
        r"(?:user|bot|organization|mannequin):[a-z0-9][a-z0-9-]{0,38}", value,
    ) is not None


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
    """A successful typed hosted evaluation retained for one exact capture."""

    evidence: HostedCheckEvidence
    policy: HostedCheckPolicy
    ref: str
    evaluated_at: int
    workflow_run_id: str
    check_suite_id: str
    evaluation: HostedCheckEvaluation = field(init=False)
    evaluation_identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.evidence) is not HostedCheckEvidence or type(self.policy) is not HostedCheckPolicy:
            raise ExternalValidationAdapterError("hosted check snapshot is invalid")
        if (
            not re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.ref)
            or self.ref != f"refs/heads/{self.evidence.branch}"
            or type(self.evaluated_at) is not int or self.evaluated_at < 0
            or not _safe_token(self.workflow_run_id) or not _safe_token(self.check_suite_id)
        ):
            raise ExternalValidationAdapterError("hosted check snapshot is invalid")
        try:
            evaluation = evaluate_hosted_check_evidence(
                self.evidence, repository=self.evidence.repository, workflow=self.evidence.workflow,
                candidate_sha=self.evidence.candidate_sha, branch=self.evidence.branch,
                policy=self.policy, now=self.evaluated_at,
                workflow_run_id=self.workflow_run_id, check_suite_id=self.check_suite_id,
            )
        except ValueError as error:
            raise ExternalValidationAdapterError("hosted check snapshot is invalid") from error
        if evaluation.outcome is not HostedEvidenceOutcome.PASS:
            raise ExternalValidationAdapterError("hosted check snapshot is not a passing evaluation")
        object.__setattr__(self, "evaluation", evaluation)
        object.__setattr__(
            self, "evaluation_identity",
            _hosted_check_evaluation_identity(self.policy, evaluation, self.evaluated_at),
        )

    def public_payload(self) -> dict[str, object]:
        evidence = self.evidence
        return {
            "repository": evidence.repository, "workflow": evidence.workflow,
            "ref": self.ref, "branch": evidence.branch,
            "candidate_sha": evidence.candidate_sha, "observed_at": evidence.observed_at,
            "evaluated_at": self.evaluated_at,
            "workflow_run_id": self.workflow_run_id, "check_suite_id": self.check_suite_id,
            "checks": [
                {"check_id": item.check_id, "suite_id": item.suite_id, "name": item.name,
                 "state": item.state.value, "head_sha": item.head_sha, "checked_out_sha": item.checked_out_sha}
                for item in evidence.checks
            ],
            "workflow_runs": [
                {"run_id": run.run_id, "workflow": run.workflow, "state": run.state.value,
                 "head_sha": run.head_sha, "ref": run.ref,
                 "jobs": [{"job_id": job.job_id, "name": job.name, "state": job.state.value,
                           "checked_out_sha": job.checked_out_sha} for job in run.jobs]}
                for run in evidence.workflow_runs
            ],
            "artifacts": [{"name": name, "digest": digest} for name, digest in evidence.artifacts],
            "policy": _hosted_check_policy_payload(self.policy),
            "evaluation": {"outcome": self.evaluation.outcome.value,
                           "candidate_sha": self.evaluation.candidate_sha,
                           "required_checks": list(self.evaluation.required_checks),
                           "observed_checks": list(self.evaluation.observed_checks),
                           "evidence_digest": self.evaluation.evidence_digest,
                           "workflow_run_id": self.evaluation.workflow_run_id,
                           "check_suite_id": self.evaluation.check_suite_id,
                           "evaluation_identity": self.evaluation_identity},
        }


def _hosted_check_policy_payload(policy: HostedCheckPolicy) -> dict[str, object]:
    return {"required_checks": list(policy.required_checks),
            "required_artifacts": list(policy.required_artifacts),
            "max_age_seconds": policy.max_age_seconds}


def _safe_hosted_name(value: object) -> bool:
    """Match the public hosted-policy name grammar without accepting controls."""

    return type(value) is str and bool(re.fullmatch(r"[^\x00-\x1f\x7f]{1,256}", value))


def _hosted_check_evaluation_identity(
    policy: HostedCheckPolicy, evaluation: HostedCheckEvaluation, evaluated_at: int,
) -> str:
    return _digest({
        "schema": "roundwright-hosted-check-evaluation/v1",
        "policy": _hosted_check_policy_payload(policy),
        "evidence_digest": evaluation.evidence_digest,
        "evaluated_at": evaluated_at,
    })


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
    workflow_run_id: str
    check_suite_id: str
    required_checks: tuple[str, ...]
    required_artifacts: tuple[str, ...]
    max_age_seconds: int
    evaluated_at: int
    schema: str = "roundwright-hosted-check-runtime/v1"

    @classmethod
    def parse(cls, value: object) -> "HostedCheckRuntimeDescriptor":
        if type(value) not in (dict, MappingProxyType):
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")
        raw = dict(value)
        expected = {
            "schema", "repository", "workflow", "ref", "branch", "base_sha",
            "candidate_sha", "capture_plan_digest", "case_id", "ready_at", "pull_request",
            "workflow_run_id", "check_suite_id",
            "required_checks", "required_artifacts", "max_age_seconds", "evaluated_at",
        }
        if set(raw) != expected:
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")
        try:
            if type(raw["required_checks"]) not in (list, tuple) or type(raw["required_artifacts"]) not in (list, tuple):
                raise TypeError("hosted check policy collections must be arrays or frozen tuples")
            raw["required_checks"] = tuple(raw["required_checks"])
            raw["required_artifacts"] = tuple(raw["required_artifacts"])
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
            or not _safe_token(self.workflow_run_id) or not _safe_token(self.check_suite_id)
            or type(self.required_checks) is not tuple or not self.required_checks
            or any(not _safe_hosted_name(value) for value in self.required_checks)
            or tuple(sorted(self.required_checks)) != self.required_checks
            or len(set(self.required_checks)) != len(self.required_checks)
            or type(self.required_artifacts) is not tuple
            or any(not _safe_token(value) for value in self.required_artifacts)
            or tuple(sorted(self.required_artifacts)) != self.required_artifacts
            or len(set(self.required_artifacts)) != len(self.required_artifacts)
            or type(self.max_age_seconds) is not int or not 0 <= self.max_age_seconds <= 86_400
            or type(self.evaluated_at) is not int or self.evaluated_at != self.ready_at
        ):
            raise ExternalValidationAdapterError("hosted check runtime descriptor is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "repository": self.repository, "workflow": self.workflow,
            "ref": self.ref, "branch": self.branch, "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "capture_plan_digest": self.capture_plan_digest, "case_id": self.case_id,
            "ready_at": self.ready_at, "pull_request": self.pull_request,
            "workflow_run_id": self.workflow_run_id, "check_suite_id": self.check_suite_id,
            "required_checks": list(self.required_checks), "required_artifacts": list(self.required_artifacts),
            "max_age_seconds": self.max_age_seconds, "evaluated_at": self.evaluated_at,
        }

    @property
    def policy(self) -> HostedCheckPolicy:
        return HostedCheckPolicy(self.required_checks, self.required_artifacts, self.max_age_seconds)


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


def _bound_hosted_check_evaluation(
    binding: object,
    snapshot: HostedCheckSnapshot,
    context: MaterializedHostedCheckContext,
) -> HostedCheckEvaluation:
    """Re-evaluate a typed observation against the immutable V2 context."""

    descriptor = context.descriptor
    if (
        snapshot.evidence.candidate_sha != binding.candidate_sha
        or (snapshot.evidence.repository, snapshot.evidence.workflow, snapshot.ref, snapshot.evidence.branch)
        != (descriptor.repository, descriptor.workflow, descriptor.ref, descriptor.branch)
        or (snapshot.workflow_run_id, snapshot.check_suite_id)
        != (descriptor.workflow_run_id, descriptor.check_suite_id)
    ):
        raise ExternalValidationAdapterError("hosted check snapshot candidate has drifted")
    if snapshot.policy != descriptor.policy:
        raise ExternalValidationAdapterError("hosted check snapshot policy has drifted")
    if snapshot.evaluated_at != descriptor.evaluated_at:
        raise ExternalValidationAdapterError("hosted check snapshot evaluation time has drifted")
    try:
        evaluation = evaluate_hosted_check_evidence(
            snapshot.evidence, repository=descriptor.repository, workflow=descriptor.workflow,
            candidate_sha=binding.candidate_sha, branch=descriptor.branch,
            policy=descriptor.policy, now=descriptor.evaluated_at,
            workflow_run_id=descriptor.workflow_run_id, check_suite_id=descriptor.check_suite_id,
        )
    except ValueError as error:
        raise ExternalValidationAdapterError("hosted check snapshot evaluation is invalid") from error
    if (
        evaluation.outcome is not HostedEvidenceOutcome.PASS
        or evaluation != snapshot.evaluation
        or snapshot.evaluation_identity
        != _hosted_check_evaluation_identity(descriptor.policy, evaluation, descriptor.evaluated_at)
    ):
        raise ExternalValidationAdapterError("hosted check snapshot evaluation has drifted")
    return evaluation


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
        _bound_hosted_check_evaluation(binding, snapshot, context)
        return _harness_executor().ProfileExecution(
            {"schema": HOSTED_CHECK_SCHEMA, "binding_identity": identity, "snapshot": snapshot},
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        identity = _hosted_check_binding_identity(binding)
        context = _hosted_check_context(binding)
        try:
            value, mutation_count = execution.value, execution.mutation_count
            snapshot = value["snapshot"]
        except (AttributeError, KeyError, TypeError) as error:
            raise ExternalValidationAdapterError("hosted check result is invalid") from error
        if (
            type(value) is not dict or value.get("schema") != HOSTED_CHECK_SCHEMA
            or value.get("binding_identity") != identity or type(snapshot) is not HostedCheckSnapshot
            or mutation_count != 0 or snapshot.evidence.candidate_sha != binding.candidate_sha
        ):
            raise ExternalValidationAdapterError("hosted check result has drifted")
        _bound_hosted_check_evaluation(binding, snapshot, context)
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
        status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        return _harness_executor().ProfileComparison(status, _digest({
            "schema": HOSTED_CHECK_SCHEMA, "status": status,
            "ready_at": binding.ready_at, "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
        }))


_LIVE_LIFECYCLE_FIXTURES = (
    "umbrella", "standalone", "ignored", "malformed-parent-owner-input",
    "dependency", "merged-pr", "supervisor-failover",
)
_LIVE_LIFECYCLE_SNAPSHOTS = (
    "repository", "issues", "scheduling", "pull-requests", "comments",
    "roundlet-trace", "candidates", "reviews", "checks", "merge", "cleanup",
)
_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES = 16

_LIVE_LIFECYCLE_CATEGORY_SECTIONS = {
    "repository": (RepositoryInventorySection.REPOSITORY,),
    "issues": (RepositoryInventorySection.ISSUES,),
    "scheduling": (RepositoryInventorySection.ISSUE_RELATIONSHIPS, RepositoryInventorySection.ISSUE_LABELS),
    "pull-requests": (RepositoryInventorySection.PULL_REQUESTS,),
    "comments": (RepositoryInventorySection.COMMENTS,),
    "roundlet-trace": (RepositoryInventorySection.COMMENTS,),
    "candidates": (RepositoryInventorySection.PULL_REQUESTS, RepositoryInventorySection.REMOTE_HEADS),
    "reviews": (RepositoryInventorySection.REVIEWS, RepositoryInventorySection.REQUESTED_REVIEWERS),
    "checks": (RepositoryInventorySection.CHECKS, RepositoryInventorySection.WORKFLOW_RUNS),
    "merge": (RepositoryInventorySection.MERGEABILITY, RepositoryInventorySection.CLOSING_REFERENCES),
    "cleanup": (RepositoryInventorySection.REMOTE_HEADS,),
}


@dataclass(frozen=True)
class _FixtureOutcome:
    """One typed, public-safe Roundlet fixture outcome at ``ready_at``."""

    fixture: str
    classification: str
    dependencies: str
    attempt_accounting: str
    state: str
    gates: str
    blockers: str
    next_action: str

    def __post_init__(self) -> None:
        if (
            self.fixture not in _LIVE_LIFECYCLE_FIXTURES
            or not all(_safe_token(value) for value in (
                self.classification, self.dependencies, self.attempt_accounting,
                self.state, self.gates, self.blockers, self.next_action,
            ))
        ):
            raise ExternalValidationAdapterError("live lifecycle fixture outcome is invalid")


@dataclass(frozen=True)
class FixtureSelectionManifest:
    """Closed owner-reviewed selectors and expectations bound into V2 context.

    Expectations are supplied externally and remain independent of observed
    inventory/lifecycle facts.  The product validates their shape and digest,
    then derives observations only from its own normalizer/classifier and the
    verified lifecycle ledger.
    """

    value: Mapping[str, object]
    manifest_digest: str
    raw_utf8: bytes | None = field(default=None, repr=False, compare=False)

    @classmethod
    def parse(cls, raw_utf8: object, manifest_digest: object) -> "FixtureSelectionManifest":
        """Verify owner-sealed UTF-8 bytes before decoding the manifest."""

        if type(raw_utf8) is not bytes or type(manifest_digest) is not str:
            raise ExternalValidationAdapterError("fixture manifest is invalid")
        if len(raw_utf8) > 65_536 or "sha256:" + hashlib.sha256(raw_utf8).hexdigest() != manifest_digest:
            raise ExternalValidationAdapterError("fixture manifest digest has drifted")
        try:
            def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
                value: dict[str, object] = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate key")
                    value[key] = item
                return value
            value = json.loads(raw_utf8.decode("utf-8"), object_pairs_hook=reject_duplicates)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise ExternalValidationAdapterError("fixture manifest is invalid") from error
        if type(value) is not dict:
            raise ExternalValidationAdapterError("fixture manifest is invalid")
        return cls(MappingProxyType(value), manifest_digest, raw_utf8)

    @classmethod
    def from_projection(cls, value: object, manifest_digest: object) -> "FixtureSelectionManifest":
        """Rehydrate a checked public projection; it is not an owner seal."""

        if type(value) not in (dict, MappingProxyType) or type(manifest_digest) is not str:
            raise ExternalValidationAdapterError("fixture manifest is invalid")
        copied = cls._thaw(value)
        if type(copied) is not dict:
            raise ExternalValidationAdapterError("fixture manifest is invalid")
        return cls(MappingProxyType(copied), manifest_digest)

    @staticmethod
    def _freeze(value: object) -> object:
        if type(value) is dict:
            return MappingProxyType({key: FixtureSelectionManifest._freeze(item) for key, item in value.items()})
        if type(value) is list:
            return tuple(FixtureSelectionManifest._freeze(item) for item in value)
        return value

    @staticmethod
    def _thaw(value: object) -> object:
        if type(value) is MappingProxyType:
            return {key: FixtureSelectionManifest._thaw(item) for key, item in value.items()}
        if type(value) is tuple:
            return [FixtureSelectionManifest._thaw(item) for item in value]
        return value

    def __post_init__(self) -> None:
        raw = dict(self.value) if type(self.value) is MappingProxyType else None
        contract = lifecycle_observation.lifecycle_observation_contract()
        required = {"schema", "run_id", "contract_id", "leaf", "target", "binding", "authority", "fixtures"}
        if (
            raw is None or set(raw) != required
            or raw.get("schema") != "roundlet-owner-reviewed-fixture-selection-expectation-manifest/v1"
            or not _safe_token(raw.get("run_id"))
            or type(raw.get("contract_id")) is not str or re.fullmatch(r"[0-9a-f]{64}", raw["contract_id"]) is None
            or type(raw.get("leaf")) is not int or raw["leaf"] < 1
            or _DIGEST.fullmatch(self.manifest_digest) is None
            or (self.raw_utf8 is not None and (
                type(self.raw_utf8) is not bytes
                or "sha256:" + hashlib.sha256(self.raw_utf8).hexdigest() != self.manifest_digest
            ))
            or type(raw.get("target")) is not dict
            or set(raw["target"]) != {"repository", "baseline_sha"}
            or raw["target"].get("repository") != "ythdelmar68/roundlet-forward-test"
            or _SHA.fullmatch(raw["target"].get("baseline_sha", "")) is None
            or type(raw.get("binding")) is not dict
            or set(raw["binding"]) != {
                "authoritative_extension_point", "capture_observation_identity_must_commit_manifest_digest",
                "lifecycle_contract_identity", "lifecycle_contract_identity_must_remain_unchanged",
            }
            or raw["binding"].get("authoritative_extension_point") != "roundwright-harness-profile-executor-request/v2.execution_context"
            or raw["binding"].get("capture_observation_identity_must_commit_manifest_digest") is not True
            or raw["binding"].get("lifecycle_contract_identity") != contract["contract_identity"]
            or raw["binding"].get("lifecycle_contract_identity_must_remain_unchanged") is not True
            or type(raw.get("authority")) is not dict
            or set(raw["authority"]) != {
                "effect", "owner_allowlist", "repository_mutation", "target_mutation", "trace_publisher_identity",
            }
            or raw["authority"].get("effect") != "external-owner-reviewed-reference-decision"
            or raw["authority"].get("repository_mutation") is not False
            or raw["authority"].get("target_mutation") is not False
            or type(raw["authority"].get("owner_allowlist")) is not list
            or raw["authority"]["owner_allowlist"] != ["ythdelmar68"]
            or raw["authority"].get("trace_publisher_identity") != "user:ythdelmar68"
            or type(raw.get("fixtures")) is not list or len(raw["fixtures"]) != len(_LIVE_LIFECYCLE_FIXTURES)
        ):
            raise ExternalValidationAdapterError("fixture manifest is invalid")
        fixtures: dict[str, object] = {}
        selectors: set[tuple[object, ...]] = set()
        for item in raw["fixtures"]:
            if type(item) is not dict or set(item) != {"fixture", "selector", "expectation"}:
                raise ExternalValidationAdapterError("fixture manifest is invalid")
            fixture, selector, expectation = item["fixture"], item["selector"], item["expectation"]
            if fixture not in _LIVE_LIFECYCLE_FIXTURES or fixture in fixtures or type(selector) is not dict or type(expectation) is not dict:
                raise ExternalValidationAdapterError("fixture manifest is invalid")
            if set(expectation) != {"classification", "dependencies", "attempt_accounting", "state", "gates", "blockers", "next_action"}:
                raise ExternalValidationAdapterError("fixture manifest is invalid")
            try:
                _FixtureOutcome(fixture, **expectation)
            except (TypeError, ExternalValidationAdapterError) as error:
                raise ExternalValidationAdapterError("fixture manifest is invalid") from error
            if fixture == "supervisor-failover":
                if set(selector) != {"kind", "attempts"} or selector.get("kind") != "sealed-lifecycle-attempt-sequence" or type(selector.get("attempts")) is not list or len(selector["attempts"]) != 3:
                    raise ExternalValidationAdapterError("fixture manifest is invalid")
                attempts = []
                for ordinal, attempt in enumerate(selector["attempts"], 1):
                    if type(attempt) is not dict or set(attempt) != {"ordinal", "model", "reasoning", "disposition"} or attempt.get("ordinal") != ordinal or not all(_safe_token(attempt.get(field)) for field in ("model", "reasoning", "disposition")):
                        raise ExternalValidationAdapterError("fixture manifest is invalid")
                    attempts.append((attempt["model"], attempt["reasoning"], attempt["disposition"]))
                if len(set(attempts)) != len(attempts):
                    raise ExternalValidationAdapterError("fixture manifest is invalid")
            else:
                if set(selector) != {"kind", "number"} or selector.get("kind") not in {"issue", "pull-request"} or type(selector.get("number")) is not int or selector["number"] < 1:
                    raise ExternalValidationAdapterError("fixture manifest is invalid")
                key = (selector["kind"], selector["number"])
                if key in selectors:
                    raise ExternalValidationAdapterError("fixture manifest selectors conflict")
                selectors.add(key)
            fixtures[fixture] = item
        if tuple(fixtures) != _LIVE_LIFECYCLE_FIXTURES:
            raise ExternalValidationAdapterError("fixture manifest is incomplete")
        object.__setattr__(self, "value", self._freeze(raw))

    @property
    def is_owner_sealed(self) -> bool:
        return self.raw_utf8 is not None

    @property
    def target_repository(self) -> str:
        return self.value["target"]["repository"]  # type: ignore[index]

    @property
    def target_baseline_sha(self) -> str:
        return self.value["target"]["baseline_sha"]  # type: ignore[index]

    @property
    def trace_publisher_identity(self) -> str:
        return self.value["authority"]["trace_publisher_identity"]  # type: ignore[index]

    def selector_map(self) -> dict[str, tuple[str, int]]:
        return {
            item["fixture"]: (item["selector"]["kind"], item["selector"]["number"])
            for item in self.value["fixtures"]  # type: ignore[index]
            if item["fixture"] != "supervisor-failover"
        }

    def expected_outcomes(self) -> tuple[_FixtureOutcome, ...]:
        return tuple(_FixtureOutcome(item["fixture"], **item["expectation"]) for item in self.value["fixtures"])  # type: ignore[index]

    def supervisor_attempts(self) -> tuple[tuple[str, str, str], ...]:
        item = next(item for item in self.value["fixtures"] if item["fixture"] == "supervisor-failover")  # type: ignore[index]
        return tuple((attempt["model"], attempt["reasoning"], attempt["disposition"]) for attempt in item["selector"]["attempts"])

    def payload(self) -> dict[str, object]:
        value = self._thaw(self.value)
        assert type(value) is dict
        return value


@dataclass(frozen=True)
class LiveLifecycleShadowSnapshot:
    """One public-safe, armed read-only lifecycle observation.

    The snapshot carries only normalized identifiers and digests.  Raw GitHub
    responses, local paths, credentials, and provider output stay with the
    repository-owned Recorder and can never enter the profile projection.
    """

    target_repository: str
    target_baseline_sha: str
    target_observed_sha: str
    candidate_sha: str
    capture_plan_digest: str
    case_id: str
    observation_window: str
    ready_at: int
    lifecycle_projection: lifecycle_observation.LifecycleShadowProjection
    snapshot_digests: Mapping[str, str]
    fixture_classes: tuple[str, ...]
    classified_differences: tuple[str, ...]
    before_target_state_digest: str
    after_target_state_digest: str
    zero_mutation_readback_digest: str = field(init=False)

    def __post_init__(self) -> None:
        snapshots = dict(self.snapshot_digests) if type(self.snapshot_digests) in (dict, MappingProxyType) else None
        if (
            self.target_repository != "ythdelmar68/roundlet-forward-test"
            or _SHA.fullmatch(self.target_baseline_sha) is None
            or self.target_observed_sha != self.target_baseline_sha
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or not _safe_token(self.case_id)
            or not _safe_token(self.observation_window)
            or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.lifecycle_projection) is not lifecycle_observation.LifecycleShadowProjection
            or snapshots is None or set(snapshots) != set(_LIVE_LIFECYCLE_SNAPSHOTS)
            or any(_DIGEST.fullmatch(value) is None for value in snapshots.values())
            or type(self.fixture_classes) is not tuple
            or any(item not in _LIVE_LIFECYCLE_FIXTURES for item in self.fixture_classes)
            or len(set(self.fixture_classes)) != len(self.fixture_classes)
            or self.fixture_classes != tuple(item for item in _LIVE_LIFECYCLE_FIXTURES if item in self.fixture_classes)
            or type(self.classified_differences) is not tuple
            or any(not _safe_token(value) for value in self.classified_differences)
            or len(set(self.classified_differences)) != len(self.classified_differences)
            or self.classified_differences != tuple(sorted(self.classified_differences))
            or len(self.classified_differences) > _LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES
            or _DIGEST.fullmatch(self.before_target_state_digest) is None
            or self.after_target_state_digest != self.before_target_state_digest
        ):
            raise ExternalValidationAdapterError("live lifecycle snapshot is invalid")
        if (
            self.lifecycle_projection.candidate_sha != self.candidate_sha
            or self.lifecycle_projection.ready_at != self.ready_at
            or self.lifecycle_projection.review_epoch < 1
            or self.lifecycle_projection.review_round < 1
            or self.lifecycle_projection.review_mode not in {"complete", "converging"}
            or not self.lifecycle_projection.events
        ):
            raise ExternalValidationAdapterError("verified live lifecycle projection has drifted")
        object.__setattr__(self, "snapshot_digests", MappingProxyType(snapshots))
        object.__setattr__(self, "zero_mutation_readback_digest", _digest({
            "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA,
            "target_repository": self.target_repository,
            "target_baseline_sha": self.target_baseline_sha,
            "target_observed_sha": self.target_observed_sha,
            "before_target_state_digest": self.before_target_state_digest,
            "after_target_state_digest": self.after_target_state_digest,
        }))

    def public_payload(self) -> dict[str, object]:
        return {
            "target_repository": self.target_repository,
            "target_baseline_sha": self.target_baseline_sha,
            "target_observed_sha": self.target_observed_sha,
            "observation_window": self.observation_window,
            "ready_at": self.ready_at,
            "snapshot_digests": dict(self.snapshot_digests),
            "fixture_classes": list(self.fixture_classes),
            "classified_differences": list(self.classified_differences),
            "classified_difference_count": len(self.classified_differences),
            "verified_lifecycle": {
                "ledger_digest": self.lifecycle_projection.ledger_digest,
                "plan_digest": self.lifecycle_projection.plan_digest,
                "window_identity": self.lifecycle_projection.window_identity,
                "candidate_sha": self.lifecycle_projection.candidate_sha,
                "ready_at": self.lifecycle_projection.ready_at,
                "review_epoch": self.lifecycle_projection.review_epoch,
                "review_round": self.lifecycle_projection.review_round,
                "event_digest": _digest(self.lifecycle_projection.semantic_payload()),
            },
            "zero_mutation_readback_digest": self.zero_mutation_readback_digest,
        }


@dataclass(frozen=True)
class LiveLifecycleRuntimeDescriptor:
    """Closed V2 context that pins one public target/window before arming."""

    target_repository: str
    target_baseline_sha: str
    candidate_sha: str
    capture_plan_digest: str
    case_id: str
    observation_window: str
    ready_at: int
    fixture_manifest: FixtureSelectionManifest
    trace_repository: str = "ythdelmar68/roundwright"
    trace_pull_request: int = 85
    trace_publisher_identity: str | None = None
    schema: str = "roundwright-live-lifecycle-runtime/v2"

    @classmethod
    def parse(cls, value: object) -> "LiveLifecycleRuntimeDescriptor":
        if type(value) not in (dict, MappingProxyType):
            raise ExternalValidationAdapterError("live lifecycle runtime descriptor is invalid")
        raw = dict(value)
        if set(raw) != {
            "schema", "target_repository", "target_baseline_sha", "candidate_sha",
            "capture_plan_digest", "case_id", "observation_window", "ready_at", "fixture_manifest", "fixture_manifest_digest",
            "trace_repository", "trace_pull_request", "trace_publisher_identity",
        }:
            raise ExternalValidationAdapterError("live lifecycle runtime descriptor is invalid")
        try:
            raw["fixture_manifest"] = FixtureSelectionManifest.from_projection(
                raw["fixture_manifest"], raw.pop("fixture_manifest_digest"),
            )
            return cls(**raw)
        except (TypeError, ValueError) as error:
            raise ExternalValidationAdapterError("live lifecycle runtime descriptor is invalid") from error

    def __post_init__(self) -> None:
        if (
            self.schema != "roundwright-live-lifecycle-runtime/v2"
            or self.target_repository != "ythdelmar68/roundlet-forward-test"
            or _SHA.fullmatch(self.target_baseline_sha) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or not _safe_token(self.case_id) or not _safe_token(self.observation_window)
            or type(self.ready_at) is not int or self.ready_at < 0
            or self.trace_repository != "ythdelmar68/roundwright"
            or self.trace_pull_request != 85
            or not _trace_publisher_identity(self.trace_publisher_identity)
            or type(self.fixture_manifest) is not FixtureSelectionManifest
            or (self.fixture_manifest.target_repository, self.fixture_manifest.target_baseline_sha)
            != (self.target_repository, self.target_baseline_sha)
            or self.trace_publisher_identity != self.fixture_manifest.trace_publisher_identity
        ):
            raise ExternalValidationAdapterError("live lifecycle runtime descriptor is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "target_repository": self.target_repository,
            "target_baseline_sha": self.target_baseline_sha,
            "candidate_sha": self.candidate_sha, "capture_plan_digest": self.capture_plan_digest,
            "case_id": self.case_id, "observation_window": self.observation_window,
            "ready_at": self.ready_at, "fixture_manifest": self.fixture_manifest.payload(),
            "fixture_manifest_digest": self.fixture_manifest.manifest_digest,
            "trace_repository": self.trace_repository, "trace_pull_request": self.trace_pull_request,
            "trace_publisher_identity": self.trace_publisher_identity,
        }


@dataclass(frozen=True)
class MaterializedLiveLifecycleContext:
    descriptor: LiveLifecycleRuntimeDescriptor

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-live-lifecycle-context/v1", "descriptor": self.descriptor.payload()})


@dataclass(frozen=True)
class LiveLifecycleLedgerBinding:
    """Public-safe locator for the exact ledger sealed before the live read."""

    plan: Mapping[str, object]
    ledger_digest: str

    def __post_init__(self) -> None:
        plan = dict(self.plan) if type(self.plan) in (dict, MappingProxyType) else None
        if plan is None or _DIGEST.fullmatch(self.ledger_digest) is None:
            raise ExternalValidationAdapterError("live lifecycle ledger binding is invalid")
        try:
            lifecycle_observation._validated_plan(plan)
        except lifecycle_observation.LifecycleObservationError as error:
            raise ExternalValidationAdapterError("live lifecycle ledger binding is invalid") from error
        object.__setattr__(self, "plan", MappingProxyType(plan))

    @property
    def plan_digest(self) -> str:
        return lifecycle_observation._digest(dict(self.plan))

    def public_payload(self) -> dict[str, object]:
        return {"plan": dict(self.plan), "ledger_digest": self.ledger_digest}


@dataclass(frozen=True)
class LiveLifecycleRequestInputs:
    """Already-bound public primitives accepted at the opaque preflight boundary."""

    base_sha: str
    candidate_sha: str
    target_repository: str
    target_baseline_sha: str
    case_id: str
    observation_window: str
    ready_at: int
    recorder_commit: str
    recorder_content: str
    recorder_tree: str
    retention_namespace: str
    lifecycle_ledger: LiveLifecycleLedgerBinding
    fixture_manifest: FixtureSelectionManifest | None = None
    trace_repository: str = "ythdelmar68/roundwright"
    trace_pull_request: int = 85
    trace_publisher_identity: str | None = None

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.base_sha) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or self.target_repository != "ythdelmar68/roundlet-forward-test"
            or _SHA.fullmatch(self.target_baseline_sha) is None
            or not _safe_token(self.case_id) or not _safe_token(self.observation_window)
            or type(self.ready_at) is not int or self.ready_at < 0
            or any(_SHA.fullmatch(value) is None for value in (
                self.recorder_commit, self.recorder_content, self.recorder_tree,
            ))
            or not _safe_token(self.retention_namespace)
            or type(self.lifecycle_ledger) is not LiveLifecycleLedgerBinding
            or (self.fixture_manifest is not None and type(self.fixture_manifest) is not FixtureSelectionManifest)
            or self.trace_repository != "ythdelmar68/roundwright"
            or self.trace_pull_request != 85
            or not _trace_publisher_identity(self.trace_publisher_identity)
            or (
                self.lifecycle_ledger.plan["candidate_sha"], self.lifecycle_ledger.plan["ready_at"]
            ) != (self.candidate_sha, self.ready_at)
        ):
            raise ExternalValidationAdapterError("live lifecycle request inputs are invalid")


@dataclass(frozen=True)
class LiveLifecyclePreparedRequest:
    """Sealed request material consumed only by the product-owned run entrypoint."""

    inputs: LiveLifecycleRequestInputs
    capture_plan_digest: str
    request_digest: str
    recorder_identity: str
    store_root_identity: str
    store_identity: str
    observation_identity: str
    _request_value: Mapping[str, object] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.inputs) is not LiveLifecycleRequestInputs
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.capture_plan_digest, self.request_digest, self.recorder_identity,
                self.store_root_identity, self.store_identity, self.observation_identity,
            ))
            or type(self._request_value) is not MappingProxyType
        ):
            raise ExternalValidationAdapterError("live lifecycle prepared request is invalid")

    def public_receipt(self) -> dict[str, object]:
        return {
            "schema": "roundwright-live-lifecycle-prepared-request/v1",
            "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
            "base_sha": self.inputs.base_sha,
            "candidate_sha": self.inputs.candidate_sha,
            "trace_repository": self.inputs.trace_repository,
            "trace_pull_request": self.inputs.trace_pull_request,
            "trace_publisher_identity": self.inputs.trace_publisher_identity,
            "case_id": self.inputs.case_id,
            "observation_window": self.inputs.observation_window,
            "ready_at": self.inputs.ready_at,
            "lifecycle_plan_digest": self.inputs.lifecycle_ledger.plan_digest,
            "lifecycle_ledger_digest": self.inputs.lifecycle_ledger.ledger_digest,
            "capture_plan_digest": self.capture_plan_digest,
            "request_digest": self.request_digest,
            "recorder_identity": self.recorder_identity,
            "store_identity": self.store_identity,
            "observation_identity": self.observation_identity,
        }


_LIVE_LIFECYCLE_READINESS_SEAL = object()
_LIVE_LIFECYCLE_READY_CAPSULE_SEAL = object()


@dataclass(frozen=True)
class LiveLifecycleReadinessReceipt:
    """Path-free V2 readiness facts copied from the reviewed Harness receipt."""

    capture_plan_digest: str
    candidate_sha: str
    case_id: str
    ready_at: int
    producer_identity: str
    exporter_identity: str
    comparator_identity: str
    execution_context_input_digest: str
    execution_context_identity: str
    receipt_digest: str
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if (
            self._seal is not _LIVE_LIFECYCLE_READINESS_SEAL
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or not _safe_token(self.case_id)
            or type(self.ready_at) is not int or self.ready_at < 0
            or any(_DIGEST.fullmatch(value) is None for value in (
                self.producer_identity, self.exporter_identity, self.comparator_identity,
                self.execution_context_input_digest, self.execution_context_identity,
                self.receipt_digest,
            ))
            or self.receipt_digest != _digest({
                "schema": "roundwright-harness-profile-executor-readiness/v2",
                "status": "ready", "state": "PREFLIGHT_READY",
                "plan_digest": self.capture_plan_digest,
                "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
                "case_id": self.case_id, "candidate_sha": self.candidate_sha,
                "ready_at": self.ready_at,
                "producer_identity": self.producer_identity,
                "exporter_identity": self.exporter_identity,
                "comparator_identity": self.comparator_identity,
                "dispatch_count": 0, "record_count": 0, "verify_count": 0, "mutation_count": 0,
                "execution_context_input_digest": self.execution_context_input_digest,
                "execution_context_identity": self.execution_context_identity,
            })
        ):
            raise ExternalValidationAdapterError("live lifecycle readiness receipt is invalid")

    def public_receipt(self) -> dict[str, object]:
        return {
            "schema": "roundwright-live-lifecycle-readiness/v1",
            "capture_plan_digest": self.capture_plan_digest,
            "candidate_sha": self.candidate_sha,
            "case_id": self.case_id,
            "ready_at": self.ready_at,
            "producer_identity": self.producer_identity,
            "exporter_identity": self.exporter_identity,
            "comparator_identity": self.comparator_identity,
            "execution_context_input_digest": self.execution_context_input_digest,
            "execution_context_identity": self.execution_context_identity,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class LiveLifecycleSessionReceipt:
    """Path-free handle for one durable, trace-gated lifecycle session."""

    session_id: str
    readiness: LiveLifecycleReadinessReceipt
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        payload = {
            "schema": "roundwright-live-lifecycle-session-receipt/v1",
            "session_id": self.session_id,
            "readiness": self.readiness.public_receipt(),
        }
        digest = _digest(payload)
        if (
            _DIGEST.fullmatch(self.session_id) is None
            or type(self.readiness) is not LiveLifecycleReadinessReceipt
            or self.readiness._seal is not _LIVE_LIFECYCLE_READINESS_SEAL
            or (self.receipt_digest and self.receipt_digest != digest)
        ):
            raise ExternalValidationAdapterError("live lifecycle session receipt is invalid")
        object.__setattr__(self, "receipt_digest", digest)

    def public_receipt(self) -> dict[str, object]:
        return {
            "schema": "roundwright-live-lifecycle-session-receipt/v1",
            "session_id": self.session_id,
            "readiness": self.readiness.public_receipt(),
            "receipt_digest": self.receipt_digest,
        }

    @classmethod
    def parse(cls, value: object) -> "LiveLifecycleSessionReceipt":
        if (
            type(value) is not dict or set(value) != {"schema", "session_id", "readiness", "receipt_digest"}
            or value["schema"] != "roundwright-live-lifecycle-session-receipt/v1"
        ):
            raise ExternalValidationAdapterError("live lifecycle session receipt is invalid")
        readiness_value = value["readiness"]
        if (
            type(readiness_value) is not dict or set(readiness_value) != {
            "schema", "capture_plan_digest", "candidate_sha", "case_id", "ready_at",
            "producer_identity", "exporter_identity", "comparator_identity",
            "execution_context_input_digest", "execution_context_identity", "receipt_digest",
            } or readiness_value["schema"] != "roundwright-live-lifecycle-readiness/v1"
        ):
            raise ExternalValidationAdapterError("live lifecycle session receipt is invalid")
        try:
            readiness = LiveLifecycleReadinessReceipt(
                readiness_value["capture_plan_digest"], readiness_value["candidate_sha"],
                readiness_value["case_id"], readiness_value["ready_at"],
                readiness_value["producer_identity"], readiness_value["exporter_identity"],
                readiness_value["comparator_identity"], readiness_value["execution_context_input_digest"],
                readiness_value["execution_context_identity"], readiness_value["receipt_digest"],
                _LIVE_LIFECYCLE_READINESS_SEAL,
            )
            return cls(value["session_id"], readiness, value["receipt_digest"])
        except (TypeError, ValueError) as error:
            raise ExternalValidationAdapterError("live lifecycle session receipt is invalid") from error


@dataclass(frozen=True)
class _LiveLifecycleReadyCapsule:
    """One sealed product preflight binding, consumed at most once."""

    prepared_request: LiveLifecyclePreparedRequest
    readiness: LiveLifecycleReadinessReceipt
    capsule_digest: str = ""
    _consumed: bool = field(default=False, repr=False, compare=False)
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        payload = {
            "schema": "roundwright-live-lifecycle-ready-capsule/v1",
            "request_digest": self.prepared_request.request_digest,
            "capture_plan_digest": self.prepared_request.capture_plan_digest,
            "store_identity": self.prepared_request.store_identity,
            "readiness": self.readiness.public_receipt(),
        }
        digest = _digest(payload)
        if (
            self._seal is not _LIVE_LIFECYCLE_READY_CAPSULE_SEAL
            or type(self.prepared_request) is not LiveLifecyclePreparedRequest
            or type(self.readiness) is not LiveLifecycleReadinessReceipt
            or type(self._consumed) is not bool
            or (self.capsule_digest and self.capsule_digest != digest)
        ):
            raise ExternalValidationAdapterError("live lifecycle ready capsule is invalid")
        object.__setattr__(self, "capsule_digest", digest)

    def public_receipt(self) -> dict[str, object]:
        return {
            "schema": "roundwright-live-lifecycle-ready-capsule/v1",
            "capsule_digest": self.capsule_digest,
            "readiness": self.readiness.public_receipt(),
        }


@dataclass(frozen=True)
class _LiveLifecycleTargetState:
    """Normalized target identity from one independent read-only observation."""

    target_repository: str
    target_sha: str
    state_digest: str

    def __post_init__(self) -> None:
        if (
            self.target_repository != "ythdelmar68/roundlet-forward-test"
            or _SHA.fullmatch(self.target_sha) is None
            or _DIGEST.fullmatch(self.state_digest) is None
        ):
            raise ExternalValidationAdapterError("live lifecycle target state is invalid")


@dataclass(frozen=True)
class _LiveLifecycleProviderObservation:
    """Normalized content-free observations from an armed read-only window."""

    snapshot_digests: Mapping[str, str]
    fixture_classes: tuple[str, ...]
    classified_differences: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        snapshots = dict(self.snapshot_digests) if type(self.snapshot_digests) in (dict, MappingProxyType) else None
        if (
            snapshots is None or set(snapshots) != set(_LIVE_LIFECYCLE_SNAPSHOTS)
            or any(_DIGEST.fullmatch(value) is None for value in snapshots.values())
            or type(self.fixture_classes) is not tuple
            or any(item not in _LIVE_LIFECYCLE_FIXTURES for item in self.fixture_classes)
            or len(set(self.fixture_classes)) != len(self.fixture_classes)
            or self.fixture_classes != tuple(item for item in _LIVE_LIFECYCLE_FIXTURES if item in self.fixture_classes)
            or type(self.classified_differences) is not tuple
            or any(not _safe_token(value) for value in self.classified_differences)
            or len(set(self.classified_differences)) != len(self.classified_differences)
            or self.classified_differences != tuple(sorted(self.classified_differences))
            or len(self.classified_differences) > _LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES
        ):
            raise ExternalValidationAdapterError("live lifecycle provider observation is invalid")
        object.__setattr__(self, "snapshot_digests", MappingProxyType(snapshots))


@dataclass(frozen=True)
class _RoundletLifecycleProjection:
    """The independently specified Roundlet lifecycle fixture at ``ready_at``."""

    candidate_sha: str
    review_epoch: int
    formal_round: str
    review_mode: str
    ready_at: int


@dataclass(frozen=True)
class _RoundwrightLifecycleProjection:
    """The independently normalized Roundwright lifecycle facts at ``ready_at``."""

    candidate_sha: str
    review_epoch: int
    formal_round: str
    review_mode: str
    ready_at: int
    supervisor_attempts: tuple[tuple[str, str, str], ...]
    supervisor_sequence_valid: bool
    accepted_pass_attempt_identity: str | None


@dataclass(frozen=True)
class _RoundwrightTraceReceipt:
    """Normalized, public-safe implementation-PR Conversation evidence."""

    digest: str
    differences: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            _DIGEST.fullmatch(self.digest) is None
            or type(self.differences) is not tuple
            or any(not _safe_token(value) for value in self.differences)
            or self.differences != tuple(sorted(set(self.differences)))
        ):
            raise ExternalValidationAdapterError("Roundwright PR trace receipt is invalid")


def _roundlet_pr_conversation_marker(
    candidate_sha: str, review_epoch: int, formal_round: str, review_mode: str,
    observation_window: str, ready_at: int,
) -> str:
    """Canonical marker whose digest safely crosses the generic comments boundary."""

    if (
        _SHA.fullmatch(candidate_sha) is None
        or type(review_epoch) is not int or review_epoch < 1
        or not _safe_token(formal_round) or not _safe_token(review_mode)
        or not _safe_token(observation_window)
        or type(ready_at) is not int or ready_at < 0
    ):
        raise ExternalValidationAdapterError("Roundwright PR trace marker is invalid")
    return (
        "ROUNDLET_LIFECYCLE event=formal-result"
        f" candidate={candidate_sha} epoch={review_epoch} round={formal_round}"
        f" mode={review_mode} window={observation_window} ready_at={ready_at}"
        "\n"
    )


def _roundlet_validation_readiness_marker(
    candidate_sha: str, capture_plan_digest: str, review_epoch: int, formal_round: str,
    review_mode: str, observation_window: str, ready_at: int,
) -> str:
    """Canonical pre-review Lane A marker, distinct from a formal result."""

    if (
        _SHA.fullmatch(candidate_sha) is None
        or _DIGEST.fullmatch(capture_plan_digest) is None
        or type(review_epoch) is not int or review_epoch < 1
        or not _safe_token(formal_round) or not _safe_token(review_mode)
        or not _safe_token(observation_window)
        or type(ready_at) is not int or ready_at < 0
    ):
        raise ExternalValidationAdapterError("Roundwright validation readiness marker is invalid")
    return (
        "ROUNDLET_VALIDATION event=readiness"
        f" candidate={candidate_sha} plan={capture_plan_digest} epoch={review_epoch}"
        f" round={formal_round} mode={review_mode} window={observation_window} ready_at={ready_at}"
        "\n"
    )


def _private_supervisor_profile(artifact_references: tuple[str, ...]) -> tuple[str, str]:
    """Decode one retained Supervisor profile only for the live comparator.

    The authoritative lifecycle projection deliberately remains the reviewed
    v1 shape.  A profile is a private interpretation of an already sealed
    artifact reference: absence, duplication, and unknown references are all
    explicit missing evidence and consequently block the comparison.
    """

    if type(artifact_references) is not tuple or len(artifact_references) != 1:
        return ("missing", "missing")
    profiles = {
        lifecycle_observation.supervisor_profile_artifact("sol", "xhigh"): ("sol", "xhigh"),
        lifecycle_observation.supervisor_profile_artifact("terra", "high"): ("terra", "high"),
    }
    return profiles.get(artifact_references[0], ("missing", "missing"))


def _roundlet_lifecycle_projection(
    lifecycle: lifecycle_observation.LifecycleShadowProjection,
) -> _RoundletLifecycleProjection:
    """Project the selected, sealed formal tuple without synthetic assumptions.

    The #82 Sol/Terra failover is a retained synthetic qualification fixture;
    #49 instead compares the prospective window's actual formal tuple.
    """

    return _RoundletLifecycleProjection(
        lifecycle.candidate_sha, lifecycle.review_epoch,
        f"formal-round-{lifecycle.review_round}", lifecycle.review_mode,
        lifecycle.ready_at,
    )


def _roundwright_lifecycle_projection(
    lifecycle: lifecycle_observation.LifecycleShadowProjection,
) -> _RoundwrightLifecycleProjection:
    """Project dynamic lifecycle facts from one verified sealed ledger.

    Forward-target inventory is intentionally absent here: it establishes only
    read-only fixture coverage and before/after target state.  Candidate and
    review facts belong to the exact lifecycle ledger read back through the
    repository lifecycle-observation contract.  Model and disposition values
    are captured artifact/event facts; never infer them from ordinal or kind.
    """
    completed = tuple(
        event for event in lifecycle.events
        if event.role == "supervisor" and event.transition == "attempt_completed"
    )
    first_ordinal = completed[0].review_attempt if completed else 0
    expected_order = tuple(range(first_ordinal, first_ordinal + len(completed)))
    sequence_valid = (
        bool(completed)
        and first_ordinal > 0
        and tuple(event.review_attempt for event in completed) == expected_order
        and len({event.attempt_identity for event in completed}) == len(completed)
    )
    attempts_by_ordinal = {
        event.review_attempt: event for event in completed
    } if sequence_valid else {}
    completed_by_identity = {
        event.attempt_identity: event for event in completed
    }
    accepted_passes = tuple(
        event for event in lifecycle.events
        if (
            event.role == "supervisor"
            and event.transition == "result_accepted"
            and event.disposition == "accepted"
            and event.accepted_result
            and event.attempt_identity == lifecycle.accepted_attempt_identity
            and (completed_event := completed_by_identity.get(event.attempt_identity)) is not None
            and completed_event.disposition == "pass"
            and (completed_event.task_identity, completed_event.review_attempt)
            == (event.task_identity, event.review_attempt)
        )
    )
    accepted_pass_attempt_identity = (
        accepted_passes[0].attempt_identity if len(accepted_passes) == 1 else None
    )

    def supervisor_outcome(ordinal: int) -> tuple[str, str, str]:
        event = attempts_by_ordinal.get(ordinal)
        if event is None:
            return ("missing", "missing", "missing")
        model, reasoning = _private_supervisor_profile(event.artifact_references)
        return (model, reasoning, event.disposition.replace("_", "-"))

    return _RoundwrightLifecycleProjection(
        lifecycle.candidate_sha,
        lifecycle.review_epoch,
        f"formal-round-{lifecycle.review_round}",
        lifecycle.review_mode,
        lifecycle.ready_at,
        tuple(supervisor_outcome(ordinal) for ordinal in expected_order),
        sequence_valid,
        accepted_pass_attempt_identity,
    )


def _classified_lifecycle_differences(
    roundlet: _RoundletLifecycleProjection, roundwright: _RoundwrightLifecycleProjection,
) -> tuple[str, ...]:
    """Preserve each classification; qualification fails rather than masking drift."""

    differences: list[str] = []
    if roundlet.candidate_sha != roundwright.candidate_sha:
        differences.append("candidate-drift")
    if roundlet.review_epoch != roundwright.review_epoch:
        differences.append("review-epoch-drift")
    if roundlet.formal_round != roundwright.formal_round:
        differences.append("formal-round-drift")
    if roundlet.review_mode != roundwright.review_mode:
        differences.append("review-mode-drift")
    if roundlet.ready_at != roundwright.ready_at:
        differences.append("ready-at-drift")
    if not roundwright.supervisor_sequence_valid:
        differences.append("supervisor-sequence-drift")
    return tuple(sorted(set(differences)))


def _roundwright_fixture_outcomes(
    inventory: RepositoryInventorySnapshot,
    lifecycle: _RoundwrightLifecycleProjection,
    manifest: FixtureSelectionManifest,
) -> tuple[_FixtureOutcome, ...]:
    """Classify every declared fixture through the normalized production facts.

    The generic inventory normalizer has already applied its scheduling and
    pagination rules.  This function intentionally consumes those product
    facts at the immutable ``ready_at`` boundary; it does not accept a caller
    supplied fixture result and it never derives the Roundlet expectation.
    """

    try:
        repository = {
            item.fixture: item
            for item in project_repository_fixture_outcomes(inventory, manifest.selector_map())
        }
    except GitHubRuntimeError as error:
        raise ExternalValidationAdapterError("repository inventory fixture evidence is incomplete") from error
    outcomes = [
        _FixtureOutcome(
            fixture, item.classification, item.dependencies, "not-applicable",
            item.state, item.gates, item.blockers, item.next_action,
        )
        for fixture in _LIVE_LIFECYCLE_FIXTURES[:-1]
        for item in (repository.get(fixture),)
        if item is not None
    ]
    accepted_pass = (
        lifecycle.supervisor_sequence_valid
        and lifecycle.accepted_pass_attempt_identity is not None
    )
    outcomes.append(_FixtureOutcome(
        "supervisor-failover",
        "supervisor-failover" if lifecycle.supervisor_sequence_valid else "missing",
        "not-applicable" if lifecycle.supervisor_sequence_valid else "missing",
        "actual-sealed-attempts" if lifecycle.supervisor_sequence_valid else "missing",
        "accepted" if lifecycle.supervisor_sequence_valid else "missing",
        "passed" if accepted_pass else "blocked",
        "none" if accepted_pass else "accepted-pass-required",
        "retain-readonly" if accepted_pass else "blocked",
    ))
    return tuple(outcomes)


def _roundlet_fixture_outcomes(manifest: FixtureSelectionManifest) -> tuple[_FixtureOutcome, ...]:
    """Return externally reviewed expectations, never target-read results."""

    return manifest.expected_outcomes()


def _fixture_outcome_differences(
    expected: tuple[_FixtureOutcome, ...], observed: tuple[_FixtureOutcome, ...],
) -> tuple[str, ...]:
    """Compare all declared outcome dimensions with bounded safe labels."""

    actual = {item.fixture: item for item in observed}
    differences: list[str] = []
    baseline_by_fixture = {item.fixture: item for item in expected}
    for fixture in _LIVE_LIFECYCLE_FIXTURES:
        fields = (
            ("gates", "blockers", "next_action")
            if fixture == "supervisor-failover"
            # The known three-attempt sequence is #82 synthetic evidence;
            # live #49 preserves its real shape but still requires accepted PASS.
            else ("classification", "dependencies", "attempt_accounting", "state", "gates", "blockers", "next_action")
        )
        baseline = baseline_by_fixture.get(fixture)
        if baseline is None:
            differences.append(f"fixture-{fixture}-expectation-missing")
            continue
        item = actual.get(fixture)
        if item is None:
            differences.append(f"fixture-{fixture}-missing")
            continue
        for field in fields:
            if getattr(baseline, field) != getattr(item, field):
                differences.append(f"fixture-{fixture}-{field}-drift")
    return tuple(sorted(set(differences))[:_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES])


def _roundlet_trace_differences(
    inventory: RepositoryInventorySnapshot,
    lifecycle: lifecycle_observation.LifecycleShadowProjection,
    expected: _RoundletLifecycleProjection,
) -> tuple[str, ...]:
    """Bind normalized Roundlet trace facts to the sealed ledger.

    Generic ``COMMENTS`` evidence proves collection completeness, but cannot
    stand in for the ordered lifecycle trace.  This private projection uses
    only the normalizer's public-safe facts: trace identities are sorted for a
    stable identity set while ordinals retain the authored lifecycle order.
    """

    records: dict[str, dict[str, str]] = {}
    for fact in inventory.facts:
        if not fact.subject.startswith("roundlet-trace-"):
            continue
        identity = fact.subject.removeprefix("roundlet-trace-")
        record = records.setdefault(identity, {})
        if fact.predicate in record:
            record["duplicate"] = "true"
        record[fact.predicate] = fact.object
    differences: list[str] = []
    identities = tuple(sorted(records))
    if len(identities) != 3 or len(set(identities)) != 3:
        differences.append("trace-identity-drift")
    required = {
        "surface", "marker", "semantic", "ordinal", "profile", "reasoning",
        "disposition", "formal-round", "ready-at", "candidate",
    }
    completed = tuple(
        event for event in lifecycle.events
        if event.role == "supervisor" and event.transition == "attempt_completed"
    )
    expected_profiles = tuple((item[0], item[1]) for item in expected.supervisor_attempts)
    expected_dispositions = tuple(item[2] for item in expected.supervisor_attempts)
    for ordinal in range(1, 4):
        matches = [record for record in records.values() if record.get("ordinal") == str(ordinal)]
        if len(matches) != 1:
            differences.append(f"trace-order-{ordinal}-drift")
            continue
        record = matches[0]
        if set(record) - {"duplicate"} != required or "duplicate" in record:
            differences.append(f"trace-fields-{ordinal}-drift")
            continue
        expected_profile = expected_profiles[ordinal - 1] if len(expected_profiles) == 3 else ("missing", "missing")
        expected_disposition = expected_dispositions[ordinal - 1] if len(expected_dispositions) == 3 else "missing"
        expected = {
            "marker": "lifecycle", "semantic": f"supervisor-{ordinal}", "profile": expected_profile[0],
            "reasoning": expected_profile[1], "disposition": expected_disposition,
            "formal-round": f"formal-round-{lifecycle.review_round}",
            "ready-at": str(lifecycle.ready_at), "candidate": lifecycle.candidate_sha,
        }
        for field, value in expected.items():
            if record.get(field) != value:
                differences.append(f"trace-{field}-{ordinal}-drift")
        if record["surface"] not in {"issue", "pull-request"}:
            differences.append(f"trace-surface-{ordinal}-drift")
    return tuple(sorted(set(differences))[:_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES])


class GitHubReadCapability(Protocol):
    """Reviewed generic GitHub read boundary, independent of this profile."""

    def read(self, request: GitHubReadRequest) -> GitHubReadResult: ...


def _require_github_read_capability(capability: object) -> GitHubReadCapability:
    if not callable(getattr(capability, "read", None)):
        raise ExternalValidationAdapterError("generic GitHub read capability is invalid")
    return capability  # type: ignore[return-value]


class _RoundwrightLiveLifecycleProvider:
    """Product adapter selecting generic GitHub reads and all profile projection."""

    def __init__(self, capability: GitHubReadCapability, inputs: LiveLifecycleRequestInputs) -> None:
        owner, name = inputs.target_repository.split("/", 1)
        self._inputs = inputs
        self._capability = _require_github_read_capability(capability)
        self._repository = RepositoryRef(owner, name)
        # #49's trace is a second, non-substitutable source: it is read from
        # the exact Roundwright implementation PR, never from the forward
        # target inventory.
        trace_owner, trace_name = inputs.trace_repository.split("/", 1)
        self._trace_repository = RepositoryRef(trace_owner, trace_name)
        self._trace_pull_request = inputs.trace_pull_request
        self._trace_publisher_identity = inputs.trace_publisher_identity
        self._baseline_sha = inputs.target_baseline_sha
        self._candidate_sha = inputs.candidate_sha
        self._ready_at = inputs.ready_at
        self._manifest = inputs.fixture_manifest
        self._armed = False
        if self._manifest is None:
            raise ExternalValidationAdapterError("live lifecycle fixture manifest is unavailable")

    def _read(self, request: GitHubReadRequest, expected: type[object]) -> object:
        try:
            result = self._capability.read(request)
        except Exception as error:
            raise RepositoryInventoryFirstReadBoundaryError(
                RepositoryInventoryReadFailureCode.HOST_FAILURE,
            ) from error
        if type(result) is GitHubReadResult and result.request == request and result.failure is not None:
            retained = credentialed_repository_inventory_failure(self._capability, request, result)
            if retained is None:
                retained = (
                    RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                    RepositoryInventoryFailureStage.UNKNOWN,
                )
            raise RepositoryInventoryFirstReadBoundaryError(*retained)
        if (
            type(result) is not GitHubReadResult or result.request != request
            or not result.ok or type(result.snapshot) is not expected
        ):
            raise RepositoryInventoryFirstReadBoundaryError(
                RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
            )
        return result.snapshot

    def _inventory(self) -> RepositoryInventorySnapshot:
        inventory = self._read(
            GitHubReadRequest(
                GitHubReadOperation.REPOSITORY_INVENTORY, self._repository,
                expected_sha=self._baseline_sha,
            ), RepositoryInventorySnapshot,
        )
        assert type(inventory) is RepositoryInventorySnapshot
        if (
            inventory.repository != self._repository
            or inventory.baseline_sha != self._baseline_sha
            or inventory.collection(RepositoryInventorySection.REPOSITORY).complete is not True
        ):
            raise ExternalValidationAdapterError("generic GitHub repository inventory has drifted")
        return inventory

    @staticmethod
    def _fixture_classes(
        inventory: RepositoryInventorySnapshot,
        lifecycle: _RoundwrightLifecycleProjection,
        manifest: FixtureSelectionManifest,
    ) -> tuple[str, ...]:
        observed = _roundwright_fixture_outcomes(inventory, lifecycle, manifest)
        differences = _fixture_outcome_differences(_roundlet_fixture_outcomes(manifest), observed)
        if differences:
            # The caller receives no partially qualified fixture set.  The
            # bounded dimension labels remain available to the sealed profile
            # comparator for explicit mismatch regressions.
            raise ExternalValidationAdapterError("repository inventory fixture evidence is incomplete")
        return tuple(
            fixture for fixture in _LIVE_LIFECYCLE_FIXTURES
            if not any(item.startswith(f"fixture-{fixture}-") for item in differences)
        )

    def _trace_receipt(self, lifecycle: _RoundwrightLifecycleProjection) -> _RoundwrightTraceReceipt:
        pull_request = self._read(
            GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, self._trace_repository,
                number=self._trace_pull_request, expected_sha=self._candidate_sha),
            PullRequestSnapshot,
        )
        comments = self._read(
            GitHubReadRequest(GitHubReadOperation.COMMENTS, self._trace_repository,
                number=self._trace_pull_request),
            CommentsSnapshot,
        )
        assert type(pull_request) is PullRequestSnapshot and type(comments) is CommentsSnapshot
        if (
            pull_request.repository != self._trace_repository
            or pull_request.number != self._trace_pull_request
            or pull_request.base_repository != self._trace_repository
            or pull_request.head_repository != self._trace_repository
            or pull_request.head_sha != self._candidate_sha
            or comments.repository != self._trace_repository
            or comments.issue_number != self._trace_pull_request
            or comments.target_kind != "PULL_REQUEST"
        ):
            raise ExternalValidationAdapterError("Roundwright PR trace read-back has drifted")
        marker = _roundlet_pr_conversation_marker(
            self._candidate_sha, lifecycle.review_epoch, lifecycle.formal_round,
            lifecycle.review_mode, self._inputs.observation_window, lifecycle.ready_at,
        )
        expected_marker_digest = _digest(("comment-body", marker))
        marker_comments = tuple(
            item for item in comments.comments if item.body_digest == expected_marker_digest
        )
        differences: list[str] = []
        if not marker_comments:
            differences.append("trace-marker-missing")
        elif len(marker_comments) != 1:
            differences.append("trace-marker-duplicate")
        elif marker_comments[0].author_id != self._trace_publisher_identity:
            differences.append("trace-publisher-drift")
        matching_comments = tuple(
            item for item in marker_comments if item.author_id == self._trace_publisher_identity
        )
        return _RoundwrightTraceReceipt(_digest({
            "repository": self._trace_repository.slug, "pull_request": self._trace_pull_request,
            "candidate_sha": self._candidate_sha,
            "review_epoch": lifecycle.review_epoch, "formal_round": lifecycle.formal_round,
            "review_mode": lifecycle.review_mode, "window": self._inputs.observation_window,
            "ready_at": lifecycle.ready_at, "marker_digest": expected_marker_digest,
            "publisher_identity": self._trace_publisher_identity,
            "comments": [(item.comment_id, item.author_id, item.body_digest, item.created_at) for item in matching_comments],
        }), tuple(sorted(set(differences))))

    def _trace_receipt_digest(self, lifecycle: _RoundwrightLifecycleProjection) -> str:
        receipt = self._trace_receipt(lifecycle)
        if receipt.differences:
            raise ExternalValidationAdapterError("Roundwright PR trace semantic evidence has drifted")
        return receipt.digest

    @staticmethod
    def _observation(
        inventory: RepositoryInventorySnapshot,
        lifecycle: _RoundwrightLifecycleProjection,
        sealed_lifecycle: lifecycle_observation.LifecycleShadowProjection,
        manifest: FixtureSelectionManifest,
    ) -> _LiveLifecycleProviderObservation:
        fixtures = _RoundwrightLiveLifecycleProvider._fixture_classes(inventory, lifecycle, manifest)
        fixture_differences = _fixture_outcome_differences(
            _roundlet_fixture_outcomes(manifest), _roundwright_fixture_outcomes(inventory, lifecycle, manifest),
        )
        snapshot_digests = {
            category: _digest({
                "category": category,
                "repository": inventory.repository.slug,
                "baseline_sha": inventory.baseline_sha,
                "sections": [
                    {
                        "section": section.value,
                        "evidence": inventory.collection(section).evidence_identity,
                        "items": inventory.collection(section).item_identities,
                        "pages": inventory.collection(section).page_count,
                    }
                    for section in _LIVE_LIFECYCLE_CATEGORY_SECTIONS[category]
                ],
                "facts": [
                    (fact.subject, fact.predicate, fact.object)
                    for fact in inventory.facts
                    if any(section.value.split("-")[0] in fact.subject for section in _LIVE_LIFECYCLE_CATEGORY_SECTIONS[category])
                ],
                "fixtures": fixtures,
            })
            for category in _LIVE_LIFECYCLE_SNAPSHOTS
        }
        return _LiveLifecycleProviderObservation(
            snapshot_digests, fixtures,
            tuple(sorted(set(fixture_differences))[:_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES]),
        )

    @staticmethod
    def _target_state_digest(inventory: RepositoryInventorySnapshot) -> str:
        """Bind before/after read-back to every observed generic collection."""

        return _digest({
            "repository": inventory.repository_evidence_identity,
            "default_branch": inventory.default_branch_evidence_identity,
            "baseline_sha": inventory.baseline_sha,
            "collections": [
                (item.section.value, item.evidence_identity, item.item_identities, item.page_count)
                for item in inventory.collections
            ],
            "facts": [(item.subject, item.predicate, item.object) for item in inventory.facts],
        })

    def read_before(self) -> _LiveLifecycleTargetState:
        inventory = self._inventory()
        return _LiveLifecycleTargetState(
            self._repository.slug, inventory.baseline_sha,
            self._target_state_digest(inventory),
        )

    def read_lifecycle(
        self, lifecycle: _RoundwrightLifecycleProjection,
        sealed_lifecycle: lifecycle_observation.LifecycleShadowProjection,
    ) -> _LiveLifecycleProviderObservation:
        self._armed = True
        observation = self._observation(self._inventory(), lifecycle, sealed_lifecycle, self._manifest)
        trace = self._trace_receipt(lifecycle)
        if trace.differences:
            raise ExternalValidationAdapterError("Roundwright PR trace semantic evidence has drifted")
        return _LiveLifecycleProviderObservation(
            {**observation.snapshot_digests, "roundlet-trace": trace.digest},
            observation.fixture_classes, observation.classified_differences,
        )

    def read_after(self) -> _LiveLifecycleTargetState:
        if not self._armed:
            raise ExternalValidationAdapterError("live lifecycle window was not armed")
        inventory = self._inventory()
        return _LiveLifecycleTargetState(
            self._repository.slug, inventory.baseline_sha,
            self._target_state_digest(inventory),
        )


@dataclass(frozen=True)
class ReadOnlyExternalObservationInputs:
    """Closed Lane A inputs, intentionally independent of a lifecycle result."""

    target_repository: str
    target_baseline_sha: str
    candidate_sha: str
    capture_plan_digest: str
    trace_repository: str
    trace_pull_request: int
    trace_publisher_identity: str
    review_epoch: int
    formal_round: str
    review_mode: str
    observation_window: str
    ready_at: int
    fixture_manifest: FixtureSelectionManifest

    def __post_init__(self) -> None:
        if (
            not _safe_repository(self.target_repository)
            or _SHA.fullmatch(self.target_baseline_sha) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or not _safe_repository(self.trace_repository)
            or type(self.trace_pull_request) is not int or self.trace_pull_request < 1
            or not _trace_publisher_identity(self.trace_publisher_identity)
            or type(self.review_epoch) is not int or self.review_epoch < 1
            or not _safe_token(self.formal_round)
            or self.review_mode not in {"complete", "converging"}
            or not _safe_token(self.observation_window)
            or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.fixture_manifest) is not FixtureSelectionManifest
            or not self.fixture_manifest.is_owner_sealed
            or (self.fixture_manifest.target_repository, self.fixture_manifest.target_baseline_sha)
            != (self.target_repository, self.target_baseline_sha)
            or self.fixture_manifest.trace_publisher_identity != self.trace_publisher_identity
        ):
            raise ExternalValidationAdapterError("read-only external observation inputs are invalid")


@dataclass(frozen=True)
class ReadOnlyExternalObservationSnapshot:
    """Public-safe Lane A evidence from exact external read-back sources."""

    candidate_sha: str
    capture_plan_digest: str
    ready_at: int
    target_state_digest: str
    trace_receipt_digest: str
    fixture_receipt_digest: str

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or type(self.ready_at) is not int or self.ready_at < 0
            or any(_DIGEST.fullmatch(item) is None for item in (
                self.target_state_digest, self.trace_receipt_digest, self.fixture_receipt_digest,
            ))
        ):
            raise ExternalValidationAdapterError("read-only external observation snapshot is invalid")


@dataclass(frozen=True)
class ReadOnlyExternalObservationRuntimeDescriptor:
    """Closed Lane A V2 context, excluding the trusted read capability."""

    target_repository: str
    target_baseline_sha: str
    candidate_sha: str
    capture_plan_digest: str
    case_id: str
    trace_repository: str
    trace_pull_request: int
    trace_publisher_identity: str
    review_epoch: int
    formal_round: str
    review_mode: str
    observation_window: str
    ready_at: int
    fixture_manifest: FixtureSelectionManifest
    schema: str = "roundwright-read-only-external-observation-runtime/v2"

    @classmethod
    def parse(cls, value: object) -> "ReadOnlyExternalObservationRuntimeDescriptor":
        if type(value) not in (dict, MappingProxyType):
            raise ExternalValidationAdapterError("read-only external observation runtime descriptor is invalid")
        raw = dict(value)
        if set(raw) != {
            "schema", "target_repository", "target_baseline_sha", "candidate_sha", "capture_plan_digest",
            "case_id", "trace_repository", "trace_pull_request", "trace_publisher_identity", "review_epoch",
            "formal_round", "review_mode", "observation_window", "ready_at", "fixture_manifest", "fixture_manifest_digest",
        }:
            raise ExternalValidationAdapterError("read-only external observation runtime descriptor is invalid")
        try:
            raw["fixture_manifest"] = FixtureSelectionManifest.from_projection(
                raw["fixture_manifest"], raw.pop("fixture_manifest_digest"),
            )
            return cls(**raw)
        except (TypeError, ValueError) as error:
            raise ExternalValidationAdapterError("read-only external observation runtime descriptor is invalid") from error

    def __post_init__(self) -> None:
        if (
            self.schema != "roundwright-read-only-external-observation-runtime/v2"
            or not _safe_repository(self.target_repository)
            or _SHA.fullmatch(self.target_baseline_sha) is None
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or not _safe_token(self.case_id)
            or not _safe_repository(self.trace_repository)
            or type(self.trace_pull_request) is not int or self.trace_pull_request < 1
            or not _trace_publisher_identity(self.trace_publisher_identity)
            or type(self.review_epoch) is not int or self.review_epoch < 1
            or not _safe_token(self.formal_round)
            or self.review_mode not in {"complete", "converging"}
            or not _safe_token(self.observation_window)
            or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.fixture_manifest) is not FixtureSelectionManifest
            or (self.fixture_manifest.target_repository, self.fixture_manifest.target_baseline_sha)
            != (self.target_repository, self.target_baseline_sha)
            or self.fixture_manifest.trace_publisher_identity != self.trace_publisher_identity
        ):
            raise ExternalValidationAdapterError("read-only external observation runtime descriptor is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema, "target_repository": self.target_repository,
            "target_baseline_sha": self.target_baseline_sha, "candidate_sha": self.candidate_sha,
            "capture_plan_digest": self.capture_plan_digest, "case_id": self.case_id,
            "trace_repository": self.trace_repository, "trace_pull_request": self.trace_pull_request,
            "trace_publisher_identity": self.trace_publisher_identity, "review_epoch": self.review_epoch,
            "formal_round": self.formal_round, "review_mode": self.review_mode,
            "observation_window": self.observation_window, "ready_at": self.ready_at,
            "fixture_manifest": self.fixture_manifest.payload(),
            "fixture_manifest_digest": self.fixture_manifest.manifest_digest,
        }


@dataclass(frozen=True)
class MaterializedReadOnlyExternalObservationContext:
    descriptor: ReadOnlyExternalObservationRuntimeDescriptor

    @property
    def identity(self) -> str:
        return _digest({
            "schema": "roundwright-read-only-external-observation-context/v1",
            "descriptor": self.descriptor.payload(),
        })


@dataclass(frozen=True)
class ReadOnlyExternalObservationHostInputs:
    """Trusted product host inputs, never serialized into the V2 request."""

    capability: GitHubReadCapability
    fixture_manifest: FixtureSelectionManifest

    def __post_init__(self) -> None:
        if type(self.fixture_manifest) is not FixtureSelectionManifest or not self.fixture_manifest.is_owner_sealed:
            raise ExternalValidationAdapterError("read-only external observation host inputs are invalid")
        _require_github_read_capability(self.capability)


def prepare_read_only_external_observation_context(
    descriptor_value: object, *, plan_digest: str, candidate_sha: str, case_id: str, ready_at: int,
) -> MaterializedReadOnlyExternalObservationContext:
    descriptor = ReadOnlyExternalObservationRuntimeDescriptor.parse(descriptor_value)
    if (descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at) != (
        plan_digest, candidate_sha, case_id, ready_at,
    ):
        raise ExternalValidationAdapterError("read-only external observation runtime descriptor does not match capture plan")
    return MaterializedReadOnlyExternalObservationContext(descriptor)


def _read_only_external_observation_context(binding: object) -> MaterializedReadOnlyExternalObservationContext:
    try:
        context, descriptor_digest = binding.execution_context, binding.execution_context_input_digest
        value = context.value
    except AttributeError as error:
        raise ExternalValidationAdapterError("read-only external observation V2 execution context is unavailable") from error
    if (
        type(value) is not MaterializedReadOnlyExternalObservationContext
        or _DIGEST.fullmatch(descriptor_digest) is None
        or descriptor_digest != _digest(value.descriptor.payload())
        or getattr(context, "identity", None) != value.identity
    ):
        raise ExternalValidationAdapterError("read-only external observation V2 execution context has drifted")
    descriptor = value.descriptor
    if (descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at) != (
        binding.plan.plan_digest, binding.candidate_sha, binding.case_id, binding.ready_at,
    ):
        raise ExternalValidationAdapterError("read-only external observation V2 execution context has drifted")
    return value


def _materialize_read_only_external_observation_provider(
    descriptor: ReadOnlyExternalObservationRuntimeDescriptor,
    host_inputs: ReadOnlyExternalObservationHostInputs,
) -> ReadOnlyExternalObservationProvider:
    if descriptor.fixture_manifest != host_inputs.fixture_manifest:
        raise ExternalValidationAdapterError("read-only external observation host inputs have drifted")
    return ReadOnlyExternalObservationProvider(host_inputs.capability, ReadOnlyExternalObservationInputs(
        descriptor.target_repository, descriptor.target_baseline_sha, descriptor.candidate_sha,
        descriptor.capture_plan_digest, descriptor.trace_repository, descriptor.trace_pull_request,
        descriptor.trace_publisher_identity, descriptor.review_epoch, descriptor.formal_round,
        descriptor.review_mode, descriptor.observation_window, descriptor.ready_at, host_inputs.fixture_manifest,
    ))


def _lane_a_fixture_differences(
    inventory: RepositoryInventorySnapshot, manifest: FixtureSelectionManifest,
) -> tuple[str, ...]:
    """Compare target-derived fixture facts without admitting Lane B semantics."""

    try:
        observed = {item.fixture: item for item in project_repository_fixture_outcomes(inventory, manifest.selector_map())}
    except GitHubRuntimeError as error:
        raise ExternalValidationAdapterError("read-only external fixture evidence is incomplete") from error
    expected = {item.fixture: item for item in manifest.expected_outcomes()}
    differences: list[str] = []
    for fixture in _LIVE_LIFECYCLE_FIXTURES[:-1]:
        actual, baseline = observed.get(fixture), expected.get(fixture)
        if actual is None or baseline is None:
            differences.append(f"fixture-{fixture}-missing")
            continue
        for field in ("classification", "dependencies", "state", "gates", "blockers", "next_action"):
            if getattr(actual, field) != getattr(baseline, field):
                differences.append(f"fixture-{fixture}-{field}-drift")
    return tuple(sorted(set(differences))[:_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES])


class ReadOnlyExternalObservationProvider(_RoundwrightLiveLifecycleProvider):
    """Lane A's exact target/PR read-back without lifecycle-result coupling."""

    def __init__(self, capability: GitHubReadCapability, inputs: ReadOnlyExternalObservationInputs) -> None:
        owner, name = inputs.target_repository.split("/", 1)
        trace_owner, trace_name = inputs.trace_repository.split("/", 1)
        self._capability = _require_github_read_capability(capability)
        self._repository = RepositoryRef(owner, name)
        self._trace_repository = RepositoryRef(trace_owner, trace_name)
        self._baseline_sha = inputs.target_baseline_sha
        self._candidate_sha = inputs.candidate_sha
        self._trace_pull_request = inputs.trace_pull_request
        self._trace_publisher_identity = inputs.trace_publisher_identity
        self._inputs = inputs

    def _trace_receipt_digest(self) -> str:
        pull_request = self._read(
            GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, self._trace_repository,
                number=self._trace_pull_request, expected_sha=self._candidate_sha), PullRequestSnapshot,
        )
        comments = self._read(
            GitHubReadRequest(GitHubReadOperation.COMMENTS, self._trace_repository,
                number=self._trace_pull_request), CommentsSnapshot,
        )
        assert type(pull_request) is PullRequestSnapshot and type(comments) is CommentsSnapshot
        marker = _roundlet_validation_readiness_marker(
            self._candidate_sha, self._inputs.capture_plan_digest, self._inputs.review_epoch, self._inputs.formal_round,
            self._inputs.review_mode, self._inputs.observation_window, self._inputs.ready_at,
        )
        marker_digest = _digest(("comment-body", marker))
        matching = tuple(item for item in comments.comments if item.body_digest == marker_digest)
        if (
            pull_request.repository != self._trace_repository
            or pull_request.number != self._trace_pull_request
            or pull_request.base_repository != self._trace_repository
            or pull_request.head_repository != self._trace_repository
            or pull_request.head_sha != self._candidate_sha
            or comments.repository != self._trace_repository
            or comments.issue_number != self._trace_pull_request
            or comments.target_kind != "PULL_REQUEST"
            or len(matching) != 1
            or matching[0].author_id != self._trace_publisher_identity
        ):
            raise ExternalValidationAdapterError("read-only external PR trace has drifted")
        return _digest({
            "repository": self._trace_repository.slug, "pull_request": self._trace_pull_request,
            "candidate_sha": self._candidate_sha, "capture_plan_digest": self._inputs.capture_plan_digest,
            "review_epoch": self._inputs.review_epoch,
            "formal_round": self._inputs.formal_round, "review_mode": self._inputs.review_mode,
            "window": self._inputs.observation_window, "ready_at": self._inputs.ready_at,
            "publisher": self._trace_publisher_identity, "marker_digest": marker_digest,
            "comment": (matching[0].comment_id, matching[0].author_id, matching[0].body_digest, matching[0].created_at),
        })

    def observe(self) -> ReadOnlyExternalObservationSnapshot:
        before = self._inventory()
        differences = _lane_a_fixture_differences(before, self._inputs.fixture_manifest)
        if differences:
            raise ExternalValidationAdapterError("read-only external fixture evidence has drifted")
        trace = self._trace_receipt_digest()
        after = self._inventory()
        before_digest = self._target_state_digest(before)
        if before_digest != self._target_state_digest(after):
            raise ExternalValidationAdapterError("read-only external target mutation has drifted")
        return ReadOnlyExternalObservationSnapshot(
            self._candidate_sha, self._inputs.capture_plan_digest, self._inputs.ready_at, before_digest, trace,
            _digest({"manifest": self._inputs.fixture_manifest.manifest_digest, "differences": differences}),
        )


def _live_lifecycle_store_root_identity(store_root: Path) -> str:
    if not isinstance(store_root, Path) or not store_root.is_absolute():
        raise ExternalValidationAdapterError("live lifecycle store root is invalid")
    return _digest({
        "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA,
        "store_root": str(store_root.resolve(strict=False)).replace("\\", "/"),
    })


def _prepare_live_lifecycle_shadow_request(
    inputs: LiveLifecycleRequestInputs, store_root: Path,
) -> LiveLifecyclePreparedRequest:
    """Construct and validate one closed V2 request without exposing Harness internals.

    This is the only product boundary that derives component, Recorder, store,
    observation, and plan identities.  Callers supply selected public facts and
    the exact retention root; they neither import Harness nor assemble a plan.
    """

    if type(inputs) is not LiveLifecycleRequestInputs:
        raise ExternalValidationAdapterError("live lifecycle preflight inputs are invalid")
    if inputs.fixture_manifest is None:
        raise ExternalValidationAdapterError("live lifecycle fixture manifest is unavailable")
    manifest = inputs.fixture_manifest
    if not manifest.is_owner_sealed:
        raise ExternalValidationAdapterError("live lifecycle fixture manifest is unsealed")
    if (manifest.target_repository, manifest.target_baseline_sha) != (
        inputs.target_repository, inputs.target_baseline_sha,
    ):
        raise ExternalValidationAdapterError("live lifecycle fixture manifest target has drifted")
    if inputs.trace_publisher_identity != manifest.trace_publisher_identity:
        raise ExternalValidationAdapterError("live lifecycle trace publisher is not owner-authorized")
    store_root_identity = _live_lifecycle_store_root_identity(store_root)
    recorder_identity = _digest({
        "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA,
        "recorder_commit": inputs.recorder_commit,
        "recorder_content": inputs.recorder_content,
        "recorder_tree": inputs.recorder_tree,
    })
    store_identity = _digest({
        "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA,
        "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
        "candidate_sha": inputs.candidate_sha,
        "retention_namespace": inputs.retention_namespace,
        "recorder_identity": recorder_identity,
        "store_root_identity": store_root_identity,
    })
    observation_identity = _digest({
        "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA,
        "base_sha": inputs.base_sha,
        "candidate_sha": inputs.candidate_sha,
        "target_repository": inputs.target_repository,
        "target_baseline_sha": inputs.target_baseline_sha,
        "trace_repository": inputs.trace_repository,
        "trace_pull_request": inputs.trace_pull_request,
        "trace_publisher_identity": inputs.trace_publisher_identity,
        "trace_candidate_sha": inputs.candidate_sha,
        "case_id": inputs.case_id,
        "observation_window": inputs.observation_window,
        "ready_at": inputs.ready_at,
        "lifecycle_plan_digest": inputs.lifecycle_ledger.plan_digest,
        "lifecycle_ledger_digest": inputs.lifecycle_ledger.ledger_digest,
        "fixture_manifest_digest": manifest.manifest_digest,
        "store_identity": store_identity,
    })
    producer, exporter, comparator = live_lifecycle_shadow_component_identities()
    capture_plan = {
        "schema": "roundwright-harness-capture-plan/v1",
        "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
        "case_id": inputs.case_id,
        "candidate_sha": inputs.candidate_sha,
        "ready_at": inputs.ready_at,
        "producer_identity": producer,
        "exporter_identity": exporter,
        "comparator_identity": comparator,
        "recorder_identity": recorder_identity,
        "store_identity": store_identity,
        "observation_identity": observation_identity,
    }
    harness = _harness_executor()
    try:
        plan = harness.prepare_capture(capture_plan)
        plan_digest = plan.plan_digest
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("live lifecycle capture plan is invalid") from error
    if _DIGEST.fullmatch(plan_digest) is None:
        raise ExternalValidationAdapterError("live lifecycle capture plan is invalid")
    descriptor = LiveLifecycleRuntimeDescriptor(
        inputs.target_repository, inputs.target_baseline_sha, inputs.candidate_sha,
        plan_digest, inputs.case_id, inputs.observation_window, inputs.ready_at, manifest,
        inputs.trace_repository, inputs.trace_pull_request, inputs.trace_publisher_identity,
    )
    request_value = {
        "schema": "roundwright-harness-profile-executor-request/v2",
        "capture_plan": capture_plan,
        "execution_context": descriptor.payload(),
    }
    request_digest = _digest(request_value)
    return LiveLifecyclePreparedRequest(
        inputs, plan_digest, request_digest, recorder_identity, store_root_identity, store_identity,
        observation_identity, MappingProxyType(request_value),
    )


def _live_lifecycle_readiness_receipt(
    harness_receipt: object, prepared_request: LiveLifecyclePreparedRequest,
) -> LiveLifecycleReadinessReceipt:
    """Validate and copy only public-safe fields from the Harness V2 receipt."""

    harness = _harness_executor()
    try:
        if type(harness_receipt) is not harness.ExecutorReadinessReceipt:
            raise ValueError
        value = harness_receipt.as_dict()
        if type(value) is not dict or set(value) != {
            "schema", "status", "state", "plan_digest", "profile", "case_id", "candidate_sha",
            "ready_at", "producer_identity", "exporter_identity", "comparator_identity",
            "dispatch_count", "record_count", "verify_count", "mutation_count",
            "execution_context_input_digest", "execution_context_identity", "receipt_digest",
        }:
            raise ValueError
        receipt_digest = value["receipt_digest"]
        core = {key: item for key, item in value.items() if key != "receipt_digest"}
        producer, exporter, comparator = live_lifecycle_shadow_component_identities()
        descriptor = prepare_live_lifecycle_context(
            dict(prepared_request._request_value["execution_context"]),
            plan_digest=prepared_request.capture_plan_digest,
            candidate_sha=prepared_request.inputs.candidate_sha,
            case_id=prepared_request.inputs.case_id,
            ready_at=prepared_request.inputs.ready_at,
        )
        if (
            value["schema"] != "roundwright-harness-profile-executor-readiness/v2"
            or value["status"] != "ready" or value["state"] != "PREFLIGHT_READY"
            or value["plan_digest"] != prepared_request.capture_plan_digest
            or value["profile"] != LIVE_LIFECYCLE_SHADOW_PROFILE
            or value["case_id"] != prepared_request.inputs.case_id
            or value["candidate_sha"] != prepared_request.inputs.candidate_sha
            or value["ready_at"] != prepared_request.inputs.ready_at
            or (value["producer_identity"], value["exporter_identity"], value["comparator_identity"])
            != (producer, exporter, comparator)
            or (value["dispatch_count"], value["record_count"], value["verify_count"], value["mutation_count"])
            != (0, 0, 0, 0)
            or value["execution_context_input_digest"] != _digest(prepared_request._request_value["execution_context"])
            or value["execution_context_identity"] != descriptor.identity
            or type(receipt_digest) is not str or _DIGEST.fullmatch(receipt_digest) is None
            or _digest(core) != receipt_digest
        ):
            raise ValueError
        return LiveLifecycleReadinessReceipt(
            prepared_request.capture_plan_digest, prepared_request.inputs.candidate_sha,
            prepared_request.inputs.case_id, prepared_request.inputs.ready_at,
            producer, exporter, comparator, value["execution_context_input_digest"],
            value["execution_context_identity"], receipt_digest, _LIVE_LIFECYCLE_READINESS_SEAL,
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("live lifecycle readiness receipt is invalid") from error


def _preflight_live_lifecycle_shadow_profile(
    inputs: LiveLifecycleRequestInputs, store_root: Path,
) -> tuple[LiveLifecyclePreparedRequest, LiveLifecycleReadinessReceipt]:
    """Construct and provider-free validate one product-owned readiness binding."""

    prepared_request = _prepare_live_lifecycle_shadow_request(inputs, store_root)
    request_value = _validated_live_lifecycle_request(prepared_request, store_root)
    harness = _harness_executor()
    try:
        harness_receipt = harness.run_profile_executor(
            "validate", request_value, LiveLifecycleShadowProfileAdapter(), store_root,
        )
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("live lifecycle preflight validation failed") from error
    readiness = _live_lifecycle_readiness_receipt(harness_receipt, prepared_request)
    return prepared_request, readiness


def _validated_live_lifecycle_request(
    prepared_request: LiveLifecyclePreparedRequest, store_root: Path,
) -> dict[str, object]:
    if type(prepared_request) is not LiveLifecyclePreparedRequest:
        raise ExternalValidationAdapterError("live lifecycle prepared request is invalid")
    request_value = dict(prepared_request._request_value)
    inputs = prepared_request.inputs
    producer, exporter, comparator = live_lifecycle_shadow_component_identities()
    expected_capture_plan = {
        "schema": "roundwright-harness-capture-plan/v1",
        "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
        "case_id": inputs.case_id,
        "candidate_sha": inputs.candidate_sha,
        "ready_at": inputs.ready_at,
        "producer_identity": producer,
        "exporter_identity": exporter,
        "comparator_identity": comparator,
        "recorder_identity": prepared_request.recorder_identity,
        "store_identity": prepared_request.store_identity,
        "observation_identity": prepared_request.observation_identity,
    }
    expected_descriptor = LiveLifecycleRuntimeDescriptor(
        inputs.target_repository, inputs.target_baseline_sha, inputs.candidate_sha,
        prepared_request.capture_plan_digest, inputs.case_id, inputs.observation_window, inputs.ready_at,
        inputs.fixture_manifest, inputs.trace_repository, inputs.trace_pull_request, inputs.trace_publisher_identity,
    ).payload()
    if (
        _digest(request_value) != prepared_request.request_digest
        or _live_lifecycle_store_root_identity(store_root) != prepared_request.store_root_identity
        or set(request_value) != {"schema", "capture_plan", "execution_context"}
        or request_value.get("schema") != "roundwright-harness-profile-executor-request/v2"
        or type(request_value["capture_plan"]) is not dict
        or type(request_value["execution_context"]) is not dict
        or request_value.get("capture_plan") != expected_capture_plan
        or _digest(request_value["capture_plan"]) != prepared_request.capture_plan_digest
        or request_value.get("execution_context") != expected_descriptor
    ):
        raise ExternalValidationAdapterError("live lifecycle prepared request has drifted")
    return request_value


def _validated_live_lifecycle_ready_capsule(
    capsule: _LiveLifecycleReadyCapsule, store_root: Path,
) -> LiveLifecyclePreparedRequest:
    if type(capsule) is not _LiveLifecycleReadyCapsule or capsule._consumed:
        raise ExternalValidationAdapterError("live lifecycle ready capsule is unavailable")
    if (
        capsule._seal is not _LIVE_LIFECYCLE_READY_CAPSULE_SEAL
        or type(capsule.prepared_request) is not LiveLifecyclePreparedRequest
        or type(capsule.readiness) is not LiveLifecycleReadinessReceipt
    ):
        raise ExternalValidationAdapterError("live lifecycle ready capsule is invalid")
    prepared_request = capsule.prepared_request
    _validated_live_lifecycle_request(prepared_request, store_root)
    readiness = capsule.readiness
    producer, exporter, comparator = live_lifecycle_shadow_component_identities()
    if (
        readiness._seal is not _LIVE_LIFECYCLE_READINESS_SEAL
        or readiness.receipt_digest != _digest({
            "schema": "roundwright-harness-profile-executor-readiness/v2",
            "status": "ready", "state": "PREFLIGHT_READY",
            "plan_digest": readiness.capture_plan_digest,
            "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
            "case_id": readiness.case_id, "candidate_sha": readiness.candidate_sha,
            "ready_at": readiness.ready_at,
            "producer_identity": readiness.producer_identity,
            "exporter_identity": readiness.exporter_identity,
            "comparator_identity": readiness.comparator_identity,
            "dispatch_count": 0, "record_count": 0, "verify_count": 0, "mutation_count": 0,
            "execution_context_input_digest": readiness.execution_context_input_digest,
            "execution_context_identity": readiness.execution_context_identity,
        })
        or capsule.capsule_digest != _digest({
            "schema": "roundwright-live-lifecycle-ready-capsule/v1",
            "request_digest": prepared_request.request_digest,
            "capture_plan_digest": prepared_request.capture_plan_digest,
            "store_identity": prepared_request.store_identity,
            "readiness": readiness.public_receipt(),
        })
        or readiness.capture_plan_digest != prepared_request.capture_plan_digest
        or (readiness.candidate_sha, readiness.case_id, readiness.ready_at)
        != (prepared_request.inputs.candidate_sha, prepared_request.inputs.case_id, prepared_request.inputs.ready_at)
        or (readiness.producer_identity, readiness.exporter_identity, readiness.comparator_identity)
        != (producer, exporter, comparator)
        or readiness.execution_context_input_digest != _digest(prepared_request._request_value["execution_context"])
        or readiness.execution_context_identity != prepare_live_lifecycle_context(
            dict(prepared_request._request_value["execution_context"]),
            plan_digest=prepared_request.capture_plan_digest,
            candidate_sha=prepared_request.inputs.candidate_sha,
            case_id=prepared_request.inputs.case_id,
            ready_at=prepared_request.inputs.ready_at,
        ).identity
    ):
        raise ExternalValidationAdapterError("live lifecycle ready capsule has drifted")
    return prepared_request


def _materialize_live_lifecycle_shadow_profile(
    prepared_request: LiveLifecyclePreparedRequest,
    readiness: LiveLifecycleReadinessReceipt,
    store_root: Path,
    capability: GitHubReadCapability,
) -> object:
    """Materialize one armed read-only lifecycle snapshot and delegate exactly once.

    Generic orchestration can provide a narrowly typed read capability, but it
    cannot create a product event graph, infer fixture coverage, construct a
    snapshot, or reach the Harness executor directly.
    """

    _validated_live_lifecycle_request(prepared_request, store_root)
    inputs = prepared_request.inputs
    # The contract-owned projection verifies the retained ledger before the
    # target read is armed.  A missing, moved, unsealed, or mismatched ledger
    # therefore blocks without provider access and cannot self-satisfy from a
    # locally manufactured event graph.
    try:
        verified_lifecycle = lifecycle_observation.project_verified_lifecycle(
            dict(inputs.lifecycle_ledger.plan), store_root,
            inputs.lifecycle_ledger.ledger_digest,
        )
    except lifecycle_observation.LifecycleObservationError as error:
        raise ExternalValidationAdapterError("live lifecycle ledger verification failed") from error
    if (
        verified_lifecycle.candidate_sha != inputs.candidate_sha
        or verified_lifecycle.ready_at != inputs.ready_at
        or verified_lifecycle.review_epoch < 1
        or verified_lifecycle.review_round < 1
        or verified_lifecycle.review_mode not in {"complete", "converging"}
        or verified_lifecycle.ledger_digest != inputs.lifecycle_ledger.ledger_digest
    ):
        raise ExternalValidationAdapterError("live lifecycle ledger binding has drifted")
    provider = _RoundwrightLiveLifecycleProvider(capability, prepared_request.inputs)
    if inputs.fixture_manifest is None:
        raise ExternalValidationAdapterError("live lifecycle fixture manifest is unavailable")
    roundlet = _roundlet_lifecycle_projection(verified_lifecycle)
    roundwright = _roundwright_lifecycle_projection(verified_lifecycle)
    before = provider.read_before()
    # The product creates this request with the arm flag before it makes the
    # sole lifecycle read.  Only the already verified ledger supplies
    # lifecycle facts; inventory remains target fixture/read-back evidence.
    observation = provider.read_lifecycle(roundwright, verified_lifecycle)
    after = provider.read_after()
    if (
        type(before) is not _LiveLifecycleTargetState
        or type(observation) is not _LiveLifecycleProviderObservation
        or type(after) is not _LiveLifecycleTargetState
        or (before.target_repository, before.target_sha) != (inputs.target_repository, inputs.target_baseline_sha)
        or after != before
    ):
        raise ExternalValidationAdapterError("live lifecycle zero-mutation read-back has drifted")
    differences = list(_classified_lifecycle_differences(roundlet, roundwright))
    differences.extend(observation.classified_differences)
    snapshot = LiveLifecycleShadowSnapshot(
        inputs.target_repository, inputs.target_baseline_sha, after.target_sha,
        inputs.candidate_sha, prepared_request.capture_plan_digest, inputs.case_id,
        inputs.observation_window, inputs.ready_at, verified_lifecycle,
        observation.snapshot_digests, observation.fixture_classes,
        tuple(sorted(set(differences))[:_LIVE_LIFECYCLE_MAX_CLASSIFIED_DIFFERENCES]), before.state_digest, after.state_digest,
    )
    return _run_prepared_live_lifecycle_shadow_profile(prepared_request, readiness, store_root, snapshot)


_LIVE_LIFECYCLE_SESSION_DIRECTORY = ".roundwright-live-lifecycle-sessions"


def _live_lifecycle_session_id(
    prepared_request: LiveLifecyclePreparedRequest, readiness: LiveLifecycleReadinessReceipt,
) -> str:
    return _digest({
        "schema": "roundwright-live-lifecycle-session/v1",
        "prepared": prepared_request.public_receipt(),
        "readiness": readiness.public_receipt(),
    })


def _live_lifecycle_session_path(store_root: Path, session_id: str) -> Path:
    if not isinstance(store_root, Path) or _DIGEST.fullmatch(session_id) is None:
        raise ExternalValidationAdapterError("live lifecycle session location is invalid")
    return store_root / _LIVE_LIFECYCLE_SESSION_DIRECTORY / f"{session_id[7:]}.json"


def _claim_live_lifecycle_session(store_root: Path, session_id: str) -> None:
    """Atomically reserve one session before any provider capability is touched.

    ``O_EXCL`` is the durable, cross-process single-winner primitive.  The
    claim is intentionally separate from the human-readable receipt update so
    a second process can never observe a stale ``consumed`` flag and dispatch.
    """

    session_path = _live_lifecycle_session_path(store_root, session_id)
    claim_path = session_path.with_suffix(".claim")
    try:
        claim_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(str(claim_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as claim:
            claim.write(session_id)
            claim.flush()
            os.fsync(claim.fileno())
    except FileExistsError as error:
        raise ExternalValidationAdapterError("live lifecycle session is already consumed") from error
    except OSError as error:
        raise ExternalValidationAdapterError("live lifecycle session claim persistence failed") from error


def _live_lifecycle_inputs_payload(inputs: LiveLifecycleRequestInputs) -> dict[str, object]:
    return {
        "base_sha": inputs.base_sha, "candidate_sha": inputs.candidate_sha,
        "target_repository": inputs.target_repository, "target_baseline_sha": inputs.target_baseline_sha,
        "case_id": inputs.case_id, "observation_window": inputs.observation_window,
        "ready_at": inputs.ready_at, "recorder_commit": inputs.recorder_commit,
        "recorder_content": inputs.recorder_content, "recorder_tree": inputs.recorder_tree,
        "retention_namespace": inputs.retention_namespace,
        "trace_repository": inputs.trace_repository,
        "trace_pull_request": inputs.trace_pull_request,
        "trace_publisher_identity": inputs.trace_publisher_identity,
        "lifecycle_ledger": inputs.lifecycle_ledger.public_payload(),
        "fixture_manifest": None if inputs.fixture_manifest is None else {
            "value": inputs.fixture_manifest.payload(),
            "manifest_digest": inputs.fixture_manifest.manifest_digest,
            "raw_utf8_b64": None if inputs.fixture_manifest.raw_utf8 is None else base64.b64encode(inputs.fixture_manifest.raw_utf8).decode("ascii"),
        },
    }


def _live_lifecycle_session_payload(
    prepared_request: LiveLifecyclePreparedRequest,
    readiness: LiveLifecycleReadinessReceipt,
    *,
    trace_readback_digest: str | None,
    consumed: bool,
) -> dict[str, object]:
    return {
        "schema": "roundwright-live-lifecycle-session/v1",
        "session_id": _live_lifecycle_session_id(prepared_request, readiness),
        "inputs": _live_lifecycle_inputs_payload(prepared_request.inputs),
        "prepared": {
            "capture_plan_digest": prepared_request.capture_plan_digest,
            "request_digest": prepared_request.request_digest,
            "recorder_identity": prepared_request.recorder_identity,
            "store_root_identity": prepared_request.store_root_identity,
            "store_identity": prepared_request.store_identity,
            "observation_identity": prepared_request.observation_identity,
            "request_value": dict(prepared_request._request_value),
        },
        "readiness": readiness.public_receipt(),
        "trace_readback_digest": trace_readback_digest,
        "consumed": consumed,
    }


def _write_live_lifecycle_session(
    store_root: Path, payload: Mapping[str, object], *, replace_existing: bool = False,
) -> None:
    session_id = payload.get("session_id")
    if type(session_id) is not str:
        raise ExternalValidationAdapterError("live lifecycle session is invalid")
    path = _live_lifecycle_session_path(store_root, session_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not replace_existing:
            raise ExternalValidationAdapterError("live lifecycle session already exists")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        temporary.replace(path)
    except OSError as error:
        raise ExternalValidationAdapterError("live lifecycle session persistence failed") from error


def _coerce_live_lifecycle_session_receipt(value: object) -> LiveLifecycleSessionReceipt:
    if type(value) is LiveLifecycleSessionReceipt:
        return value
    return LiveLifecycleSessionReceipt.parse(value)


def _load_live_lifecycle_session(
    receipt_value: object, store_root: Path,
) -> tuple[LiveLifecycleSessionReceipt, LiveLifecyclePreparedRequest, bool, str | None]:
    receipt = _coerce_live_lifecycle_session_receipt(receipt_value)
    path = _live_lifecycle_session_path(store_root, receipt.session_id)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if type(value) is not dict or set(value) != {
            "schema", "session_id", "inputs", "prepared", "readiness", "trace_readback_digest", "consumed",
        } or value["schema"] != "roundwright-live-lifecycle-session/v1" or value["session_id"] != receipt.session_id:
            raise ValueError
        if type(value["inputs"]) is not dict or type(value["prepared"]) is not dict:
            raise ValueError
        input_value = dict(value["inputs"])
        ledger_value = input_value.get("lifecycle_ledger")
        if (
            type(ledger_value) is not dict
            or set(ledger_value) != {"plan", "ledger_digest"}
        ):
            raise ValueError
        input_value["lifecycle_ledger"] = LiveLifecycleLedgerBinding(
            ledger_value["plan"], ledger_value["ledger_digest"],
        )
        manifest_value = input_value.get("fixture_manifest")
        if type(manifest_value) is not dict or set(manifest_value) != {"value", "manifest_digest", "raw_utf8_b64"}:
            raise ValueError
        if type(manifest_value["raw_utf8_b64"]) is not str:
            raise ValueError
        try:
            raw_manifest = base64.b64decode(manifest_value["raw_utf8_b64"], validate=True)
        except ValueError as error:
            raise ValueError from error
        manifest = FixtureSelectionManifest.parse(raw_manifest, manifest_value["manifest_digest"])
        if manifest.payload() != manifest_value["value"]:
            raise ValueError
        input_value["fixture_manifest"] = manifest
        inputs = LiveLifecycleRequestInputs(**input_value)
        prepared = value["prepared"]
        if set(prepared) != {
            "capture_plan_digest", "request_digest", "recorder_identity", "store_root_identity",
            "store_identity", "observation_identity", "request_value",
        } or type(prepared["request_value"]) is not dict:
            raise ValueError
        readiness = LiveLifecycleSessionReceipt.parse({
            "schema": "roundwright-live-lifecycle-session-receipt/v1",
            "session_id": receipt.session_id, "readiness": value["readiness"], "receipt_digest": receipt.receipt_digest,
        }).readiness
        materialized = LiveLifecyclePreparedRequest(
            inputs, prepared["capture_plan_digest"], prepared["request_digest"], prepared["recorder_identity"],
            prepared["store_root_identity"], prepared["store_identity"], prepared["observation_identity"],
            MappingProxyType(prepared["request_value"]),
        )
        if (
            _live_lifecycle_session_id(materialized, readiness) != receipt.session_id
            or readiness.public_receipt() != receipt.readiness.public_receipt()
            or type(value["consumed"]) is not bool
            or (value["trace_readback_digest"] is not None and _DIGEST.fullmatch(value["trace_readback_digest"]) is None)
        ):
            raise ValueError
        _validated_live_lifecycle_request(materialized, store_root)
        return receipt, materialized, value["consumed"], value["trace_readback_digest"]
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExternalValidationAdapterError("live lifecycle durable session is invalid") from error


def preflight_live_lifecycle_shadow_session(
    inputs: LiveLifecycleRequestInputs, store_root: Path,
) -> LiveLifecycleSessionReceipt:
    """Durably retain one provider-free preflight until trace confirmation."""

    prepared_request, readiness = _preflight_live_lifecycle_shadow_profile(inputs, store_root)
    payload = _live_lifecycle_session_payload(
        prepared_request, readiness, trace_readback_digest=None, consumed=False,
    )
    _write_live_lifecycle_session(store_root, payload)
    receipt = LiveLifecycleSessionReceipt(payload["session_id"], readiness)
    loaded, _prepared, consumed, trace = _load_live_lifecycle_session(receipt.public_receipt(), store_root)
    if consumed or trace is not None or loaded.public_receipt() != receipt.public_receipt():
        raise ExternalValidationAdapterError("live lifecycle session read-back failed")
    return receipt


def confirm_live_lifecycle_shadow_trace(
    session_receipt: object, store_root: Path, trace_readback_digest: str,
) -> LiveLifecycleSessionReceipt:
    """Record exact public trace read-back before any provider capability is armed."""

    if type(trace_readback_digest) is not str or _DIGEST.fullmatch(trace_readback_digest) is None:
        raise ExternalValidationAdapterError("live lifecycle trace read-back is invalid")
    receipt, prepared_request, consumed, trace = _load_live_lifecycle_session(session_receipt, store_root)
    if consumed or trace is not None:
        raise ExternalValidationAdapterError("live lifecycle session is unavailable")
    _write_live_lifecycle_session(store_root, _live_lifecycle_session_payload(
        prepared_request, receipt.readiness, trace_readback_digest=trace_readback_digest, consumed=False,
    ), replace_existing=True)
    loaded, _prepared, loaded_consumed, loaded_trace = _load_live_lifecycle_session(receipt.public_receipt(), store_root)
    if loaded_consumed or loaded_trace != trace_readback_digest:
        raise ExternalValidationAdapterError("live lifecycle trace confirmation read-back failed")
    return loaded


def execute_live_lifecycle_shadow_session(
    session_receipt: object, store_root: Path, capability: GitHubReadCapability,
) -> object:
    """Consume one trace-confirmed durable session through product-owned reads."""

    receipt, prepared_request, consumed, trace = _load_live_lifecycle_session(session_receipt, store_root)
    if consumed or trace is None:
        raise ExternalValidationAdapterError("live lifecycle session is not trace-confirmed")
    capability = _require_github_read_capability(capability)
    _claim_live_lifecycle_session(store_root, receipt.session_id)
    _write_live_lifecycle_session(store_root, _live_lifecycle_session_payload(
        prepared_request, receipt.readiness, trace_readback_digest=trace, consumed=True,
    ), replace_existing=True)
    _loaded, _prepared, consumed_readback, trace_readback = _load_live_lifecycle_session(
        receipt.public_receipt(), store_root,
    )
    if not consumed_readback or trace_readback != trace:
        raise ExternalValidationAdapterError("live lifecycle session consume read-back failed")
    return _materialize_live_lifecycle_shadow_profile(prepared_request, receipt.readiness, store_root, capability)


def prepare_live_lifecycle_context(
    descriptor_value: object, *, plan_digest: str, candidate_sha: str, case_id: str, ready_at: int,
) -> MaterializedLiveLifecycleContext:
    descriptor = LiveLifecycleRuntimeDescriptor.parse(descriptor_value)
    if (descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at) != (
        plan_digest, candidate_sha, case_id, ready_at,
    ):
        raise ExternalValidationAdapterError("live lifecycle runtime descriptor does not match capture plan")
    return MaterializedLiveLifecycleContext(descriptor)


def _live_lifecycle_binding_identity(binding: object) -> str:
    try:
        value = {
            "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "profile": binding.profile,
            "case_id": binding.case_id, "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at, "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("live lifecycle binding is invalid") from error
    if (
        value["profile"] != LIVE_LIFECYCLE_SHADOW_PROFILE
        or not _safe_token(value["case_id"])
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int or value["ready_at"] < 0
        or _DIGEST.fullmatch(value["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("live lifecycle binding is invalid")
    return _digest(value)


def _live_lifecycle_context(binding: object) -> MaterializedLiveLifecycleContext:
    try:
        context, descriptor_digest = binding.execution_context, binding.execution_context_input_digest
        value = context.value
    except AttributeError as error:
        raise ExternalValidationAdapterError("live lifecycle V2 execution context is unavailable") from error
    if type(value) is not MaterializedLiveLifecycleContext or _DIGEST.fullmatch(descriptor_digest) is None:
        raise ExternalValidationAdapterError("live lifecycle V2 execution context has drifted")
    descriptor = value.descriptor
    if (descriptor.capture_plan_digest, descriptor.candidate_sha, descriptor.case_id, descriptor.ready_at) != (
        binding.plan.plan_digest, binding.candidate_sha, binding.case_id, binding.ready_at,
    ):
        raise ExternalValidationAdapterError("live lifecycle V2 execution context has drifted")
    return value


def _bound_live_lifecycle_snapshot(
    binding: object, snapshot: LiveLifecycleShadowSnapshot, context: MaterializedLiveLifecycleContext,
) -> None:
    descriptor = context.descriptor
    if (
        snapshot.target_repository != descriptor.target_repository
        or snapshot.target_baseline_sha != descriptor.target_baseline_sha
        or (snapshot.candidate_sha, snapshot.capture_plan_digest, snapshot.case_id, snapshot.ready_at, snapshot.observation_window)
        != (binding.candidate_sha, binding.plan.plan_digest, binding.case_id, binding.ready_at, descriptor.observation_window)
    ):
        raise ExternalValidationAdapterError("live lifecycle snapshot has drifted")


@dataclass(frozen=True)
class LiveLifecycleShadowProfileAdapter:
    """Read-only adapter for an already-armed and independently read-back window."""

    snapshot: LiveLifecycleShadowSnapshot | None = None
    profile_id: str = LIVE_LIFECYCLE_SHADOW_PROFILE

    def __post_init__(self) -> None:
        if self.profile_id != LIVE_LIFECYCLE_SHADOW_PROFILE or (
            self.snapshot is not None and type(self.snapshot) is not LiveLifecycleShadowSnapshot
        ):
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        return _harness_executor().ProfileComponentIdentities(*live_lifecycle_shadow_component_identities())

    def prepare_execution_context(self, preparation: object) -> object:
        try:
            context = prepare_live_lifecycle_context(
                preparation.descriptor, plan_digest=preparation.plan.plan_digest,
                candidate_sha=preparation.plan.candidate_sha, case_id=preparation.plan.case_id,
                ready_at=preparation.plan.ready_at,
            )
            return _harness_executor().ProfileExecutionContext(context.identity, context)
        except (AttributeError, ExternalValidationAdapterError) as error:
            raise ExternalValidationAdapterError("live lifecycle V2 execution context is invalid") from error

    def validate(self, binding: object) -> None:
        _live_lifecycle_binding_identity(binding)
        _live_lifecycle_context(binding)
        try:
            actual = (
                binding.components.producer_identity, binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ExternalValidationAdapterError("live lifecycle components are invalid") from error
        if actual != live_lifecycle_shadow_component_identities():
            raise ExternalValidationAdapterError("live lifecycle components have drifted")
        if shadow_evidence_profile(LIVE_LIFECYCLE_SHADOW_PROFILE).capture_mode.value != "armed-live-events":
            raise ExternalValidationAdapterError("live lifecycle profile capture mode has drifted")

    def execute(self, binding: object) -> object:
        identity = _live_lifecycle_binding_identity(binding)
        context = _live_lifecycle_context(binding)
        if self.snapshot is None:
            raise ExternalValidationAdapterError(LIVE_LIFECYCLE_OBSERVATION_BLOCKER)
        _bound_live_lifecycle_snapshot(binding, self.snapshot, context)
        return _harness_executor().ProfileExecution(
            {"schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "binding_identity": identity, "snapshot": self.snapshot},
            mutation_count=0,
        )

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        identity = _live_lifecycle_binding_identity(binding)
        context = _live_lifecycle_context(binding)
        try:
            value, mutation_count, snapshot = execution.value, execution.mutation_count, execution.value["snapshot"]
        except (AttributeError, KeyError, TypeError) as error:
            raise ExternalValidationAdapterError("live lifecycle result is invalid") from error
        if (
            type(value) is not dict or value.get("schema") != LIVE_LIFECYCLE_SHADOW_SCHEMA
            or value.get("binding_identity") != identity or type(snapshot) is not LiveLifecycleShadowSnapshot
            or mutation_count != 0
        ):
            raise ExternalValidationAdapterError("live lifecycle result has drifted")
        _bound_live_lifecycle_snapshot(binding, snapshot, context)
        return {
            "schema": "roundwright-shadow-case/v2", "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
            "ready_at": binding.ready_at, "case_id": binding.case_id,
            "candidate_sha": binding.candidate_sha, "capture_plan_digest": binding.plan.plan_digest,
            "live_lifecycle_shadow": {
                "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "binding_identity": identity,
                "producer_identity": LIVE_LIFECYCLE_PRODUCER_IDENTITY,
                "exporter_identity": LIVE_LIFECYCLE_EXPORTER_IDENTITY,
                "comparator_identity": LIVE_LIFECYCLE_COMPARATOR_IDENTITY,
                "snapshot": snapshot.public_payload(), "mutation_count": 0,
            },
        }

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        snapshot = self.snapshot
        if snapshot is None:
            raise ExternalValidationAdapterError(LIVE_LIFECYCLE_OBSERVATION_BLOCKER)
        expected = self.project(binding, self.execute(binding))
        # A non-empty classified set is itself sealed blocked evidence.  It
        # must survive projection but can never normalize to a passing result.
        status = "fail" if snapshot.classified_differences or type(evidence) is not dict or evidence != expected else "pass"
        return _harness_executor().ProfileComparison(status, _digest({
            "schema": LIVE_LIFECYCLE_SHADOW_SCHEMA, "status": status,
            "ready_at": binding.ready_at, "expected_identity": _digest(expected),
            "observed_identity": _digest(evidence),
            "classified_differences": list(snapshot.classified_differences),
            "classified_difference_count": len(snapshot.classified_differences),
        }))


def _integrated_boundary_binding_identity(binding: object) -> str:
    try:
        payload = {
            "schema": INTEGRATED_BOUNDARY_SCHEMA, "profile": binding.profile,
            "case_id": binding.case_id, "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at, "plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ExternalValidationAdapterError("integrated boundary binding is invalid") from error
    if (
        payload["profile"] != INTEGRATED_BOUNDARY_PROFILE or not isinstance(payload["case_id"], str)
        or not payload["case_id"] or _SHA.fullmatch(payload["candidate_sha"]) is None
        or type(payload["ready_at"]) is not int or payload["ready_at"] < 0
        or _DIGEST.fullmatch(payload["plan_digest"]) is None
    ):
        raise ExternalValidationAdapterError("integrated boundary binding is invalid")
    return _digest(payload)


@dataclass(frozen=True)
class MaterializedIntegratedBoundaryContext:
    """Opaque retained inputs bound to one exact V2 composition descriptor."""

    descriptor: dict[str, object]
    inputs: IntegratedBoundaryInputs
    input_digest: str
    candidate_sha: str
    case_id: str
    capture_plan_digest: str
    ready_at: int

    def __post_init__(self) -> None:
        if (
            type(self.descriptor) is not dict
            or type(self.inputs) is not IntegratedBoundaryInputs
            or self.descriptor != integrated_boundary_execution_context(self.inputs)
            or self.input_digest != _digest(self.descriptor)
            or (self.candidate_sha, self.case_id, self.capture_plan_digest)
            != (self.inputs.candidate_sha, self.inputs.case_id, self.inputs.capture_plan_digest)
            or _SHA.fullmatch(self.candidate_sha) is None
            or not _safe_token(self.case_id)
            or _DIGEST.fullmatch(self.capture_plan_digest) is None
            or type(self.ready_at) is not int or self.ready_at < 0
        ):
            raise ExternalValidationAdapterError("integrated boundary V2 execution context is invalid")

    @property
    def identity(self) -> str:
        return _digest({
            "schema": "roundwright-integrated-boundary-context-binding/v1",
            "descriptor": self.descriptor, "input_digest": self.input_digest,
            "candidate_sha": self.candidate_sha, "case_id": self.case_id,
            "capture_plan_digest": self.capture_plan_digest, "ready_at": self.ready_at,
        })


def _integrated_boundary_context(
    binding: object, inputs: IntegratedBoundaryInputs,
) -> MaterializedIntegratedBoundaryContext:
    try:
        context = binding.execution_context
        descriptor_digest = binding.execution_context_input_digest
        value = context.value
    except AttributeError as error:
        raise ExternalValidationAdapterError("integrated boundary V2 execution context is unavailable") from error
    if (
        type(value) is not MaterializedIntegratedBoundaryContext
        or type(descriptor_digest) is not str
        or value.inputs != inputs
        or value.input_digest != descriptor_digest
        or value.descriptor != integrated_boundary_execution_context(inputs)
        or context.identity != value.identity
        or (value.candidate_sha, value.case_id, value.capture_plan_digest, value.ready_at)
        != (binding.candidate_sha, binding.case_id, binding.plan.plan_digest, binding.ready_at)
    ):
        raise ExternalValidationAdapterError("integrated boundary V2 execution context has drifted")
    return value


@dataclass(frozen=True)
class IntegratedBoundaryCompositionAdapter:
    """Reviewed V2 adapter that composes retained evidence without live access."""

    inputs: IntegratedBoundaryInputs | None = None
    profile_id: str = INTEGRATED_BOUNDARY_PROFILE

    def __post_init__(self) -> None:
        if self.profile_id != INTEGRATED_BOUNDARY_PROFILE or (self.inputs is not None and type(self.inputs) is not IntegratedBoundaryInputs):
            raise ExternalValidationAdapterError("executor profile is unsupported")

    @property
    def component_identities(self) -> object:
        return _harness_executor().ProfileComponentIdentities(*integrated_boundary_component_identities())

    def prepare_execution_context(self, preparation: object) -> object:
        """Bind the closed retained tuple to the exact Harness V2 descriptor."""

        try:
            inputs = self.inputs
            if inputs is None:
                raise ValueError
            descriptor = integrated_boundary_execution_context(inputs)
            if (
                preparation.descriptor != descriptor
                or preparation.input_digest != _digest(descriptor)
                or preparation.components != self.component_identities
                or (
                    preparation.plan.candidate_sha,
                    preparation.plan.case_id,
                    preparation.plan.plan_digest,
                ) != (inputs.candidate_sha, inputs.case_id, inputs.capture_plan_digest)
            ):
                raise ValueError
            context = MaterializedIntegratedBoundaryContext(
                descriptor, inputs, preparation.input_digest,
                preparation.plan.candidate_sha, preparation.plan.case_id,
                preparation.plan.plan_digest, preparation.plan.ready_at,
            )
            return _harness_executor().ProfileExecutionContext(context.identity, context)
        except (AttributeError, TypeError, ValueError, ExternalValidationAdapterError) as error:
            raise ExternalValidationAdapterError("integrated boundary V2 execution context is invalid") from error

    def validate(self, binding: object) -> None:
        _integrated_boundary_binding_identity(binding)
        try:
            components = (binding.components.producer_identity, binding.components.exporter_identity, binding.components.comparator_identity)
        except AttributeError as error:
            raise ExternalValidationAdapterError("integrated boundary components are invalid") from error
        if components != integrated_boundary_component_identities():
            raise ExternalValidationAdapterError("integrated boundary components have drifted")
        if self.inputs is None or (
            self.inputs.candidate_sha != binding.candidate_sha or self.inputs.case_id != binding.case_id
            or self.inputs.capture_plan_digest != binding.plan.plan_digest
        ):
            raise ExternalValidationAdapterError("integrated retained evidence is unavailable or stale")
        _integrated_boundary_context(binding, self.inputs)

    def execute(self, binding: object) -> object:
        self.validate(binding)
        assert self.inputs is not None
        manifest, result = compose_retained_evidence(self.inputs)
        return _harness_executor().ProfileExecution({"manifest": manifest.public_payload(), "result": result.public_payload()}, mutation_count=0)

    def project(self, binding: object, execution: object) -> Mapping[str, object]:
        self.validate(binding)
        assert self.inputs is not None
        manifest, result = compose_retained_evidence(self.inputs)
        try:
            if execution.mutation_count != 0 or execution.value != {"manifest": manifest.public_payload(), "result": result.public_payload()}:
                raise ValueError
        except (AttributeError, TypeError, ValueError) as error:
            raise ExternalValidationAdapterError("integrated boundary execution has drifted") from error
        return {
            "schema": "roundwright-shadow-case/v2", "profile": INTEGRATED_BOUNDARY_PROFILE,
            "ready_at": binding.ready_at, "case_id": binding.case_id, "candidate_sha": binding.candidate_sha,
            "capture_plan_digest": binding.plan.plan_digest, "integrated_boundary": execution.value,
        }

    def compare(self, binding: object, evidence: Mapping[str, object]) -> object:
        expected = self.project(binding, self.execute(binding))
        status = "pass" if type(evidence) is dict and evidence == expected else "fail"
        return _harness_executor().ProfileComparison(status, _digest({
            "schema": INTEGRATED_BOUNDARY_SCHEMA, "status": status, "ready_at": binding.ready_at,
            "expected_identity": _digest(expected), "observed_identity": _digest(evidence),
        }))


def roundwright_profile_adapter_factory(profile_id: str) -> SyntheticExecutorAdapter | ReadOnlyExternalObservationAdapter | ProviderAttemptAccountingAdapter | HostedCheckProfileAdapter | LiveLifecycleShadowProfileAdapter | IntegratedBoundaryCompositionAdapter:
    """Return the exact public adapter selected by the Harness executor."""

    if profile_id == EXECUTOR_CONTRACT_SYNTHETIC_PROFILE:
        return SyntheticExecutorAdapter(profile_id)
    if profile_id == READ_ONLY_EXTERNAL_OBSERVATION_PROFILE:
        raise ExternalValidationAdapterError(
            "read-only external observation requires the product-hosted V2 entrypoint"
        )
    if profile_id == PROVIDER_ATTEMPT_ACCOUNTING_PROFILE:
        return ProviderAttemptAccountingAdapter(profile_id)
    if profile_id == HOSTED_CHECK_PROFILE:
        return HostedCheckProfileAdapter(profile_id=profile_id)
    if profile_id == LIVE_LIFECYCLE_SHADOW_PROFILE:
        return LiveLifecycleShadowProfileAdapter(profile_id=profile_id)
    if profile_id == INTEGRATED_BOUNDARY_PROFILE:
        return IntegratedBoundaryCompositionAdapter(profile_id=profile_id)
    raise ExternalValidationAdapterError("executor profile is unsupported")


@dataclass(frozen=True)
class EvidenceLaneReceipt:
    """One public-safe, candidate-bound Lane A or Lane B state observation."""

    profile_id: str
    candidate_sha: str
    state: Literal["prepared", "armed", "verified", "stale"]
    result: Literal["pass", "fail"] | None = None

    def __post_init__(self) -> None:
        if (
            self.profile_id not in {
                READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
                LIVE_LIFECYCLE_SHADOW_PROFILE,
            }
            or _SHA.fullmatch(self.candidate_sha) is None
            or self.state not in {"prepared", "armed", "verified", "stale"}
            or (self.state == "verified") != (self.result in {"pass", "fail"})
            or (self.state != "verified" and self.result is not None)
        ):
            raise ExternalValidationAdapterError("evidence lane receipt is invalid")

    def stale(self) -> "EvidenceLaneReceipt":
        return EvidenceLaneReceipt(self.profile_id, self.candidate_sha, "stale")


@dataclass(frozen=True)
class TwoStageQualification:
    """Repository-specific Lane A/Supervisor/Lane B qualification ordering."""

    candidate_sha: str
    lane_a: EvidenceLaneReceipt | None = None
    lane_b: EvidenceLaneReceipt | None = None
    supervisor_pass: bool = False

    def __post_init__(self) -> None:
        if (
            _SHA.fullmatch(self.candidate_sha) is None
            or type(self.supervisor_pass) is not bool
            or any(
                receipt is not None and type(receipt) is not EvidenceLaneReceipt
                for receipt in (self.lane_a, self.lane_b)
            )
            or self.lane_a is not None and self.lane_a.profile_id != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
            or self.lane_b is not None and self.lane_b.profile_id != LIVE_LIFECYCLE_SHADOW_PROFILE
        ):
            raise ExternalValidationAdapterError("two-stage qualification is invalid")

    def _current(self, receipt: EvidenceLaneReceipt | None) -> bool:
        return receipt is not None and receipt.candidate_sha == self.candidate_sha and receipt.state != "stale"

    @property
    def supervisor_dispatch_allowed(self) -> bool:
        """Lane A passes and Lane B is armed before a Supervisor may start."""

        return (
            self._current(self.lane_a)
            and self.lane_a.state == "verified"
            and self.lane_a.result == "pass"
            and self._current(self.lane_b)
            and self.lane_b.state in {"armed", "verified"}
        )

    @property
    def lane_b_seal_allowed(self) -> bool:
        return self.supervisor_dispatch_allowed and self.supervisor_pass

    def merge_qualified(self, *, ci_pass: bool, policy_pass: bool, provenance_pass: bool) -> bool:
        """Require every current lane plus normal current qualification gates."""

        return (
            self.lane_b_seal_allowed
            and self.lane_b is not None
            and self.lane_b.state == "verified"
            and self.lane_b.result == "pass"
            and all(type(value) is bool and value for value in (ci_pass, policy_pass, provenance_pass))
        )

    def stale_for_candidate(self, candidate_sha: str) -> "TwoStageQualification":
        if _SHA.fullmatch(candidate_sha) is None:
            raise ExternalValidationAdapterError("two-stage qualification candidate is invalid")
        return TwoStageQualification(
            candidate_sha,
            self.lane_a.stale() if self.lane_a is not None else None,
            self.lane_b.stale() if self.lane_b is not None else None,
            False,
        )


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


def run_integrated_boundary_composition_profile(
    mode: Literal["validate", "execute"], request_value: Mapping[str, Any], store_root: Path,
    retained_inputs: IntegratedBoundaryInputs, *, expected_readiness_digest: str | None = None,
) -> object:
    """Run #50 composition through the reviewed V2 executor and Recorder path.

    ``retained_inputs`` must come from the concrete receipt parser in
    :mod:`roundwright.integrated_boundary`; this entrypoint never reads or
    replays a lower-level source itself.
    """

    harness = _harness_executor()
    try:
        request = harness.ExecutorRequest.parse(request_value)
        if (
            mode not in {"validate", "execute"}
            or request.schema != "roundwright-harness-profile-executor-request/v2"
            or request.capture_plan["profile"] != INTEGRATED_BOUNDARY_PROFILE
            or request.execution_context != integrated_boundary_execution_context(retained_inputs) or not isinstance(store_root, Path)
            or type(retained_inputs) is not IntegratedBoundaryInputs
            or (mode == "validate" and expected_readiness_digest is not None)
            or (mode == "execute" and _DIGEST.fullmatch(expected_readiness_digest or "") is None)
        ):
            raise ValueError
        plan = harness.prepare_capture(request.capture_plan)
        if (
            (plan.candidate_sha, plan.case_id, plan.plan_digest)
            != (retained_inputs.candidate_sha, retained_inputs.case_id, retained_inputs.capture_plan_digest)
        ):
            raise ValueError
        return harness.run_profile_executor(
            mode, request_value, IntegratedBoundaryCompositionAdapter(retained_inputs), store_root,
            expected_readiness_digest=expected_readiness_digest,
        )
    except (IntegratedBoundaryError, ExternalValidationAdapterError):
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("integrated boundary hosted entrypoint binding is invalid") from error


def run_read_only_external_observation_profile(
    mode: Literal["validate", "execute"],
    request_value: Mapping[str, Any],
    store_root: Path,
    host_inputs: ReadOnlyExternalObservationHostInputs,
    *,
    expected_readiness_digest: str | None = None,
) -> object:
    """Run Lane A only through the product-hosted opaque V2 executor boundary."""

    harness = _harness_executor()
    try:
        request = harness.ExecutorRequest.parse(request_value)
        if (
            mode not in {"validate", "execute"}
            or request.schema != "roundwright-harness-profile-executor-request/v2"
            or request.capture_plan["profile"] != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE
            or request.execution_context is None
            or not isinstance(store_root, Path)
            or type(host_inputs) is not ReadOnlyExternalObservationHostInputs
            or (mode == "validate" and expected_readiness_digest is not None)
            or (mode == "execute" and _DIGEST.fullmatch(expected_readiness_digest or "") is None)
        ):
            raise ValueError
        plan = harness.prepare_capture(request.capture_plan)
        context = prepare_read_only_external_observation_context(
            request.execution_context, plan_digest=plan.plan_digest, candidate_sha=plan.candidate_sha,
            case_id=plan.case_id, ready_at=plan.ready_at,
        )
        provider = _materialize_read_only_external_observation_provider(context.descriptor, host_inputs)
        return harness.run_profile_executor(
            mode, request_value, ReadOnlyExternalObservationAdapter(provider), store_root,
            expected_readiness_digest=expected_readiness_digest,
        )
    except ExternalValidationAdapterError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("read-only external observation hosted entrypoint binding is invalid") from error


def _run_prepared_live_lifecycle_shadow_profile(
    prepared_request: LiveLifecyclePreparedRequest,
    readiness: LiveLifecycleReadinessReceipt,
    store_root: Path,
    snapshot: LiveLifecycleShadowSnapshot,
) -> object:
    """Run the product-materialized lifecycle snapshot through the V2 executor.

    This private helper deliberately accepts the product-owned snapshot only
    after ``materialize_live_lifecycle_shadow_profile`` has armed the window
    and completed its independent before/after read-back.
    """

    harness = _harness_executor()
    try:
        if (
            type(prepared_request) is not LiveLifecyclePreparedRequest
            or type(readiness) is not LiveLifecycleReadinessReceipt
            or readiness._seal is not _LIVE_LIFECYCLE_READINESS_SEAL
        ):
            raise ValueError
        request_value = dict(prepared_request._request_value)
        if (
            _digest(request_value) != prepared_request.request_digest
            or _live_lifecycle_store_root_identity(store_root) != prepared_request.store_root_identity
        ):
            raise ValueError
        request = harness.ExecutorRequest.parse(request_value)
        if (
            request.schema != "roundwright-harness-profile-executor-request/v2"
            or request.capture_plan["profile"] != LIVE_LIFECYCLE_SHADOW_PROFILE
            or request.execution_context is None
            or not isinstance(store_root, Path)
            or type(snapshot) is not LiveLifecycleShadowSnapshot
            or readiness.capture_plan_digest != prepared_request.capture_plan_digest
            or (readiness.candidate_sha, readiness.case_id, readiness.ready_at)
            != (prepared_request.inputs.candidate_sha, prepared_request.inputs.case_id, prepared_request.inputs.ready_at)
        ):
            raise ValueError
        prepare_live_lifecycle_context(
            request.execution_context, plan_digest=prepared_request.capture_plan_digest,
            candidate_sha=prepared_request.inputs.candidate_sha,
            case_id=prepared_request.inputs.case_id, ready_at=prepared_request.inputs.ready_at,
        )
        return harness.run_profile_executor(
            "execute", request_value, LiveLifecycleShadowProfileAdapter(snapshot), store_root,
            expected_readiness_digest=readiness.receipt_digest,
        )
    except ExternalValidationAdapterError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        raise ExternalValidationAdapterError("live lifecycle hosted entrypoint binding is invalid") from error


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
