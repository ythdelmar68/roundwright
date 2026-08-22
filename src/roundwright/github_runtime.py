"""Orchestrator-only ``gh`` adapter and fail-closed mutation broker.

The typed values in :mod:`roundwright.github` remain usable by hermetic tests.
This module is the deliberately narrow process boundary used by a future
Orchestrator.  It never locates credentials, accepts token arguments, records
stderr, or exposes raw command output.  Workers and Supervisors receive only
the typed snapshots, capability status, and public-safe receipt digests.

Roundwright's repository authority is disabled by default.  Consequently a
``GitHubMutationBroker`` denies before calling its adapter unless *all*
repository-policy, deployment, candidate-gate, and semantic read-back evidence
has already been independently verified by an owner-side Orchestrator.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from threading import RLock
from typing import Callable, Mapping, Protocol
from urllib.parse import urlparse

from .deployment import (
    AuthorityReceiptVerification, DeploymentAuthorityDecision,
    DeploymentAuthorityReceipt, DeploymentIdentity, DeploymentMode,
    evaluate_deployment_authority,
)
from .dependency_policy import CandidateBinding, DependencyExecutionControl, DependencyPolicyError, DependencyStage
from .github import (
    BranchSnapshot,
    CommentsSnapshot,
    GitHubAdapter,
    GitHubContractError,
    GitHubFailure,
    GitHubFailureKind,
    GitHubMutationIntent,
    GitHubMutationOperation,
    GitHubMutationResult,
    GitHubReadOperation,
    GitHubReadRequest,
    GitHubReadResult,
    GitHubSnapshot,
    IssueSnapshot,
    IssueState,
    MutationDisposition,
    MutationReceipt,
    PullRequestSnapshot,
    PullRequestState,
    RemoteHeadSnapshot,
    ReviewsSnapshot,
    RequestedReviewersSnapshot,
    RepositoryRef,
    RepositoryInventoryEvidence,
    RepositoryInventoryFact,
    RepositoryInventorySection,
    RepositoryInventorySnapshot,
    normalize_github_response,
)
from .repository_policy import (
    GITHUB_REPOSITORY_OPERATION,
    RepositoryActivationReceipt,
    RepositoryDispatcherTransition,
    RepositoryMutationBinding,
    RepositoryMutationContext,
    RepositoryMutationDecision,
    RepositoryMutationOperation,
    RepositoryReceiptVerification,
    RepositoryReceiptStatus,
    StandingRepositoryAuthority,
    TrustedRepositoryPolicySnapshot,
    evaluate_repository_mutation_policy,
)


# GraphQL cursors are opaque provider values (typically base64 and therefore
# allowed to contain ``=``).  They are never interpolated into a shell.
_CURSOR = re.compile(r"[^\x00-\x1f\x7f]{1,1024}\Z")
_INVENTORY_FACT_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-\[\]]{0,255}\Z")
_STANDALONE_FIXTURE = re.compile(r"\bstandalone[ -]fixture\b", re.IGNORECASE)
_MALFORMED_PARENT_CHILD_FIXTURE = re.compile(r"\bmalformed[ -]parent child fixture\b", re.IGNORECASE)
_OWNER_INPUT_FIXTURE = re.compile(r"\bowner[ -]input fixture\b", re.IGNORECASE)
_BLOCKED_BY = re.compile(r"(?:^|\n)\s*(?:[-*]\s+)?Blocked by #(?P<number>[1-9][0-9]{0,8})\.?\s*(?=\n|\Z)", re.IGNORECASE)
_BLOCKED_BY_DECLARATION = re.compile(r"(?:^|\n)[ \t]*(?:[-*][ \t]+)?Blocked by\b[^\r\n]*", re.IGNORECASE)
ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED = (
    "roundwright-repository-inventory-first-read-boundary__safe-subcause-not-retained"
)


class RepositoryInventoryReadFailureCode(StrEnum):
    """Curated inventory failure classes; never a provider diagnostic channel."""

    HOST_FAILURE = "host-failure"
    MALFORMED_RESPONSE = "malformed-response"
    IDENTITY_DRIFT = "identity-drift"
    INCOMPLETE_CONNECTION = "incomplete-connection"
    CURSOR_FAILURE = "cursor-failure"
    DUPLICATE_EVIDENCE = "duplicate-evidence"
    CARDINALITY_FAILURE = "cardinality-failure"
    TIME_OR_HEALTH_FAILURE = "time-or-health-failure"


class RepositoryInventoryFailureStage(StrEnum):
    """Closed, public-safe inventory structural categories."""

    UNKNOWN = "unknown"
    REQUEST = "request"
    TRANSPORT = "transport"
    GRAPHQL_ENVELOPE = "graphql-envelope"
    JSON_DECODING = "json-decoding"
    CAPABILITY = "capability"
    NORMALIZER = "normalizer"
    RESULT_SEALING = "result-sealing"
    ROOT = "root"
    REPOSITORY = "repository"
    CONNECTION = "connection"
    CONNECTION_NODES = "connection-nodes"
    NODE = "node"
    FIELD = "field"
    PAGINATION = "pagination"


class RepositoryInventoryTransportSubcategory(StrEnum):
    """Closed public-safe facts for the credentialed host process seam."""

    UNKNOWN = "unknown"
    LAUNCH_EXCEPTION = "launch-exception"
    INVALID_RESULT_SHAPE = "invalid-result-shape"
    NONZERO_RETURN = "nonzero-return"


def _repository_inventory_failure_reason(
    code: RepositoryInventoryReadFailureCode,
    stage: RepositoryInventoryFailureStage = RepositoryInventoryFailureStage.UNKNOWN,
    transport_subcategory: RepositoryInventoryTransportSubcategory = RepositoryInventoryTransportSubcategory.UNKNOWN,
) -> str:
    prefix = f"{ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED}:{code.value}"
    if stage is RepositoryInventoryFailureStage.UNKNOWN:
        return prefix
    reason = f"{prefix}:{stage.value}"
    if (
        stage is RepositoryInventoryFailureStage.TRANSPORT
        and transport_subcategory is not RepositoryInventoryTransportSubcategory.UNKNOWN
    ):
        reason += f":{transport_subcategory.value}"
    return reason


def repository_inventory_failure_code(public_reason: object) -> RepositoryInventoryReadFailureCode | None:
    """Decode only this reviewed public-safe result code at the product boundary."""

    if type(public_reason) is not str:
        return None
    prefix = ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED + ":"
    if not public_reason.startswith(prefix):
        return None
    try:
        return RepositoryInventoryReadFailureCode(public_reason.removeprefix(prefix).partition(":")[0])
    except ValueError:
        return None


def repository_inventory_failure_stage(public_reason: object) -> RepositoryInventoryFailureStage | None:
    """Decode the optional closed structural category without provider detail."""

    if type(public_reason) is not str:
        return None
    prefix = ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED + ":"
    if not public_reason.startswith(prefix):
        return None
    values = public_reason.removeprefix(prefix).split(":")
    if len(values) == 1:
        return RepositoryInventoryFailureStage.UNKNOWN
    try:
        return RepositoryInventoryFailureStage(values[1])
    except ValueError:
        return RepositoryInventoryFailureStage.UNKNOWN


def repository_inventory_transport_subcategory(
    public_reason: object,
) -> RepositoryInventoryTransportSubcategory | None:
    """Decode one closed process-seam category without retaining host detail."""

    if (
        type(public_reason) is not str
        or repository_inventory_failure_code(public_reason) is None
        or repository_inventory_failure_stage(public_reason) is not RepositoryInventoryFailureStage.TRANSPORT
    ):
        return None
    values = public_reason.removeprefix(
        ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED + ":",
    ).split(":")
    if len(values) != 3:
        return RepositoryInventoryTransportSubcategory.UNKNOWN
    try:
        return RepositoryInventoryTransportSubcategory(values[2])
    except ValueError:
        return RepositoryInventoryTransportSubcategory.UNKNOWN


def _repository_inventory_failure_stage(error: BaseException) -> RepositoryInventoryFailureStage:
    if type(error) is _RepositoryInventoryDiagnosticError:
        return error.stage
    if type(error) is json.JSONDecodeError:
        return RepositoryInventoryFailureStage.ROOT
    message = str(error).lower()
    if "repository" in message or "default head" in message:
        return RepositoryInventoryFailureStage.REPOSITORY
    if "pagination" in message or "cursor" in message or "incomplete" in message or "continuation" in message:
        return RepositoryInventoryFailureStage.PAGINATION
    if "connection" in message or "collection" in message:
        return RepositoryInventoryFailureStage.CONNECTION
    if "duplicate evidence" in message:
        return RepositoryInventoryFailureStage.NODE
    if (
        "gh response object" in message
        or "gh response projection" in message
    ):
        return RepositoryInventoryFailureStage.ROOT
    if (
        "gh response field" in message
        or "gh response text" in message
        or "gh response number" in message
        or "gh response boolean" in message
        or "gh response identity" in message
        or "inventory label" in message
        or "scheduling" in message
    ):
        return RepositoryInventoryFailureStage.FIELD
    return RepositoryInventoryFailureStage.UNKNOWN


def _repository_inventory_failure_result(
    request: GitHubReadRequest,
    code: RepositoryInventoryReadFailureCode,
    stage: RepositoryInventoryFailureStage,
    kind: GitHubFailureKind = GitHubFailureKind.MALFORMED_RESPONSE,
    transport_subcategory: RepositoryInventoryTransportSubcategory = RepositoryInventoryTransportSubcategory.UNKNOWN,
) -> GitHubReadResult:
    """Seal only fixed inventory failure tokens across outer runtime layers."""

    return GitHubReadResult(request, failure=GitHubFailure(
        kind, request.operation, _repository_inventory_failure_reason(code, stage, transport_subcategory),
    ))


def _seal_repository_inventory_snapshot(
    request: GitHubReadRequest, snapshot: object,
) -> GitHubReadResult:
    """Seal a normalized inventory without exposing a construction failure."""

    try:
        return GitHubReadResult(request, snapshot=snapshot)  # type: ignore[arg-type]
    except GitHubContractError:
        return _repository_inventory_failure_result(
            request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
            RepositoryInventoryFailureStage.RESULT_SEALING,
        )


def _classify_repository_inventory_error(error: BaseException) -> RepositoryInventoryReadFailureCode:
    """Map internal validation outcomes to a finite public-safe code set."""

    message = str(error).lower()
    if "host" in message:
        return RepositoryInventoryReadFailureCode.HOST_FAILURE
    if "cursor" in message:
        return RepositoryInventoryReadFailureCode.CURSOR_FAILURE
    if "duplicate" in message:
        return RepositoryInventoryReadFailureCode.DUPLICATE_EVIDENCE
    if "exceeds bound" in message or "over-bound" in message or "cardinality" in message:
        return RepositoryInventoryReadFailureCode.CARDINALITY_FAILURE
    if "does not match" in message or "has drifted" in message or "default head" in message:
        return RepositoryInventoryReadFailureCode.IDENTITY_DRIFT
    if "incomplete" in message or "pagination" in message:
        return RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION
    return RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE


class GitHubRuntimeError(ValueError):
    """Raised when runtime-only adapter evidence is malformed."""


class _RepositoryInventoryDiagnosticError(GitHubRuntimeError):
    """Carry only a reviewed structural category to the sealed boundary."""

    def __init__(
        self,
        stage: RepositoryInventoryFailureStage,
        transport_subcategory: RepositoryInventoryTransportSubcategory = RepositoryInventoryTransportSubcategory.UNKNOWN,
    ) -> None:
        if (
            type(stage) is not RepositoryInventoryFailureStage
            or type(transport_subcategory) is not RepositoryInventoryTransportSubcategory
            or (
                stage is not RepositoryInventoryFailureStage.TRANSPORT
                and transport_subcategory is not RepositoryInventoryTransportSubcategory.UNKNOWN
            )
        ):
            raise GitHubRuntimeError("inventory diagnostic category is invalid")
        self.stage = stage
        self.transport_subcategory = transport_subcategory
        super().__init__("inventory structural validation failed")


def _trusted_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CapabilityState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission-denied"
    AUTHENTICATION_FAILED = "authentication-failed"
    TRANSPORT_FAILED = "transport-failed"


GitHubOperation = GitHubReadOperation | GitHubMutationOperation


@dataclass(frozen=True)
class OperationHealth:
    """One independently observed capability; no command transcript is kept."""

    operation: GitHubOperation
    state: CapabilityState
    observed_at: datetime
    evidence_digest: str
    fresh_until: datetime | None = None

    def __post_init__(self) -> None:
        if type(self.operation) not in (GitHubReadOperation, GitHubMutationOperation):
            raise GitHubRuntimeError("operation health operation is invalid")
        if type(self.state) is not CapabilityState or type(self.observed_at) is not datetime or self.observed_at.tzinfo is not timezone.utc:
            raise GitHubRuntimeError("operation health is invalid")
        _digest(self.evidence_digest, "operation health evidence")
        expiry = self.observed_at + timedelta(minutes=5) if self.fresh_until is None else self.fresh_until
        if type(expiry) is not datetime or expiry.tzinfo is not timezone.utc or expiry <= self.observed_at:
            raise GitHubRuntimeError("operation health freshness is invalid")
        object.__setattr__(self, "fresh_until", expiry)

    @property
    def available(self) -> bool:
        return self.state is CapabilityState.AVAILABLE

    def fresh_at(self, now: datetime) -> bool:
        return (
            type(now) is datetime
            and now.tzinfo is timezone.utc
            and self.observed_at <= now < self.fresh_until
        )


@dataclass(frozen=True)
class GitHubCapabilityHealth:
    """Exact, operation-level health matrix required before each adapter call."""

    observations: tuple[OperationHealth, ...]

    def __post_init__(self) -> None:
        declared = set(GitHubReadOperation) | set(GitHubMutationOperation)
        if type(self.observations) is not tuple or any(type(item) is not OperationHealth for item in self.observations):
            raise GitHubRuntimeError("capability health observations are invalid")
        if len(self.observations) != len(declared) or {item.operation for item in self.observations} != declared:
            raise GitHubRuntimeError("capability health must cover every declared operation")

    def for_operation(self, operation: GitHubOperation) -> OperationHealth:
        if type(operation) not in (GitHubReadOperation, GitHubMutationOperation):
            raise GitHubRuntimeError("capability operation is invalid")
        return next(item for item in self.observations if item.operation is operation)

    @property
    def identity(self) -> str:
        """Bind the complete observed capability profile, including validity."""

        return _sha256(tuple(
            (item.operation.value, item.state.value, item.observed_at.isoformat(),
             item.fresh_until.isoformat(), item.evidence_digest)
            for item in self.observations
        ))

    def fresh_at(self, now: datetime) -> bool:
        return type(now) is datetime and now.tzinfo is timezone.utc and all(
            item.fresh_at(now) for item in self.observations
        )


def _require_fresh_capabilities(
    health: GitHubCapabilityHealth, operations: tuple[GitHubOperation, ...], now: datetime,
) -> None:
    """Reject unavailable, future, or expired required capability evidence."""

    if type(health) is not GitHubCapabilityHealth or not health.fresh_at(now):
        raise GitHubRuntimeError("capability health evidence is stale or malformed")
    if any(not health.for_operation(operation).available for operation in operations):
        raise GitHubRuntimeError("required capability health is unavailable")


@dataclass(frozen=True)
class _GhCommandResult:
    """Ephemeral result from a preconfigured ``gh`` process invocation.

    ``stdout`` is parsed immediately by the adapter and never appears in a
    snapshot, receipt, exception, diagnostic, or durable trace.
    """

    exit_code: int
    stdout: str

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int or type(self.stdout) is not str:
            raise GitHubRuntimeError("gh command result is invalid")


class _FixedGhReadRunner(Protocol):
    """Private owner-host process boundary for pre-derived read commands."""

    def run(self, arguments: tuple[str, ...]) -> _GhCommandResult: ...


@dataclass(frozen=True)
class OwnerMutationRequest:
    """Sealed, non-command request accepted by an owner-controlled host."""

    intent_identity: str
    operation: GitHubMutationOperation
    authorization_bundle_identity: str
    semantic_plan_identity: str
    journal_identity: str
    repository: RepositoryRef
    target_number: int | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    marker_digest: str | None = None
    candidate_sha: str | None = None
    authorized_base_sha: str | None = None
    base_ref: str | None = None
    head_ref: str | None = None
    base_repository: RepositoryRef | None = None
    head_repository: RepositoryRef | None = None
    idempotency_identity: str | None = None
    command: BrokerMutationCommand | None = None
    deployment_identity: str | None = None
    pre_state_identity: str | None = None
    evaluated_at: str | None = None
    fresh_until: str | None = None
    time_identity: str | None = None
    capability_health_identity: str | None = None
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation:
            raise GitHubRuntimeError("owner mutation operation is invalid")
        if type(self.repository) is not RepositoryRef:
            raise GitHubRuntimeError("owner mutation repository is invalid")
        for value, name in ((self.intent_identity, "owner intent"), (self.authorization_bundle_identity, "owner bundle"), (self.semantic_plan_identity, "owner plan"), (self.journal_identity, "owner journal")):
            _digest(value, name)
        if self.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
            if any(type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value) for value in (self.base_sha, self.head_sha)):
                raise GitHubRuntimeError("owner pull request request sha is invalid")
            _digest(self.marker_digest, "owner pull request marker")
        elif self.operation is GitHubMutationOperation.COMMENT:
            if type(self.target_number) is not int or self.target_number <= 0 or self.base_sha is not None or self.head_sha is not None:
                raise GitHubRuntimeError("owner comment request target is invalid")
            _digest(self.marker_digest, "owner comment marker")
        elif any(value is not None for value in (self.base_sha, self.head_sha, self.marker_digest)):
            raise GitHubRuntimeError("owner non-allocating request resource evidence is invalid")
        sealed_values = (
            self.candidate_sha, self.idempotency_identity, self.command,
            self.deployment_identity, self.pre_state_identity, self.evaluated_at,
            self.fresh_until, self.time_identity, self.capability_health_identity,
        )
        if any(value is not None for value in sealed_values) and any(value is None for value in sealed_values):
            raise GitHubRuntimeError("owner mutation seal is incomplete")
        if all(value is not None for value in sealed_values):
            if type(self.candidate_sha) is not str or len(self.candidate_sha) not in {40, 64} or any(char not in "0123456789abcdef" for char in self.candidate_sha):
                raise GitHubRuntimeError("owner mutation candidate is invalid")
            for value, name in (
                (self.idempotency_identity, "owner idempotency"),
                (self.pre_state_identity, "owner pre-state"),
                (self.time_identity, "owner time"),
                (self.capability_health_identity, "owner capability health"),
            ):
                _digest(value, name)
            _fingerprint(self.deployment_identity, "owner deployment")
            if type(self.command) is not BrokerMutationCommand or self.command is not _MUTATION_COMMAND_BY_OPERATION[self.operation]:
                raise GitHubRuntimeError("owner mutation command is invalid")
            for value, name in ((self.evaluated_at, "owner evaluated time"), (self.fresh_until, "owner fresh until")):
                try:
                    parsed = datetime.fromisoformat(value)
                except (TypeError, ValueError) as error:
                    raise GitHubRuntimeError(f"{name} is invalid") from error
                if parsed.tzinfo is not timezone.utc:
                    raise GitHubRuntimeError(f"{name} is invalid")
            if self.time_identity != _sha256((self.evaluated_at, self.fresh_until)):
                raise GitHubRuntimeError("owner mutation time seal drifted")
            if self.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
                if (
                    type(self.authorized_base_sha) is not str
                    or len(self.authorized_base_sha) not in {40, 64}
                    or any(char not in "0123456789abcdef" for char in self.authorized_base_sha)
                    or self.base_sha != self.authorized_base_sha
                    or self.head_sha != self.candidate_sha
                    or type(self.base_ref) is not str or not self.base_ref
                    or type(self.head_ref) is not str or not self.head_ref
                    or self.base_repository != self.repository
                    or self.head_repository != self.repository
                ):
                    raise GitHubRuntimeError("owner pull request request is not bound to the authorized base and candidate")
            elif any(value is not None for value in (
                self.authorized_base_sha, self.base_ref, self.head_ref,
                self.base_repository, self.head_repository,
            )):
                raise GitHubRuntimeError("owner non-pull-request request has base authorization evidence")
        elif any(value is not None for value in (
            self.authorized_base_sha, self.base_ref, self.head_ref,
            self.base_repository, self.head_repository,
        )):
            raise GitHubRuntimeError("owner pull request base authorization seal is incomplete")
        object.__setattr__(self, "identity", _sha256(tuple(
            self.operation.value if name == "operation" else self.repository.slug if name == "repository"
            else getattr(self, name).slug if name in {"base_repository", "head_repository"} and getattr(self, name) is not None
            else self.command.value if name == "command" and self.command is not None else getattr(self, name)
            for name in self.__dataclass_fields__ if name != "identity"
        )))


@dataclass(frozen=True)
class OwnerMutationFact:
    """Curated denial result; accepted results use ``OwnerMutationAcceptedFact``."""

    accepted: bool
    request_identity: str

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise GitHubRuntimeError("owner mutation fact is invalid")
        if self.accepted:
            raise GitHubRuntimeError("accepted owner fact requires allocation-aware accepted fact")
        _digest(self.request_identity, "owner request")


@dataclass(frozen=True)
class CreatedResourceLocator:
    """Curated immutable identity allocated by one identity-creating mutation."""

    operation: GitHubMutationOperation
    repository: RepositoryRef
    pull_request_number: int | None = None
    pull_request_id: str | None = None
    issue_number: int | None = None
    comment_id: str | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    draft: bool | None = None
    marker_digest: str | None = None
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef or self.operation not in {GitHubMutationOperation.CREATE_PULL_REQUEST, GitHubMutationOperation.COMMENT}:
            raise GitHubRuntimeError("created resource operation is invalid")
        _digest(self.marker_digest, "created resource marker")
        if self.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
            if (
                type(self.pull_request_number) is not int or self.pull_request_number <= 0
                or type(self.pull_request_id) is not str or not self.pull_request_id
                or self.issue_number is not None or self.comment_id is not None
                or type(self.draft) is not bool or not self.draft
            ):
                raise GitHubRuntimeError("created pull request locator is invalid")
            for value in (self.base_sha, self.head_sha):
                if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                    raise GitHubRuntimeError("created pull request locator sha is invalid")
        else:
            if type(self.issue_number) is not int or self.issue_number <= 0 or type(self.comment_id) is not str or not self.comment_id or any(value is not None for value in (self.pull_request_number, self.pull_request_id, self.base_sha, self.head_sha, self.draft)):
                raise GitHubRuntimeError("created comment locator is invalid")
        object.__setattr__(self, "identity", _sha256({
            "operation": self.operation.value,
            "repository": self.repository.slug,
            "pull_request_number": self.pull_request_number,
            "pull_request_id": self.pull_request_id,
            "issue_number": self.issue_number,
            "comment_id": self.comment_id,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "draft": self.draft,
            "marker_digest": self.marker_digest,
        }))


@dataclass(frozen=True)
class OwnerMutationAcceptedFact:
    """Curated accepted result, with an allocation locator when one exists."""

    request_identity: str
    operation: GitHubMutationOperation
    created_resource: CreatedResourceLocator | None = None
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        _digest(self.request_identity, "owner request")
        if type(self.operation) is not GitHubMutationOperation:
            raise GitHubRuntimeError("owner accepted fact operation is invalid")
        allocates_identity = self.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        }
        if allocates_identity != (type(self.created_resource) is CreatedResourceLocator):
            raise GitHubRuntimeError("owner accepted fact resource locator is invalid")
        if self.created_resource is not None and self.created_resource.operation is not self.operation:
            raise GitHubRuntimeError("owner accepted fact resource locator operation is invalid")
        object.__setattr__(self, "identity", _sha256((
            self.request_identity, self.operation.value,
            self.created_resource.identity if self.created_resource is not None else None,
        )))


class OwnerMutationTransport(Protocol):
    """Deployment-injected fixed protocol; absent transport fails closed."""

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact | OwnerMutationAcceptedFact: ...


@dataclass(frozen=True)
class OwnerMutationIpcMessage:
    """The sole mutation message permitted across the owner IPC boundary."""

    request: OwnerMutationRequest
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.request) is not OwnerMutationRequest:
            raise GitHubRuntimeError("owner mutation IPC request is invalid")
        object.__setattr__(self, "identity", _sha256(("owner-mutation-ipc/v1", self.request.identity)))


@dataclass(frozen=True)
class OwnerMutationIpcReply:
    """Curated typed reply; IPC never returns process output or argv."""

    message_identity: str
    fact: OwnerMutationFact | OwnerMutationAcceptedFact

    def __post_init__(self) -> None:
        _digest(self.message_identity, "owner mutation IPC message")
        if type(self.fact) not in {OwnerMutationFact, OwnerMutationAcceptedFact}:
            raise GitHubRuntimeError("owner mutation IPC reply is invalid")


class OwnerMutationIpcChannel(Protocol):
    """Owner-controlled process/IPC endpoint, deliberately not a command API."""

    def exchange_mutation(self, message: OwnerMutationIpcMessage) -> OwnerMutationIpcReply: ...


class OwnerMutationIpcClient:
    """Role-visible mutation client with an opaque, typed IPC channel only.

    A production client is provisioned with an operating-system IPC channel by
    the owner host.  No default channel exists: a missing channel is a denial.
    The channel protocol carries one sealed message type, not commands,
    environment values, credentials, or provider output.
    """

    __slots__ = ("__channel", "__endpoint_identity")

    def __init__(self, endpoint_identity: str, channel: OwnerMutationIpcChannel | None = None) -> None:
        _digest(endpoint_identity, "owner mutation IPC endpoint")
        if channel is not None and not hasattr(channel, "exchange_mutation"):
            raise GitHubRuntimeError("owner mutation IPC channel is invalid")
        self.__endpoint_identity = endpoint_identity
        self.__channel = channel

    @property
    def endpoint_identity(self) -> str:
        return self.__endpoint_identity

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact | OwnerMutationAcceptedFact:
        if type(request) is not OwnerMutationRequest:
            raise GitHubRuntimeError("owner mutation IPC request is invalid")
        channel = self.__channel
        if channel is None:
            return OwnerMutationFact(False, request.identity)
        message = OwnerMutationIpcMessage(request)
        try:
            reply = channel.exchange_mutation(message)
        except (AttributeError, TypeError, ValueError):
            return OwnerMutationFact(False, request.identity)
        if (
            type(reply) is not OwnerMutationIpcReply
            or reply.message_identity != message.identity
            or reply.fact.request_identity != request.identity
        ):
            return OwnerMutationFact(False, request.identity)
        return reply.fact


class OwnerGitHubReadEndpoint(Protocol):
    """Role-visible owner-host read surface: typed requests and curated facts only."""

    @property
    def health(self) -> GitHubCapabilityHealth: ...

    def read(self, request: GitHubReadRequest) -> GitHubReadResult: ...


class OwnerGitHubReadIpcChannel(Protocol):
    """Fixed typed read IPC; no REST path, GraphQL text, or raw response."""

    def exchange_read(self, request: GitHubReadRequest) -> GitHubReadResult: ...

    def exchange_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> "CollectionPage | None": ...


class OwnerGitHubReadIpcClient:
    """Narrow role-visible client for curated read snapshots only."""

    __slots__ = ("__channel", "__health")

    def __init__(self, health: GitHubCapabilityHealth, channel: OwnerGitHubReadIpcChannel | None = None) -> None:
        if type(health) is not GitHubCapabilityHealth:
            raise GitHubRuntimeError("owner read IPC health is invalid")
        if channel is not None and (
            not hasattr(channel, "exchange_read") or not hasattr(channel, "exchange_collection_page")
        ):
            raise GitHubRuntimeError("owner read IPC channel is invalid")
        self.__health = health
        self.__channel = channel

    @property
    def health(self) -> GitHubCapabilityHealth:
        return self.__health

    def read(self, request: GitHubReadRequest) -> GitHubReadResult:
        if type(request) is not GitHubReadRequest:
            raise GitHubContractError("read request is invalid")
        channel = self.__channel
        if channel is None:
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.UNAVAILABLE, request.operation, "owner read IPC capability is unavailable",
            ))
        try:
            result = channel.exchange_read(request)
        except (AttributeError, TypeError, ValueError):
            if request.operation is GitHubReadOperation.REPOSITORY_INVENTORY:
                return _repository_inventory_failure_result(
                    request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                    RepositoryInventoryFailureStage.CAPABILITY, GitHubFailureKind.UNAVAILABLE,
                )
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.UNAVAILABLE, request.operation, "owner read IPC response is unavailable",
            ))
        if type(result) is not GitHubReadResult or result.request != request:
            if request.operation is GitHubReadOperation.REPOSITORY_INVENTORY:
                return _repository_inventory_failure_result(
                    request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                    RepositoryInventoryFailureStage.CAPABILITY,
                )
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "owner read IPC response drifted",
            ))
        return result

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> "CollectionPage | None":
        if type(request) is not GitHubReadRequest:
            return None
        channel = self.__channel
        if channel is None:
            return None
        try:
            page = channel.exchange_collection_page(request, cursor)
        except (AttributeError, TypeError, ValueError):
            return None
        if type(page) is not CollectionPage or page.request != request or page.cursor != cursor:
            return None
        return page

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult:
        """The typed read client is never a mutation transport."""

        if type(intent) is not GitHubMutationIntent:
            raise GitHubContractError("mutation intent is invalid")
        return GitHubMutationResult(intent, failure=GitHubFailure(
            GitHubFailureKind.POLICY_DENIED, intent.operation, "owner read IPC does not execute mutations",
        ))


@dataclass(frozen=True)
class _OwnerGitHubReadControl:
    """Owner-host-only sealed dependency authority for credentialed reads."""

    binding: CandidateBinding
    dependency_control: DependencyExecutionControl
    now: int

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not CandidateBinding
            or type(self.dependency_control) is not DependencyExecutionControl
            or type(self.now) is not int
        ):
            raise GitHubRuntimeError("owner read dependency control is invalid")
        try:
            self.dependency_control.require(self.binding, DependencyStage.GITHUB_READ, now=self.now)
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner read dependency control is invalid") from error

    def require(self, request: GitHubReadRequest, binding: CandidateBinding, *, now: datetime) -> None:
        if (
            type(self) is not _OwnerGitHubReadControl
            or type(request) is not GitHubReadRequest
            or type(binding) is not CandidateBinding
            or type(now) is not datetime
            or now.tzinfo is not timezone.utc
            or int(now.timestamp()) < self.now
            or self.binding != binding
            or self.binding.repository != request.repository.slug
        ):
            raise GitHubRuntimeError("owner read dependency control is invalid")
        if (
            request.expected_sha is not None
            and request.operation not in {
                GitHubReadOperation.BRANCH,
                GitHubReadOperation.REMOTE_HEAD,
                GitHubReadOperation.REPOSITORY_INVENTORY,
            }
            and request.expected_sha != self.binding.candidate_sha
        ):
            raise GitHubRuntimeError("owner read dependency control does not match the requested candidate")
        try:
            self.dependency_control.require(
                self.binding, DependencyStage.GITHUB_READ, now=int(now.timestamp()),
            )
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner read dependency control is stale") from error


class _OwnerGitHubReadHostEndpoint:
    """``gh api`` adapter with explicit health gating and no mutation fallback.

    The adapter intentionally accepts the normalized JSON response schema from
    ``gh api``.  The small command builder keeps provider-specific URLs and
    raw output inside this module; callers only observe the contract types.
    A production Orchestrator must populate health through its own credential
    isolation path.  The default health helper below marks every operation
    unavailable, which is the safe construction for workers and tests.
    """

    def __init__(
        self, runner: _FixedGhReadRunner, binding: CandidateBinding, control: _OwnerGitHubReadControl,
        health: GitHubCapabilityHealth | None = None,
        *, clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not hasattr(runner, "run") or type(binding) is not CandidateBinding or type(control) is not _OwnerGitHubReadControl or clock is None:
            raise GitHubRuntimeError("gh runner is invalid")
        self.__runner = runner
        self.__binding = binding
        self.__control = control
        self._health = health or unavailable_capability_health()
        self.__clock = clock
        self.calls: list[tuple[str, str]] = []

    @property
    def health(self) -> GitHubCapabilityHealth:
        return self._health

    def _fresh_failure(self, request: GitHubReadRequest) -> GitHubFailure | None:
        """Read-host evidence is valid only at one owner-clock observation."""

        try:
            now = self.__clock()
        except Exception:
            return GitHubFailure(GitHubFailureKind.STALE_RESPONSE, request.operation, "owner read clock is unavailable")
        if type(now) is not datetime or now.tzinfo is not timezone.utc:
            return GitHubFailure(GitHubFailureKind.STALE_RESPONSE, request.operation, "owner read clock is invalid")
        health_failure = _health_failure(request.operation, self._health, now=now)
        if health_failure is not None:
            return health_failure
        try:
            self.__control.require(request, self.__binding, now=now)
        except (DependencyPolicyError, GitHubRuntimeError, ValueError):
            return GitHubFailure(GitHubFailureKind.POLICY_DENIED, request.operation, "owner read dependency preflight blocked execution")
        return None

    def read(self, request: GitHubReadRequest) -> GitHubReadResult:
        if type(request) is not GitHubReadRequest:
            raise GitHubContractError("read request is invalid")
        blocked = self._fresh_failure(request)
        if blocked is not None:
            if request.operation is GitHubReadOperation.REPOSITORY_INVENTORY:
                return GitHubReadResult(request, failure=GitHubFailure(
                    blocked.kind, request.operation,
                    _repository_inventory_failure_reason(RepositoryInventoryReadFailureCode.TIME_OR_HEALTH_FAILURE),
                ))
            return GitHubReadResult(request, failure=blocked)
        self.calls.append(("read", request.operation.value))
        if request.operation is GitHubReadOperation.REPOSITORY:
            return self._read_repository(request)
        if request.operation is GitHubReadOperation.REPOSITORY_INVENTORY:
            return self._read_repository_inventory(request)
        if request.operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
            return self._read_issue_with_relationships(request)
        if request.operation is GitHubReadOperation.CHECKS:
            return self._read_checks_with_candidate_evidence(request)
        if request.operation is GitHubReadOperation.WORKFLOW_RUNS:
            return self._read_workflows_with_candidate_evidence(request)
        if request.operation in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS}:
            return self._read_complete_collection(request)
        outcome = self.__runner.run(_read_command(request))
        if outcome.exit_code != 0:
            try:
                missing = json.loads(outcome.stdout)
            except (json.JSONDecodeError, TypeError):
                missing = None
            if (
                request.operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}
                and type(missing) is dict and missing.get("message") == "Not Found"
            ):
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, request.operation, "requested branch is absent"))
            return GitHubReadResult(request, failure=GitHubFailure(_failure_kind(outcome.exit_code), request.operation, "gh read did not return a usable response"))
        try:
            raw = json.loads(outcome.stdout)
            snapshot = normalize_github_response(request, _project_gh_response(request, raw))
            return GitHubReadResult(request, snapshot=snapshot)
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "gh read response is malformed"))

    def _read_repository(self, request: GitHubReadRequest) -> GitHubReadResult:
        """Compose the default head from two provider-established REST reads."""

        repository_outcome = self.__runner.run(_read_command(request))
        if repository_outcome.exit_code != 0:
            return GitHubReadResult(request, failure=GitHubFailure(
                _failure_kind(repository_outcome.exit_code), request.operation,
                "gh repository read did not return a usable response",
            ))
        try:
            repository_raw = json.loads(repository_outcome.stdout)
            metadata = _project_repository_metadata(request, repository_raw)
            branch_command = _repository_default_branch_command(
                request.repository, _raw_text(metadata, "default_branch"),
            )
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh repository response is malformed",
            ))
        branch_outcome = self.__runner.run(branch_command)
        if branch_outcome.exit_code != 0:
            return GitHubReadResult(request, failure=GitHubFailure(
                _failure_kind(branch_outcome.exit_code), request.operation,
                "gh default branch read did not return a usable response",
            ))
        try:
            branch_raw = json.loads(branch_outcome.stdout)
            projected = _compose_repository_default_head(request, metadata, repository_raw, branch_raw)
            return GitHubReadResult(request, snapshot=normalize_github_response(request, projected))
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh default branch response is malformed",
            ))

    def _read_repository_inventory(self, request: GitHubReadRequest) -> GitHubReadResult:
        """Read a bounded, terminal generic public repository inventory.

        The GraphQL request deliberately asks for provider page metadata on
        every collection.  This first host boundary fails closed if any
        collection exceeds its declared bound; it never labels a first page as
        a complete inventory.  Future pagination expansion can only add pages
        behind this reviewed projection, without changing the public contract.
        """

        try:
            command = _repository_inventory_command(request)
        except (GitHubContractError, GitHubRuntimeError, TypeError, ValueError):
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                RepositoryInventoryFailureStage.REQUEST,
            )
        try:
            outcome = self.__runner.run(command)
        except _RepositoryInventoryDiagnosticError as error:
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE, error.stage,
                transport_subcategory=error.transport_subcategory,
            )
        except (GitHubContractError, GitHubRuntimeError, TypeError, ValueError):
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                RepositoryInventoryFailureStage.TRANSPORT,
            )
        if outcome.exit_code != 0:
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.HOST_FAILURE,
                RepositoryInventoryFailureStage.TRANSPORT, _failure_kind(outcome.exit_code),
                RepositoryInventoryTransportSubcategory.NONZERO_RETURN,
            )
        try:
            envelope = _decode_inventory_graphql(outcome.stdout)
        except _RepositoryInventoryDiagnosticError as error:
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE, error.stage,
                transport_subcategory=error.transport_subcategory,
            )
        except (GitHubContractError, GitHubRuntimeError, TypeError, ValueError):
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                RepositoryInventoryFailureStage.GRAPHQL_ENVELOPE,
            )
        try:
            raw = _complete_repository_inventory_connections(request, envelope, self.__runner)
            snapshot = _normalize_repository_inventory(request, raw)
        except _RepositoryInventoryDiagnosticError as error:
            return _repository_inventory_failure_result(
                request, RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE, error.stage,
                transport_subcategory=error.transport_subcategory,
            )
        except GitHubContractError as error:
            return _repository_inventory_failure_result(
                request, _classify_repository_inventory_error(error),
                RepositoryInventoryFailureStage.NORMALIZER,
            )
        except (GitHubRuntimeError, TypeError, ValueError) as error:
            stage = _repository_inventory_failure_stage(error)
            return _repository_inventory_failure_result(
                request, _classify_repository_inventory_error(error), stage,
            )
        return _seal_repository_inventory_snapshot(request, snapshot)

    def _read_issue_with_relationships(self, request: GitHubReadRequest) -> GitHubReadResult:
        """Compose REST issue metadata with every native GraphQL child page."""

        metadata_outcome = self.__runner.run(_read_command(request))
        if metadata_outcome.exit_code != 0:
            return GitHubReadResult(request, failure=GitHubFailure(
                _failure_kind(metadata_outcome.exit_code), request.operation,
                "gh issue read did not return a usable response",
            ))
        try:
            metadata_raw = json.loads(metadata_outcome.stdout)
            metadata = _project_issue_metadata(request, metadata_raw)
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh issue response is malformed",
            ))
        try:
            children: list[int] = []
            page_evidence: list[str] = []
            expected_total: int | None = None
            cursor: str | None = None
            seen_cursors: set[str] = set()
            for _ in range(32):
                page_outcome = self.__runner.run(_issue_relationship_command(request, cursor))
                if page_outcome.exit_code != 0:
                    return GitHubReadResult(request, failure=GitHubFailure(
                        _failure_kind(page_outcome.exit_code), request.operation,
                        "gh issue relationship read did not return a usable response",
                    ))
                page_raw = json.loads(page_outcome.stdout)
                page_numbers, next_cursor, total_count = _project_issue_relationship_page(request, page_raw)
                if expected_total is None:
                    expected_total = total_count
                elif expected_total != total_count:
                    raise GitHubRuntimeError("gh issue relationship total changed during pagination")
                if any(number in children for number in page_numbers):
                    raise GitHubRuntimeError("gh issue relationship children are duplicated")
                children.extend(page_numbers)
                if len(children) > 3200:
                    raise GitHubRuntimeError("gh issue relationship item limit exceeded")
                page_evidence.append(_sha256(page_raw))
                if next_cursor is None:
                    if expected_total != len(children):
                        raise GitHubRuntimeError("gh issue relationship collection is truncated")
                    projected = _compose_issue_relationships(request, metadata, metadata_raw, children, page_evidence)
                    return GitHubReadResult(request, snapshot=normalize_github_response(request, projected))
                if next_cursor in seen_cursors:
                    raise GitHubRuntimeError("gh issue relationship cursor loop detected")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            raise GitHubRuntimeError("gh issue relationship page limit exceeded")
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh issue relationship response is malformed",
            ))

    def _read_checks_with_candidate_evidence(self, request: GitHubReadRequest) -> GitHubReadResult:
        candidate, candidate_failure = self._read_candidate_pull_request_evidence(request)
        if candidate_failure is not None:
            return candidate_failure
        assert candidate is not None
        try:
            checks: list[Mapping[str, object]] = []
            evidence: list[str] = []
            expected_total: int | None = None
            seen_ids: set[str] = set()
            for page in range(1, 33):
                outcome = self.__runner.run(_checks_page_command(request, page))
                if outcome.exit_code != 0:
                    return GitHubReadResult(request, failure=GitHubFailure(
                        _failure_kind(outcome.exit_code), request.operation,
                        "gh check-runs read did not return a usable response",
                    ))
                raw = json.loads(outcome.stdout)
                items, total_count = _project_checks_page(request, raw)
                if expected_total is None:
                    expected_total = total_count
                elif expected_total != total_count:
                    raise GitHubRuntimeError("gh check-runs total changed during pagination")
                for item in items:
                    identifier = _raw_id(item, "id")
                    if identifier in seen_ids:
                        raise GitHubRuntimeError("gh check-runs are duplicated")
                    seen_ids.add(identifier)
                    checks.append(item)
                if len(checks) > expected_total:
                    raise GitHubRuntimeError("gh check-runs total is inconsistent")
                evidence.append(_sha256(raw))
                if len(checks) == expected_total:
                    projected = _compose_checks(request, candidate, checks, evidence)
                    return GitHubReadResult(request, snapshot=normalize_github_response(request, projected))
                if not items:
                    raise GitHubRuntimeError("gh check-runs pagination is truncated")
            raise GitHubRuntimeError("gh check-runs page limit exceeded")
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh check-runs response is malformed",
            ))

    def _read_workflows_with_candidate_evidence(self, request: GitHubReadRequest) -> GitHubReadResult:
        candidate, candidate_failure = self._read_candidate_pull_request_evidence(request)
        if candidate_failure is not None:
            return candidate_failure
        assert candidate is not None
        try:
            runs: list[Mapping[str, object]] = []
            evidence: list[str] = []
            expected_total: int | None = None
            seen_ids: set[str] = set()
            for page in range(1, 33):
                outcome = self.__runner.run(_workflow_runs_page_command(request, page))
                if outcome.exit_code != 0:
                    return GitHubReadResult(request, failure=GitHubFailure(
                        _failure_kind(outcome.exit_code), request.operation,
                        "gh workflow-runs read did not return a usable response",
                    ))
                raw = json.loads(outcome.stdout)
                items, total_count = _project_workflow_runs_page(request, raw)
                if expected_total is None:
                    expected_total = total_count
                elif expected_total != total_count:
                    raise GitHubRuntimeError("gh workflow-runs total changed during pagination")
                for item in items:
                    identifier = _raw_id(item, "id")
                    if identifier in seen_ids:
                        raise GitHubRuntimeError("gh workflow-runs are duplicated")
                    seen_ids.add(identifier)
                    runs.append(item)
                if len(runs) > expected_total:
                    raise GitHubRuntimeError("gh workflow-runs total is inconsistent")
                evidence.append(_sha256(raw))
                if len(runs) == expected_total:
                    projected = _compose_workflow_runs(request, candidate, runs, evidence)
                    return GitHubReadResult(request, snapshot=normalize_github_response(request, projected))
                if not items:
                    raise GitHubRuntimeError("gh workflow-runs pagination is truncated")
            raise GitHubRuntimeError("gh workflow-runs page limit exceeded")
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh workflow-runs response is malformed",
            ))

    def _read_candidate_pull_request_evidence(
        self, request: GitHubReadRequest,
    ) -> tuple[Mapping[str, object] | None, GitHubReadResult | None]:
        outcome = self.__runner.run(_candidate_pull_request_command(request))
        if outcome.exit_code != 0:
            return None, GitHubReadResult(request, failure=GitHubFailure(
                _failure_kind(outcome.exit_code), request.operation,
                "gh candidate pull-request read did not return a usable response",
            ))
        try:
            raw = json.loads(outcome.stdout)
            return _project_candidate_pull_request_evidence(request, raw), None
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return None, GitHubReadResult(request, failure=GitHubFailure(
                GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                "gh candidate pull-request response is malformed",
            ))

    def _read_complete_collection(self, request: GitHubReadRequest) -> GitHubReadResult:
        """Expose only a terminal, complete native collection to direct callers."""

        cursor: str | None = None
        pages: list[CollectionPage] = []
        while True:
            if len(pages) >= 32:
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection page limit is exceeded",
                ))
            page = self.read_collection_page(request, cursor)
            if type(page) is not CollectionPage:
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection pagination metadata is unavailable",
                ))
            if page.request != request or page.cursor != cursor:
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection page request drifted",
                ))
            if pages and page.total_count != pages[0].total_count:
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection total is inconsistent",
                ))
            if page.total_count > 3200:
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection item limit is exceeded",
                ))
            if page.next_cursor is not None and (
                any(prior.cursor == page.next_cursor for prior in pages)
                or page.next_cursor == cursor
            ):
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    "collection cursor is repeated or cyclic",
                ))
            pages.append(page)
            if page.next_cursor is None:
                return _normalize_complete_collection_pages(request, pages)
            cursor = page.next_cursor

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> "CollectionPage | None":
        """Read one native GraphQL connection page, or fail closed.

        GitHub's REST list responses deliberately do not carry a JSON terminal
        marker.  The broker must not infer completeness from that absence, so
        collection reads use the provider's typed GraphQL connection instead.
        ``pageInfo`` and ``totalCount`` are projected only after the repository,
        target, and candidate identities have been checked.
        """

        if type(request) is not GitHubReadRequest or request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS}:
            return None
        if cursor is not None and (type(cursor) is not str or not _CURSOR.fullmatch(cursor)):
            return None
        if self._fresh_failure(request) is not None:
            return None
        self.calls.append(("collection-read", request.operation.value))
        command = (
            _requested_reviewers_collection_command(request, cursor)
            if request.operation is GitHubReadOperation.REQUESTED_REVIEWERS
            else _collection_read_command(request, cursor)
        )
        outcome = self.__runner.run(command)
        if outcome.exit_code != 0:
            return None
        try:
            raw = json.loads(outcome.stdout)
            if request.operation is GitHubReadOperation.REQUESTED_REVIEWERS:
                projected = _project_requested_reviewers_page(request, raw)
                next_cursor = projected["next_cursor"]
                if next_cursor is not None and type(next_cursor) is not str:
                    raise GitHubRuntimeError("requested reviewer continuation is malformed")
                root = _raw_mapping(raw)
                graph_repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
                pull_request = _raw_mapping(graph_repository.get("pullRequest"))
                total_count = _raw_integer(_raw_mapping(pull_request.get("reviewRequests")), "totalCount")
            else:
                projected, next_cursor, total_count = _project_gh_collection_page(request, raw)
            snapshot = normalize_github_response(request, projected)
            return CollectionPage(request, cursor, next_cursor, total_count, snapshot)
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return None

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult:
        """Refuse direct writes; only the broker-only seam may execute one."""

        if type(intent) is not GitHubMutationIntent:
            raise GitHubContractError("mutation intent is invalid")
        self.calls.append(("mutation", intent.operation.value))
        blocked = _health_failure(intent.operation, self._health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked)
        return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "direct gh mutation is forbidden; use the mutation broker"))



@dataclass(frozen=True, repr=False)
class GhMutationPayload:
    """Ephemeral outbound material held by the credential-owning Orchestrator.

    It is a typed value rather than a command string.  Its raw text is never
    put into adapter calls, receipts, exceptions, or diagnostics; only the
    matching public digest from ``GitHubMutationIntent`` crosses into the core.
    """

    operation: GitHubMutationOperation
    values: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation or type(self.values) is not tuple:
            raise GitHubRuntimeError("gh mutation payload is invalid")
        if any(type(item) is not tuple or len(item) != 2 or any(type(value) is not str or "\x00" in value for value in item) for item in self.values):
            raise GitHubRuntimeError("gh mutation payload values are invalid")
        if tuple(sorted(self.values)) != self.values or len({key for key, _ in self.values}) != len(self.values):
            raise GitHubRuntimeError("gh mutation payload is not canonical")
        required = {
            GitHubMutationOperation.CREATE_BRANCH: set(),
            GitHubMutationOperation.UPDATE_BRANCH: set(),
            GitHubMutationOperation.DELETE_BRANCH: set(),
            GitHubMutationOperation.CREATE_PULL_REQUEST: {"body", "title"},
            GitHubMutationOperation.COMMENT: {"body"},
            GitHubMutationOperation.REQUEST_REVIEW: {"reviewers"},
            GitHubMutationOperation.MARK_READY: set(),
            GitHubMutationOperation.MERGE_PULL_REQUEST: set(),
            GitHubMutationOperation.CLOSE_ISSUE: set(),
        }[self.operation]
        if set(dict(self.values)) != required:
            raise GitHubRuntimeError("gh mutation payload fields are invalid")
        if self.operation is GitHubMutationOperation.REQUEST_REVIEW:
            reviewers = self.value("reviewers").split(",")
            if not reviewers or any(not re.fullmatch(r"[A-Za-z0-9-]{1,39}", reviewer) for reviewer in reviewers):
                raise GitHubRuntimeError("gh mutation reviewers are invalid")

    def value(self, key: str) -> str:
        try:
            return dict(self.values)[key]
        except KeyError as error:
            raise GitHubRuntimeError("gh mutation payload field is unavailable") from error

    def require_matches(self, intent: GitHubMutationIntent) -> None:
        if type(intent) is not GitHubMutationIntent or intent.operation is not self.operation:
            raise GitHubRuntimeError("gh mutation payload operation does not match intent")
        expected = dict(intent.payload)
        if self.operation is GitHubMutationOperation.COMMENT:
            if expected.get("body_digest") != _sha256(("comment-body", self.value("body"))):
                raise GitHubRuntimeError("gh comment payload does not match intent")
        elif self.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
            if (
                expected.get("title_digest") != _sha256(("pull-request-title", self.value("title")))
                or expected.get("body_digest") != _sha256(("pull-request-body", self.value("body")))
            ):
                raise GitHubRuntimeError("gh pull request payload does not match intent")
        elif self.operation is GitHubMutationOperation.REQUEST_REVIEW:
            reviewers = tuple(self.value("reviewers").split(","))
            if not reviewers or tuple(sorted(reviewers)) != reviewers or len(set(reviewers)) != len(reviewers) or expected.get("reviewers_digest") != _sha256(("reviewers", reviewers)):
                raise GitHubRuntimeError("gh reviewer payload does not match intent")


class _OwnerGitHubReadHostChannel:
    """Private bridge retaining process and raw-response capability at the host."""

    __slots__ = ("__endpoint",)

    def __init__(self, endpoint: _OwnerGitHubReadHostEndpoint) -> None:
        if type(endpoint) is not _OwnerGitHubReadHostEndpoint:
            raise GitHubRuntimeError("owner read host endpoint is invalid")
        self.__endpoint = endpoint

    def exchange_read(self, request: GitHubReadRequest) -> GitHubReadResult:
        return self.__endpoint.read(request)

    def exchange_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> "CollectionPage | None":
        return self.__endpoint.read_collection_page(request, cursor)


class _CredentialedGitHubReadCapability(OwnerGitHubReadIpcClient):
    """Factory-sealed read client retaining safe failure provenance privately."""

    __slots__ = ("__inventory_failure_lock", "__pending_inventory_failure", "__read_generation")

    def __init__(self, health: GitHubCapabilityHealth, channel: _OwnerGitHubReadHostChannel) -> None:
        if type(channel) is not _OwnerGitHubReadHostChannel:
            raise GitHubRuntimeError("credentialed GitHub read channel is invalid")
        super().__init__(health, channel)
        self.__inventory_failure_lock = RLock()
        self.__pending_inventory_failure: tuple[
            GitHubReadRequest, GitHubReadResult, GitHubFailure,
            RepositoryInventoryReadFailureCode, RepositoryInventoryFailureStage,
            RepositoryInventoryTransportSubcategory,
        ] | None = None
        self.__read_generation = 0

    def read(self, request: GitHubReadRequest) -> GitHubReadResult:
        # A second read always makes an earlier result stale, including when
        # the new read succeeds or the channel fails before returning a code.
        with self.__inventory_failure_lock:
            self.__pending_inventory_failure = None
            self.__read_generation += 1
            generation = self.__read_generation
        result = super().read(request)
        if (
            request.operation is GitHubReadOperation.REPOSITORY_INVENTORY
            and result.failure is not None
        ):
            code = repository_inventory_failure_code(result.failure.public_reason)
            stage = repository_inventory_failure_stage(result.failure.public_reason)
            transport_subcategory = repository_inventory_transport_subcategory(result.failure.public_reason)
            if code is not None and stage is not None:
                if transport_subcategory is None:
                    transport_subcategory = RepositoryInventoryTransportSubcategory.UNKNOWN
                with self.__inventory_failure_lock:
                    if generation == self.__read_generation:
                        self.__pending_inventory_failure = (
                            request, result, result.failure, code, stage, transport_subcategory,
                        )
        return result

    def _trusted_inventory_failure(
        self, request: GitHubReadRequest, result: GitHubReadResult,
    ) -> tuple[
        RepositoryInventoryReadFailureCode, RepositoryInventoryFailureStage,
        RepositoryInventoryTransportSubcategory,
    ] | None:
        with self.__inventory_failure_lock:
            retained = self.__pending_inventory_failure
            if retained is None:
                return None
            retained_request, retained_result, retained_failure, code, stage, transport_subcategory = retained
            if (
                retained_request is request
                and retained_result is result
                and result.request == request
                and result.failure is retained_failure
            ):
                self.__pending_inventory_failure = None
                return code, stage, transport_subcategory
            return None


def credentialed_repository_inventory_failure(
    capability: object, request: GitHubReadRequest, result: GitHubReadResult,
) -> tuple[
    RepositoryInventoryReadFailureCode, RepositoryInventoryFailureStage,
    RepositoryInventoryTransportSubcategory,
] | None:
    """Return one exact factory-retained failure tuple for a sealed result."""

    if (
        type(capability) is not _CredentialedGitHubReadCapability
        or type(request) is not GitHubReadRequest
        or type(result) is not GitHubReadResult
    ):
        return None
    return capability._trusted_inventory_failure(request, result)


def credentialed_repository_inventory_failure_code(
    capability: object, request: GitHubReadRequest, result: GitHubReadResult,
) -> RepositoryInventoryReadFailureCode | None:
    """Return a code only for the exact factory-retained read result instance."""

    retained = credentialed_repository_inventory_failure(capability, request, result)
    return None if retained is None else retained[0]


class _CredentialedGhRunnerAdapter:
    """Normalize an opaque owner-process result before it reaches the adapter.

    The public factory intentionally does not expose the private command-result
    type.  The reviewed builders supply fixed ``gh`` subcommands, while the
    credential host is a process launcher and therefore receives the executable
    as the first argv item.  Normalize its process-shaped ``returncode`` result
    once while retaining stdout only long enough for the reviewed projection to
    parse it.
    """

    __slots__ = ("__host",)

    def __init__(self, host: object) -> None:
        if not hasattr(host, "run"):
            raise GitHubRuntimeError("credentialed GitHub read host is invalid")
        self.__host = host

    def run(self, arguments: tuple[str, ...]) -> _GhCommandResult:
        try:
            result = self.__host.run(("gh", *arguments))  # type: ignore[attr-defined]
        except Exception as error:
            raise _RepositoryInventoryDiagnosticError(
                RepositoryInventoryFailureStage.TRANSPORT,
                RepositoryInventoryTransportSubcategory.LAUNCH_EXCEPTION,
            ) from error
        try:
            # Do not evaluate the legacy alias unless the conventional
            # subprocess-shaped return code is actually absent.  Some opaque
            # credential hosts expose a guarded legacy attribute whose access
            # is unavailable to this boundary; eager fallback evaluation
            # would turn an otherwise valid process result into a transport
            # failure.
            exit_code = getattr(result, "returncode", None)
            if exit_code is None:
                exit_code = getattr(result, "exit_code", None)
            stdout = getattr(result, "stdout", None)
        except Exception as error:
            raise _RepositoryInventoryDiagnosticError(
                RepositoryInventoryFailureStage.TRANSPORT,
                RepositoryInventoryTransportSubcategory.INVALID_RESULT_SHAPE,
            ) from error
        try:
            return _GhCommandResult(exit_code, stdout)
        except GitHubRuntimeError as error:
            raise _RepositoryInventoryDiagnosticError(
                RepositoryInventoryFailureStage.TRANSPORT,
                RepositoryInventoryTransportSubcategory.INVALID_RESULT_SHAPE,
            ) from error


def create_credentialed_github_read_capability(
    runner: object,
    binding: CandidateBinding,
    dependency_control: DependencyExecutionControl,
    capability_health: GitHubCapabilityHealth,
    *,
    clock: Callable[[], datetime],
) -> OwnerGitHubReadIpcClient:
    """Create the only public production read capability for Roundwright.

    The credential-owning host supplies an opaque fixed ``gh`` runner and
    already-observed dependency/capability evidence.  It cannot inject a
    query, inventory, snapshot, health default, or Harness object.  The
    returned client exposes only typed reads and an explicit deny-all mutation
    response; provider commands and raw output remain in this module.
    """

    if (
        not hasattr(runner, "run")
        or type(binding) is not CandidateBinding
        or type(dependency_control) is not DependencyExecutionControl
        or type(capability_health) is not GitHubCapabilityHealth
        or not callable(clock)
    ):
        raise GitHubRuntimeError("credentialed GitHub read capability inputs are invalid")
    try:
        observed_at = clock()
    except Exception as error:
        raise GitHubRuntimeError("credentialed GitHub read clock is unavailable") from error
    if type(observed_at) is not datetime or observed_at.tzinfo is not timezone.utc:
        raise GitHubRuntimeError("credentialed GitHub read clock is invalid")
    now = int(observed_at.timestamp())
    try:
        dependency_control.require(binding, DependencyStage.GITHUB_READ, now=now)
        _require_fresh_capabilities(
            capability_health, (GitHubReadOperation.REPOSITORY_INVENTORY,), observed_at,
        )
    except (DependencyPolicyError, GitHubRuntimeError, ValueError) as error:
        raise GitHubRuntimeError("credentialed GitHub read evidence is unavailable") from error
    control = _OwnerGitHubReadControl(binding, dependency_control, now)
    endpoint = _OwnerGitHubReadHostEndpoint(
        _CredentialedGhRunnerAdapter(runner), binding, control, capability_health, clock=clock,
    )
    return _CredentialedGitHubReadCapability(capability_health, _OwnerGitHubReadHostChannel(endpoint))


def unavailable_capability_health(*, now: datetime | None = None) -> GitHubCapabilityHealth:
    """Return the default all-disabled matrix without calling ``gh``."""

    observed = now if type(now) is datetime and now.tzinfo is timezone.utc else datetime(1970, 1, 1, tzinfo=timezone.utc)
    values = tuple(OperationHealth(operation, CapabilityState.UNAVAILABLE, observed, _sha256(("gh-health", operation.value, "unavailable"))) for operation in (*GitHubReadOperation, *GitHubMutationOperation))
    return GitHubCapabilityHealth(values)


class SemanticPostcondition(StrEnum):
    COMMENT_PRESENT = "comment-present"
    BRANCH_AT_EXPECTED_SHA = "branch-at-expected-sha"
    BRANCH_ABSENT = "branch-absent"
    PULL_REQUEST_DRAFT = "pull-request-draft"
    PULL_REQUEST_DRAFT_AT_CANDIDATE = "pull-request-draft-at-candidate"
    PULL_REQUEST_READY = "pull-request-ready"
    PULL_REQUEST_MERGED = "pull-request-merged"
    REVIEW_AT_CANDIDATE = "review-at-candidate"
    REVIEWERS_EXACT_AT_CANDIDATE = "reviewers-exact-at-candidate"
    ISSUE_CLOSED = "issue-closed"
    REMOTE_HEAD_AT_EXPECTED_SHA = "remote-head-at-expected-sha"


@dataclass(frozen=True)
class SemanticReadback:
    request: GitHubReadRequest
    condition: SemanticPostcondition

    def __post_init__(self) -> None:
        if type(self.request) is not GitHubReadRequest or type(self.condition) is not SemanticPostcondition:
            raise GitHubRuntimeError("semantic read-back is invalid")

    @property
    def identity(self) -> str:
        return _sha256((self.request.identity(), self.condition.value))


@dataclass(frozen=True)
class CollectionPage:
    """One explicit typed collection page; ``next_cursor=None`` is terminal."""

    request: GitHubReadRequest
    cursor: str | None
    next_cursor: str | None
    total_count: int
    snapshot: CommentsSnapshot | ReviewsSnapshot | RequestedReviewersSnapshot
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.request) is not GitHubReadRequest or self.request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS}:
            raise GitHubRuntimeError("collection page request is invalid")
        for value, name in ((self.cursor, "collection cursor"), (self.next_cursor, "collection continuation")):
            if value is not None and (type(value) is not str or not _CURSOR.fullmatch(value)):
                raise GitHubRuntimeError(f"{name} is invalid")
        if type(self.total_count) is not int or self.total_count < 0 or type(self.snapshot) not in {CommentsSnapshot, ReviewsSnapshot, RequestedReviewersSnapshot}:
            raise GitHubRuntimeError("collection page is invalid")
        if self.snapshot.repository != self.request.repository:
            raise GitHubRuntimeError("collection page repository does not match request")
        object.__setattr__(self, "identity", _sha256((self.request.identity(), self.cursor, self.next_cursor, self.total_count, _collection_snapshot_payload(self.snapshot))))


@dataclass(frozen=True)
class CollectionCompletenessReceipt:
    """Public-safe proof that all typed pages formed one deterministic result."""

    request_identity: str
    page_identities: tuple[str, ...]
    normalized_result_identity: str
    candidate_sha: str
    configuration_digest: str
    gate_identity: str
    authorization_bundle_identity: str
    semantic_plan_identity: str
    journal_identity: str
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.request_identity, "completeness request"), (self.normalized_result_identity, "completeness result"),
            (self.configuration_digest, "completeness configuration"), (self.gate_identity, "completeness gate"),
            (self.authorization_bundle_identity, "completeness bundle"), (self.semantic_plan_identity, "completeness plan"),
            (self.journal_identity, "completeness journal"),
        ):
            _digest(value, name)
        if type(self.page_identities) is not tuple or not self.page_identities:
            raise GitHubRuntimeError("completeness pages are invalid")
        for page in self.page_identities:
            _digest(page, "completeness page")
        if type(self.candidate_sha) is not str or len(self.candidate_sha) not in {40, 64} or any(char not in "0123456789abcdef" for char in self.candidate_sha):
            raise GitHubRuntimeError("completeness candidate is invalid")
        object.__setattr__(self, "identity", _sha256(tuple(getattr(self, name) for name in self.__dataclass_fields__ if name != "identity")))


class BrokerMutationCommand(StrEnum):
    """One broker-owned outbound command shape for each typed mutation."""

    CREATE_BRANCH = "create-branch"
    UPDATE_BRANCH = "update-branch"
    CREATE_PULL_REQUEST = "create-pull-request"
    COMMENT = "comment"
    REQUEST_REVIEW = "request-review"
    MARK_READY = "mark-ready"
    MERGE_PULL_REQUEST = "merge-pull-request"
    CLOSE_ISSUE = "close-issue"
    DELETE_BRANCH = "delete-branch"


@dataclass(frozen=True)
class BrokerSemanticPlan:
    """Immutable command and read-back semantics derived only by the broker."""

    operation: GitHubMutationOperation
    command: BrokerMutationCommand
    target_identity: str
    idempotency_identity: str
    intent_identity: str
    pre_state: GitHubReadRequest
    readback: SemanticReadback
    pre_dispatch_reads: tuple[GitHubReadRequest, ...] = ()
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation or type(self.command) is not BrokerMutationCommand:
            raise GitHubRuntimeError("broker semantic plan operation is invalid")
        if self.command is not _MUTATION_COMMAND_BY_OPERATION[self.operation]:
            raise GitHubRuntimeError("broker semantic plan command is invalid")
        for value, name in (
            (self.target_identity, "semantic target"),
            (self.idempotency_identity, "semantic idempotency"),
            (self.intent_identity, "semantic intent"),
        ):
            _digest(value, name)
        if (
            type(self.pre_state) is not GitHubReadRequest
            or type(self.readback) is not SemanticReadback
            or type(self.pre_dispatch_reads) is not tuple
            or not self.pre_dispatch_reads
            or any(type(request) is not GitHubReadRequest for request in self.pre_dispatch_reads)
        ):
            raise GitHubRuntimeError("broker semantic plan read-back is invalid")
        if self.pre_state.repository != self.readback.request.repository:
            raise GitHubRuntimeError("broker semantic plan repositories do not match")
        object.__setattr__(self, "identity", _sha256((
            self.operation.value, self.command.value, self.target_identity,
            self.idempotency_identity, self.intent_identity,
            self.pre_state.identity(), self.readback.identity,
            tuple(request.identity() for request in self.pre_dispatch_reads),
        )))


def _pre_dispatch_reads_identity(plan: BrokerSemanticPlan) -> str:
    """Seal the complete ordered pre-dispatch proof, never only its first read."""

    if type(plan) is not BrokerSemanticPlan:
        raise GitHubRuntimeError("broker semantic plan is invalid")
    return _sha256(("pre-dispatch-reads", tuple(
        request.identity() for request in plan.pre_dispatch_reads
    )))


@dataclass(frozen=True)
class MutationBrokerContext:
    """Public-safe, exact-candidate authorization inputs for one mutation."""

    policy: RepositoryMutationDecision
    deployment: DeploymentAuthorityDecision
    configuration_digest: str
    base_sha: str
    candidate_sha: str
    gate_identity: str
    standing_authority: StandingRepositoryAuthority
    receipt_verification: RepositoryReceiptVerification
    mutation_context: RepositoryMutationContext
    dispatcher_transition: RepositoryDispatcherTransition
    policy_snapshot: TrustedRepositoryPolicySnapshot
    activation_receipt: RepositoryActivationReceipt
    deployment_identity: DeploymentIdentity
    deployment_receipt: DeploymentAuthorityReceipt
    deployment_verification: AuthorityReceiptVerification
    evaluated_at: datetime
    repository: RepositoryRef
    base_repository: RepositoryRef
    head_repository: RepositoryRef
    base_ref: str
    head_ref: str
    dependency_control: DependencyExecutionControl | None = None

    def __post_init__(self) -> None:
        if (type(self.policy) is not RepositoryMutationDecision or type(self.deployment) is not DeploymentAuthorityDecision
                or type(self.standing_authority) is not StandingRepositoryAuthority or type(self.receipt_verification) is not RepositoryReceiptVerification
                or type(self.mutation_context) is not RepositoryMutationContext or type(self.dispatcher_transition) is not RepositoryDispatcherTransition
                or type(self.policy_snapshot) is not TrustedRepositoryPolicySnapshot or type(self.activation_receipt) is not RepositoryActivationReceipt
                or type(self.deployment_identity) is not DeploymentIdentity or type(self.deployment_receipt) is not DeploymentAuthorityReceipt
                or type(self.deployment_verification) is not AuthorityReceiptVerification
                or type(self.evaluated_at) is not datetime or self.evaluated_at.tzinfo is not timezone.utc
                or type(self.repository) is not RepositoryRef
                or type(self.base_repository) is not RepositoryRef
                or type(self.head_repository) is not RepositoryRef):
            raise GitHubRuntimeError("broker authority evidence is invalid")
        for value, name in ((self.configuration_digest, "configuration"), (self.gate_identity, "gate")):
            _digest(value, name)
        for value, name in ((self.base_sha, "base sha"), (self.candidate_sha, "candidate sha")):
            if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                raise GitHubRuntimeError(f"broker {name} is invalid")
        try:
            GitHubReadRequest(GitHubReadOperation.BRANCH, self.base_repository, ref=self.base_ref, expected_sha=self.base_sha)
            GitHubReadRequest(GitHubReadOperation.BRANCH, self.head_repository, ref=self.head_ref, expected_sha=self.candidate_sha)
        except (TypeError, ValueError) as error:
            raise GitHubRuntimeError("broker pull request reference evidence is invalid") from error
        if self.dependency_control is not None and type(self.dependency_control) is not DependencyExecutionControl:
            raise GitHubRuntimeError("broker dependency execution control is invalid")


def schema_v2_authorization_bundle(
    context: MutationBrokerContext, *, now: datetime | None = None,
    health: GitHubCapabilityHealth | None = None,
) -> "SchemaV2AuthorizationBundle":
    """Construct the single public-safe bundle from canonical typed evidence."""

    if type(context) is not MutationBrokerContext:
        raise GitHubRuntimeError("broker context is invalid")
    trusted_now = context.evaluated_at if now is None else now
    if type(trusted_now) is not datetime or trusted_now.tzinfo is not timezone.utc:
        raise GitHubRuntimeError("broker evaluation time is invalid")
    capability_health = unavailable_capability_health(now=trusted_now) if health is None else health
    if type(capability_health) is not GitHubCapabilityHealth or not capability_health.fresh_at(trusted_now):
        raise GitHubRuntimeError("broker capability health evidence is stale or malformed")
    decision = context.policy
    if (
        type(decision) is not RepositoryMutationDecision
        or type(context.standing_authority) is not StandingRepositoryAuthority
        or type(context.receipt_verification) is not RepositoryReceiptVerification
        or type(context.mutation_context) is not RepositoryMutationContext
        or type(context.dispatcher_transition) is not RepositoryDispatcherTransition
        or type(context.policy_snapshot) is not TrustedRepositoryPolicySnapshot
        or type(context.activation_receipt) is not RepositoryActivationReceipt
    ):
        raise GitHubRuntimeError("broker canonical evidence is unavailable or invalid")
    if context.candidate_sha != context.mutation_context.candidate_sha:
        raise GitHubRuntimeError("broker candidate does not match mutation context")
    binding = decision.binding
    if not decision.authorized or type(binding) is not RepositoryMutationBinding or decision.operation is None:
        raise GitHubRuntimeError("broker policy decision is not authorized canonical evidence")
    receipt = context.activation_receipt
    canonical = evaluate_repository_mutation_policy(
        context.policy_snapshot,
        receipt,
        context.mutation_context,
        decision.operation,
        standing_authority=context.standing_authority,
        dispatcher_transition=context.dispatcher_transition,
        receipt_verification=context.receipt_verification,
        now=trusted_now,
    )
    if not canonical.authorized or canonical != decision or canonical.binding is None:
        raise GitHubRuntimeError("broker policy decision does not match canonical evidence")
    if binding != canonical.binding or not binding.matches_context(context.mutation_context, context.receipt_verification):
        raise GitHubRuntimeError("broker policy binding is not coherently bound")
    canonical_deployment = evaluate_deployment_authority(
        context.deployment_identity, context.deployment_receipt,
        context.deployment_verification, now=trusted_now,
    )
    if not canonical_deployment.authorized or canonical_deployment != context.deployment:
        raise GitHubRuntimeError("broker deployment authority does not match canonical evidence")
    fresh_until = min(item.fresh_until for item in capability_health.observations)
    evaluated_at = trusted_now.isoformat()
    fresh_until_text = fresh_until.isoformat()
    return SchemaV2AuthorizationBundle(
        context.standing_authority.policy.digest,
        context.policy_snapshot.source.source_fingerprint,
        context.policy_snapshot.source.revision_fingerprint,
        context.policy_snapshot.policy_digest,
        receipt.receipt_fingerprint,
        context.mutation_context.repository_fingerprint, context.mutation_context.deployment_fingerprint,
        context.mutation_context.task_fingerprint, context.configuration_digest, context.base_sha,
        context.mutation_context.candidate_sha, context.gate_identity,
        context.receipt_verification.verification_fingerprint,
        context.receipt_verification.receipt_binding_digest,
        context.receipt_verification.status,
        context.dispatcher_transition.evidence_fingerprint,
        context.dispatcher_transition.digest,
        context.deployment_receipt.receipt_fingerprint,
        context.deployment_verification.receipt_binding_fingerprint,
        evaluated_at, fresh_until_text, _sha256((evaluated_at, fresh_until_text)),
        capability_health.identity,
        context.repository.slug,
        context.base_repository.slug, context.head_repository.slug,
        context.base_ref, context.head_ref,
    )


@dataclass(frozen=True)
class SchemaV2AuthorizationBundle:
    """Immutable public-safe identity bundle for a future broker preflight.

    This is deliberately evidence-only: it carries fixed fingerprints/digests
    from the schema-v2 policy evaluator and no provider response text.
    """

    standing_authority_identity: str
    policy_source_identity: str
    policy_revision_identity: str
    policy_identity: str
    receipt_identity: str
    repository_identity: str
    deployment_identity: str
    task_identity: str
    configuration_digest: str
    base_sha: str
    candidate_sha: str
    gate_identity: str
    receipt_verification_identity: str
    receipt_binding_digest: str
    receipt_status: RepositoryReceiptStatus
    dispatcher_transition_identity: str
    dispatcher_transition_digest: str
    deployment_receipt_identity: str
    deployment_verification_identity: str
    evaluated_at: str
    fresh_until: str
    time_identity: str
    capability_health_identity: str
    target_repository: str
    base_repository: str
    head_repository: str
    base_ref: str
    head_ref: str
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.standing_authority_identity, "standing authority"),
            (self.policy_source_identity, "policy source"),
            (self.policy_revision_identity, "policy revision"),
            (self.policy_identity, "policy"),
            (self.receipt_identity, "policy receipt"),
            (self.repository_identity, "repository"), (self.deployment_identity, "deployment"),
            (self.task_identity, "task"), (self.receipt_verification_identity, "receipt lifecycle"),
            (self.receipt_binding_digest, "receipt binding"),
            (self.dispatcher_transition_identity, "dispatcher transition"),
            (self.dispatcher_transition_digest, "dispatcher transition digest"),
            (self.deployment_receipt_identity, "deployment receipt"),
            (self.deployment_verification_identity, "deployment verification"),
        ):
            _fingerprint(value, name)
        for value, name in ((self.evaluated_at, "authorization evaluated time"), (self.fresh_until, "authorization fresh until")):
            try:
                parsed = datetime.fromisoformat(value)
            except (TypeError, ValueError) as error:
                raise GitHubRuntimeError(f"{name} is invalid") from error
            if parsed.tzinfo is not timezone.utc:
                raise GitHubRuntimeError(f"{name} is invalid")
        if datetime.fromisoformat(self.fresh_until) <= datetime.fromisoformat(self.evaluated_at):
            raise GitHubRuntimeError("authorization freshness interval is invalid")
        _digest(self.time_identity, "authorization time")
        if self.time_identity != _sha256((self.evaluated_at, self.fresh_until)):
            raise GitHubRuntimeError("authorization time identity drifted")
        _digest(self.capability_health_identity, "authorization capability health")
        try:
            target_owner, target_name = self.target_repository.split("/", 1)
            base_owner, base_name = self.base_repository.split("/", 1)
            head_owner, head_name = self.head_repository.split("/", 1)
            GitHubReadRequest(GitHubReadOperation.BRANCH, RepositoryRef(target_owner, target_name), ref=self.base_ref, expected_sha=self.base_sha)
            GitHubReadRequest(GitHubReadOperation.BRANCH, RepositoryRef(base_owner, base_name), ref=self.base_ref, expected_sha=self.base_sha)
            GitHubReadRequest(GitHubReadOperation.BRANCH, RepositoryRef(head_owner, head_name), ref=self.head_ref, expected_sha=self.candidate_sha)
        except (AttributeError, TypeError, ValueError) as error:
            raise GitHubRuntimeError("authorization bundle pull request reference evidence is invalid") from error
        if type(self.receipt_status) is not RepositoryReceiptStatus:
            raise GitHubRuntimeError("authorization bundle receipt lifecycle status is invalid")
        _digest(self.configuration_digest, "configuration")
        _digest(self.gate_identity, "gate")
        for value, name in ((self.base_sha, "base sha"), (self.candidate_sha, "candidate sha")):
            if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                raise GitHubRuntimeError(f"authorization bundle {name} is invalid")
        object.__setattr__(self, "identity", _sha256(tuple(
            getattr(self, name).value if name == "receipt_status" else getattr(self, name)
            for name in self.__dataclass_fields__ if name != "identity"
        )))

    def serialize(self) -> Mapping[str, str]:
        return {
            name: getattr(self, name).value if name == "receipt_status" else getattr(self, name)
            for name in self.__dataclass_fields__
        }


@dataclass(frozen=True)
class SemanticMutationReceipt:
    """Curated receipt binding a mutation to its authorization and read-back."""

    repository: str
    operation: GitHubMutationOperation
    idempotency_key: str
    authorization_bundle_identity: str
    intent_identity: str
    semantic_plan_identity: str
    semantic_readback_identity: str
    pre_state_completeness_identity: str
    post_state_completeness_identity: str
    public_payload_digest: str
    policy_binding_digest: str
    configuration_digest: str
    deployment_fingerprint: str
    task_fingerprint: str
    base_sha: str
    candidate_sha: str
    gate_identity: str
    pre_state_digest: str
    post_state_digest: str
    affected_identity: str
    created_resource_identity: str | None
    evaluated_at: str
    fresh_until: str
    time_identity: str
    disposition: MutationDisposition
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.repository) is not str or "/" not in self.repository or type(self.operation) is not GitHubMutationOperation or type(self.idempotency_key) is not str:
            raise GitHubRuntimeError("semantic receipt identity is invalid")
        for value, name in (
            (self.authorization_bundle_identity, "authorization bundle"),
            (self.intent_identity, "intent"), (self.semantic_plan_identity, "semantic plan"),
            (self.semantic_readback_identity, "semantic read-back"),
            (self.pre_state_completeness_identity, "pre-state completeness"),
            (self.post_state_completeness_identity, "post-state completeness"),
            (self.public_payload_digest, "payload"), (self.configuration_digest, "configuration"),
            (self.gate_identity, "gate"), (self.pre_state_digest, "pre-state"),
            (self.post_state_digest, "post-state"),
            (self.time_identity, "receipt time identity"),
        ):
            _digest(value, name)
        if self.time_identity != _sha256((self.evaluated_at, self.fresh_until)):
            raise GitHubRuntimeError("receipt time identity drifted")
        for value, name in ((self.policy_binding_digest, "policy binding"), (self.deployment_fingerprint, "deployment"), (self.task_fingerprint, "task")):
            _fingerprint(value, name)
        if type(self.affected_identity) is not str or not self.affected_identity:
            raise GitHubRuntimeError("semantic receipt affected identity is invalid")
        allocates_identity = self.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        }
        if allocates_identity != (type(self.created_resource_identity) is str):
            raise GitHubRuntimeError("semantic receipt created resource identity is invalid")
        if self.created_resource_identity is not None:
            _digest(self.created_resource_identity, "receipt created resource")
        if type(self.disposition) is not MutationDisposition:
            raise GitHubRuntimeError("semantic receipt disposition is invalid")
        object.__setattr__(self, "receipt_digest", _sha256(self._payload()))

    def _payload(self) -> Mapping[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "receipt_digest"}


@dataclass(frozen=True)
class BrokerMutationResult:
    receipt: SemanticMutationReceipt | None = None
    failure: GitHubFailure | None = None
    reconciliation_required: bool = False

    def __post_init__(self) -> None:
        if (self.receipt is None) == (self.failure is None):
            raise GitHubRuntimeError("broker result must contain exactly one outcome")
        if type(self.reconciliation_required) is not bool:
            raise GitHubRuntimeError("broker reconciliation state is invalid")

    @property
    def ok(self) -> bool:
        return self.receipt is not None


class JournalLifecycle(StrEnum):
    """Durable mutation states; uncertainty is never a success state."""

    CLAIMED = "claimed"
    # Compatibility name for persisted journals before the explicit checkpoint
    # model.  It is deliberately the same state, never an implicit advance.
    PENDING = "claimed"
    PRESTATE_CAPTURED = "prestate-captured"
    EXECUTION_STARTED = "execution-started"
    TRANSPORT_ACCEPTED = "transport-accepted"
    APPLIED_AWAITING_VERIFICATION = "applied-awaiting-verification"
    VERIFIED = "verified"
    DENIED = "denied"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class MutationJournalEntry:
    """Public-safe durable evidence for exactly one broker-owned mutation."""

    repository: str
    operation: GitHubMutationOperation
    idempotency_key: str
    target_identity: str
    idempotency_identity: str
    intent_identity: str
    authorization_bundle_identity: str
    candidate_sha: str
    configuration_digest: str
    gate_identity: str
    semantic_plan_identity: str
    command: BrokerMutationCommand
    pre_state_read_identity: str
    semantic_readback_identity: str
    evaluated_at: str
    fresh_until: str
    time_identity: str
    lifecycle: JournalLifecycle
    receipt: SemanticMutationReceipt | None = None
    pre_state_digest: str | None = None
    pre_state_complete: bool = False
    pre_state_identity: str | None = None
    pre_state_completeness_identity: str | None = None
    created_resource: CreatedResourceLocator | None = None

    def __post_init__(self) -> None:
        if type(self.repository) is not str or "/" not in self.repository or type(self.operation) is not GitHubMutationOperation or type(self.idempotency_key) is not str:
            raise GitHubRuntimeError("mutation journal identity is invalid")
        for value, name in (
            (self.target_identity, "journal target"), (self.idempotency_identity, "journal idempotency"),
            (self.intent_identity, "journal intent"), (self.authorization_bundle_identity, "journal authorization bundle"),
            (self.configuration_digest, "journal configuration"), (self.gate_identity, "journal gate"),
            (self.semantic_plan_identity, "journal semantic plan"),
            (self.pre_state_read_identity, "journal pre-state read"),
            (self.semantic_readback_identity, "journal semantic read-back"),
        ):
            _digest(value, name)
        for value, name in ((self.evaluated_at, "journal evaluated time"), (self.fresh_until, "journal fresh until")):
            try:
                parsed = datetime.fromisoformat(value)
            except (TypeError, ValueError) as error:
                raise GitHubRuntimeError(f"{name} is invalid") from error
            if parsed.tzinfo is not timezone.utc:
                raise GitHubRuntimeError(f"{name} is invalid")
        _digest(self.time_identity, "journal time identity")
        if self.time_identity != _sha256((self.evaluated_at, self.fresh_until)):
            raise GitHubRuntimeError("journal time identity drifted")
        if type(self.candidate_sha) is not str or len(self.candidate_sha) not in {40, 64} or any(char not in "0123456789abcdef" for char in self.candidate_sha):
            raise GitHubRuntimeError("mutation journal candidate is invalid")
        if type(self.command) is not BrokerMutationCommand or type(self.lifecycle) is not JournalLifecycle:
            raise GitHubRuntimeError("mutation journal lifecycle is invalid")
        if (self.lifecycle is JournalLifecycle.VERIFIED) != (type(self.receipt) is SemanticMutationReceipt):
            raise GitHubRuntimeError("mutation journal receipt lifecycle is invalid")
        if self.pre_state_complete:
            _digest(self.pre_state_digest, "journal pre-state")
            _digest(self.pre_state_identity, "journal pre-state identity")
            _digest(self.pre_state_completeness_identity, "journal pre-state completeness")
            if self.pre_state_identity != _sha256((
                self.key, self.repository, self.intent_identity, self.candidate_sha,
                self.authorization_bundle_identity, self.configuration_digest,
                self.gate_identity, self.semantic_plan_identity,
                self.pre_state_read_identity, self.pre_state_completeness_identity,
                self.pre_state_digest,
            )):
                raise GitHubRuntimeError("journal pre-state identity drifted")
        elif any(value is not None for value in (
            self.pre_state_digest, self.pre_state_identity,
            self.pre_state_completeness_identity,
        )):
            raise GitHubRuntimeError("incomplete journal pre-state evidence")
        execution_capable = {
            JournalLifecycle.PRESTATE_CAPTURED, JournalLifecycle.EXECUTION_STARTED,
            JournalLifecycle.TRANSPORT_ACCEPTED,
            JournalLifecycle.APPLIED_AWAITING_VERIFICATION,
            JournalLifecycle.AMBIGUOUS, JournalLifecycle.VERIFIED,
        }
        if self.lifecycle in execution_capable and not self.pre_state_complete:
            raise GitHubRuntimeError("execution-capable journal state lacks complete pre-state")
        if self.lifecycle is JournalLifecycle.CLAIMED and self.pre_state_complete:
            raise GitHubRuntimeError("claimed journal state has fabricated pre-state")
        requires_locator = self.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        } and self.lifecycle in {
            JournalLifecycle.TRANSPORT_ACCEPTED, JournalLifecycle.APPLIED_AWAITING_VERIFICATION,
            JournalLifecycle.AMBIGUOUS, JournalLifecycle.VERIFIED,
        }
        if requires_locator and type(self.created_resource) is not CreatedResourceLocator:
            raise GitHubRuntimeError("mutation journal created resource evidence is invalid")
        if self.created_resource is not None and (
            self.created_resource.operation is not self.operation
            or self.created_resource.repository.slug != self.repository
        ):
            raise GitHubRuntimeError("mutation journal created resource drifted")
        if self.created_resource is not None and self.lifecycle in {
            JournalLifecycle.CLAIMED, JournalLifecycle.PRESTATE_CAPTURED,
            JournalLifecycle.EXECUTION_STARTED,
        }:
            raise GitHubRuntimeError("mutation journal locator predates transport acceptance")
        if self.receipt is not None and (
            self.receipt.repository != self.repository or self.receipt.operation is not self.operation
            or self.receipt.idempotency_key != self.idempotency_key
            or self.receipt.authorization_bundle_identity != self.authorization_bundle_identity
            or self.receipt.intent_identity != self.intent_identity
            or self.receipt.semantic_plan_identity != self.semantic_plan_identity
            or self.receipt.semantic_readback_identity != self.semantic_readback_identity
            or self.receipt.candidate_sha != self.candidate_sha
            or self.receipt.configuration_digest != self.configuration_digest
            or self.receipt.gate_identity != self.gate_identity
            or self.receipt.evaluated_at != self.evaluated_at
            or self.receipt.fresh_until != self.fresh_until
            or self.receipt.time_identity != self.time_identity
            or self.receipt.created_resource_identity != (
                self.created_resource.identity if self.created_resource is not None else None
            )
        ):
            raise GitHubRuntimeError("mutation journal receipt does not match durable evidence")

    @classmethod
    def from_evidence(
        cls, intent: GitHubMutationIntent, context: MutationBrokerContext,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
    ) -> "MutationJournalEntry":
        if (
            type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext
            or type(bundle) is not SchemaV2AuthorizationBundle or type(plan) is not BrokerSemanticPlan
            or plan.operation is not intent.operation or plan.intent_identity != intent.identity()
        ):
            raise GitHubRuntimeError("mutation journal evidence is invalid")
        return cls(
            intent.repository.slug, intent.operation, intent.idempotency_key,
            plan.target_identity, plan.idempotency_identity, intent.identity(), bundle.identity,
            context.candidate_sha, context.configuration_digest, context.gate_identity,
            plan.identity, plan.command, _pre_dispatch_reads_identity(plan), plan.readback.identity, bundle.evaluated_at,
            bundle.fresh_until, bundle.time_identity, JournalLifecycle.PENDING,
        )

    @property
    def key(self) -> str:
        return _sha256((self.repository, self.operation.value, self.idempotency_key))

    def evidence_matches(self, other: "MutationJournalEntry") -> bool:
        return type(other) is MutationJournalEntry and all(
            getattr(self, name) == getattr(other, name)
            for name in self.__dataclass_fields__ if name not in {
                "lifecycle", "receipt", "pre_state_digest", "pre_state_complete",
                "pre_state_identity", "pre_state_completeness_identity", "created_resource",
            }
        )

    def serialize(self) -> Mapping[str, object]:
        return {
            "repository": self.repository, "operation": self.operation.value,
            "idempotency_key": self.idempotency_key, "target_identity": self.target_identity,
            "idempotency_identity": self.idempotency_identity, "intent_identity": self.intent_identity,
            "authorization_bundle_identity": self.authorization_bundle_identity,
            "candidate_sha": self.candidate_sha, "configuration_digest": self.configuration_digest,
            "gate_identity": self.gate_identity, "semantic_plan_identity": self.semantic_plan_identity,
            "command": self.command.value, "pre_state_read_identity": self.pre_state_read_identity,
            "semantic_readback_identity": self.semantic_readback_identity,
            "evaluated_at": self.evaluated_at, "fresh_until": self.fresh_until, "time_identity": self.time_identity,
            "lifecycle": self.lifecycle.value,
            "pre_state_digest": self.pre_state_digest, "pre_state_complete": self.pre_state_complete,
            "pre_state_identity": self.pre_state_identity,
            "pre_state_completeness_identity": self.pre_state_completeness_identity,
            "created_resource": None if self.created_resource is None else {
                "operation": self.created_resource.operation.value,
                "repository": self.created_resource.repository.slug,
                "pull_request_number": self.created_resource.pull_request_number,
                "pull_request_id": self.created_resource.pull_request_id,
                "issue_number": self.created_resource.issue_number,
                "comment_id": self.created_resource.comment_id,
                "base_sha": self.created_resource.base_sha,
                "head_sha": self.created_resource.head_sha,
                "draft": self.created_resource.draft,
                "marker_digest": self.created_resource.marker_digest,
                "identity": self.created_resource.identity,
            },
            "receipt": None if self.receipt is None else self.receipt._payload(),
        }

    @classmethod
    def deserialize(cls, value: object) -> "MutationJournalEntry":
        required = {
            "repository", "operation", "idempotency_key", "target_identity", "idempotency_identity",
            "intent_identity", "authorization_bundle_identity", "candidate_sha", "configuration_digest",
            "gate_identity", "semantic_plan_identity", "command", "pre_state_read_identity", "semantic_readback_identity",
            "evaluated_at", "fresh_until", "time_identity",
            "lifecycle", "receipt", "pre_state_digest", "pre_state_complete", "pre_state_identity",
            "pre_state_completeness_identity", "created_resource",
        }
        if type(value) is not dict or set(value) != required:
            raise GitHubRuntimeError("mutation journal entry is malformed")
        receipt_value = value["receipt"]
        if receipt_value is not None:
            if type(receipt_value) is not dict:
                raise GitHubRuntimeError("mutation journal receipt is malformed")
            receipt_values = dict(receipt_value)
            try:
                receipt_values["operation"] = GitHubMutationOperation(receipt_values["operation"])
                receipt_values["disposition"] = MutationDisposition(receipt_values["disposition"])
                receipt = SemanticMutationReceipt(**receipt_values)
            except (KeyError, TypeError, ValueError) as error:
                raise GitHubRuntimeError("mutation journal receipt is malformed") from error
        else:
            receipt = None
        locator_value = value["created_resource"]
        if locator_value is not None:
            if type(locator_value) is not dict or set(locator_value) != {
                "operation", "repository", "pull_request_number", "pull_request_id", "issue_number", "comment_id",
                "base_sha", "head_sha", "draft", "marker_digest", "identity",
            }:
                raise GitHubRuntimeError("mutation journal created resource is malformed")
            try:
                owner, name = locator_value["repository"].split("/", 1)
                locator = CreatedResourceLocator(
                    GitHubMutationOperation(locator_value["operation"]), RepositoryRef(owner, name),
                    pull_request_number=locator_value["pull_request_number"],
                    pull_request_id=locator_value["pull_request_id"],
                    issue_number=locator_value["issue_number"], comment_id=locator_value["comment_id"],
                    base_sha=locator_value["base_sha"], head_sha=locator_value["head_sha"],
                    draft=locator_value["draft"], marker_digest=locator_value["marker_digest"],
                )
            except (AttributeError, TypeError, ValueError) as error:
                raise GitHubRuntimeError("mutation journal created resource is malformed") from error
            if locator.identity != locator_value["identity"]:
                raise GitHubRuntimeError("mutation journal created resource identity drifted")
        else:
            locator = None
        try:
            return cls(
                value["repository"], GitHubMutationOperation(value["operation"]), value["idempotency_key"],
                value["target_identity"], value["idempotency_identity"], value["intent_identity"],
                value["authorization_bundle_identity"], value["candidate_sha"], value["configuration_digest"],
                value["gate_identity"], value["semantic_plan_identity"], BrokerMutationCommand(value["command"]),
                value["pre_state_read_identity"], value["semantic_readback_identity"],
                value["evaluated_at"], value["fresh_until"], value["time_identity"], JournalLifecycle(value["lifecycle"]),
                receipt, value["pre_state_digest"], value["pre_state_complete"], value["pre_state_identity"],
                value["pre_state_completeness_identity"], locator,
            )
        except (TypeError, ValueError) as error:
            raise GitHubRuntimeError("mutation journal entry is malformed") from error


_KEEP_CREATED_RESOURCE = object()


class DurableMutationJournal:
    """Atomic local journal that preserves uncertainty for broker reconciliation."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir():
            raise GitHubRuntimeError("mutation journal path is invalid")
        self._path = path

    def claim(self, evidence: MutationJournalEntry) -> tuple[MutationJournalEntry, bool]:
        if type(evidence) is not MutationJournalEntry:
            raise GitHubRuntimeError("mutation journal evidence is invalid")
        records = self._load()
        prior = records.get(evidence.key)
        if prior is not None:
            if not prior.evidence_matches(evidence):
                raise GitHubRuntimeError("mutation journal idempotency identity conflicts")
            return prior, False
        records[evidence.key] = evidence
        self._store(records)
        return evidence, True

    def transition(
        self, evidence: MutationJournalEntry, lifecycle: JournalLifecycle,
        receipt: SemanticMutationReceipt | None = None, *, pre_state_digest: str | None = None,
        pre_state_completeness_identity: str | None = None,
        created_resource: CreatedResourceLocator | None | object = _KEEP_CREATED_RESOURCE,
    ) -> MutationJournalEntry:
        if type(evidence) is not MutationJournalEntry or type(lifecycle) is not JournalLifecycle:
            raise GitHubRuntimeError("mutation journal transition is invalid")
        records = self._load()
        prior = records.get(evidence.key)
        if prior is None or prior != evidence:
            raise GitHubRuntimeError("mutation journal evidence is missing or conflicting")
        allowed = {
            JournalLifecycle.CLAIMED: {JournalLifecycle.PRESTATE_CAPTURED, JournalLifecycle.DENIED, JournalLifecycle.FAILED},
            JournalLifecycle.PRESTATE_CAPTURED: {JournalLifecycle.EXECUTION_STARTED, JournalLifecycle.VERIFIED, JournalLifecycle.DENIED, JournalLifecycle.FAILED},
            JournalLifecycle.EXECUTION_STARTED: {JournalLifecycle.TRANSPORT_ACCEPTED, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.TRANSPORT_ACCEPTED: {JournalLifecycle.APPLIED_AWAITING_VERIFICATION, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.APPLIED_AWAITING_VERIFICATION: {JournalLifecycle.VERIFIED, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.AMBIGUOUS: {JournalLifecycle.VERIFIED},
            JournalLifecycle.VERIFIED: set(), JournalLifecycle.DENIED: set(), JournalLifecycle.FAILED: set(),
        }
        if lifecycle not in allowed[prior.lifecycle]:
            raise GitHubRuntimeError("mutation journal transition is impossible")
        if lifecycle is JournalLifecycle.PRESTATE_CAPTURED:
            if (
                prior.pre_state_complete or receipt is not None
                or type(pre_state_digest) is not str
                or type(pre_state_completeness_identity) is not str
            ):
                raise GitHubRuntimeError("journal pre-state transition is invalid")
        elif pre_state_digest is not None or pre_state_completeness_identity is not None:
            raise GitHubRuntimeError("journal pre-state evidence may only be captured once")
        if lifecycle is JournalLifecycle.VERIFIED:
            if type(receipt) is not SemanticMutationReceipt:
                raise GitHubRuntimeError("verified journal transition lacks receipt")
        elif receipt is not None:
            raise GitHubRuntimeError("non-verified journal transition has a receipt")
        next_created_resource = prior.created_resource if created_resource is _KEEP_CREATED_RESOURCE else created_resource
        updated = replace(prior, lifecycle=lifecycle, receipt=receipt, created_resource=next_created_resource) if pre_state_digest is None else replace(
            prior, lifecycle=lifecycle, receipt=receipt, pre_state_digest=pre_state_digest,
            pre_state_complete=True,
            pre_state_identity=_sha256((
                prior.key, prior.repository, prior.intent_identity, prior.candidate_sha,
                prior.authorization_bundle_identity, prior.configuration_digest,
                prior.gate_identity, prior.semantic_plan_identity,
                prior.pre_state_read_identity, pre_state_completeness_identity,
                pre_state_digest,
            )),
            pre_state_completeness_identity=pre_state_completeness_identity,
            created_resource=next_created_resource,
        )
        records[evidence.key] = updated
        self._store(records)
        return MutationJournalEntry.deserialize(updated.serialize())

    def find(self, evidence: MutationJournalEntry) -> MutationJournalEntry | None:
        if type(evidence) is not MutationJournalEntry:
            raise GitHubRuntimeError("mutation journal evidence is invalid")
        prior = self._load().get(evidence.key)
        if prior is not None and not prior.evidence_matches(evidence):
            raise GitHubRuntimeError("mutation journal idempotency identity conflicts")
        return prior

    def find_recovery(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext, plan: BrokerSemanticPlan,
    ) -> MutationJournalEntry | None:
        """Load only an exact durable attempt; current authority is re-evaluated separately."""

        if type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext or type(plan) is not BrokerSemanticPlan:
            raise GitHubRuntimeError("mutation journal recovery evidence is invalid")
        key = _sha256((intent.repository.slug, intent.operation.value, intent.idempotency_key))
        entry = self._load().get(key)
        if entry is None:
            return None
        if (
            entry.repository != intent.repository.slug or entry.operation is not intent.operation
            or entry.idempotency_key != intent.idempotency_key or entry.intent_identity != intent.identity()
            or entry.target_identity != plan.target_identity or entry.idempotency_identity != plan.idempotency_identity
            or entry.semantic_plan_identity != plan.identity or entry.command is not plan.command
            or entry.pre_state_read_identity != _pre_dispatch_reads_identity(plan)
            or entry.semantic_readback_identity != plan.readback.identity
            or entry.candidate_sha != context.candidate_sha
            or entry.configuration_digest != context.configuration_digest
            or entry.gate_identity != context.gate_identity
        ):
            raise GitHubRuntimeError("mutation journal recovery evidence drifted")
        return entry

    def _load(self) -> dict[str, MutationJournalEntry]:
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        if temporary.exists():
            raise GitHubRuntimeError("mutation journal has an incomplete atomic replacement")
        if not self._path.exists():
            return {}
        try:
            value = json.loads(self._path.read_text(encoding="utf-8"))
            if type(value) is not dict or any(type(key) is not str for key in value):
                raise ValueError
            records = {key: MutationJournalEntry.deserialize(record) for key, record in value.items()}
            if any(entry.key != key for key, entry in records.items()):
                raise ValueError
            return records
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise GitHubRuntimeError("mutation journal is malformed") from error

    def _store(self, records: Mapping[str, MutationJournalEntry]) -> None:
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            value = {key: entry.serialize() for key, entry in records.items()}
            with temporary.open("w", encoding="utf-8", newline="") as handle:
                handle.write(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)
        except OSError as error:
            raise GitHubRuntimeError("mutation journal cannot be persisted") from error


_MUTATION_COMMAND_BY_OPERATION: Mapping[GitHubMutationOperation, BrokerMutationCommand] = MappingProxyType({
    GitHubMutationOperation.CREATE_BRANCH: BrokerMutationCommand.CREATE_BRANCH,
    GitHubMutationOperation.UPDATE_BRANCH: BrokerMutationCommand.UPDATE_BRANCH,
    GitHubMutationOperation.CREATE_PULL_REQUEST: BrokerMutationCommand.CREATE_PULL_REQUEST,
    GitHubMutationOperation.COMMENT: BrokerMutationCommand.COMMENT,
    GitHubMutationOperation.REQUEST_REVIEW: BrokerMutationCommand.REQUEST_REVIEW,
    GitHubMutationOperation.MARK_READY: BrokerMutationCommand.MARK_READY,
    GitHubMutationOperation.MERGE_PULL_REQUEST: BrokerMutationCommand.MERGE_PULL_REQUEST,
    GitHubMutationOperation.CLOSE_ISSUE: BrokerMutationCommand.CLOSE_ISSUE,
    GitHubMutationOperation.DELETE_BRANCH: BrokerMutationCommand.DELETE_BRANCH,
})


@dataclass(frozen=True)
class OwnerMutationSealRecord:
    """One owner-provisioned, single-use sealed mutation authorization.

    This is deliberately an identity-only record.  It contains neither a
    provider command nor credential material; the host may execute only its
    own fixed mapping after every broker seal has been compared.
    """

    request: OwnerMutationRequest
    intent_identity: str
    authorization_bundle_identity: str
    deployment_identity: str
    semantic_plan_identity: str
    journal_identity: str
    pre_state_identity: str
    evaluated_at: str
    fresh_until: str
    time_identity: str
    capability_health_identity: str
    operation: GitHubMutationOperation
    repository: RepositoryRef
    candidate_sha: str
    idempotency_identity: str
    command: BrokerMutationCommand
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.request) is not OwnerMutationRequest or type(self.operation) is not GitHubMutationOperation or type(self.repository) is not RepositoryRef or type(self.command) is not BrokerMutationCommand:
            raise GitHubRuntimeError("owner mutation seal record is invalid")
        if self.command is not _MUTATION_COMMAND_BY_OPERATION[self.operation]:
            raise GitHubRuntimeError("owner mutation seal command is invalid")
        for value, name in (
            (self.intent_identity, "host intent"), (self.authorization_bundle_identity, "host bundle"),
            (self.semantic_plan_identity, "host plan"), (self.journal_identity, "host journal"),
            (self.pre_state_identity, "host pre-state"), (self.idempotency_identity, "host idempotency"),
            (self.time_identity, "host time"), (self.capability_health_identity, "host capability health"),
        ):
            _digest(value, name)
        _fingerprint(self.deployment_identity, "host deployment")
        if type(self.candidate_sha) is not str or len(self.candidate_sha) not in {40, 64} or any(char not in "0123456789abcdef" for char in self.candidate_sha):
            raise GitHubRuntimeError("owner mutation seal candidate is invalid")
        for value, name in ((self.evaluated_at, "host evaluated time"), (self.fresh_until, "host fresh until")):
            try:
                parsed = datetime.fromisoformat(value)
            except (TypeError, ValueError) as error:
                raise GitHubRuntimeError(f"{name} is invalid") from error
            if parsed.tzinfo is not timezone.utc:
                raise GitHubRuntimeError(f"{name} is invalid")
        if datetime.fromisoformat(self.fresh_until) <= datetime.fromisoformat(self.evaluated_at):
            raise GitHubRuntimeError("owner mutation seal freshness is invalid")
        if self.time_identity != _sha256((self.evaluated_at, self.fresh_until)):
            raise GitHubRuntimeError("owner mutation seal time drifted")
        if not self.matches(self.request):
            raise GitHubRuntimeError("owner mutation seal does not bind request")
        object.__setattr__(self, "identity", _sha256(tuple(
            self.request.identity if name == "request" else self.operation.value if name == "operation"
            else self.repository.slug if name == "repository" else self.command.value if name == "command"
            else getattr(self, name)
            for name in self.__dataclass_fields__ if name != "identity"
        )))

    def matches(self, request: OwnerMutationRequest) -> bool:
        return type(request) is OwnerMutationRequest and (
            request.identity == self.request.identity
            and request.intent_identity == self.intent_identity
            and request.authorization_bundle_identity == self.authorization_bundle_identity
            and request.deployment_identity == self.deployment_identity
            and request.semantic_plan_identity == self.semantic_plan_identity
            and request.journal_identity == self.journal_identity
            and request.pre_state_identity == self.pre_state_identity
            and request.evaluated_at == self.evaluated_at
            and request.fresh_until == self.fresh_until
            and request.time_identity == self.time_identity
            and request.capability_health_identity == self.capability_health_identity
            and request.operation is self.operation and request.repository == self.repository
            and request.candidate_sha == self.candidate_sha
            and request.idempotency_identity == self.idempotency_identity
            and request.command is self.command
        )


class OwnerMutationSealRegistry(Protocol):
    """Owner-host storage that resolves and consumes one exact request once."""

    def resolve_and_consume(self, request: OwnerMutationRequest) -> OwnerMutationSealRecord | None: ...


@dataclass(frozen=True)
class OwnerFixedMutationCommand:
    """Host-internal fixed mutation shape, never caller-provided argv."""

    operation: GitHubMutationOperation
    command: BrokerMutationCommand
    repository: RepositoryRef
    target_number: int | None
    candidate_sha: str
    idempotency_identity: str
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            type(self.operation) is not GitHubMutationOperation
            or type(self.command) is not BrokerMutationCommand
            or self.command is not _MUTATION_COMMAND_BY_OPERATION[self.operation]
            or type(self.repository) is not RepositoryRef
            or type(self.candidate_sha) is not str
            or len(self.candidate_sha) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in self.candidate_sha)
        ):
            raise GitHubRuntimeError("owner fixed mutation command is invalid")
        if self.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST, GitHubMutationOperation.COMMENT,
            GitHubMutationOperation.REQUEST_REVIEW, GitHubMutationOperation.MARK_READY,
            GitHubMutationOperation.MERGE_PULL_REQUEST, GitHubMutationOperation.CLOSE_ISSUE,
        }:
            if type(self.target_number) is not int or self.target_number <= 0:
                raise GitHubRuntimeError("owner fixed mutation target is invalid")
        elif self.target_number is not None:
            raise GitHubRuntimeError("owner fixed branch command target is invalid")
        _digest(self.idempotency_identity, "owner fixed idempotency")
        object.__setattr__(self, "identity", _sha256((
            self.operation.value, self.command.value, self.repository.slug,
            self.target_number, self.candidate_sha, self.idempotency_identity,
        )))


def _owner_fixed_mutation_command(record: OwnerMutationSealRecord) -> OwnerFixedMutationCommand:
    """Derive the exhaustive host command shape solely from an exact seal."""

    if type(record) is not OwnerMutationSealRecord or not record.matches(record.request):
        raise GitHubRuntimeError("owner fixed mutation seal is invalid")
    command = _MUTATION_COMMAND_BY_OPERATION.get(record.operation)
    if command is not record.command or command is not record.request.command:
        raise GitHubRuntimeError("owner fixed mutation command drifted")
    return OwnerFixedMutationCommand(
        record.operation, command, record.repository, record.request.target_number,
        record.candidate_sha, record.idempotency_identity,
    )


class _OwnerFixedMutationCommandHandler(Protocol):
    """Private host-only implementation with no argv, output, or environment API."""

    def execute_fixed_command(
        self, command: OwnerFixedMutationCommand, record: OwnerMutationSealRecord,
    ) -> OwnerMutationAcceptedFact: ...


@dataclass(frozen=True)
class _OwnerGitHubMutationControl:
    """Pre-provisioned owner-only authority for one fixed mutation request."""

    request_identity: str
    binding: CandidateBinding
    operation: GitHubMutationOperation
    dependency_control: DependencyExecutionControl
    now: int

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not CandidateBinding
            or type(self.operation) is not GitHubMutationOperation
            or type(self.dependency_control) is not DependencyExecutionControl
            or type(self.now) is not int
        ):
            raise GitHubRuntimeError("owner mutation dependency control is invalid")
        _digest(self.request_identity, "owner mutation dependency request")
        try:
            self.dependency_control.require(self.binding, DependencyStage.GITHUB_MUTATION, now=self.now)
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner mutation dependency control is invalid") from error

    def require(self, request: OwnerMutationRequest, binding: CandidateBinding, *, now: datetime) -> None:
        if (
            type(self) is not _OwnerGitHubMutationControl
            or type(request) is not OwnerMutationRequest
            or type(binding) is not CandidateBinding
            or type(now) is not datetime
            or now.tzinfo is not timezone.utc
            or self.now != int(now.timestamp())
            or self.request_identity != request.identity
            or self.binding != binding
            or self.binding.repository != request.repository.slug
            or self.binding.candidate_sha != request.candidate_sha
            or self.operation is not request.operation
        ):
            raise GitHubRuntimeError("owner mutation dependency control is invalid")
        try:
            self.dependency_control.require(self.binding, DependencyStage.GITHUB_MUTATION, now=self.now)
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner mutation dependency control is stale") from error


class _OwnerMutationControlRegistry(Protocol):
    """Owner-only source for exact pre-materialized mutation controls."""

    def resolve(self, request: OwnerMutationRequest) -> _OwnerGitHubMutationControl | None: ...


class InMemoryOwnerMutationControlRegistry:
    """Hermetic immutable control registry for owner-host tests and wiring."""

    def __init__(self, controls: tuple[_OwnerGitHubMutationControl, ...]) -> None:
        if type(controls) is not tuple or any(type(control) is not _OwnerGitHubMutationControl for control in controls):
            raise GitHubRuntimeError("owner mutation dependency controls are invalid")
        if len({control.request_identity for control in controls}) != len(controls):
            raise GitHubRuntimeError("owner mutation dependency controls are duplicated")
        self.__controls = {control.request_identity: control for control in controls}

    def resolve(self, request: OwnerMutationRequest) -> _OwnerGitHubMutationControl | None:
        if type(request) is not OwnerMutationRequest:
            raise GitHubRuntimeError("owner mutation dependency request is invalid")
        return self.__controls.get(request.identity)


class OwnerFixedMutationHostExecutor:
    """Concrete disabled owner-host executor for sealed fixed command shapes.

    It deliberately has no default handler.  Deployment must inject a host
    implementation outside Worker/Supervisor code; absent injection remains a
    denial before any credential or process access.
    """

    def __init__(self, handler: _OwnerFixedMutationCommandHandler, binding: CandidateBinding) -> None:
        if not hasattr(handler, "execute_fixed_command") or type(binding) is not CandidateBinding:
            raise GitHubRuntimeError("owner fixed mutation handler is unavailable")
        self.__handler = handler
        self.__binding = binding

    def _matches_binding(self, binding: CandidateBinding) -> bool:
        return type(binding) is CandidateBinding and self.__binding == binding

    def execute_fixed(
        self, record: OwnerMutationSealRecord, *, control: _OwnerGitHubMutationControl, now: datetime,
    ) -> OwnerMutationAcceptedFact:
        """Execute only after exact host-owned mutation authority is re-proved."""

        if type(record) is not OwnerMutationSealRecord or type(control) is not _OwnerGitHubMutationControl:
            raise GitHubRuntimeError("owner fixed mutation dependency control is invalid")
        control.require(record.request, self.__binding, now=now)
        command = _owner_fixed_mutation_command(record)
        fact = self.__handler.execute_fixed_command(command, record)
        if (
            type(fact) is not OwnerMutationAcceptedFact
            or fact.request_identity != record.request.identity
            or fact.operation is not record.operation
        ):
            raise GitHubRuntimeError("owner fixed mutation result is invalid")
        return fact


class InMemoryOwnerMutationSealRegistry:
    """Hermetic owner registry with atomic single-use consumption semantics."""

    def __init__(self, records: tuple[OwnerMutationSealRecord, ...]) -> None:
        if type(records) is not tuple or any(type(record) is not OwnerMutationSealRecord for record in records):
            raise GitHubRuntimeError("owner mutation seal registry is invalid")
        if len({record.request.identity for record in records}) != len(records):
            raise GitHubRuntimeError("owner mutation seal registry has duplicate requests")
        self.__records = {record.request.identity: record for record in records}
        self.__lock = RLock()

    def resolve_and_consume(self, request: OwnerMutationRequest) -> OwnerMutationSealRecord | None:
        if type(request) is not OwnerMutationRequest:
            raise GitHubRuntimeError("owner mutation registry request is invalid")
        with self.__lock:
            return self.__records.pop(request.identity, None)


class OwnerMutationHostEndpoint:
    """Disabled host-side fixed protocol; no process, credentials, or raw output."""

    def __init__(
        self, registry: OwnerMutationSealRegistry, executor: OwnerFixedMutationHostExecutor,
        binding: CandidateBinding, controls: _OwnerMutationControlRegistry,
        *, clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not hasattr(registry, "resolve_and_consume")
            or type(executor) is not OwnerFixedMutationHostExecutor
            or type(binding) is not CandidateBinding
            or not executor._matches_binding(binding)
            or not hasattr(controls, "resolve")
            or clock is None
        ):
            raise GitHubRuntimeError("owner mutation host endpoint is unavailable")
        self.__registry = registry
        self.__executor = executor
        self.__binding = binding
        self.__controls = controls
        self.__clock = clock

    def _dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact | OwnerMutationAcceptedFact:
        if type(request) is not OwnerMutationRequest:
            raise GitHubRuntimeError("owner mutation host request is invalid")
        try:
            now = self.__clock()
        except (TypeError, ValueError):
            return OwnerMutationFact(False, request.identity)
        if type(now) is not datetime or now.tzinfo is not timezone.utc:
            return OwnerMutationFact(False, request.identity)
        try:
            control = self.__controls.resolve(request)
            if type(control) is not _OwnerGitHubMutationControl:
                return OwnerMutationFact(False, request.identity)
            control.require(request, self.__binding, now=now)
        except (AttributeError, DependencyPolicyError, TypeError, ValueError):
            return OwnerMutationFact(False, request.identity)
        record = self.__registry.resolve_and_consume(request)
        if type(record) is not OwnerMutationSealRecord or not record.matches(request):
            return OwnerMutationFact(False, request.identity)
        if request.command is not _MUTATION_COMMAND_BY_OPERATION[request.operation]:
            return OwnerMutationFact(False, request.identity)
        try:
            evaluated_at = datetime.fromisoformat(record.evaluated_at)
            fresh_until = datetime.fromisoformat(record.fresh_until)
        except (TypeError, ValueError):
            return OwnerMutationFact(False, request.identity)
        if (
            now < evaluated_at or now >= fresh_until
        ):
            return OwnerMutationFact(False, request.identity)
        try:
            fact = self.__executor.execute_fixed(record, control=control, now=now)
        except (AttributeError, TypeError, ValueError):
            return OwnerMutationFact(False, request.identity)
        if type(fact) is not OwnerMutationAcceptedFact or fact.request_identity != request.identity or fact.operation is not request.operation:
            return OwnerMutationFact(False, request.identity)
        return fact

    def exchange_mutation(self, message: OwnerMutationIpcMessage) -> OwnerMutationIpcReply:
        """Host-side typed IPC dispatch; malformed messages never reach execution."""

        if type(message) is not OwnerMutationIpcMessage:
            raise GitHubRuntimeError("owner mutation IPC message is invalid")
        return OwnerMutationIpcReply(message.identity, self._dispatch(message.request))


def _broker_semantic_plan(intent: GitHubMutationIntent) -> BrokerSemanticPlan:
    """Derive the sole command and typed read-back plan for an intent.

    An operation without enough typed target information to prove its own
    postcondition is deliberately rejected before the adapter sees it.
    """

    if type(intent) is not GitHubMutationIntent or type(intent.operation) is not GitHubMutationOperation:
        raise GitHubRuntimeError("broker semantic plan intent is invalid")
    if set(_MUTATION_COMMAND_BY_OPERATION) != set(GitHubMutationOperation):
        raise GitHubRuntimeError("broker mutation command mapping is incomplete")
    command = _MUTATION_COMMAND_BY_OPERATION.get(intent.operation)
    if type(command) is not BrokerMutationCommand:
        raise GitHubRuntimeError("broker mutation command mapping is invalid")
    payload = dict(intent.payload)
    operation = intent.operation
    pre_dispatch_reads: tuple[GitHubReadRequest, ...]
    if operation is GitHubMutationOperation.CREATE_BRANCH:
        pre_state = GitHubReadRequest(GitHubReadOperation.REPOSITORY, intent.repository)
        readback = SemanticReadback(GitHubReadRequest(GitHubReadOperation.BRANCH, intent.repository, ref=intent.target_ref, expected_sha=intent.expected_sha), SemanticPostcondition.BRANCH_AT_EXPECTED_SHA)
    elif operation is GitHubMutationOperation.UPDATE_BRANCH:
        pre_state = GitHubReadRequest(GitHubReadOperation.BRANCH, intent.repository, ref=intent.target_ref, expected_sha=payload["previous_sha"])
        readback = SemanticReadback(GitHubReadRequest(GitHubReadOperation.BRANCH, intent.repository, ref=intent.target_ref, expected_sha=intent.expected_sha), SemanticPostcondition.BRANCH_AT_EXPECTED_SHA)
    elif operation is GitHubMutationOperation.DELETE_BRANCH:
        pre_state = GitHubReadRequest(GitHubReadOperation.BRANCH, intent.repository, ref=intent.target_ref, expected_sha=intent.expected_sha)
        readback = SemanticReadback(GitHubReadRequest(GitHubReadOperation.REMOTE_HEAD, intent.repository, ref=intent.target_ref, expected_sha=intent.expected_sha), SemanticPostcondition.BRANCH_ABSENT)
    elif operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        pre_state = GitHubReadRequest(
            GitHubReadOperation.BRANCH, intent.repository,
            ref=payload["base_ref"], expected_sha=payload["base_sha"],
        )
        pre_dispatch_reads = (
            pre_state,
            GitHubReadRequest(
                GitHubReadOperation.BRANCH, intent.repository,
                ref=payload["head_ref"], expected_sha=payload["head_sha"],
            ),
        )
        readback = SemanticReadback(GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, intent.repository, number=intent.target_number, expected_sha=payload["head_sha"]), SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE)
    elif operation is GitHubMutationOperation.COMMENT:
        pre_state = GitHubReadRequest(GitHubReadOperation.COMMENTS, intent.repository, number=intent.target_number)
        readback = SemanticReadback(pre_state, SemanticPostcondition.COMMENT_PRESENT)
    elif operation is GitHubMutationOperation.REQUEST_REVIEW:
        pre_state = GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, intent.repository, number=intent.target_number, expected_sha=intent.expected_sha)
        readback = SemanticReadback(pre_state, SemanticPostcondition.REVIEWERS_EXACT_AT_CANDIDATE)
    elif operation is GitHubMutationOperation.MARK_READY:
        pre_state = GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, intent.repository, number=intent.target_number, expected_sha=intent.expected_sha)
        readback = SemanticReadback(pre_state, SemanticPostcondition.PULL_REQUEST_READY)
    elif operation is GitHubMutationOperation.MERGE_PULL_REQUEST:
        pre_state = GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, intent.repository, number=intent.target_number, expected_sha=intent.expected_sha)
        readback = SemanticReadback(pre_state, SemanticPostcondition.PULL_REQUEST_MERGED)
    elif operation is GitHubMutationOperation.CLOSE_ISSUE:
        pre_state = GitHubReadRequest(GitHubReadOperation.ISSUE, intent.repository, number=intent.target_number)
        readback = SemanticReadback(pre_state, SemanticPostcondition.ISSUE_CLOSED)
    else:
        raise GitHubRuntimeError("broker semantic plan is incomplete for this mutation operation")
    if operation is not GitHubMutationOperation.CREATE_PULL_REQUEST:
        pre_dispatch_reads = (pre_state,)
    return BrokerSemanticPlan(
        operation, command,
        _sha256((intent.repository.slug, intent.target_number, intent.target_ref, intent.expected_sha)),
        _sha256(("idempotency", intent.idempotency_key)), intent.identity(), pre_state, readback,
        pre_dispatch_reads,
    )


def _collection_snapshot_payload(snapshot: CommentsSnapshot | ReviewsSnapshot | RequestedReviewersSnapshot) -> tuple[object, ...]:
    if type(snapshot) is CommentsSnapshot:
        return ("comments", snapshot.repository.slug, snapshot.issue_number, snapshot.target_kind, tuple((item.comment_id, item.author_id, item.body_digest, item.created_at) for item in snapshot.comments))
    if type(snapshot) is ReviewsSnapshot:
        return ("reviews", snapshot.repository.slug, snapshot.pull_request_number, snapshot.head_sha, tuple((item.review_id, item.reviewer_id, item.state.value, item.commit_sha) for item in snapshot.reviews))
    if type(snapshot) is RequestedReviewersSnapshot:
        return ("requested-reviewers", snapshot.repository.slug, snapshot.pull_request_number, snapshot.candidate_sha, snapshot.reviewers, snapshot.reviewer_set_digest, snapshot.complete, snapshot.next_cursor, snapshot.raw_evidence_identity)
    raise GitHubRuntimeError("collection snapshot is invalid")


def _normalize_complete_collection_pages(
    request: GitHubReadRequest, pages: list[CollectionPage],
) -> GitHubReadResult:
    if not pages:
        return GitHubReadResult(request, failure=GitHubFailure(
            GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection has no pages",
        ))
    first = pages[0]
    items: dict[str, object] = {}
    ordered: list[object] = []
    for page in pages:
        if type(page.snapshot) is RequestedReviewersSnapshot:
            if page.snapshot.repository != first.snapshot.repository or page.snapshot.pull_request_number != first.snapshot.pull_request_number or page.snapshot.candidate_sha != first.snapshot.candidate_sha:
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "requested reviewer page identity drifted"))
            collection = page.snapshot.reviewers
            identifiers = list(collection)
        elif type(page.snapshot) is CommentsSnapshot:
            if (
                type(first.snapshot) is not CommentsSnapshot
                or page.snapshot.repository != first.snapshot.repository
                or page.snapshot.issue_number != first.snapshot.issue_number
                or page.snapshot.target_kind != first.snapshot.target_kind
            ):
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "comment page identity drifted"))
            collection = page.snapshot.comments
            identifiers = [item.comment_id for item in collection]
        else:
            if (
                type(first.snapshot) is not ReviewsSnapshot
                or page.snapshot.repository != first.snapshot.repository
                or page.snapshot.pull_request_number != first.snapshot.pull_request_number
                or page.snapshot.head_sha != first.snapshot.head_sha
            ):
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "review page identity drifted"))
            collection = page.snapshot.comments if type(page.snapshot) is CommentsSnapshot else page.snapshot.reviews
            identifiers = [item.comment_id if type(page.snapshot) is CommentsSnapshot else item.review_id for item in collection]
        if len(identifiers) != len(set(identifiers)):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection identifier is duplicated"))
        for identifier, item in zip(identifiers, collection):
            prior = items.get(identifier)
            if prior is not None:
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection identifier is duplicated"))
            if prior is None:
                items[identifier] = item
                ordered.append(item)
    if len(ordered) != first.total_count:
        return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection is incomplete"))
    if type(first.snapshot) is CommentsSnapshot:
        normalized: CommentsSnapshot | ReviewsSnapshot | RequestedReviewersSnapshot = CommentsSnapshot(first.snapshot.repository, first.snapshot.issue_number, first.snapshot.target_kind, tuple(ordered))  # type: ignore[arg-type]
    elif type(first.snapshot) is RequestedReviewersSnapshot:
        reviewers = tuple(ordered)
        normalized = RequestedReviewersSnapshot(first.snapshot.repository, first.snapshot.pull_request_number, first.snapshot.candidate_sha, reviewers, _sha256(("reviewers", reviewers)), True, None, _sha256(tuple(page.identity for page in pages)))  # type: ignore[arg-type]
    else:
        normalized = ReviewsSnapshot(first.snapshot.repository, first.snapshot.pull_request_number, first.snapshot.head_sha, tuple(ordered))  # type: ignore[arg-type]
    return GitHubReadResult(request, snapshot=normalized)


def _complete_broker_read(
    adapter: GitHubAdapter, request: GitHubReadRequest, context: MutationBrokerContext,
    bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
    journal_entry: MutationJournalEntry | None,
) -> tuple[GitHubReadResult, str]:
    """Read every typed collection page and return its completeness receipt."""

    if request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS}:
        result = adapter.read(request)
        return result, _sha256(("not-a-collection", request.identity(), plan.identity))
    read_page = getattr(adapter, "read_collection_page", None)
    cursor: str | None = None
    pages: list[CollectionPage] = []
    while True:
        if len(pages) >= 32:
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection page limit is exceeded")), ""
        if callable(read_page):
            page = read_page(request, cursor)
            if type(page) is not CollectionPage:
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection pagination metadata is unavailable")), ""
        else:
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection pagination metadata is unavailable")), ""
        if page.request != request or page.cursor != cursor:
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection page request drifted")), ""
        if pages and page.total_count != pages[0].total_count:
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection total is inconsistent")), ""
        if page.total_count > 3200:
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection item limit is exceeded")), ""
        if page.next_cursor is not None and (
            any(prior.cursor == page.next_cursor for prior in pages)
            or page.next_cursor == cursor
        ):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection cursor is repeated or cyclic")), ""
        pages.append(page)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    result = _normalize_complete_collection_pages(request, pages)
    if not result.ok or result.snapshot is None:
        return result, ""
    receipt = CollectionCompletenessReceipt(
        request.identity(), tuple(page.identity for page in pages), _sha256(_collection_snapshot_payload(result.snapshot)),
        context.candidate_sha, context.configuration_digest, context.gate_identity, bundle.identity,
        plan.identity, journal_entry.key if journal_entry is not None else _sha256(("no-journal", plan.intent_identity)),
    )
    return result, receipt.identity


def _complete_pre_dispatch_state(
    adapter: GitHubAdapter, context: MutationBrokerContext,
    bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
    journal_entry: MutationJournalEntry | None,
) -> tuple[GitHubReadResult, str, str]:
    """Capture every broker-owned pre-dispatch proof as one durable state.

    Create-PR requires two independent branch proofs.  They are never
    reconstructed from post-state and both are folded into the persisted
    pre-state digest and completeness identity before owner IPC is reachable.
    """

    results: list[GitHubReadResult] = []
    evidence: list[tuple[str, str, str]] = []
    for request in plan.pre_dispatch_reads:
        result, completeness = _complete_broker_read(
            adapter, request, context, bundle, plan, journal_entry,
        )
        snapshot = result.snapshot
        if not result.ok:
            return result, "", ""
        if request.operation is GitHubReadOperation.BRANCH and (
            type(snapshot) is not BranchSnapshot
            or snapshot.repository != request.repository
            or snapshot.name != request.ref
            or snapshot.sha != request.expected_sha
        ):
            return result, "", ""
        results.append(result)
        evidence.append((request.identity(), result.snapshot_digest, completeness))
    if not results:
        raise GitHubRuntimeError("broker pre-dispatch plan is incomplete")
    return (
        results[0],
        _sha256(("broker-pre-dispatch-state", tuple(evidence))),
        _sha256(("broker-pre-dispatch-completeness", tuple(evidence))),
    )


def _validate_created_resource_locator(
    fact: OwnerMutationAcceptedFact, request: OwnerMutationRequest,
    intent: GitHubMutationIntent, plan: BrokerSemanticPlan,
) -> None:
    """Bind a curated allocation to the sealed request and broker plan."""

    if fact.operation is not intent.operation or request.operation is not intent.operation:
        raise GitHubRuntimeError("created resource operation drifted")
    if plan.operation is not intent.operation or plan.intent_identity != intent.identity():
        raise GitHubRuntimeError("created resource semantic plan drifted")
    locator = fact.created_resource
    if intent.operation not in {
        GitHubMutationOperation.CREATE_PULL_REQUEST,
        GitHubMutationOperation.COMMENT,
    }:
        if locator is not None:
            raise GitHubRuntimeError("non-allocating operation returned a resource locator")
        return
    if type(locator) is not CreatedResourceLocator or locator.repository != request.repository or locator.repository != intent.repository:
        raise GitHubRuntimeError("created resource repository drifted")
    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        if (
            locator.base_sha != request.base_sha
            or locator.head_sha != request.head_sha
            or locator.marker_digest != request.marker_digest
            or not locator.draft
        ):
            raise GitHubRuntimeError("created pull request locator does not match fixed request")
    elif (
        locator.issue_number != request.target_number
        or locator.marker_digest != request.marker_digest
    ):
        raise GitHubRuntimeError("created comment locator does not match fixed request")


def _post_readback_for_locator(
    intent: GitHubMutationIntent, plan: BrokerSemanticPlan,
    locator: CreatedResourceLocator | None,
) -> SemanticReadback | None:
    """Use an allocated identity for creation reads; caller targets never select it."""

    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        if not _created_pull_request_locator_matches_intent(intent, plan, locator):
            return None
        return SemanticReadback(
            GitHubReadRequest(
                GitHubReadOperation.PULL_REQUEST, intent.repository,
                number=locator.pull_request_number, expected_sha=locator.head_sha,
            ),
            SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE,
        )
    if intent.operation is GitHubMutationOperation.COMMENT:
        return plan.readback if (
            type(locator) is CreatedResourceLocator
            and _created_comment_locator_matches_intent(intent, plan, locator)
        ) else None
    return plan.readback


def _created_pull_request_locator_matches_intent(
    intent: GitHubMutationIntent, plan: BrokerSemanticPlan,
    locator: CreatedResourceLocator | None,
) -> bool:
    """Revalidate durable allocation evidence before any allocated-PR read."""

    if (
        type(locator) is not CreatedResourceLocator
        or intent.operation is not GitHubMutationOperation.CREATE_PULL_REQUEST
        or plan.operation is not intent.operation
        or plan.intent_identity != intent.identity()
        or locator.operation is not intent.operation
        or locator.repository != intent.repository
        or locator.draft is not True
    ):
        return False
    payload = dict(intent.payload)
    return (
        locator.base_sha == payload.get("base_sha")
        and locator.head_sha == payload.get("head_sha")
        and locator.marker_digest == payload.get("body_digest")
    )


def _created_comment_locator_matches_intent(
    intent: GitHubMutationIntent, plan: BrokerSemanticPlan,
    locator: CreatedResourceLocator,
) -> bool:
    """Revalidate durable allocated-comment evidence before collection reads."""

    return (
        intent.operation is GitHubMutationOperation.COMMENT
        and plan.operation is intent.operation
        and plan.intent_identity == intent.identity()
        and locator.operation is intent.operation
        and locator.repository == intent.repository
        and locator.issue_number == intent.target_number
        and locator.marker_digest == dict(intent.payload).get("body_digest")
        and type(locator.comment_id) is str
    )


@dataclass(frozen=True)
class _OwnerGitHubBrokerMutationControl:
    """Owner-side sealed authority for one broker submit operation."""

    intent_identity: str
    binding: CandidateBinding
    operation: GitHubMutationOperation
    dependency_control: DependencyExecutionControl
    now: int

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not CandidateBinding
            or type(self.operation) is not GitHubMutationOperation
            or type(self.dependency_control) is not DependencyExecutionControl
            or type(self.now) is not int
        ):
            raise GitHubRuntimeError("owner broker dependency control is invalid")
        _digest(self.intent_identity, "owner broker dependency intent")
        try:
            self.dependency_control.require(self.binding, DependencyStage.GITHUB_MUTATION, now=self.now)
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner broker dependency control is invalid") from error

    def require(self, intent: GitHubMutationIntent, context: MutationBrokerContext, binding: CandidateBinding, *, now: datetime) -> None:
        if (
            type(self) is not _OwnerGitHubBrokerMutationControl
            or type(intent) is not GitHubMutationIntent
            or type(context) is not MutationBrokerContext
            or type(binding) is not CandidateBinding
            or type(now) is not datetime
            or now.tzinfo is not timezone.utc
            or self.now != int(now.timestamp())
            or self.intent_identity != intent.identity()
            or self.binding != binding
            or self.operation is not intent.operation
            or binding.repository != intent.repository.slug
            or binding.repository != context.repository.slug
            or binding.task_id != context.mutation_context.task_fingerprint
            or binding.candidate_sha != context.candidate_sha
        ):
            raise GitHubRuntimeError("owner broker dependency control is invalid")
        try:
            self.dependency_control.require(binding, DependencyStage.GITHUB_MUTATION, now=self.now)
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("owner broker dependency control is stale") from error


class _OwnerBrokerMutationControlRegistry(Protocol):
    """Private owner-side source for exact broker-submit controls."""

    def resolve(self, intent: GitHubMutationIntent) -> _OwnerGitHubBrokerMutationControl | None: ...


@dataclass(frozen=True)
class _OwnerBrokerMutationAuthorization:
    """Private proof that the owner control was resolved once for this route."""

    intent_identity: str
    binding: CandidateBinding
    now: int

    def matches(self, intent: GitHubMutationIntent, context: MutationBrokerContext, *, now: datetime) -> bool:
        return (
            type(self) is _OwnerBrokerMutationAuthorization
            and type(intent) is GitHubMutationIntent
            and type(context) is MutationBrokerContext
            and type(now) is datetime
            and now.tzinfo is timezone.utc
            and self.now == int(now.timestamp())
            and self.intent_identity == intent.identity()
            and self.binding.repository == intent.repository.slug == context.repository.slug
            and self.binding.task_id == context.mutation_context.task_fingerprint
            and self.binding.candidate_sha == context.candidate_sha
        )


class _GhBrokerExecutor:
    """Private credential-owning seam; only broker construction creates it."""

    def __init__(self, transport: OwnerMutationTransport, health: GitHubCapabilityHealth, binding: CandidateBinding | None = None, controls: _OwnerBrokerMutationControlRegistry | None = None) -> None:
        if (
            not hasattr(transport, "dispatch")
            or (binding is None) != (controls is None)
            or (binding is not None and type(binding) is not CandidateBinding)
            or (controls is not None and not hasattr(controls, "resolve"))
        ):
            raise GitHubRuntimeError("owner mutation transport is invalid")
        self.__transport = transport
        self.__health = health
        self.__binding = binding
        self.__controls = controls

    @property
    def health(self) -> GitHubCapabilityHealth:
        return self.__health

    @property
    def requires_owner_dependency_control(self) -> bool:
        return self.__controls is not None

    def require_dependency(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext, *, now: datetime,
    ) -> _OwnerBrokerMutationAuthorization:
        if self.__controls is None or self.__binding is None:
            raise GitHubRuntimeError("owner broker dependency control is unavailable")
        control = self.__controls.resolve(intent)
        if type(control) is not _OwnerGitHubBrokerMutationControl:
            raise GitHubRuntimeError("owner broker dependency control is unavailable")
        control.require(intent, context, self.__binding, now=now)
        return _OwnerBrokerMutationAuthorization(intent.identity(), self.__binding, int(now.timestamp()))

    def execute(
        self, intent: GitHubMutationIntent, payload: GhMutationPayload, command: BrokerMutationCommand,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan, journal: MutationJournalEntry, now: datetime,
        *, health_bound: bool = True,
    ) -> tuple[GitHubMutationResult, CreatedResourceLocator | None]:
        blocked = _health_failure(intent.operation, self.__health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked), None
        if health_bound and (
            bundle.capability_health_identity != self.__health.identity
            or not self.__health.fresh_at(now)
            or not self.__health.for_operation(intent.operation).fresh_at(now)
        ):
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "operation health is stale")), None
        try:
            payload.require_matches(intent)
            if command is not plan.command:
                raise GitHubRuntimeError("broker command does not match semantic plan")
            if (
                type(journal) is not MutationJournalEntry
                or journal.lifecycle is not JournalLifecycle.EXECUTION_STARTED
                or not journal.pre_state_complete
                or journal.pre_state_identity is None
                or journal.pre_state_completeness_identity is None
                or journal.pre_state_read_identity != _pre_dispatch_reads_identity(plan)
            ):
                raise GitHubRuntimeError("broker journal execution seal is unavailable")
            intent_payload = dict(intent.payload)
            if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST and (
                intent.repository.slug != bundle.target_repository
                or intent_payload.get("base_sha") != bundle.base_sha
                or intent_payload.get("head_sha") != bundle.candidate_sha
                or intent_payload.get("base_ref") != bundle.base_ref
                or intent_payload.get("head_ref") != bundle.head_ref
                or bundle.base_repository != bundle.target_repository
                or bundle.head_repository != bundle.target_repository
            ):
                raise GitHubRuntimeError("broker pull request context evidence drifted")
            request = OwnerMutationRequest(
                intent_identity=intent.identity(), operation=intent.operation,
                authorization_bundle_identity=bundle.identity, semantic_plan_identity=plan.identity,
                journal_identity=journal.key, repository=intent.repository,
                target_number=intent.target_number, base_sha=intent_payload.get("base_sha"),
                head_sha=intent_payload.get("head_sha"), marker_digest=intent_payload.get("body_digest"),
                candidate_sha=bundle.candidate_sha, idempotency_identity=plan.idempotency_identity,
                command=plan.command, deployment_identity=bundle.deployment_identity,
                pre_state_identity=journal.pre_state_identity, evaluated_at=journal.evaluated_at,
                fresh_until=journal.fresh_until, time_identity=journal.time_identity,
                capability_health_identity=bundle.capability_health_identity,
                authorized_base_sha=(
                    bundle.base_sha
                    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST
                    else None
                ),
                base_ref=intent_payload.get("base_ref"),
                head_ref=intent_payload.get("head_ref"),
                base_repository=(RepositoryRef(*bundle.base_repository.split("/", 1))
                    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST else None),
                head_repository=(RepositoryRef(*bundle.head_repository.split("/", 1))
                    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST else None),
            )
            fact = self.__transport.dispatch(request)
            request_identity = request.identity
            if type(fact) is OwnerMutationFact:
                if fact.request_identity != request_identity:
                    raise GitHubRuntimeError("owner mutation fact is not bound to request")
            elif type(fact) is OwnerMutationAcceptedFact:
                if fact.request_identity != request_identity or fact.operation is not intent.operation:
                    raise GitHubRuntimeError("owner accepted fact is not bound to request")
                _validate_created_resource_locator(fact, request, intent, plan)
            else:
                raise GitHubRuntimeError("owner mutation fact is not bound to request")
        except GitHubRuntimeError:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is invalid")), None
        if type(fact) is OwnerMutationFact and not fact.accepted:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "owner mutation transport denied fixed request")), None
        return GitHubMutationResult(intent, receipt=_broker_receipt(intent)), fact.created_resource


class GitHubMutationBroker:
    """The sole mutation seam; rejects before a write when evidence is absent."""

    def __init__(self, adapter: GitHubAdapter, *, journal: DurableMutationJournal | None = None, _executor: _GhBrokerExecutor | None = None, clock: Callable[[], datetime] | None = None, checkpoint_observer: Callable[[MutationJournalEntry], None] | None = None) -> None:
        if not hasattr(adapter, "read") or not hasattr(adapter, "submit"):
            raise GitHubRuntimeError("GitHub adapter is invalid")
        self._adapter = adapter
        self.__executor = _executor
        self.__clock = _trusted_utc_now if clock is None else clock
        self.__clock_is_default = clock is None
        self.__health = _executor.health if _executor is not None else None
        self.__checkpoint_observer = checkpoint_observer
        self._completed: dict[str, SemanticMutationReceipt] = {}
        self._journal = journal

    def _now(self, context: MutationBrokerContext) -> datetime:
        """Sample an injected UTC clock once; caller time may only attest it."""

        if self.__clock_is_default:
            # Existing embedded deployments are intentionally fail-closed to
            # their pre-attested context until they inject an owner clock.
            return context.evaluated_at
        try:
            now = self.__clock()
        except Exception as error:
            raise GitHubRuntimeError("trusted broker clock is unavailable") from error
        if type(now) is not datetime or now.tzinfo is not timezone.utc:
            raise GitHubRuntimeError("trusted broker clock is invalid")
        # The compatibility context is accepted only when it exactly attests
        # the broker observation; it never selects policy evaluation time.
        if context.evaluated_at != now:
            raise GitHubRuntimeError("caller authorization time does not match broker clock")
        return now

    def _require_capabilities(self, intent: GitHubMutationIntent, plan: BrokerSemanticPlan, now: datetime) -> None:
        """Gate every broker-owned read and dispatch on one fresh health profile."""

        if self.__health is None:
            return
        _require_fresh_capabilities(
            self.__health,
            (
                *(request.operation for request in plan.pre_dispatch_reads),
                plan.readback.request.operation, intent.operation,
            ), now,
        )

    @classmethod
    def with_owner_transport(
        cls, read_endpoint: OwnerGitHubReadIpcClient, transport: OwnerMutationIpcClient, *, journal: DurableMutationJournal, binding: CandidateBinding, controls: _OwnerBrokerMutationControlRegistry, clock: Callable[[], datetime] | None = None, checkpoint_observer: Callable[[MutationJournalEntry], None] | None = None,
    ) -> "GitHubMutationBroker":
        """Create the only production path from owner-host typed endpoints."""

        if type(journal) is not DurableMutationJournal:
            raise GitHubRuntimeError("live broker requires a durable journal")
        if type(transport) is not OwnerMutationIpcClient:
            raise GitHubRuntimeError("live broker requires an owner mutation IPC client")
        if type(read_endpoint) is not OwnerGitHubReadIpcClient:
            raise GitHubRuntimeError("live broker requires an owner github read IPC client")
        if type(binding) is not CandidateBinding or not hasattr(controls, "resolve"):
            raise GitHubRuntimeError("live broker requires owner dependency controls")
        if clock is None:
            raise GitHubRuntimeError("live broker requires an injected trusted clock")
        return cls(read_endpoint, journal=journal, _executor=_GhBrokerExecutor(transport, read_endpoint.health, binding, controls), clock=clock, checkpoint_observer=checkpoint_observer)

    def submit(
        self,
        intent: GitHubMutationIntent,
        context: MutationBrokerContext,
        *,
        payload: GhMutationPayload | None = None,
        pre_state: GitHubReadRequest | None = None,
        readback: SemanticReadback | None = None,
        semantic_plan: BrokerSemanticPlan | None = None,
        command: BrokerMutationCommand | None = None,
    ) -> BrokerMutationResult:
        """Derive semantics, authorize, submit once, then demand read-back."""

        if pre_state is not None or readback is not None or semantic_plan is not None or command is not None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "caller-supplied mutation semantics are forbidden"))
        try:
            self._require_context_dependency_control(intent, context)
            now = self._now(context)
            self._require_context_dependency_control(intent, context, now=now)
            owner_authorization = self._owner_dependency_preflight(intent, context, now=now)
        except (AttributeError, KeyError, TypeError, ValueError, GitHubRuntimeError):
            return BrokerMutationResult(failure=GitHubFailure(
                GitHubFailureKind.POLICY_DENIED, intent.operation,
                "owner dependency preflight blocked mutation execution",
            ))
        try:
            plan = _broker_semantic_plan(intent)
            self._require_capabilities(intent, plan, now)
            bound_health = self.__health if not self.__clock_is_default else None
            bundle = schema_v2_authorization_bundle(context, now=now, health=bound_health)
            failure = _authorize(intent, context, now=now, health=bound_health)
        except (AttributeError, KeyError, TypeError, ValueError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic plan is unavailable or incomplete"))
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        # A caller carrying outbound payload proves it is attempting the
        # owner-host mutation route.  Do not even open a semantic read when
        # that capability was not injected; reads must not become a fallback
        # mutation transport or process probe.
        if payload is not None and self.__executor is None:
            return BrokerMutationResult(failure=GitHubFailure(
                GitHubFailureKind.POLICY_DENIED, intent.operation,
                "owner mutation transport capability is unavailable",
            ))
        prior = self._completed.get(intent.identity())
        if prior is not None:
            return BrokerMutationResult(receipt=prior)
        evidence: MutationJournalEntry | None = None
        if self._journal is not None:
            try:
                evidence = MutationJournalEntry.from_evidence(intent, context, bundle, plan)
                journal_entry, created = self._journal.claim(evidence)
            except (AttributeError, TypeError, ValueError):
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation evidence is unavailable or conflicting"))
            if not created:
                return self._reconcile_journal(
                    intent, context, bundle, plan, evidence, journal_entry,
                    owner_authorization=owner_authorization,
                )
        if intent.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        } and self.__executor is None:
            return BrokerMutationResult(failure=GitHubFailure(
                GitHubFailureKind.POLICY_DENIED, intent.operation,
                "allocated mutation requires an owner host locator capability",
            ))
        before, pre_state_digest, pre_completeness = _complete_pre_dispatch_state(
            self._adapter, context, bundle, plan, evidence,
        )
        if not before.ok:
            if evidence is not None and self._journal is not None:
                self._journal_transition(evidence, JournalLifecycle.FAILED)
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-mutation semantic state is unavailable"))
        if evidence is not None and self._journal is not None:
            evidence = self._journal_transition(
                evidence, JournalLifecycle.PRESTATE_CAPTURED,
                pre_state_digest=pre_state_digest,
                pre_state_completeness_identity=pre_completeness,
            )
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-state checkpoint was not persisted"))
        if _readback_matches(plan.readback, intent, before):
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(
                    GitHubFailureKind.POLICY_DENIED, intent.operation,
                    "already-satisfied mutation lacks durable pre-state evidence",
                ))
            receipt = self._semantic_receipt(
                intent, context, bundle, plan, pre_state_digest, _post_state_digest(intent, before),
                pre_completeness, pre_completeness, _affected_identity(intent, before),
                MutationDisposition.ALREADY_APPLIED, durable_entry=evidence,
            )
            verified = self._journal_transition(evidence, JournalLifecycle.VERIFIED, receipt)
            if verified is None:
                return BrokerMutationResult(failure=GitHubFailure(
                    GitHubFailureKind.STALE_RESPONSE, intent.operation,
                    "already-satisfied mutation receipt was not persisted",
                ))
            self._completed[intent.identity()] = receipt
            return BrokerMutationResult(receipt=receipt)
        if evidence is not None and self._journal is not None:
            evidence = self._journal_transition(evidence, JournalLifecycle.EXECUTION_STARTED)
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "execution checkpoint was not persisted"))
        outcome, created_resource = self._execute(intent, payload, plan, bundle, evidence, now)
        if not outcome.ok:
            if evidence is not None and self._journal is not None:
                lifecycle = (
                    JournalLifecycle.AMBIGUOUS
                    if evidence.lifecycle is JournalLifecycle.EXECUTION_STARTED
                    else JournalLifecycle.DENIED
                )
                self._journal_transition(evidence, lifecycle)
            return BrokerMutationResult(failure=outcome.failure or GitHubFailure(GitHubFailureKind.UNAVAILABLE, intent.operation, "mutation outcome is unavailable"))
        if evidence is not None and self._journal is not None:
            if intent.operation in {
                GitHubMutationOperation.CREATE_PULL_REQUEST,
                GitHubMutationOperation.COMMENT,
            }:
                evidence = self._journal_transition(
                    evidence, JournalLifecycle.TRANSPORT_ACCEPTED,
                    created_resource=created_resource,
                )
            else:
                evidence = self._journal_transition(evidence, JournalLifecycle.TRANSPORT_ACCEPTED)
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(
                    GitHubFailureKind.STALE_RESPONSE, intent.operation,
                    "transport acceptance checkpoint was not persisted",
                ), reconciliation_required=True)
            evidence = self._journal_transition(evidence, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(
                    GitHubFailureKind.STALE_RESPONSE, intent.operation,
                    "verification checkpoint was not persisted",
                ), reconciliation_required=True)
        if evidence is None and self._journal is not None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation durability is uncertain"), reconciliation_required=True)
        post_readback = _post_readback_for_locator(intent, plan, created_resource)
        if post_readback is None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "created resource locator is unavailable"))
        after, post_completeness = _complete_broker_read(self._adapter, post_readback.request, context, bundle, plan, evidence)
        if not _readback_matches(post_readback, intent, after, created_resource):
            if self._journal is not None:
                assert evidence is not None
                self._journal_transition(evidence, JournalLifecycle.AMBIGUOUS)
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation requires semantic reconciliation"), reconciliation_required=True)
        assert outcome.receipt is not None
        receipt = self._semantic_receipt(
            intent, context, bundle, plan, pre_state_digest, _post_state_digest(intent, after),
            pre_completeness, post_completeness, _affected_identity(intent, after, created_resource),
            outcome.receipt.disposition, durable_entry=evidence,
        )
        self._completed[intent.identity()] = receipt
        if evidence is not None and self._journal is not None and not self._journal_transition(evidence, JournalLifecycle.VERIFIED, receipt):
            self._completed.pop(intent.identity(), None)
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "verified mutation receipt was not persisted"), reconciliation_required=True)
        return BrokerMutationResult(receipt=receipt)

    @staticmethod
    def _semantic_receipt(
        intent: GitHubMutationIntent, context: MutationBrokerContext,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
        pre_state_digest: str, post_state_digest: str, pre_state_completeness_identity: str,
        post_state_completeness_identity: str, affected_identity: str,
        disposition: MutationDisposition, durable_entry: MutationJournalEntry | None = None,
    ) -> SemanticMutationReceipt:
        binding = context.policy.binding
        assert binding is not None  # established by _authorize
        created_resource_identity = (
            durable_entry.created_resource.identity
            if durable_entry is not None and durable_entry.created_resource is not None
            else None
        )
        if intent.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        } and created_resource_identity is None:
            raise GitHubRuntimeError("allocated mutation receipt lacks durable locator")
        return SemanticMutationReceipt(
            intent.repository.slug, intent.operation, intent.idempotency_key,
            bundle.identity if durable_entry is None else durable_entry.authorization_bundle_identity,
            intent.identity(), plan.identity, plan.readback.identity,
            pre_state_completeness_identity, post_state_completeness_identity,
            _sha256(("public-payload", intent.payload)), binding.digest,
            context.configuration_digest, binding.deployment_fingerprint,
            binding.task_fingerprint, context.base_sha, context.candidate_sha,
            context.gate_identity, pre_state_digest, post_state_digest,
            affected_identity, created_resource_identity,
            bundle.evaluated_at if durable_entry is None else durable_entry.evaluated_at,
            bundle.fresh_until if durable_entry is None else durable_entry.fresh_until,
            bundle.time_identity if durable_entry is None else durable_entry.time_identity,
            disposition,
        )

    def _journal_transition(
        self, evidence: MutationJournalEntry, lifecycle: JournalLifecycle,
        receipt: SemanticMutationReceipt | None = None, *, pre_state_digest: str | None = None,
        pre_state_completeness_identity: str | None = None,
        created_resource: CreatedResourceLocator | None | object = _KEEP_CREATED_RESOURCE,
    ) -> MutationJournalEntry | None:
        assert self._journal is not None
        try:
            updated = self._journal.transition(
                evidence, lifecycle, receipt, pre_state_digest=pre_state_digest,
                pre_state_completeness_identity=pre_state_completeness_identity,
                created_resource=created_resource,
            )
        except (AttributeError, TypeError, ValueError):
            return None
        # Reconstruct from the serialized public-safe record before returning:
        # callers never retain an in-memory value that was not durably stored.
        try:
            persisted = MutationJournalEntry.deserialize(updated.serialize())
        except (AttributeError, TypeError, ValueError):
            return None
        if self.__checkpoint_observer is not None:
            self.__checkpoint_observer(persisted)
        return persisted

    def _owner_dependency_preflight(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext, *, now: datetime,
    ) -> _OwnerBrokerMutationAuthorization | None:
        if self.__executor is None or not self.__executor.requires_owner_dependency_control:
            return None
        return self.__executor.require_dependency(intent, context, now=now)

    @staticmethod
    def _require_context_dependency_control(
        intent: GitHubMutationIntent, context: MutationBrokerContext, *, now: datetime | None = None,
    ) -> None:
        """Reject invalid dependency evidence without invoking broker callbacks."""

        if type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext:
            raise GitHubRuntimeError("broker dependency context is invalid")
        attested_now = context.evaluated_at if now is None else now
        if type(attested_now) is not datetime or attested_now.tzinfo is not timezone.utc:
            raise GitHubRuntimeError("broker dependency control time is invalid")
        if intent.repository != context.repository or context.mutation_context.candidate_sha != context.candidate_sha:
            raise GitHubRuntimeError("broker dependency control does not match active context")
        control = context.dependency_control
        if type(control) is not DependencyExecutionControl:
            raise GitHubRuntimeError("broker dependency execution control is unavailable")
        binding = CandidateBinding(intent.repository.slug, context.mutation_context.task_fingerprint, context.candidate_sha)
        try:
            control.require(binding, DependencyStage.GITHUB_MUTATION, now=int(attested_now.timestamp()))
        except DependencyPolicyError as error:
            raise GitHubRuntimeError("broker dependency preflight blocked execution") from error

    def _reconcile_journal(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
        evidence: MutationJournalEntry, entry: MutationJournalEntry,
        *, owner_authorization: _OwnerBrokerMutationAuthorization | None = None,
    ) -> BrokerMutationResult:
        """Resolve a durable uncertain state only from broker-owned read-back."""

        try:
            self._require_context_dependency_control(intent, context)
            now = self._now(context)
            self._require_context_dependency_control(intent, context, now=now)
            if self.__executor is not None and self.__executor.requires_owner_dependency_control:
                if type(owner_authorization) is not _OwnerBrokerMutationAuthorization:
                    owner_authorization = self._owner_dependency_preflight(intent, context, now=now)
                if not owner_authorization.matches(intent, context, now=now):
                    raise GitHubRuntimeError("owner broker dependency authorization is invalid")
            evaluated_at = datetime.fromisoformat(entry.evaluated_at)
            fresh_until = datetime.fromisoformat(entry.fresh_until)
        except (TypeError, ValueError, GitHubRuntimeError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable authorization time evidence is invalid"))
        if now < evaluated_at or now >= fresh_until:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "durable authorization evidence has expired"))
        try:
            self._require_capabilities(intent, plan, now)
            if not self.__clock_is_default and self.__health is not None and bundle.capability_health_identity != self.__health.identity:
                raise GitHubRuntimeError("durable capability health evidence drifted")
        except (TypeError, ValueError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable capability health evidence is unavailable"))

        if entry.lifecycle in {JournalLifecycle.CLAIMED, JournalLifecycle.PRESTATE_CAPTURED}:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation has not started execution"))
        if (
            not entry.pre_state_complete or entry.pre_state_digest is None
            or entry.pre_state_completeness_identity is None
        ):
            return BrokerMutationResult(failure=GitHubFailure(
                GitHubFailureKind.POLICY_DENIED, intent.operation,
                "durable mutation pre-state provenance is unavailable",
            ))

        if entry.lifecycle is JournalLifecycle.VERIFIED:
            assert entry.receipt is not None
            self._completed[intent.identity()] = entry.receipt
            return BrokerMutationResult(receipt=entry.receipt)
        if entry.lifecycle in {JournalLifecycle.DENIED, JournalLifecycle.FAILED}:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation lifecycle is terminally denied or failed"))
        post_readback = _post_readback_for_locator(intent, plan, entry.created_resource)
        if post_readback is None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable created resource locator is unavailable"))
        observed, completeness = _complete_broker_read(self._adapter, post_readback.request, context, bundle, plan, entry)
        if not _readback_matches(post_readback, intent, observed, entry.created_resource):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "durable mutation requires semantic reconciliation"), reconciliation_required=True)
        receipt = self._semantic_receipt(
            intent, context, bundle, plan, entry.pre_state_digest, _post_state_digest(intent, observed),
            entry.pre_state_completeness_identity, completeness,
            _affected_identity(intent, observed, entry.created_resource), MutationDisposition.ALREADY_APPLIED,
            durable_entry=entry,
        )
        if self._journal is not None:
            final_entry = entry
            if entry.lifecycle is JournalLifecycle.EXECUTION_STARTED:
                final_entry = self._journal_transition(entry, JournalLifecycle.AMBIGUOUS)
            elif entry.lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
                final_entry = self._journal_transition(entry, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
            if final_entry is None or not self._journal_transition(final_entry, JournalLifecycle.VERIFIED, receipt):
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "reconciled receipt was not persisted"), reconciliation_required=True)
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)

    def _execute(
        self, intent: GitHubMutationIntent, payload: GhMutationPayload | None, plan: BrokerSemanticPlan,
        bundle: SchemaV2AuthorizationBundle, evidence: MutationJournalEntry | None, now: datetime,
    ) -> tuple[GitHubMutationResult, CreatedResourceLocator | None]:
        if type(plan) is not BrokerSemanticPlan or plan.operation is not intent.operation or plan.command is not _MUTATION_COMMAND_BY_OPERATION[intent.operation]:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic command is invalid")), None
        if self.__executor is not None:
            if type(payload) is not GhMutationPayload:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is unavailable")), None
            if self._journal is None:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "live mutation lacks durable journal evidence")), None
            if type(evidence) is not MutationJournalEntry:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "live mutation lacks sealed journal entry")), None
            return self.__executor.execute(
                intent, payload, plan.command, bundle, plan, evidence, now,
                health_bound=not self.__clock_is_default,
            )
        if payload is not None:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "adapter does not accept brokered mutation payloads")), None
        return self._adapter.submit(intent), None

    def reconcile(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext, *,
        readback: SemanticReadback | None = None, semantic_plan: BrokerSemanticPlan | None = None,
        command: BrokerMutationCommand | None = None,
    ) -> BrokerMutationResult:
        """Safely classify an interrupted attempt from post-state only.

        It never re-submits the mutation.  A match yields a durable
        ``ALREADY_APPLIED`` receipt; anything else remains blocked.
        """

        if readback is not None or semantic_plan is not None or command is not None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "caller-supplied mutation semantics are forbidden"))
        try:
            self._require_context_dependency_control(intent, context)
            now = self._now(context)
            self._require_context_dependency_control(intent, context, now=now)
            owner_authorization = self._owner_dependency_preflight(intent, context, now=now)
            plan = _broker_semantic_plan(intent)
            self._require_capabilities(intent, plan, now)
            bound_health = self.__health if not self.__clock_is_default else None
            bundle = schema_v2_authorization_bundle(context, now=now, health=bound_health)
            failure = _authorize(intent, context, now=now, health=bound_health)
        except (AttributeError, KeyError, TypeError, ValueError, GitHubRuntimeError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic plan is unavailable or incomplete"))
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        if intent.operation in {
            GitHubMutationOperation.CREATE_PULL_REQUEST,
            GitHubMutationOperation.COMMENT,
        } and self._journal is None:
            return BrokerMutationResult(failure=GitHubFailure(
                GitHubFailureKind.POLICY_DENIED, intent.operation,
                "allocated mutation requires an owner host and durable locator evidence",
            ))
        if self._journal is not None:
            try:
                entry = self._journal.find_recovery(intent, context, plan)
            except (AttributeError, TypeError, ValueError):
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation evidence is unavailable or conflicting"))
            if entry is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation evidence is missing"))
            return self._reconcile_journal(
                intent, context, bundle, plan, entry, entry,
                owner_authorization=owner_authorization,
            )
        observed, completeness = _complete_broker_read(self._adapter, plan.readback.request, context, bundle, plan, None)
        if not _readback_matches(plan.readback, intent, observed):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "interrupted mutation is not semantically reconciled"), reconciliation_required=True)
        receipt = self._semantic_receipt(intent, context, bundle, plan, observed.snapshot_digest, _post_state_digest(intent, observed), completeness, completeness, _affected_identity(intent, observed), MutationDisposition.ALREADY_APPLIED)
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)


def _authorize(
    intent: object, context: object, *, now: datetime | None = None,
    health: GitHubCapabilityHealth | None = None,
) -> GitHubFailure | None:
    if type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext:
        raise GitHubRuntimeError("broker request is invalid")
    try:
        # This is deliberately before every adapter read or mutation.  The
        # bundle is built only from exact canonical evidence and rejects any
        # receipt, authority, context, or dispatcher drift before a runner can
        # observe an intent.
        schema_v2_authorization_bundle(context, now=now, health=health)
    except (AttributeError, TypeError, ValueError):
        return GitHubFailure(
            GitHubFailureKind.POLICY_DENIED,
            intent.operation,
            "schema-v2 authorization evidence denies this mutation",
        )
    operation = _repository_operation(intent.operation)
    policy = context.policy
    binding = policy.binding
    if operation is None or not policy.authorized or policy.operation is not operation or binding is None:
        return GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "repository mutation policy denies this operation")
    if not context.deployment.authorized or context.deployment.mode is not DeploymentMode.AUTHORITATIVE:
        return GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "deployment authority denies GitHub mutation")
    if binding.candidate_sha != context.candidate_sha:
        return GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation authority is not bound to the exact candidate and deployment")
    if intent.repository != context.repository:
        return GitHubFailure(
            GitHubFailureKind.POLICY_DENIED,
            intent.operation,
            "mutation target repository is not bound to the authorized context",
        )
    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        payload = dict(intent.payload)
        if (
            payload.get("base_sha") != context.base_sha
            or payload.get("head_sha") != context.candidate_sha
            or payload.get("base_ref") != context.base_ref
            or payload.get("head_ref") != context.head_ref
            or context.base_repository != context.repository
            or context.head_repository != context.repository
        ):
            return GitHubFailure(
                GitHubFailureKind.STALE_RESPONSE,
                intent.operation,
                "pull request payload is not bound to the authorized base and candidate",
            )
    if intent.expected_sha is not None and intent.expected_sha != context.candidate_sha:
        return GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation intent is not bound to the exact candidate")
    return None


def _repository_operation(operation: GitHubMutationOperation) -> RepositoryMutationOperation:
    """Use the schema-v2 policy's canonical, total GitHub-operation mapping."""

    if type(operation) is not GitHubMutationOperation:
        raise GitHubRuntimeError("github mutation operation is invalid")
    return GITHUB_REPOSITORY_OPERATION[operation]


def _matches(readback: SemanticReadback, intent: GitHubMutationIntent, snapshot: GitHubSnapshot | None) -> bool:
    if snapshot is None:
        return False
    condition = readback.condition
    if condition is SemanticPostcondition.COMMENT_PRESENT:
        return (
            isinstance(snapshot, CommentsSnapshot)
            and snapshot.repository == intent.repository
            and snapshot.issue_number == intent.target_number
            and dict(intent.payload).get("body_digest") in {item.body_digest for item in snapshot.comments}
        )
    if condition is SemanticPostcondition.BRANCH_AT_EXPECTED_SHA:
        return isinstance(snapshot, BranchSnapshot) and snapshot.repository == intent.repository and snapshot.name == intent.target_ref and snapshot.sha == intent.expected_sha
    if condition is SemanticPostcondition.BRANCH_ABSENT:
        return snapshot is None
    if condition is SemanticPostcondition.PULL_REQUEST_DRAFT:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.repository == intent.repository and snapshot.base_repository == intent.repository and snapshot.head_repository == intent.repository and snapshot.number == intent.target_number and snapshot.state is PullRequestState.OPEN and snapshot.draft
    if condition is SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.repository == intent.repository and snapshot.base_repository == intent.repository and snapshot.head_repository == intent.repository and snapshot.number == intent.target_number and snapshot.state is PullRequestState.OPEN and snapshot.draft and snapshot.head_sha == dict(intent.payload).get("head_sha") and snapshot.base_sha == dict(intent.payload).get("base_sha") and snapshot.head_ref == dict(intent.payload).get("head_ref") and snapshot.base_ref == dict(intent.payload).get("base_ref")
    if condition is SemanticPostcondition.PULL_REQUEST_READY:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.repository == intent.repository and snapshot.base_repository == intent.repository and snapshot.head_repository == intent.repository and snapshot.number == intent.target_number and snapshot.state is PullRequestState.OPEN and not snapshot.draft and snapshot.head_sha == intent.expected_sha
    if condition is SemanticPostcondition.PULL_REQUEST_MERGED:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.repository == intent.repository and snapshot.base_repository == intent.repository and snapshot.head_repository == intent.repository and snapshot.number == intent.target_number and snapshot.state is PullRequestState.MERGED and snapshot.head_sha == intent.expected_sha and type(snapshot.merge_commit_sha) is str
    if condition is SemanticPostcondition.REVIEW_AT_CANDIDATE:
        return isinstance(snapshot, ReviewsSnapshot) and snapshot.repository == intent.repository and snapshot.pull_request_number == intent.target_number and snapshot.head_sha == intent.expected_sha and bool(snapshot.reviews)
    if condition is SemanticPostcondition.REVIEWERS_EXACT_AT_CANDIDATE:
        return isinstance(snapshot, RequestedReviewersSnapshot) and snapshot.repository == intent.repository and snapshot.pull_request_number == intent.target_number and snapshot.candidate_sha == intent.expected_sha and snapshot.complete and snapshot.reviewer_set_digest == dict(intent.payload).get("reviewers_digest")
    if condition is SemanticPostcondition.ISSUE_CLOSED:
        return isinstance(snapshot, IssueSnapshot) and snapshot.repository == intent.repository and snapshot.number == intent.target_number and snapshot.state is IssueState.CLOSED
    if condition is SemanticPostcondition.REMOTE_HEAD_AT_EXPECTED_SHA:
        return isinstance(snapshot, RemoteHeadSnapshot) and snapshot.repository == intent.repository and snapshot.ref == intent.target_ref and snapshot.sha == intent.expected_sha
    return False


def _readback_matches(
    readback: SemanticReadback, intent: GitHubMutationIntent, result: GitHubReadResult,
    locator: CreatedResourceLocator | None = None,
) -> bool:
    """Interpret the one explicit branch-absence result without inventing success."""

    if readback.condition is SemanticPostcondition.BRANCH_ABSENT:
        return (
            result.failure is not None
            and result.failure.kind is GitHubFailureKind.STALE_RESPONSE
            and result.request == readback.request
        )
    if not result.ok:
        return False
    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        if type(locator) is not CreatedResourceLocator or type(result.snapshot) is not PullRequestSnapshot:
            return False
        payload = dict(intent.payload)
        return (
            result.snapshot.repository == intent.repository
            and result.snapshot.base_repository == intent.repository
            and result.snapshot.head_repository == intent.repository
            and result.snapshot.number == locator.pull_request_number
            and result.snapshot.pull_request_id == locator.pull_request_id
            and result.snapshot.state is PullRequestState.OPEN
            and result.snapshot.draft is locator.draft
            and result.snapshot.base_sha == locator.base_sha == payload.get("base_sha")
            and result.snapshot.head_sha == locator.head_sha == payload.get("head_sha")
            and locator.marker_digest == payload.get("body_digest")
            and result.snapshot.base_ref == payload.get("base_ref")
            and result.snapshot.head_ref == payload.get("head_ref")
        )
    if intent.operation is GitHubMutationOperation.COMMENT:
        return (
            type(locator) is CreatedResourceLocator
            and type(result.snapshot) is CommentsSnapshot
            and result.snapshot.repository == intent.repository
            and result.snapshot.issue_number == locator.issue_number == intent.target_number
            and any(
                item.comment_id == locator.comment_id
                and item.body_digest == locator.marker_digest
                for item in result.snapshot.comments
            )
        )
    return _matches(readback, intent, result.snapshot)


def _affected_identity(
    intent: GitHubMutationIntent, result: GitHubReadResult,
    locator: CreatedResourceLocator | None = None,
) -> str:
    """Bind a receipt to the exact normalized post-state, never a transport label."""

    if type(intent) is not GitHubMutationIntent or type(result) is not GitHubReadResult:
        raise GitHubRuntimeError("semantic affected identity is unavailable")
    if intent.operation is GitHubMutationOperation.DELETE_BRANCH:
        if result.failure is not None and result.failure.kind is GitHubFailureKind.STALE_RESPONSE and result.request.repository == intent.repository and result.request.ref == intent.target_ref:
            return _sha256(("affected", intent.operation.value, intent.repository.slug, intent.target_ref, "absent"))
        raise GitHubRuntimeError("deleted branch affected identity is unavailable")
    if not result.ok or result.snapshot is None:
        raise GitHubRuntimeError("semantic affected identity is unavailable")
    if intent.operation in {GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH} and type(result.snapshot) is BranchSnapshot:
        return _sha256(("affected", intent.operation.value, result.snapshot.repository.slug, result.snapshot.name, result.snapshot.sha))
    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST and type(result.snapshot) is PullRequestSnapshot:
        if (
            type(locator) is not CreatedResourceLocator
            or locator.operation is not intent.operation
            or locator.repository != intent.repository
            or locator.pull_request_number != result.snapshot.number
            or locator.pull_request_id != result.snapshot.pull_request_id
            or result.snapshot.repository != intent.repository
            or result.snapshot.base_repository != intent.repository
            or result.snapshot.head_repository != intent.repository
        ):
            raise GitHubRuntimeError("allocated pull request affected identity is unavailable")
        return _sha256((
            "affected", intent.operation.value, result.snapshot.repository.slug,
            result.snapshot.pull_request_id, result.snapshot.number, result.snapshot.state.value,
            result.snapshot.base_ref, result.snapshot.base_sha, result.snapshot.head_ref,
            result.snapshot.head_sha, result.snapshot.base_repository.slug,
            result.snapshot.head_repository.slug, result.snapshot.draft,
        ))
    if intent.operation is GitHubMutationOperation.COMMENT and type(locator) is CreatedResourceLocator and type(result.snapshot) is CommentsSnapshot:
        if (
            locator.operation is not intent.operation
            or locator.repository != intent.repository
            or result.snapshot.repository != intent.repository
            or result.snapshot.issue_number != locator.issue_number
            or locator.issue_number != intent.target_number
        ):
            raise GitHubRuntimeError("allocated comment affected identity is unavailable")
        for comment in result.snapshot.comments:
            if comment.comment_id == locator.comment_id and comment.body_digest == locator.marker_digest:
                return _sha256((
                    "affected", intent.operation.value, result.snapshot.repository.slug,
                    result.snapshot.issue_number, comment.comment_id, comment.body_digest,
                    comment.created_at,
                ))
        raise GitHubRuntimeError("allocated comment affected identity is unavailable")
    if intent.operation in {GitHubMutationOperation.MARK_READY, GitHubMutationOperation.MERGE_PULL_REQUEST} and type(result.snapshot) is PullRequestSnapshot:
        if intent.operation is GitHubMutationOperation.MERGE_PULL_REQUEST and type(result.snapshot.merge_commit_sha) is not str:
            raise GitHubRuntimeError("merged pull request affected identity is unavailable")
        return _sha256((
            "affected", intent.operation.value, result.snapshot.repository.slug,
            result.snapshot.pull_request_id, result.snapshot.number, result.snapshot.state.value,
            result.snapshot.base_ref, result.snapshot.base_sha, result.snapshot.head_ref,
            result.snapshot.head_sha, result.snapshot.base_repository.slug,
            result.snapshot.head_repository.slug, result.snapshot.draft, result.snapshot.merge_commit_sha,
        ))
    if intent.operation is GitHubMutationOperation.REQUEST_REVIEW and type(result.snapshot) is RequestedReviewersSnapshot:
        return _sha256((
            "affected", intent.operation.value, result.snapshot.repository.slug,
            result.snapshot.pull_request_number, result.snapshot.candidate_sha,
            result.snapshot.reviewers, result.snapshot.reviewer_set_digest,
        ))
    if intent.operation is GitHubMutationOperation.CLOSE_ISSUE and type(result.snapshot) is IssueSnapshot:
        return _sha256((
            "affected", intent.operation.value, result.snapshot.repository.slug,
            result.snapshot.issue_id, result.snapshot.number, result.snapshot.state.value,
        ))
    # The typed snapshot digest commits repository, target, candidate and the
    # operation-specific normalized fields selected by the broker read-back.
    return _sha256(("affected", intent.operation.value, intent.repository.slug, intent.target_ref, intent.target_number, result.snapshot_digest))


def _post_state_digest(intent: GitHubMutationIntent, result: GitHubReadResult) -> str:
    """Represent a verified absence without inventing a provider snapshot."""

    if intent.operation is GitHubMutationOperation.DELETE_BRANCH:
        if result.failure is not None and result.failure.kind is GitHubFailureKind.STALE_RESPONSE:
            return _sha256(("branch-absent", intent.repository.slug, intent.target_ref))
        raise GitHubRuntimeError("deleted branch post-state is unavailable")
    _digest(result.snapshot_digest, "post-state")
    return result.snapshot_digest


def _project_repository_metadata(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    """Project only the repository fields the first REST response establishes."""

    item = _raw_mapping(raw)
    _raw_repository_matches(item, request)
    if _raw_text(item, "full_name") != request.repository.slug:
        raise GitHubRuntimeError("gh repository full name does not match request")
    return {
        "repository": {"owner": request.repository.owner, "name": request.repository.name},
        "id": _raw_id(item, "id"),
        "default_branch": _raw_text(item, "default_branch"),
    }


def _compose_repository_default_head(
    request: GitHubReadRequest, metadata: Mapping[str, object], repository_raw: object, branch_raw: object,
) -> Mapping[str, object]:
    """Bind one exact branch ref response to its preceding repository metadata."""

    default_branch = _raw_text(metadata, "default_branch")
    branch = _raw_mapping(branch_raw)
    if _raw_text(branch, "name") != default_branch:
        raise GitHubRuntimeError("gh default branch changed between repository reads")
    _raw_branch_repository_matches(branch, request)
    commit = _raw_mapping(branch.get("commit"))
    sha = _raw_text(commit, "sha")
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise GitHubRuntimeError("gh default branch sha is malformed")
    if not _raw_text(commit, "url").rstrip("/").endswith(
        f"/repos/{request.repository.slug}/commits/{sha}",
    ):
        raise GitHubRuntimeError("gh default branch commit identity does not match response")
    return {
        "repository": _raw_mapping(metadata.get("repository")),
        "id": _raw_id(metadata, "id"),
        "default_branch": default_branch,
        "default_branch_sha": sha,
        "repository_evidence_identity": _sha256(repository_raw),
        "default_branch_evidence_identity": _sha256(branch_raw),
    }


def _provider_url_path(value: object) -> str:
    if type(value) is not str:
        raise GitHubRuntimeError("gh provider url is malformed")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise GitHubRuntimeError("gh provider url is malformed")
    return parsed.path.rstrip("/")


def _provider_repository_from_url(value: object) -> RepositoryRef:
    match = re.fullmatch(r"/repos/([A-Za-z0-9][A-Za-z0-9._-]{0,99})/([A-Za-z0-9][A-Za-z0-9._-]{0,99})", _provider_url_path(value))
    if match is None:
        raise GitHubRuntimeError("gh repository url is malformed")
    return RepositoryRef(match.group(1), match.group(2))


def _provider_issue_number_from_url(value: object, repository: RepositoryRef) -> int:
    match = re.fullmatch(
        rf"/(?:repos/)?{re.escape(repository.owner)}/{re.escape(repository.name)}/issues/([1-9][0-9]*)",
        _provider_url_path(value),
    )
    if match is None:
        raise GitHubRuntimeError("gh issue url is malformed")
    return int(match.group(1))


def _project_issue_metadata(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    """Project provider-established issue metadata without relationship inference."""

    item = _raw_mapping(raw)
    repository = _provider_repository_from_url(_raw_text(item, "repository_url"))
    if repository != request.repository:
        raise GitHubRuntimeError("gh issue repository does not match request")
    number = _raw_integer(item, "number")
    if number <= 0 or number != request.number:
        raise GitHubRuntimeError("gh issue number does not match request")
    if _provider_issue_number_from_url(_raw_text(item, "url"), repository) != number:
        raise GitHubRuntimeError("gh issue api url does not match response")
    if _provider_issue_number_from_url(_raw_text(item, "html_url"), repository) != number:
        raise GitHubRuntimeError("gh issue html url does not match response")
    state = {"open": "OPEN", "closed": "CLOSED"}.get(_raw_text(item, "state"))
    if state is None:
        raise GitHubRuntimeError("gh issue state is malformed")
    parent_value = item.get("parent_issue_url")
    parent_number = None if parent_value is None else _provider_issue_number_from_url(parent_value, repository)
    if parent_number == number:
        raise GitHubRuntimeError("gh issue parent cannot be self")
    summary = item.get("sub_issues_summary")
    if summary is None:
        summary_total = None
    else:
        summary_total = _raw_integer(_raw_mapping(summary), "total")
        if summary_total < 0:
            raise GitHubRuntimeError("gh issue sub-issue summary is malformed")
    return {
        "repository": {"owner": repository.owner, "name": repository.name},
        "id": _raw_id(item, "id"), "number": number, "state": state,
        "parent_number": parent_number, "summary_total": summary_total,
    }


def _project_issue_relationship_page(
    request: GitHubReadRequest, raw: object,
) -> tuple[list[int], str | None, int]:
    root = _raw_mapping(raw)
    data = _raw_mapping(root.get("data"))
    repository = _raw_mapping(data.get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    issue = _raw_mapping(repository.get("issue"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name or _raw_integer(issue, "number") != request.number:
        raise GitHubRuntimeError("gh issue relationship identity does not match request")
    connection = _raw_mapping(issue.get("subIssues"))
    total_count = _raw_integer(connection, "totalCount")
    if total_count < 0:
        raise GitHubRuntimeError("gh issue relationship total is malformed")
    page_info = _raw_mapping(connection.get("pageInfo"))
    has_next = _raw_bool(page_info, "hasNextPage")
    end_cursor = page_info.get("endCursor")
    if has_next:
        if type(end_cursor) is not str or not _CURSOR.fullmatch(end_cursor):
            raise GitHubRuntimeError("gh issue relationship continuation is malformed")
        next_cursor: str | None = end_cursor
    else:
        if end_cursor is not None and (type(end_cursor) is not str or not _CURSOR.fullmatch(end_cursor)):
            raise GitHubRuntimeError("gh issue relationship terminal cursor is malformed")
        next_cursor = None
    nodes = connection.get("nodes")
    if type(nodes) is not list:
        raise GitHubRuntimeError("gh issue relationship nodes are malformed")
    numbers = [_raw_integer(_raw_mapping(node), "number") for node in nodes]
    if any(number <= 0 or number == request.number for number in numbers) or len(set(numbers)) != len(numbers):
        raise GitHubRuntimeError("gh issue relationship children are malformed")
    return numbers, next_cursor, total_count


def _compose_issue_relationships(
    request: GitHubReadRequest, metadata: Mapping[str, object], metadata_raw: object,
    children: list[int], relationship_page_evidence: list[str],
) -> Mapping[str, object]:
    summary_total = metadata.get("summary_total")
    if summary_total is not None and (type(summary_total) is not int or summary_total != len(children)):
        raise GitHubRuntimeError("gh issue sub-issue summary does not match complete child collection")
    if len(set(children)) != len(children):
        raise GitHubRuntimeError("gh issue relationship children are duplicated")
    return {
        "repository": _raw_mapping(metadata.get("repository")), "id": _raw_id(metadata, "id"),
        "number": _raw_integer(metadata, "number"), "state": _raw_text(metadata, "state"),
        "parent_number": metadata.get("parent_number"), "sub_issue_numbers": sorted(children),
        "issue_evidence_identity": _sha256(metadata_raw),
        "relationship_evidence_identity": _sha256(("issue-relationship-pages", tuple(relationship_page_evidence))),
    }


def _repository_from_full_name(value: object) -> RepositoryRef:
    if type(value) is not str or value.count("/") != 1:
        raise GitHubRuntimeError("gh repository full name is malformed")
    owner, name = value.split("/", 1)
    return RepositoryRef(owner, name)


def _project_candidate_pull_request_evidence(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    item = _raw_mapping(raw)
    if _raw_integer(item, "number") != request.number:
        raise GitHubRuntimeError("gh candidate pull-request number does not match request")
    base_repository = _repository_from_full_name(_raw_text(_raw_mapping(_raw_mapping(item.get("base")).get("repo")), "full_name"))
    head = _raw_mapping(item.get("head"))
    head_repository = _repository_from_full_name(_raw_text(_raw_mapping(head.get("repo")), "full_name"))
    if base_repository != request.repository or head_repository != request.repository:
        raise GitHubRuntimeError("gh candidate pull-request repository does not match request")
    head_sha = _raw_text(head, "sha")
    if head_sha != request.expected_sha:
        raise GitHubRuntimeError("gh candidate pull-request head does not match request")
    return {
        "repository": {"owner": base_repository.owner, "name": base_repository.name},
        "pull_request_number": _raw_integer(item, "number"), "head_sha": head_sha,
        "candidate_evidence_identity": _sha256(raw),
    }


def _project_checks_page(request: GitHubReadRequest, raw: object) -> tuple[list[Mapping[str, object]], int]:
    envelope = _raw_mapping(raw)
    total_count = _raw_integer(envelope, "total_count")
    items = envelope.get("check_runs")
    if total_count < 0 or type(items) is not list:
        raise GitHubRuntimeError("gh check-runs response is incomplete")
    projected: list[Mapping[str, object]] = []
    for value in items:
        check = _raw_mapping(value)
        head_sha = _raw_text(check, "head_sha")
        if head_sha != request.expected_sha:
            raise GitHubRuntimeError("gh check-run candidate does not match request")
        suite = check.get("check_suite")
        if suite is not None and _raw_text(_raw_mapping(suite), "head_sha") != request.expected_sha:
            raise GitHubRuntimeError("gh check-suite candidate does not match request")
        projected.append({
            "id": _raw_id(check, "id"), "name": _raw_text(check, "name"),
            "state": _raw_text(check, "status").upper(),
            "conclusion": _raw_optional_text(check, "conclusion", upper=True), "head_sha": head_sha,
        })
    return projected, total_count


def _project_workflow_runs_page(request: GitHubReadRequest, raw: object) -> tuple[list[Mapping[str, object]], int]:
    envelope = _raw_mapping(raw)
    total_count = _raw_integer(envelope, "total_count")
    items = envelope.get("workflow_runs")
    if total_count < 0 or type(items) is not list:
        raise GitHubRuntimeError("gh workflow-runs response is incomplete")
    projected: list[Mapping[str, object]] = []
    for value in items:
        run = _raw_mapping(value)
        if (
            _repository_from_full_name(_raw_text(_raw_mapping(run.get("repository")), "full_name")) != request.repository
            or _repository_from_full_name(_raw_text(_raw_mapping(run.get("head_repository")), "full_name")) != request.repository
        ):
            raise GitHubRuntimeError("gh workflow repository does not match request")
        head_sha = _raw_text(run, "head_sha")
        if head_sha != request.expected_sha:
            raise GitHubRuntimeError("gh workflow candidate does not match request")
        relationships = run.get("pull_requests")
        if type(relationships) is not list or not relationships:
            raise GitHubRuntimeError("gh workflow pull-request relationship is incomplete")
        matching = []
        for relation in relationships:
            relationship = _raw_mapping(relation)
            if _raw_integer(relationship, "number") == request.number:
                matching.append(relationship)
        if len(matching) != 1 or _raw_text(_raw_mapping(matching[0].get("head")), "sha") != request.expected_sha:
            raise GitHubRuntimeError("gh workflow pull-request relationship does not match request")
        projected.append({
            "id": _raw_id(run, "id"), "workflow_name": _raw_text(run, "name"),
            "state": _raw_text(run, "status").upper(),
            "conclusion": _raw_optional_text(run, "conclusion", upper=True), "head_sha": head_sha,
        })
    return projected, total_count


def _compose_checks(
    request: GitHubReadRequest, candidate: Mapping[str, object], checks: list[Mapping[str, object]], evidence: list[str],
) -> Mapping[str, object]:
    return {
        "repository": _raw_mapping(candidate.get("repository")),
        "pull_request_number": _raw_integer(candidate, "pull_request_number"),
        "head_sha": _raw_text(candidate, "head_sha"), "checks": checks,
        "check_evidence_identity": _sha256(("check-run-pages", tuple(evidence))),
        "candidate_evidence_identity": _raw_text(candidate, "candidate_evidence_identity"),
    }


def _compose_workflow_runs(
    request: GitHubReadRequest, candidate: Mapping[str, object], runs: list[Mapping[str, object]], evidence: list[str],
) -> Mapping[str, object]:
    return {
        "repository": _raw_mapping(candidate.get("repository")),
        "pull_request_number": _raw_integer(candidate, "pull_request_number"),
        "head_sha": _raw_text(candidate, "head_sha"), "runs": runs,
        "workflow_evidence_identity": _sha256(("workflow-run-pages", tuple(evidence))),
        "candidate_evidence_identity": _raw_text(candidate, "candidate_evidence_identity"),
    }


def _project_requested_reviewers_page(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    repository = {"owner": request.repository.owner, "name": request.repository.name}
    root = _raw_mapping(raw)
    graph_repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    pull_request = _raw_mapping(graph_repository.get("pullRequest"))
    if _raw_text(_raw_mapping(graph_repository.get("owner")), "login") != request.repository.owner or _raw_text(graph_repository, "name") != request.repository.name or _raw_integer(pull_request, "number") != request.number or _raw_text(pull_request, "headRefOid") != request.expected_sha:
        raise GitHubRuntimeError("gh requested-reviewer identity does not match request")
    connection = _raw_mapping(pull_request.get("reviewRequests"))
    page_info = _raw_mapping(connection.get("pageInfo"))
    has_next = _raw_bool(page_info, "hasNextPage")
    cursor = page_info.get("endCursor")
    if (has_next and (type(cursor) is not str or not _CURSOR.fullmatch(cursor))) or (not has_next and cursor is not None and (type(cursor) is not str or not _CURSOR.fullmatch(cursor))):
        raise GitHubRuntimeError("gh requested-reviewer pagination is malformed")
    nodes = connection.get("nodes")
    if type(nodes) is not list:
        raise GitHubRuntimeError("gh requested-reviewer nodes are malformed")
    reviewers: list[str] = []
    for node in nodes:
        reviewer = _raw_mapping(_raw_mapping(node).get("requestedReviewer"))
        reviewer_type = _raw_text(reviewer, "__typename")
        if reviewer_type in {"User", "Bot", "Organization", "Mannequin"}:
            login = _raw_text(reviewer, "login")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[[A-Za-z0-9-]{1,39}\])?", login):
                raise GitHubRuntimeError("gh requested-reviewer login is malformed")
            reviewers.append(login)
        elif reviewer_type == "Team":
            organization = _raw_text(_raw_mapping(reviewer.get("organization")), "login")
            slug = _raw_text(reviewer, "slug")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", organization) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", slug):
                raise GitHubRuntimeError("gh requested-reviewer team is malformed")
            reviewers.append(f"{organization}/{slug}")
        else:
            raise GitHubRuntimeError("gh requested-reviewer variant is malformed")
    if len(set(reviewers)) != len(reviewers):
        raise GitHubRuntimeError("gh requested-reviewer entries are duplicated")
    reviewers.sort()
    return {"repository": repository, "pull_request_number": request.number, "candidate_sha": request.expected_sha, "reviewers": reviewers, "reviewer_set_digest": _sha256(("reviewers", tuple(reviewers))), "complete": not has_next, "next_cursor": cursor if has_next else None, "raw_evidence_identity": _sha256(raw)}


def _project_gh_response(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    """Project one REST response into the exact core schema.

    Provider objects never cross this boundary.  The request supplies the
    authoritative repository/number/ref identities and any contradictory raw
    identity is rejected.  Collection endpoints accept at most ten slurped
    pages; a different shape is incomplete rather than silently partial.
    """

    repository = {"owner": request.repository.owner, "name": request.repository.name}
    operation = request.operation
    if operation is GitHubReadOperation.REQUESTED_REVIEWERS:
        return _project_requested_reviewers_page(request, raw)
    if operation is GitHubReadOperation.CLOSING_REFERENCES:
        root = _raw_mapping(raw)
        data = _raw_mapping(root.get("data"))
        graph_repository = _raw_mapping(data.get("repository"))
        owner = _raw_mapping(graph_repository.get("owner"))
        pull_request = _raw_mapping(graph_repository.get("pullRequest"))
        if _raw_text(owner, "login") != request.repository.owner or _raw_text(graph_repository, "name") != request.repository.name:
            raise GitHubRuntimeError("gh closing-reference repository does not match request")
        if _raw_integer(pull_request, "number") != request.number or _raw_text(pull_request, "headRefOid") != request.expected_sha:
            raise GitHubRuntimeError("gh closing-reference pull request does not match request")
        connection = _raw_mapping(pull_request.get("closingIssuesReferences"))
        page_info = _raw_mapping(connection.get("pageInfo"))
        if _raw_bool(page_info, "hasNextPage"):
            raise GitHubRuntimeError("gh closing-reference pagination is incomplete")
        closing_cursor = page_info.get("endCursor")
        if closing_cursor is not None and (type(closing_cursor) is not str or not _CURSOR.fullmatch(closing_cursor)):
            raise GitHubRuntimeError("gh closing-reference terminal cursor is malformed")
        nodes = connection.get("nodes")
        if type(nodes) is not list:
            raise GitHubRuntimeError("gh closing-reference nodes are malformed")
        return {
            "repository": repository, "pull_request_number": request.number,
            "head_sha": request.expected_sha,
            "references": [
                {"issue_number": _raw_integer(_raw_mapping(node), "number"), "pull_request_number": request.number,
                 "keyword": "closing-reference", "head_sha": request.expected_sha}
                for node in nodes
            ],
        }
    if operation is GitHubReadOperation.REPOSITORY:
        raise GitHubRuntimeError("repository reads require default-head composition")
    if operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
        raise GitHubRuntimeError("issue reads require native relationship composition")
    if operation is GitHubReadOperation.COMMENTS:
        if type(raw) is not dict or "data" not in raw:
            raise GitHubRuntimeError("gh comment response must use the native target connection")
        projected, next_cursor, _ = _project_gh_collection_page(request, raw)
        if next_cursor is not None:
            raise GitHubRuntimeError("gh comment response is not terminal")
        return projected
    if operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}:
        item = _raw_mapping(raw)
        name = _raw_text(item, "name")
        if name != request.ref:
            raise GitHubRuntimeError("gh branch reference does not match request")
        _raw_branch_repository_matches(item, request)
        projected = {"repository": repository, "ref": name, "sha": _raw_text(_raw_mapping(item.get("commit")), "sha")}
        return projected
    if operation is GitHubReadOperation.PULL_REQUEST:
        item = _raw_mapping(raw)
        _raw_number_matches(item, request)
        base, head = _raw_mapping(item.get("base")), _raw_mapping(item.get("head"))
        base_repository = _repository_from_full_name(_raw_text(_raw_mapping(base.get("repo")), "full_name"))
        head_repository = _repository_from_full_name(_raw_text(_raw_mapping(head.get("repo")), "full_name"))
        if base_repository != request.repository:
            raise GitHubRuntimeError("gh pull request base repository does not match request")
        state = _raw_text(item, "state").upper()
        merged = item.get("merged")
        if merged is not None:
            if type(merged) is not bool:
                raise GitHubRuntimeError("gh pull request merged state is malformed")
            if merged:
                state = "MERGED"
        return {"repository": {"owner": base_repository.owner, "name": base_repository.name}, "base_repository": {"owner": base_repository.owner, "name": base_repository.name}, "head_repository": {"owner": head_repository.owner, "name": head_repository.name}, "id": _raw_id(item, "id"), "number": _raw_integer(item, "number"), "state": state, "base_ref": _raw_text(base, "ref"), "base_sha": _raw_text(base, "sha"), "head_ref": _raw_text(head, "ref"), "head_sha": _raw_text(head, "sha"), "draft": _raw_bool(item, "draft"), "merge_commit_sha": _raw_optional_text(item, "merge_commit_sha")}
    if operation is GitHubReadOperation.REVIEWS:
        if type(raw) is dict and "data" in raw:
            projected, next_cursor, _ = _project_gh_collection_page(request, raw)
            if next_cursor is not None:
                raise GitHubRuntimeError("gh review response is not terminal")
            return projected
        items = _raw_collection(raw, "reviews")
        if not items:
            raise GitHubRuntimeError("gh review response cannot establish candidate identity")
        head_sha = _raw_text(items[0], "commit_id")
        if head_sha != request.expected_sha or any(_raw_text(item, "commit_id") != head_sha for item in items):
            raise GitHubRuntimeError("gh review candidate does not match request")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": head_sha, "reviews": [{"id": _raw_id(item, "id"), "reviewer_id": _raw_id(_raw_mapping(item.get("user")), "id"), "state": _raw_text(item, "state").upper(), "commit_sha": _raw_text(item, "commit_id")} for item in items]}
    if operation is GitHubReadOperation.CHECKS:
        raise GitHubRuntimeError("check reads require candidate evidence composition")
    if operation is GitHubReadOperation.WORKFLOW_RUNS:
        raise GitHubRuntimeError("workflow reads require candidate evidence composition")
    if operation is GitHubReadOperation.MERGEABILITY:
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        _raw_number_matches(item, request)
        head = _raw_mapping(item.get("head"))
        state = {"clean": "MERGEABLE", "dirty": "CONFLICTING", "unknown": "UNKNOWN"}.get(_raw_text(item, "mergeable_state"))
        if state is None:
            raise GitHubRuntimeError("gh mergeability is incomplete")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": _raw_text(head, "sha"), "mergeability": state}
    raise GitHubRuntimeError("gh response projection is unavailable")


def _raw_mapping(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise GitHubRuntimeError("gh response object is malformed")
    return value


def _raw_actor_identity(value: object) -> str:
    """Return the canonical, schema-proven identity of a GraphQL actor.

    GitHub's ``Actor`` interface does not give the collection projection a
    stable provider id to rely on.  The concrete actor type and login are the
    only evidence requested from the native query, so keep that distinction in
    the typed snapshot instead of manufacturing an id from the request.
    """

    actor = _raw_mapping(value)
    actor_type = _raw_text(actor, "__typename")
    if actor_type not in {"User", "Bot", "Organization", "Mannequin"}:
        raise GitHubRuntimeError("gh collection actor type is unsupported")
    login = _raw_text(actor, "login")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:\[[A-Za-z0-9-]{1,39}\])?", login):
        raise GitHubRuntimeError("gh collection actor login is malformed")
    return f"{actor_type.lower()}:{login.lower()}"


def _project_gh_collection_page(
    request: GitHubReadRequest, raw: object,
) -> tuple[Mapping[str, object], str | None, int]:
    """Project one provider-native GraphQL connection with explicit terminality."""

    root = _raw_mapping(raw)
    data = _raw_mapping(root.get("data"))
    graph_repository = _raw_mapping(data.get("repository"))
    owner = _raw_mapping(graph_repository.get("owner"))
    if (
        _raw_text(owner, "login") != request.repository.owner
        or _raw_text(graph_repository, "name") != request.repository.name
    ):
        raise GitHubRuntimeError("gh collection repository does not match request")
    target_key = "issueOrPullRequest" if request.operation is GitHubReadOperation.COMMENTS else "pullRequest"
    target = _raw_mapping(graph_repository.get(target_key))
    if _raw_integer(target, "number") != request.number:
        raise GitHubRuntimeError("gh collection target does not match request")
    if request.operation is GitHubReadOperation.REVIEWS:
        if _raw_text(target, "headRefOid") != request.expected_sha:
            raise GitHubRuntimeError("gh review candidate does not match request")
        connection_name, output_name = "reviews", "reviews"
    else:
        connection_name, output_name = "comments", "comments"
    connection = _raw_mapping(target.get(connection_name))
    page_info = _raw_mapping(connection.get("pageInfo"))
    has_next = _raw_bool(page_info, "hasNextPage")
    end_cursor = page_info.get("endCursor")
    if has_next:
        if type(end_cursor) is not str or not _CURSOR.fullmatch(end_cursor):
            raise GitHubRuntimeError("gh collection continuation is malformed")
        next_cursor: str | None = end_cursor
    else:
        if end_cursor is not None and (type(end_cursor) is not str or not _CURSOR.fullmatch(end_cursor)):
            raise GitHubRuntimeError("gh terminal collection cursor is malformed")
        next_cursor = None
    total_count = _raw_integer(connection, "totalCount")
    nodes = connection.get("nodes")
    if type(nodes) is not list:
        raise GitHubRuntimeError("gh collection nodes are malformed")
    repository = {"owner": _raw_text(owner, "login"), "name": _raw_text(graph_repository, "name")}
    if request.operation is GitHubReadOperation.COMMENTS:
        target_kind = _raw_text(target, "__typename")
        if target_kind == "Issue":
            normalized_target_kind = "ISSUE"
        elif target_kind == "PullRequest":
            normalized_target_kind = "PULL_REQUEST"
        else:
            raise GitHubRuntimeError("gh comment target kind is malformed")
        projected = {
            "repository": repository, "issue_number": _raw_integer(target, "number"), "target_kind": normalized_target_kind,
            output_name: [
                {"id": _raw_id(_raw_mapping(node), "id"),
                 "author_id": _raw_actor_identity(_raw_mapping(node).get("author")),
                 "body": _raw_text(_raw_mapping(node), "body"),
                 "created_at": _raw_text(_raw_mapping(node), "createdAt")}
                for node in nodes
            ],
        }
    else:
        projected = {
            "repository": repository, "pull_request_number": request.number,
            "head_sha": _raw_text(target, "headRefOid"),
            output_name: [
                {"id": _raw_id(_raw_mapping(node), "id"),
                 "reviewer_id": _raw_actor_identity(_raw_mapping(node).get("author")),
                 "state": _raw_text(_raw_mapping(node), "state").upper(),
                 "commit_sha": _raw_text(_raw_mapping(_raw_mapping(node).get("commit")), "oid")}
                for node in nodes
            ],
        }
    return projected, next_cursor, total_count


def _raw_collection(value: object, name: str) -> list[Mapping[str, object]]:
    if type(value) is list and all(type(item) is dict for item in value):
        return [_raw_mapping(item) for item in value]
    pages = value if type(value) is list else [value]
    if not 1 <= len(pages) <= 10:
        raise GitHubRuntimeError("gh pagination is incomplete")
    flattened: list[Mapping[str, object]] = []
    for page in pages:
        if type(page) is list:
            flattened.extend(_raw_mapping(item) for item in page)
        elif type(page) is dict and type(page.get(name)) is list:
            flattened.extend(_raw_mapping(item) for item in page[name])
        else:
            raise GitHubRuntimeError("gh collection response is malformed")
    return flattened


def _raw_text(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str:
        raise GitHubRuntimeError("gh response field is malformed")
    return value


def _raw_optional_text(mapping: Mapping[str, object], key: str, *, upper: bool = False) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if type(value) is not str:
        raise GitHubRuntimeError("gh response field is malformed")
    return value.upper() if upper else value


def _raw_id(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) not in (str, int) or isinstance(value, bool):
        raise GitHubRuntimeError("gh response identity is malformed")
    return str(value)


def _raw_integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int:
        raise GitHubRuntimeError("gh response number is malformed")
    return value


def _raw_bool(mapping: Mapping[str, object], key: str) -> bool:
    value = mapping.get(key)
    if type(value) is not bool:
        raise GitHubRuntimeError("gh response Boolean is malformed")
    return value


def _inventory_graphql_envelope(raw: object) -> Mapping[str, object]:
    """Require a complete GraphQL success envelope before inventory parsing."""

    if type(raw) is not dict:
        raise _RepositoryInventoryDiagnosticError(RepositoryInventoryFailureStage.ROOT)
    if (
        "data" not in raw
        or "errors" in raw
        or type(raw["data"]) is not dict
    ):
        raise _RepositoryInventoryDiagnosticError(
            RepositoryInventoryFailureStage.GRAPHQL_ENVELOPE,
        )
    return raw


def _decode_inventory_graphql(stdout: str) -> Mapping[str, object]:
    """Decode one private host response into a required GraphQL envelope."""

    try:
        return _inventory_graphql_envelope(json.loads(stdout))
    except json.JSONDecodeError as error:
        raise _RepositoryInventoryDiagnosticError(
            RepositoryInventoryFailureStage.JSON_DECODING,
        ) from error


def _inventory_connection_nodes(
    connection: Mapping[str, object], page: Mapping[str, object],
) -> list[object]:
    """Accept only GitHub's terminal empty/null connection representation.

    GraphQL may encode an empty terminal connection as ``nodes: null``.  That
    shape carries no missing evidence when its declared count is zero and it
    has no next page.  Every other non-list representation remains a sealed,
    fail-closed structural error; the stage retains neither a field value nor
    provider output.
    """

    if "nodes" not in connection:
        raise _RepositoryInventoryDiagnosticError(
            RepositoryInventoryFailureStage.CONNECTION_NODES,
        )
    nodes = connection["nodes"]
    if type(nodes) is list:
        return nodes
    if (
        nodes is None
        and _raw_integer(connection, "totalCount") == 0
        and not _raw_bool(page, "hasNextPage")
    ):
        return []
    raise _RepositoryInventoryDiagnosticError(
        RepositoryInventoryFailureStage.CONNECTION_NODES,
    )


def _raw_number_matches(mapping: Mapping[str, object], request: GitHubReadRequest) -> None:
    if request.number is None or _raw_integer(mapping, "number") != request.number:
        raise GitHubRuntimeError("gh response number does not match request")


def _raw_repository_matches(mapping: Mapping[str, object], request: GitHubReadRequest) -> None:
    """Require provider-established repository identity; never borrow request data."""

    candidate = mapping
    if "repository" in mapping:
        candidate = _raw_mapping(mapping.get("repository"))
    elif "base" in mapping:
        candidate = _raw_mapping(_raw_mapping(mapping.get("base")).get("repo"))
    owner, name = candidate.get("owner"), candidate.get("name")
    if owner is not None and name is not None:
        owner_map = _raw_mapping(owner)
        if _raw_text(owner_map, "login") == request.repository.owner and _raw_text(candidate, "name") == request.repository.name:
            return
    repository_url = mapping.get("repository_url")
    if repository_url is not None and _provider_repository_from_url(repository_url) == request.repository:
        return
    raise GitHubRuntimeError("gh response repository does not match request")


def _raw_branch_repository_matches(mapping: Mapping[str, object], request: GitHubReadRequest) -> None:
    """A REST branch response establishes its repository through commit URLs."""

    commit = _raw_mapping(mapping.get("commit"))
    path = _provider_url_path(commit.get("url"))
    if re.fullmatch(
        rf"/repos/{re.escape(request.repository.owner)}/{re.escape(request.repository.name)}/commits/[0-9a-f]{{40}}",
        path,
    ) is None:
        raise GitHubRuntimeError("gh branch response repository does not match request")


def _read_command(request: GitHubReadRequest) -> tuple[str, ...]:
    """Build an inert, read-only ``gh api`` request; no user text is injected."""

    base = f"repos/{request.repository.slug}"
    if request.operation is GitHubReadOperation.REPOSITORY:
        path = base
    elif request.operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
        path = f"{base}/issues/{request.number}"
    elif request.operation is GitHubReadOperation.COMMENTS:
        return _collection_read_command(request, None)
    elif request.operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}:
        path = f"{base}/branches/{request.ref}"
    elif request.operation is GitHubReadOperation.PULL_REQUEST:
        path = f"{base}/pulls/{request.number}"
    elif request.operation is GitHubReadOperation.REVIEWS:
        return _collection_read_command(request, None)
    elif request.operation is GitHubReadOperation.REQUESTED_REVIEWERS:
        return _requested_reviewers_collection_command(request, None)
    elif request.operation is GitHubReadOperation.CHECKS:
        path = f"{base}/commits/{request.expected_sha}/check-runs"
    elif request.operation is GitHubReadOperation.WORKFLOW_RUNS:
        path = f"{base}/actions/runs?head_sha={request.expected_sha}"
    elif request.operation is GitHubReadOperation.MERGEABILITY:
        path = f"{base}/pulls/{request.number}"
    elif request.operation is GitHubReadOperation.CLOSING_REFERENCES:
        query = "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){name owner{login} pullRequest(number:$number){number headRefOid closingIssuesReferences(first:100){nodes{number} pageInfo{hasNextPage endCursor}}}}}"
        return ("api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}", "-F", f"name={request.repository.name}", "-F", f"number={request.number}")
    else:
        raise GitHubRuntimeError("unsupported gh read operation")
    return ("api", "--method", "GET", path)


def _repository_inventory_command(request: GitHubReadRequest) -> tuple[str, ...]:
    """Build the single read-only, profile-neutral inventory query."""

    if (
        type(request) is not GitHubReadRequest
        or request.operation is not GitHubReadOperation.REPOSITORY_INVENTORY
        or request.expected_sha is None
    ):
        raise GitHubRuntimeError("repository inventory request is invalid")
    query = (
        "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){"
        "id name owner{login} defaultBranchRef{name target{... on Commit{oid}}} "
        "issues(first:100,states:[OPEN,CLOSED]){totalCount pageInfo{hasNextPage endCursor}nodes{id number state title body comments(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id body}} labels(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{name}} subIssues(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{number}}}} "
        "pullRequests(first:100,states:[OPEN,CLOSED,MERGED]){totalCount pageInfo{hasNextPage endCursor}nodes{id number state headRefOid headRefName mergeStateStatus mergeCommit{oid} comments(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id body}} reviews(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id}} reviewRequests(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id}} closingIssuesReferences(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{number}} commits(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{commit{oid checkSuites(first:10){totalCount pageInfo{hasNextPage endCursor}nodes{id status conclusion workflowRun{id}}}}}}}} "
        "refs(first:100,refPrefix:\"refs/heads/\"){totalCount pageInfo{hasNextPage endCursor}nodes{name target{... on Commit{oid}}}}}}"
    )
    return ("api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}", "-F", f"name={request.repository.name}")


def _repository_inventory_check_suites_command(
    request: GitHubReadRequest, commit_oid: str, cursor: str,
) -> tuple[str, ...]:
    """Build the repository-owned continuation for one retained commit.

    This command is intentionally private: callers can request only a generic
    inventory, while the reviewed host owns the nested connection traversal.
    """

    if (
        type(request) is not GitHubReadRequest
        or request.operation is not GitHubReadOperation.REPOSITORY_INVENTORY
        or request.expected_sha is None
        or type(commit_oid) is not str
        or re.fullmatch(r"[0-9a-f]{40}", commit_oid) is None
        or type(cursor) is not str
        or _CURSOR.fullmatch(cursor) is None
    ):
        raise GitHubRuntimeError("repository inventory check-suite continuation is invalid")
    query = (
        "query($owner:String!,$name:String!,$oid:String!,$cursor:String!){repository(owner:$owner,name:$name){"
        "name owner{login} object(expression:$oid){... on Commit{oid checkSuites(first:100,after:$cursor){"
        "totalCount pageInfo{hasNextPage endCursor} nodes{id status conclusion workflowRun{id}}}}}}}"
    )
    return (
        "api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}",
        "-F", f"name={request.repository.name}", "-F", f"oid={commit_oid}", "-F", f"cursor={cursor}",
    )


def _repository_inventory_connection_command(
    request: GitHubReadRequest, connection: str, cursor: str, number: int | None = None,
) -> tuple[str, ...]:
    """Build one fixed continuation selected only by product inventory code."""

    if (
        type(request) is not GitHubReadRequest
        or request.operation is not GitHubReadOperation.REPOSITORY_INVENTORY
        or type(cursor) is not str
        or _CURSOR.fullmatch(cursor) is None
    ):
        raise GitHubRuntimeError("inventory continuation request is invalid")
    issue_node = (
        "id number state title body comments(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id body}} labels(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{name}} "
        "subIssues(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{number}}"
    )
    pull_request_node = (
        "id number state headRefOid headRefName mergeStateStatus mergeCommit{oid} "
        "comments(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id body}} "
        "reviews(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id}} "
        "reviewRequests(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{id}} "
        "closingIssuesReferences(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{number}} "
        "commits(first:100){totalCount pageInfo{hasNextPage endCursor}nodes{commit{oid "
        "checkSuites(first:10){totalCount pageInfo{hasNextPage endCursor}nodes{id status conclusion workflowRun{id}}}}}"
    )
    connections = {
        "issues": f"issues(first:100,after:$cursor,states:[OPEN,CLOSED]){{totalCount pageInfo{{hasNextPage endCursor}}nodes{{{issue_node}}}}}",
        "pull-requests": f"pullRequests(first:100,after:$cursor,states:[OPEN,CLOSED,MERGED]){{totalCount pageInfo{{hasNextPage endCursor}}nodes{{{pull_request_node}}}}}",
        "refs": "refs(first:100,after:$cursor,refPrefix:\"refs/heads/\"){totalCount pageInfo{hasNextPage endCursor}nodes{name target{... on Commit{oid}}}}",
        "issue-labels": "labels(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{name}}",
        "issue-sub-issues": "subIssues(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{number}}",
        "issue-comments": "comments(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{id body}}",
        "pull-request-comments": "comments(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{id body}}",
        "pull-request-reviews": "reviews(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{id}}",
        "pull-request-review-requests": "reviewRequests(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{id}}",
        "pull-request-closing-references": "closingIssuesReferences(first:100,after:$cursor){totalCount pageInfo{hasNextPage endCursor}nodes{number}}",
    }
    selection = connections.get(connection)
    if selection is None:
        raise GitHubRuntimeError("inventory continuation selection is invalid")
    base = "query($owner:String!,$name:String!,$cursor:String!){repository(owner:$owner,name:$name){name owner{login}"
    command: tuple[str, ...]
    if connection in {"issues", "pull-requests", "refs"}:
        query = base + " " + selection + "}}"
        command = ("api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}", "-F", f"name={request.repository.name}")
    else:
        if type(number) is not int or number <= 0:
            raise GitHubRuntimeError("inventory continuation number is invalid")
        target = "issue" if connection.startswith("issue-") else "pullRequest"
        query = (
            "query($owner:String!,$name:String!,$number:Int!,$cursor:String!){repository(owner:$owner,name:$name){"
            + "name owner{login} " + target + "(number:$number){number " + selection + "}"
            + "}}"
        )
        command = (
            "api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}",
            "-F", f"name={request.repository.name}", "-F", f"number={number}",
        )
    return command + ("-F", f"cursor={cursor}")


def _inventory_connection_identity(connection: str, node: object) -> str:
    try:
        value = _raw_mapping(node)
    except GitHubRuntimeError as error:
        raise _RepositoryInventoryDiagnosticError(RepositoryInventoryFailureStage.NODE) from error
    if connection in {"issue-labels", "refs"}:
        return _raw_text(value, "name")
    if connection in {"issue-sub-issues", "pull-request-closing-references"}:
        return str(_raw_integer(value, "number"))
    if connection == "pull-request-commits":
        return _raw_text(_raw_mapping(value.get("commit")), "oid")
    return _raw_id(value, "id")


def _inventory_continuation_connection(
    request: GitHubReadRequest, raw: object, connection: str, number: int | None,
) -> Mapping[str, object]:
    root = _raw_mapping(raw)
    repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name:
        raise GitHubRuntimeError("inventory continuation repository does not match request")
    top_level = {"issues": "issues", "pull-requests": "pullRequests", "refs": "refs"}
    if connection in top_level:
        return _raw_mapping(repository.get(top_level[connection]))
    target = _raw_mapping(repository.get("issue" if connection.startswith("issue-") else "pullRequest"))
    if number is None or _raw_integer(target, "number") != number:
        raise GitHubRuntimeError("inventory continuation target does not match request")
    fields = {
        "issue-labels": "labels", "issue-sub-issues": "subIssues", "issue-comments": "comments",
        "pull-request-comments": "comments", "pull-request-reviews": "reviews",
        "pull-request-review-requests": "reviewRequests",
        "pull-request-closing-references": "closingIssuesReferences",
    }
    return _raw_mapping(target.get(fields[connection]))


def _complete_repository_inventory_connection(
    request: GitHubReadRequest, runner: _FixedGhReadRunner, connection: str,
    value: object, *, number: int | None = None, maximum: int = 3200,
) -> None:
    """Merge a bounded generic GraphQL connection into its private raw page."""

    if type(value) is not dict or not 0 < maximum <= 3200:
        raise GitHubRuntimeError("inventory connection is malformed")
    try:
        total = _raw_integer(value, "totalCount")
        page = _raw_mapping(value.get("pageInfo"))
        has_next = _raw_bool(page, "hasNextPage")
        nodes = _inventory_connection_nodes(value, page)
    except _RepositoryInventoryDiagnosticError:
        raise
    except GitHubRuntimeError as error:
        raise _RepositoryInventoryDiagnosticError(RepositoryInventoryFailureStage.CONNECTION) from error
    if total < 0 or total > maximum or len(nodes) > 100 or len(nodes) > total:
        raise GitHubRuntimeError("inventory connection cardinality exceeds bound")
    identities = {_inventory_connection_identity(connection, node) for node in nodes}
    if len(identities) != len(nodes):
        raise GitHubRuntimeError("inventory connection has duplicate evidence")
    if not has_next:
        if len(nodes) != total:
            raise GitHubRuntimeError("inventory connection is incomplete")
        value["_roundwright_page_count"] = 1
        return
    if connection == "pull-request-commits":
        raise GitHubRuntimeError("inventory commit pagination is incomplete")
    cursor = page.get("endCursor")
    if type(cursor) is not str or _CURSOR.fullmatch(cursor) is None:
        raise GitHubRuntimeError("inventory connection cursor is malformed")
    seen_cursors = {cursor}
    merged = list(nodes)
    for _ in range(31):
        outcome = runner.run(_repository_inventory_connection_command(request, connection, cursor, number))
        if outcome.exit_code != 0:
            raise _RepositoryInventoryDiagnosticError(
                RepositoryInventoryFailureStage.TRANSPORT,
                RepositoryInventoryTransportSubcategory.NONZERO_RETURN,
            )
        page_value = _inventory_continuation_connection(
            request, _decode_inventory_graphql(outcome.stdout), connection, number,
        )
        page_total = _raw_integer(page_value, "totalCount")
        page_info = _raw_mapping(page_value.get("pageInfo"))
        page_has_next = _raw_bool(page_info, "hasNextPage")
        page_nodes = _inventory_connection_nodes(page_value, page_info)
        if page_total != total or len(page_nodes) > 100 or len(merged) + len(page_nodes) > total:
            raise GitHubRuntimeError("inventory connection cardinality is incomplete")
        page_ids = {_inventory_connection_identity(connection, node) for node in page_nodes}
        if len(page_ids) != len(page_nodes) or identities.intersection(page_ids):
            raise GitHubRuntimeError("inventory connection has duplicate evidence")
        merged.extend(page_nodes)
        identities.update(page_ids)
        next_cursor = page_info.get("endCursor")
        if not page_has_next:
            if len(merged) != total:
                raise GitHubRuntimeError("inventory connection is incomplete")
            value["nodes"] = merged
            value["pageInfo"] = {"hasNextPage": False, "endCursor": next_cursor}
            value["_roundwright_page_count"] = len(seen_cursors) + 1
            return
        if type(next_cursor) is not str or _CURSOR.fullmatch(next_cursor) is None or next_cursor in seen_cursors:
            raise GitHubRuntimeError("inventory connection cursor is malformed")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise GitHubRuntimeError("inventory connection exceeds bound")


def _complete_repository_inventory_connections(
    request: GitHubReadRequest, raw: object, runner: _FixedGhReadRunner,
) -> object:
    """Complete every retained non-check-suite inventory connection privately."""

    root = _raw_mapping(raw)
    repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name:
        raise GitHubRuntimeError("inventory repository does not match request")
    default_ref = _raw_mapping(repository.get("defaultBranchRef"))
    if _raw_text(_raw_mapping(default_ref.get("target")), "oid") != request.expected_sha:
        raise GitHubRuntimeError("inventory default head does not match baseline")
    for connection, key in (("issues", "issues"), ("pull-requests", "pullRequests"), ("refs", "refs")):
        _complete_repository_inventory_connection(request, runner, connection, repository.get(key))
    issues_connection = _raw_mapping(repository.get("issues"))
    pull_requests_connection = _raw_mapping(repository.get("pullRequests"))
    issues = _inventory_connection_nodes(
        issues_connection, _raw_mapping(issues_connection.get("pageInfo")),
    )
    pull_requests = _inventory_connection_nodes(
        pull_requests_connection, _raw_mapping(pull_requests_connection.get("pageInfo")),
    )
    for node in issues:
        issue = _raw_mapping(node)
        number = _raw_integer(issue, "number")
        _complete_repository_inventory_connection(request, runner, "issue-labels", issue.get("labels"), number=number)
        _complete_repository_inventory_connection(request, runner, "issue-sub-issues", issue.get("subIssues"), number=number)
        _complete_repository_inventory_connection(request, runner, "issue-comments", issue.get("comments"), number=number)
    for node in pull_requests:
        pull_request = _raw_mapping(node)
        number = _raw_integer(pull_request, "number")
        for connection, key in (
            ("pull-request-comments", "comments"), ("pull-request-reviews", "reviews"),
            ("pull-request-review-requests", "reviewRequests"),
            ("pull-request-closing-references", "closingIssuesReferences"),
        ):
            _complete_repository_inventory_connection(request, runner, connection, pull_request.get(key), number=number)
        _complete_repository_inventory_connection(
            request, runner, "pull-request-commits", pull_request.get("commits"), number=number, maximum=100,
        )
    return _complete_repository_inventory_check_suites(request, raw, runner)


def _complete_repository_inventory_check_suites(
    request: GitHubReadRequest, raw: object, runner: _FixedGhReadRunner,
) -> object:
    """Complete bounded nested check-suite pages before public normalization.

    The first inventory response establishes the retained pull-request commits.
    Every non-terminal suite connection is then continued through a fixed query,
    with repository, commit, cursor, cardinality, and duplicate checks on every
    response.  A connection above its reviewed 100-item bound remains invalid.
    """

    root = _raw_mapping(raw)
    repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name:
        raise GitHubRuntimeError("inventory repository does not match request")
    default_ref = _raw_mapping(repository.get("defaultBranchRef"))
    if _raw_text(_raw_mapping(default_ref.get("target")), "oid") != request.expected_sha:
        raise GitHubRuntimeError("inventory default head does not match baseline")
    pull_requests = _raw_mapping(repository.get("pullRequests"))
    pull_request_nodes = _inventory_connection_nodes(
        pull_requests, _raw_mapping(pull_requests.get("pageInfo")),
    )
    for pull_request_node in pull_request_nodes:
        pull_request = _raw_mapping(pull_request_node)
        commits = _raw_mapping(pull_request.get("commits"))
        commit_page = _raw_mapping(commits.get("pageInfo"))
        commit_nodes = _inventory_connection_nodes(commits, commit_page)
        if _raw_integer(commits, "totalCount") > 100 or len(commit_nodes) > 100:
            raise GitHubRuntimeError("inventory commit cardinality exceeds bound")
        if (
            _raw_bool(commit_page, "hasNextPage")
            or _raw_integer(commits, "totalCount") != len(commit_nodes)
        ):
            raise GitHubRuntimeError("inventory commit pagination is incomplete")
        for commit_node in commit_nodes:
            commit = _raw_mapping(_raw_mapping(commit_node).get("commit"))
            commit_oid = _raw_text(commit, "oid")
            if re.fullmatch(r"[0-9a-f]{40}", commit_oid) is None:
                raise GitHubRuntimeError("inventory commit identity is malformed")
            suites = _raw_mapping(commit.get("checkSuites"))
            if type(suites) is not dict:
                raise GitHubRuntimeError("inventory check-suite collection is malformed")
            total = _raw_integer(suites, "totalCount")
            page = _raw_mapping(suites.get("pageInfo"))
            has_next = _raw_bool(page, "hasNextPage")
            initial_nodes = _inventory_connection_nodes(suites, page)
            if total > 100 or len(initial_nodes) > 100:
                raise GitHubRuntimeError("inventory check-suite cardinality exceeds bound")
            if total < 0 or len(initial_nodes) > total:
                raise GitHubRuntimeError("inventory check pagination is incomplete")
            suite_nodes = list(initial_nodes)
            seen_ids = {_raw_id(_raw_mapping(node), "id") for node in suite_nodes}
            if len(seen_ids) != len(suite_nodes):
                raise GitHubRuntimeError("inventory check-suite evidence has duplicates")
            cursor = page.get("endCursor")
            if not has_next:
                if len(suite_nodes) != total:
                    raise GitHubRuntimeError("inventory check pagination is incomplete")
                suites["_roundwright_page_count"] = 1
                continue
            if type(cursor) is not str or _CURSOR.fullmatch(cursor) is None:
                raise GitHubRuntimeError("inventory check-suite cursor is malformed")
            seen_cursors = {cursor}
            for _ in range(32):
                outcome = runner.run(_repository_inventory_check_suites_command(request, commit_oid, cursor))
                if outcome.exit_code != 0:
                    raise _RepositoryInventoryDiagnosticError(
                        RepositoryInventoryFailureStage.TRANSPORT,
                        RepositoryInventoryTransportSubcategory.NONZERO_RETURN,
                    )
                page_total, page_nodes, has_next, next_cursor = _project_repository_inventory_check_suites_page(
                    request, _decode_inventory_graphql(outcome.stdout), commit_oid,
                )
                if page_total != total or len(suite_nodes) + len(page_nodes) > total:
                    raise GitHubRuntimeError("inventory check pagination is incomplete")
                page_ids = {_raw_id(_raw_mapping(node), "id") for node in page_nodes}
                if len(page_ids) != len(page_nodes) or seen_ids.intersection(page_ids):
                    raise GitHubRuntimeError("inventory check-suite evidence has duplicates")
                suite_nodes.extend(page_nodes)
                seen_ids.update(page_ids)
                if not has_next:
                    if len(suite_nodes) != total:
                        raise GitHubRuntimeError("inventory check pagination is incomplete")
                    suites["nodes"] = suite_nodes
                    suites["pageInfo"] = {"hasNextPage": False, "endCursor": next_cursor}
                    suites["_roundwright_page_count"] = len(seen_cursors) + 1
                    break
                if type(next_cursor) is not str or _CURSOR.fullmatch(next_cursor) is None or next_cursor in seen_cursors:
                    raise GitHubRuntimeError("inventory check-suite cursor is malformed")
                seen_cursors.add(next_cursor)
                cursor = next_cursor
            else:
                raise GitHubRuntimeError("inventory check-suite pagination exceeds bound")
    return raw


def _project_repository_inventory_check_suites_page(
    request: GitHubReadRequest, raw: object, commit_oid: str,
) -> tuple[int, list[object], bool, object]:
    """Validate one continuation response without exposing its raw payload."""

    root = _raw_mapping(raw)
    repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name:
        raise GitHubRuntimeError("inventory continuation repository does not match request")
    commit = _raw_mapping(repository.get("object"))
    if _raw_text(commit, "oid") != commit_oid:
        raise GitHubRuntimeError("inventory continuation commit does not match request")
    suites = _raw_mapping(commit.get("checkSuites"))
    page = _raw_mapping(suites.get("pageInfo"))
    nodes = _inventory_connection_nodes(suites, page)
    if len(nodes) > 100:
        raise GitHubRuntimeError("inventory check pagination is incomplete")
    return _raw_integer(suites, "totalCount"), nodes, _raw_bool(page, "hasNextPage"), page.get("endCursor")


def _inventory_scheduling_facts(
    subject: str, title: str, body: str,
) -> tuple[RepositoryInventoryFact, ...]:
    """Project bounded public scheduling markers without retaining title/body prose."""

    if len(title) > 512 or len(body) > 65_536 or "\x00" in title or "\x00" in body:
        raise GitHubRuntimeError("inventory issue scheduling text is malformed")
    text = f"{title}\n{body}"
    facts: list[RepositoryInventoryFact] = []
    standalone = len(_STANDALONE_FIXTURE.findall(text))
    malformed_parent = len(_MALFORMED_PARENT_CHILD_FIXTURE.findall(text))
    owner_input = len(_OWNER_INPUT_FIXTURE.findall(text))
    if standalone > 1 or malformed_parent > 1 or owner_input > 1:
        raise GitHubRuntimeError("inventory scheduling fixture is ambiguous")
    if standalone:
        facts.append(RepositoryInventoryFact(subject, "standalone", "true"))
    if malformed_parent:
        facts.append(RepositoryInventoryFact(subject, "malformed-parent-child", "true"))
    if owner_input:
        facts.append(RepositoryInventoryFact(subject, "owner-input-fixture", "true"))
    dependency_lines = tuple(match[0] for match in _BLOCKED_BY_DECLARATION.finditer(body))
    dependencies = tuple(match["number"] for match in _BLOCKED_BY.finditer(body))
    if len(dependencies) != len(dependency_lines) or len(dependencies) != len(set(dependencies)):
        raise GitHubRuntimeError("inventory dependency scheduling is malformed")
    facts.extend(RepositoryInventoryFact(subject, "depends-on", f"issue-{number}") for number in dependencies)
    return tuple(facts)


@dataclass(frozen=True)
class RepositoryFixtureOutcome:
    """One normalized repository scheduling result for the live fixture set."""

    fixture: str
    classification: str
    dependencies: str
    state: str
    gates: str
    blockers: str
    next_action: str

    def __post_init__(self) -> None:
        if not all(
            type(value) is str and _INVENTORY_FACT_TOKEN.fullmatch(value)
            for value in (
                self.fixture, self.classification, self.dependencies, self.state,
                self.gates, self.blockers, self.next_action,
            )
        ):
            raise GitHubRuntimeError("repository fixture outcome is invalid")


def project_repository_fixture_outcomes(
    inventory: RepositoryInventorySnapshot,
    selectors: Mapping[str, tuple[str, int]] | None = None,
) -> tuple[RepositoryFixtureOutcome, ...]:
    """Run the production inventory classifier and scheduler for each fixture.

    This projection intentionally has no Roundlet expectation dependency.  It
    consumes the normalized issue topology, labels, dependency declarations,
    and PR state produced by the credentialed inventory normalizer.
    """

    facts_value = getattr(inventory, "facts", None)
    if type(facts_value) is not tuple or any(type(item) is not RepositoryInventoryFact for item in facts_value):
        raise GitHubRuntimeError("repository fixture inventory is invalid")
    facts = {(item.subject, item.predicate, item.object) for item in facts_value}
    if selectors is not None:
        # The product classifier normally discovers its fixture subjects from
        # a complete inventory.  A sealed external manifest may instead name
        # the exact public subjects to classify.  It supplies only selectors,
        # never outcomes, and a duplicate or conflicting subject fails before
        # any scheduler result is produced.
        if type(selectors) is not dict or set(selectors) != {
            "umbrella", "standalone", "ignored", "malformed-parent-owner-input",
            "dependency", "merged-pr",
        }:
            raise GitHubRuntimeError("repository fixture selectors are invalid")
        subjects: dict[str, str] = {}
        for fixture, value in selectors.items():
            if (
                type(value) is not tuple or len(value) != 2
                or value[0] not in {"issue", "pull-request"}
                or type(value[1]) is not int or value[1] < 1
            ):
                raise GitHubRuntimeError("repository fixture selectors are invalid")
            subjects[fixture] = f"{value[0]}-{value[1]}"
        if len(set(subjects.values())) != len(subjects.values()):
            raise GitHubRuntimeError("repository fixture selectors conflict")

        def state(subject: str) -> str:
            values = {item.object for item in facts_value if item.subject == subject and item.predicate == "state"}
            if len(values) != 1 or next(iter(values)) not in {"open", "closed", "merged"}:
                raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
            return next(iter(values))

        def outcome(fixture: str, classification: str, dependency: str, gates: str, blockers: str) -> RepositoryFixtureOutcome:
            return RepositoryFixtureOutcome(
                fixture, classification, dependency, state(subjects[fixture]), gates, blockers, "retain-readonly",
            )

        def has(subject: str, predicate: str, object_value: str | None = None) -> bool:
            return any(
                item.subject == subject and item.predicate == predicate
                and (object_value is None or item.object == object_value)
                for item in facts_value
            )

        umbrella = subjects["umbrella"]
        standalone = subjects["standalone"]
        ignored = subjects["ignored"]
        malformed = subjects["malformed-parent-owner-input"]
        dependency = subjects["dependency"]
        merged = subjects["merged-pr"]
        if not any(item.subject == umbrella and item.predicate == "child" for item in facts_value):
            raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
        if not has(standalone, "standalone", "true") or any(
            item.predicate == "child" and item.object == standalone for item in facts_value
        ):
            raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
        if not has(ignored, "label", "roundlet:ignore"):
            raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
        if not has(malformed, "malformed-parent", "owner-input"):
            raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
        dependency_edges = [item for item in facts_value if item.subject == dependency and item.predicate == "depends-on"]
        if len(dependency_edges) != 1:
            raise GitHubRuntimeError("repository fixture selected subject is absent or conflicting")
        return (
            outcome("umbrella", "umbrella", "children-present", "not-applicable", "none"),
            outcome("standalone", "standalone", "no-parent", "not-applicable", "none"),
            outcome("ignored", "ignored", "not-applicable", "excluded", "roundlet-ignore"),
            outcome("malformed-parent-owner-input", "malformed-parent", "owner-input", "blocked", "owner-input"),
            outcome("dependency", "dependent", "blocked-by-parent", "blocked", "dependency"),
            outcome("merged-pr", "merged-pr", "not-applicable", "passed", "none"),
        )
    state_by_subject = {
        subject: value for subject, predicate, value in facts
        if predicate == "state" and value in {"open", "closed", "merged"}
    }
    child_edges = tuple((subject, object) for subject, predicate, object in facts if predicate == "child")
    dependencies = tuple((subject, object) for subject, predicate, object in facts if predicate == "depends-on")
    def result(
        fixture: str, classification: str, dependency: str, subject: str | None,
        gates: str, blockers: str,
    ) -> RepositoryFixtureOutcome:
        state = state_by_subject.get(subject or "", "missing")
        if state == "missing":
            return RepositoryFixtureOutcome(fixture, classification, dependency, state, "blocked", "missing", "blocked")
        return RepositoryFixtureOutcome(fixture, classification, dependency, state, gates, blockers, "retain-readonly")
    umbrella_parent = child_edges[0][0] if len(child_edges) == 1 else None
    standalone_subjects = tuple(subject for subject, predicate, value in facts if predicate == "standalone" and value == "true")
    ignored_subjects = tuple(subject for subject, predicate, value in facts if predicate == "label" and value == "roundlet:ignore")
    malformed_subjects = tuple(subject for subject, predicate, value in facts if predicate == "malformed-parent" and value == "owner-input")
    dependency_subject = dependencies[0][0] if len(dependencies) == 1 else None
    merged_subjects = tuple(subject for subject, predicate, value in facts if predicate == "state" and value == "merged")
    values = (
        result("umbrella", "umbrella" if umbrella_parent else "missing", "children-present" if umbrella_parent else "missing", umbrella_parent, "not-applicable", "none"),
        result("standalone", "standalone" if len(standalone_subjects) == 1 else "missing", "no-parent" if len(standalone_subjects) == 1 else "missing", standalone_subjects[0] if len(standalone_subjects) == 1 else None, "not-applicable", "none"),
        result("ignored", "ignored" if len(ignored_subjects) == 1 else "missing", "not-applicable" if len(ignored_subjects) == 1 else "missing", ignored_subjects[0] if len(ignored_subjects) == 1 else None, "excluded", "roundlet-ignore"),
        result("malformed-parent-owner-input", "malformed-parent" if len(malformed_subjects) == 1 else "missing", "owner-input" if len(malformed_subjects) == 1 else "missing", malformed_subjects[0] if len(malformed_subjects) == 1 else None, "blocked", "owner-input"),
        result("dependency", "dependent" if dependency_subject else "missing", "blocked-by-parent" if dependency_subject else "missing", dependency_subject, "blocked", "dependency"),
        result("merged-pr", "merged-pr" if len(merged_subjects) == 1 else "missing", "not-applicable" if len(merged_subjects) == 1 else "missing", merged_subjects[0] if len(merged_subjects) == 1 else None, "passed", "none"),
    )
    return values


def _inventory_label_fact_value(value: object) -> str:
    """Project a label without treating provider display prose as a fact token.

    ``RepositoryInventoryFact`` intentionally accepts only a small token
    alphabet.  GitHub label names, however, are public display strings and can
    legitimately contain spaces or punctuation.  Preserve labels that already
    carry product semantics (such as ``roundlet:ignore``), while committing
    every other valid label to a deterministic public-safe identity.  The
    complete raw label collection remains bound by its evidence digest.
    """

    if type(value) is not str or not value or len(value) > 512 or "\x00" in value or "\x7f" in value:
        raise GitHubRuntimeError("inventory label is malformed")
    if _INVENTORY_FACT_TOKEN.fullmatch(value):
        return value
    return "label-" + _sha256(("repository-inventory-label", value)).removeprefix("sha256:")


_ROUNDLET_FAILOVER_TRACE = re.compile(
    r"ROUNDLET_LIFECYCLE\s+supervisor=(sol|terra)\s+reasoning=(xhigh|high)\s+disposition=(cancelled|invalid-context|pass)\s+round=(formal-round-1)\s+ready_at=([0-9]+)\s+candidate=([0-9a-f]{40})\Z"
)


def _inventory_connection_page_count(connection: Mapping[str, object]) -> int:
    """Read the host-retained terminal page count without trusting raw input."""

    value = connection.get("_roundwright_page_count", 1)
    if type(value) is not int or not 1 <= value <= 32:
        raise GitHubRuntimeError("inventory page count is invalid")
    return value


def _inventory_section_identity(section: RepositoryInventorySection, node: object) -> str:
    value = _raw_mapping(node)
    if section is RepositoryInventorySection.ISSUE_LABELS:
        return _inventory_label_fact_value(value.get("name"))
    if section in {RepositoryInventorySection.ISSUE_RELATIONSHIPS, RepositoryInventorySection.CLOSING_REFERENCES}:
        return str(_raw_integer(value, "number"))
    if section is RepositoryInventorySection.REMOTE_HEADS:
        return _raw_text(value, "name")
    return _raw_id(value, "id")


def _inventory_roundlet_trace_facts(nodes: list[tuple[str, object]]) -> tuple[RepositoryInventoryFact, ...]:
    """Project the complete ordered marker trace without retaining bodies."""

    records: list[tuple[str, str, str, str, str, str, str, str]] = []
    for surface, node in nodes:
        value = _raw_mapping(node)
        body = _raw_optional_text(value, "body")
        if body is None:
            continue
        match = _ROUNDLET_FAILOVER_TRACE.fullmatch(body)
        if match is None and body.startswith("ROUNDLET_LIFECYCLE"):
            # Version-1/model-only markers cannot prove the exact configured
            # Supervisor profile.  Reject them rather than treating them as
            # absent evidence or upgrading them by inference.
            raise GitHubRuntimeError("inventory Roundlet failover trace is legacy or malformed")
        if match is not None:
            records.append((surface, _raw_id(value, "id"), *match.groups()))
    if not records:
        return ()
    if (
        len(records) != 3
        or len({identity for _surface, identity, *_rest in records}) != 3
        or tuple((profile, reasoning, disposition) for _surface, _identity, profile, reasoning, disposition, _round, _ready_at, _candidate in records) != (
        ("sol", "xhigh", "cancelled"), ("terra", "high", "invalid-context"), ("terra", "high", "pass"),
        )
    ):
        raise GitHubRuntimeError("inventory Roundlet failover trace is incomplete")
    rounds = {round_id for _surface, _identity, _profile, _reasoning, _disposition, round_id, _ready_at, _candidate in records}
    ready_values = {ready_at for _surface, _identity, _profile, _reasoning, _disposition, _round_id, ready_at, _candidate in records}
    candidates = {candidate for _surface, _identity, _profile, _reasoning, _disposition, _round_id, _ready_at, candidate in records}
    if rounds != {"formal-round-1"} or len(ready_values) != 1 or len(candidates) != 1:
        raise GitHubRuntimeError("inventory Roundlet failover trace is inconsistent")
    facts: list[RepositoryInventoryFact] = []
    for ordinal, (surface, identity, profile, reasoning, disposition, _round_id, _ready_at, _candidate) in enumerate(records, start=1):
        facts.extend((
            RepositoryInventoryFact(f"lifecycle-supervisor-{ordinal}", "profile", profile),
            RepositoryInventoryFact(f"lifecycle-supervisor-{ordinal}", "reasoning", reasoning),
            RepositoryInventoryFact(f"lifecycle-supervisor-{ordinal}", "disposition", disposition),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "surface", surface),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "marker", "lifecycle"),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "semantic", f"supervisor-{ordinal}"),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "ordinal", str(ordinal)),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "profile", profile),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "reasoning", reasoning),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "disposition", disposition),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "formal-round", _round_id),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "ready-at", _ready_at),
            RepositoryInventoryFact(f"roundlet-trace-{identity}", "candidate", _candidate),
        ))
    facts.append(RepositoryInventoryFact("lifecycle-formal-round-1", "candidate", next(iter(candidates))))
    facts.append(RepositoryInventoryFact("lifecycle-formal-round-1", "ready-at", next(iter(ready_values))))
    return tuple(facts)


def _normalize_repository_inventory(request: GitHubReadRequest, raw: object) -> RepositoryInventorySnapshot:
    """Normalize terminal GraphQL inventory data into the core-only snapshot.

    The projection rejects continuation pages and inconsistent totals instead
    of inferring completeness.  It intentionally retains only IDs, state,
    relationship labels and evidence digests.
    """

    root = _raw_mapping(raw)
    repository = _raw_mapping(_raw_mapping(root.get("data")).get("repository"))
    owner = _raw_mapping(repository.get("owner"))
    if _raw_text(owner, "login") != request.repository.owner or _raw_text(repository, "name") != request.repository.name:
        raise GitHubRuntimeError("inventory repository does not match request")
    default_ref = _raw_mapping(repository.get("defaultBranchRef"))
    target = _raw_mapping(default_ref.get("target"))
    if _raw_text(target, "oid") != request.expected_sha:
        raise GitHubRuntimeError("inventory default head does not match baseline")
    collection_keys = {
        RepositoryInventorySection.ISSUES: "issues",
        RepositoryInventorySection.PULL_REQUESTS: "pullRequests",
        RepositoryInventorySection.REMOTE_HEADS: "refs",
    }
    roots: dict[RepositoryInventorySection, Mapping[str, object]] = {}
    root_nodes: dict[RepositoryInventorySection, list[object]] = {}
    for section, key in collection_keys.items():
        connection = _raw_mapping(repository.get(key))
        page = _raw_mapping(connection.get("pageInfo"))
        nodes = _inventory_connection_nodes(connection, page)
        if _raw_bool(page, "hasNextPage"):
            raise GitHubRuntimeError("inventory pagination is incomplete")
        if _raw_integer(connection, "totalCount") != len(nodes) or len(nodes) > 3200:
            raise GitHubRuntimeError("inventory collection is incomplete")
        roots[section] = connection
        root_nodes[section] = nodes
    issues = roots[RepositoryInventorySection.ISSUES]
    pull_requests = roots[RepositoryInventorySection.PULL_REQUESTS]
    refs = roots[RepositoryInventorySection.REMOTE_HEADS]
    nested: dict[RepositoryInventorySection, list[Mapping[str, object]]] = {
        RepositoryInventorySection.ISSUE_RELATIONSHIPS: [],
        RepositoryInventorySection.ISSUE_LABELS: [],
        RepositoryInventorySection.COMMENTS: [],
        RepositoryInventorySection.REVIEWS: [],
        RepositoryInventorySection.REQUESTED_REVIEWERS: [],
        RepositoryInventorySection.CHECKS: [],
        RepositoryInventorySection.WORKFLOW_RUNS: [],
        RepositoryInventorySection.MERGEABILITY: [],
        RepositoryInventorySection.CLOSING_REFERENCES: [],
    }
    facts: list[RepositoryInventoryFact] = []
    trace_nodes: list[tuple[str, object]] = []
    for issue in root_nodes[RepositoryInventorySection.ISSUES]:
        value = _raw_mapping(issue)
        subject = f"issue-{_raw_integer(value, 'number')}"
        facts.append(RepositoryInventoryFact(subject, "state", _raw_text(value, "state").lower()))
        if "body" not in value:
            raise GitHubRuntimeError("inventory issue scheduling body is malformed")
        body = _raw_optional_text(value, "body")
        facts.extend(_inventory_scheduling_facts(subject, _raw_text(value, "title"), "" if body is None else body))
        comment_connection = _raw_mapping(value.get("comments")); comment_page = _raw_mapping(comment_connection.get("pageInfo")); comment_nodes = _inventory_connection_nodes(comment_connection, comment_page)
        if _raw_bool(comment_page, "hasNextPage") or _raw_integer(comment_connection, "totalCount") != len(comment_nodes):
            raise GitHubRuntimeError("inventory nested pagination is incomplete")
        nested[RepositoryInventorySection.COMMENTS].append(comment_connection)
        trace_nodes.extend(("issue", node) for node in comment_nodes)
        for section, key, predicate in ((RepositoryInventorySection.ISSUE_LABELS, "labels", "label"), (RepositoryInventorySection.ISSUE_RELATIONSHIPS, "subIssues", "child")):
            connection = _raw_mapping(value.get(key)); page = _raw_mapping(connection.get("pageInfo")); nodes = _inventory_connection_nodes(connection, page)
            if _raw_bool(page, "hasNextPage") or _raw_integer(connection, "totalCount") != len(nodes):
                raise GitHubRuntimeError("inventory nested pagination is incomplete")
            nested[section].append(connection)
            if section is RepositoryInventorySection.COMMENTS:
                trace_nodes.extend(("pull-request", node) for node in nodes)
            for node in nodes:
                child = _raw_mapping(node)
                fact_value = (
                    _inventory_label_fact_value(child.get("name"))
                    if predicate == "label"
                    else f"issue-{_raw_integer(child, 'number')}"
                )
                facts.append(RepositoryInventoryFact(subject, predicate, fact_value))
    issue_subjects = {item.subject for item in facts if item.predicate == "state" and item.subject.startswith("issue-")}
    child_edges = [(item.subject, item.object) for item in facts if item.predicate == "child"]
    child_subjects = {child for _, child in child_edges}
    parent_counts = {child: sum(candidate == child for _, candidate in child_edges) for child in child_subjects}
    malformed_children = {item.subject for item in facts if item.predicate == "malformed-parent-child"}
    owner_input_parents = {item.subject for item in facts if item.predicate == "owner-input-fixture"}
    if (
        len(child_edges) != len(set(child_edges))
        or any(parent == child or parent not in issue_subjects or child not in issue_subjects for parent, child in child_edges)
        or any(count != 1 for count in parent_counts.values())
        or any(item.subject not in issue_subjects or item.subject in child_subjects for item in facts if item.predicate == "standalone")
        or any(
            item.subject not in issue_subjects or item.object not in issue_subjects or item.subject == item.object
            for item in facts if item.predicate == "depends-on"
        )
    ):
        raise GitHubRuntimeError("inventory scheduling topology is malformed")
    if malformed_children or owner_input_parents:
        if len(malformed_children) != 1 or len(owner_input_parents) != 1:
            raise GitHubRuntimeError("inventory malformed-parent topology is incomplete")
        malformed_child = next(iter(malformed_children))
        malformed_parents = {parent for parent, child in child_edges if child == malformed_child}
        if len(malformed_parents) != 1 or malformed_parents != owner_input_parents:
            raise GitHubRuntimeError("inventory malformed-parent topology is incomplete")
        facts.append(RepositoryInventoryFact(malformed_child, "malformed-parent", "owner-input"))
    for pull_request in root_nodes[RepositoryInventorySection.PULL_REQUESTS]:
        value = _raw_mapping(pull_request); subject = f"pull-request-{_raw_integer(value, 'number')}"
        facts.append(RepositoryInventoryFact(subject, "state", _raw_text(value, "state").lower()))
        head_sha = _raw_optional_text(value, "headRefOid")
        if head_sha is not None:
            facts.append(RepositoryInventoryFact(subject, "head-sha", head_sha))
        nested[RepositoryInventorySection.MERGEABILITY].append(value)
        for section, key in ((RepositoryInventorySection.COMMENTS, "comments"), (RepositoryInventorySection.REVIEWS, "reviews"), (RepositoryInventorySection.REQUESTED_REVIEWERS, "reviewRequests"), (RepositoryInventorySection.CLOSING_REFERENCES, "closingIssuesReferences")):
            connection = _raw_mapping(value.get(key)); page = _raw_mapping(connection.get("pageInfo")); nodes = _inventory_connection_nodes(connection, page)
            if _raw_bool(page, "hasNextPage") or _raw_integer(connection, "totalCount") != len(nodes):
                raise GitHubRuntimeError("inventory nested pagination is incomplete")
            nested[section].append(connection)
            # Trace markers may be split across issue and pull-request
            # comments.  Keep terminal PR comments in the same bounded trace
            # ledger, with their actual surface, before normalizing markers.
            if section is RepositoryInventorySection.COMMENTS:
                trace_nodes.extend(("pull-request", node) for node in nodes)
        commits = _raw_mapping(value.get("commits")); commits_page = _raw_mapping(commits.get("pageInfo")); commit_nodes = _inventory_connection_nodes(commits, commits_page)
        if (
            _raw_bool(commits_page, "hasNextPage")
            or _raw_integer(commits, "totalCount") != len(commit_nodes)
            or len(commit_nodes) > 100
        ):
            raise GitHubRuntimeError("inventory commit pagination is incomplete")
        for commit_node in commit_nodes:
            commit = _raw_mapping(_raw_mapping(commit_node).get("commit"))
            suites = _raw_mapping(commit.get("checkSuites")); suites_page = _raw_mapping(suites.get("pageInfo")); suite_nodes = _inventory_connection_nodes(suites, suites_page)
            if _raw_bool(suites_page, "hasNextPage") or _raw_integer(suites, "totalCount") != len(suite_nodes):
                raise GitHubRuntimeError("inventory check pagination is incomplete")
            nested[RepositoryInventorySection.CHECKS].append(suites)
            for suite in suite_nodes:
                suite_value = _raw_mapping(suite)
                workflow = suite_value.get("workflowRun")
                if workflow is not None:
                    nested[RepositoryInventorySection.WORKFLOW_RUNS].append(_raw_mapping(workflow))
    facts.extend(_inventory_roundlet_trace_facts(trace_nodes))
    collections: list[RepositoryInventoryEvidence] = []
    for section in RepositoryInventorySection:
        if section is RepositoryInventorySection.REPOSITORY:
            source: object = repository
            identities = [_raw_id(repository, "id")]
            page_count = 1
        elif section in roots:
            connection = roots[section]
            source = connection
            identities = [_inventory_section_identity(section, node) for node in root_nodes[section]]
            page_count = _inventory_connection_page_count(connection)
        else:
            connections = nested.get(section, [])
            source = connections
            identities = []
            page_count = 0
            if section in {RepositoryInventorySection.MERGEABILITY, RepositoryInventorySection.WORKFLOW_RUNS}:
                identities = [_raw_id(connection, "id") for connection in connections]
                if section is RepositoryInventorySection.MERGEABILITY:
                    page_count = _inventory_connection_page_count(roots[RepositoryInventorySection.PULL_REQUESTS])
                else:
                    page_count = sum(_inventory_connection_page_count(item) for item in nested[RepositoryInventorySection.CHECKS]) or 1
            else:
                for connection in connections:
                    page = _raw_mapping(connection.get("pageInfo"))
                    nodes = _inventory_connection_nodes(connection, page)
                    identities.extend(_inventory_section_identity(section, node) for node in nodes)
                    page_count += _inventory_connection_page_count(connection)
            if not connections:
                page_count = 1
        identities.sort()
        if len(identities) != len(set(identities)):
            raise GitHubRuntimeError("inventory collection has duplicate evidence")
        collections.append(RepositoryInventoryEvidence(section, _sha256(source), tuple(identities), page_count, True))
    return RepositoryInventorySnapshot(
        request.repository, _raw_id(repository, "id"), _raw_text(default_ref, "name"), request.expected_sha,
        _sha256({"id": repository.get("id"), "owner": owner.get("login"), "name": repository.get("name")} ),
        _sha256({"name": default_ref.get("name"), "oid": target.get("oid")} ),
        tuple(sorted(collections, key=lambda item: item.section.value)),
        tuple(sorted(set(facts), key=lambda item: (item.subject, item.predicate, item.object))),
    )


def _repository_default_branch_command(repository: RepositoryRef, default_branch: str) -> tuple[str, ...]:
    """Read the ref selected by already-validated repository metadata."""

    if type(repository) is not RepositoryRef or type(default_branch) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", default_branch):
        raise GitHubRuntimeError("repository default branch command is invalid")
    return ("api", "--method", "GET", f"repos/{repository.slug}/branches/{default_branch}")


def _candidate_pull_request_command(request: GitHubReadRequest) -> tuple[str, ...]:
    if type(request) is not GitHubReadRequest or request.operation not in {GitHubReadOperation.CHECKS, GitHubReadOperation.WORKFLOW_RUNS} or request.number is None:
        raise GitHubRuntimeError("candidate pull-request request is invalid")
    return ("api", "--method", "GET", f"repos/{request.repository.slug}/pulls/{request.number}")


def _checks_page_command(request: GitHubReadRequest, page: int) -> tuple[str, ...]:
    if type(request) is not GitHubReadRequest or request.operation is not GitHubReadOperation.CHECKS or request.expected_sha is None or type(page) is not int or not 1 <= page <= 32:
        raise GitHubRuntimeError("check-runs page request is invalid")
    return ("api", "--method", "GET", f"repos/{request.repository.slug}/commits/{request.expected_sha}/check-runs?per_page=100&page={page}")


def _workflow_runs_page_command(request: GitHubReadRequest, page: int) -> tuple[str, ...]:
    if type(request) is not GitHubReadRequest or request.operation is not GitHubReadOperation.WORKFLOW_RUNS or request.expected_sha is None or type(page) is not int or not 1 <= page <= 32:
        raise GitHubRuntimeError("workflow-runs page request is invalid")
    return ("api", "--method", "GET", f"repos/{request.repository.slug}/actions/runs?head_sha={request.expected_sha}&per_page=100&page={page}")


def _issue_relationship_command(request: GitHubReadRequest, cursor: str | None) -> tuple[str, ...]:
    """Read one native ``subIssues`` page selected by validated issue metadata."""

    if type(request) is not GitHubReadRequest or request.operation not in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS} or request.number is None:
        raise GitHubRuntimeError("issue relationship request is invalid")
    if cursor is not None and (type(cursor) is not str or not _CURSOR.fullmatch(cursor)):
        raise GitHubRuntimeError("issue relationship cursor is invalid")
    query = "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name){name owner{login} issue(number:$number){number subIssues(first:100,after:$cursor){totalCount nodes{number} pageInfo{hasNextPage endCursor}}}}}"
    command: tuple[str, ...] = (
        "api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}",
        "-F", f"name={request.repository.name}", "-F", f"number={request.number}",
    )
    return command if cursor is None else command + ("-F", f"cursor={cursor}")


def _requested_reviewers_collection_command(request: GitHubReadRequest, cursor: str | None) -> tuple[str, ...]:
    if type(request) is not GitHubReadRequest or request.operation is not GitHubReadOperation.REQUESTED_REVIEWERS or request.number is None or request.expected_sha is None:
        raise GitHubRuntimeError("requested reviewer collection request is invalid")
    if cursor is not None and (type(cursor) is not str or not _CURSOR.fullmatch(cursor)):
        raise GitHubRuntimeError("requested reviewer collection cursor is invalid")
    query = "query($owner:String!,$name:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$name){name owner{login} pullRequest(number:$number){number headRefOid reviewRequests(first:100,after:$cursor){totalCount nodes{requestedReviewer{__typename ... on User{login} ... on Bot{login} ... on Organization{login} ... on Mannequin{login} ... on Team{slug organization{login}}}} pageInfo{hasNextPage endCursor}}}}}"
    command: tuple[str, ...] = (
        "api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}",
        "-F", f"name={request.repository.name}", "-F", f"number={request.number}",
    )
    return command if cursor is None else command + ("-F", f"cursor={cursor}")


def _collection_read_command(request: GitHubReadRequest, cursor: str | None) -> tuple[str, ...]:
    """Build the sole native-provider collection query shape.

    GraphQL connections expose terminality in the response itself.  This is
    intentionally separate from ordinary GET commands so a caller cannot tack
    a cursor onto an unrelated endpoint and manufacture collection evidence.
    """

    if request.operation is GitHubReadOperation.COMMENTS:
        target = "issueOrPullRequest(number:$number){__typename ... on Issue{number comments(first:100,after:$cursor){totalCount nodes{id author{__typename ... on User{login} ... on Bot{login} ... on Organization{login} ... on Mannequin{login}} body createdAt} pageInfo{hasNextPage endCursor}}} ... on PullRequest{number comments(first:100,after:$cursor){totalCount nodes{id author{__typename ... on User{login} ... on Bot{login} ... on Organization{login} ... on Mannequin{login}} body createdAt} pageInfo{hasNextPage endCursor}}}}"
    elif request.operation is GitHubReadOperation.REVIEWS:
        target = "pullRequest(number:$number){number headRefOid reviews(first:100,after:$cursor){totalCount nodes{id author{__typename ... on User{login} ... on Bot{login} ... on Organization{login} ... on Mannequin{login}} state commit{oid}} pageInfo{hasNextPage endCursor}}}"
    else:
        raise GitHubRuntimeError("unsupported gh collection read operation")
    query = f"query($owner:String!,$name:String!,$number:Int!,$cursor:String){{repository(owner:$owner,name:$name){{name owner{{login}} {target}}}}}"
    arguments: tuple[str, ...] = (
        "api", "graphql", "-f", f"query={query}", "-F", f"owner={request.repository.owner}",
        "-F", f"name={request.repository.name}", "-F", f"number={request.number}",
    )
    return arguments if cursor is None else arguments + ("-F", f"cursor={cursor}")


def _mutation_command(
    intent: GitHubMutationIntent, payload: GhMutationPayload, command: BrokerMutationCommand
) -> tuple[str, ...]:
    """Map each declared mutation to one fixed ``gh`` command shape.

    The only variable outbound text comes from the validated, digest-bound
    payload supplied by the Orchestrator.  No command is passed through a
    shell and no result text is returned from this function.
    """

    if (
        type(intent) is not GitHubMutationIntent
        or type(payload) is not GhMutationPayload
        or type(command) is not BrokerMutationCommand
        or command is not _MUTATION_COMMAND_BY_OPERATION[intent.operation]
    ):
        raise GitHubRuntimeError("broker mutation command is invalid")
    repository = intent.repository.slug
    values = dict(intent.payload)
    operation = intent.operation
    if operation is GitHubMutationOperation.CREATE_BRANCH:
        return ("api", "--method", "POST", f"repos/{repository}/git/refs", "-f", f"ref=refs/heads/{intent.target_ref}", "-f", f"sha={intent.expected_sha}")
    if operation is GitHubMutationOperation.UPDATE_BRANCH:
        return ("api", "--method", "PATCH", f"repos/{repository}/git/refs/heads/{intent.target_ref}", "-f", f"sha={intent.expected_sha}", "-F", "force=false")
    if operation is GitHubMutationOperation.DELETE_BRANCH:
        return ("api", "--method", "DELETE", f"repos/{repository}/git/refs/heads/{intent.target_ref}")
    if operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        return ("pr", "create", "--repo", repository, "--base", values["base_ref"], "--head", values["head_ref"], "--title", payload.value("title"), "--body", payload.value("body"), "--draft")
    if operation is GitHubMutationOperation.COMMENT:
        return ("api", "--method", "POST", f"repos/{repository}/issues/{intent.target_number}/comments", "-f", f"body={payload.value('body')}")
    if operation is GitHubMutationOperation.REQUEST_REVIEW:
        return ("pr", "edit", str(intent.target_number), "--repo", repository, "--add-reviewer", payload.value("reviewers"))
    if operation is GitHubMutationOperation.MARK_READY:
        return ("pr", "ready", str(intent.target_number), "--repo", repository)
    if operation is GitHubMutationOperation.MERGE_PULL_REQUEST:
        return ("pr", "merge", str(intent.target_number), "--repo", repository, f"--{values['method']}")
    if operation is GitHubMutationOperation.CLOSE_ISSUE:
        return ("issue", "close", str(intent.target_number), "--repo", repository, "--reason", values["reason"].lower())
    raise GitHubRuntimeError("unsupported gh mutation operation")


def _broker_receipt(intent: GitHubMutationIntent) -> MutationReceipt:
    """Make a non-semantic transport receipt; read-back establishes success."""

    return MutationReceipt(intent.identity(), intent.operation, MutationDisposition.ACCEPTED, f"gh-{intent.operation.value}", _sha256(("transport", intent.identity())))


def _health_failure(
    operation: GitHubOperation, health: GitHubCapabilityHealth, *, now: datetime | None = None,
) -> GitHubFailure | None:
    item = health.for_operation(operation)
    if item.available:
        if now is None or item.fresh_at(now):
            return None
        return GitHubFailure(GitHubFailureKind.STALE_RESPONSE, operation, "gh capability evidence is stale")
    kind = {
        CapabilityState.UNAVAILABLE: GitHubFailureKind.UNAVAILABLE,
        CapabilityState.PERMISSION_DENIED: GitHubFailureKind.PERMISSION_DENIED,
        CapabilityState.AUTHENTICATION_FAILED: GitHubFailureKind.AUTHENTICATION_FAILED,
        CapabilityState.TRANSPORT_FAILED: GitHubFailureKind.TRANSPORT_FAILED,
    }[item.state]
    return GitHubFailure(kind, operation, "gh capability is unavailable for this operation")


def _failure_kind(exit_code: int) -> GitHubFailureKind:
    return GitHubFailureKind.AUTHENTICATION_FAILED if exit_code == 4 else GitHubFailureKind.TRANSPORT_FAILED


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _digest(value: object, name: str) -> None:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:") or any(char not in "0123456789abcdef" for char in value[7:]):
        raise GitHubRuntimeError(f"{name} digest is invalid")


def _fingerprint(value: object, name: str) -> None:
    if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise GitHubRuntimeError(f"{name} fingerprint is invalid")
