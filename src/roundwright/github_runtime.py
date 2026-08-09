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
import subprocess
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from .deployment import (
    AuthorityReceiptVerification, DeploymentAuthorityDecision,
    DeploymentAuthorityReceipt, DeploymentIdentity, DeploymentMode,
    evaluate_deployment_authority,
)
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


class GitHubRuntimeError(ValueError):
    """Raised when runtime-only adapter evidence is malformed."""


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
        return type(now) is datetime and now.tzinfo is timezone.utc and now <= self.fresh_until


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


@dataclass(frozen=True)
class GhCommandResult:
    """Ephemeral result from a preconfigured ``gh`` process invocation.

    ``stdout`` is parsed immediately by the adapter and never appears in a
    snapshot, receipt, exception, diagnostic, or durable trace.
    """

    exit_code: int
    stdout: str

    def __post_init__(self) -> None:
        if type(self.exit_code) is not int or type(self.stdout) is not str:
            raise GitHubRuntimeError("gh command result is invalid")


class GhRunner(Protocol):
    """Credential-owning process boundary supplied only by the Orchestrator."""

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult: ...


class _SubprocessGhReadRunner:
    """Owner-host implementation for read-only adapter traffic only.

    This deliberately is not a mutation capability.  Mutation transport is a
    separately injected fixed-protocol endpoint below.
    """

    def __init__(self, executable: str = "gh") -> None:
        if type(executable) is not str or executable != "gh":
            raise GitHubRuntimeError("gh executable must be the configured default")
        self._executable = executable

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult:
        if type(arguments) is not tuple or any(type(value) is not str or not value or "\x00" in value for value in arguments):
            raise GitHubRuntimeError("gh command arguments are invalid")
        # No shell, only explicit credential/configuration variables, and no
        # stderr retention.  Provider output never reaches diagnostics.
        try:
            child_environment = {
                key: os.environ[key] for key in (
                    "APPDATA", "COMSPEC", "GH_CONFIG_DIR", "GH_ENTERPRISE_TOKEN", "GH_TOKEN",
                    "HOME", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PATHEXT",
                    "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE", "WINDIR",
                ) if key in os.environ
            }
            completed = subprocess.run(
                (self._executable, *arguments), check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="strict", timeout=30, env=child_environment,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return GhCommandResult(127, "")
        return GhCommandResult(completed.returncode, completed.stdout)


@dataclass(frozen=True)
class OwnerMutationRequest:
    """Sealed, non-command request accepted by an owner-controlled host."""

    intent_identity: str
    operation: GitHubMutationOperation
    authorization_bundle_identity: str
    semantic_plan_identity: str
    journal_identity: str

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation:
            raise GitHubRuntimeError("owner mutation operation is invalid")
        for value, name in ((self.intent_identity, "owner intent"), (self.authorization_bundle_identity, "owner bundle"), (self.semantic_plan_identity, "owner plan"), (self.journal_identity, "owner journal")):
            _digest(value, name)


@dataclass(frozen=True)
class OwnerMutationFact:
    """Curated host result; provider output and process status never cross it."""

    accepted: bool
    request_identity: str

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise GitHubRuntimeError("owner mutation fact is invalid")
        _digest(self.request_identity, "owner request")


class OwnerMutationTransport(Protocol):
    """Deployment-injected fixed protocol; absent transport fails closed."""

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact: ...


class GhGitHubAdapter:
    """``gh api`` adapter with explicit health gating and no mutation fallback.

    The adapter intentionally accepts the normalized JSON response schema from
    ``gh api``.  The small command builder keeps provider-specific URLs and
    raw output inside this module; callers only observe the contract types.
    A production Orchestrator must populate health through its own credential
    isolation path.  The default health helper below marks every operation
    unavailable, which is the safe construction for workers and tests.
    """

    def __init__(self, runner: GhRunner, health: GitHubCapabilityHealth | None = None) -> None:
        if not hasattr(runner, "run"):
            raise GitHubRuntimeError("gh runner is invalid")
        self.__runner = runner
        self._health = health or unavailable_capability_health()
        self.calls: list[tuple[str, str]] = []

    @property
    def health(self) -> GitHubCapabilityHealth:
        return self._health

    def read(self, request: GitHubReadRequest) -> GitHubReadResult:
        if type(request) is not GitHubReadRequest:
            raise GitHubContractError("read request is invalid")
        self.calls.append(("read", request.operation.value))
        blocked = _health_failure(request.operation, self._health)
        if blocked is not None:
            return GitHubReadResult(request, failure=blocked)
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

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> "CollectionPage | None":
        """Read one native GraphQL connection page, or fail closed.

        GitHub's REST list responses deliberately do not carry a JSON terminal
        marker.  The broker must not infer completeness from that absence, so
        collection reads use the provider's typed GraphQL connection instead.
        ``pageInfo`` and ``totalCount`` are projected only after the repository,
        target, and candidate identities have been checked.
        """

        if type(request) is not GitHubReadRequest or request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS}:
            return None
        if cursor is not None and (type(cursor) is not str or not _CURSOR.fullmatch(cursor)):
            return None
        self.calls.append(("collection-read", request.operation.value))
        if _health_failure(request.operation, self._health) is not None:
            return None
        command = _collection_read_command(request, cursor)
        outcome = self.__runner.run(command)
        if outcome.exit_code != 0:
            return None
        try:
            raw = json.loads(outcome.stdout)
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
    snapshot: CommentsSnapshot | ReviewsSnapshot
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.request) is not GitHubReadRequest or self.request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS}:
            raise GitHubRuntimeError("collection page request is invalid")
        for value, name in ((self.cursor, "collection cursor"), (self.next_cursor, "collection continuation")):
            if value is not None and (type(value) is not str or not _CURSOR.fullmatch(value)):
                raise GitHubRuntimeError(f"{name} is invalid")
        if type(self.total_count) is not int or self.total_count < 0 or type(self.snapshot) not in {CommentsSnapshot, ReviewsSnapshot}:
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
        if type(self.pre_state) is not GitHubReadRequest or type(self.readback) is not SemanticReadback:
            raise GitHubRuntimeError("broker semantic plan read-back is invalid")
        if self.pre_state.repository != self.readback.request.repository:
            raise GitHubRuntimeError("broker semantic plan repositories do not match")
        object.__setattr__(self, "identity", _sha256((
            self.operation.value, self.command.value, self.target_identity,
            self.idempotency_identity, self.intent_identity,
            self.pre_state.identity(), self.readback.identity,
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

    def __post_init__(self) -> None:
        if (type(self.policy) is not RepositoryMutationDecision or type(self.deployment) is not DeploymentAuthorityDecision
                or type(self.standing_authority) is not StandingRepositoryAuthority or type(self.receipt_verification) is not RepositoryReceiptVerification
                or type(self.mutation_context) is not RepositoryMutationContext or type(self.dispatcher_transition) is not RepositoryDispatcherTransition
                or type(self.policy_snapshot) is not TrustedRepositoryPolicySnapshot or type(self.activation_receipt) is not RepositoryActivationReceipt
                or type(self.deployment_identity) is not DeploymentIdentity or type(self.deployment_receipt) is not DeploymentAuthorityReceipt
                or type(self.deployment_verification) is not AuthorityReceiptVerification
                or type(self.evaluated_at) is not datetime or self.evaluated_at.tzinfo is not timezone.utc):
            raise GitHubRuntimeError("broker authority evidence is invalid")
        for value, name in ((self.configuration_digest, "configuration"), (self.gate_identity, "gate")):
            _digest(value, name)
        for value, name in ((self.base_sha, "base sha"), (self.candidate_sha, "candidate sha")):
            if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                raise GitHubRuntimeError(f"broker {name} is invalid")


def schema_v2_authorization_bundle(context: MutationBrokerContext, *, now: datetime | None = None) -> "SchemaV2AuthorizationBundle":
    """Construct the single public-safe bundle from canonical typed evidence."""

    if type(context) is not MutationBrokerContext:
        raise GitHubRuntimeError("broker context is invalid")
    trusted_now = context.evaluated_at if now is None else now
    if type(trusted_now) is not datetime or trusted_now.tzinfo is not timezone.utc:
        raise GitHubRuntimeError("broker evaluation time is invalid")
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
        _sha256((trusted_now.isoformat(),)),
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
    evaluation_time_identity: str
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
        _digest(self.evaluation_time_identity, "evaluation time")
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
    semantic_readback_identity: str
    evaluated_at: str
    fresh_until: str
    time_identity: str
    lifecycle: JournalLifecycle
    receipt: SemanticMutationReceipt | None = None
    pre_state_digest: str | None = None
    pre_state_complete: bool = False
    pre_state_identity: str | None = None

    def __post_init__(self) -> None:
        if type(self.repository) is not str or "/" not in self.repository or type(self.operation) is not GitHubMutationOperation or type(self.idempotency_key) is not str:
            raise GitHubRuntimeError("mutation journal identity is invalid")
        for value, name in (
            (self.target_identity, "journal target"), (self.idempotency_identity, "journal idempotency"),
            (self.intent_identity, "journal intent"), (self.authorization_bundle_identity, "journal authorization bundle"),
            (self.configuration_digest, "journal configuration"), (self.gate_identity, "journal gate"),
            (self.semantic_plan_identity, "journal semantic plan"), (self.semantic_readback_identity, "journal semantic read-back"),
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
            if self.pre_state_identity != _sha256((self.intent_identity, self.pre_state_digest)):
                raise GitHubRuntimeError("journal pre-state identity drifted")
        elif self.pre_state_digest is not None or self.pre_state_identity is not None:
            raise GitHubRuntimeError("incomplete journal pre-state evidence")
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
            plan.identity, plan.command, plan.readback.identity, context.evaluated_at.isoformat(),
            (context.evaluated_at + timedelta(minutes=5)).isoformat(),
            _sha256((context.evaluated_at.isoformat(), (context.evaluated_at + timedelta(minutes=5)).isoformat())), JournalLifecycle.PENDING,
        )

    @property
    def key(self) -> str:
        return _sha256((self.repository, self.operation.value, self.idempotency_key))

    def evidence_matches(self, other: "MutationJournalEntry") -> bool:
        return type(other) is MutationJournalEntry and all(
            getattr(self, name) == getattr(other, name)
            for name in self.__dataclass_fields__ if name not in {"lifecycle", "receipt", "pre_state_digest", "pre_state_complete", "pre_state_identity"}
        )

    def serialize(self) -> Mapping[str, object]:
        return {
            "repository": self.repository, "operation": self.operation.value,
            "idempotency_key": self.idempotency_key, "target_identity": self.target_identity,
            "idempotency_identity": self.idempotency_identity, "intent_identity": self.intent_identity,
            "authorization_bundle_identity": self.authorization_bundle_identity,
            "candidate_sha": self.candidate_sha, "configuration_digest": self.configuration_digest,
            "gate_identity": self.gate_identity, "semantic_plan_identity": self.semantic_plan_identity,
            "command": self.command.value, "semantic_readback_identity": self.semantic_readback_identity,
            "evaluated_at": self.evaluated_at, "fresh_until": self.fresh_until, "time_identity": self.time_identity,
            "lifecycle": self.lifecycle.value,
            "pre_state_digest": self.pre_state_digest, "pre_state_complete": self.pre_state_complete,
            "pre_state_identity": self.pre_state_identity,
            "receipt": None if self.receipt is None else self.receipt._payload(),
        }

    @classmethod
    def deserialize(cls, value: object) -> "MutationJournalEntry":
        required = {
            "repository", "operation", "idempotency_key", "target_identity", "idempotency_identity",
            "intent_identity", "authorization_bundle_identity", "candidate_sha", "configuration_digest",
            "gate_identity", "semantic_plan_identity", "command", "semantic_readback_identity",
            "evaluated_at", "fresh_until", "time_identity",
            "lifecycle", "receipt", "pre_state_digest", "pre_state_complete", "pre_state_identity",
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
        try:
            return cls(
                value["repository"], GitHubMutationOperation(value["operation"]), value["idempotency_key"],
                value["target_identity"], value["idempotency_identity"], value["intent_identity"],
                value["authorization_bundle_identity"], value["candidate_sha"], value["configuration_digest"],
                value["gate_identity"], value["semantic_plan_identity"], BrokerMutationCommand(value["command"]),
                value["semantic_readback_identity"], value["evaluated_at"], value["fresh_until"], value["time_identity"], JournalLifecycle(value["lifecycle"]), receipt, value["pre_state_digest"], value["pre_state_complete"], value["pre_state_identity"],
            )
        except (TypeError, ValueError) as error:
            raise GitHubRuntimeError("mutation journal entry is malformed") from error


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
    ) -> MutationJournalEntry:
        if type(evidence) is not MutationJournalEntry or type(lifecycle) is not JournalLifecycle:
            raise GitHubRuntimeError("mutation journal transition is invalid")
        records = self._load()
        prior = records.get(evidence.key)
        if prior is None or not prior.evidence_matches(evidence):
            raise GitHubRuntimeError("mutation journal evidence is missing or conflicting")
        allowed = {
            JournalLifecycle.CLAIMED: {JournalLifecycle.PRESTATE_CAPTURED, JournalLifecycle.APPLIED_AWAITING_VERIFICATION, JournalLifecycle.VERIFIED, JournalLifecycle.DENIED, JournalLifecycle.FAILED, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.PRESTATE_CAPTURED: {JournalLifecycle.EXECUTION_STARTED, JournalLifecycle.DENIED, JournalLifecycle.FAILED},
            JournalLifecycle.EXECUTION_STARTED: {JournalLifecycle.TRANSPORT_ACCEPTED, JournalLifecycle.APPLIED_AWAITING_VERIFICATION, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.TRANSPORT_ACCEPTED: {JournalLifecycle.APPLIED_AWAITING_VERIFICATION, JournalLifecycle.VERIFIED, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.APPLIED_AWAITING_VERIFICATION: {JournalLifecycle.VERIFIED, JournalLifecycle.AMBIGUOUS},
            JournalLifecycle.AMBIGUOUS: {JournalLifecycle.VERIFIED},
            JournalLifecycle.VERIFIED: set(), JournalLifecycle.DENIED: set(), JournalLifecycle.FAILED: set(),
        }
        if lifecycle not in allowed[prior.lifecycle]:
            raise GitHubRuntimeError("mutation journal transition is impossible")
        updated = replace(prior, lifecycle=lifecycle, receipt=receipt) if pre_state_digest is None else replace(
            prior, lifecycle=lifecycle, receipt=receipt, pre_state_digest=pre_state_digest,
            pre_state_complete=True, pre_state_identity=_sha256((prior.intent_identity, pre_state_digest)),
        )
        records[evidence.key] = updated
        self._store(records)
        return updated

    def find(self, evidence: MutationJournalEntry) -> MutationJournalEntry | None:
        if type(evidence) is not MutationJournalEntry:
            raise GitHubRuntimeError("mutation journal evidence is invalid")
        prior = self._load().get(evidence.key)
        if prior is not None and not prior.evidence_matches(evidence):
            raise GitHubRuntimeError("mutation journal idempotency identity conflicts")
        return prior

    def _load(self) -> dict[str, MutationJournalEntry]:
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
            temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
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
        pre_state = GitHubReadRequest(GitHubReadOperation.REPOSITORY, intent.repository)
        readback = SemanticReadback(GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, intent.repository, number=intent.target_number, expected_sha=payload["head_sha"]), SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE)
    elif operation is GitHubMutationOperation.COMMENT:
        pre_state = GitHubReadRequest(GitHubReadOperation.COMMENTS, intent.repository, number=intent.target_number)
        readback = SemanticReadback(pre_state, SemanticPostcondition.COMMENT_PRESENT)
    elif operation is GitHubMutationOperation.REQUEST_REVIEW:
        pre_state = GitHubReadRequest(GitHubReadOperation.REVIEWS, intent.repository, number=intent.target_number, expected_sha=intent.expected_sha)
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
    return BrokerSemanticPlan(
        operation, command,
        _sha256((intent.repository.slug, intent.target_number, intent.target_ref, intent.expected_sha)),
        _sha256(("idempotency", intent.idempotency_key)), intent.identity(), pre_state, readback,
    )


def _collection_snapshot_payload(snapshot: CommentsSnapshot | ReviewsSnapshot) -> tuple[object, ...]:
    if type(snapshot) is CommentsSnapshot:
        return ("comments", snapshot.repository.slug, snapshot.issue_number, tuple((item.comment_id, item.author_id, item.body_digest, item.created_at) for item in snapshot.comments))
    if type(snapshot) is ReviewsSnapshot:
        return ("reviews", snapshot.repository.slug, snapshot.pull_request_number, snapshot.head_sha, tuple((item.review_id, item.reviewer_id, item.state.value, item.commit_sha) for item in snapshot.reviews))
    raise GitHubRuntimeError("collection snapshot is invalid")


def _complete_broker_read(
    adapter: GitHubAdapter, request: GitHubReadRequest, context: MutationBrokerContext,
    bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
    journal_entry: MutationJournalEntry | None,
) -> tuple[GitHubReadResult, str]:
    """Read every typed collection page and return its completeness receipt."""

    if request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS}:
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
        if page.next_cursor is not None and (
            any(prior.cursor == page.next_cursor for prior in pages)
            or page.next_cursor == cursor
        ):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection cursor is repeated or cyclic")), ""
        pages.append(page)
        if page.next_cursor is None:
            break
        cursor = page.next_cursor
    first = pages[0]
    items: dict[str, object] = {}
    ordered: list[object] = []
    last_unique_identifier: str | None = None
    for page in pages:
        collection = page.snapshot.comments if type(page.snapshot) is CommentsSnapshot else page.snapshot.reviews
        identifiers = [item.comment_id if type(page.snapshot) is CommentsSnapshot else item.review_id for item in collection]
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection ordering is unstable")), ""
        for identifier, item in zip(identifiers, collection):
            prior = items.get(identifier)
            if prior is not None and prior != item:
                return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection duplicate conflicts")), ""
            if prior is None:
                if last_unique_identifier is not None and identifier <= last_unique_identifier:
                    return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection ordering is unstable")), ""
                items[identifier] = item
                ordered.append(item)
                last_unique_identifier = identifier
    if len(ordered) != first.total_count:
        return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "collection is incomplete")), ""
    if type(first.snapshot) is CommentsSnapshot:
        normalized: CommentsSnapshot | ReviewsSnapshot = CommentsSnapshot(first.snapshot.repository, first.snapshot.issue_number, tuple(ordered))  # type: ignore[arg-type]
    else:
        normalized = ReviewsSnapshot(first.snapshot.repository, first.snapshot.pull_request_number, first.snapshot.head_sha, tuple(ordered))  # type: ignore[arg-type]
    result = GitHubReadResult(request, snapshot=normalized)
    receipt = CollectionCompletenessReceipt(
        request.identity(), tuple(page.identity for page in pages), _sha256(_collection_snapshot_payload(normalized)),
        context.candidate_sha, context.configuration_digest, context.gate_identity, bundle.identity,
        plan.identity, journal_entry.key if journal_entry is not None else _sha256(("no-journal", plan.intent_identity)),
    )
    return result, receipt.identity


class _GhBrokerExecutor:
    """Private credential-owning seam; only broker construction creates it."""

    def __init__(self, transport: OwnerMutationTransport, health: GitHubCapabilityHealth) -> None:
        if not hasattr(transport, "dispatch"):
            raise GitHubRuntimeError("owner mutation transport is invalid")
        self.__transport = transport
        self.__health = health

    def execute(
        self, intent: GitHubMutationIntent, payload: GhMutationPayload, command: BrokerMutationCommand,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan, journal_identity: str, now: datetime,
    ) -> GitHubMutationResult:
        blocked = _health_failure(intent.operation, self.__health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked)
        if not self.__health.for_operation(intent.operation).fresh_at(now):
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "operation health is stale"))
        try:
            payload.require_matches(intent)
            if command is not plan.command:
                raise GitHubRuntimeError("broker command does not match semantic plan")
            request = OwnerMutationRequest(intent.identity(), intent.operation, bundle.identity, plan.identity, journal_identity)
            fact = self.__transport.dispatch(request)
            if type(fact) is not OwnerMutationFact or fact.request_identity != _sha256((request.intent_identity, request.operation.value, request.authorization_bundle_identity, request.semantic_plan_identity, request.journal_identity)):
                raise GitHubRuntimeError("owner mutation fact is not bound to request")
        except GitHubRuntimeError:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is invalid"))
        if not fact.accepted:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "owner mutation transport denied fixed request"))
        return GitHubMutationResult(intent, receipt=_broker_receipt(intent))


class GitHubMutationBroker:
    """The sole mutation seam; rejects before a write when evidence is absent."""

    def __init__(self, adapter: GitHubAdapter, *, journal: DurableMutationJournal | None = None, _executor: _GhBrokerExecutor | None = None, clock: Callable[[], datetime] | None = None) -> None:
        if not hasattr(adapter, "read") or not hasattr(adapter, "submit"):
            raise GitHubRuntimeError("GitHub adapter is invalid")
        self._adapter = adapter
        self.__executor = _executor
        self.__clock = _trusted_utc_now if clock is None else clock
        self.__clock_is_default = clock is None
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

    @classmethod
    def with_owner_transport(
        cls, read_runner: GhRunner, transport: OwnerMutationTransport, health: GitHubCapabilityHealth, *, journal: DurableMutationJournal,
    ) -> "GitHubMutationBroker":
        """Create the only production mutation path without exposing its executor."""

        if type(journal) is not DurableMutationJournal:
            raise GitHubRuntimeError("live broker requires a durable journal")
        return cls(GhGitHubAdapter(read_runner, health), journal=journal, _executor=_GhBrokerExecutor(transport, health))

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
        failure = _authorize(intent, context)
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        try:
            now = self._now(context)
            bundle = schema_v2_authorization_bundle(context, now=now)
            plan = _broker_semantic_plan(intent)
        except (AttributeError, KeyError, TypeError, ValueError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic plan is unavailable or incomplete"))
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
                return self._reconcile_journal(intent, context, bundle, plan, evidence, journal_entry)
        before, pre_completeness = _complete_broker_read(self._adapter, plan.pre_state, context, bundle, plan, evidence)
        if not before.ok:
            if evidence is not None and self._journal is not None:
                self._journal_transition(evidence, JournalLifecycle.FAILED)
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-mutation semantic state is unavailable"))
        if evidence is not None and self._journal is not None:
            evidence = self._journal_transition(evidence, JournalLifecycle.PRESTATE_CAPTURED, pre_state_digest=before.snapshot_digest)
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-state checkpoint was not persisted"))
            evidence = self._journal_transition(evidence, JournalLifecycle.EXECUTION_STARTED)
            if evidence is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "execution checkpoint was not persisted"))
        outcome = self._execute(intent, payload, plan, bundle, evidence, now)
        if not outcome.ok:
            if evidence is not None and self._journal is not None:
                lifecycle = JournalLifecycle.DENIED if outcome.failure is not None and outcome.failure.kind is GitHubFailureKind.POLICY_DENIED else JournalLifecycle.FAILED
                self._journal_transition(evidence, lifecycle)
            return BrokerMutationResult(failure=outcome.failure or GitHubFailure(GitHubFailureKind.UNAVAILABLE, intent.operation, "mutation outcome is unavailable"))
        if evidence is not None and self._journal is not None:
            evidence = self._journal_transition(evidence, JournalLifecycle.TRANSPORT_ACCEPTED)
        if evidence is None and self._journal is not None:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation durability is uncertain"), reconciliation_required=True)
        after, post_completeness = _complete_broker_read(self._adapter, plan.readback.request, context, bundle, plan, evidence)
        if not _readback_matches(plan.readback, intent, after):
            if self._journal is not None:
                assert evidence is not None
                self._journal_transition(evidence, JournalLifecycle.AMBIGUOUS)
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation requires semantic reconciliation"), reconciliation_required=True)
        assert outcome.receipt is not None
        receipt = self._semantic_receipt(intent, context, bundle, plan, before.snapshot_digest, after.snapshot_digest, pre_completeness, post_completeness, outcome.receipt.affected_identity, outcome.receipt.disposition)
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
        disposition: MutationDisposition,
    ) -> SemanticMutationReceipt:
        binding = context.policy.binding
        assert binding is not None  # established by _authorize
        return SemanticMutationReceipt(
            intent.repository.slug, intent.operation, intent.idempotency_key, bundle.identity,
            intent.identity(), plan.identity, plan.readback.identity,
            pre_state_completeness_identity, post_state_completeness_identity,
            _sha256(("public-payload", intent.payload)), binding.digest,
            context.configuration_digest, binding.deployment_fingerprint,
            binding.task_fingerprint, context.base_sha, context.candidate_sha,
            context.gate_identity, pre_state_digest, post_state_digest,
            affected_identity, context.evaluated_at.isoformat(), (context.evaluated_at + timedelta(minutes=5)).isoformat(),
            _sha256((context.evaluated_at.isoformat(), (context.evaluated_at + timedelta(minutes=5)).isoformat())), disposition,
        )

    def _journal_transition(
        self, evidence: MutationJournalEntry, lifecycle: JournalLifecycle,
        receipt: SemanticMutationReceipt | None = None, *, pre_state_digest: str | None = None,
    ) -> MutationJournalEntry | None:
        assert self._journal is not None
        try:
            updated = self._journal.transition(evidence, lifecycle, receipt, pre_state_digest=pre_state_digest)
        except (AttributeError, TypeError, ValueError):
            return None
        # Reconstruct from the serialized public-safe record before returning:
        # callers never retain an in-memory value that was not durably stored.
        try:
            return MutationJournalEntry.deserialize(updated.serialize())
        except (AttributeError, TypeError, ValueError):
            return None

    def _reconcile_journal(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext,
        bundle: SchemaV2AuthorizationBundle, plan: BrokerSemanticPlan,
        evidence: MutationJournalEntry, entry: MutationJournalEntry,
    ) -> BrokerMutationResult:
        """Resolve a durable uncertain state only from broker-owned read-back."""

        try:
            now = self._now(context)
            fresh_until = datetime.fromisoformat(entry.fresh_until)
        except (TypeError, ValueError, GitHubRuntimeError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable authorization time evidence is invalid"))
        if now >= fresh_until:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "durable authorization evidence has expired"))

        if entry.lifecycle in {JournalLifecycle.CLAIMED, JournalLifecycle.PRESTATE_CAPTURED}:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation has not started execution"))

        if entry.lifecycle is JournalLifecycle.VERIFIED:
            assert entry.receipt is not None
            self._completed[intent.identity()] = entry.receipt
            return BrokerMutationResult(receipt=entry.receipt)
        if entry.lifecycle in {JournalLifecycle.DENIED, JournalLifecycle.FAILED}:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation lifecycle is terminally denied or failed"))
        observed, completeness = _complete_broker_read(self._adapter, plan.readback.request, context, bundle, plan, evidence)
        if not _readback_matches(plan.readback, intent, observed):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "durable mutation requires semantic reconciliation"), reconciliation_required=True)
        receipt = self._semantic_receipt(
            intent, context, bundle, plan, observed.snapshot_digest, observed.snapshot_digest,
            completeness, completeness,
            "reconciled", MutationDisposition.ALREADY_APPLIED,
        )
        if self._journal is not None and not self._journal_transition(evidence, JournalLifecycle.VERIFIED, receipt):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "reconciled receipt was not persisted"), reconciliation_required=True)
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)

    def _execute(
        self, intent: GitHubMutationIntent, payload: GhMutationPayload | None, plan: BrokerSemanticPlan,
        bundle: SchemaV2AuthorizationBundle, evidence: MutationJournalEntry | None, now: datetime,
    ) -> GitHubMutationResult:
        if type(plan) is not BrokerSemanticPlan or plan.operation is not intent.operation or plan.command is not _MUTATION_COMMAND_BY_OPERATION[intent.operation]:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic command is invalid"))
        if self.__executor is not None:
            if type(payload) is not GhMutationPayload:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is unavailable"))
            if self._journal is None:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "live mutation lacks durable journal evidence"))
            if type(evidence) is not MutationJournalEntry:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "live mutation lacks sealed journal entry"))
            return self.__executor.execute(intent, payload, plan.command, bundle, plan, evidence.key, now)
        if payload is not None:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "adapter does not accept brokered mutation payloads"))
        return self._adapter.submit(intent)

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
        failure = _authorize(intent, context)
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        try:
            bundle = schema_v2_authorization_bundle(context, now=self._now(context))
            plan = _broker_semantic_plan(intent)
        except (AttributeError, KeyError, TypeError, ValueError):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker semantic plan is unavailable or incomplete"))
        if self._journal is not None:
            try:
                evidence = MutationJournalEntry.from_evidence(intent, context, bundle, plan)
                entry = self._journal.find(evidence)
            except (AttributeError, TypeError, ValueError):
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation evidence is unavailable or conflicting"))
            if entry is None:
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "durable mutation evidence is missing"))
            return self._reconcile_journal(intent, context, bundle, plan, evidence, entry)
        observed, completeness = _complete_broker_read(self._adapter, plan.readback.request, context, bundle, plan, None)
        if not _readback_matches(plan.readback, intent, observed):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "interrupted mutation is not semantically reconciled"), reconciliation_required=True)
        receipt = self._semantic_receipt(intent, context, bundle, plan, observed.snapshot_digest, observed.snapshot_digest, completeness, completeness, "reconciled", MutationDisposition.ALREADY_APPLIED)
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)


def _authorize(intent: object, context: object) -> GitHubFailure | None:
    if type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext:
        raise GitHubRuntimeError("broker request is invalid")
    try:
        # This is deliberately before every adapter read or mutation.  The
        # bundle is built only from exact canonical evidence and rejects any
        # receipt, authority, context, or dispatcher drift before a runner can
        # observe an intent.
        schema_v2_authorization_bundle(context)
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
        return isinstance(snapshot, CommentsSnapshot) and dict(intent.payload).get("body_digest") in {item.body_digest for item in snapshot.comments}
    if condition is SemanticPostcondition.BRANCH_AT_EXPECTED_SHA:
        return isinstance(snapshot, BranchSnapshot) and snapshot.sha == intent.expected_sha
    if condition is SemanticPostcondition.BRANCH_ABSENT:
        return snapshot is None
    if condition is SemanticPostcondition.PULL_REQUEST_DRAFT:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.OPEN and snapshot.draft
    if condition is SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.OPEN and snapshot.draft and snapshot.head_sha == dict(intent.payload).get("head_sha") and snapshot.base_sha == dict(intent.payload).get("base_sha") and snapshot.head_ref == dict(intent.payload).get("head_ref") and snapshot.base_ref == dict(intent.payload).get("base_ref")
    if condition is SemanticPostcondition.PULL_REQUEST_READY:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.OPEN and not snapshot.draft and snapshot.head_sha == intent.expected_sha
    if condition is SemanticPostcondition.PULL_REQUEST_MERGED:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.MERGED and snapshot.head_sha == intent.expected_sha
    if condition is SemanticPostcondition.REVIEW_AT_CANDIDATE:
        return isinstance(snapshot, ReviewsSnapshot) and snapshot.head_sha == intent.expected_sha and bool(snapshot.reviews)
    if condition is SemanticPostcondition.REVIEWERS_EXACT_AT_CANDIDATE:
        return isinstance(snapshot, ReviewsSnapshot) and snapshot.head_sha == intent.expected_sha and _sha256(("reviewers", tuple(sorted(review.reviewer_id for review in snapshot.reviews)))) == dict(intent.payload).get("reviewers_digest")
    if condition is SemanticPostcondition.ISSUE_CLOSED:
        return isinstance(snapshot, IssueSnapshot) and snapshot.state is IssueState.CLOSED
    if condition is SemanticPostcondition.REMOTE_HEAD_AT_EXPECTED_SHA:
        return isinstance(snapshot, RemoteHeadSnapshot) and snapshot.sha == intent.expected_sha
    return False


def _readback_matches(
    readback: SemanticReadback, intent: GitHubMutationIntent, result: GitHubReadResult,
) -> bool:
    """Interpret the one explicit branch-absence result without inventing success."""

    if readback.condition is SemanticPostcondition.BRANCH_ABSENT:
        return (
            result.failure is not None
            and result.failure.kind is GitHubFailureKind.STALE_RESPONSE
        )
    return result.ok and _matches(readback, intent, result.snapshot)


def _project_gh_response(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    """Project one REST response into the exact core schema.

    Provider objects never cross this boundary.  The request supplies the
    authoritative repository/number/ref identities and any contradictory raw
    identity is rejected.  Collection endpoints accept at most ten slurped
    pages; a different shape is incomplete rather than silently partial.
    """

    repository = {"owner": request.repository.owner, "name": request.repository.name}
    operation = request.operation
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
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        return {"repository": repository, "id": _raw_id(item, "id"), "default_branch": _raw_text(item, "default_branch"), "default_branch_sha": _raw_text(item, "default_branch_sha")}
    if operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        _raw_number_matches(item, request)
        parent = item.get("parent_issue")
        parent_number = _raw_integer(_raw_mapping(parent), "number") if parent is not None else None
        children = item.get("sub_issues", [])
        if type(children) is not list:
            raise GitHubRuntimeError("gh issue sub-issues are incomplete")
        return {"repository": repository, "id": _raw_id(item, "id"), "number": request.number, "state": _raw_text(item, "state"), "parent_number": parent_number, "sub_issue_numbers": [_raw_integer(_raw_mapping(child), "number") for child in children]}
    if operation is GitHubReadOperation.COMMENTS:
        if type(raw) is dict and "data" in raw:
            projected, next_cursor, _ = _project_gh_collection_page(request, raw)
            if next_cursor is not None:
                raise GitHubRuntimeError("gh comment response is not terminal")
            return projected
        return {"repository": repository, "issue_number": request.number, "comments": [{"id": _raw_id(item, "id"), "author_id": _raw_id(_raw_mapping(item.get("user")), "id"), "body": _raw_text(item, "body"), "created_at": _raw_text(item, "created_at")} for item in _raw_collection(raw, "comments")]}
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
        _raw_repository_matches(item, request)
        _raw_number_matches(item, request)
        base, head = _raw_mapping(item.get("base")), _raw_mapping(item.get("head"))
        return {"repository": repository, "id": _raw_id(item, "id"), "number": request.number, "state": _raw_text(item, "state"), "base_ref": _raw_text(base, "ref"), "base_sha": _raw_text(base, "sha"), "head_ref": _raw_text(head, "ref"), "head_sha": _raw_text(head, "sha"), "draft": _raw_bool(item, "draft")}
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
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        runs = item.get("check_runs")
        if type(runs) is not list:
            raise GitHubRuntimeError("gh check-runs response is incomplete")
        head_sha = _raw_text(item, "head_sha")
        if head_sha != request.expected_sha or any(_raw_text(_raw_mapping(run), "head_sha") != head_sha for run in runs):
            raise GitHubRuntimeError("gh checks candidate does not match request")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": head_sha, "checks": [{"id": _raw_id(run, "id"), "name": _raw_text(run, "name"), "state": _raw_text(run, "status").upper(), "conclusion": _raw_optional_text(run, "conclusion", upper=True), "head_sha": _raw_text(run, "head_sha")} for run in runs]}
    if operation is GitHubReadOperation.WORKFLOW_RUNS:
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        runs = item.get("workflow_runs")
        if type(runs) is not list:
            raise GitHubRuntimeError("gh workflow-runs response is incomplete")
        if not runs:
            raise GitHubRuntimeError("gh workflow response cannot establish candidate identity")
        head_sha = _raw_text(_raw_mapping(runs[0]), "head_sha")
        if head_sha != request.expected_sha or any(_raw_text(_raw_mapping(run), "head_sha") != head_sha for run in runs):
            raise GitHubRuntimeError("gh workflow candidate does not match request")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": head_sha, "runs": [{"id": _raw_id(run, "id"), "workflow_name": _raw_text(run, "name"), "state": _raw_text(run, "status").upper(), "conclusion": _raw_optional_text(run, "conclusion", upper=True), "head_sha": _raw_text(run, "head_sha")} for run in runs]}
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
    target_key = "issue" if request.operation is GitHubReadOperation.COMMENTS else "pullRequest"
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
    repository = {"owner": request.repository.owner, "name": request.repository.name}
    if request.operation is GitHubReadOperation.COMMENTS:
        projected = {
            "repository": repository, "issue_number": request.number,
            output_name: [
                {"id": _raw_id(_raw_mapping(node), "id"),
                 "author_id": _raw_id(_raw_mapping(_raw_mapping(node).get("author")), "id"),
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
                 "reviewer_id": _raw_id(_raw_mapping(_raw_mapping(node).get("author")), "id"),
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
    if type(repository_url) is str and repository_url.rstrip("/").endswith(f"/repos/{request.repository.slug}"):
        return
    raise GitHubRuntimeError("gh response repository does not match request")


def _raw_branch_repository_matches(mapping: Mapping[str, object], request: GitHubReadRequest) -> None:
    """A REST branch response establishes its repository through commit URLs."""

    commit = _raw_mapping(mapping.get("commit"))
    url = commit.get("url")
    if type(url) is not str or f"/repos/{request.repository.slug}/commits/" not in url:
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


def _collection_read_command(request: GitHubReadRequest, cursor: str | None) -> tuple[str, ...]:
    """Build the sole native-provider collection query shape.

    GraphQL connections expose terminality in the response itself.  This is
    intentionally separate from ordinary GET commands so a caller cannot tack
    a cursor onto an unrelated endpoint and manufacture collection evidence.
    """

    if request.operation is GitHubReadOperation.COMMENTS:
        target = "issue(number:$number){number comments(first:100,after:$cursor){totalCount nodes{id author{id} body createdAt} pageInfo{hasNextPage endCursor}}}"
    elif request.operation is GitHubReadOperation.REVIEWS:
        target = "pullRequest(number:$number){number headRefOid reviews(first:100,after:$cursor){totalCount nodes{id author{id} state commit{oid}} pageInfo{hasNextPage endCursor}}}"
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


def _health_failure(operation: GitHubOperation, health: GitHubCapabilityHealth) -> GitHubFailure | None:
    item = health.for_operation(operation)
    if item.available:
        return None
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
