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
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping, Protocol

from .deployment import DeploymentAuthorityDecision, DeploymentMode
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
    PullRequestSnapshot,
    PullRequestState,
    RemoteHeadSnapshot,
    ReviewsSnapshot,
    normalize_github_response,
)
from .repository_policy import (
    RepositoryMutationBinding,
    RepositoryMutationDecision,
    RepositoryMutationOperation,
)


class GitHubRuntimeError(ValueError):
    """Raised when runtime-only adapter evidence is malformed."""


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

    def __post_init__(self) -> None:
        if type(self.operation) not in (GitHubReadOperation, GitHubMutationOperation):
            raise GitHubRuntimeError("operation health operation is invalid")
        if type(self.state) is not CapabilityState or type(self.observed_at) is not datetime or self.observed_at.tzinfo is not timezone.utc:
            raise GitHubRuntimeError("operation health is invalid")
        _digest(self.evidence_digest, "operation health evidence")

    @property
    def available(self) -> bool:
        return self.state is CapabilityState.AVAILABLE


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


class SubprocessGhRunner:
    """Minimal ``gh`` runner; it does not inspect auth state or environment."""

    def __init__(self, executable: str = "gh") -> None:
        if type(executable) is not str or executable != "gh":
            raise GitHubRuntimeError("gh executable must be the configured default")
        self._executable = executable

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult:
        if type(arguments) is not tuple or any(type(value) is not str or not value or "\x00" in value for value in arguments):
            raise GitHubRuntimeError("gh command arguments are invalid")
        # No shell, inherited credential lookup only, and stderr is discarded.
        try:
            completed = subprocess.run(
                (self._executable, *arguments), check=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                encoding="utf-8", errors="strict", timeout=30,
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return GhCommandResult(127, "")
        return GhCommandResult(completed.returncode, completed.stdout)


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
        self._runner = runner
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
        outcome = self._runner.run(_read_command(request))
        if outcome.exit_code != 0:
            return GitHubReadResult(request, failure=GitHubFailure(_failure_kind(outcome.exit_code), request.operation, "gh read did not return a usable response"))
        try:
            raw = json.loads(outcome.stdout)
            snapshot = normalize_github_response(request, raw)
            return GitHubReadResult(request, snapshot=snapshot)
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "gh read response is malformed"))

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult:
        """Refuse direct writes; only the broker may authorize a future runner."""

        if type(intent) is not GitHubMutationIntent:
            raise GitHubContractError("mutation intent is invalid")
        self.calls.append(("mutation", intent.operation.value))
        blocked = _health_failure(intent.operation, self._health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked)
        return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "direct gh mutation is forbidden; use the mutation broker"))


def unavailable_capability_health(*, now: datetime | None = None) -> GitHubCapabilityHealth:
    """Return the default all-disabled matrix without calling ``gh``."""

    observed = now if type(now) is datetime and now.tzinfo is timezone.utc else datetime(1970, 1, 1, tzinfo=timezone.utc)
    values = tuple(OperationHealth(operation, CapabilityState.UNAVAILABLE, observed, _sha256(("gh-health", operation.value, "unavailable"))) for operation in (*GitHubReadOperation, *GitHubMutationOperation))
    return GitHubCapabilityHealth(values)


class SemanticPostcondition(StrEnum):
    COMMENT_PRESENT = "comment-present"
    BRANCH_AT_EXPECTED_SHA = "branch-at-expected-sha"
    PULL_REQUEST_DRAFT = "pull-request-draft"
    PULL_REQUEST_READY = "pull-request-ready"
    PULL_REQUEST_MERGED = "pull-request-merged"
    REVIEW_AT_CANDIDATE = "review-at-candidate"
    ISSUE_CLOSED = "issue-closed"
    REMOTE_HEAD_AT_EXPECTED_SHA = "remote-head-at-expected-sha"


@dataclass(frozen=True)
class SemanticReadback:
    request: GitHubReadRequest
    condition: SemanticPostcondition

    def __post_init__(self) -> None:
        if type(self.request) is not GitHubReadRequest or type(self.condition) is not SemanticPostcondition:
            raise GitHubRuntimeError("semantic read-back is invalid")


@dataclass(frozen=True)
class MutationBrokerContext:
    """Public-safe, exact-candidate authorization inputs for one mutation."""

    policy: RepositoryMutationDecision
    deployment: DeploymentAuthorityDecision
    configuration_digest: str
    base_sha: str
    candidate_sha: str
    gate_identity: str

    def __post_init__(self) -> None:
        if type(self.policy) is not RepositoryMutationDecision or type(self.deployment) is not DeploymentAuthorityDecision:
            raise GitHubRuntimeError("broker authority evidence is invalid")
        for value, name in ((self.configuration_digest, "configuration"), (self.gate_identity, "gate")):
            _digest(value, name)
        for value, name in ((self.base_sha, "base sha"), (self.candidate_sha, "candidate sha")):
            if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                raise GitHubRuntimeError(f"broker {name} is invalid")


@dataclass(frozen=True)
class SemanticMutationReceipt:
    """Curated receipt binding a mutation to its authorization and read-back."""

    repository: str
    operation: GitHubMutationOperation
    idempotency_key: str
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
    disposition: MutationDisposition
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.repository) is not str or "/" not in self.repository or type(self.operation) is not GitHubMutationOperation or type(self.idempotency_key) is not str:
            raise GitHubRuntimeError("semantic receipt identity is invalid")
        for value, name in ((self.public_payload_digest, "payload"), (self.configuration_digest, "configuration"), (self.gate_identity, "gate"), (self.pre_state_digest, "pre-state"), (self.post_state_digest, "post-state")):
            _digest(value, name)
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


class GitHubMutationBroker:
    """The sole mutation seam; rejects before a write when evidence is absent."""

    def __init__(self, adapter: GitHubAdapter) -> None:
        if not hasattr(adapter, "read") or not hasattr(adapter, "submit"):
            raise GitHubRuntimeError("GitHub adapter is invalid")
        self._adapter = adapter
        self._completed: dict[str, SemanticMutationReceipt] = {}

    def submit(
        self,
        intent: GitHubMutationIntent,
        context: MutationBrokerContext,
        *,
        pre_state: GitHubReadRequest,
        readback: SemanticReadback,
    ) -> BrokerMutationResult:
        """Read pre-state, authorize, submit once, then demand semantic read-back."""

        failure = _authorize(intent, context)
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        prior = self._completed.get(intent.identity())
        if prior is not None:
            return BrokerMutationResult(receipt=prior)
        if pre_state.repository != intent.repository or readback.request.repository != intent.repository:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "semantic reads must target the mutation repository"))
        before = self._adapter.read(pre_state)
        if not before.ok:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-mutation semantic state is unavailable"))
        outcome = self._adapter.submit(intent)
        if not outcome.ok:
            return BrokerMutationResult(failure=outcome.failure or GitHubFailure(GitHubFailureKind.UNAVAILABLE, intent.operation, "mutation outcome is unavailable"))
        after = self._adapter.read(readback.request)
        if not after.ok or not _matches(readback, intent, after.snapshot):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "mutation requires semantic reconciliation"), reconciliation_required=True)
        binding = context.policy.binding
        assert binding is not None  # established by _authorize
        receipt = SemanticMutationReceipt(
            intent.repository.slug, intent.operation, intent.idempotency_key,
            _sha256(("public-payload", intent.payload)), binding.digest,
            context.configuration_digest, binding.deployment_fingerprint,
            binding.task_fingerprint, context.base_sha, context.candidate_sha,
            context.gate_identity, before.snapshot_digest, after.snapshot_digest,
            outcome.receipt.affected_identity, outcome.receipt.disposition,
        )
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)

    def reconcile(
        self, intent: GitHubMutationIntent, context: MutationBrokerContext, *, readback: SemanticReadback
    ) -> BrokerMutationResult:
        """Safely classify an interrupted attempt from post-state only.

        It never re-submits the mutation.  A match yields a durable
        ``ALREADY_APPLIED`` receipt; anything else remains blocked.
        """

        failure = _authorize(intent, context)
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        observed = self._adapter.read(readback.request)
        if not observed.ok or not _matches(readback, intent, observed.snapshot):
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "interrupted mutation is not semantically reconciled"), reconciliation_required=True)
        binding = context.policy.binding
        assert binding is not None
        receipt = SemanticMutationReceipt(intent.repository.slug, intent.operation, intent.idempotency_key, _sha256(("public-payload", intent.payload)), binding.digest, context.configuration_digest, binding.deployment_fingerprint, binding.task_fingerprint, context.base_sha, context.candidate_sha, context.gate_identity, observed.snapshot_digest, observed.snapshot_digest, "reconciled", MutationDisposition.ALREADY_APPLIED)
        self._completed[intent.identity()] = receipt
        return BrokerMutationResult(receipt=receipt)


def _authorize(intent: object, context: object) -> GitHubFailure | None:
    if type(intent) is not GitHubMutationIntent or type(context) is not MutationBrokerContext:
        raise GitHubRuntimeError("broker request is invalid")
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


def _repository_operation(operation: GitHubMutationOperation) -> RepositoryMutationOperation | None:
    return {
        GitHubMutationOperation.CREATE_BRANCH: RepositoryMutationOperation.PUSH_BRANCH,
        GitHubMutationOperation.CREATE_PULL_REQUEST: RepositoryMutationOperation.CREATE_DRAFT_PR,
        GitHubMutationOperation.COMMENT: RepositoryMutationOperation.ISSUE_COMMENT,
        GitHubMutationOperation.REQUEST_REVIEW: None,
        GitHubMutationOperation.MARK_READY: RepositoryMutationOperation.MARK_PR_READY,
        GitHubMutationOperation.MERGE_PULL_REQUEST: RepositoryMutationOperation.MERGE_PR,
        GitHubMutationOperation.CLOSE_ISSUE: RepositoryMutationOperation.CLOSE_LEAF_ISSUE,
        GitHubMutationOperation.DELETE_BRANCH: RepositoryMutationOperation.DELETE_REMOTE_BRANCH,
    }[operation]


def _matches(readback: SemanticReadback, intent: GitHubMutationIntent, snapshot: GitHubSnapshot | None) -> bool:
    if snapshot is None:
        return False
    condition = readback.condition
    if condition is SemanticPostcondition.COMMENT_PRESENT:
        return isinstance(snapshot, CommentsSnapshot) and dict(intent.payload).get("body_digest") in {item.body_digest for item in snapshot.comments}
    if condition is SemanticPostcondition.BRANCH_AT_EXPECTED_SHA:
        return isinstance(snapshot, BranchSnapshot) and snapshot.sha == intent.expected_sha
    if condition is SemanticPostcondition.PULL_REQUEST_DRAFT:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.OPEN and snapshot.draft
    if condition is SemanticPostcondition.PULL_REQUEST_READY:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.OPEN and not snapshot.draft and snapshot.head_sha == intent.expected_sha
    if condition is SemanticPostcondition.PULL_REQUEST_MERGED:
        return isinstance(snapshot, PullRequestSnapshot) and snapshot.state is PullRequestState.MERGED and snapshot.head_sha == intent.expected_sha
    if condition is SemanticPostcondition.REVIEW_AT_CANDIDATE:
        return isinstance(snapshot, ReviewsSnapshot) and snapshot.head_sha == intent.expected_sha and bool(snapshot.reviews)
    if condition is SemanticPostcondition.ISSUE_CLOSED:
        return isinstance(snapshot, IssueSnapshot) and snapshot.state is IssueState.CLOSED
    if condition is SemanticPostcondition.REMOTE_HEAD_AT_EXPECTED_SHA:
        return isinstance(snapshot, RemoteHeadSnapshot) and snapshot.sha == intent.expected_sha
    return False


def _read_command(request: GitHubReadRequest) -> tuple[str, ...]:
    """Build an inert, read-only ``gh api`` request; no user text is injected."""

    base = f"repos/{request.repository.slug}"
    if request.operation is GitHubReadOperation.REPOSITORY:
        path = base
    elif request.operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
        path = f"{base}/issues/{request.number}"
    elif request.operation is GitHubReadOperation.COMMENTS:
        path = f"{base}/issues/{request.number}/comments"
    elif request.operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}:
        path = f"{base}/branches/{request.ref}"
    elif request.operation is GitHubReadOperation.PULL_REQUEST:
        path = f"{base}/pulls/{request.number}"
    elif request.operation is GitHubReadOperation.REVIEWS:
        path = f"{base}/pulls/{request.number}/reviews"
    elif request.operation is GitHubReadOperation.CHECKS:
        path = f"{base}/commits/{request.expected_sha}/check-runs"
    elif request.operation is GitHubReadOperation.WORKFLOW_RUNS:
        path = f"{base}/actions/runs?head_sha={request.expected_sha}"
    elif request.operation is GitHubReadOperation.MERGEABILITY:
        path = f"{base}/pulls/{request.number}"
    elif request.operation is GitHubReadOperation.CLOSING_REFERENCES:
        path = f"{base}/issues/{request.number}/timeline"
    else:
        raise GitHubRuntimeError("unsupported gh read operation")
    return ("api", "--method", "GET", path)


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
