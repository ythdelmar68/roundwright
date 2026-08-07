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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
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
    MutationReceipt,
    PullRequestSnapshot,
    PullRequestState,
    RemoteHeadSnapshot,
    ReviewsSnapshot,
    normalize_github_response,
)
from .repository_policy import (
    GITHUB_REPOSITORY_OPERATION,
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
        self._broker_token = object()
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
            snapshot = normalize_github_response(request, _project_gh_response(request, raw))
            return GitHubReadResult(request, snapshot=snapshot)
        except (json.JSONDecodeError, GitHubContractError, TypeError, ValueError):
            return GitHubReadResult(request, failure=GitHubFailure(GitHubFailureKind.MALFORMED_RESPONSE, request.operation, "gh read response is malformed"))

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult:
        """Refuse direct writes; only the broker-only seam may execute one."""

        if type(intent) is not GitHubMutationIntent:
            raise GitHubContractError("mutation intent is invalid")
        self.calls.append(("mutation", intent.operation.value))
        blocked = _health_failure(intent.operation, self._health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked)
        return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "direct gh mutation is forbidden; use the mutation broker"))

    def _issue_broker_capability(self) -> object:
        """Return the unforgeable in-process capability consumed by the broker."""

        return self._broker_token

    def _execute_brokered(
        self, intent: GitHubMutationIntent, payload: "GhMutationPayload", *, capability: object
    ) -> GitHubMutationResult:
        """Execute one authorized intent without retaining provider output.

        This method is deliberately separate from ``submit``.  The broker calls
        it only after the exact policy/deployment/candidate/gate checks and
        captures semantic read-back itself.  It accepts no token, executable,
        shell string, or arbitrary command line.
        """

        if capability is not self._broker_token:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "unbrokered gh mutation execution is forbidden"))
        if type(intent) is not GitHubMutationIntent or type(payload) is not GhMutationPayload:
            raise GitHubRuntimeError("brokered gh mutation request is invalid")
        self.calls.append(("brokered-mutation", intent.operation.value))
        blocked = _health_failure(intent.operation, self._health)
        if blocked is not None:
            return GitHubMutationResult(intent, failure=blocked)
        try:
            payload.require_matches(intent)
            outcome = self._runner.run(_mutation_command(intent, payload))
        except GitHubRuntimeError:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is invalid"))
        if outcome.exit_code != 0:
            return GitHubMutationResult(intent, failure=GitHubFailure(_failure_kind(outcome.exit_code), intent.operation, "gh mutation did not return a usable status"))
        # Command output is deliberately discarded.  The broker's typed
        # postcondition read is the only success signal it may retain.
        return GitHubMutationResult(intent, receipt=_broker_receipt(intent))


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
            if expected.get("reviewers_digest") != _sha256(("reviewers", tuple(self.value("reviewers").split(",")))):
                raise GitHubRuntimeError("gh reviewer payload does not match intent")


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
class SchemaV2AuthorizationBundle:
    """Immutable public-safe identity bundle for a future broker preflight.

    This is deliberately evidence-only: it carries fixed fingerprints/digests
    from the schema-v2 policy evaluator and no provider response text.
    """

    standing_authority_identity: str
    verified_policy_receipt_identity: str
    repository_identity: str
    deployment_identity: str
    task_identity: str
    configuration_digest: str
    base_sha: str
    candidate_sha: str
    gate_identity: str
    receipt_lifecycle_identity: str
    dispatcher_transition_identity: str
    identity: str = field(init=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.standing_authority_identity, "standing authority"),
            (self.verified_policy_receipt_identity, "policy receipt"),
            (self.repository_identity, "repository"), (self.deployment_identity, "deployment"),
            (self.task_identity, "task"), (self.receipt_lifecycle_identity, "receipt lifecycle"),
            (self.dispatcher_transition_identity, "dispatcher transition"),
        ):
            _fingerprint(value, name)
        _digest(self.configuration_digest, "configuration")
        _digest(self.gate_identity, "gate")
        for value, name in ((self.base_sha, "base sha"), (self.candidate_sha, "candidate sha")):
            if type(value) is not str or len(value) not in {40, 64} or any(char not in "0123456789abcdef" for char in value):
                raise GitHubRuntimeError(f"authorization bundle {name} is invalid")
        object.__setattr__(self, "identity", _sha256(tuple(getattr(self, name) for name in self.__dataclass_fields__ if name != "identity")))

    def serialize(self) -> Mapping[str, str]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


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


class DurableMutationJournal:
    """Atomic public-safe idempotency state for an Orchestrator composition root.

    Records contain only repository, operation, idempotency key, intent digest,
    and lifecycle state.  A restarted broker therefore reconciles instead of
    issuing another write after an interrupted attempt.
    """

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir():
            raise GitHubRuntimeError("mutation journal path is invalid")
        self._path = path

    def begin(self, intent: GitHubMutationIntent) -> str:
        records = self._load()
        key, digest = self._key(intent), intent.identity()
        prior = records.get(key)
        if prior is not None:
            if prior.get("intent_digest") != digest:
                return "conflict"
            return str(prior.get("state"))
        records[key] = {"repository": intent.repository.slug, "operation": intent.operation.value, "idempotency_key": intent.idempotency_key, "intent_digest": digest, "state": "started"}
        self._store(records)
        return "started"

    def transition(self, intent: GitHubMutationIntent, state: str) -> None:
        if state not in {"applied", "ambiguous"}:
            raise GitHubRuntimeError("mutation journal state is invalid")
        records = self._load()
        key = self._key(intent)
        prior = records.get(key)
        if prior is None or prior.get("intent_digest") != intent.identity():
            raise GitHubRuntimeError("mutation journal record is missing")
        prior["state"] = state
        self._store(records)

    def _load(self) -> dict[str, dict[str, str]]:
        if not self._path.exists():
            return {}
        try:
            value = json.loads(self._path.read_text(encoding="utf-8"))
            if type(value) is not dict or any(type(key) is not str or type(record) is not dict or set(record) != {"repository", "operation", "idempotency_key", "intent_digest", "state"} or any(type(item) is not str for item in record.values()) for key, record in value.items()):
                raise ValueError
            return value
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise GitHubRuntimeError("mutation journal is malformed") from error

    def _store(self, records: Mapping[str, Mapping[str, str]]) -> None:
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            temporary.write_text(json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True), encoding="utf-8")
            os.replace(temporary, self._path)
        except OSError as error:
            raise GitHubRuntimeError("mutation journal cannot be persisted") from error

    @staticmethod
    def _key(intent: GitHubMutationIntent) -> str:
        return _sha256((intent.repository.slug, intent.operation.value, intent.idempotency_key))


class GitHubMutationBroker:
    """The sole mutation seam; rejects before a write when evidence is absent."""

    def __init__(self, adapter: GitHubAdapter, *, journal: DurableMutationJournal | None = None) -> None:
        if not hasattr(adapter, "read") or not hasattr(adapter, "submit"):
            raise GitHubRuntimeError("GitHub adapter is invalid")
        self._adapter = adapter
        issuer = getattr(adapter, "_issue_broker_capability", None)
        self._broker_capability = issuer() if callable(issuer) else None
        self._completed: dict[str, SemanticMutationReceipt] = {}
        self._journal = journal

    def submit(
        self,
        intent: GitHubMutationIntent,
        context: MutationBrokerContext,
        *,
        pre_state: GitHubReadRequest,
        readback: SemanticReadback,
        payload: GhMutationPayload | None = None,
    ) -> BrokerMutationResult:
        """Read pre-state, authorize, submit once, then demand semantic read-back."""

        failure = _authorize(intent, context)
        if failure is not None:
            return BrokerMutationResult(failure=failure)
        prior = self._completed.get(intent.identity())
        if prior is not None:
            return BrokerMutationResult(receipt=prior)
        if self._journal is not None:
            journal_state = self._journal.begin(intent)
            if journal_state == "conflict":
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "idempotency key conflicts with a different mutation intent"))
            if journal_state != "started":
                return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "durable mutation state requires semantic reconciliation"), reconciliation_required=True)
        if pre_state.repository != intent.repository or readback.request.repository != intent.repository:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "semantic reads must target the mutation repository"))
        before = self._adapter.read(pre_state)
        if not before.ok:
            return BrokerMutationResult(failure=GitHubFailure(GitHubFailureKind.STALE_RESPONSE, intent.operation, "pre-mutation semantic state is unavailable"))
        outcome = self._execute(intent, payload)
        if not outcome.ok:
            return BrokerMutationResult(failure=outcome.failure or GitHubFailure(GitHubFailureKind.UNAVAILABLE, intent.operation, "mutation outcome is unavailable"))
        after = self._adapter.read(readback.request)
        if not after.ok or not _matches(readback, intent, after.snapshot):
            if self._journal is not None:
                self._journal.transition(intent, "ambiguous")
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
        if self._journal is not None:
            self._journal.transition(intent, "applied")
        return BrokerMutationResult(receipt=receipt)

    def _execute(self, intent: GitHubMutationIntent, payload: GhMutationPayload | None) -> GitHubMutationResult:
        execute = getattr(self._adapter, "_execute_brokered", None)
        if callable(execute):
            if type(payload) is not GhMutationPayload:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "brokered gh mutation payload is unavailable"))
            if self._broker_capability is None:
                return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "broker execution capability is unavailable"))
            return execute(intent, payload, capability=self._broker_capability)
        if payload is not None:
            return GitHubMutationResult(intent, failure=GitHubFailure(GitHubFailureKind.POLICY_DENIED, intent.operation, "adapter does not accept brokered mutation payloads"))
        return self._adapter.submit(intent)

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
        if self._journal is not None:
            self._journal.begin(intent)
            self._journal.transition(intent, "applied")
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


def _project_gh_response(request: GitHubReadRequest, raw: object) -> Mapping[str, object]:
    """Project one REST response into the exact core schema.

    Provider objects never cross this boundary.  The request supplies the
    authoritative repository/number/ref identities and any contradictory raw
    identity is rejected.  Collection endpoints accept at most ten slurped
    pages; a different shape is incomplete rather than silently partial.
    """

    if type(raw) is dict and "repository" in raw:
        return raw
    repository = {"owner": request.repository.owner, "name": request.repository.name}
    operation = request.operation
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
        return {"repository": repository, "issue_number": request.number, "comments": [{"id": _raw_id(item, "id"), "author_id": _raw_id(_raw_mapping(item.get("user")), "id"), "body": _raw_text(item, "body"), "created_at": _raw_text(item, "created_at")} for item in _raw_collection(raw, "comments")]}
    if operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}:
        item = _raw_mapping(raw)
        name = _raw_text(item, "name")
        if name != request.ref:
            raise GitHubRuntimeError("gh branch reference does not match request")
        projected = {"repository": repository, "ref": name, "sha": _raw_text(_raw_mapping(item.get("commit")), "sha")}
        return projected
    if operation is GitHubReadOperation.PULL_REQUEST:
        item = _raw_mapping(raw)
        _raw_repository_matches(item, request)
        _raw_number_matches(item, request)
        base, head = _raw_mapping(item.get("base")), _raw_mapping(item.get("head"))
        return {"repository": repository, "id": _raw_id(item, "id"), "number": request.number, "state": _raw_text(item, "state"), "base_ref": _raw_text(base, "ref"), "base_sha": _raw_text(base, "sha"), "head_ref": _raw_text(head, "ref"), "head_sha": _raw_text(head, "sha"), "draft": _raw_bool(item, "draft")}
    if operation is GitHubReadOperation.REVIEWS:
        items = _raw_collection(raw, "reviews")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": request.expected_sha, "reviews": [{"id": _raw_id(item, "id"), "reviewer_id": _raw_id(_raw_mapping(item.get("user")), "id"), "state": _raw_text(item, "state").upper(), "commit_sha": _raw_text(item, "commit_id")} for item in items]}
    if operation is GitHubReadOperation.CHECKS:
        item = _raw_mapping(raw)
        runs = item.get("check_runs")
        if type(runs) is not list:
            raise GitHubRuntimeError("gh check-runs response is incomplete")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": request.expected_sha, "checks": [{"id": _raw_id(run, "id"), "name": _raw_text(run, "name"), "state": _raw_text(run, "status").upper(), "conclusion": _raw_optional_text(run, "conclusion", upper=True), "head_sha": request.expected_sha} for run in runs]}
    if operation is GitHubReadOperation.WORKFLOW_RUNS:
        item = _raw_mapping(raw)
        runs = item.get("workflow_runs")
        if type(runs) is not list:
            raise GitHubRuntimeError("gh workflow-runs response is incomplete")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": request.expected_sha, "runs": [{"id": _raw_id(run, "id"), "workflow_name": _raw_text(run, "name"), "state": _raw_text(run, "status").upper(), "conclusion": _raw_optional_text(run, "conclusion", upper=True), "head_sha": request.expected_sha} for run in runs]}
    if operation is GitHubReadOperation.MERGEABILITY:
        item = _raw_mapping(raw)
        _raw_number_matches(item, request)
        head = _raw_mapping(item.get("head"))
        state = {"clean": "MERGEABLE", "dirty": "CONFLICTING", "unknown": "UNKNOWN"}.get(_raw_text(item, "mergeable_state"))
        if state is None:
            raise GitHubRuntimeError("gh mergeability is incomplete")
        return {"repository": repository, "pull_request_number": request.number, "head_sha": _raw_text(head, "sha"), "mergeability": state}
    # Timeline closing semantics cannot be reconstructed from REST event text
    # without a complete, authenticated parser; reject rather than infer.
    raise GitHubRuntimeError("gh response projection is unavailable")


def _raw_mapping(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise GitHubRuntimeError("gh response object is malformed")
    return value


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
    owner, name = mapping.get("owner"), mapping.get("name")
    if owner is None and name is None:
        return
    owner_map = _raw_mapping(owner)
    if _raw_text(owner_map, "login") != request.repository.owner or _raw_text(mapping, "name") != request.repository.name:
        raise GitHubRuntimeError("gh response repository does not match request")


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


def _mutation_command(intent: GitHubMutationIntent, payload: GhMutationPayload) -> tuple[str, ...]:
    """Map each declared mutation to one fixed ``gh`` command shape.

    The only variable outbound text comes from the validated, digest-bound
    payload supplied by the Orchestrator.  No command is passed through a
    shell and no result text is returned from this function.
    """

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
