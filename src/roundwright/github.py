"""Typed, hermetic GitHub boundary for Phase 3.

This module deliberately contains no ``gh`` invocation, network client, or
MCP import.  Core code can describe a read or a mutation intent using these
immutable values; a later adapter may translate that request to a provider.
All data crossing back into the core is normalized into a small, public-safe
snapshot.  Unknown and incomplete provider shapes are failures, never partial
successes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping, Protocol, TypeAlias


_SHA = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_PUBLIC_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,512}\Z")
_COMMENT_TEXT = re.compile(r"(?s)[^\x00\x7f]{1,65536}\Z")


class GitHubContractError(ValueError):
    """Raised when a caller constructs invalid typed GitHub contract data."""


class GitHubReadOperation(StrEnum):
    REPOSITORY = "repository"
    ISSUE = "issue"
    ISSUE_RELATIONSHIPS = "issue-relationships"
    COMMENTS = "comments"
    BRANCH = "branch"
    PULL_REQUEST = "pull-request"
    REVIEWS = "reviews"
    REQUESTED_REVIEWERS = "requested-reviewers"
    CHECKS = "checks"
    WORKFLOW_RUNS = "workflow-runs"
    MERGEABILITY = "mergeability"
    CLOSING_REFERENCES = "closing-references"
    REMOTE_HEAD = "remote-head"


class GitHubMutationOperation(StrEnum):
    CREATE_BRANCH = "create-branch"
    UPDATE_BRANCH = "update-branch"
    CREATE_PULL_REQUEST = "create-pull-request"
    COMMENT = "comment"
    REQUEST_REVIEW = "request-review"
    MARK_READY = "mark-ready"
    MERGE_PULL_REQUEST = "merge-pull-request"
    CLOSE_ISSUE = "close-issue"
    DELETE_BRANCH = "delete-branch"


class GitHubFailureKind(StrEnum):
    UNAVAILABLE = "unavailable-capability"
    PERMISSION_DENIED = "permission-denied"
    AUTHENTICATION_FAILED = "authentication-failed"
    TRANSPORT_FAILED = "transport-failed"
    MALFORMED_RESPONSE = "malformed-response"
    STALE_RESPONSE = "stale-response"
    POLICY_DENIED = "policy-denied"


class IssueState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"


class PullRequestState(StrEnum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    MERGED = "MERGED"


class ReviewState(StrEnum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    COMMENTED = "COMMENTED"
    DISMISSED = "DISMISSED"
    PENDING = "PENDING"


class CheckState(StrEnum):
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class CheckConclusion(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    NEUTRAL = "NEUTRAL"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"
    TIMED_OUT = "TIMED_OUT"
    ACTION_REQUIRED = "ACTION_REQUIRED"


class Mergeability(StrEnum):
    MERGEABLE = "MERGEABLE"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class MutationDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    ALREADY_APPLIED = "ALREADY_APPLIED"
    REJECTED = "REJECTED"


@dataclass(frozen=True)
class RepositoryRef:
    owner: str
    name: str

    def __post_init__(self) -> None:
        if type(self.owner) is not str or type(self.name) is not str or not _PATH_SEGMENT.fullmatch(self.owner) or not _PATH_SEGMENT.fullmatch(self.name):
            raise GitHubContractError("repository identity is invalid")

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass(frozen=True)
class GitHubReadRequest:
    operation: GitHubReadOperation
    repository: RepositoryRef
    number: int | None = None
    ref: str | None = None
    expected_sha: str | None = None

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubReadOperation or type(self.repository) is not RepositoryRef:
            raise GitHubContractError("read request is invalid")
        if self.number is not None and (type(self.number) is not int or self.number <= 0):
            raise GitHubContractError("read request number is invalid")
        if self.ref is not None and (type(self.ref) is not str or not _IDENTIFIER.fullmatch(self.ref)):
            raise GitHubContractError("read request reference is invalid")
        if self.expected_sha is not None:
            _validate_sha(self.expected_sha, "expected sha")
        numbered = {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS, GitHubReadOperation.COMMENTS, GitHubReadOperation.PULL_REQUEST, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS, GitHubReadOperation.CHECKS, GitHubReadOperation.WORKFLOW_RUNS, GitHubReadOperation.MERGEABILITY, GitHubReadOperation.CLOSING_REFERENCES}
        ref_required = {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}
        candidate_bound = {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD, GitHubReadOperation.PULL_REQUEST, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS, GitHubReadOperation.CHECKS, GitHubReadOperation.WORKFLOW_RUNS, GitHubReadOperation.MERGEABILITY, GitHubReadOperation.CLOSING_REFERENCES}
        if self.operation in numbered and self.number is None:
            raise GitHubContractError("read request requires a number")
        if self.operation not in numbered and self.number is not None:
            raise GitHubContractError("read request number is not applicable")
        if self.operation in ref_required and self.ref is None:
            raise GitHubContractError("read request requires a reference")
        if self.operation not in ref_required and self.ref is not None:
            raise GitHubContractError("read request reference is not applicable")
        if self.operation in candidate_bound and self.expected_sha is None:
            raise GitHubContractError("read request requires an expected sha")
        if self.operation not in candidate_bound and self.expected_sha is not None:
            raise GitHubContractError("read request sha is not applicable")

    def identity(self) -> str:
        return _digest((self.operation.value, self.repository.owner, self.repository.name, self.number, self.ref, self.expected_sha))


@dataclass(frozen=True)
class RepositorySnapshot:
    repository_id: str
    repository: RepositoryRef
    default_branch: str
    default_branch_sha: str
    repository_evidence_identity: str
    default_branch_evidence_identity: str

    def __post_init__(self) -> None:
        _validate_token(self.repository_id, "repository id")
        if type(self.repository) is not RepositoryRef or type(self.default_branch) is not str or not _IDENTIFIER.fullmatch(self.default_branch):
            raise GitHubContractError("repository snapshot is invalid")
        if type(self.default_branch_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.default_branch_sha):
            raise GitHubContractError("default branch sha is invalid")
        _validate_digest(self.repository_evidence_identity, "repository evidence")
        _validate_digest(self.default_branch_evidence_identity, "default branch evidence")


@dataclass(frozen=True)
class IssueSnapshot:
    repository: RepositoryRef
    issue_id: str
    number: int
    state: IssueState
    issue_evidence_identity: str
    relationship_evidence_identity: str
    parent_number: int | None = None
    sub_issue_numbers: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("issue repository is invalid")
        _validate_token(self.issue_id, "issue id")
        _validate_number(self.number, "issue number")
        if type(self.state) is not IssueState or (self.parent_number is not None and (type(self.parent_number) is not int or self.parent_number <= 0)):
            raise GitHubContractError("issue snapshot is invalid")
        _validate_numbers(self.sub_issue_numbers, "sub issue numbers")
        if self.number == self.parent_number or self.number in self.sub_issue_numbers:
            raise GitHubContractError("issue relationship is invalid")
        _validate_digest(self.issue_evidence_identity, "issue evidence")
        _validate_digest(self.relationship_evidence_identity, "issue relationship evidence")


@dataclass(frozen=True)
class CommentSnapshot:
    comment_id: str
    author_id: str
    body_digest: str
    created_at: str

    def __post_init__(self) -> None:
        _validate_token(self.comment_id, "comment id")
        _validate_token(self.author_id, "comment author")
        _validate_digest(self.body_digest, "comment body digest")
        _validate_token(self.created_at, "comment timestamp")


@dataclass(frozen=True)
class CommentsSnapshot:
    repository: RepositoryRef
    issue_number: int
    comments: tuple[CommentSnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("comments repository is invalid")
        _validate_number(self.issue_number, "issue number")
        if type(self.comments) is not tuple or any(type(item) is not CommentSnapshot for item in self.comments):
            raise GitHubContractError("comments snapshot is invalid")
        _unique((item.comment_id for item in self.comments), "comment identities")


@dataclass(frozen=True)
class BranchSnapshot:
    repository: RepositoryRef
    name: str
    sha: str

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef or type(self.name) is not str or not _IDENTIFIER.fullmatch(self.name):
            raise GitHubContractError("branch name is invalid")
        _validate_sha(self.sha, "branch sha")


@dataclass(frozen=True)
class PullRequestSnapshot:
    repository: RepositoryRef
    pull_request_id: str
    number: int
    state: PullRequestState
    base_ref: str
    base_sha: str
    head_ref: str
    head_sha: str
    draft: bool
    merge_commit_sha: str | None = None

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("pull request repository is invalid")
        _validate_token(self.pull_request_id, "pull request id")
        _validate_number(self.number, "pull request number")
        if type(self.state) is not PullRequestState or type(self.draft) is not bool:
            raise GitHubContractError("pull request state is invalid")
        for value, name in ((self.base_ref, "base reference"), (self.head_ref, "head reference")):
            if type(value) is not str or not _IDENTIFIER.fullmatch(value):
                raise GitHubContractError(f"{name} is invalid")
        _validate_sha(self.base_sha, "base sha")
        _validate_sha(self.head_sha, "head sha")
        if self.state is PullRequestState.MERGED:
            if type(self.merge_commit_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", self.merge_commit_sha):
                raise GitHubContractError("merge commit sha is invalid")
        elif self.merge_commit_sha is not None:
            raise GitHubContractError("unmerged pull request merge commit is invalid")


@dataclass(frozen=True)
class ReviewSnapshot:
    review_id: str
    reviewer_id: str
    state: ReviewState
    commit_sha: str

    def __post_init__(self) -> None:
        _validate_token(self.review_id, "review id")
        _validate_token(self.reviewer_id, "reviewer id")
        if type(self.state) is not ReviewState:
            raise GitHubContractError("review state is invalid")
        _validate_sha(self.commit_sha, "review sha")


@dataclass(frozen=True)
class ReviewsSnapshot:
    repository: RepositoryRef
    pull_request_number: int
    head_sha: str
    reviews: tuple[ReviewSnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("reviews repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.head_sha, "reviews head sha")
        if type(self.reviews) is not tuple or any(type(item) is not ReviewSnapshot for item in self.reviews):
            raise GitHubContractError("reviews snapshot is invalid")
        _unique((item.review_id for item in self.reviews), "review identities")


@dataclass(frozen=True)
class RequestedReviewersSnapshot:
    """Complete, provider-evidenced requested-reviewer state for one PR."""

    repository: RepositoryRef
    pull_request_number: int
    candidate_sha: str
    reviewers: tuple[str, ...]
    reviewer_set_digest: str
    complete: bool
    next_cursor: str | None
    raw_evidence_identity: str

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("requested reviewers repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.candidate_sha, "requested reviewers candidate")
        if type(self.reviewers) is not tuple or any(type(login) is not str or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login) for login in self.reviewers):
            raise GitHubContractError("requested reviewer logins are invalid")
        if tuple(sorted(self.reviewers)) != self.reviewers or len(set(self.reviewers)) != len(self.reviewers):
            raise GitHubContractError("requested reviewer logins are not canonical")
        _validate_digest(self.reviewer_set_digest, "requested reviewer digest")
        if self.reviewer_set_digest != _digest(("reviewers", self.reviewers)):
            raise GitHubContractError("requested reviewer digest does not match logins")
        if type(self.complete) is not bool or (self.complete and self.next_cursor is not None) or (not self.complete and (type(self.next_cursor) is not str or not self.next_cursor)):
            raise GitHubContractError("requested reviewer completeness is invalid")
        _validate_digest(self.raw_evidence_identity, "requested reviewer evidence")


@dataclass(frozen=True)
class CheckSnapshot:
    check_id: str
    name: str
    state: CheckState
    conclusion: CheckConclusion | None
    head_sha: str

    def __post_init__(self) -> None:
        _validate_token(self.check_id, "check id")
        if type(self.name) is not str or not _PUBLIC_TEXT.fullmatch(self.name) or type(self.state) is not CheckState:
            raise GitHubContractError("check snapshot is invalid")
        if self.conclusion is not None and type(self.conclusion) is not CheckConclusion:
            raise GitHubContractError("check conclusion is invalid")
        if (self.state is CheckState.COMPLETED) != (self.conclusion is not None):
            raise GitHubContractError("check completion is invalid")
        _validate_sha(self.head_sha, "check head sha")


@dataclass(frozen=True)
class ChecksSnapshot:
    repository: RepositoryRef
    pull_request_number: int
    head_sha: str
    check_evidence_identity: str
    candidate_evidence_identity: str
    checks: tuple[CheckSnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("checks repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.head_sha, "checks head sha")
        _validate_digest(self.check_evidence_identity, "check evidence")
        _validate_digest(self.candidate_evidence_identity, "check candidate evidence")
        if type(self.checks) is not tuple or any(type(item) is not CheckSnapshot for item in self.checks):
            raise GitHubContractError("checks snapshot is invalid")
        _unique((item.check_id for item in self.checks), "check identities")


@dataclass(frozen=True)
class WorkflowRunSnapshot:
    run_id: str
    workflow_name: str
    state: CheckState
    conclusion: CheckConclusion | None
    head_sha: str

    def __post_init__(self) -> None:
        _validate_token(self.run_id, "workflow run id")
        if type(self.workflow_name) is not str or not _PUBLIC_TEXT.fullmatch(self.workflow_name) or type(self.state) is not CheckState:
            raise GitHubContractError("workflow run snapshot is invalid")
        if self.conclusion is not None and type(self.conclusion) is not CheckConclusion:
            raise GitHubContractError("workflow conclusion is invalid")
        if (self.state is CheckState.COMPLETED) != (self.conclusion is not None):
            raise GitHubContractError("workflow completion is invalid")
        _validate_sha(self.head_sha, "workflow head sha")


@dataclass(frozen=True)
class WorkflowRunsSnapshot:
    repository: RepositoryRef
    pull_request_number: int
    head_sha: str
    workflow_evidence_identity: str
    candidate_evidence_identity: str
    runs: tuple[WorkflowRunSnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("workflow runs repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.head_sha, "workflow runs head sha")
        _validate_digest(self.workflow_evidence_identity, "workflow evidence")
        _validate_digest(self.candidate_evidence_identity, "workflow candidate evidence")
        if type(self.runs) is not tuple or any(type(item) is not WorkflowRunSnapshot for item in self.runs):
            raise GitHubContractError("workflow runs snapshot is invalid")
        _unique((item.run_id for item in self.runs), "workflow run identities")


@dataclass(frozen=True)
class MergeabilitySnapshot:
    repository: RepositoryRef
    pull_request_number: int
    head_sha: str
    mergeability: Mergeability

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("mergeability repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.head_sha, "mergeability head sha")
        if type(self.mergeability) is not Mergeability:
            raise GitHubContractError("mergeability state is invalid")


@dataclass(frozen=True)
class ClosingReferenceSnapshot:
    issue_number: int
    pull_request_number: int
    keyword: str
    head_sha: str

    def __post_init__(self) -> None:
        _validate_number(self.issue_number, "closing issue number")
        _validate_number(self.pull_request_number, "closing pull request number")
        if type(self.keyword) is not str or self.keyword not in {"close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved", "closing-reference"}:
            raise GitHubContractError("closing keyword is invalid")
        _validate_sha(self.head_sha, "closing reference head sha")


@dataclass(frozen=True)
class ClosingReferencesSnapshot:
    repository: RepositoryRef
    pull_request_number: int
    head_sha: str
    references: tuple[ClosingReferenceSnapshot, ...]

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef:
            raise GitHubContractError("closing references repository is invalid")
        _validate_number(self.pull_request_number, "pull request number")
        _validate_sha(self.head_sha, "closing references head sha")
        if type(self.references) is not tuple or any(type(item) is not ClosingReferenceSnapshot for item in self.references):
            raise GitHubContractError("closing references snapshot is invalid")
        _unique(((item.issue_number, item.pull_request_number, item.keyword, item.head_sha) for item in self.references), "closing references")


@dataclass(frozen=True)
class RemoteHeadSnapshot:
    repository: RepositoryRef
    ref: str
    sha: str

    def __post_init__(self) -> None:
        if type(self.repository) is not RepositoryRef or type(self.ref) is not str or not _IDENTIFIER.fullmatch(self.ref):
            raise GitHubContractError("remote head reference is invalid")
        _validate_sha(self.sha, "remote head sha")


GitHubSnapshot: TypeAlias = RepositorySnapshot | IssueSnapshot | CommentsSnapshot | BranchSnapshot | PullRequestSnapshot | ReviewsSnapshot | RequestedReviewersSnapshot | ChecksSnapshot | WorkflowRunsSnapshot | MergeabilitySnapshot | ClosingReferencesSnapshot | RemoteHeadSnapshot


@dataclass(frozen=True)
class GitHubFailure:
    kind: GitHubFailureKind
    operation: GitHubReadOperation | GitHubMutationOperation
    public_reason: str

    def __post_init__(self) -> None:
        if type(self.kind) is not GitHubFailureKind or type(self.operation) not in (GitHubReadOperation, GitHubMutationOperation):
            raise GitHubContractError("GitHub failure is invalid")
        if type(self.public_reason) is not str or not _PUBLIC_TEXT.fullmatch(self.public_reason):
            raise GitHubContractError("GitHub failure reason is invalid")


@dataclass(frozen=True)
class GitHubReadResult:
    request: GitHubReadRequest
    snapshot: GitHubSnapshot | None = None
    failure: GitHubFailure | None = None
    snapshot_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.request) is not GitHubReadRequest or (self.snapshot is None) == (self.failure is None):
            raise GitHubContractError("read result must contain exactly one outcome")
        if self.failure is not None and self.failure.operation is not self.request.operation:
            raise GitHubContractError("read failure operation is invalid")
        if self.snapshot is not None:
            _validate_snapshot_for(self.request, self.snapshot)
            object.__setattr__(self, "snapshot_digest", _digest(_snapshot_payload(self.snapshot)))
        else:
            object.__setattr__(self, "snapshot_digest", "")

    @property
    def ok(self) -> bool:
        return self.snapshot is not None


@dataclass(frozen=True)
class GitHubMutationIntent:
    operation: GitHubMutationOperation
    repository: RepositoryRef
    idempotency_key: str
    target_number: int | None = None
    expected_sha: str | None = None
    target_ref: str | None = None
    payload: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation or type(self.repository) is not RepositoryRef:
            raise GitHubContractError("mutation intent is invalid")
        _validate_token(self.idempotency_key, "idempotency key")
        if self.target_number is not None:
            _validate_number(self.target_number, "mutation target number")
        if self.expected_sha is not None:
            _validate_sha(self.expected_sha, "mutation expected sha")
        if self.target_ref is not None and (type(self.target_ref) is not str or not _IDENTIFIER.fullmatch(self.target_ref)):
            raise GitHubContractError("mutation target reference is invalid")
        number_required = {GitHubMutationOperation.CREATE_PULL_REQUEST, GitHubMutationOperation.COMMENT, GitHubMutationOperation.REQUEST_REVIEW, GitHubMutationOperation.MARK_READY, GitHubMutationOperation.MERGE_PULL_REQUEST, GitHubMutationOperation.CLOSE_ISSUE}
        if self.operation in number_required and self.target_number is None:
            raise GitHubContractError("mutation intent requires a target number")
        if self.operation in {GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH} and self.target_ref is None:
            raise GitHubContractError("branch mutation requires a reference")
        _validate_mutation_payload(self.operation, self.target_number, self.expected_sha, self.target_ref, self.payload)

    def identity(self) -> str:
        return _digest((self.operation.value, self.repository.owner, self.repository.name, self.idempotency_key, self.target_number, self.expected_sha, self.target_ref, self.payload))


@dataclass(frozen=True)
class MutationReceipt:
    intent_identity: str
    operation: GitHubMutationOperation
    disposition: MutationDisposition
    affected_identity: str
    semantic_readback_digest: str

    def __post_init__(self) -> None:
        _validate_digest(self.intent_identity, "intent identity")
        if type(self.operation) is not GitHubMutationOperation or type(self.disposition) is not MutationDisposition:
            raise GitHubContractError("mutation receipt is invalid")
        _validate_token(self.affected_identity, "affected identity")
        _validate_digest(self.semantic_readback_digest, "semantic read-back digest")


@dataclass(frozen=True)
class GitHubMutationResult:
    intent: GitHubMutationIntent
    receipt: MutationReceipt | None = None
    failure: GitHubFailure | None = None

    def __post_init__(self) -> None:
        if type(self.intent) is not GitHubMutationIntent or (self.receipt is None) == (self.failure is None):
            raise GitHubContractError("mutation result must contain exactly one outcome")
        if self.receipt is not None and (self.receipt.operation is not self.intent.operation or self.receipt.intent_identity != self.intent.identity()):
            raise GitHubContractError("mutation receipt does not bind intent")
        if self.failure is not None and self.failure.operation is not self.intent.operation:
            raise GitHubContractError("mutation failure operation is invalid")

    @property
    def ok(self) -> bool:
        return self.receipt is not None and self.receipt.disposition is not MutationDisposition.REJECTED


@dataclass(frozen=True)
class AdapterCall:
    kind: str
    operation: str
    identity: str


class GitHubAdapter(Protocol):
    """The only GitHub boundary usable by a future core state machine."""

    def read(self, request: GitHubReadRequest) -> GitHubReadResult: ...

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult: ...


@dataclass(frozen=True)
class FakeGitHubScenario:
    """Fixture-only deterministic adapter behavior for one operation identity."""

    response: Mapping[str, object] | GitHubSnapshot | None = None
    failure: GitHubFailureKind | None = None
    stale: bool = False
    duplicate_receipt: bool = False
    affected_identity: str = "fixture"
    semantic_readback_digest: str | None = None

    def __post_init__(self) -> None:
        if self.response is not None and self.failure is not None:
            raise GitHubContractError("fake scenario cannot contain response and failure")
        if self.failure is not None and type(self.failure) is not GitHubFailureKind:
            raise GitHubContractError("fake failure is invalid")
        if type(self.stale) is not bool or type(self.duplicate_receipt) is not bool:
            raise GitHubContractError("fake scenario flags are invalid")
        _validate_token(self.affected_identity, "fake affected identity")
        if self.duplicate_receipt != (self.semantic_readback_digest is not None):
            raise GitHubContractError("fake accepted mutation requires one semantic read-back digest")
        if self.semantic_readback_digest is not None:
            _validate_digest(self.semantic_readback_digest, "fake semantic read-back digest")


class FakeGitHubAdapter:
    """Hermetic adapter with call recording and explicit injected outcomes.

    No provider code is hidden behind this fake.  An intent only obtains a
    fixture receipt when the scenario explicitly permits it; otherwise it is
    rejected by policy.  Duplicate receipts preserve the original semantic
    receipt and never create another applied operation.
    """

    def __init__(self, scenarios: Mapping[str, FakeGitHubScenario] | None = None) -> None:
        if scenarios is not None and (type(scenarios) is not dict or any(type(key) is not str or type(value) is not FakeGitHubScenario for key, value in scenarios.items())):
            raise GitHubContractError("fake scenarios are invalid")
        self._scenarios = dict(scenarios or {})
        self.calls: list[AdapterCall] = []
        self._receipts: dict[str, MutationReceipt] = {}

    def read(self, request: GitHubReadRequest) -> GitHubReadResult:
        if type(request) is not GitHubReadRequest:
            raise GitHubContractError("read request is invalid")
        identity = request.identity()
        self.calls.append(AdapterCall("read", request.operation.value, identity))
        scenario = self._scenarios.get(identity)
        if scenario is None:
            return _read_failure(request, GitHubFailureKind.UNAVAILABLE, "fixture has no response")
        if scenario.failure is not None:
            return _read_failure(request, scenario.failure, "fixture injected failure")
        if scenario.stale:
            return _read_failure(request, GitHubFailureKind.STALE_RESPONSE, "fixture response is stale")
        if scenario.response is None:
            return _read_failure(request, GitHubFailureKind.MALFORMED_RESPONSE, "fixture response is missing")
        try:
            snapshot = scenario.response if _is_snapshot(scenario.response) else normalize_github_response(request, scenario.response)
            return GitHubReadResult(request, snapshot=snapshot)
        except GitHubContractError:
            return _read_failure(request, GitHubFailureKind.MALFORMED_RESPONSE, "fixture response is malformed")

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> object:
        """Expose an explicit terminal page for typed hermetic fixtures only."""

        if request.operation not in {GitHubReadOperation.COMMENTS, GitHubReadOperation.REVIEWS} or cursor is not None:
            return None
        result = self.read(request)
        if not result.ok or type(result.snapshot) not in {CommentsSnapshot, ReviewsSnapshot}:
            return None
        # Delayed import avoids making the core contracts depend on the runtime
        # process boundary while still giving tests explicit page metadata.
        from .github_runtime import CollectionPage
        count = len(result.snapshot.comments if type(result.snapshot) is CommentsSnapshot else result.snapshot.reviews)
        return CollectionPage(request, None, None, count, result.snapshot)

    def submit(self, intent: GitHubMutationIntent) -> GitHubMutationResult:
        if type(intent) is not GitHubMutationIntent:
            raise GitHubContractError("mutation intent is invalid")
        identity = intent.identity()
        self.calls.append(AdapterCall("mutation", intent.operation.value, identity))
        scenario = self._scenarios.get(identity)
        if scenario is None:
            return _mutation_failure(intent, GitHubFailureKind.POLICY_DENIED, "fixture rejects mutation intent")
        if scenario.failure is not None:
            return _mutation_failure(intent, scenario.failure, "fixture injected failure")
        if scenario.stale:
            return _mutation_failure(intent, GitHubFailureKind.STALE_RESPONSE, "fixture receipt is stale")
        prior = self._receipts.get(identity)
        if prior is not None:
            return GitHubMutationResult(intent, receipt=MutationReceipt(identity, intent.operation, MutationDisposition.ALREADY_APPLIED, prior.affected_identity, prior.semantic_readback_digest))
        if not scenario.duplicate_receipt:
            return _mutation_failure(intent, GitHubFailureKind.POLICY_DENIED, "fixture mutation execution is disabled")
        assert scenario.semantic_readback_digest is not None
        receipt = MutationReceipt(identity, intent.operation, MutationDisposition.ACCEPTED, scenario.affected_identity, scenario.semantic_readback_digest)
        self._receipts[identity] = receipt
        return GitHubMutationResult(intent, receipt=receipt)

    def call_count(self, *, kind: str | None = None) -> int:
        if kind is not None and kind not in {"read", "mutation"}:
            raise GitHubContractError("call kind is invalid")
        return len(self.calls) if kind is None else sum(call.kind == kind for call in self.calls)


def normalize_github_response(request: GitHubReadRequest, response: Mapping[str, object]) -> GitHubSnapshot:
    """Normalize one untrusted response mapping or reject it before use."""

    if type(request) is not GitHubReadRequest or type(response) is not dict:
        raise GitHubContractError("GitHub response is invalid")
    try:
        operation = request.operation
        if operation is GitHubReadOperation.REPOSITORY:
            _exact_shape(response, {"repository", "id", "default_branch", "default_branch_sha", "repository_evidence_identity", "default_branch_evidence_identity"})
            repository = _repository(response)
            return RepositorySnapshot(
                _string(response, "id"), repository, _string(response, "default_branch"),
                _string(response, "default_branch_sha"), _string(response, "repository_evidence_identity"),
                _string(response, "default_branch_evidence_identity"),
            )
        if operation in {GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS}:
            _exact_shape(response, {"repository", "id", "number", "state", "parent_number", "sub_issue_numbers", "issue_evidence_identity", "relationship_evidence_identity"})
            return IssueSnapshot(
                _repository(response), _string(response, "id"), _integer(response, "number"),
                IssueState(_string(response, "state")), _string(response, "issue_evidence_identity"),
                _string(response, "relationship_evidence_identity"), _optional_integer(response, "parent_number"),
                _integer_tuple(response, "sub_issue_numbers"),
            )
        if operation is GitHubReadOperation.COMMENTS:
            _exact_shape(response, {"repository", "issue_number", "comments"})
            return CommentsSnapshot(_repository(response), _integer(response, "issue_number"), tuple(CommentSnapshot(_string(item, "id"), _string(item, "author_id"), _digest_text(_string(item, "body")), _string(item, "created_at")) for item in _mappings(response, "comments", {"id", "author_id", "body", "created_at"})))
        if operation is GitHubReadOperation.BRANCH:
            _exact_shape(response, {"repository", "ref", "sha"})
            return BranchSnapshot(_repository(response), _string(response, "ref"), _string(response, "sha"))
        if operation is GitHubReadOperation.PULL_REQUEST:
            _exact_shape(response, {"repository", "id", "number", "state", "base_ref", "base_sha", "head_ref", "head_sha", "draft", "merge_commit_sha"})
            return PullRequestSnapshot(_repository(response), _string(response, "id"), _integer(response, "number"), PullRequestState(_string(response, "state")), _string(response, "base_ref"), _string(response, "base_sha"), _string(response, "head_ref"), _string(response, "head_sha"), _boolean(response, "draft"), _optional_string(response, "merge_commit_sha"))
        if operation is GitHubReadOperation.REVIEWS:
            _exact_shape(response, {"repository", "pull_request_number", "head_sha", "reviews"})
            head_sha = _string(response, "head_sha")
            reviews = tuple(ReviewSnapshot(_string(item, "id"), _string(item, "reviewer_id"), ReviewState(_string(item, "state")), _string(item, "commit_sha")) for item in _mappings(response, "reviews", {"id", "reviewer_id", "state", "commit_sha"}))
            _validate_collection_head(head_sha, tuple(item.commit_sha for item in reviews))
            return ReviewsSnapshot(_repository(response), _integer(response, "pull_request_number"), head_sha, reviews)
        if operation is GitHubReadOperation.REQUESTED_REVIEWERS:
            _exact_shape(response, {"repository", "pull_request_number", "candidate_sha", "reviewers", "reviewer_set_digest", "complete", "next_cursor", "raw_evidence_identity"})
            snapshot = RequestedReviewersSnapshot(_repository(response), _integer(response, "pull_request_number"), _string(response, "candidate_sha"), tuple(_strings(response, "reviewers")), _string(response, "reviewer_set_digest"), _boolean(response, "complete"), _optional_string(response, "next_cursor"), _string(response, "raw_evidence_identity"))
            if snapshot.repository != request.repository or snapshot.pull_request_number != request.number or snapshot.candidate_sha != request.expected_sha:
                raise GitHubContractError("requested reviewer identity drifted")
            return snapshot
        if operation is GitHubReadOperation.CHECKS:
            _exact_shape(response, {"repository", "pull_request_number", "head_sha", "check_evidence_identity", "candidate_evidence_identity", "checks"})
            head_sha = _string(response, "head_sha")
            checks = tuple(CheckSnapshot(_string(item, "id"), _string(item, "name"), CheckState(_string(item, "state")), _optional_enum(item, "conclusion", CheckConclusion), _string(item, "head_sha")) for item in _mappings(response, "checks", {"id", "name", "state", "conclusion", "head_sha"}))
            _validate_collection_head(head_sha, tuple(item.head_sha for item in checks))
            return ChecksSnapshot(_repository(response), _integer(response, "pull_request_number"), head_sha, _string(response, "check_evidence_identity"), _string(response, "candidate_evidence_identity"), checks)
        if operation is GitHubReadOperation.WORKFLOW_RUNS:
            _exact_shape(response, {"repository", "pull_request_number", "head_sha", "workflow_evidence_identity", "candidate_evidence_identity", "runs"})
            head_sha = _string(response, "head_sha")
            runs = tuple(WorkflowRunSnapshot(_string(item, "id"), _string(item, "workflow_name"), CheckState(_string(item, "state")), _optional_enum(item, "conclusion", CheckConclusion), _string(item, "head_sha")) for item in _mappings(response, "runs", {"id", "workflow_name", "state", "conclusion", "head_sha"}))
            _validate_collection_head(head_sha, tuple(item.head_sha for item in runs))
            return WorkflowRunsSnapshot(_repository(response), _integer(response, "pull_request_number"), head_sha, _string(response, "workflow_evidence_identity"), _string(response, "candidate_evidence_identity"), runs)
        if operation is GitHubReadOperation.MERGEABILITY:
            _exact_shape(response, {"repository", "pull_request_number", "head_sha", "mergeability"})
            return MergeabilitySnapshot(_repository(response), _integer(response, "pull_request_number"), _string(response, "head_sha"), Mergeability(_string(response, "mergeability")))
        if operation is GitHubReadOperation.CLOSING_REFERENCES:
            _exact_shape(response, {"repository", "pull_request_number", "head_sha", "references"})
            pull_request_number = _integer(response, "pull_request_number")
            head_sha = _string(response, "head_sha")
            references = tuple(ClosingReferenceSnapshot(_integer(item, "issue_number"), _integer(item, "pull_request_number"), _string(item, "keyword"), _string(item, "head_sha")) for item in _mappings(response, "references", {"issue_number", "pull_request_number", "keyword", "head_sha"}))
            if any(item.pull_request_number != pull_request_number for item in references):
                raise GitHubContractError("closing reference pull request is invalid")
            _validate_collection_head(head_sha, tuple(item.head_sha for item in references))
            return ClosingReferencesSnapshot(_repository(response), pull_request_number, head_sha, references)
        if operation is GitHubReadOperation.REMOTE_HEAD:
            _exact_shape(response, {"repository", "ref", "sha"})
            return RemoteHeadSnapshot(_repository(response), _string(response, "ref"), _string(response, "sha"))
    except (KeyError, TypeError, ValueError, GitHubContractError) as error:
        raise GitHubContractError("GitHub response is malformed") from error
    raise GitHubContractError("GitHub operation is unknown")


def _validate_snapshot_for(request: GitHubReadRequest, snapshot: GitHubSnapshot) -> None:
    expected: dict[GitHubReadOperation, type[object]] = {
        GitHubReadOperation.REPOSITORY: RepositorySnapshot,
        GitHubReadOperation.ISSUE: IssueSnapshot,
        GitHubReadOperation.ISSUE_RELATIONSHIPS: IssueSnapshot,
        GitHubReadOperation.COMMENTS: CommentsSnapshot,
        GitHubReadOperation.BRANCH: BranchSnapshot,
        GitHubReadOperation.PULL_REQUEST: PullRequestSnapshot,
        GitHubReadOperation.REVIEWS: ReviewsSnapshot,
        GitHubReadOperation.CHECKS: ChecksSnapshot,
        GitHubReadOperation.WORKFLOW_RUNS: WorkflowRunsSnapshot,
        GitHubReadOperation.MERGEABILITY: MergeabilitySnapshot,
        GitHubReadOperation.CLOSING_REFERENCES: ClosingReferencesSnapshot,
        GitHubReadOperation.REMOTE_HEAD: RemoteHeadSnapshot,
    }
    if type(snapshot) is not expected[request.operation]:
        raise GitHubContractError("snapshot does not match read operation")
    if snapshot.repository != request.repository:
        raise GitHubContractError("snapshot repository does not match request")
    if request.number is not None and hasattr(snapshot, "number") and getattr(snapshot, "number") != request.number:
        raise GitHubContractError("snapshot number does not match request")
    if request.number is not None and hasattr(snapshot, "issue_number") and getattr(snapshot, "issue_number") != request.number:
        raise GitHubContractError("snapshot number does not match request")
    if request.number is not None and hasattr(snapshot, "pull_request_number") and getattr(snapshot, "pull_request_number") != request.number:
        raise GitHubContractError("snapshot number does not match request")
    if request.ref is not None and hasattr(snapshot, "ref") and getattr(snapshot, "ref") != request.ref:
        raise GitHubContractError("snapshot reference does not match request")
    if request.ref is not None and hasattr(snapshot, "name") and getattr(snapshot, "name") != request.ref:
        raise GitHubContractError("snapshot reference does not match request")
    if request.expected_sha is not None:
        observed = _snapshot_sha(snapshot)
        if observed != request.expected_sha:
            raise GitHubContractError("snapshot sha does not match request")


def _snapshot_sha(snapshot: GitHubSnapshot) -> str | None:
    for name in ("sha", "head_sha", "default_branch_sha"):
        value = getattr(snapshot, name, None)
        if type(value) is str:
            return value
    return None


def _snapshot_payload(snapshot: GitHubSnapshot) -> tuple[object, ...]:
    return (type(snapshot).__name__, tuple((name, _public_value(getattr(snapshot, name))) for name in snapshot.__dataclass_fields__))


def _public_value(value: object) -> object:
    if type(value) in (str, int, bool, type(None)):
        return value
    if type(value) is tuple:
        return tuple(_public_value(item) for item in value)
    if isinstance(value, StrEnum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return _snapshot_payload(value)  # type: ignore[arg-type]
    raise GitHubContractError("snapshot value is invalid")


def _read_failure(request: GitHubReadRequest, kind: GitHubFailureKind, reason: str) -> GitHubReadResult:
    return GitHubReadResult(request, failure=GitHubFailure(kind, request.operation, reason))


def _mutation_failure(intent: GitHubMutationIntent, kind: GitHubFailureKind, reason: str) -> GitHubMutationResult:
    return GitHubMutationResult(intent, failure=GitHubFailure(kind, intent.operation, reason))


def _is_snapshot(value: object) -> bool:
    return type(value) in {RepositorySnapshot, IssueSnapshot, CommentsSnapshot, BranchSnapshot, PullRequestSnapshot, ReviewsSnapshot, ChecksSnapshot, WorkflowRunsSnapshot, MergeabilitySnapshot, ClosingReferencesSnapshot, RemoteHeadSnapshot}


def _string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping[key]
    if type(value) is not str:
        raise GitHubContractError("response field is invalid")
    return value


def _optional_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping[key]
    if value is not None and type(value) is not str:
        raise GitHubContractError("response string is invalid")
    return value


def _strings(mapping: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = mapping[key]
    if type(value) is not list or any(type(item) is not str for item in value):
        raise GitHubContractError("response strings are invalid")
    return tuple(value)


def _integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping[key]
    if type(value) is not int:
        raise GitHubContractError("response field is invalid")
    return value


def _optional_integer(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if value is None:
        return None
    if type(value) is not int:
        raise GitHubContractError("response field is invalid")
    return value


def _boolean(mapping: Mapping[str, object], key: str) -> bool:
    value = mapping[key]
    if type(value) is not bool:
        raise GitHubContractError("response field is invalid")
    return value


def _integer_tuple(mapping: Mapping[str, object], key: str) -> tuple[int, ...]:
    value = mapping.get(key, ())
    if type(value) is not list or any(type(item) is not int for item in value):
        raise GitHubContractError("response field is invalid")
    return tuple(value)


def _mappings(mapping: Mapping[str, object], key: str, fields: set[str]) -> tuple[Mapping[str, object], ...]:
    value = mapping[key]
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise GitHubContractError("response collection is invalid")
    for item in value:
        _exact_shape(item, fields)
    return tuple(value)


def _optional_enum(mapping: Mapping[str, object], key: str, enum: type[StrEnum]) -> StrEnum | None:
    value = mapping.get(key)
    if value is None:
        return None
    if type(value) is not str:
        raise GitHubContractError("response field is invalid")
    return enum(value)


def _repository(mapping: Mapping[str, object]) -> RepositoryRef:
    value = mapping["repository"]
    if type(value) is not dict:
        raise GitHubContractError("response repository is invalid")
    _exact_shape(value, {"owner", "name"})
    return RepositoryRef(_string(value, "owner"), _string(value, "name"))


def _exact_shape(mapping: Mapping[str, object], fields: set[str]) -> None:
    if type(mapping) is not dict or set(mapping) != fields:
        raise GitHubContractError("response shape is invalid")


def _validate_collection_head(head_sha: str, nested_shas: tuple[str, ...]) -> None:
    _validate_sha(head_sha, "collection head sha")
    if any(sha != head_sha for sha in nested_shas):
        raise GitHubContractError("collection evidence is not bound to one head")


def _validate_mutation_payload(
    operation: GitHubMutationOperation,
    target_number: int | None,
    expected_sha: str | None,
    target_ref: str | None,
    payload: object,
) -> None:
    if type(payload) is not tuple or any(type(item) is not tuple or len(item) != 2 or any(type(value) is not str for value in item) for item in payload):
        raise GitHubContractError("mutation payload is invalid")
    if tuple(sorted(payload)) != payload or len({key for key, _ in payload}) != len(payload):
        raise GitHubContractError("mutation payload is not canonical")
    values = dict(payload)
    fields = set(values)
    required: dict[GitHubMutationOperation, set[str]] = {
        GitHubMutationOperation.CREATE_BRANCH: set(),
        GitHubMutationOperation.UPDATE_BRANCH: {"previous_sha"},
        GitHubMutationOperation.DELETE_BRANCH: set(),
        GitHubMutationOperation.CREATE_PULL_REQUEST: {"base_ref", "base_sha", "body_digest", "head_ref", "head_sha", "title_digest"},
        GitHubMutationOperation.COMMENT: {"body_digest"},
        GitHubMutationOperation.REQUEST_REVIEW: {"reviewers_digest"},
        GitHubMutationOperation.MARK_READY: set(),
        GitHubMutationOperation.MERGE_PULL_REQUEST: {"method"},
        GitHubMutationOperation.CLOSE_ISSUE: {"reason"},
    }
    if fields != required[operation]:
        raise GitHubContractError("mutation payload fields are invalid")
    if operation is GitHubMutationOperation.CREATE_BRANCH:
        if target_number is not None or expected_sha is None:
            raise GitHubContractError("branch creation identity is invalid")
    elif operation is GitHubMutationOperation.UPDATE_BRANCH:
        if target_number is not None or expected_sha is None:
            raise GitHubContractError("branch update identity is invalid")
        _validate_sha(values["previous_sha"], "branch previous sha")
    elif operation is GitHubMutationOperation.DELETE_BRANCH:
        if target_number is not None or expected_sha is None:
            raise GitHubContractError("branch deletion identity is invalid")
    elif operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
        if target_number is None or expected_sha is not None or target_ref is not None:
            raise GitHubContractError("pull request creation identity is invalid")
        for field in ("base_ref", "head_ref"):
            if not _IDENTIFIER.fullmatch(values[field]):
                raise GitHubContractError("pull request payload reference is invalid")
        _validate_sha(values["base_sha"], "pull request base sha")
        _validate_sha(values["head_sha"], "pull request head sha")
        _validate_digest(values["title_digest"], "pull request title digest")
        _validate_digest(values["body_digest"], "pull request body digest")
    elif operation is GitHubMutationOperation.COMMENT:
        if expected_sha is not None or target_ref is not None:
            raise GitHubContractError("comment identity is invalid")
        _validate_digest(values["body_digest"], "comment body digest")
    elif operation is GitHubMutationOperation.REQUEST_REVIEW:
        if expected_sha is None or target_ref is not None:
            raise GitHubContractError("review request identity is invalid")
        _validate_digest(values["reviewers_digest"], "reviewers digest")
    elif operation is GitHubMutationOperation.MARK_READY:
        if expected_sha is None or target_ref is not None:
            raise GitHubContractError("ready conversion identity is invalid")
    elif operation is GitHubMutationOperation.MERGE_PULL_REQUEST:
        if expected_sha is None or target_ref is not None or values["method"] not in {"merge", "squash", "rebase"}:
            raise GitHubContractError("merge payload is invalid")
    elif operation is GitHubMutationOperation.CLOSE_ISSUE:
        if expected_sha is not None or target_ref is not None or values["reason"] not in {"COMPLETED", "NOT_PLANNED"}:
            raise GitHubContractError("issue close payload is invalid")


def _validate_sha(value: object, name: str) -> None:
    if type(value) is not str or not _SHA.fullmatch(value):
        raise GitHubContractError(f"{name} is invalid")


def _validate_digest(value: object, name: str) -> None:
    if type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise GitHubContractError(f"{name} is invalid")


def _validate_token(value: object, name: str) -> None:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise GitHubContractError(f"{name} is invalid")


def _validate_number(value: object, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise GitHubContractError(f"{name} is invalid")


def _validate_numbers(values: object, name: str) -> None:
    if type(values) is not tuple or any(type(item) is not int or item <= 0 for item in values):
        raise GitHubContractError(f"{name} are invalid")
    _unique(values, name)


def _unique(values: object, name: str) -> None:
    collected = tuple(values)
    if len(collected) != len(set(collected)):
        raise GitHubContractError(f"{name} are not unique")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _digest_text(value: str) -> str:
    if not _COMMENT_TEXT.fullmatch(value):
        raise GitHubContractError("response text is invalid")
    return _digest(("comment-body", value))
