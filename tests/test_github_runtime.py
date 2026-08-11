"""Hermetic coverage for the ``gh`` process seam and mutation broker."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from uuid import UUID

from roundwright.deployment import (
    AuthorityReceiptStatus, AuthorityReceiptVerification, DeploymentAuthorityDecision,
    DeploymentAuthorityReceipt, DeploymentIdentity, DeploymentMode,
    _receipt_binding_fingerprint, evaluate_deployment_authority,
)
from roundwright.dependency_policy import BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent, DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition, PolicyTransitionKind, TrustedDependencyAdmission, VersionRange
from roundwright.github import (
    CommentSnapshot,
    CommentsSnapshot,
    FakeGitHubAdapter,
    FakeGitHubScenario,
    GitHubFailureKind,
    GitHubMutationIntent,
    GitHubMutationOperation,
    GitHubReadOperation,
    GitHubReadRequest,
    MutationDisposition,
    RepositoryRef,
    RequestedReviewersSnapshot,
)
from roundwright.github_runtime import (
    CapabilityState,
    BrokerMutationCommand,
    CollectionPage,
    CreatedResourceLocator,
    _GhCommandResult as GhCommandResult,
    DurableMutationJournal,
    _OwnerGitHubReadHostEndpoint as _OwnerGitHubReadHostEndpoint,
    _OwnerGitHubReadControl as _OwnerGitHubReadControl,
    _OwnerGitHubMutationControl as _OwnerGitHubMutationControl,
    _OwnerGitHubBrokerMutationControl as _OwnerGitHubBrokerMutationControl,
    GhMutationPayload,
    GitHubCapabilityHealth,
    GitHubMutationBroker,
    JournalLifecycle,
    MutationJournalEntry,
    MutationBrokerContext,
    OwnerMutationFact,
    OwnerMutationAcceptedFact,
    OwnerMutationHostEndpoint,
    OwnerMutationIpcClient,
    OwnerMutationIpcMessage,
    OwnerMutationIpcReply,
    OwnerMutationRequest,
    OwnerMutationSealRecord,
    OwnerGitHubReadIpcClient,
    OwnerFixedMutationCommand,
    OwnerFixedMutationHostExecutor,
    InMemoryOwnerMutationControlRegistry,
    InMemoryOwnerMutationSealRegistry,
    OperationHealth,
    SemanticPostcondition,
    SemanticReadback,
    _broker_semantic_plan,
    _complete_broker_read,
    _pre_dispatch_reads_identity,
    _GhBrokerExecutor,
    _validate_created_resource_locator,
    schema_v2_authorization_bundle,
    unavailable_capability_health,
)
from roundwright.repository_policy import (
    GITHUB_REPOSITORY_OPERATION,
    RepositoryDispatcherTransition,
    RepositoryActivationReceipt,
    RepositoryMutationContext,
    RepositoryMutationOperation,
    RepositoryPolicySource,
    RepositoryReceiptStatus,
    RepositoryReceiptVerification,
    RepositoryMutationPolicy,
    StandingRepositoryAuthority,
    TrustedRepositoryPolicySnapshot,
    evaluate_repository_mutation_policy,
)
from roundwright.runtime_binding import RuntimeBinding


SHA = "a" * 40
BASE = "b" * 40
DIGEST = "sha256:" + "c" * 64
COMMENT_DIGEST = "sha256:" + hashlib.sha256(
    json.dumps(("comment-body", "curated evidence"), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
).hexdigest()
REPOSITORY = RepositoryRef("example", "roundwright")
NOW = datetime(2026, 8, 7, tzinfo=timezone.utc)


def owner_read_binding() -> CandidateBinding:
    return CandidateBinding(REPOSITORY.slug, "github-read-host", SHA)


def owner_mutation_binding(candidate_sha: str = SHA) -> CandidateBinding:
    return CandidateBinding(REPOSITORY.slug, "github-mutation-host", candidate_sha)


def owner_broker_binding(candidate_sha: str = SHA) -> CandidateBinding:
    return CandidateBinding(REPOSITORY.slug, "7" * 64, candidate_sha)


def GhGitHubAdapter(
    runner: Runner, matrix: GitHubCapabilityHealth | None = None, *, clock=lambda: NOW,
) -> _OwnerGitHubReadHostEndpoint:
    """Construct the credentialed host only with a hermetic owner clock."""

    try:
        observed_at = clock()
    except Exception:
        observed_at = NOW
    control_now = observed_at if type(observed_at) is datetime and observed_at.tzinfo is timezone.utc else NOW
    binding = owner_read_binding()
    return _OwnerGitHubReadHostEndpoint(runner, binding, owner_read_control(binding=binding, now=control_now), matrix, clock=clock)


class Runner:
    def __init__(self, *results: GhCommandResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult:
        self.calls.append(arguments)
        return self.results.pop(0)


def owner_read_control(
    *, binding: CandidateBinding | None = None, now: datetime = NOW,
) -> _OwnerGitHubReadControl:
    """Build only test-owned sealed read evidence; role clients never receive it."""

    digest = lambda value: "sha256:" + value * 64
    candidate_binding = binding or owner_read_binding()
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", digest("5"), digest("6")),
    )
    policy = DependencyPolicy(candidate_binding, digest("9"), int(now.timestamp()), 3600, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("a"), authority_digest=digest("b"))
    policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
    observations = tuple(
        ObservedDependency(candidate_binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, int(now.timestamp()), policy.policy_digest)
        for item in components
    )
    return _OwnerGitHubReadControl(
        candidate_binding,
        DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(candidate_binding, policy.core_fingerprint, receipt.receipt_digest, digest("a"), digest("b"))),
        int(now.timestamp()),
    )


class OwnerTransport:
    def __init__(self, accepted: bool = True, created_resource: CreatedResourceLocator | None = None) -> None:
        self.accepted = accepted
        self.created_resource = created_resource
        self.requests: list[OwnerMutationRequest] = []
        self.commands: list[OwnerFixedMutationCommand] = []

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact | OwnerMutationAcceptedFact:
        self.requests.append(request)
        identity = request.identity
        if not self.accepted:
            return OwnerMutationFact(False, identity)
        locator: CreatedResourceLocator | None = None
        if request.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
            locator = CreatedResourceLocator(
                request.operation, request.repository, pull_request_number=58,
                pull_request_id="pr-58",
                base_sha=request.base_sha, head_sha=request.head_sha, draft=True,
                marker_digest=request.marker_digest,
            )
        elif request.operation is GitHubMutationOperation.COMMENT:
            locator = CreatedResourceLocator(
                request.operation, request.repository, issue_number=request.target_number,
                comment_id="comment-46", marker_digest=request.marker_digest,
            )
        if self.created_resource is not None:
            locator = self.created_resource
        return OwnerMutationAcceptedFact(identity, request.operation, locator)

    def execute_fixed_command(
        self, command: OwnerFixedMutationCommand, record: OwnerMutationSealRecord,
    ) -> OwnerMutationAcceptedFact:
        self.commands.append(command)
        result = self.dispatch(record.request)
        assert type(result) is OwnerMutationAcceptedFact
        return result


def owner_mutation_control(
    request: OwnerMutationRequest, *, now: datetime = NOW,
    binding: CandidateBinding | None = None, operation: GitHubMutationOperation | None = None,
) -> _OwnerGitHubMutationControl:
    """Build test-only sealed fixed-host evidence; no role client receives it."""

    digest = lambda value: "sha256:" + value * 64
    candidate_binding = binding or owner_mutation_binding(request.candidate_sha)
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", digest("5"), digest("6")),
    )
    policy = DependencyPolicy(candidate_binding, digest("9"), int(now.timestamp()), 3600, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("a"), authority_digest=digest("b"))
    policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
    observations = tuple(
        ObservedDependency(candidate_binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, int(now.timestamp()), policy.policy_digest)
        for item in components
    )
    return _OwnerGitHubMutationControl(
        request.identity, candidate_binding, operation or request.operation,
        DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(candidate_binding, policy.core_fingerprint, receipt.receipt_digest, digest("a"), digest("b"))),
        int(now.timestamp()),
    )


class FixtureOwnerMutationControlRegistry:
    """Test-only control source; production hosts receive a fixed registry."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def resolve(self, request: OwnerMutationRequest) -> _OwnerGitHubMutationControl:
        return owner_mutation_control(request, now=self.now)


def owner_broker_control(
    intent: GitHubMutationIntent, *, now: datetime = NOW,
    binding: CandidateBinding | None = None, operation: GitHubMutationOperation | None = None,
) -> _OwnerGitHubBrokerMutationControl:
    """Build test-only sealed broker evidence; role callers cannot receive it."""

    digest = lambda value: "sha256:" + value * 64
    candidate_binding = binding or owner_broker_binding()
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", digest("5"), digest("6")),
    )
    policy = DependencyPolicy(candidate_binding, digest("9"), int(now.timestamp()), 3600, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("a"), authority_digest=digest("b"))
    policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
    observations = tuple(
        ObservedDependency(candidate_binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, int(now.timestamp()), policy.policy_digest)
        for item in components
    )
    return _OwnerGitHubBrokerMutationControl(
        intent.identity(), candidate_binding, operation or intent.operation,
        DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(candidate_binding, policy.core_fingerprint, receipt.receipt_digest, digest("a"), digest("b"))),
        int(now.timestamp()),
    )


class FixtureOwnerBrokerMutationControlRegistry:
    """Test-only pre-provisioned source; the production constructor requires it."""

    def __init__(self, binding: CandidateBinding, clock=lambda: NOW) -> None:
        self.binding = binding
        self.clock = clock

    def resolve(self, intent: GitHubMutationIntent) -> _OwnerGitHubBrokerMutationControl:
        return owner_broker_control(intent, binding=self.binding, now=self.clock())


def owner_broker_controls(*, binding: CandidateBinding | None = None, clock=lambda: NOW) -> FixtureOwnerBrokerMutationControlRegistry:
    return FixtureOwnerBrokerMutationControlRegistry(binding or owner_broker_binding(), clock)


class FixtureOwnerSealRegistry:
    """Hermetic endpoint registry; production registry records are pre-provisioned."""

    def resolve_and_consume(self, request: OwnerMutationRequest) -> OwnerMutationSealRecord:
        return OwnerMutationSealRecord(
            request, request.intent_identity, request.authorization_bundle_identity,
            request.deployment_identity, request.semantic_plan_identity,
            request.journal_identity, request.pre_state_identity,
            request.evaluated_at, request.fresh_until, request.time_identity,
            request.capability_health_identity,
            request.operation, request.repository, request.candidate_sha,
            request.idempotency_identity, request.command,
        )


class ReadIpcChannel:
    """Hermetic typed IPC double; it exposes snapshots, never raw results."""

    def __init__(self, endpoint: GhGitHubAdapter) -> None:
        self._endpoint = endpoint
        self.calls = 0

    def exchange_read(self, request: GitHubReadRequest):
        self.calls += 1
        return self._endpoint.read(request)

    def exchange_collection_page(self, request: GitHubReadRequest, cursor: str | None):
        self.calls += 1
        return self._endpoint.read_collection_page(request, cursor)


def owner_endpoint(
    transport: OwnerTransport | None = None, *, clock=lambda: NOW,
) -> OwnerMutationIpcClient:
    host = transport or OwnerTransport()
    try:
        observed_at = clock()
    except Exception:
        observed_at = NOW
    control_now = observed_at if type(observed_at) is datetime and observed_at.tzinfo is timezone.utc else NOW
    binding = owner_mutation_binding()
    endpoint = OwnerMutationHostEndpoint(
        FixtureOwnerSealRegistry(), OwnerFixedMutationHostExecutor(host, binding), binding, FixtureOwnerMutationControlRegistry(control_now), clock=clock,
    )
    return OwnerMutationIpcClient(DIGEST, endpoint)


def owner_read_endpoint(
    runner: Runner, matrix: GitHubCapabilityHealth, *, clock=lambda: NOW,
) -> OwnerGitHubReadIpcClient:
    return OwnerGitHubReadIpcClient(matrix, ReadIpcChannel(GhGitHubAdapter(runner, matrix, clock=clock)))


def sealed_owner_request(*, evaluated_at: datetime = NOW, fresh_until: datetime | None = None) -> OwnerMutationRequest:
    evaluated_text = evaluated_at.isoformat()
    expires_at = (evaluated_at + timedelta(minutes=5) if fresh_until is None else fresh_until).isoformat()
    time_identity = "sha256:" + hashlib.sha256(
        json.dumps((evaluated_text, expires_at), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
    ).hexdigest()
    return OwnerMutationRequest(
        DIGEST, GitHubMutationOperation.COMMENT, DIGEST, DIGEST, DIGEST, REPOSITORY,
        46, marker_digest=COMMENT_DIGEST, candidate_sha=SHA,
        idempotency_identity=DIGEST, command=BrokerMutationCommand.COMMENT,
        deployment_identity="a" * 64, pre_state_identity=DIGEST,
        evaluated_at=evaluated_text, fresh_until=expires_at, time_identity=time_identity,
        capability_health_identity=DIGEST,
    )


def sealed_owner_record(request: OwnerMutationRequest) -> OwnerMutationSealRecord:
    return OwnerMutationSealRecord(
        request, request.intent_identity, request.authorization_bundle_identity,
        request.deployment_identity, request.semantic_plan_identity,
        request.journal_identity, request.pre_state_identity,
        request.evaluated_at, request.fresh_until, request.time_identity,
        request.capability_health_identity,
        request.operation, request.repository, request.candidate_sha,
        request.idempotency_identity, request.command,
    )


class PagedFakeGitHubAdapter(FakeGitHubAdapter):
    """Hermetic typed collection-page fixture; it never invokes a provider."""

    def __init__(self, scenarios: dict[str, FakeGitHubScenario], pages: dict[str | None, object]) -> None:
        super().__init__(scenarios)
        self.pages = pages
        self.page_requests: list[tuple[GitHubReadRequest, str | None]] = []

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> object:
        self.page_requests.append((request, cursor))
        return self.pages.get(cursor)


def health(
    *available: object, observed_at: datetime = NOW, fresh_until: datetime | None = None,
) -> GitHubCapabilityHealth:
    return GitHubCapabilityHealth(
        tuple(
            OperationHealth(
                operation, CapabilityState.AVAILABLE if operation in available else CapabilityState.UNAVAILABLE,
                observed_at, "sha256:" + hashlib.sha256(str(index).encode("utf-8")).hexdigest(), fresh_until,
            )
            for index, operation in enumerate((*GitHubReadOperation, *GitHubMutationOperation))
        )
    )


def comments_request(number: int = 46) -> GitHubReadRequest:
    return GitHubReadRequest(GitHubReadOperation.COMMENTS, REPOSITORY, number=number)


def reviews_request() -> GitHubReadRequest:
    return GitHubReadRequest(GitHubReadOperation.REVIEWS, REPOSITORY, number=46, expected_sha=SHA)


def comments_payload() -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "issue_number": 46,
        "target_kind": "ISSUE",
        "comments": [{"id": "comment-46", "author_id": "owner-1", "body": "curated evidence", "created_at": "2026-08-07T00:00:00Z"}],
    }


def comment_locator(*, comment_id: str = "comment-46", marker_digest: str = COMMENT_DIGEST) -> CreatedResourceLocator:
    return CreatedResourceLocator(
        GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
        comment_id=comment_id, marker_digest=marker_digest,
    )


def checkpointed_journal_entry(
    intent: GitHubMutationIntent, context: MutationBrokerContext,
    lifecycle: JournalLifecycle, *, locator: CreatedResourceLocator | None = None,
) -> MutationJournalEntry:
    """Build only legal durable checkpoints for recovery-contract tests."""

    plan = _broker_semantic_plan(intent)
    entry = MutationJournalEntry.from_evidence(
        intent, context, schema_v2_authorization_bundle(context), plan,
    )
    with tempfile.TemporaryDirectory() as directory:
        journal = DurableMutationJournal(Path(directory) / "journal.json")
        claimed, _ = journal.claim(entry)
        if lifecycle is JournalLifecycle.CLAIMED:
            return claimed
        captured = journal.transition(
            claimed, JournalLifecycle.PRESTATE_CAPTURED,
            pre_state_digest=DIGEST, pre_state_completeness_identity=DIGEST,
        )
        if lifecycle is JournalLifecycle.PRESTATE_CAPTURED:
            return captured
        started = journal.transition(captured, JournalLifecycle.EXECUTION_STARTED)
        if lifecycle is JournalLifecycle.EXECUTION_STARTED:
            return started
        accepted = journal.transition(
            started, JournalLifecycle.TRANSPORT_ACCEPTED,
            created_resource=locator,
        )
        if lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
            return accepted
        applied = journal.transition(accepted, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
        if lifecycle is JournalLifecycle.APPLIED_AWAITING_VERIFICATION:
            return applied
        if lifecycle is JournalLifecycle.AMBIGUOUS:
            return journal.transition(applied, JournalLifecycle.AMBIGUOUS)
    raise AssertionError("test helper cannot fabricate a verified journal entry")


def repository_payload() -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "id": "repository-1", "default_branch": "main", "default_branch_sha": BASE,
        "repository_evidence_identity": DIGEST,
        "default_branch_evidence_identity": "sha256:" + "d" * 64,
    }


def branch_payload(*, ref: str, sha: str, repository: RepositoryRef = REPOSITORY) -> dict[str, object]:
    """The normalized proof returned for a broker-owned pre-dispatch ref read."""

    return {
        "repository": {"owner": repository.owner, "name": repository.name},
        "ref": ref,
        "sha": sha,
    }


def gh_repository_metadata(*, default_branch: str = "main", full_name: str = "example/roundwright") -> dict[str, object]:
    return {
        "id": 1, "name": "roundwright", "full_name": full_name,
        "owner": {"login": "example"}, "default_branch": default_branch,
    }


def gh_default_branch(*, name: str = "main", sha: str = BASE, repository: str = "example/roundwright", include_commit: bool = True, include_url: bool = True) -> dict[str, object]:
    branch: dict[str, object] = {"name": name}
    if include_commit:
        commit: dict[str, object] = {"sha": sha}
        if include_url:
            commit["url"] = f"https://api.github.com/repos/{repository}/commits/{sha}"
        branch["commit"] = commit
    return branch


def gh_issue_metadata(*, parent_number: int | None = None, child_total: int | None = None, state: str = "open", repository: str = "example/roundwright", number: int = 46) -> dict[str, object]:
    item: dict[str, object] = {
        "id": f"issue-{number}", "number": number, "state": state,
        "repository_url": f"https://api.github.com/repos/{repository}",
        "url": f"https://api.github.com/repos/{repository}/issues/{number}",
        "html_url": f"https://github.com/{repository}/issues/{number}",
    }
    if parent_number is not None:
        item["parent_issue_url"] = f"https://api.github.com/repos/{repository}/issues/{parent_number}"
    if child_total is not None:
        item["sub_issues_summary"] = {"total": child_total, "completed": 0, "percent_completed": 0}
    return item


def gh_issue_relationship_page(*children: int, total: int | None = None, next_cursor: str | None = None, repository: str = "example/roundwright", number: int = 46) -> dict[str, object]:
    count = len(children) if total is None else total
    owner, name = repository.split("/", 1)
    return {
        "data": {"repository": {
            "name": name, "owner": {"login": owner},
            "issue": {"number": number, "subIssues": {
                "totalCount": count, "nodes": [{"number": child} for child in children],
                "pageInfo": {"hasNextPage": next_cursor is not None, "endCursor": next_cursor},
            }},
        }},
    }


def gh_candidate_pull_request(*, number: int = 46, head_sha: str = SHA, base_repository: str = "example/roundwright", head_repository: str = "example/roundwright") -> dict[str, object]:
    return {
        "number": number,
        "base": {"repo": {"full_name": base_repository}},
        "head": {"sha": head_sha, "repo": {"full_name": head_repository}},
    }


def gh_checks_page(*, total: int | None = None, head_sha: str = SHA, suite_sha: str | None = SHA) -> dict[str, object]:
    run: dict[str, object] = {
        "id": 1, "name": "tests", "status": "completed", "conclusion": "success", "head_sha": head_sha,
    }
    if suite_sha is not None:
        run["check_suite"] = {"head_sha": suite_sha}
    return {"total_count": 1 if total is None else total, "check_runs": [] if total == 0 else [run]}


def gh_workflow_page(*, total: int | None = None, head_sha: str = SHA, repository: str = "example/roundwright", head_repository: str = "example/roundwright", pull_request_number: int = 46, pull_request_head: str = SHA) -> dict[str, object]:
    run = {
        "id": 1, "name": "tests", "status": "completed", "conclusion": "success", "head_sha": head_sha,
        "repository": {"full_name": repository}, "head_repository": {"full_name": head_repository},
        "pull_requests": [{"number": pull_request_number, "head": {"sha": pull_request_head}}],
    }
    return {"total_count": 1 if total is None else total, "workflow_runs": [] if total == 0 else [run]}


def pull_request_intent() -> tuple[GitHubMutationIntent, GhMutationPayload]:
    title, body = "draft title", "draft body"
    title_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-title", title), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    body_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-body", body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    return (
        GitHubMutationIntent(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "allocate-pr-46",
            target_number=46,
            payload=(("base_ref", "main"), ("base_sha", BASE), ("body_digest", body_digest),
                     ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", title_digest)),
        ),
        GhMutationPayload(GitHubMutationOperation.CREATE_PULL_REQUEST, (("body", body), ("title", title))),
    )


def pull_request_payload(
    *, number: int = 58, pull_request_id: str | None = None,
    base_sha: str = BASE, head_sha: str = SHA, draft: bool = True,
    state: str = "OPEN", merge_commit_sha: str | None = None,
    base_repository: str = "example/roundwright",
    head_repository: str = "example/roundwright",
) -> dict[str, object]:
    base_owner, base_name = base_repository.split("/", 1)
    head_owner, head_name = head_repository.split("/", 1)
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "base_repository": {"owner": base_owner, "name": base_name},
        "head_repository": {"owner": head_owner, "name": head_name}, "id": pull_request_id or f"pr-{number}",
        "number": number, "state": state, "base_ref": "main", "base_sha": base_sha,
        "head_ref": "codex/issue-46", "head_sha": head_sha, "draft": draft,
        "merge_commit_sha": merge_commit_sha,
    }


def gh_comments_page(
    *, present: bool = True, next_cursor: str | None = None, total: int | None = None,
    identifier: str = "comment-46", identifiers: tuple[str, ...] | None = None,
    target_kind: str = "Issue", number: int = 46, repository: str = "example/roundwright",
) -> dict[str, object]:
    count = (1 if present else 0) if total is None else total
    owner, name = repository.split("/", 1)
    comment_identifiers = identifiers if identifiers is not None else ((identifier,) if present else ())
    return {
        "data": {"repository": {
            "name": name, "owner": {"login": owner},
            "issueOrPullRequest": {"__typename": target_kind, "number": number, "comments": {
                "totalCount": count,
                "nodes": [{"id": item, "author": {"__typename": "User", "login": "OctoCat"}, "body": "curated evidence", "createdAt": "2026-08-07T00:00:00Z"} for item in comment_identifiers],
                "pageInfo": {"hasNextPage": next_cursor is not None, "endCursor": next_cursor},
            }},
        }},
    }


def gh_reviews_page(*, present: bool = True, next_cursor: str | None = None, total: int | None = None, identifier: str = "review-46") -> dict[str, object]:
    count = (1 if present else 0) if total is None else total
    return {
        "data": {"repository": {
            "name": "roundwright", "owner": {"login": "example"},
            "pullRequest": {"number": 46, "headRefOid": SHA, "reviews": {
                "totalCount": count,
                "nodes": ([] if not present else [{"id": identifier, "author": {"__typename": "Bot", "login": "Build-Bot"}, "state": "APPROVED", "commit": {"oid": SHA}}]),
                "pageInfo": {"hasNextPage": next_cursor is not None, "endCursor": next_cursor},
            }},
        }},
    }


def gh_requested_reviewers_page(*reviewers: str, next_cursor: str | None = None, total: int | None = None) -> dict[str, object]:
    count = len(reviewers) if total is None else total
    return {
        "data": {"repository": {
            "name": "roundwright", "owner": {"login": "example"},
            "pullRequest": {"number": 46, "headRefOid": SHA, "reviewRequests": {
                "totalCount": count,
                "nodes": [{"requestedReviewer": {"__typename": "User", "login": reviewer}} for reviewer in reviewers],
                "pageInfo": {"hasNextPage": next_cursor is not None, "endCursor": next_cursor},
            }},
        }},
    }


def comment(identifier: str, body_digest: str = COMMENT_DIGEST) -> CommentSnapshot:
    return CommentSnapshot(identifier, "owner-1", body_digest, "2026-08-07T00:00:00Z")


def comments_page(
    cursor: str | None, next_cursor: str | None, total: int, *items: CommentSnapshot,
    request: GitHubReadRequest | None = None,
) -> CollectionPage:
    actual_request = request or comments_request()
    return CollectionPage(actual_request, cursor, next_cursor, total, CommentsSnapshot(REPOSITORY, 46, "ISSUE", items))


def allowed_context(
    operation: RepositoryMutationOperation = RepositoryMutationOperation.ISSUE_COMMENT, *, now: datetime = NOW,
) -> MutationBrokerContext:
    document = RepositoryMutationPolicy(2, True, True, True, True, True, True, True, True, True, True, True, True)
    snapshot = TrustedRepositoryPolicySnapshot(RepositoryPolicySource("0" * 64, "1" * 64), document)
    mutation_context = RepositoryMutationContext("5" * 64, "6" * 64, "7" * 64, SHA)
    transition = RepositoryDispatcherTransition("8" * 64, mutation_context.repository_fingerprint, mutation_context.deployment_fingerprint, mutation_context.candidate_sha, False, True, True)
    receipt = RepositoryActivationReceipt(
        "3" * 64, "4" * 64, snapshot.source.source_fingerprint, snapshot.source.revision_fingerprint,
        snapshot.policy_digest, document.schema_version, mutation_context.repository_fingerprint,
        mutation_context.deployment_fingerprint, mutation_context.task_fingerprint, mutation_context.candidate_sha,
        transition.digest, now, now + timedelta(hours=1),
    )
    standing = StandingRepositoryAuthority(document)
    verification = RepositoryReceiptVerification("a" * 64, receipt.receipt_fingerprint, receipt.binding_digest, RepositoryReceiptStatus.FRESH)
    policy = evaluate_repository_mutation_policy(
        snapshot, receipt, mutation_context, operation, standing_authority=standing,
        dispatcher_transition=transition, receipt_verification=verification, now=now,
    )
    assert policy.authorized
    runtime = RuntimeBinding("roundwright-runtime/v1", DIGEST, "sha256:" + "d" * 64, ("sha256:" + "e" * 64,))
    deployment_identity = DeploymentIdentity(
        mutation_context.repository_fingerprint, "9" * 64, "a" * 64,
        UUID("12345678-1234-5678-1234-567812345678"), mutation_context.deployment_fingerprint, runtime,
    )
    deployment_receipt = DeploymentAuthorityReceipt("f" * 64, deployment_identity, DeploymentMode.AUTHORITATIVE, now - timedelta(minutes=1), now + timedelta(minutes=1))
    deployment_verification = AuthorityReceiptVerification(
        deployment_receipt.receipt_fingerprint, _receipt_binding_fingerprint(deployment_receipt),
        deployment_identity.repository_fingerprint, deployment_identity.state_id,
        deployment_identity.deployment_fingerprint, AuthorityReceiptStatus.FRESH, runtime,
    )
    deployment = evaluate_deployment_authority(deployment_identity, deployment_receipt, deployment_verification, now=now)
    assert deployment.authorized
    dependency_digest = lambda value: "sha256:" + value * 64
    dependency_binding = CandidateBinding(REPOSITORY.slug, mutation_context.task_fingerprint, SHA)
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", dependency_digest("1"), dependency_digest("2")),
        ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME, "codex-sdk", VersionRange("1.0.0", "2.0.0"), "registry/codex-sdk", dependency_digest("3"), dependency_digest("4")),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", dependency_digest("5"), dependency_digest("6")),
        ComponentPolicy(DependencyComponent.BUILD_BACKEND, "setuptools", VersionRange("69.0.0", "70.0.0"), "pypi/setuptools", dependency_digest("7"), dependency_digest("8")),
    )
    dependency_policy = DependencyPolicy(dependency_binding, dependency_digest("9"), int(now.timestamp()), 3600, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    dependency_receipt = BootstrapPolicyReceipt.create(dependency_policy, reviewer_identity=dependency_digest("a"), authority_digest=dependency_digest("b"))
    dependency_policy = replace(dependency_policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, dependency_receipt))
    dependency_control = DependencyExecutionControl(dependency_policy, tuple(ObservedDependency(dependency_binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, int(now.timestamp()), dependency_policy.policy_digest) for item in components), TrustedDependencyAdmission(dependency_binding, dependency_policy.core_fingerprint, dependency_receipt.receipt_digest, dependency_digest("a"), dependency_digest("b")))
    return MutationBrokerContext(
        policy, deployment, DIGEST, BASE, SHA, DIGEST, standing, verification,
        mutation_context, transition, snapshot, receipt, deployment_identity,
        deployment_receipt, deployment_verification, now, REPOSITORY,
        REPOSITORY, REPOSITORY, "main", "codex/issue-46", dependency_control,
    )


class GitHubRuntimeTests(unittest.TestCase):
    def test_missing_dependency_control_blocks_before_reads_journal_or_transport(self) -> None:
        intent, payload = pull_request_intent()
        context = replace(allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR), dependency_control=None)
        matrix = health(
            GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
            GitHubMutationOperation.CREATE_PULL_REQUEST,
        )
        with tempfile.TemporaryDirectory() as directory:
            journal_path = Path(directory) / "journal.json"
            adapter, transport = FakeGitHubAdapter({}), OwnerTransport()
            result = GitHubMutationBroker(
                adapter, journal=DurableMutationJournal(journal_path),
                _executor=_GhBrokerExecutor(transport, matrix),
            ).submit(intent, context, payload=payload)
            self.assertFalse(result.ok)
            self.assertEqual(adapter.call_count(kind="read"), 0)
            self.assertEqual(transport.requests, [])
            self.assertFalse(journal_path.exists())

    def test_invalid_context_dependency_precedes_broker_clock_and_owner_control_callbacks(self) -> None:
        """Submit and reconcile reject context evidence before every broker callback."""

        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "context-ordering-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        base = allowed_context()
        assert base.dependency_control is not None
        control = base.dependency_control
        stale_observations = tuple(replace(item, observed_at=int(NOW.timestamp()) - 3_601) for item in control.observations)
        missing_stage = DependencyExecutionControl(control.policy, control.observations[:2], control.admission)
        replaced = replace(base)
        object.__setattr__(replaced, "dependency_control", object())
        contexts = (
            replace(base, dependency_control=None),
            replaced,
            replace(base, dependency_control=DependencyExecutionControl(control.policy, stale_observations, control.admission)),
            replace(base, dependency_control=missing_stage),
            replace(base, candidate_sha="f" * 40),
            replace(base, repository=RepositoryRef("other", "repository")),
            replace(base, mutation_context=replace(base.mutation_context, task_fingerprint="e" * 64)),
        )

        class CountingClock:
            def __init__(self) -> None:
                self.calls = 0

            def __call__(self) -> datetime:
                self.calls += 1
                raise AssertionError("invalid context reached broker clock")

        class CountingControls:
            def __init__(self) -> None:
                self.calls = 0

            def resolve(self, _: GitHubMutationIntent) -> object:
                self.calls += 1
                raise AssertionError("invalid context reached owner control resolver")

        class CountingReadChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_read(self, _: GitHubReadRequest) -> object:
                self.calls += 1
                raise AssertionError("invalid context reached read IPC")

            def exchange_collection_page(self, _: GitHubReadRequest, __: str | None) -> object:
                self.calls += 1
                raise AssertionError("invalid context reached paginated read IPC")

        class CountingMutationChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_mutation(self, _: OwnerMutationIpcMessage) -> object:
                self.calls += 1
                raise AssertionError("invalid context reached mutation IPC")

        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        for context in contexts:
            for route in ("submit", "reconcile"):
                with self.subTest(route=route, context_type=type(context.dependency_control).__name__), tempfile.TemporaryDirectory() as directory:
                    clock, controls = CountingClock(), CountingControls()
                    reads, mutations = CountingReadChannel(), CountingMutationChannel()
                    journal_path = Path(directory) / "journal.json"
                    broker = GitHubMutationBroker.with_owner_transport(
                        OwnerGitHubReadIpcClient(matrix, reads), OwnerMutationIpcClient(DIGEST, mutations),
                        journal=DurableMutationJournal(journal_path), binding=owner_broker_binding(),
                        controls=controls, clock=clock,
                    )
                    result = getattr(broker, route)(intent, context)
                    self.assertFalse(result.ok)
                    self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                    self.assertEqual((clock.calls, controls.calls, reads.calls, mutations.calls), (0, 0, 0, 0))
                    self.assertFalse(journal_path.exists())

    def test_owner_broker_control_denials_precede_journal_readback_and_transport(self) -> None:
        """Broker submit consumes only the exact owner control before every action."""

        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "broker-control-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )

        class CountingReadChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_read(self, _: GitHubReadRequest) -> object:
                self.calls += 1
                raise AssertionError("denied broker submit reached readback IPC")

            def exchange_collection_page(self, _: GitHubReadRequest, __: str | None) -> object:
                self.calls += 1
                raise AssertionError("denied broker submit reached paginated readback IPC")

        class CountingMutationChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_mutation(self, _: OwnerMutationIpcMessage) -> object:
                self.calls += 1
                raise AssertionError("denied broker submit reached mutation IPC")

        class StaticControls:
            def __init__(self, control: object | None) -> None:
                self.control = control
                self.calls = 0

            def resolve(self, _: GitHubMutationIntent) -> object | None:
                self.calls += 1
                return self.control

        controls: tuple[object | None, ...] = (
            None,
            object(),
            owner_broker_control(intent, binding=CandidateBinding("other/repository", "7" * 64, SHA)),
            owner_broker_control(intent, binding=CandidateBinding(REPOSITORY.slug, "other-task", SHA)),
            owner_broker_control(intent, binding=CandidateBinding(REPOSITORY.slug, "7" * 64, "f" * 40)),
            owner_broker_control(intent, operation=GitHubMutationOperation.CLOSE_ISSUE),
            owner_broker_control(intent, now=NOW - timedelta(seconds=1)),
        )
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        for control in controls:
            with self.subTest(control_type=type(control).__name__), tempfile.TemporaryDirectory() as directory:
                reads, mutations, registry = CountingReadChannel(), CountingMutationChannel(), StaticControls(control)
                journal_path = Path(directory) / "journal.json"
                broker = GitHubMutationBroker.with_owner_transport(
                    OwnerGitHubReadIpcClient(matrix, reads), OwnerMutationIpcClient(DIGEST, mutations),
                    journal=DurableMutationJournal(journal_path), binding=owner_broker_binding(),
                    controls=registry, clock=lambda: NOW,
                )
                result = broker.submit(intent, allowed_context())
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                self.assertEqual(registry.calls, 1)
                self.assertEqual(reads.calls, 0)
                self.assertEqual(mutations.calls, 0)
                self.assertFalse(journal_path.exists())

    def test_owner_broker_control_precedes_direct_and_existing_journal_reconciliation(self) -> None:
        """Reconcile needs the same owner control without re-resolving it on submit."""

        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "broker-reconcile-control-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )

        class CountingReadChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_read(self, _: GitHubReadRequest) -> object:
                self.calls += 1
                raise AssertionError("denied reconciliation reached readback IPC")

            def exchange_collection_page(self, _: GitHubReadRequest, __: str | None) -> object:
                self.calls += 1
                raise AssertionError("denied reconciliation reached paginated readback IPC")

        class CountingMutationChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_mutation(self, _: OwnerMutationIpcMessage) -> object:
                self.calls += 1
                raise AssertionError("denied reconciliation reached mutation IPC")

        class StaticControls:
            def __init__(self, control: object | None) -> None:
                self.control = control
                self.calls = 0

            def resolve(self, _: GitHubMutationIntent) -> object | None:
                self.calls += 1
                return self.control

        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        denied_controls: tuple[object | None, ...] = (
            None,
            object(),
            owner_broker_control(intent, binding=CandidateBinding("other/repository", "7" * 64, SHA)),
            owner_broker_control(intent, binding=CandidateBinding(REPOSITORY.slug, "other-task", SHA)),
            owner_broker_control(intent, binding=CandidateBinding(REPOSITORY.slug, "7" * 64, "f" * 40)),
            owner_broker_control(replace(intent, idempotency_key="other-intent-46")),
            owner_broker_control(intent, operation=GitHubMutationOperation.CLOSE_ISSUE),
            owner_broker_control(intent, now=NOW - timedelta(seconds=1)),
        )
        for control in denied_controls:
            with self.subTest(route="direct", control_type=type(control).__name__), tempfile.TemporaryDirectory() as directory:
                reads, mutations, controls = CountingReadChannel(), CountingMutationChannel(), StaticControls(control)
                journal = DurableMutationJournal(Path(directory) / "journal.json")
                broker = GitHubMutationBroker.with_owner_transport(
                    OwnerGitHubReadIpcClient(matrix, reads), OwnerMutationIpcClient(DIGEST, mutations),
                    journal=journal, binding=owner_broker_binding(), controls=controls, clock=lambda: NOW,
                )
                with mock.patch.object(DurableMutationJournal, "find_recovery", side_effect=AssertionError("denied reconciliation loaded journal")):
                    result = broker.reconcile(intent, allowed_context())
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                self.assertEqual(controls.calls, 1)
                self.assertEqual(reads.calls, 0)
                self.assertEqual(mutations.calls, 0)

        with tempfile.TemporaryDirectory() as directory:
            context = allowed_context()
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            entry = MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent),
            )
            journal.claim(entry)
            reads, mutations = CountingReadChannel(), CountingMutationChannel()
            controls = StaticControls(owner_broker_control(intent))
            broker = GitHubMutationBroker.with_owner_transport(
                OwnerGitHubReadIpcClient(matrix, reads), OwnerMutationIpcClient(DIGEST, mutations),
                journal=journal, binding=owner_broker_binding(), controls=controls, clock=lambda: NOW,
            )
            result = broker.submit(intent, context)
            self.assertFalse(result.ok)
            self.assertEqual(controls.calls, 1)
            self.assertEqual(reads.calls, 0)
            self.assertEqual(mutations.calls, 0)

    def test_created_resource_locator_is_total_and_canonical(self) -> None:
        pull_request = CreatedResourceLocator(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
            pull_request_number=58, pull_request_id="pr-58", base_sha=BASE, head_sha=SHA, draft=True,
            marker_digest=COMMENT_DIGEST,
        )
        comment = CreatedResourceLocator(
            GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
            comment_id="comment-46", marker_digest=COMMENT_DIGEST,
        )
        self.assertEqual(pull_request.identity, CreatedResourceLocator(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
            pull_request_number=58, pull_request_id="pr-58", base_sha=BASE, head_sha=SHA, draft=True,
            marker_digest=COMMENT_DIGEST,
        ).identity)
        self.assertNotEqual(pull_request.identity, comment.identity)
        for locator in (
            lambda: CreatedResourceLocator(
                GitHubMutationOperation.REQUEST_REVIEW, REPOSITORY,
                marker_digest=COMMENT_DIGEST,
            ),
            lambda: CreatedResourceLocator(
                GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
                pull_request_number=58, pull_request_id="pr-58", base_sha=BASE, head_sha=SHA, draft=False,
                marker_digest=COMMENT_DIGEST,
            ),
            lambda: CreatedResourceLocator(
                GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
                comment_id="comment-46", draft=True, marker_digest=COMMENT_DIGEST,
            ),
            lambda: CreatedResourceLocator(
                GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
                marker_digest=COMMENT_DIGEST,
            ),
        ):
            with self.subTest(locator=locator), self.assertRaises(ValueError):
                locator()

    def test_allocated_journal_and_receipt_reject_missing_or_drifted_locator_identity(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "locator-journal-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context = allowed_context()
        entry = MutationJournalEntry.from_evidence(
            intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent),
        )
        with self.assertRaises(ValueError):
            replace(entry, lifecycle=JournalLifecycle.TRANSPORT_ACCEPTED)
        accepted = checkpointed_journal_entry(
            intent, context, JournalLifecycle.TRANSPORT_ACCEPTED,
            locator=comment_locator(),
        )
        receipt = GitHubMutationBroker._semantic_receipt(
            intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent),
            DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, MutationDisposition.ACCEPTED,
            durable_entry=accepted,
        )
        with self.assertRaises(ValueError):
            replace(
                accepted, lifecycle=JournalLifecycle.VERIFIED, receipt=replace(
                    receipt, created_resource_identity=DIGEST,
                ),
            )

    def test_owner_accepted_fact_requires_exact_locator_operation(self) -> None:
        comment = CreatedResourceLocator(
            GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
            comment_id="comment-46", marker_digest=COMMENT_DIGEST,
        )
        accepted = OwnerMutationAcceptedFact(
            DIGEST, GitHubMutationOperation.COMMENT, comment,
        )
        self.assertEqual(accepted.identity, OwnerMutationAcceptedFact(
            DIGEST, GitHubMutationOperation.COMMENT, comment,
        ).identity)
        self.assertNotEqual(accepted.identity, OwnerMutationAcceptedFact(
            DIGEST, GitHubMutationOperation.COMMENT, replace(comment, comment_id="comment-47"),
        ).identity)
        for fact in (
            lambda: OwnerMutationFact(True, DIGEST),
            lambda: OwnerMutationAcceptedFact(DIGEST, GitHubMutationOperation.COMMENT),
            lambda: OwnerMutationAcceptedFact(
                DIGEST, GitHubMutationOperation.REQUEST_REVIEW, comment,
            ),
        ):
            with self.subTest(fact=fact), self.assertRaises(ValueError):
                fact()

    def test_owner_host_endpoint_consumes_exact_seals_before_fixed_execution(self) -> None:
        """The owner endpoint, not the broker, rejects every missing or drifted seal."""
        request = sealed_owner_request()
        transport = OwnerTransport()
        endpoint = OwnerMutationHostEndpoint(
            InMemoryOwnerMutationSealRegistry((sealed_owner_record(request),)), OwnerFixedMutationHostExecutor(transport, owner_mutation_binding(request.candidate_sha)),
            owner_mutation_binding(request.candidate_sha), InMemoryOwnerMutationControlRegistry((owner_mutation_control(request),)),
            clock=lambda: NOW,
        )
        self.assertFalse(hasattr(endpoint, "dispatch"))
        accepted = endpoint.exchange_mutation(OwnerMutationIpcMessage(request)).fact
        self.assertIsInstance(accepted, OwnerMutationAcceptedFact)
        self.assertEqual(len(transport.requests), 1)
        reused = endpoint.exchange_mutation(OwnerMutationIpcMessage(request)).fact
        self.assertIsInstance(reused, OwnerMutationFact)
        self.assertEqual(len(transport.requests), 1)

        class StaticRegistry:
            def __init__(self, record: OwnerMutationSealRecord | None) -> None:
                self.record = record

            def resolve_and_consume(self, _: OwnerMutationRequest) -> OwnerMutationSealRecord | None:
                return self.record

        stale = sealed_owner_request(evaluated_at=NOW - timedelta(minutes=1), fresh_until=NOW)
        wrong_operation = OwnerMutationRequest(
            DIGEST, GitHubMutationOperation.CLOSE_ISSUE, DIGEST, DIGEST, DIGEST, REPOSITORY,
            46, candidate_sha=SHA, idempotency_identity=DIGEST,
            command=BrokerMutationCommand.CLOSE_ISSUE, deployment_identity="a" * 64,
            pre_state_identity=DIGEST, evaluated_at=request.evaluated_at,
            fresh_until=request.fresh_until, time_identity=request.time_identity,
            capability_health_identity=DIGEST,
        )
        drifted = (
            replace(request, authorization_bundle_identity="sha256:" + "e" * 64),
            replace(request, candidate_sha=BASE),
            replace(request, idempotency_identity="sha256:" + "e" * 64),
            replace(request, semantic_plan_identity="sha256:" + "e" * 64),
            replace(request, journal_identity="sha256:" + "e" * 64),
            replace(request, capability_health_identity="sha256:" + "e" * 64),
        )
        cases: tuple[OwnerMutationSealRecord | None, ...] = (
            None, *(sealed_owner_record(value) for value in drifted),
            sealed_owner_record(stale), sealed_owner_record(wrong_operation),
        )
        for record in cases:
            with self.subTest(record=record is None):
                denied_transport = OwnerTransport()
                denied = OwnerMutationHostEndpoint(
                    StaticRegistry(record), OwnerFixedMutationHostExecutor(denied_transport, owner_mutation_binding(request.candidate_sha)), owner_mutation_binding(request.candidate_sha), FixtureOwnerMutationControlRegistry(NOW), clock=lambda: NOW,
                ).exchange_mutation(OwnerMutationIpcMessage(request)).fact
                self.assertIsInstance(denied, OwnerMutationFact)
                self.assertEqual(denied_transport.requests, [])
                self.assertEqual(denied_transport.commands, [])

    def test_owner_mutation_dependency_controls_block_before_seal_consumption_or_transport(self) -> None:
        """The fixed host rejects every untrusted control before any mutable seam."""

        request = sealed_owner_request()

        class CountingSealRegistry:
            def __init__(self) -> None:
                self.calls = 0

            def resolve_and_consume(self, _: OwnerMutationRequest) -> OwnerMutationSealRecord:
                self.calls += 1
                return sealed_owner_record(request)

        class StaticControls:
            def __init__(self, control: object | None) -> None:
                self.control = control
                self.calls = 0

            def resolve(self, _: OwnerMutationRequest) -> object | None:
                self.calls += 1
                return self.control

        controls: tuple[object | None, ...] = (
            None,
            object(),
            owner_mutation_control(request, binding=CandidateBinding("other/repository", "github-mutation-host", SHA)),
            owner_mutation_control(request, binding=CandidateBinding(REPOSITORY.slug, "other-task", SHA)),
            owner_mutation_control(request, binding=CandidateBinding(REPOSITORY.slug, "github-mutation-host", "f" * 40)),
            owner_mutation_control(request, operation=GitHubMutationOperation.CLOSE_ISSUE),
            owner_mutation_control(request, now=NOW - timedelta(seconds=1)),
        )
        for control in controls:
            with self.subTest(control_type=type(control).__name__):
                transport, seals, registry = OwnerTransport(), CountingSealRegistry(), StaticControls(control)
                endpoint = OwnerMutationHostEndpoint(
                    seals, OwnerFixedMutationHostExecutor(transport, owner_mutation_binding(request.candidate_sha)), owner_mutation_binding(request.candidate_sha), registry, clock=lambda: NOW,
                )
                fact = endpoint.exchange_mutation(OwnerMutationIpcMessage(request)).fact
                self.assertIsInstance(fact, OwnerMutationFact)
                self.assertEqual(registry.calls, 1)
                self.assertEqual(seals.calls, 0)
                self.assertEqual(transport.requests, [])
                self.assertEqual(transport.commands, [])

    def test_fixed_executor_requires_exact_mutation_control_before_handler(self) -> None:
        """The direct fixed-executor seam cannot bypass endpoint preflight."""

        request = sealed_owner_request()
        record = sealed_owner_record(request)
        binding = owner_mutation_binding(request.candidate_sha)
        valid = owner_mutation_control(request, binding=binding)
        forged_wrong_stage = object.__new__(_OwnerGitHubMutationControl)
        object.__setattr__(forged_wrong_stage, "request_identity", valid.request_identity)
        object.__setattr__(forged_wrong_stage, "binding", valid.binding)
        object.__setattr__(forged_wrong_stage, "operation", valid.operation)
        object.__setattr__(
            forged_wrong_stage, "dependency_control",
            DependencyExecutionControl(valid.dependency_control.policy, valid.dependency_control.observations[:1], valid.dependency_control.admission),
        )
        object.__setattr__(forged_wrong_stage, "now", valid.now)
        controls: tuple[object | None, ...] = (
            None,
            object(),
            owner_mutation_control(request, binding=CandidateBinding("other/repository", binding.task_id, request.candidate_sha)),
            owner_mutation_control(request, binding=CandidateBinding(binding.repository, "other-task", request.candidate_sha)),
            owner_mutation_control(request, binding=CandidateBinding(binding.repository, binding.task_id, "f" * 40)),
            owner_mutation_control(request, operation=GitHubMutationOperation.CLOSE_ISSUE),
            owner_mutation_control(request, now=NOW - timedelta(seconds=1)),
            forged_wrong_stage,
        )
        for control in controls:
            with self.subTest(control_type=type(control).__name__):
                transport = OwnerTransport()
                executor = OwnerFixedMutationHostExecutor(transport, binding)
                with self.assertRaises(ValueError):
                    executor.execute_fixed(record, control=control, now=NOW)  # type: ignore[arg-type]
                self.assertEqual(transport.commands, [])
                self.assertEqual(transport.requests, [])

    def test_owner_fixed_executor_has_total_sealed_operation_mapping_without_process_access(self) -> None:
        """Every operation reaches the host only as a sealed fixed command shape."""
        import roundwright.github_runtime as runtime

        self.assertEqual(set(runtime._MUTATION_COMMAND_BY_OPERATION), set(GitHubMutationOperation))
        numbered = {
            GitHubMutationOperation.CREATE_PULL_REQUEST, GitHubMutationOperation.COMMENT,
            GitHubMutationOperation.REQUEST_REVIEW, GitHubMutationOperation.MARK_READY,
            GitHubMutationOperation.MERGE_PULL_REQUEST, GitHubMutationOperation.CLOSE_ISSUE,
        }
        for operation, command in runtime._MUTATION_COMMAND_BY_OPERATION.items():
            values: dict[str, object] = {
                "candidate_sha": SHA, "idempotency_identity": DIGEST, "command": command,
                "deployment_identity": "a" * 64, "pre_state_identity": DIGEST,
                "evaluated_at": NOW.isoformat(), "fresh_until": (NOW + timedelta(minutes=5)).isoformat(),
                "time_identity": "sha256:" + hashlib.sha256(
                    json.dumps((NOW.isoformat(), (NOW + timedelta(minutes=5)).isoformat()), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
                ).hexdigest(),
                "capability_health_identity": DIGEST,
            }
            if operation in numbered:
                values["target_number"] = 46
            if operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
                values.update({
                    "base_sha": BASE, "head_sha": SHA, "marker_digest": COMMENT_DIGEST,
                    "authorized_base_sha": BASE, "base_ref": "main", "head_ref": "codex/issue-46",
                    "base_repository": REPOSITORY, "head_repository": REPOSITORY,
                })
            elif operation is GitHubMutationOperation.COMMENT:
                values["marker_digest"] = COMMENT_DIGEST
            request = OwnerMutationRequest(DIGEST, operation, DIGEST, DIGEST, DIGEST, REPOSITORY, **values)
            transport = OwnerTransport()
            binding = owner_mutation_binding(request.candidate_sha)
            fact = OwnerFixedMutationHostExecutor(transport, binding).execute_fixed(
                sealed_owner_record(request), control=owner_mutation_control(request, binding=binding), now=NOW,
            )
            with self.subTest(operation=operation):
                self.assertIsInstance(fact, OwnerMutationAcceptedFact)
                self.assertEqual(transport.commands[0].command, command)
                self.assertEqual(transport.commands[0].operation, operation)
                self.assertEqual(len(transport.requests), 1)

    def test_role_visible_runtime_has_no_generic_runner_or_raw_command_result(self) -> None:
        """Public role code sees typed endpoints, never a generic gh process API."""
        import roundwright.github_runtime as runtime

        for name in ("GhRunner", "GhCommandResult", "GhGitHubAdapter", "_SubprocessGhReadRunner"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(runtime, name))
        runner = Runner()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                GitHubMutationBroker.with_owner_transport(
                    runner, owner_endpoint(), journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW,
                )
        self.assertEqual(runner.calls, [])

        with self.assertRaises(ValueError):
            OwnerMutationHostEndpoint(FixtureOwnerSealRegistry(), OwnerTransport(), object(), object())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            OwnerFixedMutationHostExecutor(object(), object())  # type: ignore[arg-type]

    def test_production_ipc_clients_have_no_reachable_process_or_credential_capability(self) -> None:
        """The broker graph retains only absent-by-default typed IPC clients."""

        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "ipc-isolation-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        read_client = OwnerGitHubReadIpcClient(matrix)
        mutation_client = OwnerMutationIpcClient(DIGEST)
        with tempfile.TemporaryDirectory() as directory:
            broker = GitHubMutationBroker.with_owner_transport(
                read_client, mutation_client,
                journal=DurableMutationJournal(Path(directory) / "journal.json"),
                binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW,
            )

            seen: set[int] = set()
            forbidden = ("runner", "handler", "credential", "stdout", "stderr", "argv", "commandresult")

            def inspect(value: object) -> None:
                if id(value) in seen or type(value) in {str, int, bool, type(None), bytes}:
                    return
                seen.add(id(value))
                names = set(getattr(value, "__dict__", {}))
                names.update(getattr(value, "__slots__", ()) if type(getattr(value, "__slots__", ())) in {tuple, list} else ())
                for name in names:
                    self.assertFalse(any(token in name.lower() for token in forbidden), name)
                    try:
                        inspect(getattr(value, name))
                    except AttributeError:
                        pass
                if type(value) is dict:
                    for item in value.values():
                        inspect(item)

            inspect(broker)
            for value in (broker, read_client, mutation_client):
                for name in ("run", "execute", "execute_fixed_command", "graphql", "api", "environ"):
                    self.assertFalse(hasattr(value, name), name)
            self.assertFalse(read_client.submit(intent).ok)
            self.assertFalse(mutation_client.dispatch(sealed_owner_request()).accepted)

    def test_malformed_and_cross_request_ipc_messages_do_not_reach_host_execution(self) -> None:
        """Only an exact sealed IPC message may reach the owner fixed executor."""

        request = sealed_owner_request()
        transport = OwnerTransport()
        host = OwnerMutationHostEndpoint(
            InMemoryOwnerMutationSealRegistry((sealed_owner_record(request),)),
            OwnerFixedMutationHostExecutor(transport, owner_mutation_binding(request.candidate_sha)), owner_mutation_binding(request.candidate_sha), InMemoryOwnerMutationControlRegistry((owner_mutation_control(request),)), clock=lambda: NOW,
        )
        client = OwnerMutationIpcClient(DIGEST, host)
        with self.assertRaises(ValueError):
            client.dispatch(object())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            host.exchange_mutation(object())  # type: ignore[arg-type]
        self.assertEqual(transport.requests, [])
        self.assertEqual(transport.commands, [])

        cross_request = replace(request, journal_identity="sha256:" + "e" * 64)
        denied = client.dispatch(cross_request)
        self.assertIsInstance(denied, OwnerMutationFact)
        self.assertEqual(transport.requests, [])
        self.assertEqual(transport.commands, [])

        accepted = client.dispatch(request)
        self.assertIsInstance(accepted, OwnerMutationAcceptedFact)
        self.assertEqual(len(transport.requests), 1)

    def test_production_clock_and_health_boundaries_fail_before_owner_or_read_calls(self) -> None:
        """Only the injected broker clock selects authorization evaluation time."""
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "clock-boundary-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
        context = allowed_context()
        cases = (
            ("caller-backdate", NOW, NOW + timedelta(minutes=5), NOW, NOW - timedelta(microseconds=1)),
            ("before-observed", NOW + timedelta(microseconds=1), NOW + timedelta(minutes=5), NOW, NOW),
            ("fresh-until", NOW, NOW + timedelta(minutes=5), NOW + timedelta(minutes=5), NOW + timedelta(minutes=5)),
        )
        for name, observed_at, fresh_until, clock_now, context_now in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                matrix = health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                    observed_at=observed_at, fresh_until=fresh_until,
                )
                runner, transport = Runner(), OwnerTransport()
                broker = GitHubMutationBroker.with_owner_transport(
                    owner_read_endpoint(runner, matrix), owner_endpoint(transport),
                    journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    binding=owner_broker_binding(), controls=owner_broker_controls(clock=lambda: clock_now), clock=lambda: clock_now,
                )
                result = broker.submit(intent, replace(context, evaluated_at=context_now), payload=payload)
                self.assertFalse(result.ok)
                self.assertEqual(runner.calls, [])
                self.assertEqual(transport.requests, [])
                self.assertEqual(transport.commands, [])

    def test_production_health_half_open_interval_allows_observed_and_pre_expiry(self) -> None:
        """The validity interval is [observed_at, fresh_until), never inclusive at expiry."""
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "clock-allowed-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
        fresh_until = NOW + timedelta(minutes=5)
        for now in (NOW, fresh_until - timedelta(microseconds=1)):
            with self.subTest(now=now), tempfile.TemporaryDirectory() as directory:
                matrix = health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                    observed_at=NOW, fresh_until=fresh_until,
                )
                runner = Runner(
                    GhCommandResult(0, json.dumps(gh_comments_page())),
                    GhCommandResult(0, json.dumps(gh_comments_page())),
                )
                transport = OwnerTransport()
                result = GitHubMutationBroker.with_owner_transport(
                    owner_read_endpoint(runner, matrix, clock=lambda: now), owner_endpoint(transport, clock=lambda: now),
                    journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    binding=owner_broker_binding(), controls=owner_broker_controls(clock=lambda: now), clock=lambda: now,
                ).submit(intent, allowed_context(now=now), payload=payload)
                self.assertTrue(result.ok)
                self.assertEqual(len(transport.requests), 1)

    def test_credentialed_read_host_rejects_future_and_expired_health_before_runner(self) -> None:
        """AVAILABLE is insufficient outside the owner-clock validity interval."""

        with self.assertRaises(ValueError):
            _OwnerGitHubReadHostEndpoint(Runner(), owner_read_binding(), health(GitHubReadOperation.COMMENTS))
        observed_at = NOW
        fresh_until = NOW + timedelta(minutes=5)
        cases = (
            ("future-observation", observed_at - timedelta(microseconds=1)),
            ("expiry-boundary", fresh_until),
        )
        for name, now in cases:
            with self.subTest(name=name):
                runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
                adapter = GhGitHubAdapter(
                    runner,
                    health(GitHubReadOperation.COMMENTS, observed_at=observed_at, fresh_until=fresh_until),
                    clock=lambda: now,
                )
                result = adapter.read(comments_request())
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.STALE_RESPONSE)  # type: ignore[union-attr]
                self.assertEqual(runner.calls, [])

    def test_credentialed_read_host_control_denials_precede_runner_and_host_actions(self) -> None:
        """Missing, replaced, and stale sealed controls cannot start a host read."""

        matrix = health(GitHubReadOperation.REVIEWS)
        request = reviews_request()
        runner = Runner(GhCommandResult(0, json.dumps(gh_reviews_page())))
        with self.assertRaises(ValueError):
            _OwnerGitHubReadHostEndpoint(runner, owner_read_binding(), None, matrix, clock=lambda: NOW)  # type: ignore[arg-type]
        self.assertEqual(runner.calls, [])
        controls = (
            owner_read_control(binding=CandidateBinding("other/repository", "github-read-host", SHA)),
            owner_read_control(binding=CandidateBinding(REPOSITORY.slug, "other-task", SHA)),
            owner_read_control(binding=CandidateBinding(REPOSITORY.slug, "github-read-host", "f" * 40)),
            owner_read_control(now=NOW - timedelta(seconds=1)),
        )
        for control in controls:
            with self.subTest(binding=control.binding, control_now=control.now):
                runner = Runner(GhCommandResult(0, json.dumps(gh_reviews_page())))
                endpoint = _OwnerGitHubReadHostEndpoint(runner, owner_read_binding(), control, matrix, clock=lambda: NOW)
                result = endpoint.read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                self.assertEqual(runner.calls, [])
                self.assertEqual(endpoint.calls, [])

    def test_mutation_host_rejects_pre_evaluated_and_expired_seals_before_execution(self) -> None:
        """Host execution is valid only in [evaluated_at, fresh_until)."""

        future = sealed_owner_request(
            evaluated_at=NOW + timedelta(minutes=1), fresh_until=NOW + timedelta(minutes=6),
        )
        expired = sealed_owner_request(
            evaluated_at=NOW - timedelta(minutes=6), fresh_until=NOW,
        )
        for name, request in (("pre-evaluated", future), ("expired", expired)):
            with self.subTest(name=name):
                transport = OwnerTransport()
                host = OwnerMutationHostEndpoint(
                    InMemoryOwnerMutationSealRegistry((sealed_owner_record(request),)),
                    OwnerFixedMutationHostExecutor(transport, owner_mutation_binding(request.candidate_sha)), owner_mutation_binding(request.candidate_sha), InMemoryOwnerMutationControlRegistry((owner_mutation_control(request),)), clock=lambda: NOW,
                )
                reply = host.exchange_mutation(OwnerMutationIpcMessage(request))
                self.assertIsInstance(reply.fact, OwnerMutationFact)
                self.assertEqual(transport.requests, [])
                self.assertEqual(transport.commands, [])

    def test_production_restart_revalidates_original_freshness_before_any_downstream_call(self) -> None:
        """Restart may read before expiry, but the exact expiry is denied before read/host dispatch."""
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "clock-restart-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
        fresh_until = NOW + timedelta(minutes=5)
        matrix = health(
            GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
            observed_at=NOW, fresh_until=fresh_until,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.EXECUTION_STARTED:
                    raise RuntimeError("crash")
            with self.assertRaises(RuntimeError):
                GitHubMutationBroker.with_owner_transport(
                    owner_read_endpoint(Runner(GhCommandResult(0, json.dumps(gh_comments_page()))), matrix),
                    owner_endpoint(OwnerTransport()), journal=DurableMutationJournal(path),
                    binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW, checkpoint_observer=crash,
                ).submit(intent, allowed_context(), payload=payload)

            before_expiry = fresh_until - timedelta(microseconds=1)
            restart_runner, restart_transport = Runner(GhCommandResult(0, json.dumps(gh_comments_page()))), OwnerTransport()
            recovered = GitHubMutationBroker.with_owner_transport(
                owner_read_endpoint(restart_runner, matrix), owner_endpoint(restart_transport),
                journal=DurableMutationJournal(path), binding=owner_broker_binding(),
                controls=owner_broker_controls(clock=lambda: before_expiry), clock=lambda: before_expiry,
            ).reconcile(intent, allowed_context(now=before_expiry))
            self.assertFalse(recovered.ok)
            self.assertEqual(restart_runner.calls, [])
            self.assertEqual(restart_transport.requests, [])

            expired_runner, expired_transport = Runner(), OwnerTransport()
            expired = GitHubMutationBroker.with_owner_transport(
                owner_read_endpoint(expired_runner, matrix), owner_endpoint(expired_transport),
                journal=DurableMutationJournal(path), binding=owner_broker_binding(),
                controls=owner_broker_controls(clock=lambda: fresh_until), clock=lambda: fresh_until,
            ).reconcile(intent, allowed_context(now=fresh_until))
            self.assertFalse(expired.ok)
            self.assertEqual(expired_runner.calls, [])
            self.assertEqual(expired_transport.requests, [])

    def test_created_resource_locator_binds_to_fixed_request_and_plan(self) -> None:
        comment_intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "locator-comment-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        comment_request = OwnerMutationRequest(
            DIGEST, comment_intent.operation, DIGEST, _broker_semantic_plan(comment_intent).identity,
            DIGEST, REPOSITORY, 46, marker_digest=COMMENT_DIGEST,
        )
        comment_locator = CreatedResourceLocator(
            comment_intent.operation, REPOSITORY, issue_number=46,
            comment_id="comment-46", marker_digest=COMMENT_DIGEST,
        )
        comment_fact = OwnerMutationAcceptedFact(DIGEST, comment_intent.operation, comment_locator)
        _validate_created_resource_locator(
            comment_fact, comment_request, comment_intent, _broker_semantic_plan(comment_intent),
        )
        for locator in (
            replace(comment_locator, repository=RepositoryRef("other", "repository")),
            replace(comment_locator, issue_number=47),
            replace(comment_locator, marker_digest=DIGEST),
        ):
            with self.subTest(locator=locator), self.assertRaises(ValueError):
                _validate_created_resource_locator(
                    OwnerMutationAcceptedFact(DIGEST, comment_intent.operation, locator),
                    comment_request, comment_intent, _broker_semantic_plan(comment_intent),
                )

        pull_request_intent = GitHubMutationIntent(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "locator-pr-46",
            target_number=46,
            payload=(("base_ref", "main"), ("base_sha", BASE), ("body_digest", COMMENT_DIGEST),
                     ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", COMMENT_DIGEST)),
        )
        pull_request_request = OwnerMutationRequest(
            DIGEST, pull_request_intent.operation, DIGEST, _broker_semantic_plan(pull_request_intent).identity,
            DIGEST, REPOSITORY, base_sha=BASE, head_sha=SHA, marker_digest=COMMENT_DIGEST,
        )
        pull_request_locator = CreatedResourceLocator(
            pull_request_intent.operation, REPOSITORY, pull_request_number=58,
            pull_request_id="pr-58",
            base_sha=BASE, head_sha=SHA, draft=True, marker_digest=COMMENT_DIGEST,
        )
        for locator in (pull_request_locator, replace(pull_request_locator, base_sha=SHA), replace(pull_request_locator, head_sha=BASE)):
            fact = OwnerMutationAcceptedFact(DIGEST, pull_request_intent.operation, locator)
            if locator is pull_request_locator:
                _validate_created_resource_locator(fact, pull_request_request, pull_request_intent, _broker_semantic_plan(pull_request_intent))
            else:
                with self.subTest(locator=locator), self.assertRaises(ValueError):
                    _validate_created_resource_locator(fact, pull_request_request, pull_request_intent, _broker_semantic_plan(pull_request_intent))

    def test_created_pull_request_reads_only_the_allocated_locator_identity(self) -> None:
        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        allocated_request = GitHubReadRequest(
            GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=58, expected_sha=SHA,
        )
        adapter = FakeGitHubAdapter({
            plan.pre_dispatch_reads[0].identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
            plan.pre_dispatch_reads[1].identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=SHA)),
            allocated_request.identity(): FakeGitHubScenario(response=pull_request_payload()),
        })
        transport = OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            broker = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
                    GitHubMutationOperation.CREATE_PULL_REQUEST,
                )),
            )
            result = broker.submit(intent, context, payload=payload)
            self.assertTrue(result.ok)
            self.assertEqual([call.identity for call in adapter.calls if call.kind == "read"], [
                plan.pre_dispatch_reads[0].identity(), plan.pre_dispatch_reads[1].identity(),
                allocated_request.identity(),
            ])
            self.assertEqual(len(transport.requests), 1)
            stored = journal.find(MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), plan,
            ))
            self.assertEqual(stored.created_resource.pull_request_number, 58)  # type: ignore[union-attr]
            self.assertEqual(result.receipt.created_resource_identity, stored.created_resource.identity)  # type: ignore[union-attr]
            self.assertTrue(result.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]

    def test_create_pull_request_context_binding_rejects_base_head_and_repository_drift_before_ipc(self) -> None:
        """Creation has no ``expected_sha``; payload commits must bind context instead."""

        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        matrix = health(
            GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
            GitHubMutationOperation.CREATE_PULL_REQUEST,
        )

        class CountingReadChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_read(self, _: GitHubReadRequest) -> object:
                self.calls += 1
                raise AssertionError("denied create request reached read IPC")

            def exchange_collection_page(self, _: GitHubReadRequest, __: str | None) -> object:
                self.calls += 1
                raise AssertionError("denied create request reached collection IPC")

        class CountingMutationChannel:
            def __init__(self) -> None:
                self.calls = 0

            def exchange_mutation(self, _: OwnerMutationIpcMessage) -> object:
                self.calls += 1
                raise AssertionError("denied create request reached mutation IPC")

        values = dict(intent.payload)
        cases = (
            ("base", replace(intent, payload=tuple(sorted({**values, "base_sha": SHA}.items()))), context),
            ("head", replace(intent, payload=tuple(sorted({**values, "head_sha": BASE}.items()))), context),
            ("repository", replace(intent, repository=RepositoryRef("other", "roundwright")), context),
            ("base-ref", replace(intent, payload=tuple(sorted({**values, "base_ref": "trunk"}.items()))), context),
            ("head-ref", replace(intent, payload=tuple(sorted({**values, "head_ref": "other-head"}.items()))), context),
            ("base-repository", intent, replace(context, base_repository=RepositoryRef("fork", "roundwright"))),
            ("head-repository", intent, replace(context, head_repository=RepositoryRef("fork", "roundwright"))),
        )
        for name, drifted, drifted_context in cases:
            with self.subTest(drift=name), tempfile.TemporaryDirectory() as directory:
                reads, mutations = CountingReadChannel(), CountingMutationChannel()
                broker = GitHubMutationBroker.with_owner_transport(
                    OwnerGitHubReadIpcClient(matrix, reads), OwnerMutationIpcClient(DIGEST, mutations),
                    journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW,
                )
                result = broker.submit(drifted, drifted_context, payload=payload)
                self.assertFalse(result.ok)
                self.assertEqual(reads.calls, 0)
                self.assertEqual(mutations.calls, 0)

    def test_create_pull_request_requires_exact_live_base_and_head_ref_proofs_before_transport(self) -> None:
        """Both authorized refs must prove their exact commits before owner dispatch."""

        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        base_read, head_read = plan.pre_dispatch_reads
        matrix = health(
            GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
            GitHubMutationOperation.CREATE_PULL_REQUEST,
        )
        cases = (
            ("base-live-drift", {
                base_read.identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=SHA)),
            }, 1),
            ("head-live-drift", {
                base_read.identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
                head_read.identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=BASE)),
            }, 2),
            ("missing-base", {}, 1),
            ("cross-repository", {
                base_read.identity(): FakeGitHubScenario(
                    response=branch_payload(ref="main", sha=BASE, repository=RepositoryRef("fork", "roundwright")),
                ),
            }, 1),
            ("ref-drift", {
                base_read.identity(): FakeGitHubScenario(response=branch_payload(ref="trunk", sha=BASE)),
            }, 1),
        )
        for name, scenarios, expected_reads in cases:
            with self.subTest(proof=name), tempfile.TemporaryDirectory() as directory:
                adapter, transport = FakeGitHubAdapter(scenarios), OwnerTransport()
                result = GitHubMutationBroker(
                    adapter, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    _executor=_GhBrokerExecutor(transport, matrix),
                ).submit(intent, context, payload=payload)
                self.assertFalse(result.ok)
                self.assertEqual(adapter.call_count(kind="read"), expected_reads)
                self.assertEqual(transport.requests, [])
                self.assertEqual(transport.commands, [])

    def test_create_pull_request_interrupted_before_execution_never_invents_recovery_success(self) -> None:
        """A durable pair of ref proofs is not proof that a PR was dispatched."""

        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        matrix = health(
            GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
            GitHubMutationOperation.CREATE_PULL_REQUEST,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            transport = OwnerTransport()

            def interrupt(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.PRESTATE_CAPTURED:
                    raise RuntimeError("simulated interruption after ref proofs")

            broker = GitHubMutationBroker(
                FakeGitHubAdapter({
                    plan.pre_dispatch_reads[0].identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
                    plan.pre_dispatch_reads[1].identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=SHA)),
                }),
                journal=DurableMutationJournal(path),
                _executor=_GhBrokerExecutor(transport, matrix), checkpoint_observer=interrupt,
            )
            with self.assertRaises(RuntimeError):
                broker.submit(intent, context, payload=payload)
            evidence = MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), plan,
            )
            stored = DurableMutationJournal(path).find(evidence)
            self.assertIs(stored.lifecycle, JournalLifecycle.PRESTATE_CAPTURED)  # type: ignore[union-attr]
            self.assertTrue(stored.pre_state_complete)  # type: ignore[union-attr]
            self.assertEqual(transport.requests, [])

            recovered_adapter = FakeGitHubAdapter({
                GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=58, expected_sha=SHA).identity():
                FakeGitHubScenario(response=pull_request_payload()),
            })
            recovered = GitHubMutationBroker(
                recovered_adapter, journal=DurableMutationJournal(path),
                _executor=_GhBrokerExecutor(transport, matrix),
            ).submit(intent, context, payload=payload)
            self.assertFalse(recovered.ok)
            self.assertEqual(recovered_adapter.call_count(kind="read"), 0)
            self.assertEqual(transport.requests, [])

    def test_create_pull_request_request_and_receipt_bind_the_authorized_candidate(self) -> None:
        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        allocated_request = GitHubReadRequest(
            GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=58, expected_sha=SHA,
        )
        adapter = FakeGitHubAdapter({
            plan.pre_dispatch_reads[0].identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
            plan.pre_dispatch_reads[1].identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=SHA)),
            allocated_request.identity(): FakeGitHubScenario(response=pull_request_payload()),
        })
        transport = OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            result = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
                    GitHubMutationOperation.CREATE_PULL_REQUEST,
                )),
            ).submit(intent, context, payload=payload)
            self.assertTrue(result.ok)
            self.assertEqual(transport.requests[0].authorized_base_sha, context.base_sha)
            self.assertEqual(transport.requests[0].head_sha, context.candidate_sha)
            self.assertEqual(transport.requests[0].base_ref, dict(intent.payload)["base_ref"])
            self.assertEqual(transport.requests[0].head_ref, dict(intent.payload)["head_ref"])
            self.assertEqual(transport.requests[0].base_repository, context.repository)
            self.assertEqual(transport.requests[0].head_repository, context.repository)
            with self.assertRaises(ValueError):
                replace(transport.requests[0], head_repository=RepositoryRef("fork", "roundwright"))
            with self.assertRaises(ValueError):
                replace(transport.requests[0], head_ref="")
            self.assertEqual(result.receipt.candidate_sha, context.candidate_sha)  # type: ignore[union-attr]
            self.assertEqual(result.receipt.created_resource_identity, journal.find(
                MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context), plan)
            ).created_resource.identity)  # type: ignore[union-attr]

    def test_created_pull_request_locator_and_post_state_drift_fail_closed(self) -> None:
        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        allocated_request = GitHubReadRequest(
            GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=58, expected_sha=SHA,
        )
        body_digest = dict(intent.payload)["body_digest"]
        wrong_locator = CreatedResourceLocator(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
            pull_request_number=58, pull_request_id="pr-58", base_sha=SHA, head_sha=SHA, draft=True,
            marker_digest=body_digest,
        )
        for transport, post_state in (
            (OwnerTransport(created_resource=wrong_locator), None),
            (OwnerTransport(), pull_request_payload(number=46)),
            (OwnerTransport(), pull_request_payload(pull_request_id="pr-59")),
            (OwnerTransport(), pull_request_payload(head_repository="fork/roundwright")),
        ):
            with self.subTest(transport=transport, post_state=post_state), tempfile.TemporaryDirectory() as directory:
                scenarios = {
                    plan.pre_dispatch_reads[0].identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
                    plan.pre_dispatch_reads[1].identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=SHA)),
                }
                if post_state is not None:
                    scenarios[allocated_request.identity()] = FakeGitHubScenario(response=post_state)
                adapter = FakeGitHubAdapter(scenarios)
                result = GitHubMutationBroker(
                    adapter, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    _executor=_GhBrokerExecutor(transport, health(
                        GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
                        GitHubMutationOperation.CREATE_PULL_REQUEST,
                    )),
                ).submit(intent, context, payload=payload)
                self.assertFalse(result.ok)
                self.assertEqual(len(transport.requests), 1)

    def test_created_pull_request_acceptance_crash_recovers_without_second_transport(self) -> None:
        intent, payload = pull_request_intent()
        context = allowed_context(RepositoryMutationOperation.CREATE_DRAFT_PR)
        plan = _broker_semantic_plan(intent)
        allocated_request = GitHubReadRequest(
            GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=58, expected_sha=SHA,
        )
        transport = OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            initial = FakeGitHubAdapter({
                plan.pre_dispatch_reads[0].identity(): FakeGitHubScenario(response=branch_payload(ref="main", sha=BASE)),
                plan.pre_dispatch_reads[1].identity(): FakeGitHubScenario(response=branch_payload(ref="codex/issue-46", sha=SHA)),
            })
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
                    raise RuntimeError("crash after allocated acceptance")
            broker = GitHubMutationBroker(
                initial, journal=DurableMutationJournal(path),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.BRANCH, GitHubReadOperation.PULL_REQUEST,
                    GitHubMutationOperation.CREATE_PULL_REQUEST,
                )), checkpoint_observer=crash,
            )
            with self.assertRaises(RuntimeError):
                broker.submit(intent, context, payload=payload)
            evidence = MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context), plan)
            stored = DurableMutationJournal(path).find(evidence)
            self.assertIs(stored.lifecycle, JournalLifecycle.TRANSPORT_ACCEPTED)  # type: ignore[union-attr]
            self.assertIsNotNone(stored.created_resource)  # type: ignore[union-attr]
            restarted = FakeGitHubAdapter({allocated_request.identity(): FakeGitHubScenario(response=pull_request_payload())})
            result = GitHubMutationBroker(restarted, journal=DurableMutationJournal(path)).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(restarted.call_count(kind="mutation"), 0)
            self.assertEqual(len(transport.requests), 1)
            self.assertEqual(result.receipt.candidate_sha, context.candidate_sha)  # type: ignore[union-attr]
            self.assertEqual(result.receipt.created_resource_identity, stored.created_resource.identity)  # type: ignore[union-attr]

    def test_allocated_comment_post_read_requires_the_exact_comment_identity(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "allocated-comment-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context, plan = allowed_context(), _broker_semantic_plan(intent)
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
        transport = OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            result = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, context, payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(result.ok)
            stored = journal.find(MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), plan,
            ))
            self.assertEqual(stored.created_resource.comment_id, "comment-46")  # type: ignore[union-attr]
            self.assertEqual(result.receipt.created_resource_identity, stored.created_resource.identity)  # type: ignore[union-attr]
            self.assertTrue(result.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]

    def test_allocated_comment_locator_rejects_body_fallback_but_allows_the_exact_duplicate(self) -> None:
        """Only the immutable locator selects one of two identical comment bodies."""

        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "allocated-comment-duplicate-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        response = {
            **comments_payload(), "comments": [
                {"id": "comment-46", "author_id": "owner-1", "body": "curated evidence", "created_at": "2026-08-07T00:00:01Z"},
                {"id": "comment-47", "author_id": "owner-1", "body": "curated evidence", "created_at": "2026-08-07T00:00:00Z"},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=response)})
            transport = OwnerTransport()
            result = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(result.ok)
            stored = journal.find(MutationJournalEntry.from_evidence(
                intent, allowed_context(), schema_v2_authorization_bundle(allowed_context()),
                _broker_semantic_plan(intent),
            ))
            self.assertEqual(stored.created_resource.comment_id, "comment-46")  # type: ignore[union-attr]
            self.assertEqual(result.receipt.created_resource_identity, stored.created_resource.identity)  # type: ignore[union-attr]

    def test_allocated_comment_locator_body_and_identity_drift_are_rejected(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "allocated-comment-drift-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
        other_id = {**comments_payload(), "comments": [{
            "id": "comment-47", "author_id": "owner-1", "body": "curated evidence",
            "created_at": "2026-08-07T00:00:00Z",
        }]}
        wrong_id = CreatedResourceLocator(
            GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
            comment_id="comment-47", marker_digest=COMMENT_DIGEST,
        )
        wrong_body = CreatedResourceLocator(
            GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
            comment_id="comment-46", marker_digest=DIGEST,
        )
        for transport, response in (
            (OwnerTransport(created_resource=wrong_id), comments_payload()),
            (OwnerTransport(), other_id),
            (OwnerTransport(created_resource=wrong_body), comments_payload()),
        ):
            with self.subTest(transport=transport, response=response), tempfile.TemporaryDirectory() as directory:
                adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=response)})
                result = GitHubMutationBroker(
                    adapter, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    _executor=_GhBrokerExecutor(transport, health(
                        GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                    )),
                ).submit(intent, allowed_context(), payload=payload)
                self.assertFalse(result.ok)
                self.assertEqual(len(transport.requests), 1)

    def test_allocated_comment_acceptance_crash_reconciles_without_second_transport(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "allocated-comment-crash-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context, transport = allowed_context(), OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            initial = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
                    raise RuntimeError("crash after allocated comment")
            with self.assertRaises(RuntimeError):
                GitHubMutationBroker(
                    initial, journal=DurableMutationJournal(path),
                    _executor=_GhBrokerExecutor(transport, health(
                        GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                    )), checkpoint_observer=crash,
                ).submit(intent, context, payload=GhMutationPayload(
                    GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
                ))
            restarted = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(restarted, journal=DurableMutationJournal(path)).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(restarted.call_count(kind="mutation"), 0)
            self.assertEqual(len(transport.requests), 1)

    def test_schema_v2_authorization_bundle_is_immutable_and_deterministic(self) -> None:
        bundle = schema_v2_authorization_bundle(allowed_context())
        self.assertEqual(bundle, schema_v2_authorization_bundle(allowed_context()))
        self.assertEqual(bundle.identity, schema_v2_authorization_bundle(allowed_context()).identity)
        self.assertEqual(bundle.serialize()["candidate_sha"], SHA)
        with self.assertRaises((AttributeError, TypeError)):
            bundle.candidate_sha = BASE  # type: ignore[misc]
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        bound = schema_v2_authorization_bundle(allowed_context(), now=NOW, health=matrix)
        self.assertEqual(bound.capability_health_identity, matrix.identity)
        self.assertNotEqual(bound.identity, bundle.identity)
        with self.assertRaises(ValueError):
            replace(bound, time_identity=DIGEST)
        future = health(
            GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
            observed_at=NOW + timedelta(microseconds=1), fresh_until=NOW + timedelta(minutes=5),
        )
        with self.assertRaises(ValueError):
            schema_v2_authorization_bundle(allowed_context(), now=NOW, health=future)

    def test_context_constructs_schema_v2_bundle_from_canonical_evidence(self) -> None:
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        self.assertEqual(bundle.repository_identity, context.mutation_context.repository_fingerprint)
        self.assertEqual(bundle.dispatcher_transition_identity, context.dispatcher_transition.evidence_fingerprint)
        self.assertEqual(bundle.dispatcher_transition_digest, context.dispatcher_transition.digest)
        self.assertEqual(bundle.receipt_identity, context.activation_receipt.receipt_fingerprint)
        self.assertEqual(bundle.receipt_binding_digest, context.activation_receipt.binding_digest)
        self.assertIs(bundle.receipt_status, RepositoryReceiptStatus.FRESH)
        self.assertEqual(bundle.target_repository, context.repository.slug)
        self.assertEqual(bundle.base_repository, context.base_repository.slug)
        self.assertEqual(bundle.head_repository, context.head_repository.slug)
        self.assertEqual(bundle.base_ref, context.base_ref)
        self.assertEqual(bundle.head_ref, context.head_ref)
        self.assertNotEqual(
            bundle.identity,
            schema_v2_authorization_bundle(replace(context, head_ref="other-head")).identity,
        )

    def test_schema_v2_authorization_bundle_rejects_each_mismatched_evidence_input(self) -> None:
        def mismatched_policy() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "policy_snapshot", TrustedRepositoryPolicySnapshot(RepositoryPolicySource("c" * 64, "1" * 64), context.policy_snapshot.document))
            return context

        def mismatched_receipt() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "activation_receipt", replace(context.activation_receipt, candidate_sha=BASE))
            return context

        def mismatched_transition() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "dispatcher_transition", replace(context.dispatcher_transition, candidate_sha=BASE))
            return context

        def mismatched_context() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "mutation_context", replace(context.mutation_context, candidate_sha=BASE))
            return context

        def mismatched_standing_authority() -> MutationBrokerContext:
            context = allowed_context()
            narrowed = replace(context.standing_authority.policy, allow_issue_comment=False)
            object.__setattr__(context, "standing_authority", StandingRepositoryAuthority(narrowed))
            return context

        def mismatched_binding() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context.policy, "binding", None)
            return context

        def missing_receipt() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "activation_receipt", None)
            return context

        def mismatched_broker_candidate() -> MutationBrokerContext:
            context = allowed_context()
            object.__setattr__(context, "candidate_sha", BASE)
            return context

        for name, build in (
            ("policy snapshot", mismatched_policy),
            ("receipt", mismatched_receipt),
            ("dispatcher transition", mismatched_transition),
            ("mutation context", mismatched_context),
            ("standing authority", mismatched_standing_authority),
            ("policy binding", mismatched_binding),
            ("missing receipt", missing_receipt),
            ("broker candidate", mismatched_broker_candidate),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                schema_v2_authorization_bundle(build())

    def test_schema_v2_pre_run_gate_allows_only_canonical_evidence(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "schema-v2-comment-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        request = comments_request()
        fake = FakeGitHubAdapter({
            request.identity(): FakeGitHubScenario(response=comments_payload()),
            intent.identity(): FakeGitHubScenario(
                duplicate_receipt=True, affected_identity="comment-46",
                semantic_readback_digest=DIGEST,
            ),
        })
        context = allowed_context()
        with tempfile.TemporaryDirectory() as directory:
            transport = OwnerTransport()
            result = GitHubMutationBroker(
                fake, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, context, payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(result.ok)
            self.assertEqual(len(transport.requests), 1)
            assert result.receipt is not None
            plan = _broker_semantic_plan(intent)
            self.assertEqual(result.receipt.authorization_bundle_identity, schema_v2_authorization_bundle(context).identity)
            self.assertEqual(result.receipt.intent_identity, intent.identity())
            self.assertEqual(result.receipt.semantic_plan_identity, plan.identity)
            self.assertEqual(result.receipt.semantic_readback_identity, plan.readback.identity)

    def test_broker_semantic_plan_is_total_for_every_supported_operation(self) -> None:
        reviewers = "octocat"
        reviewers_digest = "sha256:" + hashlib.sha256(json.dumps(("reviewers", (reviewers,)), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        cases = (
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "create-46", expected_sha=SHA, target_ref="codex/issue-46"), GitHubReadOperation.REPOSITORY, SemanticPostcondition.BRANCH_AT_EXPECTED_SHA),
            (GitHubMutationIntent(GitHubMutationOperation.UPDATE_BRANCH, REPOSITORY, "update-46", expected_sha=SHA, target_ref="codex/issue-46", payload=(("previous_sha", BASE),)), GitHubReadOperation.BRANCH, SemanticPostcondition.BRANCH_AT_EXPECTED_SHA),
            (GitHubMutationIntent(GitHubMutationOperation.DELETE_BRANCH, REPOSITORY, "delete-46", expected_sha=SHA, target_ref="codex/issue-46"), GitHubReadOperation.BRANCH, SemanticPostcondition.BRANCH_ABSENT),
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", target_number=46, payload=(("base_ref", "main"), ("base_sha", SHA), ("body_digest", COMMENT_DIGEST), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", COMMENT_DIGEST))), GitHubReadOperation.BRANCH, SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE),
            (GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),)), GitHubReadOperation.COMMENTS, SemanticPostcondition.COMMENT_PRESENT),
            (GitHubMutationIntent(GitHubMutationOperation.REQUEST_REVIEW, REPOSITORY, "review-46", target_number=46, expected_sha=SHA, payload=(("reviewers_digest", reviewers_digest),)), GitHubReadOperation.REQUESTED_REVIEWERS, SemanticPostcondition.REVIEWERS_EXACT_AT_CANDIDATE),
            (GitHubMutationIntent(GitHubMutationOperation.MARK_READY, REPOSITORY, "ready-46", target_number=46, expected_sha=SHA), GitHubReadOperation.PULL_REQUEST, SemanticPostcondition.PULL_REQUEST_READY),
            (GitHubMutationIntent(GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "merge-46", target_number=46, expected_sha=SHA, payload=(("method", "merge"),)), GitHubReadOperation.PULL_REQUEST, SemanticPostcondition.PULL_REQUEST_MERGED),
            (GitHubMutationIntent(GitHubMutationOperation.CLOSE_ISSUE, REPOSITORY, "close-46", target_number=46, payload=(("reason", "COMPLETED"),)), GitHubReadOperation.ISSUE, SemanticPostcondition.ISSUE_CLOSED),
        )
        for intent, read_operation, condition in cases:
            with self.subTest(operation=intent.operation):
                plan = _broker_semantic_plan(intent)
                self.assertIs(plan.command, BrokerMutationCommand(intent.operation.value))
                self.assertIs(plan.pre_state.operation, read_operation)
                self.assertIs(plan.readback.condition, condition)
                self.assertEqual(plan.intent_identity, intent.identity())

    def test_delete_branch_uses_explicit_absence_and_affected_identity(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.DELETE_BRANCH, REPOSITORY, "delete-branch-46",
            expected_sha=SHA, target_ref="codex/issue-46",
        )
        context, plan = allowed_context(RepositoryMutationOperation.DELETE_REMOTE_BRANCH), _broker_semantic_plan(intent)
        adapter = FakeGitHubAdapter({
            plan.pre_state.identity(): FakeGitHubScenario(response={
                "repository": {"owner": "example", "name": "roundwright"},
                "ref": "codex/issue-46", "sha": SHA,
            }),
            plan.readback.request.identity(): FakeGitHubScenario(stale=True),
            intent.identity(): FakeGitHubScenario(
                duplicate_receipt=True, affected_identity="deleted-branch-46",
                semantic_readback_digest=DIGEST,
            ),
        })
        result = GitHubMutationBroker(adapter).submit(intent, context)
        self.assertTrue(result.ok)
        self.assertTrue(result.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]
        self.assertEqual(adapter.call_count(kind="mutation"), 1)

    def test_merged_pull_request_binds_merge_commit_and_reuses_receipt_on_restart(self) -> None:
        merge_sha = "d" * 40
        intent = GitHubMutationIntent(
            GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "merge-46",
            target_number=46, expected_sha=SHA, payload=(("method", "merge"),),
        )
        context, plan = allowed_context(RepositoryMutationOperation.MERGE_PR), _broker_semantic_plan(intent)
        merged = pull_request_payload(number=46, draft=False, state="MERGED", merge_commit_sha=merge_sha)
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            adapter = FakeGitHubAdapter({
                plan.pre_state.identity(): FakeGitHubScenario(response=merged),
                intent.identity(): FakeGitHubScenario(
                    duplicate_receipt=True, affected_identity="merge-46", semantic_readback_digest=DIGEST,
                ),
            })
            first = GitHubMutationBroker(adapter, journal=journal).submit(intent, context)
            self.assertTrue(first.ok)
            self.assertTrue(first.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]
            restarted = FakeGitHubAdapter()
            retry = GitHubMutationBroker(restarted, journal=DurableMutationJournal(Path(directory) / "journal.json")).reconcile(intent, context)
            self.assertTrue(retry.ok)
            self.assertEqual(retry.receipt, first.receipt)
            self.assertEqual(restarted.call_count(), 0)

    def test_merged_pull_request_rejects_missing_or_drifted_merge_evidence(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "merge-drift-46",
            target_number=46, expected_sha=SHA, payload=(("method", "merge"),),
        )
        context, plan = allowed_context(RepositoryMutationOperation.MERGE_PR), _broker_semantic_plan(intent)
        for response in (
            pull_request_payload(number=46, draft=False, state="MERGED"),
            pull_request_payload(number=46, head_sha=BASE, draft=False, state="MERGED", merge_commit_sha="d" * 40),
            pull_request_payload(number=46, draft=False, state="MERGED", merge_commit_sha="not-a-sha"),
        ):
            with self.subTest(response=response):
                adapter = FakeGitHubAdapter({
                    plan.pre_state.identity(): FakeGitHubScenario(response=response),
                    intent.identity(): FakeGitHubScenario(
                        duplicate_receipt=True, affected_identity="merge-46", semantic_readback_digest=DIGEST,
                    ),
                })
                result = GitHubMutationBroker(adapter).submit(intent, context)
                self.assertFalse(result.ok)
                self.assertEqual(adapter.call_count(kind="mutation"), 0)

    def test_native_pull_request_projection_requires_merge_commit_for_merged_state(self) -> None:
        request = GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=46, expected_sha=SHA)
        raw = {
            "repository_url": "https://api.github.example/repos/example/roundwright", "id": 46,
            "number": 46, "state": "closed", "merged": True, "draft": False, "merge_commit_sha": "d" * 40,
            "base": {"ref": "main", "sha": BASE, "repo": {"full_name": "example/roundwright", "owner": {"login": "example"}, "name": "roundwright"}},
            "head": {"ref": "codex/issue-46", "sha": SHA, "repo": {"full_name": "example/roundwright"}},
        }
        adapter = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(raw))), health(GitHubReadOperation.PULL_REQUEST))
        result = adapter.read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.merge_commit_sha, "d" * 40)  # type: ignore[union-attr]
        missing = dict(raw)
        missing["merge_commit_sha"] = None
        denied = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(missing))), health(GitHubReadOperation.PULL_REQUEST)).read(request)
        self.assertFalse(denied.ok)

    def test_native_pull_request_projection_preserves_open_merge_sha_and_repository_evidence(self) -> None:
        request = GitHubReadRequest(GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=46, expected_sha=SHA)
        raw = {
            "id": 46, "number": 46, "state": "open", "merged": False, "draft": True,
            "merge_commit_sha": "d" * 40,
            "base": {"ref": "main", "sha": BASE, "repo": {"full_name": "example/roundwright"}},
            "head": {"ref": "codex/issue-46", "sha": SHA, "repo": {"full_name": "fork/roundwright"}},
        }
        result = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(raw))), health(GitHubReadOperation.PULL_REQUEST)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.merge_commit_sha, "d" * 40)  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.base_repository, REPOSITORY)  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.head_repository, RepositoryRef("fork", "roundwright"))  # type: ignore[union-attr]

        malformed = dict(raw)
        malformed["head"] = {"ref": "codex/issue-46", "sha": SHA, "repo": {"full_name": "not-a-repository"}}
        self.assertFalse(GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(malformed))), health(GitHubReadOperation.PULL_REQUEST)).read(request).ok)

    def test_native_requested_reviewer_variants_preserve_users_bots_and_teams(self) -> None:
        request = GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46, expected_sha=SHA)
        raw = gh_requested_reviewers_page("octocat", total=3)
        raw["data"]["repository"]["pullRequest"]["reviewRequests"]["nodes"] = [  # type: ignore[index]
            {"requestedReviewer": {"__typename": "User", "login": "octocat"}},
            {"requestedReviewer": {"__typename": "Bot", "login": "dependabot[bot]"}},
            {"requestedReviewer": {"__typename": "Team", "slug": "core-team", "organization": {"login": "example"}}},
        ]
        result = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(raw))), health(GitHubReadOperation.REQUESTED_REVIEWERS)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.reviewers, ("dependabot[bot]", "example/core-team", "octocat"))  # type: ignore[union-attr]

        unsupported = json.loads(json.dumps(raw))
        unsupported["data"]["repository"]["pullRequest"]["reviewRequests"]["nodes"][0]["requestedReviewer"] = {"__typename": "EnterpriseUserAccount", "login": "octocat"}  # type: ignore[index]
        self.assertFalse(GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(unsupported))), health(GitHubReadOperation.REQUESTED_REVIEWERS)).read(request).ok)

    def test_broker_rejects_caller_semantic_overrides_and_incomplete_operations_before_adapter_calls(self) -> None:
        comment = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "override-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        complete = (
            GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "create-46", expected_sha=SHA, target_ref="codex/issue-46"),
            GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", target_number=46, payload=(("base_ref", "main"), ("base_sha", BASE), ("body_digest", COMMENT_DIGEST), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", COMMENT_DIGEST))),
            GitHubMutationIntent(GitHubMutationOperation.DELETE_BRANCH, REPOSITORY, "delete-46", expected_sha=SHA, target_ref="codex/issue-46"),
        )
        override = _broker_semantic_plan(comment)
        for name, arguments in (
            ("pre-state", {"pre_state": comments_request()}),
            ("read-back", {"readback": SemanticReadback(comments_request(), SemanticPostcondition.COMMENT_PRESENT)}),
            ("plan", {"semantic_plan": override}),
            ("command", {"command": BrokerMutationCommand.COMMENT}),
        ):
            with self.subTest(override=name):
                fake = FakeGitHubAdapter()
                result = GitHubMutationBroker(fake).submit(comment, allowed_context(), **arguments)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                self.assertEqual(fake.call_count(), 0)
        for intent in complete:
            with self.subTest(operation=intent.operation):
                fake = FakeGitHubAdapter()
                result = GitHubMutationBroker(fake).submit(intent, allowed_context(GITHUB_REPOSITORY_OPERATION[intent.operation]))
                self.assertFalse(result.ok)
                expected = (
                    GitHubFailureKind.POLICY_DENIED
                    if intent.operation is GitHubMutationOperation.CREATE_PULL_REQUEST
                    else GitHubFailureKind.STALE_RESPONSE
                )
                self.assertEqual(result.failure.kind, expected)  # type: ignore[union-attr]
                self.assertEqual(fake.call_count(kind="mutation"), 0)

    def test_schema_v2_pre_run_gate_rejects_drift_before_any_adapter_call(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "schema-v2-denied-comment-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        request = comments_request()

        def policy_drift(context: MutationBrokerContext) -> None:
            document = replace(context.policy_snapshot.document, enabled=False)
            object.__setattr__(context, "policy_snapshot", TrustedRepositoryPolicySnapshot(context.policy_snapshot.source, document))

        def missing_receipt(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "activation_receipt", None)

        def invalid_receipt(context: MutationBrokerContext) -> None:
            object.__setattr__(context.activation_receipt, "candidate_sha", "not-a-commit")

        def stale_receipt(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "receipt_verification", replace(context.receipt_verification, status=RepositoryReceiptStatus.STALE))

        def standing_authority_drift(context: MutationBrokerContext) -> None:
            policy = replace(context.standing_authority.policy, allow_issue_comment=False)
            object.__setattr__(context, "standing_authority", StandingRepositoryAuthority(policy))

        def mutation_context_drift(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "mutation_context", replace(context.mutation_context, candidate_sha=BASE))

        def dispatcher_transition_drift(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "dispatcher_transition", replace(context.dispatcher_transition, candidate_sha=BASE))

        def configuration_drift(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "configuration_digest", "not-a-digest")

        def expired_evaluation(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "evaluated_at", NOW + timedelta(hours=2))

        def fabricated_deployment_decision(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "deployment", DeploymentAuthorityDecision(DeploymentMode.AUTHORITATIVE, True, "fabricated", "0" * 64))

        def mismatched_deployment_receipt(context: MutationBrokerContext) -> None:
            object.__setattr__(context, "deployment_receipt", replace(context.deployment_receipt, receipt_fingerprint="0" * 64))

        for name, drift in (
            ("policy", policy_drift),
            ("missing receipt", missing_receipt),
            ("invalid receipt", invalid_receipt),
            ("stale receipt", stale_receipt),
            ("standing authority", standing_authority_drift),
            ("mutation context", mutation_context_drift),
            ("dispatcher transition", dispatcher_transition_drift),
            ("configuration", configuration_drift),
            ("expired evaluation", expired_evaluation),
            ("fabricated deployment decision", fabricated_deployment_decision),
            ("mismatched deployment receipt", mismatched_deployment_receipt),
        ):
            with self.subTest(name=name):
                context = allowed_context()
                drift(context)
                fake = FakeGitHubAdapter({})
                broker = GitHubMutationBroker(fake)
                result = broker.submit(intent, context)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
                self.assertEqual(fake.call_count(), 0)

    def test_schema_v2_pre_run_gate_blocks_reconciliation_before_any_adapter_call(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "schema-v2-reconcile-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context = allowed_context()
        object.__setattr__(context, "dispatcher_transition", replace(context.dispatcher_transition, candidate_sha=BASE))
        fake = FakeGitHubAdapter({})
        result = GitHubMutationBroker(fake).reconcile(intent, context)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(fake.call_count(), 0)

    def test_default_gh_adapter_is_all_operations_unavailable_without_running_gh(self) -> None:
        runner = Runner(GhCommandResult(0, "{}"))
        adapter = GhGitHubAdapter(runner)
        result = adapter.read(comments_request())
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.UNAVAILABLE)  # type: ignore[union-attr]
        self.assertEqual(runner.calls, [])
        self.assertEqual(len(adapter.health.observations), len(GitHubReadOperation) + len(GitHubMutationOperation))

    def test_requested_reviewers_request_is_candidate_bound(self) -> None:
        request = GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46, expected_sha=SHA)
        self.assertTrue(request.identity().startswith("sha256:"))
        with self.assertRaises(ValueError):
            GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46)

    def test_requested_reviewers_command_uses_typed_graphql_variants(self) -> None:
        from roundwright.github_runtime import _read_command
        command = _read_command(GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46, expected_sha=SHA))
        query = next(value for value in command if value.startswith("query="))
        self.assertIn("reviewRequests(first:100,after:$cursor)", query)
        self.assertIn("... on User{login}", query)
        self.assertIn("... on Team{slug organization{login}}", query)
        self.assertNotIn("Actor.id", query)

    def test_requested_reviewers_snapshot_requires_canonical_complete_evidence(self) -> None:
        digest = "sha256:" + hashlib.sha256(json.dumps(("reviewers", ("octocat",)), separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        evidence = "sha256:" + "d" * 64
        snapshot = RequestedReviewersSnapshot(REPOSITORY, 46, SHA, ("octocat",), digest, True, None, evidence)
        self.assertTrue(snapshot.complete)
        with self.assertRaises(ValueError):
            RequestedReviewersSnapshot(REPOSITORY, 46, SHA, ("octocat", "octocat"), digest, True, None, evidence)

    def test_gh_adapter_uses_read_only_api_and_normalizes_only_typed_response(self) -> None:
        import json

        runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS))
        result = adapter.read(comments_request())
        self.assertTrue(result.ok)
        self.assertEqual(runner.calls[0][:2], ("api", "graphql"))
        self.assertNotIn("curated evidence", repr(result.snapshot))

    def test_native_single_response_reads_bind_exact_provider_identities(self) -> None:
        """Branch, PR, mergeability, and remote-head reads use raw provider identities."""
        import json

        branch_request = GitHubReadRequest(
            GitHubReadOperation.BRANCH, REPOSITORY, ref="main", expected_sha=BASE,
        )
        remote_head_request = GitHubReadRequest(
            GitHubReadOperation.REMOTE_HEAD, REPOSITORY, ref="main", expected_sha=BASE,
        )
        pull_request = GitHubReadRequest(
            GitHubReadOperation.PULL_REQUEST, REPOSITORY, number=46, expected_sha=SHA,
        )
        mergeability_request = GitHubReadRequest(
            GitHubReadOperation.MERGEABILITY, REPOSITORY, number=46, expected_sha=SHA,
        )
        pull_raw = {
            "id": 58, "number": 46, "state": "open", "merged": False, "draft": True,
            "base": {"ref": "main", "sha": BASE, "repo": {"full_name": "example/roundwright", "name": "roundwright", "owner": {"login": "example"}}},
            "head": {"ref": "codex/issue-46", "sha": SHA, "repo": {"full_name": "example/roundwright"}}, "merge_commit_sha": "d" * 40,
        }
        mergeability_raw = {
            "number": 46, "mergeable_state": "clean",
            "base": {"repo": {"name": "roundwright", "owner": {"login": "example"}}},
            "head": {"sha": SHA},
        }
        cases = (
            (branch_request, gh_default_branch()),
            (remote_head_request, gh_default_branch()),
            (pull_request, pull_raw),
            (mergeability_request, mergeability_raw),
        )
        for request, raw in cases:
            with self.subTest(operation=request.operation):
                result = GhGitHubAdapter(
                    Runner(GhCommandResult(0, json.dumps(raw))), health(request.operation),
                ).read(request)
                self.assertTrue(result.ok)

        malformed_branch = gh_default_branch()
        malformed_branch["commit"]["url"] = f"https://api.github.com/repos/example/roundwright/commits/{BASE}/extra"  # type: ignore[index]
        malformed_mergeability = dict(mergeability_raw)
        malformed_mergeability["repository_url"] = "https://api.github.com/evil/repos/example/roundwright"
        malformed_mergeability["base"] = {"repo": {}}
        for request, raw in ((branch_request, malformed_branch), (mergeability_request, malformed_mergeability)):
            with self.subTest(rejected=request.operation):
                result = GhGitHubAdapter(
                    Runner(GhCommandResult(0, json.dumps(raw))), health(request.operation),
                ).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_native_repository_read_composes_default_head_from_two_bound_rest_responses(self) -> None:
        import json

        runner = Runner(
            GhCommandResult(0, json.dumps(gh_repository_metadata())),
            GhCommandResult(0, json.dumps(gh_default_branch())),
        )
        request = GitHubReadRequest(GitHubReadOperation.REPOSITORY, REPOSITORY)
        result = GhGitHubAdapter(runner, health(GitHubReadOperation.REPOSITORY)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.default_branch, "main")  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.default_branch_sha, BASE)  # type: ignore[union-attr]
        self.assertNotEqual(result.snapshot.repository_evidence_identity, result.snapshot.default_branch_evidence_identity)  # type: ignore[union-attr]
        self.assertEqual(runner.calls, [
            ("api", "--method", "GET", "repos/example/roundwright"),
            ("api", "--method", "GET", "repos/example/roundwright/branches/main"),
        ])

    def test_native_repository_read_rejects_default_head_drift_and_truncated_branch_evidence(self) -> None:
        import json

        malformed_sha = "c" * 64
        cases = (
            ("wrong-default-branch", gh_repository_metadata(), gh_default_branch(name="master")),
            ("wrong-full-name", gh_repository_metadata(full_name="other/repository"), None),
            ("wrong-branch-repository", gh_repository_metadata(), gh_default_branch(repository="other/repository")),
            ("missing-commit", gh_repository_metadata(), gh_default_branch(include_commit=False)),
            ("truncated-commit", gh_repository_metadata(), gh_default_branch(include_url=False)),
            ("malformed-sha", gh_repository_metadata(), gh_default_branch(sha=malformed_sha)),
        )
        request = GitHubReadRequest(GitHubReadOperation.REPOSITORY, REPOSITORY)
        for name, metadata, branch in cases:
            with self.subTest(name=name):
                outcomes = [GhCommandResult(0, json.dumps(metadata))]
                if branch is not None:
                    outcomes.append(GhCommandResult(0, json.dumps(branch)))
                runner = Runner(*outcomes)
                result = GhGitHubAdapter(runner, health(GitHubReadOperation.REPOSITORY)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]
                self.assertEqual(len(runner.calls), 1 if branch is None else 2)

    def test_native_issue_read_normalizes_lowercase_state_and_binds_complete_relationship_evidence(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.ISSUE_RELATIONSHIPS, REPOSITORY, number=46)
        runner = Runner(
            GhCommandResult(0, json.dumps(gh_issue_metadata(parent_number=2, child_total=2))),
            GhCommandResult(0, json.dumps(gh_issue_relationship_page(47, 48, total=2))),
        )
        result = GhGitHubAdapter(runner, health(GitHubReadOperation.ISSUE_RELATIONSHIPS)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.state.value, "OPEN")  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.parent_number, 2)  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.sub_issue_numbers, (47, 48))  # type: ignore[union-attr]
        self.assertNotEqual(result.snapshot.issue_evidence_identity, result.snapshot.relationship_evidence_identity)  # type: ignore[union-attr]
        self.assertEqual(runner.calls[0], ("api", "--method", "GET", "repos/example/roundwright/issues/46"))
        query = next(value for value in runner.calls[1] if value.startswith("query="))
        self.assertIn("subIssues(first:100,after:$cursor)", query)
        self.assertIn("totalCount", query)

    def test_native_issue_read_accepts_no_relationships_and_bounded_multi_page_relationships(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.ISSUE, REPOSITORY, number=46)
        empty = GhGitHubAdapter(Runner(
            GhCommandResult(0, json.dumps(gh_issue_metadata(child_total=0, state="closed"))),
            GhCommandResult(0, json.dumps(gh_issue_relationship_page(total=0))),
        ), health(GitHubReadOperation.ISSUE)).read(request)
        self.assertTrue(empty.ok)
        self.assertEqual(empty.snapshot.state.value, "CLOSED")  # type: ignore[union-attr]
        self.assertEqual(empty.snapshot.sub_issue_numbers, ())  # type: ignore[union-attr]

        runner = Runner(
            GhCommandResult(0, json.dumps(gh_issue_metadata(child_total=2))),
            GhCommandResult(0, json.dumps(gh_issue_relationship_page(47, total=2, next_cursor="cursor-1"))),
            GhCommandResult(0, json.dumps(gh_issue_relationship_page(48, total=2))),
        )
        multi = GhGitHubAdapter(runner, health(GitHubReadOperation.ISSUE)).read(request)
        self.assertTrue(multi.ok)
        self.assertEqual(multi.snapshot.sub_issue_numbers, (47, 48))  # type: ignore[union-attr]
        self.assertIn("cursor=cursor-1", runner.calls[2])

    def test_native_issue_read_rejects_url_summary_and_pagination_drift(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.ISSUE_RELATIONSHIPS, REPOSITORY, number=46)
        malformed_parent = gh_issue_metadata()
        malformed_parent["parent_issue_url"] = "https://api.github.com/repos/other/repository/issues/2"
        malformed_parent_url = gh_issue_metadata()
        malformed_parent_url["parent_issue_url"] = "not-a-provider-url"
        malformed_html = gh_issue_metadata()
        malformed_html["html_url"] = "https://github.com/other/repository/issues/46"
        drifting_page = gh_issue_relationship_page(47, total=1)
        drifting_page["data"]["repository"]["issue"]["number"] = 47  # type: ignore[index]
        cases = (
            ("cross-repository-parent", malformed_parent, []),
            ("malformed-parent-url", malformed_parent_url, []),
            ("cross-repository-html", malformed_html, []),
            ("relationship-number-drift", gh_issue_metadata(), [drifting_page]),
            ("summary-mismatch", gh_issue_metadata(child_total=2), [gh_issue_relationship_page(47, total=1)]),
            ("terminal-truncation", gh_issue_metadata(), [gh_issue_relationship_page(47, total=2)]),
            ("duplicate-child", gh_issue_metadata(), [gh_issue_relationship_page(47, 47, total=2)]),
            ("cursor-loop", gh_issue_metadata(), [gh_issue_relationship_page(47, total=2, next_cursor="loop"), gh_issue_relationship_page(48, total=2, next_cursor="loop")]),
        )
        for name, metadata, pages in cases:
            with self.subTest(name=name):
                runner = Runner(*(
                    [GhCommandResult(0, json.dumps(metadata))]
                    + [GhCommandResult(0, json.dumps(page)) for page in pages]
                ))
                result = GhGitHubAdapter(runner, health(GitHubReadOperation.ISSUE_RELATIONSHIPS)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_native_checks_use_run_and_candidate_pull_request_evidence(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.CHECKS, REPOSITORY, number=46, expected_sha=SHA)
        runner = Runner(
            GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
            GhCommandResult(0, json.dumps(gh_checks_page())),
        )
        result = GhGitHubAdapter(runner, health(GitHubReadOperation.CHECKS)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.pull_request_number, 46)  # type: ignore[union-attr]
        self.assertEqual(result.snapshot.head_sha, SHA)  # type: ignore[union-attr]
        self.assertNotEqual(result.snapshot.check_evidence_identity, result.snapshot.candidate_evidence_identity)  # type: ignore[union-attr]
        self.assertEqual(runner.calls[0], ("api", "--method", "GET", "repos/example/roundwright/pulls/46"))
        self.assertEqual(runner.calls[1], ("api", "--method", "GET", f"repos/example/roundwright/commits/{SHA}/check-runs?per_page=100&page=1"))

        empty = GhGitHubAdapter(Runner(
            GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
            GhCommandResult(0, json.dumps(gh_checks_page(total=0))),
        ), health(GitHubReadOperation.CHECKS)).read(request)
        self.assertTrue(empty.ok)
        self.assertEqual(empty.snapshot.checks, ())  # type: ignore[union-attr]

    def test_native_checks_reject_mixed_candidates_and_candidate_repository_drift(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.CHECKS, REPOSITORY, number=46, expected_sha=SHA)
        cases = (
            ("mixed-check-head", gh_candidate_pull_request(), gh_checks_page(head_sha=BASE)),
            ("check-suite-head", gh_candidate_pull_request(), gh_checks_page(suite_sha=BASE)),
            ("candidate-pr-number", gh_candidate_pull_request(number=47), None),
            ("candidate-fork", gh_candidate_pull_request(head_repository="fork/repository"), None),
            ("truncated-page", gh_candidate_pull_request(), {"total_count": 2, "check_runs": []}),
        )
        for name, candidate, page in cases:
            with self.subTest(name=name):
                outcomes = [GhCommandResult(0, json.dumps(candidate))]
                if page is not None:
                    outcomes.append(GhCommandResult(0, json.dumps(page)))
                result = GhGitHubAdapter(Runner(*outcomes), health(GitHubReadOperation.CHECKS)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_native_workflow_runs_bind_provider_repository_head_and_pull_request_relationship(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.WORKFLOW_RUNS, REPOSITORY, number=46, expected_sha=SHA)
        runner = Runner(
            GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
            GhCommandResult(0, json.dumps(gh_workflow_page())),
        )
        result = GhGitHubAdapter(runner, health(GitHubReadOperation.WORKFLOW_RUNS)).read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.runs[0].head_sha, SHA)  # type: ignore[union-attr]
        self.assertNotEqual(result.snapshot.workflow_evidence_identity, result.snapshot.candidate_evidence_identity)  # type: ignore[union-attr]
        self.assertEqual(runner.calls[1], ("api", "--method", "GET", f"repos/example/roundwright/actions/runs?head_sha={SHA}&per_page=100&page=1"))

        first_page = gh_workflow_page(total=2)
        second_page = gh_workflow_page(total=2)
        second_page["workflow_runs"][0]["id"] = 2  # type: ignore[index]
        paged_runner = Runner(
            GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
            GhCommandResult(0, json.dumps(first_page)),
            GhCommandResult(0, json.dumps(second_page)),
        )
        paged = GhGitHubAdapter(paged_runner, health(GitHubReadOperation.WORKFLOW_RUNS)).read(request)
        self.assertTrue(paged.ok)
        self.assertEqual([run.run_id for run in paged.snapshot.runs], ["1", "2"])  # type: ignore[union-attr]
        self.assertTrue(any("page=2" in argument for argument in paged_runner.calls[2]))

    def test_native_workflow_runs_allow_empty_complete_results_and_reject_identity_or_pagination_drift(self) -> None:
        import json

        request = GitHubReadRequest(GitHubReadOperation.WORKFLOW_RUNS, REPOSITORY, number=46, expected_sha=SHA)
        empty = GhGitHubAdapter(Runner(
            GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
            GhCommandResult(0, json.dumps(gh_workflow_page(total=0))),
        ), health(GitHubReadOperation.WORKFLOW_RUNS)).read(request)
        self.assertTrue(empty.ok)
        self.assertEqual(empty.snapshot.runs, ())  # type: ignore[union-attr]

        missing_relationship = gh_workflow_page()
        missing_relationship["workflow_runs"][0]["pull_requests"] = []  # type: ignore[index]
        cases = (
            ("mixed-head", gh_workflow_page(head_sha=BASE)),
            ("repository-drift", gh_workflow_page(repository="other/repository")),
            ("fork-drift", gh_workflow_page(head_repository="fork/repository")),
            ("pull-request-drift", gh_workflow_page(pull_request_number=47)),
            ("missing-relationship", missing_relationship),
            ("truncated-page", {"total_count": 2, "workflow_runs": []}),
        )
        for name, page in cases:
            with self.subTest(name=name):
                result = GhGitHubAdapter(Runner(
                    GhCommandResult(0, json.dumps(gh_candidate_pull_request())),
                    GhCommandResult(0, json.dumps(page)),
                ), health(GitHubReadOperation.WORKFLOW_RUNS)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_native_comment_and_review_actor_queries_use_only_concrete_login_shapes(self) -> None:
        from roundwright.github_runtime import _collection_read_command

        for request in (comments_request(), reviews_request()):
            with self.subTest(operation=request.operation):
                command = _collection_read_command(request, None)
                query = next(value for value in command if value.startswith("query="))
                self.assertIn("author{__typename", query)
                for actor_type in ("User", "Bot", "Organization", "Mannequin"):
                    self.assertIn(f"... on {actor_type}{{login}}", query)
                self.assertNotIn("author{id}", query)
                self.assertNotIn("Actor.id", query)

    def test_native_collection_actor_projection_normalizes_comments_and_reviews(self) -> None:
        import json

        comment_runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
        comment_adapter = GhGitHubAdapter(comment_runner, health(GitHubReadOperation.COMMENTS))
        comment_result = comment_adapter.read(comments_request())
        self.assertTrue(comment_result.ok)
        self.assertEqual(comment_result.snapshot.comments[0].author_id, "user:octocat")  # type: ignore[union-attr]

        review_runner = Runner(GhCommandResult(0, json.dumps(gh_reviews_page())))
        review_adapter = GhGitHubAdapter(review_runner, health(GitHubReadOperation.REVIEWS))
        review_result = review_adapter.read(reviews_request())
        self.assertTrue(review_result.ok)
        self.assertEqual(review_result.snapshot.reviews[0].reviewer_id, "bot:build-bot")  # type: ignore[union-attr]

        for actor_type, login, expected in (
            ("Organization", "octo-org", "organization:octo-org"),
            ("Mannequin", "former-user", "mannequin:former-user"),
            ("Bot", "dependabot[bot]", "bot:dependabot[bot]"),
        ):
            page = gh_comments_page()
            page["data"]["repository"]["issueOrPullRequest"]["comments"]["nodes"][0]["author"] = {  # type: ignore[index]
                "__typename": actor_type, "login": login,
            }
            with self.subTest(actor_type=actor_type):
                result = GhGitHubAdapter(
                    Runner(GhCommandResult(0, json.dumps(page))), health(GitHubReadOperation.COMMENTS),
                ).read(comments_request())
                self.assertTrue(result.ok)
                self.assertEqual(result.snapshot.comments[0].author_id, expected)  # type: ignore[union-attr]

    def test_native_collection_actor_projection_allows_empty_terminal_pages(self) -> None:
        import json

        for request, response in (
            (comments_request(), gh_comments_page(present=False)),
            (reviews_request(), gh_reviews_page(present=False)),
        ):
            with self.subTest(operation=request.operation):
                runner = Runner(GhCommandResult(0, json.dumps(response)))
                adapter = GhGitHubAdapter(runner, health(request.operation))
                page = adapter.read_collection_page(request, None)
                self.assertIsNotNone(page)
                self.assertIsNone(page.next_cursor)  # type: ignore[union-attr]
                self.assertEqual(page.total_count, 0)  # type: ignore[union-attr]
                self.assertEqual(len(runner.calls), 1)

    def test_native_collection_actor_projection_rejects_malformed_unsupported_and_drifting_evidence(self) -> None:
        import json

        malformed_comment = gh_comments_page()
        malformed_comment["data"]["repository"]["issueOrPullRequest"]["comments"]["nodes"][0]["author"] = {"__typename": "Team", "login": "core"}  # type: ignore[index]
        wrong_repository = gh_comments_page()
        wrong_repository["data"]["repository"]["owner"]["login"] = "other"  # type: ignore[index]
        malformed_review = gh_reviews_page()
        malformed_review["data"]["repository"]["pullRequest"]["reviews"]["nodes"][0]["author"] = {"__typename": "User"}  # type: ignore[index]
        wrong_head = gh_reviews_page()
        wrong_head["data"]["repository"]["pullRequest"]["headRefOid"] = BASE  # type: ignore[index]
        for request, response in (
            (comments_request(), malformed_comment),
            (comments_request(), wrong_repository),
            (reviews_request(), malformed_review),
            (reviews_request(), wrong_head),
        ):
            with self.subTest(operation=request.operation):
                runner = Runner(GhCommandResult(0, json.dumps(response)))
                result = GhGitHubAdapter(runner, health(request.operation)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(len(runner.calls), 1)

    def test_native_collection_reads_complete_two_pages_for_every_supported_collection(self) -> None:
        import json

        requested = GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46, expected_sha=SHA)
        cases = (
            (comments_request(), [gh_comments_page(next_cursor="cursor-1", total=2, identifier="comment-46"), gh_comments_page(total=2, identifier="comment-47")], ("comment-46", "comment-47")),
            (reviews_request(), [gh_reviews_page(next_cursor="cursor-1", total=2, identifier="review-46"), gh_reviews_page(total=2, identifier="review-47")], ("review-46", "review-47")),
            (requested, [gh_requested_reviewers_page("alice", next_cursor="cursor-1", total=2), gh_requested_reviewers_page("octocat", total=2)], ("alice", "octocat")),
        )
        for request, pages, expected in cases:
            with self.subTest(operation=request.operation):
                runner = Runner(*(GhCommandResult(0, json.dumps(page)) for page in pages))
                result = GhGitHubAdapter(runner, health(request.operation)).read(request)
                self.assertTrue(result.ok)
                if request.operation is GitHubReadOperation.COMMENTS:
                    actual = tuple(item.comment_id for item in result.snapshot.comments)  # type: ignore[union-attr]
                elif request.operation is GitHubReadOperation.REVIEWS:
                    actual = tuple(item.review_id for item in result.snapshot.reviews)  # type: ignore[union-attr]
                else:
                    actual = result.snapshot.reviewers  # type: ignore[union-attr]
                self.assertEqual(actual, expected)
                self.assertEqual(len(runner.calls), 2)
                self.assertTrue(any("cursor=cursor-1" in argument for argument in runner.calls[1]))

    def test_native_comments_read_pr_conversation_with_provider_ordered_opaque_ids(self) -> None:
        """A PR conversation is an Issue-or-PullRequest target, not ``issue``."""

        import json

        request = comments_request(58)
        first = gh_comments_page(
            number=58, target_kind="PullRequest", identifiers=("opaque-z", "opaque-a"),
            total=3, next_cursor="cursor-1",
        )
        terminal = gh_comments_page(
            number=58, target_kind="PullRequest", identifiers=("opaque-m",), total=3,
        )
        runner = Runner(
            GhCommandResult(0, json.dumps(first)), GhCommandResult(0, json.dumps(terminal)),
        )
        result = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS)).read(request)

        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.target_kind, "PULL_REQUEST")  # type: ignore[union-attr]
        self.assertEqual(
            tuple(item.comment_id for item in result.snapshot.comments),  # type: ignore[union-attr]
            ("opaque-z", "opaque-a", "opaque-m"),
        )
        query = next(value for value in runner.calls[0] if value.startswith("query="))
        self.assertIn("issueOrPullRequest(number:$number)", query)
        self.assertIn("... on Issue", query)
        self.assertIn("... on PullRequest", query)
        self.assertNotIn(" issue(number:$number)", query)
        self.assertTrue(any("cursor=cursor-1" in argument for argument in runner.calls[1]))

    def test_native_comments_reject_target_pagination_and_identity_drift(self) -> None:
        """Provider page order is preserved; all identity/completeness defects fail closed."""

        import json

        request = comments_request()
        missing_cursor = gh_comments_page(next_cursor="cursor-1", total=2)
        missing_cursor["data"]["repository"]["issueOrPullRequest"]["comments"]["pageInfo"]["endCursor"] = None  # type: ignore[index]
        malformed_target = gh_comments_page(target_kind="Discussion")
        target_drift = gh_comments_page(number=47, total=2, identifier="opaque-b")
        type_drift = gh_comments_page(target_kind="PullRequest", total=2, identifier="opaque-b")
        repository_drift = gh_comments_page(repository="other/repository", total=2, identifier="opaque-b")
        cases = (
            ("duplicate-within-page", [gh_comments_page(identifiers=("opaque-a", "opaque-a"), total=2)]),
            ("duplicate", [gh_comments_page(next_cursor="cursor-1", total=2, identifier="opaque-a"), gh_comments_page(total=2, identifier="opaque-a")]),
            ("number-drift", [gh_comments_page(next_cursor="cursor-1", total=2, identifier="opaque-a"), target_drift]),
            ("target-kind-drift", [gh_comments_page(next_cursor="cursor-1", total=2, identifier="opaque-a"), type_drift]),
            ("repository-drift", [gh_comments_page(next_cursor="cursor-1", total=2, identifier="opaque-a"), repository_drift]),
            ("cursor-cycle", [gh_comments_page(next_cursor="loop", total=2, identifier="opaque-a"), gh_comments_page(next_cursor="loop", total=2, identifier="opaque-b")]),
            ("incomplete-total", [gh_comments_page(total=2, identifier="opaque-a")]),
            ("truncated-continuation", [missing_cursor]),
            ("malformed-target", [malformed_target]),
        )
        for name, pages in cases:
            with self.subTest(name=name):
                runner = Runner(*(GhCommandResult(0, json.dumps(page)) for page in pages))
                result = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS)).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_native_collection_reads_reject_pagination_drift_duplicates_and_limits(self) -> None:
        import json

        requested = GitHubReadRequest(GitHubReadOperation.REQUESTED_REVIEWERS, REPOSITORY, number=46, expected_sha=SHA)
        missing_cursor = gh_comments_page(next_cursor="cursor-1", total=2)
        missing_cursor["data"]["repository"]["issueOrPullRequest"]["comments"]["pageInfo"]["endCursor"] = None  # type: ignore[index]
        review_drift = gh_reviews_page(total=2, identifier="review-47")
        review_drift["data"]["repository"]["pullRequest"]["headRefOid"] = BASE  # type: ignore[index]
        requested_drift = gh_requested_reviewers_page("octocat", total=2)
        requested_drift["data"]["repository"]["owner"]["login"] = "other"  # type: ignore[index]
        cases = (
            ("missing-cursor", comments_request(), [missing_cursor]),
            ("comment-cursor-loop", comments_request(), [gh_comments_page(next_cursor="loop", total=2), gh_comments_page(next_cursor="loop", total=2, identifier="comment-47")]),
            ("review-identity-drift", reviews_request(), [gh_reviews_page(next_cursor="cursor-1", total=2), review_drift]),
            ("requested-identity-drift", requested, [gh_requested_reviewers_page("alice", next_cursor="cursor-1", total=2), requested_drift]),
            ("comment-duplicate", comments_request(), [gh_comments_page(next_cursor="cursor-1", total=2), gh_comments_page(total=2)]),
            ("review-duplicate", reviews_request(), [gh_reviews_page(next_cursor="cursor-1", total=2), gh_reviews_page(total=2)]),
            ("requested-duplicate", requested, [gh_requested_reviewers_page("octocat", next_cursor="cursor-1", total=2), gh_requested_reviewers_page("octocat", total=2)]),
            ("item-overflow", comments_request(), [gh_comments_page(present=False, total=3201)]),
        )
        for name, request, pages in cases:
            with self.subTest(name=name):
                result = GhGitHubAdapter(
                    Runner(*(GhCommandResult(0, json.dumps(page)) for page in pages)), health(request.operation),
                ).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

        overflow_pages = [gh_comments_page(present=False, next_cursor=f"cursor-{index}", total=1) for index in range(32)]
        overflow = GhGitHubAdapter(
            Runner(*(GhCommandResult(0, json.dumps(page)) for page in overflow_pages)), health(GitHubReadOperation.COMMENTS),
        ).read(comments_request())
        self.assertFalse(overflow.ok)
        self.assertEqual(overflow.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_broker_completeness_uses_native_requested_reviewer_pages(self) -> None:
        import json

        reviewers = ("alice", "octocat")
        reviewer_digest = "sha256:" + hashlib.sha256(
            json.dumps(("reviewers", reviewers), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        ).hexdigest()
        intent = GitHubMutationIntent(
            GitHubMutationOperation.REQUEST_REVIEW, REPOSITORY, "native-reviewers-46",
            target_number=46, expected_sha=SHA, payload=(("reviewers_digest", reviewer_digest),),
        )
        context = allowed_context()
        plan = _broker_semantic_plan(intent)
        runner = Runner(
            GhCommandResult(0, json.dumps(gh_requested_reviewers_page("alice", next_cursor="cursor-1", total=2))),
            GhCommandResult(0, json.dumps(gh_requested_reviewers_page("octocat", total=2))),
        )
        result, receipt = _complete_broker_read(
            GhGitHubAdapter(runner, health(GitHubReadOperation.REQUESTED_REVIEWERS)),
            plan.pre_state, context, schema_v2_authorization_bundle(context), plan, None,
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.reviewers, reviewers)  # type: ignore[union-attr]
        self.assertTrue(receipt.startswith("sha256:"))
        self.assertEqual(len(runner.calls), 2)

    def test_collection_completeness_consumes_single_and_multi_page_typed_results(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "paged-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        plan = _broker_semantic_plan(intent)
        request = comments_request()
        single = PagedFakeGitHubAdapter({}, {None: comments_page(None, None, 1, comment("comment-01"))})
        one, one_receipt = _complete_broker_read(single, request, context, bundle, plan, None)
        self.assertTrue(one.ok)
        self.assertTrue(one_receipt.startswith("sha256:"))
        self.assertEqual([item.comment_id for item in one.snapshot.comments], ["comment-01"])  # type: ignore[union-attr]

        multi = PagedFakeGitHubAdapter({}, {
            None: comments_page(None, "cursor-1", 2, comment("comment-01")),
            "cursor-1": comments_page("cursor-1", None, 2, comment("comment-02", DIGEST)),
        })
        complete, receipt = _complete_broker_read(multi, request, context, bundle, plan, None)
        self.assertTrue(complete.ok)
        self.assertEqual([item.comment_id for item in complete.snapshot.comments], ["comment-01", "comment-02"])  # type: ignore[union-attr]
        self.assertNotEqual(one_receipt, receipt)
        self.assertEqual(multi.page_requests, [(request, None), (request, "cursor-1")])

    def test_incomplete_or_drifting_collection_pages_deny_before_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "reject-paging-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        other_request = GitHubReadRequest(GitHubReadOperation.COMMENTS, REPOSITORY, number=47)
        over_limit: dict[str | None, object] = {}
        for index in range(33):
            cursor = None if index == 0 else f"cursor-{index - 1:02d}"
            next_cursor = None if index == 32 else f"cursor-{index:02d}"
            over_limit[cursor] = comments_page(cursor, next_cursor, 33, comment(f"comment-{index:02d}"))
        cases: dict[str, dict[str | None, object]] = {
            "missing": {None: None},
            "request-drift": {None: comments_page(None, None, 1, comment("comment-01"), request=other_request)},
            "truncated": {None: comments_page(None, None, 2, comment("comment-01"))},
            "cyclic": {
                None: comments_page(None, "cursor-1", 2, comment("comment-01")),
                "cursor-1": comments_page("cursor-1", "cursor-1", 2, comment("comment-02", DIGEST)),
            },
            "inconsistent-total": {
                None: comments_page(None, "cursor-1", 2, comment("comment-01")),
                "cursor-1": comments_page("cursor-1", None, 1, comment("comment-02", DIGEST)),
            },
            "duplicate-conflict": {
                None: comments_page(None, "cursor-1", 1, comment("comment-01")),
                "cursor-1": comments_page("cursor-1", None, 1, comment("comment-01", DIGEST)),
            },
            "unstable-order": {
                None: comments_page(None, "cursor-1", 2, comment("comment-02", DIGEST)),
                "cursor-1": comments_page("cursor-1", None, 2, comment("comment-01")),
            },
            "over-limit": over_limit,
        }
        for name, pages in cases.items():
            with self.subTest(name=name):
                adapter = PagedFakeGitHubAdapter(
                    {intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST)}, pages,
                )
                result = GitHubMutationBroker(adapter).submit(intent, allowed_context())
                self.assertFalse(result.ok)
                self.assertEqual(adapter.call_count(kind="mutation"), 0)

    def test_gh_adapter_projects_rest_comment_schema_and_rejects_identity_drift(self) -> None:
        raw = gh_comments_page()
        runner = Runner(GhCommandResult(0, json.dumps(raw)), GhCommandResult(0, json.dumps({"number": 47, "state": "OPEN", "id": 46})))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS, GitHubReadOperation.ISSUE))
        self.assertTrue(adapter.read(comments_request()).ok)
        self.assertFalse(adapter.read(GitHubReadRequest(GitHubReadOperation.ISSUE, REPOSITORY, number=46)).ok)

    def test_gh_adapter_requires_native_collection_pageinfo_and_binds_each_page(self) -> None:
        first = gh_comments_page(next_cursor="cursor-1", total=2)
        second = gh_comments_page(present=False, total=2)
        malformed = gh_comments_page(next_cursor="cursor-2", total=1)
        malformed["data"]["repository"]["owner"]["login"] = "drift"  # type: ignore[index]
        runner = Runner(GhCommandResult(0, json.dumps(first)), GhCommandResult(0, json.dumps(second)), GhCommandResult(0, json.dumps(malformed)))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS))
        initial = adapter.read_collection_page(comments_request(), None)
        terminal = adapter.read_collection_page(comments_request(), "cursor-1")
        rejected = adapter.read_collection_page(comments_request(), "cursor-2")
        self.assertEqual(initial.next_cursor, "cursor-1")  # type: ignore[union-attr]
        self.assertIsNone(terminal.next_cursor)  # type: ignore[union-attr]
        self.assertIsNone(rejected)
        self.assertEqual(runner.calls[0][:2], ("api", "graphql"))

    def test_gh_adapter_projects_terminal_graphql_closing_references(self) -> None:
        request = GitHubReadRequest(GitHubReadOperation.CLOSING_REFERENCES, REPOSITORY, number=46, expected_sha=SHA)
        raw = {
            "data": {"repository": {
                "name": "roundwright", "owner": {"login": "example"},
                "pullRequest": {"number": 46, "headRefOid": SHA, "closingIssuesReferences": {
                    "nodes": [{"number": 46}], "pageInfo": {"hasNextPage": False, "endCursor": "Y3Vyc29yOjE="},
                }},
            }},
        }
        runner = Runner(GhCommandResult(0, json.dumps(raw)), GhCommandResult(0, json.dumps({**raw, "data": {"repository": {**raw["data"]["repository"], "pullRequest": {**raw["data"]["repository"]["pullRequest"], "closingIssuesReferences": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"}}}}}})))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.CLOSING_REFERENCES))
        result = adapter.read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.references[0].issue_number, 46)  # type: ignore[union-attr]
        self.assertEqual(runner.calls[0][:2], ("api", "graphql"))
        self.assertFalse(adapter.read(request).ok)

    def test_malformed_or_partial_capability_matrix_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            GitHubCapabilityHealth(())
        matrix = unavailable_capability_health(now=NOW)
        self.assertFalse(matrix.for_operation(GitHubMutationOperation.MERGE_PULL_REQUEST).available)

    def test_durable_journal_binds_full_evidence_and_rejects_conflicts(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        conflicting = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-46", target_number=46, payload=(("body_digest", DIGEST),))
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        entry = MutationJournalEntry.from_evidence(intent, context, bundle, _broker_semantic_plan(intent))
        with tempfile.TemporaryDirectory() as directory:
            first = DurableMutationJournal(Path(directory) / "journal.json")
            claimed, created = first.claim(entry)
            self.assertTrue(created)
            self.assertIs(claimed.lifecycle, JournalLifecycle.PENDING)
            with self.assertRaises(ValueError):
                first.claim(MutationJournalEntry.from_evidence(conflicting, context, bundle, _broker_semantic_plan(conflicting)))
            captured = first.transition(
                claimed, JournalLifecycle.PRESTATE_CAPTURED,
                pre_state_digest=DIGEST, pre_state_completeness_identity=DIGEST,
            )
            started = first.transition(captured, JournalLifecycle.EXECUTION_STARTED)
            accepted = first.transition(
                started, JournalLifecycle.TRANSPORT_ACCEPTED,
                created_resource=comment_locator(),
            )
            first.transition(accepted, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
            with self.assertRaises(ValueError):
                first.transition(entry, JournalLifecycle.FAILED)
            restarted = DurableMutationJournal(Path(directory) / "journal.json")
            observed = restarted.find(entry)
            self.assertIsNotNone(observed)
            self.assertIs(observed.lifecycle, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)  # type: ignore[union-attr]

    def test_prestate_provenance_must_be_complete_and_stale_callers_cannot_skip_it(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "prestate-contract-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context = allowed_context()
        evidence = MutationJournalEntry.from_evidence(
            intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent),
        )
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            claimed, _ = journal.claim(evidence)
            with self.assertRaises(ValueError):
                journal.transition(claimed, JournalLifecycle.EXECUTION_STARTED)
            with self.assertRaises(ValueError):
                journal.transition(
                    claimed, JournalLifecycle.PRESTATE_CAPTURED,
                    pre_state_digest=DIGEST,
                )
            captured = journal.transition(
                claimed, JournalLifecycle.PRESTATE_CAPTURED,
                pre_state_digest=DIGEST, pre_state_completeness_identity=DIGEST,
            )
            with self.assertRaises(ValueError):
                journal.transition(claimed, JournalLifecycle.EXECUTION_STARTED)
            started = journal.transition(captured, JournalLifecycle.EXECUTION_STARTED)
            self.assertTrue(started.pre_state_complete)
            self.assertEqual(started.pre_state_read_identity, _pre_dispatch_reads_identity(_broker_semantic_plan(intent)))
            with self.assertRaises(ValueError):
                journal.find_recovery(intent, replace(context, candidate_sha=BASE), _broker_semantic_plan(intent))
            encoded = dict(started.serialize())
            encoded["pre_state_digest"] = "sha256:" + "f" * 64
            with self.assertRaises(ValueError):
                MutationJournalEntry.deserialize(encoded)
            encoded = dict(started.serialize())
            encoded["pre_state_completeness_identity"] = "sha256:" + "e" * 64
            with self.assertRaises(ValueError):
                MutationJournalEntry.deserialize(encoded)

    def test_exact_already_satisfied_prestate_is_verified_without_dispatch(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.CLOSE_ISSUE, REPOSITORY, "preclosed-46",
            target_number=46, payload=(("reason", "COMPLETED"),),
        )
        context = allowed_context(RepositoryMutationOperation.CLOSE_LEAF_ISSUE)
        plan = _broker_semantic_plan(intent)
        closed = {
            "repository": {"owner": "example", "name": "roundwright"},
            "id": "issue-46", "number": 46, "state": "CLOSED",
            "parent_number": None, "sub_issue_numbers": [],
            "issue_evidence_identity": DIGEST,
            "relationship_evidence_identity": "sha256:" + "d" * 64,
        }
        adapter = FakeGitHubAdapter({plan.pre_state.identity(): FakeGitHubScenario(response=closed)})
        with tempfile.TemporaryDirectory() as directory:
            result = GitHubMutationBroker(
                adapter, journal=DurableMutationJournal(Path(directory) / "journal.json"),
            ).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(adapter.call_count(kind="mutation"), 0)
            self.assertEqual(adapter.call_count(kind="read"), 1)
            self.assertEqual(result.receipt.disposition, MutationDisposition.ALREADY_APPLIED)  # type: ignore[union-attr]

    def test_journal_time_fields_reject_individual_and_recomputed_drift(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "time-drift-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        entry = MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent))
        for field, value in (
            ("evaluated_at", "2026-08-08T00:00:00+00:00"),
            ("fresh_until", "2026-08-08T00:05:00+00:00"),
            ("time_identity", DIGEST),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                replace(entry, **{field: value})
        serialized = dict(entry.serialize())
        serialized["evaluated_at"] = "2026-08-08T00:00:00+00:00"
        serialized["time_identity"] = "sha256:" + hashlib.sha256(json.dumps((serialized["evaluated_at"], serialized["fresh_until"]), separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        altered = MutationJournalEntry.deserialize(serialized)
        self.assertNotEqual(altered, entry)

    def test_persisted_receipt_time_drift_is_rejected(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "receipt-time-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        plan = _broker_semantic_plan(intent)
        entry = MutationJournalEntry.from_evidence(intent, context, bundle, plan)
        accepted = checkpointed_journal_entry(
            intent, context, JournalLifecycle.TRANSPORT_ACCEPTED,
            locator=comment_locator(),
        )
        receipt = GitHubMutationBroker._semantic_receipt(
            intent, context, bundle, plan, DIGEST, DIGEST, DIGEST, DIGEST,
            "comment-46", MutationDisposition.ACCEPTED, durable_entry=accepted,
        )
        verified = replace(accepted, lifecycle=JournalLifecycle.VERIFIED, receipt=receipt)
        encoded = dict(verified.serialize())
        encoded_receipt = dict(encoded["receipt"])
        encoded_receipt["fresh_until"] = "2026-08-08T00:05:00+00:00"
        encoded_receipt["time_identity"] = "sha256:" + hashlib.sha256(json.dumps((encoded_receipt["evaluated_at"], encoded_receipt["fresh_until"]), separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        encoded["receipt"] = encoded_receipt
        with self.assertRaises(ValueError):
            MutationJournalEntry.deserialize(encoded)

    def test_recovery_at_fresh_until_minus_one_microsecond_reads(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "fresh-boundary-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        initial = allowed_context()
        bundle, plan = schema_v2_authorization_bundle(initial), _broker_semantic_plan(intent)
        entry = checkpointed_journal_entry(
            intent, initial, JournalLifecycle.TRANSPORT_ACCEPTED,
            locator=comment_locator(),
        )
        now = NOW + timedelta(minutes=5) - timedelta(microseconds=1)
        context = replace(initial, evaluated_at=now)
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
        broker = GitHubMutationBroker(adapter, clock=lambda: now)
        result = broker._reconcile_journal(intent, context, bundle, plan, entry, entry)
        self.assertTrue(result.ok)
        self.assertEqual(adapter.call_count(kind="read"), 1)

    def test_recovery_at_fresh_until_denies_without_calls(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "expired-boundary-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        initial = allowed_context()
        bundle, plan = schema_v2_authorization_bundle(initial), _broker_semantic_plan(intent)
        entry = MutationJournalEntry.from_evidence(intent, initial, bundle, plan)
        now = NOW + timedelta(minutes=5)
        context = replace(initial, evaluated_at=now)
        adapter = FakeGitHubAdapter()
        broker = GitHubMutationBroker(adapter, clock=lambda: now)
        result = broker._reconcile_journal(intent, context, bundle, plan, entry, entry)
        self.assertFalse(result.ok)
        self.assertEqual(adapter.call_count(), 0)

    def test_comment_recovery_blocks_unstarted_and_reads_started_provenance(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-state-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle, plan = schema_v2_authorization_bundle(context), _broker_semantic_plan(intent)
        claimed = checkpointed_journal_entry(intent, context, JournalLifecycle.CLAIMED)
        for state in (JournalLifecycle.CLAIMED, JournalLifecycle.PRESTATE_CAPTURED):
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            entry = checkpointed_journal_entry(intent, context, state)
            result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, entry, entry)
            self.assertFalse(result.ok)
            self.assertEqual(adapter.call_count(), 0)
        started = checkpointed_journal_entry(intent, context, JournalLifecycle.EXECUTION_STARTED)
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
        result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, started, started)
        self.assertFalse(result.ok)
        self.assertEqual(adapter.call_count(), 0)
        for state in (JournalLifecycle.TRANSPORT_ACCEPTED, JournalLifecycle.AMBIGUOUS):
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            entry = checkpointed_journal_entry(intent, context, state, locator=comment_locator())
            result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, entry, entry)
            self.assertTrue(result.ok)
            self.assertNotEqual(result.receipt.affected_identity, "reconciled")  # type: ignore[union-attr]
        empty = {**comments_payload(), "comments": []}
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=empty)})
        ambiguous = checkpointed_journal_entry(
            intent, context, JournalLifecycle.AMBIGUOUS, locator=comment_locator(),
        )
        result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, ambiguous, ambiguous)
        self.assertFalse(result.ok)
        self.assertTrue(result.reconciliation_required)

    def test_checkpoint_observer_stops_after_persisted_prestate(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "observer-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            def stop(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.PRESTATE_CAPTURED:
                    raise RuntimeError("crash")
            broker = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(OwnerTransport(), health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )), checkpoint_observer=stop,
            )
            with self.assertRaises(RuntimeError):
                broker.submit(intent, allowed_context(), payload=GhMutationPayload(
                    GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
                ))
            stored = journal.find(MutationJournalEntry.from_evidence(intent, allowed_context(), schema_v2_authorization_bundle(allowed_context()), _broker_semantic_plan(intent)))
            self.assertIs(stored.lifecycle, JournalLifecycle.PRESTATE_CAPTURED)  # type: ignore[union-attr]
            self.assertEqual(adapter.call_count(kind="mutation"), 0)

    def test_execution_started_crash_recovers_without_second_comment_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "started-crash-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        evidence = MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent))
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            transport = OwnerTransport()
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.EXECUTION_STARTED:
                    raise RuntimeError("crash")
            with self.assertRaises(RuntimeError):
                GitHubMutationBroker(
                    adapter, journal=journal,
                    _executor=_GhBrokerExecutor(transport, health(
                        GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                    )), checkpoint_observer=crash,
                ).submit(intent, context, payload=GhMutationPayload(
                    GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
                ))
            stored = journal.find(evidence)
            self.assertIs(stored.lifecycle, JournalLifecycle.EXECUTION_STARTED)  # type: ignore[union-attr]
            self.assertTrue(stored.pre_state_complete)  # type: ignore[union-attr]
            self.assertEqual(adapter.call_count(kind="mutation"), 0)
            restart = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(restart, journal=DurableMutationJournal(Path(directory) / "journal.json")).submit(intent, context)
            self.assertFalse(result.ok)
            self.assertEqual(restart.call_count(kind="mutation"), 0)
            self.assertEqual(restart.call_count(kind="read"), 0)
            self.assertEqual(transport.requests, [])

    def test_transport_accepted_crash_recovers_without_second_transport(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "accepted-crash-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
            transport = OwnerTransport()
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
                    raise RuntimeError("crash")
            broker = GitHubMutationBroker.with_owner_transport(owner_read_endpoint(runner, matrix), owner_endpoint(transport), journal=journal, binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW, checkpoint_observer=crash)
            with self.assertRaises(RuntimeError):
                broker.submit(intent, context, payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),)))
            entry = MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context, health=matrix), _broker_semantic_plan(intent))
            stored = journal.find(entry)
            self.assertIs(stored.lifecycle, JournalLifecycle.TRANSPORT_ACCEPTED)  # type: ignore[union-attr]
            self.assertEqual(len(transport.requests), 1)
            restart_runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
            restart_transport = OwnerTransport()
            result = GitHubMutationBroker.with_owner_transport(
                owner_read_endpoint(restart_runner, matrix), owner_endpoint(restart_transport),
                journal=DurableMutationJournal(Path(directory) / "journal.json"),
                binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW,
            ).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(restart_transport.requests, [])
            self.assertEqual(result.receipt.pre_state_digest, stored.pre_state_digest)  # type: ignore[union-attr]

    def test_applied_awaiting_verification_crash_recovers_without_duplicate_transport(self) -> None:
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "applied-crash-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        context = allowed_context()
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            transport = OwnerTransport()
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.APPLIED_AWAITING_VERIFICATION:
                    raise RuntimeError("crash after application checkpoint")
            with self.assertRaises(RuntimeError):
                GitHubMutationBroker(
                    FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())}),
                    journal=DurableMutationJournal(path),
                    _executor=_GhBrokerExecutor(transport, matrix), checkpoint_observer=crash,
                ).submit(intent, context, payload=GhMutationPayload(
                    GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
                ))
            evidence = MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent),
            )
            stored = DurableMutationJournal(path).find(evidence)
            self.assertIs(stored.lifecycle, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)  # type: ignore[union-attr]
            recovered = GitHubMutationBroker(
                FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())}),
                journal=DurableMutationJournal(path),
            ).submit(intent, context)
            self.assertTrue(recovered.ok)
            self.assertEqual(len(transport.requests), 1)

    def test_execution_started_incomplete_postread_remains_blocked(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "started-incomplete-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle, plan = schema_v2_authorization_bundle(context), _broker_semantic_plan(intent)
        entry = checkpointed_journal_entry(intent, context, JournalLifecycle.EXECUTION_STARTED)
        adapter = FakeGitHubAdapter()
        result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, entry, entry)
        self.assertFalse(result.ok)
        self.assertFalse(result.reconciliation_required)
        self.assertEqual(adapter.call_count(kind="mutation"), 0)

    def test_journal_verified_receipt_is_reused_across_restart_without_adapter_calls(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-reuse-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            fake = FakeGitHubAdapter({
                request.identity(): FakeGitHubScenario(response=comments_payload()),
                intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST),
            })
            transport = OwnerTransport()
            first = GitHubMutationBroker(
                fake, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(first.ok)
            self.assertEqual(len(transport.requests), 1)
            restarted_fake = FakeGitHubAdapter()
            retry = GitHubMutationBroker(
                restarted_fake, journal=DurableMutationJournal(Path(directory) / "journal.json"),
            ).submit(intent, allowed_context())
            self.assertTrue(retry.ok)
            self.assertEqual(retry.receipt, first.receipt)
            self.assertEqual(restarted_fake.call_count(), 0)

    def test_journal_ambiguous_retry_reconciles_without_duplicate_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-ambiguous-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        empty = {**comments_payload(), "comments": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            first_fake = FakeGitHubAdapter({
                request.identity(): FakeGitHubScenario(response=empty),
                intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST),
            })
            transport = OwnerTransport()
            first = GitHubMutationBroker(
                first_fake, journal=DurableMutationJournal(path),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertFalse(first.ok)
            self.assertTrue(first.reconciliation_required)
            self.assertEqual(len(transport.requests), 1)
            reconciler = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=comments_payload())})
            retry = GitHubMutationBroker(
                reconciler, journal=DurableMutationJournal(path),
            ).submit(intent, allowed_context())
            self.assertTrue(retry.ok)
            self.assertEqual(retry.receipt.disposition, MutationDisposition.ALREADY_APPLIED)  # type: ignore[union-attr]
            self.assertEqual(reconciler.call_count(kind="mutation"), 0)

    def test_journal_applied_awaiting_verification_recovers_without_second_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-applied-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        evidence = MutationJournalEntry.from_evidence(intent, context, bundle, _broker_semantic_plan(intent))
        request = comments_request()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            journal = DurableMutationJournal(path)
            claimed, _ = journal.claim(evidence)
            captured = journal.transition(
                claimed, JournalLifecycle.PRESTATE_CAPTURED,
                pre_state_digest=DIGEST, pre_state_completeness_identity=DIGEST,
            )
            started = journal.transition(captured, JournalLifecycle.EXECUTION_STARTED)
            accepted = journal.transition(
                started, JournalLifecycle.TRANSPORT_ACCEPTED,
                created_resource=comment_locator(),
            )
            journal.transition(accepted, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
            reconciler = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(reconciler, journal=DurableMutationJournal(path)).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(result.receipt.disposition, MutationDisposition.ALREADY_APPLIED)  # type: ignore[union-attr]
            self.assertEqual(reconciler.call_count(kind="mutation"), 0)

    def test_journal_corruption_and_missing_reconciliation_fail_closed_before_adapter_calls(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "journal-corrupt-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.json"
            path.write_text("{not-json", encoding="utf-8")
            fake = FakeGitHubAdapter()
            denied = GitHubMutationBroker(fake, journal=DurableMutationJournal(path)).submit(intent, allowed_context())
            self.assertFalse(denied.ok)
            self.assertEqual(fake.call_count(), 0)
            path.unlink()
            missing = GitHubMutationBroker(fake, journal=DurableMutationJournal(path)).reconcile(intent, allowed_context())
            self.assertFalse(missing.ok)
            self.assertEqual(fake.call_count(), 0)
            path.with_suffix(path.suffix + ".tmp").write_text("{}", encoding="utf-8")
            torn = GitHubMutationBroker(fake, journal=DurableMutationJournal(path)).submit(intent, allowed_context())
            self.assertFalse(torn.ok)
            self.assertEqual(fake.call_count(), 0)

    def test_broker_requires_policy_deployment_candidate_and_prestate_before_adapter_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        fake = FakeGitHubAdapter({intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST)})
        result = GitHubMutationBroker(fake).submit(intent, allowed_context(RepositoryMutationOperation.MARK_PR_READY))
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(fake.call_count(), 0)

    def test_broker_receipt_binds_pre_and_post_state_and_retries_without_second_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        fake = FakeGitHubAdapter({
            request.identity(): FakeGitHubScenario(response=comments_payload()),
            intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST),
        })
        with tempfile.TemporaryDirectory() as directory:
            transport = OwnerTransport()
            broker = GitHubMutationBroker(
                fake, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            )
            first = broker.submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(first.ok)
            self.assertEqual(first.receipt.candidate_sha, SHA)  # type: ignore[union-attr]
            self.assertTrue(first.receipt.receipt_digest.startswith("sha256:"))  # type: ignore[union-attr]
            self.assertEqual(len(transport.requests), 1)
            second = broker.submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertTrue(second.ok)
            self.assertEqual(second.receipt, first.receipt)
            self.assertEqual(len(transport.requests), 1)

    def test_ambiguous_post_state_requires_reconciliation_not_invented_success(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        fake = FakeGitHubAdapter({
            request.identity(): FakeGitHubScenario(response={**comments_payload(), "comments": []}),
            intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST),
        })
        with tempfile.TemporaryDirectory() as directory:
            transport = OwnerTransport()
            result = GitHubMutationBroker(
                fake, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT,
                )),
            ).submit(intent, allowed_context(), payload=GhMutationPayload(
                GitHubMutationOperation.COMMENT, (("body", "curated evidence"),),
            ))
            self.assertFalse(result.ok)
            self.assertTrue(result.reconciliation_required)
            self.assertEqual(len(transport.requests), 1)

    def test_brokered_gh_execution_runs_once_while_direct_submit_stays_denied(self) -> None:
        request = comments_request()
        body = "curated evidence"
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        runner = Runner(
            GhCommandResult(0, json.dumps(gh_comments_page())),
            GhCommandResult(0, json.dumps(gh_comments_page())),
        )
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        with tempfile.TemporaryDirectory() as directory:
            transport = OwnerTransport()
            broker = GitHubMutationBroker.with_owner_transport(owner_read_endpoint(runner, matrix), owner_endpoint(transport), journal=DurableMutationJournal(Path(directory) / "journal.json"), binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW)
            result = broker.submit(intent, allowed_context(), payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", body),)))
            self.assertTrue(result.ok)
            self.assertEqual(len(runner.calls), 2)
            self.assertEqual(len(transport.requests), 1)
            direct = GhGitHubAdapter(runner, matrix).submit(intent)
            self.assertFalse(direct.ok)
            self.assertEqual(direct.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
            self.assertEqual(len(runner.calls), 2)
            retry = broker.submit(intent, allowed_context(), payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", body),)))
            self.assertTrue(retry.ok)
            self.assertEqual(len(runner.calls), 2)

    def test_brokered_gh_ambiguous_readback_reconciles_without_duplicate_write(self) -> None:
        request = comments_request()
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        empty = gh_comments_page(present=False)
        runner = Runner(
            GhCommandResult(0, json.dumps(empty)),
            GhCommandResult(0, json.dumps(empty)),
            GhCommandResult(0, json.dumps(empty)),
        )
        matrix = health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT)
        with tempfile.TemporaryDirectory() as directory:
            broker = GitHubMutationBroker.with_owner_transport(owner_read_endpoint(runner, matrix), owner_endpoint(), journal=DurableMutationJournal(Path(directory) / "journal.json"), binding=owner_broker_binding(), controls=owner_broker_controls(), clock=lambda: NOW)
            payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
            first = broker.submit(intent, allowed_context(), payload=payload)
            self.assertFalse(first.ok)
            self.assertTrue(first.reconciliation_required)
            self.assertEqual(len(runner.calls), 2)
            reconciled = broker.reconcile(intent, allowed_context())
            self.assertFalse(reconciled.ok)
            self.assertTrue(reconciled.reconciliation_required)
            self.assertEqual(len(runner.calls), 3)

    def test_direct_execution_surface_is_absent_for_every_declared_mutation(self) -> None:
        title, body, reviewers = "draft title", "draft body", "octocat"
        title_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-title", title), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        body_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-body", body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        reviewers_digest = "sha256:" + hashlib.sha256(json.dumps(("reviewers", (reviewers,)), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        intents = (
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "branch-46", expected_sha=SHA, target_ref="codex/issue-46"), GhMutationPayload(GitHubMutationOperation.CREATE_BRANCH)),
            (GitHubMutationIntent(GitHubMutationOperation.UPDATE_BRANCH, REPOSITORY, "branch-update-46", expected_sha=SHA, target_ref="codex/issue-46", payload=(("previous_sha", BASE),)), GhMutationPayload(GitHubMutationOperation.UPDATE_BRANCH)),
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", target_number=46, payload=(("base_ref", "main"), ("base_sha", SHA), ("body_digest", body_digest), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", title_digest))), GhMutationPayload(GitHubMutationOperation.CREATE_PULL_REQUEST, (("body", body), ("title", title)))),
            (GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),)), GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))),
            (GitHubMutationIntent(GitHubMutationOperation.REQUEST_REVIEW, REPOSITORY, "review-46", target_number=46, expected_sha=SHA, payload=(("reviewers_digest", reviewers_digest),)), GhMutationPayload(GitHubMutationOperation.REQUEST_REVIEW, (("reviewers", reviewers),))),
            (GitHubMutationIntent(GitHubMutationOperation.MARK_READY, REPOSITORY, "ready-46", target_number=46, expected_sha=SHA), GhMutationPayload(GitHubMutationOperation.MARK_READY)),
            (GitHubMutationIntent(GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "merge-46", target_number=46, expected_sha=SHA, payload=(("method", "merge"),)), GhMutationPayload(GitHubMutationOperation.MERGE_PULL_REQUEST)),
            (GitHubMutationIntent(GitHubMutationOperation.CLOSE_ISSUE, REPOSITORY, "close-46", target_number=46, payload=(("reason", "COMPLETED"),)), GhMutationPayload(GitHubMutationOperation.CLOSE_ISSUE)),
            (GitHubMutationIntent(GitHubMutationOperation.DELETE_BRANCH, REPOSITORY, "delete-46", expected_sha=SHA, target_ref="codex/issue-46"), GhMutationPayload(GitHubMutationOperation.DELETE_BRANCH)),
        )
        runner = Runner(*(GhCommandResult(0, "unretained output") for _ in intents))
        adapter = GhGitHubAdapter(runner, health(*GitHubMutationOperation))
        self.assertFalse(hasattr(adapter, "execute_brokered"))
        self.assertFalse(hasattr(adapter, "_execute_brokered"))
        self.assertFalse(hasattr(adapter, "_issue_broker_capability"))
        for intent, payload in intents:
            with self.subTest(operation=intent.operation):
                self.assertFalse(adapter.submit(intent).ok)
        self.assertEqual(runner.calls, [])

    def test_role_runtime_has_no_process_or_credential_runner(self) -> None:
        """This role-visible module owns no subprocess or credential capability."""
        import roundwright.github_runtime as runtime

        self.assertFalse(hasattr(runtime, "subprocess"))
        self.assertFalse(hasattr(runtime, "_OwnerFixedGhReadExecutor"))

    def test_missing_owner_transport_denies_payload_before_reads_or_adapter_mutation(self) -> None:
        """Payload never activates the legacy adapter when no owner endpoint exists."""
        intent = GitHubMutationIntent(
            GitHubMutationOperation.COMMENT, REPOSITORY, "no-owner-transport-46",
            target_number=46, payload=(("body_digest", COMMENT_DIGEST),),
        )
        runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
        adapter = GhGitHubAdapter(
            runner, health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT),
        )
        result = GitHubMutationBroker(adapter).submit(
            intent, allowed_context(),
            payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),)),
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(runner.calls, [])
        self.assertEqual(adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
