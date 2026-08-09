"""Hermetic coverage for the ``gh`` process seam and mutation broker."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from uuid import UUID

from roundwright.deployment import (
    AuthorityReceiptStatus, AuthorityReceiptVerification, DeploymentAuthorityDecision,
    DeploymentAuthorityReceipt, DeploymentIdentity, DeploymentMode,
    _receipt_binding_fingerprint, evaluate_deployment_authority,
)
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
    GhCommandResult,
    DurableMutationJournal,
    GhGitHubAdapter,
    GhMutationPayload,
    GitHubCapabilityHealth,
    GitHubMutationBroker,
    JournalLifecycle,
    MutationJournalEntry,
    MutationBrokerContext,
    OwnerMutationFact,
    OwnerMutationAcceptedFact,
    OwnerMutationRequest,
    OperationHealth,
    SemanticPostcondition,
    SemanticReadback,
    _broker_semantic_plan,
    _complete_broker_read,
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


class Runner:
    def __init__(self, *results: GhCommandResult) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult:
        self.calls.append(arguments)
        return self.results.pop(0)


class OwnerTransport:
    def __init__(self, accepted: bool = True, created_resource: CreatedResourceLocator | None = None) -> None:
        self.accepted = accepted
        self.created_resource = created_resource
        self.requests: list[OwnerMutationRequest] = []

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact | OwnerMutationAcceptedFact:
        self.requests.append(request)
        identity = "sha256:" + hashlib.sha256(json.dumps((request.intent_identity, request.operation.value, request.authorization_bundle_identity, request.semantic_plan_identity, request.journal_identity), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        if not self.accepted:
            return OwnerMutationFact(False, identity)
        locator: CreatedResourceLocator | None = None
        if request.operation is GitHubMutationOperation.CREATE_PULL_REQUEST:
            locator = CreatedResourceLocator(
                request.operation, request.repository, pull_request_number=58,
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


class PagedFakeGitHubAdapter(FakeGitHubAdapter):
    """Hermetic typed collection-page fixture; it never invokes a provider."""

    def __init__(self, scenarios: dict[str, FakeGitHubScenario], pages: dict[str | None, object]) -> None:
        super().__init__(scenarios)
        self.pages = pages
        self.page_requests: list[tuple[GitHubReadRequest, str | None]] = []

    def read_collection_page(self, request: GitHubReadRequest, cursor: str | None) -> object:
        self.page_requests.append((request, cursor))
        return self.pages.get(cursor)


def health(*available: object) -> GitHubCapabilityHealth:
    return GitHubCapabilityHealth(
        tuple(
            OperationHealth(operation, CapabilityState.AVAILABLE if operation in available else CapabilityState.UNAVAILABLE, NOW, "sha256:" + hashlib.sha256(str(index).encode("utf-8")).hexdigest())
            for index, operation in enumerate((*GitHubReadOperation, *GitHubMutationOperation))
        )
    )


def comments_request() -> GitHubReadRequest:
    return GitHubReadRequest(GitHubReadOperation.COMMENTS, REPOSITORY, number=46)


def reviews_request() -> GitHubReadRequest:
    return GitHubReadRequest(GitHubReadOperation.REVIEWS, REPOSITORY, number=46, expected_sha=SHA)


def comments_payload() -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "issue_number": 46,
        "comments": [{"id": "comment-46", "author_id": "owner-1", "body": "curated evidence", "created_at": "2026-08-07T00:00:00Z"}],
    }


def repository_payload() -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "id": "repository-1", "default_branch": "main", "default_branch_sha": BASE,
        "repository_evidence_identity": DIGEST,
        "default_branch_evidence_identity": "sha256:" + "d" * 64,
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


def pull_request_payload(*, number: int = 58, base_sha: str = BASE, head_sha: str = SHA, draft: bool = True, state: str = "OPEN", merge_commit_sha: str | None = None) -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"}, "id": f"pr-{number}",
        "number": number, "state": state, "base_ref": "main", "base_sha": base_sha,
        "head_ref": "codex/issue-46", "head_sha": head_sha, "draft": draft,
        "merge_commit_sha": merge_commit_sha,
    }


def gh_comments_page(*, present: bool = True, next_cursor: str | None = None, total: int | None = None) -> dict[str, object]:
    count = (1 if present else 0) if total is None else total
    return {
        "data": {"repository": {
            "name": "roundwright", "owner": {"login": "example"},
            "issue": {"number": 46, "comments": {
                "totalCount": count,
                "nodes": ([] if not present else [{"id": "comment-46", "author": {"__typename": "User", "login": "OctoCat"}, "body": "curated evidence", "createdAt": "2026-08-07T00:00:00Z"}]),
                "pageInfo": {"hasNextPage": next_cursor is not None, "endCursor": next_cursor},
            }},
        }},
    }


def gh_reviews_page(*, present: bool = True, next_cursor: str | None = None, total: int | None = None) -> dict[str, object]:
    count = (1 if present else 0) if total is None else total
    return {
        "data": {"repository": {
            "name": "roundwright", "owner": {"login": "example"},
            "pullRequest": {"number": 46, "headRefOid": SHA, "reviews": {
                "totalCount": count,
                "nodes": ([] if not present else [{"id": "review-46", "author": {"__typename": "Bot", "login": "Build-Bot"}, "state": "APPROVED", "commit": {"oid": SHA}}]),
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
    return CollectionPage(actual_request, cursor, next_cursor, total, CommentsSnapshot(REPOSITORY, 46, items))


def allowed_context(operation: RepositoryMutationOperation = RepositoryMutationOperation.ISSUE_COMMENT) -> MutationBrokerContext:
    document = RepositoryMutationPolicy(2, True, True, True, True, True, True, True, True, True, True, True, True)
    snapshot = TrustedRepositoryPolicySnapshot(RepositoryPolicySource("0" * 64, "1" * 64), document)
    mutation_context = RepositoryMutationContext("5" * 64, "6" * 64, "7" * 64, SHA)
    transition = RepositoryDispatcherTransition("8" * 64, mutation_context.repository_fingerprint, mutation_context.deployment_fingerprint, mutation_context.candidate_sha, False, True, True)
    receipt = RepositoryActivationReceipt(
        "3" * 64, "4" * 64, snapshot.source.source_fingerprint, snapshot.source.revision_fingerprint,
        snapshot.policy_digest, document.schema_version, mutation_context.repository_fingerprint,
        mutation_context.deployment_fingerprint, mutation_context.task_fingerprint, mutation_context.candidate_sha,
        transition.digest, NOW, NOW + timedelta(hours=1),
    )
    standing = StandingRepositoryAuthority(document)
    verification = RepositoryReceiptVerification("a" * 64, receipt.receipt_fingerprint, receipt.binding_digest, RepositoryReceiptStatus.FRESH)
    policy = evaluate_repository_mutation_policy(
        snapshot, receipt, mutation_context, operation, standing_authority=standing,
        dispatcher_transition=transition, receipt_verification=verification, now=NOW,
    )
    assert policy.authorized
    runtime = RuntimeBinding("roundwright-runtime/v1", DIGEST, "sha256:" + "d" * 64, ("sha256:" + "e" * 64,))
    deployment_identity = DeploymentIdentity(
        mutation_context.repository_fingerprint, "9" * 64, "a" * 64,
        UUID("12345678-1234-5678-1234-567812345678"), mutation_context.deployment_fingerprint, runtime,
    )
    deployment_receipt = DeploymentAuthorityReceipt("f" * 64, deployment_identity, DeploymentMode.AUTHORITATIVE, NOW - timedelta(minutes=1), NOW + timedelta(minutes=1))
    deployment_verification = AuthorityReceiptVerification(
        deployment_receipt.receipt_fingerprint, _receipt_binding_fingerprint(deployment_receipt),
        deployment_identity.repository_fingerprint, deployment_identity.state_id,
        deployment_identity.deployment_fingerprint, AuthorityReceiptStatus.FRESH, runtime,
    )
    deployment = evaluate_deployment_authority(deployment_identity, deployment_receipt, deployment_verification, now=NOW)
    assert deployment.authorized
    return MutationBrokerContext(policy, deployment, DIGEST, BASE, SHA, DIGEST, standing, verification, mutation_context, transition, snapshot, receipt, deployment_identity, deployment_receipt, deployment_verification, NOW)


class GitHubRuntimeTests(unittest.TestCase):
    def test_created_resource_locator_is_total_and_canonical(self) -> None:
        pull_request = CreatedResourceLocator(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
            pull_request_number=58, base_sha=BASE, head_sha=SHA, draft=True,
            marker_digest=COMMENT_DIGEST,
        )
        comment = CreatedResourceLocator(
            GitHubMutationOperation.COMMENT, REPOSITORY, issue_number=46,
            comment_id="comment-46", marker_digest=COMMENT_DIGEST,
        )
        self.assertEqual(pull_request.identity, CreatedResourceLocator(
            GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY,
            pull_request_number=58, base_sha=BASE, head_sha=SHA, draft=True,
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
                pull_request_number=58, base_sha=BASE, head_sha=SHA, draft=False,
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
            plan.pre_state.identity(): FakeGitHubScenario(response=repository_payload()),
            allocated_request.identity(): FakeGitHubScenario(response=pull_request_payload()),
        })
        transport = OwnerTransport()
        with tempfile.TemporaryDirectory() as directory:
            journal = DurableMutationJournal(Path(directory) / "journal.json")
            broker = GitHubMutationBroker(
                adapter, journal=journal,
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.REPOSITORY, GitHubReadOperation.PULL_REQUEST,
                    GitHubMutationOperation.CREATE_PULL_REQUEST,
                )),
            )
            result = broker.submit(intent, context, payload=payload)
            self.assertTrue(result.ok)
            self.assertEqual([call.identity for call in adapter.calls if call.kind == "read"], [
                plan.pre_state.identity(), allocated_request.identity(),
            ])
            self.assertEqual(len(transport.requests), 1)
            stored = journal.find(MutationJournalEntry.from_evidence(
                intent, context, schema_v2_authorization_bundle(context), plan,
            ))
            self.assertEqual(stored.created_resource.pull_request_number, 58)  # type: ignore[union-attr]
            self.assertTrue(result.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]

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
            pull_request_number=58, base_sha=SHA, head_sha=SHA, draft=True,
            marker_digest=body_digest,
        )
        for transport, post_state in (
            (OwnerTransport(created_resource=wrong_locator), None),
            (OwnerTransport(), pull_request_payload(number=46)),
        ):
            with self.subTest(transport=transport, post_state=post_state), tempfile.TemporaryDirectory() as directory:
                scenarios = {plan.pre_state.identity(): FakeGitHubScenario(response=repository_payload())}
                if post_state is not None:
                    scenarios[allocated_request.identity()] = FakeGitHubScenario(response=post_state)
                adapter = FakeGitHubAdapter(scenarios)
                result = GitHubMutationBroker(
                    adapter, journal=DurableMutationJournal(Path(directory) / "journal.json"),
                    _executor=_GhBrokerExecutor(transport, health(
                        GitHubReadOperation.REPOSITORY, GitHubReadOperation.PULL_REQUEST,
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
            initial = FakeGitHubAdapter({plan.pre_state.identity(): FakeGitHubScenario(response=repository_payload())})
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.TRANSPORT_ACCEPTED:
                    raise RuntimeError("crash after allocated acceptance")
            broker = GitHubMutationBroker(
                initial, journal=DurableMutationJournal(path),
                _executor=_GhBrokerExecutor(transport, health(
                    GitHubReadOperation.REPOSITORY, GitHubReadOperation.PULL_REQUEST,
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
            self.assertTrue(result.receipt.affected_identity.startswith("sha256:"))  # type: ignore[union-attr]

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

    def test_context_constructs_schema_v2_bundle_from_canonical_evidence(self) -> None:
        context = allowed_context()
        bundle = schema_v2_authorization_bundle(context)
        self.assertEqual(bundle.repository_identity, context.mutation_context.repository_fingerprint)
        self.assertEqual(bundle.dispatcher_transition_identity, context.dispatcher_transition.evidence_fingerprint)
        self.assertEqual(bundle.dispatcher_transition_digest, context.dispatcher_transition.digest)
        self.assertEqual(bundle.receipt_identity, context.activation_receipt.receipt_fingerprint)
        self.assertEqual(bundle.receipt_binding_digest, context.activation_receipt.binding_digest)
        self.assertIs(bundle.receipt_status, RepositoryReceiptStatus.FRESH)

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
        result = GitHubMutationBroker(fake).submit(intent, context)
        self.assertTrue(result.ok)
        self.assertEqual(fake.call_count(kind="mutation"), 1)
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
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", target_number=46, payload=(("base_ref", "main"), ("base_sha", SHA), ("body_digest", COMMENT_DIGEST), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", COMMENT_DIGEST))), GitHubReadOperation.REPOSITORY, SemanticPostcondition.PULL_REQUEST_DRAFT_AT_CANDIDATE),
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
            "base": {"ref": "main", "sha": BASE, "repo": {"owner": {"login": "example"}, "name": "roundwright"}},
            "head": {"ref": "codex/issue-46", "sha": SHA},
        }
        adapter = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(raw))), health(GitHubReadOperation.PULL_REQUEST))
        result = adapter.read(request)
        self.assertTrue(result.ok)
        self.assertEqual(result.snapshot.merge_commit_sha, "d" * 40)  # type: ignore[union-attr]
        missing = dict(raw)
        missing["merge_commit_sha"] = None
        denied = GhGitHubAdapter(Runner(GhCommandResult(0, json.dumps(missing))), health(GitHubReadOperation.PULL_REQUEST)).read(request)
        self.assertFalse(denied.ok)

    def test_broker_rejects_caller_semantic_overrides_and_incomplete_operations_before_adapter_calls(self) -> None:
        comment = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "override-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        complete = (
            GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "create-46", expected_sha=SHA, target_ref="codex/issue-46"),
            GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", target_number=46, payload=(("base_ref", "main"), ("base_sha", SHA), ("body_digest", COMMENT_DIGEST), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", COMMENT_DIGEST))),
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
                self.assertEqual(result.failure.kind, GitHubFailureKind.STALE_RESPONSE)  # type: ignore[union-attr]
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
        malformed_comment["data"]["repository"]["issue"]["comments"]["nodes"][0]["author"] = {"__typename": "Team", "login": "core"}  # type: ignore[index]
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
            "cursor-1": comments_page("cursor-1", None, 2, comment("comment-01"), comment("comment-02", DIGEST)),
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
            first.transition(entry, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
            with self.assertRaises(ValueError):
                first.transition(entry, JournalLifecycle.FAILED)
            restarted = DurableMutationJournal(Path(directory) / "journal.json")
            observed = restarted.find(entry)
            self.assertIsNotNone(observed)
            self.assertIs(observed.lifecycle, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)  # type: ignore[union-attr]

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
        receipt = GitHubMutationBroker._semantic_receipt(intent, context, bundle, plan, DIGEST, DIGEST, DIGEST, DIGEST, "comment-46", MutationDisposition.ACCEPTED)
        verified = replace(entry, lifecycle=JournalLifecycle.VERIFIED, receipt=receipt)
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
        entry = MutationJournalEntry.from_evidence(intent, initial, bundle, plan)
        entry = replace(entry, lifecycle=JournalLifecycle.EXECUTION_STARTED)
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
        claimed = MutationJournalEntry.from_evidence(intent, context, bundle, plan)
        for state in (JournalLifecycle.CLAIMED, JournalLifecycle.PRESTATE_CAPTURED):
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, claimed, replace(claimed, lifecycle=state))
            self.assertFalse(result.ok)
            self.assertEqual(adapter.call_count(), 0)
        started = replace(claimed, lifecycle=JournalLifecycle.EXECUTION_STARTED)
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
        result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, started, started)
        self.assertTrue(result.ok)
        self.assertNotEqual(result.receipt.affected_identity, "reconciled")  # type: ignore[union-attr]
        for state in (JournalLifecycle.TRANSPORT_ACCEPTED, JournalLifecycle.AMBIGUOUS):
            adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            entry = replace(claimed, lifecycle=state)
            result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, entry, entry)
            self.assertTrue(result.ok)
            self.assertNotEqual(result.receipt.affected_identity, "reconciled")  # type: ignore[union-attr]
        empty = {**comments_payload(), "comments": []}
        adapter = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=empty)})
        ambiguous = replace(claimed, lifecycle=JournalLifecycle.AMBIGUOUS)
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
            broker = GitHubMutationBroker(adapter, journal=journal, checkpoint_observer=stop)
            with self.assertRaises(RuntimeError):
                broker.submit(intent, allowed_context())
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
            def crash(entry: MutationJournalEntry) -> None:
                if entry.lifecycle is JournalLifecycle.EXECUTION_STARTED:
                    raise RuntimeError("crash")
            with self.assertRaises(RuntimeError):
                GitHubMutationBroker(adapter, journal=journal, checkpoint_observer=crash).submit(intent, context)
            stored = journal.find(evidence)
            self.assertIs(stored.lifecycle, JournalLifecycle.EXECUTION_STARTED)  # type: ignore[union-attr]
            self.assertTrue(stored.pre_state_complete)  # type: ignore[union-attr]
            self.assertEqual(adapter.call_count(kind="mutation"), 0)
            restart = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(restart, journal=DurableMutationJournal(Path(directory) / "journal.json")).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(restart.call_count(kind="mutation"), 0)
            self.assertEqual(result.receipt.pre_state_digest, stored.pre_state_digest)  # type: ignore[union-attr]

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
            broker = GitHubMutationBroker.with_owner_transport(runner, transport, matrix, journal=journal, checkpoint_observer=crash)
            with self.assertRaises(RuntimeError):
                broker.submit(intent, context, payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),)))
            entry = MutationJournalEntry.from_evidence(intent, context, schema_v2_authorization_bundle(context), _broker_semantic_plan(intent))
            stored = journal.find(entry)
            self.assertIs(stored.lifecycle, JournalLifecycle.TRANSPORT_ACCEPTED)  # type: ignore[union-attr]
            self.assertEqual(len(transport.requests), 1)
            restart = FakeGitHubAdapter({comments_request().identity(): FakeGitHubScenario(response=comments_payload())})
            result = GitHubMutationBroker(restart, journal=DurableMutationJournal(Path(directory) / "journal.json")).submit(intent, context)
            self.assertTrue(result.ok)
            self.assertEqual(restart.call_count(kind="mutation"), 0)
            self.assertEqual(result.receipt.pre_state_digest, stored.pre_state_digest)  # type: ignore[union-attr]

    def test_execution_started_incomplete_postread_remains_blocked(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "started-incomplete-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        context = allowed_context()
        bundle, plan = schema_v2_authorization_bundle(context), _broker_semantic_plan(intent)
        entry = replace(MutationJournalEntry.from_evidence(intent, context, bundle, plan), lifecycle=JournalLifecycle.EXECUTION_STARTED)
        adapter = FakeGitHubAdapter()
        result = GitHubMutationBroker(adapter)._reconcile_journal(intent, context, bundle, plan, entry, entry)
        self.assertFalse(result.ok)
        self.assertTrue(result.reconciliation_required)
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
            first = GitHubMutationBroker(fake, journal=journal).submit(intent, allowed_context())
            self.assertTrue(first.ok)
            self.assertEqual(fake.call_count(kind="mutation"), 1)
            restarted_fake = FakeGitHubAdapter()
            retry = GitHubMutationBroker(restarted_fake, journal=DurableMutationJournal(Path(directory) / "journal.json")).submit(intent, allowed_context())
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
            first = GitHubMutationBroker(first_fake, journal=DurableMutationJournal(path)).submit(intent, allowed_context())
            self.assertFalse(first.ok)
            self.assertTrue(first.reconciliation_required)
            self.assertEqual(first_fake.call_count(kind="mutation"), 1)
            reconciler = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=comments_payload())})
            retry = GitHubMutationBroker(reconciler, journal=DurableMutationJournal(path)).submit(intent, allowed_context())
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
            journal.claim(evidence)
            journal.transition(evidence, JournalLifecycle.APPLIED_AWAITING_VERIFICATION)
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

    def test_broker_requires_policy_deployment_candidate_and_prestate_before_adapter_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", DIGEST),))
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
        broker = GitHubMutationBroker(fake)
        first = broker.submit(intent, allowed_context())
        self.assertTrue(first.ok)
        self.assertEqual(first.receipt.candidate_sha, SHA)  # type: ignore[union-attr]
        self.assertTrue(first.receipt.receipt_digest.startswith("sha256:"))  # type: ignore[union-attr]
        self.assertEqual(fake.call_count(kind="mutation"), 1)
        second = broker.submit(intent, allowed_context())
        self.assertTrue(second.ok)
        self.assertEqual(second.receipt, first.receipt)
        self.assertEqual(fake.call_count(kind="mutation"), 1)

    def test_ambiguous_post_state_requires_reconciliation_not_invented_success(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", DIGEST),))
        request = comments_request()
        fake = FakeGitHubAdapter({
            request.identity(): FakeGitHubScenario(response={**comments_payload(), "comments": []}),
            intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST),
        })
        result = GitHubMutationBroker(fake).submit(intent, allowed_context())
        self.assertFalse(result.ok)
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(fake.call_count(kind="mutation"), 1)

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
            broker = GitHubMutationBroker.with_owner_transport(runner, transport, matrix, journal=DurableMutationJournal(Path(directory) / "journal.json"))
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
            broker = GitHubMutationBroker.with_owner_transport(runner, OwnerTransport(), matrix, journal=DurableMutationJournal(Path(directory) / "journal.json"))
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


if __name__ == "__main__":
    unittest.main()
