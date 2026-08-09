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
)
from roundwright.github_runtime import (
    CapabilityState,
    BrokerMutationCommand,
    CollectionPage,
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
    OwnerMutationRequest,
    OperationHealth,
    SemanticPostcondition,
    SemanticReadback,
    _broker_semantic_plan,
    _complete_broker_read,
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
    def __init__(self, accepted: bool = True) -> None:
        self.accepted = accepted
        self.requests: list[OwnerMutationRequest] = []

    def dispatch(self, request: OwnerMutationRequest) -> OwnerMutationFact:
        self.requests.append(request)
        identity = "sha256:" + hashlib.sha256(json.dumps((request.intent_identity, request.operation.value, request.authorization_bundle_identity, request.semantic_plan_identity, request.journal_identity), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        return OwnerMutationFact(self.accepted, identity)


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


def comments_payload() -> dict[str, object]:
    return {
        "repository": {"owner": "example", "name": "roundwright"},
        "issue_number": 46,
        "comments": [{"id": "comment-46", "author_id": "owner-1", "body": "curated evidence", "created_at": "2026-08-07T00:00:00Z"}],
    }


def gh_comments_page(*, present: bool = True, next_cursor: str | None = None, total: int | None = None) -> dict[str, object]:
    count = (1 if present else 0) if total is None else total
    return {
        "data": {"repository": {
            "name": "roundwright", "owner": {"login": "example"},
            "issue": {"number": 46, "comments": {
                "totalCount": count,
                "nodes": ([] if not present else [{"id": "17", "author": {"id": "4"}, "body": "curated evidence", "createdAt": "2026-08-07T00:00:00Z"}]),
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
            (GitHubMutationIntent(GitHubMutationOperation.REQUEST_REVIEW, REPOSITORY, "review-46", target_number=46, expected_sha=SHA, payload=(("reviewers_digest", reviewers_digest),)), GitHubReadOperation.REVIEWS, SemanticPostcondition.REVIEWERS_EXACT_AT_CANDIDATE),
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

    def test_gh_adapter_uses_read_only_api_and_normalizes_only_typed_response(self) -> None:
        import json

        runner = Runner(GhCommandResult(0, json.dumps(gh_comments_page())))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS))
        result = adapter.read(comments_request())
        self.assertTrue(result.ok)
        self.assertEqual(runner.calls[0][:2], ("api", "graphql"))
        self.assertNotIn("curated evidence", repr(result.snapshot))

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
