"""Hermetic coverage for the ``gh`` process seam and mutation broker."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from roundwright.deployment import DeploymentAuthorityDecision, DeploymentMode
from roundwright.github import (
    FakeGitHubAdapter,
    FakeGitHubScenario,
    GitHubFailureKind,
    GitHubMutationIntent,
    GitHubMutationOperation,
    GitHubReadOperation,
    GitHubReadRequest,
    RepositoryRef,
)
from roundwright.github_runtime import (
    CapabilityState,
    GhCommandResult,
    DurableMutationJournal,
    GhGitHubAdapter,
    GhMutationPayload,
    GitHubCapabilityHealth,
    GitHubMutationBroker,
    MutationBrokerContext,
    OperationHealth,
    SemanticPostcondition,
    SemanticReadback,
    SchemaV2AuthorizationBundle,
    unavailable_capability_health,
)
from roundwright.repository_policy import (
    RepositoryMutationBinding,
    RepositoryMutationDecision,
    RepositoryMutationOperation,
    RepositoryReceiptStatus,
)


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


def allowed_context(operation: RepositoryMutationOperation = RepositoryMutationOperation.ISSUE_COMMENT) -> MutationBrokerContext:
    binding = RepositoryMutationBinding(
        "0" * 64, "1" * 64, "2" * 64, 2, "3" * 64, "4" * 64,
        "5" * 64, "6" * 64, "7" * 64, SHA, "8" * 64, "9" * 64, "a" * 64, "b" * 64,
        RepositoryReceiptStatus.FRESH,
    )
    policy = RepositoryMutationDecision(operation, True, "authorized fixture", "2" * 64, "0" * 64, "4" * 64, True, True, "mutation-adapter-may-attempt-readback", binding)
    deployment = DeploymentAuthorityDecision(DeploymentMode.AUTHORITATIVE, True, "authorized fixture", "f" * 64)
    return MutationBrokerContext(policy, deployment, DIGEST, BASE, SHA, DIGEST)


def authorization_bundle(**replace: str) -> SchemaV2AuthorizationBundle:
    values = {
        "standing_authority_identity": "0" * 64, "verified_policy_receipt_identity": "1" * 64,
        "repository_identity": "2" * 64, "deployment_identity": "3" * 64, "task_identity": "4" * 64,
        "configuration_digest": DIGEST, "base_sha": BASE, "candidate_sha": SHA, "gate_identity": DIGEST,
        "receipt_lifecycle_identity": "5" * 64, "dispatcher_transition_identity": "6" * 64,
    }
    values.update(replace)
    return SchemaV2AuthorizationBundle(**values)


class GitHubRuntimeTests(unittest.TestCase):
    def test_schema_v2_authorization_bundle_is_immutable_deterministic_and_rejects_empty_bindings(self) -> None:
        bundle = authorization_bundle()
        self.assertEqual(bundle, authorization_bundle())
        self.assertEqual(bundle.identity, authorization_bundle().identity)
        self.assertEqual(bundle.serialize()["candidate_sha"], SHA)
        with self.assertRaises((AttributeError, TypeError)):
            bundle.candidate_sha = BASE  # type: ignore[misc]
        for field in ("standing_authority_identity", "verified_policy_receipt_identity", "repository_identity", "deployment_identity", "task_identity", "configuration_digest", "base_sha", "candidate_sha", "gate_identity", "receipt_lifecycle_identity", "dispatcher_transition_identity"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                authorization_bundle(**{field: ""})
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

        runner = Runner(GhCommandResult(0, json.dumps(comments_payload())))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS))
        result = adapter.read(comments_request())
        self.assertTrue(result.ok)
        self.assertEqual(runner.calls, [("api", "--method", "GET", "repos/example/roundwright/issues/46/comments")])
        self.assertNotIn("curated evidence", repr(result.snapshot))

    def test_gh_adapter_projects_rest_comment_schema_and_rejects_identity_drift(self) -> None:
        raw = [{"id": 17, "user": {"id": 4}, "body": "curated evidence", "created_at": "2026-08-07T00:00:00Z"}]
        runner = Runner(GhCommandResult(0, json.dumps(raw)), GhCommandResult(0, json.dumps({"number": 47, "state": "OPEN", "id": 46})))
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS, GitHubReadOperation.ISSUE))
        self.assertTrue(adapter.read(comments_request()).ok)
        self.assertFalse(adapter.read(GitHubReadRequest(GitHubReadOperation.ISSUE, REPOSITORY, number=46)).ok)

    def test_malformed_or_partial_capability_matrix_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            GitHubCapabilityHealth(())
        matrix = unavailable_capability_health(now=NOW)
        self.assertFalse(matrix.for_operation(GitHubMutationOperation.MERGE_PULL_REQUEST).available)

    def test_durable_journal_rejects_conflict_and_requires_restart_reconciliation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "branch-46", expected_sha=SHA, target_ref="codex/issue-46")
        conflicting = GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "branch-46", expected_sha=BASE, target_ref="codex/issue-46")
        with tempfile.TemporaryDirectory() as directory:
            first = DurableMutationJournal(Path(directory) / "journal.json")
            self.assertEqual(first.begin(intent), "started")
            self.assertEqual(first.begin(conflicting), "conflict")
            first.transition(intent, "ambiguous")
            restarted = DurableMutationJournal(Path(directory) / "journal.json")
            self.assertEqual(restarted.begin(intent), "ambiguous")

    def test_broker_requires_policy_deployment_candidate_and_prestate_before_adapter_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", DIGEST),))
        fake = FakeGitHubAdapter({intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46", semantic_readback_digest=DIGEST)})
        result = GitHubMutationBroker(fake).submit(intent, allowed_context(RepositoryMutationOperation.MARK_PR_READY), pre_state=comments_request(), readback=SemanticReadback(comments_request(), SemanticPostcondition.COMMENT_PRESENT))
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
        readback = SemanticReadback(request, SemanticPostcondition.COMMENT_PRESENT)
        first = broker.submit(intent, allowed_context(), pre_state=request, readback=readback)
        self.assertTrue(first.ok)
        self.assertEqual(first.receipt.candidate_sha, SHA)  # type: ignore[union-attr]
        self.assertTrue(first.receipt.receipt_digest.startswith("sha256:"))  # type: ignore[union-attr]
        self.assertEqual(fake.call_count(kind="mutation"), 1)
        second = broker.submit(intent, allowed_context(), pre_state=request, readback=readback)
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
        result = GitHubMutationBroker(fake).submit(intent, allowed_context(), pre_state=request, readback=SemanticReadback(request, SemanticPostcondition.COMMENT_PRESENT))
        self.assertFalse(result.ok)
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(fake.call_count(kind="mutation"), 1)

    def test_brokered_gh_execution_runs_once_while_direct_submit_stays_denied(self) -> None:
        request = comments_request()
        body = "curated evidence"
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        runner = Runner(
            GhCommandResult(0, json.dumps(comments_payload())),
            GhCommandResult(0, "ignored provider output"),
            GhCommandResult(0, json.dumps(comments_payload())),
        )
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT))
        broker = GitHubMutationBroker(adapter)
        readback = SemanticReadback(request, SemanticPostcondition.COMMENT_PRESENT)
        result = broker.submit(intent, allowed_context(), pre_state=request, readback=readback, payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", body),)))
        self.assertTrue(result.ok)
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(runner.calls[1][:5], ("api", "--method", "POST", "repos/example/roundwright/issues/46/comments", "-f"))
        direct = adapter.submit(intent)
        self.assertFalse(direct.ok)
        self.assertEqual(direct.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(len(runner.calls), 3)
        retry = broker.submit(intent, allowed_context(), pre_state=request, readback=readback, payload=GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", body),)))
        self.assertTrue(retry.ok)
        self.assertEqual(len(runner.calls), 3)

    def test_brokered_gh_ambiguous_readback_reconciles_without_duplicate_write(self) -> None:
        request = comments_request()
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        empty = {**comments_payload(), "comments": []}
        runner = Runner(
            GhCommandResult(0, json.dumps(empty)),
            GhCommandResult(0, "ignored provider output"),
            GhCommandResult(0, json.dumps(empty)),
            GhCommandResult(0, json.dumps(empty)),
        )
        adapter = GhGitHubAdapter(runner, health(GitHubReadOperation.COMMENTS, GitHubMutationOperation.COMMENT))
        broker = GitHubMutationBroker(adapter)
        readback = SemanticReadback(request, SemanticPostcondition.COMMENT_PRESENT)
        payload = GhMutationPayload(GitHubMutationOperation.COMMENT, (("body", "curated evidence"),))
        first = broker.submit(intent, allowed_context(), pre_state=request, readback=readback, payload=payload)
        self.assertFalse(first.ok)
        self.assertTrue(first.reconciliation_required)
        self.assertEqual(len(runner.calls), 3)
        reconciled = broker.reconcile(intent, allowed_context(), readback=readback)
        self.assertFalse(reconciled.ok)
        self.assertTrue(reconciled.reconciliation_required)
        self.assertEqual(len(runner.calls), 4)

    def test_direct_execution_surface_is_absent_for_every_declared_mutation(self) -> None:
        title, body, reviewers = "draft title", "draft body", "octocat"
        title_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-title", title), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        body_digest = "sha256:" + hashlib.sha256(json.dumps(("pull-request-body", body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        reviewers_digest = "sha256:" + hashlib.sha256(json.dumps(("reviewers", (reviewers,)), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
        intents = (
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_BRANCH, REPOSITORY, "branch-46", expected_sha=SHA, target_ref="codex/issue-46"), GhMutationPayload(GitHubMutationOperation.CREATE_BRANCH)),
            (GitHubMutationIntent(GitHubMutationOperation.UPDATE_BRANCH, REPOSITORY, "branch-update-46", expected_sha=SHA, target_ref="codex/issue-46", payload=(("previous_sha", BASE),)), GhMutationPayload(GitHubMutationOperation.UPDATE_BRANCH)),
            (GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "pr-46", payload=(("base_ref", "main"), ("base_sha", SHA), ("body_digest", body_digest), ("head_ref", "codex/issue-46"), ("head_sha", SHA), ("title_digest", title_digest))), GhMutationPayload(GitHubMutationOperation.CREATE_PULL_REQUEST, (("body", body), ("title", title)))),
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
        for intent, payload in intents:
            with self.subTest(operation=intent.operation):
                self.assertFalse(adapter.submit(intent).ok)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
