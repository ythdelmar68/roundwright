"""Hermetic coverage for the ``gh`` process seam and mutation broker."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
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
    GhGitHubAdapter,
    GitHubCapabilityHealth,
    GitHubMutationBroker,
    MutationBrokerContext,
    OperationHealth,
    SemanticPostcondition,
    SemanticReadback,
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
    def __init__(self, result: GhCommandResult) -> None:
        self.result = result
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: tuple[str, ...]) -> GhCommandResult:
        self.calls.append(arguments)
        return self.result


def health(available: object) -> GitHubCapabilityHealth:
    return GitHubCapabilityHealth(
        tuple(
            OperationHealth(operation, CapabilityState.AVAILABLE if operation is available else CapabilityState.UNAVAILABLE, NOW, "sha256:" + hashlib.sha256(str(index).encode("utf-8")).hexdigest())
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
        "0" * 64, "1" * 64, "2" * 64, 1, "3" * 64, "4" * 64,
        "5" * 64, "6" * 64, "7" * 64, SHA, "8" * 64, "9" * 64,
        RepositoryReceiptStatus.FRESH,
    )
    policy = RepositoryMutationDecision(operation, True, "authorized fixture", "2" * 64, "0" * 64, "4" * 64, True, True, "mutation-adapter-may-attempt-readback", binding)
    deployment = DeploymentAuthorityDecision(DeploymentMode.AUTHORITATIVE, True, "authorized fixture", "f" * 64)
    return MutationBrokerContext(policy, deployment, DIGEST, BASE, SHA, DIGEST)


class GitHubRuntimeTests(unittest.TestCase):
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

    def test_malformed_or_partial_capability_matrix_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            GitHubCapabilityHealth(())
        matrix = unavailable_capability_health(now=NOW)
        self.assertFalse(matrix.for_operation(GitHubMutationOperation.MERGE_PULL_REQUEST).available)

    def test_broker_requires_policy_deployment_candidate_and_prestate_before_adapter_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", DIGEST),))
        fake = FakeGitHubAdapter({intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46")})
        result = GitHubMutationBroker(fake).submit(intent, allowed_context(RepositoryMutationOperation.MARK_PR_READY), pre_state=comments_request(), readback=SemanticReadback(comments_request(), SemanticPostcondition.COMMENT_PRESENT))
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(fake.call_count(), 0)

    def test_broker_receipt_binds_pre_and_post_state_and_retries_without_second_mutation(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-46", target_number=46, payload=(("body_digest", COMMENT_DIGEST),))
        request = comments_request()
        fake = FakeGitHubAdapter({
            request.identity(): FakeGitHubScenario(response=comments_payload()),
            intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46"),
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
            intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-46"),
        })
        result = GitHubMutationBroker(fake).submit(intent, allowed_context(), pre_state=request, readback=SemanticReadback(request, SemanticPostcondition.COMMENT_PRESENT))
        self.assertFalse(result.ok)
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(fake.call_count(kind="mutation"), 1)


if __name__ == "__main__":
    unittest.main()
