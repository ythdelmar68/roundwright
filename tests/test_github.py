"""Hermetic contracts for the Phase 3 typed GitHub adapter seam."""

from __future__ import annotations

import unittest

from roundwright.github import (
    FakeGitHubAdapter,
    FakeGitHubScenario,
    GitHubFailureKind,
    GitHubMutationIntent,
    GitHubMutationOperation,
    GitHubMutationResult,
    GitHubReadOperation,
    GitHubReadRequest,
    GitHubContractError,
    Mergeability,
    MutationDisposition,
    MutationReceipt,
    RepositoryRef,
    normalize_github_response,
)


SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
READBACK_DIGEST = "sha256:" + "c" * 64
REPOSITORY = RepositoryRef("example", "roundwright")


class GitHubAdapterTests(unittest.TestCase):
    def request(self, operation: GitHubReadOperation, **changes: object) -> GitHubReadRequest:
        values: dict[str, object] = {"operation": operation, "repository": REPOSITORY}
        if operation in {
            GitHubReadOperation.ISSUE, GitHubReadOperation.ISSUE_RELATIONSHIPS,
            GitHubReadOperation.COMMENTS, GitHubReadOperation.PULL_REQUEST,
            GitHubReadOperation.REVIEWS, GitHubReadOperation.CHECKS,
            GitHubReadOperation.REQUESTED_REVIEWERS,
            GitHubReadOperation.WORKFLOW_RUNS, GitHubReadOperation.MERGEABILITY,
            GitHubReadOperation.CLOSING_REFERENCES,
        }:
            values["number"] = 40
        if operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD}:
            values["ref"] = "main"
        if operation in {GitHubReadOperation.BRANCH, GitHubReadOperation.REMOTE_HEAD, GitHubReadOperation.PULL_REQUEST, GitHubReadOperation.REVIEWS, GitHubReadOperation.REQUESTED_REVIEWERS, GitHubReadOperation.CHECKS, GitHubReadOperation.WORKFLOW_RUNS, GitHubReadOperation.MERGEABILITY, GitHubReadOperation.CLOSING_REFERENCES}:
            values["expected_sha"] = SHA
        values.update(changes)
        return GitHubReadRequest(**values)  # type: ignore[arg-type]

    def payload(self, operation: GitHubReadOperation) -> dict[str, object]:
        repository = {"owner": "example", "name": "roundwright"}
        payloads: dict[GitHubReadOperation, dict[str, object]] = {
            GitHubReadOperation.REPOSITORY: {"repository": repository, "id": "repo-1", "default_branch": "main", "default_branch_sha": SHA},
            GitHubReadOperation.ISSUE: {"repository": repository, "id": "issue-40", "number": 40, "state": "OPEN", "parent_number": 2, "sub_issue_numbers": []},
            GitHubReadOperation.ISSUE_RELATIONSHIPS: {"repository": repository, "id": "issue-40", "number": 40, "state": "OPEN", "parent_number": 2, "sub_issue_numbers": [41]},
            GitHubReadOperation.COMMENTS: {"repository": repository, "issue_number": 40, "comments": [{"id": "comment-1", "author_id": "owner-1", "body": "public evidence", "created_at": "2026-08-05T00:00:00Z"}]},
            GitHubReadOperation.BRANCH: {"repository": repository, "ref": "main", "sha": SHA},
            GitHubReadOperation.PULL_REQUEST: {"repository": repository, "id": "pr-40", "number": 40, "state": "OPEN", "base_ref": "main", "base_sha": SHA, "head_ref": "codex/issue-40", "head_sha": SHA, "draft": True},
            GitHubReadOperation.REVIEWS: {"repository": repository, "pull_request_number": 40, "head_sha": SHA, "reviews": [{"id": "review-1", "reviewer_id": "reviewer-1", "state": "APPROVED", "commit_sha": SHA}]},
            GitHubReadOperation.CHECKS: {"repository": repository, "pull_request_number": 40, "head_sha": SHA, "checks": [{"id": "check-1", "name": "tests", "state": "COMPLETED", "conclusion": "SUCCESS", "head_sha": SHA}]},
            GitHubReadOperation.WORKFLOW_RUNS: {"repository": repository, "pull_request_number": 40, "head_sha": SHA, "runs": [{"id": "run-1", "workflow_name": "tests", "state": "COMPLETED", "conclusion": "SUCCESS", "head_sha": SHA}]},
            GitHubReadOperation.MERGEABILITY: {"repository": repository, "pull_request_number": 40, "head_sha": SHA, "mergeability": "MERGEABLE"},
            GitHubReadOperation.CLOSING_REFERENCES: {"repository": repository, "pull_request_number": 40, "head_sha": SHA, "references": [{"issue_number": 40, "pull_request_number": 40, "keyword": "closes", "head_sha": SHA}]},
            GitHubReadOperation.REMOTE_HEAD: {"repository": repository, "ref": "main", "sha": SHA},
        }
        return payloads[operation]

    def test_every_declared_read_normalizes_to_the_expected_immutable_snapshot(self) -> None:
        for operation in GitHubReadOperation:
            if operation is GitHubReadOperation.REQUESTED_REVIEWERS:
                continue  # projection is introduced in the following increment
            with self.subTest(operation=operation):
                request = self.request(operation)
                snapshot = normalize_github_response(request, self.payload(operation))
                fake = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=self.payload(operation))})
                result = fake.read(request)
                self.assertTrue(result.ok)
                self.assertEqual(result.snapshot, snapshot)
                self.assertTrue(result.snapshot_digest.startswith("sha256:"))

    def test_response_shapes_fail_closed_without_preserving_comment_bodies(self) -> None:
        request = self.request(GitHubReadOperation.COMMENTS)
        fake = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response={"repository": {"owner": "example", "name": "roundwright"}, "issue_number": 40, "comments": [{"id": "comment-1"}]})})
        result = fake.read(request)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]
        snapshot = normalize_github_response(request, self.payload(GitHubReadOperation.COMMENTS))
        self.assertNotIn("public evidence", repr(snapshot))

    def test_collection_response_identity_is_never_synthesized_from_the_request(self) -> None:
        request = self.request(GitHubReadOperation.COMMENTS)
        mismatched = self.payload(request.operation)
        mismatched["issue_number"] = 99
        result = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=mismatched)}).read(request)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]
        wrong_repository = self.payload(request.operation)
        wrong_repository["repository"] = {"owner": "other", "name": "repository"}
        self.assertFalse(FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=wrong_repository)}).read(request).ok)

    def test_unknown_missing_and_inapplicable_response_fields_fail_closed(self) -> None:
        request = self.request(GitHubReadOperation.REPOSITORY)
        for payload in (
            {**self.payload(request.operation), "unexpected": "value"},
            {"repository": {"owner": "example", "name": "roundwright"}, "id": "repo-1", "default_branch": "main"},
            {"repository": {"owner": "example", "name": "roundwright"}, "id": "repo-1", "default_branch": "main", "default_branch_sha": SHA, "number": 40},
        ):
            with self.subTest(payload=payload):
                result = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=payload)}).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_comment_normalization_redacts_multiline_and_bounded_long_bodies(self) -> None:
        request = self.request(GitHubReadOperation.COMMENTS)
        payload = self.payload(request.operation)
        comment = payload["comments"][0]  # type: ignore[index]
        comment["body"] = "first line\nsecond line\n" + "x" * 4096  # type: ignore[index]
        snapshot = normalize_github_response(request, payload)
        self.assertNotIn("first line", repr(snapshot))
        self.assertTrue(snapshot.comments[0].body_digest.startswith("sha256:"))  # type: ignore[union-attr]
        comment["body"] = "x" * 65537  # type: ignore[index]
        self.assertFalse(FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=payload)}).read(request).ok)

    def test_every_failure_class_is_distinguished_and_recorded(self) -> None:
        request = self.request(GitHubReadOperation.REPOSITORY)
        for kind in GitHubFailureKind:
            with self.subTest(kind=kind):
                scenario = FakeGitHubScenario(failure=kind)
                result = FakeGitHubAdapter({request.identity(): scenario}).read(request)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, kind)  # type: ignore[union-attr]

    def test_stale_response_blocks_before_a_snapshot_can_be_observed(self) -> None:
        request = self.request(GitHubReadOperation.MERGEABILITY)
        result = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=self.payload(request.operation), stale=True)}).read(request)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.STALE_RESPONSE)  # type: ignore[union-attr]

    def test_mutation_intents_are_typed_and_disabled_without_a_fixture_receipt(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "merge-40", target_number=40, expected_sha=SHA, payload=(("method", "merge"),))
        adapter = FakeGitHubAdapter()
        result = adapter.submit(intent)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(adapter.call_count(kind="mutation"), 1)

    def test_fake_covers_and_denies_every_declared_mutation_by_default(self) -> None:
        adapter = FakeGitHubAdapter()
        for operation in GitHubMutationOperation:
            with self.subTest(operation=operation):
                intent = self.intent(operation)
                result = adapter.submit(intent)
                self.assertFalse(result.ok)
                self.assertEqual(result.failure.kind, GitHubFailureKind.POLICY_DENIED)  # type: ignore[union-attr]
        self.assertEqual(adapter.call_count(kind="mutation"), len(GitHubMutationOperation))

    def test_duplicate_receipts_are_idempotent_not_second_external_actions(self) -> None:
        intent = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-40", target_number=40, payload=(("body_digest", DIGEST),))
        adapter = FakeGitHubAdapter({intent.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-40", semantic_readback_digest=READBACK_DIGEST)})
        first = adapter.submit(intent)
        second = adapter.submit(intent)
        self.assertEqual(first.receipt.disposition, MutationDisposition.ACCEPTED)  # type: ignore[union-attr]
        self.assertEqual(second.receipt.disposition, MutationDisposition.ALREADY_APPLIED)  # type: ignore[union-attr]
        self.assertEqual(first.receipt.affected_identity, second.receipt.affected_identity)  # type: ignore[union-attr]
        self.assertEqual(first.receipt.semantic_readback_digest, second.receipt.semantic_readback_digest)  # type: ignore[union-attr]

    def test_rejected_receipts_are_not_successes(self) -> None:
        intent = self.intent(GitHubMutationOperation.MARK_READY)
        receipt = MutationReceipt(intent.identity(), intent.operation, MutationDisposition.REJECTED, "pr-40", READBACK_DIGEST)
        result = GitHubMutationResult(intent, receipt=receipt)
        self.assertFalse(result.ok)

    def test_mutation_payload_is_operation_specific_and_bound_to_the_receipt_identity(self) -> None:
        first = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-40", target_number=40, payload=(("body_digest", DIGEST),))
        changed = GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "comment-40", target_number=40, payload=(("body_digest", "sha256:" + "c" * 64),))
        self.assertNotEqual(first.identity(), changed.identity())
        adapter = FakeGitHubAdapter({first.identity(): FakeGitHubScenario(duplicate_receipt=True, affected_identity="comment-40", semantic_readback_digest=READBACK_DIGEST)})
        self.assertTrue(adapter.submit(first).ok)
        self.assertFalse(adapter.submit(changed).ok)
        with self.assertRaises(GitHubContractError):
            GitHubMutationIntent(GitHubMutationOperation.COMMENT, REPOSITORY, "bad-comment", target_number=40)
        with self.assertRaises(GitHubContractError):
            GitHubMutationIntent(GitHubMutationOperation.MERGE_PULL_REQUEST, REPOSITORY, "bad-merge", target_number=40, expected_sha=SHA, payload=(("body_digest", DIGEST),))
        with self.assertRaises(GitHubContractError):
            GitHubMutationIntent(GitHubMutationOperation.CREATE_PULL_REQUEST, REPOSITORY, "bad-pr", target_number=40, payload=(("base_ref", "main"), ("body_digest", DIGEST), ("head_ref", "codex/issue-40"), ("title_digest", DIGEST)))

    def test_collection_candidate_identity_rejects_mixed_or_stale_nested_evidence(self) -> None:
        for operation, collection, nested in (
            (GitHubReadOperation.REVIEWS, "reviews", "commit_sha"),
            (GitHubReadOperation.CHECKS, "checks", "head_sha"),
            (GitHubReadOperation.WORKFLOW_RUNS, "runs", "head_sha"),
        ):
            with self.subTest(operation=operation):
                request = self.request(operation)
                mixed = self.payload(operation)
                mixed[collection][0][nested] = "b" * 40  # type: ignore[index]
                self.assertFalse(FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=mixed)}).read(request).ok)
        request = self.request(GitHubReadOperation.CLOSING_REFERENCES)
        mixed = self.payload(request.operation)
        mixed["references"][0]["pull_request_number"] = 99  # type: ignore[index]
        self.assertFalse(FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=mixed)}).read(request).ok)
        stale = self.payload(request.operation)
        stale["references"][0]["head_sha"] = "b" * 40  # type: ignore[index]
        self.assertFalse(FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=stale)}).read(request).ok)

    def test_ref_sensitive_mutations_bind_exact_commits_and_stale_heads(self) -> None:
        create_pr = self.intent(GitHubMutationOperation.CREATE_PULL_REQUEST)
        changed_payload = tuple((key, "b" * 40 if key == "head_sha" else value) for key, value in create_pr.payload)
        changed_pr = GitHubMutationIntent(create_pr.operation, create_pr.repository, create_pr.idempotency_key, target_number=create_pr.target_number, payload=changed_payload)
        self.assertNotEqual(create_pr.identity(), changed_pr.identity())
        for operation in (GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH, GitHubMutationOperation.REQUEST_REVIEW, GitHubMutationOperation.MARK_READY, GitHubMutationOperation.MERGE_PULL_REQUEST):
            with self.subTest(operation=operation):
                intent = self.intent(operation)
                self.assertEqual(intent.expected_sha, SHA)
        with self.assertRaises(GitHubContractError):
            GitHubMutationIntent(GitHubMutationOperation.DELETE_BRANCH, REPOSITORY, "unbound-delete", target_ref="codex/issue-40")

    def test_request_review_and_branch_mutations_require_semantic_readback_receipts(self) -> None:
        for operation in (
            GitHubMutationOperation.REQUEST_REVIEW,
            GitHubMutationOperation.CREATE_BRANCH,
            GitHubMutationOperation.UPDATE_BRANCH,
            GitHubMutationOperation.DELETE_BRANCH,
        ):
            intent = self.intent(operation)
            adapter = FakeGitHubAdapter({
                intent.identity(): FakeGitHubScenario(
                    duplicate_receipt=True,
                    affected_identity=f"effect-{operation.value}",
                    semantic_readback_digest=READBACK_DIGEST,
                )
            })
            with self.subTest(operation=operation):
                result = adapter.submit(intent)
                self.assertTrue(result.ok)
                self.assertEqual(result.receipt.semantic_readback_digest, READBACK_DIGEST)  # type: ignore[union-attr]
                stale = FakeGitHubAdapter({
                    intent.identity(): FakeGitHubScenario(failure=GitHubFailureKind.STALE_RESPONSE)
                }).submit(intent)
                self.assertFalse(stale.ok)
                self.assertEqual(stale.failure.kind, GitHubFailureKind.STALE_RESPONSE)  # type: ignore[union-attr]
        with self.assertRaises(GitHubContractError):
            FakeGitHubScenario(duplicate_receipt=True)

    def test_repository_path_segments_and_request_applicability_fail_closed(self) -> None:
        with self.assertRaises(GitHubContractError):
            RepositoryRef("owner/name", "repository")
        first = GitHubReadRequest(GitHubReadOperation.REPOSITORY, RepositoryRef("a-b", "c"))
        second = GitHubReadRequest(GitHubReadOperation.REPOSITORY, RepositoryRef("a", "b-c"))
        self.assertNotEqual(first.identity(), second.identity())
        with self.assertRaises(GitHubContractError):
            GitHubReadRequest(GitHubReadOperation.REPOSITORY, REPOSITORY, number=40)
        with self.assertRaises(GitHubContractError):
            GitHubReadRequest(GitHubReadOperation.ISSUE, REPOSITORY, number=40, expected_sha=SHA)
        with self.assertRaises(GitHubContractError):
            GitHubReadRequest(GitHubReadOperation.CHECKS, REPOSITORY, number=40, expected_sha="a" * 41)

    def test_exact_requested_identity_is_preserved_and_mismatch_fails_closed(self) -> None:
        request = self.request(GitHubReadOperation.REMOTE_HEAD, expected_sha=SHA)
        result = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=self.payload(request.operation))}).read(request)
        self.assertTrue(result.ok)
        changed = dict(self.payload(request.operation), sha="b" * 40)
        result = FakeGitHubAdapter({request.identity(): FakeGitHubScenario(response=changed)}).read(request)
        self.assertFalse(result.ok)
        self.assertEqual(result.failure.kind, GitHubFailureKind.MALFORMED_RESPONSE)  # type: ignore[union-attr]

    def test_invalid_requests_and_unknown_mergeability_are_rejected_at_the_boundary(self) -> None:
        with self.assertRaises(GitHubContractError):
            GitHubReadRequest(GitHubReadOperation.ISSUE, REPOSITORY)
        with self.assertRaises(GitHubContractError):
            GitHubReadRequest(GitHubReadOperation.REMOTE_HEAD, REPOSITORY, ref="main", expected_sha="short")
        request = self.request(GitHubReadOperation.MERGEABILITY)
        malformed = dict(self.payload(request.operation), mergeability="MAYBE")
        with self.assertRaises(GitHubContractError):
            normalize_github_response(request, malformed)
        self.assertIs(Mergeability.MERGEABLE, Mergeability("MERGEABLE"))

    def intent(self, operation: GitHubMutationOperation) -> GitHubMutationIntent:
        payloads = {
            GitHubMutationOperation.CREATE_BRANCH: (),
            GitHubMutationOperation.UPDATE_BRANCH: (("previous_sha", "b" * 40),),
            GitHubMutationOperation.DELETE_BRANCH: (),
            GitHubMutationOperation.CREATE_PULL_REQUEST: (("base_ref", "main"), ("base_sha", SHA), ("body_digest", DIGEST), ("head_ref", "codex/issue-40"), ("head_sha", SHA), ("title_digest", DIGEST)),
            GitHubMutationOperation.COMMENT: (("body_digest", DIGEST),),
            GitHubMutationOperation.REQUEST_REVIEW: (("reviewers_digest", DIGEST),),
            GitHubMutationOperation.MARK_READY: (),
            GitHubMutationOperation.MERGE_PULL_REQUEST: (("method", "merge"),),
            GitHubMutationOperation.CLOSE_ISSUE: (("reason", "COMPLETED"),),
        }
        return GitHubMutationIntent(
            operation, REPOSITORY, f"intent-{operation.value}",
            target_number=40 if operation not in {GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH} else None,
            expected_sha=SHA if operation in {GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH, GitHubMutationOperation.REQUEST_REVIEW, GitHubMutationOperation.MARK_READY, GitHubMutationOperation.MERGE_PULL_REQUEST} else None,
            target_ref="codex/issue-40" if operation in {GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.UPDATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH} else None,
            payload=payloads[operation],
        )


if __name__ == "__main__":
    unittest.main()
