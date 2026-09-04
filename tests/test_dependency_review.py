"""Hermetic contract coverage for dependency-review state isolation."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity, load_configuration
from roundwright.dependency_review import (
    AffectedMember, AffectedSubset, Confidence, DependencyProposal,
    DependencyReviewError, DependencyReviewStore, EdgeDirection, EdgeKind,
    ProposedEdge, RequestedDisposition,
)
from roundwright.git_identity import acquire_transition_lease
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


def digest(character: str) -> str:
    return "sha256:" + character * 64


class DependencyReviewTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        value = object.__new__(RepositoryIdentity)
        object.__setattr__(value, "root", root.resolve())
        return value

    def setup_review(self, root: Path) -> tuple[RepositoryIdentity, AffectedSubset]:
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("task-113", "source-113", "repo-113", "codex/113", "C:/review-113", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="dependency-review-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        subset = AffectedSubset(
            "subset-113", identity.task_id, "b" * 64, "c" * 40, digest("d"), digest("e"), digest("f"), "initial",
            (AffectedMember("member-a", digest("1"), digest("2")), AffectedMember("member-b", digest("3"), digest("4"))),
        )
        return repository, subset

    def proposal(self, attempt_id: str, *, semantic: bool = False) -> DependencyProposal:
        return DependencyProposal(
            "proposal-113", attempt_id,
            RequestedDisposition.OWNER_REVIEW if semantic else RequestedDisposition.AUTO_ACTIVATE,
            "owner-review" if semantic else "not-required",
            (ProposedEdge(EdgeKind.SEMANTIC_INFERRED if semantic else EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),),
        )

    def test_default_role_and_input_are_exact_and_public_safe(self) -> None:
        configuration = load_configuration(cwd=Path.cwd(), environment={}, home=Path.cwd() / "missing-home")
        self.assertEqual((configuration.dependency_review.value.model, configuration.dependency_review.value.reasoning_effort.value), ("gpt-5.6-terra", "high"))
        self.assertEqual(configuration.dependency_review.source.value, "default")
        with tempfile.TemporaryDirectory() as temporary:
            _, subset = self.setup_review(Path(temporary))
            input_value = DependencyReviewStore.model_input(subset, attempt_id="attempt-113", profile_identity=digest("7"))
        self.assertEqual(set(input_value), {"schema", "attempt_id", "profile_identity", "subset_digest", "task_id", "source_digest", "candidate_sha", "policy_digest", "configuration_digest", "boundary_digest", "members"})
        self.assertNotIn("credential", str(input_value))
        self.assertNotIn("prompt", str(input_value))

    def test_accepts_one_schema_valid_proposal_idempotently_without_graph_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", profile_identity=digest("7"))
            self.assertEqual(attempt.state, "prepared")
            proposal = self.proposal(attempt.attempt_id)
            self.assertEqual(store.accept_proposal(repository, proposal), proposal.proposal_digest)
            self.assertEqual(store.accept_proposal(repository, proposal), proposal.proposal_digest)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id='attempt-113'").fetchone(), ("accepted",))
                self.assertEqual(connection.execute("SELECT outcome, reason_code FROM dependency_review_validation_outcomes WHERE attempt_id='attempt-113'").fetchone(), ("accepted", "schema-valid"))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependency_review_proposal_edges").fetchone(), (1,))
            finally:
                connection.close()

    def test_malformed_drifted_and_missing_member_results_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", profile_identity=digest("7"))
            with self.assertRaises(DependencyReviewError):
                DependencyProposal.parse({"schema": "roundwright-dependency-review-proposal/v1"})
            missing = DependencyProposal("proposal-113", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "missing", digest("5"), Confidence.HIGH, digest("6")),))
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, missing)
            changed = AffectedSubset(subset.snapshot_id, subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, digest("0"), subset.creation_reason, subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, changed, attempt_id="attempt-113", profile_identity=digest("7"))
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, self.proposal(attempt.attempt_id))

    def test_semantic_edges_require_owner_routing_and_retries_are_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", profile_identity=digest("7"))
            with self.assertRaises(DependencyReviewError):
                DependencyProposal("bad-semantic", first.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.SEMANTIC_INFERRED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            retry_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            retry = store.start_attempt(repository, retry_subset, attempt_id="attempt-114", profile_identity=digest("7"), supersedes_attempt_id=first.attempt_id)
            self.assertEqual(store.accept_proposal(repository, self.proposal(retry.attempt_id, semantic=True)), self.proposal(retry.attempt_id, semantic=True).proposal_digest)


if __name__ == "__main__":
    unittest.main()
