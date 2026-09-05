"""Hermetic contract coverage for dependency-review state isolation."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity, load_configuration
from roundwright.dependency_review import (
    AffectedMember, AffectedSubset, Confidence, DependencyProposal,
    DependencyReviewBinding, DependencyReviewError, DependencyReviewStore, EdgeDirection, EdgeKind,
    ProposedEdge, RequestedDisposition,
)
from roundwright.dependency_graph import (
    DependencyGraphBinding, DependencyGraphError, DependencyGraphStore,
    GraphDecision,
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

    def binding(self, subset: AffectedSubset, *, candidate: str | None = None, policy: str | None = None, configuration: str | None = None, profile: str | None = None) -> DependencyReviewBinding:
        return DependencyReviewBinding(candidate or subset.candidate_sha, policy or subset.policy_digest, configuration or subset.configuration_digest, profile or digest("7"))

    def test_default_role_and_input_are_exact_and_public_safe(self) -> None:
        configuration = load_configuration(cwd=Path.cwd(), environment={}, home=Path.cwd() / "missing-home")
        self.assertEqual((configuration.dependency_review.value.model, configuration.dependency_review.value.reasoning_effort.value), ("gpt-5.6-terra", "high"))
        self.assertEqual(configuration.dependency_review.source.value, "default")
        resolved = DependencyReviewBinding.from_configuration(configuration, candidate_sha="c" * 40, policy_digest=digest("d"))
        self.assertEqual((resolved.configuration_digest, resolved.profile_identity), (configuration.pin().digest, configuration.pin().dependency_review_profile_identity))
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
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            self.assertEqual(attempt.state, "prepared")
            proposal = self.proposal(attempt.attempt_id)
            self.assertEqual(store.accept_proposal(repository, proposal, binding=self.binding(subset)), proposal.proposal_digest)
            self.assertEqual(store.accept_proposal(repository, proposal, binding=self.binding(subset)), proposal.proposal_digest)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id='attempt-113'").fetchone(), ("accepted",))
                self.assertEqual(connection.execute("SELECT outcome, reason_code FROM dependency_review_validation_outcomes WHERE attempt_id='attempt-113'").fetchone(), ("accepted", "schema-valid"))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependency_review_proposal_edges").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependency_review_successors").fetchone(), (0,))
            finally:
                connection.close()

    def test_malformed_drifted_and_missing_member_results_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            with self.assertRaises(DependencyReviewError):
                DependencyProposal.parse({"schema": "roundwright-dependency-review-proposal/v1"})
            missing = DependencyProposal("proposal-113", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "missing", digest("5"), Confidence.HIGH, digest("6")),))
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, missing, binding=self.binding(subset))
            changed = AffectedSubset(subset.snapshot_id, subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, digest("0"), subset.creation_reason, subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, changed, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, self.proposal(attempt.attempt_id), binding=self.binding(subset))

    def test_semantic_edges_require_owner_routing_and_retries_are_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            with self.assertRaises(DependencyReviewError):
                DependencyProposal("bad-semantic", first.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.SEMANTIC_INFERRED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            retry_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            retry = store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), supersedes_attempt_id=first.attempt_id)
            self.assertEqual(store.accept_proposal(repository, self.proposal(retry.attempt_id, semantic=True), binding=self.binding(retry_subset)), self.proposal(retry.attempt_id, semantic=True).proposal_digest)

    def test_acceptance_rejects_current_binding_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            for binding in (
                self.binding(subset, candidate="0" * 40),
                self.binding(subset, policy=digest("0")),
                self.binding(subset, configuration=digest("0")),
                self.binding(subset, profile=digest("0")),
            ):
                with self.subTest(binding=binding):
                    with self.assertRaises(DependencyReviewError):
                        store.accept_proposal(repository, self.proposal(attempt.attempt_id), binding=binding)
            self.assertEqual(store.accept_proposal(repository, self.proposal(attempt.attempt_id), binding=self.binding(subset)), self.proposal(attempt.attempt_id).proposal_digest)

    def test_subset_order_is_normalized_and_retry_lineage_is_task_terminal_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            reordered = AffectedSubset(subset.snapshot_id, subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, subset.creation_reason, tuple(reversed(subset.members)))
            self.assertEqual((reordered.members, reordered.content_digest), (subset.members, subset.content_digest))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            retry_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), supersedes_attempt_id=first.attempt_id)
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            replay = store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), supersedes_attempt_id=first.attempt_id)
            self.assertEqual(store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), supersedes_attempt_id=first.attempt_id), replay)
            other = TaskIdentity("task-114", "source-114", "repo-113", "codex/114", "C:/review-114", "a" * 40)
            lease = acquire_transition_lease(repository, repository_id=other.repository_id, owner="dependency-review-tests", ttl_seconds=60)
            admit_task(repository, other, (SourceSnapshot(other.source_id, other.repository_id, "c" * 64),), lease=lease)
            other_subset = AffectedSubset("subset-115", other.task_id, "c" * 64, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "initial", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, other_subset, attempt_id="attempt-115", binding=self.binding(other_subset), supersedes_attempt_id=first.attempt_id)

    def test_retry_lineage_has_one_head_and_one_successor_across_restarts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            successor = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            replay = store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=first.attempt_id)
            self.assertEqual(store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=first.attempt_id), replay)
            competing = AffectedSubset("subset-115", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, competing, attempt_id="attempt-115", binding=self.binding(competing), supersedes_attempt_id=first.attempt_id)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, competing, attempt_id="attempt-115", binding=self.binding(competing))
            store.record_invalid(repository, attempt_id=replay.attempt_id, output_digest=digest("9"), reason_code="malformed-response")
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, competing, attempt_id="attempt-115", binding=self.binding(competing), supersedes_attempt_id=first.attempt_id)

    def test_concurrent_successor_creation_admits_exactly_one_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            def create(ordinal: int) -> bool:
                candidate = AffectedSubset(f"subset-11{ordinal}", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
                try:
                    DependencyReviewStore().start_attempt(repository, candidate, attempt_id=f"attempt-11{ordinal}", binding=self.binding(candidate), supersedes_attempt_id=first.attempt_id)
                    return True
                except DependencyReviewError:
                    return False
            with ThreadPoolExecutor(max_workers=2) as executor:
                self.assertEqual(sum(executor.map(create, (4, 5))), 1)

    def test_acceptance_reconstructs_all_durable_material_on_replay(self) -> None:
        def accepted() -> tuple[RepositoryIdentity, AffectedSubset, DependencyReviewStore, DependencyProposal]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            repository, subset = self.setup_review(Path(temporary.name))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            store.accept_proposal(repository, proposal, binding=self.binding(subset))
            return repository, subset, store, proposal
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_subset_members SET content_digest = ? WHERE snapshot_id = ? AND member_id = ?", (digest("0"), subset.snapshot_id, "member-a"))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            store.accept_proposal(repository, proposal, binding=self.binding(subset))
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_proposal_edges SET confidence = 'low' WHERE proposal_id = ?", (proposal.proposal_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            store.accept_proposal(repository, proposal, binding=self.binding(subset))

    def test_terminal_replays_never_repair_missing_or_extra_outcomes(self) -> None:
        def accepted() -> tuple[RepositoryIdentity, AffectedSubset, DependencyReviewStore, DependencyProposal]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            repository, subset = self.setup_review(Path(temporary.name))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            store.accept_proposal(repository, proposal, binding=self.binding(subset))
            return repository, subset, store, proposal
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("DELETE FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (proposal.attempt_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            store.accept_proposal(repository, proposal, binding=self.binding(subset))
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_validation_outcomes SET reason_code = 'tampered' WHERE attempt_id = ?", (proposal.attempt_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            store.accept_proposal(repository, proposal, binding=self.binding(subset))
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("INSERT INTO dependency_review_validation_outcomes(attempt_id, outcome, reason_code, output_digest, owner_route) VALUES (?, 'invalid', 'unexpected', ?, 'owner-review')", (attempt.attempt_id, digest("8")))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, self.proposal(attempt.attempt_id), binding=self.binding(subset))
            with self.assertRaises(DependencyReviewError):
                store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")

    def test_lineage_claim_and_predecessor_drift_fail_closed_on_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            successor = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=first.attempt_id)
            store.record_invalid(repository, attempt_id=second.attempt_id, output_digest=digest("9"), reason_code="malformed-response")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("DELETE FROM dependency_review_successors WHERE predecessor_attempt_id = ?", (first.attempt_id,))
                connection.commit()
            finally:
                connection.close()
            fork = AffectedSubset("subset-115", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, fork, attempt_id="attempt-115", binding=self.binding(fork), supersedes_attempt_id=first.attempt_id)
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            successor = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=first.attempt_id)
            proposal = self.proposal(second.attempt_id)
            store.accept_proposal(repository, proposal, binding=self.binding(successor))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_review_attempts SET supersedes_attempt_id = NULL WHERE attempt_id = ?", (second.attempt_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, proposal, binding=self.binding(successor))

    def test_invalid_terminal_replay_and_successor_require_complete_evidence(self) -> None:
        def invalid_terminal() -> tuple[RepositoryIdentity, AffectedSubset, DependencyReviewStore, object]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            repository, subset = self.setup_review(Path(temporary.name))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            return repository, subset, store, attempt
        repository, subset, store, attempt = invalid_terminal()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("DELETE FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (attempt.attempt_id,))
            connection.commit()
        finally:
            connection.close()
        successor = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
        with self.assertRaises(DependencyReviewError):
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
        with self.assertRaises(DependencyReviewError):
            store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=attempt.attempt_id)
        repository, subset, store, attempt = invalid_terminal()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_subset_members SET content_digest = ? WHERE snapshot_id = ? AND member_id = ?", (digest("0"), subset.snapshot_id, "member-a"))
            connection.commit()
        finally:
            connection.close()
        successor = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
        with self.assertRaises(DependencyReviewError):
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
        with self.assertRaises(DependencyReviewError):
            store.start_attempt(repository, successor, attempt_id="attempt-114", binding=self.binding(successor), supersedes_attempt_id=attempt.attempt_id)

    def test_lineage_reconstructs_every_ancestor_and_raw_successor_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            second_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, second_subset, attempt_id="attempt-114", binding=self.binding(second_subset), supersedes_attempt_id=first.attempt_id)
            store.record_invalid(repository, attempt_id=second.attempt_id, output_digest=digest("9"), reason_code="malformed-response")
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("DELETE FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (first.attempt_id,))
                connection.commit()
            finally:
                connection.close()
            third_subset = AffectedSubset("subset-115", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, third_subset, attempt_id="attempt-115", binding=self.binding(third_subset), supersedes_attempt_id=second.attempt_id)
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            second_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, second_subset, attempt_id="attempt-114", binding=self.binding(second_subset), supersedes_attempt_id=first.attempt_id)
            proposal = self.proposal(second.attempt_id)
            store.accept_proposal(repository, proposal, binding=self.binding(second_subset))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_review_successors SET successor_attempt_id = ? WHERE predecessor_attempt_id = ?", ("missing-attempt", first.attempt_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyReviewError):
                store.accept_proposal(repository, proposal, binding=self.binding(second_subset))

    def test_accepted_predecessor_rejects_proposal_edge_ordinal_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            second_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, second_subset, attempt_id="attempt-114", binding=self.binding(second_subset), supersedes_attempt_id=first.attempt_id)
            proposal = self.proposal(second.attempt_id)
            store.accept_proposal(repository, proposal, binding=self.binding(second_subset))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_review_proposal_edges SET ordinal = 5 WHERE proposal_id = ?", (proposal.proposal_id,))
                connection.commit()
            finally:
                connection.close()
            third_subset = AffectedSubset("subset-115", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, third_subset, attempt_id="attempt-115", binding=self.binding(third_subset), supersedes_attempt_id=second.attempt_id)

    def test_graph_activation_is_candidate_bound_transactional_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            review_store = DependencyReviewStore()
            attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            review_store.accept_proposal(repository, proposal, binding=self.binding(subset))
            graph_binding = DependencyGraphBinding.from_review_binding(self.binding(subset))
            graph_store = DependencyGraphStore()
            result = graph_store.activate(repository, proposal, binding=graph_binding, graph_version_id="graph-113")
            self.assertEqual((result.decision, result.graph_version_id), (GraphDecision.ACCEPTED, "graph-113"))
            self.assertEqual(graph_store.activate(repository, proposal, binding=graph_binding, graph_version_id="graph-113"), result)
            graph = graph_store.current(repository, binding=graph_binding)
            self.assertEqual(graph.graph_version_id, "graph-113")
            self.assertEqual([(edge.subject_member_id, edge.object_member_id) for edge in graph.edges], [("member-a", "member-b")])
            with self.assertRaises(DependencyGraphError):
                graph_store.current(repository, binding=DependencyGraphBinding("0" * 40, subset.policy_digest, subset.configuration_digest))

    def test_graph_activation_routes_semantic_and_rejects_incomplete_or_cyclic_edges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            review_store = DependencyReviewStore()
            graph_store = DependencyGraphStore()
            binding = self.binding(subset)
            graph_binding = DependencyGraphBinding.from_review_binding(binding)
            semantic_attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=binding)
            semantic = self.proposal(semantic_attempt.attempt_id, semantic=True)
            review_store.accept_proposal(repository, semantic, binding=binding)
            pending = graph_store.activate(repository, semantic, binding=graph_binding, graph_version_id="graph-113")
            self.assertEqual((pending.decision, pending.graph_version_id), (GraphDecision.PENDING_OWNER, None))
            retry_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", (*subset.members, AffectedMember("member-c", digest("9"), digest("a"))))
            attempt = review_store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), supersedes_attempt_id=semantic_attempt.attempt_id)
            incomplete = DependencyProposal("proposal-114", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),))
            review_store.accept_proposal(repository, incomplete, binding=self.binding(retry_subset))
            self.assertEqual(graph_store.activate(repository, incomplete, binding=graph_binding, graph_version_id="graph-114").reason_code, "affected-subset-incomplete")
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            review_store = DependencyReviewStore()
            attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            cycle = DependencyProposal("proposal-113", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8")),
            ))
            review_store.accept_proposal(repository, cycle, binding=self.binding(subset))
            result = DependencyGraphStore().activate(repository, cycle, binding=DependencyGraphBinding.from_review_binding(self.binding(subset)), graph_version_id="graph-113")
            self.assertEqual(result.decision, GraphDecision.REJECTED)
            self.assertEqual(result.reason_code, "cycle-detected")


if __name__ == "__main__":
    unittest.main()
