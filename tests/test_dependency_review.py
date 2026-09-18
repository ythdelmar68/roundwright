"""Hermetic contract coverage for dependency-review state isolation."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity, load_configuration
from roundwright.dependency_review import (
    AffectedMember, AffectedSubset, Confidence, DependencyProposal,
    DependencyReviewBinding, DependencyReviewError, DependencyReviewStore, EdgeDirection, EdgeKind,
    ProposedEdge, RequestedDisposition, SourceOwnedRelation,
)
from roundwright.dependency_graph import (
    DependencyGraphBinding, DependencyGraphError, DependencyGraphStore,
    GraphDecision,
)
from roundwright.git_identity import acquire_transition_lease
from roundwright.failure_recovery import FailureRecoveryError, ScopeAdmissionDenied
from roundwright.runtime_binding import RuntimeBinding
from roundwright.state import SourceSnapshot, StateError, TaskIdentity, admit_task, database_path, initialize, record_runtime_binding


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
        with closing(sqlite3.connect(database_path(repository))) as connection:
            connection.execute(
                "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                (identity.task_id, identity.base_sha, subset.candidate_sha, "authority-113"),
            )
            connection.commit()
        record_runtime_binding(
            repository, identity,
            RuntimeBinding("roundwright-runtime/v1", subset.configuration_digest, digest("8"), (digest("9"),)),
        )
        return repository, subset

    def accept(self, store: DependencyReviewStore, repository: RepositoryIdentity, proposal: DependencyProposal, *, binding: DependencyReviewBinding) -> str:
        """Authenticate the provider turn before exercising proposal acceptance."""

        identity = TaskIdentity("task-113", "source-113", "repo-113", "codex/113", "C:/review-113", "a" * 40)
        with closing(sqlite3.connect(database_path(repository))) as connection:
            claim = connection.execute(
                "SELECT state FROM dependency_review_dispatch_claims WHERE attempt_id=?",
                (proposal.attempt_id,),
            ).fetchone()
        if claim is None:
            store.claim_pre_dispatch(repository, attempt_id=proposal.attempt_id, task_identity=identity, binding=binding)
            store.claim_session(repository, attempt_id=proposal.attempt_id, session_identity="session-" + proposal.attempt_id, task_identity=identity, binding=binding)
            store.claim_turn(repository, attempt_id=proposal.attempt_id, session_identity="session-" + proposal.attempt_id, turn_identity="turn-" + proposal.attempt_id)
        return store.accept_proposal(
            repository, proposal, binding=binding, task_identity=identity,
            observed_session_identity="session-" + proposal.attempt_id,
            observed_turn_identity="turn-" + proposal.attempt_id,
            observed_output_digest=proposal.proposal_digest,
        )

    def proposal(self, attempt_id: str, *, semantic: bool = False) -> DependencyProposal:
        kind = EdgeKind.SEMANTIC_INFERRED if semantic else EdgeKind.EXPLICIT
        relation = None if semantic else SourceOwnedRelation(kind, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
        return DependencyProposal(
            "proposal-113", attempt_id,
            RequestedDisposition.OWNER_REVIEW if semantic else RequestedDisposition.AUTO_ACTIVATE,
            "owner-review" if semantic else "not-required",
            (ProposedEdge(kind, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), relation.relation_digest if relation else None),),
        )

    def binding(self, subset: AffectedSubset, *, candidate: str | None = None, policy: str | None = None, configuration: str | None = None, profile: str | None = None) -> DependencyReviewBinding:
        return DependencyReviewBinding(candidate or subset.candidate_sha, policy or subset.policy_digest, configuration or subset.configuration_digest, profile or digest("7"))

    def source_owned_relations(self, proposal: DependencyProposal) -> tuple[SourceOwnedRelation, ...]:
        return tuple(
            SourceOwnedRelation(edge.kind, edge.direction, edge.subject_member_id, edge.object_member_id, edge.rationale_digest, edge.confidence, edge.conflicts_digest)
            for edge in proposal.edges if edge.kind is not EdgeKind.SEMANTIC_INFERRED
        )

    def replace_with_schema(self, repository: RepositoryIdentity, version: int) -> None:
        """Project current fixture rows into one exact historical schema."""

        from roundwright.state import MIGRATIONS, _apply_migrations

        path = database_path(repository)
        legacy_path = path.with_name(f"dependency-schema-{version}.sqlite")
        with closing(sqlite3.connect(legacy_path)) as connection, connection:
            _apply_migrations(connection, MIGRATIONS[:version])
            connection.execute("ATTACH DATABASE ? AS current", (str(path),))
            tables = [row[0] for row in connection.execute(
                "SELECT name FROM main.sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )]
            for table in tables:
                if table == "schema_migrations":
                    continue
                columns = [row[1] for row in connection.execute(
                    f'PRAGMA main.table_info("{table}")'
                )]
                names = ",".join('"' + name + '"' for name in columns)
                connection.execute(f'DELETE FROM main."{table}"')
                connection.execute(
                    f'INSERT INTO main."{table}" ({names}) '
                    f'SELECT {names} FROM current."{table}"'
                )
        legacy_path.replace(path)

    def test_default_role_and_input_are_exact_and_public_safe(self) -> None:
        configuration = load_configuration(cwd=Path.cwd(), environment={}, home=Path.cwd() / "missing-home")
        self.assertEqual((configuration.dependency_review.value.model, configuration.dependency_review.value.reasoning_effort.value), ("gpt-5.6-terra", "high"))
        self.assertEqual(configuration.dependency_review.source.value, "default")
        resolved = DependencyReviewBinding.from_configuration(configuration, candidate_sha="c" * 40, policy_digest=digest("d"))
        self.assertEqual((resolved.configuration_digest, resolved.profile_identity), (configuration.pin().digest, configuration.pin().dependency_review_profile_identity))
        with tempfile.TemporaryDirectory() as temporary:
            _, subset = self.setup_review(Path(temporary))
            input_value = DependencyReviewStore.model_input(subset, attempt_id="attempt-113", profile_identity=digest("7"))
        self.assertEqual(set(input_value), {"schema", "attempt_id", "profile_identity", "subset_digest", "task_id", "source_digest", "candidate_sha", "policy_digest", "configuration_digest", "boundary_digest", "members", "trusted_relations"})
        self.assertNotIn("credential", str(input_value))
        self.assertNotIn("prompt", str(input_value))

    def test_accepts_one_schema_valid_proposal_idempotently_without_graph_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            self.assertEqual(attempt.state, "prepared")
            proposal = self.proposal(attempt.attempt_id)
            self.assertEqual(self.accept(store, repository, proposal, binding=self.binding(subset)), proposal.proposal_digest)
            self.assertEqual(self.accept(store, repository, proposal, binding=self.binding(subset)), proposal.proposal_digest)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id='attempt-113'").fetchone(), ("accepted",))
                self.assertEqual(connection.execute("SELECT outcome, reason_code FROM dependency_review_validation_outcomes WHERE attempt_id='attempt-113'").fetchone(), ("accepted", "schema-valid"))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependency_review_proposal_edges").fetchone(), (1,))
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM dependency_review_successors").fetchone(), (0,))
            finally:
                connection.close()

    def test_acceptance_requires_complete_dispatch_identity_evidence(self) -> None:
        """Prepared or session-only attempts cannot be accepted by a direct caller."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            proposal = self.proposal("acceptance-evidence")
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            with self.assertRaisesRegex(DependencyReviewError, "acceptance evidence"):
                store.accept_proposal(repository, proposal, binding=binding)
            identity = TaskIdentity("task-113", "source-113", "repo-113", "codex/113", "C:/review-113", "a" * 40)
            store.claim_pre_dispatch(repository, attempt_id=proposal.attempt_id, task_identity=identity, binding=binding)
            store.claim_session(
                repository, attempt_id=proposal.attempt_id,
                session_identity="acceptance-session", task_identity=identity, binding=binding,
            )
            with self.assertRaisesRegex(DependencyReviewError, "acceptance evidence"):
                store.accept_proposal(repository, proposal, binding=binding)
            store.claim_turn(
                repository, attempt_id=proposal.attempt_id,
                session_identity="acceptance-session", turn_identity="acceptance-turn",
            )
            self.assertEqual(
                store.accept_proposal(
                    repository, proposal, binding=binding,
                    observed_session_identity="acceptance-session",
                    observed_turn_identity="acceptance-turn",
                    observed_output_digest=proposal.proposal_digest,
                ),
                proposal.proposal_digest,
            )

    def test_pre_dispatch_claim_rechecks_scope_in_its_writer_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            store.start_attempt(
                repository, subset, attempt_id="claim-scope", binding=binding,
            )
            identity = TaskIdentity(
                "task-113", "source-113", "repo-113", "codex/113",
                "C:/review-113", "a" * 40,
            )
            with mock.patch(
                "roundwright.dependency_review.require_scope_open",
                side_effect=FailureRecoveryError("injected stopped scope"),
            ), self.assertRaisesRegex(FailureRecoveryError, "stopped scope"):
                store.claim_pre_dispatch(
                    repository, attempt_id="claim-scope",
                    task_identity=identity, binding=binding,
                )
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT 1 FROM dependency_review_dispatch_claims WHERE attempt_id='claim-scope'"
                ).fetchone(), None)

    def test_scope_denial_requires_the_typed_admission_exception(self) -> None:
        """Malformed recovery evidence cannot be relabeled as a host denial."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            store.start_attempt(repository, subset, attempt_id="denial-provenance", binding=binding)
            identity = TaskIdentity(
                "task-113", "source-113", "repo-113", "codex/113",
                "C:/review-113", "a" * 40,
            )
            with mock.patch(
                "roundwright.dependency_review.require_scope_open",
                side_effect=FailureRecoveryError("malformed recovery evidence"),
            ), self.assertRaisesRegex(FailureRecoveryError, "malformed recovery evidence"):
                store.record_scope_denied(
                    repository, attempt_id="denial-provenance", output_digest=digest("a"),
                    task_identity=identity, binding=binding,
                )
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT state FROM dependency_review_attempts WHERE attempt_id='denial-provenance'"
                ).fetchone(), ("prepared",))
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM dependency_review_validation_outcomes"
                ).fetchone(), (0,))

    def test_initial_acceptance_rejects_a_substituted_durable_turn(self) -> None:
        """Adapter-observed identity must match the claim in the acceptance transaction."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            proposal = self.proposal("acceptance-turn-race")
            identity = TaskIdentity(
                "task-113", "source-113", "repo-113", "codex/113",
                "C:/review-113", "a" * 40,
            )
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            store.claim_pre_dispatch(
                repository, attempt_id=proposal.attempt_id,
                task_identity=identity, binding=binding,
            )
            store.claim_session(
                repository, attempt_id=proposal.attempt_id,
                session_identity="observed-session", task_identity=identity, binding=binding,
            )
            store.claim_turn(
                repository, attempt_id=proposal.attempt_id,
                session_identity="observed-session", turn_identity="observed-turn",
            )
            with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                connection.execute(
                    "UPDATE dependency_review_dispatch_claims SET turn_identity='substituted-turn' "
                    "WHERE attempt_id=?", (proposal.attempt_id,),
                )
            with self.assertRaisesRegex(DependencyReviewError, "dispatch has drifted"):
                store.accept_proposal(
                    repository, proposal, binding=binding, task_identity=identity,
                    observed_session_identity="observed-session",
                    observed_turn_identity="observed-turn",
                    observed_output_digest=proposal.proposal_digest,
                )
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT state FROM dependency_review_attempts WHERE attempt_id=?",
                    (proposal.attempt_id,),
                ).fetchone(), ("prepared",))
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM dependency_review_accepted_result_dispatches"
                ).fetchone(), (0,))

    def test_terminal_snapshot_authenticates_one_database_snapshot(self) -> None:
        """A concurrent outcome replacement cannot be combined with earlier auth rows."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            proposal = self.proposal("terminal-snapshot-race")
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            self.accept(store, repository, proposal, binding=binding)
            path = database_path(repository)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
            authenticate = DependencyReviewStore._require_authenticated_dispatch

            def replace_after_authentication(*args, **kwargs):
                result = authenticate(*args, **kwargs)
                with closing(sqlite3.connect(path)) as writer, writer:
                    writer.execute(
                        "UPDATE dependency_review_validation_outcomes SET output_digest=? "
                        "WHERE attempt_id=?", (digest("0"), proposal.attempt_id),
                    )
                return result

            with mock.patch.object(
                DependencyReviewStore, "_require_authenticated_dispatch",
                side_effect=replace_after_authentication,
            ):
                snapshot = store.terminal_snapshot(
                    repository, attempt_id=proposal.attempt_id, binding=binding,
                )
            self.assertEqual(snapshot["output_digest"], proposal.proposal_digest)
            with self.assertRaises(DependencyReviewError):
                store.terminal_snapshot(
                    repository, attempt_id=proposal.attempt_id, binding=binding,
                )

    def test_all_dependency_consumers_share_exact_dispatch_authentication(self) -> None:
        """Acceptance, terminal read-back, and graph replay reject the same drift."""

        mutations = {
            "missing-claim": "DELETE FROM dependency_review_dispatch_claims WHERE attempt_id=?",
            "invalid-session": "UPDATE dependency_review_dispatch_claims SET session_identity='bad session' WHERE attempt_id=?",
            "invalid-turn": "UPDATE dependency_review_dispatch_claims SET turn_identity='bad turn' WHERE attempt_id=?",
            "substituted-valid-turn": "UPDATE dependency_review_dispatch_claims SET turn_identity='other-valid-turn' WHERE attempt_id=?",
            "admission-session": "UPDATE dependency_review_failure_admissions SET session_identity='other-session' WHERE attempt_id=?",
            "admission-profile": "UPDATE dependency_review_failure_admissions SET profile_identity='sha256:" + "0" * 64 + "' WHERE attempt_id=?",
        }
        for name, statement in mutations.items():
            with self.subTest(drift=name), tempfile.TemporaryDirectory() as temporary:
                repository, subset = self.setup_review(Path(temporary))
                store = DependencyReviewStore()
                binding = self.binding(subset)
                proposal = self.proposal("dispatch-auth")
                store.start_attempt(
                    repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                    source_owned_relations=self.source_owned_relations(proposal),
                )
                self.accept(store, repository, proposal, binding=binding)
                graph = DependencyGraphStore()
                graph_binding = DependencyGraphBinding.from_review_binding(binding)
                graph.activate(
                    repository, proposal, binding=graph_binding,
                    graph_version_id="graph-auth",
                )
                with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                    connection.execute(statement, (proposal.attempt_id,))
                with self.assertRaisesRegex(DependencyReviewError, "acceptance evidence"):
                    store.accept_proposal(repository, proposal, binding=binding)
                with self.assertRaisesRegex(DependencyReviewError, "snapshot"):
                    store.terminal_snapshot(
                        repository, attempt_id=proposal.attempt_id, binding=binding,
                    )
                with self.assertRaisesRegex(DependencyGraphError, "graph evidence"):
                    graph.activate(
                        repository, proposal, binding=graph_binding,
                        graph_version_id="graph-auth",
                    )
                with self.assertRaisesRegex(DependencyGraphError, "current dependency graph"):
                    graph.current(repository, binding=graph_binding)

    def test_graph_activation_rechecks_scope_immediately_before_mutation(self) -> None:
        """A same-scope durable denial leaves every graph table unchanged."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            proposal = self.proposal("graph-scope-stop")
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            self.accept(store, repository, proposal, binding=binding)
            graph = DependencyGraphStore()
            with mock.patch(
                "roundwright.dependency_graph.require_scope_open",
                side_effect=ScopeAdmissionDenied("injected graph scope stop"),
            ), self.assertRaisesRegex(DependencyGraphError, "activation is unavailable"):
                graph.activate(
                    repository, proposal,
                    binding=DependencyGraphBinding.from_review_binding(binding),
                    graph_version_id="graph-scope-stop",
                )
            with closing(sqlite3.connect(database_path(repository))) as connection:
                for table in (
                    "dependency_graph_versions", "dependency_graph_members",
                    "dependency_graph_edges", "dependency_graph_current",
                    "dependency_graph_decisions",
                ):
                    self.assertEqual(
                        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone(),
                        (0,),
                    )

    def test_schema67_dependency_evidence_migrates_with_original_dispatch(self) -> None:
        """Accepted evidence and its active graph survive the exact v67 upgrade."""

        from roundwright.state import MIGRATIONS, _apply_migrations

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            graph_binding = DependencyGraphBinding.from_review_binding(binding)
            proposal = self.proposal("migration-dispatch")
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            self.accept(store, repository, proposal, binding=binding)
            graph = DependencyGraphStore()
            graph.activate(
                repository, proposal, binding=graph_binding,
                graph_version_id="graph-migration-dispatch",
            )
            path = database_path(repository)
            self.replace_with_schema(repository, 67)
            self.assertEqual(initialize(repository).version, len(MIGRATIONS))
            self.assertEqual(
                store.accept_proposal(repository, proposal, binding=binding),
                proposal.proposal_digest,
            )
            self.assertEqual(
                store.terminal_snapshot(
                    repository, attempt_id=proposal.attempt_id, binding=binding,
                )["outcome"],
                "accepted",
            )
            self.assertEqual(
                graph.activate(
                    repository, proposal, binding=graph_binding,
                    graph_version_id="graph-migration-dispatch",
                ).decision,
                GraphDecision.ACCEPTED,
            )
            self.assertEqual(
                graph.current(repository, binding=graph_binding).graph_version_id,
                "graph-migration-dispatch",
            )
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT session_identity, turn_identity FROM "
                    "dependency_review_accepted_result_dispatches WHERE attempt_id=?",
                    (proposal.attempt_id,),
                ).fetchone(), (
                    "session-" + proposal.attempt_id,
                    "turn-" + proposal.attempt_id,
                ))
                self.assertEqual(connection.execute(
                    "SELECT session_identity FROM dependency_review_failure_admissions "
                    "WHERE attempt_id=?", (proposal.attempt_id,),
                ).fetchone(), ("session-" + proposal.attempt_id,))

    def test_schema83_missing_admission_is_not_reconstructed(self) -> None:
        """A schema that required admission cannot heal deletion at v84."""

        from roundwright.state import MIGRATIONS

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            proposal = self.proposal("schema83-admission-gap")
            store.start_attempt(
                repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                source_owned_relations=self.source_owned_relations(proposal),
            )
            self.accept(store, repository, proposal, binding=binding)
            path = database_path(repository)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("DROP TABLE dependency_review_accepted_result_dispatches")
                connection.execute("DELETE FROM schema_migrations WHERE version=84")
                connection.execute(
                    "DELETE FROM dependency_review_failure_admissions WHERE attempt_id=?",
                    (proposal.attempt_id,),
                )
            with self.assertRaisesRegex(StateError, "admission is missing"):
                initialize(repository)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone(), (83,))
                self.assertEqual(len(MIGRATIONS), 84)

    def test_schema67_and_schema83_accepted_history_survive_candidate_invalidation(self) -> None:
        """A removed current seal preserves history without minting new authority."""

        from roundwright.state import MIGRATIONS

        for version in (67, 83):
            with self.subTest(schema=version), tempfile.TemporaryDirectory() as temporary:
                repository, subset = self.setup_review(Path(temporary))
                store = DependencyReviewStore()
                binding = self.binding(subset)
                proposal = self.proposal(f"schema{version}-invalidated-history")
                store.start_attempt(
                    repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                    source_owned_relations=self.source_owned_relations(proposal),
                )
                self.accept(store, repository, proposal, binding=binding)
                path = database_path(repository)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        "DELETE FROM candidate_seals WHERE task_id=?", (subset.task_id,),
                    )
                self.replace_with_schema(repository, version)
                self.assertEqual(initialize(repository).version, len(MIGRATIONS))
                with closing(sqlite3.connect(path)) as connection:
                    self.assertIsNone(connection.execute(
                        "SELECT 1 FROM candidate_seals WHERE task_id=?", (subset.task_id,),
                    ).fetchone())
                    self.assertEqual(connection.execute(
                        "SELECT session_identity, turn_identity, output_digest "
                        "FROM dependency_review_accepted_result_dispatches WHERE attempt_id=?",
                        (proposal.attempt_id,),
                    ).fetchone(), (
                        "session-" + proposal.attempt_id,
                        "turn-" + proposal.attempt_id,
                        proposal.proposal_digest,
                    ))
                    admission_count = connection.execute(
                        "SELECT COUNT(*) FROM dependency_review_failure_admissions WHERE attempt_id=?",
                        (proposal.attempt_id,),
                    ).fetchone()
                    self.assertEqual(admission_count, (0,) if version == 67 else (1,))
                with self.assertRaises(DependencyReviewError):
                    store.terminal_snapshot(
                        repository, attempt_id=proposal.attempt_id, binding=binding,
                    )

    def test_schema67_and_schema83_history_survives_newer_seal_but_rejects_tampering(self) -> None:
        """A newer candidate preserves only complete authenticated old history."""

        from roundwright.state import MIGRATIONS

        for version in (67, 83):
            with self.subTest(schema=version), tempfile.TemporaryDirectory() as temporary:
                repository, subset = self.setup_review(Path(temporary))
                store = DependencyReviewStore()
                binding = self.binding(subset)
                proposal = self.proposal(f"schema{version}-newer-seal-history")
                store.start_attempt(
                    repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                    source_owned_relations=self.source_owned_relations(proposal),
                )
                self.accept(store, repository, proposal, binding=binding)
                path = database_path(repository)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        "UPDATE candidate_seals SET candidate_sha=? WHERE task_id=?",
                        ("f" * 40, subset.task_id),
                    )
                self.replace_with_schema(repository, version)
                self.assertEqual(initialize(repository).version, len(MIGRATIONS))
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT candidate_sha FROM candidate_seals WHERE task_id=?",
                        (subset.task_id,),
                    ).fetchone(), ("f" * 40,))
                    self.assertEqual(connection.execute(
                        "SELECT session_identity, turn_identity, output_digest "
                        "FROM dependency_review_accepted_result_dispatches WHERE attempt_id=?",
                        (proposal.attempt_id,),
                    ).fetchone(), (
                        "session-" + proposal.attempt_id,
                        "turn-" + proposal.attempt_id,
                        proposal.proposal_digest,
                    ))
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM dependency_review_failure_admissions WHERE attempt_id=?",
                        (proposal.attempt_id,),
                    ).fetchone(), (0,) if version == 67 else (1,))
                with self.assertRaises(DependencyReviewError):
                    store.terminal_snapshot(
                        repository, attempt_id=proposal.attempt_id, binding=binding,
                    )

        for tamper in ("missing-proposal", "conflicting-output", "substituted-subset-candidate"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temporary:
                repository, subset = self.setup_review(Path(temporary))
                store = DependencyReviewStore()
                binding = self.binding(subset)
                proposal = self.proposal("schema67-newer-seal-" + tamper)
                store.start_attempt(
                    repository, subset, attempt_id=proposal.attempt_id, binding=binding,
                    source_owned_relations=self.source_owned_relations(proposal),
                )
                self.accept(store, repository, proposal, binding=binding)
                path = database_path(repository)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        "UPDATE candidate_seals SET candidate_sha=? WHERE task_id=?",
                        ("f" * 40, subset.task_id),
                    )
                    if tamper == "missing-proposal":
                        connection.execute(
                            "DELETE FROM dependency_review_proposals WHERE attempt_id=?",
                            (proposal.attempt_id,),
                        )
                    elif tamper == "conflicting-output":
                        connection.execute(
                            "UPDATE dependency_review_validation_outcomes SET output_digest=? WHERE attempt_id=?",
                            (digest("f"), proposal.attempt_id),
                        )
                    else:
                        # Advance the current seal, then rewrite only the old
                        # subset's candidate column.  Its retained subset and
                        # request digests still authenticate the original value.
                        connection.execute(
                            "UPDATE dependency_review_subsets SET candidate_sha=? WHERE snapshot_id=?",
                            ("e" * 40, subset.snapshot_id),
                        )
                self.replace_with_schema(repository, 67)
                with self.assertRaisesRegex(StateError, "unauthenticated"):
                    initialize(repository)
                if tamper == "substituted-subset-candidate":
                    with closing(sqlite3.connect(path)) as connection:
                        self.assertEqual(connection.execute(
                            "SELECT MAX(version) FROM schema_migrations",
                        ).fetchone(), (67,))
                        for table in (
                            "dependency_review_failure_admissions",
                            "dependency_review_accepted_result_dispatches",
                            "recovery_route_authorizations",
                        ):
                            self.assertIsNone(connection.execute(
                                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                                (table,),
                            ).fetchone())

    def test_incomplete_schema67_claim_does_not_mint_admission_authority(self) -> None:
        """Only complete accepted legacy evidence receives a historical binding."""

        from roundwright.state import MIGRATIONS

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            binding = self.binding(subset)
            identity = TaskIdentity(
                "task-113", "source-113", "repo-113", "codex/113",
                "C:/review-113", "a" * 40,
            )
            store.start_attempt(
                repository, subset, attempt_id="schema67-incomplete", binding=binding,
            )
            store.claim_pre_dispatch(
                repository, attempt_id="schema67-incomplete",
                task_identity=identity, binding=binding,
            )
            store.claim_session(
                repository, attempt_id="schema67-incomplete",
                session_identity="legacy-session", task_identity=identity, binding=binding,
            )
            store.claim_turn(
                repository, attempt_id="schema67-incomplete",
                session_identity="legacy-session", turn_identity="legacy-turn",
            )
            self.replace_with_schema(repository, 67)
            self.assertEqual(initialize(repository).version, len(MIGRATIONS))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM dependency_review_failure_admissions "
                    "WHERE attempt_id='schema67-incomplete'"
                ).fetchone(), (0,))

    def test_graph_requires_the_pre_dispatch_relation_identity_not_caller_scalars(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            relation = SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
            proposal = DependencyProposal("proposal-113", "attempt-113", RequestedDisposition.AUTO_ACTIVATE, "not-required", (
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), digest("0")),
            ))
            reviews = DependencyReviewStore()
            attempt = reviews.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset), source_owned_relations=(relation,))
            model_input = reviews.model_input(subset, attempt_id=attempt.attempt_id, profile_identity=self.binding(subset).profile_identity, source_owned_relations=(relation,))
            self.assertEqual(model_input["trusted_relations"][0]["trusted_relation_digest"], relation.relation_digest)
            self.accept(reviews, repository, proposal, binding=self.binding(subset))
            result = DependencyGraphStore().activate(repository, proposal, binding=DependencyGraphBinding.from_review_binding(self.binding(subset)), graph_version_id="graph-113")
            self.assertEqual((result.decision, result.reason_code), (GraphDecision.REJECTED, "provenance-unavailable"))

    def test_malformed_drifted_and_missing_member_results_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            with self.assertRaises(DependencyReviewError):
                DependencyProposal.parse({"schema": "roundwright-dependency-review-proposal/v1"})
            missing = DependencyProposal("proposal-113", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "missing", digest("5"), Confidence.HIGH, digest("6")),))
            with self.assertRaises(DependencyReviewError):
                self.accept(store, repository, missing, binding=self.binding(subset))
            changed = AffectedSubset(subset.snapshot_id, subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, digest("0"), subset.creation_reason, subset.members)
            with self.assertRaises(DependencyReviewError):
                store.start_attempt(repository, changed, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            with self.assertRaises(DependencyReviewError):
                self.accept(store, repository, self.proposal(attempt.attempt_id), binding=self.binding(subset))

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
            self.assertEqual(self.accept(store, repository, self.proposal(retry.attempt_id, semantic=True), binding=self.binding(retry_subset)), self.proposal(retry.attempt_id, semantic=True).proposal_digest)

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
                        self.accept(store, repository, self.proposal(attempt.attempt_id), binding=binding)
            self.assertEqual(self.accept(store, repository, self.proposal(attempt.attempt_id), binding=self.binding(subset)), self.proposal(attempt.attempt_id).proposal_digest)

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
            self.accept(store, repository, proposal, binding=self.binding(subset))
            return repository, subset, store, proposal
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_subset_members SET content_digest = ? WHERE snapshot_id = ? AND member_id = ?", (digest("0"), subset.snapshot_id, "member-a"))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            self.accept(store, repository, proposal, binding=self.binding(subset))
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_proposal_edges SET confidence = 'low' WHERE proposal_id = ?", (proposal.proposal_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            self.accept(store, repository, proposal, binding=self.binding(subset))

    def test_terminal_replays_never_repair_missing_or_extra_outcomes(self) -> None:
        def accepted() -> tuple[RepositoryIdentity, AffectedSubset, DependencyReviewStore, DependencyProposal]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            repository, subset = self.setup_review(Path(temporary.name))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            self.accept(store, repository, proposal, binding=self.binding(subset))
            return repository, subset, store, proposal
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("DELETE FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (proposal.attempt_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            self.accept(store, repository, proposal, binding=self.binding(subset))
        repository, subset, store, proposal = accepted()
        connection = sqlite3.connect(database_path(repository))
        try:
            connection.execute("UPDATE dependency_review_validation_outcomes SET reason_code = 'tampered' WHERE attempt_id = ?", (proposal.attempt_id,))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DependencyReviewError):
            self.accept(store, repository, proposal, binding=self.binding(subset))
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
                self.accept(store, repository, self.proposal(attempt.attempt_id), binding=self.binding(subset))
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
            self.accept(store, repository, proposal, binding=self.binding(successor))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_review_attempts SET supersedes_attempt_id = NULL WHERE attempt_id = ?", (second.attempt_id,))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyReviewError):
                self.accept(store, repository, proposal, binding=self.binding(successor))

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
            self.accept(store, repository, proposal, binding=self.binding(second_subset))
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_review_successors SET successor_attempt_id = ? WHERE predecessor_attempt_id = ?", ("missing-attempt", first.attempt_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyReviewError):
                self.accept(store, repository, proposal, binding=self.binding(second_subset))

    def test_accepted_predecessor_rejects_proposal_edge_ordinal_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            store.record_invalid(repository, attempt_id=first.attempt_id, output_digest=digest("8"), reason_code="malformed-response")
            second_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            second = store.start_attempt(repository, second_subset, attempt_id="attempt-114", binding=self.binding(second_subset), supersedes_attempt_id=first.attempt_id)
            proposal = self.proposal(second.attempt_id)
            self.accept(store, repository, proposal, binding=self.binding(second_subset))
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
            proposal = self.proposal("attempt-113")
            attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset), source_owned_relations=self.source_owned_relations(proposal))
            self.accept(review_store, repository, proposal, binding=self.binding(subset))
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

    def test_graph_activation_rolls_back_partial_write_and_serializes_concurrent_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            reviews = DependencyReviewStore()
            proposal = self.proposal("attempt-113")
            attempt = reviews.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset), source_owned_relations=self.source_owned_relations(proposal))
            self.accept(reviews, repository, proposal, binding=self.binding(subset))
            binding = DependencyGraphBinding.from_review_binding(self.binding(subset))
            graph = DependencyGraphStore()
            with mock.patch.object(DependencyGraphStore, "_write_version", side_effect=RuntimeError("injected")):
                with self.assertRaises(DependencyGraphError):
                    graph.activate(repository, proposal, binding=binding, graph_version_id="graph-113")
            with self.assertRaises(DependencyGraphError):
                graph.current(repository, binding=binding)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = tuple(executor.map(lambda _: graph.activate(repository, proposal, binding=binding, graph_version_id="graph-113"), range(2)))
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[0].decision, GraphDecision.ACCEPTED)

    def test_conflicting_canonical_edges_leave_the_current_graph_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            reviews = DependencyReviewStore()
            binding = self.binding(subset)
            graph_binding = DependencyGraphBinding.from_review_binding(binding)
            first = self.proposal("attempt-113")
            reviews.start_attempt(repository, subset, attempt_id="attempt-113", binding=binding, source_owned_relations=self.source_owned_relations(first))
            self.accept(reviews, repository, first, binding=binding)
            graph = DependencyGraphStore()
            self.assertEqual(graph.activate(repository, first, binding=graph_binding, graph_version_id="graph-113").decision, GraphDecision.ACCEPTED)
            successor_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", (*subset.members, AffectedMember("member-c", digest("9"), digest("a"))))
            relations = (
                SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),
                SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.BLOCKS, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8")),
                SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-b", "member-c", digest("b"), Confidence.HIGH, digest("c")),
            )
            proposal = DependencyProposal("proposal-114", "attempt-114", RequestedDisposition.AUTO_ACTIVATE, "not-required", (
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), relations[0].relation_digest),
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.BLOCKS, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8"), relations[1].relation_digest),
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-b", "member-c", digest("b"), Confidence.HIGH, digest("c"), relations[2].relation_digest),
            ))
            reviews.start_attempt(repository, successor_subset, attempt_id="attempt-114", binding=self.binding(successor_subset), source_owned_relations=relations, supersedes_attempt_id="attempt-113")
            self.accept(reviews, repository, proposal, binding=self.binding(successor_subset))
            result = graph.activate(repository, proposal, binding=graph_binding, graph_version_id="graph-114")
            self.assertEqual((result.decision, result.reason_code), (GraphDecision.REJECTED, "duplicate-or-conflicting-edge"))
            self.assertEqual(graph.current(repository, binding=graph_binding).graph_version_id, "graph-113")

    def test_graph_activation_routes_semantic_and_rejects_incomplete_or_cyclic_edges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            review_store = DependencyReviewStore()
            graph_store = DependencyGraphStore()
            binding = self.binding(subset)
            graph_binding = DependencyGraphBinding.from_review_binding(binding)
            semantic_attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=binding)
            semantic = self.proposal(semantic_attempt.attempt_id, semantic=True)
            self.accept(review_store, repository, semantic, binding=binding)
            pending = graph_store.activate(repository, semantic, binding=graph_binding, graph_version_id="graph-113")
            self.assertEqual((pending.decision, pending.graph_version_id), (GraphDecision.PENDING_OWNER, None))
            retry_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", (*subset.members, AffectedMember("member-c", digest("9"), digest("a"))))
            relation = SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
            incomplete = DependencyProposal("proposal-114", "attempt-114", RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), relation.relation_digest),))
            attempt = review_store.start_attempt(repository, retry_subset, attempt_id="attempt-114", binding=self.binding(retry_subset), source_owned_relations=(relation,), supersedes_attempt_id=semantic_attempt.attempt_id)
            self.accept(review_store, repository, incomplete, binding=self.binding(retry_subset))
            self.assertEqual(graph_store.activate(repository, incomplete, binding=graph_binding, graph_version_id="graph-114").reason_code, "affected-subset-incomplete")
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            review_store = DependencyReviewStore()
            first_relation = SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
            second_relation = SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8"))
            attempt = review_store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset), source_owned_relations=(first_relation, second_relation))
            cycle = DependencyProposal("proposal-113", attempt.attempt_id, RequestedDisposition.AUTO_ACTIVATE, "not-required", (
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), first_relation.relation_digest),
                ProposedEdge(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8"), second_relation.relation_digest),
            ))
            self.accept(review_store, repository, cycle, binding=self.binding(subset))
            graph_binding = DependencyGraphBinding.from_review_binding(self.binding(subset))
            result = DependencyGraphStore().activate(repository, cycle, binding=graph_binding, graph_version_id="graph-113")
            self.assertEqual(result.decision, GraphDecision.REJECTED)
            self.assertEqual(result.reason_code, "cycle-detected")

    def test_semantic_owner_routing_requires_complete_nonconflicting_acyclic_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            expanded = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", (*subset.members, AffectedMember("member-c", digest("9"), digest("a"))))
            binding = self.binding(expanded)
            reviews = DependencyReviewStore()
            reviews.start_attempt(repository, expanded, attempt_id="attempt-113", binding=binding)
            incomplete = DependencyProposal("proposal-113", "attempt-113", RequestedDisposition.OWNER_REVIEW, "owner-review", (
                ProposedEdge(EdgeKind.SEMANTIC_INFERRED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),
            ))
            self.accept(reviews, repository, incomplete, binding=binding)
            result = DependencyGraphStore().activate(repository, incomplete, binding=DependencyGraphBinding.from_review_binding(binding), graph_version_id="graph-113")
            self.assertEqual((result.decision, result.reason_code), (GraphDecision.REJECTED, "affected-subset-incomplete"))
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            binding = self.binding(subset)
            reviews = DependencyReviewStore()
            reviews.start_attempt(repository, subset, attempt_id="attempt-113", binding=binding)
            cyclic = DependencyProposal("proposal-113", "attempt-113", RequestedDisposition.OWNER_REVIEW, "owner-review", (
                ProposedEdge(EdgeKind.SEMANTIC_INFERRED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),
                ProposedEdge(EdgeKind.SEMANTIC_INFERRED, EdgeDirection.DEPENDS_ON, "member-b", "member-a", digest("7"), Confidence.HIGH, digest("8")),
            ))
            self.accept(reviews, repository, cyclic, binding=binding)
            result = DependencyGraphStore().activate(repository, cyclic, binding=DependencyGraphBinding.from_review_binding(binding), graph_version_id="graph-113")
            self.assertEqual((result.decision, result.reason_code), (GraphDecision.REJECTED, "cycle-detected"))

    def test_graph_requires_provenance_and_replaces_only_the_terminal_subset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            review_binding = self.binding(subset)
            graph_binding = DependencyGraphBinding.from_review_binding(review_binding)
            proposal = self.proposal("attempt-113")
            first = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=review_binding, source_owned_relations=self.source_owned_relations(proposal))
            self.accept(store, repository, proposal, binding=review_binding)
            graph = DependencyGraphStore()
            first_result = graph.activate(repository, proposal, binding=graph_binding, graph_version_id="graph-113")
            self.assertEqual(first_result.decision, GraphDecision.ACCEPTED)
            successor_subset = AffectedSubset("subset-114", subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, "retry", subset.members)
            replacement = DependencyProposal("proposal-114", "attempt-114", RequestedDisposition.AUTO_ACTIVATE, "not-required", proposal.edges)
            successor = store.start_attempt(repository, successor_subset, attempt_id="attempt-114", binding=self.binding(successor_subset), source_owned_relations=self.source_owned_relations(replacement), supersedes_attempt_id=first.attempt_id)
            self.accept(store, repository, replacement, binding=self.binding(successor_subset))
            with self.assertRaisesRegex(DependencyGraphError, "superseded"):
                graph.activate(repository, proposal, binding=graph_binding, graph_version_id="graph-113")
            result = graph.activate(repository, replacement, binding=graph_binding, graph_version_id="graph-114")
            self.assertEqual((result.decision, result.graph_version_id), (GraphDecision.ACCEPTED, "graph-114"))
            self.assertEqual(graph.current(repository, binding=graph_binding).graph_version_id, "graph-114")
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            self.accept(store, repository, proposal, binding=self.binding(subset))
            self.assertEqual(DependencyGraphStore().activate(repository, proposal, binding=DependencyGraphBinding.from_review_binding(self.binding(subset)), graph_version_id="graph-113").reason_code, "provenance-unavailable")

    def test_graph_provenance_and_persisted_decision_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset))
            proposal = self.proposal(attempt.attempt_id)
            self.accept(store, repository, proposal, binding=self.binding(subset))
            binding = DependencyGraphBinding.from_review_binding(self.binding(subset))
            self.assertEqual(DependencyGraphStore().activate(repository, proposal, binding=binding, graph_version_id="graph-113").reason_code, "provenance-unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset = self.setup_review(Path(temporary))
            store = DependencyReviewStore()
            relation = SourceOwnedRelation(EdgeKind.POLICY_DERIVED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
            policy = DependencyProposal("proposal-114", "attempt-113", RequestedDisposition.AUTO_ACTIVATE, "not-required", (ProposedEdge(EdgeKind.POLICY_DERIVED, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"), relation.relation_digest),))
            attempt = store.start_attempt(repository, subset, attempt_id="attempt-113", binding=self.binding(subset), source_owned_relations=(relation,))
            self.accept(store, repository, policy, binding=self.binding(subset))
            binding = DependencyGraphBinding.from_review_binding(self.binding(subset))
            graph = DependencyGraphStore()
            self.assertEqual(graph.activate(repository, policy, binding=binding, graph_version_id="graph-113").decision, GraphDecision.ACCEPTED)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE dependency_graph_trusted_relations SET rationale_digest = ? WHERE snapshot_id = ?", (digest("0"), subset.snapshot_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(DependencyGraphError):
                graph.current(repository, binding=binding)


if __name__ == "__main__":
    unittest.main()
