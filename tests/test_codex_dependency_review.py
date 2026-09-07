"""Contract tests for fresh, credential-isolated dependency-review turns."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.codex_dependency_review import (
    CodexDependencyReviewAdapter, DependencyReviewResultKind, DependencyReviewService,
    NativeDependencyReviewResponse,
)
from roundwright import external_validation
from roundwright.configuration import ProviderProfile, ReasoningEffort, RepositoryIdentity
from roundwright.dependency_review import (
    AffectedMember, AffectedSubset, Confidence, DependencyReviewBinding, EdgeDirection,
    EdgeKind, ProposedEdge, RequestedDisposition, SourceOwnedRelation,
)
from roundwright.git_identity import acquire_transition_lease
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize
from roundwright.shadow import DEPENDENCY_REVIEW_ATTEMPT_PROFILE, shadow_evidence_profile


def digest(character: str) -> str:
    return "sha256:" + character * 64


class Turn:
    def __init__(self, response: NativeDependencyReviewResponse) -> None:
        self.response = response
        self.aborted = False

    def identity(self) -> str: return "turn-116"
    def abort(self) -> None: self.aborted = True
    def read_response(self) -> NativeDependencyReviewResponse: return self.response


class Session:
    def __init__(self, response: NativeDependencyReviewResponse) -> None:
        self.response = response
        self.requests = []
        self.closed = False

    def identity(self) -> str: return "session-116"
    def close(self) -> None: self.closed = True
    def start_turn(self, request):
        self.requests.append(request)
        return Turn(self.response)


class Backend:
    def __init__(self, response: NativeDependencyReviewResponse) -> None:
        self.response = response
        self.sessions = []

    def open_fresh_session(self, profile: ProviderProfile) -> Session:
        session = Session(self.response)
        self.sessions.append(session)
        return session


class DependencyReviewServiceTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", root.resolve())
        return repository

    def setup(self, root: Path):
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("task-116", "source-116", "repo-116", "codex/116", "C:/review-116", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="dependency-review-tests", ttl_seconds=60)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        subset = AffectedSubset("subset-116", identity.task_id, "b" * 64, "c" * 40, digest("d"), digest("e"), digest("f"), "initial", (
            AffectedMember("member-a", digest("1"), digest("2")),
            AffectedMember("member-b", digest("3"), digest("4")),
        ))
        binding = DependencyReviewBinding(subset.candidate_sha, subset.policy_digest, subset.configuration_digest, digest("7"))
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile, binding.profile_identity)
        return repository, subset, binding, profile, audit

    def proposal(self, attempt_id: str) -> dict[str, object]:
        relation = SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6"))
        return {
            "schema": "roundwright-dependency-review-proposal/v2", "proposal_id": "proposal-116",
            "attempt_id": attempt_id, "requested_disposition": RequestedDisposition.AUTO_ACTIVATE.value,
            "owner_route": "not-required", "edges": [{
                "kind": EdgeKind.EXPLICIT.value, "direction": EdgeDirection.DEPENDS_ON.value,
                "subject_member_id": "member-a", "object_member_id": "member-b",
                "rationale_digest": digest("5"), "confidence": Confidence.HIGH.value,
                "conflicts_digest": digest("6"), "trusted_relation_digest": relation.relation_digest,
            }],
        }

    def test_fresh_no_tools_attempt_accepts_only_the_bound_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, self.proposal("attempt-116")))
            adapter = CodexDependencyReviewAdapter(backend, profile, audit)
            result = DependencyReviewService().run(repository, subset, attempt_id="attempt-116", binding=binding, adapter=adapter, checkpoint_session=lambda session: self.assertEqual(session, "session-116"), checkpoint_turn=lambda session, turn: self.assertEqual((session, turn), ("session-116", "turn-116")), source_owned_relations=(SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),))
            self.assertEqual(result.kind, DependencyReviewResultKind.ACCEPTED)
            self.assertEqual(len(backend.sessions), 1)
            request = backend.sessions[0].requests[0]
            self.assertEqual(set(request.input_material), {"schema", "attempt_id", "profile_identity", "subset_digest", "task_id", "source_digest", "candidate_sha", "policy_digest", "configuration_digest", "boundary_digest", "members", "trusted_relations"})
            self.assertNotIn("credential", str(request.input_material))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id = 'attempt-116'").fetchone(), ("accepted",))
            finally:
                connection.close()

    def test_ambiguous_turn_is_terminal_and_requires_a_successor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS))
            result = DependencyReviewService().run(repository, subset, attempt_id="attempt-116", binding=binding, adapter=CodexDependencyReviewAdapter(backend, profile, audit), checkpoint_session=lambda _: None, checkpoint_turn=lambda _session, _turn: (_ for _ in ()).throw(RuntimeError("checkpoint unavailable")))
            self.assertEqual((result.kind, result.reason_code), (DependencyReviewResultKind.AMBIGUOUS, "uncertain-provider-turn"))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id = 'attempt-116'").fetchone(), ("blocked",))
            finally:
                connection.close()

    def test_live_lane_preflight_is_candidate_bound_and_provider_free(self) -> None:
        plan = SimpleNamespace(
            plan_digest=digest("a"), profile=DEPENDENCY_REVIEW_ATTEMPT_PROFILE,
            case_id="case-116", candidate_sha="c" * 40, ready_at=1,
        )
        components = SimpleNamespace(
            producer_identity=external_validation.DEPENDENCY_REVIEW_ATTEMPT_PRODUCER_IDENTITY,
            exporter_identity=external_validation.DEPENDENCY_REVIEW_ATTEMPT_EXPORTER_IDENTITY,
            comparator_identity=external_validation.DEPENDENCY_REVIEW_ATTEMPT_COMPARATOR_IDENTITY,
        )
        binding = SimpleNamespace(
            plan=plan, profile=plan.profile, case_id=plan.case_id,
            candidate_sha=plan.candidate_sha, ready_at=plan.ready_at, components=components,
        )
        adapter = external_validation.DependencyReviewAttemptAdapter()
        self.assertEqual(shadow_evidence_profile(DEPENDENCY_REVIEW_ATTEMPT_PROFILE).capture_mode.value, "armed-live-events")
        adapter.validate(binding)
        self.assertIsInstance(
            external_validation.roundwright_profile_adapter_factory(DEPENDENCY_REVIEW_ATTEMPT_PROFILE),
            external_validation.DependencyReviewAttemptAdapter,
        )
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "hosted fresh-session dispatch"):
            adapter.execute(binding)

    def test_sealed_lane_preflight_is_provider_free_and_executes_once(self) -> None:
        """The public product boundary owns request, host, and replay state."""

        class Receipt:
            def __init__(self, value): self.value = value
            def as_dict(self): return self.value

        class Execution:
            def __init__(self, value, mutation_count=0): self.value, self.mutation_count = value, mutation_count

        class Harness:
            ExecutorReadinessReceipt = Receipt
            ProfileExecution = Execution

            @staticmethod
            def prepare_capture(capture):
                return SimpleNamespace(
                    plan_digest=external_validation._digest(capture), profile=capture["profile"],
                    case_id=capture["case_id"], candidate_sha=capture["candidate_sha"], ready_at=capture["ready_at"],
                )

            @staticmethod
            def run_profile_executor(mode, request_value, adapter, store_root, **keywords):
                request = dict(request_value)
                capture = request["capture_plan"]
                plan = Harness.prepare_capture(capture)
                if mode == "execute":
                    components = SimpleNamespace(
                        producer_identity=capture["producer_identity"], exporter_identity=capture["exporter_identity"],
                        comparator_identity=capture["comparator_identity"],
                    )
                    return adapter.execute(SimpleNamespace(
                        plan=plan, profile=plan.profile, case_id=plan.case_id,
                        candidate_sha=plan.candidate_sha, ready_at=plan.ready_at, components=components,
                    ))
                core = {
                    "schema": "roundwright-harness-profile-executor-readiness/v2", "status": "ready", "state": "PREFLIGHT_READY",
                    "plan_digest": plan.plan_digest, "profile": plan.profile, "case_id": plan.case_id,
                    "candidate_sha": plan.candidate_sha, "ready_at": plan.ready_at,
                    "producer_identity": capture["producer_identity"], "exporter_identity": capture["exporter_identity"],
                    "comparator_identity": capture["comparator_identity"], "dispatch_count": 0, "record_count": 0,
                    "verify_count": 0, "mutation_count": 0,
                    "execution_context_input_digest": external_validation._digest(request["execution_context"]),
                    "execution_context_identity": external_validation._dependency_review_context_identity(request["execution_context"]),
                }
                return Receipt({**core, "receipt_digest": external_validation._digest(core)})

        with tempfile.TemporaryDirectory() as temporary, patch.object(external_validation, "_harness_executor", return_value=Harness):
            repository, subset, binding, _profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, self.proposal(subset.snapshot_id)))
            base_sha = "a" * 40
            inputs = external_validation.DependencyReviewRequestInputs(
                repository, base_sha, subset, binding, audit, subset.snapshot_id, 17, backend,
            )
            prepared, readiness, capsule = external_validation.prepare_dependency_review_attempt_profile(inputs, Path(temporary).resolve())
            self.assertEqual(len(backend.sessions), 0)
            self.assertEqual(prepared.capture_plan_digest, readiness.capture_plan_digest)
            self.assertEqual(prepared.public_receipt()["base_sha"], base_sha)
            self.assertEqual(prepared._request_value["execution_context"]["base_sha"], base_sha)
            object.__setattr__(inputs, "base_sha", "b" * 40)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "prepared request has drifted"):
                external_validation.materialize_dependency_review_attempt_profile(capsule, Path(temporary).resolve())
            self.assertEqual(len(backend.sessions), 0)
            fresh_inputs = external_validation.DependencyReviewRequestInputs(
                repository, base_sha, subset, binding, audit, subset.snapshot_id, 17, backend,
            )
            _prepared, _readiness, fresh_capsule = external_validation.prepare_dependency_review_attempt_profile(fresh_inputs, Path(temporary).resolve())
            external_validation.materialize_dependency_review_attempt_profile(fresh_capsule, Path(temporary).resolve())
            self.assertEqual(len(backend.sessions), 1)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "unavailable"):
                external_validation.materialize_dependency_review_attempt_profile(fresh_capsule, Path(temporary).resolve())


if __name__ == "__main__":
    unittest.main()
