"""Contract tests for fresh, credential-isolated dependency-review turns."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.codex_dependency_review import (
    CodexDependencyReviewAdapter, DependencyReviewRequest, DependencyReviewResultKind, DependencyReviewService,
    NativeDependencyReviewResponse, DependencyReviewDispatchError, prepare_dependency_review_host,
)
from roundwright.dependency_review_toolbox import (
    HarnessNativeCodexDependencyReviewBackend, _Turn, _schema,
    dependency_review_native_control_contract, dependency_review_native_control_digest,
)
from roundwright.worker_toolbox import CompletionDeadline
from roundwright import external_validation
from roundwright.configuration import ProviderProfile, ReasoningEffort, RepositoryIdentity
from roundwright.dependency_review import (
    AffectedMember, AffectedSubset, Confidence, DependencyReviewBinding, EdgeDirection,
    EdgeKind, ProposedEdge, RequestedDisposition, SourceOwnedRelation, DependencyReviewStore,
)
from roundwright.git_identity import acquire_transition_lease
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.role_capability_policy import AdvisoryRole, trusted_provider_launch_context
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize
from roundwright.failure_recovery import EvidenceSource, FailureBinding, FailureClass, FailureRole, classify, record_durable_failure
from roundwright.shadow import DEPENDENCY_REVIEW_ATTEMPT_PROFILE, shadow_evidence_profile
from tests.role_admission_fixture import independent_execution, sealed_execution, sealed_execution_for_effect, trusted_execution_host


def digest(character: str) -> str:
    return "sha256:" + character * 64


class Turn:
    def __init__(self, response: NativeDependencyReviewResponse, identity: str = "turn-116") -> None:
        self.response = response
        self._identity = identity
        self.aborted = False

    def identity(self) -> str: return self._identity
    def abort(self) -> None: self.aborted = True
    def read_response(self) -> NativeDependencyReviewResponse: return self.response


class Session:
    def __init__(self, response: NativeDependencyReviewResponse, identity: str = "session-116", turn_identity: str = "turn-116") -> None:
        self.response = response
        self._identity, self._turn_identity = identity, turn_identity
        self.requests = []
        self.closed = False

    def identity(self) -> str: return self._identity
    def close(self) -> None: self.closed = True
    def start_turn(self, request):
        self.requests.append(request)
        return Turn(self.response, self._turn_identity)


class Backend:
    def __init__(self, response: NativeDependencyReviewResponse, session_identity: str = "session-116", turn_identity: str = "turn-116") -> None:
        self.response = response
        self.session_identity, self.turn_identity = session_identity, turn_identity
        self.sessions = []

    def open_fresh_session(self, profile: ProviderProfile) -> Session:
        session = Session(self.response, self.session_identity, self.turn_identity)
        self.sessions.append(session)
        return session


class DependencyReviewServiceTests(unittest.TestCase):
    @staticmethod
    def admission(profile):
        return sealed_execution(AdvisoryRole.DEPENDENCY_REVIEW, profile)

    @staticmethod
    def expectation(profile):
        return independent_execution(AdvisoryRole.DEPENDENCY_REVIEW, profile)

    def launch_context(self, repository, profile):
        return trusted_provider_launch_context(
            self.admission(profile), cwd=repository.root,
        )

    def effect_kwargs(self, repository, subset, binding, adapter, *, attempt_id, source_owned_relations=()):
        material = DependencyReviewStore().model_input(
            subset, attempt_id=attempt_id, profile_identity=binding.profile_identity,
            source_owned_relations=source_owned_relations,
        )
        request = DependencyReviewRequest(
            attempt_id, material,
            "sha256:" + hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest(),
            binding.profile_identity,
        )
        request_material, preflight_material = adapter.effect_material(request)
        return {
            "advisory_execution": sealed_execution_for_effect(
                AdvisoryRole.DEPENDENCY_REVIEW, adapter._profile,
                request_identity=attempt_id, request_material=request_material,
                preflight_material=preflight_material,
            ),
            "execution_host": trusted_execution_host(AdvisoryRole.DEPENDENCY_REVIEW, adapter._profile),
            "budget_ledger_path": repository.root / f"{attempt_id}-role-budget.sqlite",
        }

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

    def test_native_bridge_schema_uses_the_supported_single_value_enum(self) -> None:
        schema = _schema()
        self.assertEqual(
            schema["properties"]["schema"],
            {"type": "string", "enum": ["roundwright-dependency-review-proposal/v2"]},
        )
        self.assertNotIn("const", str(schema))

    def test_injected_native_factory_cannot_bypass_not_activated(self) -> None:
        session_calls: list[dict[str, object]] = []
        turn_calls: list[tuple[dict[str, object], dict[str, object]]] = []

        class Handle:
            id = "turn-116"

        class Thread:
            id = "session-116"
            def turn(self, prompt, **keywords):
                turn_calls.append((json.loads(prompt), keywords))
                return Handle()

        class Codex:
            def __enter__(self): return self
            def close(self): return None
            def thread_start(self, *, approval_mode, cwd, developer_instructions, ephemeral, model, sandbox):
                session_calls.append({"approval_mode": approval_mode, "cwd": cwd, "developer_instructions": developer_instructions, "ephemeral": ephemeral, "model": model, "sandbox": sandbox})
                return Thread()

        with tempfile.TemporaryDirectory() as temporary:
            repository, _subset, _binding, profile, audit = self.setup(Path(temporary))
            backend = HarnessNativeCodexDependencyReviewBackend(
                cwd=repository.root, completion=CompletionDeadline(100, 600), codex_factory=Codex,
                approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value,
                launch_context=self.launch_context(repository, profile),
            )
            with self.assertRaisesRegex(CodexAdapterError, "sdk-incompatible"):
                backend.open_fresh_session(profile)
            self.assertEqual(session_calls, [])
            self.assertEqual(turn_calls, [])

    def test_native_dependency_review_requires_a_sealed_launch_context_before_factory_creation(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            repository, _subset, _binding, _profile, _audit = self.setup(Path(temporary))
            with self.assertRaises(TypeError):
                HarnessNativeCodexDependencyReviewBackend(
                    cwd=repository.root, completion=CompletionDeadline(100, 600),
                    codex_factory=lambda: calls.append("factory"),
                    approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value,
                )
        self.assertEqual(calls, [])

    def test_native_bridge_rejects_every_tool_event_before_accepting_schema_output(self) -> None:
        class Handle:
            id = "turn-116"
            events = ()
            def stream(self):
                class Stream(list):
                    def close(self): return None
                return Stream((*self.events,
                    {"method": "item/completed", "payload": {"turn_id": self.id, "item": {"type": "agentMessage", "phase": "final_answer", "text": "{}"}}},
                    {"method": "turn/completed", "payload": {"turn": {"id": self.id, "status": "completed"}}},
                ))

        cases = (
            {"method": "item/started", "payload": {"turn_id": Handle.id, "item": {"type": "commandExecution"}}},
            {"method": "item/completed", "payload": {"turn_id": Handle.id, "item": {"type": "mcpToolCall"}}},
            {"method": "item/completed", "payload": {"turn_id": "wrong-turn", "item": {"type": "dynamicToolCall"}}},
            {"method": "tool/call", "payload": {"turn_id": Handle.id}},
            {"method": "command/exec", "payload": {"turn_id": Handle.id}},
        )
        for event in cases:
            with self.subTest(event=event["method"]):
                Handle.events = (event,)
                session = SimpleNamespace(completion=CompletionDeadline(100, 600), clock=lambda: 0, close=lambda: None)
                response = _Turn(Handle(), session).read_response()
                self.assertEqual((response.kind, response.reason_code), (DependencyReviewResultKind.INVALID, "tool-event-observed"))

    def test_native_bridge_rejects_a_safe_item_from_another_turn_without_claiming_tool_use(self) -> None:
        class Handle:
            id = "turn-116"
            def stream(self):
                class Stream(list):
                    def close(self): return None
                return Stream((
                    {"method": "item/completed", "payload": {"turn_id": "wrong-turn", "item": {"type": "agentMessage", "phase": "final_answer", "text": "{}"}}},
                ))

        session = SimpleNamespace(completion=CompletionDeadline(100, 600), clock=lambda: 0, close=lambda: None)
        response = _Turn(Handle(), session).read_response()
        self.assertEqual((response.kind, response.reason_code), (DependencyReviewResultKind.INVALID, None))

    def test_fresh_no_tools_attempt_accepts_only_the_bound_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, self.proposal("attempt-116")))
            adapter = CodexDependencyReviewAdapter(backend, profile, audit)
            relations = (SourceOwnedRelation(EdgeKind.EXPLICIT, EdgeDirection.DEPENDS_ON, "member-a", "member-b", digest("5"), Confidence.HIGH, digest("6")),)
            result = DependencyReviewService().run(repository, subset, attempt_id="attempt-116", binding=binding, adapter=adapter, checkpoint_session=lambda session: self.assertEqual(session, "session-116"), checkpoint_turn=lambda session, turn: self.assertEqual((session, turn), ("session-116", "turn-116")), source_owned_relations=relations, **self.effect_kwargs(repository, subset, binding, adapter, attempt_id="attempt-116", source_owned_relations=relations))
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
            self.assertEqual(
                DependencyReviewStore().terminal_snapshot(repository, attempt_id="attempt-116", binding=binding),
                {
                    "attempt_id": "attempt-116", "input_digest": request.input_digest,
                    "output_digest": result.output_digest, "outcome": "accepted", "proposal_count": 1,
                    "validation_state": "accepted", "tool_event_count": 0,
                    "mutation_count": 0, "credential_exposure_count": 0,
                },
            )

    def test_observed_tool_event_is_durable_terminal_and_ineligible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(
                DependencyReviewResultKind.INVALID, reason_code="tool-event-observed",
            ))
            result = DependencyReviewService().run(
                repository, subset, attempt_id="attempt-116", binding=binding,
                adapter=(adapter := CodexDependencyReviewAdapter(backend, profile, audit)),
                checkpoint_session=lambda _session: None,
                checkpoint_turn=lambda _session, _turn: None,
                **self.effect_kwargs(repository, subset, binding, adapter, attempt_id="attempt-116"),
            )
            self.assertEqual((result.kind, result.reason_code), (DependencyReviewResultKind.INVALID, "tool-event-observed"))
            snapshot = DependencyReviewStore().terminal_snapshot(repository, attempt_id="attempt-116", binding=binding)
            self.assertEqual(
                (snapshot["outcome"], snapshot["validation_state"], snapshot["proposal_count"], snapshot["tool_event_count"]),
                ("invalid", "terminal", 0, 1),
            )
            self.assertEqual((snapshot["mutation_count"], snapshot["credential_exposure_count"]), (0, 0))

    def test_ambiguous_turn_is_terminal_and_requires_a_successor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS))
            adapter = CodexDependencyReviewAdapter(backend, profile, audit)
            result = DependencyReviewService().run(repository, subset, attempt_id="attempt-116", binding=binding, adapter=adapter, checkpoint_session=lambda _: None, checkpoint_turn=lambda _session, _turn: None, **self.effect_kwargs(repository, subset, binding, adapter, attempt_id="attempt-116"))
            self.assertEqual((result.kind, result.reason_code), (DependencyReviewResultKind.AMBIGUOUS, "uncertain-provider-turn"))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id = 'attempt-116'").fetchone(), ("blocked",))
            finally:
                connection.close()

    def test_restart_after_persisted_session_claim_blocks_without_a_second_turn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            store = DependencyReviewStore()
            store.start_attempt(repository, subset, attempt_id="attempt-116", binding=binding)
            store.claim_session(repository, attempt_id="attempt-116", session_identity="session-116")
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS))
            result = DependencyReviewService().run(
                repository, subset, attempt_id="attempt-116", binding=binding,
                adapter=(adapter := CodexDependencyReviewAdapter(backend, profile, audit)),
                checkpoint_session=lambda _: None, checkpoint_turn=lambda _session, _turn: None,
                **self.effect_kwargs(repository, subset, binding, adapter, attempt_id="attempt-116"),
            )
            self.assertEqual((result.kind, result.reason_code, len(backend.sessions)), (DependencyReviewResultKind.AMBIGUOUS, "uncertain-provider-turn", 0))

    def test_restart_scope_denial_blocks_before_dependency_provider_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            identity = TaskIdentity("task-116", "source-116", "repo-116", "codex/116", "C:/review-116", "a" * 40)
            record_durable_failure(repository, identity, classify(FailureBinding(subset.candidate_sha, subset.policy_digest, subset.configuration_digest, "dependency-review:" + subset.task_id, FailureRole.DEPENDENCY_REVIEW, binding.profile_identity, "prior-session", "prior-attempt"), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS))
            adapter = CodexDependencyReviewAdapter(backend, profile, audit)
            with self.assertRaisesRegex(Exception, "scope is stopped"):
                DependencyReviewStore().start_attempt(repository, subset, attempt_id="changed-attempt", binding=binding)
            self.assertEqual(backend.sessions, [])

    def test_digit_leading_native_ids_persist_the_exact_durable_turn_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(
                NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS),
                session_identity="01a07bb4-2916-73b1-97c6-68712c35667c",
                turn_identity="01a07bb4-2916-73b1-97c6-68712c35667d",
            )
            result = DependencyReviewService().run(
                repository, subset, attempt_id="attempt-116", binding=binding,
                adapter=(adapter := CodexDependencyReviewAdapter(backend, profile, audit)),
                checkpoint_session=lambda _: None, checkpoint_turn=lambda _session, _turn: None,
                **self.effect_kwargs(repository, subset, binding, adapter, attempt_id="attempt-116"),
            )
            self.assertEqual(result.kind, DependencyReviewResultKind.AMBIGUOUS)
            DependencyReviewStore().require_turn_claim(
                repository, attempt_id="attempt-116",
                session_identity="01a07bb4-2916-73b1-97c6-68712c35667c",
                turn_identity="01a07bb4-2916-73b1-97c6-68712c35667d",
            )

    def test_adapter_rejects_the_removed_expected_execution_argument(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, _subset, _binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.AMBIGUOUS))
            material = {"schema": "roundwright-dependency-review-input/v1"}
            request = DependencyReviewRequest("attempt-116", material, "sha256:" + hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(), audit.profile_identity)
            with self.assertRaises(TypeError):
                CodexDependencyReviewAdapter(backend, profile, audit).dispatch(
                    request, checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None,
                    advisory_execution=self.admission(profile), expected_execution=object(),  # type: ignore[call-arg]
                )
            self.assertEqual(backend.sessions, [])

    def test_service_rejects_the_removed_expected_execution_argument(self) -> None:
        """A caller cannot substitute an effect binding at the service seam."""

        with tempfile.TemporaryDirectory() as temporary:
            repository, subset, binding, profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(
                DependencyReviewResultKind.ACCEPTED, self.proposal("attempt-116"),
            ))
            with self.assertRaises(TypeError):
                DependencyReviewService().run(
                    repository, subset, attempt_id="attempt-116", binding=binding,
                    adapter=CodexDependencyReviewAdapter(backend, profile, audit),
                    checkpoint_session=lambda _session: None,
                    checkpoint_turn=lambda _session, _turn: None,
                    advisory_execution=self.admission(profile), expected_execution=object(),  # type: ignore[call-arg]
                )
            self.assertEqual(backend.sessions, [])

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
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "V2 execution context is unavailable"):
            adapter.validate(binding)
        self.assertIsInstance(
            external_validation.roundwright_profile_adapter_factory(DEPENDENCY_REVIEW_ATTEMPT_PROFILE),
            external_validation.DependencyReviewAttemptAdapter,
        )
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "V2 execution context is unavailable"):
            adapter.execute(binding)

    def test_sealed_lane_preflight_is_provider_free_and_executes_once(self) -> None:
        """The public product boundary owns request, host, and replay state."""

        class Receipt:
            def __init__(self, value): self.value = value
            def as_dict(self): return self.value

        class Execution:
            def __init__(self, value, mutation_count=0): self.value, self.mutation_count = value, mutation_count

        class ContextValue:
            def __init__(self, identity, value): self.identity, self.value = identity, value

        class Harness:
            ExecutorReadinessReceipt = Receipt
            ProfileExecution = Execution
            ProfileExecutionContext = ContextValue

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
                components = SimpleNamespace(
                    producer_identity=capture["producer_identity"], exporter_identity=capture["exporter_identity"],
                    comparator_identity=capture["comparator_identity"],
                )
                prepared_context = adapter.prepare_execution_context(SimpleNamespace(
                    descriptor=request["execution_context"], plan=plan,
                    input_digest=external_validation._digest(request["execution_context"]), components=components,
                ))
                bound = SimpleNamespace(
                    plan=plan, profile=plan.profile, case_id=plan.case_id,
                    candidate_sha=plan.candidate_sha, ready_at=plan.ready_at, components=components,
                    execution_context=prepared_context,
                    execution_context_input_digest=external_validation._digest(request["execution_context"]),
                )
                if mode == "execute":
                    return adapter.execute(bound)
                adapter.validate(bound)
                core = {
                    "schema": "roundwright-harness-profile-executor-readiness/v2", "status": "ready", "state": "PREFLIGHT_READY",
                    "plan_digest": plan.plan_digest, "profile": plan.profile, "case_id": plan.case_id,
                    "candidate_sha": plan.candidate_sha, "ready_at": plan.ready_at,
                    "producer_identity": capture["producer_identity"], "exporter_identity": capture["exporter_identity"],
                    "comparator_identity": capture["comparator_identity"], "dispatch_count": 0, "record_count": 0,
                    "verify_count": 0, "mutation_count": 0,
                    "execution_context_input_digest": external_validation._digest(request["execution_context"]),
                    "execution_context_identity": prepared_context.identity,
                }
                return Receipt({**core, "receipt_digest": external_validation._digest(core)})

        with tempfile.TemporaryDirectory() as temporary, patch.object(external_validation, "_harness_executor", return_value=Harness):
            repository, subset, binding, _profile, audit = self.setup(Path(temporary))
            backend = Backend(NativeDependencyReviewResponse(DependencyReviewResultKind.ACCEPTED, self.proposal(subset.snapshot_id)))
            base_sha = "a" * 40
            effect = self.effect_kwargs(
                repository, subset, binding,
                CodexDependencyReviewAdapter(backend, audit.profile, audit),
                attempt_id=subset.snapshot_id,
            )
            inputs = external_validation.DependencyReviewRequestInputs(
                repository, base_sha, subset, binding, audit, subset.snapshot_id, 17,
                effect["advisory_execution"], backend,
                execution_host=effect["execution_host"],
            )
            prepared, readiness, capsule = external_validation.prepare_dependency_review_attempt_profile(inputs, Path(temporary).resolve())
            self.assertEqual(prepared.native_control_digest, dependency_review_native_control_digest())
            self.assertEqual(prepared.public_receipt()["native_control"], dependency_review_native_control_contract())
            self.assertEqual(
                prepared._request_value["execution_context"]["native_control_digest"],
                dependency_review_native_control_digest(),
            )
            self.assertEqual(len(backend.sessions), 0)
            self.assertEqual(prepared.capture_plan_digest, readiness.capture_plan_digest)
            self.assertEqual(prepared.public_receipt()["base_sha"], base_sha)
            self.assertEqual(prepared._request_value["execution_context"]["base_sha"], base_sha)
            plan = Harness.prepare_capture(dict(prepared._request_value["capture_plan"]))
            components = SimpleNamespace(
                producer_identity=prepared._request_value["capture_plan"]["producer_identity"],
                exporter_identity=prepared._request_value["capture_plan"]["exporter_identity"],
                comparator_identity=prepared._request_value["capture_plan"]["comparator_identity"],
            )
            adapter = external_validation.DependencyReviewAttemptAdapter(prepared._host_inputs)
            materialized_context = adapter.prepare_execution_context(SimpleNamespace(
                descriptor=prepared._request_value["execution_context"], plan=plan,
            ))
            contextual_binding = SimpleNamespace(
                plan=plan, profile=plan.profile, case_id=plan.case_id, candidate_sha=plan.candidate_sha,
                ready_at=plan.ready_at, components=components, execution_context=materialized_context,
                execution_context_input_digest=external_validation._digest(prepared._request_value["execution_context"]),
            )
            adapter.validate(contextual_binding)
            object.__setattr__(materialized_context.value, "identity", digest("f"))
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "execution context has drifted"):
                adapter.validate(contextual_binding)
            object.__setattr__(inputs, "base_sha", "b" * 40)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "prepared request has drifted"):
                external_validation.materialize_dependency_review_attempt_profile(capsule, Path(temporary).resolve())
            self.assertEqual(len(backend.sessions), 0)
            fresh_inputs = external_validation.DependencyReviewRequestInputs(
                repository, base_sha, subset, binding, audit, subset.snapshot_id, 17,
                effect["advisory_execution"], backend,
                execution_host=effect["execution_host"],
            )
            _prepared, _readiness, fresh_capsule = external_validation.prepare_dependency_review_attempt_profile(fresh_inputs, Path(temporary).resolve())
            external_validation.materialize_dependency_review_attempt_profile(fresh_capsule, Path(temporary).resolve())
            self.assertEqual(len(backend.sessions), 1)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "unavailable"):
                external_validation.materialize_dependency_review_attempt_profile(fresh_capsule, Path(temporary).resolve())

class ProductionActivationTests(unittest.TestCase):
    def test_missing_external_root_denies_before_input_construction(self) -> None:
        with self.assertRaisesRegex(DependencyReviewDispatchError, "activation is unavailable"):
            prepare_dependency_review_host(
                None, None, None, None, advisory_execution=None,
                execution_host=None, budget_ledger_path=None,
            )  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
