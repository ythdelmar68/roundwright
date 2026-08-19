from __future__ import annotations

import json
import inspect
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType, ModuleType, SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright import external_validation
from roundwright.hosted_evidence import (
    HostedCheck,
    HostedCheckEvidence,
    HostedCheckPolicy,
    HostedCheckState,
    HostedWorkflowJob,
    HostedWorkflowRun,
)
from roundwright.shadow import (
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    HOSTED_CHECK_PROFILE,
    LIVE_LIFECYCLE_SHADOW_PROFILE,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    EvidenceRole,
    LifecycleAttempt,
    LifecycleAttemptKind,
    ShadowV2Event,
    ShadowV2EventGraph,
)


@dataclass(frozen=True)
class ProfileComponentIdentities:
    producer_identity: str
    exporter_identity: str
    comparator_identity: str


@dataclass(frozen=True)
class ProfileExecution:
    value: object
    mutation_count: int = 0


@dataclass(frozen=True)
class ProfileExecutionContext:
    identity: str
    value: object


@dataclass(frozen=True)
class ProfileComparison:
    status: str
    result_identity: str


@dataclass(frozen=True)
class CapturePlanReceipt:
    plan_digest: str
    profile: str
    case_id: str
    candidate_sha: str
    ready_at: int


@dataclass(frozen=True)
class ExecutorBinding:
    """The public reviewed Harness binding shape, without candidate extensions."""

    plan: CapturePlanReceipt
    components: ProfileComponentIdentities

    @property
    def profile(self) -> str:
        return self.plan.profile

    @property
    def case_id(self) -> str:
        return self.plan.case_id

    @property
    def candidate_sha(self) -> str:
        return self.plan.candidate_sha

    @property
    def ready_at(self) -> int:
        return self.plan.ready_at


@dataclass(frozen=True)
class ExecutorRequest:
    schema: str
    capture_plan: dict[str, object]
    execution_context: dict[str, object] | None

    @classmethod
    def parse(cls, value: object) -> "ExecutorRequest":
        if type(value) not in (dict, MappingProxyType):
            raise ValueError("request is invalid")
        raw = dict(value)
        if set(raw) != {"schema", "capture_plan", "execution_context"}:
            raise ValueError("request is invalid")
        return cls(raw["schema"], raw["capture_plan"], raw["execution_context"])


@dataclass(frozen=True)
class ExecutorReadinessReceipt:
    plan: CapturePlanReceipt
    components: ProfileComponentIdentities
    request_schema: str
    execution_context_input_digest: str
    execution_context_identity: str

    def as_dict(self) -> dict[str, object]:
        core = {
            "schema": "roundwright-harness-profile-executor-readiness/v2",
            "status": "ready",
            "state": "PREFLIGHT_READY",
            "plan_digest": self.plan.plan_digest,
            "profile": self.plan.profile,
            "case_id": self.plan.case_id,
            "candidate_sha": self.plan.candidate_sha,
            "ready_at": self.plan.ready_at,
            "producer_identity": self.components.producer_identity,
            "exporter_identity": self.components.exporter_identity,
            "comparator_identity": self.components.comparator_identity,
            "dispatch_count": 0,
            "record_count": 0,
            "verify_count": 0,
            "mutation_count": 0,
            "execution_context_input_digest": self.execution_context_input_digest,
            "execution_context_identity": self.execution_context_identity,
        }
        return {**core, "receipt_digest": external_validation._digest(core)}


def fake_harness() -> tuple[object | None, object | None]:
    prior_package = sys.modules.get("roundwright_harness")
    prior_module = sys.modules.get("roundwright_harness.executor")
    package = ModuleType("roundwright_harness")
    package.__path__ = []  # type: ignore[attr-defined]
    module = ModuleType("roundwright_harness.executor")
    module.ProfileComponentIdentities = ProfileComponentIdentities  # type: ignore[attr-defined]
    module.ProfileExecution = ProfileExecution  # type: ignore[attr-defined]
    module.ProfileExecutionContext = ProfileExecutionContext  # type: ignore[attr-defined]
    module.ProfileComparison = ProfileComparison  # type: ignore[attr-defined]
    module.ExecutorRequest = ExecutorRequest  # type: ignore[attr-defined]
    module.ExecutorReadinessReceipt = ExecutorReadinessReceipt  # type: ignore[attr-defined]
    module.prepare_calls = []  # type: ignore[attr-defined]
    module.run_calls = []  # type: ignore[attr-defined]
    def prepare_capture(plan: dict[str, object]) -> CapturePlanReceipt:
        module.prepare_calls.append(plan)  # type: ignore[attr-defined]
        return CapturePlanReceipt(
            external_validation._digest(plan), plan["profile"], plan["case_id"],
            plan["candidate_sha"], plan["ready_at"],
        )
    def run_profile_executor(*arguments: object, **keywords: object) -> object:
        module.run_calls.append((arguments, keywords))  # type: ignore[attr-defined]
        if arguments[0] == "validate":
            request = ExecutorRequest.parse(arguments[1])
            plan = CapturePlanReceipt(
                external_validation._digest(request.capture_plan),
                request.capture_plan["profile"], request.capture_plan["case_id"],
                request.capture_plan["candidate_sha"], request.capture_plan["ready_at"],
            )
            components = ProfileComponentIdentities(
                request.capture_plan["producer_identity"], request.capture_plan["exporter_identity"],
                request.capture_plan["comparator_identity"],
            )
            context = request.execution_context
            assert context is not None
            return ExecutorReadinessReceipt(
                plan, components, request.schema, external_validation._digest(context),
                external_validation._digest({
                    "schema": "roundwright-live-lifecycle-context/v1", "descriptor": context,
                }),
            )
        return {"status": "fake"}
    module.prepare_capture = prepare_capture  # type: ignore[attr-defined]
    module.run_profile_executor = run_profile_executor  # type: ignore[attr-defined]
    sys.modules["roundwright_harness"] = package
    sys.modules["roundwright_harness.executor"] = module
    return prior_package, prior_module


def binding(**updates: object) -> SimpleNamespace:
    producer, exporter, comparator = external_validation.synthetic_component_identities()
    values: dict[str, object] = {
        "profile": EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
        "case_id": "contract-synthetic",
        "candidate_sha": "a" * 40,
        "ready_at": 17,
        "plan": SimpleNamespace(plan_digest="sha256:" + "1" * 64),
        "components": SimpleNamespace(
            producer_identity=producer,
            exporter_identity=exporter,
            comparator_identity=comparator,
        ),
    }
    values.update(updates)
    return SimpleNamespace(**values)


def provider_binding(**updates: object) -> ExecutorBinding:
    producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
    values: dict[str, object] = {
        "profile": PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
        "case_id": "provider-attempt-case",
        "candidate_sha": "a" * 40,
        "ready_at": 17,
        "plan_digest": "sha256:" + "3" * 64,
        "components": ProfileComponentIdentities(
            producer_identity=producer,
            exporter_identity=exporter,
            comparator_identity=comparator,
        ),
    }
    values.update(updates)
    return ExecutorBinding(
        CapturePlanReceipt(
            values["plan_digest"], values["profile"], values["case_id"],
            values["candidate_sha"], values["ready_at"],
        ),
        values["components"],
    )


class ExternalValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prior_package, self._prior_module = fake_harness()

    def tearDown(self) -> None:
        for name, value in (
            ("roundwright_harness", self._prior_package),
            ("roundwright_harness.executor", self._prior_module),
        ):
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_public_factory_exposes_stable_typed_components(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            EXECUTOR_CONTRACT_SYNTHETIC_PROFILE
        )

        self.assertEqual(
            adapter.component_identities,
            ProfileComponentIdentities(*external_validation.synthetic_component_identities()),
        )
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            external_validation.roundwright_profile_adapter_factory(
                "roundwright-shadow-profile/unknown/v1"
            )

    def test_hosted_check_profile_is_context_free_and_disabled_without_a_typed_snapshot(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(HOSTED_CHECK_PROFILE)
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        self.assertEqual(adapter.component_identities, ProfileComponentIdentities(producer, exporter, comparator))
        adapter.validate(exact)
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "observation-unavailable"):
            adapter.execute(exact)

    def test_live_lifecycle_profile_requires_an_armed_typed_snapshot(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(LIVE_LIFECYCLE_SHADOW_PROFILE)
        producer, exporter, comparator = external_validation.live_lifecycle_shadow_component_identities()
        exact = self.live_lifecycle_binding(adapter, producer, exporter, comparator)
        self.assertEqual(adapter.component_identities, ProfileComponentIdentities(producer, exporter, comparator))
        adapter.validate(exact)
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "observation-unavailable"):
            adapter.execute(exact)

    def test_live_lifecycle_profile_projects_only_public_safe_zero_mutation_evidence(self) -> None:
        snapshot = self.live_lifecycle_snapshot()
        adapter = external_validation.LiveLifecycleShadowProfileAdapter(snapshot)
        producer, exporter, comparator = external_validation.live_lifecycle_shadow_component_identities()
        exact = self.live_lifecycle_binding(adapter, producer, exporter, comparator)
        adapter.validate(exact)
        execution = adapter.execute(exact)
        evidence = adapter.project(exact, execution)
        comparison = adapter.compare(exact, evidence)
        projection = evidence["live_lifecycle_shadow"]
        self.assertEqual(execution.mutation_count, 0)
        self.assertEqual(projection["snapshot"]["target_observed_sha"], "b" * 40)
        self.assertEqual(projection["snapshot"]["fixture_classes"], list(external_validation._LIVE_LIFECYCLE_FIXTURES))
        self.assertTrue(projection["snapshot"]["zero_mutation_readback_digest"].startswith("sha256:"))
        self.assertNotIn("raw", json.dumps(evidence).lower())
        self.assertEqual(comparison.status, "pass")

    def test_public_live_lifecycle_preflight_persists_a_path_free_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(
                self.live_lifecycle_request_inputs(), root,
            )
        harness = sys.modules["roundwright_harness.executor"]
        self.assertEqual(len(harness.prepare_calls), 1)
        self.assertEqual([arguments[0] for arguments, _ in harness.run_calls], ["validate"])
        plan = harness.prepare_calls[0]
        self.assertEqual(plan["schema"], "roundwright-harness-capture-plan/v1")
        self.assertEqual(plan["profile"], LIVE_LIFECYCLE_SHADOW_PROFILE)
        self.assertEqual(session.readiness.capture_plan_digest, external_validation._digest(plan))
        self.assertNotIn(str(root), json.dumps(session.public_receipt()))
        self.assertEqual(session.readiness.receipt_digest, session.public_receipt()["readiness"]["receipt_digest"])
        self.assertFalse(hasattr(external_validation, "prepare_live_lifecycle_shadow_request"))
        self.assertFalse(hasattr(external_validation, "preflight_live_lifecycle_shadow_profile"))
        self.assertFalse(hasattr(external_validation, "materialize_live_lifecycle_shadow_profile"))
        self.assertFalse(hasattr(external_validation, "LiveLifecycleReadOnlyProvider"))

    def test_live_lifecycle_request_factory_rejects_moved_inputs_and_changes_every_binding(self) -> None:
        inputs = self.live_lifecycle_request_inputs()
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            prepared = external_validation.preflight_live_lifecycle_shadow_session(
                inputs, Path(first).resolve(),
            )
            moved = external_validation.preflight_live_lifecycle_shadow_session(
                replace(inputs, candidate_sha="c" * 40, observation_window="window-49-fresh"),
                Path(second).resolve(),
            )
        self.assertNotEqual(prepared.session_id, moved.session_id)
        self.assertNotEqual(prepared.readiness.capture_plan_digest, moved.readiness.capture_plan_digest)
        self.assertNotEqual(prepared.readiness.receipt_digest, moved.readiness.receipt_digest)
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            external_validation.LiveLifecycleRequestInputs(
                inputs.base_sha, "not-a-sha", inputs.target_repository, inputs.target_baseline_sha,
                inputs.case_id, inputs.observation_window, inputs.ready_at, inputs.recorder_commit,
                inputs.recorder_content, inputs.recorder_tree, inputs.retention_namespace,
            )

    def test_live_lifecycle_durable_session_owns_transport_projection_and_one_shot_execute(self) -> None:
        class ReadTransport:
            def __init__(self) -> None:
                self.calls: list[external_validation.LiveLifecycleTransportRequest] = []

            def read(self, request: external_validation.LiveLifecycleTransportRequest) -> dict[str, object]:
                self.calls.append(request)
                if request.operation in ("before", "after"):
                    return {"target_sha": request.target_baseline_sha, "target_state": {"state": "unchanged"}}
                return {
                    "snapshots": {name: {"snapshot": name} for name in external_validation._LIVE_LIFECYCLE_SNAPSHOTS},
                    "classified_differences": ["fixture-coverage"],
                }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            transport = ReadTransport()
            serialized = json.loads(json.dumps(session.public_receipt()))
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(serialized, root, transport)
            self.assertEqual(transport.calls, [])
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(
                serialized, root, "sha256:" + "f" * 64,
            )
            result = external_validation.execute_live_lifecycle_shadow_session(
                json.loads(json.dumps(confirmed.public_receipt())), root, transport,
            )
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, transport)
        harness = sys.modules["roundwright_harness.executor"]
        self.assertEqual(result, {"status": "fake"})
        self.assertEqual([item.operation for item in transport.calls], ["before", "lifecycle", "after"])
        self.assertTrue(transport.calls[1].arm_before_first_live_event)
        self.assertFalse(hasattr(transport, "read_before"))
        self.assertEqual([arguments[0] for arguments, _ in harness.run_calls], ["validate", "execute"])
        self.assertEqual(harness.run_calls[1][1]["expected_readiness_digest"], session.readiness.receipt_digest)
        snapshot = harness.run_calls[1][0][2].snapshot
        self.assertEqual(snapshot.fixture_classes, external_validation._LIVE_LIFECYCLE_FIXTURES)
        self.assertEqual(tuple(event.event_kind for event in snapshot.event_graph.events), tuple(external_validation.shadow_evidence_profile(LIVE_LIFECYCLE_SHADOW_PROFILE).event_kinds))

    def test_live_lifecycle_session_rejects_drift_before_transport_dispatch(self) -> None:
        class NeverCalledTransport:
            def __init__(self) -> None: self.calls = 0
            def read(self, request: object) -> dict[str, object]:
                self.calls += 1
                raise AssertionError("transport must not be called")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            transport = NeverCalledTransport()
            malformed = session.public_receipt(); malformed["readiness"]["candidate_sha"] = "c" * 40
            with self.assertRaises(external_validation.ExternalValidationAdapterError):
                external_validation.confirm_live_lifecycle_shadow_trace(malformed, root, "sha256:" + "f" * 64)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(session.public_receipt(), root, transport)
            self.assertEqual(transport.calls, 0)

    def test_hosted_check_profile_projects_and_compares_a_deterministic_typed_fake(self) -> None:
        snapshot = self.hosted_snapshot()
        adapter = external_validation.HostedCheckProfileAdapter(snapshot)
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        adapter.validate(exact)
        execution = adapter.execute(exact)
        evidence = adapter.project(exact, execution)
        comparison = adapter.compare(exact, evidence)
        self.assertEqual(execution.mutation_count, 0)
        self.assertEqual(evidence["hosted_check"]["snapshot"]["workflow"], "CI")
        self.assertEqual(evidence["hosted_check"]["snapshot"]["checks"][0]["checked_out_sha"], "a" * 40)
        self.assertEqual(evidence["hosted_check"]["snapshot"]["workflow_runs"][0]["jobs"][0]["state"], "success")
        self.assertEqual(evidence["hosted_check"]["snapshot"]["artifacts"][0]["digest"], "b" * 64)
        self.assertEqual(evidence["hosted_check"]["snapshot"]["evaluation"]["outcome"], "pass")
        self.assertIsInstance(json.loads(json.dumps(evidence)), dict)
        self.assertEqual(comparison.status, "pass")

    def test_hosted_snapshot_rejects_a_non_passing_typed_evaluation(self) -> None:
        evidence = self.hosted_snapshot().evidence
        failed = HostedCheckEvidence(
            evidence.repository, evidence.workflow, evidence.candidate_sha, evidence.branch,
            evidence.observed_at,
            (HostedCheck("check-48", "suite-48", "unit", HostedCheckState.FAILURE, "a" * 40, "a" * 40),),
            evidence.workflow_runs, evidence.artifacts,
        )
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "not a passing"):
            external_validation.HostedCheckSnapshot(
                failed, self.hosted_snapshot().policy, "refs/heads/codex/issue-48", 17,
                "run-48", "suite-48",
            )

    def test_hosted_check_execution_rejects_a_substituted_or_omitted_policy(self) -> None:
        snapshot = self.hosted_snapshot()
        substituted = external_validation.HostedCheckSnapshot(
            snapshot.evidence, HostedCheckPolicy(("unit",), (), 60), snapshot.ref, snapshot.evaluated_at,
            snapshot.workflow_run_id, snapshot.check_suite_id,
        )
        adapter = external_validation.HostedCheckProfileAdapter(substituted)
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "policy has drifted"):
            adapter.execute(exact)

        descriptor = exact.execution_context.value.descriptor.payload()
        descriptor.pop("required_artifacts")
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "execution context is invalid"):
            adapter.prepare_execution_context(SimpleNamespace(descriptor=descriptor, plan=exact.plan))

    def test_hosted_check_execution_rejects_a_mismatched_evaluation_time(self) -> None:
        snapshot = self.hosted_snapshot()
        historical = external_validation.HostedCheckSnapshot(
            snapshot.evidence, snapshot.policy, snapshot.ref, 16,
            snapshot.workflow_run_id, snapshot.check_suite_id,
        )
        adapter = external_validation.HostedCheckProfileAdapter(historical)
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "evaluation time has drifted"):
            adapter.execute(exact)

    def test_hosted_runtime_descriptor_accepts_public_matrix_check_names(self) -> None:
        adapter = external_validation.HostedCheckProfileAdapter()
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        descriptor = exact.execution_context.value.descriptor.payload()
        names = (
            "build-package (windows-latest, 3.12)",
            "verify-package (windows-latest, 3.12)",
        )
        descriptor["required_checks"] = list(names)
        context = adapter.prepare_execution_context(SimpleNamespace(descriptor=descriptor, plan=exact.plan))
        self.assertEqual(context.value.descriptor.required_checks, names)

    def test_hosted_runtime_descriptor_rejects_non_array_policy_collections(self) -> None:
        adapter = external_validation.HostedCheckProfileAdapter()
        producer, exporter, comparator = external_validation.hosted_check_component_identities()
        exact = self.hosted_binding(adapter, producer, exporter, comparator)
        for field in ("required_checks", "required_artifacts"):
            with self.subTest(field=field):
                descriptor = exact.execution_context.value.descriptor.payload()
                descriptor[field] = "unit"
                with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "execution context is invalid"):
                    adapter.prepare_execution_context(SimpleNamespace(descriptor=descriptor, plan=exact.plan))

    def hosted_snapshot(self) -> external_validation.HostedCheckSnapshot:
        evidence = HostedCheckEvidence(
            "ythdelmar68/roundwright", "CI", "a" * 40, "codex/issue-48", 12,
            (HostedCheck("check-48", "suite-48", "unit", HostedCheckState.SUCCESS, "a" * 40, "a" * 40),),
            (HostedWorkflowRun("run-48", "CI", HostedCheckState.SUCCESS, "a" * 40, "refs/heads/codex/issue-48", (HostedWorkflowJob("job-48", "unit", HostedCheckState.SUCCESS, "a" * 40),), "suite-48"),),
            (("build-manifest", "b" * 64),),
        )
        return external_validation.HostedCheckSnapshot(
            evidence, HostedCheckPolicy(("unit",), ("build-manifest",), 60),
            "refs/heads/codex/issue-48", 17, "run-48", "suite-48",
        )

    def live_lifecycle_snapshot(self) -> external_validation.LiveLifecycleShadowSnapshot:
        candidate = "a" * 40
        graph = ShadowV2EventGraph(
            (LifecycleAttempt("worker-49", 1, LifecycleAttemptKind.WORKER, EvidenceRole.WORKER),),
            (), (), (), (),
            (ShadowV2Event("event-49", 1, "worker-49", "repository-snapshot", None, False),),
        )
        return external_validation.LiveLifecycleShadowSnapshot(
            "ythdelmar68/roundlet-forward-test", "b" * 40, "b" * 40, candidate,
            "sha256:" + "1" * 64, "live-lifecycle-case", "window-49", 17, "event-49", graph,
            {name: "sha256:" + (f"{index:x}" * 64) for index, name in enumerate(external_validation._LIVE_LIFECYCLE_SNAPSHOTS, start=1)},
            external_validation._LIVE_LIFECYCLE_FIXTURES, (), "sha256:" + "e" * 64, "sha256:" + "e" * 64,
        )

    def live_lifecycle_request_inputs(self) -> external_validation.LiveLifecycleRequestInputs:
        return external_validation.LiveLifecycleRequestInputs(
            "b" * 40, "a" * 40, "ythdelmar68/roundlet-forward-test", "d" * 40,
            "live-lifecycle-case", "window-49", 17, "1" * 40, "2" * 40,
            "3" * 40, "retention-49",
        )

    def live_lifecycle_binding(self, adapter: object, producer: str, exporter: str, comparator: str) -> SimpleNamespace:
        plan = SimpleNamespace(
            plan_digest="sha256:" + "1" * 64, profile=LIVE_LIFECYCLE_SHADOW_PROFILE,
            case_id="live-lifecycle-case", candidate_sha="a" * 40, ready_at=17,
        )
        descriptor = {
            "schema": "roundwright-live-lifecycle-runtime/v1",
            "target_repository": "ythdelmar68/roundlet-forward-test", "target_baseline_sha": "b" * 40,
            "candidate_sha": plan.candidate_sha, "capture_plan_digest": plan.plan_digest,
            "case_id": plan.case_id, "observation_window": "window-49", "ready_at": plan.ready_at,
        }
        context = adapter.prepare_execution_context(SimpleNamespace(descriptor=descriptor, plan=plan))  # type: ignore[attr-defined]
        return SimpleNamespace(
            profile=LIVE_LIFECYCLE_SHADOW_PROFILE, case_id=plan.case_id,
            candidate_sha=plan.candidate_sha, ready_at=plan.ready_at, plan=plan,
            components=SimpleNamespace(
                producer_identity=producer, exporter_identity=exporter, comparator_identity=comparator,
            ),
            execution_context=context, execution_context_input_digest="sha256:" + "2" * 64,
        )

    def hosted_binding(self, adapter: object, producer: str, exporter: str, comparator: str) -> SimpleNamespace:
        plan = SimpleNamespace(
            plan_digest="sha256:" + "1" * 64, profile=HOSTED_CHECK_PROFILE,
            case_id="hosted-check-case", candidate_sha="a" * 40, ready_at=17,
        )
        descriptor = {
            "schema": "roundwright-hosted-check-runtime/v1",
            "repository": "ythdelmar68/roundwright", "workflow": "CI",
            "ref": "refs/heads/codex/issue-48", "branch": "codex/issue-48",
            "base_sha": "b" * 40, "candidate_sha": "a" * 40,
            "capture_plan_digest": plan.plan_digest, "case_id": plan.case_id,
            "ready_at": plan.ready_at, "pull_request": 80,
            "workflow_run_id": "run-48", "check_suite_id": "suite-48",
            "required_checks": ["unit"], "required_artifacts": ["build-manifest"],
            "max_age_seconds": 60, "evaluated_at": plan.ready_at,
        }
        context = adapter.prepare_execution_context(SimpleNamespace(descriptor=descriptor, plan=plan))  # type: ignore[attr-defined]
        return SimpleNamespace(
            profile=HOSTED_CHECK_PROFILE, case_id=plan.case_id,
            candidate_sha=plan.candidate_sha, ready_at=plan.ready_at, plan=plan,
            components=SimpleNamespace(
                producer_identity=producer, exporter_identity=exporter, comparator_identity=comparator,
            ),
            execution_context=context, execution_context_input_digest="sha256:" + "2" * 64,
        )

    def test_synthetic_adapter_executes_projects_and_compares_at_capture_time(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        exact = binding(ready_at=7)
        adapter.validate(exact)

        execution = adapter.execute(exact)
        evidence = adapter.project(exact, execution)
        comparison = adapter.compare(exact, evidence)

        self.assertEqual(execution.mutation_count, 0)
        self.assertEqual(evidence["ready_at"], 7)
        self.assertEqual(evidence["executor_contract"]["mutation_count"], 0)
        self.assertEqual(comparison.status, "pass")
        self.assertTrue(comparison.result_identity.startswith("sha256:"))

    def test_adapter_rejects_binding_or_component_drift_before_execution(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        wrong_components = SimpleNamespace(
            producer_identity="sha256:" + "2" * 64,
            exporter_identity=external_validation.SYNTHETIC_EXPORTER_IDENTITY,
            comparator_identity=external_validation.SYNTHETIC_COMPARATOR_IDENTITY,
        )

        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(binding(components=wrong_components))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(binding(candidate_sha="main"))

    def test_comparator_returns_typed_failure_without_exposing_payload(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        exact = binding()
        evidence = dict(adapter.project(exact, adapter.execute(exact)))
        evidence["ready_at"] = 18

        comparison = adapter.compare(exact, evidence)

        self.assertEqual(comparison.status, "fail")
        self.assertTrue(comparison.result_identity.startswith("sha256:"))

    def test_provider_attempt_profile_bare_public_binding_blocks_before_dispatch(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        self.assertEqual(
            adapter.component_identities,
            ProfileComponentIdentities(*external_validation.provider_attempt_accounting_component_identities()),
        )
        with self.assertRaisesRegex(
            external_validation.ExternalValidationAdapterError,
            external_validation.PROVIDER_ATTEMPT_HISTORY_BLOCKER,
        ):
            adapter.validate(exact)

        # V2 never lets a caller bypass provider-free readiness.  A bare V1
        # binding cannot fabricate an execution envelope or history.
        with self.assertRaisesRegex(
            external_validation.ExternalValidationAdapterError,
            "V2 execution context",
        ):
            adapter.execute(exact)

    def test_provider_attempt_profile_rejects_fabricated_history_and_context_drift(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        fabricated = {
            "provider_attempt_accounting": {
                "history": "complete",
                "snapshot": {"event_graph": {"provider_attempts": ["invented"]}},
            }
        }
        # No JSON payload can supply a qualifying result without the opaque
        # V2 context and a fresh durable read-back.
        self.assertEqual(adapter.compare(exact, fabricated).status, "fail")
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(ready_at=True))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(components=ProfileComponentIdentities(
                "sha256:" + "f" * 64,
                external_validation.PROVIDER_ATTEMPT_EXPORTER_IDENTITY,
                external_validation.PROVIDER_ATTEMPT_COMPARATOR_IDENTITY,
            )))

    def test_durable_snapshot_requires_base_and_context_bindings(self) -> None:
        candidate = "a" * 40
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            external_validation.ProviderAttemptAccountingSnapshot(
                "task-45", "sha256:" + "2" * 64, "not-a-sha", candidate, "sha256:" + "3" * 64, 17,
                1, 1, "COMPLETE", 1, 10, 1, "sha256:" + "4" * 64,
                "sha256:" + "5" * 64, "selected-provider", "sha256:" + "6" * 64,
                "accepted-review", None, "candidate-gates", False,
            )
