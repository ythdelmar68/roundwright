from __future__ import annotations

import json
import inspect
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from types import MappingProxyType, ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright import external_validation
import roundwright.github_runtime as github_runtime
from roundwright.hosted_evidence import (
    HostedCheck,
    HostedCheckEvidence,
    HostedCheckPolicy,
    HostedCheckState,
    HostedWorkflowJob,
    HostedWorkflowRun,
)
from roundwright.github import (
    GitHubContractError,
    GitHubReadOperation,
    GitHubMutationOperation,
    GitHubReadRequest,
    GitHubReadResult,
    RepositoryRef,
    RepositoryInventoryEvidence,
    RepositoryInventoryFact,
    RepositoryInventorySection,
    RepositoryInventorySnapshot,
)
from roundwright.dependency_policy import (
    BootstrapPolicyReceipt,
    CandidateBinding,
    ComponentPolicy,
    DependencyComponent,
    DependencyExecutionControl,
    DependencyPolicy,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    TrustedDependencyAdmission,
    VersionRange,
)
from roundwright.github_runtime import (
    CapabilityState,
    GitHubCapabilityHealth,
    OperationHealth,
    ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED,
    RepositoryInventoryFailureStage,
    RepositoryInventoryTransportSubcategory,
    credentialed_repository_inventory_failure_code,
    create_credentialed_github_read_capability,
    repository_inventory_failure_code,
    repository_inventory_failure_stage,
    repository_inventory_transport_subcategory,
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
        class GenericReadCapability:
            def __init__(self) -> None:
                self.calls: list[GitHubReadRequest] = []

            def read(self, request: GitHubReadRequest) -> GitHubReadResult:
                self.calls.append(request)
                collections = tuple(sorted((
                    RepositoryInventoryEvidence(section, "sha256:" + format(index, "064x"), (f"{section.value}-1",), 1, True)
                    for index, section in enumerate(RepositoryInventorySection, 1)
                ), key=lambda item: item.section.value))
                facts = tuple(sorted((
                    RepositoryInventoryFact("issue-4", "child", "issue-49"),
                    RepositoryInventoryFact("issue-49", "standalone", "true"),
                    RepositoryInventoryFact("issue-50", "label", "roundlet:ignore"),
                    RepositoryInventoryFact("issue-51", "malformed-parent", "owner-input"),
                    RepositoryInventoryFact("issue-49", "depends-on", "issue-4"),
                    RepositoryInventoryFact("pull-request-81", "state", "merged"),
                    RepositoryInventoryFact("lifecycle-supervisor-1", "profile", "sol"),
                    RepositoryInventoryFact("lifecycle-supervisor-1", "disposition", "cancelled"),
                    RepositoryInventoryFact("lifecycle-supervisor-2", "profile", "terra"),
                    RepositoryInventoryFact("lifecycle-supervisor-2", "disposition", "invalid-context"),
                    RepositoryInventoryFact("lifecycle-supervisor-3", "profile", "terra"),
                    RepositoryInventoryFact("lifecycle-supervisor-3", "disposition", "pass"),
                    RepositoryInventoryFact("lifecycle-formal-round-1", "candidate", "a" * 40),
                    RepositoryInventoryFact("lifecycle-formal-round-1", "ready-at", "17"),
                ), key=lambda item: (item.subject, item.predicate, item.object)))
                return GitHubReadResult(request, RepositoryInventorySnapshot(
                    request.repository, "forward-target", "main", "d" * 40,
                    "sha256:" + "a" * 64, "sha256:" + "b" * 64, collections, facts,
                ))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            capability = GenericReadCapability()
            serialized = json.loads(json.dumps(session.public_receipt()))
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(serialized, root, capability)
            self.assertEqual(capability.calls, [])
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(
                serialized, root, "sha256:" + "f" * 64,
            )
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "capability"):
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, object())
            self.assertEqual(capability.calls, [])
            result = external_validation.execute_live_lifecycle_shadow_session(
                json.loads(json.dumps(confirmed.public_receipt())), root, capability,
            )
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, capability)
        harness = sys.modules["roundwright_harness.executor"]
        self.assertEqual(result, {"status": "fake"})
        self.assertEqual([item.operation for item in capability.calls], [
            GitHubReadOperation.REPOSITORY_INVENTORY,
            GitHubReadOperation.REPOSITORY_INVENTORY,
            GitHubReadOperation.REPOSITORY_INVENTORY,
        ])
        self.assertFalse(hasattr(capability, "read_before"))
        self.assertFalse(hasattr(external_validation, "LiveLifecycleTransportRequest"))
        self.assertEqual([arguments[0] for arguments, _ in harness.run_calls], ["validate", "execute"])
        self.assertEqual(harness.run_calls[1][1]["expected_readiness_digest"], session.readiness.receipt_digest)
        snapshot = harness.run_calls[1][0][2].snapshot
        self.assertEqual(snapshot.fixture_classes, external_validation._LIVE_LIFECYCLE_FIXTURES)
        self.assertEqual(tuple(event.event_kind for event in snapshot.event_graph.events), tuple(external_validation.shadow_evidence_profile(LIVE_LIFECYCLE_SHADOW_PROFILE).event_kinds))

    def test_live_lifecycle_session_rejects_drift_before_transport_dispatch(self) -> None:
        class NeverCalledCapability:
            def __init__(self) -> None: self.calls = 0
            def read(self, request: object) -> object:
                self.calls += 1
                raise AssertionError("transport must not be called")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            capability = NeverCalledCapability()
            malformed = session.public_receipt(); malformed["readiness"]["candidate_sha"] = "c" * 40
            with self.assertRaises(external_validation.ExternalValidationAdapterError):
                external_validation.confirm_live_lifecycle_shadow_trace(malformed, root, "sha256:" + "f" * 64)
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "trace-confirmed"):
                external_validation.execute_live_lifecycle_shadow_session(session.public_receipt(), root, capability)
            self.assertEqual(capability.calls, 0)

    def test_live_lifecycle_concurrent_execute_claims_one_winner_before_provider_access(self) -> None:
        """An overlap barrier proves a loser cannot reach the provider seam."""
        class Capability:
            def read(self, request: object) -> object:
                raise AssertionError("the patched provider seam is the only permitted access")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, "sha256:" + "f" * 64)
            entered, release, calls, outcomes = Event(), Event(), [], []
            def materialize(*_arguments: object) -> object:
                calls.append("provider")
                entered.set()
                release.wait(2)
                return {"status": "fake"}
            def execute() -> None:
                try:
                    outcomes.append(external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, Capability()))
                except external_validation.ExternalValidationAdapterError as error:
                    outcomes.append(str(error))
            with patch.object(external_validation, "_materialize_live_lifecycle_shadow_profile", materialize):
                first, second = Thread(target=execute), Thread(target=execute)
                first.start(); self.assertTrue(entered.wait(2)); second.start(); second.join(2); release.set(); first.join(2)
            self.assertEqual(calls, ["provider"])
            self.assertEqual(outcomes.count({"status": "fake"}), 1)
            self.assertTrue(any(type(value) is str and ("already consumed" in value or "not trace-confirmed" in value) for value in outcomes))

    def test_live_lifecycle_inventory_category_drift_blocks_before_harness_execute(self) -> None:
        def inventory(repository: RepositoryRef, comment_evidence: str) -> RepositoryInventorySnapshot:
            collections = []
            for index, section in enumerate(RepositoryInventorySection, 1):
                evidence = comment_evidence if section is RepositoryInventorySection.COMMENTS else "sha256:" + format(index, "064x")
                collections.append(RepositoryInventoryEvidence(section, evidence, (f"{section.value}-1",), 1, True))
            facts = (
                RepositoryInventoryFact("issue-4", "child", "issue-49"),
                RepositoryInventoryFact("issue-49", "depends-on", "issue-4"),
                RepositoryInventoryFact("issue-49", "standalone", "true"),
                RepositoryInventoryFact("lifecycle-supervisor-1", "profile", "sol"),
                RepositoryInventoryFact("lifecycle-supervisor-1", "disposition", "cancelled"),
                RepositoryInventoryFact("lifecycle-supervisor-2", "profile", "terra"),
                RepositoryInventoryFact("lifecycle-supervisor-2", "disposition", "invalid-context"),
                RepositoryInventoryFact("lifecycle-supervisor-3", "profile", "terra"),
                RepositoryInventoryFact("lifecycle-supervisor-3", "disposition", "pass"),
                RepositoryInventoryFact("lifecycle-formal-round-1", "candidate", "a" * 40),
                RepositoryInventoryFact("lifecycle-formal-round-1", "ready-at", "17"),
                RepositoryInventoryFact("issue-50", "label", "roundlet:ignore"),
                RepositoryInventoryFact("issue-51", "malformed-parent", "owner-input"),
                RepositoryInventoryFact("pull-request-81", "state", "merged"),
            )
            return RepositoryInventorySnapshot(
                repository, "forward-target", "main", "d" * 40, "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                tuple(sorted(collections, key=lambda item: item.section.value)),
                tuple(sorted(facts, key=lambda item: (item.subject, item.predicate, item.object))),
            )

        class DriftingReadCapability:
            def __init__(self) -> None: self.calls = 0
            def read(self, request: GitHubReadRequest) -> GitHubReadResult:
                self.calls += 1
                evidence = "sha256:" + ("c" if self.calls < 3 else "d") * 64
                return GitHubReadResult(request, inventory(request.repository, evidence))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(self.live_lifecycle_request_inputs(), root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, "sha256:" + "f" * 64)
            capability = DriftingReadCapability()
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "zero-mutation"):
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, capability)
        harness = sys.modules["roundwright_harness.executor"]
        self.assertEqual(capability.calls, 3)
        self.assertEqual([arguments[0] for arguments, _ in harness.run_calls], ["validate"])

    def test_public_credentialed_factory_drives_three_product_owned_inventory_reads(self) -> None:
        """The caller gives the factory only opaque host/evidence, never product data."""

        now = datetime(2026, 8, 19, tzinfo=timezone.utc)
        inputs = self.live_lifecycle_request_inputs()
        owner, name = inputs.target_repository.split("/", 1)
        binding = CandidateBinding(inputs.target_repository, "live-lifecycle-factory", inputs.candidate_sha)
        digest = lambda character: "sha256:" + character * 64
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi-roundwright", digest("1"), digest("2")),
            ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github-gh", digest("3"), digest("4")),
        )
        policy = DependencyPolicy(binding, digest("5"), int(now.timestamp()), 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("6"), authority_digest=digest("7"))
        policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        dependency_control = DependencyExecutionControl(
            policy,
            tuple(ObservedDependency(binding, component.component, component.identifier, component.versions.minimum, component.source_identity, component.artifact_digest, component.executable_digest, int(now.timestamp()), policy.policy_digest) for component in components),
            TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, digest("6"), digest("7")),
        )
        health = GitHubCapabilityHealth(tuple(
            OperationHealth(
                operation,
                CapabilityState.AVAILABLE if operation is GitHubReadOperation.REPOSITORY_INVENTORY else CapabilityState.UNAVAILABLE,
                now, digest(format(index % 10, "x")), now + timedelta(minutes=1),
            )
            for index, operation in enumerate((*GitHubReadOperation, *GitHubMutationOperation))
        ))
        raw_inventory = {
            "data": {"repository": {
                "id": "forward-target", "name": name, "owner": {"login": owner},
                "defaultBranchRef": {"name": "main", "target": {"oid": inputs.target_baseline_sha}},
                "issues": {"totalCount": 3, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                    {"id": "issue-1", "number": 1, "state": "OPEN", "title": "Umbrella owner-input fixture", "body": "2. #3 — Dependent proof leaf (P0; blocked by #2).", "comments": {"totalCount": 3, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"id": "trace-1", "body": f"ROUNDLET_LIFECYCLE supervisor=sol disposition=cancelled round=formal-round-1 ready_at=17 candidate={inputs.candidate_sha}"}, {"id": "trace-2", "body": f"ROUNDLET_LIFECYCLE supervisor=terra disposition=invalid-context round=formal-round-1 ready_at=17 candidate={inputs.candidate_sha}"}, {"id": "trace-3", "body": f"ROUNDLET_LIFECYCLE supervisor=terra disposition=pass round=formal-round-1 ready_at=17 candidate={inputs.candidate_sha}"}]}, "labels": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"name": "needs triage"}]}, "subIssues": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"number": 3}]}},
                    {"id": "issue-3", "number": 3, "state": "OPEN", "title": "Malformed-parent child fixture", "body": "- Blocked by #2.", "comments": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "labels": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": None}, "subIssues": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}},
                    {"id": "issue-2", "number": 2, "state": "OPEN", "title": "Standalone fixture", "body": None, "comments": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "labels": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"name": "roundlet:ignore"}]}, "subIssues": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}},
                ]},
                "pullRequests": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{
                    "id": "pull-request-81", "number": 81, "state": "MERGED", "headRefOid": None, "headRefName": "codex-issue-49", "mergeStateStatus": "CLEAN", "mergeCommit": {"oid": inputs.candidate_sha},
                    "comments": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "reviews": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "reviewRequests": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "closingIssuesReferences": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
                    "commits": {"totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                        {"commit": {"oid": "1" * 40, "checkSuites": {"totalCount": 12, "pageInfo": {"hasNextPage": True, "endCursor": "suite-cursor-1"}, "nodes": [
                            {"id": f"check-suite-1-{number}", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": f"workflow-run-1-{number}"}}
                            for number in range(1, 11)
                        ]}}},
                        {"commit": {"oid": "2" * 40, "checkSuites": {"totalCount": 12, "pageInfo": {"hasNextPage": True, "endCursor": "suite-cursor-2"}, "nodes": [
                            {"id": f"check-suite-2-{number}", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": f"workflow-run-2-{number}"}}
                            for number in range(1, 11)
                        ]}}},
                    ]},
                }]},
                "refs": {"totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                    {"name": "main", "target": {"oid": inputs.target_baseline_sha}},
                    {"name": "codex/docs/26-public-target-contract", "target": {"oid": inputs.target_baseline_sha}},
                ]},
            }},
        }

        @dataclass(frozen=True)
        class OpaqueResult:
            returncode: int
            stdout: str

        class OpaqueCredentialHost:
            def __init__(self, payload: object, *, issue_page: object | None = None, pull_request_page: object | None = None, comment_page: object | None = None, exit_code: int = 0) -> None:
                self.commands: list[tuple[str, ...]] = []
                self.payload = payload
                self.issue_page = issue_page
                self.pull_request_page = pull_request_page
                self.comment_page = comment_page
                self.exit_code = exit_code
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.commands.append(arguments)
                if self.exit_code:
                    return OpaqueResult(self.exit_code, "")
                if "object(expression:$oid)" in arguments[4]:
                    oid = next(value.removeprefix("oid=") for value in arguments if value.startswith("oid="))
                    suffix = "1" if oid == "1" * 40 else "2" if oid == "2" * 40 else "unknown"
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "object": {"oid": oid, "checkSuites": {
                            "totalCount": 12, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                                {"id": f"check-suite-{suffix}-continued-1", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": f"workflow-run-{suffix}-continued-1"}},
                                {"id": f"check-suite-{suffix}-continued-2", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": f"workflow-run-{suffix}-continued-2"}},
                            ],
                        }},
                    }}}))
                if "issues(first:100,after:$cursor" in arguments[4] and self.issue_page is not None:
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "issues": self.issue_page,
                    }}}))
                if "pullRequests(first:100,after:$cursor" in arguments[4] and self.pull_request_page is not None:
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "pullRequests": self.pull_request_page,
                    }}}))
                if "comments(first:100,after:$cursor" in arguments[4] and self.comment_page is not None:
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "pullRequest": {"number": 81, "comments": self.comment_page},
                    }}}))
                return OpaqueResult(0, json.dumps(self.payload))

        scheduling_host = OpaqueCredentialHost(raw_inventory)
        scheduling_result = create_credentialed_github_read_capability(
            scheduling_host, binding, dependency_control, health, clock=lambda: now,
        ).read(GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        ))
        self.assertTrue(scheduling_result.ok)
        assert scheduling_result.snapshot is not None
        inventory_evidence = scheduling_result.snapshot
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.COMMENTS).page_count, 4)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.ISSUE_LABELS).page_count, 3)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.ISSUE_RELATIONSHIPS).page_count, 3)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.REVIEWS).page_count, 1)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.REQUESTED_REVIEWERS).page_count, 1)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.CLOSING_REFERENCES).page_count, 1)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.CHECKS).page_count, 4)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.WORKFLOW_RUNS).page_count, 4)
        self.assertEqual(inventory_evidence.collection(RepositoryInventorySection.MERGEABILITY).page_count, 1)
        self.assertTrue(all(item.item_identities == tuple(sorted(set(item.item_identities))) for item in inventory_evidence.collections))
        self.assertNotIn(RepositoryInventoryFact("pull-request-81", "head-sha", inputs.candidate_sha), scheduling_result.snapshot.facts)
        self.assertIn(RepositoryInventoryFact("issue-3", "depends-on", "issue-2"), scheduling_result.snapshot.facts)
        self.assertNotIn(RepositoryInventoryFact("issue-1", "depends-on", "issue-2"), scheduling_result.snapshot.facts)
        projected_labels = [
            fact.object for fact in scheduling_result.snapshot.facts
            if fact.subject == "issue-1" and fact.predicate == "label"
        ]
        self.assertEqual(len(projected_labels), 1)
        self.assertTrue(projected_labels[0].startswith("label-"))
        self.assertNotIn("needs triage", projected_labels)
        host = OpaqueCredentialHost(raw_inventory)
        advancing_times = iter((
            now,
            now + timedelta(seconds=1),
            now + timedelta(seconds=2),
            now + timedelta(seconds=3),
        ))
        capability = create_credentialed_github_read_capability(
            host, binding, dependency_control, health, clock=lambda: next(advancing_times),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("f"))
            result = external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, capability)
        harness = sys.modules["roundwright_harness.executor"]
        self.assertEqual(result, {"status": "fake"})
        inventory_commands = [command for command in host.commands if "object(expression:$oid)" not in command[4]]
        continuation_commands = [command for command in host.commands if "object(expression:$oid)" in command[4]]
        self.assertEqual(len(inventory_commands), 3)
        self.assertEqual(inventory_commands, [inventory_commands[0]] * 3)
        self.assertEqual(len(continuation_commands), 6)
        self.assertEqual(inventory_commands[0][0:4], ("gh", "api", "graphql", "-f"))
        self.assertIn("repository(owner:$owner,name:$name)", inventory_commands[0][4])
        self.assertIn("nodes{id number state title body", inventory_commands[0][4])
        self.assertIn("commits(first:100)", inventory_commands[0][4])
        self.assertIn("checkSuites(first:10)", inventory_commands[0][4])
        self.assertEqual(inventory_commands[0][-4:], ("-F", f"owner={owner}", "-F", f"name={name}"))
        self.assertTrue(all("checkSuites(first:100,after:$cursor)" in command[4] for command in continuation_commands))

        class ReturnCodeResultWithGuardedLegacyAlias:
            def __init__(self, result: OpaqueResult) -> None:
                self.returncode = result.returncode
                self.stdout = result.stdout

            @property
            def exit_code(self) -> int:
                raise RuntimeError("private legacy return-code marker")

        class ReturnCodeHost(OpaqueCredentialHost):
            def run(self, arguments: tuple[str, ...]) -> ReturnCodeResultWithGuardedLegacyAlias:
                return ReturnCodeResultWithGuardedLegacyAlias(super().run(arguments))

        guarded_alias_host = ReturnCodeHost(raw_inventory)
        guarded_alias_request = GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name),
            expected_sha=inputs.target_baseline_sha,
        )
        guarded_alias_result = create_credentialed_github_read_capability(
            guarded_alias_host, binding, dependency_control, health, clock=lambda: now,
        ).read(guarded_alias_request)
        self.assertTrue(guarded_alias_result.ok)
        self.assertEqual(
            guarded_alias_host.commands[0][-4:],
            ("-F", f"owner={owner}", "-F", f"name={name}"),
        )

        class SubprocessLaunchHost(OpaqueCredentialHost):
            """Hermetic process launcher: its argv must include the executable."""

            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                if arguments[0:4] != ("gh", "api", "graphql", "-f"):
                    raise FileNotFoundError("private executable launch marker")
                return super().run(arguments)

        process_host = SubprocessLaunchHost(raw_inventory)
        process_capability = create_credentialed_github_read_capability(
            process_host, binding, dependency_control, health, clock=lambda: now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("8"))
            process_result = external_validation.execute_live_lifecycle_shadow_session(
                confirmed.public_receipt(), root, process_capability,
            )
        self.assertEqual(process_result, {"status": "fake"})
        self.assertTrue(process_host.commands)
        self.assertTrue(all(command[0:4] == ("gh", "api", "graphql", "-f") for command in process_host.commands))
        self.assertEqual(
            [arguments[0] for arguments, _ in harness.run_calls],
            ["validate", "execute", "validate", "execute"],
        )
        self.assertTrue(harness.run_calls[1][0][2].snapshot.zero_mutation_readback_digest.startswith("sha256:"))
        self.assertFalse(hasattr(capability, "query"))
        self.assertFalse(hasattr(capability, "snapshot"))
        def fixture_blocks_before_harness(inventory: object, expected_reads: int) -> None:
            fixture_host = OpaqueCredentialHost(inventory)
            fixture_capability = create_credentialed_github_read_capability(
                fixture_host, binding, dependency_control, health, clock=lambda: now,
            )
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("e"))
                with self.assertRaises(external_validation.ExternalValidationAdapterError):
                    external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, fixture_capability)
            inventory_commands = [command for command in fixture_host.commands if "object(expression:$oid)" not in command[4]]
            self.assertEqual(len(inventory_commands), expected_reads)

        missing_membership = json.loads(json.dumps(raw_inventory))
        missing_membership["data"]["repository"]["issues"]["nodes"][0]["subIssues"] = {
            "totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [],
        }
        missing_standalone = json.loads(json.dumps(raw_inventory))
        missing_standalone["data"]["repository"]["issues"]["nodes"][2]["title"] = "Ignored fixture"
        missing_ignore = json.loads(json.dumps(raw_inventory))
        missing_ignore["data"]["repository"]["issues"]["nodes"][2]["labels"] = {
            "totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [],
        }
        missing_malformed = json.loads(json.dumps(raw_inventory))
        missing_malformed["data"]["repository"]["issues"]["nodes"][1]["title"] = "Dependency fixture"
        missing_owner_input = json.loads(json.dumps(raw_inventory))
        missing_owner_input["data"]["repository"]["issues"]["nodes"][0]["title"] = "Umbrella fixture"
        missing_dependency = json.loads(json.dumps(raw_inventory))
        missing_dependency["data"]["repository"]["issues"]["nodes"][1]["body"] = ""
        missing_merged_pr = json.loads(json.dumps(raw_inventory))
        missing_merged_pr["data"]["repository"]["pullRequests"]["nodes"][0]["state"] = "OPEN"
        for fixture_name, inventory, expected_reads in (
            ("membership", missing_membership, 1), ("standalone", missing_standalone, 2),
            ("ignore", missing_ignore, 2), ("malformed-parent", missing_malformed, 1),
            ("owner-input", missing_owner_input, 1), ("dependency", missing_dependency, 2),
            ("merged-pr", missing_merged_pr, 2),
        ):
            with self.subTest(missing_fixture=fixture_name):
                fixture_blocks_before_harness(inventory, expected_reads)
        self.assertEqual(
            [arguments[0] for arguments, _ in harness.run_calls],
            ["validate", "execute", "validate", "execute"] + ["validate"] * 7,
        )
        def issue(number: int) -> dict[str, object]:
            return {
                "id": f"issue-{number}", "number": number, "state": "OPEN",
                "title": "ordinary issue", "body": "",
                "comments": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
                "labels": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
                "subIssues": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
            }
        top_level_inventory = json.loads(json.dumps(raw_inventory))
        top_level_inventory["data"]["repository"]["issues"] = {
            "totalCount": 101, "pageInfo": {"hasNextPage": True, "endCursor": "issues-page-1"},
            "nodes": [issue(number) for number in range(1, 101)],
        }
        top_level_host = OpaqueCredentialHost(
            top_level_inventory,
            issue_page={"totalCount": 101, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [issue(101)]},
        )
        top_level_capability = create_credentialed_github_read_capability(
            top_level_host, binding, dependency_control, health, clock=lambda: now,
        )
        top_level_result = top_level_capability.read(GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        ))
        self.assertTrue(top_level_result.ok, top_level_result.failure)
        self.assertEqual(len(top_level_result.snapshot.collection(RepositoryInventorySection.ISSUES).item_identities), 101)  # type: ignore[union-attr]
        self.assertEqual(
            top_level_result.snapshot.collection(RepositoryInventorySection.REMOTE_HEADS).item_identities,  # type: ignore[union-attr]
            ("codex/docs/26-public-target-contract", "main"),
        )
        self.assertEqual(sum("issues(first:100,after:$cursor" in command[4] for command in top_level_host.commands), 1)
        def pull_request(number: int) -> dict[str, object]:
            empty = {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}
            return {
                "id": f"pull-request-{number}", "number": number, "state": "MERGED",
                "headRefOid": inputs.candidate_sha, "headRefName": "codex-issue-49",
                "mergeStateStatus": "CLEAN", "mergeCommit": {"oid": inputs.candidate_sha},
                "comments": dict(empty), "reviews": dict(empty), "reviewRequests": dict(empty),
                "closingIssuesReferences": dict(empty), "commits": dict(empty),
            }
        pull_request_inventory = json.loads(json.dumps(raw_inventory))
        pull_request_inventory["data"]["repository"]["pullRequests"] = {
            "totalCount": 101, "pageInfo": {"hasNextPage": True, "endCursor": "pull-request-page-1"},
            "nodes": [pull_request(number) for number in range(1, 101)],
        }
        pull_request_host = OpaqueCredentialHost(
            pull_request_inventory,
            pull_request_page={"totalCount": 101, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [pull_request(101)]},
        )
        pull_request_capability = create_credentialed_github_read_capability(
            pull_request_host, binding, dependency_control, health, clock=lambda: now,
        )
        self.assertTrue(pull_request_capability.read(GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        )).ok)
        initial_query = next(command[4] for command in pull_request_host.commands if "pullRequests(first:100,states" in command[4])
        pull_request_query = next(command[4] for command in pull_request_host.commands if "pullRequests(first:100,after:$cursor" in command[4])
        def page_size(query: str, connection: str) -> int:
            value = query.split(f"{connection}(first:", 1)[1]
            return int(value.split(",", 1)[0].split(")", 1)[0])
        def pull_request_node_budget(query: str, *, includes_initial_roots: bool) -> int:
            pulls = page_size(query, "pullRequests")
            commits = page_size(query, "commits")
            suites = page_size(query, "checkSuites")
            nested = sum(page_size(query, connection) for connection in (
                "comments", "reviews", "reviewRequests", "closingIssuesReferences",
            ))
            budget = 1 + pulls * (1 + nested + commits * (1 + suites))
            if includes_initial_roots:
                issues = page_size(query, "issues")
                budget += issues * (1 + page_size(query, "labels") + page_size(query, "subIssues"))
                budget += page_size(query, "refs")
            return budget
        self.assertEqual(page_size(initial_query, "checkSuites"), 10)
        self.assertEqual(page_size(pull_request_query, "checkSuites"), 10)
        self.assertLessEqual(pull_request_node_budget(initial_query, includes_initial_roots=True), 500_000)
        self.assertLessEqual(pull_request_node_budget(pull_request_query, includes_initial_roots=False), 500_000)
        nested_inventory = json.loads(json.dumps(raw_inventory))
        nested_inventory["data"]["repository"]["pullRequests"]["nodes"][0]["comments"] = {
            "totalCount": 101, "pageInfo": {"hasNextPage": True, "endCursor": "comments-page-1"},
            "nodes": [{"id": f"comment-{number}"} for number in range(1, 101)],
        }
        nested_host = OpaqueCredentialHost(
            nested_inventory,
            comment_page={"totalCount": 101, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"id": "comment-101"}]},
        )
        nested_capability = create_credentialed_github_read_capability(
            nested_host, binding, dependency_control, health, clock=lambda: now,
        )
        self.assertTrue(nested_capability.read(GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        )).ok)
        self.assertEqual(sum("comments(first:100,after:$cursor" in command[4] for command in nested_host.commands), 1)
        request = GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        )
        def failure_code(host: OpaqueCredentialHost) -> external_validation.RepositoryInventoryReadFailureCode:
            failed = create_credentialed_github_read_capability(
                host, binding, dependency_control, health, clock=lambda: now,
            ).read(request)
            self.assertFalse(failed.ok)
            assert failed.failure is not None
            code = repository_inventory_failure_code(failed.failure.public_reason)
            self.assertIsNotNone(code)
            assert code is not None
            return code
        diagnostic_inventory = json.loads(json.dumps(raw_inventory))
        diagnostic_connection = diagnostic_inventory["data"]["repository"]["issues"]["nodes"][1]["labels"]
        diagnostic_connection["totalCount"] = 1
        diagnostic_connection["nodes"] = None
        diagnostic_connection["private-response-marker"] = "provider-secret-must-not-escape"
        diagnostic_result = create_credentialed_github_read_capability(
            OpaqueCredentialHost(diagnostic_inventory), binding, dependency_control, health, clock=lambda: now,
        ).read(request)
        self.assertFalse(diagnostic_result.ok)
        assert diagnostic_result.failure is not None
        self.assertEqual(
            repository_inventory_failure_code(diagnostic_result.failure.public_reason),
            external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
        )
        self.assertEqual(
            repository_inventory_failure_stage(diagnostic_result.failure.public_reason),
            RepositoryInventoryFailureStage.CONNECTION_NODES,
        )
        self.assertNotIn("provider-secret-must-not-escape", diagnostic_result.failure.public_reason)
        for label, total_count, has_next, remove_nodes in (
            ("missing-terminal-empty", 0, False, True),
            ("nonempty-null", 1, False, False),
            ("paginated-null", 0, True, False),
        ):
            with self.subTest(null_nodes_boundary=label):
                malformed_inventory = json.loads(json.dumps(raw_inventory))
                connection = malformed_inventory["data"]["repository"]["issues"]["nodes"][1]["labels"]
                connection["totalCount"] = total_count
                connection["pageInfo"]["hasNextPage"] = has_next
                if remove_nodes:
                    connection.pop("nodes")
                failed = create_credentialed_github_read_capability(
                    OpaqueCredentialHost(malformed_inventory), binding, dependency_control, health, clock=lambda: now,
                ).read(request)
                self.assertFalse(failed.ok)
                assert failed.failure is not None
                self.assertEqual(
                    repository_inventory_failure_code(failed.failure.public_reason),
                    external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                )
                self.assertEqual(
                    repository_inventory_failure_stage(failed.failure.public_reason),
                    RepositoryInventoryFailureStage.CONNECTION_NODES,
                )
        for label, connection_path in (
            ("root-refs", ("data", "repository", "refs")),
            ("issue-sub-issues", ("data", "repository", "issues", "nodes", 1, "subIssues")),
            ("pull-request-comments", ("data", "repository", "pullRequests", "nodes", 0, "comments")),
            ("pull-request-reviews", ("data", "repository", "pullRequests", "nodes", 0, "reviews")),
            ("pull-request-review-requests", ("data", "repository", "pullRequests", "nodes", 0, "reviewRequests")),
            ("pull-request-closing-references", ("data", "repository", "pullRequests", "nodes", 0, "closingIssuesReferences")),
        ):
            with self.subTest(terminal_empty_nullability=label):
                nullable_inventory = json.loads(json.dumps(raw_inventory))
                connection: object = nullable_inventory
                for component in connection_path:
                    connection = connection[component]  # type: ignore[index]
                assert type(connection) is dict
                connection["totalCount"] = 0
                connection["pageInfo"] = {"hasNextPage": False, "endCursor": None}
                connection["nodes"] = None
                self.assertTrue(create_credentialed_github_read_capability(
                    OpaqueCredentialHost(nullable_inventory), binding, dependency_control, health, clock=lambda: now,
                ).read(request).ok)
        def failure_stage(host: OpaqueCredentialHost) -> RepositoryInventoryFailureStage:
            failed = create_credentialed_github_read_capability(
                host, binding, dependency_control, health, clock=lambda: now,
            ).read(request)
            self.assertFalse(failed.ok)
            assert failed.failure is not None
            stage = repository_inventory_failure_stage(failed.failure.public_reason)
            self.assertIsNotNone(stage)
            assert stage is not None
            return stage
        root_inventory: object = []
        repository_inventory = json.loads(json.dumps(raw_inventory))
        repository_inventory["data"]["repository"]["owner"]["login"] = "unexpected-owner"
        connection_inventory = json.loads(json.dumps(raw_inventory))
        connection_inventory["data"]["repository"]["issues"]["nodes"][1]["labels"] = {}
        node_inventory = json.loads(json.dumps(raw_inventory))
        node_inventory["data"]["repository"]["issues"]["nodes"][0]["labels"]["nodes"] = [None]
        field_inventory = json.loads(json.dumps(raw_inventory))
        field_inventory["data"]["repository"]["issues"]["nodes"][0]["labels"]["nodes"] = [{"name": 1}]
        pagination_inventory = json.loads(json.dumps(raw_inventory))
        pagination_connection = pagination_inventory["data"]["repository"]["issues"]["nodes"][1]["subIssues"]
        pagination_connection["pageInfo"] = {"hasNextPage": True, "endCursor": None}
        for label, inventory, expected_stage in (
            ("root", root_inventory, RepositoryInventoryFailureStage.ROOT),
            ("repository", repository_inventory, RepositoryInventoryFailureStage.REPOSITORY),
            ("connection", connection_inventory, RepositoryInventoryFailureStage.CONNECTION),
            ("node", node_inventory, RepositoryInventoryFailureStage.NODE),
            ("field", field_inventory, RepositoryInventoryFailureStage.FIELD),
            ("pagination", pagination_inventory, RepositoryInventoryFailureStage.PAGINATION),
        ):
            with self.subTest(structural_stage=label):
                self.assertEqual(failure_stage(OpaqueCredentialHost(inventory)), expected_stage)
        self.assertEqual(
            repository_inventory_failure_stage(
                f"{ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED}:malformed-response",
            ),
            RepositoryInventoryFailureStage.UNKNOWN,
        )
        self.assertEqual(
            repository_inventory_transport_subcategory(
                f"{ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED}:malformed-response:transport",
            ),
            RepositoryInventoryTransportSubcategory.UNKNOWN,
        )
        self.assertEqual(
            repository_inventory_transport_subcategory(
                f"{ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED}:malformed-response:transport:unrecognized",
            ),
            RepositoryInventoryTransportSubcategory.UNKNOWN,
        )
        def outer_failure_stage(host: object) -> tuple[
            external_validation.RepositoryInventoryReadFailureCode,
            RepositoryInventoryFailureStage,
            RepositoryInventoryTransportSubcategory | None,
            str,
        ]:
            failed = create_credentialed_github_read_capability(
                host, binding, dependency_control, health, clock=lambda: now,
            ).read(request)
            self.assertFalse(failed.ok)
            assert failed.failure is not None
            code = repository_inventory_failure_code(failed.failure.public_reason)
            stage = repository_inventory_failure_stage(failed.failure.public_reason)
            transport_subcategory = repository_inventory_transport_subcategory(failed.failure.public_reason)
            self.assertIsNotNone(code)
            self.assertIsNotNone(stage)
            assert code is not None and stage is not None
            return code, stage, transport_subcategory, failed.failure.public_reason
        class TransportFailureHost:
            def __init__(self) -> None:
                self.commands: list[tuple[str, ...]] = []
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.commands.append(arguments)
                raise FileNotFoundError("private transport marker")
        class NonzeroReturnHost:
            def __init__(self) -> None:
                self.commands: list[tuple[str, ...]] = []
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.commands.append(arguments)
                return OpaqueResult(9, "private nonzero return marker")
        class InvalidResultHost:
            def run(self, arguments: tuple[str, ...]) -> object:
                return object()
        class InvalidJsonHost:
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                return OpaqueResult(0, "{private-json-marker")
        normalizer_inventory = json.loads(json.dumps(raw_inventory))
        normalizer_inventory["data"]["repository"]["id"] = "invalid repository identity"
        for label, host, expected_stage, expected_subcategory in (
            ("launch", TransportFailureHost(), RepositoryInventoryFailureStage.TRANSPORT, RepositoryInventoryTransportSubcategory.LAUNCH_EXCEPTION),
            ("invalid-result", InvalidResultHost(), RepositoryInventoryFailureStage.TRANSPORT, RepositoryInventoryTransportSubcategory.INVALID_RESULT_SHAPE),
            ("json", InvalidJsonHost(), RepositoryInventoryFailureStage.JSON_DECODING, None),
            ("graphql-envelope", OpaqueCredentialHost({"errors": [{"message": "private-graphql-marker"}]}), RepositoryInventoryFailureStage.GRAPHQL_ENVELOPE, None),
            ("normalizer", OpaqueCredentialHost(normalizer_inventory), RepositoryInventoryFailureStage.NORMALIZER, None),
        ):
            with self.subTest(outer_inventory_stage=label):
                code, stage, transport_subcategory, public_reason = outer_failure_stage(host)
                self.assertEqual(
                    code,
                    external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION
                    if label == "normalizer" else external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
                )
                self.assertEqual(stage, expected_stage)
                self.assertEqual(transport_subcategory, expected_subcategory)
                self.assertNotIn("private", public_reason)
        transport_host = TransportFailureHost()
        code, stage, transport_subcategory, public_reason = outer_failure_stage(transport_host)
        self.assertEqual(code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
        self.assertEqual(stage, RepositoryInventoryFailureStage.TRANSPORT)
        self.assertEqual(transport_subcategory, RepositoryInventoryTransportSubcategory.LAUNCH_EXCEPTION)
        self.assertNotIn("private", public_reason)
        self.assertEqual(transport_host.commands[0][0:4], ("gh", "api", "graphql", "-f"))
        nonzero_host = NonzeroReturnHost()
        code, stage, transport_subcategory, public_reason = outer_failure_stage(nonzero_host)
        self.assertEqual(code, external_validation.RepositoryInventoryReadFailureCode.HOST_FAILURE)
        self.assertEqual(stage, RepositoryInventoryFailureStage.TRANSPORT)
        self.assertEqual(transport_subcategory, RepositoryInventoryTransportSubcategory.NONZERO_RETURN)
        self.assertNotIn("private", public_reason)
        self.assertEqual(nonzero_host.commands[0][-4:], ("-F", f"owner={owner}", "-F", f"name={name}"))
        with patch.object(
            github_runtime, "_repository_inventory_command",
            side_effect=github_runtime.GitHubRuntimeError("private request marker"),
        ):
            code, stage, transport_subcategory, public_reason = outer_failure_stage(OpaqueCredentialHost(raw_inventory))
        self.assertEqual(code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
        self.assertEqual(stage, RepositoryInventoryFailureStage.REQUEST)
        self.assertIsNone(transport_subcategory)
        self.assertNotIn("private", public_reason)
        sealing_result = github_runtime._seal_repository_inventory_snapshot(request, object())
        assert sealing_result.failure is not None
        self.assertEqual(
            repository_inventory_failure_code(sealing_result.failure.public_reason),
            external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
        )
        self.assertEqual(
            repository_inventory_failure_stage(sealing_result.failure.public_reason),
            RepositoryInventoryFailureStage.RESULT_SEALING,
        )
        for label, title, body, expected in (
            ("malformed-parent", "Malformed-parent fixture", "", external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("malformed-dependency-marker", "Dependency fixture", "- Blocked by #not-an-issue", external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE),
            ("ambiguous-dependency", "Dependency fixture", "Blocked by #4\nBlocked by #4", external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE),
        ):
            with self.subTest(scheduling_fixture=label):
                malformed_scheduling_inventory = json.loads(json.dumps(raw_inventory))
                malformed_scheduling_inventory["data"]["repository"]["issues"]["nodes"][1]["title"] = title
                malformed_scheduling_inventory["data"]["repository"]["issues"]["nodes"][1]["body"] = body
                self.assertEqual(
                    failure_code(OpaqueCredentialHost(malformed_scheduling_inventory)),
                    expected,
                )
        valid_remote_heads = ("codex/docs/26-public-target-contract", "main")
        self.assertIsInstance(
            RepositoryInventoryEvidence(
                RepositoryInventorySection.REMOTE_HEADS, digest("d"), valid_remote_heads, 1, True,
            ),
            RepositoryInventoryEvidence,
        )
        for label, identities in (
            ("control", ("bad\x01ref",)),
            ("malformed", ("codex//docs",)),
            ("overlong", ("a" * 257,)),
            ("double-dot", ("feature..name",)),
            ("trailing-dot", ("feature.",)),
            ("lock-component", ("feature.lock",)),
            ("nested-lock-component", ("feature/release.lock/fix",)),
            ("duplicate", ("main", "main")),
            ("unsorted", ("main", "codex/docs/26-public-target-contract")),
            ("over-bound", tuple(f"head-{number:04d}" for number in range(3201))),
        ):
            with self.subTest(remote_head_contract=label):
                with self.assertRaises(GitHubContractError):
                    RepositoryInventoryEvidence(
                        RepositoryInventorySection.REMOTE_HEADS, digest("d"), identities, 1, True,
                    )
        for label, names, expected in (
            ("control", ("bad\x01ref",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("malformed", ("codex//docs",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("double-dot", ("feature..name",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("trailing-dot", ("feature.",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("lock-component", ("feature.lock",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("nested-lock-component", ("feature/release.lock/fix",), external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION),
            ("duplicate", ("main", "main"), external_validation.RepositoryInventoryReadFailureCode.DUPLICATE_EVIDENCE),
        ):
            with self.subTest(remote_head_product=label):
                malformed_inventory = json.loads(json.dumps(raw_inventory))
                malformed_inventory["data"]["repository"]["refs"] = {
                    "totalCount": len(names), "pageInfo": {"hasNextPage": False, "endCursor": None},
                    "nodes": [{"name": item, "target": {"oid": inputs.target_baseline_sha}} for item in names],
                }
                self.assertEqual(failure_code(OpaqueCredentialHost(malformed_inventory)), expected)
        self.assertEqual(
            [arguments[0] for arguments, _ in harness.run_calls],
            ["validate", "execute", "validate", "execute"] + ["validate"] * 7,
        )
        self.assertEqual(
            failure_code(OpaqueCredentialHost(raw_inventory, exit_code=1)),
            external_validation.RepositoryInventoryReadFailureCode.HOST_FAILURE,
        )
        self.assertEqual(
            failure_code(OpaqueCredentialHost({"data": {"repository": {}}})),
            external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE,
        )
        looping_inventory = json.loads(json.dumps(raw_inventory))
        looping_inventory["data"]["repository"]["pullRequests"]["nodes"][0]["comments"] = {
            "totalCount": 2, "pageInfo": {"hasNextPage": True, "endCursor": "comments-page-1"}, "nodes": [{"id": "comment-1"}],
        }
        self.assertEqual(
            failure_code(OpaqueCredentialHost(
                looping_inventory,
                comment_page={"totalCount": 2, "pageInfo": {"hasNextPage": True, "endCursor": "comments-page-1"}, "nodes": [{"id": "comment-2"}]},
            )),
            external_validation.RepositoryInventoryReadFailureCode.CURSOR_FAILURE,
        )
        over_bound_inventory = json.loads(json.dumps(raw_inventory))
        over_bound_inventory["data"]["repository"]["pullRequests"]["nodes"][0]["comments"] = {
            "totalCount": 3201, "pageInfo": {"hasNextPage": True, "endCursor": "comments-page-1"}, "nodes": [{"id": "comment-1"}],
        }
        self.assertEqual(
            failure_code(OpaqueCredentialHost(over_bound_inventory)),
            external_validation.RepositoryInventoryReadFailureCode.CARDINALITY_FAILURE,
        )
        sealed_capability = create_credentialed_github_read_capability(
            OpaqueCredentialHost(raw_inventory, exit_code=1), binding, dependency_control, health, clock=lambda: now,
        )
        first_failure = sealed_capability.read(request)
        assert first_failure.failure is not None
        copied_failure = GitHubReadResult(request, failure=first_failure.failure)
        recreated_request = GitHubReadRequest(
            GitHubReadOperation.REPOSITORY_INVENTORY, RepositoryRef(owner, name), expected_sha=inputs.target_baseline_sha,
        )
        recreated_failure = GitHubReadResult(recreated_request, failure=first_failure.failure)
        self.assertIsNone(credentialed_repository_inventory_failure_code(sealed_capability, request, copied_failure))
        self.assertIsNone(credentialed_repository_inventory_failure_code(sealed_capability, recreated_request, recreated_failure))
        second_failure = sealed_capability.read(request)
        self.assertIsNone(credentialed_repository_inventory_failure_code(sealed_capability, request, first_failure))
        self.assertEqual(
            credentialed_repository_inventory_failure_code(sealed_capability, request, second_failure),
            external_validation.RepositoryInventoryReadFailureCode.HOST_FAILURE,
        )
        self.assertIsNone(credentialed_repository_inventory_failure_code(sealed_capability, request, second_failure))
        class InterleavingHost:
            def __init__(self) -> None:
                self.calls = 0
                self.lock = Lock()
                self.older_entered = Event()
                self.release_older = Event()
                self.newer_completed = Event()
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                with self.lock:
                    self.calls += 1
                    ordinal = self.calls
                if ordinal == 1:
                    self.older_entered.set()
                    if not self.release_older.wait(5):
                        raise RuntimeError("interleaving test timed out")
                else:
                    self.newer_completed.set()
                return OpaqueResult(1, "")
        interleaving_host = InterleavingHost()
        interleaving_capability = create_credentialed_github_read_capability(
            interleaving_host, binding, dependency_control, health, clock=lambda: now,
        )
        interleaved: dict[str, GitHubReadResult] = {}
        older_thread = Thread(target=lambda: interleaved.setdefault("older", interleaving_capability.read(request)))
        newer_thread = Thread(target=lambda: interleaved.setdefault("newer", interleaving_capability.read(request)))
        older_thread.start()
        self.assertTrue(interleaving_host.older_entered.wait(5))
        newer_thread.start()
        newer_thread.join(5)
        self.assertFalse(newer_thread.is_alive())
        self.assertTrue(interleaving_host.newer_completed.is_set())
        interleaving_host.release_older.set()
        older_thread.join(5)
        self.assertFalse(older_thread.is_alive())
        self.assertIsNone(credentialed_repository_inventory_failure_code(interleaving_capability, request, interleaved["older"]))
        self.assertEqual(
            credentialed_repository_inventory_failure_code(interleaving_capability, request, interleaved["newer"]),
            external_validation.RepositoryInventoryReadFailureCode.HOST_FAILURE,
        )
        self.assertIsNone(credentialed_repository_inventory_failure_code(interleaving_capability, request, interleaved["newer"]))
        class FirstFailureThenValidHost:
            def __init__(self) -> None:
                self.calls = 0
                self.valid = OpaqueCredentialHost(raw_inventory)
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.calls += 1
                return OpaqueResult(1, "") if self.calls == 1 else self.valid.run(arguments)
        success_capability = create_credentialed_github_read_capability(
            FirstFailureThenValidHost(), binding, dependency_control, health, clock=lambda: now,
        )
        success_stale = success_capability.read(request)
        self.assertTrue(success_capability.read(request).ok)
        self.assertIsNone(credentialed_repository_inventory_failure_code(success_capability, request, success_stale))
        class FirstFailureThenExceptionHost:
            def __init__(self) -> None: self.calls = 0
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.calls += 1
                if self.calls == 1:
                    return OpaqueResult(1, "")
                raise RuntimeError("host exception")
        exception_capability = create_credentialed_github_read_capability(
            FirstFailureThenExceptionHost(), binding, dependency_control, health, clock=lambda: now,
        )
        exception_stale = exception_capability.read(request)
        self.assertFalse(exception_capability.read(request).ok)
        self.assertIsNone(credentialed_repository_inventory_failure_code(exception_capability, request, exception_stale))
        uncoded_capability = create_credentialed_github_read_capability(
            OpaqueCredentialHost(raw_inventory, exit_code=1), binding, dependency_control, health, clock=lambda: now,
        )
        uncoded_stale = uncoded_capability.read(request)
        uncoded_capability.read(GitHubReadRequest(GitHubReadOperation.REPOSITORY, RepositoryRef(owner, name)))
        self.assertIsNone(credentialed_repository_inventory_failure_code(uncoded_capability, request, uncoded_stale))
        class ReplayCapability:
            def __init__(self, result: GitHubReadResult) -> None:
                self.calls = 0
                self.result = result
            def read(self, request: GitHubReadRequest) -> GitHubReadResult:
                self.calls += 1
                return self.result
        executes_before = len([item for item in harness.run_calls if item[0][0] == "execute"])
        for label, replayed_result in (
            ("copied", copied_failure), ("recreated", recreated_failure),
            ("stale", first_failure), ("consumed", second_failure),
            ("interleaved", interleaved["older"]),
        ):
            with self.subTest(replay=label):
                replay = ReplayCapability(replayed_result)
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                    confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("9"))
                    with self.assertRaises(external_validation.RepositoryInventoryFirstReadBoundaryError) as captured:
                        external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, replay)
                self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
                self.assertEqual(replay.calls, 1)
        self.assertEqual(len([item for item in harness.run_calls if item[0][0] == "execute"]), executes_before)
        drifted_inventory = json.loads(json.dumps(raw_inventory))
        drifted_inventory["data"]["repository"]["defaultBranchRef"]["target"]["oid"] = "e" * 40
        drifted_host = OpaqueCredentialHost(drifted_inventory)
        drifted_capability = create_credentialed_github_read_capability(
            drifted_host, binding, dependency_control, health, clock=lambda: now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("e"))
            with self.assertRaisesRegex(external_validation.RepositoryInventoryFirstReadBoundaryError, "safe-subcause-not-retained") as captured:
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, drifted_capability)
        self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.IDENTITY_DRIFT)
        self.assertEqual(len(drifted_host.commands), 1)
        executes_before_malformed_body = len([item for item in harness.run_calls if item[0][0] == "execute"])
        for label, body in (("missing-body", None), ("non-text-body", 1)):
            with self.subTest(label=label):
                malformed_inventory = json.loads(json.dumps(raw_inventory))
                issue = malformed_inventory["data"]["repository"]["issues"]["nodes"][0]
                if label == "missing-body":
                    issue.pop("body")
                else:
                    issue["body"] = body
                malformed_host = OpaqueCredentialHost(malformed_inventory)
                malformed_capability = create_credentialed_github_read_capability(
                    malformed_host, binding, dependency_control, health, clock=lambda: now,
                )
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                    confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("d"))
                    with self.assertRaisesRegex(external_validation.RepositoryInventoryFirstReadBoundaryError, "safe-subcause-not-retained") as captured:
                        external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, malformed_capability)
                self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
                self.assertEqual(
                    len([command for command in malformed_host.commands if "object(expression:$oid)" not in command[4]]), 1,
                )
        self.assertEqual(len([item for item in harness.run_calls if item[0][0] == "execute"]), executes_before_malformed_body)
        for label, total_count in (("incomplete", 3), ("over-bound", 101)):
            with self.subTest(label=label):
                malformed_inventory = json.loads(json.dumps(raw_inventory))
                commits = malformed_inventory["data"]["repository"]["pullRequests"]["nodes"][0]["commits"]
                commits["totalCount"] = total_count
                if total_count > 100:
                    commits["nodes"] = commits["nodes"] + [commits["nodes"][0]] * 99
                malformed_host = OpaqueCredentialHost(malformed_inventory)
                malformed_capability = create_credentialed_github_read_capability(
                    malformed_host, binding, dependency_control, health, clock=lambda: now,
                )
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                    confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("b"))
                    with self.assertRaisesRegex(external_validation.RepositoryInventoryFirstReadBoundaryError, "safe-subcause-not-retained") as captured:
                        external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, malformed_capability)
                expected = external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION if label == "incomplete" else external_validation.RepositoryInventoryReadFailureCode.CARDINALITY_FAILURE
                self.assertEqual(captured.exception.code, expected)
                self.assertEqual(len(malformed_host.commands), 1)
        for label, total_count, has_next in (("partial-suite", 2, False), ("over-bound-suite", 101, True)):
            with self.subTest(label=label):
                malformed_inventory = json.loads(json.dumps(raw_inventory))
                suites = malformed_inventory["data"]["repository"]["pullRequests"]["nodes"][0]["commits"]["nodes"][0]["commit"]["checkSuites"]
                suites["totalCount"] = total_count
                suites["pageInfo"]["hasNextPage"] = has_next
                malformed_host = OpaqueCredentialHost(malformed_inventory)
                malformed_capability = create_credentialed_github_read_capability(
                    malformed_host, binding, dependency_control, health, clock=lambda: now,
                )
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                    confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("a"))
                    with self.assertRaisesRegex(external_validation.RepositoryInventoryFirstReadBoundaryError, "safe-subcause-not-retained") as captured:
                        external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, malformed_capability)
                expected = external_validation.RepositoryInventoryReadFailureCode.INCOMPLETE_CONNECTION if label == "partial-suite" else external_validation.RepositoryInventoryReadFailureCode.CARDINALITY_FAILURE
                self.assertEqual(captured.exception.code, expected)
                self.assertEqual(len(malformed_host.commands), 1)
        for label, read_time in (
            ("reversed", now - timedelta(seconds=1)),
            ("expired", now + timedelta(minutes=2)),
        ):
            with self.subTest(label=label):
                denied_host = OpaqueCredentialHost(raw_inventory)
                times = iter((now, read_time))
                denied_capability = create_credentialed_github_read_capability(
                    denied_host, binding, dependency_control, health, clock=lambda: next(times),
                )
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve()
                    session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
                    confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("c"))
                    with self.assertRaisesRegex(external_validation.RepositoryInventoryFirstReadBoundaryError, "safe-subcause-not-retained") as captured:
                        external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, denied_capability)
                self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.TIME_OR_HEALTH_FAILURE)
                self.assertEqual(denied_host.commands, [])
        seam_host = InvalidJsonHost()
        seam_capability = create_credentialed_github_read_capability(
            seam_host, binding, dependency_control, health, clock=lambda: now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("a"))
            with self.assertRaises(external_validation.RepositoryInventoryFirstReadBoundaryError) as captured:
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, seam_capability)
        self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
        self.assertEqual(captured.exception.stage, RepositoryInventoryFailureStage.JSON_DECODING)
        self.assertNotIn("private-json-marker", str(captured.exception))
        transport_seam_host = NonzeroReturnHost()
        transport_seam_capability = create_credentialed_github_read_capability(
            transport_seam_host, binding, dependency_control, health, clock=lambda: now,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("b"))
            with self.assertRaises(external_validation.RepositoryInventoryFirstReadBoundaryError) as captured:
                external_validation.execute_live_lifecycle_shadow_session(
                    confirmed.public_receipt(), root, transport_seam_capability,
                )
        self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.HOST_FAILURE)
        self.assertEqual(captured.exception.stage, RepositoryInventoryFailureStage.TRANSPORT)
        self.assertEqual(
            captured.exception.transport_subcategory,
            RepositoryInventoryTransportSubcategory.NONZERO_RETURN,
        )
        self.assertNotIn("private nonzero return marker", str(captured.exception))
        self.assertEqual(len(transport_seam_host.commands), 1)

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
