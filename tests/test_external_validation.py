from __future__ import annotations

import json
import inspect
import sys
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
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
from roundwright.github import (
    GitHubFailure,
    GitHubFailureKind,
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
    create_credentialed_github_read_capability,
    repository_inventory_failure_code,
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
                    RepositoryInventoryFact("issue-50", "label", "roundlet-ignore"),
                    RepositoryInventoryFact("issue-51", "malformed-parent", "owner-input"),
                    RepositoryInventoryFact("issue-49", "depends-on", "issue-4"),
                    RepositoryInventoryFact("pull-request-81", "state", "merged"),
                    RepositoryInventoryFact("issue-49", "supervisor-failover", "observed"),
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
                RepositoryInventoryFact("issue-49", "supervisor-failover", "observed"),
                RepositoryInventoryFact("issue-50", "label", "roundlet-ignore"),
                RepositoryInventoryFact("issue-51", "malformed-parent", "owner-input"),
                RepositoryInventoryFact("pull-request-81", "state", "merged"),
            )
            return RepositoryInventorySnapshot(
                repository, "forward-target", "main", "d" * 40, "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                tuple(sorted(collections, key=lambda item: item.section.value)), facts,
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
                "issues": {"totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                    {"id": "issue-4", "number": 4, "state": "OPEN", "labels": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "subIssues": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"number": 49}]}},
                    {"id": "issue-49", "number": 49, "state": "OPEN", "labels": {"totalCount": 4, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{"name": "roundlet-ignore"}, {"name": "roundlet-malformed-parent-owner-input"}, {"name": "roundlet-dependency"}, {"name": "roundlet-supervisor-failover"}]}, "subIssues": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}},
                ]},
                "pullRequests": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{
                    "id": "pull-request-81", "number": 81, "state": "MERGED", "headRefOid": inputs.candidate_sha, "headRefName": "codex-issue-49", "mergeStateStatus": "CLEAN", "mergeCommit": {"oid": inputs.candidate_sha},
                    "comments": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "reviews": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "reviewRequests": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}, "closingIssuesReferences": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
                    "commits": {"totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
                        {"commit": {"oid": "1" * 40, "checkSuites": {"totalCount": 2, "pageInfo": {"hasNextPage": True, "endCursor": "suite-cursor-1"}, "nodes": [
                            {"id": "check-suite-1", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": "workflow-run-1"}},
                        ]}}},
                        {"commit": {"oid": "2" * 40, "checkSuites": {"totalCount": 2, "pageInfo": {"hasNextPage": True, "endCursor": "suite-cursor-2"}, "nodes": [
                            {"id": "check-suite-2", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": "workflow-run-2"}},
                        ]}}},
                    ]},
                }]},
                "refs": {"totalCount": 0, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []},
            }},
        }

        @dataclass(frozen=True)
        class OpaqueResult:
            returncode: int
            stdout: str

        class OpaqueCredentialHost:
            def __init__(self, payload: object, *, issue_page: object | None = None, comment_page: object | None = None, exit_code: int = 0) -> None:
                self.commands: list[tuple[str, ...]] = []
                self.payload = payload
                self.issue_page = issue_page
                self.comment_page = comment_page
                self.exit_code = exit_code
            def run(self, arguments: tuple[str, ...]) -> OpaqueResult:
                self.commands.append(arguments)
                if self.exit_code:
                    return OpaqueResult(self.exit_code, "")
                if "object(expression:$oid)" in arguments[3]:
                    oid = next(value.removeprefix("oid=") for value in arguments if value.startswith("oid="))
                    suffix = "1" if oid == "1" * 40 else "2" if oid == "2" * 40 else "unknown"
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "object": {"oid": oid, "checkSuites": {
                            "totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [{
                                "id": f"check-suite-{suffix}-continued", "status": "COMPLETED", "conclusion": "SUCCESS", "workflowRun": {"id": f"workflow-run-{suffix}-continued"},
                            }],
                        }},
                    }}}))
                if "issues(first:100,after:$cursor" in arguments[3] and self.issue_page is not None:
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "issues": self.issue_page,
                    }}}))
                if "comments(first:100,after:$cursor" in arguments[3] and self.comment_page is not None:
                    return OpaqueResult(0, json.dumps({"data": {"repository": {
                        "name": name, "owner": {"login": owner}, "pullRequest": {"number": 81, "comments": self.comment_page},
                    }}}))
                return OpaqueResult(0, json.dumps(self.payload))

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
        inventory_commands = [command for command in host.commands if "object(expression:$oid)" not in command[3]]
        continuation_commands = [command for command in host.commands if "object(expression:$oid)" in command[3]]
        self.assertEqual(len(inventory_commands), 3)
        self.assertEqual(inventory_commands, [inventory_commands[0]] * 3)
        self.assertEqual(len(continuation_commands), 6)
        self.assertEqual(inventory_commands[0][0:3], ("api", "graphql", "-f"))
        self.assertIn("repository(owner:$owner,name:$name)", inventory_commands[0][3])
        self.assertIn("commits(first:100)", inventory_commands[0][3])
        self.assertEqual(inventory_commands[0][-4:], ("-F", f"owner={owner}", "-F", f"name={name}"))
        self.assertTrue(all("checkSuites(first:100,after:$cursor)" in command[3] for command in continuation_commands))
        self.assertEqual([arguments[0] for arguments, _ in harness.run_calls], ["validate", "execute"])
        self.assertTrue(harness.run_calls[1][0][2].snapshot.zero_mutation_readback_digest.startswith("sha256:"))
        self.assertFalse(hasattr(capability, "query"))
        self.assertFalse(hasattr(capability, "snapshot"))
        def issue(number: int) -> dict[str, object]:
            return {
                "id": f"issue-{number}", "number": number, "state": "OPEN",
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
        self.assertTrue(top_level_result.ok)
        self.assertEqual(len(top_level_result.snapshot.collection(RepositoryInventorySection.ISSUES).item_identities), 101)  # type: ignore[union-attr]
        self.assertEqual(sum("issues(first:100,after:$cursor" in command[3] for command in top_level_host.commands), 1)
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
        self.assertEqual(sum("comments(first:100,after:$cursor" in command[3] for command in nested_host.commands), 1)
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
        class ArbitraryPublicReasonCapability:
            def __init__(self) -> None: self.calls = 0
            def read(self, request: GitHubReadRequest) -> GitHubReadResult:
                self.calls += 1
                return GitHubReadResult(request, failure=GitHubFailure(
                    GitHubFailureKind.MALFORMED_RESPONSE, request.operation,
                    ROUNDWRIGHT_REPOSITORY_INVENTORY_FIRST_READ_BOUNDARY__SAFE_SUBCAUSE_NOT_RETAINED + ":identity-drift",
                ))
        arbitrary_failure = ArbitraryPublicReasonCapability()
        executes_before = len([item for item in harness.run_calls if item[0][0] == "execute"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            session = external_validation.preflight_live_lifecycle_shadow_session(inputs, root)
            confirmed = external_validation.confirm_live_lifecycle_shadow_trace(session.public_receipt(), root, digest("9"))
            with self.assertRaises(external_validation.RepositoryInventoryFirstReadBoundaryError) as captured:
                external_validation.execute_live_lifecycle_shadow_session(confirmed.public_receipt(), root, arbitrary_failure)
        self.assertEqual(captured.exception.code, external_validation.RepositoryInventoryReadFailureCode.MALFORMED_RESPONSE)
        self.assertEqual(arbitrary_failure.calls, 1)
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
