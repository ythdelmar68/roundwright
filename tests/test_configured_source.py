"""Hermetic contracts for configured-source normalization and selection."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity, load_configuration
from roundwright.configured_source import (
    ConfiguredSource, ConfiguredSourceError, ConfiguredSourceStore, SourceIngestionBinding,
    ConfiguredSourceHostInputs, ConfiguredSourceIngestionAdapter, SourceItem, SourcePage,
    SourceType, TrustedConfiguredSourceReadHost, configured_source_capture_plan,
    configured_source_component_identities, configured_source_executor_request,
    _seal_configured_source_authority, create_configured_source_read_capability,
    _create_task_feed_fixture_capability, create_task_feed_read_host,
    create_issue_list_read_host, prepare_configured_source_ingestion,
    resolve_source_ingestion_binding,
    scan_configured_sources, select_runnable_work,
)
from roundwright.dependency_graph import DependencyGraphBinding, DependencyGraphStore, GraphEdge, GraphMember, GraphSnapshot
from roundwright.github_runtime import OwnerGitHubReadIpcClient, unavailable_capability_health
from roundwright.dependency_review import AffectedMember, EdgeKind
from roundwright.external_validation import run_configured_source_ingestion_profile
from roundwright.state import initialize


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def freeze_harness_json(value: object) -> object:
    if type(value) is dict:
        return MappingProxyType({str(key): freeze_harness_json(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze_harness_json(item) for item in value)
    return value


class Adapter:
    def __init__(self, pages): self.pages, self.calls = pages, []
    def read(self, source, *, cursor):
        self.calls.append((source.public_identity, cursor))
        return self.pages[(source.public_identity, cursor)]


class Harness:
    class ProfileComponentIdentities:
        def __init__(self, *values): self.values = values
        def __eq__(self, other): return isinstance(other, Harness.ProfileComponentIdentities) and self.values == other.values
    class ProfileExecution:
        def __init__(self, value, *, mutation_count): self.value, self.mutation_count = value, mutation_count
    class ProfileExecutionContext:
        def __init__(self, identity, value): self.identity, self.value = identity, value
    class ProfileComparison:
        def __init__(self, status, result_identity): self.status, self.result_identity = status, result_identity


class ExactHarnessV2:
    """Hermetic model of the reviewed Harness V2 validation boundary.

    Its request and plan checks deliberately match the pinned V2 public
    contract, including Recorder/store binding.  Validate never calls execute,
    record, verify, or a configured-source reader.
    """

    plan_fields = {
        "schema", "profile", "case_id", "candidate_sha", "ready_at",
        "producer_identity", "exporter_identity", "comparator_identity",
        "recorder_identity", "store_identity", "observation_identity",
    }
    calls = {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0}
    run_calls = 0

    class ProfileComponentIdentities:
        def __init__(self, producer_identity, exporter_identity, comparator_identity):
            self.producer_identity = producer_identity
            self.exporter_identity = exporter_identity
            self.comparator_identity = comparator_identity
        def __eq__(self, other):
            return type(other) is ExactHarnessV2.ProfileComponentIdentities and self.__dict__ == other.__dict__

    class ProfileExecutionContext:
        def __init__(self, identity, value): self.identity, self.value = identity, value

    class ProfileExecution:
        def __init__(self, value, *, mutation_count): self.value, self.mutation_count = value, mutation_count

    class ProfileComparison:
        def __init__(self, status, result_identity): self.status, self.result_identity = status, result_identity

    class ExecutorRequest:
        def __init__(self, value):
            self.schema = value["schema"]
            self.capture_plan = value["capture_plan"]
            self.execution_context = value["execution_context"]
        @classmethod
        def parse(cls, value):
            if type(value) is not dict or set(value) != {"schema", "capture_plan", "execution_context"}:
                raise ValueError("V2 request is not closed")
            if value["schema"] != "roundwright-harness-profile-executor-request/v2":
                raise ValueError("wrong executor schema")
            if type(value["capture_plan"]) is not dict or type(value["execution_context"]) is not dict:
                raise ValueError("V2 request must be structured")
            return cls(value)

    @staticmethod
    def prepare_capture(plan):
        if type(plan) is not dict or set(plan) != ExactHarnessV2.plan_fields:
            raise ValueError("V2 plan is incomplete")
        if plan["schema"] != "roundwright-harness-capture-plan/v1":
            raise ValueError("wrong capture schema")
        return SimpleNamespace(
            plan_digest=digest(plan), profile=plan["profile"], case_id=plan["case_id"],
            candidate_sha=plan["candidate_sha"], ready_at=plan["ready_at"],
        )

    @staticmethod
    def run_profile_executor(mode, request_value, adapter, store_root, *, expected_readiness_digest=None):
        ExactHarnessV2.run_calls += 1
        if mode != "validate" or expected_readiness_digest is not None:
            raise ValueError("this hermetic gate only validates")
        request = ExactHarnessV2.ExecutorRequest.parse(request_value)
        plan = ExactHarnessV2.prepare_capture(request.capture_plan)
        components = adapter.component_identities
        context = adapter.prepare_execution_context(SimpleNamespace(
            descriptor=freeze_harness_json(request.execution_context), input_digest=digest(request.execution_context),
            components=components, plan=plan,
        ))
        binding = SimpleNamespace(
            profile=plan.profile, case_id=plan.case_id, candidate_sha=plan.candidate_sha,
            ready_at=plan.ready_at, plan=plan, components=components,
            execution_context=context, execution_context_input_digest=digest(request.execution_context),
        )
        adapter.validate(binding)
        return SimpleNamespace(
            status="ready", state="PREFLIGHT_READY", plan_digest=plan.plan_digest,
            dispatch_count=0, record_count=0, verify_count=0, mutation_count=0,
        )


class ConfiguredSourceTests(unittest.TestCase):
    candidate = "a" * 40
    policy = digest("policy")
    configuration = digest("configuration")

    def source(self, identity="team/queue", *, pages=2):
        return ConfiguredSource(SourceType.TASK_FEED, identity, pages, 10)

    def production_configuration(self, root, sources):
        config = root / "configured-sources.toml"
        rendered = ", ".join(
            "{ source_type = \"%s\", public_identity = \"%s\", max_pages = %d, max_items = %d }"
            % (source["source_type"], source["public_identity"], source["max_pages"], source["max_items"])
            for source in sources
        )
        config.write_text(
            "[runtime]\n"
            "schema_version = \"roundwright-runtime/v1\"\n"
            f"configured_sources = [{rendered}]\n",
            encoding="utf-8",
        )
        return load_configuration(cwd=root, user_config=config, environment={}, home=root / "home").pin()

    @staticmethod
    def issue_host():
        client = OwnerGitHubReadIpcClient(unavailable_capability_health())
        with patch("roundwright.configured_source.credentialed_github_read_capability_identity", return_value=digest("issue-host")):
            return create_issue_list_read_host(client)

    def item(self, public, member, content="a", mechanical="1"):
        return SourceItem(public, member, digest({"content": content}), digest({"mechanical": mechanical}))

    def inventory(self, sources, pages):
        return scan_configured_sources(SourceIngestionBinding(self.candidate, self.policy, self.configuration, tuple(sources)), Adapter(pages))

    @staticmethod
    def source_host(authority, reader):
        capability = _create_task_feed_fixture_capability(reader.pages)
        reader.source_capability = capability
        return TrustedConfiguredSourceReadHost(
            authority,
            create_configured_source_read_capability(
                authority, task_feed=create_task_feed_read_host(capability),
            ),
        )

    def test_only_explicit_bounded_sources_and_cursor_progress_are_accepted(self):
        source = self.source()
        first = SourcePage(source, None, "page-2", (self.item("item/a", "task-a"),))
        second = SourcePage(source, "page-2", None, (self.item("item/b", "task-b", "b", "2"),))
        inventory = self.inventory((source,), {(source.public_identity, None): first, (source.public_identity, "page-2"): second})
        self.assertEqual([item.member_id for item in inventory.items], ["task-a", "task-b"])
        with self.assertRaises(ConfiguredSourceError):
            ConfiguredSource(SourceType.TASK_FEED, "org/*", 1, 1)
        loop = SourcePage(source, None, "same", ())
        with self.assertRaises(ConfiguredSourceError):
            self.inventory((source,), {(source.public_identity, None): loop, (source.public_identity, "same"): SourcePage(source, "same", "same", ())})

    def test_production_binding_derives_only_the_resolved_typed_allowlist(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "configured-sources.toml"
            config.write_text(
                "[runtime]\n"
                "schema_version = \"roundwright-runtime/v1\"\n"
                "configured_sources = [{ source_type = \"task-feed\", public_identity = \"team/queue\", max_pages = 2, max_items = 10 }]\n",
                encoding="utf-8",
            )
            resolved = load_configuration(cwd=root, user_config=config, environment={}, home=root / "home").pin()
        binding = resolve_source_ingestion_binding(resolved, self.candidate)
        self.assertEqual(binding.configured_sources, (self.source(),))
        self.assertEqual(binding.configuration_digest, resolved.digest)
        self.assertEqual(binding.policy_digest, "sha256:" + resolved.runtime_binding().review_policy_digest)
        with self.assertRaises(ConfiguredSourceError):
            resolve_source_ingestion_binding(resolved, "not-a-sha")

    def test_production_prepare_treats_one_source_graph_as_not_applicable(self):
        source = {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/117", "max_pages": 1, "max_items": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            configuration = self.production_configuration(root, [source])
            ExactHarnessV2.run_calls = 0
            with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
                inputs, request = prepare_configured_source_ingestion(
                    repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71,
                    digest("recorder"), digest("store"), issue_list=self.issue_host(),
                )
        self.assertIsNone(inputs.graph)
        self.assertEqual(inputs.authority.graph_applicability.value, "not-applicable")
        self.assertIsNone(request["execution_context"]["graph_digest"])
        self.assertEqual(ExactHarnessV2.run_calls, 0)

    def test_production_prepare_requires_matching_current_graph_for_multiple_sources(self):
        sources = [
            {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/117", "max_pages": 1, "max_items": 1},
            {"source_type": "issue-list", "public_identity": "ythdelmar68/roundwright/issue/118", "max_pages": 1, "max_items": 1},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", root.resolve())
            initialize(repository)
            configuration = self.production_configuration(root, sources)
            with self.assertRaises(ConfiguredSourceError):
                prepare_configured_source_ingestion(repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71, digest("recorder"), digest("store"), issue_list=self.issue_host())
            binding = resolve_source_ingestion_binding(configuration, self.candidate)
            graph_binding = DependencyGraphBinding(binding.candidate_sha, binding.policy_digest, binding.configuration_digest)
            current = GraphSnapshot("graph-117", graph_binding, (), (), ())
            ExactHarnessV2.run_calls = 0
            with patch.object(DependencyGraphStore, "current", return_value=current), patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
                inputs, _ = prepare_configured_source_ingestion(repository, configuration, self.candidate, "b" * 40, "configured-source-case", 71, digest("recorder"), digest("store"), issue_list=self.issue_host())
        self.assertEqual(inputs.graph, current)
        self.assertEqual(inputs.authority.graph_applicability.value, "required")
        self.assertEqual(ExactHarnessV2.run_calls, 0)

    def test_owner_host_factories_expose_no_callback_or_claimed_identity_seam(self):
        source = self.source()
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, ())})
        with self.assertRaises(ConfiguredSourceError):
            create_task_feed_read_host(reader.read)
        from roundwright.configured_source import create_issue_list_read_host
        with self.assertRaises(ConfiguredSourceError):
            create_issue_list_read_host(reader.read)

    def test_identical_typed_endpoint_reconstruction_is_stable_and_changed_endpoint_is_not(self):
        source = self.source()
        page = SourcePage(source, None, None, (self.item("item/a", "task-a"),))
        stable_first = _create_task_feed_fixture_capability({(source.public_identity, None): page})
        stable_second = _create_task_feed_fixture_capability({(source.public_identity, None): page})
        changed = _create_task_feed_fixture_capability({
            (source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a", content="changed"),)),
        })
        self.assertEqual(stable_first.endpoint_identity, stable_second.endpoint_identity)
        self.assertNotEqual(stable_first.endpoint_identity, changed.endpoint_identity)

    def test_only_mechanically_identical_items_merge_and_content_collision_blocks(self):
        first, second = self.source("team/one"), self.source("team/two")
        identical = self.item("item/a", "task-a")
        same_content_other_identity = self.item("item/b", "task-b", mechanical="2")
        inventory = self.inventory(
            (first, second),
            {(first.public_identity, None): SourcePage(first, None, None, (identical,)),
             (second.public_identity, None): SourcePage(second, None, None, (same_content_other_identity,))},
        )
        self.assertEqual(len(inventory.items), 2)
        result = select_runnable_work(inventory, None)
        self.assertTrue(all("current-graph-unavailable" in decision.blockers for decision in result.decisions))
        self.assertTrue(any("ambiguous-deduplication" in decision.blockers for decision in result.decisions))

    def test_multi_source_selection_requires_current_matching_graph_and_leaves_unrelated_root_runnable(self):
        first, second = self.source("team/one"), self.source("team/two")
        a, b, c = self.item("item/a", "task-a"), self.item("item/b", "task-b", "b", "2"), self.item("item/c", "task-c", "c", "3")
        inventory = self.inventory(
            (first, second),
            {(first.public_identity, None): SourcePage(first, None, None, (a, b)),
             (second.public_identity, None): SourcePage(second, None, None, (c,))},
        )
        binding = DependencyGraphBinding(self.candidate, self.policy, self.configuration)
        members = tuple(GraphMember("task-117", "subset-117", AffectedMember(item.member_id, digest({"fingerprint": item.member_id}), item.content_digest)) for item in inventory.items)
        edges = (GraphEdge("task-a", "task-b", EdgeKind.EXPLICIT, "proposal-117", digest("edge")),)
        graph = GraphSnapshot("graph-117", binding, members, edges, ("proposal-117",))
        result = select_runnable_work(inventory, graph)
        by_id = {decision.opaque_id: decision for decision in result.decisions}
        self.assertEqual(len(result.runnable_ids), 2)
        self.assertTrue(any("dependency-not-complete" in decision.blockers for decision in by_id.values()))

    def test_inventory_store_is_append_only_and_content_addressed(self):
        source = self.source()
        inventory = self.inventory((source,), {(source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a"),))})
        with tempfile.TemporaryDirectory() as temporary:
            repository = object.__new__(RepositoryIdentity)
            object.__setattr__(repository, "root", Path(temporary).resolve())
            initialize(repository)
            store = ConfiguredSourceStore()
            self.assertEqual(store.record(repository, inventory), inventory.inventory_digest)
            self.assertEqual(store.record(repository, inventory), inventory.inventory_digest)
            self.assertEqual(json.loads(store.read(repository, inventory.inventory_digest))["candidate_sha"], self.candidate)

    def test_profile_exports_public_safe_capture_time_evidence_without_a_provider(self):
        source = self.source()
        item = self.item("item/private-looking", "task-a")
        source_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph_binding = DependencyGraphBinding(self.candidate, self.policy, self.configuration)
        graph = GraphSnapshot(
            "graph-117", graph_binding,
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = _seal_configured_source_authority(source_binding)
        read_host = self.source_host(authority, reader)
        host = ConfiguredSourceHostInputs(
            "b" * 40, authority, "configured-source-case", 71, read_host,
            digest("recorder"), digest("store"),
        )
        capture = digest(configured_source_capture_plan(host))
        plan = SimpleNamespace(candidate_sha=self.candidate, case_id=host.case_id, plan_digest=capture, ready_at=71)
        context_value = host.execution_context(capture)
        binding = SimpleNamespace(
            profile="roundwright-shadow-profile/configured-source-ingestion/v1", case_id=host.case_id,
            candidate_sha=self.candidate, ready_at=71, plan=plan,
            components=SimpleNamespace(**dict(zip(("producer_identity", "exporter_identity", "comparator_identity"), configured_source_component_identities(), strict=True))),
            execution_context=SimpleNamespace(value=host, identity=digest({
                "observation_identity": host.observation_identity, "capture_plan_digest": capture,
                "execution_context_input_digest": digest(context_value),
            })),
            execution_context_input_digest=digest(context_value),
        )
        with patch("roundwright.external_validation._harness_executor", return_value=Harness):
            adapter = ConfiguredSourceIngestionAdapter(host)
            adapter.validate(binding)
            execution = adapter.execute(binding)
            evidence = adapter.project(binding, execution)
            comparison = adapter.compare(binding, evidence)
            self.assertEqual((execution.mutation_count, comparison.status), (0, "pass"))
            self.assertEqual(evidence["ready_at"], 71)
            self.assertNotIn("item/private-looking", json.dumps(evidence))
            self.assertEqual(evidence["configured_source_ingestion"]["zero_mutation_proof"]["provider_dispatch_count"], 0)
            changed = dict(evidence); changed["ready_at"] = 72
            self.assertEqual(adapter.compare(binding, changed).status, "fail")
            self.assertEqual(configured_source_capture_plan(host)["observation_identity"], host.observation_identity)

    def test_exact_v2_harness_validate_is_closed_and_performs_zero_live_actions(self):
        source = self.source()
        item = self.item("item/a", "task-a")
        source_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph = GraphSnapshot(
            "graph-117", DependencyGraphBinding(self.candidate, self.policy, self.configuration),
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = _seal_configured_source_authority(source_binding)
        host = ConfiguredSourceHostInputs(
            "b" * 40, authority, "configured-source-case", 71, self.source_host(authority, reader),
            digest("recorder"), digest("store"),
        )
        ExactHarnessV2.calls = {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0}
        with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
            request = configured_source_executor_request(host)
            receipt = run_configured_source_ingestion_profile("validate", request, Path("unused-store"), host)
        self.assertEqual(receipt.state, "PREFLIGHT_READY")
        self.assertEqual(
            (receipt.dispatch_count, receipt.record_count, receipt.verify_count, receipt.mutation_count),
            (0, 0, 0, 0),
        )
        self.assertEqual(reader.calls, [])
        self.assertEqual(ExactHarnessV2.calls, {"dispatch": 0, "record": 0, "verify": 0, "mutation": 0})
        self.assertEqual(set(request["capture_plan"]), ExactHarnessV2.plan_fields)
        self.assertEqual(request["capture_plan"]["observation_identity"], host.observation_identity)

    def test_preflight_rejects_capability_authority_and_request_movement_before_read(self):
        source = self.source()
        item = self.item("item/a", "task-a")
        binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (source,))
        graph = GraphSnapshot(
            "graph-117", DependencyGraphBinding(self.candidate, self.policy, self.configuration),
            (GraphMember("task-117", "subset-117", AffectedMember("task-a", digest("member"), item.content_digest)),), (), (),
        )
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        authority = _seal_configured_source_authority(binding)
        host = ConfiguredSourceHostInputs(
            "b" * 40, authority, "configured-source-case", 71, self.source_host(authority, reader),
            digest("recorder"), digest("store"),
        )
        different_reader = Adapter({
            (source.public_identity, None): SourcePage(source, None, None, (self.item("item/a", "task-a", content="replacement"),)),
        })
        changed_capability = ConfiguredSourceHostInputs(
            host.base_sha, authority, host.case_id, host.ready_at,
            self.source_host(authority, different_reader), host.recorder_identity, host.store_identity,
        )
        changed_source = self.source("team/other")
        changed_binding = SourceIngestionBinding(self.candidate, self.policy, self.configuration, (changed_source,))
        changed_source_graph = GraphSnapshot("graph-119", DependencyGraphBinding(self.candidate, self.policy, self.configuration), graph.members, graph.edges, graph.proposal_ids)
        changed_source_authority = _seal_configured_source_authority(changed_binding)
        changed_source_reader = Adapter({(changed_source.public_identity, None): SourcePage(changed_source, None, None, (item,))})
        changed_configuration = ConfiguredSourceHostInputs(
            host.base_sha, changed_source_authority, host.case_id, host.ready_at,
            self.source_host(changed_source_authority, changed_source_reader), host.recorder_identity, host.store_identity,
        )
        moved_candidate = "c" * 40
        moved_binding = SourceIngestionBinding(moved_candidate, self.policy, self.configuration, (source,))
        moved_graph = GraphSnapshot(
            "graph-120", DependencyGraphBinding(moved_candidate, self.policy, self.configuration),
            graph.members, graph.edges, graph.proposal_ids,
        )
        moved_authority = _seal_configured_source_authority(moved_binding)
        moved_candidate_host = ConfiguredSourceHostInputs(
            host.base_sha, moved_authority, host.case_id, host.ready_at,
            self.source_host(moved_authority, reader), host.recorder_identity, host.store_identity,
        )
        changed_ready = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, 72, host.read_host, host.recorder_identity, host.store_identity)
        changed_recorder = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, host.ready_at, host.read_host, digest("other-recorder"), host.store_identity)
        changed_store = ConfiguredSourceHostInputs(host.base_sha, authority, host.case_id, host.ready_at, host.read_host, host.recorder_identity, digest("other-store"))
        ExactHarnessV2.run_calls = 0
        with patch("roundwright.external_validation._harness_executor", return_value=ExactHarnessV2):
            request = configured_source_executor_request(host)
            for moved in (changed_capability, changed_configuration, moved_candidate_host, changed_ready, changed_recorder, changed_store):
                with self.subTest(moved=moved.observation_identity), self.assertRaises(Exception):
                    run_configured_source_ingestion_profile("validate", request, Path("unused-store"), moved)
        self.assertEqual(ExactHarnessV2.run_calls, 0)
        self.assertEqual(reader.calls, [])
        self.assertEqual(reader.source_capability.source_read_count, 0)
        self.assertEqual(different_reader.source_capability.source_read_count, 0)
        self.assertEqual(changed_source_reader.calls, [])


if __name__ == "__main__":
    unittest.main()
