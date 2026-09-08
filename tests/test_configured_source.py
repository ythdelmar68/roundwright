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

from roundwright.configuration import RepositoryIdentity
from roundwright.configured_source import (
    ConfiguredSource, ConfiguredSourceError, ConfiguredSourceStore, SourceIngestionBinding,
    ConfiguredSourceHostInputs, ConfiguredSourceIngestionAdapter, SourceItem, SourcePage,
    SourceType, TaskFeedReadHost, TrustedConfiguredSourceReadHost, configured_source_capture_plan,
    configured_source_component_identities, configured_source_executor_request,
    scan_configured_sources, select_runnable_work,
)
from roundwright.dependency_graph import DependencyGraphBinding, GraphEdge, GraphMember, GraphSnapshot
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

    def item(self, public, member, content="a", mechanical="1"):
        return SourceItem(public, member, digest({"content": content}), digest({"mechanical": mechanical}))

    def inventory(self, sources, pages):
        return scan_configured_sources(SourceIngestionBinding(self.candidate, self.policy, self.configuration, tuple(sources)), Adapter(pages))

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
        read_host = TrustedConfiguredSourceReadHost(source_binding, task_feed=TaskFeedReadHost(reader.read))
        host = ConfiguredSourceHostInputs(
            "b" * 40, source_binding, graph, "configured-source-case", 71, read_host,
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
        host = ConfiguredSourceHostInputs(
            "b" * 40, source_binding, graph, "configured-source-case", 71,
            TrustedConfiguredSourceReadHost(source_binding, task_feed=TaskFeedReadHost(reader.read)),
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


if __name__ == "__main__":
    unittest.main()
