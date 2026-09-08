"""Hermetic contracts for configured-source normalization and selection."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.configured_source import (
    ConfiguredSource, ConfiguredSourceError, ConfiguredSourceStore, SourceIngestionBinding,
    ConfiguredSourceHostInputs, ConfiguredSourceIngestionAdapter, SourceItem, SourcePage,
    SourceType, configured_source_capture_plan, configured_source_component_identities,
    scan_configured_sources, select_runnable_work,
)
from roundwright.dependency_graph import DependencyGraphBinding, GraphEdge, GraphMember, GraphSnapshot
from roundwright.dependency_review import AffectedMember, EdgeKind
from roundwright.state import initialize


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


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
        capture = digest("capture-plan")
        reader = Adapter({(source.public_identity, None): SourcePage(source, None, None, (item,))})
        host = ConfiguredSourceHostInputs("b" * 40, source_binding, graph, "configured-source-case", 71, capture, reader)
        plan = SimpleNamespace(candidate_sha=self.candidate, case_id=host.case_id, plan_digest=capture, ready_at=71)
        binding = SimpleNamespace(
            profile="roundwright-shadow-profile/configured-source-ingestion/v1", case_id=host.case_id,
            candidate_sha=self.candidate, ready_at=71, plan=plan,
            components=SimpleNamespace(**dict(zip(("producer_identity", "exporter_identity", "comparator_identity"), configured_source_component_identities(), strict=True))),
            execution_context=SimpleNamespace(value=host, identity=host.observation_identity),
            execution_context_input_digest=host.observation_identity,
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


if __name__ == "__main__":
    unittest.main()
