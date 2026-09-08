"""Hermetic contracts for configured-source normalization and selection."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.configured_source import (
    ConfiguredSource, ConfiguredSourceError, ConfiguredSourceStore, SourceIngestionBinding,
    SourceItem, SourcePage, SourceType, scan_configured_sources, select_runnable_work,
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


if __name__ == "__main__":
    unittest.main()
