"""Fail-closed ingestion of explicitly configured work sources.

This boundary deliberately deals only in public identities and digests.  It
does not know how to create worktrees, call a provider, or mutate a source.
An adapter may *read* a configured source into pages; all normalization,
deduplication, graph joining, and runnable selection remain deterministic.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .configuration import RepositoryIdentity
from .dependency_graph import DependencyGraphBinding, GraphSnapshot
from .state import _open_writable_connection, database_path


_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_PUBLIC_ID = re.compile(r"[a-z][a-z0-9._/-]{0,255}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~-]{1,256}\Z")
SOURCE_INGESTION_PROFILE = "roundwright-shadow-profile/configured-source-ingestion/v1"


class ConfiguredSourceError(ValueError):
    """Raised when source evidence or selection input is not trustworthy."""


class SourceType(StrEnum):
    ISSUE_LIST = "issue-list"
    TASK_FEED = "task-feed"


class SelectionState(StrEnum):
    RUNNABLE = "runnable"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ConfiguredSource:
    """One exact source selected by trusted configuration, never a pattern."""

    source_type: SourceType
    public_identity: str
    max_pages: int
    max_items: int

    def __post_init__(self) -> None:
        if (type(self.source_type) is not SourceType or not _PUBLIC_ID.fullmatch(self.public_identity)
                or type(self.max_pages) is not int or not 1 <= self.max_pages <= 1000
                or type(self.max_items) is not int or not 1 <= self.max_items <= 100_000
                or "*" in self.public_identity):
            raise ConfiguredSourceError("configured source is invalid")

    @property
    def source_digest(self) -> str:
        return _digest_value(self.payload())

    def payload(self) -> dict[str, object]:
        return {"source_type": self.source_type.value, "public_identity": self.public_identity,
                "max_pages": self.max_pages, "max_items": self.max_items}


@dataclass(frozen=True)
class SourceItem:
    """A source adapter's public-safe item projection.

    ``member_id`` is the independently assigned graph identifier.  Content
    equality alone never supplies this identifier and consequently cannot
    create a dependency edge or runnable authorization.
    """

    public_item_id: str
    member_id: str
    content_digest: str
    mechanical_identity_digest: str

    def __post_init__(self) -> None:
        if (not _PUBLIC_ID.fullmatch(self.public_item_id) or not _TOKEN.fullmatch(self.member_id)
                or not _DIGEST_PATTERN.fullmatch(self.content_digest)
                or not _DIGEST_PATTERN.fullmatch(self.mechanical_identity_digest)):
            raise ConfiguredSourceError("source item is invalid")

    def payload(self) -> dict[str, str]:
        return {"public_item_id": self.public_item_id, "member_id": self.member_id,
                "content_digest": self.content_digest,
                "mechanical_identity_digest": self.mechanical_identity_digest}


@dataclass(frozen=True)
class SourcePage:
    """A bounded read result.  Adapters must echo the requested cursor."""

    source: ConfiguredSource
    requested_cursor: str | None
    next_cursor: str | None
    items: tuple[SourceItem, ...]

    def __post_init__(self) -> None:
        if (type(self.source) is not ConfiguredSource or self.requested_cursor is not None and not _CURSOR.fullmatch(self.requested_cursor)
                or self.next_cursor is not None and not _CURSOR.fullmatch(self.next_cursor)
                or type(self.items) is not tuple or any(type(item) is not SourceItem for item in self.items)
                or self.next_cursor is not None and self.next_cursor == self.requested_cursor):
            raise ConfiguredSourceError("source page is invalid")


class ConfiguredSourceAdapter(Protocol):
    """Read-only adapter seam; no mutation operation is part of this protocol."""

    def read(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage: ...


@dataclass(frozen=True)
class SourceIngestionBinding:
    candidate_sha: str
    policy_digest: str
    configuration_digest: str
    configured_sources: tuple[ConfiguredSource, ...]

    def __post_init__(self) -> None:
        if (not _SHA.fullmatch(self.candidate_sha) or not _DIGEST_PATTERN.fullmatch(self.policy_digest)
                or not _DIGEST_PATTERN.fullmatch(self.configuration_digest)
                or type(self.configured_sources) is not tuple or not self.configured_sources
                or any(type(source) is not ConfiguredSource for source in self.configured_sources)
                or len({source.public_identity for source in self.configured_sources}) != len(self.configured_sources)):
            raise ConfiguredSourceError("source ingestion binding is invalid")

    @property
    def source_set_digest(self) -> str:
        return _digest_value({"sources": [source.payload() for source in sorted(self.configured_sources, key=lambda item: item.public_identity)]})


@dataclass(frozen=True)
class NormalizedItem:
    opaque_id: str
    member_id: str
    content_digest: str
    mechanical_identity_digest: str
    source_identities: tuple[str, ...]
    ambiguous: bool

    def __post_init__(self) -> None:
        if (not _DIGEST_PATTERN.fullmatch(self.opaque_id) or not _TOKEN.fullmatch(self.member_id)
                or not _DIGEST_PATTERN.fullmatch(self.content_digest)
                or not _DIGEST_PATTERN.fullmatch(self.mechanical_identity_digest)
                or type(self.source_identities) is not tuple or not self.source_identities
                or tuple(sorted(self.source_identities)) != self.source_identities
                or any(not _PUBLIC_ID.fullmatch(value) for value in self.source_identities)
                or type(self.ambiguous) is not bool):
            raise ConfiguredSourceError("normalized source item is invalid")

    def payload(self) -> dict[str, object]:
        return {"opaque_id": self.opaque_id, "member_id": self.member_id,
                "content_digest": self.content_digest,
                "mechanical_identity_digest": self.mechanical_identity_digest,
                "source_identities": list(self.source_identities), "ambiguous": self.ambiguous}


@dataclass(frozen=True)
class SourceInventory:
    binding: SourceIngestionBinding
    source_content_digests: tuple[tuple[str, str], ...]
    items: tuple[NormalizedItem, ...]

    def __post_init__(self) -> None:
        expected_sources = () if type(self.binding) is not SourceIngestionBinding else tuple(sorted(source.public_identity for source in self.binding.configured_sources))
        valid_observations = all(
            type(observation) is tuple and len(observation) == 2 and type(observation[0]) is str and type(observation[1]) is str
            for observation in self.source_content_digests
        )
        if (type(self.binding) is not SourceIngestionBinding or type(self.source_content_digests) is not tuple
                or type(self.items) is not tuple or any(type(item) is not NormalizedItem for item in self.items)
                or not valid_observations
                or tuple(sorted(identity for identity, _ in self.source_content_digests)) != tuple(identity for identity, _ in self.source_content_digests)
                or tuple(identity for identity, _ in self.source_content_digests) != expected_sources
                or any(not _PUBLIC_ID.fullmatch(identity) or not _DIGEST_PATTERN.fullmatch(digest) for identity, digest in self.source_content_digests)
                or len({item.opaque_id for item in self.items}) != len(self.items)):
            raise ConfiguredSourceError("source inventory is invalid")

    @property
    def inventory_digest(self) -> str:
        return _digest_value(self.payload())

    def payload(self) -> dict[str, object]:
        return {"schema": "roundwright-configured-source-inventory/v1", "profile": SOURCE_INGESTION_PROFILE,
                "candidate_sha": self.binding.candidate_sha, "policy_digest": self.binding.policy_digest,
                "configuration_digest": self.binding.configuration_digest,
                "source_set_digest": self.binding.source_set_digest,
                "source_content_digests": [{"public_identity": identity, "content_digest": digest} for identity, digest in self.source_content_digests],
                "items": [item.payload() for item in self.items]}


@dataclass(frozen=True)
class SelectionDecision:
    opaque_id: str
    state: SelectionState
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class RunnableSelection:
    inventory_digest: str
    graph_digest: str | None
    decisions: tuple[SelectionDecision, ...]
    runnable_ids: tuple[str, ...]


def scan_configured_sources(binding: SourceIngestionBinding, adapter: ConfiguredSourceAdapter) -> SourceInventory:
    """Read exactly the configured finite sources and construct an immutable inventory."""
    if type(binding) is not SourceIngestionBinding or not hasattr(adapter, "read"):
        raise ConfiguredSourceError("source scanner is invalid")
    observations: list[tuple[str, tuple[SourceItem, ...]]] = []
    for source in sorted(binding.configured_sources, key=lambda item: item.public_identity):
        cursor: str | None = None
        seen_cursors: set[str] = set()
        pages = 0
        collected: list[SourceItem] = []
        while True:
            page = adapter.read(source, cursor=cursor)
            if type(page) is not SourcePage or page.source != source or page.requested_cursor != cursor:
                raise ConfiguredSourceError("source adapter identity has drifted")
            pages += 1
            collected.extend(page.items)
            if pages > source.max_pages or len(collected) > source.max_items:
                raise ConfiguredSourceError("configured source bounds exceeded")
            if page.next_cursor is None:
                break
            if page.next_cursor in seen_cursors:
                raise ConfiguredSourceError("configured source cursor is unsafe")
            seen_cursors.add(page.next_cursor)
            cursor = page.next_cursor
        if len({item.public_item_id for item in collected}) != len(collected):
            raise ConfiguredSourceError("configured source repeated an item")
        observations.append((source.public_identity, tuple(collected)))
    return _normalize(binding, tuple(observations))


def _normalize(binding: SourceIngestionBinding, observations: tuple[tuple[str, tuple[SourceItem, ...]], ...]) -> SourceInventory:
    records: list[tuple[str, SourceItem]] = [(identity, item) for identity, items in observations for item in items]
    # Only an exact, independent mechanical identity can merge records.  Same
    # content with different mechanical identities remains explicit ambiguity.
    grouped: dict[str, list[tuple[str, SourceItem]]] = {}
    content_identities: dict[str, set[str]] = {}
    for identity, item in records:
        grouped.setdefault(item.mechanical_identity_digest, []).append((identity, item))
        content_identities.setdefault(item.content_digest, set()).add(item.mechanical_identity_digest)
    normalized: list[NormalizedItem] = []
    for mechanical, group in sorted(grouped.items()):
        items = {item for _, item in group}
        member_ids = {item.member_id for item in items}
        content_digests = {item.content_digest for item in items}
        # A claimed mechanical match that disagrees on either content or graph
        # member is ambiguous rather than silently collapsed.
        ambiguous = len(member_ids) != 1 or len(content_digests) != 1 or len(content_identities[next(iter(content_digests))]) != 1
        for member_id, content_digest in sorted({(item.member_id, item.content_digest) for item in items}):
            opaque_id = _digest_value({"mechanical_identity_digest": mechanical, "member_id": member_id,
                                 "content_digest": content_digest, "source_identities": sorted(identity for identity, item in group if item.member_id == member_id and item.content_digest == content_digest)})
            normalized.append(NormalizedItem(opaque_id, member_id, content_digest, mechanical,
                                              tuple(sorted(identity for identity, item in group if item.member_id == member_id and item.content_digest == content_digest)), ambiguous))
    source_digests = tuple((identity, _digest_value({"items": [item.payload() for item in items]})) for identity, items in observations)
    return SourceInventory(binding, source_digests, tuple(sorted(normalized, key=lambda item: (item.member_id, item.opaque_id))))


def select_runnable_work(inventory: SourceInventory, graph: GraphSnapshot | None, *, unresolved_owner_member_ids: tuple[str, ...] = ()) -> RunnableSelection:
    """Return only independently eligible roots in deterministic topological order.

    A graph is evidence, not an inference source: for multi-source work every
    item must match the current graph exactly.  A graph mismatch blocks the
    affected selection, while unrelated valid roots remain selectable.
    """
    if type(inventory) is not SourceInventory or type(unresolved_owner_member_ids) is not tuple or any(not _TOKEN.fullmatch(value) for value in unresolved_owner_member_ids):
        raise ConfiguredSourceError("runnable selection input is invalid")
    items = {item.member_id: item for item in inventory.items}
    if len(items) != len(inventory.items):
        raise ConfiguredSourceError("normalized graph members are ambiguous")
    blockers: dict[str, set[str]] = {member_id: set() for member_id in items}
    for item in inventory.items:
        if item.ambiguous:
            blockers[item.member_id].add("ambiguous-deduplication")
        if item.member_id in unresolved_owner_member_ids:
            blockers[item.member_id].add("owner-item-unresolved")
    graph_digest: str | None = None
    edges: tuple[tuple[str, str], ...] = ()
    if graph is not None:
        expected_binding = DependencyGraphBinding(inventory.binding.candidate_sha, inventory.binding.policy_digest, inventory.binding.configuration_digest)
        if type(graph) is not GraphSnapshot or graph.binding != expected_binding:
            for member_id in blockers:
                blockers[member_id].add("current-graph-unavailable")
        else:
            graph_digest = graph.graph_digest
        if type(graph) is GraphSnapshot and graph.binding == expected_binding:
            graph_members = {member.member.member_id: member.member.content_digest for member in graph.members}
            for member_id, item in items.items():
                if graph_members.get(member_id) != item.content_digest:
                    blockers[member_id].add("graph-member-unavailable")
            edges = tuple((edge.subject_member_id, edge.object_member_id) for edge in graph.edges)
    elif len(inventory.binding.configured_sources) > 1:
        for member_id in blockers: blockers[member_id].add("current-graph-unavailable")
    if len(inventory.binding.configured_sources) > 1 and graph is not None and graph.binding is None:
        for member_id in blockers: blockers[member_id].add("current-graph-unavailable")
    for subject, dependency in edges:
        if subject in blockers and dependency not in items:
            blockers[subject].add("dependency-outside-inventory")
        if subject in blockers and dependency in blockers and blockers[dependency]:
            blockers[subject].add("dependency-blocked")
        if subject in blockers and dependency in items:
            blockers[subject].add("dependency-not-complete")
    ready_members = sorted(member_id for member_id, reasons in blockers.items() if not reasons)
    decisions = tuple(SelectionDecision(items[member_id].opaque_id, SelectionState.RUNNABLE if not blockers[member_id] else SelectionState.BLOCKED, tuple(sorted(blockers[member_id]))) for member_id in sorted(items))
    return RunnableSelection(inventory.inventory_digest, graph_digest, decisions, tuple(items[member_id].opaque_id for member_id in ready_members))


class ConfiguredSourceStore:
    """Append-only local inventory ledger; scans never overwrite prior evidence."""

    def record(self, repository: RepositoryIdentity, inventory: SourceInventory) -> str:
        if type(inventory) is not SourceInventory:
            raise ConfiguredSourceError("source inventory is invalid")
        payload = json.dumps(inventory.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            connection = _open_writable_connection(repository)
            try:
                existing = connection.execute("SELECT content_json FROM configured_source_inventories WHERE inventory_digest = ?", (inventory.inventory_digest,)).fetchone()
                if existing is None:
                    connection.execute("INSERT INTO configured_source_inventories(inventory_digest, candidate_sha, configuration_digest, source_set_digest, content_json) VALUES (?, ?, ?, ?, ?)", (inventory.inventory_digest, inventory.binding.candidate_sha, inventory.binding.configuration_digest, inventory.binding.source_set_digest, payload))
                elif existing[0] != payload:
                    raise ConfiguredSourceError("source inventory digest has drifted")
                connection.commit()
            finally:
                connection.close()
        except ConfiguredSourceError:
            raise
        except (OSError, sqlite3.DatabaseError):
            raise ConfiguredSourceError("source inventory store is unavailable") from None
        return inventory.inventory_digest

    def read(self, repository: RepositoryIdentity, inventory_digest: str) -> str:
        if not _DIGEST_PATTERN.fullmatch(inventory_digest):
            raise ConfiguredSourceError("source inventory digest is invalid")
        try:
            connection = sqlite3.connect(f"{database_path(repository).resolve().as_uri()}?mode=ro", uri=True)
            try:
                row = connection.execute("SELECT content_json FROM configured_source_inventories WHERE inventory_digest = ?", (inventory_digest,)).fetchone()
            finally:
                connection.close()
        except (OSError, sqlite3.DatabaseError):
            raise ConfiguredSourceError("source inventory store is unavailable") from None
        if row is None or _digest_value(json.loads(row[0])) != inventory_digest:
            raise ConfiguredSourceError("source inventory is unavailable")
        return row[0]


def _digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
