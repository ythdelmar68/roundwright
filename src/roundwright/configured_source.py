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
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from .configuration import ConfigurationError, RepositoryIdentity, ResolvedConfigurationBinding
from .dependency_graph import DependencyGraphBinding, DependencyGraphStore, GraphSnapshot
from .github import GitHubReadOperation, GitHubReadRequest, IssueSnapshot, RepositoryRef
from .github_runtime import (
    CredentialedGitHubReadCapabilityBinding, OwnerGitHubReadIpcClient,
    credentialed_github_read_capability_binding,
    credentialed_github_read_capability_identity,
)
from .review_lifecycle import (
    OwnerBlockerStateReceipt, ReviewLifecycleError, owner_blocker_state_receipt,
)
from .shadow import CONFIGURED_SOURCE_INGESTION_PROFILE, shadow_evidence_profile
from .state import _open_writable_connection, database_path


_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_PUBLIC_ID = re.compile(r"[a-z][a-z0-9._/-]{0,255}\Z")
_CURSOR = re.compile(r"[A-Za-z0-9._~-]{1,256}\Z")
SOURCE_INGESTION_PROFILE = CONFIGURED_SOURCE_INGESTION_PROFILE
CONFIGURED_SOURCE_EVIDENCE_SCHEMA = "roundwright-configured-source-evidence/v1"
CONFIGURED_SOURCE_EXECUTION_CONTEXT_SCHEMA = "roundwright-configured-source-ingestion-context/v1"


class ConfiguredSourceError(ValueError):
    """Raised when source evidence or selection input is not trustworthy."""


class SourceType(StrEnum):
    ISSUE_LIST = "issue-list"
    TASK_FEED = "task-feed"


class SelectionState(StrEnum):
    RUNNABLE = "runnable"
    BLOCKED = "blocked"


class GraphApplicability(StrEnum):
    """Whether this closed source selection has a dependency-graph lane."""

    NOT_APPLICABLE = "not-applicable"
    REQUIRED = "required"


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


_CONFIGURED_SOURCE_AUTHORITY_SEAL = object()
_CONFIGURED_SOURCE_CAPABILITY_SEAL = object()
_CONFIGURED_SOURCE_ENDPOINT_SEAL = object()
_OWNER_BLOCKER_STATE_SEAL = object()


@dataclass(frozen=True)
class IssueListReadHost:
    """Factory-sealed ISSUE_LIST endpoint over the owner GitHub read boundary."""

    read_capability: OwnerGitHubReadIpcClient = field(repr=False, compare=False)
    endpoint_identity: str = ""
    binding_receipt: CredentialedGitHubReadCapabilityBinding | None = field(repr=False, compare=False, default=None)
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if (
            self._seal is not _CONFIGURED_SOURCE_ENDPOINT_SEAL
            or not isinstance(self.read_capability, OwnerGitHubReadIpcClient)
            or type(self.binding_receipt) is not CredentialedGitHubReadCapabilityBinding
            or not _DIGEST_PATTERN.fullmatch(self.endpoint_identity)
        ):
            raise ConfiguredSourceError("issue-list read host is invalid")

    def read_page(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage:
        parsed = _issue_list_identity(source)
        if cursor is not None or parsed is None:
            raise ConfiguredSourceError("configured issue-list request is invalid")
        repository, number = parsed
        result = self.read_capability.read(GitHubReadRequest(GitHubReadOperation.ISSUE, repository, number=number))
        if not result.ok or type(result.snapshot) is not IssueSnapshot:
            raise ConfiguredSourceError("configured issue-list read is unavailable")
        issue = result.snapshot
        if issue.repository != repository or issue.number != number:
            raise ConfiguredSourceError("configured issue-list response has drifted")
        item = SourceItem(
            f"issue-{issue.number}", f"issue-{issue.number}",
            _digest_value({"issue_evidence": issue.issue_evidence_identity, "relationship_evidence": issue.relationship_evidence_identity, "state": issue.state.value}),
            _digest_value({"repository": issue.repository.slug, "issue_id": issue.issue_id, "number": issue.number}),
        )
        return SourcePage(source, None, None, (item,))


@dataclass(frozen=True)
class TaskFeedReadHost:
    """Factory-sealed TASK_FEED endpoint with no command or discovery surface."""

    read_capability: "TaskFeedReadIpcClient" = field(repr=False, compare=False)
    endpoint_identity: str = ""
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._seal is not _CONFIGURED_SOURCE_ENDPOINT_SEAL or type(self.read_capability) is not TaskFeedReadIpcClient or self.endpoint_identity != self.read_capability.endpoint_identity:
            raise ConfiguredSourceError("task-feed read host is invalid")
    def read_page(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage:
        return self.read_capability.read_page(source, cursor=cursor)


class _TaskFeedOwnerEndpoint:
    """Owner-only typed IPC endpoint; it is never a public callback seam."""

    def __init__(self, pages: Mapping[tuple[str, str | None], SourcePage]) -> None:
        if type(pages) is not dict or any(type(key) is not tuple or len(key) != 2 or type(key[0]) is not str or (key[1] is not None and type(key[1]) is not str) or type(value) is not SourcePage for key, value in pages.items()):
            raise ConfiguredSourceError("task-feed owner IPC endpoint is invalid")
        self._pages = dict(pages)
        self.identity = _digest_value({
            "schema": "roundwright-configured-source-task-feed-ipc/v1",
            "pages": [
                {"source": key[0], "cursor": key[1], "page": {
                    "source": value.source.payload(), "requested_cursor": value.requested_cursor,
                    "next_cursor": value.next_cursor, "items": [item.payload() for item in value.items],
                }}
                for key, value in sorted(self._pages.items(), key=lambda item: (item[0][0], item[0][1] or ""))
            ],
        })
        self.calls = 0

    def exchange_page(self, source: ConfiguredSource, cursor: str | None) -> SourcePage:
        self.calls += 1
        try:
            return self._pages[(source.public_identity, cursor)]
        except KeyError as error:
            raise ConfiguredSourceError("task-feed IPC page is unavailable") from error


class TaskFeedReadIpcClient:
    """Minimal sealed TASK_FEED IPC client; no commands or provider surface."""

    __slots__ = ("__endpoint", "endpoint_identity")

    def __init__(self, endpoint: _TaskFeedOwnerEndpoint, seal: object) -> None:
        if type(endpoint) is not _TaskFeedOwnerEndpoint or seal is not _CONFIGURED_SOURCE_ENDPOINT_SEAL:
            raise ConfiguredSourceError("task-feed IPC capability is invalid")
        self.__endpoint = endpoint
        self.endpoint_identity = endpoint.identity

    def read_page(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage:
        if type(source) is not ConfiguredSource or source.source_type is not SourceType.TASK_FEED:
            raise ConfiguredSourceError("task-feed IPC request is invalid")
        return self.__endpoint.exchange_page(source, cursor)

    @property
    def source_read_count(self) -> int:
        return self.__endpoint.calls


def _create_task_feed_fixture_capability(pages: Mapping[tuple[str, str | None], SourcePage]) -> TaskFeedReadIpcClient:
    """Internal hermetic owner-endpoint fixture; not a production callback API."""

    return TaskFeedReadIpcClient(_TaskFeedOwnerEndpoint(pages), _CONFIGURED_SOURCE_ENDPOINT_SEAL)


def create_issue_list_read_host(read_capability: OwnerGitHubReadIpcClient) -> IssueListReadHost:
    """Seal one typed ISSUE_LIST page endpoint owned by the host factory.

    It consumes only the existing credentialed GitHub IPC capability; callers
    cannot supply a callback, endpoint name, implementation digest, or query.
    """

    identity = credentialed_github_read_capability_identity(read_capability)
    receipt = credentialed_github_read_capability_binding(read_capability)
    if (
        identity is None or type(receipt) is not CredentialedGitHubReadCapabilityBinding
        or receipt.capability_identity != identity
    ):
        raise ConfiguredSourceError("issue-list requires a credentialed owner read capability")
    return IssueListReadHost(read_capability, _digest_value({
        "schema": "roundwright-configured-source-issue-list-endpoint/v1",
        "credentialed_read_identity": identity,
        "credentialed_binding_receipt": receipt.receipt_identity,
        "operation": GitHubReadOperation.ISSUE.value,
    }), receipt, _CONFIGURED_SOURCE_ENDPOINT_SEAL)


def create_task_feed_read_host(read_capability: TaskFeedReadIpcClient) -> TaskFeedReadHost:
    """Seal the minimal typed TASK_FEED page endpoint."""

    if type(read_capability) is not TaskFeedReadIpcClient:
        raise ConfiguredSourceError("task-feed requires a sealed owner IPC capability")
    return TaskFeedReadHost(read_capability, read_capability.endpoint_identity, _CONFIGURED_SOURCE_ENDPOINT_SEAL)


def _issue_list_identity(source: ConfiguredSource) -> tuple[RepositoryRef, int] | None:
    """Parse the fixed public ``owner/repository/issue/number`` source form."""

    if type(source) is not ConfiguredSource or source.source_type is not SourceType.ISSUE_LIST:
        return None
    try:
        owner, name, kind, raw_number = source.public_identity.split("/")
        if kind != "issue" or not raw_number.isdecimal():
            raise ValueError
        return RepositoryRef(owner, name), int(raw_number)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class ConfiguredSourceAuthority:
    """Factory-sealed receipt for the resolved source configuration and graph."""

    binding: SourceIngestionBinding
    graph_applicability: GraphApplicability
    graph: GraphSnapshot | None
    configuration_receipt_identity: str
    graph_receipt_identity: str
    authority_identity: str
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        expected = DependencyGraphBinding(
            self.binding.candidate_sha, self.binding.policy_digest, self.binding.configuration_digest,
        ) if type(self.binding) is SourceIngestionBinding else None
        expected_configuration = _digest_value({
            "schema": "roundwright-configured-source-configuration-receipt/v1",
            "candidate_sha": self.binding.candidate_sha,
            "policy_digest": self.binding.policy_digest,
            "configuration_digest": self.binding.configuration_digest,
            "source_set_digest": self.binding.source_set_digest,
        }) if expected is not None else ""
        applicability = _graph_applicability(self.binding) if type(self.binding) is SourceIngestionBinding else None
        expected_graph = _digest_value({
            "schema": "roundwright-configured-source-accepted-graph-receipt/v1",
            "configuration_receipt_identity": expected_configuration,
            "applicability": applicability.value if applicability is not None else None,
            "graph_version_id": self.graph.graph_version_id if type(self.graph) is GraphSnapshot else None,
            "graph_digest": self.graph.graph_digest if type(self.graph) is GraphSnapshot else None,
        }) if expected is not None else ""
        expected_authority = _digest_value({
            "schema": "roundwright-configured-source-authority/v1",
            "configuration_receipt_identity": expected_configuration,
            "graph_receipt_identity": expected_graph,
        }) if expected is not None else ""
        if (
            self._seal is not _CONFIGURED_SOURCE_AUTHORITY_SEAL
            or type(self.binding) is not SourceIngestionBinding or self.graph_applicability is not applicability
            or (applicability is GraphApplicability.NOT_APPLICABLE and self.graph is not None)
            or (applicability is GraphApplicability.REQUIRED and (type(self.graph) is not GraphSnapshot or self.graph.binding != expected or self.graph.graph_version_id is None))
            or (self.configuration_receipt_identity, self.graph_receipt_identity, self.authority_identity)
            != (expected_configuration, expected_graph, expected_authority)
        ):
            raise ConfiguredSourceError("configured source authority is invalid")


def _seal_configured_source_authority(
    binding: SourceIngestionBinding, graph: GraphSnapshot | None = None,
) -> ConfiguredSourceAuthority:
    """Internal constructor for a graph that has already been read back."""

    expected = DependencyGraphBinding(
        binding.candidate_sha, binding.policy_digest, binding.configuration_digest,
    ) if type(binding) is SourceIngestionBinding else None
    applicability = _graph_applicability(binding) if type(binding) is SourceIngestionBinding else None
    if (
        type(binding) is not SourceIngestionBinding or applicability is None
        or (applicability is GraphApplicability.NOT_APPLICABLE and graph is not None)
        or (applicability is GraphApplicability.REQUIRED and (type(graph) is not GraphSnapshot or graph.binding != expected or graph.graph_version_id is None))
    ):
        raise ConfiguredSourceError("configured source authority inputs are invalid")
    configuration = _digest_value({
        "schema": "roundwright-configured-source-configuration-receipt/v1",
        "candidate_sha": binding.candidate_sha, "policy_digest": binding.policy_digest,
        "configuration_digest": binding.configuration_digest, "source_set_digest": binding.source_set_digest,
    })
    graph_receipt = _digest_value({
        "schema": "roundwright-configured-source-accepted-graph-receipt/v1",
        "configuration_receipt_identity": configuration,
        "applicability": applicability.value,
        "graph_version_id": graph.graph_version_id if graph is not None else None,
        "graph_digest": graph.graph_digest if graph is not None else None,
    })
    authority = _digest_value({
        "schema": "roundwright-configured-source-authority/v1",
        "configuration_receipt_identity": configuration, "graph_receipt_identity": graph_receipt,
    })
    return ConfiguredSourceAuthority(binding, applicability, graph, configuration, graph_receipt, authority, _CONFIGURED_SOURCE_AUTHORITY_SEAL)


def resolve_source_ingestion_binding(
    configuration: ResolvedConfigurationBinding, candidate_sha: str,
) -> "SourceIngestionBinding":
    """Derive the only production source binding from resolved material."""

    if type(configuration) is not ResolvedConfigurationBinding or not _SHA.fullmatch(candidate_sha):
        raise ConfiguredSourceError("configured source resolved inputs are invalid")
    try:
        sources = tuple(ConfiguredSource(
            SourceType(item["source_type"]), item["public_identity"], item["max_pages"], item["max_items"],
        ) for item in configuration.configured_source_allowlist())
    except (ConfigurationError, KeyError, TypeError, ValueError) as error:
        raise ConfiguredSourceError("configured source allowlist is invalid") from error
    if not sources:
        raise ConfiguredSourceError("configured source allowlist is empty")
    return SourceIngestionBinding(
        candidate_sha, "sha256:" + configuration.runtime_binding().review_policy_digest,
        configuration.digest, sources,
    )


def resolve_configured_source_authority(
    repository: RepositoryIdentity, configuration: ResolvedConfigurationBinding,
    candidate_sha: str,
) -> ConfiguredSourceAuthority:
    """Read the accepted graph only through the durable product boundaries.

    Callers cannot supply a graph snapshot.  The source binding must agree
    with the independently resolved configuration before the durable #114
    graph is read and replay-verified by :class:`DependencyGraphStore`.
    """

    if (
        type(repository) is not RepositoryIdentity or type(configuration) is not ResolvedConfigurationBinding
        or not _SHA.fullmatch(candidate_sha)
    ):
        raise ConfiguredSourceError("configured source authoritative inputs are invalid")
    binding = resolve_source_ingestion_binding(configuration, candidate_sha)
    if _graph_applicability(binding) is GraphApplicability.NOT_APPLICABLE:
        return _seal_configured_source_authority(binding)
    graph_binding = DependencyGraphBinding(binding.candidate_sha, binding.policy_digest, binding.configuration_digest)
    try:
        graph = DependencyGraphStore().current(repository, binding=graph_binding)
    except Exception as error:
        raise ConfiguredSourceError("configured source accepted graph is unavailable") from error
    return _seal_configured_source_authority(binding, graph)


@dataclass(frozen=True)
class ConfiguredSourceReadCapability:
    """Factory-sealed read-only capability, with no provider command surface."""

    binding: SourceIngestionBinding
    authority_identity: str
    capability_identity: str
    issue_list: IssueListReadHost | None
    task_feed: TaskFeedReadHost | None
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        required = {source.source_type for source in self.binding.configured_sources} if type(self.binding) is SourceIngestionBinding else set()
        expected_identity = _digest_value({
            "schema": "roundwright-configured-source-owner-read-capability/v1",
            "authority_identity": self.authority_identity,
            "issue_list_endpoint": None if self.issue_list is None else self.issue_list.endpoint_identity,
            "task_feed_endpoint": None if self.task_feed is None else self.task_feed.endpoint_identity,
        })
        if (
            self._seal is not _CONFIGURED_SOURCE_CAPABILITY_SEAL or type(self.binding) is not SourceIngestionBinding
            or not _DIGEST_PATTERN.fullmatch(self.authority_identity)
            or self.capability_identity != expected_identity
            or (SourceType.ISSUE_LIST in required) != (type(self.issue_list) is IssueListReadHost)
            or (SourceType.TASK_FEED in required) != (type(self.task_feed) is TaskFeedReadHost)
            or (SourceType.ISSUE_LIST not in required and self.issue_list is not None)
            or (SourceType.TASK_FEED not in required and self.task_feed is not None)
        ):
            raise ConfiguredSourceError("configured source read capability is invalid")

    def read(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage:
        if type(source) is not ConfiguredSource or source not in self.binding.configured_sources:
            raise ConfiguredSourceError("configured source is outside the trusted allowlist")
        reader = self.issue_list if source.source_type is SourceType.ISSUE_LIST else self.task_feed
        if reader is None:
            raise ConfiguredSourceError("configured source reader is unavailable")
        page = reader.read_page(source, cursor=cursor)
        if type(page) is not SourcePage or page.source != source or page.requested_cursor != cursor:
            raise ConfiguredSourceError("configured source capability has drifted")
        return page


def create_configured_source_read_capability(
    authority: ConfiguredSourceAuthority, *, task_id: str | None = None,
    issue_list: IssueListReadHost | None = None, task_feed: TaskFeedReadHost | None = None,
) -> ConfiguredSourceReadCapability:
    """Bind an owner-resolved typed source capability to exact source bounds.

    The constructor accepts only typed page readers; credentials, raw payloads,
    provider commands, and mutation surfaces remain outside this product seam.
    """

    if type(authority) is not ConfiguredSourceAuthority:
        raise ConfiguredSourceError("configured source capability inputs are invalid")
    issue_sources = tuple(source for source in authority.binding.configured_sources if source.source_type is SourceType.ISSUE_LIST)
    if issue_sources:
        if type(task_id) is not str or not _TOKEN.fullmatch(task_id) or type(issue_list) is not IssueListReadHost:
            raise ConfiguredSourceError("configured source issue-list binding is invalid")
        parsed = tuple(_issue_list_identity(source) for source in issue_sources)
        if any(value is None for value in parsed):
            raise ConfiguredSourceError("configured source issue-list identity is invalid")
        repositories = {value[0].slug for value in parsed if value is not None}
        receipt = issue_list.binding_receipt
        if (
            len(repositories) != 1
            or type(receipt) is not CredentialedGitHubReadCapabilityBinding
            or receipt.repository not in repositories
            or receipt.task_id != task_id
            or receipt.candidate_sha != authority.binding.candidate_sha
        ):
            raise ConfiguredSourceError("configured source issue-list binding has drifted")
    elif task_id is not None and (type(task_id) is not str or not _TOKEN.fullmatch(task_id)):
        raise ConfiguredSourceError("configured source task identity is invalid")
    capability_identity = _digest_value({
        "schema": "roundwright-configured-source-owner-read-capability/v1",
        "authority_identity": authority.authority_identity,
        "issue_list_endpoint": None if issue_list is None else issue_list.endpoint_identity,
        "task_feed_endpoint": None if task_feed is None else task_feed.endpoint_identity,
    })
    return ConfiguredSourceReadCapability(
        authority.binding, authority.authority_identity, capability_identity, issue_list, task_feed, _CONFIGURED_SOURCE_CAPABILITY_SEAL,
    )


class TrustedConfiguredSourceReadHost:
    """Concrete, typed, read-only host for the closed configured-source set.

    This is intentionally not a structural provider protocol.  The host owns
    the exact allowlist, query/cursor contract, and the only two typed read
    capabilities.  It exposes no mutation or provider-discovery operation.
    """

    def __init__(
        self,
        authority: ConfiguredSourceAuthority, capability: ConfiguredSourceReadCapability,
    ) -> None:
        if type(authority) is not ConfiguredSourceAuthority or type(capability) is not ConfiguredSourceReadCapability or capability.binding != authority.binding or capability.authority_identity != authority.authority_identity:
            raise ConfiguredSourceError("trusted configured-source readers are invalid")
        self._authority = authority
        self._capability = capability

    @property
    def binding(self) -> SourceIngestionBinding:
        return self._authority.binding

    @property
    def authority_identity(self) -> str:
        return self._authority.authority_identity

    @property
    def query_identity(self) -> str:
        return _digest_value({
            "schema": "roundwright-configured-source-read-host/v1",
            "authority_identity": self._authority.authority_identity,
            "capability_identity": self._capability.capability_identity,
            "source_set_digest": self.binding.source_set_digest,
            "queries": [
                {"source": source.payload(), "cursor_contract": "bounded-opaque-cursor/v1"}
                for source in sorted(self.binding.configured_sources, key=lambda value: value.public_identity)
            ],
        })

    def read(self, source: ConfiguredSource, *, cursor: str | None) -> SourcePage:
        return self._capability.read(source, cursor=cursor)

    def scan(self) -> SourceInventory:
        return scan_configured_sources(self.binding, self)


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


def _graph_applicability(binding: SourceIngestionBinding) -> GraphApplicability:
    """A graph is meaningful only when selection joins multiple sources."""

    if type(binding) is not SourceIngestionBinding:
        raise ConfiguredSourceError("source ingestion binding is invalid")
    return GraphApplicability.NOT_APPLICABLE if len(binding.configured_sources) == 1 else GraphApplicability.REQUIRED


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
            # A continuation after the final authorized page is a rejection,
            # never permission to over-read one extra provider page.
            if pages == source.max_pages:
                raise ConfiguredSourceError("configured source bounds exceeded")
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


def select_runnable_work(
    inventory: SourceInventory, graph: GraphSnapshot | None, *, owner_blockers_pending: bool = False,
) -> RunnableSelection:
    """Return only independently eligible roots in deterministic topological order.

    A graph is evidence, not an inference source: for multi-source work every
    item must match the current graph exactly.  A graph mismatch blocks the
    affected selection, while unrelated valid roots remain selectable.
    """
    if type(inventory) is not SourceInventory or type(owner_blockers_pending) is not bool:
        raise ConfiguredSourceError("runnable selection input is invalid")
    by_member: dict[str, list[NormalizedItem]] = {}
    for item in inventory.items:
        by_member.setdefault(item.member_id, []).append(item)
    items = {item.opaque_id: item for item in inventory.items}
    blockers: dict[str, set[str]] = {opaque_id: set() for opaque_id in items}
    for item in inventory.items:
        if item.ambiguous:
            blockers[item.opaque_id].add("ambiguous-deduplication")
        if len(by_member[item.member_id]) > 1:
            blockers[item.opaque_id].add("member-identity-ambiguous")
        if owner_blockers_pending:
            blockers[item.opaque_id].add("owner-item-unresolved")
    graph_digest: str | None = None
    edges: tuple[tuple[str, str], ...] = ()
    if graph is not None:
        expected_binding = DependencyGraphBinding(inventory.binding.candidate_sha, inventory.binding.policy_digest, inventory.binding.configuration_digest)
        if type(graph) is not GraphSnapshot or graph.binding != expected_binding:
            for opaque_id in blockers:
                blockers[opaque_id].add("current-graph-unavailable")
        else:
            graph_digest = graph.graph_digest
        if type(graph) is GraphSnapshot and graph.binding == expected_binding:
            graph_members = {member.member.member_id: member.member.content_digest for member in graph.members}
            for opaque_id, item in items.items():
                if graph_members.get(item.member_id) != item.content_digest:
                    blockers[opaque_id].add("graph-member-unavailable")
            edges = tuple((edge.subject_member_id, edge.object_member_id) for edge in graph.edges)
    elif len(inventory.binding.configured_sources) > 1:
        for opaque_id in blockers: blockers[opaque_id].add("current-graph-unavailable")
    if len(inventory.binding.configured_sources) > 1 and graph is not None and graph.binding is None:
        for opaque_id in blockers: blockers[opaque_id].add("current-graph-unavailable")
    for subject, dependency in edges:
        subjects, dependencies = by_member.get(subject, ()), by_member.get(dependency, ())
        for item in subjects:
            if not dependencies:
                blockers[item.opaque_id].add("dependency-outside-inventory")
            else:
                if any(blockers[dependency_item.opaque_id] for dependency_item in dependencies):
                    blockers[item.opaque_id].add("dependency-blocked")
                blockers[item.opaque_id].add("dependency-not-complete")
    ready = sorted(opaque_id for opaque_id, reasons in blockers.items() if not reasons)
    decisions = tuple(SelectionDecision(opaque_id, SelectionState.RUNNABLE if not blockers[opaque_id] else SelectionState.BLOCKED, tuple(sorted(blockers[opaque_id]))) for opaque_id in sorted(items))
    return RunnableSelection(inventory.inventory_digest, graph_digest, decisions, tuple(ready))


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


class OwnerBlockerStateReadHost:
    """Factory-sealed canonical owner-blocker state boundary."""

    __slots__ = ("__repository", "__task_id", "__candidate_sha", "__receipt")

    def __init__(
        self, repository: RepositoryIdentity, task_id: str, candidate_sha: str,
        receipt: OwnerBlockerStateReceipt, seal: object,
    ) -> None:
        if (
            seal is not _OWNER_BLOCKER_STATE_SEAL or type(repository) is not RepositoryIdentity
            or type(receipt) is not OwnerBlockerStateReceipt
            or receipt.task_id != task_id or receipt.candidate_sha != candidate_sha
        ):
            raise ConfiguredSourceError("configured source owner-blocker host is invalid")
        self.__repository = repository
        self.__task_id = task_id
        self.__candidate_sha = candidate_sha
        self.__receipt = receipt

    @property
    def receipt(self) -> OwnerBlockerStateReceipt:
        return self.__receipt

    def current(self) -> OwnerBlockerStateReceipt:
        current = _owner_blocker_state_receipt(
            self.__repository, self.__task_id, self.__candidate_sha,
        )
        if current != self.__receipt:
            raise ConfiguredSourceError("configured source owner-blocker state has drifted")
        return current


def _owner_blocker_state_receipt(
    repository: RepositoryIdentity, task_id: str, candidate_sha: str,
) -> OwnerBlockerStateReceipt:
    """Read the canonical task-scoped owner-blocker receipt without mutation."""

    try:
        connection = sqlite3.connect(f"{database_path(repository).resolve().as_uri()}?mode=ro", uri=True)
        try:
            return owner_blocker_state_receipt(connection, task_id, candidate_sha)
        finally:
            connection.close()
    except (OSError, sqlite3.DatabaseError, ReviewLifecycleError) as error:
        raise ConfiguredSourceError("configured source owner-blocker state is unavailable") from error


def _create_owner_blocker_state_read_host(
    repository: RepositoryIdentity, task_id: str, candidate_sha: str,
) -> OwnerBlockerStateReadHost:
    receipt = _owner_blocker_state_receipt(repository, task_id, candidate_sha)
    return OwnerBlockerStateReadHost(
        repository, task_id, candidate_sha, receipt, _OWNER_BLOCKER_STATE_SEAL,
    )


def _digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _materialize_json(value: object) -> object:
    """Canonicalize the Harness V2 immutable JSON view for local comparison."""

    if isinstance(value, Mapping):
        return {str(key): _materialize_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_materialize_json(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ConfiguredSourceError("configured source execution context is not JSON")


# These identities are part of the selected profile contract.  They are not
# loaded from a source configuration or an adapter, so neither can widen the
# capture surface.
CONFIGURED_SOURCE_PRODUCER_IDENTITY = _digest_value(
    {"schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA, "component": "typed-read-only-configured-source-reader"}
)
CONFIGURED_SOURCE_EXPORTER_IDENTITY = _digest_value(
    {"schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA, "component": "public-safe-normalized-inventory-exporter"}
)
CONFIGURED_SOURCE_COMPARATOR_IDENTITY = _digest_value(
    {"schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA, "component": "capture-time-configured-source-comparator"}
)


def configured_source_component_identities() -> tuple[str, str, str]:
    """Return the exact producer/exporter/comparator identities for #117."""

    return (
        CONFIGURED_SOURCE_PRODUCER_IDENTITY,
        CONFIGURED_SOURCE_EXPORTER_IDENTITY,
        CONFIGURED_SOURCE_COMPARATOR_IDENTITY,
    )


@dataclass(frozen=True)
class ConfiguredSourceHostInputs:
    """Typed product inputs for one future live, read-only observation.

    Construction binds only public configuration, graph, and time facts.  The
    adapter is deliberately not called until a reviewed Harness executes the
    profile; this makes validate mode incapable of opening a source read.
    """

    base_sha: str
    authority: ConfiguredSourceAuthority
    case_id: str
    ready_at: int
    read_host: TrustedConfiguredSourceReadHost
    recorder_identity: str
    store_identity: str
    owner_blockers_pending: bool
    owner_blocker_receipt: OwnerBlockerStateReceipt
    owner_blocker_read_host: OwnerBlockerStateReadHost = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            not _SHA.fullmatch(self.base_sha) or type(self.authority) is not ConfiguredSourceAuthority
            or not _TOKEN.fullmatch(self.case_id) or type(self.ready_at) is not int or self.ready_at < 0
            or type(self.read_host) is not TrustedConfiguredSourceReadHost or self.read_host.binding != self.authority.binding
            or self.read_host.authority_identity != self.authority.authority_identity
            or not _DIGEST_PATTERN.fullmatch(self.recorder_identity) or not _DIGEST_PATTERN.fullmatch(self.store_identity)
            or type(self.owner_blockers_pending) is not bool
            or type(self.owner_blocker_receipt) is not OwnerBlockerStateReceipt
            or type(self.owner_blocker_read_host) is not OwnerBlockerStateReadHost
            or self.owner_blocker_receipt.candidate_sha != self.authority.binding.candidate_sha
            or self.owner_blocker_receipt.blockers_pending != self.owner_blockers_pending
            or self.owner_blocker_read_host.receipt != self.owner_blocker_receipt
        ):
            raise ConfiguredSourceError("configured source host inputs are invalid")
        # This lookup also proves that the profile is registered with the
        # immutable Shadow capture-readiness registry.
        if shadow_evidence_profile(SOURCE_INGESTION_PROFILE).capture_mode.value != "terminal-snapshot":
            raise ConfiguredSourceError("configured source profile is unavailable")

    @property
    def binding(self) -> SourceIngestionBinding:
        return self.authority.binding

    @property
    def graph(self) -> GraphSnapshot | None:
        return self.authority.graph

    @property
    def observation_identity(self) -> str:
        return _digest_value({
            "schema": "roundwright-configured-source-observation/v1",
            "descriptor": self.observation_descriptor(),
        })

    def observation_descriptor(self) -> dict[str, object]:
        return {
            "schema": CONFIGURED_SOURCE_EXECUTION_CONTEXT_SCHEMA,
            "base_sha": self.base_sha,
            "candidate_sha": self.binding.candidate_sha,
            "policy_digest": self.binding.policy_digest,
            "configuration_digest": self.binding.configuration_digest,
            "configured_sources": [source.payload() for source in sorted(self.binding.configured_sources, key=lambda item: item.public_identity)],
            "source_set_digest": self.binding.source_set_digest,
            "configuration_receipt_identity": self.authority.configuration_receipt_identity,
            "graph_receipt_identity": self.authority.graph_receipt_identity,
            "graph_applicability": self.authority.graph_applicability.value,
            "authority_identity": self.authority.authority_identity,
            "trusted_query_identity": self.read_host.query_identity,
            "graph_digest": None if self.graph is None else self.graph.graph_digest,
            "case_id": self.case_id,
            "ready_at": self.ready_at,
            "recorder_identity": self.recorder_identity,
            "store_identity": self.store_identity,
            "owner_blockers_pending": self.owner_blockers_pending,
            "owner_blocker_state_receipt": self.owner_blocker_receipt.receipt_identity,
        }

    def execution_context(self, capture_plan_digest: str) -> dict[str, object]:
        if not _DIGEST_PATTERN.fullmatch(capture_plan_digest):
            raise ConfiguredSourceError("configured source capture plan identity is invalid")
        return {
            **self.observation_descriptor(),
            "capture_plan_digest": capture_plan_digest,
        }

    def verify_owner_blocker_state(self) -> None:
        """Deny execution when the current canonical owner state moved."""

        current = self.owner_blocker_read_host.current()
        if current != self.owner_blocker_receipt:
            raise ConfiguredSourceError("configured source owner-blocker state has drifted")


@dataclass(frozen=True)
class ConfiguredSourceExecution:
    inventory: SourceInventory
    selection: RunnableSelection

    def __post_init__(self) -> None:
        if type(self.inventory) is not SourceInventory or type(self.selection) is not RunnableSelection or self.selection.inventory_digest != self.inventory.inventory_digest:
            raise ConfiguredSourceError("configured source execution is invalid")


def configured_source_capture_plan(inputs: ConfiguredSourceHostInputs) -> dict[str, object]:
    """Construct the sole public V2 capture-plan input for the selected lane."""

    if type(inputs) is not ConfiguredSourceHostInputs:
        raise ConfiguredSourceError("configured source host inputs are invalid")
    producer, exporter, comparator = configured_source_component_identities()
    return {
        "schema": "roundwright-harness-capture-plan/v1",
        "profile": SOURCE_INGESTION_PROFILE,
        "case_id": inputs.case_id,
        "candidate_sha": inputs.binding.candidate_sha,
        "ready_at": inputs.ready_at,
        "producer_identity": producer,
        "exporter_identity": exporter,
        "comparator_identity": comparator,
        "recorder_identity": inputs.recorder_identity,
        "store_identity": inputs.store_identity,
        "observation_identity": inputs.observation_identity,
    }


def configured_source_executor_request(inputs: ConfiguredSourceHostInputs) -> dict[str, object]:
    """Close a V2 request in two acyclic phases before any source read.

    The observation identity is derived only from stable host facts.  Harness
    then derives the plan digest, which is bound into the execution context.
    The resulting request has no self-referential digest dependency.
    """

    if type(inputs) is not ConfiguredSourceHostInputs:
        raise ConfiguredSourceError("configured source host inputs are invalid")
    from .external_validation import _harness_executor
    capture_plan = configured_source_capture_plan(inputs)
    plan = _harness_executor().prepare_capture(capture_plan)
    return {
        "schema": "roundwright-harness-profile-executor-request/v2",
        "capture_plan": capture_plan,
        "execution_context": inputs.execution_context(plan.plan_digest),
    }


def prepare_configured_source_ingestion(
    repository: RepositoryIdentity, configuration: ResolvedConfigurationBinding,
    candidate_sha: str, base_sha: str, case_id: str, ready_at: int,
    recorder_identity: str, store_identity: str, task_id: str, *,
    issue_list: IssueListReadHost | None = None,
    task_feed: TaskFeedReadHost | None = None,
) -> tuple[ConfiguredSourceHostInputs, dict[str, object]]:
    """Prepare #117's sole host inputs and V2 request from closed authority.

    The durable graph is resolved through ``DependencyGraphStore.current``;
    source lists, graph snapshots, readers, endpoint identities, and Harness
    bindings are deliberately absent from this public production interface.
    """

    if not _TOKEN.fullmatch(task_id):
        raise ConfiguredSourceError("configured source task identity is invalid")
    authority = resolve_configured_source_authority(repository, configuration, candidate_sha)
    capability = create_configured_source_read_capability(
        authority, task_id=task_id, issue_list=issue_list, task_feed=task_feed,
    )
    owner_blocker_host = _create_owner_blocker_state_read_host(repository, task_id, candidate_sha)
    inputs = ConfiguredSourceHostInputs(
        base_sha, authority, case_id, ready_at,
        TrustedConfiguredSourceReadHost(authority, capability),
        recorder_identity, store_identity, owner_blocker_host.receipt.blockers_pending,
        owner_blocker_host.receipt, owner_blocker_host,
    )
    return inputs, configured_source_executor_request(inputs)


def _configured_source_binding_identity(binding: object) -> str:
    try:
        value = {
            "schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA, "profile": binding.profile,
            "case_id": binding.case_id, "candidate_sha": binding.candidate_sha,
            "ready_at": binding.ready_at, "capture_plan_digest": binding.plan.plan_digest,
        }
    except AttributeError as error:
        raise ConfiguredSourceError("configured source executor binding is invalid") from error
    if (
        value["profile"] != SOURCE_INGESTION_PROFILE or not _TOKEN.fullmatch(value["case_id"])
        or not _SHA.fullmatch(value["candidate_sha"]) or type(value["ready_at"]) is not int or value["ready_at"] < 0
        or not _DIGEST_PATTERN.fullmatch(value["capture_plan_digest"])
    ):
        raise ConfiguredSourceError("configured source executor binding is invalid")
    return _digest_value(value)


def _source_execution_context(binding: object, inputs: ConfiguredSourceHostInputs) -> ConfiguredSourceHostInputs:
    try:
        context = binding.execution_context
        value = context.value
        input_digest = binding.execution_context_input_digest
        plan = binding.plan
    except AttributeError as error:
        raise ConfiguredSourceError("configured source execution context is unavailable") from error
    if (
        type(value) is not ConfiguredSourceHostInputs or value != inputs
        or context.identity != _digest_value({
            "observation_identity": inputs.observation_identity,
            "capture_plan_digest": plan.plan_digest,
            "execution_context_input_digest": input_digest,
        })
        or input_digest != _digest_value(inputs.execution_context(plan.plan_digest))
        or (plan.candidate_sha, plan.case_id, plan.plan_digest, plan.ready_at)
        != (inputs.binding.candidate_sha, inputs.case_id, plan.plan_digest, inputs.ready_at)
    ):
        raise ConfiguredSourceError("configured source execution context has drifted")
    return value


def configured_source_evidence(
    binding: object, execution: ConfiguredSourceExecution,
) -> dict[str, object]:
    """Export only the selected lane's public-safe terminal projection."""

    identity = _configured_source_binding_identity(binding)
    inventory, selection = execution.inventory, execution.selection
    decisions = [
        {"opaque_id": item.opaque_id, "state": item.state.value, "blockers": list(item.blockers)}
        for item in selection.decisions
    ]
    return {
        "schema": "roundwright-shadow-case/v2", "profile": SOURCE_INGESTION_PROFILE,
        "ready_at": binding.ready_at, "case_id": binding.case_id,
        "candidate_sha": binding.candidate_sha, "capture_plan_digest": binding.plan.plan_digest,
        "configured_source_ingestion": {
            "schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA,
            "binding_identity": identity,
            "producer_identity": CONFIGURED_SOURCE_PRODUCER_IDENTITY,
            "exporter_identity": CONFIGURED_SOURCE_EXPORTER_IDENTITY,
            "comparator_identity": CONFIGURED_SOURCE_COMPARATOR_IDENTITY,
            "source_set_digest": inventory.binding.source_set_digest,
            "source_content_digests": [
                {"public_identity": source, "content_digest": digest}
                for source, digest in inventory.source_content_digests
            ],
            "normalized_inventory_digest": inventory.inventory_digest,
            "graph_digest": selection.graph_digest,
            "selection_decisions": decisions,
            "selection_digest": _digest_value(decisions),
            "runnable_ids": list(selection.runnable_ids),
            "zero_mutation_proof": {
                "source_mutation_count": 0, "git_mutation_count": 0,
                "github_mutation_count": 0, "provider_dispatch_count": 0,
            },
        },
    }


class ConfiguredSourceIngestionAdapter:
    """Product-hosted Harness adapter for the configured-source terminal lane."""

    profile_id = SOURCE_INGESTION_PROFILE

    def __init__(self, inputs: ConfiguredSourceHostInputs | None = None) -> None:
        if inputs is not None and type(inputs) is not ConfiguredSourceHostInputs:
            raise ConfiguredSourceError("configured source adapter inputs are invalid")
        self._inputs = inputs

    @property
    def component_identities(self) -> object:
        from .external_validation import _harness_executor
        return _harness_executor().ProfileComponentIdentities(*configured_source_component_identities())

    def prepare_execution_context(self, preparation: object) -> object:
        from .external_validation import _harness_executor
        inputs = self._require_inputs()
        try:
            if (
                _materialize_json(preparation.descriptor) != inputs.execution_context(preparation.plan.plan_digest)
                or preparation.input_digest != _digest_value(inputs.execution_context(preparation.plan.plan_digest))
                or preparation.components != self.component_identities
                or (preparation.plan.candidate_sha, preparation.plan.case_id, preparation.plan.plan_digest, preparation.plan.ready_at)
                != (inputs.binding.candidate_sha, inputs.case_id, preparation.plan.plan_digest, inputs.ready_at)
            ):
                raise ValueError
        except (AttributeError, ValueError) as error:
            raise ConfiguredSourceError("configured source execution context is invalid") from error
        return _harness_executor().ProfileExecutionContext(_digest_value({
            "observation_identity": inputs.observation_identity,
            "capture_plan_digest": preparation.plan.plan_digest,
            "execution_context_input_digest": preparation.input_digest,
        }), inputs)

    def validate(self, binding: object) -> None:
        inputs = self._require_inputs()
        _configured_source_binding_identity(binding)
        _source_execution_context(binding, inputs)
        try:
            actual = (
                binding.components.producer_identity, binding.components.exporter_identity,
                binding.components.comparator_identity,
            )
        except AttributeError as error:
            raise ConfiguredSourceError("configured source components are invalid") from error
        if actual != configured_source_component_identities():
            raise ConfiguredSourceError("configured source components have drifted")

    def execute(self, binding: object) -> object:
        self.validate(binding)
        inputs = self._require_inputs()
        inputs.verify_owner_blocker_state()
        # This is the only source-read point.  Validate, compare, and project
        # never invoke an adapter, provider, Git, or GitHub operation.
        inventory = inputs.read_host.scan()
        selection = select_runnable_work(
            inventory, inputs.graph, owner_blockers_pending=inputs.owner_blockers_pending,
        )
        execution = ConfiguredSourceExecution(inventory, selection)
        from .external_validation import _harness_executor
        return _harness_executor().ProfileExecution(execution, mutation_count=0)

    def project(self, binding: object, execution: object) -> dict[str, object]:
        self.validate(binding)
        try:
            if execution.mutation_count != 0 or type(execution.value) is not ConfiguredSourceExecution:
                raise ValueError
        except (AttributeError, ValueError) as error:
            raise ConfiguredSourceError("configured source execution has drifted") from error
        return configured_source_evidence(binding, execution.value)

    def compare(self, binding: object, evidence: object) -> object:
        self.validate(binding)
        status = "pass" if _valid_configured_source_evidence(binding, evidence) else "fail"
        from .external_validation import _harness_executor
        return _harness_executor().ProfileComparison(status, _digest_value({
            "schema": CONFIGURED_SOURCE_EVIDENCE_SCHEMA, "status": status,
            "ready_at": binding.ready_at,
            "expected_binding_identity": _configured_source_binding_identity(binding),
            "observed_identity": _digest_value(evidence),
        }))

    def _require_inputs(self) -> ConfiguredSourceHostInputs:
        if type(self._inputs) is not ConfiguredSourceHostInputs:
            raise ConfiguredSourceError("configured source profile requires product-hosted inputs")
        return self._inputs


def _valid_configured_source_evidence(binding: object, evidence: object) -> bool:
    """Compare a sealed terminal projection without a second live source read."""

    try:
        value = evidence
        if (
            type(value) is not dict or set(value) != {
                "schema", "profile", "ready_at", "case_id", "candidate_sha", "capture_plan_digest", "configured_source_ingestion",
            } or (value["schema"], value["profile"], value["ready_at"], value["case_id"], value["candidate_sha"], value["capture_plan_digest"])
            != ("roundwright-shadow-case/v2", SOURCE_INGESTION_PROFILE, binding.ready_at, binding.case_id, binding.candidate_sha, binding.plan.plan_digest)
        ):
            return False
        lane = value["configured_source_ingestion"]
        zero = lane["zero_mutation_proof"]
        decisions = lane["selection_decisions"]
        return (
            type(lane) is dict and lane["schema"] == CONFIGURED_SOURCE_EVIDENCE_SCHEMA
            and lane["binding_identity"] == _configured_source_binding_identity(binding)
            and (lane["producer_identity"], lane["exporter_identity"], lane["comparator_identity"])
            == configured_source_component_identities()
            and type(lane["source_content_digests"]) is list and type(decisions) is list
            and lane["selection_digest"] == _digest_value(decisions)
            and type(lane["normalized_inventory_digest"]) is str and _DIGEST_PATTERN.fullmatch(lane["normalized_inventory_digest"])
            and all(zero[name] == 0 for name in ("source_mutation_count", "git_mutation_count", "github_mutation_count", "provider_dispatch_count"))
        )
    except (KeyError, TypeError, AttributeError):
        return False
