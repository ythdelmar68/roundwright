"""Deterministic validation and transactional activation of dependency graphs.

The dependency-review model may propose digest-only edges, but it never owns
their interpretation or activation.  This module is the small deterministic
boundary that decides whether one durable proposal can advance the active
graph.  It deliberately has no provider, scanner, scheduler, or GitHub seam.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .dependency_review import (
    AffectedMember,
    AffectedSubset,
    DependencyProposal,
    DependencyReviewBinding,
    DependencyReviewError,
    DependencyReviewStore,
    EdgeDirection,
    EdgeKind,
    ProposedEdge,
    RequestedDisposition,
)
from .state import _open_writable_connection, database_path


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_REASON = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
VALIDATOR_DIGEST = "sha256:" + hashlib.sha256(b"roundwright-dependency-graph-validator/v1").hexdigest()


class DependencyGraphError(ValueError):
    """Raised when graph evidence is absent, stale, contradictory, or unsafe."""


class GraphDecision(StrEnum):
    ACCEPTED = "accepted"
    PENDING_OWNER = "pending-owner"
    REJECTED = "rejected"


@dataclass(frozen=True)
class DependencyGraphBinding:
    """The current candidate/policy/configuration identities for activation."""

    candidate_sha: str
    policy_digest: str
    configuration_digest: str
    validator_digest: str = VALIDATOR_DIGEST

    def __post_init__(self) -> None:
        if not _SHA.fullmatch(self.candidate_sha) or not all(
            _digest(value) for value in (self.policy_digest, self.configuration_digest, self.validator_digest)
        ):
            raise DependencyGraphError("dependency graph binding is invalid")

    @classmethod
    def from_review_binding(cls, binding: DependencyReviewBinding, *, validator_digest: str = VALIDATOR_DIGEST) -> "DependencyGraphBinding":
        if type(binding) is not DependencyReviewBinding:
            raise DependencyGraphError("dependency graph binding is invalid")
        return cls(binding.candidate_sha, binding.policy_digest, binding.configuration_digest, validator_digest)

    def require_subset(self, subset: AffectedSubset) -> None:
        if (subset.candidate_sha, subset.policy_digest, subset.configuration_digest) != (
            self.candidate_sha,
            self.policy_digest,
            self.configuration_digest,
        ):
            raise DependencyGraphError("dependency graph binding has drifted")


@dataclass(frozen=True)
class GraphEdge:
    """One canonical directed edge: subject depends on object."""

    subject_member_id: str
    object_member_id: str
    kind: EdgeKind
    proposal_id: str

    def __post_init__(self) -> None:
        if (
            not _TOKEN.fullmatch(self.subject_member_id)
            or not _TOKEN.fullmatch(self.object_member_id)
            or self.subject_member_id == self.object_member_id
            or self.kind not in {EdgeKind.EXPLICIT, EdgeKind.POLICY_DERIVED}
            or not _TOKEN.fullmatch(self.proposal_id)
        ):
            raise DependencyGraphError("dependency graph edge is invalid")

    def payload(self) -> dict[str, str]:
        return {
            "subject_member_id": self.subject_member_id,
            "object_member_id": self.object_member_id,
            "kind": self.kind.value,
            "proposal_id": self.proposal_id,
        }


@dataclass(frozen=True)
class GraphMember:
    task_id: str
    snapshot_id: str
    member: AffectedMember

    def __post_init__(self) -> None:
        if not _TOKEN.fullmatch(self.task_id) or not _TOKEN.fullmatch(self.snapshot_id) or type(self.member) is not AffectedMember:
            raise DependencyGraphError("dependency graph member is invalid")

    def payload(self) -> dict[str, str]:
        return {"task_id": self.task_id, "snapshot_id": self.snapshot_id, **self.member.payload()}


@dataclass(frozen=True)
class GraphSnapshot:
    graph_version_id: str | None
    binding: DependencyGraphBinding | None
    members: tuple[GraphMember, ...]
    edges: tuple[GraphEdge, ...]
    proposal_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.graph_version_id is not None and not _TOKEN.fullmatch(self.graph_version_id):
            raise DependencyGraphError("dependency graph snapshot is invalid")
        if (self.graph_version_id is None) != (self.binding is None):
            raise DependencyGraphError("dependency graph snapshot is invalid")
        if type(self.members) is not tuple or type(self.edges) is not tuple or type(self.proposal_ids) is not tuple:
            raise DependencyGraphError("dependency graph snapshot is invalid")
        if any(type(item) is not GraphMember for item in self.members) or any(type(item) is not GraphEdge for item in self.edges):
            raise DependencyGraphError("dependency graph snapshot is invalid")
        if len({item.member.member_id for item in self.members}) != len(self.members) or len(set(self.proposal_ids)) != len(self.proposal_ids):
            raise DependencyGraphError("dependency graph snapshot is invalid")

    @property
    def graph_digest(self) -> str:
        return _digest_value(
            {
                "members": [item.payload() for item in sorted(self.members, key=lambda value: value.member.member_id)],
                "edges": [item.payload() for item in sorted(self.edges, key=lambda value: (value.subject_member_id, value.object_member_id, value.kind.value, value.proposal_id))],
            }
        )

    @property
    def proposal_set_digest(self) -> str:
        return _digest_value({"proposal_ids": sorted(self.proposal_ids)})


@dataclass(frozen=True)
class GraphValidation:
    decision: GraphDecision
    reason_code: str
    edges: tuple[GraphEdge, ...]

    def __post_init__(self) -> None:
        if type(self.decision) is not GraphDecision or not _REASON.fullmatch(self.reason_code) or type(self.edges) is not tuple or any(type(edge) is not GraphEdge for edge in self.edges):
            raise DependencyGraphError("dependency graph decision is invalid")
        if self.decision is not GraphDecision.ACCEPTED and self.edges:
            raise DependencyGraphError("non-accepted graph decision cannot contain edges")

    def digest(self, proposal: DependencyProposal, subset: AffectedSubset, binding: DependencyGraphBinding) -> str:
        return _digest_value(
            {
                "proposal_digest": proposal.proposal_digest,
                "subset_digest": subset.content_digest,
                "validator_digest": binding.validator_digest,
                "policy_digest": binding.policy_digest,
                "candidate_sha": binding.candidate_sha,
                "configuration_digest": binding.configuration_digest,
                "decision": self.decision.value,
                "reason_code": self.reason_code,
                "edges": [edge.payload() for edge in self.edges],
            }
        )


@dataclass(frozen=True)
class GraphActivation:
    proposal_id: str
    decision: GraphDecision
    reason_code: str
    decision_digest: str
    graph_version_id: str | None


class DependencyGraphValidator:
    """Pure policy/graph validation for one candidate-bound proposed change."""

    @staticmethod
    def validate(proposal: DependencyProposal, subset: AffectedSubset, binding: DependencyGraphBinding, active: GraphSnapshot) -> GraphValidation:
        if type(proposal) is not DependencyProposal or type(subset) is not AffectedSubset or type(binding) is not DependencyGraphBinding or type(active) is not GraphSnapshot:
            raise DependencyGraphError("dependency graph validation input is invalid")
        binding.require_subset(subset)
        if active.binding is not None and active.binding != binding:
            # Candidate movement starts a new aggregate.  An old PASS is never input to it.
            active = GraphSnapshot(None, None, (), (), ())
        if proposal.requested_disposition is RequestedDisposition.REJECT:
            return GraphValidation(GraphDecision.REJECTED, "proposal-rejected", ())
        if proposal.requested_disposition is RequestedDisposition.OWNER_REVIEW or any(edge.kind is EdgeKind.SEMANTIC_INFERRED for edge in proposal.edges):
            return GraphValidation(GraphDecision.PENDING_OWNER, "owner-decision-required", ())
        if proposal.requested_disposition is not RequestedDisposition.AUTO_ACTIVATE or proposal.owner_route != "not-required":
            return GraphValidation(GraphDecision.REJECTED, "invalid-disposition", ())
        members = {member.member_id for member in subset.members}
        proposed_members = {item for edge in proposal.edges for item in (edge.subject_member_id, edge.object_member_id)}
        if proposed_members != members:
            return GraphValidation(GraphDecision.REJECTED, "affected-subset-incomplete", ())
        canonical: list[GraphEdge] = []
        for edge in proposal.edges:
            if edge.kind not in {EdgeKind.EXPLICIT, EdgeKind.POLICY_DERIVED}:
                return GraphValidation(GraphDecision.REJECTED, "edge-kind-not-verifiable", ())
            if edge.direction is EdgeDirection.DEPENDS_ON:
                subject, object_ = edge.subject_member_id, edge.object_member_id
            elif edge.direction is EdgeDirection.BLOCKS:
                subject, object_ = edge.object_member_id, edge.subject_member_id
            else:
                return GraphValidation(GraphDecision.REJECTED, "direction-invalid", ())
            canonical.append(GraphEdge(subject, object_, edge.kind, proposal.proposal_id))
        pairs = {(edge.subject_member_id, edge.object_member_id) for edge in canonical}
        if len(pairs) != len(canonical):
            return GraphValidation(GraphDecision.REJECTED, "duplicate-or-conflicting-edge", ())
        existing_pairs = {(edge.subject_member_id, edge.object_member_id) for edge in active.edges}
        if pairs & existing_pairs:
            return GraphValidation(GraphDecision.REJECTED, "duplicate-or-conflicting-edge", ())
        if _has_cycle((*active.edges, *canonical)):
            return GraphValidation(GraphDecision.REJECTED, "cycle-detected", ())
        return GraphValidation(GraphDecision.ACCEPTED, "graph-valid", tuple(sorted(canonical, key=lambda edge: (edge.subject_member_id, edge.object_member_id, edge.kind.value))))


class DependencyGraphStore:
    """Persist a complete graph version and its decision in one SQLite transaction."""

    def activate(self, repository: RepositoryIdentity, proposal: DependencyProposal, *, binding: DependencyGraphBinding, graph_version_id: str) -> GraphActivation:
        if type(binding) is not DependencyGraphBinding or not _TOKEN.fullmatch(graph_version_id):
            raise DependencyGraphError("dependency graph activation identity is invalid")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            attempt, subset = DependencyReviewStore._read_attempt(connection, proposal.attempt_id)
            stored = DependencyReviewStore._read_proposal(connection, proposal.proposal_id)
            if stored != proposal or attempt[6] != "accepted":
                raise DependencyGraphError("dependency proposal is not durably accepted")
            binding.require_subset(subset)
            active = self._read_current(connection)
            existing = connection.execute(
                "SELECT attempt_id, subset_digest, validator_digest, policy_digest, candidate_sha, configuration_digest, decision, reason_code, decision_digest, graph_version_id FROM dependency_graph_decisions WHERE proposal_id = ?",
                (proposal.proposal_id,),
            ).fetchone()
            if existing is not None:
                expected_context = (proposal.attempt_id, subset.content_digest, binding.validator_digest, binding.policy_digest, binding.candidate_sha, binding.configuration_digest)
                if tuple(existing[:6]) != expected_context:
                    raise DependencyGraphError("dependency graph decision has drifted")
                decision = GraphDecision(existing[6])
                reason_code, decision_digest, version = existing[7:]
                if not _REASON.fullmatch(reason_code) or not _digest(decision_digest):
                    raise DependencyGraphError("dependency graph decision has drifted")
                if decision is GraphDecision.ACCEPTED and version != graph_version_id:
                    raise DependencyGraphError("dependency graph version has drifted")
                if decision is not GraphDecision.ACCEPTED and version is not None:
                    raise DependencyGraphError("dependency graph decision has drifted")
                connection.commit()
                return GraphActivation(proposal.proposal_id, decision, reason_code, decision_digest, version)
            validation = DependencyGraphValidator.validate(proposal, subset, binding, active)
            expected_digest = validation.digest(proposal, subset, binding)
            expected = (proposal.attempt_id, subset.content_digest, binding.validator_digest, binding.policy_digest, binding.candidate_sha, binding.configuration_digest, validation.decision.value, validation.reason_code, expected_digest)
            version: str | None = None
            if validation.decision is GraphDecision.ACCEPTED:
                snapshot = self._next_snapshot(active, subset, validation.edges, proposal.proposal_id, binding)
                if active.binding == binding:
                    predecessor = active.graph_version_id
                else:
                    predecessor = None
                self._write_version(connection, graph_version_id, predecessor, snapshot, binding)
                connection.execute(
                    "INSERT INTO dependency_graph_current(singleton, graph_version_id) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET graph_version_id = excluded.graph_version_id",
                    (graph_version_id,),
                )
                version = graph_version_id
            connection.execute(
                "INSERT INTO dependency_graph_decisions(proposal_id, attempt_id, subset_digest, validator_digest, policy_digest, candidate_sha, configuration_digest, decision, reason_code, decision_digest, graph_version_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (proposal.proposal_id, *expected, version),
            )
            connection.commit()
            return GraphActivation(proposal.proposal_id, validation.decision, validation.reason_code, expected_digest, version)
        except (DependencyReviewError, DependencyGraphError):
            connection.rollback()
            raise
        except Exception:
            connection.rollback()
            raise DependencyGraphError("dependency graph activation is unavailable") from None
        finally:
            connection.close()

    def current(self, repository: RepositoryIdentity, *, binding: DependencyGraphBinding) -> GraphSnapshot:
        path = database_path(repository)
        try:
            connection = __import__("sqlite3").connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
            try:
                snapshot = self._read_current(connection)
            finally:
                connection.close()
        except OSError as error:
            raise DependencyGraphError("dependency graph is unavailable") from error
        if snapshot.binding != binding:
            raise DependencyGraphError("current dependency graph is unavailable")
        return snapshot

    @staticmethod
    def _read_current(connection: object) -> GraphSnapshot:
        current = connection.execute("SELECT graph_version_id FROM dependency_graph_current WHERE singleton = 1").fetchone()
        if current is None:
            return GraphSnapshot(None, None, (), (), ())
        version = current[0]
        row = connection.execute("SELECT proposal_set_digest, validator_digest, policy_digest, candidate_sha, configuration_digest, graph_digest FROM dependency_graph_versions WHERE graph_version_id = ?", (version,)).fetchone()
        if row is None:
            raise DependencyGraphError("current dependency graph is unavailable")
        binding = DependencyGraphBinding(row[3], row[2], row[4], row[1])
        members = tuple(GraphMember(task_id, snapshot_id, AffectedMember(member_id, fingerprint, content)) for task_id, snapshot_id, member_id, fingerprint, content in connection.execute("SELECT task_id, snapshot_id, member_id, member_fingerprint, content_digest FROM dependency_graph_members WHERE graph_version_id = ? ORDER BY member_id", (version,)))
        edges = tuple(GraphEdge(subject, object_, EdgeKind(kind), proposal_id) for subject, object_, kind, proposal_id in connection.execute("SELECT subject_member_id, object_member_id, edge_kind, proposal_id FROM dependency_graph_edges WHERE graph_version_id = ? ORDER BY subject_member_id, object_member_id", (version,)))
        proposal_ids = tuple(item[0] for item in connection.execute("SELECT DISTINCT proposal_id FROM dependency_graph_edges WHERE graph_version_id = ? ORDER BY proposal_id", (version,)))
        snapshot = GraphSnapshot(version, binding, members, edges, proposal_ids)
        if snapshot.proposal_set_digest != row[0] or snapshot.graph_digest != row[5] or _has_cycle(snapshot.edges):
            raise DependencyGraphError("current dependency graph has drifted")
        return snapshot

    @staticmethod
    def _next_snapshot(active: GraphSnapshot, subset: AffectedSubset, edges: tuple[GraphEdge, ...], proposal_id: str, binding: DependencyGraphBinding) -> GraphSnapshot:
        old_members = active.members if active.binding == binding else ()
        replaced = {member.member.member_id for member in old_members if member.task_id == subset.task_id}
        members = tuple(member for member in old_members if member.member.member_id not in replaced) + tuple(GraphMember(subset.task_id, subset.snapshot_id, member) for member in subset.members)
        retained_edges = tuple(edge for edge in (active.edges if active.binding == binding else ()) if edge.subject_member_id not in replaced and edge.object_member_id not in replaced)
        retained_proposals = tuple(item for item in (active.proposal_ids if active.binding == binding else ()) if item not in {edge.proposal_id for edge in active.edges if edge.subject_member_id in replaced or edge.object_member_id in replaced})
        return GraphSnapshot(None, None, tuple(sorted(members, key=lambda member: member.member.member_id)), tuple(sorted((*retained_edges, *edges), key=lambda edge: (edge.subject_member_id, edge.object_member_id, edge.kind.value))), tuple(sorted((*retained_proposals, proposal_id))))

    @staticmethod
    def _write_version(connection: object, version: str, predecessor: str | None, snapshot: GraphSnapshot, binding: DependencyGraphBinding) -> None:
        connection.execute("INSERT INTO dependency_graph_versions(graph_version_id, predecessor_graph_version_id, proposal_set_digest, validator_digest, policy_digest, candidate_sha, configuration_digest, graph_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (version, predecessor, snapshot.proposal_set_digest, binding.validator_digest, binding.policy_digest, binding.candidate_sha, binding.configuration_digest, snapshot.graph_digest))
        connection.executemany("INSERT INTO dependency_graph_members(graph_version_id, task_id, snapshot_id, member_id, member_fingerprint, content_digest) VALUES (?, ?, ?, ?, ?, ?)", ((version, member.task_id, member.snapshot_id, member.member.member_id, member.member.member_fingerprint, member.member.content_digest) for member in snapshot.members))
        connection.executemany("INSERT INTO dependency_graph_edges(graph_version_id, subject_member_id, object_member_id, edge_kind, proposal_id) VALUES (?, ?, ?, ?, ?)", ((version, edge.subject_member_id, edge.object_member_id, edge.kind.value, edge.proposal_id) for edge in snapshot.edges))


def _has_cycle(edges: tuple[GraphEdge, ...] | list[GraphEdge]) -> bool:
    adjacency: dict[str, set[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.subject_member_id, set()).add(edge.object_member_id)
        adjacency.setdefault(edge.object_member_id, set())
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        result = any(visit(next_node) for next_node in adjacency[node])
        visiting.remove(node)
        visited.add(node)
        return result

    return any(visit(node) for node in adjacency)


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
