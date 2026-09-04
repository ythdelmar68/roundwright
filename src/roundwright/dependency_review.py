"""Credential-free dependency-review identities and durable proposal records.

This module intentionally stops before graph activation or provider execution.
It accepts only normalized, digest-only review material and makes every review
attempt an independently durable SQLite transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum

from .configuration import RepositoryIdentity
from .state import StateError, _open_writable_connection


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_REASON = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


class DependencyReviewError(ValueError):
    """Raised when a dependency-review record is incomplete or has drifted."""


class EdgeKind(StrEnum):
    EXPLICIT = "explicit"
    POLICY_DERIVED = "policy-derived"
    SEMANTIC_INFERRED = "semantic-inferred"


class EdgeDirection(StrEnum):
    DEPENDS_ON = "depends-on"
    BLOCKS = "blocks"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RequestedDisposition(StrEnum):
    AUTO_ACTIVATE = "auto-activate"
    OWNER_REVIEW = "owner-review"
    REJECT = "reject"


@dataclass(frozen=True)
class AffectedMember:
    member_id: str
    member_fingerprint: str
    content_digest: str

    def __post_init__(self) -> None:
        if not _token(self.member_id) or not _digest(self.member_fingerprint) or not _digest(self.content_digest):
            raise DependencyReviewError("affected subset member is invalid")

    def payload(self) -> dict[str, str]:
        return {"member_id": self.member_id, "member_fingerprint": self.member_fingerprint, "content_digest": self.content_digest}


@dataclass(frozen=True)
class AffectedSubset:
    """One immutable, normalized boundary.  It contains no source prose."""

    snapshot_id: str
    task_id: str
    source_digest: str
    candidate_sha: str
    policy_digest: str
    configuration_digest: str
    boundary_digest: str
    creation_reason: str
    members: tuple[AffectedMember, ...]

    def __post_init__(self) -> None:
        if (not _token(self.snapshot_id) or not _token(self.task_id) or not _plain_digest(self.source_digest)
                or not _SHA.fullmatch(self.candidate_sha) or not all(_digest(value) for value in (self.policy_digest, self.configuration_digest, self.boundary_digest))
                or not _REASON.fullmatch(self.creation_reason) or type(self.members) is not tuple or not self.members
                or any(type(member) is not AffectedMember for member in self.members)):
            raise DependencyReviewError("affected subset is invalid")
        if len({member.member_id for member in self.members}) != len(self.members) or len({member.member_fingerprint for member in self.members}) != len(self.members):
            raise DependencyReviewError("affected subset members are ambiguous")

    def payload(self) -> dict[str, object]:
        return {
            "schema": "roundwright-dependency-review-subset/v1",
            "snapshot_id": self.snapshot_id,
            "task_id": self.task_id,
            "source_digest": self.source_digest,
            "candidate_sha": self.candidate_sha,
            "policy_digest": self.policy_digest,
            "configuration_digest": self.configuration_digest,
            "boundary_digest": self.boundary_digest,
            "creation_reason": self.creation_reason,
            "members": [member.payload() for member in self.members],
        }

    @property
    def content_digest(self) -> str:
        return _digest_value(self.payload())


@dataclass(frozen=True)
class ProposedEdge:
    kind: EdgeKind
    direction: EdgeDirection
    subject_member_id: str
    object_member_id: str
    rationale_digest: str
    confidence: Confidence
    conflicts_digest: str

    def __post_init__(self) -> None:
        if (type(self.kind) is not EdgeKind or type(self.direction) is not EdgeDirection or not _token(self.subject_member_id)
                or not _token(self.object_member_id) or self.subject_member_id == self.object_member_id
                or not _digest(self.rationale_digest) or type(self.confidence) is not Confidence or not _digest(self.conflicts_digest)):
            raise DependencyReviewError("dependency proposal edge is invalid")

    def payload(self) -> dict[str, str]:
        return {
            "kind": self.kind.value,
            "direction": self.direction.value,
            "subject_member_id": self.subject_member_id,
            "object_member_id": self.object_member_id,
            "rationale_digest": self.rationale_digest,
            "confidence": self.confidence.value,
            "conflicts_digest": self.conflicts_digest,
        }


@dataclass(frozen=True)
class DependencyProposal:
    proposal_id: str
    attempt_id: str
    requested_disposition: RequestedDisposition
    owner_route: str
    edges: tuple[ProposedEdge, ...]

    def __post_init__(self) -> None:
        if (not _token(self.proposal_id) or not _token(self.attempt_id) or type(self.requested_disposition) is not RequestedDisposition
                or not _REASON.fullmatch(self.owner_route) or type(self.edges) is not tuple or not self.edges
                or any(type(edge) is not ProposedEdge for edge in self.edges)):
            raise DependencyReviewError("dependency proposal is invalid")
        key = {(edge.kind, edge.direction, edge.subject_member_id, edge.object_member_id) for edge in self.edges}
        if len(key) != len(self.edges):
            raise DependencyReviewError("dependency proposal contains duplicate edges")
        semantic = any(edge.kind is EdgeKind.SEMANTIC_INFERRED for edge in self.edges)
        if semantic and (self.requested_disposition is not RequestedDisposition.OWNER_REVIEW or self.owner_route != "owner-review"):
            raise DependencyReviewError("semantic inferred edge requires owner routing")
        if not semantic and self.requested_disposition is RequestedDisposition.OWNER_REVIEW and self.owner_route != "owner-review":
            raise DependencyReviewError("owner review proposal has no owner route")

    def payload(self) -> dict[str, object]:
        return {
            "schema": "roundwright-dependency-review-proposal/v1",
            "proposal_id": self.proposal_id,
            "attempt_id": self.attempt_id,
            "requested_disposition": self.requested_disposition.value,
            "owner_route": self.owner_route,
            "edges": [edge.payload() for edge in self.edges],
        }

    @property
    def proposal_digest(self) -> str:
        return _digest_value(self.payload())

    @classmethod
    def parse(cls, material: object) -> "DependencyProposal":
        """Parse only the strict public-safe provider response shape."""

        try:
            if type(material) is not dict or set(material) != {"schema", "proposal_id", "attempt_id", "requested_disposition", "owner_route", "edges"} or material["schema"] != "roundwright-dependency-review-proposal/v1" or type(material["edges"]) is not list:
                raise ValueError
            edges = tuple(ProposedEdge(EdgeKind(edge["kind"]), EdgeDirection(edge["direction"]), edge["subject_member_id"], edge["object_member_id"], edge["rationale_digest"], Confidence(edge["confidence"]), edge["conflicts_digest"]) for edge in material["edges"] if type(edge) is dict and set(edge) == {"kind", "direction", "subject_member_id", "object_member_id", "rationale_digest", "confidence", "conflicts_digest"})
            if len(edges) != len(material["edges"]):
                raise ValueError
            proposal = cls(material["proposal_id"], material["attempt_id"], RequestedDisposition(material["requested_disposition"]), material["owner_route"], edges)
            if proposal.payload() != material:
                raise ValueError
            return proposal
        except (KeyError, TypeError, ValueError) as error:
            raise DependencyReviewError("dependency proposal response is malformed") from error


@dataclass(frozen=True)
class DependencyReviewAttempt:
    attempt_id: str
    snapshot_id: str
    profile_identity: str
    configuration_digest: str
    input_digest: str
    supersedes_attempt_id: str | None
    state: str


class DependencyReviewStore:
    """Transactional persistence for isolated dependency-review records only."""

    def start_attempt(self, repository: RepositoryIdentity, subset: AffectedSubset, *, attempt_id: str, profile_identity: str, supersedes_attempt_id: str | None = None) -> DependencyReviewAttempt:
        if not _token(attempt_id) or not _digest(profile_identity) or (supersedes_attempt_id is not None and not _token(supersedes_attempt_id)):
            raise DependencyReviewError("dependency review attempt identity is invalid")
        input_digest = _digest_value(self.model_input(subset, attempt_id=attempt_id, profile_identity=profile_identity))
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            task = connection.execute("SELECT source_id FROM tasks WHERE task_id = ?", (subset.task_id,)).fetchone()
            source = connection.execute("SELECT source_digest FROM source_snapshots WHERE source_id = ?", task or (None,)).fetchone()
            if task is None or source != (subset.source_digest,):
                raise DependencyReviewError("dependency review source/task identity is unavailable")
            existing_subset = connection.execute("SELECT task_id, source_digest, candidate_sha, policy_digest, configuration_digest, boundary_digest, creation_reason, content_digest, member_count FROM dependency_review_subsets WHERE snapshot_id = ?", (subset.snapshot_id,)).fetchone()
            expected_subset = (subset.task_id, subset.source_digest, subset.candidate_sha, subset.policy_digest, subset.configuration_digest, subset.boundary_digest, subset.creation_reason, subset.content_digest, len(subset.members))
            if existing_subset is None:
                connection.execute("INSERT INTO dependency_review_subsets(snapshot_id, task_id, source_digest, candidate_sha, policy_digest, configuration_digest, boundary_digest, creation_reason, content_digest, member_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (subset.snapshot_id, *expected_subset))
                connection.executemany("INSERT INTO dependency_review_subset_members(snapshot_id, member_id, member_fingerprint, content_digest) VALUES (?, ?, ?, ?)", ((subset.snapshot_id, member.member_id, member.member_fingerprint, member.content_digest) for member in subset.members))
            elif tuple(existing_subset) != expected_subset or tuple(connection.execute("SELECT member_id, member_fingerprint, content_digest FROM dependency_review_subset_members WHERE snapshot_id = ? ORDER BY member_id", (subset.snapshot_id,))) != tuple((member.member_id, member.member_fingerprint, member.content_digest) for member in sorted(subset.members, key=lambda item: item.member_id)):
                raise DependencyReviewError("dependency review subset has drifted")
            existing = connection.execute("SELECT snapshot_id, profile_identity, configuration_digest, input_digest, supersedes_attempt_id, state FROM dependency_review_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            expected = (subset.snapshot_id, profile_identity, subset.configuration_digest, input_digest, supersedes_attempt_id, "prepared")
            if supersedes_attempt_id is not None and connection.execute("SELECT 1 FROM dependency_review_attempts WHERE attempt_id = ?", (supersedes_attempt_id,)).fetchone() is None:
                raise DependencyReviewError("dependency review supersession is unavailable")
            if existing is None:
                connection.execute("INSERT INTO dependency_review_attempts(attempt_id, task_id, snapshot_id, profile_identity, configuration_digest, input_digest, supersedes_attempt_id, state) VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared')", (attempt_id, subset.task_id, subset.snapshot_id, profile_identity, subset.configuration_digest, input_digest, supersedes_attempt_id))
                state = "prepared"
            elif tuple(existing) == expected:
                state = "prepared"
            else:
                raise DependencyReviewError("dependency review attempt has drifted")
            connection.commit()
            return DependencyReviewAttempt(attempt_id, subset.snapshot_id, profile_identity, subset.configuration_digest, input_digest, supersedes_attempt_id, state)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def model_input(subset: AffectedSubset, *, attempt_id: str, profile_identity: str) -> dict[str, object]:
        """Return the only model input surface: identifiers and digests, never prose or credentials."""

        if not _token(attempt_id) or not _digest(profile_identity):
            raise DependencyReviewError("dependency review model input is invalid")
        return {
            "schema": "roundwright-dependency-review-input/v1",
            "attempt_id": attempt_id,
            "profile_identity": profile_identity,
            "subset_digest": subset.content_digest,
            "task_id": subset.task_id,
            "source_digest": subset.source_digest,
            "candidate_sha": subset.candidate_sha,
            "policy_digest": subset.policy_digest,
            "configuration_digest": subset.configuration_digest,
            "boundary_digest": subset.boundary_digest,
            "members": [member.payload() for member in subset.members],
        }

    def accept_proposal(self, repository: RepositoryIdentity, proposal: DependencyProposal) -> str:
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            attempt = connection.execute("SELECT snapshot_id, state FROM dependency_review_attempts WHERE attempt_id = ?", (proposal.attempt_id,)).fetchone()
            if attempt is None or attempt[1] not in {"prepared", "accepted"}:
                raise DependencyReviewError("dependency review attempt is not available")
            members = {row[0] for row in connection.execute("SELECT member_id FROM dependency_review_subset_members WHERE snapshot_id = ?", (attempt[0],))}
            if any(edge.subject_member_id not in members or edge.object_member_id not in members for edge in proposal.edges):
                raise DependencyReviewError("dependency proposal references a missing member")
            existing = connection.execute("SELECT attempt_id, proposal_digest, requested_disposition, owner_route FROM dependency_review_proposals WHERE proposal_id = ?", (proposal.proposal_id,)).fetchone()
            expected = (proposal.attempt_id, proposal.proposal_digest, proposal.requested_disposition.value, proposal.owner_route)
            if existing is None:
                collision = connection.execute("SELECT proposal_id FROM dependency_review_proposals WHERE attempt_id = ?", (proposal.attempt_id,)).fetchone()
                if collision is not None:
                    raise DependencyReviewError("dependency review attempt already has a proposal")
                connection.execute("INSERT INTO dependency_review_proposals(proposal_id, attempt_id, proposal_digest, requested_disposition, owner_route) VALUES (?, ?, ?, ?, ?)", (proposal.proposal_id, *expected))
                connection.executemany("INSERT INTO dependency_review_proposal_edges(proposal_id, ordinal, edge_kind, direction, subject_member_id, object_member_id, rationale_digest, confidence, conflicts_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ((proposal.proposal_id, ordinal, edge.kind.value, edge.direction.value, edge.subject_member_id, edge.object_member_id, edge.rationale_digest, edge.confidence.value, edge.conflicts_digest) for ordinal, edge in enumerate(proposal.edges)))
            elif tuple(existing) != expected:
                raise DependencyReviewError("dependency proposal has drifted")
            outcome = ("accepted", "schema-valid", proposal.proposal_digest, proposal.owner_route)
            stored = connection.execute("SELECT outcome, reason_code, output_digest, owner_route FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (proposal.attempt_id,)).fetchone()
            if stored is None:
                connection.execute("INSERT INTO dependency_review_validation_outcomes(attempt_id, outcome, reason_code, output_digest, owner_route) VALUES (?, ?, ?, ?, ?)", (proposal.attempt_id, *outcome))
                connection.execute("UPDATE dependency_review_attempts SET state = 'accepted' WHERE attempt_id = ?", (proposal.attempt_id,))
            elif tuple(stored) != outcome:
                raise DependencyReviewError("dependency proposal outcome has drifted")
            connection.commit()
            return proposal.proposal_digest
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_invalid(self, repository: RepositoryIdentity, *, attempt_id: str, output_digest: str, reason_code: str, owner_route: str = "owner-review") -> None:
        """Retain a malformed or ambiguous result without accepting a proposal."""

        if not _token(attempt_id) or not _digest(output_digest) or not _REASON.fullmatch(reason_code) or not _REASON.fullmatch(owner_route):
            raise DependencyReviewError("dependency review invalid outcome is malformed")
        connection = _open_writable_connection(repository)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT state FROM dependency_review_attempts WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if row is None or row[0] not in {"prepared", "invalid"}:
                raise DependencyReviewError("dependency review attempt is not available")
            outcome = ("invalid", reason_code, output_digest, owner_route)
            stored = connection.execute("SELECT outcome, reason_code, output_digest, owner_route FROM dependency_review_validation_outcomes WHERE attempt_id = ?", (attempt_id,)).fetchone()
            if stored is None:
                connection.execute("INSERT INTO dependency_review_validation_outcomes(attempt_id, outcome, reason_code, output_digest, owner_route) VALUES (?, ?, ?, ?, ?)", (attempt_id, *outcome))
                connection.execute("UPDATE dependency_review_attempts SET state = 'invalid' WHERE attempt_id = ?", (attempt_id,))
            elif tuple(stored) != outcome:
                raise DependencyReviewError("dependency review invalid outcome has drifted")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _digest_value(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _token(value: object) -> bool:
    return type(value) is str and bool(_TOKEN.fullmatch(value))


def _digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _plain_digest(value: object) -> bool:
    return type(value) is str and bool(re.fullmatch(r"[0-9a-f]{64}", value))
