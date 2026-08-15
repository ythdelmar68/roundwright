"""Versioned, source-auditable runtime configuration.

Configuration is deliberately a pure, fail-closed boundary: it selects an
already-authorized execution profile, but never grants repository authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from dataclasses import dataclass, replace
from enum import Enum
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any, Generic, Mapping, TypeVar
from .runtime_binding import RuntimeBinding
from .policy import PolicyDocument, TrustedControlSource, TrustedPolicySnapshot


class ConfigurationError(ValueError):
    """Raised when configuration cannot safely be understood."""


class ConfigurationSource(str, Enum):
    DEFAULT = "default"
    USER = "user configuration"
    REPOSITORY = "repository configuration"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command line"


class PreflightMode(str, Enum):
    READ_ONLY = "read-only"
    DISPATCH_CAPABLE = "dispatch-capable"


class ReasoningEffort(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"
    ULTRA = "ultra"


class ReviewMode(str, Enum):
    COMPLETE = "COMPLETE"
    CONVERGING = "CONVERGING"


class FinalFindingsPolicy(str, Enum):
    WORKER_FINAL_REPAIR_THEN_MERGE = "worker-final-repair-then-merge"


class ReviewOutcome(str, Enum):
    PASS = "PASS"
    FINDINGS = "FINDINGS"


class ReviewDisposition(str, Enum):
    EARLY_PASS = "EARLY_PASS"
    NEXT_ROUND = "NEXT_ROUND"
    WORKER_FINAL_REPAIR = "WORKER_FINAL_REPAIR"
    REVIEW_LIMIT_REACHED_WORKER_FINALIZED = "REVIEW_LIMIT_REACHED_WORKER_FINALIZED"


T = TypeVar("T")
_SCHEMA_VERSION = "roundwright-runtime/v1"
_REPOSITORY_CONFIG = ".roundwright.toml"
_EXPECTED_REPOSITORY = "ythdelmar68/roundwright"
_SUPPORTED_MODELS = frozenset({"gpt-5.6-terra", "gpt-5.6-sol"})
_REVIEW_ENVIRONMENT_KEYS = {
    "complete_rounds": "ROUNDWRIGHT_REVIEW_COMPLETE_ROUNDS",
    "max_rounds": "ROUNDWRIGHT_REVIEW_MAX_ROUNDS",
    "max_supervisor_attempts_per_round": "ROUNDWRIGHT_REVIEW_MAX_SUPERVISOR_ATTEMPTS_PER_ROUND",
    "on_final_findings": "ROUNDWRIGHT_REVIEW_ON_FINAL_FINDINGS",
}
_PATH_ENVIRONMENT_KEYS = {
    "repository_root": "ROUNDWRIGHT_REPOSITORY_ROOT",
    "cache_directory": "ROUNDWRIGHT_CACHE_DIRECTORY",
}


@dataclass(frozen=True)
class EffectiveValue(Generic[T]):
    value: T
    source: ConfigurationSource


@dataclass(frozen=True)
class ProviderProfile:
    model: str
    reasoning_effort: ReasoningEffort
    name: str | None = None


@dataclass(frozen=True)
class ReviewPolicy:
    complete_rounds: int
    max_rounds: int
    max_supervisor_attempts_per_round: int
    on_final_findings: FinalFindingsPolicy

    def mode_for_round(self, round_number: int) -> ReviewMode:
        if type(round_number) is not int or round_number < 1 or round_number > self.max_rounds:
            raise ConfigurationError("review round is outside the configured limit")
        return ReviewMode.COMPLETE if round_number <= self.complete_rounds else ReviewMode.CONVERGING

    def disposition(self, round_number: int, outcome: ReviewOutcome, *, worker_finalized: bool = False) -> ReviewDisposition:
        self.mode_for_round(round_number)
        if worker_finalized:
            if outcome is not ReviewOutcome.FINDINGS or round_number != self.max_rounds:
                raise ConfigurationError("final worker repair has no valid review predecessor")
            return ReviewDisposition.REVIEW_LIMIT_REACHED_WORKER_FINALIZED
        if outcome is ReviewOutcome.PASS:
            return ReviewDisposition.EARLY_PASS
        if outcome is not ReviewOutcome.FINDINGS:
            raise ConfigurationError("review outcome is unsupported")
        return ReviewDisposition.WORKER_FINAL_REPAIR if round_number == self.max_rounds else ReviewDisposition.NEXT_ROUND

    def enforce_floor(self, floor: "ReviewPolicy") -> "ReviewPolicy":
        """A trusted policy may only make review stricter, never relax it."""
        if type(floor) is not ReviewPolicy or self.complete_rounds < floor.complete_rounds or self.max_rounds < floor.max_rounds or self.max_supervisor_attempts_per_round < floor.max_supervisor_attempts_per_round:
            raise ConfigurationError("review configuration violates the trusted policy floor")
        if self.on_final_findings is not floor.on_final_findings:
            raise ConfigurationError("review configuration violates the trusted terminal policy")
        return self


@dataclass(frozen=True)
class TrustedReviewAuthorityReceipt:
    """Independent control-plane binding for a dispatch-capable review floor.

    The receipt deliberately carries the floor and the authorized durable
    runtime source together.  Qualification must compare this immutable
    binding with configuration and readiness; neither value may be learned
    from a readiness object or a runtime-store response.
    """

    source_identity: str
    authority_identity: str
    policy_snapshot_digest: str
    trusted_review_floor: ReviewPolicy
    runtime_store_source_identity: str

    def __post_init__(self) -> None:
        if (not all(_is_digest(value) for value in (
            self.source_identity, self.authority_identity,
            self.policy_snapshot_digest, self.runtime_store_source_identity,
        )) or type(self.trusted_review_floor) is not ReviewPolicy):
            raise ConfigurationError("trusted review authority receipt is invalid")
        self.trusted_review_floor.enforce_floor(self.trusted_review_floor)

    def payload(self) -> dict[str, object]:
        return {
            "schema": "roundwright-trusted-review-authority/v1",
            "source_identity": self.source_identity,
            "authority_identity": self.authority_identity,
            "policy_snapshot_digest": self.policy_snapshot_digest,
            "trusted_review_floor": _review_policy_payload(self.trusted_review_floor),
            "runtime_store_source_identity": self.runtime_store_source_identity,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.payload())

    @classmethod
    def from_snapshot(cls, snapshot: object, floor: object) -> "TrustedReviewAuthorityReceipt":
        if not _is_trusted_review_floor_evidence(snapshot, floor):
            raise ConfigurationError("trusted review policy evidence is unavailable")
        assert type(snapshot) is TrustedPolicySnapshot
        assert type(floor) is ReviewPolicy
        source = "sha256:" + snapshot.source.source_fingerprint
        authority = "sha256:" + snapshot.source.revision_fingerprint
        policy_digest = "sha256:" + snapshot.policy_digest
        runtime_source = _digest({
            "schema": "roundwright-supervisor-runtime-store-authority/v2",
            "source_identity": source,
            "authority_identity": authority,
            "policy_snapshot_digest": policy_digest,
            "trusted_review_floor": _review_policy_payload(floor),
        })
        return cls(source, authority, policy_digest, floor, runtime_source)


@dataclass(frozen=True)
class ReviewAuthorityEvidenceReceipt:
    """Append-only authority observation consumed by dispatch-capable review.

    This receipt intentionally has a different lifecycle from the convenient
    ``TrustedReviewAuthorityReceipt`` value above.  The latter describes a
    policy claim; this value proves that an independently pinned authority
    source persisted and was read back for one candidate/configuration/time
    interval before a Supervisor sequence can run.
    """

    source_identity: str
    authority_identity: str
    runtime_store_source_identity: str
    authority_store_identity: str
    authority_receipt_digest: str
    policy_snapshot_digest: str
    trusted_review_floor: ReviewPolicy
    candidate_sha: str
    configuration_anchor_digest: str
    ready_at: int
    freshness_until: int
    record_identity: str

    def __post_init__(self) -> None:
        if (not all(_is_digest(value) for value in (
            self.source_identity, self.authority_identity,
            self.runtime_store_source_identity, self.authority_store_identity, self.authority_receipt_digest,
            self.policy_snapshot_digest, self.configuration_anchor_digest,
            self.record_identity,
        )) or type(self.trusted_review_floor) is not ReviewPolicy
                or type(self.candidate_sha) is not str or len(self.candidate_sha) != 40
                or any(character not in "0123456789abcdef" for character in self.candidate_sha)
                or type(self.ready_at) is not int or type(self.freshness_until) is not int
                or self.freshness_until < self.ready_at):
            raise ConfigurationError("review authority evidence receipt is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "schema": "roundwright-review-authority-evidence/v1",
            "source_identity": self.source_identity,
            "authority_identity": self.authority_identity,
            "runtime_store_source_identity": self.runtime_store_source_identity,
            "authority_store_identity": self.authority_store_identity,
            "authority_receipt_digest": self.authority_receipt_digest,
            "policy_snapshot_digest": self.policy_snapshot_digest,
            "trusted_review_floor": _review_policy_payload(self.trusted_review_floor),
            "candidate_sha": self.candidate_sha,
            "configuration_anchor_digest": self.configuration_anchor_digest,
            "ready_at": self.ready_at,
            "freshness_until": self.freshness_until,
            "record_identity": self.record_identity,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.payload())

    @classmethod
    def from_canonical(cls, material: str) -> "ReviewAuthorityEvidenceReceipt":
        try:
            value = json.loads(material)
            if type(value) is not dict or json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != material or set(value) != {
                "schema", "source_identity", "authority_identity", "runtime_store_source_identity", "authority_store_identity",
                "authority_receipt_digest", "policy_snapshot_digest", "trusted_review_floor",
                "candidate_sha", "configuration_anchor_digest", "ready_at", "freshness_until", "record_identity",
            } or value["schema"] != "roundwright-review-authority-evidence/v1":
                raise ValueError
            floor = ReviewPolicy(
                value["trusted_review_floor"]["complete_rounds"],
                value["trusted_review_floor"]["max_rounds"],
                value["trusted_review_floor"]["max_supervisor_attempts_per_round"],
                FinalFindingsPolicy(value["trusted_review_floor"]["on_final_findings"]),
            )
            return cls(
                value["source_identity"], value["authority_identity"], value["runtime_store_source_identity"], value["authority_store_identity"],
                value["authority_receipt_digest"], value["policy_snapshot_digest"], floor,
                value["candidate_sha"], value["configuration_anchor_digest"], value["ready_at"],
                value["freshness_until"], value["record_identity"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ConfigurationError("review authority evidence is not canonical") from error


@dataclass(frozen=True)
class ReviewAuthorityExpectation:
    """Independent pins that a dispatch configuration must authenticate.

    This is deliberately not derived from a candidate configuration or a
    persisted receipt.  A trusted bootstrap/control boundary supplies it and
    the file store merely proves that its immutable observation agrees.
    """

    source_identity: str
    authority_identity: str
    runtime_store_source_identity: str
    authority_store_identity: str
    authority_receipt_digest: str
    policy_snapshot_digest: str
    trusted_review_floor: ReviewPolicy
    candidate_sha: str
    configuration_anchor_digest: str
    ready_at: int
    freshness_until: int

    def __post_init__(self) -> None:
        if (not all(_is_digest(value) for value in (
            self.source_identity, self.authority_identity,
            self.runtime_store_source_identity, self.authority_store_identity, self.authority_receipt_digest,
            self.policy_snapshot_digest, self.configuration_anchor_digest,
        )) or type(self.trusted_review_floor) is not ReviewPolicy
                or type(self.candidate_sha) is not str or len(self.candidate_sha) != 40
                or any(character not in "0123456789abcdef" for character in self.candidate_sha)
                or type(self.ready_at) is not int or type(self.freshness_until) is not int
                or self.freshness_until < self.ready_at):
            raise ConfigurationError("review authority expectation is invalid")


class FileReviewAuthorityStore:
    """Explicit-root append-only store for independently pinned authority data."""

    def __init__(self, root: str | Path, *, expectation: ReviewAuthorityExpectation) -> None:
        if not isinstance(root, (str, os.PathLike)) or type(expectation) is not ReviewAuthorityExpectation:
            raise ConfigurationError("review authority store source is invalid")
        candidate = Path(root)
        # Resolve an ordinary spelling first: macOS /var and Windows junction
        # ancestors may legitimately normalize to a different canonical root.
        # The requested authority-store leaf itself must never be a reparse.
        if _reparse(candidate):
            raise ConfigurationError("review authority store root is invalid")
        candidate.mkdir(parents=True, exist_ok=True)
        resolved = candidate.resolve(strict=True)
        if _reparse(candidate) or _reparse(resolved) or not resolved.is_dir():
            raise ConfigurationError("review authority store root is invalid")
        self._root = resolved
        self.authority_store_identity = self.identity_for_root(resolved)
        if self.authority_store_identity != expectation.authority_store_identity:
            raise ConfigurationError("review authority store root is not independently pinned")
        self.expectation = expectation
        self.source_identity = expectation.source_identity
        self.authority_identity = expectation.authority_identity
        self.runtime_store_source_identity = expectation.runtime_store_source_identity

    @staticmethod
    def identity_for_root(root: str | Path) -> str:
        candidate = Path(root)
        # Identity is always of the canonical storage root, not a legitimate
        # platform spelling that traverses /var or a normalized ancestor.
        if _reparse(candidate):
            raise ConfigurationError("review authority store root is invalid")
        if candidate.exists():
            if not candidate.is_dir():
                raise ConfigurationError("review authority store root is invalid")
            resolved = candidate.resolve(strict=True)
        else:
            parent = candidate.parent.resolve(strict=True)
            if not parent.is_dir():
                raise ConfigurationError("review authority store root is invalid")
            resolved = parent / candidate.name
        if _reparse(resolved):
            raise ConfigurationError("review authority store root is invalid")
        return _digest({"schema": "roundwright-review-authority-store/v1", "canonical_root": os.path.normcase(os.path.normpath(os.fspath(resolved)))})

    def _path(self, record_identity: str) -> Path:
        if not _is_digest(record_identity):
            raise ConfigurationError("review authority record identity is invalid")
        path = self._root / record_identity.removeprefix("sha256:") / "authority.json"
        try:
            path.parent.relative_to(self._root)
        except ValueError as error:
            raise ConfigurationError("review authority record escapes its root") from error
        if _reparse(path.parent) or _reparse(path):
            raise ConfigurationError("review authority record path is invalid")
        return path

    def persist(self, authority: TrustedReviewAuthorityReceipt, *, candidate_sha: str, configuration_anchor_digest: str, ready_at: int, freshness_until: int) -> ReviewAuthorityEvidenceReceipt:
        expected = self.expectation
        if (type(authority) is not TrustedReviewAuthorityReceipt
                or (authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, authority.receipt_digest, authority.policy_snapshot_digest, authority.trusted_review_floor) != (expected.source_identity, expected.authority_identity, expected.runtime_store_source_identity, expected.authority_receipt_digest, expected.policy_snapshot_digest, expected.trusted_review_floor)
                or (candidate_sha, configuration_anchor_digest, ready_at, freshness_until) != (expected.candidate_sha, expected.configuration_anchor_digest, expected.ready_at, expected.freshness_until)):
            raise ConfigurationError("review authority source is not independently pinned")
        provisional = {
            "source_identity": authority.source_identity,
            "authority_identity": authority.authority_identity,
            "runtime_store_source_identity": authority.runtime_store_source_identity,
            "authority_store_identity": self.authority_store_identity,
            "authority_receipt_digest": authority.receipt_digest,
            "policy_snapshot_digest": authority.policy_snapshot_digest,
            "trusted_review_floor": _review_policy_payload(authority.trusted_review_floor),
            "candidate_sha": candidate_sha,
            "configuration_anchor_digest": configuration_anchor_digest,
            "ready_at": ready_at,
            "freshness_until": freshness_until,
        }
        record = _digest(provisional)
        receipt = ReviewAuthorityEvidenceReceipt(
            authority.source_identity, authority.authority_identity,
            authority.runtime_store_source_identity, self.authority_store_identity, authority.receipt_digest,
            authority.policy_snapshot_digest, authority.trusted_review_floor,
            candidate_sha, configuration_anchor_digest, ready_at, freshness_until,
            record,
        )
        path = self._path(record)
        path.parent.mkdir(parents=False, exist_ok=False)
        try:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(receipt.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
        except Exception:
            raise
        return receipt

    def read(self, receipt: ReviewAuthorityEvidenceReceipt, *, evidence_time: int) -> ReviewAuthorityEvidenceReceipt:
        if type(receipt) is not ReviewAuthorityEvidenceReceipt or type(evidence_time) is not int or not receipt.ready_at <= evidence_time <= receipt.freshness_until:
            raise ConfigurationError("review authority evidence time is invalid")
        expected = self.expectation
        if (receipt.source_identity, receipt.authority_identity, receipt.runtime_store_source_identity, receipt.authority_store_identity, receipt.authority_receipt_digest, receipt.policy_snapshot_digest, receipt.trusted_review_floor, receipt.candidate_sha, receipt.configuration_anchor_digest, receipt.ready_at, receipt.freshness_until) != (expected.source_identity, expected.authority_identity, expected.runtime_store_source_identity, expected.authority_store_identity, expected.authority_receipt_digest, expected.policy_snapshot_digest, expected.trusted_review_floor, expected.candidate_sha, expected.configuration_anchor_digest, expected.ready_at, expected.freshness_until):
            raise ConfigurationError("review authority source drifted")
        path = self._path(receipt.record_identity)
        try:
            material = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ConfigurationError("review authority evidence is unavailable") from error
        if _reparse(path) or material.endswith("\n") is False:
            raise ConfigurationError("review authority evidence is invalid")
        parsed = ReviewAuthorityEvidenceReceipt.from_canonical(material[:-1])
        if parsed != receipt or parsed.record_identity != _digest({key: value for key, value in parsed.payload().items() if key not in {"schema", "record_identity"}}):
            raise ConfigurationError("review authority evidence has drifted")
        return parsed


@dataclass(frozen=True)
class ResolvedConfigurationBinding:
    """Immutable evidence pinned before dispatch, review, Shadow, or mutation."""

    schema_version: str
    digest: str
    sources: Mapping[str, ConfigurationSource]
    worker_profile_identity: str
    supervisor_profile_identities: tuple[str, ...]
    review_policy: ReviewPolicy
    repository_root_identity: str | None
    cache_directory_identity: str
    trusted_review_floor: ReviewPolicy
    canonical_material: str = ""
    trusted_floor_evidence_required: bool = False

    def __post_init__(self) -> None:
        try:
            material = json.loads(self.canonical_material)
            if type(material) is not dict or json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != self.canonical_material or self.digest != _digest(material):
                raise ValueError
            base_keys = {"schema_version", "worker", "supervisor_attempt_profiles", "paths", "review", "trusted_review_floor", "sources"}
            if set(material) not in (base_keys, base_keys | {"trusted_floor_evidence"}) or set(material["paths"]) != {"repository_root", "cache_directory"}:
                raise ValueError
            policy = material["review"]
            profiles = tuple(_digest(item) for item in material["supervisor_attempt_profiles"])
            sources = {name: value.value for name, value in self.sources.items()}
            expected_source_keys = {"repository_root", "cache_directory", "roles.worker", "roles.supervisor.attempt_profiles", "review.complete_rounds", "review.max_rounds", "review.max_supervisor_attempts_per_round", "review.on_final_findings"}
            if set(material["sources"]) != expected_source_keys or set(sources) != expected_source_keys or material["schema_version"] != self.schema_version or _digest(material["worker"]) != self.worker_profile_identity or profiles != self.supervisor_profile_identities or len(set(profiles)) != len(profiles) or material["sources"] != sources or material["review"] != _review_policy_payload(self.review_policy) or material["trusted_review_floor"] != _review_policy_payload(self.trusted_review_floor) or material["paths"]["repository_root"] != self.repository_root_identity or material["paths"]["cache_directory"] != self.cache_directory_identity:
                raise ValueError
            self.review_policy.enforce_floor(self.trusted_review_floor)
            if self.review_policy.max_supervisor_attempts_per_round != len(self.supervisor_profile_identities): raise ValueError
            has_trusted_evidence = "trusted_floor_evidence" in material
            trusted_keys = {"source_identity", "authority_identity", "policy_snapshot_digest", "runtime_store_source_identity", "authority_store_identity", "authority_receipt_digest", "evidence_receipt_digest", "configuration_anchor_digest"}
            if self.trusted_floor_evidence_required != has_trusted_evidence or (has_trusted_evidence and (type(material["trusted_floor_evidence"]) is not dict or set(material["trusted_floor_evidence"]) != trusted_keys or not all(_is_digest(material["trusted_floor_evidence"][name]) for name in trusted_keys))): raise ValueError
            object.__setattr__(self, "sources", MappingProxyType(dict(self.sources)))
            object.__setattr__(self, "supervisor_profile_identities", tuple(self.supervisor_profile_identities))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ConfigurationError("resolved configuration binding is not self-authenticating") from error

    def require_matches(self, other: "ResolvedConfigurationBinding") -> None:
        if type(other) is not ResolvedConfigurationBinding or self != other:
            raise ConfigurationError("resolved configuration binding has drifted")

    def runtime_binding(self) -> RuntimeBinding:
        policy = self.review_policy
        policy_digest = _digest({
            "complete_rounds": policy.complete_rounds,
            "max_rounds": policy.max_rounds,
            "max_supervisor_attempts_per_round": policy.max_supervisor_attempts_per_round,
            "on_final_findings": policy.on_final_findings.value,
        }).removeprefix("sha256:")
        return RuntimeBinding(
            self.schema_version, self.digest, self.worker_profile_identity, self.supervisor_profile_identities,
            policy.complete_rounds, policy.max_rounds, policy.max_supervisor_attempts_per_round,
            policy.on_final_findings.value, policy_digest,
        )

    @property
    def trusted_floor_source_identity(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["source_identity"]

    @property
    def trusted_floor_authority_identity(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["authority_identity"]

    @property
    def trusted_floor_authority_receipt_digest(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["authority_receipt_digest"]

    @property
    def runtime_store_authority_identity(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["runtime_store_source_identity"]

    @property
    def review_authority_store_identity(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["authority_store_identity"]

    @property
    def review_authority_evidence_digest(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["evidence_receipt_digest"]

    @property
    def review_authority_configuration_anchor_digest(self) -> str | None:
        value = json.loads(self.canonical_material).get("trusted_floor_evidence")
        return None if value is None else value["configuration_anchor_digest"]


@dataclass(frozen=True)
class RepositoryIdentity:
    root: Path

    @classmethod
    def from_root(cls, root: Path) -> "RepositoryIdentity":
        try:
            normalized = root.expanduser().resolve(strict=True)
        except OSError as error:
            raise ConfigurationError("the repository root is unavailable") from error
        if not normalized.is_dir() or not _is_git_worktree_marker(normalized, normalized / ".git"):
            raise ConfigurationError("the repository root is not a Git worktree")
        return cls(normalized)

    @property
    def state_directory(self) -> Path:
        return self.resolve_path(".roundwright")

    def resolve_path(self, relative_path: str | Path) -> Path:
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise ConfigurationError("repository-relative paths must not be absolute")
        try:
            resolved = (self.root / candidate).resolve(strict=False)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as error:
            raise ConfigurationError("repository-relative path escapes the repository") from error
        return resolved


@dataclass(frozen=True)
class Configuration:
    """The resolved runtime snapshot; no later ambient drift can alter it."""

    repository_root: EffectiveValue[Path | None]
    cache_directory: EffectiveValue[Path]
    worker: EffectiveValue[ProviderProfile]
    supervisor_attempt_profiles: EffectiveValue[tuple[ProviderProfile, ...]]
    review: Mapping[str, EffectiveValue[object]]
    schema_version: str = _SCHEMA_VERSION
    repository_configuration_root: Path | None = None
    trusted_review_floor: ReviewPolicy | None = None
    trusted_policy_snapshot: TrustedPolicySnapshot | None = None
    trusted_review_authority_receipt: TrustedReviewAuthorityReceipt | None = None
    review_authority_evidence: ReviewAuthorityEvidenceReceipt | None = None

    @property
    def repository(self) -> RepositoryIdentity | None:
        return None if self.repository_root.value is None else RepositoryIdentity.from_root(self.repository_root.value)

    @property
    def review_policy(self) -> ReviewPolicy:
        return ReviewPolicy(
            complete_rounds=self.review["complete_rounds"].value,  # type: ignore[arg-type]
            max_rounds=self.review["max_rounds"].value,  # type: ignore[arg-type]
            max_supervisor_attempts_per_round=self.review["max_supervisor_attempts_per_round"].value,  # type: ignore[arg-type]
            on_final_findings=self.review["on_final_findings"].value,  # type: ignore[arg-type]
        )

    @property
    def sources(self) -> Mapping[str, ConfigurationSource]:
        values = {
            "repository_root": self.repository_root.source,
            "cache_directory": self.cache_directory.source,
            "roles.worker": self.worker.source,
            "roles.supervisor.attempt_profiles": self.supervisor_attempt_profiles.source,
        }
        values.update({f"review.{name}": value.source for name, value in self.review.items()})
        return values

    @property
    def resolved_digest(self) -> str:
        trusted_floor = self.review_policy if self.trusted_review_floor is None else self.trusted_review_floor
        return _digest({
            "schema_version": self.schema_version,
            "worker": _profile_payload(self.worker.value),
            "supervisor_attempt_profiles": [_profile_payload(item) for item in self.supervisor_attempt_profiles.value],
            "paths": {
                "repository_root": None if self.repository_root.value is None else _digest({"path": os.fspath(self.repository_root.value)}),
                "cache_directory": _digest({"path": os.fspath(self.cache_directory.value)}),
            },
            "review": {
                name: value.value.value if isinstance(value.value, Enum) else value.value
                for name, value in sorted(self.review.items())
            },
            "trusted_review_floor": _review_policy_payload(trusted_floor),
            "sources": {name: value.value for name, value in sorted(self.sources.items())},
        })

    def pin(self) -> ResolvedConfigurationBinding:
        trusted_floor = self.review_policy if self.trusted_review_floor is None else self.trusted_review_floor
        material = {
            "schema_version": self.schema_version,
            "worker": _profile_payload(self.worker.value),
            "supervisor_attempt_profiles": [_profile_payload(profile) for profile in self.supervisor_attempt_profiles.value],
            "paths": {"repository_root": None if self.repository_root.value is None else _digest({"path": os.fspath(self.repository_root.value)}), "cache_directory": _digest({"path": os.fspath(self.cache_directory.value)})},
            "review": _review_policy_payload(self.review_policy),
            "trusted_review_floor": _review_policy_payload(trusted_floor),
            "sources": {name: value.value for name, value in sorted(self.sources.items())},
        }
        if self.trusted_policy_snapshot is not None or self.trusted_review_authority_receipt is not None or self.review_authority_evidence is not None:
            authority = self.trusted_review_authority_receipt
            evidence = self.review_authority_evidence
            if authority is None or evidence is None or not _is_trusted_review_floor_evidence(self.trusted_policy_snapshot, trusted_floor) or authority != TrustedReviewAuthorityReceipt.from_snapshot(self.trusted_policy_snapshot, trusted_floor) or (evidence.source_identity, evidence.authority_identity, evidence.runtime_store_source_identity, evidence.authority_receipt_digest, evidence.policy_snapshot_digest, evidence.trusted_review_floor, evidence.configuration_anchor_digest) != (authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, authority.receipt_digest, authority.policy_snapshot_digest, trusted_floor, self.resolved_digest) or not _is_digest(evidence.authority_store_identity):
                raise ConfigurationError("trusted review policy evidence is unavailable")
            material["trusted_floor_evidence"] = {
                "source_identity": authority.source_identity,
                "authority_identity": authority.authority_identity,
                "policy_snapshot_digest": authority.policy_snapshot_digest,
                "runtime_store_source_identity": authority.runtime_store_source_identity,
                "authority_store_identity": evidence.authority_store_identity,
                "authority_receipt_digest": authority.receipt_digest,
                "evidence_receipt_digest": evidence.receipt_digest,
                "configuration_anchor_digest": evidence.configuration_anchor_digest,
            }
        canonical_material = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return ResolvedConfigurationBinding(
            self.schema_version,
            _digest(material),
            dict(self.sources),
            _digest(_profile_payload(self.worker.value)),
            tuple(_digest(_profile_payload(profile)) for profile in self.supervisor_attempt_profiles.value),
            self.review_policy,
            material["paths"]["repository_root"],
            material["paths"]["cache_directory"],
            trusted_floor,
            canonical_material,
            self.review_authority_evidence is not None,
        )


@dataclass(frozen=True)
class PreflightReport:
    mode: PreflightMode
    repository_ready: bool


def user_config_path(*, platform: str | None = None, environment: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    system, env, base_home = sys.platform if platform is None else platform, os.environ if environment is None else environment, Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "APPDATA", base_home / "AppData" / "Roaming") / "Roundwright" / "config.toml"
    if system == "darwin":
        return base_home / "Library" / "Application Support" / "roundwright" / "config.toml"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CONFIG_HOME", base_home / ".config") / "roundwright" / "config.toml"
    raise ConfigurationError("the platform is unsupported")


def user_cache_path(*, platform: str | None = None, environment: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    system, env, base_home = sys.platform if platform is None else platform, os.environ if environment is None else environment, Path.home() if home is None else home
    if system.startswith("win"):
        return _environment_directory(env, "LOCALAPPDATA", base_home / "AppData" / "Local") / "Roundwright" / "Cache"
    if system == "darwin":
        return base_home / "Library" / "Caches" / "roundwright"
    if system.startswith("linux"):
        return _environment_directory(env, "XDG_CACHE_HOME", base_home / ".cache") / "roundwright"
    raise ConfigurationError("the platform is unsupported")


def discover_repository(start: Path | None = None) -> RepositoryIdentity | None:
    try:
        current = (Path.cwd() if start is None else start).expanduser().resolve(strict=True)
    except OSError as error:
        raise ConfigurationError("the starting directory is unavailable") from error
    if not current.is_dir():
        raise ConfigurationError("the starting directory is not a directory")
    for directory in (current, *current.parents):
        if (directory / ".git").exists():
            return RepositoryIdentity.from_root(directory)
    return None


def load_configuration(*, cwd: Path | None = None, environment: Mapping[str, str] | None = None, cli_values: Mapping[str, object] | None = None, user_config: Path | None = None, authoritative_repository_root: Path | None = None, trusted_review_floor: ReviewPolicy | None = None, platform: str | None = None, home: Path | None = None, git_binding: object | None = None, git_entrypoint_control: object | None = None) -> Configuration:
    """Resolve defaults < user < authoritative repository < env < CLI.

    Repository configuration is read only from the discovered/validated root;
    no configuration layer may rebind that root or carry authority switches.
    """
    env = os.environ if environment is None else environment
    repository = discover_repository(cwd)
    raw, sources = _default_runtime()[0], {}
    _mark_all(sources, raw, ConfigurationSource.DEFAULT)
    paths: dict[str, EffectiveValue[Path | None]] = {
        "repository_root": EffectiveValue(repository.root if repository else None, ConfigurationSource.DEFAULT),
        "cache_directory": EffectiveValue(user_cache_path(platform=platform, environment=env, home=home), ConfigurationSource.DEFAULT),
    }
    configured_user = user_config_path(platform=platform, environment=env, home=home) if user_config is None else user_config
    user_values = _read_runtime_toml(configured_user, required=user_config is not None)
    _apply_paths(paths, user_values.get("paths", {}), ConfigurationSource.USER)
    _merge_runtime(raw, sources, user_values, ConfigurationSource.USER)
    if paths["repository_root"].value is not None:
        repository = RepositoryIdentity.from_root(paths["repository_root"].value)
    repository_config_root: Path | None = None
    if authoritative_repository_root is None and repository is not None and git_binding is not None and git_entrypoint_control is not None:
        authoritative_repository_root = discover_authoritative_repository(
            repository, binding=git_binding, control=git_entrypoint_control,
        )
    if authoritative_repository_root is not None:
        authoritative_root = _validated_authoritative_repository(
            authoritative_repository_root, binding=git_binding, control=git_entrypoint_control,
        )
        repository_values = _read_authoritative_runtime_toml(
            authoritative_root, binding=git_binding, control=git_entrypoint_control,
        )
        _apply_paths(paths, repository_values.get("paths", {}), ConfigurationSource.REPOSITORY, required_repository_root=authoritative_root)
        # The validated authoritative repository remains the mutation target
        # even when it intentionally has no optional runtime TOML.
        repository_config_root = authoritative_root
        _merge_runtime(raw, sources, repository_values, ConfigurationSource.REPOSITORY)
    _merge_runtime(raw, sources, _environment_updates(env), ConfigurationSource.ENVIRONMENT)
    _apply_paths(paths, _environment_path_updates(env), ConfigurationSource.ENVIRONMENT)
    cli_updates = _cli_updates(cli_values or {})
    _apply_paths(paths, cli_updates.get("paths", {}), ConfigurationSource.COMMAND_LINE)
    _merge_runtime(raw, sources, cli_updates, ConfigurationSource.COMMAND_LINE)
    worker = _parse_profile(raw["roles"]["worker"], name_required=False)
    supervisors = tuple(_parse_profile(value, name_required=True) for value in raw["roles"]["supervisor"]["attempt_profiles"])
    review = _parse_review(raw["review"])
    if trusted_review_floor is not None:
        review.enforce_floor(trusted_review_floor)
    if len(supervisors) != review.max_supervisor_attempts_per_round:
        raise ConfigurationError("supervisor profile count must equal the configured attempt budget")
    if len({item.name for item in supervisors}) != len(supervisors):
        raise ConfigurationError("supervisor profile names must be unique")
    return Configuration(
        repository_root=paths["repository_root"],
        cache_directory=paths["cache_directory"],  # type: ignore[arg-type]
        worker=EffectiveValue(worker, sources["roles.worker"]),
        supervisor_attempt_profiles=EffectiveValue(supervisors, sources["roles.supervisor.attempt_profiles"]),
        review={name: EffectiveValue(value, sources[f"review.{name}"]) for name, value in review.__dict__.items()},
        repository_configuration_root=repository_config_root,
        trusted_review_floor=trusted_review_floor,
    )


def resolve_dispatch_configuration(*, trusted_policy_snapshot: object, trusted_review_floor: object, trusted_review_authority_receipt: object | None = None, review_authority_expectation: object | None = None, review_authority_store: object | None = None, review_authority_evidence: object | None = None, candidate_sha: object | None = None, evidence_time: object | None = None, cwd: Path | None = None, environment: Mapping[str, str] | None = None, cli_values: Mapping[str, object] | None = None, user_config: Path | None = None, authoritative_repository_root: Path | None = None, platform: str | None = None, home: Path | None = None, git_binding: object | None = None, git_entrypoint_control: object | None = None) -> Configuration:
    """Resolve dispatch-capable configuration only under typed trusted control evidence."""

    if not _is_trusted_review_floor_evidence(trusted_policy_snapshot, trusted_review_floor):
        raise ConfigurationError("trusted review policy evidence is unavailable")
    if type(review_authority_expectation) is not ReviewAuthorityExpectation or type(candidate_sha) is not str or type(evidence_time) is not int:
        raise ConfigurationError("independent review authority evidence is unavailable")
    expected_authority = TrustedReviewAuthorityReceipt.from_snapshot(trusted_policy_snapshot, trusted_review_floor)
    if type(trusted_review_authority_receipt) is not TrustedReviewAuthorityReceipt or trusted_review_authority_receipt != expected_authority or (expected_authority.source_identity, expected_authority.authority_identity, expected_authority.runtime_store_source_identity, expected_authority.receipt_digest, expected_authority.policy_snapshot_digest, expected_authority.trusted_review_floor, candidate_sha) != (review_authority_expectation.source_identity, review_authority_expectation.authority_identity, review_authority_expectation.runtime_store_source_identity, review_authority_expectation.authority_receipt_digest, review_authority_expectation.policy_snapshot_digest, review_authority_expectation.trusted_review_floor, review_authority_expectation.candidate_sha):
        raise ConfigurationError("trusted review authority receipt is unavailable")
    try:
        trusted_policy_snapshot.policy_digest
    except (AttributeError, TypeError, ValueError):
        raise ConfigurationError("trusted review policy evidence is unavailable") from None
    provisional = load_configuration(
        cwd=cwd,
        environment=environment,
        cli_values=cli_values,
        user_config=user_config,
        authoritative_repository_root=authoritative_repository_root,
        trusted_review_floor=trusted_review_floor,
        platform=platform,
        home=home,
        git_binding=git_binding,
        git_entrypoint_control=git_entrypoint_control,
    )
    if provisional.resolved_digest != review_authority_expectation.configuration_anchor_digest:
        raise ConfigurationError("review authority configuration anchor is unavailable")
    if type(review_authority_store) is not FileReviewAuthorityStore or review_authority_store.expectation != review_authority_expectation or type(review_authority_evidence) is not ReviewAuthorityEvidenceReceipt:
        raise ConfigurationError("independent review authority evidence is unavailable")
    try:
        evidence = review_authority_store.read(review_authority_evidence, evidence_time=evidence_time)
    except Exception as error:
        raise ConfigurationError("independent review authority evidence is unavailable") from error
    if evidence is review_authority_evidence or (review_authority_store.authority_store_identity != review_authority_expectation.authority_store_identity or evidence.source_identity, evidence.authority_identity, evidence.runtime_store_source_identity, evidence.authority_store_identity, evidence.authority_receipt_digest, evidence.policy_snapshot_digest, evidence.trusted_review_floor, evidence.candidate_sha, evidence.configuration_anchor_digest, evidence.ready_at, evidence.freshness_until) != (review_authority_expectation.source_identity, review_authority_expectation.authority_identity, review_authority_expectation.runtime_store_source_identity, review_authority_expectation.authority_store_identity, review_authority_expectation.authority_receipt_digest, review_authority_expectation.policy_snapshot_digest, review_authority_expectation.trusted_review_floor, review_authority_expectation.candidate_sha, review_authority_expectation.configuration_anchor_digest, review_authority_expectation.ready_at, review_authority_expectation.freshness_until):
        raise ConfigurationError("independent review authority evidence has drifted")
    return replace(provisional, trusted_policy_snapshot=trusted_policy_snapshot, trusted_review_authority_receipt=trusted_review_authority_receipt, review_authority_evidence=evidence)


def _is_trusted_review_floor_evidence(snapshot: object, floor: object) -> bool:
    try:
        if (
            type(snapshot) is not TrustedPolicySnapshot
            or type(snapshot.source) is not TrustedControlSource
            or type(snapshot.document) is not PolicyDocument
            or type(floor) is not ReviewPolicy
            or type(floor.complete_rounds) is not int
            or type(floor.max_rounds) is not int
            or type(floor.max_supervisor_attempts_per_round) is not int
            or not isinstance(floor.on_final_findings, FinalFindingsPolicy)
            or floor.complete_rounds <= 0
            or floor.max_rounds < floor.complete_rounds
            or floor.max_supervisor_attempts_per_round <= 0
        ):
            return False
        for value in (snapshot.source.source_fingerprint, snapshot.source.revision_fingerprint, snapshot.policy_digest):
            if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                return False
        return snapshot.document.schema_version == 1 and type(snapshot.document.allowed_actions) is frozenset
    except (AttributeError, TypeError, ValueError):
        return False


def preflight(configuration: Configuration, mode: PreflightMode | str) -> PreflightReport:
    try:
        selected = PreflightMode(mode)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("the capability preflight mode is unsupported") from error
    repository = configuration.repository
    if selected is PreflightMode.DISPATCH_CAPABLE and repository is None:
        raise ConfigurationError("dispatch-capable commands require a repository root")
    if selected is PreflightMode.DISPATCH_CAPABLE and configuration.repository_configuration_root is not None and repository is not None and repository.root != configuration.repository_configuration_root:
        raise ConfigurationError("repository configuration does not match the effective repository root")
    return PreflightReport(selected, repository is not None)


def _default_runtime() -> tuple[dict[str, Any], dict[str, ConfigurationSource]]:
    try:
        document = tomllib.loads(resources.files("roundwright").joinpath("runtime-defaults.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("packaged runtime defaults are unavailable") from error
    _validate_document(document, complete=True)
    return document, {}


def _read_runtime_toml(path: Path, *, required: bool) -> dict[str, Any]:
    if not path.exists():
        if required:
            raise ConfigurationError("an explicit configuration file is unavailable")
        return {}
    if not path.is_file():
        raise ConfigurationError("a configuration location is not a regular file")
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("configuration TOML is malformed or unreadable") from error
    _validate_document(document, complete=False)
    return document


def _validated_authoritative_repository(root: Path, *, binding: object, control: object) -> Path:
    """Accept persistent repository settings only from checked-out origin/main."""
    _require_configuration_git_control(binding, control)
    repository = RepositoryIdentity.from_root(root)
    try:
        branch = subprocess.run(["git", "-C", os.fspath(repository.root), "symbolic-ref", "--quiet", "--short", "HEAD"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        head = subprocess.run(["git", "-C", os.fspath(repository.root), "rev-parse", "--verify", "HEAD^{commit}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        remote = subprocess.run(["git", "-C", os.fspath(repository.root), "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        origin = subprocess.run(["git", "-C", os.fspath(repository.root), "config", "--get", "remote.origin.url"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        status = subprocess.run(["git", "-C", os.fspath(repository.root), "status", "--porcelain=v1", "--ignored=matching", "--untracked-files=all", "--", _REPOSITORY_CONFIG], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        index = subprocess.run(["git", "-C", os.fspath(repository.root), "ls-files", "--stage", "--", _REPOSITORY_CONFIG], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        unmerged = subprocess.run(["git", "-C", os.fspath(repository.root), "ls-files", "--stage", "--unmerged", "--", _REPOSITORY_CONFIG], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
        flags = subprocess.run(["git", "-C", os.fspath(repository.root), "ls-files", "-v", "--", _REPOSITORY_CONFIG], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConfigurationError("authoritative repository identity is unavailable") from error
    index_entries = [line for line in index.stdout.splitlines() if line]
    ordinary_index = not index_entries
    if len(index_entries) == 1:
        fields, separator, path = index_entries[0].partition("\t")
        parts = fields.split()
        mode, object_id, stage = parts if separator and len(parts) == 3 else ("", "", "")
        ordinary_index = mode == "100644" and len(object_id) == 40 and stage == "0" and path == _REPOSITORY_CONFIG
    flag_entries = [line for line in flags.stdout.splitlines() if line]
    visible_flags = not index_entries and not flag_entries
    if len(index_entries) == 1:
        visible_flags = flag_entries == [f"H {_REPOSITORY_CONFIG}"]
    if branch.returncode or head.returncode or remote.returncode or origin.returncode or status.returncode or index.returncode or unmerged.returncode or flags.returncode or branch.stdout.strip() != "main" or head.stdout.strip() != remote.stdout.strip() or remote.stdout.strip() != binding.candidate_sha or not _origin_matches(origin.stdout.strip()) or status.stdout.strip() or unmerged.stdout.strip() or not ordinary_index or not visible_flags:
        raise ConfigurationError("repository configuration is not from authoritative main")
    return repository.root


def _read_authoritative_runtime_toml(root: Path, *, binding: object, control: object) -> dict[str, Any]:
    """Read configuration only from the exact origin/main Git blob, never checkout bytes."""

    _require_configuration_git_control(binding, control)
    repository = RepositoryIdentity.from_root(root)
    try:
        remote = subprocess.run(["git", "-C", os.fspath(repository.root), "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConfigurationError("authoritative repository configuration is unavailable") from error
    if remote.returncode or remote.stdout.strip() != binding.candidate_sha:
        raise ConfigurationError("authoritative repository configuration is unavailable")
    try:
        blob = subprocess.run(["git", "-C", os.fspath(repository.root), "show", f"{remote.stdout.strip()}:{_REPOSITORY_CONFIG}"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ConfigurationError("authoritative repository configuration is unavailable") from error
    if blob.returncode == 128:
        return {}
    if blob.returncode:
        raise ConfigurationError("authoritative repository configuration is unavailable")
    try:
        document = tomllib.loads(blob.stdout.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigurationError("authoritative repository configuration is malformed") from error
    _validate_document(document, complete=False)
    return document


def discover_authoritative_repository(repository: RepositoryIdentity, *, binding: object, control: object) -> Path | None:
    """Locate the sole clean local worktree checked out at trusted origin/main."""
    _require_configuration_git_control(binding, control)
    try:
        listed = subprocess.run(["git", "-C", os.fspath(repository.root), "worktree", "list", "--porcelain"], check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5, env=_hermetic_git_environment())
    except (OSError, subprocess.TimeoutExpired):
        return None
    if listed.returncode:
        return None
    roots = [Path(line.removeprefix("worktree ")) for line in listed.stdout.splitlines() if line.startswith("worktree ")]
    candidates: list[Path] = []
    for root in roots:
        try:
            candidates.append(_validated_authoritative_repository(root, binding=binding, control=control))
        except ConfigurationError:
            continue
    if len(candidates) > 1:
        raise ConfigurationError("authoritative repository identity is ambiguous")
    return candidates[0] if candidates else None


def _origin_matches(value: str) -> bool:
    normalized = value.strip().removesuffix(".git")
    accepted = {
        f"https://github.com/{_EXPECTED_REPOSITORY}",
        f"http://github.com/{_EXPECTED_REPOSITORY}",
        f"ssh://git@github.com/{_EXPECTED_REPOSITORY}",
        f"git@github.com:{_EXPECTED_REPOSITORY}",
    }
    return normalized.casefold() in {item.casefold() for item in accepted}


def _validate_document(document: object, *, complete: bool) -> None:
    if type(document) is not dict or set(document) - {"runtime", "paths", "roles", "review"}:
        raise ConfigurationError("configuration contains an unknown section")
    if complete and set(document) != {"runtime", "roles", "review"}:
        raise ConfigurationError("packaged runtime defaults are incomplete")
    runtime = document.get("runtime")
    if runtime is not None:
        if type(runtime) is not dict or set(runtime) != {"schema_version"} or runtime.get("schema_version") != _SCHEMA_VERSION:
            raise ConfigurationError("configuration schema version is unsupported")
    elif complete:
        raise ConfigurationError("configuration schema version is missing")
    paths = document.get("paths")
    if paths is not None:
        if type(paths) is not dict or set(paths) - {"repository_root", "cache_directory"} or not all(isinstance(item, (str, Path)) and str(item).strip() for item in paths.values()):
            raise ConfigurationError("configuration path settings are unsupported")
    roles = document.get("roles")
    if roles is not None:
        if type(roles) is not dict or set(roles) - {"worker", "supervisor"}:
            raise ConfigurationError("configuration contains an unknown role")
        if "worker" in roles:
            _validate_profile_document(roles["worker"], name_required=False)
        if "supervisor" in roles:
            supervisor = roles["supervisor"]
            if type(supervisor) is not dict or set(supervisor) != {"attempt_profiles"} or type(supervisor["attempt_profiles"]) is not list or not supervisor["attempt_profiles"]:
                raise ConfigurationError("supervisor profiles must be replaced as one non-empty list")
            for item in supervisor["attempt_profiles"]:
                _validate_profile_document(item, name_required=True)
        if complete and set(roles) != {"worker", "supervisor"}:
            raise ConfigurationError("packaged runtime roles are incomplete")
    elif complete:
        raise ConfigurationError("packaged runtime roles are missing")
    review = document.get("review")
    fields = {"complete_rounds", "max_rounds", "max_supervisor_attempts_per_round", "on_final_findings"}
    if review is not None:
        if type(review) is not dict or set(review) - fields:
            raise ConfigurationError("configuration contains an unknown review setting")
        if complete and set(review) != fields:
            raise ConfigurationError("packaged review policy is incomplete")
    elif complete:
        raise ConfigurationError("packaged review policy is missing")


def _validate_profile_document(value: object, *, name_required: bool) -> None:
    required = {"model", "reasoning_effort"} | ({"name"} if name_required else set())
    if type(value) is not dict or set(value) != required:
        raise ConfigurationError("role profile data is partial, aliased, or unsupported")


def _merge_runtime(current: dict[str, Any], sources: dict[str, ConfigurationSource], update: dict[str, Any], source: ConfigurationSource) -> None:
    if not update:
        return
    if "roles" in update:
        roles = update["roles"]
        if "worker" in roles:
            current["roles"]["worker"] = roles["worker"]
            sources["roles.worker"] = source
        if "supervisor" in roles:
            current["roles"]["supervisor"] = roles["supervisor"]
            sources["roles.supervisor.attempt_profiles"] = source
    if "review" in update:
        current["review"].update(update["review"])
        for name in update["review"]:
            sources[f"review.{name}"] = source


def _mark_all(sources: dict[str, ConfigurationSource], runtime: dict[str, Any], source: ConfigurationSource) -> None:
    sources["roles.worker"] = source
    sources["roles.supervisor.attempt_profiles"] = source
    for name in runtime["review"]:
        sources[f"review.{name}"] = source


def _environment_updates(environment: Mapping[str, str]) -> dict[str, Any]:
    review = {name: environment[variable] for name, variable in _REVIEW_ENVIRONMENT_KEYS.items() if variable in environment}
    return {} if not review else {"review": review}


def _environment_path_updates(environment: Mapping[str, str]) -> dict[str, object]:
    return {name: environment[key] for name, key in _PATH_ENVIRONMENT_KEYS.items() if key in environment}


def _cli_updates(values: Mapping[str, object]) -> dict[str, Any]:
    update: dict[str, Any] = {}
    for key, value in values.items():
        if key.startswith("review."):
            name = key.removeprefix("review.")
            if name not in _REVIEW_ENVIRONMENT_KEYS:
                raise ConfigurationError("configuration contains an unknown review setting")
            update.setdefault("review", {})[name] = value
        elif key == "roles.worker":
            update.setdefault("roles", {})["worker"] = value
        elif key == "roles.supervisor.attempt_profiles":
            update.setdefault("roles", {})["supervisor"] = {"attempt_profiles": value}
        elif key in {"repository_root", "cache_directory"}:
            update.setdefault("paths", {})[key] = value
        else:
            raise ConfigurationError("CLI override is unsupported")
    _validate_document(update, complete=False)
    return update


def _apply_paths(current: dict[str, EffectiveValue[Path | None]], updates: Mapping[str, object], source: ConfigurationSource, *, required_repository_root: Path | None = None) -> None:
    for name, raw in updates.items():
        if name not in {"repository_root", "cache_directory"} or not isinstance(raw, (str, Path)) or not str(raw).strip():
            raise ConfigurationError("configuration path settings are unsupported")
        value = Path(raw).expanduser()
        if not value.is_absolute():
            raise ConfigurationError("configuration paths must be absolute")
        if name == "repository_root":
            root = RepositoryIdentity.from_root(value).root
            if required_repository_root is not None and root != required_repository_root:
                raise ConfigurationError("repository configuration must not rebind the repository root")
            current[name] = EffectiveValue(root, source)
        else:
            current[name] = EffectiveValue(value, source)


def parse_cli_overrides(values: list[str]) -> dict[str, object]:
    """Parse one-shot ``--set key=value`` values without accepting aliases."""
    parsed: dict[str, object] = {}
    for item in values:
        if type(item) is not str or item.count("=") != 1:
            raise ConfigurationError("CLI override must be one key=value pair")
        key, raw = item.split("=", 1)
        if not key or not raw or key in parsed:
            raise ConfigurationError("CLI override is empty or duplicated")
        if key == "roles.supervisor.attempt_profiles":
            try:
                parsed[key] = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ConfigurationError("supervisor profiles CLI override must be JSON") from error
        elif key == "roles.worker":
            try:
                parsed[key] = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ConfigurationError("worker CLI override must be JSON") from error
        else:
            parsed[key] = raw
    return parsed


def _parse_profile(value: object, *, name_required: bool) -> ProviderProfile:
    _validate_profile_document(value, name_required=name_required)
    assert type(value) is dict
    model, effort = value["model"], value["reasoning_effort"]
    if type(model) is not str or model not in _SUPPORTED_MODELS:
        raise ConfigurationError("the configured model is unsupported")
    try:
        reasoning_effort = ReasoningEffort(effort)
    except (TypeError, ValueError) as error:
        raise ConfigurationError("the configured reasoning effort is unsupported") from error
    name = value.get("name")
    if name_required and (type(name) is not str or not name or any(character.isspace() for character in name)):
        raise ConfigurationError("supervisor profile name is invalid")
    return ProviderProfile(model, reasoning_effort, name)


def _parse_review(value: object) -> ReviewPolicy:
    fields = {"complete_rounds", "max_rounds", "max_supervisor_attempts_per_round", "on_final_findings"}
    if type(value) is not dict or set(value) != fields:
        raise ConfigurationError("review policy is incomplete")
    integers = ("complete_rounds", "max_rounds", "max_supervisor_attempts_per_round")
    parsed: dict[str, int] = {}
    for name in integers:
        raw = value[name]
        try:
            candidate = int(raw) if type(raw) is str and raw.isdecimal() else raw
        except ValueError as error:
            raise ConfigurationError("review limits must be positive integers") from error
        if type(candidate) is not int or candidate <= 0:
            raise ConfigurationError("review limits must be positive integers")
        parsed[name] = candidate
    if parsed["complete_rounds"] > parsed["max_rounds"]:
        raise ConfigurationError("complete review rounds cannot exceed maximum review rounds")
    try:
        terminal = FinalFindingsPolicy(value["on_final_findings"])
    except (TypeError, ValueError) as error:
        raise ConfigurationError("review terminal policy is unsupported") from error
    return ReviewPolicy(**parsed, on_final_findings=terminal)


def _profile_payload(profile: ProviderProfile) -> dict[str, str]:
    result = {"model": profile.model, "reasoning_effort": profile.reasoning_effort.value}
    if profile.name is not None:
        result["name"] = profile.name
    return result


def _review_policy_payload(policy: ReviewPolicy | None) -> dict[str, object] | None:
    if policy is None:
        return None
    return {
        "complete_rounds": policy.complete_rounds,
        "max_rounds": policy.max_rounds,
        "max_supervisor_attempts_per_round": policy.max_supervisor_attempts_per_round,
        "on_final_findings": policy.on_final_findings.value,
    }


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _reparse(path: Path) -> bool:
    """Treat Windows junctions as authority-store traversal, like symlinks."""
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _is_digest(value: object) -> bool:
    return type(value) is str and len(value) == 71 and value.startswith("sha256:") and all(character in "0123456789abcdef" for character in value[7:])


def _environment_directory(environment: Mapping[str, str], name: str, fallback: Path) -> Path:
    raw_value = environment.get(name)
    if raw_value is None:
        return fallback
    if type(raw_value) is not str or not raw_value.strip():
        raise ConfigurationError("a platform configuration directory is invalid")
    directory = Path(raw_value).expanduser()
    if not directory.is_absolute():
        raise ConfigurationError("a platform configuration directory is invalid")
    return directory


def _is_git_worktree_marker(root: Path, marker: Path) -> bool:
    try:
        if _has_repository_selecting_git_environment() or _is_reparse_point(marker):
            return False
        if marker.is_dir():
            return _is_complete_git_directory(marker)
        if not marker.is_file():
            return False
        pointer = marker.read_text(encoding="utf-8").strip()
        if not pointer.startswith("gitdir:"):
            return False
        target = Path(pointer.removeprefix("gitdir:").strip())
        if not target.is_absolute():
            target = marker.parent / target
        normalized_target = target.resolve(strict=True)
        return _is_bound_linked_worktree(root, marker, normalized_target)
    except (OSError, ValueError):
        return False


def _require_configuration_git_control(binding: object, control: object) -> None:
    """Authorize an authoritative configuration Git read before any Git helper.

    This lazy import avoids a configuration/git-identity import cycle while
    keeping the control's exact runtime type private to the execution seam.
    """

    from .dependency_policy import CandidateBinding, DependencyStage
    from .git_identity import GitEntrypointControl, GitIdentityError

    if type(binding) is not CandidateBinding or type(control) is not GitEntrypointControl:
        raise ConfigurationError("authoritative repository Git control is unavailable")
    if control.binding != binding or binding.repository != _EXPECTED_REPOSITORY:
        raise ConfigurationError("authoritative repository Git control does not match the active task")
    try:
        control.dependency_control.require(binding, DependencyStage.GIT_ENTRYPOINT, now=control.now)
    except (GitIdentityError, ValueError, TypeError):
        raise ConfigurationError("authoritative repository Git preflight blocked execution") from None


def _has_repository_selecting_git_environment() -> bool:
    return any(name in os.environ for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"))


def _hermetic_git_environment() -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _is_reparse_point(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _is_complete_git_directory(directory: Path) -> bool:
    return all(((directory / "HEAD").is_file(), (directory / "config").is_file(), (directory / "objects").is_dir(), (directory / "refs").is_dir()))


def _is_bound_linked_worktree(root: Path, marker: Path, git_directory: Path) -> bool:
    commondir, backlink = git_directory / "commondir", git_directory / "gitdir"
    if _is_reparse_point(git_directory) or not git_directory.is_dir() or not (git_directory / "HEAD").is_file() or not commondir.is_file() or not backlink.is_file():
        return False
    common_directory, bound_marker = _read_git_pointer(commondir, git_directory), _read_git_pointer(backlink, git_directory)
    return common_directory is not None and bound_marker is not None and _is_complete_git_directory(common_directory) and bound_marker == marker.resolve(strict=True) and root == marker.parent


def _read_git_pointer(pointer: Path, relative_to: Path) -> Path | None:
    try:
        raw_value = pointer.read_text(encoding="utf-8").strip()
        if not raw_value:
            return None
        target = Path(raw_value)
        return (target if target.is_absolute() else relative_to / target).resolve(strict=True)
    except (OSError, ValueError):
        return None
