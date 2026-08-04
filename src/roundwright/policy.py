"""Pure, fail-closed trusted-policy activation.

This module deliberately has no filesystem, network, credential, subprocess,
or mutation dependency.  An Orchestrator must obtain a reviewed control-source
snapshot and owner receipt elsewhere, then pass their public-safe identities to
this evaluator.  In particular, a task worktree is never a policy source.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from .runtime_binding import RuntimeBinding

_DEFAULT_RUNTIME_BINDING = RuntimeBinding("roundwright-runtime/v1", "sha256:" + "0" * 64, "sha256:" + "1" * 64, tuple("sha256:" + value * 64 for value in "234"))


POLICY_SCHEMA_VERSION = 1
_FINGERPRINT_LENGTH = 64
_COMMIT_SHA_LENGTHS = frozenset({40, 64})


class PolicyError(ValueError):
    """Raised when a policy input cannot be safely interpreted."""


class PolicyAction(str, Enum):
    """Named authority scopes; this module does not execute any action."""

    ISSUE_COMMENT = "issue-comment"
    PULL_REQUEST_READY = "pull-request-ready"
    MERGE_PULL_REQUEST = "merge-pull-request"
    RELEASE = "release"


class ReceiptStatus(str, Enum):
    """Externally observed lifecycle state for an activation receipt."""

    FRESH = "fresh"
    CONSUMED = "consumed"
    CONFLICTING = "conflicting"
    REVOKED = "revoked"


@dataclass(frozen=True)
class TrustedControlSource:
    """An externally verified immutable control-source identity.

    Both fields are digests rather than URLs or paths, so diagnostics cannot
    disclose private control-plane locations.
    """

    source_fingerprint: str
    revision_fingerprint: str

    def __post_init__(self) -> None:
        _require_fingerprint(self.source_fingerprint, "control source")
        _require_fingerprint(self.revision_fingerprint, "control revision")


@dataclass(frozen=True)
class PolicyDocument:
    """The one versioned policy shape accepted by this release."""

    schema_version: int
    allowed_actions: frozenset[PolicyAction]

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != POLICY_SCHEMA_VERSION
        ):
            raise PolicyError("the policy schema version is unsupported")
        if (
            type(self.allowed_actions) is not frozenset
            or not all(isinstance(action, PolicyAction) for action in self.allowed_actions)
        ):
            raise PolicyError("the policy actions are invalid")

    def canonical_bytes(self) -> bytes:
        """Return the stable representation used for the content digest."""

        return _canonical_policy_bytes(self)

    @property
    def digest(self) -> str:
        return _policy_digest(self)


@dataclass(frozen=True)
class TrustedPolicySnapshot:
    """A policy document supplied from a trusted, immutable control source."""

    source: TrustedControlSource
    document: PolicyDocument

    @property
    def policy_digest(self) -> str:
        return _policy_digest(self.document)


@dataclass(frozen=True)
class StandingAuthority:
    """Reviewed authority ceiling that policy is allowed only to narrow."""

    allowed_actions: frozenset[PolicyAction]

    def __post_init__(self) -> None:
        if (
            type(self.allowed_actions) is not frozenset
            or not all(isinstance(action, PolicyAction) for action in self.allowed_actions)
        ):
            raise PolicyError("the standing authority actions are invalid")


@dataclass(frozen=True)
class ActivationReceipt:
    """An externally verified owner activation binding for one task candidate."""

    owner_fingerprint: str
    receipt_fingerprint: str
    source_fingerprint: str
    revision_fingerprint: str
    policy_digest: str
    schema_version: int
    task_fingerprint: str
    candidate_sha: str
    activated_at: datetime
    expires_at: datetime
    runtime_binding: RuntimeBinding = _DEFAULT_RUNTIME_BINDING

    def __post_init__(self) -> None:
        for value, description in (
            (self.owner_fingerprint, "owner receipt"),
            (self.receipt_fingerprint, "activation receipt"),
            (self.source_fingerprint, "receipt source"),
            (self.revision_fingerprint, "receipt revision"),
            (self.policy_digest, "receipt policy digest"),
            (self.task_fingerprint, "receipt task"),
        ):
            _require_fingerprint(value, description)
        _require_commit_sha(self.candidate_sha, "receipt candidate")
        if (
            type(self.schema_version) is not int
            or self.schema_version != POLICY_SCHEMA_VERSION
        ):
            raise PolicyError("the receipt schema version is unsupported")
        _require_utc(self.activated_at, "activation timestamp")
        _require_utc(self.expires_at, "receipt expiry")
        if self.expires_at <= self.activated_at:
            raise PolicyError("the activation receipt has an invalid lifetime")
        if type(self.runtime_binding) is not RuntimeBinding:
            raise PolicyError("the activation receipt runtime configuration binding is invalid")


@dataclass(frozen=True)
class PolicyDecision:
    """An owner-safe result that a future mutation layer may consume."""

    authorized: bool
    reason: str
    schema_version: int | None
    source_fingerprint: str | None
    policy_digest: str | None
    receipt_fingerprint: str | None
    activated_at: datetime | None
    allowed_actions: frozenset[PolicyAction]

    def diagnostic(self) -> Mapping[str, str | bool | int | None]:
        """Return only status and fingerprints, never credentials or paths."""

        return {
            "authorized": self.authorized,
            "reason": self.reason,
            "schema_version": self.schema_version,
            "source_fingerprint": self.source_fingerprint,
            "policy_digest": self.policy_digest,
            "receipt_fingerprint": self.receipt_fingerprint,
            "activated_at": self.activated_at.isoformat()
            if type(self.activated_at) is datetime
            else None,
        }


def parse_policy_document(contents: bytes | str) -> PolicyDocument:
    """Parse an exact typed policy document and reject unknown fields."""

    try:
        raw = json.loads(contents)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError("the policy document is malformed") from error
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "allowed_actions"}:
        raise PolicyError("the policy document contains unsupported fields")
    version = raw["schema_version"]
    actions = raw["allowed_actions"]
    if not isinstance(version, int) or isinstance(version, bool):
        raise PolicyError("the policy schema version is invalid")
    if not isinstance(actions, list) or any(not isinstance(value, str) for value in actions):
        raise PolicyError("the policy actions are invalid")
    try:
        typed_actions = frozenset(PolicyAction(value) for value in actions)
    except ValueError as error:
        raise PolicyError("the policy contains an unknown authority action") from error
    if len(typed_actions) != len(actions):
        raise PolicyError("the policy contains duplicate authority actions")
    return PolicyDocument(schema_version=version, allowed_actions=typed_actions)


def evaluate_policy(
    snapshot: TrustedPolicySnapshot | None,
    receipt: ActivationReceipt | None,
    *,
    task_fingerprint: str,
    candidate_sha: str,
    standing_authority: StandingAuthority,
    now: datetime,
    receipt_status: ReceiptStatus | None = None,
) -> PolicyDecision:
    """Evaluate one receipt-bound policy without performing any mutation.

    ``snapshot`` is deliberately an explicit input: callers cannot make a
    candidate worktree file authoritative by changing a path or environment
    variable.  Any inconsistency returns a deny decision rather than a partial
    authorization.
    """

    if type(snapshot) is not TrustedPolicySnapshot:
        return _denied("trusted policy evidence is unavailable", snapshot, receipt)
    if type(getattr(snapshot, "source", None)) is not TrustedControlSource:
        return _denied("trusted policy source evidence is unavailable", snapshot, receipt)
    if type(getattr(snapshot, "document", None)) is not PolicyDocument:
        return _denied("trusted policy document evidence is unavailable", snapshot, receipt)
    if not _snapshot_is_structurally_valid(snapshot):
        return _denied("trusted policy evidence is invalid", snapshot, receipt)
    if type(receipt) is not ActivationReceipt:
        return _denied("activation receipt evidence is unavailable", snapshot, receipt)
    if not _receipt_is_structurally_valid(receipt):
        return _denied("activation receipt evidence is invalid", snapshot, receipt)
    if type(standing_authority) is not StandingAuthority:
        return _denied("standing authority evidence is unavailable", snapshot, receipt)
    if not _standing_authority_is_structurally_valid(standing_authority):
        return _denied("standing authority evidence is invalid", snapshot, receipt)

    source = snapshot.source
    document = snapshot.document
    try:
        policy_digest = _policy_digest(document)
        _require_fingerprint(task_fingerprint, "candidate task")
        _require_commit_sha(candidate_sha, "candidate")
        _require_utc(now, "evaluation timestamp")
        if not isinstance(receipt_status, ReceiptStatus):
            raise PolicyError("verified activation receipt status is unavailable")
    except PolicyError as error:
        return _denied(str(error), snapshot, receipt)

    checks = (
        (receipt.source_fingerprint == source.source_fingerprint, "the control source does not match the activation receipt"),
        (receipt.revision_fingerprint == source.revision_fingerprint, "the control revision does not match the activation receipt"),
        (receipt.policy_digest == policy_digest, "the policy digest does not match the activation receipt"),
        (receipt.schema_version == document.schema_version, "the policy schema does not match the activation receipt"),
        (receipt.task_fingerprint == task_fingerprint, "the activation receipt is not bound to this task"),
        (receipt.candidate_sha == candidate_sha, "the activation receipt is not bound to this candidate"),
        (receipt.activated_at <= now < receipt.expires_at, "the activation receipt is stale or not yet active"),
        (receipt_status is ReceiptStatus.FRESH, "the activation receipt is replayed, conflicting, or revoked"),
        (document.allowed_actions <= standing_authority.allowed_actions, "the policy would widen standing authority"),
    )
    for passed, reason in checks:
        if not passed:
            return _denied(reason, snapshot, receipt)
    return PolicyDecision(
        authorized=True,
        reason="policy activation is valid",
        schema_version=document.schema_version,
        source_fingerprint=source.source_fingerprint,
        policy_digest=policy_digest,
        receipt_fingerprint=receipt.receipt_fingerprint,
        activated_at=receipt.activated_at,
        allowed_actions=document.allowed_actions,
    )


def _denied(
    reason: str,
    snapshot: TrustedPolicySnapshot | None,
    receipt: ActivationReceipt | None,
) -> PolicyDecision:
    valid_snapshot = type(snapshot) is TrustedPolicySnapshot and _snapshot_is_structurally_valid(snapshot)
    valid_receipt = type(receipt) is ActivationReceipt and _receipt_is_structurally_valid(receipt)
    source = snapshot.source if valid_snapshot else None
    document = snapshot.document if valid_snapshot else None
    return PolicyDecision(
        authorized=False,
        reason=reason,
        schema_version=document.schema_version if document else None,
        source_fingerprint=source.source_fingerprint if source else None,
        policy_digest=_safe_policy_digest(snapshot) if valid_snapshot else None,
        receipt_fingerprint=receipt.receipt_fingerprint if valid_receipt else None,
        activated_at=receipt.activated_at if valid_receipt else None,
        allowed_actions=frozenset(),
    )


def _snapshot_is_structurally_valid(snapshot: TrustedPolicySnapshot) -> bool:
    """Check nested trusted policy values without leaking malformed contents."""

    try:
        source = snapshot.source
        document = snapshot.document
        if type(source) is not TrustedControlSource or type(document) is not PolicyDocument:
            return False
        if not _trusted_control_source_is_structurally_valid(source):
            return False
        if not _policy_document_is_structurally_valid(document):
            return False
        _policy_digest(document)
    except (AttributeError, TypeError, PolicyError):
        return False
    return True


def _receipt_is_structurally_valid(receipt: ActivationReceipt) -> bool:
    """Revalidate receipt fields at the untrusted evaluation boundary."""

    try:
        for value, description in (
            (receipt.owner_fingerprint, "owner receipt"),
            (receipt.receipt_fingerprint, "activation receipt"),
            (receipt.source_fingerprint, "receipt source"),
            (receipt.revision_fingerprint, "receipt revision"),
            (receipt.policy_digest, "receipt policy digest"),
            (receipt.task_fingerprint, "receipt task"),
        ):
            _require_fingerprint(value, description)
        _require_commit_sha(receipt.candidate_sha, "receipt candidate")
        if (
            type(receipt.schema_version) is not int
            or receipt.schema_version != POLICY_SCHEMA_VERSION
        ):
            return False
        _require_utc(receipt.activated_at, "activation timestamp")
        _require_utc(receipt.expires_at, "receipt expiry")
        if receipt.expires_at <= receipt.activated_at:
            return False
    except (AttributeError, TypeError, PolicyError):
        return False
    return True


def _trusted_control_source_is_structurally_valid(source: TrustedControlSource) -> bool:
    """Validate exact trusted-source fields without invoking source methods."""

    try:
        _require_fingerprint(source.source_fingerprint, "control source")
        _require_fingerprint(source.revision_fingerprint, "control revision")
    except (AttributeError, TypeError, PolicyError):
        return False
    return True


def _policy_document_is_structurally_valid(document: PolicyDocument) -> bool:
    """Validate exact policy fields without invoking document methods."""

    try:
        return (
            set(document.__dict__) == {"schema_version", "allowed_actions"}
            and
            type(document.schema_version) is int
            and document.schema_version == POLICY_SCHEMA_VERSION
            and type(document.allowed_actions) is frozenset
            and all(isinstance(action, PolicyAction) for action in document.allowed_actions)
        )
    except (AttributeError, TypeError):
        return False


def _standing_authority_is_structurally_valid(authority: StandingAuthority) -> bool:
    """Validate the no-widening ceiling without calling evidence methods."""

    try:
        allowed_actions = authority.allowed_actions
    except (AttributeError, TypeError, PolicyError):
        return False
    return type(allowed_actions) is frozenset and all(
        isinstance(action, PolicyAction) for action in allowed_actions
    )


def _safe_policy_digest(snapshot: TrustedPolicySnapshot) -> str | None:
    try:
        document = snapshot.document
        if not _policy_document_is_structurally_valid(document):
            return None
        return _policy_digest(document)
    except (AttributeError, TypeError, PolicyError):
        return None


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_policy_bytes(document: PolicyDocument) -> bytes:
    """Render independently validated policy fields without instance dispatch."""

    return _canonical_json(
        {
            "allowed_actions": sorted(action.value for action in document.allowed_actions),
            "schema_version": document.schema_version,
        }
    )


def _policy_digest(document: PolicyDocument) -> str:
    """Compute a policy digest without calling an evidence-instance method."""

    return hashlib.sha256(_canonical_policy_bytes(document)).hexdigest()


def _require_fingerprint(value: str, description: str) -> None:
    if (
        type(value) is not str
        or len(value) != _FINGERPRINT_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PolicyError(f"the {description} fingerprint is invalid")


def _require_commit_sha(value: str, description: str) -> None:
    """Accept only exact Git object identities, never generic fingerprints."""

    if (
        type(value) is not str
        or len(value) not in _COMMIT_SHA_LENGTHS
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PolicyError(f"the {description} commit identity is invalid")


def _require_utc(value: datetime, description: str) -> None:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise PolicyError(f"the {description} must use UTC")
