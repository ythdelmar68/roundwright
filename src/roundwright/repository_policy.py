"""Fail-closed Boolean authority decisions for repository mutations.

This is an evaluator, not a mutation adapter.  It accepts only a policy from
an already trusted external source and an independently verified owner receipt;
it never reads a worktree, environment, command line, or network service.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


REPOSITORY_POLICY_SCHEMA_VERSION = 1
_FINGERPRINT_LENGTH = 64
_COMMIT_SHA_LENGTHS = frozenset((40, 64))
_POLICY_KEYS = frozenset((
    "schema_version", "enabled", "allow_issue_comment", "allow_push_branch",
    "allow_create_draft_pr", "allow_mark_pr_ready", "allow_merge_pr",
    "allow_close_leaf_issue", "allow_delete_remote_branch",
    "allow_delete_local_branch", "allow_remove_worktree",
))


class RepositoryPolicyError(ValueError):
    """Raised when a repository-policy value cannot be represented safely."""


class RepositoryMutationOperation(str, Enum):
    """The only repository mutations this Phase 3 contract can describe."""

    ISSUE_COMMENT = "issue-comment"
    PUSH_BRANCH = "push-branch"
    CREATE_DRAFT_PR = "create-draft-pr"
    MARK_PR_READY = "mark-pr-ready"
    MERGE_PR = "merge-pr"
    CLOSE_LEAF_ISSUE = "close-leaf-issue"
    DELETE_REMOTE_BRANCH = "delete-remote-branch"
    DELETE_LOCAL_BRANCH = "delete-local-branch"
    REMOVE_WORKTREE = "remove-worktree"


class RepositoryReceiptStatus(str, Enum):
    """Externally verified lifecycle state for a single activation receipt."""

    FRESH = "fresh"
    MISSING = "missing"
    STALE = "stale"
    REPLAYED = "replayed"
    CONFLICTING = "conflicting"
    REVOKED = "revoked"


@dataclass(frozen=True)
class RepositoryPolicySource:
    """Opaque immutable control-source identities, never a candidate path."""

    source_fingerprint: str
    revision_fingerprint: str

    def __post_init__(self) -> None:
        _require_fingerprint(self.source_fingerprint, "policy source")
        _require_fingerprint(self.revision_fingerprint, "policy source revision")


@dataclass(frozen=True)
class RepositoryMutationPolicy:
    """Exact Boolean document shape; no implicit or wildcard permissions."""

    schema_version: int
    enabled: bool
    allow_issue_comment: bool
    allow_push_branch: bool
    allow_create_draft_pr: bool
    allow_mark_pr_ready: bool
    allow_merge_pr: bool
    allow_close_leaf_issue: bool
    allow_delete_remote_branch: bool
    allow_delete_local_branch: bool
    allow_remove_worktree: bool

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != REPOSITORY_POLICY_SCHEMA_VERSION:
            raise RepositoryPolicyError("repository policy schema version is unsupported")
        for name in _POLICY_KEYS - {"schema_version"}:
            if type(getattr(self, name)) is not bool:
                raise RepositoryPolicyError("repository policy Boolean switch is invalid")

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_policy_bytes(self)).hexdigest()

    def allows(self, operation: RepositoryMutationOperation) -> bool:
        """Return the exact switch result; callers must also check ``enabled``."""

        if type(operation) is not RepositoryMutationOperation:
            raise RepositoryPolicyError("repository mutation operation is invalid")
        return bool(getattr(self, _OPERATION_SWITCH[operation]))


@dataclass(frozen=True)
class TrustedRepositoryPolicySnapshot:
    """A policy supplied by a trusted immutable source outside candidate control."""

    source: RepositoryPolicySource
    document: RepositoryMutationPolicy

    @property
    def policy_digest(self) -> str:
        return self.document.digest


@dataclass(frozen=True)
class StandingRepositoryAuthority:
    """Reviewed Boolean ceiling that an activated policy may only narrow."""

    policy: RepositoryMutationPolicy

    def __post_init__(self) -> None:
        if type(self.policy) is not RepositoryMutationPolicy or not _policy_is_valid(self.policy):
            raise RepositoryPolicyError("standing repository authority is invalid")


@dataclass(frozen=True)
class RepositoryMutationContext:
    """Exact repository, deployment, task, and candidate being considered."""

    repository_fingerprint: str
    deployment_fingerprint: str
    task_fingerprint: str
    candidate_sha: str

    def __post_init__(self) -> None:
        for value, description in (
            (self.repository_fingerprint, "repository"),
            (self.deployment_fingerprint, "deployment"),
            (self.task_fingerprint, "task"),
        ):
            _require_fingerprint(value, description)
        _require_commit_sha(self.candidate_sha, "candidate")


@dataclass(frozen=True)
class RepositoryActivationReceipt:
    """Owner receipt bound to one source, policy, and repository mutation target."""

    owner_fingerprint: str
    receipt_fingerprint: str
    source_fingerprint: str
    revision_fingerprint: str
    policy_digest: str
    schema_version: int
    repository_fingerprint: str
    deployment_fingerprint: str
    task_fingerprint: str
    candidate_sha: str
    activated_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_receipt(self)


@dataclass(frozen=True)
class RepositoryMutationBinding:
    """Complete immutable evidence identity retained with one decision."""

    source_fingerprint: str
    revision_fingerprint: str
    policy_digest: str
    schema_version: int
    owner_fingerprint: str
    receipt_fingerprint: str
    repository_fingerprint: str
    deployment_fingerprint: str
    task_fingerprint: str
    candidate_sha: str
    receipt_status: RepositoryReceiptStatus

    def __post_init__(self) -> None:
        _validate_binding(self)

    @property
    def digest(self) -> str:
        payload = {
            "source_fingerprint": self.source_fingerprint,
            "revision_fingerprint": self.revision_fingerprint,
            "policy_digest": self.policy_digest,
            "schema_version": self.schema_version,
            "owner_fingerprint": self.owner_fingerprint,
            "receipt_fingerprint": self.receipt_fingerprint,
            "repository_fingerprint": self.repository_fingerprint,
            "deployment_fingerprint": self.deployment_fingerprint,
            "task_fingerprint": self.task_fingerprint,
            "candidate_sha": self.candidate_sha,
            "receipt_status": self.receipt_status.value,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()

    def matches_context(
        self, context: RepositoryMutationContext, receipt_status: RepositoryReceiptStatus
    ) -> bool:
        """Reject reuse against a different target or receipt-lifecycle state."""

        return (
            type(context) is RepositoryMutationContext
            and type(receipt_status) is RepositoryReceiptStatus
            and self.repository_fingerprint == context.repository_fingerprint
            and self.deployment_fingerprint == context.deployment_fingerprint
            and self.task_fingerprint == context.task_fingerprint
            and self.candidate_sha == context.candidate_sha
            and self.receipt_status is receipt_status
        )


@dataclass(frozen=True)
class RepositoryMutationDecision:
    """Public-safe result of a requested mutation; it never executes one."""

    operation: RepositoryMutationOperation | None
    authorized: bool
    reason: str
    policy_digest: str | None
    source_fingerprint: str | None
    receipt_fingerprint: str | None
    enabled: bool
    action_enabled: bool
    next_action: str
    binding: RepositoryMutationBinding | None = None

    def diagnostic(self) -> Mapping[str, str | bool | None]:
        return {
            "operation": self.operation.value if type(self.operation) is RepositoryMutationOperation else None,
            "authorized": self.authorized,
            "reason": self.reason,
            "policy_digest": self.policy_digest,
            "source_fingerprint": self.source_fingerprint,
            "receipt_fingerprint": self.receipt_fingerprint,
            "binding_digest": self.binding.digest if type(self.binding) is RepositoryMutationBinding else None,
            "enabled": self.enabled,
            "action_enabled": self.action_enabled,
            "next_action": self.next_action,
        }


_OPERATION_SWITCH = {
    RepositoryMutationOperation.ISSUE_COMMENT: "allow_issue_comment",
    RepositoryMutationOperation.PUSH_BRANCH: "allow_push_branch",
    RepositoryMutationOperation.CREATE_DRAFT_PR: "allow_create_draft_pr",
    RepositoryMutationOperation.MARK_PR_READY: "allow_mark_pr_ready",
    RepositoryMutationOperation.MERGE_PR: "allow_merge_pr",
    RepositoryMutationOperation.CLOSE_LEAF_ISSUE: "allow_close_leaf_issue",
    RepositoryMutationOperation.DELETE_REMOTE_BRANCH: "allow_delete_remote_branch",
    RepositoryMutationOperation.DELETE_LOCAL_BRANCH: "allow_delete_local_branch",
    RepositoryMutationOperation.REMOVE_WORKTREE: "allow_remove_worktree",
}


def parse_repository_mutation_policy(contents: bytes | str) -> RepositoryMutationPolicy:
    """Parse exactly one duplicate-free Boolean policy document."""

    try:
        raw = json.loads(contents, object_pairs_hook=_reject_duplicate_keys)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError, RepositoryPolicyError) as error:
        raise RepositoryPolicyError("repository policy document is malformed") from error
    if type(raw) is not dict or set(raw) != _POLICY_KEYS:
        raise RepositoryPolicyError("repository policy document has missing or unsupported keys")
    try:
        return RepositoryMutationPolicy(**raw)
    except (TypeError, RepositoryPolicyError) as error:
        raise RepositoryPolicyError("repository policy document is invalid") from error


def evaluate_repository_mutation_policy(
    snapshot: TrustedRepositoryPolicySnapshot | None,
    receipt: RepositoryActivationReceipt | None,
    context: RepositoryMutationContext | None,
    operation: RepositoryMutationOperation | None,
    *,
    standing_authority: StandingRepositoryAuthority | None,
    receipt_status: RepositoryReceiptStatus | None,
    now: datetime | None,
) -> RepositoryMutationDecision:
    """Authorize only an exact, fresh, externally activated Boolean switch."""

    if type(operation) is not RepositoryMutationOperation:
        return _denied("repository mutation operation is unavailable", snapshot, receipt)
    if type(snapshot) is not TrustedRepositoryPolicySnapshot or not _snapshot_is_valid(snapshot):
        return _denied("trusted repository policy evidence is unavailable or invalid", snapshot, receipt, operation, context, receipt_status)
    if type(receipt) is not RepositoryActivationReceipt or not _receipt_is_valid(receipt):
        return _denied("repository policy activation receipt is unavailable or invalid", snapshot, receipt, operation, context, receipt_status)
    if type(context) is not RepositoryMutationContext or not _context_is_valid(context):
        return _denied("repository mutation context is unavailable or invalid", snapshot, receipt, operation, context, receipt_status)
    if type(standing_authority) is not StandingRepositoryAuthority or not _standing_authority_is_valid(standing_authority):
        return _denied("standing repository authority is unavailable or invalid", snapshot, receipt, operation, context, receipt_status)
    if type(receipt_status) is not RepositoryReceiptStatus:
        return _denied("repository policy receipt lifecycle is unavailable", snapshot, receipt, operation, context, receipt_status)
    if type(now) is not datetime or now.tzinfo is not timezone.utc:
        return _denied("repository policy evaluation time is unavailable or invalid", snapshot, receipt, operation, context, receipt_status)

    document = snapshot.document
    if not _policy_narrows(document, standing_authority.policy):
        return _denied("repository policy would widen standing authority", snapshot, receipt, operation, context, receipt_status)
    checks = (
        (receipt.source_fingerprint == snapshot.source.source_fingerprint, "repository policy source does not match activation receipt"),
        (receipt.revision_fingerprint == snapshot.source.revision_fingerprint, "repository policy revision does not match activation receipt"),
        (receipt.policy_digest == snapshot.policy_digest, "repository policy digest does not match activation receipt"),
        (receipt.schema_version == document.schema_version, "repository policy schema does not match activation receipt"),
        (receipt.repository_fingerprint == context.repository_fingerprint, "activation receipt is not bound to this repository"),
        (receipt.deployment_fingerprint == context.deployment_fingerprint, "activation receipt is not bound to this deployment"),
        (receipt.task_fingerprint == context.task_fingerprint, "activation receipt is not bound to this task"),
        (receipt.candidate_sha == context.candidate_sha, "activation receipt is not bound to this candidate"),
        (receipt.activated_at <= now < receipt.expires_at, "repository policy activation receipt is stale or not yet active"),
        (receipt_status is RepositoryReceiptStatus.FRESH, "repository policy activation receipt is not fresh"),
    )
    for passed, reason in checks:
        if not passed:
            return _denied(reason, snapshot, receipt, operation, context, receipt_status)
    if not document.enabled:
        return _denied("repository mutation policy is disabled", snapshot, receipt, operation, context, receipt_status)
    if not _action_switch_is_enabled(document, operation):
        return _denied("repository mutation action is disabled", snapshot, receipt, operation, context, receipt_status)
    return RepositoryMutationDecision(operation, True, "repository mutation policy is active for this exact operation", snapshot.policy_digest, snapshot.source.source_fingerprint, receipt.receipt_fingerprint, True, True, "mutation-adapter-may-attempt-readback", _binding_from_evidence(snapshot, receipt, context, receipt_status))


def evaluate_shadow_mutation_policy(operation: RepositoryMutationOperation | None) -> RepositoryMutationDecision:
    """Return Shadow's mandatory all-switches-disabled counterfactual result."""

    if type(operation) is not RepositoryMutationOperation:
        return _denied("shadow mutation operation is unavailable", operation=operation)
    return RepositoryMutationDecision(operation, False, "shadow replay is read-only and all repository mutation switches are disabled", None, None, None, False, False, "retain-zero-mutation-evidence")


def _denied(reason: str, snapshot: object = None, receipt: object = None, operation: object = None, context: object = None, receipt_status: object = None) -> RepositoryMutationDecision:
    valid_snapshot = type(snapshot) is TrustedRepositoryPolicySnapshot and _snapshot_is_valid(snapshot)
    valid_receipt = type(receipt) is RepositoryActivationReceipt and _receipt_is_valid(receipt)
    policy = snapshot.document if valid_snapshot else None
    return RepositoryMutationDecision(
        operation if type(operation) is RepositoryMutationOperation else None,
        False,
        reason,
        snapshot.policy_digest if valid_snapshot else None,
        snapshot.source.source_fingerprint if valid_snapshot else None,
        receipt.receipt_fingerprint if valid_receipt else None,
        bool(policy.enabled) if policy is not None else False,
        _action_switch_is_enabled(policy, operation) if policy is not None and type(operation) is RepositoryMutationOperation else False,
        "resolve-policy-or-owner-receipt",
        _binding_from_evidence(snapshot, receipt, context, receipt_status),
    )


def _binding_from_evidence(
    snapshot: object, receipt: object, context: object, receipt_status: object
) -> RepositoryMutationBinding | None:
    if (
        type(snapshot) is not TrustedRepositoryPolicySnapshot
        or not _snapshot_is_valid(snapshot)
        or type(receipt) is not RepositoryActivationReceipt
        or not _receipt_is_valid(receipt)
        or type(context) is not RepositoryMutationContext
        or not _context_is_valid(context)
        or type(receipt_status) is not RepositoryReceiptStatus
    ):
        return None
    return RepositoryMutationBinding(
        snapshot.source.source_fingerprint,
        snapshot.source.revision_fingerprint,
        snapshot.policy_digest,
        snapshot.document.schema_version,
        receipt.owner_fingerprint,
        receipt.receipt_fingerprint,
        context.repository_fingerprint,
        context.deployment_fingerprint,
        context.task_fingerprint,
        context.candidate_sha,
        receipt_status,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RepositoryPolicyError("repository policy document contains duplicate keys")
        result[key] = value
    return result


def _canonical_policy_bytes(policy: RepositoryMutationPolicy) -> bytes:
    return json.dumps({name: getattr(policy, name) for name in sorted(_POLICY_KEYS)}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _policy_narrows(policy: RepositoryMutationPolicy, ceiling: RepositoryMutationPolicy) -> bool:
    return all(not getattr(policy, name) or getattr(ceiling, name) for name in _POLICY_KEYS - {"schema_version"})


def _action_switch_is_enabled(
    policy: RepositoryMutationPolicy, operation: RepositoryMutationOperation
) -> bool:
    """Read only validated fields; never dispatch through an evidence method."""

    if operation is RepositoryMutationOperation.ISSUE_COMMENT:
        return policy.allow_issue_comment
    if operation is RepositoryMutationOperation.PUSH_BRANCH:
        return policy.allow_push_branch
    if operation is RepositoryMutationOperation.CREATE_DRAFT_PR:
        return policy.allow_create_draft_pr
    if operation is RepositoryMutationOperation.MARK_PR_READY:
        return policy.allow_mark_pr_ready
    if operation is RepositoryMutationOperation.MERGE_PR:
        return policy.allow_merge_pr
    if operation is RepositoryMutationOperation.CLOSE_LEAF_ISSUE:
        return policy.allow_close_leaf_issue
    if operation is RepositoryMutationOperation.DELETE_REMOTE_BRANCH:
        return policy.allow_delete_remote_branch
    if operation is RepositoryMutationOperation.DELETE_LOCAL_BRANCH:
        return policy.allow_delete_local_branch
    if operation is RepositoryMutationOperation.REMOVE_WORKTREE:
        return policy.allow_remove_worktree
    raise RepositoryPolicyError("repository mutation operation is invalid")


def _policy_is_valid(policy: object) -> bool:
    if type(policy) is not RepositoryMutationPolicy:
        return False
    try:
        RepositoryMutationPolicy(**{name: getattr(policy, name) for name in _POLICY_KEYS})
    except (AttributeError, TypeError, RepositoryPolicyError):
        return False
    return True


def _snapshot_is_valid(snapshot: object) -> bool:
    if type(snapshot) is not TrustedRepositoryPolicySnapshot:
        return False
    try:
        return type(snapshot.source) is RepositoryPolicySource and _source_is_valid(snapshot.source) and _policy_is_valid(snapshot.document)
    except (AttributeError, TypeError, RepositoryPolicyError):
        return False


def _source_is_valid(source: object) -> bool:
    if type(source) is not RepositoryPolicySource:
        return False
    try:
        _require_fingerprint(source.source_fingerprint, "policy source")
        _require_fingerprint(source.revision_fingerprint, "policy source revision")
    except (AttributeError, TypeError, RepositoryPolicyError):
        return False
    return True


def _context_is_valid(context: object) -> bool:
    if type(context) is not RepositoryMutationContext:
        return False
    try:
        RepositoryMutationContext(context.repository_fingerprint, context.deployment_fingerprint, context.task_fingerprint, context.candidate_sha)
    except (AttributeError, TypeError, RepositoryPolicyError):
        return False
    return True


def _receipt_is_valid(receipt: object) -> bool:
    if type(receipt) is not RepositoryActivationReceipt:
        return False
    try:
        _validate_receipt(receipt)
    except (AttributeError, TypeError, RepositoryPolicyError):
        return False
    return True


def _standing_authority_is_valid(authority: object) -> bool:
    return type(authority) is StandingRepositoryAuthority and _policy_is_valid(authority.policy)


def _validate_receipt(receipt: RepositoryActivationReceipt) -> None:
    for value, description in (
        (receipt.owner_fingerprint, "owner"), (receipt.receipt_fingerprint, "activation receipt"),
        (receipt.source_fingerprint, "receipt source"), (receipt.revision_fingerprint, "receipt revision"),
        (receipt.policy_digest, "receipt policy digest"), (receipt.repository_fingerprint, "receipt repository"),
        (receipt.deployment_fingerprint, "receipt deployment"), (receipt.task_fingerprint, "receipt task"),
    ):
        _require_fingerprint(value, description)
    if type(receipt.schema_version) is not int or receipt.schema_version != REPOSITORY_POLICY_SCHEMA_VERSION:
        raise RepositoryPolicyError("repository policy receipt schema version is unsupported")
    _require_commit_sha(receipt.candidate_sha, "receipt candidate")
    if type(receipt.activated_at) is not datetime or receipt.activated_at.tzinfo is not timezone.utc:
        raise RepositoryPolicyError("repository policy receipt activation time is invalid")
    if type(receipt.expires_at) is not datetime or receipt.expires_at.tzinfo is not timezone.utc or receipt.expires_at <= receipt.activated_at:
        raise RepositoryPolicyError("repository policy receipt validity window is invalid")


def _validate_binding(binding: RepositoryMutationBinding) -> None:
    for value, description in (
        (binding.source_fingerprint, "binding policy source"),
        (binding.revision_fingerprint, "binding policy revision"),
        (binding.policy_digest, "binding policy digest"),
        (binding.owner_fingerprint, "binding owner"),
        (binding.receipt_fingerprint, "binding receipt"),
        (binding.repository_fingerprint, "binding repository"),
        (binding.deployment_fingerprint, "binding deployment"),
        (binding.task_fingerprint, "binding task"),
    ):
        _require_fingerprint(value, description)
    if type(binding.schema_version) is not int or binding.schema_version != REPOSITORY_POLICY_SCHEMA_VERSION:
        raise RepositoryPolicyError("repository policy binding schema version is unsupported")
    _require_commit_sha(binding.candidate_sha, "binding candidate")
    if type(binding.receipt_status) is not RepositoryReceiptStatus:
        raise RepositoryPolicyError("repository policy binding receipt lifecycle is invalid")


def _require_fingerprint(value: object, description: str) -> None:
    if type(value) is not str or len(value) != _FINGERPRINT_LENGTH or any(character not in "0123456789abcdef" for character in value):
        raise RepositoryPolicyError(f"{description} fingerprint is invalid")


def _require_commit_sha(value: object, description: str) -> None:
    if type(value) is not str or len(value) not in _COMMIT_SHA_LENGTHS or any(character not in "0123456789abcdef" for character in value):
        raise RepositoryPolicyError(f"{description} commit identity is invalid")
