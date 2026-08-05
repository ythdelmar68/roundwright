"""Pure, fail-closed deployment-authority preflight for command shells.

This module deliberately does not locate receipts, acquire credentials, open
state, invoke Git, or dispatch work.  A future repository-external authority
service must supply the already-verified receipt observation; this boundary
only decides whether that evidence is exact and current.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Mapping
from uuid import UUID
from .runtime_binding import RuntimeBinding


class DeploymentMode(str, Enum):
    """Public deployment modes, including explicit non-authoritative modes."""

    READ_ONLY = "read-only"
    TEST_ONLY = "test-only"
    AUTHORITATIVE = "authoritative"
    BLOCKED = "blocked"


class AuthorityReceiptStatus(str, Enum):
    """Externally verified lifecycle status for one deployment receipt."""

    FRESH = "fresh"
    MISSING = "missing"
    EXPIRED = "expired"
    COPIED = "copied"
    CONFLICTING = "conflicting"
    REVOKED = "revoked"


class DeploymentAuthorityError(ValueError):
    """Raised when an authority value cannot be represented safely."""


@dataclass(frozen=True)
class DeploymentIdentity:
    """Opaque identities that must agree before dispatch could be considered.

    These are fingerprints and a UUID rather than paths, URLs, credentials, or
    state contents, so decisions can remain owner-safe.
    """

    repository_fingerprint: str
    canonical_checkout_fingerprint: str
    state_fingerprint: str
    state_id: UUID
    deployment_fingerprint: str
    runtime_binding: RuntimeBinding

    def __post_init__(self) -> None:
        _validate_identity(self)


@dataclass(frozen=True)
class DeploymentAuthorityReceipt:
    """An owner receipt bound to exactly one authoritative deployment."""

    receipt_fingerprint: str
    identity: DeploymentIdentity
    mode: DeploymentMode
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _validate_receipt(self)


@dataclass(frozen=True)
class AuthorityReceiptVerification:
    """Repo-external observation of the one deployment currently designated.

    Receipt bytes alone cannot establish that they were not copied.  The
    future authority service therefore supplies this independent observation
    and declares exactly one active deployment identity.
    """

    receipt_fingerprint: str
    receipt_binding_fingerprint: str
    repository_fingerprint: str
    state_id: UUID
    authoritative_deployment_fingerprint: str
    status: AuthorityReceiptStatus
    runtime_binding: RuntimeBinding

    def __post_init__(self) -> None:
        _validate_verification(self)


@dataclass(frozen=True)
class DeploymentAuthorityDecision:
    """A path-free result; authorization does not execute a command."""

    mode: DeploymentMode
    authorized: bool
    reason: str
    receipt_fingerprint: str | None = None

    def diagnostic(self) -> Mapping[str, str | bool | None]:
        """Return a public-safe status surface without paths or credentials."""

        return {
            "mode": self.mode.value,
            "authorized": self.authorized,
            "reason": self.reason,
            "receipt_fingerprint": self.receipt_fingerprint,
        }


def evaluate_deployment_authority(
    identity: DeploymentIdentity | None,
    receipt: DeploymentAuthorityReceipt | None = None,
    verification: AuthorityReceiptVerification | None = None,
    *,
    mode: DeploymentMode = DeploymentMode.AUTHORITATIVE,
    now: datetime | None = None,
) -> DeploymentAuthorityDecision:
    """Fail closed unless one exact, externally verified authority is current.

    Read-only and test-only modes are deliberately available without a receipt.
    They never authorize dispatch.  Authoritative mode requires receipt and
    verification evidence that bind the repository, checkout, state UUID,
    deployment identity, and validity window together.
    """

    if type(mode) is not DeploymentMode:
        return _blocked("the deployment mode is invalid")
    if mode is DeploymentMode.READ_ONLY:
        return DeploymentAuthorityDecision(mode, False, "read-only inspection does not require dispatch authority")
    if mode is DeploymentMode.TEST_ONLY:
        return DeploymentAuthorityDecision(mode, False, "test-only mode cannot dispatch work")
    if mode is DeploymentMode.BLOCKED:
        return _blocked("the deployment is explicitly blocked")
    if type(identity) is not DeploymentIdentity or not _identity_is_valid(identity):
        return _blocked("deployment identity evidence is unavailable or invalid")
    if type(receipt) is not DeploymentAuthorityReceipt or not _receipt_is_valid(receipt):
        return _blocked("deployment authority receipt evidence is unavailable or invalid")
    if type(verification) is not AuthorityReceiptVerification or not _verification_is_valid(verification):
        return _blocked("repository-external authority verification is unavailable or invalid")
    if type(now) is not datetime or not _is_utc(now):
        return _blocked("the authority evaluation time is unavailable or invalid")
    if receipt.mode is not DeploymentMode.AUTHORITATIVE:
        return _blocked("the deployment authority receipt is not authoritative", receipt)
    if not _identities_match(identity, receipt.identity):
        return _blocked("the deployment authority receipt does not match this deployment identity", receipt)
    if verification.status is not AuthorityReceiptStatus.FRESH:
        return _blocked("the repository-external authority receipt is not fresh", receipt)
    if verification.receipt_fingerprint != receipt.receipt_fingerprint:
        return _blocked("the repository-external receipt identity does not match", receipt)
    if verification.receipt_binding_fingerprint != _receipt_binding_fingerprint(receipt):
        return _blocked("the repository-external receipt binding does not match", receipt)
    if verification.repository_fingerprint != identity.repository_fingerprint:
        return _blocked("the repository-external repository identity does not match", receipt)
    if verification.state_id != identity.state_id:
        return _blocked("the repository-external state identity does not match", receipt)
    if verification.authoritative_deployment_fingerprint != identity.deployment_fingerprint:
        return _blocked("a different deployment is authoritative for this repository state", receipt)
    if not _runtime_bindings_match(identity.runtime_binding, verification.runtime_binding):
        return _blocked("the repository-external runtime configuration binding does not match", receipt)
    if not receipt.issued_at <= now < receipt.expires_at:
        return _blocked("the deployment authority receipt is expired or not yet active", receipt)
    return DeploymentAuthorityDecision(
        DeploymentMode.AUTHORITATIVE,
        True,
        "one exact repository-external authority receipt is current",
        receipt.receipt_fingerprint,
    )


def blocked_command_shell_preflight() -> DeploymentAuthorityDecision:
    """Return the Phase 1 shell result without inspecting or mutating anything."""

    return evaluate_deployment_authority(None, mode=DeploymentMode.AUTHORITATIVE, now=datetime.now(timezone.utc))


def _blocked(
    reason: str, receipt: DeploymentAuthorityReceipt | None = None
) -> DeploymentAuthorityDecision:
    fingerprint = receipt.receipt_fingerprint if _receipt_is_valid(receipt) else None
    return DeploymentAuthorityDecision(DeploymentMode.BLOCKED, False, reason, fingerprint)


def _identities_match(left: DeploymentIdentity, right: DeploymentIdentity) -> bool:
    return (
        left.repository_fingerprint == right.repository_fingerprint
        and left.canonical_checkout_fingerprint == right.canonical_checkout_fingerprint
        and left.state_fingerprint == right.state_fingerprint
        and left.state_id == right.state_id
        and left.deployment_fingerprint == right.deployment_fingerprint
        and _runtime_bindings_match(left.runtime_binding, right.runtime_binding)
    )


def _identity_is_valid(identity: object) -> bool:
    if type(identity) is not DeploymentIdentity:
        return False
    try:
        _validate_identity(identity)
    except (AttributeError, DeploymentAuthorityError, TypeError, ValueError):
        return False
    return True


def _receipt_is_valid(receipt: object) -> bool:
    if type(receipt) is not DeploymentAuthorityReceipt:
        return False
    try:
        _validate_receipt(receipt)
    except (AttributeError, DeploymentAuthorityError, TypeError, ValueError):
        return False
    return True


def _verification_is_valid(verification: object) -> bool:
    if type(verification) is not AuthorityReceiptVerification:
        return False
    try:
        _validate_verification(verification)
    except (AttributeError, DeploymentAuthorityError, TypeError, ValueError):
        return False
    return True


def _validate_identity(identity: DeploymentIdentity) -> None:
    for value, description in (
        (identity.repository_fingerprint, "repository identity"),
        (identity.canonical_checkout_fingerprint, "canonical checkout identity"),
        (identity.state_fingerprint, "state identity"),
        (identity.deployment_fingerprint, "deployment identity"),
    ):
        _require_fingerprint(value, description)
    if type(identity.state_id) is not UUID:
        raise DeploymentAuthorityError("the authoritative state UUID is invalid")
    if type(identity.runtime_binding) is not RuntimeBinding:
        raise DeploymentAuthorityError("the runtime configuration binding is invalid")


def _validate_receipt(receipt: DeploymentAuthorityReceipt) -> None:
    _require_fingerprint(receipt.receipt_fingerprint, "authority receipt")
    if type(receipt.identity) is not DeploymentIdentity or not _identity_is_valid(receipt.identity):
        raise DeploymentAuthorityError("the authority receipt identity is invalid")
    if receipt.mode is not DeploymentMode.AUTHORITATIVE:
        raise DeploymentAuthorityError("the authority receipt mode is invalid")
    _require_utc(receipt.issued_at, "authority receipt issue time")
    _require_utc(receipt.expires_at, "authority receipt expiry")
    if receipt.expires_at <= receipt.issued_at:
        raise DeploymentAuthorityError("the authority receipt validity window is invalid")


def _validate_verification(verification: AuthorityReceiptVerification) -> None:
    for value, description in (
        (verification.receipt_fingerprint, "verified receipt"),
        (verification.receipt_binding_fingerprint, "verified receipt binding"),
        (verification.repository_fingerprint, "verified repository"),
        (verification.authoritative_deployment_fingerprint, "verified deployment"),
    ):
        _require_fingerprint(value, description)
    if type(verification.state_id) is not UUID:
        raise DeploymentAuthorityError("the verified state UUID is invalid")
    if type(verification.status) is not AuthorityReceiptStatus:
        raise DeploymentAuthorityError("the verified authority receipt status is invalid")
    if type(verification.runtime_binding) is not RuntimeBinding:
        raise DeploymentAuthorityError("the verified runtime configuration binding is invalid")


def _receipt_binding_fingerprint(receipt: DeploymentAuthorityReceipt) -> str:
    """Hash every authority-bearing receipt field in one canonical encoding."""

    canonical_receipt = {
        "expires_at": receipt.expires_at.isoformat(),
        "identity": {
            "canonical_checkout_fingerprint": receipt.identity.canonical_checkout_fingerprint,
            "deployment_fingerprint": receipt.identity.deployment_fingerprint,
            "repository_fingerprint": receipt.identity.repository_fingerprint,
            "state_fingerprint": receipt.identity.state_fingerprint,
            "state_id": str(receipt.identity.state_id),
            "runtime_binding": receipt.identity.runtime_binding.fingerprint,
        },
        "issued_at": receipt.issued_at.isoformat(),
        "mode": receipt.mode.value,
        "receipt_fingerprint": receipt.receipt_fingerprint,
    }
    encoded = json.dumps(canonical_receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _runtime_bindings_match(expected: RuntimeBinding, actual: object) -> bool:
    try:
        expected.require_matches(actual)
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def _require_fingerprint(value: str, description: str) -> None:
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DeploymentAuthorityError(f"the {description} fingerprint is invalid")


def _require_utc(value: datetime, description: str) -> None:
    if type(value) is not datetime or not _is_utc(value):
        raise DeploymentAuthorityError(f"the {description} is invalid")


def _is_utc(value: datetime) -> bool:
    try:
        return value.tzinfo is timezone.utc and value.utcoffset() is not None
    except (AttributeError, TypeError, ValueError):
        return False
