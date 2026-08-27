"""Hermetic, fail-closed deployment-authority handoff coordination.

The real authority store belongs outside this package.  This module describes
the exact state transitions that such a store must serialize: an active
receipt is first made non-dispatching, then its dispatcher/children/lease are
reconciled, then it is revoked, and only then can a new receipt be active.
It deliberately contains no filesystem, container, scheduler, subprocess, or
provider capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from threading import RLock
from uuid import UUID

from .runtime_binding import RuntimeBinding


class DeploymentHandoffError(ValueError):
    """Raised when public-safe handoff evidence cannot be represented."""


class HandoffPhase(str, Enum):
    """Durable phases; every non-active phase denies dispatch."""

    STOPPING = "stopping"
    RECONCILED = "reconciled"
    REVOKED = "revoked"


class AuthorityReceiptVerificationStatus(str, Enum):
    """Independent lifecycle states reported by the canonical authority store."""

    FRESH = "fresh"
    MISSING = "missing"
    STALE = "stale"
    COPIED = "copied"
    CONFLICTING = "conflicting"
    REVOKED = "revoked"


_FINGERPRINT_LENGTH = 64
_COMMIT_SHA_LENGTHS = frozenset((40, 64))


def _require_fingerprint(value: object, description: str) -> None:
    if (
        type(value) is not str
        or len(value) != _FINGERPRINT_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DeploymentHandoffError(f"{description} fingerprint is invalid")


def _require_candidate(value: object, description: str) -> None:
    if (
        type(value) is not str
        or len(value) not in _COMMIT_SHA_LENGTHS
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DeploymentHandoffError(f"{description} candidate identity is invalid")


def _require_utc(value: object, description: str) -> None:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise DeploymentHandoffError(f"{description} is invalid")


@dataclass(frozen=True)
class DeploymentAuthorityIdentity:
    """The exact environment and candidate a receipt may authorize."""

    repository_fingerprint: str
    canonical_checkout_fingerprint: str
    state_store_fingerprint: str
    state_id: UUID
    deployment_fingerprint: str
    candidate_sha: str
    environment_fingerprint: str
    runtime_binding: RuntimeBinding

    def __post_init__(self) -> None:
        for value, description in (
            (self.repository_fingerprint, "repository"),
            (self.canonical_checkout_fingerprint, "canonical checkout"),
            (self.state_store_fingerprint, "state store"),
            (self.deployment_fingerprint, "deployment"),
            (self.environment_fingerprint, "environment"),
        ):
            _require_fingerprint(value, description)
        if type(self.state_id) is not UUID:
            raise DeploymentHandoffError("authoritative state UUID is invalid")
        _require_candidate(self.candidate_sha, "deployment")
        if type(self.runtime_binding) is not RuntimeBinding:
            raise DeploymentHandoffError("runtime binding is invalid")


@dataclass(frozen=True)
class DeploymentAuthorityHandoffReceipt:
    """A receipt which is valid only while the canonical state names it active."""

    receipt_fingerprint: str
    identity: DeploymentAuthorityIdentity
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _require_fingerprint(self.receipt_fingerprint, "authority receipt")
        if type(self.identity) is not DeploymentAuthorityIdentity:
            raise DeploymentHandoffError("authority receipt identity is invalid")
        _require_utc(self.issued_at, "authority receipt issue time")
        _require_utc(self.expires_at, "authority receipt expiry")
        if self.expires_at <= self.issued_at:
            raise DeploymentHandoffError("authority receipt validity window is invalid")

    @property
    def binding_digest(self) -> str:
        payload = {
            "receipt_fingerprint": self.receipt_fingerprint,
            "repository_fingerprint": self.identity.repository_fingerprint,
            "canonical_checkout_fingerprint": self.identity.canonical_checkout_fingerprint,
            "state_store_fingerprint": self.identity.state_store_fingerprint,
            "state_id": str(self.identity.state_id),
            "deployment_fingerprint": self.identity.deployment_fingerprint,
            "candidate_sha": self.identity.candidate_sha,
            "environment_fingerprint": self.identity.environment_fingerprint,
            "runtime_binding": self.identity.runtime_binding.fingerprint,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True)
class DeploymentAuthorityReceiptVerification:
    """Repository-external receipt observation required before an authority claim.

    Receipt bytes cannot prove that they were not copied.  This observation is
    supplied by the canonical authority store and is deliberately bound to the
    receipt, state, candidate, and environment before a coordinator may claim
    it.
    """

    evidence_fingerprint: str
    receipt_fingerprint: str
    receipt_binding_digest: str
    repository_fingerprint: str
    state_store_fingerprint: str
    state_id: UUID
    candidate_sha: str
    environment_fingerprint: str
    status: AuthorityReceiptVerificationStatus

    def __post_init__(self) -> None:
        for value, description in (
            (self.evidence_fingerprint, "receipt verification evidence"),
            (self.receipt_fingerprint, "verified receipt"),
            (self.receipt_binding_digest, "verified receipt binding"),
            (self.repository_fingerprint, "verified repository"),
            (self.state_store_fingerprint, "verified state store"),
            (self.environment_fingerprint, "verified environment"),
        ):
            _require_fingerprint(value, description)
        if type(self.state_id) is not UUID:
            raise DeploymentHandoffError("verified state UUID is invalid")
        _require_candidate(self.candidate_sha, "verified")
        if type(self.status) is not AuthorityReceiptVerificationStatus:
            raise DeploymentHandoffError("authority receipt verification status is invalid")


@dataclass(frozen=True)
class HandoffReconciliation:
    """Bounded evidence that the old authority is safe to revoke."""

    handoff_fingerprint: str
    old_receipt_fingerprint: str
    state_store_fingerprint: str
    state_id: UUID
    dispatcher_stopped: bool
    children_reconciled: bool
    lease_reconciled: bool
    evidence_fingerprint: str

    def __post_init__(self) -> None:
        for value, description in (
            (self.handoff_fingerprint, "handoff"),
            (self.old_receipt_fingerprint, "old receipt"),
            (self.state_store_fingerprint, "state store"),
            (self.evidence_fingerprint, "reconciliation evidence"),
        ):
            _require_fingerprint(value, description)
        if type(self.state_id) is not UUID:
            raise DeploymentHandoffError("reconciliation state UUID is invalid")
        if any(type(value) is not bool for value in (
            self.dispatcher_stopped, self.children_reconciled, self.lease_reconciled,
        )):
            raise DeploymentHandoffError("reconciliation state is invalid")

    @property
    def complete(self) -> bool:
        return self.dispatcher_stopped and self.children_reconciled and self.lease_reconciled


@dataclass(frozen=True)
class HandoffProgress:
    """Machine truth retained across an interrupted handoff."""

    handoff_fingerprint: str
    old_receipt_fingerprint: str
    new_identity: DeploymentAuthorityIdentity
    phase: HandoffPhase
    reconciliation: HandoffReconciliation | None = None

    def __post_init__(self) -> None:
        _require_fingerprint(self.handoff_fingerprint, "handoff")
        _require_fingerprint(self.old_receipt_fingerprint, "old receipt")
        if type(self.new_identity) is not DeploymentAuthorityIdentity or type(self.phase) is not HandoffPhase:
            raise DeploymentHandoffError("handoff progress is invalid")
        if self.phase is HandoffPhase.STOPPING and self.reconciliation is not None:
            raise DeploymentHandoffError("stopping handoff cannot have reconciliation evidence")
        if self.phase is HandoffPhase.RECONCILED:
            if type(self.reconciliation) is not HandoffReconciliation or not self.reconciliation.complete:
                raise DeploymentHandoffError("reconciled handoff lacks complete evidence")
        if self.phase is HandoffPhase.REVOKED and (
            type(self.reconciliation) is not HandoffReconciliation or not self.reconciliation.complete
        ):
            raise DeploymentHandoffError("revoked handoff lacks complete evidence")


@dataclass(frozen=True)
class HandoffDecision:
    """A path-free result; no decision dispatches work."""

    authorized: bool
    reason: str
    receipt_fingerprint: str | None = None


@dataclass(frozen=True)
class SchedulerWakeupDecision:
    """A scheduler may request work, never mint or transfer authority."""

    requested: bool
    reason: str
    receipt_fingerprint: str | None = None


class InMemoryDeploymentAuthorityStore:
    """Atomic test adapter for one already-selected canonical authority store.

    Production adapters must provide the same atomic compare-and-transition
    behavior against their external store.  A second store is intentionally
    not an authority source: receipts must name this store's fingerprint.
    """

    def __init__(self, state_store_fingerprint: str, state_id: UUID) -> None:
        _require_fingerprint(state_store_fingerprint, "state store")
        if type(state_id) is not UUID:
            raise DeploymentHandoffError("authoritative state UUID is invalid")
        self.state_store_fingerprint = state_store_fingerprint
        self.state_id = state_id
        self._lock = RLock()
        self._active: DeploymentAuthorityHandoffReceipt | None = None
        self._verification: DeploymentAuthorityReceiptVerification | None = None
        self._progress: HandoffProgress | None = None
        self._revoked: set[str] = set()
        self._claim_owner_token: object | None = None
        self._claim_receipt_fingerprint: str | None = None
        self._claim_binding_digest: str | None = None


class DeploymentAuthorityHandoffCoordinator:
    """Serialize receipt issuance and handoff without any dispatch capability."""

    def __init__(self, store: InMemoryDeploymentAuthorityStore) -> None:
        if type(store) is not InMemoryDeploymentAuthorityStore:
            raise DeploymentHandoffError("authority store is invalid")
        self._store = store
        # This private capability represents an authenticated orchestrator
        # session in the in-memory test adapter.  A production canonical store
        # must enforce the equivalent claim with its own atomic identity-bound
        # lease; receipt equality alone is never a claim.
        self._claim_owner_token = object()

    @property
    def progress(self) -> HandoffProgress | None:
        with self._store._lock:
            return self._store._progress

    @property
    def active_receipt(self) -> DeploymentAuthorityHandoffReceipt | None:
        with self._store._lock:
            return self._store._active

    def activate_initial(
        self, receipt: DeploymentAuthorityHandoffReceipt, verification: DeploymentAuthorityReceiptVerification, *, now: datetime
    ) -> HandoffDecision:
        """Atomically accept the one initial externally-issued receipt."""

        with self._store._lock:
            if not self._receipt_names_this_store(receipt):
                return HandoffDecision(False, "receipt does not name the canonical authority state")
            if not _receipt_current(receipt, now):
                return HandoffDecision(False, "receipt is not current")
            if not _verification_matches(receipt, verification):
                return HandoffDecision(False, "receipt lacks fresh canonical verification")
            if self._store._active is not None or self._store._progress is not None:
                return HandoffDecision(False, "an authority is already active or handing off")
            if receipt.receipt_fingerprint in self._store._revoked:
                return HandoffDecision(False, "receipt was revoked")
            self._store._active = receipt
            self._store._verification = verification
            self._clear_claim()
            return HandoffDecision(True, "initial receipt is the sole active authority", receipt.receipt_fingerprint)

    def claim_orchestrator(
        self, receipt: DeploymentAuthorityHandoffReceipt, *, now: datetime
    ) -> HandoffDecision:
        """Atomically bind one authenticated coordinator to the fresh receipt.

        This is intentionally separate from issuance.  A scheduler wakeup or a
        copied receipt cannot create a claim, and a second coordinator loses
        before it can reach authorization or wakeup handling.
        """

        with self._store._lock:
            if self._store._progress is not None:
                return HandoffDecision(False, "authority handoff is incomplete; no orchestrator may claim it")
            if self._store._active != receipt or not self._receipt_names_this_store(receipt):
                return HandoffDecision(False, "receipt is absent, copied, revoked, or not the active authority")
            if not _receipt_current(receipt, now) or not _verification_matches(receipt, self._store._verification):
                return HandoffDecision(False, "receipt lacks fresh canonical verification")
            if self._store._claim_owner_token is None:
                self._store._claim_owner_token = self._claim_owner_token
                self._store._claim_receipt_fingerprint = receipt.receipt_fingerprint
                self._store._claim_binding_digest = receipt.binding_digest
                return HandoffDecision(True, "exclusive canonical orchestrator claim acquired", receipt.receipt_fingerprint)
            if self._holds_claim(receipt):
                return HandoffDecision(True, "exclusive canonical orchestrator claim remains current", receipt.receipt_fingerprint)
            return HandoffDecision(False, "receipt is copied or conflicting; another orchestrator holds the canonical claim")

    def authorize(
        self, identity: DeploymentAuthorityIdentity, receipt: DeploymentAuthorityHandoffReceipt, *, now: datetime
    ) -> HandoffDecision:
        """Authorize only the exact current receipt while no handoff is open."""

        with self._store._lock:
            if type(identity) is not DeploymentAuthorityIdentity or not self._receipt_names_this_store(receipt):
                return HandoffDecision(False, "authority identity is unavailable or names another state store")
            if self._store._progress is not None:
                return HandoffDecision(False, "authority handoff is incomplete; dispatch remains blocked")
            if self._store._active != receipt:
                return HandoffDecision(False, "receipt is absent, copied, revoked, or not the active authority")
            if receipt.receipt_fingerprint in self._store._revoked:
                return HandoffDecision(False, "receipt was revoked")
            if not _verification_matches(receipt, self._store._verification):
                return HandoffDecision(False, "receipt lacks fresh canonical verification")
            if not self._holds_claim(receipt):
                return HandoffDecision(False, "receipt has no exclusive canonical orchestrator claim")
            if receipt.identity != identity:
                return HandoffDecision(False, "receipt does not match deployment candidate or environment")
            if not _receipt_current(receipt, now):
                return HandoffDecision(False, "receipt is stale or not yet active")
            return HandoffDecision(True, "one exact authority receipt is current", receipt.receipt_fingerprint)

    def request_scheduler_wakeup(
        self, identity: DeploymentAuthorityIdentity, receipt: DeploymentAuthorityHandoffReceipt, *, now: datetime
    ) -> SchedulerWakeupDecision:
        """Accept only a request directed to an already-authorized orchestrator."""

        decision = self.authorize(identity, receipt, now=now)
        if not decision.authorized:
            return SchedulerWakeupDecision(False, decision.reason, decision.receipt_fingerprint)
        return SchedulerWakeupDecision(True, "work may be requested from the receipt-bound orchestrator", decision.receipt_fingerprint)

    def begin_handoff(
        self, old_receipt: DeploymentAuthorityHandoffReceipt, new_identity: DeploymentAuthorityIdentity, *, handoff_fingerprint: str
    ) -> HandoffDecision:
        """Stop dispatch first and retain the only resumable handoff identity."""

        _require_fingerprint(handoff_fingerprint, "handoff")
        with self._store._lock:
            if self._store._progress is not None:
                return HandoffDecision(False, "another handoff is already incomplete")
            if self._store._active != old_receipt or not self._receipt_names_this_store(old_receipt):
                return HandoffDecision(False, "old receipt is not the active canonical authority")
            if not self._identity_names_this_store(new_identity):
                return HandoffDecision(False, "new authority names another state store")
            if not _same_authority_domain(old_receipt.identity, new_identity):
                return HandoffDecision(False, "new authority does not match the canonical repository state")
            if old_receipt.identity == new_identity:
                return HandoffDecision(False, "handoff must select a distinct candidate or environment")
            self._store._progress = HandoffProgress(
                handoff_fingerprint, old_receipt.receipt_fingerprint, new_identity, HandoffPhase.STOPPING,
            )
            return HandoffDecision(True, "old authority is now non-dispatching pending reconciliation", old_receipt.receipt_fingerprint)

    def reconcile(self, evidence: HandoffReconciliation) -> HandoffDecision:
        """Record complete dispatcher, child, and lease reconciliation evidence."""

        with self._store._lock:
            progress = self._store._progress
            if progress is None or progress.phase is not HandoffPhase.STOPPING:
                return HandoffDecision(False, "no stopping handoff can accept reconciliation evidence")
            if (
                evidence.handoff_fingerprint != progress.handoff_fingerprint
                or evidence.old_receipt_fingerprint != progress.old_receipt_fingerprint
                or evidence.state_store_fingerprint != self._store.state_store_fingerprint
                or evidence.state_id != self._store.state_id
                or not evidence.complete
            ):
                return HandoffDecision(False, "reconciliation evidence is incomplete or does not match machine truth")
            self._store._progress = HandoffProgress(
                progress.handoff_fingerprint, progress.old_receipt_fingerprint, progress.new_identity,
                HandoffPhase.RECONCILED, evidence,
            )
            return HandoffDecision(True, "old authority is reconciled and may be revoked", progress.old_receipt_fingerprint)

    def revoke_old_receipt(self, *, handoff_fingerprint: str) -> HandoffDecision:
        """Irreversibly revoke the old receipt only after reconciliation."""

        _require_fingerprint(handoff_fingerprint, "handoff")
        with self._store._lock:
            progress = self._store._progress
            if progress is None or progress.phase is not HandoffPhase.RECONCILED or progress.handoff_fingerprint != handoff_fingerprint:
                return HandoffDecision(False, "old receipt cannot be revoked before matching reconciliation")
            active = self._store._active
            if active is None or active.receipt_fingerprint != progress.old_receipt_fingerprint:
                return HandoffDecision(False, "machine truth no longer contains the old active receipt")
            self._store._revoked.add(active.receipt_fingerprint)
            self._store._active = None
            self._store._verification = None
            self._clear_claim()
            self._store._progress = HandoffProgress(
                progress.handoff_fingerprint, progress.old_receipt_fingerprint, progress.new_identity,
                HandoffPhase.REVOKED, progress.reconciliation,
            )
            return HandoffDecision(True, "old receipt is revoked; no authority is dispatching", active.receipt_fingerprint)

    def issue_new_receipt(
        self, receipt: DeploymentAuthorityHandoffReceipt, verification: DeploymentAuthorityReceiptVerification, *, handoff_fingerprint: str, now: datetime
    ) -> HandoffDecision:
        """Activate the new externally-issued receipt only after revocation."""

        _require_fingerprint(handoff_fingerprint, "handoff")
        with self._store._lock:
            progress = self._store._progress
            if progress is None or progress.phase is not HandoffPhase.REVOKED or progress.handoff_fingerprint != handoff_fingerprint:
                return HandoffDecision(False, "new receipt cannot issue before old receipt revocation")
            if receipt.identity != progress.new_identity or not self._receipt_names_this_store(receipt):
                return HandoffDecision(False, "new receipt does not match the reconciled handoff target")
            if (
                not _receipt_current(receipt, now)
                or receipt.receipt_fingerprint in self._store._revoked
                or not _verification_matches(receipt, verification)
            ):
                return HandoffDecision(False, "new receipt is stale, revoked, or not yet active")
            self._store._active = receipt
            self._store._verification = verification
            self._clear_claim()
            self._store._progress = None
            return HandoffDecision(True, "new receipt is the sole active authority", receipt.receipt_fingerprint)

    def _identity_names_this_store(self, identity: object) -> bool:
        return (
            type(identity) is DeploymentAuthorityIdentity
            and identity.state_store_fingerprint == self._store.state_store_fingerprint
            and identity.state_id == self._store.state_id
        )

    def _receipt_names_this_store(self, receipt: object) -> bool:
        return type(receipt) is DeploymentAuthorityHandoffReceipt and self._identity_names_this_store(receipt.identity)

    def _holds_claim(self, receipt: DeploymentAuthorityHandoffReceipt) -> bool:
        return (
            self._store._claim_owner_token is self._claim_owner_token
            and self._store._claim_receipt_fingerprint == receipt.receipt_fingerprint
            and self._store._claim_binding_digest == receipt.binding_digest
        )

    def _clear_claim(self) -> None:
        self._store._claim_owner_token = None
        self._store._claim_receipt_fingerprint = None
        self._store._claim_binding_digest = None


def _receipt_current(receipt: object, now: object) -> bool:
    return (
        type(receipt) is DeploymentAuthorityHandoffReceipt
        and type(now) is datetime
        and now.tzinfo is timezone.utc
        and receipt.issued_at <= now < receipt.expires_at
    )


def _verification_matches(
    receipt: object, verification: object,
) -> bool:
    return (
        type(receipt) is DeploymentAuthorityHandoffReceipt
        and type(verification) is DeploymentAuthorityReceiptVerification
        and verification.status is AuthorityReceiptVerificationStatus.FRESH
        and verification.receipt_fingerprint == receipt.receipt_fingerprint
        and verification.receipt_binding_digest == receipt.binding_digest
        and verification.repository_fingerprint == receipt.identity.repository_fingerprint
        and verification.state_store_fingerprint == receipt.identity.state_store_fingerprint
        and verification.state_id == receipt.identity.state_id
        and verification.candidate_sha == receipt.identity.candidate_sha
        and verification.environment_fingerprint == receipt.identity.environment_fingerprint
    )


def _same_authority_domain(left: DeploymentAuthorityIdentity, right: DeploymentAuthorityIdentity) -> bool:
    return (
        left.repository_fingerprint == right.repository_fingerprint
        and left.canonical_checkout_fingerprint == right.canonical_checkout_fingerprint
        and left.state_store_fingerprint == right.state_store_fingerprint
        and left.state_id == right.state_id
        and left.runtime_binding == right.runtime_binding
    )
