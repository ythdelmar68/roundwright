"""Fail-closed, credential-free execution boundary for bounded Canaries.

This module deliberately has no provider client, subprocess runner, credential
loader, or filesystem transport.  An owner-host supplies the two narrow
capabilities below: an atomic orchestrator lease and a mutation broker.  The
coordinator therefore gives workers no way to dispatch a Canary directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
import hashlib
import json
from threading import RLock
from typing import Protocol

from .canary_policy import (
    BoundedCanaryPolicy,
    BoundedCanaryReceipt,
    CanaryAuthorityContext,
    CanaryAuthorization,
    CanaryDecision,
    CanaryMutationRequest,
    CanaryPolicyError,
    advance_canary_receipt,
    authorize_canary_request,
    genesis_canary_receipt,
)


class CanaryExecutionError(ValueError):
    """Raised when an execution boundary is malformed or has drifted."""


class CanaryReadbackState(StrEnum):
    """The only semantic states a broker may disclose to this boundary."""

    APPLIED = "applied"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"


class CanaryTransitionState(StrEnum):
    CLAIMED = "claimed"
    VERIFIED = "verified"
    QUARANTINED = "quarantined"
    RETRY_ALLOWED = "retry-allowed"
    PRESERVED_FOR_OWNER = "preserved-for-owner"


class CanaryTransitionPurpose(StrEnum):
    EXECUTE = "execute"
    ROLLBACK = "rollback"
    CLEANUP = "cleanup"


_DIGEST_PREFIX = "sha256:"


def _digest(value: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _require_digest(value: object, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != len(_DIGEST_PREFIX) + 64
        or not value.startswith(_DIGEST_PREFIX)
        or any(character not in "0123456789abcdef" for character in value[len(_DIGEST_PREFIX):])
    ):
        raise CanaryExecutionError(f"{name} is invalid")


@dataclass(frozen=True, slots=True)
class CanarySemanticReadback:
    """A path-free semantic read-back from the owner-host broker."""

    state: CanaryReadbackState
    digest: str

    def __post_init__(self) -> None:
        if type(self.state) is not CanaryReadbackState:
            raise CanaryExecutionError("Canary read-back state is invalid")
        _require_digest(self.digest, "Canary read-back digest")


@dataclass(frozen=True, slots=True)
class CanaryDispatchResult:
    """Public-safe dispatch acknowledgement; it is never proof of success."""

    accepted: bool
    transition_id: str

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool or type(self.transition_id) is not str or not self.transition_id:
            raise CanaryExecutionError("Canary dispatch result is invalid")


class CanaryOrchestratorLease(Protocol):
    """Owner-host atomic claim for one policy/receipt-chain consumption fence."""

    def claim(self, consumption_key: str, claim_digest: str) -> bool:
        """Atomically claim a transition; ``False`` means another process owns it."""


class CanaryMutationBroker(Protocol):
    """The sole owner-host bridge allowed to dispatch and read a Canary state."""

    def dispatch(
        self,
        authorization: CanaryAuthorization,
        request: CanaryMutationRequest,
        purpose: CanaryTransitionPurpose,
    ) -> CanaryDispatchResult:
        """Dispatch exactly the authorized transition, without exposing credentials."""

    def semantic_readback(
        self, authorization: CanaryAuthorization, request: CanaryMutationRequest,
    ) -> CanarySemanticReadback:
        """Return only the exact postcondition's semantic state and digest."""


@dataclass(frozen=True, slots=True)
class CanaryExecutionReceipt:
    """Path-free receipt for one coordinator outcome, including quarantine."""

    policy_digest: str
    contract_digest: str
    claim_digest: str
    request_digest: str
    receipt_chain_head_digest: str
    purpose: CanaryTransitionPurpose
    state: CanaryTransitionState
    semantic_readback_digest: str | None = None
    canary_receipt_digest: str | None = None
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        for value, name in (
            (self.policy_digest, "Canary policy digest"),
            (self.contract_digest, "Canary contract digest"),
            (self.claim_digest, "Canary claim digest"),
            (self.request_digest, "Canary request digest"),
            (self.receipt_chain_head_digest, "Canary chain head digest"),
        ):
            _require_digest(value, name)
        if type(self.purpose) is not CanaryTransitionPurpose or type(self.state) is not CanaryTransitionState:
            raise CanaryExecutionError("Canary execution receipt state is invalid")
        if self.semantic_readback_digest is not None:
            _require_digest(self.semantic_readback_digest, "Canary execution read-back digest")
        if self.canary_receipt_digest is not None:
            _require_digest(self.canary_receipt_digest, "Canary execution receipt digest")
        if self.state is CanaryTransitionState.VERIFIED:
            if self.semantic_readback_digest is None or self.canary_receipt_digest is None:
                raise CanaryExecutionError("verified Canary transition lacks semantic receipt evidence")
        elif self.canary_receipt_digest is not None:
            raise CanaryExecutionError("unverified Canary transition cannot advance the receipt chain")
        object.__setattr__(self, "receipt_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        """Render a path-free receipt suitable for public-safe retention."""

        value: dict[str, object] = {
            "policy_digest": self.policy_digest,
            "contract_digest": self.contract_digest,
            "claim_digest": self.claim_digest,
            "request_digest": self.request_digest,
            "receipt_chain_head_digest": self.receipt_chain_head_digest,
            "purpose": self.purpose.value,
            "state": self.state.value,
            "semantic_readback_digest": self.semantic_readback_digest,
            "canary_receipt_digest": self.canary_receipt_digest,
        }
        return value | ({"receipt_digest": self.receipt_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class CanaryExecutionResult:
    """A bounded result.  Callers can never infer success from dispatch alone."""

    decision: CanaryDecision
    receipt: CanaryExecutionReceipt | None
    canary_receipt: BoundedCanaryReceipt | None

    @property
    def verified(self) -> bool:
        return self.receipt is not None and self.receipt.state is CanaryTransitionState.VERIFIED


@dataclass(slots=True)
class _TransitionRecord:
    authorization: CanaryAuthorization
    request: CanaryMutationRequest
    purpose: CanaryTransitionPurpose
    state: CanaryTransitionState
    receipt: CanaryExecutionReceipt
    canary_receipt: BoundedCanaryReceipt | None = None
    retry_used: bool = False


class CanaryExecutionLedger:
    """Coordinator state with idempotent local replay semantics.

    The owner-host lease is still required for cross-process exclusion.  This
    ledger prevents duplicate delivery or request substitution within one
    coordinator and retains every non-success outcome for reconciliation.
    """

    def __init__(self, policy: BoundedCanaryPolicy) -> None:
        if type(policy) is not BoundedCanaryPolicy:
            raise CanaryExecutionError("Canary execution policy is invalid")
        self._policy = policy
        self._chain: list[BoundedCanaryReceipt] = [genesis_canary_receipt(policy)]
        self._records: dict[str, _TransitionRecord] = {}
        self._lock = RLock()

    def chain(self) -> tuple[BoundedCanaryReceipt, ...]:
        with self._lock:
            return tuple(self._chain)

    @property
    def policy_digest(self) -> str:
        return self._policy.policy_digest

    def record(self, claim_digest: str) -> _TransitionRecord | None:
        _require_digest(claim_digest, "Canary claim digest")
        with self._lock:
            return self._records.get(claim_digest)

    def matching(
        self, request: CanaryMutationRequest, purpose: CanaryTransitionPurpose,
    ) -> _TransitionRecord | None:
        """Find a prior exact delivery without using a newer chain head."""

        if type(request) is not CanaryMutationRequest or type(purpose) is not CanaryTransitionPurpose:
            raise CanaryExecutionError("Canary execution replay request is invalid")
        with self._lock:
            matches = [
                record for record in self._records.values()
                if record.request == request and record.purpose is purpose
            ]
            if len(matches) > 1:
                raise CanaryExecutionError("Canary execution replay is ambiguous")
            return matches[0] if matches else None

    def reserve(
        self, authorization: CanaryAuthorization, request: CanaryMutationRequest,
        purpose: CanaryTransitionPurpose,
    ) -> tuple[_TransitionRecord, bool]:
        if type(authorization) is not CanaryAuthorization or type(request) is not CanaryMutationRequest or type(purpose) is not CanaryTransitionPurpose:
            raise CanaryExecutionError("Canary execution reservation is invalid")
        with self._lock:
            existing = self._records.get(authorization.claim_digest)
            if existing is not None:
                if existing.request != request or existing.purpose is not purpose:
                    raise CanaryExecutionError("Canary consumption fence was reused with a different transition")
                return existing, False
            receipt = CanaryExecutionReceipt(
                authorization.policy_digest, authorization.contract_digest,
                authorization.claim_digest, authorization.request_digest,
                authorization.receipt_chain_head_digest, purpose,
                CanaryTransitionState.CLAIMED,
            )
            record = _TransitionRecord(authorization, request, purpose, CanaryTransitionState.CLAIMED, receipt)
            self._records[authorization.claim_digest] = record
            return record, True

    def update(
        self, record: _TransitionRecord, state: CanaryTransitionState,
        *, readback_digest: str | None = None, canary_receipt: BoundedCanaryReceipt | None = None,
    ) -> _TransitionRecord:
        if type(record) is not _TransitionRecord or type(state) is not CanaryTransitionState:
            raise CanaryExecutionError("Canary execution record is invalid")
        with self._lock:
            current = self._records.get(record.authorization.claim_digest)
            if current is not record:
                raise CanaryExecutionError("Canary execution record is stale")
            if state is CanaryTransitionState.VERIFIED:
                if type(canary_receipt) is not BoundedCanaryReceipt:
                    raise CanaryExecutionError("verified Canary transition has no receipt")
                if canary_receipt.predecessor_receipt_digest != record.authorization.receipt_chain_head_digest:
                    raise CanaryExecutionError("verified Canary transition has stale chain evidence")
                self._chain.append(canary_receipt)
            elif canary_receipt is not None:
                raise CanaryExecutionError("unverified Canary transition cannot advance the chain")
            record.state = state
            record.canary_receipt = canary_receipt
            record.receipt = CanaryExecutionReceipt(
                record.authorization.policy_digest, record.authorization.contract_digest,
                record.authorization.claim_digest, record.authorization.request_digest,
                record.authorization.receipt_chain_head_digest, record.purpose, state,
                readback_digest, canary_receipt.receipt_digest if canary_receipt is not None else None,
            )
            return record

    def consume_retry(self, record: _TransitionRecord) -> bool:
        """Atomically consume the single retry allowance for an absent state."""

        with self._lock:
            if (
                self._records.get(record.authorization.claim_digest) is not record
                or record.state is not CanaryTransitionState.RETRY_ALLOWED
                or record.retry_used
            ):
                return False
            record.retry_used = True
            return True


class CanaryOrchestrator:
    """Run a policy-bound transition only through an owner-host lease and broker."""

    def __init__(
        self, policy: BoundedCanaryPolicy, context: CanaryAuthorityContext,
        lease: CanaryOrchestratorLease, broker: CanaryMutationBroker,
        *, ledger: CanaryExecutionLedger | None = None,
    ) -> None:
        if type(policy) is not BoundedCanaryPolicy or type(context) is not CanaryAuthorityContext:
            raise CanaryExecutionError("Canary orchestration evidence is invalid")
        if not hasattr(lease, "claim") or not hasattr(broker, "dispatch") or not hasattr(broker, "semantic_readback"):
            raise CanaryExecutionError("Canary owner-host capabilities are unavailable")
        self._policy = policy
        self._context = context
        self._lease = lease
        self._broker = broker
        self._ledger = CanaryExecutionLedger(policy) if ledger is None else ledger
        if type(self._ledger) is not CanaryExecutionLedger or self._ledger.policy_digest != policy.policy_digest:
            raise CanaryExecutionError("Canary execution ledger is not bound to the selected policy")
        if self._context.prior_receipt_digest != self._ledger.chain()[-1].receipt_digest:
            raise CanaryExecutionError("Canary execution context is not bound to the ledger genesis receipt")

    @property
    def ledger(self) -> CanaryExecutionLedger:
        return self._ledger

    def execute(self, request: CanaryMutationRequest) -> CanaryExecutionResult:
        return self._begin(request, CanaryTransitionPurpose.EXECUTE)

    def rollback(self, request: CanaryMutationRequest) -> CanaryExecutionResult:
        return self._begin(request, CanaryTransitionPurpose.ROLLBACK)

    def cleanup(self, request: CanaryMutationRequest) -> CanaryExecutionResult:
        return self._begin(request, CanaryTransitionPurpose.CLEANUP)

    def _decision(self, request: CanaryMutationRequest) -> CanaryDecision:
        chain = self._ledger.chain()
        # The selection context pins the genesis head in ``__init__``.  Only a
        # receipt produced and retained by this coordinator may move it.
        context = replace(self._context, prior_receipt_digest=chain[-1].receipt_digest)
        return authorize_canary_request(self._policy, context, request, chain)

    def _begin(self, request: CanaryMutationRequest, purpose: CanaryTransitionPurpose) -> CanaryExecutionResult:
        try:
            prior = self._ledger.matching(request, purpose)
        except CanaryExecutionError:
            prior = None
        if prior is not None:
            return CanaryExecutionResult(
                CanaryDecision(True, "duplicate Canary delivery converged on its retained receipt", self._policy.policy_digest, "reuse-receipt"),
                prior.receipt, prior.canary_receipt,
            )
        try:
            decision = self._decision(request)
        except (AttributeError, TypeError, ValueError, CanaryPolicyError):
            decision = CanaryDecision(False, "Canary execution evidence is unavailable", None, "preserve-for-owner")
        if not decision.authorized or decision.authorization is None:
            return CanaryExecutionResult(decision, None, None)
        try:
            record, newly_reserved = self._ledger.reserve(decision.authorization, request, purpose)
        except CanaryExecutionError:
            return CanaryExecutionResult(
                CanaryDecision(False, "Canary consumption fence conflicts", decision.policy_digest, "preserve-for-owner"), None, None,
            )
        if not newly_reserved:
            return CanaryExecutionResult(decision, record.receipt, record.canary_receipt)
        try:
            claimed = self._lease.claim(decision.authorization.consumption_key, decision.authorization.claim_digest)
        except Exception:
            claimed = False
        if not claimed:
            record = self._ledger.update(record, CanaryTransitionState.PRESERVED_FOR_OWNER)
            return CanaryExecutionResult(
                CanaryDecision(False, "another Orchestrator owns this Canary transition", decision.policy_digest, "preserve-for-owner"), record.receipt, None,
            )
        return self._dispatch(decision, record)

    def reconcile(self, claim_digest: str) -> CanaryExecutionResult:
        """Read back a quarantined transition; this method never redispatches it."""

        record = self._ledger.record(claim_digest)
        if record is None:
            return CanaryExecutionResult(CanaryDecision(False, "Canary transition is unknown", None, "preserve-for-owner"), None, None)
        decision = self._decision(record.request)
        if not decision.authorized or decision.authorization != record.authorization:
            return CanaryExecutionResult(CanaryDecision(False, "Canary reconciliation evidence has drifted", decision.policy_digest, "preserve-for-owner"), record.receipt, record.canary_receipt)
        if record.state not in {CanaryTransitionState.QUARANTINED, CanaryTransitionState.RETRY_ALLOWED}:
            return CanaryExecutionResult(decision, record.receipt, record.canary_receipt)
        return self._readback(decision, record, allow_retry=True)

    def retry(self, claim_digest: str) -> CanaryExecutionResult:
        """Retry only after an explicit absent semantic read-back permits it."""

        record = self._ledger.record(claim_digest)
        if record is None:
            return CanaryExecutionResult(CanaryDecision(False, "Canary transition is unknown", None, "preserve-for-owner"), None, None)
        decision = self._decision(record.request)
        if not decision.authorized or decision.authorization != record.authorization:
            return CanaryExecutionResult(CanaryDecision(False, "Canary retry evidence has drifted", decision.policy_digest, "preserve-for-owner"), record.receipt, record.canary_receipt)
        if record.state is not CanaryTransitionState.RETRY_ALLOWED:
            return CanaryExecutionResult(CanaryDecision(False, "Canary retry requires an absent semantic read-back", decision.policy_digest, "preserve-for-owner"), record.receipt, None)
        if not self._ledger.consume_retry(record):
            return CanaryExecutionResult(CanaryDecision(False, "Canary retry budget is exhausted", decision.policy_digest, "preserve-for-owner"), record.receipt, None)
        return self._dispatch(decision, record)

    def _dispatch(self, decision: CanaryDecision, record: _TransitionRecord) -> CanaryExecutionResult:
        assert decision.authorization is not None
        try:
            dispatch = self._broker.dispatch(decision.authorization, record.request, record.purpose)
            if not dispatch.accepted:
                return self._readback(decision, record, allow_retry=True)
        except Exception:
            return self._readback(decision, record, allow_retry=True)
        return self._readback(decision, record, allow_retry=False)

    def _readback(
        self, decision: CanaryDecision, record: _TransitionRecord, *, allow_retry: bool,
    ) -> CanaryExecutionResult:
        assert decision.authorization is not None
        try:
            readback = self._broker.semantic_readback(decision.authorization, record.request)
        except Exception:
            readback = None
        if type(readback) is not CanarySemanticReadback or readback.state is CanaryReadbackState.AMBIGUOUS:
            record = self._ledger.update(
                record, CanaryTransitionState.QUARANTINED,
                readback_digest=readback.digest if type(readback) is CanarySemanticReadback else None,
            )
            return CanaryExecutionResult(
                CanaryDecision(False, "Canary outcome is ambiguous; semantic reconciliation is required", decision.policy_digest, "preserve-for-owner"), record.receipt, None,
            )
        if readback.state is CanaryReadbackState.APPLIED:
            try:
                canary_receipt = advance_canary_receipt(
                    self._ledger.chain()[-1], record.request.operation, readback.digest,
                )
                record = self._ledger.update(
                    record, CanaryTransitionState.VERIFIED,
                    readback_digest=readback.digest, canary_receipt=canary_receipt,
                )
            except (AttributeError, TypeError, ValueError, CanaryExecutionError, CanaryPolicyError):
                record = self._ledger.update(record, CanaryTransitionState.QUARANTINED)
                return CanaryExecutionResult(CanaryDecision(False, "Canary receipt reconciliation failed", decision.policy_digest, "preserve-for-owner"), record.receipt, None)
            return CanaryExecutionResult(decision, record.receipt, record.canary_receipt)
        state = CanaryTransitionState.RETRY_ALLOWED if allow_retry else CanaryTransitionState.QUARANTINED
        record = self._ledger.update(record, state, readback_digest=readback.digest)
        next_action = "retry-after-semantic-readback" if state is CanaryTransitionState.RETRY_ALLOWED else "preserve-for-owner"
        return CanaryExecutionResult(CanaryDecision(False, "Canary read-back does not prove the requested transition", decision.policy_digest, next_action), record.receipt, None)
