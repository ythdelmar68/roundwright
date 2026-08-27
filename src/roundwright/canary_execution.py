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
from typing import Mapping, Protocol

from .canary_policy import (
    BoundedCanaryPolicy,
    BoundedCanaryReceipt,
    CanaryAuthorityContext,
    CanaryAuthorization,
    CanaryDecision,
    CanaryMutationRequest,
    CanaryPolicyError,
    CanaryResult,
    advance_canary_receipt,
    authorize_canary_request,
    genesis_canary_receipt,
    validate_canary_receipt_chain,
)
from .github import GitHubMutationOperation


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
_INVERSE_CLEANUP_OPERATION = {
    GitHubMutationOperation.CREATE_BRANCH: GitHubMutationOperation.DELETE_BRANCH,
}


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


def _cleanup_action_for(operation: GitHubMutationOperation) -> GitHubMutationOperation:
    """Return the one reversible policy operation; all other actions fail closed."""

    try:
        return _INVERSE_CLEANUP_OPERATION[operation]
    except (KeyError, TypeError) as error:
        raise CanaryExecutionError("Canary predecessor has no reversible cleanup action") from error


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

    def semantic_pre_readback(
        self, authorization: CanaryAuthorization, request: CanaryMutationRequest,
        predecessor_receipt_digest: str,
    ) -> CanarySemanticReadback:
        """Prove a reversible predecessor state before rollback or cleanup."""


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
    predecessor_transition_receipt_digest: str | None = None
    pre_state_readback_digest: str | None = None
    retry_used: bool = False
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
        for value, name in (
            (self.predecessor_transition_receipt_digest, "Canary predecessor receipt digest"),
            (self.pre_state_readback_digest, "Canary pre-state read-back digest"),
        ):
            if value is not None:
                _require_digest(value, name)
        if type(self.retry_used) is not bool:
            raise CanaryExecutionError("Canary retry consumption is invalid")
        if self.purpose is CanaryTransitionPurpose.EXECUTE:
            if self.predecessor_transition_receipt_digest is not None or self.pre_state_readback_digest is not None:
                raise CanaryExecutionError("ordinary Canary execution cannot carry cleanup preconditions")
        elif self.predecessor_transition_receipt_digest is None or self.pre_state_readback_digest is None:
            raise CanaryExecutionError("rollback or cleanup lacks reconciled predecessor evidence")
        if self.retry_used and self.state is CanaryTransitionState.RETRY_ALLOWED:
            raise CanaryExecutionError("consumed Canary retry cannot remain retry-allowed")
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
            "predecessor_transition_receipt_digest": self.predecessor_transition_receipt_digest,
            "pre_state_readback_digest": self.pre_state_readback_digest,
            "retry_used": self.retry_used,
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
    predecessor_transition_receipt_digest: str | None = None
    pre_state_readback_digest: str | None = None


class CanaryExecutionLedger:
    """Coordinator state with validated, hydratable replay semantics.

    The owner-host lease is still required for cross-process exclusion.  This
    ledger prevents duplicate delivery or request substitution and retains a
    sealed, local-only snapshot that a replacement coordinator can validate
    before it reconciles a verified, quarantined, or retry-allowed transition.
    """

    def __init__(self, policy: BoundedCanaryPolicy) -> None:
        if type(policy) is not BoundedCanaryPolicy:
            raise CanaryExecutionError("Canary execution policy is invalid")
        self._policy = policy
        self._chain: list[BoundedCanaryReceipt] = [genesis_canary_receipt(policy)]
        self._records: dict[str, _TransitionRecord] = {}
        self._lock = RLock()
        self._hydrated = False

    def chain(self) -> tuple[BoundedCanaryReceipt, ...]:
        with self._lock:
            return tuple(self._chain)

    @property
    def policy_digest(self) -> str:
        return self._policy.policy_digest

    @property
    def requires_retry_lease_proof(self) -> bool:
        """A replacement coordinator must re-establish the original fence."""

        return self._hydrated

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

    def predecessor(self) -> _TransitionRecord | None:
        """Return the exact record which advanced the retained chain head."""

        with self._lock:
            head = self._chain[-1]
            if head.predecessor_receipt_digest is None:
                return None
            matches = [
                record for record in self._records.values()
                if record.state is CanaryTransitionState.VERIFIED
                and record.canary_receipt is head
                and record.receipt.canary_receipt_digest == head.receipt_digest
            ]
            if len(matches) != 1:
                raise CanaryExecutionError("Canary retained predecessor is unavailable or ambiguous")
            return matches[0]

    def reserve(
        self, authorization: CanaryAuthorization, request: CanaryMutationRequest,
        purpose: CanaryTransitionPurpose, *, predecessor_transition_receipt_digest: str | None = None,
        pre_state_readback_digest: str | None = None,
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
                CanaryTransitionState.CLAIMED, predecessor_transition_receipt_digest=predecessor_transition_receipt_digest,
                pre_state_readback_digest=pre_state_readback_digest,
            )
            record = _TransitionRecord(
                authorization, request, purpose, CanaryTransitionState.CLAIMED, receipt,
                predecessor_transition_receipt_digest=predecessor_transition_receipt_digest,
                pre_state_readback_digest=pre_state_readback_digest,
            )
            self._records[authorization.claim_digest] = record
            return record, True

    def update(
        self, record: _TransitionRecord, state: CanaryTransitionState,
        *, readback_digest: str | None = None, canary_receipt: BoundedCanaryReceipt | None = None,
        retry_used: bool | None = None,
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
            if retry_used is not None:
                if type(retry_used) is not bool:
                    raise CanaryExecutionError("Canary retry consumption is invalid")
                record.retry_used = retry_used
            record.receipt = CanaryExecutionReceipt(
                record.authorization.policy_digest, record.authorization.contract_digest,
                record.authorization.claim_digest, record.authorization.request_digest,
                record.authorization.receipt_chain_head_digest, record.purpose, state,
                readback_digest, canary_receipt.receipt_digest if canary_receipt is not None else None,
                record.predecessor_transition_receipt_digest, record.pre_state_readback_digest,
                record.retry_used,
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
            record.state = CanaryTransitionState.CLAIMED
            record.receipt = CanaryExecutionReceipt(
                record.authorization.policy_digest, record.authorization.contract_digest,
                record.authorization.claim_digest, record.authorization.request_digest,
                record.authorization.receipt_chain_head_digest, record.purpose,
                CanaryTransitionState.CLAIMED,
                predecessor_transition_receipt_digest=record.predecessor_transition_receipt_digest,
                pre_state_readback_digest=record.pre_state_readback_digest,
                retry_used=True,
            )
            return True

    def sealed_state(self) -> dict[str, object]:
        """Return local-only, validated hydration material; never publish it."""

        with self._lock:
            return {
                "schema": "roundwright-canary-execution-ledger/v1",
                "policy_digest": self._policy.policy_digest,
                "contract_digest": self._policy.contract_digest,
                "candidate_sha": self._policy.candidate_sha,
                "chain": [receipt.public_payload() for receipt in self._chain],
                "records": [
                    {
                        "authorization": {
                            "policy_digest": record.authorization.policy_digest,
                            "contract_digest": record.authorization.contract_digest,
                            "request_digest": record.authorization.request_digest,
                            "receipt_chain_head_digest": record.authorization.receipt_chain_head_digest,
                        },
                        "request": {
                            "operation": record.request.operation.value,
                            "branch": record.request.branch,
                            "paths": list(record.request.paths),
                        },
                        "purpose": record.purpose.value,
                        "state": record.state.value,
                        "receipt": record.receipt.public_payload(),
                        "canary_receipt_digest": record.canary_receipt.receipt_digest if record.canary_receipt is not None else None,
                        "retry_used": record.retry_used,
                        "predecessor_transition_receipt_digest": record.predecessor_transition_receipt_digest,
                        "pre_state_readback_digest": record.pre_state_readback_digest,
                    }
                    for record in self._records.values()
                ],
            }

    @classmethod
    def hydrate(cls, policy: BoundedCanaryPolicy, sealed: object) -> "CanaryExecutionLedger":
        """Recreate only an exact policy-bound ledger, failing closed on drift."""

        try:
            if type(policy) is not BoundedCanaryPolicy or type(sealed) is not dict or set(sealed) != {
                "schema", "policy_digest", "contract_digest", "candidate_sha", "chain", "records",
            }:
                raise ValueError
            if (
                sealed["schema"] != "roundwright-canary-execution-ledger/v1"
                or sealed["policy_digest"] != policy.policy_digest
                or sealed["contract_digest"] != policy.contract_digest
                or sealed["candidate_sha"] != policy.candidate_sha
                or type(sealed["chain"]) is not list or type(sealed["records"]) is not list
            ):
                raise ValueError
            chain = tuple(cls._hydrate_canary_receipt(policy, value) for value in sealed["chain"])
            validate_canary_receipt_chain(policy, chain)
            by_digest = {receipt.receipt_digest: receipt for receipt in chain}
            if len(by_digest) != len(chain):
                raise ValueError
            records: dict[str, _TransitionRecord] = {}
            idempotency_identities: set[tuple[str, CanaryTransitionPurpose]] = set()
            for value in sealed["records"]:
                record = cls._hydrate_record(policy, value, by_digest, chain[-1].receipt_digest)
                if record.authorization.claim_digest in records:
                    raise ValueError
                identity = (record.request.request_digest, record.purpose)
                if identity in idempotency_identities:
                    raise ValueError
                idempotency_identities.add(identity)
                records[record.authorization.claim_digest] = record
            cls._require_verified_record_bijection(policy, chain, records)
            ledger = cls(policy)
            ledger._chain = list(chain)
            ledger._records = records
            ledger._hydrated = True
            if chain[-1].predecessor_receipt_digest is not None:
                ledger.predecessor()
            return ledger
        except (KeyError, TypeError, ValueError, CanaryExecutionError, CanaryPolicyError) as error:
            raise CanaryExecutionError("Canary execution ledger hydration is invalid or stale") from error

    @staticmethod
    def _hydrate_canary_receipt(policy: BoundedCanaryPolicy, value: object) -> BoundedCanaryReceipt:
        if type(value) is not dict or set(value) != {
            "schema", "policy_digest", "contract_digest", "base_sha", "candidate_sha",
            "target_repository", "target_baseline_sha", "target_leaf_number", "leaf_number",
            "requested_operations", "operation_counts", "total_calls", "result",
            "semantic_readback_digest", "predecessor_receipt_digest", "receipt_digest",
        }:
            raise ValueError
        if (
            value["schema"] != "roundwright-bounded-canary-receipt/v1"
            or value["policy_digest"] != policy.policy_digest or value["contract_digest"] != policy.contract_digest
            or value["base_sha"] != policy.base_sha or value["candidate_sha"] != policy.candidate_sha
            or value["target_repository"] != policy.target.repository or value["target_baseline_sha"] != policy.target.baseline_sha
            or value["target_leaf_number"] != policy.target.leaf_number or value["leaf_number"] != policy.leaf_number
            or value["requested_operations"] != [operation.value for operation in policy.requested_operations]
            or type(value["operation_counts"]) is not dict
            or set(value["operation_counts"]) != {operation.value for operation in policy.requested_operations}
            or any(type(count) is not int or count < 0 for count in value["operation_counts"].values())
            or type(value["total_calls"]) is not int
            or value["total_calls"] != sum(value["operation_counts"].values())
        ):
            raise ValueError
        counts = tuple((operation, value["operation_counts"].get(operation.value)) for operation in policy.requested_operations)
        receipt = BoundedCanaryReceipt(
            policy, CanaryResult(value["result"]), counts, value["semantic_readback_digest"],
            value["predecessor_receipt_digest"],
        )
        if receipt.receipt_digest != value["receipt_digest"]:
            raise ValueError
        return receipt

    @staticmethod
    def _require_verified_record_bijection(
        policy: BoundedCanaryPolicy, chain: tuple[BoundedCanaryReceipt, ...],
        records: Mapping[str, _TransitionRecord],
    ) -> None:
        """Bind every non-genesis receipt to one exact verified action record."""

        verified = [record for record in records.values() if record.state is CanaryTransitionState.VERIFIED]
        if len(verified) != len(chain) - 1:
            raise ValueError
        previous = chain[0]
        matched: set[str] = set()
        for receipt in chain[1:]:
            before, after = dict(previous.operation_counts), dict(receipt.operation_counts)
            changed = [
                operation for operation in policy.requested_operations
                if after[operation] - before[operation] == 1
            ]
            if (
                len(changed) != 1
                or any(after[operation] - before[operation] not in {0, 1} for operation in policy.requested_operations)
            ):
                raise ValueError
            operation = changed[0]
            candidates = [
                record for record in verified
                if record.canary_receipt is receipt
                and record.authorization.receipt_chain_head_digest == previous.receipt_digest
                and record.request.operation is operation
                and record.receipt.canary_receipt_digest == receipt.receipt_digest
                and record.receipt.semantic_readback_digest == receipt.semantic_readback_digest
            ]
            if len(candidates) != 1 or candidates[0].authorization.claim_digest in matched:
                raise ValueError
            record = candidates[0]
            CanaryExecutionLedger._require_hydrated_policy_authorization(policy, record, previous)
            if record.purpose is not CanaryTransitionPurpose.EXECUTE:
                previous_record = next(
                    (item for item in verified if item.canary_receipt is previous), None,
                )
                if (
                    previous_record is None
                    or record.predecessor_transition_receipt_digest != previous_record.receipt.receipt_digest
                    or record.pre_state_readback_digest is None
                    or record.request.operation is not _cleanup_action_for(previous_record.request.operation)
                    or record.request.branch != previous_record.request.branch
                    or record.request.paths != previous_record.request.paths
                ):
                    raise ValueError
            matched.add(record.authorization.claim_digest)
            previous = receipt
        if len(matched) != len(verified):
            raise ValueError
        for record in records.values():
            predecessor = next(
                (receipt for receipt in chain if receipt.receipt_digest == record.authorization.receipt_chain_head_digest),
                None,
            )
            if predecessor is None:
                raise ValueError
            CanaryExecutionLedger._require_hydrated_policy_authorization(policy, record, predecessor)
            if record.purpose is not CanaryTransitionPurpose.EXECUTE:
                previous_record = next(
                    (item for item in verified if item.canary_receipt is predecessor), None,
                )
                if (
                    previous_record is None
                    or record.predecessor_transition_receipt_digest != previous_record.receipt.receipt_digest
                    or record.pre_state_readback_digest is None
                    or record.request.operation is not _cleanup_action_for(previous_record.request.operation)
                    or record.request.branch != previous_record.request.branch
                    or record.request.paths != previous_record.request.paths
                ):
                    raise ValueError

    @staticmethod
    def _require_hydrated_policy_authorization(
        policy: BoundedCanaryPolicy, record: _TransitionRecord,
        predecessor: BoundedCanaryReceipt,
    ) -> None:
        """Reject self-consistent records that are outside the selected policy."""

        request, authorization = record.request, record.authorization
        expected = CanaryAuthorization(
            policy.policy_digest, policy.contract_digest, request.request_digest,
            predecessor.receipt_digest,
        )
        if (
            request.operation not in policy.requested_operations
            or request.branch != policy.branch
            or any(path not in policy.allowed_paths for path in request.paths)
            or authorization != expected
        ):
            raise ValueError
        if record.purpose is CanaryTransitionPurpose.EXECUTE:
            if record.predecessor_transition_receipt_digest is not None or record.pre_state_readback_digest is not None:
                raise ValueError

    @staticmethod
    def _hydrate_record(
        policy: BoundedCanaryPolicy, value: object, by_digest: Mapping[str, BoundedCanaryReceipt],
        chain_head: str,
    ) -> _TransitionRecord:
        if type(value) is not dict or set(value) != {
            "authorization", "request", "purpose", "state", "receipt", "canary_receipt_digest",
            "retry_used", "predecessor_transition_receipt_digest", "pre_state_readback_digest",
        } or type(value["authorization"]) is not dict or type(value["request"]) is not dict:
            raise ValueError
        authorization_value, request_value = value["authorization"], value["request"]
        if set(authorization_value) != {
            "policy_digest", "contract_digest", "request_digest", "receipt_chain_head_digest",
        } or set(request_value) != {"operation", "branch", "paths"} or type(request_value["paths"]) is not list:
            raise ValueError
        request = CanaryMutationRequest(
            GitHubMutationOperation(request_value["operation"]), request_value["branch"],
            tuple(request_value["paths"]),
        )
        authorization = CanaryAuthorization(
            authorization_value["policy_digest"], authorization_value["contract_digest"],
            authorization_value["request_digest"], authorization_value["receipt_chain_head_digest"],
        )
        if (
            authorization.policy_digest != policy.policy_digest or authorization.contract_digest != policy.contract_digest
            or authorization.request_digest != request.request_digest
            or authorization.receipt_chain_head_digest not in by_digest
        ):
            raise ValueError
        receipt = CanaryExecutionLedger._hydrate_execution_receipt(value["receipt"])
        purpose, state = CanaryTransitionPurpose(value["purpose"]), CanaryTransitionState(value["state"])
        if (
            receipt.policy_digest != authorization.policy_digest or receipt.contract_digest != authorization.contract_digest
            or receipt.claim_digest != authorization.claim_digest or receipt.request_digest != authorization.request_digest
            or receipt.receipt_chain_head_digest != authorization.receipt_chain_head_digest
            or receipt.purpose is not purpose or receipt.state is not state
            or receipt.retry_used != value["retry_used"]
            or receipt.predecessor_transition_receipt_digest != value["predecessor_transition_receipt_digest"]
            or receipt.pre_state_readback_digest != value["pre_state_readback_digest"]
        ):
            raise ValueError
        canary_digest = value["canary_receipt_digest"]
        canary_receipt = by_digest.get(canary_digest) if canary_digest is not None else None
        if state is CanaryTransitionState.VERIFIED:
            if canary_receipt is None or receipt.canary_receipt_digest != canary_digest or canary_receipt.predecessor_receipt_digest != authorization.receipt_chain_head_digest:
                raise ValueError
        elif canary_receipt is not None or receipt.canary_receipt_digest is not None:
            raise ValueError
        if state is not CanaryTransitionState.VERIFIED and authorization.receipt_chain_head_digest != chain_head:
            raise ValueError
        return _TransitionRecord(
            authorization, request, purpose, state, receipt, canary_receipt,
            value["retry_used"], value["predecessor_transition_receipt_digest"],
            value["pre_state_readback_digest"],
        )

    @staticmethod
    def _hydrate_execution_receipt(value: object) -> CanaryExecutionReceipt:
        if type(value) is not dict or set(value) != {
            "policy_digest", "contract_digest", "claim_digest", "request_digest", "receipt_chain_head_digest",
            "purpose", "state", "semantic_readback_digest", "canary_receipt_digest",
            "predecessor_transition_receipt_digest", "pre_state_readback_digest", "retry_used", "receipt_digest",
        }:
            raise ValueError
        receipt = CanaryExecutionReceipt(
            value["policy_digest"], value["contract_digest"], value["claim_digest"], value["request_digest"],
            value["receipt_chain_head_digest"], CanaryTransitionPurpose(value["purpose"]),
            CanaryTransitionState(value["state"]), value["semantic_readback_digest"], value["canary_receipt_digest"],
            value["predecessor_transition_receipt_digest"], value["pre_state_readback_digest"], value["retry_used"],
        )
        if receipt.receipt_digest != value["receipt_digest"]:
            raise ValueError
        return receipt


class CanaryOrchestrator:
    """Run a policy-bound transition only through an owner-host lease and broker."""

    def __init__(
        self, policy: BoundedCanaryPolicy, context: CanaryAuthorityContext,
        lease: CanaryOrchestratorLease, broker: CanaryMutationBroker,
        *, ledger: CanaryExecutionLedger | None = None,
    ) -> None:
        if type(policy) is not BoundedCanaryPolicy or type(context) is not CanaryAuthorityContext:
            raise CanaryExecutionError("Canary orchestration evidence is invalid")
        if not all(hasattr(broker, name) for name in ("dispatch", "semantic_readback", "semantic_pre_readback")) or not hasattr(lease, "claim"):
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
            return CanaryExecutionResult(
                CanaryDecision(False, "Canary duplicate-delivery identity is ambiguous", self._policy.policy_digest, "preserve-for-owner"),
                None, None,
            )
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
        predecessor_transition_receipt_digest: str | None = None
        pre_state_readback_digest: str | None = None
        if purpose is not CanaryTransitionPurpose.EXECUTE:
            try:
                predecessor = self._ledger.predecessor()
                if predecessor is None or predecessor.canary_receipt is None:
                    raise CanaryExecutionError("Canary rollback has no retained predecessor transition")
                inverse = _cleanup_action_for(predecessor.request.operation)
                if (
                    request.operation is not inverse
                    or request.branch != predecessor.request.branch
                    or request.paths != predecessor.request.paths
                ):
                    raise CanaryExecutionError("Canary rollback action does not exactly reverse its retained predecessor")
                pre_state = self._broker.semantic_pre_readback(
                    decision.authorization, request, predecessor.receipt.receipt_digest,
                )
                disposition = self._policy.rollback.cleanup_disposition(
                    resource_is_reversible=request.operation is inverse,
                    readback_is_unambiguous=type(pre_state) is CanarySemanticReadback and pre_state.state is CanaryReadbackState.APPLIED,
                )
                if disposition.value != "rollback":
                    raise CanaryExecutionError("Canary rollback pre-state is absent or ambiguous")
                predecessor_transition_receipt_digest = predecessor.receipt.receipt_digest
                pre_state_readback_digest = pre_state.digest
            except (AttributeError, TypeError, ValueError, CanaryExecutionError, CanaryPolicyError):
                return CanaryExecutionResult(
                    CanaryDecision(False, "Canary rollback or cleanup requires retained reversible semantic pre-state", decision.policy_digest, "preserve-for-owner"), None, None,
                )
        try:
            record, newly_reserved = self._ledger.reserve(
                decision.authorization, request, purpose,
                predecessor_transition_receipt_digest=predecessor_transition_receipt_digest,
                pre_state_readback_digest=pre_state_readback_digest,
            )
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
        if self._ledger.requires_retry_lease_proof:
            try:
                owns_fence = self._lease.claim(
                    record.authorization.consumption_key, record.authorization.claim_digest,
                )
            except Exception:
                owns_fence = False
            if not owns_fence:
                record = self._ledger.update(record, CanaryTransitionState.PRESERVED_FOR_OWNER)
                return CanaryExecutionResult(
                    CanaryDecision(False, "replacement Orchestrator cannot prove the original retry fence", decision.policy_digest, "preserve-for-owner"),
                    record.receipt, None,
                )
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
        state = (
            CanaryTransitionState.RETRY_ALLOWED
            if allow_retry and not record.retry_used
            else CanaryTransitionState.PRESERVED_FOR_OWNER
        )
        record = self._ledger.update(record, state, readback_digest=readback.digest)
        next_action = "retry-after-semantic-readback" if state is CanaryTransitionState.RETRY_ALLOWED else "preserve-for-owner"
        return CanaryExecutionResult(CanaryDecision(False, "Canary read-back does not prove the requested transition", decision.policy_digest, next_action), record.receipt, None)
