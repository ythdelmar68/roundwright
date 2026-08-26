"""Fail-closed, mutation-free policy contract for a bounded Phase 4 Canary.

This module deliberately describes an authorization boundary only.  It does not
open a network connection, load credentials, call GitHub, or execute rollback.
The later execution leaf must present the exact contract and consume the
decision/receipt types defined here.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Mapping

from .github import GitHubMutationOperation


CANARY_POLICY_SCHEMA = "roundwright-bounded-canary-policy/v1"
CANARY_RECEIPT_SCHEMA = "roundwright-bounded-canary-receipt/v1"
PHASE_4 = 4
FORWARD_TEST_ROUTE = "harness+forward-test"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,38}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")


class CanaryPolicyError(ValueError):
    """Raised when a Canary policy could widen or lose an exact binding."""


class CanaryResult(StrEnum):
    GENESIS = "genesis"
    PASS = "pass"
    DENIED = "denied"
    ROLLED_BACK = "rolled-back"
    OWNER_INPUT_REQUIRED = "owner-input-required"


class CleanupDisposition(StrEnum):
    ROLLBACK = "rollback"
    PRESERVE_FOR_OWNER = "preserve-for-owner"


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _require_sha(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise CanaryPolicyError(f"{name} must be an exact commit SHA")


def _require_digest(value: object, name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise CanaryPolicyError(f"{name} must be a SHA-256 digest")


def _safe_path(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and not value.startswith(("/", "\\"))
        and "\\" not in value
        and ":" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


@dataclass(frozen=True, slots=True)
class CanaryTarget:
    """One controlled target pinned to its baseline, never a floating ref."""

    repository: str
    baseline_sha: str
    leaf_number: int

    def __post_init__(self) -> None:
        if type(self.repository) is not str or _SLUG.fullmatch(self.repository) is None:
            raise CanaryPolicyError("Canary target repository is invalid")
        _require_sha(self.baseline_sha, "Canary target baseline")
        if type(self.leaf_number) is not int or self.leaf_number <= 0:
            raise CanaryPolicyError("Canary target leaf is invalid")


@dataclass(frozen=True, slots=True)
class CanaryBudget:
    """Exact per-operation and total call ceilings for one selected contract."""

    per_operation: tuple[tuple[GitHubMutationOperation, int], ...]
    total_calls: int

    def __post_init__(self) -> None:
        if type(self.per_operation) is not tuple or type(self.total_calls) is not int or self.total_calls < 1:
            raise CanaryPolicyError("Canary call budget is invalid")
        operations = tuple(item[0] for item in self.per_operation if type(item) is tuple and len(item) == 2)
        if len(operations) != len(self.per_operation) or len(set(operations)) != len(operations):
            raise CanaryPolicyError("Canary call budget has duplicate or invalid operations")
        if not all(type(operation) is GitHubMutationOperation and type(count) is int and count > 0 for operation, count in self.per_operation):
            raise CanaryPolicyError("Canary call budget is invalid")
        if sum(count for _, count in self.per_operation) < self.total_calls:
            raise CanaryPolicyError("Canary total budget exceeds per-operation budgets")

    def limit_for(self, operation: GitHubMutationOperation) -> int:
        if type(operation) is not GitHubMutationOperation:
            raise CanaryPolicyError("Canary operation is invalid")
        return dict(self.per_operation).get(operation, 0)


@dataclass(frozen=True, slots=True)
class CanaryRollbackPlan:
    """Typed stop and preservation rules; execution remains outside this leaf."""

    rollback_trigger: str
    kill_switch: str
    semantic_readback: str

    def __post_init__(self) -> None:
        for value, name in ((self.rollback_trigger, "rollback trigger"), (self.kill_switch, "kill switch"), (self.semantic_readback, "semantic read-back")):
            if type(value) is not str or not value or len(value) > 160:
                raise CanaryPolicyError(f"Canary {name} is invalid")

    def cleanup_disposition(self, *, resource_is_reversible: bool, readback_is_unambiguous: bool) -> CleanupDisposition:
        if type(resource_is_reversible) is not bool or type(readback_is_unambiguous) is not bool:
            raise CanaryPolicyError("Canary cleanup evidence is invalid")
        return CleanupDisposition.ROLLBACK if resource_is_reversible and readback_is_unambiguous else CleanupDisposition.PRESERVE_FOR_OWNER


@dataclass(frozen=True, slots=True)
class BoundedCanaryPolicy:
    """The complete versioned policy that a later mutator must not broaden."""

    base_sha: str
    candidate_sha: str
    contract_digest: str
    phase: int
    leaf_number: int
    target: CanaryTarget
    branch: str
    allowed_paths: tuple[str, ...]
    requested_operations: tuple[GitHubMutationOperation, ...]
    budget: CanaryBudget
    rollback: CanaryRollbackPlan
    schema: str = CANARY_POLICY_SCHEMA
    policy_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _require_sha(self.base_sha, "Canary base")
        _require_sha(self.candidate_sha, "Canary candidate")
        _require_digest(self.contract_digest, "Canary contract")
        if self.base_sha == self.candidate_sha:
            raise CanaryPolicyError("Canary candidate must differ from its base")
        if type(self.phase) is not int or self.phase != PHASE_4 or type(self.leaf_number) is not int or self.leaf_number <= 0:
            raise CanaryPolicyError("Canary phase or leaf is invalid")
        if type(self.target) is not CanaryTarget or type(self.budget) is not CanaryBudget or type(self.rollback) is not CanaryRollbackPlan:
            raise CanaryPolicyError("Canary policy component is invalid")
        if type(self.branch) is not str or _BRANCH.fullmatch(self.branch) is None or self.branch.startswith(("refs/", "/")) or "//" in self.branch:
            raise CanaryPolicyError("Canary branch is invalid")
        if type(self.allowed_paths) is not tuple or not self.allowed_paths or len(set(self.allowed_paths)) != len(self.allowed_paths) or not all(_safe_path(path) for path in self.allowed_paths):
            raise CanaryPolicyError("Canary path allowlist is invalid")
        if type(self.requested_operations) is not tuple or not self.requested_operations or len(set(self.requested_operations)) != len(self.requested_operations) or not all(type(operation) is GitHubMutationOperation for operation in self.requested_operations):
            raise CanaryPolicyError("Canary operation vocabulary is invalid")
        if set(operation for operation, _ in self.budget.per_operation) != set(self.requested_operations):
            raise CanaryPolicyError("Canary budget does not bind exactly the requested operations")
        if self.schema != CANARY_POLICY_SCHEMA:
            raise CanaryPolicyError("Canary policy schema is unsupported")
        object.__setattr__(self, "policy_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": self.schema, "base_sha": self.base_sha, "candidate_sha": self.candidate_sha,
            "contract_digest": self.contract_digest,
            "phase": self.phase, "leaf_number": self.leaf_number,
            "target": {"repository": self.target.repository, "baseline_sha": self.target.baseline_sha, "leaf_number": self.target.leaf_number},
            "branch": self.branch, "allowed_paths": list(self.allowed_paths),
            "requested_operations": [operation.value for operation in self.requested_operations],
            "budget": {"per_operation": {operation.value: count for operation, count in self.budget.per_operation}, "total_calls": self.budget.total_calls},
            "rollback": {"rollback_trigger": self.rollback.rollback_trigger, "kill_switch": self.rollback.kill_switch, "semantic_readback": self.rollback.semantic_readback},
        }
        return value | ({"policy_digest": self.policy_digest} if include_digest else {})

    def validate(self) -> None:
        rebuilt = replace(self)
        if rebuilt.policy_digest != self.policy_digest:
            raise CanaryPolicyError("Canary policy has drifted")


@dataclass(frozen=True, slots=True)
class CanaryAuthorityContext:
    """Independent selection and standing-authority read-back for one call."""

    roundlet_enabled: bool
    read_only_external_validation_allowed: bool
    disposable_target_mutation_allowed: bool
    phase: int
    leaf_number: int
    route: str
    base_sha: str
    candidate_sha: str
    contract_digest: str
    target: CanaryTarget
    policy_digest: str
    branch: str
    prior_receipt_digest: str | None = None
    kill_switch_active: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.roundlet_enabled) is not bool
            or type(self.read_only_external_validation_allowed) is not bool
            or type(self.disposable_target_mutation_allowed) is not bool
            or type(self.kill_switch_active) is not bool
        ):
            raise CanaryPolicyError("Canary standing authority is invalid")
        if type(self.phase) is not int or type(self.leaf_number) is not int or self.route != FORWARD_TEST_ROUTE:
            raise CanaryPolicyError("Canary selection route is invalid")
        _require_sha(self.base_sha, "selected base")
        _require_sha(self.candidate_sha, "selected candidate")
        _require_digest(self.contract_digest, "selected contract")
        if type(self.target) is not CanaryTarget:
            raise CanaryPolicyError("selected Canary target is invalid")
        _require_digest(self.policy_digest, "selected policy")
        if type(self.branch) is not str or _BRANCH.fullmatch(self.branch) is None:
            raise CanaryPolicyError("selected Canary branch is invalid")
        if self.prior_receipt_digest is not None:
            _require_digest(self.prior_receipt_digest, "selected prior receipt")


@dataclass(frozen=True, slots=True)
class CanaryDecision:
    authorized: bool
    reason: str
    policy_digest: str | None
    next_action: str


def evaluate_bounded_canary_policy(policy: BoundedCanaryPolicy | None, context: CanaryAuthorityContext | None) -> CanaryDecision:
    """Return a fail-closed decision without executing or scheduling a mutation."""

    if type(policy) is not BoundedCanaryPolicy or type(context) is not CanaryAuthorityContext:
        return CanaryDecision(False, "Canary policy or authority context is unavailable", None, "preserve-for-owner")
    try:
        policy.validate()
    except CanaryPolicyError:
        return CanaryDecision(False, "Canary policy has drifted", policy.policy_digest, "preserve-for-owner")
    if (
        not context.roundlet_enabled
        or not context.read_only_external_validation_allowed
        or not context.disposable_target_mutation_allowed
    ):
        return CanaryDecision(False, "standing Canary authority is disabled", policy.policy_digest, "preserve-for-owner")
    if context.kill_switch_active:
        return CanaryDecision(False, "Canary kill switch is active", policy.policy_digest, "preserve-for-owner")
    if (context.phase, context.leaf_number, context.base_sha, context.candidate_sha, context.contract_digest, context.target, context.policy_digest, context.branch) != (policy.phase, policy.leaf_number, policy.base_sha, policy.candidate_sha, policy.contract_digest, policy.target, policy.policy_digest, policy.branch):
        return CanaryDecision(False, "Canary identity or policy binding is stale", policy.policy_digest, "preserve-for-owner")
    return CanaryDecision(True, "exact bounded Canary policy is authorized", policy.policy_digest, "execute-through-mutation-broker")


@dataclass(frozen=True, slots=True)
class CanaryMutationRequest:
    """One broker input, checked before every future external mutation."""

    operation: GitHubMutationOperation
    branch: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.operation) is not GitHubMutationOperation or type(self.branch) is not str or _BRANCH.fullmatch(self.branch) is None:
            raise CanaryPolicyError("Canary request operation or branch is invalid")
        if type(self.paths) is not tuple or not self.paths or not all(_safe_path(path) for path in self.paths):
            raise CanaryPolicyError("Canary request paths are invalid")
def authorize_canary_request(
    policy: BoundedCanaryPolicy | None,
    context: CanaryAuthorityContext | None,
    request: CanaryMutationRequest | None,
    receipt_chain: tuple[BoundedCanaryReceipt, ...] | None,
) -> CanaryDecision:
    """Enforce scope and derive every call count from a validated receipt chain."""

    decision = evaluate_bounded_canary_policy(policy, context)
    if not decision.authorized or type(policy) is not BoundedCanaryPolicy or type(request) is not CanaryMutationRequest:
        return CanaryDecision(False, decision.reason if not decision.authorized else "Canary request is unavailable", decision.policy_digest, "preserve-for-owner")
    if request.operation not in policy.requested_operations:
        return CanaryDecision(False, "Canary operation is outside the selected vocabulary", policy.policy_digest, "preserve-for-owner")
    if request.branch != policy.branch:
        return CanaryDecision(False, "Canary branch is outside the selected allowlist", policy.policy_digest, "preserve-for-owner")
    if any(path not in policy.allowed_paths for path in request.paths):
        return CanaryDecision(False, "Canary path is outside the selected allowlist", policy.policy_digest, "preserve-for-owner")
    if context.prior_receipt_digest is None or type(receipt_chain) is not tuple:
        return CanaryDecision(False, "Canary receipt-chain state is unavailable", policy.policy_digest, "preserve-for-owner")
    try:
        prior_receipt = validate_canary_receipt_chain(policy, receipt_chain)
    except CanaryPolicyError:
        return CanaryDecision(False, "Canary receipt-chain state is invalid or stale", policy.policy_digest, "preserve-for-owner")
    if prior_receipt.receipt_digest != context.prior_receipt_digest:
        return CanaryDecision(False, "Canary receipt-chain head conflicts with selection state", policy.policy_digest, "preserve-for-owner")
    counts = dict(prior_receipt.operation_counts)
    prior_operation_calls = counts[request.operation]
    prior_total_calls = sum(counts.values())
    if prior_operation_calls >= policy.budget.limit_for(request.operation) or prior_total_calls >= policy.budget.total_calls:
        return CanaryDecision(False, "Canary call budget is exhausted", policy.policy_digest, "preserve-for-owner")
    return decision


@dataclass(frozen=True, slots=True)
class BoundedCanaryReceipt:
    """Public-safe proof projection, deliberately excluding paths and raw output."""

    policy: BoundedCanaryPolicy
    result: CanaryResult
    operation_counts: tuple[tuple[GitHubMutationOperation, int], ...]
    semantic_readback_digest: str
    predecessor_receipt_digest: str | None = None
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.policy) is not BoundedCanaryPolicy or type(self.result) is not CanaryResult:
            raise CanaryPolicyError("Canary receipt is invalid")
        self.policy.validate()
        if type(self.operation_counts) is not tuple or len(set(operation for operation, _ in self.operation_counts)) != len(self.operation_counts):
            raise CanaryPolicyError("Canary receipt operation counts are invalid")
        counts = dict(self.operation_counts)
        if not all(type(operation) is GitHubMutationOperation and type(count) is int and count >= 0 for operation, count in self.operation_counts):
            raise CanaryPolicyError("Canary receipt operation counts are invalid")
        if set(counts) != set(self.policy.requested_operations) or sum(counts.values()) > self.policy.budget.total_calls or any(count > self.policy.budget.limit_for(operation) for operation, count in counts.items()):
            raise CanaryPolicyError("Canary receipt exceeds its budget")
        _require_digest(self.semantic_readback_digest, "semantic read-back")
        if self.predecessor_receipt_digest is not None:
            _require_digest(self.predecessor_receipt_digest, "receipt predecessor")
        if self.result is CanaryResult.GENESIS:
            if self.predecessor_receipt_digest is not None or any(counts.values()):
                raise CanaryPolicyError("Canary genesis receipt is invalid")
        elif self.predecessor_receipt_digest is None:
            raise CanaryPolicyError("Canary non-genesis receipt has no predecessor")
        object.__setattr__(self, "receipt_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": CANARY_RECEIPT_SCHEMA, "policy_digest": self.policy.policy_digest,
            "contract_digest": self.policy.contract_digest, "base_sha": self.policy.base_sha, "candidate_sha": self.policy.candidate_sha,
            "target_repository": self.policy.target.repository, "target_baseline_sha": self.policy.target.baseline_sha,
            "target_leaf_number": self.policy.target.leaf_number, "leaf_number": self.policy.leaf_number,
            "requested_operations": [operation.value for operation in self.policy.requested_operations],
            "operation_counts": {operation.value: count for operation, count in self.operation_counts},
            "total_calls": sum(count for _, count in self.operation_counts), "result": self.result.value,
            "semantic_readback_digest": self.semantic_readback_digest, "predecessor_receipt_digest": self.predecessor_receipt_digest,
        }
        return value | ({"receipt_digest": self.receipt_digest} if include_digest else {})

    def validate_for(self, policy: BoundedCanaryPolicy) -> None:
        if type(policy) is not BoundedCanaryPolicy:
            raise CanaryPolicyError("Canary receipt policy is invalid")
        rebuilt = replace(self)
        if policy.policy_digest != self.policy.policy_digest or rebuilt.receipt_digest != self.receipt_digest:
            raise CanaryPolicyError("Canary receipt has drifted")


def genesis_canary_receipt(policy: BoundedCanaryPolicy, semantic_readback_digest: str) -> BoundedCanaryReceipt:
    """Create the one explicit zero-count receipt that starts a Canary chain."""

    if type(policy) is not BoundedCanaryPolicy:
        raise CanaryPolicyError("Canary genesis policy is invalid")
    return BoundedCanaryReceipt(
        policy, CanaryResult.GENESIS,
        tuple((operation, 0) for operation in policy.requested_operations),
        semantic_readback_digest,
    )


def advance_canary_receipt(
    predecessor: BoundedCanaryReceipt, operation: GitHubMutationOperation, semantic_readback_digest: str,
) -> BoundedCanaryReceipt:
    """Represent exactly one successful broker action after its semantic read-back."""

    if type(predecessor) is not BoundedCanaryReceipt or type(operation) is not GitHubMutationOperation:
        raise CanaryPolicyError("Canary receipt advancement is invalid")
    predecessor.validate_for(predecessor.policy)
    if predecessor.result not in {CanaryResult.GENESIS, CanaryResult.PASS} or operation not in predecessor.policy.requested_operations:
        raise CanaryPolicyError("Canary receipt advancement is not permitted")
    counts = dict(predecessor.operation_counts)
    if counts[operation] >= predecessor.policy.budget.limit_for(operation) or sum(counts.values()) >= predecessor.policy.budget.total_calls:
        raise CanaryPolicyError("Canary receipt advancement exceeds budget")
    counts[operation] += 1
    return BoundedCanaryReceipt(
        predecessor.policy, CanaryResult.PASS, tuple(counts.items()), semantic_readback_digest,
        predecessor.receipt_digest,
    )


def validate_canary_receipt_chain(
    policy: BoundedCanaryPolicy, receipt_chain: tuple[BoundedCanaryReceipt, ...],
) -> BoundedCanaryReceipt:
    """Require a monotonic genesis-to-head chain before every broker authorization."""

    if type(policy) is not BoundedCanaryPolicy or type(receipt_chain) is not tuple or not receipt_chain:
        raise CanaryPolicyError("Canary receipt chain is unavailable")
    previous: BoundedCanaryReceipt | None = None
    for receipt in receipt_chain:
        if type(receipt) is not BoundedCanaryReceipt:
            raise CanaryPolicyError("Canary receipt chain is invalid")
        receipt.validate_for(policy)
        counts = dict(receipt.operation_counts)
        if previous is None:
            if receipt.result is not CanaryResult.GENESIS or receipt.predecessor_receipt_digest is not None or any(counts.values()):
                raise CanaryPolicyError("Canary receipt chain has no genesis")
        else:
            previous_counts = dict(previous.operation_counts)
            differences = [counts[operation] - previous_counts[operation] for operation in policy.requested_operations]
            if (
                receipt.result is not CanaryResult.PASS
                or receipt.predecessor_receipt_digest != previous.receipt_digest
                or any(difference < 0 for difference in differences)
                or sum(differences) != 1
                or differences.count(1) != 1
            ):
                raise CanaryPolicyError("Canary receipt chain is not monotonic")
        previous = receipt
    assert previous is not None
    return previous


def parse_bounded_canary_policy(contents: bytes | str) -> BoundedCanaryPolicy:
    """Parse one exact JSON schema and reject duplicates or extra fields."""

    try:
        raw = json.loads(contents, object_pairs_hook=_reject_duplicates)
        required = {"schema", "base_sha", "candidate_sha", "contract_digest", "phase", "leaf_number", "target", "branch", "allowed_paths", "requested_operations", "budget", "rollback"}
        if type(raw) is not dict or set(raw) != required or type(raw["target"]) is not dict or set(raw["target"]) != {"repository", "baseline_sha", "leaf_number"} or type(raw["budget"]) is not dict or set(raw["budget"]) != {"per_operation", "total_calls"} or type(raw["budget"]["per_operation"]) is not dict or type(raw["rollback"]) is not dict or set(raw["rollback"]) != {"rollback_trigger", "kill_switch", "semantic_readback"} or type(raw["allowed_paths"]) is not list or any(type(path) is not str for path in raw["allowed_paths"]):
            raise ValueError
        operations = raw["requested_operations"]
        if type(operations) is not list or any(type(value) is not str for value in operations):
            raise ValueError
        typed_operations = tuple(GitHubMutationOperation(value) for value in operations)
        budget = CanaryBudget(tuple((GitHubMutationOperation(name), count) for name, count in raw["budget"]["per_operation"].items()), raw["budget"]["total_calls"])
        return BoundedCanaryPolicy(raw["base_sha"], raw["candidate_sha"], raw["contract_digest"], raw["phase"], raw["leaf_number"], CanaryTarget(**raw["target"]), raw["branch"], tuple(raw["allowed_paths"]), typed_operations, budget, CanaryRollbackPlan(**raw["rollback"]), raw["schema"])
    except (KeyError, TypeError, ValueError, CanaryPolicyError) as error:
        raise CanaryPolicyError("bounded Canary policy document is malformed") from error


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanaryPolicyError("bounded Canary policy contains duplicate keys")
        result[key] = value
    return result
