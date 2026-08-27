"""Deterministic fake-adapter qualification for the Canary execution boundary."""

from __future__ import annotations

from dataclasses import replace
import unittest

from roundwright.canary_execution import (
    CanaryDispatchResult, CanaryExecutionLedger, CanaryOrchestrator,
    CanaryReadbackState, CanarySemanticReadback, CanaryTransitionPurpose,
    CanaryTransitionState,
)
from roundwright.canary_policy import (
    BoundedCanaryPolicy, CanaryAuthorityContext, CanaryBudget, CanaryRollbackPlan,
    CanaryMutationRequest, CanaryTarget, FORWARD_TEST_ROUTE,
    canary_target_policy_identity, genesis_canary_receipt,
)
from roundwright.github import GitHubMutationOperation
from roundwright.repository_policy import (
    GITHUB_REPOSITORY_OPERATION, REPOSITORY_OPERATION_SWITCH,
    REPOSITORY_POLICY_SCHEMA_VERSION, RepositoryMutationPolicy, RepositoryPolicySource,
    TrustedRepositoryPolicySnapshot,
)


BASE = "a" * 40
CANDIDATE = "b" * 40
TARGET_BASE = "c" * 40
CONTRACT = "sha256:" + "d" * 64


def target_policy(operations: tuple[GitHubMutationOperation, ...]) -> TrustedRepositoryPolicySnapshot:
    fields: dict[str, object] = {
        "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
        "enabled": True,
        **{switch: False for switch in REPOSITORY_OPERATION_SWITCH.values()},
    }
    for operation in operations:
        fields[REPOSITORY_OPERATION_SWITCH[GITHUB_REPOSITORY_OPERATION[operation]]] = True
    return TrustedRepositoryPolicySnapshot(
        RepositoryPolicySource("1" * 64, "2" * 64), RepositoryMutationPolicy(**fields),  # type: ignore[arg-type]
    )


def policy(*, operations: tuple[GitHubMutationOperation, ...] = (GitHubMutationOperation.CREATE_BRANCH,)) -> BoundedCanaryPolicy:
    target = CanaryTarget("ythdelmar68/roundlet-forward-test", TARGET_BASE, 96)
    selected = target_policy(operations)
    return BoundedCanaryPolicy(
        BASE, CANDIDATE, CONTRACT, 4, 88, target, canary_target_policy_identity(selected, target),
        "roundlet/canary-88", ("canary/probe.txt",), operations,
        CanaryBudget(tuple((operation, 1) for operation in operations), len(operations)),
        CanaryRollbackPlan("semantic-readback-failure", "owner-kill-switch", "read-target-branch"),
    )


def genesis(value: BoundedCanaryPolicy):
    return genesis_canary_receipt(value)


def context(value: BoundedCanaryPolicy, chain):
    selected = target_policy(value.requested_operations)
    return CanaryAuthorityContext(
        True, True, True, value.phase, value.leaf_number, FORWARD_TEST_ROUTE,
        value.base_sha, value.candidate_sha, value.contract_digest, value.target, selected,
        canary_target_policy_identity(selected, value.target), value.policy_digest, value.branch,
        chain[-1].receipt_digest,
    )


class FakeLease:
    def __init__(self, *, claimed: bool = True) -> None:
        self.claimed = claimed
        self.calls: list[tuple[str, str]] = []

    def claim(self, consumption_key: str, claim_digest: str) -> bool:
        self.calls.append((consumption_key, claim_digest))
        return self.claimed


class FakeBroker:
    def __init__(self, *readbacks: CanarySemanticReadback, accepted: bool = True, raises: bool = False) -> None:
        self.readbacks = list(readbacks)
        self.accepted = accepted
        self.raises = raises
        self.dispatches: list[tuple[object, object, object]] = []
        self.reads: list[tuple[object, object]] = []

    def dispatch(self, authorization, request, purpose):
        self.dispatches.append((authorization, request, purpose))
        if self.raises:
            raise TimeoutError("fake transport timeout")
        return CanaryDispatchResult(self.accepted, "fake-transition")

    def semantic_readback(self, authorization, request):
        self.reads.append((authorization, request))
        return self.readbacks.pop(0)


def readback(state: CanaryReadbackState, suffix: str) -> CanarySemanticReadback:
    return CanarySemanticReadback(state, "sha256:" + suffix * 64)


class CanaryExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = policy()
        self.chain = (genesis(self.policy),)
        self.request = CanaryMutationRequest(
            GitHubMutationOperation.CREATE_BRANCH, self.policy.branch, ("canary/probe.txt",),
        )

    def orchestrator(self, broker: FakeBroker, lease: FakeLease | None = None, *, kill: bool = False):
        return CanaryOrchestrator(
            self.policy, replace(context(self.policy, self.chain), kill_switch_active=kill),
            lease or FakeLease(), broker,
        )

    def test_full_sequence_is_brokered_once_and_duplicate_delivery_reuses_receipt(self) -> None:
        broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "f"))
        executor = self.orchestrator(broker)
        first = executor.execute(self.request)
        second = executor.execute(self.request)
        self.assertTrue(first.verified)
        self.assertTrue(second.verified)
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(len(broker.dispatches), 1)
        self.assertEqual(len(broker.reads), 1)
        self.assertEqual(first.receipt.state, CanaryTransitionState.VERIFIED)  # type: ignore[union-attr]
        self.assertEqual(first.canary_receipt.operation_counts[0][1], 1)  # type: ignore[union-attr]
        self.assertTrue(first.receipt.receipt_digest.startswith("sha256:"))  # type: ignore[union-attr]
        self.assertNotIn("canary/probe.txt", str(first.receipt.public_payload()))  # type: ignore[union-attr]

    def test_timeout_and_ambiguous_readback_quarantine_without_retry_dispatch(self) -> None:
        broker = FakeBroker(readback(CanaryReadbackState.AMBIGUOUS, "e"), readback(CanaryReadbackState.AMBIGUOUS, "d"), raises=True)
        executor = self.orchestrator(broker)
        first = executor.execute(self.request)
        self.assertFalse(first.verified)
        self.assertEqual(first.receipt.state, CanaryTransitionState.QUARANTINED)  # type: ignore[union-attr]
        reconciled = executor.reconcile(first.receipt.claim_digest)  # type: ignore[union-attr]
        retried = executor.retry(first.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertEqual(reconciled.receipt.state, CanaryTransitionState.QUARANTINED)  # type: ignore[union-attr]
        self.assertFalse(retried.verified)
        self.assertEqual(len(broker.dispatches), 1)
        self.assertEqual(len(broker.reads), 2)

    def test_absent_readback_permits_one_explicit_retry_then_receipt_advancement(self) -> None:
        broker = FakeBroker(readback(CanaryReadbackState.ABSENT, "c"), readback(CanaryReadbackState.APPLIED, "b"), accepted=False)
        executor = self.orchestrator(broker)
        first = executor.execute(self.request)
        self.assertEqual(first.receipt.state, CanaryTransitionState.RETRY_ALLOWED)  # type: ignore[union-attr]
        retry = executor.retry(first.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertTrue(retry.verified)
        self.assertEqual(len(broker.dispatches), 2)

    def test_kill_switch_budget_drift_and_lease_conflict_prevent_dispatch(self) -> None:
        broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "f"))
        denied = self.orchestrator(broker, kill=True).execute(self.request)
        self.assertFalse(denied.verified)
        self.assertEqual(broker.dispatches, [])
        conflict = self.orchestrator(broker, FakeLease(claimed=False)).execute(self.request)
        self.assertFalse(conflict.verified)
        self.assertEqual(conflict.receipt.state, CanaryTransitionState.PRESERVED_FOR_OWNER)  # type: ignore[union-attr]
        self.assertEqual(broker.dispatches, [])

    def test_rollback_and_cleanup_are_explicit_policy_bound_transitions(self) -> None:
        contract = policy(operations=(GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH))
        start = (genesis(contract),)
        delete = CanaryMutationRequest(GitHubMutationOperation.DELETE_BRANCH, contract.branch, ("canary/probe.txt",))
        broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "a"))
        executor = CanaryOrchestrator(contract, context(contract, start), FakeLease(), broker)
        result = executor.rollback(delete)
        self.assertTrue(result.verified)
        self.assertEqual(broker.dispatches[0][2], CanaryTransitionPurpose.ROLLBACK)

    def test_ledger_rejects_substitution_at_the_same_consumption_fence(self) -> None:
        ledger = CanaryExecutionLedger(self.policy)
        broker = FakeBroker(readback(CanaryReadbackState.AMBIGUOUS, "f"))
        executor = CanaryOrchestrator(self.policy, context(self.policy, (genesis(self.policy),)), FakeLease(), broker, ledger=ledger)
        result = executor.execute(self.request)
        self.assertEqual(result.receipt.state, CanaryTransitionState.QUARANTINED)  # type: ignore[union-attr]
        denied = executor.cleanup(self.request)
        self.assertFalse(denied.verified)
        self.assertEqual(len(broker.dispatches), 1)


if __name__ == "__main__":
    unittest.main()
