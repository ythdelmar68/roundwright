"""Deterministic fake-adapter qualification for the Canary execution boundary."""

from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.canary_execution import (
    CanaryDispatchResult, CanaryExecutionError, CanaryExecutionLedger, CanaryOrchestrator,
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
    def __init__(
        self, *readbacks: CanarySemanticReadback, accepted: bool = True, raises: bool = False,
        pre_readbacks: tuple[CanarySemanticReadback, ...] = (),
    ) -> None:
        self.readbacks = list(readbacks)
        self.pre_readbacks = list(pre_readbacks)
        self.accepted = accepted
        self.raises = raises
        self.dispatches: list[tuple[object, object, object]] = []
        self.reads: list[tuple[object, object]] = []
        self.pre_reads: list[tuple[object, object, object]] = []

    def dispatch(self, authorization, request, purpose):
        self.dispatches.append((authorization, request, purpose))
        if self.raises:
            raise TimeoutError("fake transport timeout")
        return CanaryDispatchResult(self.accepted, "fake-transition")

    def semantic_readback(self, authorization, request):
        self.reads.append((authorization, request))
        return self.readbacks.pop(0)

    def semantic_pre_readback(self, authorization, request, predecessor_receipt_digest):
        self.pre_reads.append((authorization, request, predecessor_receipt_digest))
        return self.pre_readbacks.pop(0)


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

    def test_rollback_and_cleanup_require_reconciled_retained_predecessors(self) -> None:
        contract = policy(operations=(GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH))
        start = (genesis(contract),)
        create = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        delete = CanaryMutationRequest(GitHubMutationOperation.DELETE_BRANCH, contract.branch, ("canary/probe.txt",))
        broker = FakeBroker(
            readback(CanaryReadbackState.APPLIED, "a"), readback(CanaryReadbackState.APPLIED, "b"),
            pre_readbacks=(readback(CanaryReadbackState.APPLIED, "c"),),
        )
        executor = CanaryOrchestrator(contract, context(contract, start), FakeLease(), broker)
        fresh_cleanup = executor.cleanup(delete)
        self.assertFalse(fresh_cleanup.verified)
        self.assertEqual(broker.dispatches, [])
        executed = executor.execute(create)
        self.assertTrue(executed.verified)
        result = executor.rollback(delete)
        self.assertTrue(result.verified)
        self.assertEqual(broker.dispatches[1][2], CanaryTransitionPurpose.ROLLBACK)
        self.assertEqual(len(broker.pre_reads), 1)
        self.assertEqual(result.receipt.predecessor_transition_receipt_digest, executed.receipt.receipt_digest)  # type: ignore[union-attr]
        self.assertEqual(result.receipt.pre_state_readback_digest, readback(CanaryReadbackState.APPLIED, "c").digest)  # type: ignore[union-attr]

        cleanup_broker = FakeBroker(
            readback(CanaryReadbackState.APPLIED, "d"), readback(CanaryReadbackState.APPLIED, "e"),
            pre_readbacks=(readback(CanaryReadbackState.APPLIED, "f"),),
        )
        cleanup_executor = CanaryOrchestrator(contract, context(contract, start), FakeLease(), cleanup_broker)
        self.assertTrue(cleanup_executor.execute(create).verified)
        cleaned = cleanup_executor.cleanup(delete)
        self.assertTrue(cleaned.verified)
        self.assertEqual(cleanup_broker.dispatches[1][2], CanaryTransitionPurpose.CLEANUP)

    def test_rollback_rejects_same_unrelated_and_irreversible_actions_before_dispatch(self) -> None:
        operations = (GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH)
        contract = replace(
            policy(operations=operations),
            budget=CanaryBudget(((GitHubMutationOperation.CREATE_BRANCH, 2), (GitHubMutationOperation.DELETE_BRANCH, 1)), 3),
        )
        start, create = (genesis(contract),), CanaryMutationRequest(
            GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",),
        )
        broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "a"))
        executor = CanaryOrchestrator(contract, context(contract, start), FakeLease(), broker)
        self.assertTrue(executor.execute(create).verified)
        same_action = executor.rollback(create)
        self.assertFalse(same_action.verified)
        self.assertEqual(len(broker.dispatches), 1)
        self.assertEqual(broker.pre_reads, [])

        irreversible = policy(operations=(GitHubMutationOperation.COMMENT, GitHubMutationOperation.DELETE_BRANCH))
        comment = CanaryMutationRequest(GitHubMutationOperation.COMMENT, irreversible.branch, ("canary/probe.txt",))
        delete = CanaryMutationRequest(GitHubMutationOperation.DELETE_BRANCH, irreversible.branch, ("canary/probe.txt",))
        irreversible_broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "b"))
        irreversible_executor = CanaryOrchestrator(
            irreversible, context(irreversible, (genesis(irreversible),)), FakeLease(), irreversible_broker,
        )
        self.assertTrue(irreversible_executor.execute(comment).verified)
        self.assertFalse(irreversible_executor.cleanup(delete).verified)
        self.assertEqual(len(irreversible_broker.dispatches), 1)
        self.assertEqual(irreversible_broker.pre_reads, [])

    def test_ledger_rejects_substitution_at_the_same_consumption_fence(self) -> None:
        ledger = CanaryExecutionLedger(self.policy)
        broker = FakeBroker(readback(CanaryReadbackState.AMBIGUOUS, "f"))
        executor = CanaryOrchestrator(self.policy, context(self.policy, (genesis(self.policy),)), FakeLease(), broker, ledger=ledger)
        result = executor.execute(self.request)
        self.assertEqual(result.receipt.state, CanaryTransitionState.QUARANTINED)  # type: ignore[union-attr]
        denied = executor.cleanup(self.request)
        self.assertFalse(denied.verified)
        self.assertEqual(len(broker.dispatches), 1)

    def test_restart_hydrates_verified_quarantined_retry_and_duplicate_records(self) -> None:
        verified_broker = FakeBroker(readback(CanaryReadbackState.APPLIED, "a"))
        verified_executor = self.orchestrator(verified_broker)
        verified = verified_executor.execute(self.request)
        verified_ledger = CanaryExecutionLedger.hydrate(self.policy, verified_executor.ledger.sealed_state())
        verified_restart = CanaryOrchestrator(
            self.policy, context(self.policy, verified_ledger.chain()), FakeLease(), FakeBroker(), ledger=verified_ledger,
        )
        duplicate = verified_restart.execute(self.request)
        self.assertEqual(duplicate.receipt, verified.receipt)

        quarantined_broker = FakeBroker(readback(CanaryReadbackState.AMBIGUOUS, "b"))
        quarantined_executor = self.orchestrator(quarantined_broker)
        quarantined = quarantined_executor.execute(self.request)
        quarantined_ledger = CanaryExecutionLedger.hydrate(self.policy, quarantined_executor.ledger.sealed_state())
        quarantined_restart = CanaryOrchestrator(
            self.policy, context(self.policy, quarantined_ledger.chain()), FakeLease(),
            FakeBroker(readback(CanaryReadbackState.APPLIED, "c")), ledger=quarantined_ledger,
        )
        reconciled = quarantined_restart.reconcile(quarantined.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertTrue(reconciled.verified)

        retry_broker = FakeBroker(readback(CanaryReadbackState.ABSENT, "d"), accepted=False)
        retry_executor = self.orchestrator(retry_broker)
        retry_ready = retry_executor.execute(self.request)
        retry_ledger = CanaryExecutionLedger.hydrate(self.policy, retry_executor.ledger.sealed_state())
        retry_restart = CanaryOrchestrator(
            self.policy, context(self.policy, retry_ledger.chain()), FakeLease(),
            FakeBroker(readback(CanaryReadbackState.APPLIED, "e")), ledger=retry_ledger,
        )
        retried = retry_restart.retry(retry_ready.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertTrue(retried.verified)

    def test_hydration_requires_exact_receipt_record_bijection_and_nested_counts(self) -> None:
        executor = self.orchestrator(FakeBroker(readback(CanaryReadbackState.APPLIED, "a")))
        self.assertTrue(executor.execute(self.request).verified)
        state = executor.ledger.sealed_state()
        missing = copy.deepcopy(state)
        missing["records"] = []
        unknown_count = copy.deepcopy(state)
        unknown_count["chain"][1]["operation_counts"]["unknown-operation"] = 0
        duplicate_record = copy.deepcopy(state)
        duplicate_record["records"].append(copy.deepcopy(duplicate_record["records"][0]))
        for mutated in (missing, unknown_count, duplicate_record):
            with self.subTest(mutated=mutated):
                with self.assertRaises(CanaryExecutionError):
                    CanaryExecutionLedger.hydrate(self.policy, mutated)

    def test_absent_after_consumed_retry_is_preserved_for_owner(self) -> None:
        broker = FakeBroker(
            readback(CanaryReadbackState.ABSENT, "a"), readback(CanaryReadbackState.ABSENT, "b"),
            accepted=False,
        )
        executor = self.orchestrator(broker)
        initial = executor.execute(self.request)
        exhausted = executor.retry(initial.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertEqual(exhausted.receipt.state, CanaryTransitionState.PRESERVED_FOR_OWNER)  # type: ignore[union-attr]
        self.assertEqual(exhausted.decision.next_action, "preserve-for-owner")
        repeated = executor.retry(initial.receipt.claim_digest)  # type: ignore[union-attr]
        self.assertFalse(repeated.verified)
        self.assertEqual(len(broker.dispatches), 2)


if __name__ == "__main__":
    unittest.main()
