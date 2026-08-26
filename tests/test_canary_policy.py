"""Hermetic adversarial coverage for the bounded Phase 4 Canary policy."""

from __future__ import annotations

import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.canary_policy import (
    BoundedCanaryPolicy, BoundedCanaryReceipt, CanaryAuthorityContext, CanaryBudget,
    CanaryMutationRequest, CanaryPolicyError, CanaryResult, CanaryRollbackPlan,
    CanaryTarget, CleanupDisposition, FORWARD_TEST_ROUTE, advance_canary_receipt,
    authorize_canary_request, evaluate_bounded_canary_policy, genesis_canary_receipt,
    parse_bounded_canary_policy, validate_canary_receipt_chain,
)
from roundwright.github import GitHubMutationOperation


BASE = "a" * 40
CANDIDATE = "b" * 40
TARGET_BASE = "c" * 40
CONTRACT = "sha256:" + "d" * 64
DIGEST = "sha256:" + "e" * 64


def policy() -> BoundedCanaryPolicy:
    operations = (GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH)
    return BoundedCanaryPolicy(
        BASE, CANDIDATE, CONTRACT, 4, 87,
        CanaryTarget("ythdelmar68/roundlet-forward-test", TARGET_BASE, 96),
        "roundlet/canary-87", ("canary/probe.txt",), operations,
        CanaryBudget(((operations[0], 1), (operations[1], 1)), 2),
        CanaryRollbackPlan("semantic-readback-failure", "owner-kill-switch", "read-target-branch"),
    )


def genesis(value: BoundedCanaryPolicy) -> BoundedCanaryReceipt:
    return genesis_canary_receipt(value, DIGEST)


def context(value: BoundedCanaryPolicy, chain: tuple[BoundedCanaryReceipt, ...] | None = None) -> CanaryAuthorityContext:
    return CanaryAuthorityContext(
        True, True, True, value.phase, value.leaf_number, FORWARD_TEST_ROUTE,
        value.base_sha, value.candidate_sha, value.contract_digest, value.target,
        value.policy_digest, value.branch, chain[-1].receipt_digest if chain else None,
    )


class BoundedCanaryPolicyTests(unittest.TestCase):
    def test_genesis_binds_initial_authorization_and_public_receipt_is_path_free(self) -> None:
        contract = policy()
        initial = genesis(contract)
        chain = (initial,)
        request = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        self.assertTrue(authorize_canary_request(contract, context(contract, chain), request, chain).authorized)
        receipt = advance_canary_receipt(initial, request.operation, "sha256:" + "f" * 64)
        payload = receipt.public_payload()
        self.assertEqual(payload["schema"], "roundwright-bounded-canary-receipt/v1")
        self.assertEqual(payload["contract_digest"], CONTRACT)
        self.assertNotIn("allowed_paths", payload)
        self.assertNotIn("branch", payload)
        self.assertNotIn("canary/probe.txt", json.dumps(payload))
        self.assertIs(validate_canary_receipt_chain(contract, (initial, receipt)), receipt)

    def test_missing_authority_kill_switch_and_all_identity_drift_deny(self) -> None:
        contract = policy()
        chain = (genesis(contract),)
        cases = (
            replace(context(contract, chain), roundlet_enabled=False),
            replace(context(contract, chain), read_only_external_validation_allowed=False),
            replace(context(contract, chain), disposable_target_mutation_allowed=False),
            replace(context(contract, chain), kill_switch_active=True),
            replace(context(contract, chain), phase=3),
            replace(context(contract, chain), leaf_number=88),
            replace(context(contract, chain), base_sha="f" * 40),
            replace(context(contract, chain), candidate_sha="f" * 40),
            replace(context(contract, chain), contract_digest="sha256:" + "f" * 64),
            replace(context(contract, chain), target=CanaryTarget("ythdelmar68/another-target", TARGET_BASE, 96)),
            replace(context(contract, chain), policy_digest="sha256:" + "f" * 64),
            replace(context(contract, chain), branch="roundlet/wrong-branch"),
        )
        for item in cases:
            with self.subTest(item=item):
                self.assertFalse(evaluate_bounded_canary_policy(contract, item).authorized)

    def test_rejects_floating_identity_path_escape_duplicates_and_budget_broadening(self) -> None:
        operation = GitHubMutationOperation.CREATE_BRANCH
        with self.assertRaises(CanaryPolicyError):
            CanaryTarget("ythdelmar68/roundlet-forward-test", "main", 96)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, CONTRACT, 4, 87, policy().target, "roundlet/canary", ("../escape",), (operation,), CanaryBudget(((operation, 1),), 1), policy().rollback)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, CONTRACT, 4, 87, policy().target, "roundlet/canary", ("one", "one"), (operation,), CanaryBudget(((operation, 1),), 1), policy().rollback)
        with self.assertRaises(CanaryPolicyError):
            CanaryBudget(((operation, 1),), 2)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, CONTRACT, 4, 87, policy().target, "roundlet/canary", ("one",), (operation, operation), CanaryBudget(((operation, 1),), 1), policy().rollback)

    def test_receipt_rejects_budget_exhaustion_and_preserves_ambiguous_resources(self) -> None:
        contract = policy()
        initial = genesis(contract)
        with self.assertRaises(CanaryPolicyError):
            advance_canary_receipt(advance_canary_receipt(initial, GitHubMutationOperation.CREATE_BRANCH, DIGEST), GitHubMutationOperation.CREATE_BRANCH, DIGEST)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=True, readback_is_unambiguous=True), CleanupDisposition.ROLLBACK)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=True, readback_is_unambiguous=False), CleanupDisposition.PRESERVE_FOR_OWNER)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=False, readback_is_unambiguous=True), CleanupDisposition.PRESERVE_FOR_OWNER)

    def test_each_broker_request_requires_exact_branch_path_operation_and_chain_budget(self) -> None:
        contract = policy()
        initial = genesis(contract)
        chain = (initial,)
        exact = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        self.assertTrue(authorize_canary_request(contract, context(contract, chain), exact, chain).authorized)
        invalid = (
            replace(exact, operation=GitHubMutationOperation.MARK_READY),
            replace(exact, branch="roundlet/wrong-branch"),
            replace(exact, paths=("canary/other.txt",)),
        )
        for request in invalid:
            with self.subTest(request=request):
                self.assertFalse(authorize_canary_request(contract, context(contract, chain), request, chain).authorized)
        advanced = advance_canary_receipt(initial, exact.operation, DIGEST)
        advanced_chain = (initial, advanced)
        self.assertFalse(authorize_canary_request(contract, context(contract, advanced_chain), exact, advanced_chain).authorized)

    def test_none_empty_and_repeated_fresh_contexts_cannot_reset_the_chain(self) -> None:
        contract = policy()
        request = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        for chain in (None, ()):
            with self.subTest(chain=chain):
                self.assertFalse(authorize_canary_request(contract, context(contract), request, chain).authorized)
                self.assertFalse(authorize_canary_request(contract, context(contract), request, chain).authorized)
        initial = genesis(contract)
        self.assertFalse(authorize_canary_request(contract, context(contract), request, (initial,)).authorized)

    def test_chain_rejects_stale_wrong_contract_wrong_candidate_and_mismatched_predecessor(self) -> None:
        contract = policy()
        initial = genesis(contract)
        request = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        object.__setattr__(initial, "semantic_readback_digest", "sha256:" + "f" * 64)
        self.assertFalse(authorize_canary_request(contract, context(contract, (initial,)), request, (initial,)).authorized)
        wrong_policies = (
            BoundedCanaryPolicy(
                BASE, "f" * 40, CONTRACT, 4, 87, contract.target, contract.branch,
                contract.allowed_paths, contract.requested_operations, contract.budget, contract.rollback,
            ),
            BoundedCanaryPolicy(
                BASE, CANDIDATE, "sha256:" + "f" * 64, 4, 87, contract.target, contract.branch,
                contract.allowed_paths, contract.requested_operations, contract.budget, contract.rollback,
            ),
        )
        for other in wrong_policies:
            with self.subTest(other=other):
                wrong = genesis(other)
                self.assertFalse(authorize_canary_request(contract, replace(context(contract), prior_receipt_digest=wrong.receipt_digest), request, (wrong,)).authorized)
        clean_initial = genesis(contract)
        mismatch = BoundedCanaryReceipt(
            contract, CanaryResult.PASS,
            ((GitHubMutationOperation.CREATE_BRANCH, 1), (GitHubMutationOperation.DELETE_BRANCH, 0)),
            DIGEST, "sha256:" + "f" * 64,
        )
        self.assertFalse(authorize_canary_request(contract, replace(context(contract), prior_receipt_digest=mismatch.receipt_digest), request, (clean_initial, mismatch)).authorized)

    def test_chain_requires_one_monotonic_operation_per_receipt(self) -> None:
        contract = policy()
        initial = genesis(contract)
        invalid = BoundedCanaryReceipt(
            contract, CanaryResult.PASS,
            ((GitHubMutationOperation.CREATE_BRANCH, 1), (GitHubMutationOperation.DELETE_BRANCH, 1)),
            DIGEST, initial.receipt_digest,
        )
        with self.assertRaises(CanaryPolicyError):
            validate_canary_receipt_chain(contract, (initial, invalid))

    def test_parser_rejects_unknown_duplicate_and_non_array_paths(self) -> None:
        contract = policy()
        raw = contract.public_payload(include_digest=False)
        parsed = parse_bounded_canary_policy(json.dumps(raw))
        self.assertEqual(parsed.policy_digest, contract.policy_digest)
        raw["requested_operations"] = ["create-branch", "create-branch"]
        with self.assertRaises(CanaryPolicyError):
            parse_bounded_canary_policy(json.dumps(raw))
        raw = contract.public_payload(include_digest=False)
        raw["unknown"] = False
        with self.assertRaises(CanaryPolicyError):
            parse_bounded_canary_policy(json.dumps(raw))
        duplicate = '{"schema":"roundwright-bounded-canary-policy/v1","schema":"roundwright-bounded-canary-policy/v1"}'
        with self.assertRaises(CanaryPolicyError):
            parse_bounded_canary_policy(duplicate)
        for value in ("ab", {"canary/probe.txt": True}, None):
            with self.subTest(value=value):
                raw = contract.public_payload(include_digest=False)
                raw["allowed_paths"] = value
                with self.assertRaises(CanaryPolicyError):
                    parse_bounded_canary_policy(json.dumps(raw))


if __name__ == "__main__":
    unittest.main()
