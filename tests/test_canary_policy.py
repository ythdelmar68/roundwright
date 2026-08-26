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
    CanaryMutationRequest,
    CanaryPolicyError, CanaryResult, CanaryRollbackPlan, CanaryTarget,
    CleanupDisposition, FORWARD_TEST_ROUTE, authorize_canary_request, evaluate_bounded_canary_policy,
    parse_bounded_canary_policy,
)
from roundwright.github import GitHubMutationOperation


BASE = "a" * 40
CANDIDATE = "b" * 40
TARGET_BASE = "c" * 40
DIGEST = "sha256:" + "d" * 64


def policy() -> BoundedCanaryPolicy:
    operations = (GitHubMutationOperation.CREATE_BRANCH, GitHubMutationOperation.DELETE_BRANCH)
    return BoundedCanaryPolicy(
        BASE, CANDIDATE, 4, 87, CanaryTarget("ythdelmar68/roundlet-forward-test", TARGET_BASE, 96),
        "roundlet/canary-87", ("canary/probe.txt",), operations,
        CanaryBudget(((operations[0], 1), (operations[1], 1)), 2),
        CanaryRollbackPlan("semantic-readback-failure", "owner-kill-switch", "read-target-branch"),
    )


def context(value: BoundedCanaryPolicy, *, prior_receipt: BoundedCanaryReceipt | None = None) -> CanaryAuthorityContext:
    return CanaryAuthorityContext(True, True, True, value.phase, value.leaf_number, FORWARD_TEST_ROUTE, value.base_sha, value.candidate_sha, value.target, value.policy_digest, value.branch, prior_receipt.receipt_digest if prior_receipt is not None else None)


class BoundedCanaryPolicyTests(unittest.TestCase):
    def test_exact_contract_authorizes_and_public_receipt_is_path_free(self) -> None:
        contract = policy()
        decision = evaluate_bounded_canary_policy(contract, context(contract))
        self.assertTrue(decision.authorized)
        receipt = BoundedCanaryReceipt(contract, CanaryResult.PASS, ((GitHubMutationOperation.CREATE_BRANCH, 1), (GitHubMutationOperation.DELETE_BRANCH, 1)), DIGEST)
        payload = receipt.public_payload()
        self.assertEqual(payload["schema"], "roundwright-bounded-canary-receipt/v1")
        self.assertNotIn("allowed_paths", payload)
        self.assertNotIn("branch", payload)
        self.assertNotIn("canary/probe.txt", json.dumps(payload))
        receipt.validate_for(contract)

    def test_missing_authority_kill_switch_and_all_identity_drift_deny(self) -> None:
        contract = policy()
        cases = (
            replace(context(contract), roundlet_enabled=False),
            replace(context(contract), read_only_external_validation_allowed=False),
            replace(context(contract), disposable_target_mutation_allowed=False),
            replace(context(contract), kill_switch_active=True),
            replace(context(contract), phase=3),
            replace(context(contract), leaf_number=88),
            replace(context(contract), base_sha="e" * 40),
            replace(context(contract), candidate_sha="e" * 40),
            replace(context(contract), target=CanaryTarget("ythdelmar68/another-target", TARGET_BASE, 96)),
            replace(context(contract), policy_digest="sha256:" + "e" * 64),
            replace(context(contract), branch="roundlet/wrong-branch"),
        )
        for item in cases:
            with self.subTest(item=item):
                self.assertFalse(evaluate_bounded_canary_policy(contract, item).authorized)

    def test_rejects_floating_identity_path_escape_duplicates_and_budget_broadening(self) -> None:
        operation = GitHubMutationOperation.CREATE_BRANCH
        with self.assertRaises(CanaryPolicyError):
            CanaryTarget("ythdelmar68/roundlet-forward-test", "main", 96)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, 4, 87, policy().target, "roundlet/canary", ("../escape",), (operation,), CanaryBudget(((operation, 1),), 1), policy().rollback)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, 4, 87, policy().target, "roundlet/canary", ("one", "one"), (operation,), CanaryBudget(((operation, 1),), 1), policy().rollback)
        with self.assertRaises(CanaryPolicyError):
            CanaryBudget(((operation, 1),), 2)
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryPolicy(BASE, CANDIDATE, 4, 87, policy().target, "roundlet/canary", ("one",), (operation, operation), CanaryBudget(((operation, 1),), 1), policy().rollback)

    def test_receipt_rejects_budget_exhaustion_and_preserves_ambiguous_resources(self) -> None:
        contract = policy()
        with self.assertRaises(CanaryPolicyError):
            BoundedCanaryReceipt(contract, CanaryResult.PASS, ((GitHubMutationOperation.CREATE_BRANCH, 2), (GitHubMutationOperation.DELETE_BRANCH, 0)), DIGEST)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=True, readback_is_unambiguous=True), CleanupDisposition.ROLLBACK)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=True, readback_is_unambiguous=False), CleanupDisposition.PRESERVE_FOR_OWNER)
        self.assertIs(contract.rollback.cleanup_disposition(resource_is_reversible=False, readback_is_unambiguous=True), CleanupDisposition.PRESERVE_FOR_OWNER)

    def test_each_broker_request_requires_exact_branch_path_operation_and_budget(self) -> None:
        contract = policy()
        exact = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        self.assertTrue(authorize_canary_request(contract, context(contract), exact, None).authorized)
        invalid = (
            replace(exact, operation=GitHubMutationOperation.MARK_READY),
            replace(exact, branch="roundlet/wrong-branch"),
            replace(exact, paths=("canary/other.txt",)),
        )
        for request in invalid:
            with self.subTest(request=request):
                self.assertFalse(authorize_canary_request(contract, context(contract), request, None).authorized)

    def test_subsequent_request_requires_the_exact_prior_receipt_and_derives_budget(self) -> None:
        contract = policy()
        prior = BoundedCanaryReceipt(
            contract, CanaryResult.PASS,
            ((GitHubMutationOperation.CREATE_BRANCH, 1), (GitHubMutationOperation.DELETE_BRANCH, 0)),
            DIGEST,
        )
        next_request = CanaryMutationRequest(GitHubMutationOperation.DELETE_BRANCH, contract.branch, ("canary/probe.txt",))
        self.assertTrue(authorize_canary_request(contract, context(contract, prior_receipt=prior), next_request, prior).authorized)
        self.assertFalse(authorize_canary_request(contract, context(contract, prior_receipt=prior), next_request, None).authorized)
        exhausted = CanaryMutationRequest(GitHubMutationOperation.CREATE_BRANCH, contract.branch, ("canary/probe.txt",))
        self.assertFalse(authorize_canary_request(contract, context(contract, prior_receipt=prior), exhausted, prior).authorized)
        self.assertFalse(authorize_canary_request(contract, replace(context(contract, prior_receipt=prior), prior_receipt_digest="sha256:" + "e" * 64), next_request, prior).authorized)
        wrong_target_policy = BoundedCanaryPolicy(
            BASE, "e" * 40, 4, 87,
            CanaryTarget("ythdelmar68/another-target", TARGET_BASE, 96),
            contract.branch, contract.allowed_paths, contract.requested_operations, contract.budget, contract.rollback,
        )
        wrong_receipt = BoundedCanaryReceipt(
            wrong_target_policy, CanaryResult.PASS,
            ((GitHubMutationOperation.CREATE_BRANCH, 1), (GitHubMutationOperation.DELETE_BRANCH, 0)),
            DIGEST,
        )
        self.assertFalse(authorize_canary_request(contract, replace(context(contract), prior_receipt_digest=wrong_receipt.receipt_digest), next_request, wrong_receipt).authorized)
        object.__setattr__(prior, "semantic_readback_digest", "sha256:" + "e" * 64)
        self.assertFalse(authorize_canary_request(contract, context(contract, prior_receipt=prior), next_request, prior).authorized)

    def test_parser_rejects_unknown_duplicate_and_silent_operation_substitution(self) -> None:
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
