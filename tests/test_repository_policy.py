"""Hermetic contracts for explicit Boolean repository mutation policy."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.repository_policy import (
    REPOSITORY_POLICY_SCHEMA_VERSION,
    RepositoryActivationReceipt,
    RepositoryMutationContext,
    RepositoryMutationOperation,
    RepositoryPolicyError,
    RepositoryPolicySource,
    RepositoryReceiptStatus,
    StandingRepositoryAuthority,
    TrustedRepositoryPolicySnapshot,
    evaluate_repository_mutation_policy,
    evaluate_shadow_mutation_policy,
    parse_repository_mutation_policy,
)


def fingerprint(character: str) -> str:
    return character * 64


class RepositoryMutationPolicyTests(unittest.TestCase):
    now = datetime(2026, 8, 5, 8, 0, tzinfo=timezone.utc)
    candidate = "a" * 40

    def policy(self, **changes: object):
        values: dict[str, object] = {
            "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
            "enabled": True,
            "allow_issue_comment": False,
            "allow_push_branch": False,
            "allow_create_draft_pr": False,
            "allow_mark_pr_ready": False,
            "allow_merge_pr": False,
            "allow_close_leaf_issue": False,
            "allow_delete_remote_branch": False,
            "allow_delete_local_branch": False,
            "allow_remove_worktree": False,
        }
        values.update(changes)
        import json
        return parse_repository_mutation_policy(json.dumps(values))

    def snapshot(self, **changes: object) -> TrustedRepositoryPolicySnapshot:
        return TrustedRepositoryPolicySnapshot(RepositoryPolicySource(fingerprint("a"), fingerprint("b")), self.policy(**changes))

    def context(self, **changes: object) -> RepositoryMutationContext:
        values: dict[str, object] = {
            "repository_fingerprint": fingerprint("c"), "deployment_fingerprint": fingerprint("d"),
            "task_fingerprint": fingerprint("e"), "candidate_sha": self.candidate,
        }
        values.update(changes)
        return RepositoryMutationContext(**values)  # type: ignore[arg-type]

    def receipt(self, snapshot: TrustedRepositoryPolicySnapshot, context: RepositoryMutationContext, **changes: object) -> RepositoryActivationReceipt:
        values: dict[str, object] = {
            "owner_fingerprint": fingerprint("f"), "receipt_fingerprint": fingerprint("0"),
            "source_fingerprint": snapshot.source.source_fingerprint,
            "revision_fingerprint": snapshot.source.revision_fingerprint,
            "policy_digest": snapshot.policy_digest, "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
            "repository_fingerprint": context.repository_fingerprint,
            "deployment_fingerprint": context.deployment_fingerprint,
            "task_fingerprint": context.task_fingerprint, "candidate_sha": context.candidate_sha,
            "activated_at": self.now - timedelta(minutes=1), "expires_at": self.now + timedelta(minutes=1),
        }
        values.update(changes)
        return RepositoryActivationReceipt(**values)  # type: ignore[arg-type]

    def evaluate(self, snapshot: TrustedRepositoryPolicySnapshot, receipt: RepositoryActivationReceipt, context: RepositoryMutationContext, operation: RepositoryMutationOperation, **changes: object):
        values: dict[str, object] = {
            "standing_authority": StandingRepositoryAuthority(self.policy(**{name: True for name in (
                "allow_issue_comment", "allow_push_branch", "allow_create_draft_pr", "allow_mark_pr_ready", "allow_merge_pr",
                "allow_close_leaf_issue", "allow_delete_remote_branch", "allow_delete_local_branch", "allow_remove_worktree",
            )})),
            "receipt_status": RepositoryReceiptStatus.FRESH,
            "now": self.now,
        }
        values.update(changes)
        return evaluate_repository_mutation_policy(snapshot, receipt, context, operation, **values)  # type: ignore[arg-type]

    def test_document_requires_every_exact_strict_boolean_and_no_duplicates(self) -> None:
        valid = self.policy()
        self.assertEqual(valid.digest, self.policy().digest)
        base = '{"schema_version":1,"enabled":true,"allow_issue_comment":true,"allow_push_branch":false,"allow_create_draft_pr":false,"allow_mark_pr_ready":false,"allow_merge_pr":false,"allow_close_leaf_issue":false,"allow_delete_remote_branch":false,"allow_delete_local_branch":false,"allow_remove_worktree":false'
        for suffix in (
            ',"unknown":false}',
            ',"enabled":false}',
        ):
            with self.subTest(suffix=suffix), self.assertRaises(RepositoryPolicyError):
                parse_repository_mutation_policy(base + suffix)
        for value in ('"true"', '1', 'null'):
            with self.subTest(value=value), self.assertRaises(RepositoryPolicyError):
                parse_repository_mutation_policy(base + ',"allow_push_branch":' + value + '}')
        with self.assertRaises(RepositoryPolicyError):
            parse_repository_mutation_policy('{"schema_version":1,"enabled":true}')

    def test_enabled_false_denies_every_operation_before_any_action_adapter_exists(self) -> None:
        snapshot, context = self.snapshot(enabled=False, allow_push_branch=True), self.context()
        receipt = self.receipt(snapshot, context)
        for operation in RepositoryMutationOperation:
            with self.subTest(operation=operation):
                decision = self.evaluate(snapshot, receipt, context, operation)
                self.assertFalse(decision.authorized)
                self.assertFalse(decision.enabled)
                self.assertIn("disabled", decision.reason)

    def test_each_action_requires_its_own_exact_switch(self) -> None:
        context = self.context()
        for operation in RepositoryMutationOperation:
            enabled_key = {
                RepositoryMutationOperation.ISSUE_COMMENT: "allow_issue_comment",
                RepositoryMutationOperation.PUSH_BRANCH: "allow_push_branch",
                RepositoryMutationOperation.CREATE_DRAFT_PR: "allow_create_draft_pr",
                RepositoryMutationOperation.MARK_PR_READY: "allow_mark_pr_ready",
                RepositoryMutationOperation.MERGE_PR: "allow_merge_pr",
                RepositoryMutationOperation.CLOSE_LEAF_ISSUE: "allow_close_leaf_issue",
                RepositoryMutationOperation.DELETE_REMOTE_BRANCH: "allow_delete_remote_branch",
                RepositoryMutationOperation.DELETE_LOCAL_BRANCH: "allow_delete_local_branch",
                RepositoryMutationOperation.REMOVE_WORKTREE: "allow_remove_worktree",
            }[operation]
            snapshot = self.snapshot(**{enabled_key: True})
            receipt = self.receipt(snapshot, context)
            with self.subTest(operation=operation):
                self.assertTrue(self.evaluate(snapshot, receipt, context, operation).authorized)
                other = next(item for item in RepositoryMutationOperation if item is not operation)
                self.assertFalse(self.evaluate(snapshot, receipt, context, other).authorized)

    def test_policy_can_only_narrow_standing_boolean_authority(self) -> None:
        snapshot, context = self.snapshot(allow_push_branch=True), self.context()
        receipt = self.receipt(snapshot, context)
        ceiling = StandingRepositoryAuthority(self.policy(allow_issue_comment=True))
        decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.PUSH_BRANCH, standing_authority=ceiling)
        self.assertFalse(decision.authorized)
        self.assertIn("widen", decision.reason)

    def test_receipt_binds_source_digest_schema_repository_deployment_task_and_candidate(self) -> None:
        snapshot, context = self.snapshot(), self.context()
        receipt = self.receipt(snapshot, context)
        changes = (
            {"source_fingerprint": fingerprint("1")}, {"revision_fingerprint": fingerprint("1")},
            {"policy_digest": fingerprint("1")}, {"schema_version": 2},
            {"repository_fingerprint": fingerprint("1")}, {"deployment_fingerprint": fingerprint("1")},
            {"task_fingerprint": fingerprint("1")}, {"candidate_sha": "b" * 40},
        )
        for change in changes:
            with self.subTest(change=change):
                if change == {"schema_version": 2}:
                    with self.assertRaises(RepositoryPolicyError):
                        self.receipt(snapshot, context, **change)
                else:
                    decision = self.evaluate(snapshot, self.receipt(snapshot, context, **change), context, RepositoryMutationOperation.ISSUE_COMMENT)
                    self.assertFalse(decision.authorized)

    def test_candidate_policy_edits_lifecycle_and_clock_drift_fail_closed(self) -> None:
        snapshot, context = self.snapshot(allow_issue_comment=True), self.context()
        receipt = self.receipt(snapshot, context)
        altered = self.snapshot(allow_push_branch=True)
        self.assertFalse(self.evaluate(altered, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT).authorized)
        for status in RepositoryReceiptStatus:
            with self.subTest(status=status):
                decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT, receipt_status=status)
                self.assertEqual(decision.authorized, status is RepositoryReceiptStatus.FRESH)
        stale = self.receipt(snapshot, context, expires_at=self.now - timedelta(seconds=1))
        self.assertFalse(self.evaluate(snapshot, stale, context, RepositoryMutationOperation.ISSUE_COMMENT).authorized)

    def test_unknown_operations_and_forged_values_cannot_create_authority(self) -> None:
        snapshot, context = self.snapshot(), self.context()
        receipt = self.receipt(snapshot, context)
        decision = evaluate_repository_mutation_policy(snapshot, receipt, context, "release", standing_authority=StandingRepositoryAuthority(self.policy()), receipt_status=RepositoryReceiptStatus.FRESH, now=self.now)  # type: ignore[arg-type]
        self.assertFalse(decision.authorized)
        self.assertIsNone(decision.operation)
        self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_shadow_counterfactual_disables_every_operation_and_cannot_widen_policy(self) -> None:
        for operation in RepositoryMutationOperation:
            with self.subTest(operation=operation):
                decision = evaluate_shadow_mutation_policy(operation)
                self.assertFalse(decision.authorized)
                self.assertFalse(decision.enabled)
                self.assertFalse(decision.action_enabled)
                self.assertEqual(decision.next_action, "retain-zero-mutation-evidence")


if __name__ == "__main__":
    unittest.main()
