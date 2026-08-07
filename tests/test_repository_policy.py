"""Hermetic contracts for explicit Boolean repository mutation policy."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.repository_policy import (
    GITHUB_REPOSITORY_OPERATION,
    REPOSITORY_POLICY_SCHEMA_VERSION,
    REPOSITORY_OPERATION_SWITCH,
    RepositoryActivationReceipt,
    RepositoryDispatcherTransition,
    RepositoryMutationContext,
    RepositoryMutationOperation,
    RepositoryPolicyError,
    RepositoryPolicySource,
    RepositoryReceiptVerification,
    RepositoryReceiptStatus,
    RoundletAuthorityState,
    StandingRepositoryAuthority,
    TrustedRepositoryPolicySnapshot,
    evaluate_repository_mutation_policy,
    evaluate_shadow_mutation_policy,
    parse_roundlet_authority_state,
    parse_roundwright_authority_block,
    parse_repository_mutation_policy,
    repository_operation_for_github,
    validate_dispatcher_exclusivity,
    validate_repository_mutation_vocabulary,
)
from roundwright.github import GitHubMutationOperation


def fingerprint(character: str) -> str:
    return character * 64


class RepositoryMutationPolicyTests(unittest.TestCase):
    now = datetime(2026, 8, 5, 8, 0, tzinfo=timezone.utc)
    candidate = "a" * 40

    def policy(self, **changes: object):
        values: dict[str, object] = {
            "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
            "enabled": True,
            **{name: False for name in REPOSITORY_OPERATION_SWITCH.values()},
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

    def transition(self, context: RepositoryMutationContext, **changes: object) -> RepositoryDispatcherTransition:
        values: dict[str, object] = {
            "evidence_fingerprint": fingerprint("8"),
            "repository_fingerprint": context.repository_fingerprint,
            "deployment_fingerprint": context.deployment_fingerprint,
            "candidate_sha": context.candidate_sha,
            "roundlet_mutation_capable": False,
            "roundlet_reconciled": True,
            "roundwright_mutation_capable": True,
        }
        values.update(changes)
        return RepositoryDispatcherTransition(**values)  # type: ignore[arg-type]

    def receipt(
        self,
        snapshot: TrustedRepositoryPolicySnapshot,
        context: RepositoryMutationContext,
        transition: RepositoryDispatcherTransition | None = None,
        **changes: object,
    ) -> RepositoryActivationReceipt:
        transition = transition or self.transition(context)
        values: dict[str, object] = {
            "owner_fingerprint": fingerprint("f"), "receipt_fingerprint": fingerprint("0"),
            "source_fingerprint": snapshot.source.source_fingerprint,
            "revision_fingerprint": snapshot.source.revision_fingerprint,
            "policy_digest": snapshot.policy_digest, "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
            "repository_fingerprint": context.repository_fingerprint,
            "deployment_fingerprint": context.deployment_fingerprint,
            "task_fingerprint": context.task_fingerprint, "candidate_sha": context.candidate_sha,
            "dispatcher_transition_digest": transition.digest,
            "activated_at": self.now - timedelta(minutes=1), "expires_at": self.now + timedelta(minutes=1),
        }
        values.update(changes)
        return RepositoryActivationReceipt(**values)  # type: ignore[arg-type]

    def verification(self, receipt: RepositoryActivationReceipt, **changes: object) -> RepositoryReceiptVerification:
        from roundwright.repository_policy import _receipt_binding_digest
        values: dict[str, object] = {
            "verification_fingerprint": fingerprint("9"),
            "receipt_fingerprint": receipt.receipt_fingerprint,
            "receipt_binding_digest": _receipt_binding_digest(receipt),
            "status": RepositoryReceiptStatus.FRESH,
        }
        values.update(changes)
        return RepositoryReceiptVerification(**values)  # type: ignore[arg-type]

    def evaluate(self, snapshot: TrustedRepositoryPolicySnapshot, receipt: RepositoryActivationReceipt, context: RepositoryMutationContext, operation: RepositoryMutationOperation, **changes: object):
        values: dict[str, object] = {
            "standing_authority": StandingRepositoryAuthority(self.policy(**{name: True for name in REPOSITORY_OPERATION_SWITCH.values()})),
            "dispatcher_transition": self.transition(context),
            "receipt_verification": self.verification(receipt),
            "now": self.now,
        }
        values.update(changes)
        return evaluate_repository_mutation_policy(snapshot, receipt, context, operation, **values)  # type: ignore[arg-type]

    def test_document_requires_every_exact_strict_boolean_and_no_duplicates(self) -> None:
        valid = self.policy()
        self.assertEqual(valid.digest, self.policy().digest)
        import json
        valid_values = {
            "schema_version": REPOSITORY_POLICY_SCHEMA_VERSION,
            "enabled": True,
            **{name: False for name in REPOSITORY_OPERATION_SWITCH.values()},
        }
        base = json.dumps(valid_values, separators=(",", ":"))[:-1]
        for suffix in (
            ',"unknown":false}',
            ',"enabled":false}',
        ):
            with self.subTest(suffix=suffix), self.assertRaises(RepositoryPolicyError):
                parse_repository_mutation_policy(base + suffix)
        for value in ('"true"', '1', 'null'):
            with self.subTest(value=value), self.assertRaises(RepositoryPolicyError):
                parse_repository_mutation_policy(base + ',"allow_update_remote_branch":' + value + '}')
        with self.assertRaises(RepositoryPolicyError):
            parse_repository_mutation_policy('{"schema_version":2,"enabled":true}')
        valid_values["schema_version"] = 1
        with self.assertRaises(RepositoryPolicyError):
            parse_repository_mutation_policy(json.dumps(valid_values))

    def test_enabled_false_denies_every_operation_before_any_action_adapter_exists(self) -> None:
        snapshot, context = self.snapshot(enabled=False, allow_update_remote_branch=True), self.context()
        receipt = self.receipt(snapshot, context)
        for operation in RepositoryMutationOperation:
            with self.subTest(operation=operation):
                decision = self.evaluate(snapshot, receipt, context, operation)
                self.assertFalse(decision.authorized)
                self.assertFalse(decision.enabled)
                self.assertIn("disabled", decision.reason)

    def test_operation_vocabulary_is_total_one_to_one_and_has_no_nullable_escape(self) -> None:
        validate_repository_mutation_vocabulary()
        self.assertEqual(set(GITHUB_REPOSITORY_OPERATION), set(GitHubMutationOperation))
        for operation in GitHubMutationOperation:
            with self.subTest(operation=operation):
                self.assertIs(repository_operation_for_github(operation), GITHUB_REPOSITORY_OPERATION[operation])

        repository_mutations: list[dict[object, object]] = []
        missing_repository = dict(REPOSITORY_OPERATION_SWITCH)
        missing_repository.pop(RepositoryMutationOperation.REQUEST_REVIEW)
        repository_mutations.append(missing_repository)
        nullable_repository = dict(REPOSITORY_OPERATION_SWITCH)
        nullable_repository[RepositoryMutationOperation.REQUEST_REVIEW] = None
        repository_mutations.append(nullable_repository)
        duplicate_repository = dict(REPOSITORY_OPERATION_SWITCH)
        duplicate_repository[RepositoryMutationOperation.UPDATE_REMOTE_BRANCH] = duplicate_repository[RepositoryMutationOperation.CREATE_REMOTE_BRANCH]
        repository_mutations.append(duplicate_repository)
        extra_repository = dict(REPOSITORY_OPERATION_SWITCH)
        extra_repository["unexpected-operation"] = "allow_unexpected"
        repository_mutations.append(extra_repository)
        for mapping in repository_mutations:
            with self.subTest(repository_mapping=mapping), self.assertRaises(RepositoryPolicyError):
                validate_repository_mutation_vocabulary(mapping, GITHUB_REPOSITORY_OPERATION)

        github_mutations: list[dict[object, object]] = []
        missing_github = dict(GITHUB_REPOSITORY_OPERATION)
        missing_github.pop(GitHubMutationOperation.REQUEST_REVIEW)
        github_mutations.append(missing_github)
        nullable_github = dict(GITHUB_REPOSITORY_OPERATION)
        nullable_github[GitHubMutationOperation.REQUEST_REVIEW] = None
        github_mutations.append(nullable_github)
        duplicate_github = dict(GITHUB_REPOSITORY_OPERATION)
        duplicate_github[GitHubMutationOperation.UPDATE_BRANCH] = duplicate_github[GitHubMutationOperation.CREATE_BRANCH]
        github_mutations.append(duplicate_github)
        extra_github = dict(GITHUB_REPOSITORY_OPERATION)
        extra_github["unexpected-operation"] = RepositoryMutationOperation.REMOVE_WORKTREE
        github_mutations.append(extra_github)
        for mapping in github_mutations:
            with self.subTest(github_mapping=mapping), self.assertRaises(RepositoryPolicyError):
                validate_repository_mutation_vocabulary(REPOSITORY_OPERATION_SWITCH, mapping)

    def test_authority_parsers_are_marker_isolated_and_current_blocks_are_exclusive(self) -> None:
        contents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        roundlet = parse_roundlet_authority_state(contents)
        roundwright = parse_roundwright_authority_block(contents)
        self.assertTrue(roundlet.enabled)
        self.assertFalse(roundwright.enabled)
        self.assertTrue(all(not getattr(roundwright, name) for name in REPOSITORY_OPERATION_SWITCH.values()))
        validate_dispatcher_exclusivity(roundlet, roundwright, roundlet_reconciled=False)

        changed_roundlet = contents.replace("roundlet:\n  enabled: true", "roundlet:\n  enabled: false", 1)
        self.assertEqual(parse_roundwright_authority_block(changed_roundlet), roundwright)
        changed_roundwright = contents.replace(
            "roundwright:\n  schema_version: 2\n  enabled: false",
            "roundwright:\n  schema_version: 2\n  enabled: true",
            1,
        )
        self.assertEqual(parse_roundlet_authority_state(changed_roundwright), roundlet)

        roundlet_only = contents[contents.index("# roundlet:repository-authority"):contents.index("# roundlet:end-repository-authority") + len("# roundlet:end-repository-authority")]
        roundwright_only = contents[contents.index("# roundwright:repository-authority"):contents.index("# roundwright:end-repository-authority") + len("# roundwright:end-repository-authority")]
        with self.assertRaises(RepositoryPolicyError):
            parse_roundwright_authority_block(roundlet_only)
        with self.assertRaises(RepositoryPolicyError):
            parse_roundlet_authority_state(roundwright_only)
        with self.assertRaises(RepositoryPolicyError):
            parse_roundwright_authority_block(contents + "\n" + roundwright_only)

    def test_roundwright_activation_requires_stopped_reconciled_roundlet_and_bound_transition(self) -> None:
        active_roundwright = self.policy(enabled=True)
        active_roundlet = RoundletAuthorityState(True, fingerprint("1"))
        inactive_roundlet = RoundletAuthorityState(False, fingerprint("2"))
        with self.assertRaises(RepositoryPolicyError):
            validate_dispatcher_exclusivity(active_roundlet, active_roundwright, roundlet_reconciled=True)
        with self.assertRaises(RepositoryPolicyError):
            validate_dispatcher_exclusivity(inactive_roundlet, active_roundwright, roundlet_reconciled=False)
        validate_dispatcher_exclusivity(inactive_roundlet, active_roundwright, roundlet_reconciled=True)
        with self.assertRaises(RepositoryPolicyError):
            RepositoryDispatcherTransition(
                fingerprint("8"), fingerprint("c"), fingerprint("d"), self.candidate,
                True, True, True,
            )

        context = self.context()
        snapshot = self.snapshot(allow_issue_comment=True)
        transition = self.transition(context)
        receipt = self.receipt(snapshot, context, transition)
        self.assertTrue(self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT, dispatcher_transition=transition).authorized)
        wrong_transition = self.transition(context, evidence_fingerprint=fingerprint("7"))
        denied = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT, dispatcher_transition=wrong_transition)
        self.assertFalse(denied.authorized)
        self.assertIn("transition", denied.reason)

    def test_request_review_and_remote_branch_actions_cover_denied_allowed_stale_and_wrong_candidate(self) -> None:
        operations = (
            RepositoryMutationOperation.REQUEST_REVIEW,
            RepositoryMutationOperation.CREATE_REMOTE_BRANCH,
            RepositoryMutationOperation.UPDATE_REMOTE_BRANCH,
            RepositoryMutationOperation.DELETE_REMOTE_BRANCH,
        )
        for operation in operations:
            context = self.context()
            transition = self.transition(context)
            key = REPOSITORY_OPERATION_SWITCH[operation]
            denied_snapshot = self.snapshot()
            denied_receipt = self.receipt(denied_snapshot, context, transition)
            with self.subTest(operation=operation, case="denied"):
                self.assertFalse(self.evaluate(denied_snapshot, denied_receipt, context, operation, dispatcher_transition=transition).authorized)

            allowed_snapshot = self.snapshot(**{key: True})
            allowed_receipt = self.receipt(allowed_snapshot, context, transition)
            with self.subTest(operation=operation, case="allowed"):
                self.assertTrue(self.evaluate(allowed_snapshot, allowed_receipt, context, operation, dispatcher_transition=transition).authorized)

            stale_receipt = self.receipt(allowed_snapshot, context, transition, expires_at=self.now - timedelta(seconds=1))
            with self.subTest(operation=operation, case="stale"):
                self.assertFalse(self.evaluate(allowed_snapshot, stale_receipt, context, operation, dispatcher_transition=transition).authorized)

            wrong_context = self.context(candidate_sha="b" * 40)
            with self.subTest(operation=operation, case="wrong-candidate"):
                self.assertFalse(self.evaluate(allowed_snapshot, allowed_receipt, wrong_context, operation, dispatcher_transition=transition).authorized)

    def test_each_action_requires_its_own_exact_switch(self) -> None:
        context = self.context()
        for operation in RepositoryMutationOperation:
            enabled_key = REPOSITORY_OPERATION_SWITCH[operation]
            snapshot = self.snapshot(**{enabled_key: True})
            receipt = self.receipt(snapshot, context)
            with self.subTest(operation=operation):
                self.assertTrue(self.evaluate(snapshot, receipt, context, operation).authorized)
                other = next(item for item in RepositoryMutationOperation if item is not operation)
                self.assertFalse(self.evaluate(snapshot, receipt, context, other).authorized)

    def test_policy_can_only_narrow_standing_boolean_authority(self) -> None:
        snapshot, context = self.snapshot(allow_update_remote_branch=True), self.context()
        receipt = self.receipt(snapshot, context)
        ceiling = StandingRepositoryAuthority(self.policy(allow_issue_comment=True))
        decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.UPDATE_REMOTE_BRANCH, standing_authority=ceiling)
        self.assertFalse(decision.authorized)
        self.assertIn("widen", decision.reason)

    def test_receipt_binds_source_digest_schema_repository_deployment_task_and_candidate(self) -> None:
        snapshot, context = self.snapshot(), self.context()
        receipt = self.receipt(snapshot, context)
        changes = (
            {"source_fingerprint": fingerprint("1")}, {"revision_fingerprint": fingerprint("1")},
            {"policy_digest": fingerprint("1")}, {"schema_version": 1},
            {"repository_fingerprint": fingerprint("1")}, {"deployment_fingerprint": fingerprint("1")},
            {"task_fingerprint": fingerprint("1")}, {"candidate_sha": "b" * 40},
        )
        for change in changes:
            with self.subTest(change=change):
                if change == {"schema_version": 1}:
                    with self.assertRaises(RepositoryPolicyError):
                        self.receipt(snapshot, context, **change)
                else:
                    decision = self.evaluate(snapshot, self.receipt(snapshot, context, **change), context, RepositoryMutationOperation.ISSUE_COMMENT)
                    self.assertFalse(decision.authorized)

    def test_authorized_decision_retains_complete_binding_and_cannot_be_reused(self) -> None:
        snapshot, context = self.snapshot(allow_issue_comment=True), self.context()
        transition = self.transition(context)
        receipt = self.receipt(snapshot, context, transition)
        decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT, dispatcher_transition=transition)
        self.assertTrue(decision.authorized)
        binding = decision.binding
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding.source_fingerprint, snapshot.source.source_fingerprint)
        self.assertEqual(binding.revision_fingerprint, snapshot.source.revision_fingerprint)
        self.assertEqual(binding.policy_digest, snapshot.policy_digest)
        self.assertEqual(binding.schema_version, snapshot.document.schema_version)
        self.assertEqual(binding.owner_fingerprint, receipt.owner_fingerprint)
        self.assertEqual(binding.receipt_fingerprint, receipt.receipt_fingerprint)
        self.assertEqual(binding.dispatcher_transition_fingerprint, transition.evidence_fingerprint)
        self.assertEqual(binding.dispatcher_transition_digest, transition.digest)
        verification = self.verification(receipt)
        self.assertTrue(binding.matches_context(context, verification))
        other = self.context(repository_fingerprint=fingerprint("1"))
        self.assertFalse(binding.matches_context(other, verification))
        cross_receipt = self.verification(receipt, receipt_fingerprint=fingerprint("2"))
        self.assertFalse(binding.matches_context(context, cross_receipt))
        class EqualitySpoofingFingerprint(str):
            invoked = False

            def __eq__(self, other: object) -> bool:
                type(self).invoked = True
                return True

        object.__setattr__(cross_receipt, "receipt_fingerprint", EqualitySpoofingFingerprint(fingerprint("3")))
        self.assertFalse(binding.matches_context(context, cross_receipt))
        self.assertFalse(EqualitySpoofingFingerprint.invoked)
        reused = self.evaluate(snapshot, receipt, other, RepositoryMutationOperation.ISSUE_COMMENT)
        self.assertFalse(reused.authorized)
        self.assertNotEqual(binding.digest, reused.binding.digest)

    def test_candidate_policy_edits_lifecycle_and_clock_drift_fail_closed(self) -> None:
        snapshot, context = self.snapshot(allow_issue_comment=True), self.context()
        receipt = self.receipt(snapshot, context)
        altered = self.snapshot(allow_update_remote_branch=True)
        self.assertFalse(self.evaluate(altered, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT).authorized)
        for status in RepositoryReceiptStatus:
            with self.subTest(status=status):
                decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT, receipt_verification=self.verification(receipt, status=status))
                self.assertEqual(decision.authorized, status is RepositoryReceiptStatus.FRESH)
        stale = self.receipt(snapshot, context, expires_at=self.now - timedelta(seconds=1))
        self.assertFalse(self.evaluate(snapshot, stale, context, RepositoryMutationOperation.ISSUE_COMMENT).authorized)

    def test_unknown_operations_and_forged_values_cannot_create_authority(self) -> None:
        snapshot, context = self.snapshot(), self.context()
        receipt = self.receipt(snapshot, context)
        decision = evaluate_repository_mutation_policy(snapshot, receipt, context, "release", standing_authority=StandingRepositoryAuthority(self.policy()), dispatcher_transition=self.transition(context), receipt_verification=self.verification(receipt), now=self.now)  # type: ignore[arg-type]
        self.assertFalse(decision.authorized)
        self.assertIsNone(decision.operation)
        self.assertNotIn("path", str(decision.diagnostic()).casefold())

    def test_shadowed_policy_method_or_extra_attribute_cannot_authorize_or_raise(self) -> None:
        snapshot, context = self.snapshot(allow_issue_comment=False), self.context()
        receipt = self.receipt(snapshot, context)
        object.__setattr__(snapshot.document, "allows", lambda operation: True)
        object.__setattr__(snapshot.document, "untrusted_extra", "ignored")
        decision = self.evaluate(snapshot, receipt, context, RepositoryMutationOperation.ISSUE_COMMENT)
        self.assertFalse(decision.authorized)
        self.assertFalse(decision.action_enabled)
        self.assertIn("action is disabled", decision.reason)
        stale = self.receipt(snapshot, context, expires_at=self.now - timedelta(seconds=1))
        denied = self.evaluate(snapshot, stale, context, RepositoryMutationOperation.ISSUE_COMMENT)
        self.assertFalse(denied.authorized)
        self.assertFalse(denied.action_enabled)

    def test_lifecycle_verification_for_one_receipt_cannot_authorize_another(self) -> None:
        snapshot, context = self.snapshot(allow_issue_comment=True), self.context()
        first = self.receipt(snapshot, context)
        second = self.receipt(snapshot, context, receipt_fingerprint=fingerprint("1"))
        first_verification = self.verification(first)
        denied = self.evaluate(snapshot, second, context, RepositoryMutationOperation.ISSUE_COMMENT, receipt_verification=first_verification)
        self.assertFalse(denied.authorized)
        self.assertIn("not bound", denied.reason)
        second_verification = self.verification(second)
        allowed = self.evaluate(snapshot, second, context, RepositoryMutationOperation.ISSUE_COMMENT, receipt_verification=second_verification)
        self.assertTrue(allowed.authorized)
        assert allowed.binding is not None
        self.assertEqual(allowed.binding.receipt_verification_fingerprint, second_verification.verification_fingerprint)
        self.assertEqual(allowed.binding.receipt_binding_digest, second_verification.receipt_binding_digest)

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
