"""Hermetic split-brain and deployment-authority handoff coverage."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from threading import Barrier, Thread
import unittest
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.deployment_handoff import (
    AuthorityReceiptVerificationStatus,
    DeploymentAuthorityHandoffCoordinator,
    DeploymentAuthorityHandoffReceipt,
    DeploymentAuthorityIdentity,
    DeploymentAuthorityReceiptVerification,
    HandoffRecoveryClaim,
    HandoffRecoveryStatus,
    HandoffPhase,
    HandoffReconciliation,
    HandoffTeardown,
    InMemoryDeploymentAuthorityStore,
)
from roundwright.runtime_binding import RuntimeBinding


def fingerprint(character: str) -> str:
    return character * 64


class DeploymentAuthorityHandoffTests(unittest.TestCase):
    now = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
    state_id = UUID("12345678-1234-5678-1234-567812345678")

    def setUp(self) -> None:
        self.store = InMemoryDeploymentAuthorityStore(fingerprint("c"), self.state_id)
        self.coordinator = DeploymentAuthorityHandoffCoordinator(self.store)

    def binding(self) -> RuntimeBinding:
        return RuntimeBinding("roundwright-runtime/v1", "sha256:" + "0" * 64, "sha256:" + "1" * 64, ("sha256:" + "2" * 64,))

    def identity(self, *, deployment: str = "d", candidate: str = "a", environment: str = "e", store: str = "c") -> DeploymentAuthorityIdentity:
        return DeploymentAuthorityIdentity(
            fingerprint("0"), fingerprint("1"), fingerprint(store), self.state_id, fingerprint(deployment),
            candidate * 40, fingerprint(environment), self.binding(),
        )

    def receipt(self, identity: DeploymentAuthorityIdentity, character: str = "f", *, expires_at: datetime | None = None) -> DeploymentAuthorityHandoffReceipt:
        return DeploymentAuthorityHandoffReceipt(
            fingerprint(character), identity, self.now - timedelta(minutes=1), expires_at or self.now + timedelta(minutes=1),
        )

    def verification(
        self, receipt: DeploymentAuthorityHandoffReceipt,
        *, status: AuthorityReceiptVerificationStatus = AuthorityReceiptVerificationStatus.FRESH,
    ) -> DeploymentAuthorityReceiptVerification:
        identity = receipt.identity
        return DeploymentAuthorityReceiptVerification(
            fingerprint("7"), receipt.receipt_fingerprint, receipt.binding_digest,
            identity.repository_fingerprint, identity.state_store_fingerprint, identity.state_id,
            identity.candidate_sha, identity.environment_fingerprint, status,
        )

    def reconciliation(self, handoff: str = "9", old: str = "f") -> HandoffReconciliation:
        return HandoffReconciliation(
            fingerprint(handoff), fingerprint(old), self.store.state_store_fingerprint, self.state_id,
            True, True, True, fingerprint("8"),
        )

    def recovery(
        self, old: DeploymentAuthorityHandoffReceipt, *, prior_claim: str = "5", generation: int = 1,
        replacement_claim: str = "4", evidence: str = "6", status: HandoffRecoveryStatus = HandoffRecoveryStatus.STALE_OWNER,
        observed_at: datetime | None = None, expires_at: datetime | None = None,
    ) -> HandoffRecoveryClaim:
        observed = self.now if observed_at is None else observed_at
        return HandoffRecoveryClaim(
            fingerprint(evidence), fingerprint("9"), old.receipt_fingerprint, old.binding_digest,
            fingerprint(prior_claim), generation, fingerprint(replacement_claim),
            self.store.state_store_fingerprint, self.state_id, status, observed,
            observed + timedelta(minutes=1) if expires_at is None else expires_at,
        )

    def teardown(self, handoff: str = "9", old: str = "f", *, resources_torn_down: bool = True) -> HandoffTeardown:
        return HandoffTeardown(
            fingerprint(handoff), fingerprint(old), self.store.state_store_fingerprint, self.state_id,
            resources_torn_down, fingerprint("a"),
        )

    def test_concurrent_initial_acquisition_has_exactly_one_active_authority(self) -> None:
        first, second = self.receipt(self.identity(), "f"), self.receipt(self.identity(candidate="b"), "e")
        barrier = Barrier(3)
        results = []
        def claim(receipt: DeploymentAuthorityHandoffReceipt) -> None:
            barrier.wait()
            results.append(self.coordinator.activate_initial(receipt, self.verification(receipt), now=self.now))
        threads = [Thread(target=claim, args=(receipt,)) for receipt in (first, second)]
        for thread in threads: thread.start()
        barrier.wait()
        for thread in threads: thread.join()
        self.assertEqual(sum(result.authorized for result in results), 1)
        self.assertIn(self.coordinator.active_receipt, (first, second))

    def test_copied_receipt_second_clone_alternate_state_and_mismatch_fail_closed(self) -> None:
        identity, receipt = self.identity(), self.receipt(self.identity())
        self.assertTrue(self.coordinator.activate_initial(receipt, self.verification(receipt), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(receipt, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        self.assertTrue(self.coordinator.authorize(identity, receipt, now=self.now).authorized)
        self.assertFalse(self.coordinator.authorize(self.identity(candidate="b"), receipt, now=self.now).authorized)
        self.assertFalse(self.coordinator.authorize(self.identity(environment="b"), receipt, now=self.now).authorized)
        self.assertFalse(self.coordinator.authorize(self.identity(store="b"), receipt, now=self.now).authorized)
        copied_identity = replace(identity)
        copied_receipt = replace(receipt, identity=copied_identity)
        clone = DeploymentAuthorityHandoffCoordinator(self.store)
        self.assertFalse(clone.claim_orchestrator(copied_receipt, claim_fingerprint=fingerprint("4"), now=self.now).authorized)
        self.assertFalse(clone.authorize(copied_identity, copied_receipt, now=self.now).authorized)
        self.assertFalse(clone.request_scheduler_wakeup(copied_identity, copied_receipt, now=self.now).requested)
        alternate_store = DeploymentAuthorityHandoffCoordinator(InMemoryDeploymentAuthorityStore(fingerprint("c"), self.state_id))
        self.assertFalse(alternate_store.authorize(identity, receipt, now=self.now).authorized)
        self.assertFalse(self.coordinator.authorize(identity, receipt, now=self.now + timedelta(minutes=2)).authorized)

    def test_handoff_orders_stop_reconcile_revoke_then_new_receipt(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b", environment="b")
        old, new = self.receipt(old_identity), self.receipt(new_identity, "e")
        handoff = fingerprint("9")
        self.assertTrue(self.coordinator.activate_initial(old, self.verification(old), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(old, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        self.assertFalse(self.coordinator.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(self.coordinator.begin_handoff(old, new_identity, handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertFalse(self.coordinator.authorize(old_identity, old, now=self.now).authorized)
        self.assertFalse(self.coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertTrue(self.coordinator.reconcile(self.reconciliation()).authorized)
        self.assertTrue(self.coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertFalse(self.coordinator.authorize(old_identity, old, now=self.now).authorized)
        self.assertTrue(self.coordinator.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(new, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        self.assertTrue(self.coordinator.authorize(new_identity, new, now=self.now).authorized)

    def test_interrupted_handoff_is_non_dispatching_and_resumes_from_machine_truth(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b")
        old, new = self.receipt(old_identity), self.receipt(new_identity, "e")
        handoff = fingerprint("9")
        self.coordinator.activate_initial(old, self.verification(old), now=self.now)
        self.coordinator.claim_orchestrator(old, claim_fingerprint=fingerprint("5"), now=self.now)
        self.coordinator.begin_handoff(old, new_identity, handoff_fingerprint=handoff, now=self.now)
        restarted = DeploymentAuthorityHandoffCoordinator(self.store)
        self.assertEqual(restarted.progress.phase, HandoffPhase.STOPPING)  # type: ignore[union-attr]
        self.assertFalse(restarted.authorize(old_identity, old, now=self.now).authorized)
        self.assertFalse(restarted.reconcile(self.reconciliation()).authorized)
        self.assertFalse(restarted.recover_handoff(self.recovery(
            old, observed_at=self.now - timedelta(minutes=2), expires_at=self.now - timedelta(minutes=1),
        ), now=self.now).authorized)
        self.assertTrue(restarted.recover_handoff(self.recovery(old), now=self.now).authorized)
        self.assertFalse(DeploymentAuthorityHandoffCoordinator(self.store).recover_handoff(self.recovery(old), now=self.now).authorized)
        second_restart = DeploymentAuthorityHandoffCoordinator(self.store)
        self.assertTrue(second_restart.recover_handoff(self.recovery(
            old, prior_claim="4", generation=2, replacement_claim="3", evidence="2",
        ), now=self.now).authorized)
        self.assertTrue(second_restart.reconcile(self.reconciliation()).authorized)
        self.assertTrue(second_restart.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertTrue(second_restart.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(second_restart.claim_orchestrator(new, claim_fingerprint=fingerprint("3"), now=self.now).authorized)

    def test_stale_owner_recovery_and_wakeups_never_create_authority(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b")
        stale = self.receipt(old_identity, expires_at=self.now - timedelta(seconds=1))
        new = self.receipt(new_identity, "e")
        self.assertFalse(self.coordinator.request_scheduler_wakeup(old_identity, stale, now=self.now).requested)
        self.assertTrue(self.coordinator.activate_initial(stale, self.verification(stale), now=self.now - timedelta(seconds=30)).authorized)
        self.assertFalse(self.coordinator.authorize(old_identity, stale, now=self.now).authorized)
        handoff = fingerprint("9")
        self.assertTrue(self.coordinator.claim_orchestrator(stale, claim_fingerprint=fingerprint("5"), now=self.now - timedelta(seconds=30)).authorized)
        self.assertTrue(self.coordinator.begin_handoff(
            stale, new_identity, handoff_fingerprint=handoff, now=self.now, recovery_claim=self.recovery(stale),
        ).authorized)
        self.assertTrue(self.coordinator.reconcile(self.reconciliation()).authorized)
        self.assertTrue(self.coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertTrue(self.coordinator.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(new, claim_fingerprint=fingerprint("4"), now=self.now).authorized)
        self.assertTrue(self.coordinator.request_scheduler_wakeup(new_identity, new, now=self.now).requested)

    def test_missing_copied_and_conflicting_verification_cannot_activate_or_claim(self) -> None:
        identity, receipt = self.identity(), self.receipt(self.identity())
        for status in (
            AuthorityReceiptVerificationStatus.MISSING,
            AuthorityReceiptVerificationStatus.COPIED,
            AuthorityReceiptVerificationStatus.CONFLICTING,
        ):
            with self.subTest(status=status):
                store = InMemoryDeploymentAuthorityStore(fingerprint("c"), self.state_id)
                coordinator = DeploymentAuthorityHandoffCoordinator(store)
                self.assertFalse(coordinator.activate_initial(receipt, self.verification(receipt, status=status), now=self.now).authorized)

    def test_denied_claimant_cannot_take_over_or_advance_a_same_store_handoff(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b")
        old, new = self.receipt(old_identity), self.receipt(new_identity, "e")
        handoff = fingerprint("9")
        self.assertTrue(self.coordinator.activate_initial(old, self.verification(old), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(old, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        denied = DeploymentAuthorityHandoffCoordinator(self.store)
        self.assertFalse(denied.claim_orchestrator(old, claim_fingerprint=fingerprint("4"), now=self.now).authorized)
        self.assertFalse(denied.begin_handoff(old, new_identity, handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(self.coordinator.begin_handoff(old, new_identity, handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertFalse(denied.reconcile(self.reconciliation()).authorized)
        self.assertFalse(denied.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertFalse(denied.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertFalse(denied.recover_handoff(self.recovery(old, status=HandoffRecoveryStatus.MISSING), now=self.now).authorized)
        self.assertTrue(self.coordinator.reconcile(self.reconciliation()).authorized)
        self.assertTrue(self.coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertTrue(self.coordinator.issue_new_receipt(new, self.verification(new), handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertFalse(denied.claim_orchestrator(new, claim_fingerprint=fingerprint("4"), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(new, claim_fingerprint=fingerprint("5"), now=self.now).authorized)

    def test_fresh_owner_rejects_expired_mismatched_and_replayed_recovery_claims(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b")
        old = self.receipt(old_identity)
        self.assertTrue(self.coordinator.activate_initial(old, self.verification(old), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(old, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        expired = self.recovery(
            old, observed_at=self.now - timedelta(minutes=2), expires_at=self.now - timedelta(minutes=1),
        )
        mismatched = self.recovery(old, prior_claim="4")
        replayed = self.recovery(old, evidence="3")
        self.store._consumed_recovery_evidence_fingerprints.add(replayed.evidence_fingerprint)
        for claim in (expired, mismatched, replayed):
            with self.subTest(claim=claim.evidence_fingerprint):
                decision = self.coordinator.begin_handoff(
                    old, new_identity, handoff_fingerprint=fingerprint("9"), now=self.now, recovery_claim=claim,
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(self.coordinator.progress)

    def test_terminal_teardown_clears_only_a_fully_revoked_and_cleaned_handoff(self) -> None:
        old_identity, new_identity = self.identity(), self.identity(candidate="b")
        old = self.receipt(old_identity)
        handoff = fingerprint("9")
        self.assertTrue(self.coordinator.activate_initial(old, self.verification(old), now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(old, claim_fingerprint=fingerprint("5"), now=self.now).authorized)
        self.assertTrue(self.coordinator.begin_handoff(old, new_identity, handoff_fingerprint=handoff, now=self.now).authorized)
        self.assertTrue(self.coordinator.reconcile(self.reconciliation()).authorized)
        self.assertTrue(self.coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized)
        self.assertFalse(self.coordinator.complete_teardown(self.teardown(resources_torn_down=False)).authorized)
        self.assertEqual(self.coordinator.progress.phase, HandoffPhase.REVOKED)  # type: ignore[union-attr]
        self.assertTrue(self.coordinator.complete_teardown(self.teardown()).authorized)
        self.assertIsNone(self.coordinator.active_receipt)
        self.assertIsNone(self.coordinator.progress)
        restarted = DeploymentAuthorityHandoffCoordinator(self.store)
        self.assertIsNone(restarted.active_receipt)
        self.assertIsNone(restarted.progress)


if __name__ == "__main__":
    unittest.main()
