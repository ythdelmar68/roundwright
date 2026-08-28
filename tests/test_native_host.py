"""Hermetic native-host installation and lifecycle parity coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
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
    InMemoryDeploymentAuthorityStore,
)
from roundwright.native_host import NativeHostInstallation, NativeHostState, install_native_host
from roundwright.runtime_binding import RuntimeBinding


def fingerprint(character: str) -> str:
    return character * 64


class NativeHostTests(unittest.TestCase):
    now = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)

    def setUp(self) -> None:
        self.state_id = UUID("12345678-1234-5678-1234-567812345678")
        self.store = InMemoryDeploymentAuthorityStore(fingerprint("c"), self.state_id)
        self.coordinator = DeploymentAuthorityHandoffCoordinator(self.store)
        self.identity = DeploymentAuthorityIdentity(
            fingerprint("0"), fingerprint("1"), fingerprint("c"), self.state_id,
            fingerprint("d"), "a" * 40, fingerprint("e"),
            RuntimeBinding("roundwright-runtime/v1", "sha256:" + "0" * 64, "sha256:" + "1" * 64, ("sha256:" + "2" * 64,)),
        )
        self.receipt = DeploymentAuthorityHandoffReceipt(
            fingerprint("f"), self.identity, self.now - timedelta(minutes=1), self.now + timedelta(minutes=1),
        )
        self.verification = DeploymentAuthorityReceiptVerification(
            fingerprint("7"), self.receipt.receipt_fingerprint, self.receipt.binding_digest,
            self.identity.repository_fingerprint, self.identity.state_store_fingerprint, self.identity.state_id,
            self.identity.candidate_sha, self.identity.environment_fingerprint, AuthorityReceiptVerificationStatus.FRESH,
        )
        self.installation = NativeHostInstallation(fingerprint("8"), self.identity, self.receipt)

    def install(self):
        self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
        self.assertTrue(self.coordinator.claim_orchestrator(self.receipt, claim_fingerprint=fingerprint("9"), now=self.now).authorized)
        host, decision = install_native_host(self.coordinator, self.installation, now=self.now)
        self.assertTrue(decision.accepted)
        self.assertIsNotNone(host)
        assert host is not None
        return host

    def test_install_requires_an_existing_exclusive_authority_claim(self) -> None:
        self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
        host, decision = install_native_host(self.coordinator, self.installation, now=self.now)
        self.assertIsNone(host)
        self.assertFalse(decision.accepted)

    def test_one_shot_and_scheduler_wake_share_admission_and_lifecycle(self) -> None:
        host = self.install()
        direct = host.run_once("one-shot-1", now=self.now)
        self.assertTrue(direct.accepted)
        self.assertEqual(host.state, NativeHostState.RUNNING)
        self.assertFalse(host.request_scheduler_wake("wake-1", now=self.now).accepted)
        self.assertTrue(host.complete("one-shot-1").accepted)
        wake = host.request_scheduler_wake("wake-1", now=self.now)
        self.assertTrue(wake.accepted)
        self.assertIn("scheduler-wake", wake.reason)
        self.assertTrue(host.complete("wake-1").accepted)
        self.assertFalse(host.run_once("wake-1", now=self.now).accepted)
        self.assertEqual(host.state, NativeHostState.IDLE)

    def test_stale_authority_cannot_start_or_wake_a_process(self) -> None:
        host = self.install()
        stale = self.now + timedelta(minutes=2)
        self.assertFalse(host.run_once("stale-direct", now=stale).accepted)
        self.assertFalse(host.request_scheduler_wake("stale-wake", now=stale).accepted)
        self.assertEqual(host.state, NativeHostState.IDLE)

    def test_stop_requires_process_reconciliation_and_is_terminal(self) -> None:
        host = self.install()
        self.assertTrue(host.run_once("process-1", now=self.now).accepted)
        self.assertFalse(host.stop().accepted)
        self.assertTrue(host.complete("process-1").accepted)
        self.assertTrue(host.stop().accepted)
        self.assertEqual(host.state, NativeHostState.STOPPED)
        self.assertFalse(host.run_once("process-2", now=self.now).accepted)
        self.assertTrue(host.stop().accepted)

    def test_competing_coordinator_cannot_install_with_a_copied_receipt(self) -> None:
        self.install()
        competitor = DeploymentAuthorityHandoffCoordinator(self.store)
        other_host, installation = install_native_host(competitor, self.installation, now=self.now)
        self.assertIsNone(other_host)
        self.assertFalse(installation.accepted)


if __name__ == "__main__":
    unittest.main()
