"""Hermetic deployment-authority and command-shell coverage."""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
from uuid import UUID

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.cli import main
from roundwright.deployment import (
    AuthorityReceiptStatus,
    AuthorityReceiptVerification,
    DeploymentAuthorityReceipt,
    DeploymentIdentity,
    DeploymentMode,
    evaluate_deployment_authority,
)


def fingerprint(character: str) -> str:
    return character * 64


class DeploymentAuthorityTests(unittest.TestCase):
    now = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)

    def identity(self, deployment: str = "e") -> DeploymentIdentity:
        return DeploymentIdentity(
            fingerprint("a"), fingerprint("b"), fingerprint("c"),
            UUID("12345678-1234-5678-1234-567812345678"), fingerprint(deployment),
        )

    def receipt(self, identity: DeploymentIdentity) -> DeploymentAuthorityReceipt:
        return DeploymentAuthorityReceipt(
            fingerprint("d"), identity, DeploymentMode.AUTHORITATIVE,
            self.now - timedelta(minutes=1), self.now + timedelta(minutes=1),
        )

    def verification(
        self, identity: DeploymentIdentity, receipt: DeploymentAuthorityReceipt, *,
        deployment: str | None = None, status: AuthorityReceiptStatus = AuthorityReceiptStatus.FRESH,
    ) -> AuthorityReceiptVerification:
        return AuthorityReceiptVerification(
            receipt.receipt_fingerprint, identity.repository_fingerprint, identity.state_id,
            identity.deployment_fingerprint if deployment is None else fingerprint(deployment), status,
        )

    def test_read_only_and_test_only_need_no_dispatch_receipt(self) -> None:
        read_only = evaluate_deployment_authority(None, mode=DeploymentMode.READ_ONLY, now=self.now)
        test_only = evaluate_deployment_authority(None, mode=DeploymentMode.TEST_ONLY, now=self.now)
        self.assertEqual(read_only.mode, DeploymentMode.READ_ONLY)
        self.assertFalse(read_only.authorized)
        self.assertEqual(test_only.mode, DeploymentMode.TEST_ONLY)
        self.assertFalse(test_only.authorized)

    def test_exact_current_external_receipt_passes_authority_preflight(self) -> None:
        identity = self.identity()
        receipt = self.receipt(identity)
        decision = evaluate_deployment_authority(identity, receipt, self.verification(identity, receipt), now=self.now)
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.mode, DeploymentMode.AUTHORITATIVE)
        self.assertEqual(decision.receipt_fingerprint, receipt.receipt_fingerprint)

    def test_missing_expired_and_conflicting_receipts_fail_closed(self) -> None:
        identity = self.identity()
        receipt = self.receipt(identity)
        cases = (
            (None, None),
            (receipt, self.verification(identity, receipt, status=AuthorityReceiptStatus.EXPIRED)),
            (receipt, self.verification(identity, receipt, status=AuthorityReceiptStatus.COPIED)),
            (receipt, self.verification(identity, receipt, status=AuthorityReceiptStatus.CONFLICTING)),
        )
        for supplied_receipt, verification in cases:
            with self.subTest(status=verification.status if verification else None):
                decision = evaluate_deployment_authority(identity, supplied_receipt, verification, now=self.now)
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.mode, DeploymentMode.BLOCKED)

    def test_wrong_repository_checkout_state_and_deployment_fail_closed(self) -> None:
        identity = self.identity()
        receipt = self.receipt(identity)
        for changed in (
            DeploymentIdentity(fingerprint("0"), fingerprint("b"), fingerprint("c"), identity.state_id, fingerprint("e")),
            DeploymentIdentity(fingerprint("a"), fingerprint("0"), fingerprint("c"), identity.state_id, fingerprint("e")),
            DeploymentIdentity(fingerprint("a"), fingerprint("b"), fingerprint("0"), identity.state_id, fingerprint("e")),
            DeploymentIdentity(fingerprint("a"), fingerprint("b"), fingerprint("c"), UUID("87654321-4321-8765-4321-876543218765"), fingerprint("e")),
            DeploymentIdentity(fingerprint("a"), fingerprint("b"), fingerprint("c"), identity.state_id, fingerprint("0")),
        ):
            with self.subTest(changed=changed):
                decision = evaluate_deployment_authority(changed, receipt, self.verification(identity, receipt), now=self.now)
                self.assertFalse(decision.authorized)

    def test_second_deployment_cannot_pass_the_same_external_designation(self) -> None:
        first = self.identity("e")
        second = self.identity("f")
        receipt = self.receipt(second)
        verification = self.verification(second, receipt, deployment="e")
        decision = evaluate_deployment_authority(second, receipt, verification, now=self.now)
        self.assertFalse(decision.authorized)
        self.assertIn("different deployment", decision.reason)

    def test_expired_receipt_window_fails_closed(self) -> None:
        identity = self.identity()
        receipt = DeploymentAuthorityReceipt(
            fingerprint("d"), identity, DeploymentMode.AUTHORITATIVE,
            self.now - timedelta(minutes=2), self.now - timedelta(minutes=1),
        )
        decision = evaluate_deployment_authority(identity, receipt, self.verification(identity, receipt), now=self.now)
        self.assertFalse(decision.authorized)

    def test_command_shells_stop_without_filesystem_git_network_or_dispatch(self) -> None:
        for command in ("run-once", "run-daemon"):
            output = io.StringIO()
            with self.subTest(command=command), contextlib.redirect_stdout(output), mock.patch(
                "builtins.open", side_effect=AssertionError("filesystem access")
            ), mock.patch("subprocess.run", side_effect=AssertionError("Git access")):
                result = main([command])
            self.assertEqual(result, 3)
            self.assertIn("result: blocked", output.getvalue())
            self.assertIn("dispatch: not started", output.getvalue())

    def test_status_and_doctor_render_each_deployment_mode(self) -> None:
        for command in ("status", "doctor"):
            output = io.StringIO()
            with self.subTest(command=command), contextlib.redirect_stdout(output):
                result = main([command])
            if command == "status":
                self.assertEqual(result, 0)
            rendered = output.getvalue()
            for mode in ("read-only", "test-only", "authoritative", "blocked"):
                self.assertIn(mode, rendered)
