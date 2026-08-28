"""Hermetic native-host installation and lifecycle parity coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
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
from roundwright.native_host import (
    NativeHostControlStore,
    NativeHostError,
    NativeHostInstallation,
    NativeHostPaths,
    NativeHostState,
    install_native_host,
)
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

    def test_platform_paths_are_explicit_and_unsupported_platforms_fail_closed(self) -> None:
        home = Path("C:/profiles/roundwright")
        worktree = Path("C:/repositories/roundwright")
        windows = NativeHostPaths.resolve(
            platform="win32", environment={"APPDATA": "C:/profile/roaming", "LOCALAPPDATA": "C:/profile/local"}, home=home, worktree=worktree
        )
        self.assertTrue(str(windows.configuration).replace("\\", "/").endswith("profile/roaming/Roundwright/config.toml"))
        self.assertTrue(str(windows.cache).replace("\\", "/").endswith("profile/local/Roundwright/Cache"))
        self.assertTrue(str(windows.authentication).replace("\\", "/").endswith("Roundwright/auth.toml"))
        macos = NativeHostPaths.resolve(platform="darwin", environment={}, home=home, worktree=worktree)
        self.assertTrue(str(macos.configuration).replace("\\", "/").endswith("Library/Application Support/roundwright/config.toml"))
        linux = NativeHostPaths.resolve(platform="linux", environment={}, home=home, worktree=worktree)
        self.assertTrue(str(linux.cache).replace("\\", "/").endswith(".cache/roundwright"))
        with self.assertRaisesRegex(NativeHostError, "unsupported"):
            NativeHostPaths.resolve(platform="plan9", environment={}, home=home, worktree=worktree)

    def test_durable_sqlite_lifecycle_serializes_children_and_recovers_stale_ones(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = self._bound_worktree(root / "repository")
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=worktree)
            self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
            self.assertTrue(self.coordinator.claim_orchestrator(self.receipt, claim_fingerprint=fingerprint("9"), now=self.now).authorized)
            host, installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(installed.accepted)
            self.assertIsNotNone(host)
            assert host is not None
            peer, peer_installation = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(peer_installation.accepted)
            self.assertIsNotNone(peer)
            assert peer is not None
            self.assertTrue(host.run_once("owned-child", now=self.now).accepted)
            self.assertFalse(peer.run_once("competing-child", now=self.now).accepted)
            self.assertTrue(host.cancel("owned-child", now=self.now).accepted)
            self.assertTrue(host.cancel("owned-child", now=self.now).accepted)
            self.assertTrue(peer.run_once("stale-child", now=self.now).accepted)
            self.assertFalse(host.recover_stale_child("stale-child", now=self.now, stale_after=timedelta(minutes=1)).accepted)
            self.assertTrue(host.recover_stale_child("stale-child", now=self.now + timedelta(minutes=2), stale_after=timedelta(minutes=1)).accepted)
            self.assertTrue(host.run_once("replacement-child", now=self.now).accepted)
            self.assertTrue(host.complete("replacement-child").accepted)
            self.assertTrue(paths.state_database.is_file())

    def test_durable_install_rejects_detached_worktree_and_candidate_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = self._bound_worktree(root / "repository")
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=worktree)
            self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
            self.assertTrue(self.coordinator.claim_orchestrator(self.receipt, claim_fingerprint=fingerprint("9"), now=self.now).authorized)
            host, installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(installed.accepted)
            self.assertIsNotNone(host)
            drifted_identity = replace(self.identity, candidate_sha="b" * 40)
            drifted_receipt = replace(self.receipt, identity=drifted_identity)
            drifted = NativeHostInstallation(fingerprint("6"), drifted_identity, drifted_receipt)
            self.assertFalse(NativeHostControlStore(paths.state_database).install(drifted).accepted)
            (worktree / ".git" / "HEAD").write_text("a" * 40 + "\n", encoding="utf-8")
            detached_host, detached = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertIsNone(detached_host)
            self.assertFalse(detached.accepted)
            self.assertIn("detached", detached.reason)

    def test_one_shot_wrapper_cleans_up_an_injected_child_action(self) -> None:
        host = self.install()
        invoked: list[str] = []
        decision = host.execute_one_shot("wrapped-child", lambda: invoked.append("ran"), now=self.now)
        self.assertTrue(decision.accepted)
        self.assertEqual(invoked, ["ran"])
        self.assertEqual(host.state, NativeHostState.IDLE)

    @staticmethod
    def _bound_worktree(root: Path) -> Path:
        root.mkdir()
        git = root / ".git"
        git.mkdir()
        (git / "HEAD").write_text("ref: refs/heads/codex/issue-90\n", encoding="utf-8")
        return root


if __name__ == "__main__":
    unittest.main()
