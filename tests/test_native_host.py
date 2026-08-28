"""Hermetic native-host installation and lifecycle parity coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
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
    InvocationSource,
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
        self.assertTrue(windows.configuration.is_absolute())
        self.assertNotEqual(windows.cache, windows.state_directory)
        macos = NativeHostPaths.resolve(platform="darwin", environment={}, home=Path("/Users/roundwright"), worktree=Path("/repositories/roundwright"))
        self.assertTrue(str(macos.configuration).replace("\\", "/").endswith("Library/Application Support/roundwright/config.toml"))
        self.assertTrue(macos.configuration.is_absolute())
        linux = NativeHostPaths.resolve(platform="linux", environment={}, home=Path("/home/roundwright"), worktree=Path("/repositories/roundwright"))
        self.assertTrue(str(linux.cache).replace("\\", "/").endswith(".cache/roundwright"))
        self.assertTrue(linux.cache.is_absolute())
        with self.assertRaisesRegex(NativeHostError, "unsupported"):
            NativeHostPaths.resolve(platform="plan9", environment={}, home=home, worktree=worktree)
        with self.assertRaisesRegex(NativeHostError, "worktree path is not absolute"):
            NativeHostPaths.resolve(platform="linux", environment={}, home=Path("/home/roundwright"), worktree=Path("relative-worktree"))

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
            self.assertFalse(peer.complete("owned-child", now=self.now).accepted)
            self.assertTrue(host.cancel("owned-child", now=self.now).accepted)
            self.assertTrue(host.cancel("owned-child", now=self.now).accepted)
            self.assertTrue(peer.run_once("stale-child", now=self.now).accepted)
            interval = timedelta(seconds=1, microseconds=500000)
            self.assertFalse(host.recover_stale_child("stale-child", now=self.now + timedelta(seconds=1, microseconds=499999), stale_after=interval).accepted)
            self.assertTrue(host.recover_stale_child("stale-child", now=self.now + timedelta(minutes=2), stale_after=interval).accepted)
            self.assertTrue(host.run_once("replacement-child", now=self.now).accepted)
            self.assertTrue(host.complete("replacement-child", now=self.now).accepted)
            self.assertTrue(paths.state_database.is_file())

    def test_live_child_lease_blocks_peer_recovery_and_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=self._bound_worktree(root / "repository"))
            self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
            self.assertTrue(self.coordinator.claim_orchestrator(self.receipt, claim_fingerprint=fingerprint("9"), now=self.now).authorized)
            host, installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(installed.accepted)
            assert host is not None
            peer, peer_installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(peer_installed.accepted)
            assert peer is not None
            self.assertTrue(host.run_once("live-child", now=self.now).accepted)
            self.assertTrue(host.renew_child_lease("live-child", now=self.now + timedelta(seconds=30), lease_for=timedelta(minutes=2)).accepted)
            self.assertFalse(peer.recover_stale_child("live-child", now=self.now + timedelta(minutes=1), stale_after=timedelta(seconds=1)).accepted)
            self.assertFalse(peer.run_once("replacement-child", now=self.now + timedelta(minutes=1)).accepted)
            self.assertEqual(host.state, NativeHostState.RUNNING)

    def test_cache_removal_cannot_remove_durable_process_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=self._bound_worktree(root / "repository"))
            self.assertTrue(self.coordinator.activate_initial(self.receipt, self.verification, now=self.now).authorized)
            self.assertTrue(self.coordinator.claim_orchestrator(self.receipt, claim_fingerprint=fingerprint("9"), now=self.now).authorized)
            host, installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(installed.accepted)
            assert host is not None
            peer, peer_installed = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertTrue(peer_installed.accepted)
            assert peer is not None
            self.assertTrue(host.run_once("durable-child", now=self.now).accepted)
            assert isinstance(paths.cache, Path)
            paths.cache.mkdir(parents=True, exist_ok=True)
            (paths.cache / "evictable").write_text("cache", encoding="utf-8")
            shutil.rmtree(paths.cache)
            self.assertTrue(paths.state_database.is_file())
            self.assertFalse(peer.run_once("replacement-child", now=self.now).accepted)

    def test_stale_deadline_uses_exact_microseconds_at_far_future_dates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=self._bound_worktree(root / "repository"))
            store = NativeHostControlStore(paths.state_database)
            self.assertTrue(store.install(self.installation).accepted)
            far_future = datetime(9999, 1, 1, 12, 0, tzinfo=timezone.utc)
            self.assertTrue(store.admit(self.installation, "future-child", source=InvocationSource.ONE_SHOT, now=far_future, lease_for=timedelta(microseconds=1)).accepted)
            self.assertFalse(store.recover_stale(self.installation, "future-child", now=far_future, stale_after=timedelta(microseconds=1)).accepted)
            self.assertTrue(store.recover_stale(self.installation, "future-child", now=far_future + timedelta(microseconds=1), stale_after=timedelta(microseconds=1)).accepted)

    def test_state_database_filesystem_failures_are_public_safe_denials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=self._bound_worktree(root / "repository"))
            with mock.patch.object(Path, "mkdir", side_effect=OSError("denied")):
                decision = NativeHostControlStore(paths.state_database).install(self.installation)
            self.assertFalse(decision.accepted)
            self.assertEqual(decision.reason, "native host state database is unavailable")

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
            (worktree / ".git" / "refs" / "heads" / "codex" / "issue-90").write_text("b" * 40 + "\n", encoding="utf-8")
            drifted_host, drifted_decision = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertIsNone(drifted_host)
            self.assertFalse(drifted_decision.accepted)
            self.assertIn("candidate SHA", drifted_decision.reason)
            (worktree / ".git" / "HEAD").write_text("a" * 40 + "\n", encoding="utf-8")
            detached_host, detached = install_native_host(self.coordinator, self.installation, now=self.now, paths=paths)
            self.assertIsNone(detached_host)
            self.assertFalse(detached.accepted)
            self.assertIn("detached", detached.reason)

    def test_linked_worktree_resolves_its_common_head_to_the_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            worktree.mkdir()
            metadata = root / "metadata"
            metadata.mkdir()
            common = root / "common"
            (common / "refs" / "heads" / "codex").mkdir(parents=True)
            (common / "refs" / "heads" / "codex" / "issue-90").write_text("a" * 40 + "\n", encoding="utf-8")
            (metadata / "HEAD").write_text("ref: refs/heads/codex/issue-90\n", encoding="utf-8")
            (metadata / "commondir").write_text("../common\n", encoding="utf-8")
            (worktree / ".git").write_text("gitdir: ../metadata\n", encoding="utf-8")
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=worktree)
            paths.require_authoritative_worktree(self.identity.candidate_sha)
            loose = common / "refs" / "heads" / "codex" / "issue-90"
            (common / "packed-refs").write_text("a" * 40 + " refs/heads/codex/issue-90\n", encoding="utf-8")
            loose.write_text("malformed\n", encoding="utf-8")
            with self.assertRaisesRegex(NativeHostError, "loose worktree reference is malformed"):
                paths.require_authoritative_worktree(self.identity.candidate_sha)
            loose.unlink()
            paths.require_authoritative_worktree(self.identity.candidate_sha)

    def test_loose_worktree_refs_fail_closed_before_packed_ref_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = self._bound_worktree(root / "repository")
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=worktree)
            loose = worktree / ".git" / "refs" / "heads" / "codex" / "issue-90"
            packed = worktree / ".git" / "packed-refs"
            packed.write_text("a" * 40 + " refs/heads/codex/issue-90\n", encoding="utf-8")
            loose.write_text("malformed\n", encoding="utf-8")
            with self.assertRaisesRegex(NativeHostError, "loose worktree reference is malformed"):
                paths.require_authoritative_worktree(self.identity.candidate_sha)
            original_read = Path.read_text

            def deny_loose(path: Path, *args: object, **kwargs: object) -> str:
                if path == loose:
                    raise PermissionError("denied")
                return original_read(path, *args, **kwargs)

            loose.write_text("a" * 40 + "\n", encoding="utf-8")
            with mock.patch.object(Path, "read_text", new=deny_loose):
                with self.assertRaisesRegex(NativeHostError, "loose worktree reference is unreadable"):
                    paths.require_authoritative_worktree(self.identity.candidate_sha)
            loose.unlink()
            paths.require_authoritative_worktree(self.identity.candidate_sha)

    def test_worktree_branch_references_reject_traversal_absolute_and_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = self._bound_worktree(root / "repository")
            paths = NativeHostPaths.resolve(platform=sys.platform, environment={}, home=root / "home", worktree=worktree)
            head = worktree / ".git" / "HEAD"
            for reference in ("refs/heads/../../candidate", "refs/heads//candidate", "refs/heads/C:/candidate", "refs/heads/candidate\x01"):
                head.write_text(f"ref: {reference}\n", encoding="utf-8")
                with self.assertRaisesRegex(NativeHostError, "reference is malformed"):
                    paths.require_authoritative_worktree(self.identity.candidate_sha)

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
        reference = git / "refs" / "heads" / "codex"
        reference.mkdir(parents=True)
        (reference / "issue-90").write_text("a" * 40 + "\n", encoding="utf-8")
        return root


if __name__ == "__main__":
    unittest.main()
