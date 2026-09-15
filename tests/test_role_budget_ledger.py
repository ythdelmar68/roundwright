"""Provider-free durability tests for exact advisory-role budget reservations."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.role_capability_policy import (
    AdvisoryRole, DurableRoleBudgetLedger, ExecutionInstanceBinding,
    RoleBudget, RoleCapabilityError,
)


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def binding(identity: str, *, profile_name: str = "primary") -> ExecutionInstanceBinding:
    return ExecutionInstanceBinding(
        digest("repository"), "task-136", "a" * 40, digest("instance-" + profile_name),
        digest("host"), digest("deployment"), 1, "generation-13",
        AdvisoryRole.SUPERVISOR,
        ProviderProfile("gpt-5.6-sol", ReasoningEffort.HIGH, profile_name),
        identity, digest("preflight-" + identity),
    )


class DurableRoleBudgetLedgerTests(unittest.TestCase):
    def test_full_exposure_denies_second_dispatch_after_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "role-budget.sqlite"
            exact = binding("attempt-a")
            budget = RoleBudget(1, 60, 4_000)
            first = DurableRoleBudgetLedger(
                path, grant_receipt_digest=digest("grant"),
                execution_binding=exact, budget=budget,
            )
            reserved = first.reserve_effect(exposure=budget)
            self.assertEqual((reserved.calls, reserved.duration_seconds, reserved.tokens), (1, 60, 4_000))
            readback = first.require_reserved(exposure=budget)
            self.assertEqual((readback.calls, readback.duration_seconds, readback.tokens), (1, 60, 4_000))
            reconstructed = DurableRoleBudgetLedger(
                path, grant_receipt_digest=digest("grant"),
                execution_binding=exact, budget=budget,
            )
            with self.assertRaisesRegex(RoleCapabilityError, "exhausted"):
                reconstructed.reserve_effect(exposure=budget)

    def test_concurrent_final_slot_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "role-budget.sqlite"
            exact = binding("attempt-concurrent")
            budget = RoleBudget(1, 1, 1)
            barrier = threading.Barrier(8)
            results: list[str] = []

            def reserve() -> None:
                ledger = DurableRoleBudgetLedger(
                    path, grant_receipt_digest=digest("grant"),
                    execution_binding=exact, budget=budget,
                )
                barrier.wait()
                try:
                    ledger.reserve_effect(exposure=budget)
                    results.append("allowed")
                except RoleCapabilityError:
                    results.append("denied")

            workers = [threading.Thread(target=reserve) for _ in range(8)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()
            self.assertEqual(results.count("allowed"), 1)
            self.assertEqual(results.count("denied"), 7)

    def test_fallback_is_recorded_under_its_own_exact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "role-budget.sqlite"
            primary = binding("attempt-primary", profile_name="primary")
            fallback = binding("attempt-fallback", profile_name="fallback")
            budget = RoleBudget(1, 60, 4_000)
            for exact in (primary, fallback):
                DurableRoleBudgetLedger(
                    path, grant_receipt_digest=digest("grant-" + exact.provider_profile.name),
                    execution_binding=exact, budget=budget,
                ).reserve_effect(exposure=budget)
            connection = sqlite3.connect(path)
            try:
                rows = connection.execute(
                    "SELECT binding_digest, calls, duration_seconds, tokens "
                    "FROM role_budget_usage ORDER BY binding_digest"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(
                rows,
                sorted(((primary.digest, 1, 60, 4_000), (fallback.digest, 1, 60, 4_000))),
            )

    def test_readback_rejects_duration_or_token_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "role-budget.sqlite"
            exact = binding("attempt-tamper")
            budget = RoleBudget(1, 60, 4_000)
            ledger = DurableRoleBudgetLedger(
                path, grant_receipt_digest=digest("grant"),
                execution_binding=exact, budget=budget,
            )
            ledger.reserve_effect(exposure=budget)
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    "UPDATE role_budget_usage SET duration_seconds=59, tokens=3999"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(RoleCapabilityError, "drifted"):
                ledger.require_reserved(exposure=budget)


if __name__ == "__main__":
    unittest.main()
