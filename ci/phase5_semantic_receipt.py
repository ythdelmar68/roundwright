"""Execute the closed Phase 5 adversarial contracts and seal their result."""
from __future__ import annotations

import argparse, hashlib, json, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TESTS = (
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_direct_production_runtime_construction_denies_before_provider_or_local_effect",
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_fabricated_direct_runtime_dispatch_denies_before_any_effect",
    "tests.test_worker_toolbox.WorkerToolboxTests.test_sealed_launch_context_rejects_coherent_public_instruction_mutation",
    "tests.test_coding_tools.BoundedCodingToolsTests.test_scope_root_label_cannot_authorize_a_different_resolved_workspace",
    "tests.test_role_capability_policy.RoleCapabilityPolicyTests.test_scope_traversal_unknown_descriptors_and_capability_expansion_fail_closed",
    "tests.test_codex_worker.CodexWorkerAdapterTests.test_typed_denial_and_transport_failure_remain_typed",
    "tests.test_codex_supervisor.SupervisorTests.test_security_denial_stops_before_a_prebound_profile_fallback",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_scope_denial_blocks_before_dependency_provider_session",
    "tests.test_failure_recovery.FailureRecoveryTests.test_denial_blocks_same_scope_across_restart_until_exact_clearance",
    "tests.test_failure_recovery.FailureRecoveryTests.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route",
    "tests.test_failure_recovery.FailureRecoveryTests.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories",
    "tests.test_failure_recovery.FailureRecoveryTests.test_closed_record_parser_rejects_tampered_or_unknown_payload",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_failure_readback_revalidates_current_admission_authority",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_supervisor_coordinates_are_unique_and_strictly_monotonic",
    "tests.test_candidate_review.CandidateReviewTests.test_diff_dispatch_requires_the_exact_within_round_profile",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_terminal_block_and_invalid_output_replays_keep_their_original_classification",
    "tests.test_codex_supervisor.SupervisorTests.test_ambiguous_and_incomplete_results_stop_before_fallback",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure",
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_hermetic_production_runtime_persists_typed_terminal_failure_and_blocks_restart_before_dispatch",
    "tests.test_codex_supervisor.SupervisorTests.test_sequence_advances_invalid_primary_to_valid_fallback",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_typed_blocked_turn_records_a_shared_durable_failure_from_the_session_claim",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_of_an_authoritative_session_claim_has_zero_later_provider_or_budget_effects",
    "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_unknown_predecessor_requires_reconciliation_before_successor_effect",
    "tests.test_codex_supervisor.SupervisorTests.test_every_non_format_invalid_stops_before_successor",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_recovery_route_is_exact_single_use_and_restart_safe",
)
WINDOWS_DECLARED_SKIPS: tuple[str, ...] = ()

def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def current() -> str:
    return subprocess.run(("git", "rev-parse", "HEAD"), cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


class _SemanticResult(unittest.TextTestResult):
    """Capture exact test identities instead of trusting an exit status."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed: list[str] = []
        self.skipped_ids: list[str] = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

    def addSkip(self, test, reason):
        self.skipped_ids.append(test.id())
        super().addSkip(test, reason)


def _run_declared_tests() -> tuple[tuple[str, ...], tuple[str, ...]]:
    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromNames(TESTS)
    result = unittest.TextTestRunner(verbosity=2, resultclass=_SemanticResult).run(suite)
    executed, skipped = tuple(result.executed), tuple(result.skipped_ids)
    if result.errors or result.failures or result.unexpectedSuccesses:
        raise SystemExit("Phase 5 semantic tests failed")
    if len(executed) != len(TESTS) or set(executed) != set(TESTS) or len(set(executed)) != len(executed):
        raise SystemExit("Phase 5 semantic tests did not execute the declared inventory")
    expected_skips = WINDOWS_DECLARED_SKIPS if sys.platform == "win32" else ()
    if skipped != expected_skips:
        raise SystemExit("Phase 5 semantic tests have undeclared or missing skips")
    if tuple(test for test in executed if test not in skipped) != tuple(test for test in TESTS if test not in skipped):
        raise SystemExit("Phase 5 semantic tests did not complete the declared inventory")
    return executed, skipped

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--candidate",required=True); parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.candidate != current() or len(args.candidate) != 40: raise SystemExit("candidate is not checked out")
    executed, skipped = _run_declared_tests()
    payload={"schema":"roundwright-phase5-semantic-execution/v3","candidate_sha":args.candidate,"tests":TESTS,"executed_tests":executed,"skipped_tests":skipped,"windows_declared_skips":WINDOWS_DECLARED_SKIPS,"status":"passed"}
    receipt={**payload,"receipt_digest":digest(payload)}
    args.output.write_bytes(canonical(receipt)+b"\n")
    return 0

if __name__ == "__main__": raise SystemExit(main())
