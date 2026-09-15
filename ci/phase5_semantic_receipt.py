"""Execute the closed Issue 136 adversarial contract and seal its result."""
from __future__ import annotations

import argparse, hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_direct_production_runtime_construction_denies_before_provider_or_local_effect",
    "tests.test_production_coding_runtime.ProductionRuntimeTests.test_fabricated_direct_runtime_dispatch_denies_before_any_effect",
    "tests.test_worker_toolbox.WorkerToolboxTests.test_sealed_launch_context_rejects_coherent_public_instruction_mutation",
    "tests.test_coding_tools.BoundedCodingToolsTests.test_scope_root_label_cannot_authorize_a_different_resolved_workspace",
    "tests.test_role_capability_policy.RoleCapabilityPolicyTests.test_scope_traversal_unknown_descriptors_and_capability_expansion_fail_closed",
    "tests.test_failure_recovery.FailureRecoveryTests.test_denial_blocks_same_scope_across_restart_until_exact_clearance",
    "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
    "tests.test_codex_supervisor.SupervisorTests.test_ambiguous_and_incomplete_results_stop_before_fallback",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
    "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure",
)

def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def current() -> str:
    return subprocess.run(("git", "rev-parse", "HEAD"), cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE).stdout.strip()

def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("--candidate",required=True); parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.candidate != current() or len(args.candidate) != 40: raise SystemExit("candidate is not checked out")
    result=subprocess.run((sys.executable,"-m","unittest",*TESTS),cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    if result.returncode: raise SystemExit("Phase 5 semantic tests failed")
    payload={"schema":"roundwright-phase5-semantic-execution/v1","candidate_sha":args.candidate,"tests":TESTS,"status":"passed"}
    receipt={**payload,"receipt_digest":digest(payload)}
    args.output.write_bytes(canonical(receipt)+b"\n")
    return 0

if __name__ == "__main__": raise SystemExit(main())
