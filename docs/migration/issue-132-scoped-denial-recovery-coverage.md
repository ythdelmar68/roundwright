# Issue 132 scoped-denial and recovery coverage

Issue #132 qualifies the provider-neutral `roundwright-failure-recovery/v1`
contract and the durable Supervisor accounting path.  It binds production
denial classification, restart reconstruction, append-only clearance and
revocation, and same-profile format correction ordinals to one candidate-bound
semantic receipt.  It neither activates a provider nor publishes provider
output.

| E1R2 finding | Requirement | Producer | Public-safe consuming gate |
| --- | --- | --- | --- |
| E1R2-01 | Production Worker denial stays typed and cannot mint a substitute turn | `codex_worker.py` native seam | `test_codex_worker.test_typed_denial_and_transport_failure_remain_typed` |
| E1R2-02 | Production Supervisor denial stops before any prebound fallback | `codex_supervisor.py` native seam | `test_codex_supervisor.test_security_denial_stops_before_a_prebound_profile_fallback` |
| E1R2-03 | Dependency-review restart denial blocks before a second provider session | `codex_dependency_review.py` native seam | `test_codex_dependency_review.test_restart_scope_denial_blocks_before_dependency_provider_session` |
| E1R2-04 | Only authenticated verified transient evidence reaches the prebound equivalent route | `failure_recovery.py` admission | `test_failure_recovery.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route` |
| E1R2-05 | Incompatible, unknown, and tampered evidence fail closed | `failure_recovery.py` closed parser and matrix | `test_failure_recovery.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories` |
| E1R2-06 | Missing or stale authoritative durable read-back is not accepted | `provider_recovery.py` read-back gate | `test_provider_recovery.test_durable_failure_readback_revalidates_current_admission_authority` |
| E1R2-07 | Fabricated, replayed, stale, cross-task, and revoked clearances remain closed until an exact newer decision | `failure_recovery.py` clearance ledger | `test_provider_recovery.test_durable_clearance_and_revocation_are_append_only_and_restart_verified` |
| E1R2-08 | Duplicate, gapped, regressive, and conflicting attempt coordinates fail closed | `provider_recovery.py` coordinate ledger | `test_provider_recovery.test_supervisor_coordinates_are_unique_and_strictly_monotonic` |

This extends #112's public-safe coverage destinations with public type names,
case identities, and record digests only.  It does not rewrite historical
receipts, publish provider output, or establish live-provider qualification.

The durable state migration retains an idempotent canonical record per digest.
The original denial remains immutable: an explicit verified-host clearance is a
new decision bound to the same candidate, policy, configuration, scope, role,
profile, session, and attempt.  Changed binding, unavailable evidence, or an
unapproved route fails closed.

The receipt also executes independently pinned continuation checks: restart
continues only the next format ordinal, bounded profile/format retries exhaust
before a fourth dispatch, and a terminal denial retains its original class
across restart. Windows has no omitted cases in this hermetic slice; its empty
skip declaration is sealed in the semantic receipt.
