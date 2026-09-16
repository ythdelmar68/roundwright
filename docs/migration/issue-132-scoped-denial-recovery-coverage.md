# Issue 132 scoped-denial and recovery coverage

Issue #132 qualifies the provider-neutral `roundwright-failure-recovery/v1`
contract and the durable Supervisor accounting path.  It binds production
denial classification, restart reconstruction, append-only clearance and
revocation, and same-profile format correction ordinals to one candidate-bound
semantic receipt.  It neither activates a provider nor publishes provider
output.

The authoritative affected-module regression set also includes
`candidate_review.py`: its within-round dispatch test supplies the exact
preceding durable Supervisor coordinates before exercising profile 2+.
Consequently, a fresh production history can still begin only at logical
profile 1 / physical ordinal 0, while an established round can progress to
its later declared profiles.

| E1R2 finding | Requirement | Producer | Public-safe consuming gate |
| --- | --- | --- | --- |
| E1R2-01 | Production Worker preserves an authenticated typed denial, while an out-of-order tool protocol remains ambiguous and cannot mint a substitute turn | `codex_worker.py` native seam | `test_codex_worker.test_typed_denial_and_transport_failure_remain_typed` |
| E1R2-02 | Production Supervisor denial stops before any prebound fallback | `codex_supervisor.py` native seam | `test_codex_supervisor.test_security_denial_stops_before_a_prebound_profile_fallback` |
| E1R2-03 | Dependency-review restart denial blocks before a second provider session | `codex_dependency_review.py` native seam | `test_codex_dependency_review.test_restart_scope_denial_blocks_before_dependency_provider_session` |
| E1R2-04 | Only authenticated verified transient evidence reaches the prebound equivalent route | `failure_recovery.py` admission | `test_failure_recovery.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route` |
| E1R2-05 | Incompatible, unknown, and tampered evidence fail closed | `failure_recovery.py` closed parser and matrix | `test_failure_recovery.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories` |
| E1R2-06 | Missing or stale authoritative durable read-back is not accepted | `provider_recovery.py` read-back gate | `test_provider_recovery.test_durable_failure_readback_revalidates_current_admission_authority` |
| E1R2-07 | Fabricated, replayed, stale, cross-task, and revoked clearances remain closed until an exact newer decision | `failure_recovery.py` clearance ledger | `test_provider_recovery.test_durable_clearance_and_revocation_are_append_only_and_restart_verified` |
| E1R2-08 | Duplicate, gapped, regressive, and conflicting attempt coordinates fail closed | `provider_recovery.py` coordinate ledger | `test_provider_recovery.test_supervisor_coordinates_are_unique_and_strictly_monotonic` |
| E1R3-01 | A security denial can reopen only through a dedicated, single-use clear/revoke authority bound to the exact denial, repository/task, candidate seal, scope, target, and verified-host result; generic review-item commands are inert | `failure_recovery.py` denial ledger | `test_provider_recovery.test_durable_clearance_and_revocation_are_append_only_and_restart_verified` |

## E1R3 stable finding closure

The qualification validator pins every E1R3 review finding by its stable
identifier. `RW132-PROD-001`, `RW132-RECOVERY-002`, `RW132-BINDING-003`,
`RW132-DURABLE-004`, `RW132-EVIDENCE-005`, `RW132-TAXONOMY-006`,
`RW132-ACCOUNTING-007`, and `RW132-QUALIFICATION-008` each name an exact
production boundary and executable test. In particular, a transient Supervisor
successor consumes a durable route before dispatch; an UNKNOWN dependency review
is a reconciliation-required terminal decision; revocation authenticates its
exact predecessor clearance; and fresh production coordinates begin at logical
profile 1 / physical ordinal 0. The map and receipt reject omitted, reordered,
or stale entries.

This extends #112's public-safe coverage destinations with public type names,
case identities, and record digests only.  It does not rewrite historical
receipts, publish provider output, or establish live-provider qualification.

The durable state migration retains an idempotent canonical record per digest.
The original denial remains immutable: an explicit verified-host clearance is a
new decision bound to the same candidate, policy, configuration, scope, role,
profile, session, and attempt.  The record seals a closed, versioned clearance
condition set and its exact provenance binding.  A separate authority and
command namespace binds the denial digest, repository/task, current candidate
seal, scope, target, command result, and verified-host result; the generic
review-item command tables have no clearance read path.  Changed binding,
unavailable evidence, replayed command, malformed provenance, or an unapproved
route fails closed.

The receipt also executes independently pinned continuation checks: restart
continues only the next format ordinal, bounded profile/format retries exhaust
before a fourth dispatch, and a terminal denial retains its original class
across restart. Windows has no omitted cases in this hermetic slice; its empty
skip declaration is sealed in the semantic receipt.

## E1R6 recovery closure

`RW132-RECOVERY-002` now treats route consumption, its sealed exact budget
reservation, and first successor admission as one recoverable local boundary.
If local admission fails after consumption but before a provider turn, the
route is restored only when its exact reservation digest still matches and the
reservation is released. `RW132-PROD-001` separately permits successor
dispatch only for durable `SYNTAX` and `SHAPE` invalid outcomes; `CONTEXT`,
`CANDIDATE`, `NON_FINAL`, and every unclassified invalid outcome remain
terminal with zero successor effects. The qualification inventory pins both
the exact route-release replay and every non-format-invalid denial case.

## E1R7 fenced successor admission

An eligible recovery route now moves through `issued`, `reserving`, and
`consumed`. The route fence is durable before the separate role-budget ledger
reservation; a restart that finds an unadmitted fence releases only its exact
reservation (if one exists), restores the route, and then retries. A prepared
provider or dependency-review successor instead recovers its original sealed
reservation and commits the route idempotently, so it is never released and
re-reserved on restart. The generic Supervisor path records a durable successor
admission in the same transaction as its route consumption before native
dispatch. Three injected interruption tests pin those provider-runtime,
dependency-review, and generic-Supervisor interleavings; no successor session
or turn is opened until the appropriate admission is durable.

## E1R7 correction closure

The qualification inventory now pins production-path adversarial boundaries:
an `INVALID` dependency predecessor cannot create a successor budget or native
session; a one-shot dependency pre-dispatch claim blocks a restart before
native session creation; and FileSupervisorLifecycle replays only an exact
authenticated plan after a generic Supervisor restart.  A profile transition
without a durable terminal route fails before a provider attempt.  The
single-use route release helper also rejects every route that already has a
durable successor admission, so an admitted turn cannot be re-armed.
