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

The qualification inventory pins production-path adversarial boundaries:
dependency supersession requires a canonical blocked `sdk-turn-failed` outcome,
the prebound transient owner route, and one exact verified-service decision.
Invalid, accepted, missing, ambiguous, unverified, and corrupted predecessors
are rejected before budget reservation or successor lineage creation.

The dependency crash regression kills execution after native session opening
but before its session identity callback. The earlier durable one-shot claim
makes restart ambiguous without another session or another budget debit.

`RW132-SUPERVISOR-FENCE-011` runs the full qualification dispatcher with file
lifecycle and runtime stores. It injects process death after plan creation,
route fencing, budget reservation, atomic successor admission, and native
session opening. Exact pre-effect restarts reconstruct the original invalid
event, source decision, and reservations; they do not repeat the predecessor.
Admission, budget, and dispatch-claim drift fail closed. This is dispatcher
recovery evidence, not merely a lifecycle `prepare` replay test.

The provider-runtime regression rejects a format-invalid profile jump on
fresh execution and restart, including exhaustion at physical ordinal two.
Only a separately authenticated terminal recovery route can change profiles.
The release-helper storage tests reject both a generic successor admission
and existing provider/dependency successor rows, preserving consumed state.
The map seals the runtime store and all affected shared #136 artifacts as
well as the #132 implementation and ordered semantic inventory.

## E1R8 identity and bounded recovery

Generic Supervisor syntax/shape outcomes retain `format-invalid` provenance.
The original output and two same-profile corrections exhaust that allowance;
they cannot authenticate session termination or dispatch the next profile.
Dependency claim recovery authenticates the incoming task, complete subset,
request digest, profile, configuration, authority and predecessor in the same
transaction before it can block an in-flight attempt.

Migration 80 authenticates each existing review against the explicit legacy
or physical-ordinal digest encoding and retains that version for read-back,
replay and completion. It preserves existing input and output identities;
unverifiable or ambiguous rows roll back the migration. Populated schema-67
accepted and in-flight fixtures exercise both preservation and drift rejection.

Accounting validates historical format coordinates within each logical
profile and retains cumulative cost across a verified outage and fallback.
Deterministic accounting validation precedes route consumption and dispatch
claiming. Both route-rearming APIs transactionally reject any admitted
provider, dependency or generic successor. The production regression stops
after preparing a successor, proves its reservation cannot be abandoned, and
then completes restart with exactly one budget debit per physical attempt.

## Native correction and retained evidence compatibility

The native verdict schema emits logical profile position and physical format
ordinal. The stream parser accepts that closed shape and the historical initial
output shape; the adapter authenticates every value against the host request.
Legacy bindings cannot authorize corrections, and a substituted request digest,
coordinate, or boolean ordinal cannot authenticate a result. The production
session/schema/parser/adapter regression uses injected SDK handles beneath the
disabled launch gate and exercises durable same-profile correction, acceptance,
and exhaustion. It performs no live provider observation.

Typed native security denial is recorded in the shared scope ledger before
lifecycle append/finalization. Scope admission is rechecked before budget and
dispatch. The regression verifies a blocked lifecycle read-back and zero further
dispatch or budget change across restart, including a crash after persistence
and another prepared attempt identity in the same scope. The existing exact
clearance/revocation regressions remain part of the semantic suite.

Durable route issuance, reconstruction, reservation, and consumption require
current v3 verified failure evidence. Retained v1 unavailable, v2 historical,
and unknown evidence cannot authorize a route or successor effect.

Expected-lifecycle v3 owns the extended invalid/blocked terminal vocabulary.
Historical v2 retains its exact canonical payload, result vocabulary, source,
plan, and record identities. Literal base-schema in-flight and accepted file
fixtures are read without rewriting; changing the schema or blessing an
extended payload under v2 fails closed. Historical v1 tests remain unchanged.

## E1R10 dispatch, restart, and clearance boundaries

Worker dispatch rechecks the authenticated durable scope before reserving any
budget. A peer denial fences an already prepared attempt across lifecycle
reconstruction, with no session, route, or budget effect. Exact clearance
reopens that attempt; exact revocation closes it again. Dependency review
checks scope before claim recovery, route issuance, and reservation, including
fresh identities, repeated identities, and already prepared retries.

Same-profile physical correction restart authenticates the persisted attempt,
input, profile, lease, coordinates, and unclaimed state before recovering its
exact budget reservation. The injected crash occurs immediately after
preparation commits and before dispatch claiming. Restart retains cumulative
cost and opens only the previously undispatched correction; changed bindings
fail closed. The original output plus two corrections remains the closed limit.

Revocation now compares the requested clearance with the current authenticated
history predecessor inside the append transaction. A command for a later
clearance cannot revoke it through a stale request, and substituted or replayed
commands append nothing. The command still independently binds the denial,
task, repository, candidate seal, and authority scope.

The generic Supervisor validates distinct logical profiles against the policy
limit and physical ordinals independently. Native one-profile fixtures accept
one or two format corrections, exhaust after ordinal two, and reject terminal
replay without spending or dispatching again. A multi-profile jump that skips
required physical coordinates is rejected before any provider or budget effect.
The semantic inventory retains every earlier E1R1–E1R9 and compatibility test.

## E1R11 serialized effect and correction recovery boundaries

Every Worker, dependency-review, and direct Supervisor correction effect now
rechecks the durable scope through an immediate product-ledger transaction.
That transaction is the linearization point against a concurrent same-scope
STOP decision, and adapters repeat it before native session, turn, response,
checkpoint, and local tool boundaries. Candidate-bound regressions inject a
denial after the earlier preflight read and prove that neither Worker nor
dependency-review constructs a provider session.

Recovery reservation refunds are no longer caller-owned. The public refund
seam fails closed, including after a completed Worker turn. A route refund can
occur only while the recovery helper holds the product ledger's exclusive
transaction and has proved the exact reservation is still unconsumed and has
no provider, dependency-review, or generic Supervisor successor admission.
This keeps an admitted retry and its retained debit intact under stale replay.

A same-profile correction checks the stopped Supervisor scope before preflight
or budget reservation. Rejection leaves attempts, coordinates, claims, routes,
invalid results, sessions, provider calls, and budget rows byte-for-byte
unchanged. Readiness accepts the same exact authenticated PREPARED/UNCLAIMED
correction checkpoint that execution recovers, while changed request/lease/
coordinate material or a consumed dispatch claim fails closed.

## E1R12 admission atomicity and exact persisted-state replay

Worker and dependency-review reserve an advisory budget only through a single
product-ledger admission operation.  It retains the product `BEGIN IMMEDIATE`
lock from authenticated scope verification through the separate budget write,
in that order, so a durable stop cannot land between the check and a stranded
one-call/60-second/4,000-token debit.  Later adapter boundaries still reread
the scope before every native or durable effect.

The generic ordered Supervisor dispatcher now carries the repository-bound
scope callback into every adapter boundary.  A stop persisted after the
session checkpoint prevents turn creation, response read, and accepted output.
The budget deletion primitive independently requires the opaque exclusive
recovery authorization; public ledgers and reservations cannot refund an
admitted row.  Only the recovery transaction, after durable no-successor
read-back, may perform the route-bound reconciliation refund.

Provider-attempt readiness distinguishes a genuinely absent row from invalid
persisted state.  It shares the exact unclaimed-PREPARED validator used by
execution: role/profile/input and lease binding, logical and physical
coordinates, context/health binding, dispatch claim, session/turn/output and
completion fields, plus accepted identity invariants.  Thus a changed
coordinate or structurally inconsistent row is rejected at readiness, while
the exact persisted PREPARED/unclaimed correction remains resumable.

## E1R13 end-to-end scope, acceptance, and budget closure

The repository-bound Supervisor qualification entrypoint now supplies both the
adapter scope callback and a product-ledger-serialized reservation admission.
`E1R13-01` persists a same-scope denial from the real session checkpoint and
proves that no turn, response read, or accepted result can follow. The direct
correction regression persists a denial after the durable route fence but
before budget admission and proves that the successor has no provider call,
budget row, or successor-admission row.

Diff PASS acceptance checks the Supervisor scope inside the same
`BEGIN IMMEDIATE` transaction that writes the formal and provider acceptance
rows. `E1R13-02` stops the scope while the response is being read and proves
that completed evidence cannot overtake the denial into ACCEPTED state.

Readiness and replay execution both use one complete persisted-attempt
validator. For ACCEPTED attempts it requires the exact claim, coordinate,
formal diff review, provider acceptance, output, candidate, profile, and policy
bindings. `E1R13-03` deletes each independently required chain element and
proves both entrypoints fail closed without redispatch.

Worker dispatch now consumes a durable pre-effect claim immediately before the
native session boundary. A restart may reuse a debit only when the exact
attempt remains PREPARED, unclaimed, and has no session, turn, output,
completion, or accepted evidence. `E1R13-04` proves a denial ordered before
that claim leaves zero provider calls and that exact authoritative no-effect
proof can recover the unused reservation after clearance. No public or
completed-reservation refund surface is added or weakened.

## E1R14 response-time acceptance and prepared-restart closure

The E1R14 review evidence is retained below as an explicit before/after ledger.
“Before” names the concrete candidate behavior identified by review; “after”
names the candidate-bound invariant and executable regression that closes it.

| Finding | Before: reproduced defect boundary | After: durable invariant and semantic evidence |
| --- | --- | --- |
| E1R14-01 | The real Supervisor qualification path could read a response after a same-scope denial and append PASS lifecycle evidence without another product-ledger fence. | Lifecycle acceptance authenticates the current task and open scope while holding `BEGIN IMMEDIATE`; `test_real_qualification_response_time_denial_cannot_seal_pass` proves no event or terminal PASS survives the denial. |
| E1R14-02 | Dependency review checked scope after response parsing outside proposal persistence, so response-time denial could not produce one authoritative blocked outcome. | Proposal acceptance and outcome persistence authenticate authority and scope in their write transaction; `test_response_time_scope_denial_records_blocked_not_accepted_or_invalid` records only `blocked/scope-stopped`, with no proposal or second session. |
| E1R14-03 | FINDINGS persistence lacked the PASS path's scope fence and changed task state in a later transaction, allowing partial artifacts/routes/items. | Scope check, artifact, route, review items, and `diff-review` to `implementing` transition share one transaction; `test_response_time_denial_rolls_back_findings_route_and_transition` proves complete rollback. |
| E1R14-04 | Accepted replay validation did not require the exact persisted session checkpoint and formal turn binding. | Readiness and execution share the complete session/formal/claim/coordinate/acceptance validator; `test_readiness_and_execution_share_complete_accepted_state_validation` rejects deleted checkpoints and substituted turns without redispatch. |
| E1R14-05 | Scope admission and reservation were separable, and a preparation rejection after an ordinary correction debit could strand that debit. | Scope admission serializes the budget write against STOP; only an exact sealed debit with no attempt, claim, checkpoint, completion, or formal review may be released. Concurrent stopped writers and `test_unused_correction_debit_is_recovered_when_preparation_fails` prove zero escaped or stranded cost. |
| E1R14-06 | A physical-ordinal-zero PREPARED restart always attempted a fresh reservation instead of recovering an existing exact debit. | Initial PREPARED recovery accepts an optional exact reservation and reuses it; `test_initial_prepared_reservation_resumes_after_crash_without_double_debit` proves one debit and one provider call across the crash. |
| E1R14-07 | Prepared-state readiness recognized only initial and same-profile correction shapes, rejecting an authorized next-profile fallback. | One classifier covers initial, correction, and terminal-authorized fallback attempts, including reserving and consumed route states. `test_format_correction_then_verified_outage_falls_back_without_stranding` proves both preparation and route-commit restarts; `test_prepared_fallback_readiness_rejects_route_identity_claim_and_reservation_drift` rejects every substituted binding. |

All E1R14 tests are appended to the independently ordered Issue #132 semantic
inventory. Windows declares no E1R14 skip, and the candidate-bound receipt must
execute every entry before the coverage manifest can render or verify.

## E1R15 durable acceptance, debit-intent, and legacy replay closure

The E1R15 review evidence is retained as one repair set. Each row binds the
reported bypass or restart gap to a candidate-enforced invariant and one
independently ordered semantic regression.

| Finding | Durable invariant and semantic evidence |
| --- | --- |
| E1R15-01 | A production dependency attempt is identified by its durable dispatch claim. Proposal acceptance reconstructs the exact task identity from the attempt and rechecks candidate/runtime authority plus the stopped scope even when `task_identity` is omitted. `test_default_acceptance_derives_production_task_and_rechecks_stopped_scope_after_restart` proves both default-argument and reconstructed-store rejection. |
| E1R15-02 | The unused-provider refund primitive accepts only Supervisor reservations backed by an exact repository/task/scope debit intent. Dependency-review reservations are categorically non-refundable, including prepared, claimed, and accepted attempts, as proven by `test_dependency_review_reservations_are_never_refundable_by_provider_release`. |
| E1R15-03 | Every non-route Supervisor debit is preceded by a repository-side exact reservation intent. Restart recovers the matching budget row or, when interruption preceded that row, performs the first debit. `test_process_death_after_correction_debit_before_prepare_recovers_exact_intent` uses a `BaseException` boundary before `prepare_attempt` and proves one debit, one later effect, and intent reconciliation. |
| E1R15-04 | A cleared stop is not standalone authority. Every scope/effect admission reauthenticates the original failure admission and session checkpoint while holding the product transaction. `test_cleared_scope_effect_reauthenticates_original_admission_and_session` deletes each evidence class after an authentic clearance and proves the reserve callback remains untouched. |
| E1R15-05 | Migration 81 recovers a schema-67 generic prepared Supervisor's logical profile position only when the selected profile is unique and its attempt/runtime contexts agree exactly. `test_schema67_generic_prepared_supervisor_replays_after_position_migration` migrates a populated database with no diff-review row and replays the unchanged attempt. |

All five E1R15 tests are appended to the independent Issue #132 semantic
inventory. Windows declares no E1R15 skip; render and verify require the exact
candidate-bound execution receipt.

## E1R16 dispatch identity, denial, and reservation closure

E1R16 closes the remaining boundaries where an operation could be accepted,
refunded, or restarted without the complete identity that originally admitted
its effect.

| Finding | Durable invariant and semantic evidence |
| --- | --- |
| E1R16-01 | Dependency proposal acceptance requires a durable task plus a dispatch claim containing both the native session and turn in `turn-dispatched` state. It always rechecks current candidate/runtime authority and the open scope. `test_acceptance_requires_complete_dispatch_identity_evidence` rejects missing and session-only claims before accepting the complete claim. |
| E1R16-02 | Migration 82 binds each non-route reservation intent to the exact sealed budget repository and task identities. The unused-refund transaction compares both identities before touching the budget ledger or deleting the intent. `test_unused_correction_refund_rejects_foreign_reservation_owner` substitutes a foreign repository owner and proves the completed debit and intent remain intact. |
| E1R16-03 | The dependency service derives its production `TaskIdentity` from the durable task row before model input, reservation, or dispatch, and rejects missing or caller-substituted authority. `test_service_derives_durable_task_identity_and_rejects_missing_authority_before_dispatch` proves zero provider and budget effects. |
| E1R16-04 | Worker, Supervisor, and dependency-review claims persist a domain-separated pre-dispatch session surrogate before native construction. A typed SDK denial can therefore retain its classification, record a durable scope stop, and block restart even when no turn identity exists. The three pre-session semantic regressions exercise each role end to end. |
| E1R16-05 | Clearance successor admission now authenticates the session checkpoint fingerprint against the original before-dispatch checkpoint, in addition to task, attempt, session, candidate, policy, configuration, and runtime bindings. The extended `test_cleared_scope_effect_reauthenticates_original_admission_and_session` rejects a substituted checkpoint fingerprint with no reservation callback. |
| E1R16-06 | Generic Supervisor qualification persists an exact initial reservation intent before the separate budget debit, recovers that debit after process death, and retires the intent atomically with its dispatch claim. The extended crash-boundary regression proves one initial debit, no pre-claim provider call, and exact restart recovery. |

The six new E1R16 tests are appended to the ordered semantic inventory; the
two extended admission/crash tests retain their existing positions. Windows
declares no E1R16 skip, and coverage render/verify requires their exact
candidate-bound execution receipt.

## E1R17 dispatch admission, identity, and restart closure

E1R17 closes the five remaining review boundaries without weakening the
existing no-effect, no-double-debit, or candidate-bound replay rules.

| Finding | Durable invariant and semantic evidence |
| --- | --- |
| E1R17-01 | A Supervisor scope denial before a native session or turn is a typed durable terminal result. It binds either the authenticated pre-dispatch surrogate or the real session checkpoint, never invents a turn, and blocks restart. `test_scope_denial_before_session_or_turn_is_durable_without_invented_turn` covers both boundaries. |
| E1R17-02 | Every initial dependency-review debit has an exact repository/task reservation intent before budget I/O. Restart recovers interruption before or after durable attempt preparation, reuses one debit, dispatches once, and retires the intent only after the exact attempt is durable. `test_initial_reservation_intent_recovers_before_and_after_preparation` covers both crash windows. |
| E1R17-03 | Dependency acceptance, terminal read-back, graph activation, and current-graph replay share one dispatch authenticator. It reconstructs durable task authority and rejects missing claims plus substituted session, turn, admission-session, or profile bindings. `test_all_dependency_consumers_share_exact_dispatch_authentication` exercises every consumer. |
| E1R17-04 | Supervisor and dependency-review pre-dispatch claims recheck the stopped scope inside the same `BEGIN IMMEDIATE` transaction that inserts the claim. `test_supervisor_claim_rechecks_scope_inside_the_claim_transaction` and `test_pre_dispatch_claim_rechecks_scope_in_its_writer_transaction` prove neither writer can overtake a concurrent stop. |
| E1R17-05 | Cleared-scope successor admission reconstructs the original health authorization and full sealed launch-context fingerprints, derives the expected before-dispatch checkpoint, and authenticates the persisted session checkpoint against it. The extended `test_cleared_scope_effect_reauthenticates_original_admission_and_session` rejects forged equal fingerprints and a substituted health seal before any reservation callback. |

The five new semantic tests are appended to the independently ordered Issue
#132 inventory; the extended clearance test retains its earlier position and
both claim-writer races are required for E1R17-04. Windows declares no E1R17
skip, and render/verify requires the exact candidate-bound execution receipt.
