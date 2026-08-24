# Dogfood promotion roadmap

## Status and purpose

This is the canonical, public-safe roadmap for moving from Phase 2 evidence to
any future Roundwright operation. It separates implementation phase from
operational maturity: completing a phase never activates a runtime, grants a
repository mutation, or changes the active Orchestrator.

Roundlet remains the sole mutation-capable development Orchestrator for the
Roundwright repository throughout Phase 3 and until a later, explicit
owner-reviewed transition changes that fact. Shadow is a permanent read-only
regression layer governed by the [Shadow validation protocol](../architecture/shadow-validation.md).
The disabled Roundwright Boolean surface in [`AGENTS.md`](../../AGENTS.md) is
not effective authority.

Milestones group execution work. Qualification issues consume and assess
evidence. Neither a milestone nor a qualification result grants authority;
`AGENTS.md` records only authority that is effective now. A new proposal cannot
authorize, promote, merge, release, publish, retire Roundlet, or destructively
clean itself.

## Operational maturity

| Mode | Meaning | Repository mutation | Exit only when |
| --- | --- | --- | --- |
| `SHADOW_ONLY` | Replay production-shaped, immutable inputs and compare results. | None; Shadow is always read-only. | The required read-only evidence is retained and a qualification issue records its assessment. |
| `FORWARD_TEST_CANARY` | A bounded experiment selected by an exact Phase 4-or-later leaf under reviewed standing authority. | Only the leaf/target-policy intersection in the controlled forward-test repository. Never Roundwright production authority. | The bounded experiment is reconciled, read back, and rolled back or advanced through the next reviewed phase gate. |
| `CROSS_ENV_CANARY` | The controlled experiment is repeated across declared environments. | Only the same bounded forward-test authority. | Cross-environment evidence is complete, comparable, and owner-reviewed. |
| `PROMOTION_READY` | Evidence is sufficient to request a promotion decision. | No new authority; this mode does not activate anything. | An allowlisted owner records a candidate-bound activation or rejection decision. |
| `ACTIVE` | A later external, owner-approved transition has made one declared runtime authoritative. | Only explicit, externally verified, current authority. | A superseding owner decision moves the runtime to recovery or replacement. |
| `DORMANT_RECOVERY` | A non-dispatching recovery posture after an authority transition or rollback. | None except a separately authorized recovery action. | Reconciliation establishes a safe next owner decision. |

`PROMOTION_READY` is a request for an owner decision, not a self-promotion
state. `ACTIVE` is unavailable unless the owner explicitly establishes it;
this Phase 3 document does not establish it.

## External qualification routing

The [qualification test infrastructure](qualification-test-infrastructure.md)
is the single source for selecting the external execution toolbox and public
disposable target. Root `AGENTS.md` owns independent standing read-only and
disposable-target mutation Booleans; the repository execution skill applies
them only to an exact conforming leaf. Every gate pins an exact candidate and
exact infrastructure commits; a floating branch or `main` reference is never
evidence. These contracts do not activate Roundwright or widen the phase and
repository boundaries below.

Leaf qualification may compose typed Evidence lanes. Each lane is independently
candidate-bound and capability-intersected; qualification remains conjunctive,
not a route or receipt substitution. A zero-lane leaf keeps the existing zero
Roundwright-specific external/lifecycle loading behavior. #49's Lane A is a
read-only external observation before Supervisor; its Lane B lifecycle evidence
is armed before Supervisor and verified only after an accepted PASS. Any
candidate movement makes both lanes stale.

Lane A evidence is an observed receipt, not a plan-only assertion: it reads the
exact target inventory, fixture-manifest classification, implementation-PR
curated trace, immutable readiness point, and a matching before/after
zero-mutation target state.

## Phase plan

| Phase | Entry criteria | Work and required evidence | Exit criteria | Authority and rollback | Owner decision |
| --- | --- | --- | --- | --- | --- |
| 2 — substrate | Hermetic single-task baseline is defined. | Isolated-package, local-Git, restart, and adversarial-path evidence. | #26 and #27 are closed; no external-runtime claim. | No Roundwright mutation authority; return to blocked local diagnosis on failure. | None; Phase 2 does not promote. |
| 3 — contracts | Phase 2 evidence is complete. | Roadmap, immutable Shadow protocol, typed contracts, fail-closed Boolean policy, provider health, receipts, provenance, and qualification evidence. | Every Phase 3 P0 leaf and qualification issue pass on the exact candidate; Shadow and any forward-target observation remain read-only. | Roundlet remains authoritative for Roundwright. Rollback means stop the candidate, preserve evidence, and resume `SHADOW_ONLY` or `DORMANT_RECOVERY`. | No fresh per-attempt approval for conforming read-only routes; Phase 3 never performs Canary mutation. |
| 4 — controlled canary | Phase 3 qualification is complete and an exact leaf-scoped forward-test route matches standing and target authority. | Forward-test and cross-environment canary evidence, read-back, semantic receipts, and rollback rehearsal. | Every stated environment has matching evidence or a recorded blocked/rejected disposition. | Roundlet remains the Roundwright authority. The public forward-test repository is limited to the exact leaf/target-policy intersection. Disable the affected route and reconcile on failure. | Approve, reject, or constrain a Phase 5 promotion evaluation. |
| 5 — promotion evaluation | Controlled-canary evidence is complete and comparable. | Legacy parity, retention, maintenance, cleanup eligibility, final promotion evidence, and Roundlet stop/reconciliation plan. | An owner has a complete, candidate-bound evidence bundle; no automatic transition occurs. | No dual dispatch: any replacement requires stopping and reconciling Roundlet before a successor can dispatch. Roll back to `DORMANT_RECOVERY` on uncertainty. | Make the external self-hosting/activation decision, or reject it. |
| 6+ — release/publication | A separate owner decision authorizes release preparation. | Release-specific checks and public artifacts. | Criteria defined by that separate decision. | This roadmap grants none. | Authorize each release/publication action separately. |

The Phase 3 sequence is the canonical order in umbrella #2: #37, #38, #39,
then #40, #41, #42, #59, #46, planning correction #65, external-validation
correction #67, #47, capture-plan correction #72, #44, executor correction
#75, #45, reviewed-Runlet binding correction #78, #48, lifecycle observation
correction #82, then #49–#51.
Issue #59
completes the canonical schema v2 mutation vocabulary and authority-block
isolation before the live broker can continue. Issue #65 installs the
repository-owned leaf-planning transaction and migrates the remaining open
leaves before dispatch resumes. Issue #67 adopts reviewed generic Roundlet
routing, standing repository authority, repo-owned execution mechanics, and
capture-time replay. Issue #72 binds profile readiness, dispatch, export,
comparison, Recorder sealing, and read-back to one immutable Harness capture
plan before the remaining live gates run. Issue #75 makes generic Roundlet
consume one reviewed Harness executor while Roundwright supplies the public
typed profile adapter; a hermetic synthetic activation qualifies that boundary
before live provider-attempt accounting resumes. Issue #78 adopts reviewed
Roundlet PR #82 merge `1004cf0143aef9a777a64a3a0703b10a5680e959` after
#45 and requires one fresh post-merge provider-free synthetic receipt before
#48. It reuses the existing synthetic profile and does not modify Harness or
create a new evidence profile. Issue #82 follows completed #48 and adopts the
reviewed Roundlet lifecycle producer plus Harness lifecycle ledger into one
exact repository-owned contract. Its provider-free synthetic sequence must
seal, project, and compare successfully before a completely fresh #49 live
window begins. It does not move #49's product profile or live evidence into the
correction. The Phase 3 qualification
result may produce `PROMOTION_READY` only; it cannot start a Canary by itself.

Phase 3 reuses the routing source for native/Shadow qualification; Phase 4 for
canary and cross-environment work; Phase 5 for operations, migration, and
promotion evaluation; and Phase 6 for release-readiness validation. These are
evidence routes only and never expand the authority stated in this roadmap.

## Deferred Phase 5 dependency-review lifecycle

Phase 3 records, but does not implement or activate, dependency review. Its
default future profile is Codex `gpt-5.6-terra` with `high` reasoning effort.
There is no Phase 3 activation key, runnable job, provider adapter, or created
dependency-review leaf. A Phase 5 planning issue may be opened only after the
Phase 4 closing qualification gate is closed and an allowlisted owner
explicitly requests that planning step.

When it is separately implemented and authorized, each dependency-review job
will start a fresh, read-only attempt over one immutable affected-subset
snapshot. It retains durable proposals, validation outcomes, and graph state;
it never treats a previous model conversation as durable state. The
deterministic Orchestrator may auto-activate only mechanically verifiable,
explicit or policy-derived edges. A semantic inferred hard edge is routed to
an owner for a decision. Any accepted affected-subset change requires a fresh
subset review. This is a lifecycle record, not a present capability or grant
of authority.

## Repository authority matrix

| Stage | Roundwright repository | Controlled forward-test repository | Shadow | Decision record |
| --- | --- | --- | --- | --- |
| Phase 2 | Roundlet is sole mutation-capable Orchestrator; Roundwright is non-authoritative. | Not authorized. | N/A for execution. | Closed Phase 2 leaves. |
| Phase 3 | Roundlet remains sole mutation-capable Orchestrator. The Roundwright Boolean block is disabled. | Read-only observation only; no Canary mutation. | Permanent read-only replay and comparison. | Exact-candidate qualification evidence. |
| Phase 4 | Roundlet remains sole authority for Roundwright. | May perform only an exact leaf-scoped, standing-policy and target-policy allowlisted bounded Canary. | Read-only regression check; no Roundwright dispatch. | Standing authority identity, exact leaf contract, and each semantic read-back receipt. |
| Phase 5 | Roundlet remains sole authority until it is stopped and reconciled by a later owner-approved transition. | May remain bounded only while the standing policy and exact selected route remain current. | Read-only regression check and retained comparison history. | Candidate-bound promotion or rejection decision. |
| After a transition | Exactly one declared authoritative dispatcher; Roundlet is dormant or recovery-only if replaced. | Disabled unless separately re-authorized. | Permanent read-only regression layer. | External owner-reviewed authority transition. |

Two repositories must never have two dispatchers for the same authority. The
controlled forward-test repository is not a proxy for authority over
Roundwright. A proposal from either repository cannot change that matrix.

## Promotion gate, evidence, and rollback

An owner decision must be based on public-safe, exact-candidate evidence:

- immutable replay-input identity, comparison result, mismatch disposition, and
  retention reference from Shadow;
- deterministic validation and exact candidate, base, policy, and receipt
  identities;
- declared scope, enabled Boolean actions, and semantic read-back for any
  approved forward-test action; and
- a tested rollback/reconciliation result that leaves one dispatcher or none.

Missing, unknown, malformed, stale, conflicting, unverifiable, or
candidate-authored evidence denies the next mutation and returns to
`SHADOW_ONLY` or `DORMANT_RECOVERY`. Rollback preserves immutable inputs and
curated reports, disables the relevant authority switches, stops the affected
dispatcher, and requires reconciliation before any new owner decision.

No mode or route starts a Canary by default. Standing authority becomes usable
only through an exact eligible leaf and target-policy intersection. No document
in this repository is a Roundwright activation receipt, and no candidate can
issue its own receipt.
