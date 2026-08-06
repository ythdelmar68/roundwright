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
| `FORWARD_TEST_CANARY` | A bounded, owner-authorized experiment in the controlled forward-test repository. | Only the exact actions separately enabled for that repository. Never Roundwright production authority. | The bounded experiment is reconciled, read back, and rolled back or explicitly advanced by the owner. |
| `CROSS_ENV_CANARY` | The controlled experiment is repeated across declared environments. | Only the same bounded forward-test authority. | Cross-environment evidence is complete, comparable, and owner-reviewed. |
| `PROMOTION_READY` | Evidence is sufficient to request a promotion decision. | No new authority; this mode does not activate anything. | An allowlisted owner records a candidate-bound activation or rejection decision. |
| `ACTIVE` | A later external, owner-approved transition has made one declared runtime authoritative. | Only explicit, externally verified, current authority. | A superseding owner decision moves the runtime to recovery or replacement. |
| `DORMANT_RECOVERY` | A non-dispatching recovery posture after an authority transition or rollback. | None except a separately authorized recovery action. | Reconciliation establishes a safe next owner decision. |

`PROMOTION_READY` is a request for an owner decision, not a self-promotion
state. `ACTIVE` is unavailable unless the owner explicitly establishes it;
this Phase 3 document does not establish it.

## External qualification routing

The [qualification test infrastructure](qualification-test-infrastructure.md)
is the single source for selecting the external execution toolbox and, when a
remote mutation is separately approved, the disposable target. Every gate
pins an exact candidate and exact infrastructure commits; a floating branch or
`main` reference is never evidence. The document is routing-only and does not
change the Phase 2 boundaries or authority matrix below.

## Phase plan

| Phase | Entry criteria | Work and required evidence | Exit criteria | Authority and rollback | Owner decision |
| --- | --- | --- | --- | --- | --- |
| 2 — substrate | Hermetic single-task baseline is defined. | Isolated-package, local-Git, restart, and adversarial-path evidence. | #26 and #27 are closed; no external-runtime claim. | No Roundwright mutation authority; return to blocked local diagnosis on failure. | None; Phase 2 does not promote. |
| 3 — contracts | Phase 2 evidence is complete. | Roadmap, immutable Shadow protocol, typed contracts, fail-closed Boolean policy, provider health, receipts, provenance, and qualification evidence. | Every Phase 3 P0 leaf and qualification issue pass on the exact candidate; Shadow remains read-only. | Roundlet remains authoritative for Roundwright. Rollback means stop the candidate, preserve evidence, and resume `SHADOW_ONLY` or `DORMANT_RECOVERY`. | Decide only whether a bounded Phase 4 forward-test canary may be attempted. |
| 4 — controlled canary | An owner explicitly authorizes a bounded controlled forward-test scope after Phase 3 qualification. | Forward-test and cross-environment canary evidence, read-back, semantic receipts, and rollback rehearsal. | Every stated environment has matching evidence or a recorded owner rejection. | Roundlet remains the Roundwright authority. The forward-test repository is limited to its approved scope. Disable its switches and reconcile on failure. | Approve, reject, or constrain a Phase 5 promotion evaluation. |
| 5 — promotion evaluation | Controlled-canary evidence is complete and comparable. | Legacy parity, retention, maintenance, cleanup eligibility, final promotion evidence, and Roundlet stop/reconciliation plan. | An owner has a complete, candidate-bound evidence bundle; no automatic transition occurs. | No dual dispatch: any replacement requires stopping and reconciling Roundlet before a successor can dispatch. Roll back to `DORMANT_RECOVERY` on uncertainty. | Make the external self-hosting/activation decision, or reject it. |
| 6+ — release/publication | A separate owner decision authorizes release preparation. | Release-specific checks and public artifacts. | Criteria defined by that separate decision. | This roadmap grants none. | Authorize each release/publication action separately. |

The Phase 3 sequence is the canonical order in umbrella #2: #37, #38, #39,
then #40, #41, #42, #46, and #47. The Phase 3 qualification result may produce
`PROMOTION_READY` only; it cannot start a canary.

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
| Phase 3 | Roundlet remains sole mutation-capable Orchestrator. The Roundwright Boolean block is disabled. | Not authorized; no canary. | Permanent read-only replay and comparison. | Exact-candidate qualification evidence. |
| Phase 4 | Roundlet remains sole authority for Roundwright. | May perform only an allowlisted, owner-approved, bounded canary. | Read-only regression check; no dispatch. | Owner's canary authorization and each read-back receipt. |
| Phase 5 | Roundlet remains sole authority until it is stopped and reconciled by a later owner-approved transition. | May remain bounded only while its explicit authorization is current. | Read-only regression check and retained comparison history. | Candidate-bound promotion or rejection decision. |
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

No mode authorizes a Canary by default. No document in this repository is an
activation receipt, and no candidate can issue its own receipt.
