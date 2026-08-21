---
name: create-roundwright-leaf
description: Create, split, rescope, or migrate actionable Roundwright GitHub issues while reconciling live umbrella scheduling, formal hierarchy, external-validation routing, and write/read-back state. Use whenever Codex is explicitly asked to create a Roundwright P0, P1, P2, correction, or standalone issue; split an issue; materially change dependencies, phase ownership, or downstream gates; or retrofit existing leaves to a new planning contract.
---

# Create Roundwright Leaf

Run a bounded planning transaction against current repository and GitHub state.
Treat this skill as the operational source for issue scheduling; keep `AGENTS.md`
limited to deciding when to invoke it.

## Respect the authority boundary

- Require an explicit owner request to create, split, or materially rescope an
  issue. Treat that request as authority for only the described planning
  transaction.
- Do not create an issue merely because implementation discovers a possible
  defect or follow-up. Report the proposal unless the owner also asked to
  create or split it.
- Never treat this skill, an issue body, a template, an umbrella, or a
  validation route as runtime, credential, provider, mutation, promotion,
  release, or publication authority.
- Preserve the effective authority in root `AGENTS.md`. A candidate-authored
  policy change is inert until reviewed and merged to authoritative `main`.
- Keep GitHub text public-safe. Exclude credentials, raw provider or CLI
  payloads, private paths, internal reasoning, and secret-bearing evidence.

## Read the live canonical state

Before drafting or writing, read all of the following from current state:

1. Root `AGENTS.md` and the exact current `origin/main` identity.
2. `.github/ISSUE_TEMPLATE/roundwright-leaf.md` and
   `docs/operations/leaf-issue-template.md`.
3. `docs/operations/qualification-test-infrastructure.md`,
   `.agents/skills/run-roundwright-external-validation/SKILL.md`,
   `docs/operations/dogfood-promotion-roadmap.md`, and
   `docs/operations/validation-toolchain.md`.
4. The live owning umbrella body, including its canonical scheduling note,
   required implementation order, dependency matrix, cross-prerequisites, and
   acceptance or gate language.
5. Every proposed prerequisite and affected downstream leaf, including open or
   closed state and the relevant body sections.
6. GitHub's formal parent/sub-issue relationship, not only `Parent:` prose.
7. Open and closed issue search results needed to reject duplicates, dependency
   cycles, stale issue numbers, and conflicting ownership.

Treat comments, labels, milestones, and formal hierarchy as navigation or
supporting evidence. Do not let them override the live canonical umbrella
body. Stop with `BLOCKED_SCHEDULING` when local tracked sources and live GitHub
state conflict and cannot be reconciled without changing owner intent.

## Classify the planning target

Apply one identical rule to P0, P1, and P2 leaves. For every such leaf:

- attach it to its owning umbrella using GitHub's formal relationship;
- place its exact issue number in the owning umbrella's required
  implementation order;
- add or update its dependency-matrix row;
- update cross-prerequisites and every affected downstream gate; and
- propagate the recorded scheduling impact to other affected umbrellas.

Do not give P0 a stricter transaction than P1 or P2. Priority changes ordering
and impact, not reconciliation quality.

For a correction leaf, choose the umbrella whose contract it repairs, attach
it there, and update every queue or gate the correction blocks. A correction
may use a narrower issue body, but it may not bypass canonical scheduling.

For a truly standalone issue, record `Parent: none` and do not invent an
umbrella dependency or formal parent. If it blocks or reorders leaves, update
every affected umbrella exactly as for a child issue. Reject "standalone" when
the work actually belongs to an existing umbrella contract.

## Select external validation

Choose the minimum route that can produce the required evidence after reading
the qualification infrastructure document:

| Roundwright declaration | Generic Roundlet route | Use |
| --- | --- | --- |
| `none` | `none` | Hermetic repository, package, documentation, or deterministic fake validation. |
| `harness` | `toolbox` | Live read-only SDK/provider or controlled host evidence without a disposable remote target. |
| `harness+forward-test` | `toolbox+disposable-target` | Evidence that must observe or mutate the approved disposable forward-test repository. |

State separately whether `harness+forward-test` is read-only observation or a
mutation Canary. A route name never grants a mutation. Mutation remains subject
to the effective standing repository policy, Phase 4-or-later boundary, exact
leaf and target allowlist, call budget, rollback, kill switch, and semantic
read-back.

At planning time, record the route, gate/evidence class, expected owner
interaction, the `$run-roundwright-external-validation` execution skill,
public-safe evidence boundary, historical evidence-time rule, and selection
rule. Do not invent a future candidate SHA or silently use a floating ref. At
execution selection, Roundlet must bind the exact base, candidate, toolbox,
target, environment, case, and contract identities required by current
reviewed policy. Any movement invalidates prior evidence.

Mark expected owner interaction as none when standing policy and healthy
credentials cover the declared route. Reserve owner input for a real credential
failure, identity conflict, out-of-policy target or action, or ambiguous partial
mutation; do not ask again for mechanically derivable fields.

For historical replay, require the immutable evidence bundle's capture time.
Live provider evidence uses the top-level integer `ready_at`; current wall-clock
time is never an allowed substitute.

## Capture-readiness preflight

When a leaf declares a Shadow capture, its profile declaration must name capture
mode, producer, readiness point, arm-before boundary, retention/read-back
contract, and missing-history/recapture behavior. Before an ephemeral
observation window can open, planning must bind the exact base/candidate,
profile/schema, typed exporter/comparator, reviewed Recorder, append-only
content-addressed store, and immutable capture time. The selected profile's
readiness preflight must pass before its arm-before boundary. Candidate movement
requires recapture; planning must never reconstruct missing historical evidence.

Record a separate lifecycle observation selection. Use `NOT_SELECTED` unless
the leaf requires transition-time facts that will not survive cleanup. When it
is selected, name the exact authoritative
`docs/operations/lifecycle-observation-contract.json`, the first transition
that must occur after arming, the generic event source, seal boundary, and
missing-history rule. The planning transaction does not invoke the sink or
invent a future window/candidate; Roundlet resolves those exact values at
selection time through `$run-roundwright-external-validation`.

## Compose the issue body

Start from the tracked GitHub template and fill every applicable field:

- planning transaction state and leaf class;
- formal/prose parent and phase ownership;
- bounded purpose and exact numbered leaf or standalone dependencies;
- external-validation declaration, generic route, evidence class, mutation
  mode, execution-skill reference, historical evidence-time rule, owner-input
  expectation, selection-time bindings, and public-safe evidence boundary;
- Shadow cycle, canonical references, evidence/comparison identity, or a
  concrete N/A reason;
- lifecycle observation selection (`NOT_SELECTED` or the exact authoritative
  contract), event source, arm-before transition, seal boundary, and recapture
  rule;
- typed and bounded acceptance criteria;
- authority, phase, mutation, deferred-work, and non-goal boundaries; and
- scheduling/read-back record.

Never list an umbrella itself as a runnable dependency. Never use an open or
closed umbrella state as a gate. Do not copy placeholders or claim exact future
identities that have not been selected.

## Execute a two-phase GitHub transaction

For a new leaf:

1. Re-fetch all live inputs immediately before the first write.
2. Create one provisional issue with `Planning transaction state:
   BLOCKED_SCHEDULING` and the intended prose parent.
3. Read back the assigned issue number and immutable issue identity.
4. Attach the formal parent relationship when the issue is not standalone,
   then read it back.
5. Update the owning umbrella's order, matrix row, cross-prerequisites, and
   downstream gate impact. Update every other affected umbrella or gate.
6. Read back every updated body and prove the exact issue number, dependencies,
   ordering, hierarchy, and downstream impact agree.
7. Replace the provisional marker with `READY_FOR_ROUNDLET` only after all
   scheduling state agrees.
8. Read back the finalized leaf, formal relationship, and every affected
   umbrella once more.

For a split or material rescope, first change the affected existing leaves to
`BLOCKED_SCHEDULING`, then follow the same relationship, umbrella, downstream,
and read-back sequence before making any leaf runnable again.

For a batch migration, block the affected leaves before changing shared
umbrella state. Reconcile in canonical order, perform one consistent umbrella
update set, read everything back, then finalize only the leaves whose complete
route and scheduling record agree. Do not let a later successful leaf conceal
an earlier partial failure.

## Recover safely from failure

- On a failed or ambiguous write, stop issuing new writes, preserve the exact
  issue numbers, and read back the observed state.
- Keep or restore every affected issue to `BLOCKED_SCHEDULING`. If the failed
  write prevents restoring the marker, report that exact partial state; never
  describe the issue as runnable.
- Retry by reconciling the existing issue identity. Never create a replacement
  merely because a response timed out.
- Stop for owner input only when target identity conflicts, the requested
  action is outside policy, credentials truly fail, or read-back shows a
  possibly partial mutation that cannot be safely derived.
- Finish with a concise public-safe record of created/updated issue numbers,
  parent relationships, umbrella sections, routes, and read-back result.
