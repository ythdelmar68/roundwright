# Leaf issue planning contract

The selectable GitHub body scaffold is
[`.github/ISSUE_TEMPLATE/roundwright-leaf.md`](../../.github/ISSUE_TEMPLATE/roundwright-leaf.md).
Agents must use the repository-scoped
[`$create-roundwright-leaf`](../../.agents/skills/create-roundwright-leaf/SKILL.md)
workflow when creating, splitting, materially rescoping, or migrating an
actionable issue. The template supplies fields; the skill owns the live GitHub
transaction, scheduling reconciliation, and read-back behavior.

The template does not make an umbrella a dependency or grant authority. Read
the live owning umbrella's canonical scheduling note and the
[qualification test infrastructure](qualification-test-infrastructure.md)
before selecting external validation. The planning skill records the minimum
route; the repository-owned
[`$run-roundwright-external-validation`](../../.agents/skills/run-roundwright-external-validation/SKILL.md)
skill owns execution, recovery, and historical replay.

## Common priority-leaf rule

P0, P1, and P2 leaves follow the same rule. Each transaction updates the owning
umbrella's exact required implementation order, dependency-matrix row,
cross-prerequisites, and downstream gate impact, plus any other umbrella whose
queue or gate changes. Priority determines placement and impact, not whether
reconciliation is required.

A correction leaf attaches to the umbrella whose contract it repairs and
updates every affected queue or gate. A truly standalone issue has no parent
and never lists an umbrella as a dependency; it still updates affected
umbrellas if it blocks or reorders their leaves.

## Planning and execution identities

Issue planning records the minimum validation route and the rules for selecting
exact identities. It must not guess a future candidate SHA. At execution time,
Roundlet binds the exact current base, candidate, harness, forward-test target,
environment, case, and contract identities required by reviewed policy. A
floating ref is never evidence.

Every declaration names `$run-roundwright-external-validation` and records
whether historical replay uses immutable bundle `ready_at` or is not
applicable. A current wall-clock timestamp is never a substitute for captured
evidence time.

The external-validation declaration is a routing and evidence record. The
standing Booleans in authoritative root policy remove repetitive approval only
for a mechanically conforming selected route; the declaration alone never
authorizes a credential, provider call, target mutation, promotion, or change
to the disabled Roundwright authority surface. A new or materially changed
issue stays `BLOCKED_SCHEDULING` until formal hierarchy, umbrella state, leaf
body, and all affected downstream gates are written and read back consistently.

If a leaf adds a `GitHubMutationOperation`, that same reviewed change must add
exactly one canonical `RepositoryMutationOperation`, exactly one strict
Boolean, the immutable mapping, denied/allowed/stale/wrong-candidate coverage,
and semantic read-back coverage. Missing, duplicate, extra, inferred, alias,
fallback, or `None` mappings are not deferrable follow-up work and must fail CI.
