# Authority Model

## Bounded advisory-role admission

Recovery Advisor and Owner Intent Interpreter are opt-in advisory instances,
not dispatchers. Admission requires independent authority evidence bound to the
repository, task, deployment, epoch, expiry, revocation identity, host/state/
fence-bound instance, accepted guidance at an exact trusted Git tree, and a
root-normalized typed action/path/test/process/network/resource scope. The
profile intersects that scope with a reviewed, immutable per-capability SDK
mapping and finite budgets. Drive-qualified, UNC, traversal, repeated-separator,
and non-canonical scope paths fail closed.

Configuration resolves profiles only; it cannot create an admission or
authority. A readiness receipt always leaves effective repository authority
disabled. Missing, stale, revoked, copied, reassigned, expanded, or unknown
evidence denies the request. The admission-record reader requires the existing
candidate/Git-entrypoint control that validates authoritative `origin/main`;
it cannot be constructed from a role-local path alone. Guidance derives only the root-to-task
`AGENTS.md` chain at the pinned tree; candidate, global, unrelated, and ambient
instructions are prohibited. A typed pre-effect gate is defined for Worker,
Supervisor, dependency-review, and both advisory seams. No advisory dispatch
is enabled in those existing runtime seams today.

## Roles

- **Owner:** approves the exact reviewed candidate and is the only authority that may authorize merge, release, publication, or destructive cleanup.
- **Orchestrator:** owns the repository-scoped queue, deterministic state machine, credentials, and gated GitHub actions.
- **Worker/analyst:** produces bounded proposals from minimized inputs and cannot mutate repositories or GitHub state.
- **Independent reviewer:** evaluates the public-safe candidate in a fresh read-only session and cannot approve on the owner's behalf.
- **Deterministic validator:** is authoritative for identity, coverage, privacy, and receipt checks.

## State transitions

1. Capture immutable private evidence and bind an inventory digest.
2. Accept schema-constrained proposals only after exact coverage and model-contract checks.
3. Render a public-safe candidate and bind a candidate digest.
4. Require a fresh independent review before creating or advancing a Draft PR.
5. Require one owner receipt bound to the owner-bundle digest and exact candidate commit SHA before Ready for review.
6. Never merge, release, publish, or destructively clean without a separate explicit owner approval.

## Failure policy

Any missing, stale, conflicting, privacy-sensitive, or unverifiable input stops the transition. Recovery resumes from private machine state; it never rewrites frozen source history.

## Phase 3 operational boundary

The [dogfood promotion roadmap](../operations/dogfood-promotion-roadmap.md)
defines the operational-maturity modes, phase gates, repository authority,
required evidence, rollback, and owner-only promotion decisions. The
[Shadow validation protocol](shadow-validation.md) defines the permanent
read-only regression layer. They do not activate Roundwright or weaken the
active Roundlet bootstrap policy in the root [`AGENTS.md`](../../AGENTS.md).

External credential, environment, and disposable-target routing is defined
once in the [qualification test infrastructure](../operations/qualification-test-infrastructure.md);
its commit pins and public-safe evidence requirements do not grant authority.

Exactly one repository-scoped dispatcher may be authoritative for Roundwright
at a time. A controlled forward-test repository may have only separately
approved, bounded authority over its own actions; it never becomes a second
Roundwright dispatcher.

### Repository mutation vocabulary and transition

The Python schema v2 names in `roundwright.repository_policy` are the only
canonical Roundwright action vocabulary. `AGENTS.md` carries two deliberately
different marker pairs: the ACTIVE Roundlet authority and the INACTIVE
Roundwright standing-authority proposal. Each parser reads only its own exact
pair; absence, duplication, malformed values, fallback, inference, or values
borrowed from the other block fail closed.

Every GitHub mutation maps exactly once to a repository mutation, and every
repository mutation maps exactly once to a strict Boolean. Remote branch
create, non-force update, and delete are separate operations, and review
request has its own switch. A future Roundwright activation receipt must bind
external dispatcher-transition evidence proving Roundlet is no longer
mutation-capable, has been reconciled, and Roundwright is the selected exact
candidate. Dual-capable evidence is unrepresentable and rejected.

## Phase 0 non-goals

- An MCP-first runtime
- A Skill-owned runtime
- Dev Container-only distribution
- An organization-wide scanner
- Automatic merge
- Automatic release
- Independent multi-host dispatch
- A public repository during Phase 0
