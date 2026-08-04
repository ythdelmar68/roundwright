# Authority Model

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

Exactly one repository-scoped dispatcher may be authoritative for Roundwright
at a time. A controlled forward-test repository may have only separately
approved, bounded authority over its own actions; it never becomes a second
Roundwright dispatcher.

## Phase 0 non-goals

- An MCP-first runtime
- A Skill-owned runtime
- Dev Container-only distribution
- An organization-wide scanner
- Automatic merge
- Automatic release
- Independent multi-host dispatch
- A public repository during Phase 0
