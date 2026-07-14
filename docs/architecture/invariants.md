# Architecture Invariants

These invariants define the minimum trustworthy operating boundary for Roundwright.

## Single Orchestrator

Exactly one repository-scoped Orchestrator owns dispatch and state transitions.

## Authoritative deployment

One configured deployment is authoritative for scheduling and mutation decisions.

## SQLite machine truth

SQLite is the canonical machine-readable state; prose artifacts are views and receipts.

## Deterministic gates

Code validates identity, coverage, policy, privacy, and receipts before state changes.

## Bounded model roles

Model sessions receive minimized inputs, schema-constrained outputs, and no mutation authority.

## Proposal separation

Dependency and implementation proposals remain separate from authoritative scheduling decisions.

## Credential isolation

Workers and reviewers do not receive repository or GitHub mutation credentials.

## Exact identity

Every decision, artifact, review, and approval is bound to exact digests and candidate identity.

## Trusted policy

Only repository-owned, reviewed policy may authorize automation behavior.

## Fail-closed mutation

Missing, stale, conflicting, or unverifiable evidence blocks mutation.

## Scheduler boundary

Independent workers cannot self-dispatch or bypass the Orchestrator queue.

## Explicit Phase 0 non-goals

- An MCP-first runtime
- A Skill-owned runtime
- Dev Container-only distribution
- An organization-wide scanner
- Automatic merge
- Automatic release
- Independent multi-host dispatch
- A public repository during Phase 0
