# Ownership and boundaries

## Single-source rule

`docs/operations/qualification-test-infrastructure.md` owns the complete
external-validation routing contract: approved repositories, exact pinning,
environment constraints, login handling, public-safe evidence, and
non-authority semantics. Other documents link to it and state only their local
phase use. Issue bodies use the concise declaration in the leaf template; they
do not reproduce the contract.

## Boundary table

| Concern | Owner | Not owned by |
| --- | --- | --- |
| Typed provider, Shadow, policy, and gate behavior | Roundwright product code | Harness or forward-test repositories |
| Toolbox/runtime construction and already-resolved native channels | Approved `roundwright-harness` commit | Roundwright candidate or a floating ref |
| Disposable remote lifecycle target | Approved `roundlet-forward-test` commit and separate owner scope | Production, unique work, or Roundwright authority |
| GitHub mutation and task orchestration | Roundlet under root `AGENTS.md` | Roundwright, harness, and Worker documentation |
| Sensitive interactive login/input | Owner in the approved harness | Fixtures, model sessions, public evidence, or repository state |

No link or commit in this bundle activates Roundwright. Roundlet remains the
sole mutation-capable Orchestrator until the root authority policy changes
through its separate owner-reviewed process.
