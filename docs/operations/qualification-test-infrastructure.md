# Qualification test infrastructure

## Purpose and ownership

This is Roundwright's single source for external-validation repositories,
reviewed identities, route translation, action boundaries, and public-safe
evidence. The repository-owned
[`$run-roundwright-external-validation`](../../.agents/skills/run-roundwright-external-validation/SKILL.md)
skill executes this contract after a leaf selects a route.

The active Roundlet block in root `AGENTS.md` is the authority source. This
document and the skill cannot activate Roundwright, grant credentials, promote
a candidate, or widen either repository's policy. A candidate policy edit is
inert until reviewed, merged to authoritative `origin/main`, and acknowledged
by the allowlisted owner.

## Approved infrastructure and immutable identities

| Role | Public repository | Reviewed identity | Permitted use | Never use it as |
| --- | --- | --- | --- | --- |
| Execution toolbox | `ythdelmar68/roundwright-harness` | canonical merge `42830db90acbba499989cd434cdc46b4627042e2`; tree `4107953c2d9a97c0446a5a9789bd823493cf4839` | Exact candidate-bound read-only doctor, provider, hosted, provenance, Shadow, canary, and cross-environment commands under the standing read-only switch | A floating ref, Roundwright authority source, credential store, global Python environment, or mutation target |
| Disposable remote target | `ythdelmar68/roundlet-forward-test` | baseline `4f39ef0e4e616eb896950d3756c433b624771a97` | Read-only Phase 3 observation and exact Phase 4-or-later allowlisted lifecycle/Canary work under the independent mutation switch | Production, unique work, Roundwright authority, another repository, or a floating target |

Harness PR #3 repaired content
`e5ec738c67130b17a8e723b89a4b567e1873838d`; canonical merge
`42830db90acbba499989cd434cdc46b4627042e2` has parents
`2d412311d8ddbeb1db538111126a6e5dd62297b1` and that repaired content. Both
resolve to tree `4107953c2d9a97c0446a5a9789bd823493cf4839`.
Exact-head CI run `31115923833` passed, and independent COMPLETE review
reported VALID/PASS without findings, as curated in Roundwright PR #57 comment
`5207059725`.

The original harness pin
`681c7e9359a3767892a615ffa032d42b51e7be15` remains non-qualifying. Prior
content `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`, merge
`2d412311d8ddbeb1db538111126a6e5dd62297b1`, and its evidence remain
historical only. Never replace a recorded pin because a branch, tag, or
`main` moved.

The reviewed toolbox uses a repo-local `.venv`, committed `uv.lock`, and
factory `roundwright_harness.native:native_factory`. `uv` may be installed
globally or per-user, but Python and packages remain repository-local. A
Roundwright candidate is an explicit temporary overlay, never a lockfile
dependency or global installation. The factory consumes already-resolved
native channels; it does not discover credentials, load tokens, or automate
login.

## Standing authority

The authoritative Roundlet block contains two independent strict Booleans:

- `allow_external_validation_read_only`: a selected conforming route may run
  read-only without a new per-attempt owner approval;
- `allow_external_validation_disposable_target_mutation`: a later selected
  route may perform only its exact allowlisted operations in the exact public
  disposable target, with rollback and semantic read-back.

A `true` value is standing repository-scoped owner authorization, not a waiver.
It applies only after the selected leaf, exact candidate, reviewed toolbox,
target when applicable, operation, evidence time, rollback, and read-back all
agree with authoritative source. Missing, malformed, stale, conflicting, or
unverifiable input blocks the action. A read-only leaf remains zero-mutation
even when the independent mutation Boolean is `true`.

Phase 3 never mutates the forward-test target. Phase 4-or-later mutation also
requires the exact leaf to declare mutation and the target repository's own
authoritative instructions to permit every requested operation. The effective
allowlist is their intersection: one exact target issue, isolated `codex/`
branch, changes only under `fixtures/`, reviewed pull request, and only the
ready, merge-commit, exact-leaf close, branch, worktree, and cleanup operations
whose target Booleans are true. Force push, reset, rebase, protection bypass,
tag, release, publication, visibility changes, other paths/repositories, and
destruction of unrelated or unique work are prohibited.

## Windows execution boundary

The approved Windows host is an ordinary low-privilege user. `uv` is global or
per-user only; the toolbox's `.venv` owns Python and packages. When an agent
filesystem sandbox denies child execution, the exact selected live command may
run as the same low-privilege user outside that filesystem sandbox so Python
can launch hermetic Git and the pinned Codex runtime. This is not administrator
elevation, a global package install, credential authority, or permission for a
different command.

## Routing decision

Issue planning uses Roundwright vocabulary; generic Roundlet uses phase-neutral
routes:

| Roundwright declaration | Generic Roundlet route | Target use |
| --- | --- | --- |
| `none` | `none` | No external toolbox or target. |
| `harness` | `toolbox` | Exact selected execution toolbox only. |
| `harness+forward-test` | `toolbox+disposable-target` | Exact selected toolbox and approved public disposable target. |

The planning skill records the route; the execution skill resolves it. A route
does not itself grant credentials or mutation. Roundlet mechanically fills only
values that authoritative policy makes exact. It never invents a future
candidate SHA, floating ref, missing action, or absent authority.

| Gate or work class | Declaration | Required selection | Evidence and authority boundary |
| --- | --- | --- | --- |
| Hermetic Roundwright validation | `none` | Roundwright candidate | Local deterministic evidence; no external credential, toolbox, or target. |
| Live SDK/provider or host qualification | `harness` | Candidate plus reviewed harness commit | Content-free typed read-only probe; no task dispatch or remote mutation. |
| Hosted or forward-target observation | `harness` or `harness+forward-test` | Candidate, harness, and target when used | Read-only observation plus independently verified zero mutation. |
| Disposable lifecycle/Canary | `harness+forward-test` | Candidate, harness, target baseline, exact action/budget/rollback/read-back contract | Phase 4-or-later only; Orchestrator is sole mutator and target policy must allow every action. |
| Cross-environment validation | route selected by the leaf | Candidate, harness, target when needed, environment, case, and contract | Comparable public-safe evidence; a missing environment blocks instead of waiving the gate. |

## Selection, replay, and evidence discipline

Before invocation, persist the exact Roundwright base/candidate SHA, selected
leaf, route, policy and skill blobs, contract/configuration, harness commit,
target baseline when applicable, environment, observation window or action,
Shadow case, rollback, and semantic read-back. Reconcile those durable bindings
on every retry or recovery. Movement invalidates the selection; it does not
authorize substitution.

Historical external replay uses the immutable bundle's capture time. For live
provider evidence, the required field is the top-level integer `ready_at`.
Pass that exact value to the Roundwright comparator. Never substitute replay
execution time, host wall clock, file time, or a fresh timestamp. Missing or
conflicting capture time makes the replay invalid.

Public-safe evidence may contain exact public repositories/commits, declared
environment, case/task/attempt identifiers, curated receipt or manifest
digests, capture time, typed comparison/gate result, and semantic read-back.
It excludes credentials, tokens, raw provider/GitHub payloads or prose, raw
logs, private paths, secret-bearing configuration, and internal owner
reasoning. A public-safe projection is evidence, not an authority receipt.

## Owner interaction and recovery

Do not request repetitive owner approval when the route and both required
standing/target policies match. Request owner input only for an actual
credential/login failure, repository or commit conflict, out-of-allowlist
action, unavailable required target authority, or partial/ambiguous mutation
read-back. Preserve resources on those failures; never substitute provider,
target, action, evidence time, or policy explanation.

Pause, resume, recovery, or standing-route refresh preserves the same review
epoch and round when the immutable leaf, scope, candidate review basis, and
external binding reconcile unchanged. A fresh Roundlet activation never
recovers an old bundle.

Roundlet remains the sole mutation-capable Orchestrator for Roundwright until a
separate owner-reviewed transition changes the root authority policy. The
toolbox and forward-test target never make Roundwright active and never waive
native provider health, typed Shadow, exact-candidate checks, CI, or merge
gates.

## Reuse by phase

- **Phase 3:** read-only native Codex, hosted, forward-target, and typed Shadow
  qualification; zero target mutation.
- **Phase 4:** bounded cross-environment and disposable-target Canary under the
  standing mutation Boolean plus exact leaf/target action contract.
- **Phase 5:** operations, migration, promotion evaluation, and retained
  evidence using exact infrastructure identities.
- **Phase 6:** release-readiness validation using the same selection discipline;
  release/publication remains separately prohibited unless later authorized.

See the [dogfood promotion roadmap](dogfood-promotion-roadmap.md) for phase and
activation boundaries, and the [leaf issue planning contract](leaf-issue-template.md)
for declarations created before execution.
