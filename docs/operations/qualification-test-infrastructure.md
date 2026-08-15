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
| Generic Orchestrator | `ythdelmar68/roundlet` | canonical merge `96772438b251e56d483733179939245565b1374a`; skill content `cdfaec6fbcb521edb96a65a88ed4eed62a84f07a`; tree `d2aa36b492210dc411b5c1a5c927dc7d286ff21f` | Consume one exact repository-owned executor and track only generic readiness/execution/verification state | Roundwright profile logic, Recorder, provider adapter, evidence store, or a second runner |
| Execution toolbox | `ythdelmar68/roundwright-harness` | canonical merge `0154817a6fba345b78af25017eb312a1b2349cd6`; executor content `0f980f75a05ec616395b2cbfed9724417d00d335`; tree `d9fba0facfe561850c0dbff913e8021541b98ca5` | Exact candidate-bound read-only doctor, provider, hosted, provenance, Shadow, canary, and cross-environment commands under the standing read-only switch | A floating ref, Roundwright authority source, credential store, global Python environment, or mutation target |
| Disposable remote target | `ythdelmar68/roundlet-forward-test` | baseline `4f39ef0e4e616eb896950d3756c433b624771a97` | Read-only Phase 3 observation and exact Phase 4-or-later allowlisted lifecycle/Canary work under the independent mutation switch | Production, unique work, Roundwright authority, another repository, or a floating target |

Roundlet PR #80 added generic consumption of repository-owned validation
executors. Canonical merge `96772438b251e56d483733179939245565b1374a`
has parents `8ba2813e8aac869cf1f3ebbe78104d03a9134c4a` and
`6e48b50bce06383845a92f1b403e3d461cde33e1`, resolves to tree
`d2aa36b492210dc411b5c1a5c927dc7d286ff21f`, and binds installed skill
content `cdfaec6fbcb521edb96a65a88ed4eed62a84f07a`. The official skill
validator and repository structure checks passed.

Harness PR #10 added V2 execution-context materialization to the one
phase-neutral versioned profile executor. Canonical merge
`0154817a6fba345b78af25017eb312a1b2349cd6` has first parent
`369d964c44a7ef4653e13255d7c3e6a9ae87eeeb`, content parent
`0f980f75a05ec616395b2cbfed9724417d00d335`, and tree
`d9fba0facfe561850c0dbff913e8021541b98ca5`. PR #10 is merged and its
hermetic CI succeeded. The V2 request materializes one product-owned opaque
context before validation and binds that identity through execution, projection,
comparison, Recorder sealing, and read-back.

Harness PR #8 added the historical V1 phase-neutral versioned profile executor. Canonical
merge `369d964c44a7ef4653e13255d7c3e6a9ae87eeeb` has parents
`1bb063d3f8f1fef9a24b3147b8bc99794e4637a7` and
`9680543fc5aa64b18d0c6a5f7a09c4e40697b6ae`, binds executor content
`0235427e02ea5b512a5fd5d81300f8b49ed4643c`, capture content
`cf669e186a739a8597cfaf9f050ce3bdcadda334`, and lock content
`809cd786f9776d134512b5478a5e1e48b13a4ef1`, and resolves to tree
`2756131387ab70c9511e8156fd4c595cc3996fd3`. Exact-head CI run
`31864128240` passed 68 hermetic tests. Validate and execute use the same
request, parser, adapter factory, plan, store, and entrypoint.

Harness PR #6 added the historical phase-neutral immutable capture-plan
entrypoint and binds readiness, dispatch, evidence, Recorder seal, and read-back to content
`cf669e186a739a8597cfaf9f050ce3bdcadda334`; canonical merge
`1bb063d3f8f1fef9a24b3147b8bc99794e4637a7` has parents
`10265c35c9d01d1fd26bd767ca3c1b245e4e9c52` and that content and resolves
to tree `632dcc3ecb3b8664de860844af2215ad5ade83e1`. Exact-head CI run
`31777654822` passed.

Harness PR #4 added reviewed Recorder content
`87094a4e780c692a00135421840c0e6713af5d35`; canonical merge
`10265c35c9d01d1fd26bd767ca3c1b245e4e9c52` has parents
`42830db90acbba499989cd434cdc46b4627042e2` and that Recorder content and
resolves to tree `0c594caa275262164fce1942ebd2142abe0e77bb`. Exact-head CI run
`31576479468` passed.

Harness PR #3 repaired historical phase-neutral toolbox content
`e5ec738c67130b17a8e723b89a4b567e1873838d`; canonical merge
`42830db90acbba499989cd434cdc46b4627042e2` has parents
`2d412311d8ddbeb1db538111126a6e5dd62297b1` and that repaired content. Both
resolve to tree `4107953c2d9a97c0446a5a9789bd823493cf4839`.
Exact-head CI run `31115923833` passed, and independent COMPLETE review
reported VALID/PASS without findings, as curated in Roundwright PR #57 comment
`5207059725`. This identity remains historical and cannot substitute for the
Recorder pin when a selected gate requires Recorder evidence.

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

The same authoritative block's `roundlet.enabled: true` covers Roundlet's
ordinary reversible lifecycle operations, including curated public-safe GitHub
trace publication and semantic read-back. The read-only external-validation
Boolean additionally covers a conforming leaf-selected public-safe read-only
provider observation. Once the exact leaf, candidate, profile, plan, route, and
policy reconcile, candidate movement alone does not require another owner
approval: it requires a fresh immutable plan. These standing meanings never
authorize raw provider output, credentials, hidden reasoning, repository
mutation outside the enumerated lifecycle, or a route not selected by the leaf.

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

## Capture-readiness preflight

Before an ephemeral observation begins, a selected Shadow profile must declare
and validate its capture mode, producer, readiness point, arm-before boundary,
retention/read-back contract, and missing-history/recapture behavior. The
preflight binds the exact base/candidate, schema/profile, typed
exporter/comparator, reviewed Recorder identity, append-only content-addressed
store, and immutable capture time. It must pass before the profile's arm-before
boundary; an unarmed observation, Recorder invocation, or review dispatch is
invalid.

`roundwright-shadow-profile/provenance-decision/v1` is a terminal-snapshot
profile. Its immutable `ready_at` comparator, public-safe provenance decision,
reviewed Recorder binding, and retention read-back must all be ready before
exporting the terminal candidate. Candidate movement requires a fresh capture;
the missing historical v1 lifecycle bundle is never reconstructed.

The concrete handoff is one closed
`roundwright-harness-profile-executor-request/v2` containing one
`roundwright-harness-capture-plan/v1` document with profile, case, candidate,
`ready_at`, producer, exporter, comparator, Recorder, store, and observation
identities. The reviewed Harness returns one path-free readiness receipt from
`run-profile --mode validate`. The exact same command, request, public
Roundwright adapter factory, plan, and store are then consumed once by
`--mode execute` using that readiness receipt digest. Profile readiness,
dispatch, typed export/comparison, recording, and read-back therefore use one
entrypoint and one plan. A second runner/projection, an inferred default, or any
identity movement invalidates readiness before external action; recapture
starts with a fresh request rather than rewriting evidence.

The public Roundwright factory is
`roundwright.external_validation:roundwright_profile_adapter_factory`. The
synthetic correction profile
`roundwright-shadow-profile/executor-contract-synthetic/v1` proves the contract
with deterministic zero-action, zero-mutation evidence. It does not satisfy or
replace a downstream leaf's live profile-specific evidence.

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
