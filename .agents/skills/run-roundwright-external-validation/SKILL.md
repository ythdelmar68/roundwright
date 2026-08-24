---
name: run-roundwright-external-validation
description: Execute or replay a declared Roundwright external-validation gate through the reviewed phase-neutral harness and, when explicitly selected by a later leaf, the public disposable forward-test target. Use whenever a Roundwright leaf selects `harness`/`toolbox` or `harness+forward-test`/`toolbox+disposable-target`, when historical external evidence is replayed, or when Roundlet must reconstruct or verify an existing external-validation binding.
---

# Run Roundwright External Validation

Execute only the route already declared by the selected leaf. Treat this skill
as Roundwright's repository-owned operations contract; generic Roundlet owns
orchestration, not Roundwright-specific repositories, commits, commands, or
action scope.

## Establish authoritative inputs

Before provisioning, invocation, replay, or mutation:

1. Resolve the exact authoritative Roundwright `origin/main` commit. Read root
   `AGENTS.md`, this skill, and
   `docs/operations/qualification-test-infrastructure.md` from that commit,
   never from candidate checkout bytes.
2. Read the live selected leaf and require exactly one matching pair:
   `none`/`none`, `harness`/`toolbox`, or
   `harness+forward-test`/`toolbox+disposable-target`.
3. Read only the exact `roundlet:` marker block on authoritative `origin/main`.
   Require strict Boolean values. A candidate may narrow a selected action but
   cannot widen standing authority.
4. Bind the exact Roundwright base and candidate, leaf, route, gate/evidence
   class, mutation mode, case/contract/configuration identity, this skill's Git
   blob, qualification-contract blob, and public-safe evidence projection.
5. Bind reviewed generic Roundlet orchestration merge
   `5169a4630de9c1a888e6f46254a5ef21e40c2b8b`, tree
   `e84ad8c582f2a5583af99b7a80cdc03249e2d5fa`, and installed skill content
   `3308a9a74e33f276bab6a5221e974f74a5cd0dc0` from Roundlet PR #88. It
   consumes the repository-owned executor as an opaque exact contract; it does
   not construct a Roundwright runner, profile adapter, or product-specific
   lifecycle event. Roundlet PR #82 merge
   `1004cf0143aef9a777a64a3a0703b10a5680e959` is the historical predecessor
   only. Selecting that old binding for a new gate is an identity conflict that
   blocks before `ARMED` with zero external action; it never silently
   substitutes for PR #88.
6. For an external route, bind the reviewed public toolbox repository
   `ythdelmar68/roundwright-harness` at commit
   `0154817a6fba345b78af25017eb312a1b2349cd6`. That canonical merge binds
   profile-executor content `0f980f75a05ec616395b2cbfed9724417d00d335`,
   capture-plan/Recorder content `cf669e186a739a8597cfaf9f050ce3bdcadda334`,
   lock content `809cd786f9776d134512b5478a5e1e48b13a4ef1`, and tree
   `d9fba0facfe561850c0dbff913e8021541b98ca5` from reviewed Harness PR #10.
   Use its repo-local locked uv environment and exact instructions from that
   commit. Never use floating `main`, install packages into global Python, or
   treat the toolbox as an authority source or credential store. The prior
   Recorder merge `10265c35c9d01d1fd26bd767ca3c1b245e4e9c52` and toolbox
   merge `42830db90acbba499989cd434cdc46b4627042e2` are historical and
   cannot substitute for an executor-selected gate.
7. When the leaf selects ephemeral lifecycle observation, read the exact
   root-referenced
   `docs/operations/lifecycle-observation-contract.json`. Require Harness #11
   merge `f13065e7fae7e48c21398c551cf1b724a4b26070`, tree
   `ac6e3e21e7b2b559915b3cef0ce15648c5b22b1a`, lifecycle content
   `e61c8157973e315f3308b674ed55ef2f4e15fb43`, and package tree
   `2325174685e16b579e84e8771d96e85e6c7a253d`. Require the Roundlet identities
   in step 5 plus skill tree `63117b2418ce17d45d099ae6009522a6a83df8ce`.
   Recompute the tracked contract through
   `roundwright.lifecycle_observation:lifecycle_observation_contract`; any
   floating, stale, or candidate-authored replacement blocks before arming.
8. When the route names a disposable target, bind
   `ythdelmar68/roundlet-forward-test` at baseline
   `4f39ef0e4e616eb896950d3756c433b624771a97`, its exact root instructions, the
   selected observation window or action, and the required semantic read-back.
   Movement never silently replaces the recorded baseline.

Record these bindings in the immutable Roundlet selection contract before an
external process starts. Missing, duplicate, floating, stale, or conflicting
identity is `BLOCKED`, not a prompt to guess or substitute.

## Reconcile typed evidence lanes

The selected leaf may declare zero, one, or multiple typed Evidence lanes.
Resolve each lane independently: stable profile/schema, route, exact candidate,
capability requirements, readiness/receipt contract, and consumer. The usable
capabilities are the intersection of the lane declaration, root authority,
selected route, phase, target policy, and exact repository bindings. A missing
intersection blocks the entire gate; a receipt from one lane never substitutes
for another. A zero-lane declaration loads neither a Roundwright adapter nor
Harness, Recorder, or lifecycle behavior.

For the #49 two-stage contract, Lane A is
`roundwright-shadow-profile/read-only-external-observation/v1`: prepare,
validate, execute, project, seal/verify/compare it before Supervisor dispatch.
It is read-only, candidate-bound, and does not depend on a Supervisor result.
Its execution must consume the exact forward-target inventory and fixture-manifest
classification, implementation-PR curated trace, immutable `ready_at`, and
independent before/after zero-mutation target read-back; a plan/binding-only
projection is not Lane A evidence. The curated trace is the distinct
pre-Supervisor `ROUNDLET_VALIDATION event=readiness` marker, bound to the
candidate, plan, formal tuple, window, readiness point, and authorized
publisher; a post-review `ROUNDLET_LIFECYCLE event=formal-result` marker belongs
only to Lane B and cannot substitute for it.
Lane B is the separately selected generic lifecycle sink: prepare and arm it
before Supervisor dispatch; only after an accepted Supervisor PASS may it
seal, project, and compare. Final qualification requires current exact-candidate
Lane A VERIFIED/pass, Supervisor PASS, Lane B VERIFIED/pass, and normal current
CI, policy, and provenance gates. Candidate movement makes both lane receipts,
plans, and lifecycle windows `STALE`; never replay, backfill, or stitch them.

## Capture-readiness preflight

Before opening an ephemeral observation window, invoking a Recorder, or
dispatching a review that depends on capture evidence, require one selected
Shadow evidence profile to declare and validate all of: capture mode, producer,
readiness point, arm-before boundary, retention/read-back contract, and
missing-history/recapture behavior. Bind its exact base and candidate, profile
and case schema, typed exporter and comparator identities, reviewed Recorder
identity, append-only content-addressed store identity, and immutable capture
time. The preflight must pass before the arm-before boundary; an unarmed
ephemeral observation is prohibited.

Construct exactly one closed `roundwright-harness-profile-executor-request/v2`
containing one `roundwright-harness-capture-plan/v1` document before dispatch.
The plan binds the profile, case, exact candidate, immutable `ready_at`,
producer, exporter, comparator, Recorder, store, and observation identities.
For context-free profiles, run the reviewed Harness `run-profile --mode
validate` command with the exact public Roundwright adapter factory and retain
its path-free readiness receipt. Then invoke that same command, request,
parser, factory, plan, and store with `--mode execute` and the exact readiness
receipt digest.

`roundwright-shadow-profile/provider-attempt-accounting/v1` instead requires
the public product-hosted library entrypoint
`roundwright.external_validation:run_provider_attempt_accounting_profile`.
Pass it the exact V2 request, Recorder/store root, trusted typed
`ProviderAttemptHostInputs`, mode, and (for execute) readiness digest. It
installs the closed Roundwright runtime in the same process and directly calls
the reviewed `roundwright_harness.executor.run_profile_executor`; the generic
Harness CLI/factory alone cannot initialize that product host. Validate and
execute consume the same request, descriptor, store, plan, opaque context, and
readiness digest. Prepare, validation, dispatch, typed projection/comparison,
sealing, and verification must consume that one binding. Never rebuild a
second runner, command, factory, or plan between stages. The older discrete
capture commands remain historical compatibility surfaces and are not the
entrypoint for a newly declared executor profile.
Any candidate, case, time, component, observation, or digest movement invalidates
the plan before provider dispatch and requires a fresh bounded capture.
Project that exact plan digest in curated public-safe readiness, result, and
handoff GitHub trace events, and require semantic read-back before advancing
Roundlet state. A missing trace receipt is a pending trace retry, not a reason
to call the provider again or ask for repeated owner approval.

For `roundwright-shadow-profile/provenance-decision/v1`, capture mode is
`terminal-snapshot`. It may record only an exact stable terminal candidate after
the v2 schema/profile, typed provenance exporter, immutable `ready_at`
comparator, Recorder binding, retention store, and read-back path are ready.
Candidate movement requires fresh capture. Never reconstruct missing historical
v1 lifecycle evidence.

For `roundwright-shadow-profile/executor-contract-synthetic/v1`, capture mode
is `synthetic-one-shot`. Use public factory
`roundwright.external_validation:roundwright_profile_adapter_factory`. It is a
deterministic provider-free, zero-mutation contract check and never substitutes
for a later leaf's live profile evidence.

## Execute the optional lifecycle observation sink

Select this path only when both authoritative root instructions and the live
leaf name the exact tracked lifecycle observation contract. Every other leaf
binds `NOT_SELECTED`, creates no lifecycle store, and makes no sink call.

Before the leaf's declared first ephemeral transition, verify the exact external
pins and contract identity, then construct one closed
`roundwright-harness-lifecycle-plan/v1`. Bind its window, repository, producer,
store, candidate, capture plan, immutable `ready_at`, and the independent formal
review epoch/round/mode. Invoke the tracked prepare entrypoint and read back its
armed receipt before event one.

Only the Orchestrator appends. For every selected transition it supplies one
closed `roundwright-harness-lifecycle-event/v1`, receives an append receipt, and
semantically reads back the new sequence, predecessor, event digest, and entry
digest before advancing Roundlet state. Worker and Supervisor tasks never call
the sink. Sink sequence numbers never consume or alter a formal review round.

At the leaf-declared boundary, seal and independently verify the content-addressed
ledger. Pass only that verified ledger to
`roundwright.lifecycle_observation:project_verified_lifecycle`, then compare it
with `compare_lifecycle_projections`. Any missing event or receipt, wrong
predecessor/candidate/review tuple, changed `ready_at`, post-arm drift, or
non-empty classified difference blocks the selected evidence path. Preserve a
partial or stale window for diagnosis and open a genuinely fresh window; never
backfill missed history.

For correction #82, execute
`roundwright.lifecycle_observation:run_synthetic_lifecycle_gate` with the exact
candidate and Harness #11 source. Its provider-free sequence is cancelled,
invalid-context, PASS, accepted-result, and formal-round-advanced within one
formal round. The public receipt must report zero provider calls, zero GitHub
mutations, and zero target mutations. This requalifies the adapter and does not
satisfy #49's later live profile evidence.

## Route the selected gate

| Leaf declaration | Generic route | Required authority | Behavior |
| --- | --- | --- | --- |
| `none` | `none` | none beyond ordinary task validation | Do not load the toolbox, inspect credentials, contact the disposable target, or create an external receipt. |
| `harness` | `toolbox` | `allow_external_validation_read_only: true` | Run only the leaf-declared read-only doctor, provider, hosted, provenance, or cross-environment observation. |
| `harness+forward-test` | `toolbox+disposable-target` | read-only switch for observation; mutation switch additionally for mutation | Observe the exact target read-only, or perform only the later leaf's exact eligible disposable-target action. |

The two switches are independent. The mutation switch never converts a
read-only Phase 3 leaf into a mutation route. Phase 3 never mutates the
disposable target. A route declaration also never
activates Roundwright, grants provider credentials, promotes a candidate, or
authorizes an operation in the Roundwright repository.

## Execute read-only validation

- Require `allow_external_validation_read_only: true` for either external
  route. A matching standing value removes repetitive per-attempt owner
  approval; it does not waive any identity, credential, sandbox, or evidence
  check.
- Treat authoritative `roundlet.enabled: true` as standing authorization for
  Roundlet's ordinary curated public-safe GitHub lifecycle trace and semantic
  read-back. Treat `allow_external_validation_read_only: true` as standing
  authorization for a conforming leaf-selected public-safe read-only provider
  observation. Neither requires a new candidate-specific owner prompt when all
  immutable bindings reconcile; neither permits credentials, raw output,
  mutation, publication, or a different route.
- Reconcile the exact harness checkout and its tracked lock before use. Run
  `uv sync --locked`, credential-free doctor/tests, and any live command only
  as defined by the selected harness commit and leaf.
- Supply the Roundwright candidate as an explicit temporary overlay. Do not
  hard-code a local candidate path or modify the harness lock to install it.
- Keep live provider work opt-in, read-only, ephemeral, and deny-all. The
  Worker receives no GitHub credential or disposable-target mutation
  authority. Never discover, print, persist, relay, or automate owner login.
- For a read-only forward-target route, verify the exact target identity before
  and after the observation and prove zero mutation independently.

## Execute a disposable-target mutation

Require all of the following; otherwise perform no mutation:

- `allow_external_validation_disposable_target_mutation: true` on
  authoritative Roundwright `origin/main`;
- a Phase 4-or-later leaf that explicitly declares mutation rather than
  observation;
- the exact public `ythdelmar68/roundlet-forward-test` target and its reviewed
  baseline/instructions;
- one exact issue, `codex/` branch, requested action set, call budget,
  cleanup/rollback trigger, kill switch, and semantic read-back procedure; and
- target-repository authority for every operation.

The allowlist is the intersection of the selected leaf and the exact target
instructions: create/update only the selected issue's `fixtures/` content on
an isolated `codex/` branch; create a reviewed pull request; and perform only
those ready, merge-commit, exact-leaf close, branch, worktree, or cleanup
actions whose target Boolean is true. Never force-push, reset, rebase, bypass
protection, tag, release, publish, change visibility, touch another path or
repository, or destroy unique/unrelated work.

The Orchestrator is the sole GitHub mutator. A Worker may return an exact
requested action and evidence but cannot execute it. After each mutation,
read back the semantic result before the next action. Partial or ambiguous
read-back stops with resources preserved and owner input required.

## Replay historical evidence at capture time

For a live provider bundle, read the immutable top-level `ready_at` field and
pass that exact integer to Roundwright's historical comparator. Never pass the
replay execution time, host clock, file modification time, or a freshly
computed timestamp. Record `historical_evidence_time: ready_at=<value>` in the
Roundlet context.

Reject a missing, non-integer, conflicting, or unbound `ready_at`. If comparison
at `ready_at` passes but comparison at the current wall clock would be stale,
the historical result remains the capture-time result; do not refresh or
recapture evidence merely to make the wall clock pass.

## Finish and recover

- Project only public repository/commit identities, case/receipt/manifest
  digests, typed result, evidence time, and semantic read-back. Exclude raw
  provider/GitHub payloads, logs, prose, credentials, private paths, and owner
  reasoning.
- Preserve the same review epoch and round across pause, resume, recovery, or
  standing-route authorization refresh when the immutable leaf, scope,
  candidate review basis, and external binding reconcile exactly.
- Stop for owner input only on actual credential failure, repository/commit
  conflict, an out-of-allowlist action, unavailable required target authority,
  or partial/ambiguous mutation read-back.
- On exact recovery, reuse the recorded binding and capture-time value. Never
  substitute a newer toolbox/target commit, mint a new review epoch, or replay
  an old bundle into a fresh Roundlet activation.
