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
5. For an external route, bind the reviewed public toolbox repository
   `ythdelmar68/roundwright-harness` at commit
   `42830db90acbba499989cd434cdc46b4627042e2`. Use its repo-local locked uv
   environment and exact instructions from that commit. Never use floating
   `main`, install packages into global Python, or treat the toolbox as an
   authority source or credential store.
6. When the route names a disposable target, bind
   `ythdelmar68/roundlet-forward-test` at baseline
   `4f39ef0e4e616eb896950d3756c433b624771a97`, its exact root instructions, the
   selected observation window or action, and the required semantic read-back.
   Movement never silently replaces the recorded baseline.

Record these bindings in the immutable Roundlet selection contract before an
external process starts. Missing, duplicate, floating, stale, or conflicting
identity is `BLOCKED`, not a prompt to guess or substitute.

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
