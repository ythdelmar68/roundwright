# Qualification test infrastructure

## Purpose and ownership

This is the single routing source for external validation used by Roundwright
gates. It selects a phase-neutral execution toolbox and, only when separately
approved, a disposable remote mutation target. It does not activate
Roundwright, change the disabled authority surface, grant credentials, or
authorize a repository mutation. Roundwright product code owns its typed
contracts and gates; the owner-approved external repositories only supply a
bounded environment or a disposable test target.

## Approved infrastructure and immutable bindings

| Role | Public repository | Approved identity | Use | Never use it as |
| --- | --- | --- | --- | --- |
| Execution toolbox | `ythdelmar68/roundwright-harness` | Selected content: `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`; canonical main merge: `2d412311d8ddbeb1db538111126a6e5dd62297b1`; historical non-qualifying pin: `681c7e9359a3767892a615ffa032d42b51e7be15` | Bounded native read-only provider-health and typed Shadow sequence for the separately bound Roundwright candidate | A Roundwright authority source, a credential store, a floating `main` ref, or an invocation of the historical pin |
| Remote mutation target | `ythdelmar68/roundlet-forward-test` | Canonical main: `4f39ef0e4e616eb896950d3756c433b624771a97` | A public, disposable target for explicitly approved remote lifecycle/mutation tests | Production, a unique-work target, or authority over Roundwright |

The historical qualification content pin is intentionally **not** silently
replaced by harness main. `681c7e9359a3767892a615ffa032d42b51e7be15` remains
non-qualifying and must not be invoked for this or any future candidate. The
owner selected `52b1ad81ca2e13b40f4244f431fad9c231ab4c28` from merged harness
PR #2 for one exact Roundwright binding only. Its canonical harness main merge
is `2d412311d8ddbeb1db538111126a6e5dd62297b1`, whose parents are
`50230b38aa8cfc371792286f6a14a2b92545c720` and the selected content commit;
both selected content and merge resolve to tree
`ec5bdd3f3bafbfdc9d473b2b46f4f3ec9e83c891`. All other superseded PR #2 heads
remain unselected. A branch name, tag, or `main` is never an authorization or
evidence identity.

The selected factory is `roundwright_harness.native:native_factory` at the
selected content commit. The authenticated owner selected it in issue #42
comment `5205387378` for Roundwright candidate
`b1279ff00547c84980bd413076c0b0f9fbbde432`; exact-head CI run `31104589401`
and an independent COMPLETE PASS are supporting evidence, not a waiver. The
selection permits only the bounded native read-only provider-health and typed
Shadow sequence for that exact candidate. It does not invoke either gate
automatically, authorize credentials, provider work, review, CI, merge, or any
mutation. Once the candidate moves, a later run must reconcile and persist a
fresh owner-bound selection; it cannot reuse this record by inference.

Any selected factory consumes already-resolved native channels; it does not
discover credentials, load tokens, or automate login. `uv` may be global or
per-user; Python environments and all packages remain inside the harness
repository's repo-local `.venv`, with no global Python package installation.

## Routing decision

| Gate or work class | External validation | Required immutable selection | Evidence and authority boundary |
| --- | --- | --- | --- |
| Hermetic Roundwright tests | `none` | Roundwright candidate only | Local deterministic test evidence; no external credential, toolbox, or target. |
| Live read-only SDK/provider qualification | `harness` | Candidate plus exact harness commit | At most the separately defined content-free read-only probe; owner-safe receipt and typed Shadow input only. No task dispatch or remote mutation. |
| GitHub lifecycle or mutation test | `harness+forward-test` | Candidate, exact harness commit, exact forward-test commit, and separately approved target scope | Semantic read-back and curated receipts only. The forward-test target is disposable; all mutation authority remains separately checked. |
| Cross-environment or canary | `harness` plus only an explicitly owner-approved disposable target | Candidate, exact toolbox commit, exact target commit, declared environment, scope, and rollback identity | Comparable public-safe evidence; missing environment evidence is a blocker, never a waiver. |

## Candidate, target, and evidence discipline

Before invocation, a leaf records the exact Roundwright base/candidate SHA,
contract/configuration identity, selected harness commit, selected target commit
when applicable, declared gate/evidence class, and reference/Shadow case
identity. A later run must reconcile those durable bindings; it may not replace
an old pin with a current branch head. Candidate movement, target movement,
missing read-back, or any unsupported identity invalidates the evidence.

Public-safe evidence may include exact public commit identities, repository
names, declared environment, case IDs, curated receipt or manifest digests,
typed comparison result, gate result, and semantic read-back. It must exclude
credentials, tokens, provider prose or raw payloads, private paths, raw logs,
owner-private reasoning, and secret-bearing configuration. A public-safe
projection is evidence, not an authority receipt.

## Owner interaction and non-authority semantics

The owner supplies interactive login or other sensitive input only in the
approved toolbox when a typed gate requires it. Code, tasks, and fixtures must
not discover, print, persist, relay, or automate that input. Missing or expired
authentication stops the gate for owner input with resources retained; it does
not cause provider substitution or an inferred policy explanation.

Roundlet remains the sole mutation-capable Orchestrator for Roundwright until a
separate owner-reviewed transition changes the root authority policy. The
toolbox and forward-test repository do not make Roundwright active, do not
waive native provider health, typed Shadow, exact-candidate checks, CI, or
merge gates, and do not permit a candidate to self-promote.

## Reuse by phase

- **Phase 3:** route native Codex and typed Shadow qualification through the
  harness when live evidence is separately required.
- **Phase 4:** route canary and cross-environment work through the harness and
  only the explicitly approved disposable target.
- **Phase 5:** route operations, migration, promotion evaluation, and retained
  evidence through exact infrastructure pins when external validation is
  required.
- **Phase 6:** route release-readiness validation through the same selection
  discipline; a release decision remains separately owner-authorized.

See the [dogfood promotion roadmap](dogfood-promotion-roadmap.md) for phase
entry/exit boundaries and the [leaf issue template](leaf-issue-template.md) for
the declaration every new leaf must make.
