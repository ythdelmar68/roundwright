# Proposed public issue updates

These are reviewed, deterministic **proposals only**. They were prepared from
read-only bodies on 2026-08-06 and are intentionally not applied by this
Worker. The Orchestrator must make and read back one bounded update at a time.
Each exact candidate SHA is filled at dispatch; neither `main` nor a branch
name is a substitute.

## Shared leaf declaration

For material leaves #42-#50, insert the following heading immediately before
the existing `## Shadow impact` heading, replacing the bracketed values with
the row-specific values below. Issue #51 has the dedicated deterministic patch
below because its body uses a different heading.

```markdown
## External validation declaration

- External validation: `<route>`.
- Gate/evidence class: `<class>`.
- Owner input/login required: `<owner-input>`.
- Exact candidate/target identity: persist the Roundwright base/candidate SHA,
  exact harness commit, and, when selected, exact forward-test commit before
  invocation; never use a floating ref. `<target-note>`
- Public-safe evidence boundary: exact public commit/case/receipt-or-manifest
  digest, typed result, and semantic read-back only; never credentials, tokens,
  raw provider/CLI payloads or prose, raw logs, or private paths.
```

The historical #42 harness content pin
`681c7e9359a3767892a615ffa032d42b51e7be15` is non-qualifying and must not be
invoked. For the owner-selected #42 run only, content
`52b1ad81ca2e13b40f4244f431fad9c231ab4c28` and factory
`roundwright_harness.native:native_factory` are bound to candidate
`b1279ff00547c84980bd413076c0b0f9fbbde432` by owner comment `5205387378`.
It remains distinct from canonical harness main merge
`2d412311d8ddbeb1db538111126a6e5dd62297b1`; any future candidate requires a
fresh explicit selection. The public forward-test canonical main currently read back is
`4f39ef0e4e616eb896950d3756c433b624771a97`. These values are recorded as
exact identities, never as floating references.

## Umbrella patches

| Issue | Exact anchor | Tight proposed insertion |
| --- | --- | --- |
| #2 | After `## Cross-phase scheduling extension` list | `- External validation routing for Phase 3 P0 leaves and later dependent gates is defined once in the repository qualification test infrastructure document. Each child selects exact commits and an evidence class; this umbrella does not duplicate that contract or grant authority.` |
| #3 | After `## Cross-phase scheduling extension` list | `- External validation routing for Phase 3 P1 leaves and later dependent gates is defined once in the repository qualification test infrastructure document. Each child selects exact commits and an evidence class; this umbrella does not duplicate that contract or grant authority.` |
| #4 | After `## Cross-phase scheduling extension` list | `- External validation routing for Phase 3 P2 leaves and later dependent gates is defined once in the repository qualification test infrastructure document. Each child selects exact commits and an evidence class; this umbrella does not duplicate that contract or grant authority.` |

## Leaf declaration values

| Issue | Route | Class | Owner input | Target note |
| --- | --- | --- | --- | --- |
| #42 | `harness` | live read-only SDK/provider qualification | `yes, only if the typed gate blocks for owner login in the approved harness` | `For candidate b1279ff00547c84980bd413076c0b0f9fbbde432, use selected content 52b1ad81ca2e13b40f4244f431fad9c231ab4c28 and factory roundwright_harness.native:native_factory; no forward-test target is selected. A moved candidate requires fresh owner selection.` |
| #43 | `harness` | bounded live Codex Worker adapter qualification | `yes, only if a typed provider gate requires it` | `Use the selected exact harness content commit; no remote mutation target.` |
| #44 | `harness` | bounded live Codex Supervisor attempt qualification | `yes, only if a typed provider gate requires it` | `Use the selected exact harness content commit; no remote mutation target.` |
| #45 | `harness` | candidate-bound provider/accounting qualification | `yes, only if a typed provider gate requires it` | `Use the selected exact harness content commit; no remote mutation target.` |
| #46 | `harness+forward-test` | explicitly approved GitHub lifecycle/mutation test | `yes, only in the approved harness when a typed gate requires it` | `Select exact harness and disposable forward-test commits plus the owner-approved operation scope before any remote test.` |
| #47 | `harness` | external runtime/dependency provenance qualification | `no, unless a separately typed external credential gate requires it` | `Use the selected exact harness content commit; no remote mutation target by default.` |
| #48 | `harness` | hosted CI/check read-only evidence | `no` | `Use the selected exact harness content commit; no remote mutation target by default.` |
| #49 | `harness+forward-test` | live read-only Shadow against a disposable target | `yes, only if a typed harness/provider or GitHub gate requires owner input` | `Select exact harness and forward-test commits; the target is public, disposable, read-only for this Phase 3 Shadow scope, and never production or unique work.` |
| #50 | `harness+forward-test` | integrated external-boundary proof | `yes, only in the approved harness when a typed gate requires it` | `Select exact harness and forward-test commits; any remote mutation remains separately denied or owner-authorized.` |
| #51 | `none` | qualification-gate evidence consumption | `no` | `Cite already-selected exact candidate/harness/target evidence; the gate itself does not invoke a provider or remote target.` |

## #51 dedicated declaration patch

Insert this complete section immediately before the existing
`## Shadow protocol and qualification references` heading in #51:

```markdown
## External validation declaration

- External validation: `none` for this evidence-consumption gate.
- Gate/evidence class: qualification-gate evidence consumption.
- Owner input/login required: `no`; any prior live gate retains its own typed
  owner-input boundary.
- Exact candidate/target identity: cite the already-persisted Roundwright
  base/candidate SHA, exact owner-selected harness commit, and exact
  forward-test commit when one was used. Never use a floating ref or replace a
  prior pin.
- Public-safe evidence boundary: exact public commit/case/receipt-or-manifest
  digest, typed result, and semantic read-back only; never credentials, tokens,
  raw provider/CLI payloads or prose, raw logs, or private paths.
```

## #49 stale-wording replacement

In #49, replace the first sentence under `## Phase 3 ownership`:

```markdown
This issue owns live read-only integration of the Phase 3 shadow contract with
the controlled private forward-test repository. It does not authorize canary
mutation.
```

with:

```markdown
This issue owns live read-only integration of the Phase 3 Shadow contract with
the public, disposable `ythdelmar68/roundlet-forward-test` repository at an
exact selected commit. It never treats that target as production or unique work
and does not authorize canary mutation.
```

Then insert #49's shared declaration before `## Shadow impact` using its row.
This preserves the issue's zero-mutation Phase 3 boundary while making the
public target and pinning rule explicit.

## Application record requirement

After any proposed update, the Orchestrator records the issue number, exact
post-update body revision/read-back identity, selected candidate/infrastructure
commit values if known, and public-safe operation receipt. A missing or
conflicting read-back blocks the next transition; this bundle must not be used
as evidence that the remote body has changed.
