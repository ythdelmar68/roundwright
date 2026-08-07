# Leaf issue planning template

Use this template for every new actionable leaf. It supplements the applicable
umbrella's dependency order; it does not make an umbrella a dependency or grant
authority. Consult the [qualification test infrastructure](qualification-test-infrastructure.md)
before selecting external validation.

```markdown
Parent: #<umbrella-or-none>

## Purpose

<bounded product purpose>

## Dependencies

- <exact leaf or standalone issue numbers only>

## External validation declaration

- External validation: `none` | `harness` | `harness+forward-test`
- Gate/evidence class: <hermetic, live read-only provider, hosted read-only,
  remote lifecycle/mutation, or cross-environment/canary>
- Owner input/login required: `no` | `yes, only in the approved harness`
- Exact candidate/target identity: Roundwright base/candidate `<40-hex>`;
  harness `<40-hex>` when selected; forward-test `<40-hex>` when selected;
  declared environment and approved mutation scope when applicable. Never use
  a floating ref.
- Public-safe evidence boundary: <allowed commit/case/digest/result/read-back
  fields>; no credentials, tokens, raw payloads/prose/logs, or private paths.

## Shadow impact

- Shadow cycle: <required / N/A with reason>
- Canonical references: <exact documents/issues>
- Exact evidence and comparison identity: <candidate, case, digest, result>

## Acceptance criteria

- [ ] <typed, bounded, candidate-bound conditions>

## Boundaries and non-goals

- <authority, phase, mutation, and deferred-work limits>
```

The declaration is a routing and evidence record. It never authorizes a live
provider call, remote mutation, promotion, or a change to the disabled
Roundwright authority surface.

If a leaf adds a `GitHubMutationOperation`, that same reviewed change must add
exactly one canonical `RepositoryMutationOperation`, exactly one strict
Boolean, the immutable mapping, denied/allowed/stale/wrong-candidate coverage,
and semantic read-back coverage. Missing, duplicate, extra, inferred, alias,
fallback, or `None` mappings are not deferrable follow-up work and must fail CI.
