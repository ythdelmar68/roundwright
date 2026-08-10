---
name: Roundwright actionable leaf
about: Plan a P0, P1, P2, correction, or standalone Roundwright issue
title: ''
labels: ''
assignees: ''
---

Planning transaction state: `BLOCKED_SCHEDULING`

- Leaf class: `P0` | `P1` | `P2` | `correction` | `standalone`
- Parent: #<owning-umbrella> | `none`
- Phase ownership: <phase and bounded ownership statement>

## Purpose

<bounded product purpose>

## Dependencies

- <exact leaf or standalone issue numbers only; never an umbrella>

## External validation declaration

- External validation: `none` | `harness` | `harness+forward-test`
- Generic Roundlet route: `none` | `toolbox` | `toolbox+disposable-target`
- Gate/evidence class: <hermetic, live read-only provider, hosted read-only,
  remote lifecycle/read-only, remote lifecycle/mutation, or cross-environment/canary>
- Mutation mode: <no mutation, read-only observation, or exact policy-bounded
  mutation class>
- Owner input/login expected: <no; credential failure only; or exact reason>
- Selection-time bindings: <exact base/candidate/toolbox/target/environment/case
  identities when selected; never a guessed future SHA or floating ref>
- Public-safe evidence boundary: <allowed commit/case/digest/result/read-back
  fields>; no credentials, tokens, raw payloads/prose/logs, or private paths.

## Shadow impact

- Shadow cycle: <required / N/A with reason>
- Canonical references: <exact documents/issues>
- Evidence and comparison identity: <candidate, case, digest, result, or
  selection-time rule>

## Acceptance criteria

- [ ] <typed, bounded, candidate-bound condition>

## Boundaries and non-goals

- <authority, phase, mutation, and non-goal limits>

## Deferred work

- <explicit future phase or none>

## Scheduling reconciliation

- Required implementation order: <umbrella section and exact placement>
- Dependency matrix: <exact row>
- Cross-prerequisites and downstream gates: <exact affected issues/umbrellas>
- Formal parent read-back: <pending / verified>
- Umbrella and leaf read-back: <pending / verified>
