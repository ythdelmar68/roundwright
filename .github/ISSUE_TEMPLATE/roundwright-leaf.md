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

- Evidence lanes: `[]` | ordered typed lanes below; a zero-lane leaf loads no
  Roundwright adapter, Harness, Recorder, or lifecycle sink.
- Lane <name>: <stable profile/schema>; route; required capability intersection;
  exact-candidate readiness/receipt; arm/seal boundary; consuming gate; public-safe fields.
- Lane substitution: <forbidden; each lane needs its own current receipt>
- External validation: `none` | `harness` | `harness+forward-test`
- Generic Roundlet route: `none` | `toolbox` | `toolbox+disposable-target`
- External validation execution skill: `$run-roundwright-external-validation`
- Historical replay time: immutable bundle `ready_at` | `not applicable`
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

## Capture-readiness preflight

- Lane qualification order: <Lane A prepare→validate→execute→project→seal/verify/compare
  before Supervisor; Lane B ARMED before Supervisor, then seal/project/compare after accepted PASS; or N/A>
- Evidence profile: <schema/profile identity or N/A with reason>
- Capture mode: <terminal-snapshot or profile-defined mode>
- Producer: <durable typed source; never raw provider prose>
- Capture readiness point: <all schema/exporter/comparator/Recorder/store/read-back bindings>
- Arm-before boundary: <the exact export or observation boundary>
- Retention/read-back contract: <append-only content-addressed identity and receipt>
- Missing-history/recapture behavior: <candidate movement or missing history rule>
- Lifecycle observation sink: <NOT_SELECTED or exact authoritative contract path/identity>
- Lifecycle event source: <generic Orchestrator transitions or N/A>
- Lifecycle arm-before transition: <exact first ephemeral transition or N/A>
- Lifecycle seal boundary: <exact terminal evidence boundary or N/A>

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
