# Inventory and applicability

## Repository artifacts changed locally

| Surface | Action | Reason |
| --- | --- | --- |
| `AGENTS.md` | Add mandatory pointer | A future credential/cross-environment/remote-lifecycle gate must discover the canonical route before planning. |
| `docs/operations/qualification-test-infrastructure.md` | Add canonical source | Own the complete external routing and pinning contract. |
| `docs/operations/leaf-issue-template.md` | Add template | Make the five required external-validation declarations mandatory for every new leaf. |
| Roadmap, README, Shadow, authority docs | Link only | Provide Phase 3-6 and operator reachability without duplicated policy. |
| This migration bundle | Add durable notes | Preserve inventory, ownership, conflicts, plan, execution, audit, and remote proposals. |

## Live GitHub bodies inspected read-only

The owner scope comment and open issues #2, #3, #4, and #42-#51 were read on
2026-08-06. No remote issue body, comment, label, PR, or state was changed.

| Issue | Applicability | Proposed local disposition |
| --- | --- | --- |
| #2 umbrella P0 | Material scheduling surface | Add one canonical-link scheduling sentence; no duplicated contract. |
| #3 umbrella P1 | Material scheduling surface | Add one canonical-link scheduling sentence; no duplicated contract. |
| #4 umbrella P2 | Material scheduling surface | Add one canonical-link scheduling sentence; no duplicated contract. |
| #42 provider health | Material | `harness`, live read-only provider qualification, owner login only if typed gate requests it. |
| #43 Worker adapter | Material | `harness`, bounded live Codex evidence separate from hermetic coverage. |
| #44 Supervisor adapter | Material | `harness`, bounded live Codex evidence separate from hermetic coverage. |
| #45 provider accounting | Material | `harness`, candidate-bound provider evidence only. |
| #46 GitHub adapter | Material | `harness+forward-test` only for separately approved remote lifecycle/mutation testing. |
| #47 provenance | Material | `harness`, external runtime/provenance evidence where explicitly enabled. |
| #48 hosted CI | Material | `harness`, hosted read-only evidence; no mutation target by default. |
| #49 live Shadow | Material and stale wording | `harness+forward-test`, read-only Shadow against public disposable target. |
| #50 integrated proof | Material | `harness+forward-test` for the explicit integrated external boundary. |
| #51 qualification gate | Material | `none` for gate consumption; it cites already-pinned evidence and does not itself invoke a target. |

Exact proposed text and insertion anchors are in `issue-proposals.md`.
