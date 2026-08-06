# Cross-document consistency audit

## Required discovery path

| Starting surface | Link or rule verified | Destination |
| --- | --- | --- |
| Root `AGENTS.md` | Mandatory external-validation routing pointer | `docs/operations/qualification-test-infrastructure.md` |
| Roadmap | Phase 3-6 routing link and reuse statement | Canonical infrastructure document |
| Operator-facing README | Operational documentation link | Canonical infrastructure document |
| Shadow and authority docs | External bundle/pinning and non-authority links | Canonical infrastructure document |
| New-leaf template | Mandatory five-field declaration | Canonical infrastructure document |
| Umbrella proposals #2/#3/#4 | Proposed concise canonical link | Canonical infrastructure document |

## Pin and wording checks

- Harness canonical main: `50230b38aa8cfc371792286f6a14a2b92545c720`.
- Current qualification content pin: `681c7e9359a3767892a615ffa032d42b51e7be15`.
- Forward-test canonical main: `4f39ef0e4e616eb896950d3756c433b624771a97`.
- All future leaves/gates must select exact commits; no document permits a
  floating main ref.
- Every document calls evidence public-safe and routing non-authoritative.
- No local document claims that native provider, Shadow, CI, or merge evidence
  has been produced by this transition.

## Audit result

The local repository now has a deterministic route from root instructions,
roadmap/operator documentation, future leaf template, and proposed umbrella
surfaces to one canonical contract. Remote proposals remain unapplied and
require an Orchestrator-owned bounded GitHub transition.
