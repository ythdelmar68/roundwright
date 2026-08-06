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

- Selected harness content: `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`.
- Canonical harness main merge: `2d412311d8ddbeb1db538111126a6e5dd62297b1`; parents are `50230b38aa8cfc371792286f6a14a2b92545c720` and the selected content, with shared tree `ec5bdd3f3bafbfdc9d473b2b46f4f3ec9e83c891`.
- Selection record: authenticated owner issue #42 comment `5205387378`, factory `roundwright_harness.native:native_factory`, bound only to Roundwright candidate `b1279ff00547c84980bd413076c0b0f9fbbde432`.
- Supporting facts: exact-head CI run `31104589401` succeeded; independent COMPLETE review published PASS. Neither fact is a gate waiver or provider/Shadow invocation.
- Historical non-qualifying qualification pin: `681c7e9359a3767892a615ffa032d42b51e7be15`; it must not be invoked. All superseded PR #2 heads remain unselected.
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
