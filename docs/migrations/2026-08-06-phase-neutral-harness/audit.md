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

- Repaired PR #3 content: `e5ec738c67130b17a8e723b89a4b567e1873838d`.
- Canonical harness main merge: `42830db90acbba499989cd434cdc46b4627042e2`; parents are historical prior merge `2d412311d8ddbeb1db538111126a6e5dd62297b1` and repaired content, with shared tree `4107953c2d9a97c0446a5a9789bd823493cf4839`.
- Repair evidence: exact-head CI run `31115923833` SUCCESS and independent COMPLETE VALID/PASS trace comment `5207059725`.
- Historical prior selection: factory `roundwright_harness.native:native_factory` at `52b1ad81ca2e13b40f4244f431fad9c231ab4c28` bound only to candidate `b1279ff00547c84980bd413076c0b0f9fbbde432`; it is not current invocation authority.
- Historical non-qualifying qualification pin: `681c7e9359a3767892a615ffa032d42b51e7be15`; it must not be invoked. All superseded PR #2 heads remain unselected.
- The repaired content is pending fresh authenticated owner selection for the new candidate. READY 5/5 observations/receipts/manifest before review or selection are diagnostic only and cannot be the resulting candidate's formal gate.
- Windows boundary is ordinary low-privilege user, global/per-user `uv`, and repo-local `.venv`/Python/packages. A separately authorized live host process may permit hermetic Git and pinned runtime child execution outside a denying filesystem sandbox; this is not administrator elevation or global installation, and SDK access remains deny-all/read-only/ephemeral.
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
