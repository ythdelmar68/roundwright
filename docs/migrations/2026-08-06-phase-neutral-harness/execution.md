# Execution record

## Owner-approved inputs read back on 2026-08-06

| Repository | Canonical checked main | Relevant merged topology | Current-run selection |
| --- | --- | --- | --- |
| `ythdelmar68/roundwright-harness` | `42830db90acbba499989cd434cdc46b4627042e2` | Merge parents historical prior merge `2d412311d8ddbeb1db538111126a6e5dd62297b1` and repaired PR #3 content `e5ec738c67130b17a8e723b89a4b567e1873838d`; both resolve to tree `4107953c2d9a97c0446a5a9789bd823493cf4839` | Repaired content is reviewed but pending fresh authenticated owner selection for the resulting Roundwright candidate. Prior `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`/`2d412311d8ddbeb1db538111126a6e5dd62297b1` is historical evidence only; `681c7e9359a3767892a615ffa032d42b51e7be15` remains non-qualifying. |
| `ythdelmar68/roundlet-forward-test` | `4f39ef0e4e616eb896950d3756c433b624771a97` | Merge parents `a2fbd157057eca042edd74affdb8b64ef7db560e` and `060cbd90e77e94872b89742741692887383a51b8` | No live target invocation in this documentation transition. |

Both local external checkouts were reported reconciled and clean at their stated
canonical main identities. That reconciliation is context for pin selection,
not a license to use a floating main ref. Every later leaf must persist the
exact harness commit and, if applicable, exact forward-test commit selected for
that leaf before it touches an external gate.

## Local transition

- Roundwright candidate before this documentation change:
  `b1279ff00547c84980bd413076c0b0f9fbbde432`.
- Prior selection: issue #42 comment `5205387378` bound factory
  `roundwright_harness.native:native_factory` at historical content
  `52b1ad81ca2e13b40f4244f431fad9c231ab4c28` only to the candidate above.
- Repair evidence: PR #3 content
  `e5ec738c67130b17a8e723b89a4b567e1873838d`, exact-head CI run `31115923833`
  SUCCESS, and independent COMPLETE VALID/PASS evidence in PR #57 comment
  `5207059725`.
- The repaired content is pending fresh authenticated owner selection for the
  resulting candidate. It authorizes no invocation, provider/credential access,
  Shadow, review, CI, merge, mutation, or waiver. The new candidate must enter
  fresh epoch 4 round 1 COMPLETE review after exact-head CI.
- Windows boundary: ordinary low-privilege user; global/per-user `uv` only;
  repo-local `.venv`, Python, and packages. When a filesystem sandbox denies
  child execution, a separately authorized live host process may permit Python
  to launch hermetic Git and pinned Codex runtime outside that sandbox. This is
  not administrator elevation or global package installation; the SDK remains
  deny-all, read-only, and ephemeral.
- Pre-review/pre-selection READY 5/5 observations, receipts, and manifest are
  non-qualifying diagnostic evidence only and cannot be carried forward as the
  formal provider-health gate for the resulting candidate.
- Scope: documentation, planning, issue-proposal, and migration artifacts only.
- Native provider fixture invoked: **false**.
- Shadow comparison invoked: **false**.
- GitHub mutation, push, PR readiness, merge, and closure: **false**.
