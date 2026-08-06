# Execution record

## Owner-approved inputs read back on 2026-08-06

| Repository | Canonical checked main | Relevant merged topology | Current-run selection |
| --- | --- | --- | --- |
| `ythdelmar68/roundwright-harness` | `2d412311d8ddbeb1db538111126a6e5dd62297b1` | Merge parents `50230b38aa8cfc371792286f6a14a2b92545c720` and selected content `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`; both resolve to tree `ec5bdd3f3bafbfdc9d473b2b46f4f3ec9e83c891` | Owner-selected content `52b1ad81ca2e13b40f4244f431fad9c231ab4c28` from merged PR #2 for the exact candidate record below. Historical `681c7e9359a3767892a615ffa032d42b51e7be15` remains non-qualifying and must not be invoked. |
| `ythdelmar68/roundlet-forward-test` | `4f39ef0e4e616eb896950d3756c433b624771a97` | Merge parents `a2fbd157057eca042edd74affdb8b64ef7db560e` and `060cbd90e77e94872b89742741692887383a51b8` | No live target invocation in this documentation transition. |

Both local external checkouts were reported reconciled and clean at their stated
canonical main identities. That reconciliation is context for pin selection,
not a license to use a floating main ref. Every later leaf must persist the
exact harness commit and, if applicable, exact forward-test commit selected for
that leaf before it touches an external gate.

## Local transition

- Roundwright candidate before this documentation change:
  `b1279ff00547c84980bd413076c0b0f9fbbde432`.
- Authenticated owner selection: issue #42 comment `5205387378` by
  `ythdelmar68`; selected factory
  `roundwright_harness.native:native_factory` at
  `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`.
- Supporting public evidence: exact-head CI run `31104589401` succeeded and an
  independent COMPLETE review published PASS. These facts do not invoke the
  selected gate or waive any native provider-health, Shadow, candidate, CI, or
  merge requirement.
- Scope of this selection: only bounded native read-only provider-health and
  typed Shadow for the exact candidate above. The following documentation
  commit is not itself selected; a candidate change requires fresh reconciliation
  and owner-bound selection.
- Scope: documentation, planning, issue-proposal, and migration artifacts only.
- Native provider fixture invoked: **false**.
- Shadow comparison invoked: **false**.
- GitHub mutation, push, PR readiness, merge, and closure: **false**.
