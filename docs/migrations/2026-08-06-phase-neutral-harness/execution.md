# Execution record

## Owner-approved inputs read back on 2026-08-06

| Repository | Canonical checked main | Relevant merged topology | Current-run selection |
| --- | --- | --- | --- |
| `ythdelmar68/roundwright-harness` | `50230b38aa8cfc371792286f6a14a2b92545c720` | Merge parents `63b93ca461dbd25dd8a0edd896983ec258d5dc31` and `681c7e9359a3767892a615ffa032d42b51e7be15` | Immutable qualification content: `681c7e9359a3767892a615ffa032d42b51e7be15`, a verified ancestor and second merge parent; do not substitute main. |
| `ythdelmar68/roundlet-forward-test` | `4f39ef0e4e616eb896950d3756c433b624771a97` | Merge parents `a2fbd157057eca042edd74affdb8b64ef7db560e` and `060cbd90e77e94872b89742741692887383a51b8` | No live target invocation in this documentation transition. |

Both local external checkouts were reported reconciled and clean at their stated
canonical main identities. That reconciliation is context for pin selection,
not a license to use a floating main ref. Every later leaf must persist the
exact harness commit and, if applicable, exact forward-test commit selected for
that leaf before it touches an external gate.

## Local transition

- Roundwright candidate before this documentation change:
  `6929530937de64c05bd01f8bc0262439ca8d2370`.
- Scope: documentation, planning, issue-proposal, and migration artifacts only.
- Native provider fixture invoked: **false**.
- Shadow comparison invoked: **false**.
- GitHub mutation, push, PR readiness, merge, and closure: **false**.
