# Issue 132 scoped-denial and recovery coverage

Issue #132 adds the provider-neutral `roundwright-failure-recovery/v1`
contract.  It is a production-entrypoint classification boundary for Worker,
Supervisor, and dependency-review adapters; it neither activates a provider
nor maps native SDK errors (that belongs to #137).

| Requirement | Producer | Public-safe consuming gate |
| --- | --- | --- |
| Scope-bound verified denial stops dispatch until an exact later clearance | `failure_recovery.py` typed record and immutable binding | hermetic `test_failure_recovery` |
| Missing output, ambiguous effect, model prose, and unavailable telemetry reconcile rather than replace | typed classifier | hermetic `test_failure_recovery` |
| Only verified terminal lifecycle or transient-service evidence reaches a pre-bound equivalent route | `admit_recovery` | hermetic `test_failure_recovery` |
| Worker, Supervisor, and dependency-review retain independent role positions | three production seam classifiers | hermetic `test_failure_recovery` |

This extends #112's public-safe coverage destinations with public type names,
case identities, and record digests only.  It does not rewrite historical
receipts, publish provider output, or establish live-provider qualification.

The durable state migration retains an idempotent canonical record per digest.
The original denial remains immutable: an explicit verified-host clearance is a
new decision bound to the same candidate, policy, configuration, scope, role,
profile, session, and attempt.  Changed binding, unavailable evidence, or an
unapproved route fails closed.
