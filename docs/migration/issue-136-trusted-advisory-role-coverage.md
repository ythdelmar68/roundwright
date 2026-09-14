# Issue 136 trusted advisory-role coverage

Issue 136 carries forward only the accepted behavioral boundary for two future
advisory roles. It does not migrate a legacy runtime, provider conversation,
or authority mechanism.

| Accepted behavior | Roundwright destination | Verification |
| --- | --- | --- |
| Recovery advice and owner-intent interpretation use ordinary configuration precedence, including one atomic typed environment pair. | `configuration.py` resolved profiles and source labels | Configuration precedence test. |
| The primary Supervisor uses `gpt-5.6-sol` with `high`; the two Terra/high fallbacks and review bounds remain unchanged. | `runtime-defaults.toml` | Packaged-default configuration test. |
| Every advisory request is a dedicated role instance bound to trusted guidance, repository, task, host, state, deployment, epoch, fence, and candidate. | `role_capability_policy.py` v3 instance receipt | Restart and fenced-replacement task-binding tests. |
| Capability use requires an existing owner/deployment read-back record, its independently pinned expectation, expiry, revocation, instance, and closed typed scope receipts; public output is only the granted intersection. Public/candidate callers cannot resolve or directly construct a sealed admission. The only construction route is an inert composition seam; production installs no issuer or composition root and therefore denies admission. The hermetic test issuer demonstrates the contract only, not live authority. | `role_capability_policy.py` v3 grant/admission receipts | Public-construction denial, stale, replay, drifted, post-read mutation, cross-seam, and capability-expansion adversarial tests. |
| Guidance is derived mechanically from the root-to-task `AGENTS.md` chain in an authoritative pinned Git tree selected through the existing Git-entrypoint control. Candidate, global, unrelated, omitted, and ambient files are not inputs. | `role_capability_policy.py` Git guidance resolver | Nested, traversal, revision, tree-drift, and origin-control leakage tests. |
| This milestone supplies a production-disabled contract, not a trusted host root. Every public effect-capable Worker, Supervisor/provider runtime, dependency-review, hosted/recovery adapter, and external-validation composition path denies before provider session construction or native turns. The installed coding runtime independently denies both direct construction and dispatch; the former executable fixture behavior is not an installed production route. Hermetic qualification remains explicit and uses only fake dependencies. Closed scopes cover exact paths, processes, test-input sets, deny-network posture, and resource seals; a scope-root identity is mechanically derived from the resolved effect root and a mismatch denies before tool construction. Provider seams require their own closed accepted-input, network, and resource descriptors rather than consuming a broad action alone. `TrustedProviderLaunchContext` is immutable and verification authenticates every visible instruction field against one sealed accepted-guidance payload, rejecting coherent multi-field mutation. The SQLite ledger still reserves each exact host-derived effect binding before a provider effect. No qualified native discovery-off control exists, so every real/native bridge remains `NOT_ACTIVATED`. Advisor and Interpreter stay non-dispatching. | `role_capability_policy.py`, `coding_tools.py`, `*_toolbox.py`, and `provider_attempt_runtime.py` | Omission, forged, wrong-role, stale, revoked, cross-seam, request/preflight A-to-B replay, exact-exposure and concurrent-budget, ungranted-tool, direct-runtime zero-effect denial, root-label substitution, missing test/network/resource descriptors, and coherent sealed-launch mutation tests using temporary-Git hermetic records. |
| Public output is digest-only and excludes guidance text, source locations, candidates, and instance identifiers. | `role_capability_policy.py` | Public-safety adversarial tests. |

`phase5-coverage-map.json` carries the complete versioned artifact inventory
for this issue. Its validator rejects an omitted or drifted implementation,
test, or migration record and also binds the rendered candidate receipt to the
named executable boundaries and adversarial test identities above; hashes alone
are not treated as semantic qualification.

The source attribution retained by this migration is the resolved configuration
layer label and digest identities only. It intentionally does not preserve a
legacy path, raw instruction, provider payload, or owner message.

Skill disposition: `create-roundwright-leaf` is not applicable because this
work implements an existing leaf and does not create, split, or rescope one.
`run-roundwright-external-validation` is not applicable because Issue 136 has
no declared external-validation gate. Neither disposition changes runtime
authority.
