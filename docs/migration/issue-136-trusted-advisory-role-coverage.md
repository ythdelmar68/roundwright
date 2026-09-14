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
| This milestone supplies a production-disabled contract, not a trusted host root. Every public effect-capable Worker, Supervisor/provider runtime, dependency-review, hosted/recovery adapter, and external-validation composition path fails at its first instruction before validation, state/store/Recorder construction, callbacks, checkpoints, provider-session construction, or native turns. Hermetic, zero-external-effect fixtures may exercise their typed seams only with a separately derived immutable execution expectation—repository, task, candidate, instance, host, deployment, epoch, fence, role, selected profile, actual request or attempt, and preflight—rechecked immediately before each fake effect. The provider-attempt fixture ledger serializes its admitted accounting before an attempt mutation or fake provider effect; unavailable or malformed persistence denies it. Worker tool requests remain bounded before their local callback. Accepted-main guidance bytes and the actual host cwd remain identities in a sealed launch envelope, but the native SDK exposes no qualified discovery-off control: prompt prose never claims to disable discovery, and every real bridge remains fail-closed. Dependency review uses an empty ephemeral fixture workspace while retaining the sealed host cwd for verification. Advisor and Interpreter stay non-dispatching. | `role_capability_policy.py` and Codex adapter entrypoints | Omission, forged, wrong-role, stale, revoked, cross-seam, request/preflight replay, concurrent-budget, ungranted-tool, sealed launch cwd/guidance drift, tamper, and first-instruction zero-effect denial tests using temporary-Git hermetic records. |
| Public output is digest-only and excludes guidance text, source locations, candidates, and instance identifiers. | `role_capability_policy.py` | Public-safety adversarial tests. |

`phase5-coverage-map.json` carries versioned artifact identities and digests
for this issue; its validator rejects an omitted or drifted implementation,
test, or migration record before rendering the candidate-bound coverage receipt.

The source attribution retained by this migration is the resolved configuration
layer label and digest identities only. It intentionally does not preserve a
legacy path, raw instruction, provider payload, or owner message.

Skill disposition: `create-roundwright-leaf` is not applicable because this
work implements an existing leaf and does not create, split, or rescope one.
`run-roundwright-external-validation` is not applicable because Issue 136 has
no declared external-validation gate. Neither disposition changes runtime
authority.
