# Issue 136 trusted advisory-role coverage

Issue 136 carries forward only the accepted behavioral boundary for two future
advisory roles. It does not migrate a legacy runtime, provider conversation,
or authority mechanism.

| Accepted behavior | Roundwright destination | Verification |
| --- | --- | --- |
| Recovery advice and owner-intent interpretation use ordinary configuration precedence, including one atomic typed environment pair. | `configuration.py` resolved profiles and source labels | Configuration precedence test. |
| The primary Supervisor uses `gpt-5.6-sol` with `high`; the two Terra/high fallbacks and review bounds remain unchanged. | `runtime-defaults.toml` | Packaged-default configuration test. |
| Every advisory request is a dedicated role instance bound to trusted guidance, repository, task, host, state, deployment, epoch, fence, and candidate. | `role_capability_policy.py` v3 instance receipt | Restart and fenced-replacement task-binding tests. |
| Capability use requires an existing owner/deployment read-back record, its independently pinned expectation, expiry, revocation, instance, and closed typed scope receipts; public output is only the granted intersection. | `role_capability_policy.py` v3 grant/admission receipts | Self-minted, stale, drifted, and capability-expansion adversarial tests. |
| Guidance is derived mechanically from the root-to-task `AGENTS.md` chain in an authoritative pinned Git tree. Candidate, global, unrelated, omitted, and ambient files are not inputs. | `role_capability_policy.py` Git guidance resolver | Nested, traversal, revision, and tree-drift leakage tests. |
| Advisory profiles and grants do not create effective authority or a background service. | `role_capability_policy.py` production entrypoint | Disabled-without-grant and receipt-only entrypoint tests. |
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
