# Issue 136 trusted advisory-role coverage

Issue 136 carries forward only the accepted behavioral boundary for two future
advisory roles. It does not migrate a legacy runtime, provider conversation,
or authority mechanism.

| Accepted behavior | Roundwright destination | Verification |
| --- | --- | --- |
| Recovery advice and owner-intent interpretation use ordinary configuration precedence, including one atomic typed environment pair. | `configuration.py` resolved profiles and source labels | Configuration precedence test. |
| The primary Supervisor uses `gpt-5.6-sol` with `high`; the two Terra/high fallbacks and review bounds remain unchanged. | `runtime-defaults.toml` | Packaged-default configuration test. |
| Every advisory request is a dedicated role instance bound to trusted guidance, repository, task, host, state, deployment, epoch, fence, and candidate. | `role_capability_policy.py` v2 instance receipt | Dedicated-instance mismatch tests. |
| Capability use requires independent authority, expiry, revocation, instance, and scope receipts and can only be the profile intersection. | `role_capability_policy.py` v2 grant/admission receipts | Cross-role, stale, revoked, copied-state, and excessive-capability adversarial tests. |
| Guidance is read only from an accepted-revision manifest and explicit root, with nested precedence and no ambient discovery. | `role_capability_policy.py` guidance resolver | Candidate/global/implicit-context leakage tests. |
| Advisory profiles and grants do not create effective authority or a background service. | `role_capability_policy.py` production entrypoint | Disabled-without-grant and receipt-only entrypoint tests. |
| Public output is digest-only and excludes guidance text, source locations, candidates, and instance identifiers. | `role_capability_policy.py` | Public-safety adversarial tests. |

`phase5-coverage-map.json` carries four checked implementation destinations for
this issue; its validator rejects omission or drift before rendering the
candidate-bound coverage receipt.

The source attribution retained by this migration is the resolved configuration
layer label and digest identities only. It intentionally does not preserve a
legacy path, raw instruction, provider payload, or owner message.
