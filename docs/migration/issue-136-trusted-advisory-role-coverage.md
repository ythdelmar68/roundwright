# Issue 136 trusted advisory-role coverage

Issue 136 carries forward only the accepted behavioral boundary for two future
advisory roles. It does not migrate a legacy runtime, provider conversation,
or authority mechanism.

| Accepted behavior | Roundwright destination | Verification |
| --- | --- | --- |
| Recovery advice and owner-intent interpretation use ordinary configuration precedence. | `configuration.py` resolved profiles and source labels | Configuration precedence test. |
| The primary Supervisor uses `gpt-5.6-sol` with `high`; the two Terra/high fallbacks and review bounds remain unchanged. | `runtime-defaults.toml` | Packaged-default configuration test. |
| Every advisory request is a dedicated role instance bound to trusted guidance and one candidate. | `role_capability_policy.py` | Dedicated-instance mismatch tests. |
| Capability use requires an explicit, matching receipt and can only be the profile intersection. | `role_capability_policy.py` | Cross-role and excessive-capability adversarial tests. |
| Advisory profiles and grants do not create effective authority or a background service. | `role_capability_policy.py` production entrypoint | Disabled-without-grant and receipt-only entrypoint tests. |
| Public output is digest-only and excludes guidance text, source locations, candidates, and instance identifiers. | `role_capability_policy.py` | Public-safety adversarial tests. |

The source attribution retained by this migration is the resolved configuration
layer label and digest identities only. It intentionally does not preserve a
legacy path, raw instruction, provider payload, or owner message.
