# roundwright

`roundwright` provides config-free, read-only `doctor` and `status` commands,
plus `run-once` and `run-daemon` command shells. The shells never dispatch
work in Phase 1: they fail closed before state, Git, network, provider, or
GitHub mutation unless a future caller supplies one exact, repo-external
authority receipt bound to the repository, canonical checkout, state UUID,
deployment identity, and validity window. The scheduler or service manager may
wake a shell but cannot grant authority or own workflow state.

Read-only and test-only modes require no receipt. Authoritative mode requires
one fresh external designation; missing, expired, copied, conflicting, or
drifted evidence becomes the explicit `blocked` mode. No Worker, Supervisor,
daemon lifecycle, credentials, or multi-host runtime exists here.

Its typed configuration boundary is available to later commands but creates no
files and requires no optional configuration for read-only startup. Effective
settings use this order: defaults, optional user TOML, optional
`.roundwright.toml` at a discovered repository root, environment, then command
line. Source attribution is intentionally path-free. Dispatch-capable commands
must separately pass repository preflight; no such command exists yet.
Repository TOML remains bound to the validated root that supplied it, so it
cannot rebind repository identity or make a different repository dispatch-ready.
Model and reasoning-effort defaults are typed configuration values with the
same precedence; configured values must be supplied as a validated pair.

The Codex provider-health boundary is similarly typed and deliberately narrow.
An external native credential store may supply an opaque, role-specific channel
for an exact SDK/runtime audit and one content-free read-only qualification
probe.  It cannot carry a task, prompt, tool request, or provider response.
Only adapter-supplied typed failure categories are persisted or rendered;
provider prose, raw payloads, credential locations, and secrets are rejected.
Observations are process-local and usable only through their explicit freshness
deadline.  Retry is limited to three qualification attempts and never enters a
Supervisor review lifecycle.  No Copilot SDK, runtime, or authentication path
is present.

### Opt-in live provider-health fixture

Hermetic coverage remains in `tests/test_provider_health.py` and
`tests/test_provider_health_live.py`. The separately invoked live harness is
`tests/live_provider_health.py`; its name deliberately excludes it from
`test*.py` discovery. It cannot run unless
`ROUNDWRIGHT_RUN_LIVE_PROVIDER_HEALTH` is exactly `1`.

It requires `ROUNDWRIGHT_LIVE_PROVIDER_FACTORY=dotted.module:callable`,
`ROUNDWRIGHT_CONTRACT_COMMIT=<40-lowercase-hex>`, and
`ROUNDWRIGHT_SHADOW_CASE_ID=<safe-id>`. It optionally accepts
`ROUNDWRIGHT_CANDIDATE_SHA=<40-lowercase-hex>`. The zero-argument factory must
return exactly `(RoleBoundCodexCredentialStore, CodexHealthContract,
Configuration)` using already-resolved native channels. Platform credential
discovery, token loading, login, provider substitution, and task dispatch are
excluded.

```text
python tests/live_provider_health.py
```

Exit `0` emits one canonical owner-safe READY JSON receipt bundle. A typed
qualification block emits a schema-validated owner-safe blocked bundle with
every selection observation and receipts only for fresh READY selections, then
exits `1`; malformed infrastructure emits only fixed blocked JSON. Exit `2`
emits fixed disabled JSON. No exception or provider prose, credential path,
token, raw payload, or private path is emitted. Each configured role/profile
receives at most one content-free, read-only qualification; receipt construction
may repeat only the typed runtime audit and never probes or dispatches tasks.
The resulting receipt evidence is intended for the existing typed Shadow
comparator and must be externally captured and cited before issue closure. This
documentation does not claim that a live run occurred.

The policy boundary is also pure and typed. A later Orchestrator must supply an
externally verified immutable control-source snapshot plus an owner activation
receipt bound to the exact task candidate. Policy evaluation returns only a
path-free decision and never performs mutations; task-worktree edits cannot
become active policy. Verified receipt lifecycle evidence is mandatory: absent,
unknown, replayed, stale, conflicting, or revoked evidence denies activation.
Absent or invalid policy and activation-receipt evidence also returns a
path-free denial rather than an implementation exception, including malformed
trusted source, policy-document, and activation-receipt structures. Invalid
receipt fields are not copied into owner-facing diagnostics.

For the Phase 2 positive proof, `roundwright.local_slice` exposes one explicit
test-fixture boundary. It joins the existing SQLite, local-Git, Worker, fresh
Supervisor, candidate, and gate contracts for a single isolated source. It is
not a command-shell mode and never calls a provider, GitHub, CI, or any other
networked service.

For Phase 3, `roundwright.shadow` is the reusable pure replay boundary. It
accepts only versioned, content-addressed case bundles bound to source, task,
base/candidate, policy, provider attempt, accepted review, gate, and next
action identities. The executor replays persisted Worker/Supervisor evidence
through the fixed lifecycle state machine and returns a typed comparison report.
Its capability adapter rejects Git, GitHub, repository, queue, branch,
worktree, pull-request, issue, merge, close, cleanup, and lifecycle mutations
before any callback can run.

## Operational documentation

Phase 3's [dogfood promotion roadmap](docs/operations/dogfood-promotion-roadmap.md)
keeps implementation phase separate from operational maturity. The
[Shadow validation protocol](docs/architecture/shadow-validation.md) defines
the permanent read-only comparison layer; neither document grants runtime or
repository mutation authority.

The [qualification test infrastructure](docs/operations/qualification-test-infrastructure.md)
is the single routing source for separately approved external credentials,
cross-environment execution, and disposable remote lifecycle tests. It pins
toolbox and target commits and remains non-authoritative.

## Development check

Use Python 3.12:

```text
python -m unittest discover -s tests -v
```
