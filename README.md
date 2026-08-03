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

## Development check

Use Python 3.12:

```text
python -m unittest discover -s tests -v
```
