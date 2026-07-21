# roundwright

`roundwright` currently provides only a config-free, read-only `doctor` command.
It does not dispatch work, access providers, or mutate repositories.

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
become active policy.

## Development check

Use Python 3.12:

```text
python -m unittest discover -s tests -v
```
