# roundwright

`roundwright` currently provides only a config-free, read-only `doctor` command.
It does not dispatch work, access providers, or mutate repositories.

Its typed configuration boundary is available to later commands but creates no
files and requires no optional configuration for read-only startup. Effective
settings use this order: defaults, optional user TOML, optional
`.roundwright.toml` at a discovered repository root, environment, then command
line. Source attribution is intentionally path-free. Dispatch-capable commands
must separately pass repository preflight; no such command exists yet.

## Development check

Use Python 3.12:

```text
python -m unittest discover -s tests -v
```
