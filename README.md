# roundwright

`roundwright` currently provides only a config-free, read-only `doctor` command.
It does not dispatch work, access providers, or mutate repositories.

## Development check

Use Python 3.12:

```text
python -m unittest discover -s tests -v
```
