# Packaging validation toolchain

## Boundary

Roundwright's packaging gate consumes one version-controlled lock and one
repo-local receipt. The bootstrap interpreter only executes the standard-library
resolver; it is not used to build, test, install, or qualify Roundwright and is
not part of the resulting evidence identity.

The tracked inputs are:

- `ci/validation-toolchain.lock.toml`, including the exact uv release artifacts
  and SHA-256 values for every supported OS/architecture, plus an explicit
  resolver/receipt contract revision;
- `ci/validation-build.in` and its hash-locked compiled requirements;
- `ci/validation-toolchain.in` and its hash-locked pipx dependency resolution;
- the resolver, strict lock/receipt validator, package verifier, tests, and CI
  workflow.

Generated uv binaries, managed Python installations, virtual environments,
caches, and receipts are never tracked. They remain under:

```text
.roundlet/validation-tools/
  <lock-digest>/
    <os>-<arch>-cpython-<version>/
      uv/
      python/
      build-env/
      uv-tools/pipx/
      uv-cache/
      receipt.json
```

The repository's local `.git/info/exclude` must exclude `.roundlet/`. Do not add
Roundlet runtime state or validation caches to repository-wide ignore rules.

## Provision and use

For canonical-checkout and CI validation, use any host-discovered Python 3.12
interpreter only as the bootstrap command. The resolver's default lock and
cache root are anchored to that checkout:

```text
<bootstrap-python> ci/resolve_validation_toolchain.py provision
<bootstrap-python> ci/resolve_validation_toolchain.py verify
<bootstrap-python> ci/resolve_validation_toolchain.py exec-python -- -m unittest discover -s tests -v
```

For an isolated candidate worktree, first verify the exact candidate SHA, then
run the candidate's resolver and candidate lock while naming the authoritative
checkout's shared cache explicitly. Global resolver arguments precede the
operation:

```text
<bootstrap-python> ci/resolve_validation_toolchain.py --lock ci/validation-toolchain.lock.toml --cache-root <authoritative-checkout>/.roundlet/validation-tools provision
<bootstrap-python> ci/resolve_validation_toolchain.py --lock ci/validation-toolchain.lock.toml --cache-root <authoritative-checkout>/.roundlet/validation-tools verify
<bootstrap-python> ci/resolve_validation_toolchain.py --lock ci/validation-toolchain.lock.toml --cache-root <authoritative-checkout>/.roundlet/validation-tools exec-python -- -m unittest discover -s tests -v
```

Run those commands with the candidate worktree as the current directory. Do not
copy the resolver or lock into the authoritative checkout and do not create a
candidate-local validation cache. Record the exact candidate SHA with the
public-safe lock digest, platform cache key, receipt status, and command results.
The receipt remains lock/platform-bound; the surrounding Worker handoff binds
that verified receipt and result to the candidate SHA.

`provision` is the only networked transition. It downloads the lock-selected uv
archive, verifies its SHA-256 before execution, installs only the exact managed
CPython, and synchronizes both environments from fully hashed requirements.
It disables permanent PATH changes, Python executable links, Windows Python
registry registration, user configuration discovery, and system-Python
discovery. It neither creates uv self-update metadata nor invokes self-update.
No global Python package is installed.

`verify` and `exec-python` require a complete receipt at the exact
lock/platform cache key. They never fall back to `PATH`, another Python, a
floating branch, a user tool directory, or an older cache. The receipt binds:

- the byte digest of the tracked lock;
- OS, architecture, implementation, and complete Python patch version;
- the build and pipx requirements digests;
- relative executable paths, versions, and file hashes;
- content digests for the managed Python, build, and pipx environments; and
- a canonical receipt digest.

Verification rejects missing, duplicate, or extra fields; a moved receipt;
unknown paths; path traversal; missing files; lock, requirements, platform, or
version drift; modified executables or environments; and failed version
read-back.

## Packaging preflight

After building `dist/` through `exec-python`, run:

```text
<bootstrap-python> ci/resolve_validation_toolchain.py exec-python -- ci/verify_installs.py dist
```

The verifier receives the exact receipt path from `exec-python`. It exercises a
fresh pip environment, pipx with explicit locations, pipx with the pinned
version's default locations, and a fresh uv tool location. All install commands
use absolute receipt-bound executables and the receipt-bound managed Python.
The candidate wheel is installed offline with no dependencies before each
public command smoke test.

On a Windows agent filesystem sandbox, repo-local Python may be denied when it
launches hermetic Git subprocesses. The ordinary low-privilege host boundary
documented in [qualification test infrastructure](qualification-test-infrastructure.md)
may be used for those tests when separately authorized. That boundary does not
change the toolchain receipt, grant runtime authority, or permit a remote gate.

## Ownership, recovery, and upgrades

`.roundlet/validation-tools/` is a host-owned reusable repository cache, not
run-owned state. Normal Roundlet stop, reconcile, cleanup, or worktree removal
must not delete it. CI may cache the same directory using a key derived from the
tracked lock and requirements.

A missing cache may be provisioned. A directory without `receipt.json` is an
incomplete cache and fails closed. `provision --rebuild` may remove and recreate
only the exact current lock/platform directory; use it explicitly after a failed
provision, never as automatic recovery from a receipt mismatch. A valid but
drifted receipt is evidence of tampering or corruption and must be investigated
before any cleanup.

To upgrade a tool:

1. update the applicable `.in` file or exact uv/Python entry;
2. bump the resolver revision when resolver or receipt semantics change;
3. regenerate requirements with the reviewed uv version and hash checking;
4. update the tracked requirements digests and uv artifact digests;
5. run the hermetic contract tests and packaging preflight; and
6. review and merge the lock change through a normal PR.

The changed lock bytes create a new digest-addressed cache. Never update an
existing valid cache in place. Removal of an inactive cache is a separate,
explicit owner or retention action.
