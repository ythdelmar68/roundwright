# Minimal Docker deployment consumer

This is a deliberately small deployment *consumer*. It installs the same wheel
accepted by the native-host matrix; it never copies this repository's source,
creates policy or authority, reads an embedded credential, publishes an image,
or runs a second dispatcher. The Python base image is pinned in
[`docker/Dockerfile`](../../docker/Dockerfile), currently by the immutable
`sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`
manifest digest.

## Build from the host-qualified artifact

First build the candidate distribution with the receipt-bound validation
toolchain and bind its digest:

```text
<bootstrap-python> ci/resolve_validation_toolchain.py --lock ci/validation-toolchain.lock.toml --cache-root <authoritative-checkout>/.roundlet/validation-tools exec-python -- -m pip wheel --no-build-isolation --no-deps --wheel-dir dist .
<bootstrap-python> ci/resolve_validation_toolchain.py --lock ci/validation-toolchain.lock.toml --cache-root <authoritative-checkout>/.roundlet/validation-tools exec-python -- ci/verify_package_digest.py write dist
```

Use the wheel name and SHA-256 from `dist/package-digest.json`. The build must
run with network access disabled after its pinned base image has been made
available locally:

```text
docker build --network=none -f docker/Dockerfile \
  --build-arg ROUNDWRIGHT_WHEEL=roundwright-0.0.0-py3-none-any.whl \
  --build-arg ROUNDWRIGHT_WHEEL_SHA256=<64-lowercase-hex> \
  -t roundwright-consumer:local .
```

The Dockerfile verifies that digest and runs `pip install --no-index --no-deps`.
It copies only that wheel, so an artifact mismatch fails before installation.

## Mount contract and modes

`docker/compose.yaml` provides the exact mount contract. The host owns every
input and makes it available at a stable container target:

| Input | Container target | Mode | Owner |
| --- | --- | --- | --- |
| canonical repository | `/workspace` | read-only | repository operator |
| authoritative state (including SQLite and lock) | `/var/lib/roundwright` | read/write | state authority |
| typed configuration | `/etc/roundwright/config.toml` | read-only | configuration authority |
| operator authentication location | `/run/roundwright/auth.toml` | read-only | operator |
| external authority receipt | `/run/roundwright/authority-receipt.json` | read-only | authority store |

The container runs as UID/GID `65532`. Before starting it, grant that identity
the minimum access required for the mounts: traversal/read for the read-only
inputs and read/write for the state directory. Do not place credentials or
receipt contents in environment variables, image layers, logs, or this
repository.

Every invocation declares one mode:

- `authoritative` requires the authority-receipt mount and an exact,
  candidate-bound external receipt. Missing, copied, conflicting, or mismatched
  authority input is blocked.
- `read-only` and `test-only` do not accept an authority receipt. Supplying one
  is blocked so a non-authoritative invocation cannot be confused with an
  active deployment.

The container must use the existing native-host durable control record in the
mounted state. Restart, cancellation, stale-process recovery, single active
lock, SQLite state, canonical worktree, candidate, and receipt behavior are
therefore the same deterministic paths covered by `tests/test_native_host.py`;
the Docker consumer does not replace them.

## Path-free doctor preflight

The consumer wrapper supplies only status labels to the package's `doctor`
preflight boundary; it must not print host paths, credential values, or receipt
content. It passes the exact candidate, wheel digest, base image digest, five
mount statuses, and the candidate-bound receipt result. For example:

```text
roundwright doctor --docker-mode authoritative \
  --docker-candidate-sha <40-lowercase-hex> \
  --docker-package-digest sha256:<64-lowercase-hex> \
  --docker-base-image-digest sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 \
  --docker-mount repository=ready --docker-mount state=ready \
  --docker-mount configuration=ready --docker-mount authentication=ready \
  --docker-mount authority-receipt=ready \
  --docker-authority-receipt-digest sha256:<64-lowercase-hex> \
  --docker-authority-receipt-matches-candidate
```

Doctor reports each mount's availability, ownership, or permission mismatch
plus candidate/receipt status, without exposing a secret or private path.

## Offline qualification

On a Docker-capable host with the pinned base already present, run the build
above, then run `roundwright doctor` from the image and the ordinary candidate
toolchain suite and package preflight. No registry, Canary, GitHub, provider,
or image-publication operation is part of this consumer qualification.
