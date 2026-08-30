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
  --build-arg ROUNDWRIGHT_CANDIDATE_SHA=<40-lowercase-hex> \
  --build-arg ROUNDWRIGHT_BASE_IMAGE_DIGEST=sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2 \
  -t roundwright-consumer:local .
```

The Dockerfile verifies that digest and runs `pip install --no-index --no-deps`.
It copies only that wheel, so an artifact mismatch fails before installation.

## Mount contract and modes

`docker/compose.yaml` provides three dedicated services:
`roundwright-authoritative`, `roundwright-read-only`, and
`roundwright-test-only`. The host owns every input and makes it available at a
stable container target:

| Input | Container target | Mode | Owner |
| --- | --- | --- | --- |
| canonical repository | `/workspace` | read-only | repository operator |
| authoritative state (including SQLite and lock) | `/var/lib/roundwright` | read/write only for authoritative; read-only otherwise | state authority |
| typed configuration | `/etc/roundwright/config.toml` | read-only | configuration authority |
| operator authentication location | `/run/roundwright/auth.toml` | read-only | operator |
| external authority receipt | `/run/roundwright/authority-receipt.json` | read-only | authority store |

The container runs as UID/GID `65532`. Before starting it, grant that identity
the minimum access required for the mounts: traversal/read for the read-only
inputs and read/write for the state directory. Do not place credentials or
receipt contents in environment variables, image layers, logs, or this
repository.

Prepare disposable public-safe qualification inputs with the exact candidate:

```text
python ci/write_docker_consumer_fixture.py --candidate <40-lowercase-hex> --state <state-directory> --configuration <config.toml> --authentication <auth.toml> --output <authority-receipt.json>
```

Set `ROUNDWRIGHT_REPOSITORY`, `ROUNDWRIGHT_STATE`,
`ROUNDWRIGHT_CONFIGURATION`, and `ROUNDWRIGHT_AUTHENTICATION` for every mode.
Set `ROUNDWRIGHT_AUTHORITY_RECEIPT` and its SHA-256 only for authoritative
mode. Repository, configuration, authentication, and receipt mounts must be
read-only. The authoritative state must be owned and writable by UID/GID
`65532`; read-only and test-only state must not be writable.

Every invocation selects its dedicated Compose service:

- `roundwright-authoritative` requires the authority-receipt mount and an exact,
  candidate-bound external receipt. Missing, copied, conflicting, or mismatched
  authority input is blocked.
- `roundwright-read-only` and `roundwright-test-only` do not mount an authority
  receipt. Supplying one through another service is blocked so a
  non-authoritative invocation cannot be confused with an
  active deployment.

The container must use the existing native-host durable control record in the
mounted state. Restart, cancellation, stale-process recovery, single active
lock, SQLite state, canonical worktree, candidate, and receipt behavior are
therefore the same deterministic paths covered by `tests/test_native_host.py`;
the Docker consumer does not replace them.

## Installed commands

The image entrypoint performs the path-free preflight and then dispatches the
installed package CLI. It must not print host paths, credential values, or
receipt content. Run the three modes with their dedicated Compose services:

```text
docker compose -f docker/compose.yaml run --rm roundwright-authoritative doctor
docker compose -f docker/compose.yaml run --rm roundwright-read-only status
docker compose -f docker/compose.yaml run --rm roundwright-test-only status
docker compose -f docker/compose.yaml run --rm roundwright-test-only run-once
```

`run-once` is intentionally blocked by the package and returns exit code 3;
the entrypoint propagates that exact result. Doctor reports mount availability,
ownership, permission mismatch, and candidate/receipt status without exposing
a secret or private path.

## Offline qualification

On a Docker-capable host with the pinned base already present, run the build
above and the three Compose commands, then the ordinary candidate toolchain
suite and package preflight. The hosted qualification is network-disabled
after its pinned-base pull and uploads only public-safe evidence. No registry,
Canary, GitHub, provider, or image-publication operation is part of this
consumer qualification.
