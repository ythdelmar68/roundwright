# Minimal Dev Container consumer

This optional example is a development-environment view of the minimal Docker
consumer.  It builds [`docker/Dockerfile`](../../docker/Dockerfile) directly,
so it installs the same accepted wheel, uses the same pinned Python base, and
contains no copied source runtime or alternate dispatcher.  It is not a Dev
Container Feature or Template and does not publish an image.

## Build the exact artifact

First build and bind the candidate distribution with the receipt-bound
validation toolchain, as described by the [Docker consumer](docker-consumer.md).
From the repository root, provide the public wheel and candidate identities
required by that Dockerfile before choosing **Dev Containers: Reopen in
Container**:

```text
ROUNDWRIGHT_WHEEL=<exact-wheel-name>
ROUNDWRIGHT_WHEEL_SHA256=<64-lowercase-hex>
ROUNDWRIGHT_DOCKER_CANDIDATE_SHA=<40-lowercase-hex>
```

The configuration passes those values as Docker build arguments.  Its base
digest is not host-controlled: every definition pins
`sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2`,
and the Dockerfile rejects any other value before it can write consumer
identity.  The Dockerfile checks the wheel digest before its offline
`pip install --no-index --no-deps` and writes the candidate/package/base
identity that the installed preflight subsequently observes.  A missing or
wrong value therefore makes the build fail instead of falling back to source
or a different package.

## Default open and explicit modes

The default Dev Container command is deliberately overridden.  Opening or
rebuilding it starts no dispatcher, acquires no authority, logs in nowhere,
and writes neither repository configuration nor state.  Its workspace bind is
read-only; the runtime root filesystem is read-only; and the fixed UID/GID
`65532` user has only its dedicated writable home volume and `/tmp`.  The
definitions set `updateRemoteUserUID: false`, so a host UID can never rewrite
the consumer identity.

The three opt-in files provide concrete reference-CLI launch definitions:

| Mode | Definition | State | Authority receipt |
| --- | --- | --- | --- |
| authoritative | `.devcontainer/devcontainer.authoritative.json` | read/write | required, read-only |
| read-only | `.devcontainer/devcontainer.read-only.json` | read-only | not mounted |
| test-only | `.devcontainer/devcontainer.test-only.json` | read-only | not mounted |

Set `ROUNDWRIGHT_STATE`, `ROUNDWRIGHT_CONFIGURATION`, and
`ROUNDWRIGHT_AUTHENTICATION` to the host-owned inputs for every opt-in mode.
For authoritative mode also set `ROUNDWRIGHT_AUTHORITY_RECEIPT` and
`ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256`.  These values are mounted at
exactly the same targets and with the same RO/RW semantics as
[`docker/compose.yaml`](../../docker/compose.yaml).  Start a selected mode and
invoke the installed entrypoint explicitly:

```text
devcontainer up --workspace-folder . --config .devcontainer/devcontainer.read-only.json --no-lockfile
devcontainer exec --workspace-folder . --config .devcontainer/devcontainer.read-only.json python -m roundwright.docker_entrypoint doctor
devcontainer exec --workspace-folder . --config .devcontainer/devcontainer.read-only.json python -m roundwright.docker_entrypoint status
devcontainer exec --workspace-folder . --config .devcontainer/devcontainer.test-only.json python -m roundwright.docker_entrypoint run-once
```

Select exactly one `ROUNDWRIGHT_DOCKER_MODE`: `authoritative`, `read-only`, or
`test-only`.  The repository, configuration, and authentication targets are
read-only in every mode.  State is writable only for `authoritative`; only
that mode also receives the read-only authority-receipt mount and its exact
digest.  The existing Docker preflight remains the sole authority, candidate,
receipt, and mount validator: missing mounts, stale receipts, a wrong
candidate, an unsupported path, or conflicting mode/receipt input return its
actionable fail-closed doctor report.  No setup script, Feature, or Template
is involved.

`run-once` remains intentionally blocked by the package (exit code 3).  This
example never enables automatic startup or container-owned runtime policy.

## Offline qualification

After the pinned base image is already local, the normal Docker consumer
qualification builds the same artifact with `--network=none`, runs the
installed doctor and all three mode preflights, and retains the
candidate-bound receipt.  The complementary reference-CLI qualification is:

```text
python ci/devcontainer_consumer_qualification.py --devcontainer <reference-cli> --workspace .
```

It opens the passive default container, verifies the effective user/home and
non-writable workspace, then opens and executes doctor in each opt-in mode.
It creates no lockfile, invokes no lifecycle command, and performs no
registry, GitHub, provider, image-publication, or Canary operation.
