# Minimal Dev Container consumer

This optional example is a development-environment view of the minimal Docker
consumer.  It builds [`docker/Dockerfile`](../../docker/Dockerfile) directly,
so it installs the same accepted wheel, uses the same pinned Python base, and
contains no copied source runtime or alternate dispatcher.  It is not a Dev
Container Feature or Template and does not publish an image.

## Build the exact artifact

First build and bind the candidate distribution with the receipt-bound
validation toolchain, as described by the [Docker consumer](docker-consumer.md).
From the repository root, provide only the public build identities required by
that Dockerfile before choosing **Dev Containers: Reopen in Container**:

```text
ROUNDWRIGHT_WHEEL=<exact-wheel-name>
ROUNDWRIGHT_WHEEL_SHA256=<64-lowercase-hex>
ROUNDWRIGHT_DOCKER_CANDIDATE_SHA=<40-lowercase-hex>
ROUNDWRIGHT_BASE_IMAGE_DIGEST=sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2
```

The configuration passes those values only as Docker build arguments.  The
base Dockerfile checks the wheel digest before its offline
`pip install --no-index --no-deps` and writes the candidate/package/base
identity that the installed preflight subsequently observes.  A missing or
wrong value therefore makes the build fail instead of falling back to source
or a different package.

## Default open and explicit modes

The default Dev Container command is deliberately overridden.  Opening or
rebuilding it starts no dispatcher, acquires no authority, logs in nowhere,
and writes neither repository configuration nor state.  Its workspace bind is
read-only and `/tmp` is the sole writable tmpfs.

To operate the installed consumer, supply the same host-owned mounts and
environment required by [`docker/compose.yaml`](../../docker/compose.yaml),
then invoke the installed entrypoint explicitly:

```text
python -m roundwright.docker_entrypoint doctor
python -m roundwright.docker_entrypoint status
python -m roundwright.docker_entrypoint run-once
```

Select exactly one `ROUNDWRIGHT_DOCKER_MODE`: `authoritative`, `read-only`, or
`test-only`.  The repository, configuration, and authentication targets are
read-only in every mode.  State is writable only for `authoritative`; only
that mode also receives the read-only authority-receipt mount and its exact
digest.  The existing Docker preflight remains the sole authority, candidate,
receipt, and mount validator: missing mounts, stale receipts, a wrong
candidate, an unsupported path, or conflicting mode/receipt input return its
actionable fail-closed doctor report.  Use the documented Compose commands
when launching those explicit modes from the host; they are the canonical
mount contract and do not require a Dev Container setup script.

`run-once` remains intentionally blocked by the package (exit code 3).  This
example never enables automatic startup or container-owned runtime policy.

## Offline qualification

After the pinned base image is already local, the normal Docker consumer
qualification builds the same artifact with `--network=none`, runs the
installed doctor and all three mode preflights, and retains the
candidate-bound receipt.  The Dev Container configuration is hermetically
checked as JSON alongside the package suite; it performs no registry, GitHub,
provider, image-publication, or Canary operation.
