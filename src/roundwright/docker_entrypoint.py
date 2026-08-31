"""Filesystem-observing Docker entrypoint for the pinned consumer image."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import tomllib
from typing import Mapping, Sequence
import zlib

from .cli import main as cli_main
from .docker_consumer import DockerConsumerContract, DockerMountCheck, DockerMountName, DockerMountStatus, DockerOperationMode, evaluate_docker_consumer, render_docker_consumer_diagnostics
from .docker_authority import DockerAuthorityAdapterError, MountedAuthorityEvidence, evaluate_mounted_authority, load_mounted_authority, runtime_environment_fingerprint
from .native_host import NativeHostControlStore, NativeHostError
from .runtime_binding import RuntimeBinding


_PATHS = {
    DockerMountName.REPOSITORY: Path("/workspace"),
    DockerMountName.STATE: Path("/var/lib/roundwright"),
    DockerMountName.CONFIGURATION: Path("/etc/roundwright/config.toml"),
    DockerMountName.AUTHENTICATION: Path("/run/roundwright/auth.toml"),
    DockerMountName.AUTHORITY_RECEIPT: Path("/run/roundwright/authority-receipt.json"),
}
_IDENTITY = Path("/usr/local/share/roundwright/consumer-identity.json")
_RUNTIME_ENVIRONMENT = {
    "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
    "XDG_CONFIG_HOME": "/etc",
    "XDG_STATE_HOME": "/var/lib",
}


def _digest(path: Path) -> str | None:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _identity(path: Path) -> dict[str, str] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    required = {"candidate_sha", "package_digest", "base_image_digest"}
    if type(value) is not dict or set(value) != required or not all(type(item) is str for item in value.values()):
        return None
    return value


def _git_object(git_directory: Path, object_sha: str, kind: str) -> bytes | None:
    if len(object_sha) != 40 or any(character not in "0123456789abcdef" for character in object_sha):
        return None
    try:
        path = git_directory / "objects" / object_sha[:2] / object_sha[2:]
        if not path.is_file() or path.is_symlink():
            return None
        raw = zlib.decompress(path.read_bytes())
    except (OSError, zlib.error):
        return None
    separator = raw.find(b"\0")
    if separator <= 0 or hashlib.sha1(raw).hexdigest() != object_sha:
        return None
    header, body = raw[:separator], raw[separator + 1 :]
    return body if header == f"{kind} {len(body)}".encode("ascii") else None


def _tracked_tree(git_directory: Path, tree_sha: str, prefix: str = "") -> list[dict[str, str]] | None:
    body = _git_object(git_directory, tree_sha, "tree")
    if body is None:
        return None
    entries: list[dict[str, str]] = []
    cursor = 0
    while cursor < len(body):
        separator = body.find(b"\0", cursor)
        if separator <= cursor or separator + 21 > len(body):
            return None
        try:
            mode, name = body[cursor:separator].split(b" ", 1)
            component = name.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError):
            return None
        if not component or "/" in component or "\\" in component or component in {".", ".."}:
            return None
        object_sha = body[separator + 1:separator + 21].hex()
        path = prefix + component
        if mode == b"40000":
            nested = _tracked_tree(git_directory, object_sha, path + "/")
            if nested is None:
                return None
            entries.extend(nested)
        elif mode in {b"100644", b"100755"}:
            entries.append({"path": path, "sha1": object_sha})
        else:
            return None
        cursor = separator + 21
    return entries


def _checkout_candidate(repository: Path) -> str | None:
    """Verify detached commit, tree, and every tracked mounted file without Git.

    The mounted evidence must be self-contained: linked gitdirs, packed-only
    object indirection, synthetic manifests, substituted trees, and dirty
    tracked files all fail before package dispatch.
    """

    git_directory = repository / ".git"
    try:
        if not git_directory.is_dir() or git_directory.is_symlink():
            return None
        head = git_directory / "HEAD"
        if not head.is_file() or head.is_symlink():
            return None
        value = head.read_text(encoding="ascii")
        if len(value) != 41 or value[-1] != "\n":
            return None
        candidate = value[:-1]
        commit = _git_object(git_directory, candidate, "commit")
        if commit is None:
            return None
        first_line = commit.split(b"\n", 1)[0]
        if not first_line.startswith(b"tree ") or len(first_line) != 45:
            return None
        tree_sha = first_line[5:].decode("ascii")
        tracked = _tracked_tree(git_directory, tree_sha)
        manifest = json.loads((git_directory / "roundwright-checkout.json").read_text(encoding="utf-8"))
        if (
            type(manifest) is not dict
            or set(manifest) != {"candidate_sha", "entries", "tree_sha"}
            or manifest["candidate_sha"] != candidate
            or manifest["tree_sha"] != tree_sha
            or manifest["entries"] != tracked
        ):
            return None
        for entry in tracked:
            path = repository.joinpath(*entry["path"].split("/"))
            if not path.is_file() or path.is_symlink():
                return None
            content = path.read_bytes()
            raw = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
            if hashlib.sha1(raw).hexdigest() != entry["sha1"]:
                return None
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return None
    return candidate


def _authority_issued_at(path: Path) -> datetime | None:
    """Read only the typed receipt timestamp after authority evaluation."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))["receipt"]["issued_at"]
        timestamp = datetime.fromisoformat(value)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return timestamp if timestamp.tzinfo is timezone.utc else None


def _mounted_runtime_evidence(state: Path, candidate: str) -> dict[str, object] | None:
    """Read bounded host-owned identity observations shared by every mode."""

    try:
        value = json.loads((state / "docker-runtime-evidence.json").read_text(encoding="utf-8"))
        required = {
            "authentication_identity", "candidate_sha", "installation_fingerprint",
            "receipt_fingerprint", "runtime_binding", "runtime_environment",
        }
        if type(value) is not dict or set(value) != required or value["candidate_sha"] != candidate:
            return None
        if type(value["authentication_identity"]) is not str or len(value["authentication_identity"]) != 64:
            return None
        if any(character not in "0123456789abcdef" for character in value["authentication_identity"]):
            return None
        if any(
            type(value[name]) is not str
            or len(value[name]) != 64
            or any(character not in "0123456789abcdef" for character in value[name])
            for name in ("installation_fingerprint", "receipt_fingerprint")
        ):
            return None
        binding = RuntimeBinding.from_canonical(value["runtime_binding"])
        environment = value["runtime_environment"]
        if type(environment) is not dict or environment != _RUNTIME_ENVIRONMENT:
            return None
        runtime_environment_fingerprint(candidate, environment)
        return {**value, "binding": binding}
    except (OSError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _runtime_evidence(mode: DockerOperationMode, environment: Mapping[str, str], paths: Mapping[DockerMountName, Path], candidate: str, *, authority: MountedAuthorityEvidence | None) -> dict[DockerMountName, DockerMountStatus]:
    """Validate host-owned mounted material before the package can dispatch."""

    result: dict[DockerMountName, DockerMountStatus] = {}
    repository = paths[DockerMountName.REPOSITORY]
    mounted_runtime = _mounted_runtime_evidence(paths[DockerMountName.STATE], candidate)
    if mounted_runtime is None:
        result[DockerMountName.STATE] = DockerMountStatus.EVIDENCE_MISMATCH
    # The mounted checkout is independent evidence.  A well-formed detached
    # repository for a different candidate is just as unsafe as no checkout.
    if _checkout_candidate(repository) != candidate:
        result[DockerMountName.REPOSITORY] = DockerMountStatus.EVIDENCE_MISMATCH
    try:
        configuration = tomllib.loads(paths[DockerMountName.CONFIGURATION].read_text(encoding="utf-8"))
        runtime = configuration.get("runtime")
        if type(runtime) is not dict or set(runtime) != {"candidate_sha", "binding"} or runtime["candidate_sha"] != candidate:
            raise ValueError
        binding = RuntimeBinding.from_canonical(runtime["binding"])
        if mounted_runtime is None:
            raise ValueError
        binding.require_matches(mounted_runtime["binding"])
        if authority is not None:
            authority.identity.runtime_binding.require_matches(binding)
    except (OSError, TypeError, ValueError, tomllib.TOMLDecodeError):
        result[DockerMountName.CONFIGURATION] = DockerMountStatus.EVIDENCE_MISMATCH
    try:
        authentication = tomllib.loads(paths[DockerMountName.AUTHENTICATION].read_text(encoding="utf-8"))
        operator = authentication.get("operator")
        if type(operator) is not dict or set(operator) != {"candidate_sha", "identity"} or operator["candidate_sha"] != candidate or type(operator["identity"]) is not str or len(operator["identity"]) != 64 or any(value not in "0123456789abcdef" for value in operator["identity"]):
            raise ValueError
        if mounted_runtime is None or operator["identity"] != mounted_runtime["authentication_identity"]:
            raise ValueError
        if authority is not None and operator["identity"] != authority.authentication_identity:
            raise ValueError
    except (OSError, TypeError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        result[DockerMountName.AUTHENTICATION] = DockerMountStatus.EVIDENCE_MISMATCH
    database = paths[DockerMountName.STATE] / "native-host.sqlite3"
    state_valid = False
    try:
        if not database.is_file():
            state_valid = False
        elif mode is DockerOperationMode.AUTHORITATIVE and hasattr(os, "geteuid") and database.stat().st_uid != os.geteuid():
            # Check the concrete database ownership before opening it.  An
            # authoritative container must report a host-owned mismatch as a
            # blocked preflight, rather than leaking a SQLite permission
            # exception from a file it is not allowed to inspect.
            result[DockerMountName.STATE] = DockerMountStatus.OWNERSHIP_MISMATCH
        else:
            observation = NativeHostControlStore(database).observe()
            state_valid = observation.candidate_sha == candidate
            if mounted_runtime is None:
                state_valid = False
            elif (
                observation.installation_fingerprint != mounted_runtime["installation_fingerprint"]
                or observation.receipt_fingerprint != mounted_runtime["receipt_fingerprint"]
            ):
                state_valid = False
            elif authority is not None:
                installation = authority.native_host_installation
                installation.identity.runtime_binding.require_matches(authority.identity.runtime_binding)
                if (
                    installation.identity.candidate_sha != candidate
                    or installation.identity.repository_fingerprint != authority.identity.repository_fingerprint
                    or installation.identity.canonical_checkout_fingerprint != authority.identity.canonical_checkout_fingerprint
                    or installation.identity.state_store_fingerprint != authority.identity.state_fingerprint
                    or installation.identity.state_id != authority.identity.state_id
                    or installation.identity.deployment_fingerprint != authority.identity.deployment_fingerprint
                    or observation.installation_fingerprint != installation.installation_fingerprint
                    or observation.receipt_fingerprint != installation.receipt.receipt_fingerprint
                ):
                    state_valid = False
                else:
                    state_valid = NativeHostControlStore(database).verify(installation).accepted
    except (NativeHostError, OSError, ValueError):
        # Corrupt or unreadable mounted state is untrusted input.  It must
        # produce ordinary fail-closed preflight evidence, never an unhandled
        # installed-image exception.
        state_valid = False
    if DockerMountName.STATE not in result and not state_valid:
        result[DockerMountName.STATE] = DockerMountStatus.EVIDENCE_MISMATCH
    if any(environment.get(name) != value for name, value in _RUNTIME_ENVIRONMENT.items()):
        # A wrong runtime path can otherwise make the CLI silently inspect a
        # container-local default instead of the host-owned fixtures.
        result[DockerMountName.REPOSITORY] = DockerMountStatus.EVIDENCE_MISMATCH
    elif authority is not None and mounted_runtime is not None:
        observed_environment = {name: environment[name] for name in _RUNTIME_ENVIRONMENT}
        try:
            if (
                observed_environment != mounted_runtime["runtime_environment"]
                or observed_environment != authority.runtime_environment
                or runtime_environment_fingerprint(candidate, observed_environment)
                != authority.native_host_installation.identity.environment_fingerprint
            ):
                result[DockerMountName.REPOSITORY] = DockerMountStatus.EVIDENCE_MISMATCH
        except DockerAuthorityAdapterError:
            result[DockerMountName.REPOSITORY] = DockerMountStatus.EVIDENCE_MISMATCH
    return result


def _mounts(mode: DockerOperationMode, paths: Mapping[DockerMountName, Path], evidence: Mapping[DockerMountName, DockerMountStatus]) -> tuple[DockerMountCheck, ...]:
    checks: list[DockerMountCheck] = []
    for name, path in paths.items():
        if name is DockerMountName.AUTHORITY_RECEIPT and mode is not DockerOperationMode.AUTHORITATIVE:
            checks.append(DockerMountCheck(name, DockerMountStatus.NOT_APPLICABLE if not path.exists() else DockerMountStatus.PERMISSION_MISMATCH))
            continue
        expected_directory = name in {DockerMountName.REPOSITORY, DockerMountName.STATE}
        present = path.is_dir() if expected_directory else path.is_file()
        if not present:
            status = DockerMountStatus.MISSING
        elif not os.access(path, os.R_OK):
            status = DockerMountStatus.PERMISSION_MISMATCH
        elif name is DockerMountName.STATE:
            writable = os.access(path, os.W_OK)
            if mode is DockerOperationMode.AUTHORITATIVE and not writable:
                status = DockerMountStatus.PERMISSION_MISMATCH
            elif mode is not DockerOperationMode.AUTHORITATIVE and writable:
                status = DockerMountStatus.PERMISSION_MISMATCH
            else:
                effective_uid = getattr(os, "geteuid", None)
                observed_uid = getattr(path.stat(), "st_uid", None)
                if mode is DockerOperationMode.AUTHORITATIVE and callable(effective_uid) and observed_uid is not None and observed_uid != effective_uid():
                    status = DockerMountStatus.OWNERSHIP_MISMATCH
                else:
                    status = DockerMountStatus.READY
        elif os.access(path, os.W_OK):
            # Repository, configuration, authentication, and authority
            # evidence are host-owned observations.  A writable mount lets a
            # consumer manufacture its own evidence, so fail closed.
            status = DockerMountStatus.PERMISSION_MISMATCH
        else:
            status = DockerMountStatus.READY
        checks.append(DockerMountCheck(name, evidence.get(name, status) if status is DockerMountStatus.READY else status))
    return tuple(checks)


def preflight(environment: Mapping[str, str], *, paths: Mapping[DockerMountName, Path] = _PATHS, identity_path: Path = _IDENTITY):
    """Observe the image metadata and real mounts before dispatching a command."""

    try:
        mode = DockerOperationMode(environment["ROUNDWRIGHT_DOCKER_MODE"])
        candidate = environment["ROUNDWRIGHT_DOCKER_CANDIDATE_SHA"]
        package = "sha256:" + environment["ROUNDWRIGHT_DOCKER_PACKAGE_SHA256"]
        base = environment["ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST"]
    except (KeyError, ValueError) as error:
        raise ValueError("Docker mode and image identities are required") from error
    observed = _identity(identity_path) or {}
    receipt_path = paths[DockerMountName.AUTHORITY_RECEIPT]
    receipt_digest = _digest(receipt_path)
    receipt_candidate = None
    if receipt_digest is not None:
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt_candidate = receipt.get("candidate_sha") if type(receipt) is dict else None
        except (OSError, json.JSONDecodeError):
            pass
    expected_receipt = environment.get("ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256")
    if mode is DockerOperationMode.AUTHORITATIVE:
        try:
            authority = evaluate_mounted_authority(receipt_path, candidate_sha=candidate, now=datetime.now(timezone.utc))
        except DockerAuthorityAdapterError:
            authority = None
        if authority is None or not authority.authorized:
            expected_receipt = None
    mounted_authority = None
    if mode is DockerOperationMode.AUTHORITATIVE and expected_receipt is not None:
        try:
            mounted_authority = load_mounted_authority(receipt_path, candidate_sha=candidate)
        except DockerAuthorityAdapterError:
            expected_receipt = None
    evidence = _runtime_evidence(mode, environment, paths, candidate, authority=mounted_authority)
    observed_candidate = _checkout_candidate(paths[DockerMountName.REPOSITORY])
    return evaluate_docker_consumer(DockerConsumerContract(
        mode, candidate, observed_candidate, package, observed.get("package_digest"), base,
        observed.get("base_image_digest"), _mounts(mode, paths, evidence),
        None if expected_receipt is None else "sha256:" + expected_receipt, receipt_digest, receipt_candidate,
    ))


def _render_mounted_status(output: object, *, paths: Mapping[DockerMountName, Path], candidate: str, authoritative: bool) -> int:
    """Render path-free persisted control-store facts; this never acquires dispatch authority."""

    try:
        lifecycle = NativeHostControlStore(paths[DockerMountName.STATE] / "native-host.sqlite3").observe_lifecycle()
        if lifecycle.installation.candidate_sha != candidate:
            raise NativeHostError("mounted native host candidate is mismatched")
    except NativeHostError:
        output.write("roundwright docker status\nresult: blocked\n")  # type: ignore[attr-defined]
        return 2
    output.write("roundwright docker status\n")  # type: ignore[attr-defined]
    output.write("candidate: match\nworktree: match\nsqlite: ready\nnative-host: match\nruntime-binding: match\n")  # type: ignore[attr-defined]
    output.write(f"receipt: {'match' if authoritative else 'not-applicable'}\n")  # type: ignore[attr-defined]
    output.write(f"active-lock: {'held' if lifecycle.active_lock else 'clear'}\n")  # type: ignore[attr-defined]
    output.write(f"restart: {'observed' if lifecycle.completed_count else 'none'}\n")  # type: ignore[attr-defined]
    output.write(f"cancellation: {'observed' if lifecycle.cancelled_count else 'none'}\n")  # type: ignore[attr-defined]
    output.write(f"stale-recovery: {'observed' if lifecycle.recovered_count else 'none'}\nresult: ready\n")  # type: ignore[attr-defined]
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = __import__("sys").argv[1:]
    report = preflight(os.environ)
    render_docker_consumer_diagnostics(report, __import__("sys").stdout)
    if not report.ready:
        return report.exit_code
    if list(argv) == ["status"]:
        return _render_mounted_status(
            __import__("sys").stdout, paths=_PATHS, candidate=os.environ["ROUNDWRIGHT_DOCKER_CANDIDATE_SHA"],
            authoritative=os.environ["ROUNDWRIGHT_DOCKER_MODE"] == DockerOperationMode.AUTHORITATIVE.value,
        )
    if not argv or list(argv) == ["doctor"]:
        return 0
    # The installed CLI must resolve the same mounted repository and XDG
    # locations that preflight observed; it must never fall back to /app.
    previous_directory = Path.cwd()
    previous_environment = {name: os.environ.get(name) for name in _RUNTIME_ENVIRONMENT}
    try:
        os.chdir(_PATHS[DockerMountName.REPOSITORY])
        os.environ.update(_RUNTIME_ENVIRONMENT)
        return cli_main(argv)
    finally:
        os.chdir(previous_directory)
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    raise SystemExit(main())
