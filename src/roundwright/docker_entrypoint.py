"""Filesystem-observing Docker entrypoint for the pinned consumer image."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
import subprocess
import tomllib
from typing import Mapping, Sequence

from .cli import main as cli_main
from .docker_consumer import DockerConsumerContract, DockerMountCheck, DockerMountName, DockerMountStatus, DockerOperationMode, evaluate_docker_consumer, render_docker_consumer_diagnostics
from .docker_authority import DockerAuthorityAdapterError, canonical_native_host_installation, evaluate_mounted_authority
from .native_host import NativeHostControlStore


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


def _checkout_candidate(repository: Path) -> str | None:
    """Read the mounted checkout identity rather than trusting image metadata."""

    try:
        result = subprocess.run(
            ("git", "-C", os.fspath(repository), "rev-parse", "--verify", "HEAD^{commit}"),
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and len(value) == 40 and all(character in "0123456789abcdef" for character in value) else None


def _authority_issued_at(path: Path) -> datetime | None:
    """Read only the typed receipt timestamp after authority evaluation."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))["receipt"]["issued_at"]
        timestamp = datetime.fromisoformat(value)
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return timestamp if timestamp.tzinfo is timezone.utc else None


def _runtime_evidence(mode: DockerOperationMode, environment: Mapping[str, str], paths: Mapping[DockerMountName, Path], candidate: str, *, authority_issued_at: datetime | None) -> dict[DockerMountName, DockerMountStatus]:
    """Validate host-owned mounted material before the package can dispatch."""

    result: dict[DockerMountName, DockerMountStatus] = {}
    repository = paths[DockerMountName.REPOSITORY]
    if _checkout_candidate(repository) is None:
        result[DockerMountName.REPOSITORY] = DockerMountStatus.EVIDENCE_MISMATCH
    try:
        configuration = tomllib.loads(paths[DockerMountName.CONFIGURATION].read_text(encoding="utf-8"))
        if configuration.get("runtime", {}).get("schema_version") != 1:
            raise ValueError
    except (OSError, TypeError, ValueError, tomllib.TOMLDecodeError):
        result[DockerMountName.CONFIGURATION] = DockerMountStatus.EVIDENCE_MISMATCH
    try:
        if not paths[DockerMountName.AUTHENTICATION].read_text(encoding="utf-8").strip():
            raise ValueError
    except (OSError, ValueError, UnicodeDecodeError):
        result[DockerMountName.AUTHENTICATION] = DockerMountStatus.EVIDENCE_MISMATCH
    database = paths[DockerMountName.STATE] / "native-host.sqlite3"
    if mode is DockerOperationMode.AUTHORITATIVE and authority_issued_at is not None:
        state = NativeHostControlStore(database).verify(canonical_native_host_installation(candidate, now=authority_issued_at))
        state_valid = state.accepted
    else:
        # Non-authoritative modes can inspect the existing state but cannot
        # use or synthesize an authority receipt to validate it.
        state_valid = database.is_file()
    if not state_valid:
        result[DockerMountName.STATE] = DockerMountStatus.EVIDENCE_MISMATCH
    elif mode is DockerOperationMode.AUTHORITATIVE and hasattr(os, "geteuid") and database.stat().st_uid != os.geteuid():
        result[DockerMountName.STATE] = DockerMountStatus.OWNERSHIP_MISMATCH
    if any(environment.get(name) != value for name, value in _RUNTIME_ENVIRONMENT.items()):
        # A wrong runtime path can otherwise make the CLI silently inspect a
        # container-local default instead of the host-owned fixtures.
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
    authority_issued_at = _authority_issued_at(receipt_path) if expected_receipt is not None else None
    evidence = _runtime_evidence(mode, environment, paths, candidate, authority_issued_at=authority_issued_at)
    observed_candidate = _checkout_candidate(paths[DockerMountName.REPOSITORY])
    return evaluate_docker_consumer(DockerConsumerContract(
        mode, candidate, observed_candidate, package, observed.get("package_digest"), base,
        observed.get("base_image_digest"), _mounts(mode, paths, evidence),
        None if expected_receipt is None else "sha256:" + expected_receipt, receipt_digest, receipt_candidate,
    ))


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = __import__("sys").argv[1:]
    report = preflight(os.environ)
    render_docker_consumer_diagnostics(report, __import__("sys").stdout)
    if not report.ready:
        return report.exit_code
    if not argv or list(argv) == ["doctor"]:
        return 0
    # The installed CLI must resolve the same mounted repository and XDG
    # locations that preflight observed; it must never fall back to /app.
    os.chdir(_PATHS[DockerMountName.REPOSITORY])
    os.environ.update(_RUNTIME_ENVIRONMENT)
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
