"""Filesystem-observing Docker entrypoint for the pinned consumer image."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .cli import main as cli_main
from .docker_consumer import DockerConsumerContract, DockerMountCheck, DockerMountName, DockerMountStatus, DockerOperationMode, evaluate_docker_consumer, render_docker_consumer_diagnostics
from .docker_authority import DockerAuthorityAdapterError, evaluate_mounted_authority


_PATHS = {
    DockerMountName.REPOSITORY: Path("/workspace"),
    DockerMountName.STATE: Path("/var/lib/roundwright"),
    DockerMountName.CONFIGURATION: Path("/etc/roundwright/config.toml"),
    DockerMountName.AUTHENTICATION: Path("/run/roundwright/auth.toml"),
    DockerMountName.AUTHORITY_RECEIPT: Path("/run/roundwright/authority-receipt.json"),
}
_IDENTITY = Path("/usr/local/share/roundwright/consumer-identity.json")


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


def _mounts(mode: DockerOperationMode, paths: Mapping[DockerMountName, Path]) -> tuple[DockerMountCheck, ...]:
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
        checks.append(DockerMountCheck(name, status))
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
    return evaluate_docker_consumer(DockerConsumerContract(
        mode, candidate, observed.get("candidate_sha"), package, observed.get("package_digest"), base,
        observed.get("base_image_digest"), _mounts(mode, paths),
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
    return cli_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
