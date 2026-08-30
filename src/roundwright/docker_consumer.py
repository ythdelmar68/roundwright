"""Fail-closed contract for the minimal Docker deployment consumer.

The Docker image is only a consumer of the released wheel and host-owned
inputs.  It cannot create authority, select a candidate, discover credentials,
or implement a second dispatcher.  This module keeps the mount and mode
admission checks deterministic and renders only public-safe labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import TextIO


class DockerConsumerError(ValueError):
    """Raised when a Docker consumer contract cannot be represented safely."""


class DockerOperationMode(str, Enum):
    """The only modes a Docker consumer may declare."""

    AUTHORITATIVE = "authoritative"
    READ_ONLY = "read-only"
    TEST_ONLY = "test-only"


class DockerMountName(str, Enum):
    """Host-owned inputs that must be mounted at the documented targets."""

    REPOSITORY = "repository"
    STATE = "state"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    AUTHORITY_RECEIPT = "authority-receipt"


class DockerMountStatus(str, Enum):
    """Path-free outcomes supplied by the container wrapper."""

    READY = "ready"
    MISSING = "missing"
    OWNERSHIP_MISMATCH = "ownership-mismatch"
    PERMISSION_MISMATCH = "permission-mismatch"


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class DockerMountCheck:
    """One mount's public-safe readiness result, never its host path."""

    name: DockerMountName
    status: DockerMountStatus

    def __post_init__(self) -> None:
        if type(self.name) is not DockerMountName or type(self.status) is not DockerMountStatus:
            raise DockerConsumerError("Docker mount check is invalid")


@dataclass(frozen=True)
class DockerConsumerContract:
    """Exact candidate, artifact, image, mode, and mount inputs for one run."""

    mode: DockerOperationMode
    candidate_sha: str
    package_digest: str
    base_image_digest: str
    mounts: tuple[DockerMountCheck, ...]
    authority_receipt_digest: str | None = None
    authority_receipt_matches_candidate: bool = False
    authority_inputs_conflict: bool = False

    def __post_init__(self) -> None:
        if type(self.mode) is not DockerOperationMode:
            raise DockerConsumerError("Docker operation mode is invalid")
        if type(self.candidate_sha) is not str or not _CANDIDATE.fullmatch(self.candidate_sha):
            raise DockerConsumerError("Docker candidate identity is invalid")
        for value, description in ((self.package_digest, "package"), (self.base_image_digest, "base image")):
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise DockerConsumerError(f"Docker {description} digest is invalid")
        if self.authority_receipt_digest is not None and (
            type(self.authority_receipt_digest) is not str or not _SHA256.fullmatch(self.authority_receipt_digest)
        ):
            raise DockerConsumerError("Docker authority receipt digest is invalid")
        if type(self.authority_receipt_matches_candidate) is not bool or type(self.authority_inputs_conflict) is not bool:
            raise DockerConsumerError("Docker authority input is invalid")
        if type(self.mounts) is not tuple or len(self.mounts) != len(DockerMountName):
            raise DockerConsumerError("Docker mount contract is incomplete")
        if any(type(mount) is not DockerMountCheck for mount in self.mounts) or {
            mount.name for mount in self.mounts
        } != set(DockerMountName):
            raise DockerConsumerError("Docker mount contract is invalid")


@dataclass(frozen=True)
class DockerConsumerDiagnosticReport:
    """Path-free preflight report suitable for ``roundwright doctor`` output."""

    contract: DockerConsumerContract
    ready: bool
    reason: str

    @property
    def exit_code(self) -> int:
        return 0 if self.ready else 2


def evaluate_docker_consumer(contract: DockerConsumerContract) -> DockerConsumerDiagnosticReport:
    """Fail closed before the container could use any host-owned input."""

    if type(contract) is not DockerConsumerContract:
        raise DockerConsumerError("Docker consumer contract is invalid")
    mount = next((item for item in contract.mounts if item.status is not DockerMountStatus.READY), None)
    if mount is not None:
        return DockerConsumerDiagnosticReport(contract, False, f"{mount.name.value} mount is {mount.status.value}")
    if contract.authority_inputs_conflict:
        return DockerConsumerDiagnosticReport(contract, False, "authority inputs conflict")
    if contract.mode is DockerOperationMode.AUTHORITATIVE:
        if contract.authority_receipt_digest is None:
            return DockerConsumerDiagnosticReport(contract, False, "authority receipt is missing")
        if not contract.authority_receipt_matches_candidate:
            return DockerConsumerDiagnosticReport(contract, False, "authority receipt does not match the candidate")
    elif contract.authority_receipt_digest is not None or contract.authority_receipt_matches_candidate:
        return DockerConsumerDiagnosticReport(contract, False, "non-authoritative mode received authority input")
    return DockerConsumerDiagnosticReport(contract, True, "Docker consumer contract is ready")


def render_docker_consumer_diagnostics(report: DockerConsumerDiagnosticReport, output: TextIO) -> None:
    """Render mount, candidate, and receipt status without paths or secrets."""

    if type(report) is not DockerConsumerDiagnosticReport:
        raise DockerConsumerError("Docker diagnostic report is invalid")
    output.write("roundwright Docker consumer preflight\n")
    output.write(f"mode: {report.contract.mode.value}\n")
    for mount in sorted(report.contract.mounts, key=lambda item: item.name.value):
        output.write(f"{mount.name.value} mount: {mount.status.value}\n")
    output.write("candidate: match\n")
    receipt = "not required"
    if report.contract.mode is DockerOperationMode.AUTHORITATIVE:
        receipt = "match" if report.contract.authority_receipt_matches_candidate else "mismatch"
    output.write(f"authority receipt: {receipt}\n")
    output.write(f"result: {'ready' if report.ready else 'blocked'} ({report.reason})\n")
