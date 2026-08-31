"""Fail-closed contract for the minimal Docker deployment consumer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import TextIO


class DockerConsumerError(ValueError):
    """Raised when Docker consumer evidence cannot be represented safely."""


class DockerOperationMode(str, Enum):
    AUTHORITATIVE = "authoritative"
    READ_ONLY = "read-only"
    TEST_ONLY = "test-only"


class DockerMountName(str, Enum):
    REPOSITORY = "repository"
    STATE = "state"
    CONFIGURATION = "configuration"
    AUTHENTICATION = "authentication"
    AUTHORITY_RECEIPT = "authority-receipt"


class DockerMountStatus(str, Enum):
    READY = "ready"
    NOT_APPLICABLE = "not-applicable"
    MISSING = "missing"
    OWNERSHIP_MISMATCH = "ownership-mismatch"
    PERMISSION_MISMATCH = "permission-mismatch"
    EVIDENCE_MISMATCH = "evidence-mismatch"


class DockerIdentityStatus(str, Enum):
    MATCH = "match"
    MISSING = "missing"
    MISMATCH = "mismatch"


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class DockerMountCheck:
    name: DockerMountName
    status: DockerMountStatus

    def __post_init__(self) -> None:
        if type(self.name) is not DockerMountName or type(self.status) is not DockerMountStatus:
            raise DockerConsumerError("Docker mount check is invalid")


@dataclass(frozen=True)
class DockerConsumerContract:
    """Declared build values and independently observed container values."""

    mode: DockerOperationMode
    candidate_sha: str
    observed_candidate_sha: str | None
    package_digest: str
    observed_package_digest: str | None
    base_image_digest: str
    observed_base_image_digest: str | None
    mounts: tuple[DockerMountCheck, ...]
    authority_receipt_digest: str | None = None
    observed_authority_receipt_digest: str | None = None
    observed_authority_receipt_candidate_sha: str | None = None
    authority_inputs_conflict: bool = False

    def __post_init__(self) -> None:
        if type(self.mode) is not DockerOperationMode:
            raise DockerConsumerError("Docker operation mode is invalid")
        for value, description, pattern in (
            (self.candidate_sha, "candidate", _CANDIDATE), (self.package_digest, "package", _SHA256), (self.base_image_digest, "base image", _SHA256),
        ):
            if type(value) is not str or not pattern.fullmatch(value):
                raise DockerConsumerError(f"Docker {description} identity is invalid")
        for value, description, pattern in (
            (self.observed_candidate_sha, "observed candidate", _CANDIDATE), (self.observed_package_digest, "observed package", _SHA256),
            (self.observed_base_image_digest, "observed base image", _SHA256), (self.authority_receipt_digest, "authority receipt", _SHA256),
            (self.observed_authority_receipt_digest, "observed authority receipt", _SHA256), (self.observed_authority_receipt_candidate_sha, "observed authority receipt candidate", _CANDIDATE),
        ):
            if value is not None and (type(value) is not str or not pattern.fullmatch(value)):
                raise DockerConsumerError(f"Docker {description} identity is invalid")
        if type(self.authority_inputs_conflict) is not bool:
            raise DockerConsumerError("Docker authority input is invalid")
        if type(self.mounts) is not tuple or len(self.mounts) != len(DockerMountName):
            raise DockerConsumerError("Docker mount contract is incomplete")
        if any(type(mount) is not DockerMountCheck for mount in self.mounts) or {mount.name for mount in self.mounts} != set(DockerMountName):
            raise DockerConsumerError("Docker mount contract is invalid")


def identity_status(expected: str, observed: str | None) -> DockerIdentityStatus:
    if observed is None:
        return DockerIdentityStatus.MISSING
    return DockerIdentityStatus.MATCH if observed == expected else DockerIdentityStatus.MISMATCH


@dataclass(frozen=True)
class DockerConsumerDiagnosticReport:
    contract: DockerConsumerContract
    ready: bool
    reason: str
    candidate: DockerIdentityStatus
    package: DockerIdentityStatus
    base_image: DockerIdentityStatus
    authority_receipt: DockerIdentityStatus | None

    @property
    def exit_code(self) -> int:
        return 0 if self.ready else 2


def evaluate_docker_consumer(contract: DockerConsumerContract) -> DockerConsumerDiagnosticReport:
    """Fail closed on actual mount or identity drift before command execution."""

    if type(contract) is not DockerConsumerContract:
        raise DockerConsumerError("Docker consumer contract is invalid")
    candidate = identity_status(contract.candidate_sha, contract.observed_candidate_sha)
    package = identity_status(contract.package_digest, contract.observed_package_digest)
    base_image = identity_status(contract.base_image_digest, contract.observed_base_image_digest)
    receipt = None if contract.mode is not DockerOperationMode.AUTHORITATIVE else identity_status(contract.authority_receipt_digest or "", contract.observed_authority_receipt_digest)
    mount = next((item for item in contract.mounts if item.status not in {DockerMountStatus.READY, DockerMountStatus.NOT_APPLICABLE}), None)
    if mount is not None:
        return DockerConsumerDiagnosticReport(contract, False, f"{mount.name.value} mount is {mount.status.value}", candidate, package, base_image, receipt)
    for name, status in (("candidate", candidate), ("package", package), ("base image", base_image)):
        if status is not DockerIdentityStatus.MATCH:
            return DockerConsumerDiagnosticReport(contract, False, f"{name} identity is {status.value}", candidate, package, base_image, receipt)
    if contract.authority_inputs_conflict:
        return DockerConsumerDiagnosticReport(contract, False, "authority inputs conflict", candidate, package, base_image, receipt)
    authority_mount = next(item for item in contract.mounts if item.name is DockerMountName.AUTHORITY_RECEIPT)
    if contract.mode is DockerOperationMode.AUTHORITATIVE:
        if authority_mount.status is not DockerMountStatus.READY or receipt is not DockerIdentityStatus.MATCH:
            return DockerConsumerDiagnosticReport(contract, False, "authority receipt identity is missing or mismatched", candidate, package, base_image, receipt)
        if contract.observed_authority_receipt_candidate_sha != contract.candidate_sha:
            return DockerConsumerDiagnosticReport(contract, False, "authority receipt candidate is mismatched", candidate, package, base_image, receipt)
    elif authority_mount.status is not DockerMountStatus.NOT_APPLICABLE or any(
        value is not None for value in (contract.authority_receipt_digest, contract.observed_authority_receipt_digest, contract.observed_authority_receipt_candidate_sha)
    ):
        return DockerConsumerDiagnosticReport(contract, False, "non-authoritative mode received authority input", candidate, package, base_image, receipt)
    return DockerConsumerDiagnosticReport(contract, True, "Docker consumer contract is ready", candidate, package, base_image, receipt)


def render_docker_consumer_diagnostics(report: DockerConsumerDiagnosticReport, output: TextIO) -> None:
    if type(report) is not DockerConsumerDiagnosticReport:
        raise DockerConsumerError("Docker diagnostic report is invalid")
    output.write("roundwright Docker consumer preflight\n")
    output.write(f"mode: {report.contract.mode.value}\n")
    for mount in sorted(report.contract.mounts, key=lambda item: item.name.value):
        output.write(f"{mount.name.value} mount: {mount.status.value}\n")
    output.write(f"candidate: {report.candidate.value}\npackage: {report.package.value}\nbase image: {report.base_image.value}\n")
    output.write(f"authority receipt: {'not required' if report.authority_receipt is None else report.authority_receipt.value}\n")
    output.write(f"result: {'ready' if report.ready else 'blocked'} ({report.reason})\n")
