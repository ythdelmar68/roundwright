"""Immutable, public-safe Phase 4 cross-environment qualification evidence.

This module models evidence; it does not run a host, contact a provider, or
write a retention store.  The Harness adapter owns execution and Recorder
retention, while this contract makes all cross-environment comparisons
deterministic and fail closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping


CROSS_ENVIRONMENT_CANARY_PROFILE = "roundwright-shadow-profile/cross-environment-canary/v1"
CROSS_ENVIRONMENT_EVIDENCE_SCHEMA = "roundwright-cross-environment-evidence/v1"
CROSS_ENVIRONMENT_RESULT_SCHEMA = "roundwright-cross-environment-result/v1"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}\Z")
_CREDENTIAL_SHAPES = (
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk-",
)


class CrossEnvironmentEvidenceError(ValueError):
    """Raised when a cross-environment evidence tuple is incomplete or mixed."""


class EnvironmentKind(StrEnum):
    WINDOWS_HOST_PARITY = "windows-host-parity"
    LINUX_HOST_PARITY = "linux-host-parity"
    MACOS_HOST_PARITY = "macos-host-parity"
    CI_PARITY = "ci-parity"
    DOCKER_PARITY = "docker-parity"
    DEVCONTAINER_PARITY = "devcontainer-parity"
    SEALED_CANARY_RECEIPT_CONSUMER = "sealed-canary-receipt-consumer"

    # Compatibility aliases for the pre-#97 six-lane synthetic contract.
    NATIVE_WINDOWS = WINDOWS_HOST_PARITY
    NATIVE_LINUX = LINUX_HOST_PARITY
    NATIVE_MACOS = MACOS_HOST_PARITY
    CI = CI_PARITY
    DOCKER = DOCKER_PARITY
    DEV_CONTAINER = DEVCONTAINER_PARITY


CROSS_ENVIRONMENT_LANE_ORDER = (
    EnvironmentKind.WINDOWS_HOST_PARITY,
    EnvironmentKind.LINUX_HOST_PARITY,
    EnvironmentKind.MACOS_HOST_PARITY,
    EnvironmentKind.CI_PARITY,
    EnvironmentKind.DOCKER_PARITY,
    EnvironmentKind.DEVCONTAINER_PARITY,
    EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER,
)


class ParityDimension(StrEnum):
    """The normalized runtime observations every executable lane must cover."""

    DOCTOR = "doctor"
    CONFIGURATION = "configuration"
    PATH = "path"
    LOCK = "lock"
    SQLITE = "sqlite"
    WORKTREE = "worktree"
    CANCELLATION = "cancellation"
    STALE_RECOVERY = "stale-recovery"
    CLI = "cli"
    AUTHORITY_PREFLIGHT = "authority-preflight"


PARITY_DIMENSIONS = tuple(ParityDimension)
FORWARD_TEST_REPOSITORY = "ythdelmar68/roundlet-forward-test"
SEALED_CANARY_SOURCE_CANDIDATE_SHA = "e574bb04101a66baf0a508a99f0baf41a731a054"
SEALED_CANARY_RECEIPT_DIGEST = "sha256:3f5b2e84c69d0c4cb13695c62bc6e8fb86e80765f89fcc6934272758ea37f051"
SEALED_CANARY_EXECUTION_LEDGER_DIGEST = "sha256:87856fcfd1b3c91735f5d73396475888e94aae5e3d08f41c581c6671f3c499a8"
SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST = "sha256:73159c52015b0e2607fa36f5f2925876a1751c48f2fc3787c757d23af0948f62"
SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST = "sha256:754b17ea9e901561ae0530494b833119c3e50a71a9a29f645c0c1f9477a490d2"
SEALED_CANARY_TARGET_MERGE_SHA = "dfd514757f25b88d8182c9d33c87481ce3016a7e"
SEALED_CANARY_READY_AT = 1788367569


class OperationMode(StrEnum):
    AUTHORITATIVE = "authoritative"
    READ_ONLY = "read-only"
    TEST_ONLY = "test-only"


class ReceiptState(StrEnum):
    VERIFIED = "verified"
    BLOCKED = "blocked"
    REJECTED = "rejected"


class ComparisonResult(StrEnum):
    PASS = "pass"
    BLOCKED = "blocked"
    REJECTED = "rejected"


@dataclass(frozen=True)
class SealedCanaryReceipt:
    """Immutable public-safe #96 identity consumed without target mutation."""

    source_candidate_sha: str
    receipt_digest: str
    execution_ledger_digest: str
    lifecycle_ledger_digest: str
    lifecycle_comparison_digest: str
    target_repository: str
    target_merge_sha: str
    ready_at: int

    def __post_init__(self) -> None:
        if (
            self.source_candidate_sha != SEALED_CANARY_SOURCE_CANDIDATE_SHA
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.receipt_digest,
                    self.execution_ledger_digest,
                    self.lifecycle_ledger_digest,
                    self.lifecycle_comparison_digest,
                )
            )
            or self.target_repository != FORWARD_TEST_REPOSITORY
            or _REPOSITORY.fullmatch(self.target_repository) is None
            or _SHA.fullmatch(self.target_merge_sha) is None
            or type(self.ready_at) is not int
            or self.ready_at < 0
            or (
                self.receipt_digest,
                self.execution_ledger_digest,
                self.lifecycle_ledger_digest,
                self.lifecycle_comparison_digest,
                self.target_merge_sha,
                self.ready_at,
            ) != (
                SEALED_CANARY_RECEIPT_DIGEST,
                SEALED_CANARY_EXECUTION_LEDGER_DIGEST,
                SEALED_CANARY_LIFECYCLE_LEDGER_DIGEST,
                SEALED_CANARY_LIFECYCLE_COMPARISON_DIGEST,
                SEALED_CANARY_TARGET_MERGE_SHA,
                SEALED_CANARY_READY_AT,
            )
        ):
            raise CrossEnvironmentEvidenceError("sealed Canary receipt is invalid")

    def public_payload(self) -> dict[str, object]:
        return {
            "source_candidate_sha": self.source_candidate_sha,
            "receipt_digest": self.receipt_digest,
            "execution_ledger_digest": self.execution_ledger_digest,
            "lifecycle_ledger_digest": self.lifecycle_ledger_digest,
            "lifecycle_comparison_digest": self.lifecycle_comparison_digest,
            "target_repository": self.target_repository,
            "target_merge_sha": self.target_merge_sha,
            "ready_at": self.ready_at,
        }


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def is_safe_cross_environment_public_string(value: object) -> bool:
    """Return whether a bounded public identifier cannot resemble a credential."""

    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        return False
    lowered = value.lower()
    return (
        not any(word in lowered for word in ("secret", "token", "credential", "password", "path"))
        and not any(shape in lowered for shape in _CREDENTIAL_SHAPES)
    )


def _safe_token(value: object) -> bool:
    return is_safe_cross_environment_public_string(value)


@dataclass(frozen=True)
class EnvironmentLane:
    """One normalized host observation with no paths, logs, or credentials."""

    environment: EnvironmentKind
    environment_identity: str
    mode: OperationMode
    candidate_sha: str
    artifact_digest: str
    policy_digest: str
    profile_digest: str
    schema_digest: str
    producer_identity: str
    receipt_state: ReceiptState
    receipt_digest: str | None
    observed_at: int
    result: ComparisonResult
    reason: str | None = None
    parity_dimensions: tuple[ParityDimension, ...] = PARITY_DIMENSIONS
    parity_digest: str | None = None
    sealed_canary_receipt_digest: str | None = None

    def __post_init__(self) -> None:
        fields = (
            self.candidate_sha,
            self.artifact_digest,
            self.policy_digest,
            self.profile_digest,
            self.schema_digest,
            self.producer_identity,
        )
        if (
            type(self.environment) is not EnvironmentKind
            or not _safe_token(self.environment_identity)
            or type(self.mode) is not OperationMode
            or _SHA.fullmatch(self.candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in fields[1:])
            or type(self.receipt_state) is not ReceiptState
            or self.receipt_digest is not None and _DIGEST.fullmatch(self.receipt_digest) is None
            or type(self.observed_at) is not int
            or self.observed_at < 0
            or type(self.result) is not ComparisonResult
            or self.reason is not None and not _safe_token(self.reason)
            or type(self.parity_dimensions) is not tuple
            or any(type(dimension) is not ParityDimension for dimension in self.parity_dimensions)
            or self.parity_dimensions != PARITY_DIMENSIONS
            or self.parity_digest is not None and _DIGEST.fullmatch(self.parity_digest) is None
            or self.sealed_canary_receipt_digest is not None and _DIGEST.fullmatch(self.sealed_canary_receipt_digest) is None
        ):
            raise CrossEnvironmentEvidenceError("cross-environment lane is invalid")
        if (self.receipt_state is ReceiptState.VERIFIED) != (self.receipt_digest is not None):
            raise CrossEnvironmentEvidenceError("cross-environment receipt binding is invalid")
        if self.mode is OperationMode.AUTHORITATIVE and self.receipt_state is not ReceiptState.VERIFIED:
            raise CrossEnvironmentEvidenceError("authoritative lane lacks a verified receipt")
        if self.result is ComparisonResult.PASS and (self.receipt_state is not ReceiptState.VERIFIED or self.reason is not None):
            raise CrossEnvironmentEvidenceError("passing lane receipt is invalid")
        if self.result is not ComparisonResult.PASS and self.reason is None:
            raise CrossEnvironmentEvidenceError("blocked or rejected lane needs a bounded reason")
        if self.environment is EnvironmentKind.SEALED_CANARY_RECEIPT_CONSUMER:
            if self.mode is not OperationMode.READ_ONLY or self.parity_digest is not None:
                raise CrossEnvironmentEvidenceError("sealed Canary consumer mode is invalid")
        elif self.parity_digest is None:
            raise CrossEnvironmentEvidenceError("environment lane parity is missing")

    def public_payload(self) -> dict[str, object]:
        return _environment_lane_public_payload(_validated_environment_lane(self))


def _environment_lane_public_payload(lane: EnvironmentLane) -> dict[str, object]:
    """Render a lane only after its fields have been reconstructed and checked."""

    return {
        "environment": lane.environment.value,
        "environment_identity": lane.environment_identity,
        "mode": lane.mode.value,
        "candidate_sha": lane.candidate_sha,
        "artifact_digest": lane.artifact_digest,
        "policy_digest": lane.policy_digest,
        "profile_digest": lane.profile_digest,
        "schema_digest": lane.schema_digest,
        "producer_identity": lane.producer_identity,
        "receipt_state": lane.receipt_state.value,
        "receipt_digest": lane.receipt_digest,
        "observed_at": lane.observed_at,
        "result": lane.result.value,
        "reason": lane.reason,
        "parity_dimensions": [dimension.value for dimension in lane.parity_dimensions],
        "parity_digest": lane.parity_digest,
        "sealed_canary_receipt_digest": lane.sealed_canary_receipt_digest,
    }


def _validated_environment_lane(lane: object) -> EnvironmentLane:
    """Reject post-construction changes to a frozen lane before public use."""

    if type(lane) is not EnvironmentLane:
        raise CrossEnvironmentEvidenceError("cross-environment lane is invalid")
    try:
        return EnvironmentLane(
            lane.environment, lane.environment_identity, lane.mode, lane.candidate_sha,
            lane.artifact_digest, lane.policy_digest, lane.profile_digest,
            lane.schema_digest, lane.producer_identity, lane.receipt_state,
            lane.receipt_digest, lane.observed_at, lane.result, lane.reason,
            lane.parity_dimensions, lane.parity_digest, lane.sealed_canary_receipt_digest,
        )
    except (AttributeError, TypeError) as error:
        raise CrossEnvironmentEvidenceError("cross-environment lane is invalid") from error


@dataclass(frozen=True)
class CrossEnvironmentEvidence:
    """The closed seven-lane qualification input consumed by the V2 adapter."""

    candidate_sha: str
    artifact_digest: str
    policy_digest: str
    profile_digest: str
    schema_digest: str
    producer_identity: str
    lanes: tuple[EnvironmentLane, ...]
    sealed_canary: SealedCanaryReceipt
    schema: str = CROSS_ENVIRONMENT_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        digests = (
            self.artifact_digest,
            self.policy_digest,
            self.profile_digest,
            self.schema_digest,
            self.producer_identity,
        )
        if (
            self.schema != CROSS_ENVIRONMENT_EVIDENCE_SCHEMA
            or _SHA.fullmatch(self.candidate_sha) is None
            or any(_DIGEST.fullmatch(value) is None for value in digests)
            or type(self.lanes) is not tuple
            or len(self.lanes) != len(CROSS_ENVIRONMENT_LANE_ORDER)
            or any(type(lane) is not EnvironmentLane for lane in self.lanes)
            or type(self.sealed_canary) is not SealedCanaryReceipt
        ):
            raise CrossEnvironmentEvidenceError("cross-environment evidence is invalid")
        if tuple(lane.environment for lane in self.lanes) != CROSS_ENVIRONMENT_LANE_ORDER:
            raise CrossEnvironmentEvidenceError("cross-environment lanes are missing or duplicate")
        if sum(lane.mode is OperationMode.AUTHORITATIVE for lane in self.lanes) != 1:
            raise CrossEnvironmentEvidenceError("cross-environment authority is not singular")
        if any(
            (
                lane.candidate_sha,
                lane.artifact_digest,
                lane.policy_digest,
                lane.profile_digest,
                lane.schema_digest,
                lane.producer_identity,
            ) != (self.candidate_sha, *digests)
            for lane in self.lanes
        ):
            raise CrossEnvironmentEvidenceError("cross-environment lane identity has drifted")
        if any(lane.sealed_canary_receipt_digest != self.sealed_canary.receipt_digest for lane in self.lanes):
            raise CrossEnvironmentEvidenceError("cross-environment sealed Canary binding has drifted")
        active_lanes = self.lanes[:-1]
        if len({lane.parity_digest for lane in active_lanes}) != 1:
            raise CrossEnvironmentEvidenceError("cross-environment parity results differ")
        authoritative = next(lane for lane in active_lanes if lane.mode is OperationMode.AUTHORITATIVE)
        if authoritative.receipt_digest != self.sealed_canary.receipt_digest:
            raise CrossEnvironmentEvidenceError("authoritative lane is not bound to the sealed Canary")

    @property
    def evidence_digest(self) -> str:
        return _digest(self.public_payload())

    @property
    def result(self) -> ComparisonResult:
        evidence = _validated_cross_environment_evidence(self)
        if any(lane.result is ComparisonResult.REJECTED for lane in evidence.lanes):
            return ComparisonResult.REJECTED
        if any(lane.result is ComparisonResult.BLOCKED for lane in evidence.lanes):
            return ComparisonResult.BLOCKED
        return ComparisonResult.PASS

    def public_payload(self) -> dict[str, object]:
        evidence = _validated_cross_environment_evidence(self)
        return {
            "schema": evidence.schema,
            "candidate_sha": evidence.candidate_sha,
            "artifact_digest": evidence.artifact_digest,
            "policy_digest": evidence.policy_digest,
            "profile_digest": evidence.profile_digest,
            "schema_digest": evidence.schema_digest,
            "producer_identity": evidence.producer_identity,
            "lanes": [_environment_lane_public_payload(lane) for lane in evidence.lanes],
            "sealed_canary": evidence.sealed_canary.public_payload(),
            "result": evidence.result.value,
        }


def _validated_cross_environment_evidence(evidence: object) -> CrossEnvironmentEvidence:
    """Reconstruct the complete evidence tree at each public boundary."""

    if type(evidence) is not CrossEnvironmentEvidence or type(evidence.lanes) is not tuple:
        raise CrossEnvironmentEvidenceError("cross-environment evidence is invalid")
    try:
        sealed = evidence.sealed_canary
        sealed = SealedCanaryReceipt(
            sealed.source_candidate_sha, sealed.receipt_digest,
            sealed.execution_ledger_digest, sealed.lifecycle_ledger_digest,
            sealed.lifecycle_comparison_digest, sealed.target_repository,
            sealed.target_merge_sha, sealed.ready_at,
        )
        return CrossEnvironmentEvidence(
            evidence.candidate_sha, evidence.artifact_digest, evidence.policy_digest,
            evidence.profile_digest, evidence.schema_digest, evidence.producer_identity,
            tuple(_validated_environment_lane(lane) for lane in evidence.lanes), sealed, evidence.schema,
        )
    except (AttributeError, TypeError) as error:
        raise CrossEnvironmentEvidenceError("cross-environment evidence is invalid") from error


@dataclass(frozen=True)
class CrossEnvironmentComparison:
    """A bounded, semantic read-back result for one retained evidence object."""

    result: ComparisonResult
    candidate_sha: str
    expected_digest: str
    observed_digest: str
    differences: tuple[str, ...]
    schema: str = CROSS_ENVIRONMENT_RESULT_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != CROSS_ENVIRONMENT_RESULT_SCHEMA
            or type(self.result) is not ComparisonResult
            or _SHA.fullmatch(self.candidate_sha) is None
            or _DIGEST.fullmatch(self.expected_digest) is None
            or _DIGEST.fullmatch(self.observed_digest) is None
            or type(self.differences) is not tuple
            or any(not _safe_token(value) for value in self.differences)
            or tuple(sorted(set(self.differences))) != self.differences
            or (self.result is ComparisonResult.PASS) != (not self.differences)
        ):
            raise CrossEnvironmentEvidenceError("cross-environment comparison is invalid")

    def public_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "result": self.result.value,
            "candidate_sha": self.candidate_sha,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "differences": list(self.differences),
        }


def compare_cross_environment_evidence(
    expected: CrossEnvironmentEvidence, observed: CrossEnvironmentEvidence,
) -> CrossEnvironmentComparison:
    """Compare only public-safe semantic fields; never report raw lane content."""

    expected = _validated_cross_environment_evidence(expected)
    observed = _validated_cross_environment_evidence(observed)
    differences: list[str] = []
    if expected.candidate_sha != observed.candidate_sha:
        differences.append("candidate-mismatch")
    for name in ("artifact_digest", "policy_digest", "profile_digest", "schema_digest", "producer_identity"):
        if getattr(expected, name) != getattr(observed, name):
            differences.append(name.removesuffix("_digest") + "-mismatch")
    if tuple(lane.public_payload() for lane in expected.lanes) != tuple(lane.public_payload() for lane in observed.lanes):
        differences.append("lane-mismatch")
    if observed.result is not ComparisonResult.PASS:
        differences.append("observed-" + observed.result.value)
    differences = sorted(set(differences))
    result = ComparisonResult.PASS if not differences else (
        ComparisonResult.REJECTED if observed.result is ComparisonResult.REJECTED else ComparisonResult.BLOCKED
    )
    return CrossEnvironmentComparison(
        result,
        expected.candidate_sha,
        expected.evidence_digest,
        observed.evidence_digest,
        tuple(differences),
    )


def semantic_read_back(
    retained_payload: Mapping[str, object], expected: CrossEnvironmentEvidence,
) -> CrossEnvironmentComparison:
    """Require a recorded public-safe payload to be the exact expected evidence."""

    if type(retained_payload) is not dict:
        raise CrossEnvironmentEvidenceError("cross-environment retention payload is invalid")
    expected = _validated_cross_environment_evidence(expected)
    observed = expected.public_payload()
    if retained_payload == observed:
        return compare_cross_environment_evidence(expected, expected)
    return CrossEnvironmentComparison(
        ComparisonResult.BLOCKED,
        expected.candidate_sha,
        expected.evidence_digest,
        _digest(retained_payload),
        ("retention-readback-mismatch",),
    )
