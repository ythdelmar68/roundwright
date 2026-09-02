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


class CrossEnvironmentEvidenceError(ValueError):
    """Raised when a cross-environment evidence tuple is incomplete or mixed."""


class EnvironmentKind(StrEnum):
    NATIVE_WINDOWS = "native-windows"
    NATIVE_MACOS = "native-macos"
    NATIVE_LINUX = "native-linux"
    CI = "ci"
    DOCKER = "docker"
    DEV_CONTAINER = "dev-container"


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


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _safe_token(value: object) -> bool:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        return False
    lowered = value.lower()
    return not any(word in lowered for word in ("secret", "token", "credential", "password", "path"))


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

    def public_payload(self) -> dict[str, object]:
        return {
            "environment": self.environment.value,
            "environment_identity": self.environment_identity,
            "mode": self.mode.value,
            "candidate_sha": self.candidate_sha,
            "artifact_digest": self.artifact_digest,
            "policy_digest": self.policy_digest,
            "profile_digest": self.profile_digest,
            "schema_digest": self.schema_digest,
            "producer_identity": self.producer_identity,
            "receipt_state": self.receipt_state.value,
            "receipt_digest": self.receipt_digest,
            "observed_at": self.observed_at,
            "result": self.result.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CrossEnvironmentEvidence:
    """The closed six-lane qualification input consumed by the V2 adapter."""

    candidate_sha: str
    artifact_digest: str
    policy_digest: str
    profile_digest: str
    schema_digest: str
    producer_identity: str
    lanes: tuple[EnvironmentLane, ...]
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
            or len(self.lanes) != len(EnvironmentKind)
            or any(type(lane) is not EnvironmentLane for lane in self.lanes)
        ):
            raise CrossEnvironmentEvidenceError("cross-environment evidence is invalid")
        if {lane.environment for lane in self.lanes} != set(EnvironmentKind):
            raise CrossEnvironmentEvidenceError("cross-environment lanes are missing or duplicate")
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
        if tuple(lane.environment.value for lane in self.lanes) != tuple(sorted(lane.environment.value for lane in self.lanes)):
            raise CrossEnvironmentEvidenceError("cross-environment lanes are not canonically ordered")

    @property
    def evidence_digest(self) -> str:
        return _digest(self.public_payload())

    @property
    def result(self) -> ComparisonResult:
        if any(lane.result is ComparisonResult.REJECTED for lane in self.lanes):
            return ComparisonResult.REJECTED
        if any(lane.result is ComparisonResult.BLOCKED for lane in self.lanes):
            return ComparisonResult.BLOCKED
        return ComparisonResult.PASS

    def public_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "candidate_sha": self.candidate_sha,
            "artifact_digest": self.artifact_digest,
            "policy_digest": self.policy_digest,
            "profile_digest": self.profile_digest,
            "schema_digest": self.schema_digest,
            "producer_identity": self.producer_identity,
            "lanes": [lane.public_payload() for lane in self.lanes],
            "result": self.result.value,
        }


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

    if type(expected) is not CrossEnvironmentEvidence or type(observed) is not CrossEnvironmentEvidence:
        raise CrossEnvironmentEvidenceError("cross-environment comparison inputs are invalid")
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

    if type(retained_payload) is not dict or type(expected) is not CrossEnvironmentEvidence:
        raise CrossEnvironmentEvidenceError("cross-environment retention payload is invalid")
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
