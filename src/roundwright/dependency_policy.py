"""Candidate-bound, hermetic trust gates for dependency helper execution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Iterable


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_TASK = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


class DependencyPolicyError(ValueError):
    """Raised when untrusted policy or execution evidence is supplied."""


class DependencyComponent(StrEnum):
    PACKAGE = "package"
    PROVIDER_RUNTIME = "provider-runtime"
    GITHUB_CLI = "github-cli"
    BUILD_BACKEND = "build-backend"
    GIT_EXECUTABLE = "git-executable"
    OPTIONAL_ADAPTER = "optional-adapter"


class DependencyStage(StrEnum):
    DISPATCH = "dispatch"
    GITHUB_READ = "github-read"
    GITHUB_MUTATION = "github-mutation"
    PACKAGE_BUILD = "package-build"
    PROVIDER_QUALIFICATION = "provider-qualification"
    OPTIONAL_ADAPTER = "optional-adapter"
    GIT_ENTRYPOINT = "git-entrypoint"


class PolicyTransitionKind(StrEnum):
    INITIAL = "initial"
    BOOTSTRAP = "bootstrap"
    UPGRADE = "upgrade"
    ROLLBACK = "rollback"


class DependencyDecisionOutcome(StrEnum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"


class DependencyDecisionCode(StrEnum):
    AUTHORIZED = "authorized"
    INVALID_CONTEXT = "invalid-context"
    POLICY_UNAVAILABLE = "policy-unavailable"
    POLICY_STALE = "policy-stale"
    CANDIDATE_MISMATCH = "candidate-mismatch"
    PROVENANCE_UNAVAILABLE = "provenance-unavailable"
    PROVENANCE_INVALID = "provenance-invalid"
    DUPLICATE_PROVENANCE = "duplicate-provenance"
    POLICY_COVERAGE_MISSING = "policy-coverage-missing"
    PROVENANCE_MISSING = "provenance-missing"
    PROVENANCE_STALE = "provenance-stale"
    IDENTITY_MISMATCH = "identity-mismatch"
    EXECUTABLE_MISMATCH = "executable-mismatch"
    VERSION_UNSUPPORTED = "version-unsupported"
    POLICY_TRANSITION_INVALID = "policy-transition-invalid"


_CANONICAL_STAGE_REQUIREMENTS: dict[DependencyStage, tuple[DependencyComponent, ...]] = {
    DependencyStage.DISPATCH: (
        DependencyComponent.PACKAGE,
        DependencyComponent.PROVIDER_RUNTIME,
        DependencyComponent.GITHUB_CLI,
        DependencyComponent.BUILD_BACKEND,
    ),
    DependencyStage.GITHUB_READ: (DependencyComponent.PACKAGE, DependencyComponent.GITHUB_CLI),
    DependencyStage.GITHUB_MUTATION: (DependencyComponent.PACKAGE, DependencyComponent.GITHUB_CLI),
    DependencyStage.PACKAGE_BUILD: (DependencyComponent.PACKAGE, DependencyComponent.BUILD_BACKEND),
    DependencyStage.PROVIDER_QUALIFICATION: (DependencyComponent.PACKAGE, DependencyComponent.PROVIDER_RUNTIME),
    DependencyStage.OPTIONAL_ADAPTER: (DependencyComponent.PACKAGE, DependencyComponent.OPTIONAL_ADAPTER),
    DependencyStage.GIT_ENTRYPOINT: (DependencyComponent.PACKAGE, DependencyComponent.GIT_EXECUTABLE),
}

_DIAGNOSTICS = {
    DependencyDecisionCode.AUTHORIZED: "all mandatory dependency identities are current",
    DependencyDecisionCode.INVALID_CONTEXT: "candidate dependency preflight context is invalid",
    DependencyDecisionCode.POLICY_UNAVAILABLE: "trusted dependency policy is unavailable",
    DependencyDecisionCode.POLICY_STALE: "trusted dependency policy is stale",
    DependencyDecisionCode.CANDIDATE_MISMATCH: "dependency evidence does not match the active candidate",
    DependencyDecisionCode.PROVENANCE_UNAVAILABLE: "dependency provenance is unavailable",
    DependencyDecisionCode.PROVENANCE_INVALID: "dependency provenance is invalid",
    DependencyDecisionCode.DUPLICATE_PROVENANCE: "duplicate dependency provenance was supplied",
    DependencyDecisionCode.POLICY_COVERAGE_MISSING: "required dependency is not covered by policy",
    DependencyDecisionCode.PROVENANCE_MISSING: "required dependency provenance is missing",
    DependencyDecisionCode.PROVENANCE_STALE: "dependency provenance is stale",
    DependencyDecisionCode.IDENTITY_MISMATCH: "dependency identity does not match policy",
    DependencyDecisionCode.EXECUTABLE_MISMATCH: "dependency executable identity does not match policy",
    DependencyDecisionCode.VERSION_UNSUPPORTED: "dependency version is unsupported",
    DependencyDecisionCode.POLICY_TRANSITION_INVALID: "dependency policy transition is not admitted",
}


@dataclass(frozen=True)
class CandidateBinding:
    """Exact public repository, task, and candidate identity for all evidence."""

    repository: str
    task_id: str
    candidate_sha: str

    def __post_init__(self) -> None:
        if not _REPOSITORY.fullmatch(self.repository) or not _TASK.fullmatch(self.task_id) or not _COMMIT.fullmatch(self.candidate_sha):
            raise DependencyPolicyError("candidate dependency binding is invalid")

    @property
    def fingerprint(self) -> str:
        return _fingerprint({"repository": self.repository, "task_id": self.task_id, "candidate_sha": self.candidate_sha})


@dataclass(frozen=True)
class VersionRange:
    minimum: str
    maximum_exclusive: str

    def __post_init__(self) -> None:
        if not _is_version(self.minimum) or not _is_version(self.maximum_exclusive) or _version_key(self.minimum) >= _version_key(self.maximum_exclusive):
            raise DependencyPolicyError("supported version range is invalid")

    def contains(self, version: str) -> bool:
        return _is_version(version) and _version_key(self.minimum) <= _version_key(version) < _version_key(self.maximum_exclusive)


@dataclass(frozen=True)
class ComponentPolicy:
    component: DependencyComponent
    identifier: str
    versions: VersionRange
    source_identity: str
    artifact_digest: str
    executable_digest: str

    def __post_init__(self) -> None:
        if type(self.component) is not DependencyComponent or type(self.versions) is not VersionRange:
            raise DependencyPolicyError("dependency component policy is invalid")
        if not _safe_identifier(self.identifier) or "copilot" in self.identifier or not _safe_identifier(self.source_identity):
            raise DependencyPolicyError("dependency component policy is invalid")
        if not _is_digest(self.artifact_digest) or not _is_digest(self.executable_digest):
            raise DependencyPolicyError("dependency component policy is invalid")

    def evidence(self) -> dict[str, str]:
        return {
            "component": self.component.value,
            "identifier": self.identifier,
            "minimum": self.versions.minimum,
            "maximum_exclusive": self.versions.maximum_exclusive,
            "source_identity": self.source_identity,
            "artifact_digest": self.artifact_digest,
            "executable_digest": self.executable_digest,
        }


@dataclass(frozen=True)
class PolicyTransitionReview:
    """Canonical authority receipt for one complete policy delta."""

    binding: CandidateBinding
    reviewer_identity: str
    authority_digest: str
    previous_policy_fingerprint: str
    current_policy_fingerprint: str
    delta_digest: str
    review_digest: str

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or not all(_is_digest(item) for item in (self.reviewer_identity, self.authority_digest, self.previous_policy_fingerprint, self.current_policy_fingerprint, self.delta_digest, self.review_digest)):
            raise DependencyPolicyError("policy transition review is invalid")
        if self.review_digest != _fingerprint(self._evidence_without_digest()):
            raise DependencyPolicyError("policy transition review is invalid")

    @classmethod
    def create(cls, previous: "DependencyPolicy", current: "DependencyPolicy", *, reviewer_identity: str, authority_digest: str) -> "PolicyTransitionReview":
        if type(previous) is not DependencyPolicy or type(current) is not DependencyPolicy or previous.binding != current.binding:
            raise DependencyPolicyError("policy transition review is invalid")
        evidence = {
            "binding": previous.binding.fingerprint,
            "reviewer_identity": reviewer_identity,
            "authority_digest": authority_digest,
            "previous_policy_fingerprint": previous.core_fingerprint,
            "current_policy_fingerprint": current.core_fingerprint,
            "delta_digest": _policy_delta_digest(previous, current),
        }
        return cls(previous.binding, reviewer_identity, authority_digest, previous.core_fingerprint, current.core_fingerprint, evidence["delta_digest"], _fingerprint(evidence))

    def _evidence_without_digest(self) -> dict[str, str]:
        return {
            "binding": self.binding.fingerprint,
            "reviewer_identity": self.reviewer_identity,
            "authority_digest": self.authority_digest,
            "previous_policy_fingerprint": self.previous_policy_fingerprint,
            "current_policy_fingerprint": self.current_policy_fingerprint,
            "delta_digest": self.delta_digest,
        }


@dataclass(frozen=True)
class BootstrapPolicyReceipt:
    """Trusted authority receipt for the first policy in a candidate lineage."""

    binding: CandidateBinding
    reviewer_identity: str
    authority_digest: str
    policy_fingerprint: str
    receipt_digest: str

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or not all(_is_digest(item) for item in (self.reviewer_identity, self.authority_digest, self.policy_fingerprint, self.receipt_digest)):
            raise DependencyPolicyError("bootstrap policy receipt is invalid")
        if self.receipt_digest != _fingerprint(self._evidence_without_digest()):
            raise DependencyPolicyError("bootstrap policy receipt is invalid")

    @classmethod
    def create(cls, policy: "DependencyPolicy", *, reviewer_identity: str, authority_digest: str) -> "BootstrapPolicyReceipt":
        if type(policy) is not DependencyPolicy:
            raise DependencyPolicyError("bootstrap policy receipt is invalid")
        evidence = {"binding": policy.binding.fingerprint, "reviewer_identity": reviewer_identity, "authority_digest": authority_digest, "policy_fingerprint": policy.core_fingerprint}
        return cls(policy.binding, reviewer_identity, authority_digest, policy.core_fingerprint, _fingerprint(evidence))

    def _evidence_without_digest(self) -> dict[str, str]:
        return {"binding": self.binding.fingerprint, "reviewer_identity": self.reviewer_identity, "authority_digest": self.authority_digest, "policy_fingerprint": self.policy_fingerprint}


@dataclass(frozen=True)
class PolicyTransition:
    kind: PolicyTransitionKind
    review: PolicyTransitionReview | BootstrapPolicyReceipt | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not PolicyTransitionKind:
            raise DependencyPolicyError("dependency policy transition is invalid")
        if self.kind is PolicyTransitionKind.INITIAL or (self.kind is PolicyTransitionKind.BOOTSTRAP and self.review is not None and type(self.review) is not BootstrapPolicyReceipt) or (self.kind in {PolicyTransitionKind.UPGRADE, PolicyTransitionKind.ROLLBACK} and type(self.review) is not PolicyTransitionReview):
            raise DependencyPolicyError("dependency policy transition is invalid")


@dataclass(frozen=True)
class DependencyPolicy:
    binding: CandidateBinding
    policy_digest: str
    issued_at: int
    freshness_seconds: int
    components: tuple[ComponentPolicy, ...]
    transition: PolicyTransition

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or not _is_digest(self.policy_digest) or type(self.issued_at) is not int or self.issued_at < 0 or type(self.freshness_seconds) is not int or self.freshness_seconds < 1:
            raise DependencyPolicyError("dependency policy is invalid")
        if type(self.components) is not tuple or not self.components or any(type(item) is not ComponentPolicy for item in self.components) or len({item.component for item in self.components}) != len(self.components):
            raise DependencyPolicyError("dependency policy is invalid")
        if type(self.transition) is not PolicyTransition:
            raise DependencyPolicyError("dependency policy is invalid")

    @property
    def core_fingerprint(self) -> str:
        return _fingerprint({
            "binding": self.binding.fingerprint,
            "policy_digest": self.policy_digest,
            "issued_at": self.issued_at,
            "freshness_seconds": self.freshness_seconds,
            "components": tuple(item.evidence() for item in self.components),
        })

    def component(self, kind: DependencyComponent) -> ComponentPolicy | None:
        return next((item for item in self.components if item.component is kind), None)


@dataclass(frozen=True)
class TrustedDependencyAdmission:
    """Control-plane sealed receipt and predecessor for one exact policy."""

    binding: CandidateBinding
    policy_fingerprint: str
    receipt_digest: str
    reviewer_identity: str
    authority_digest: str
    previous_policy: DependencyPolicy | None = None

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or not all(
            _is_digest(item) for item in (
                self.policy_fingerprint, self.receipt_digest,
                self.reviewer_identity, self.authority_digest,
            )
        ):
            raise DependencyPolicyError("trusted dependency admission is invalid")
        if self.previous_policy is not None and type(self.previous_policy) is not DependencyPolicy:
            raise DependencyPolicyError("trusted dependency admission is invalid")
        if self.previous_policy is not None and self.previous_policy.binding != self.binding:
            raise DependencyPolicyError("trusted dependency admission is invalid")


@dataclass(frozen=True)
class DependencyExecutionControl:
    """Selection-time sealed evidence consumed at an execution boundary."""

    policy: DependencyPolicy
    observations: tuple[ObservedDependency, ...]
    admission: TrustedDependencyAdmission

    def __post_init__(self) -> None:
        if type(self.policy) is not DependencyPolicy or type(self.observations) is not tuple or any(type(item) is not ObservedDependency for item in self.observations) or type(self.admission) is not TrustedDependencyAdmission:
            raise DependencyPolicyError("dependency execution control is invalid")
        if self.admission.binding != self.policy.binding:
            raise DependencyPolicyError("dependency execution control is invalid")

    def require(self, binding: CandidateBinding, stage: DependencyStage, *, now: int) -> None:
        """Fail closed before a provider, transport, subprocess, or mutation starts."""

        decision = evaluate_dependency_preflight(
            binding, self.policy, self.observations, stage, now=now,
            previous_policy=self.admission.previous_policy, trusted_admission=self.admission,
        )
        if decision.outcome is not DependencyDecisionOutcome.PASS:
            raise DependencyPolicyError(decision.code.value)


@dataclass(frozen=True)
class ObservedDependency:
    binding: CandidateBinding
    component: DependencyComponent
    identifier: str
    version: str
    source_identity: str
    artifact_digest: str
    executable_digest: str
    observed_at: int
    policy_digest: str

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or type(self.component) is not DependencyComponent or not _safe_identifier(self.identifier) or not _is_version(self.version) or not _safe_identifier(self.source_identity) or "copilot" in self.identifier:
            raise DependencyPolicyError("dependency observation is invalid")
        if not all(_is_digest(item) for item in (self.artifact_digest, self.executable_digest, self.policy_digest)) or type(self.observed_at) is not int or self.observed_at < 0:
            raise DependencyPolicyError("dependency observation is invalid")

    @property
    def fingerprint(self) -> str:
        return _fingerprint({
            "binding": self.binding.fingerprint,
            "component": self.component.value,
            "identifier": self.identifier,
            "version": self.version,
            "source_identity": self.source_identity,
            "artifact_digest": self.artifact_digest,
            "executable_digest": self.executable_digest,
            "observed_at": self.observed_at,
            "policy_digest": self.policy_digest,
        })


@dataclass(frozen=True)
class DependencyDecision:
    outcome: DependencyDecisionOutcome
    code: DependencyDecisionCode
    stage: DependencyStage | None
    binding_fingerprint: str | None
    policy_fingerprint: str | None
    observation_fingerprints: tuple[str, ...]
    evaluated_at: int

    def __post_init__(self) -> None:
        if type(self.outcome) is not DependencyDecisionOutcome or type(self.code) is not DependencyDecisionCode or type(self.observation_fingerprints) is not tuple or any(not _is_digest(item) for item in self.observation_fingerprints) or type(self.evaluated_at) is not int or self.evaluated_at < 0:
            raise DependencyPolicyError("dependency decision is invalid")


def canonical_stage_requirements(stage: DependencyStage) -> tuple[DependencyComponent, ...]:
    """Return the closed requirement map used by every helper boundary."""

    if type(stage) is not DependencyStage:
        raise DependencyPolicyError("dependency stage is invalid")
    return _CANONICAL_STAGE_REQUIREMENTS[stage]


def evaluate_dependency_preflight(binding: CandidateBinding, policy: DependencyPolicy | None, observations: Iterable[ObservedDependency] | None, stage: DependencyStage, *, now: int, previous_policy: DependencyPolicy | None = None, trusted_admission: TrustedDependencyAdmission | None = None) -> DependencyDecision:
    """Authorize exactly one canonical helper stage without discovering tools."""

    if type(binding) is not CandidateBinding or type(stage) is not DependencyStage or type(now) is not int or now < 0:
        return _blocked(binding, stage, DependencyDecisionCode.INVALID_CONTEXT, now)
    if type(policy) is not DependencyPolicy:
        return _blocked(binding, stage, DependencyDecisionCode.POLICY_UNAVAILABLE, now)
    if policy.binding != binding:
        return _blocked(binding, stage, DependencyDecisionCode.CANDIDATE_MISMATCH, now)
    if now - policy.issued_at > policy.freshness_seconds or policy.issued_at > now:
        return _blocked(binding, stage, DependencyDecisionCode.POLICY_STALE, now)
    if not verify_policy_admission(policy, previous_policy, trusted_admission):
        return _blocked(binding, stage, DependencyDecisionCode.POLICY_TRANSITION_INVALID, now)
    if observations is None:
        return _blocked(binding, stage, DependencyDecisionCode.PROVENANCE_UNAVAILABLE, now)
    try:
        records = tuple(observations)
    except TypeError:
        return _blocked(binding, stage, DependencyDecisionCode.PROVENANCE_INVALID, now)
    if any(type(item) is not ObservedDependency for item in records):
        return _blocked(binding, stage, DependencyDecisionCode.PROVENANCE_INVALID, now)
    if any(item.binding != binding for item in records):
        return _blocked(binding, stage, DependencyDecisionCode.CANDIDATE_MISMATCH, now)
    if len({item.component for item in records}) != len(records):
        return _blocked(binding, stage, DependencyDecisionCode.DUPLICATE_PROVENANCE, now)

    selected: list[str] = []
    records_by_component = {item.component: item for item in records}
    for component in canonical_stage_requirements(stage):
        expected = policy.component(component)
        observed = records_by_component.get(component)
        if expected is None:
            return _blocked(binding, stage, DependencyDecisionCode.POLICY_COVERAGE_MISSING, now)
        if observed is None:
            return _blocked(binding, stage, DependencyDecisionCode.PROVENANCE_MISSING, now)
        code = _validate_observation(policy, expected, observed, now)
        if code is not None:
            return _blocked(binding, stage, code, now)
        selected.append(observed.fingerprint)
    return DependencyDecision(DependencyDecisionOutcome.PASS, DependencyDecisionCode.AUTHORIZED, stage, binding.fingerprint, policy.core_fingerprint, tuple(selected), now)


def verify_policy_transition(previous: DependencyPolicy, current: DependencyPolicy) -> bool:
    """Require a canonical authority receipt over the complete policy delta."""

    if type(previous) is not DependencyPolicy or type(current) is not DependencyPolicy or previous.binding != current.binding:
        return False
    transition = current.transition
    if transition.kind not in {PolicyTransitionKind.UPGRADE, PolicyTransitionKind.ROLLBACK} or type(transition.review) is not PolicyTransitionReview:
        return False
    review = transition.review
    if review.binding != current.binding or review.previous_policy_fingerprint != previous.core_fingerprint or review.current_policy_fingerprint != current.core_fingerprint or review.delta_digest != _policy_delta_digest(previous, current):
        return False
    before = {item.component: item for item in previous.components}
    after = {item.component: item for item in current.components}
    if before.keys() != after.keys():
        return False
    minimum_direction = {_compare_version(after[key].versions.minimum, before[key].versions.minimum) for key in before}
    maximum_direction = {_compare_version(after[key].versions.maximum_exclusive, before[key].versions.maximum_exclusive) for key in before}
    if minimum_direction == {0} and maximum_direction == {0}:
        return False
    if transition.kind is PolicyTransitionKind.UPGRADE:
        return all(value >= 0 for value in minimum_direction | maximum_direction) and any(value > 0 for value in minimum_direction | maximum_direction)
    return all(value <= 0 for value in minimum_direction | maximum_direction) and any(value < 0 for value in minimum_direction | maximum_direction)


def verify_policy_admission(policy: DependencyPolicy, previous_policy: DependencyPolicy | None, trusted_admission: TrustedDependencyAdmission | None = None) -> bool:
    """Admit only an authority-receipted bootstrap or reviewed policy change."""

    if (
        type(policy) is not DependencyPolicy
        or type(trusted_admission) is not TrustedDependencyAdmission
        or trusted_admission.binding != policy.binding
        or trusted_admission.policy_fingerprint != policy.core_fingerprint
    ):
        return False
    transition = policy.transition
    if transition.kind is PolicyTransitionKind.BOOTSTRAP and type(transition.review) is BootstrapPolicyReceipt:
        receipt = transition.review
        return (
            trusted_admission.previous_policy is None
            and receipt.binding == policy.binding
            and receipt.policy_fingerprint == policy.core_fingerprint
            and (receipt.receipt_digest, receipt.reviewer_identity, receipt.authority_digest)
            == (trusted_admission.receipt_digest, trusted_admission.reviewer_identity, trusted_admission.authority_digest)
        )
    if (
        type(previous_policy) is not DependencyPolicy
        or previous_policy != trusted_admission.previous_policy
        or not verify_policy_transition(previous_policy, policy)
    ):
        return False
    review = policy.transition.review
    return type(review) is PolicyTransitionReview and (
        review.review_digest, review.reviewer_identity, review.authority_digest
    ) == (
        trusted_admission.receipt_digest,
        trusted_admission.reviewer_identity,
        trusted_admission.authority_digest,
    )


def execute_after_dependency_preflight(binding: CandidateBinding, policy: DependencyPolicy | None, observations: Iterable[ObservedDependency] | None, stage: DependencyStage, *, now: int, action: Callable[[], object], previous_policy: DependencyPolicy | None = None, trusted_admission: TrustedDependencyAdmission | None = None) -> object:
    """Run an action only after its non-optional canonical checks pass."""

    decision = evaluate_dependency_preflight(binding, policy, observations, stage, now=now, previous_policy=previous_policy, trusted_admission=trusted_admission)
    if decision.outcome is not DependencyDecisionOutcome.PASS:
        raise DependencyPolicyError(decision.code.value)
    return action()


def render_dependency_decision(decision: DependencyDecision) -> str:
    """Render only fixed public-safe diagnostic text."""

    if type(decision) is not DependencyDecision:
        return "dependency-gate=BLOCKED stage=unknown code=invalid-context reason=candidate dependency preflight context is invalid"
    stage = decision.stage.value if type(decision.stage) is DependencyStage else "unknown"
    return f"dependency-gate={decision.outcome.value} stage={stage} code={decision.code.value} reason={_DIAGNOSTICS[decision.code]}"


def _validate_observation(policy: DependencyPolicy, expected: ComponentPolicy, observed: ObservedDependency, now: int) -> DependencyDecisionCode | None:
    if observed.policy_digest != policy.policy_digest:
        return DependencyDecisionCode.CANDIDATE_MISMATCH
    if now - observed.observed_at > policy.freshness_seconds or observed.observed_at > now:
        return DependencyDecisionCode.PROVENANCE_STALE
    if (observed.identifier, observed.source_identity, observed.artifact_digest) != (expected.identifier, expected.source_identity, expected.artifact_digest):
        return DependencyDecisionCode.IDENTITY_MISMATCH
    if observed.executable_digest != expected.executable_digest:
        return DependencyDecisionCode.EXECUTABLE_MISMATCH
    if not expected.versions.contains(observed.version):
        return DependencyDecisionCode.VERSION_UNSUPPORTED
    return None


def _blocked(binding: object, stage: object, code: DependencyDecisionCode, now: object) -> DependencyDecision:
    valid_binding = binding if type(binding) is CandidateBinding else None
    return DependencyDecision(DependencyDecisionOutcome.BLOCKED, code, stage if type(stage) is DependencyStage else None, valid_binding.fingerprint if valid_binding else None, None, (), now if type(now) is int and now >= 0 else 0)


def _policy_delta_digest(previous: DependencyPolicy, current: DependencyPolicy) -> str:
    return _fingerprint({"previous": tuple(item.evidence() for item in previous.components), "current": tuple(item.evidence() for item in current.components)})


def _fingerprint(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _safe_identifier(value: object) -> bool:
    return type(value) is str and bool(_IDENTIFIER.fullmatch(value))


def _is_version(value: object) -> bool:
    return type(value) is str and bool(_VERSION.fullmatch(value))


def _version_key(value: str) -> tuple[int, int, int]:
    match = _VERSION.fullmatch(value)
    assert match is not None
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


def _compare_version(left: str, right: str) -> int:
    return (_version_key(left) > _version_key(right)) - (_version_key(left) < _version_key(right))
