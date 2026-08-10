"""Hermetic trust gates for dependencies and executable runtime components.

This module deliberately accepts observations from a caller instead of finding
or starting tools itself.  That makes the authorization decision independent
of PATH, private filesystem locations, command output, and network state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Iterable


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


class DependencyPolicyError(ValueError):
    """Raised when policy or provenance evidence is not safe to evaluate."""


class DependencyComponent(StrEnum):
    PACKAGE = "package"
    PROVIDER_RUNTIME = "provider-runtime"
    GITHUB_CLI = "github-cli"
    BUILD_BACKEND = "build-backend"
    OPTIONAL_ADAPTER = "optional-adapter"


class DependencyStage(StrEnum):
    DISPATCH = "dispatch"
    GITHUB_MUTATION = "github-mutation"
    PACKAGE_BUILD = "package-build"
    PROVIDER_QUALIFICATION = "provider-qualification"
    OPTIONAL_ADAPTER = "optional-adapter"


class PolicyTransitionKind(StrEnum):
    INITIAL = "initial"
    UPGRADE = "upgrade"
    ROLLBACK = "rollback"


class DependencyDecisionOutcome(StrEnum):
    PASS = "PASS"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class VersionRange:
    """A supported, finite semantic-version range."""

    minimum: str
    maximum_exclusive: str

    def __post_init__(self) -> None:
        if not _is_version(self.minimum) or not _is_version(self.maximum_exclusive):
            raise DependencyPolicyError("supported version range is invalid")
        if _version_key(self.minimum) >= _version_key(self.maximum_exclusive):
            raise DependencyPolicyError("supported version range is empty")

    def contains(self, version: str) -> bool:
        return _is_version(version) and _version_key(self.minimum) <= _version_key(version) < _version_key(self.maximum_exclusive)


@dataclass(frozen=True)
class ComponentPolicy:
    """Trusted immutable expectation for one independently usable component."""

    component: DependencyComponent
    identifier: str
    versions: VersionRange
    source_identity: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if type(self.component) is not DependencyComponent or not _safe_identifier(self.identifier):
            raise DependencyPolicyError("dependency component policy is invalid")
        if "copilot" in self.identifier or type(self.versions) is not VersionRange:
            raise DependencyPolicyError("dependency component policy is invalid")
        if not _safe_identifier(self.source_identity) or not _is_digest(self.artifact_digest):
            raise DependencyPolicyError("dependency component policy is invalid")


@dataclass(frozen=True)
class PolicyTransition:
    """Owner-reviewed evidence for a policy upgrade or rollback."""

    kind: PolicyTransitionKind
    previous_policy_digest: str | None
    review_digest: str | None

    def __post_init__(self) -> None:
        if type(self.kind) is not PolicyTransitionKind:
            raise DependencyPolicyError("dependency policy transition is invalid")
        if self.kind is PolicyTransitionKind.INITIAL:
            if self.previous_policy_digest is not None or self.review_digest is not None:
                raise DependencyPolicyError("initial policy transition is invalid")
        elif not _is_digest(self.previous_policy_digest) or not _is_digest(self.review_digest):
            raise DependencyPolicyError("reviewed policy transition is invalid")


@dataclass(frozen=True)
class DependencyPolicy:
    """A path-free dependency policy obtained from an already trusted source."""

    policy_digest: str
    freshness_seconds: int
    components: tuple[ComponentPolicy, ...]
    transition: PolicyTransition

    def __post_init__(self) -> None:
        if not _is_digest(self.policy_digest) or type(self.freshness_seconds) is not int or self.freshness_seconds < 1:
            raise DependencyPolicyError("dependency policy is invalid")
        if type(self.components) is not tuple or not self.components or any(type(item) is not ComponentPolicy for item in self.components):
            raise DependencyPolicyError("dependency policy is invalid")
        if len({item.component for item in self.components}) != len(self.components) or type(self.transition) is not PolicyTransition:
            raise DependencyPolicyError("dependency policy is invalid")

    def component(self, kind: DependencyComponent) -> ComponentPolicy | None:
        return next((item for item in self.components if item.component is kind), None)


@dataclass(frozen=True)
class ObservedDependency:
    """A caller-supplied, exact identity; it never contains an executable path."""

    component: DependencyComponent
    identifier: str
    version: str
    source_identity: str
    artifact_digest: str
    executable_digest: str
    observed_at: int
    policy_digest: str

    def __post_init__(self) -> None:
        if type(self.component) is not DependencyComponent or not _safe_identifier(self.identifier) or not _is_version(self.version):
            raise DependencyPolicyError("dependency observation is invalid")
        if "copilot" in self.identifier or not _safe_identifier(self.source_identity):
            raise DependencyPolicyError("dependency observation is invalid")
        if not all(_is_digest(value) for value in (self.artifact_digest, self.executable_digest, self.policy_digest)):
            raise DependencyPolicyError("dependency observation is invalid")
        if type(self.observed_at) is not int or self.observed_at < 0:
            raise DependencyPolicyError("dependency observation is invalid")

    @property
    def fingerprint(self) -> str:
        """Return a content-addressed, path-independent observation identity."""

        encoded = json.dumps(
            {
                "component": self.component.value,
                "identifier": self.identifier,
                "version": self.version,
                "source_identity": self.source_identity,
                "artifact_digest": self.artifact_digest,
                "executable_digest": self.executable_digest,
                "observed_at": self.observed_at,
                "policy_digest": self.policy_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class StageRequirement:
    """Components required for exactly one stage, keeping optional adapters isolated."""

    stage: DependencyStage
    components: tuple[DependencyComponent, ...]

    def __post_init__(self) -> None:
        if type(self.stage) is not DependencyStage or type(self.components) is not tuple or not self.components:
            raise DependencyPolicyError("dependency stage requirement is invalid")
        if any(type(item) is not DependencyComponent for item in self.components) or len(set(self.components)) != len(self.components):
            raise DependencyPolicyError("dependency stage requirement is invalid")


@dataclass(frozen=True)
class DependencyDecision:
    outcome: DependencyDecisionOutcome
    stage: DependencyStage
    reason: str
    observation_fingerprints: tuple[str, ...] = ()


def evaluate_dependency_preflight(
    policy: DependencyPolicy | None,
    observations: Iterable[ObservedDependency] | None,
    requirement: StageRequirement,
    *,
    now: int,
) -> DependencyDecision:
    """Fail closed before dispatch, mutation, build, or adapter use.

    The function is pure: it cannot inspect PATH, launch a helper, read a
    filesystem path, or contact a registry.  Callers must first supply one
    policy-bound observation for every component needed by this exact stage.
    """

    if type(requirement) is not StageRequirement or type(now) is not int or now < 0:
        return _blocked(requirement, "invalid preflight context")
    if type(policy) is not DependencyPolicy:
        return _blocked(requirement, "trusted dependency policy is unavailable")
    if observations is None:
        return _blocked(requirement, "dependency provenance is unavailable")
    try:
        records = tuple(observations)
    except TypeError:
        return _blocked(requirement, "dependency provenance is invalid")
    if any(type(item) is not ObservedDependency for item in records):
        return _blocked(requirement, "dependency provenance is invalid")
    if len({item.component for item in records}) != len(records):
        return _blocked(requirement, "duplicate dependency provenance was supplied")

    selected: list[str] = []
    by_component = {item.component: item for item in records}
    for component in requirement.components:
        expected = policy.component(component)
        observed = by_component.get(component)
        if expected is None:
            return _blocked(requirement, "required dependency is not covered by policy")
        if observed is None:
            return _blocked(requirement, "required dependency provenance is missing")
        reason = _validate_observation(policy, expected, observed, now)
        if reason is not None:
            return _blocked(requirement, reason)
        selected.append(observed.fingerprint)
    return DependencyDecision(DependencyDecisionOutcome.PASS, requirement.stage, "all required dependency identities are current", tuple(selected))


def verify_policy_transition(previous: DependencyPolicy, current: DependencyPolicy) -> bool:
    """Validate an explicitly reviewed upgrade or rollback without applying it."""

    if type(previous) is not DependencyPolicy or type(current) is not DependencyPolicy:
        return False
    transition = current.transition
    if transition.kind is PolicyTransitionKind.INITIAL or transition.previous_policy_digest != previous.policy_digest:
        return False
    if not _is_digest(transition.review_digest):
        return False
    earlier = {item.component: item for item in previous.components}
    later = {item.component: item for item in current.components}
    if earlier.keys() != later.keys():
        return False
    # Determine policy direction independently for every component.
    direction = {_compare_version(later[key].versions.minimum, earlier[key].versions.minimum) for key in earlier}
    if direction == {0}:
        return False
    if transition.kind is PolicyTransitionKind.UPGRADE:
        return all(value >= 0 for value in direction) and any(value > 0 for value in direction)
    return all(value <= 0 for value in direction) and any(value < 0 for value in direction)


def execute_after_dependency_preflight(
    policy: DependencyPolicy | None,
    observations: Iterable[ObservedDependency] | None,
    requirement: StageRequirement,
    *,
    now: int,
    action: Callable[[], object],
) -> object:
    """Run a supplied action only after the pure trust decision passes."""

    decision = evaluate_dependency_preflight(policy, observations, requirement, now=now)
    if decision.outcome is not DependencyDecisionOutcome.PASS:
        raise DependencyPolicyError(decision.reason)
    return action()


def render_dependency_decision(decision: DependencyDecision) -> str:
    """Render only stable public identifiers; no paths or raw command evidence."""

    if type(decision) is not DependencyDecision:
        return "dependency-gate=BLOCKED stage=unknown reason=invalid decision"
    return f"dependency-gate={decision.outcome.value} stage={decision.stage.value} reason={decision.reason}"


def _validate_observation(policy: DependencyPolicy, expected: ComponentPolicy, observed: ObservedDependency, now: int) -> str | None:
    if observed.policy_digest != policy.policy_digest:
        return "dependency provenance is bound to a different policy"
    if now - observed.observed_at > policy.freshness_seconds:
        return "dependency provenance is stale"
    if observed.observed_at > now:
        return "dependency provenance time is invalid"
    if (observed.identifier, observed.source_identity, observed.artifact_digest) != (expected.identifier, expected.source_identity, expected.artifact_digest):
        return "dependency identity does not match policy"
    if not expected.versions.contains(observed.version):
        return "dependency version is unsupported"
    return None


def _blocked(requirement: object, reason: str) -> DependencyDecision:
    stage = requirement.stage if type(requirement) is StageRequirement else DependencyStage.DISPATCH
    return DependencyDecision(DependencyDecisionOutcome.BLOCKED, stage, reason)


def _is_digest(value: object) -> bool:
    return type(value) is str and bool(_DIGEST.fullmatch(value))


def _safe_identifier(value: object) -> bool:
    return type(value) is str and bool(_IDENTIFIER.fullmatch(value))


def _is_version(value: object) -> bool:
    return type(value) is str and bool(_VERSION.fullmatch(value))


def _version_key(value: str) -> tuple[int, int, int]:
    matched = _VERSION.fullmatch(value)
    assert matched is not None
    return tuple(int(item) for item in matched.groups())  # type: ignore[return-value]


def _compare_version(left: str, right: str) -> int:
    return (_version_key(left) > _version_key(right)) - (_version_key(left) < _version_key(right))
