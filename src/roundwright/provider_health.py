"""Typed, credential-isolated Codex provider qualification.

This module is intentionally an adapter contract, not an SDK wrapper.  It
cannot dispatch a task: the only operation it can request is a bounded,
read-only capability qualification.  Provider display text, exception text,
raw payloads, credential locations, and secrets are not accepted as evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Protocol

from .configuration import Configuration, ProviderProfile
from .provider_recovery import ProviderRole


class ProviderHealthError(ValueError):
    """Raised when health evidence or a qualification request is unsafe."""


class CodexFailure(StrEnum):
    AUTH_MISSING = "auth-missing"
    AUTH_EXPIRED = "auth-expired"
    QUOTA_OR_RATE_LIMIT = "quota-or-rate-limit"
    MODEL_UNAVAILABLE = "model-unavailable"
    SDK_INCOMPATIBLE = "sdk-incompatible"
    SANDBOX_OR_APPROVAL_DENIED = "sandbox-or-approval-denied"
    TRANSPORT_OR_PROVIDER_OUTAGE = "transport-or-provider-outage"
    MALFORMED_RESPONSE = "malformed-response"
    UNKNOWN = "unknown"


class HealthState(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"


class ProbeKind(StrEnum):
    READ_ONLY_QUALIFICATION = "read-only-qualification"


_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CodexCapability:
    """One exact model/reasoning pair advertised by a runtime audit."""

    model: str
    reasoning_effort: str

    def __post_init__(self) -> None:
        if not _safe_identifier(self.model) or not _safe_identifier(self.reasoning_effort):
            raise ProviderHealthError("provider capability is invalid")


@dataclass(frozen=True)
class CodexRuntimeAudit:
    """Stable adapter evidence; it never contains environment or path data."""

    sdk_version: str
    runtime_version: str
    capabilities: tuple[CodexCapability, ...]

    def __post_init__(self) -> None:
        if not _SEMVER.fullmatch(self.sdk_version) or not _SEMVER.fullmatch(self.runtime_version):
            raise ProviderHealthError("provider runtime version is invalid")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities):
            raise ProviderHealthError("provider runtime capabilities are invalid")

    @property
    def fingerprint(self) -> str:
        return _digest({
            "sdk_version": self.sdk_version,
            "runtime_version": self.runtime_version,
            "capabilities": [(item.model, item.reasoning_effort) for item in self.capabilities],
        })

    def supports(self, profile: ProviderProfile) -> bool:
        return CodexCapability(profile.model, profile.reasoning_effort.value) in self.capabilities


@dataclass(frozen=True)
class CodexHealthContract:
    """The owner-approved exact runtime versions for one qualification run."""

    sdk_version: str
    runtime_version: str

    def __post_init__(self) -> None:
        if not _SEMVER.fullmatch(self.sdk_version) or not _SEMVER.fullmatch(self.runtime_version):
            raise ProviderHealthError("required provider runtime version is invalid")

    def accepts(self, audit: CodexRuntimeAudit) -> bool:
        return (audit.sdk_version, audit.runtime_version) == (self.sdk_version, self.runtime_version)


@dataclass(frozen=True)
class ReadOnlyQualification:
    """A content-free probe request that is incapable of carrying task work."""

    role: ProviderRole
    model: str
    reasoning_effort: str
    kind: ProbeKind = ProbeKind.READ_ONLY_QUALIFICATION

    def __post_init__(self) -> None:
        if not isinstance(self.role, ProviderRole) or self.kind is not ProbeKind.READ_ONLY_QUALIFICATION:
            raise ProviderHealthError("provider qualification request is invalid")
        if not _safe_identifier(self.model) or not _safe_identifier(self.reasoning_effort):
            raise ProviderHealthError("provider qualification request is invalid")


@dataclass(frozen=True)
class ProbeOutcome:
    """Typed probe result supplied by an adapter, without a provider payload."""

    available: bool
    failure: CodexFailure | None = None

    def __post_init__(self) -> None:
        if type(self.available) is not bool or (self.available != (self.failure is None)):
            raise ProviderHealthError("provider probe outcome is malformed")


class CodexAdapterError(Exception):
    """An adapter may classify an operational failure without exposing details."""

    def __init__(self, failure: CodexFailure):
        if not isinstance(failure, CodexFailure):
            raise ProviderHealthError("provider failure is invalid")
        self.failure = failure
        super().__init__(failure.value)


class CodexCredentialStore(Protocol):
    """Native store boundary.  It returns an opaque role channel, never a secret."""

    def open_role_channel(self, role: ProviderRole) -> "CodexRoleChannel": ...

    def credential_isolation(self, role: ProviderRole) -> "CredentialIsolationEvidence": ...


class CodexRoleChannel(Protocol):
    """Credentialless model-facing capability channel."""

    def audit_runtime(self) -> CodexRuntimeAudit: ...

    def qualify_read_only(self, request: ReadOnlyQualification) -> ProbeOutcome: ...


@dataclass(frozen=True)
class CredentialIsolationEvidence:
    """Static proof that only the native adapter boundary receives credentials."""

    role: ProviderRole
    model_session_can_read_secret: bool = False
    prompt_can_read_secret: bool = False
    artifact_can_read_secret: bool = False
    tool_can_read_secret: bool = False
    github_adapter_can_read_secret: bool = False
    registry_adapter_can_read_secret: bool = False
    unrelated_role_can_read_secret: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.role, ProviderRole) or any(
            value is not False
            for value in (
                self.model_session_can_read_secret, self.prompt_can_read_secret,
                self.artifact_can_read_secret, self.tool_can_read_secret,
                self.github_adapter_can_read_secret, self.registry_adapter_can_read_secret,
                self.unrelated_role_can_read_secret,
            )
        ):
            raise ProviderHealthError("provider credential isolation is not proven")


@dataclass(frozen=True)
class ProviderHealthObservation:
    """Immutable owner-safe health evidence with an explicit expiry boundary."""

    role: ProviderRole
    profile_identity: str
    runtime_fingerprint: str
    state: HealthState
    failure: CodexFailure | None
    observed_at: int
    fresh_until: int
    attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.role, ProviderRole) or not _DIGEST.fullmatch(self.profile_identity) or not _DIGEST.fullmatch(self.runtime_fingerprint):
            raise ProviderHealthError("provider health identity is invalid")
        if (self.state is HealthState.READY) != (self.failure is None):
            raise ProviderHealthError("provider health state is invalid")
        if type(self.observed_at) is not int or type(self.fresh_until) is not int or self.fresh_until <= self.observed_at:
            raise ProviderHealthError("provider health freshness is invalid")
        if type(self.attempts) is not int or not 1 <= self.attempts <= 3:
            raise ProviderHealthError("provider health retry count is invalid")

    def is_fresh_at(self, now: int) -> bool:
        return type(now) is int and self.observed_at <= now < self.fresh_until

    def evidence(self) -> dict[str, object]:
        """Return persistable evidence without raw responses, secrets, or paths."""

        return {
            "role": self.role.value,
            "profile_identity": self.profile_identity,
            "runtime_fingerprint": self.runtime_fingerprint,
            "state": self.state.value,
            "failure": None if self.failure is None else self.failure.value,
            "observed_at": self.observed_at,
            "fresh_until": self.fresh_until,
            "attempts": self.attempts,
        }

    @classmethod
    def from_evidence(cls, evidence: Mapping[str, object]) -> "ProviderHealthObservation":
        """Rehydrate only the complete, redacted record used by Shadow replay."""

        if type(evidence) is not dict or set(evidence) != {
            "role", "profile_identity", "runtime_fingerprint", "state", "failure",
            "observed_at", "fresh_until", "attempts",
        }:
            raise ProviderHealthError("provider health evidence is invalid")
        try:
            failure_value = evidence["failure"]
            return cls(
                ProviderRole(evidence["role"]),  # type: ignore[arg-type]
                evidence["profile_identity"],  # type: ignore[arg-type]
                evidence["runtime_fingerprint"],  # type: ignore[arg-type]
                HealthState(evidence["state"]),  # type: ignore[arg-type]
                None if failure_value is None else CodexFailure(failure_value),  # type: ignore[arg-type]
                evidence["observed_at"],  # type: ignore[arg-type]
                evidence["fresh_until"],  # type: ignore[arg-type]
                evidence["attempts"],  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProviderHealthError("provider health evidence is invalid") from error


@dataclass(frozen=True)
class ProviderQualificationReport:
    """Independent stage evidence for every configured Codex role/profile."""

    observations: tuple[ProviderHealthObservation, ...]

    def __post_init__(self) -> None:
        keys = [(item.role, item.profile_identity) for item in self.observations]
        if not self.observations or len(keys) != len(set(keys)):
            raise ProviderHealthError("provider qualification report is invalid")

    @property
    def ready(self) -> bool:
        return all(item.state is HealthState.READY for item in self.observations)

    def blocker_for(self, role: ProviderRole, profile: ProviderProfile) -> CodexFailure | None:
        profile_identity = profile_fingerprint(profile)
        for observation in self.observations:
            if (observation.role, observation.profile_identity) == (role, profile_identity):
                return observation.failure
        raise ProviderHealthError("configured profile was not qualified")


class ProviderHealthCache:
    """Process-local cache; it never serializes credentials or adapter payloads."""

    def __init__(self) -> None:
        self._observations: dict[tuple[ProviderRole, str], ProviderHealthObservation] = {}

    def get(self, role: ProviderRole, profile_identity: str, *, now: int) -> ProviderHealthObservation | None:
        observation = self._observations.get((role, profile_identity))
        return observation if observation is not None and observation.is_fresh_at(now) else None

    def put(self, observation: ProviderHealthObservation) -> None:
        self._observations[(observation.role, observation.profile_identity)] = observation


class CodexProviderHealth:
    """Qualifies a configured profile through a bounded, opaque adapter channel."""

    def __init__(self, credentials: CodexCredentialStore, contract: CodexHealthContract, *, cache: ProviderHealthCache | None = None) -> None:
        self._credentials = credentials
        self._contract = contract
        self._cache = ProviderHealthCache() if cache is None else cache

    def qualify(
        self,
        role: ProviderRole,
        profile: ProviderProfile,
        *,
        freshness_seconds: int,
        max_attempts: int = 2,
        force_refresh: bool = False,
        now: int | None = None,
    ) -> ProviderHealthObservation:
        """Return cached evidence or make at most three read-only probe attempts."""

        if not isinstance(role, ProviderRole) or type(freshness_seconds) is not int or freshness_seconds < 1:
            raise ProviderHealthError("provider health freshness boundary is invalid")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3 or type(force_refresh) is not bool:
            raise ProviderHealthError("provider health retry policy is invalid")
        observed_at = int(time.time()) if now is None else now
        if type(observed_at) is not int:
            raise ProviderHealthError("provider health clock is invalid")
        profile_identity = profile_fingerprint(profile)
        try:
            self.credential_isolation(role)
        except ProviderHealthError:
            return self._record(role, profile_identity, _unknown_runtime_fingerprint(), CodexFailure.UNKNOWN, observed_at, freshness_seconds, 1)
        if not force_refresh:
            cached = self._cache.get(role, profile_identity, now=observed_at)
            if cached is not None:
                return cached
        return self._refresh(role, profile, profile_identity, observed_at, freshness_seconds, max_attempts)

    def credential_isolation(self, role: ProviderRole) -> CredentialIsolationEvidence:
        """Require the native store's explicit no-secret projection for this role."""

        try:
            evidence = self._credentials.credential_isolation(role)
        except Exception as error:
            raise ProviderHealthError("provider credential isolation is not proven") from error
        if type(evidence) is not CredentialIsolationEvidence or evidence.role is not role:
            raise ProviderHealthError("provider credential isolation is not proven")
        return evidence

    def qualify_configuration(
        self,
        configuration: Configuration,
        *,
        freshness_seconds: int,
        max_attempts: int = 2,
        force_refresh: bool = False,
        now: int | None = None,
    ) -> ProviderQualificationReport:
        """Qualify Worker and each Supervisor profile independently before dispatch.

        This is intentionally separate from any lifecycle entrypoint: an
        unavailable Supervisor profile does not invalidate a healthy Worker,
        and it cannot consume a review round.
        """

        if type(configuration) is not Configuration:
            raise ProviderHealthError("provider configuration is invalid")
        selected = ((ProviderRole.WORKER, configuration.worker.value),) + tuple(
            (ProviderRole.SUPERVISOR, profile) for profile in configuration.supervisor_attempt_profiles.value
        )
        return ProviderQualificationReport(tuple(
            self.qualify(
                role, profile, freshness_seconds=freshness_seconds,
                max_attempts=max_attempts, force_refresh=force_refresh, now=now,
            )
            for role, profile in selected
        ))

    def _refresh(self, role: ProviderRole, profile: ProviderProfile, profile_identity: str, now: int, freshness_seconds: int, max_attempts: int) -> ProviderHealthObservation:
        try:
            channel = self._credentials.open_role_channel(role)
            audit = channel.audit_runtime()
        except CodexAdapterError as error:
            return self._record(role, profile_identity, _unknown_runtime_fingerprint(), error.failure, now, freshness_seconds, 1)
        except Exception:
            return self._record(role, profile_identity, _unknown_runtime_fingerprint(), CodexFailure.UNKNOWN, now, freshness_seconds, 1)
        if type(audit) is not CodexRuntimeAudit:
            return self._record(role, profile_identity, _unknown_runtime_fingerprint(), CodexFailure.MALFORMED_RESPONSE, now, freshness_seconds, 1)
        if not self._contract.accepts(audit):
            return self._record(role, profile_identity, audit.fingerprint, CodexFailure.SDK_INCOMPATIBLE, now, freshness_seconds, 1)
        if not audit.supports(profile):
            return self._record(role, profile_identity, audit.fingerprint, CodexFailure.MODEL_UNAVAILABLE, now, freshness_seconds, 1)
        request = ReadOnlyQualification(role, profile.model, profile.reasoning_effort.value)
        failure: CodexFailure | None = None
        attempts = 0
        for attempts in range(1, max_attempts + 1):
            try:
                outcome = channel.qualify_read_only(request)
                if type(outcome) is not ProbeOutcome:
                    failure = CodexFailure.MALFORMED_RESPONSE
                elif outcome.available:
                    return self._record(role, profile_identity, audit.fingerprint, None, now, freshness_seconds, attempts)
                else:
                    failure = outcome.failure
            except CodexAdapterError as error:
                failure = error.failure
            except Exception:
                failure = CodexFailure.UNKNOWN
            if failure not in {CodexFailure.QUOTA_OR_RATE_LIMIT, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE}:
                break
        return self._record(role, profile_identity, audit.fingerprint, failure or CodexFailure.UNKNOWN, now, freshness_seconds, attempts)

    def _record(self, role: ProviderRole, profile_identity: str, runtime_fingerprint: str, failure: CodexFailure | None, now: int, freshness_seconds: int, attempts: int) -> ProviderHealthObservation:
        observation = ProviderHealthObservation(
            role, profile_identity, runtime_fingerprint,
            HealthState.READY if failure is None else HealthState.BLOCKED,
            failure, now, now + freshness_seconds, attempts,
        )
        self._cache.put(observation)
        return observation


def profile_fingerprint(profile: ProviderProfile) -> str:
    """Bind health to one exact configured profile without paths or secrets."""

    if type(profile) is not ProviderProfile:
        raise ProviderHealthError("provider profile is invalid")
    payload = {"model": profile.model, "reasoning_effort": profile.reasoning_effort.value}
    if profile.name is not None:
        payload["name"] = profile.name
    return _digest(payload)


def render_health_diagnostic(observation: ProviderHealthObservation) -> str:
    """Render a stable, owner-safe diagnostic; no provider text is ever included."""

    if type(observation) is not ProviderHealthObservation:
        raise ProviderHealthError("provider health observation is invalid")
    detail = "ready" if observation.failure is None else {
        CodexFailure.AUTH_MISSING: "authentication required",
        CodexFailure.AUTH_EXPIRED: "authentication renewal required",
        CodexFailure.QUOTA_OR_RATE_LIMIT: "provider capacity temporarily unavailable",
        CodexFailure.MODEL_UNAVAILABLE: "configured model capability unavailable",
        CodexFailure.SDK_INCOMPATIBLE: "configured runtime version incompatible",
        CodexFailure.SANDBOX_OR_APPROVAL_DENIED: "provider qualification denied",
        CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE: "provider transport temporarily unavailable",
        CodexFailure.MALFORMED_RESPONSE: "provider qualification response invalid",
        CodexFailure.UNKNOWN: "provider qualification unavailable",
    }[observation.failure]
    return f"codex provider health\nrole: {observation.role.value}\nstate: {observation.state.value}\ndetail: {detail}\nresult: {'ready' if observation.state is HealthState.READY else 'blocked'}\n"


def _safe_identifier(value: object) -> bool:
    return type(value) is str and bool(value) and len(value) <= 128 and all(character.isalnum() or character in "._-" for character in value)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _unknown_runtime_fingerprint() -> str:
    return _digest({"runtime": "unavailable"})
