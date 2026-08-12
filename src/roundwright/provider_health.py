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
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping, Protocol

from .configuration import Configuration, ProviderProfile, ReasoningEffort
from .dependency_policy import CandidateBinding, DependencyExecutionControl, DependencyPolicyError, DependencyStage
from .runtime_binding import RuntimeBinding
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
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_PUBLIC_MODELS = frozenset({"gpt-5.6-terra", "gpt-5.6-sol"})
_PUBLIC_REASONING_EFFORTS = frozenset(item.value for item in ReasoningEffort)


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
        if type(self.capabilities) is not tuple or not self.capabilities or any(type(item) is not CodexCapability for item in self.capabilities) or len(set(self.capabilities)) != len(self.capabilities):
            raise ProviderHealthError("provider runtime capabilities are invalid")

    @property
    def fingerprint(self) -> str:
        return _digest({
            "sdk_version": self.sdk_version,
            "runtime_version": self.runtime_version,
            "capabilities": [(item.model, item.reasoning_effort) for item in self.capabilities],
        })

    def supports(self, profile: ProviderProfile) -> bool:
        if type(profile) is not ProviderProfile:
            raise ProviderHealthError("provider profile is invalid")
        return CodexCapability(profile.model, profile.reasoning_effort.value) in self.capabilities


@dataclass(frozen=True)
class CodexHealthContract:
    """The owner-approved exact runtime versions for one qualification run."""

    sdk_version: str
    runtime_version: str
    contract_commit: str

    def __post_init__(self) -> None:
        if not _SEMVER.fullmatch(self.sdk_version) or not _SEMVER.fullmatch(self.runtime_version) or not _commit(self.contract_commit):
            raise ProviderHealthError("required provider runtime version is invalid")

    def accepts(self, audit: CodexRuntimeAudit) -> bool:
        if type(audit) is not CodexRuntimeAudit:
            return False
        return (audit.sdk_version, audit.runtime_version) == (self.sdk_version, self.runtime_version)

    @property
    def fingerprint(self) -> str:
        """Immutable identity for cache, evidence, and replay binding."""

        return _digest({"sdk_version": self.sdk_version, "runtime_version": self.runtime_version, "contract_commit": self.contract_commit})


@dataclass(frozen=True)
class ProviderQualificationControl:
    """Selection-time sealed dependency evidence required before provider qualification."""

    binding: CandidateBinding
    dependency_control: DependencyExecutionControl
    now: int

    def __post_init__(self) -> None:
        if type(self.binding) is not CandidateBinding or type(self.dependency_control) is not DependencyExecutionControl or type(self.now) is not int or self.now < 0:
            raise ProviderHealthError("provider qualification control is invalid")
        try:
            self.dependency_control.require(self.binding, DependencyStage.PROVIDER_QUALIFICATION, now=self.now)
        except DependencyPolicyError as error:
            raise ProviderHealthError("provider qualification preflight blocked execution") from error


@dataclass(frozen=True)
class ProviderHealthAuditIdentity:
    """Exact, redacted audit/profile identity for later receipt binding."""

    audit: CodexRuntimeAudit
    profile: ProviderProfile = field(compare=False)
    profile_identity_value: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.audit) is not CodexRuntimeAudit or type(self.profile) is not ProviderProfile
            or (self.profile_identity_value != "" and (type(self.profile_identity_value) is not str or not _DIGEST.fullmatch(self.profile_identity_value)))
            or self.profile.model not in _PUBLIC_MODELS or self.profile.reasoning_effort.value not in _PUBLIC_REASONING_EFFORTS
            or any(item.model not in _PUBLIC_MODELS or item.reasoning_effort not in _PUBLIC_REASONING_EFFORTS for item in self.audit.capabilities)
            or not self.audit.supports(self.profile)
        ):
            raise ProviderHealthError("provider audit identity is invalid")

    @property
    def profile_identity(self) -> str:
        return self.profile_identity_value or profile_fingerprint(self.profile)

    @property
    def runtime_fingerprint(self) -> str:
        return self.audit.fingerprint

    def evidence(self) -> dict[str, object]:
        return {"sdk_version": self.audit.sdk_version, "runtime_version": self.audit.runtime_version,
                "capabilities": tuple((item.model, item.reasoning_effort) for item in self.audit.capabilities),
                "model": self.profile.model, "reasoning_effort": self.profile.reasoning_effort.value,
                "profile_identity": self.profile_identity,
                "runtime_fingerprint": self.runtime_fingerprint}

    @classmethod
    def from_evidence(cls, evidence: Mapping[str, object]) -> "ProviderHealthAuditIdentity":
        keys = {"sdk_version", "runtime_version", "capabilities", "model", "reasoning_effort", "profile_identity", "runtime_fingerprint"}
        if type(evidence) is not dict or set(evidence) != keys or type(evidence["capabilities"]) is not tuple:
            raise ProviderHealthError("provider audit identity evidence is invalid")
        try:
            capabilities = tuple(CodexCapability(model, effort) for model, effort in evidence["capabilities"])
            identity = cls(CodexRuntimeAudit(evidence["sdk_version"], evidence["runtime_version"], capabilities), ProviderProfile(evidence["model"], ReasoningEffort(evidence["reasoning_effort"])), evidence["profile_identity"])
        except (TypeError, ValueError) as error:
            raise ProviderHealthError("provider audit identity evidence is invalid") from error
        if type(evidence["profile_identity"]) is not str or type(evidence["runtime_fingerprint"]) is not str or (identity.profile_identity, identity.runtime_fingerprint) != (evidence["profile_identity"], evidence["runtime_fingerprint"]):
            raise ProviderHealthError("provider audit identity evidence is invalid")
        return identity


@dataclass(frozen=True)
class RoleBoundCredentialIdentity:
    """Opaque native-store channel identity; it never contains a credential."""

    store_identity: str
    role: ProviderRole
    channel_identity: str
    denied_roles: tuple[ProviderRole, ...]

    def __post_init__(self) -> None:
        expected = tuple(item for item in ProviderRole if item is not self.role)
        if type(self.store_identity) is not str or not _DIGEST.fullmatch(self.store_identity) or type(self.role) is not ProviderRole or type(self.channel_identity) is not str or not _DIGEST.fullmatch(self.channel_identity) or type(self.denied_roles) is not tuple or any(type(item) is not ProviderRole for item in self.denied_roles) or self.denied_roles != expected:
            raise ProviderHealthError("role-bound credential identity is invalid")

    def evidence(self) -> dict[str, object]:
        return {"store_identity": self.store_identity, "role": self.role.value, "channel_identity": self.channel_identity, "denied_roles": tuple(item.value for item in self.denied_roles)}

    @classmethod
    def from_evidence(cls, evidence: Mapping[str, object]) -> "RoleBoundCredentialIdentity":
        if type(evidence) is not dict or set(evidence) != {"store_identity", "role", "channel_identity", "denied_roles"} or type(evidence["denied_roles"]) is not tuple or any(type(item) is not str for item in evidence["denied_roles"]):
            raise ProviderHealthError("role-bound credential identity evidence is invalid")
        try:
            return cls(evidence["store_identity"], ProviderRole(evidence["role"]), evidence["channel_identity"], tuple(ProviderRole(item) for item in evidence["denied_roles"]))
        except (TypeError, ValueError) as error:
            raise ProviderHealthError("role-bound credential identity evidence is invalid") from error

    def authorize_channel(self, role: ProviderRole, store_identity: str, channel_identity: str) -> None:
        if type(role) is not ProviderRole or type(store_identity) is not str or type(channel_identity) is not str or (role, store_identity, channel_identity) != (self.role, self.store_identity, self.channel_identity):
            raise ProviderHealthError("role-bound credential channel is denied")


@dataclass(frozen=True)
class ProviderHealthReceipt:
    """Canonical, redacted authorization evidence for one dispatchable profile."""

    contract_commit: str
    candidate_sha: str | None
    case_id: str
    selection_ordinal: int
    configuration: RuntimeBinding
    role: ProviderRole
    profile_identity: str
    observation: "ProviderHealthObservation"
    audit_identity: ProviderHealthAuditIdentity
    schema: str = "roundwright-provider-health/v1"
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if (
            self.schema != "roundwright-provider-health/v1" or not _commit(self.contract_commit)
            or (self.candidate_sha is not None and not _commit(self.candidate_sha))
            or not _safe_identifier(self.case_id) or type(self.selection_ordinal) is not int or self.selection_ordinal < 0 or type(self.configuration) is not RuntimeBinding
            or type(self.role) is not ProviderRole or not _DIGEST.fullmatch(self.profile_identity)
            or type(self.observation) is not ProviderHealthObservation
            or type(self.audit_identity) is not ProviderHealthAuditIdentity
            or (self.observation.role, self.observation.profile_identity) != (self.role, self.profile_identity)
            or self.audit_identity.profile_identity != self.profile_identity
            or self.audit_identity.runtime_fingerprint != self.observation.runtime_fingerprint
            or CodexHealthContract(self.audit_identity.audit.sdk_version, self.audit_identity.audit.runtime_version, self.contract_commit).fingerprint != self.observation.health_contract_identity
        ):
            raise ProviderHealthError("provider health receipt is invalid")
        payload = self._payload()
        digest = _digest(payload)
        if self.receipt_digest and self.receipt_digest != digest:
            raise ProviderHealthError("provider health receipt digest is invalid")
        object.__setattr__(self, "receipt_digest", digest)

    def _payload(self) -> dict[str, object]:
        return {"schema": self.schema, "contract_commit": self.contract_commit, "candidate_sha": self.candidate_sha,
                "case_id": self.case_id, "selection_ordinal": self.selection_ordinal, "configuration": self.configuration.complete_columns(), "role": self.role.value,
                "profile_identity": self.profile_identity, "observation": self.observation.evidence(), "audit_identity": self.audit_identity.evidence()}

    def evidence(self) -> dict[str, object]:
        """Canonical redacted receipt projection suitable for Shadow ingestion."""
        return {**self._payload(), "receipt_digest": self.receipt_digest}

    @classmethod
    def from_evidence(cls, evidence: Mapping[str, object]) -> "ProviderHealthReceipt":
        required = {"schema", "contract_commit", "candidate_sha", "case_id", "selection_ordinal", "configuration", "role", "profile_identity", "observation", "audit_identity", "receipt_digest"}
        if type(evidence) is not dict or set(evidence) != required or type(evidence["configuration"]) is not tuple or type(evidence["observation"]) is not dict or type(evidence["audit_identity"]) is not dict:
            raise ProviderHealthError("provider health receipt evidence is invalid")
        values = evidence["configuration"]
        try:
            if len(values) != 9 or type(values[3]) is not str:
                raise ValueError
            supervisor_profiles = json.loads(values[3])
            if type(supervisor_profiles) is not list or not supervisor_profiles or any(type(item) is not str for item in supervisor_profiles) or json.dumps(supervisor_profiles, separators=(",", ":")) != values[3]:
                raise ValueError
            binding = RuntimeBinding(values[0], values[1], values[2], tuple(supervisor_profiles), *values[4:])
            observation = ProviderHealthObservation.from_evidence(evidence["observation"])
            return cls(evidence["contract_commit"], evidence["candidate_sha"], evidence["case_id"], evidence["selection_ordinal"], binding, ProviderRole(evidence["role"]), evidence["profile_identity"], observation, ProviderHealthAuditIdentity.from_evidence(evidence["audit_identity"]), evidence["schema"], evidence["receipt_digest"])
        except (TypeError, ValueError) as error:
            raise ProviderHealthError("provider health receipt evidence is invalid") from error

    def authorize(self, binding: RuntimeBinding, role: ProviderRole, profile_identity: str, *, contract_commit: str, candidate_sha: str | None, case_id: str, now: int) -> None:
        try:
            self.configuration.require_matches(binding)
            matching_binding = True
        except Exception:
            matching_binding = False
        if (
            type(binding) is not RuntimeBinding or type(role) is not ProviderRole or not _commit(contract_commit)
            or (candidate_sha is not None and not _commit(candidate_sha)) or not _safe_identifier(case_id) or type(now) is not int
            or (self.contract_commit, self.candidate_sha, self.case_id, self.role, self.profile_identity) != (contract_commit, candidate_sha, case_id, role, profile_identity)
            or not matching_binding or self.observation.state is not HealthState.READY or not self.observation.is_fresh_at(now)
        ):
            raise ProviderHealthError("provider health receipt does not authorize dispatch")


@dataclass(frozen=True)
class ReadOnlyQualification:
    """A content-free probe request that is incapable of carrying task work."""

    role: ProviderRole
    model: str
    reasoning_effort: str
    kind: ProbeKind = ProbeKind.READ_ONLY_QUALIFICATION

    def __post_init__(self) -> None:
        if type(self.role) is not ProviderRole or type(self.kind) is not ProbeKind or self.kind is not ProbeKind.READ_ONLY_QUALIFICATION:
            raise ProviderHealthError("provider qualification request is invalid")
        if not _safe_identifier(self.model) or not _safe_identifier(self.reasoning_effort):
            raise ProviderHealthError("provider qualification request is invalid")


@dataclass(frozen=True)
class ProbeOutcome:
    """Typed probe result supplied by an adapter, without a provider payload."""

    available: bool
    failure: CodexFailure | None = None

    def __post_init__(self) -> None:
        if type(self.available) is not bool or (self.failure is not None and type(self.failure) is not CodexFailure) or (self.available != (self.failure is None)):
            raise ProviderHealthError("provider probe outcome is malformed")


class CodexAdapterError(Exception):
    """An adapter may classify an operational failure without exposing details."""

    def __init__(self, failure: CodexFailure):
        if type(failure) is not CodexFailure:
            raise ProviderHealthError("provider failure is invalid")
        self.failure = failure
        super().__init__(failure.value)


class CodexCredentialStore(Protocol):
    """Native store boundary.  It returns an opaque role channel, never a secret."""

    def open_role_channel(self, role: ProviderRole) -> "CodexRoleChannel": ...
    def store_identity(self) -> str: ...

    def credential_isolation(self, role: ProviderRole) -> "CredentialIsolationEvidence": ...


class CodexRoleChannel(Protocol):
    """Credentialless model-facing capability channel."""

    def credential_identity(self) -> RoleBoundCredentialIdentity: ...
    def audit_runtime(self) -> CodexRuntimeAudit: ...
    def qualify_read_only(self, request: ReadOnlyQualification) -> ProbeOutcome: ...


class NativeCodexChannelBackend(Protocol):
    def audit_runtime(self) -> CodexRuntimeAudit: ...
    def qualify_read_only(self, request: ReadOnlyQualification) -> ProbeOutcome: ...


class RoleBoundCodexChannel:
    """Credentialless façade over one already-resolved native role channel."""
    __slots__ = ("_identity", "_backend")
    def __init__(self, identity: RoleBoundCredentialIdentity, backend: NativeCodexChannelBackend) -> None:
        if type(identity) is not RoleBoundCredentialIdentity:
            raise ProviderHealthError("native channel identity is invalid")
        self._identity, self._backend = identity, backend
    def credential_identity(self) -> RoleBoundCredentialIdentity: return self._identity
    def audit_runtime(self) -> CodexRuntimeAudit: return self._backend.audit_runtime()
    def qualify_read_only(self, request: ReadOnlyQualification) -> ProbeOutcome:
        if type(request) is not ReadOnlyQualification or request.role is not self._identity.role:
            raise ProviderHealthError("native credential role is invalid")
        return self._backend.qualify_read_only(request)


class RoleBoundCodexCredentialStore:
    """Injected native-channel registry; it never discovers or exposes secrets."""
    __slots__ = ("_store_identity", "_channels")
    def __init__(self, store_identity: str, channels: dict[ProviderRole, tuple[str, NativeCodexChannelBackend]]) -> None:
        if type(store_identity) is not str or not _DIGEST.fullmatch(store_identity) or type(channels) is not dict or set(channels) != set(ProviderRole):
            raise ProviderHealthError("native credential store is invalid")
        built = {}
        used_channel_identities = set()
        used_backends = set()
        for role in ProviderRole:
            entry = channels[role]
            if type(entry) is not tuple or len(entry) != 2:
                raise ProviderHealthError("native credential channel is invalid")
            channel_identity, backend = entry
            if type(channel_identity) is not str or not _DIGEST.fullmatch(channel_identity) or channel_identity in used_channel_identities or id(backend) in used_backends:
                raise ProviderHealthError("native credential channel is invalid")
            used_channel_identities.add(channel_identity)
            used_backends.add(id(backend))
            built[role] = RoleBoundCodexChannel(RoleBoundCredentialIdentity(store_identity, role, channel_identity, tuple(item for item in ProviderRole if item is not role)), backend)
        self._store_identity, self._channels = store_identity, built
    def store_identity(self) -> str: return self._store_identity
    def open_role_channel(self, role: ProviderRole) -> RoleBoundCodexChannel:
        if type(role) is not ProviderRole: raise ProviderHealthError("native credential role is invalid")
        return self._channels[role]
    def credential_isolation(self, role: ProviderRole) -> "CredentialIsolationEvidence":
        return CredentialIsolationEvidence(role, self.open_role_channel(role).credential_identity())

@dataclass(frozen=True)
class CredentialIsolationEvidence:
    """Static proof that only the native adapter boundary receives credentials."""

    role: ProviderRole
    credential_identity: RoleBoundCredentialIdentity
    model_session_can_read_secret: bool = False
    prompt_can_read_secret: bool = False
    artifact_can_read_secret: bool = False
    tool_can_read_secret: bool = False
    github_adapter_can_read_secret: bool = False
    registry_adapter_can_read_secret: bool = False
    unrelated_role_can_read_secret: bool = False

    def __post_init__(self) -> None:
        if type(self.role) is not ProviderRole or type(self.credential_identity) is not RoleBoundCredentialIdentity or self.credential_identity.role is not self.role or any(
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
    health_contract_identity: str
    runtime_fingerprint: str
    state: HealthState
    failure: CodexFailure | None
    observed_at: int
    fresh_until: int
    attempts: int

    def __post_init__(self) -> None:
        if (
            type(self.role) is not ProviderRole
            or not _DIGEST.fullmatch(self.profile_identity)
            or not _DIGEST.fullmatch(self.health_contract_identity)
            or not _DIGEST.fullmatch(self.runtime_fingerprint)
        ):
            raise ProviderHealthError("provider health identity is invalid")
        if type(self.state) is not HealthState or (self.failure is not None and type(self.failure) is not CodexFailure) or (self.state is HealthState.READY) != (self.failure is None):
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
            "health_contract_identity": self.health_contract_identity,
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
            "role", "profile_identity", "health_contract_identity", "runtime_fingerprint", "state", "failure",
            "observed_at", "fresh_until", "attempts",
        }:
            raise ProviderHealthError("provider health evidence is invalid")
        try:
            failure_value = evidence["failure"]
            return cls(
                ProviderRole(evidence["role"]),  # type: ignore[arg-type]
                evidence["profile_identity"],  # type: ignore[arg-type]
                evidence["health_contract_identity"],  # type: ignore[arg-type]
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

    health_contract_identity: str
    configuration: RuntimeBinding
    selections: tuple[tuple[int, ProviderRole, str], ...]
    observations: tuple[ProviderHealthObservation, ...]

    def __post_init__(self) -> None:
        if type(self.selections) is not tuple or any(type(item) is not tuple or len(item) != 3 for item in self.selections):
            raise ProviderHealthError("provider qualification report is invalid")
        expected = required_provider_selections(self.configuration)
        keys = [(item.role, item.profile_identity) for item in self.observations]
        selected = [(role, profile) for _, role, profile in self.selections]
        if (
            not _DIGEST.fullmatch(self.health_contract_identity)
            or type(self.configuration) is not RuntimeBinding
            or not self.observations
            or any(type(ordinal) is not int or ordinal != index or type(role) is not ProviderRole or not _DIGEST.fullmatch(profile) for index, (ordinal, role, profile) in enumerate(self.selections))
            or self.selections != expected
            or len(selected) != len(self.observations)
            or keys != selected
            or any(item.health_contract_identity != self.health_contract_identity for item in self.observations)
        ):
            raise ProviderHealthError("provider qualification report is invalid")

    @property
    def ready(self) -> bool:
        """An unbound freshness check is never dispatch-ready; use ``ready_at``."""

        return False

    def ready_at(self, now: int) -> bool:
        """Return ready only when all exact-contract observations remain fresh."""

        if type(now) is not int:
            raise ProviderHealthError("provider health clock is invalid")
        return all(item.state is HealthState.READY and item.is_fresh_at(now) for item in self.observations)

    def blocker_for(self, role: ProviderRole, profile: ProviderProfile, *, now: int, ordinal: int | None = None) -> CodexFailure | None:
        """Return a matching blocker, treating stale evidence as an exact-stage block."""

        if type(now) is not int:
            raise ProviderHealthError("provider health clock is invalid")
        if type(role) is not ProviderRole or type(profile) is not ProviderProfile or (ordinal is not None and type(ordinal) is not int):
            raise ProviderHealthError("configured profile was not qualified")
        profile_identity = profile_fingerprint(profile)
        matches = [(index, observation) for index, observation in enumerate(self.observations) if (observation.role, observation.profile_identity) == (role, profile_identity)]
        if ordinal is not None:
            matches = [(index, observation) for index, observation in matches if index == ordinal]
        if len(matches) == 1:
            observation = matches[0][1]
            return CodexFailure.UNKNOWN if not observation.is_fresh_at(now) else observation.failure
        raise ProviderHealthError("configured profile was not qualified")


def required_provider_selections(binding: RuntimeBinding) -> tuple[tuple[int, ProviderRole, str], ...]:
    """Return every dispatchable role/profile in deterministic dispatch order."""

    if type(binding) is not RuntimeBinding:
        raise ProviderHealthError("provider configuration is invalid")
    values = (
        (ProviderRole.PLANNING, binding.worker_profile_identity),
        (ProviderRole.WORKER, binding.worker_profile_identity),
        *((ProviderRole.SUPERVISOR, profile) for profile in binding.supervisor_profile_identities),
    )
    return tuple((ordinal, role, profile_identity) for ordinal, (role, profile_identity) in enumerate(values))


class ProviderHealthCache:
    """Process-local cache; it never serializes credentials or adapter payloads."""

    def __init__(self) -> None:
        self._observations: dict[tuple[ProviderRole, str, str], ProviderHealthObservation] = {}

    def get(self, role: ProviderRole, profile_identity: str, health_contract_identity: str, *, now: int) -> ProviderHealthObservation | None:
        if type(role) is not ProviderRole or not _DIGEST.fullmatch(profile_identity) or not _DIGEST.fullmatch(health_contract_identity) or type(now) is not int:
            raise ProviderHealthError("provider health cache key is invalid")
        observation = self._observations.get((role, profile_identity, health_contract_identity))
        return observation if observation is not None and observation.is_fresh_at(now) else None

    def put(self, observation: ProviderHealthObservation) -> None:
        if type(observation) is not ProviderHealthObservation:
            raise ProviderHealthError("provider health observation is invalid")
        self._observations[(observation.role, observation.profile_identity, observation.health_contract_identity)] = observation


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
        binding: CandidateBinding,
        control: ProviderQualificationControl,
        freshness_seconds: int,
        max_attempts: int = 2,
        force_refresh: bool = False,
        now: int,
    ) -> ProviderHealthObservation:
        """Return cached evidence or make at most three read-only probe attempts."""

        _authorize_qualification_control(binding, control, now)
        if type(role) is not ProviderRole or type(freshness_seconds) is not int or freshness_seconds < 1:
            raise ProviderHealthError("provider health freshness boundary is invalid")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3 or type(force_refresh) is not bool:
            raise ProviderHealthError("provider health retry policy is invalid")
        observed_at = now
        profile_identity = profile_fingerprint(profile)
        contract_identity = self._contract.fingerprint
        try:
            isolation = self.credential_isolation(role, binding=binding, control=control, now=now)
        except CodexAdapterError as error:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), error.failure, observed_at, freshness_seconds, 1)
        except ProviderHealthError:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), CodexFailure.MALFORMED_RESPONSE, observed_at, freshness_seconds, 1)
        if not force_refresh:
            cached = self._cache.get(role, profile_identity, contract_identity, now=observed_at)
            if cached is not None:
                return cached
        return self._refresh(role, profile, profile_identity, contract_identity, isolation, observed_at, freshness_seconds, max_attempts, binding, control)

    def credential_isolation(
        self, role: ProviderRole, *, binding: CandidateBinding, control: ProviderQualificationControl, now: int,
    ) -> CredentialIsolationEvidence:
        """Require the native store's explicit no-secret projection for this role."""

        _authorize_qualification_control(binding, control, now)
        try:
            store_identity = self._credentials.store_identity()
            evidence = self._credentials.credential_isolation(role)
        except CodexAdapterError:
            raise
        except Exception as error:
            raise ProviderHealthError("provider credential isolation is not proven") from error
        if type(store_identity) is not str or not _DIGEST.fullmatch(store_identity) or type(evidence) is not CredentialIsolationEvidence or evidence.role is not role:
            raise ProviderHealthError("provider credential isolation is not proven")
        try:
            evidence.credential_identity.authorize_channel(role, store_identity, evidence.credential_identity.channel_identity)
        except Exception as error:
            raise ProviderHealthError("provider credential isolation is not proven") from error
        return evidence

    def audit_runtime(
        self, role: ProviderRole, *, binding: CandidateBinding, control: ProviderQualificationControl, now: int,
    ) -> CodexRuntimeAudit:
        """Read one runtime audit only under exact qualification authority."""

        _authorize_qualification_control(binding, control, now)
        isolation = self.credential_isolation(role, binding=binding, control=control, now=now)
        try:
            channel = self._credentials.open_role_channel(role)
            channel_identity = channel.credential_identity()
            if type(channel_identity) is not RoleBoundCredentialIdentity:
                raise ProviderHealthError("provider credential channel is invalid")
            channel_identity.authorize_channel(role, isolation.credential_identity.store_identity, channel_identity.channel_identity)
            if channel_identity != isolation.credential_identity:
                raise ProviderHealthError("provider credential channel is invalid")
            audit = _audit_runtime_under_control(channel, binding, control, now)
        except CodexAdapterError:
            raise
        except Exception as error:
            raise ProviderHealthError("provider runtime audit is not proven") from error
        if type(audit) is not CodexRuntimeAudit:
            raise ProviderHealthError("provider runtime audit is not proven")
        return audit

    def qualify_configuration(
        self,
        configuration: Configuration,
        *,
        binding: CandidateBinding,
        control: ProviderQualificationControl,
        freshness_seconds: int,
        max_attempts: int = 2,
        force_refresh: bool = False,
        now: int,
    ) -> ProviderQualificationReport:
        """Qualify Worker and each Supervisor profile independently before dispatch.

        This is intentionally separate from any lifecycle entrypoint: an
        unavailable Supervisor profile does not invalidate a healthy Worker,
        and it cannot consume a review round.
        """

        _authorize_qualification_control(binding, control, now)
        if type(configuration) is not Configuration:
            raise ProviderHealthError("provider configuration is invalid")
        pin = configuration.pin().runtime_binding()
        profiles = (configuration.worker.value, configuration.worker.value, *configuration.supervisor_attempt_profiles.value)
        selected = tuple((role, profile) for (_, role, _), profile in zip(required_provider_selections(pin), profiles, strict=True))
        return ProviderQualificationReport(self._contract.fingerprint, pin, tuple(
            (ordinal, role, profile_fingerprint(profile)) for ordinal, (role, profile) in enumerate(selected)
        ), tuple(
            self.qualify(
                role, profile, binding=binding, control=control, freshness_seconds=freshness_seconds,
                max_attempts=max_attempts, force_refresh=force_refresh, now=now,
            )
            for role, profile in selected
        ))

    def _refresh(self, role: ProviderRole, profile: ProviderProfile, profile_identity: str, contract_identity: str, isolation: CredentialIsolationEvidence, now: int, freshness_seconds: int, max_attempts: int, binding: CandidateBinding, control: ProviderQualificationControl) -> ProviderHealthObservation:
        _authorize_qualification_control(binding, control, now)
        try:
            channel = self._credentials.open_role_channel(role)
            channel_identity = channel.credential_identity()
            if type(channel_identity) is not RoleBoundCredentialIdentity:
                raise ProviderHealthError("provider credential channel is invalid")
            channel_identity.authorize_channel(role, isolation.credential_identity.store_identity, channel_identity.channel_identity)
            if channel_identity != isolation.credential_identity:
                raise ProviderHealthError("provider credential channel is invalid")
        except CodexAdapterError as error:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), error.failure, now, freshness_seconds, 1)
        except Exception:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), CodexFailure.MALFORMED_RESPONSE, now, freshness_seconds, 1)
        try:
            audit = _audit_runtime_under_control(channel, binding, control, now)
        except CodexAdapterError as error:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), error.failure, now, freshness_seconds, 1)
        except Exception:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), CodexFailure.UNKNOWN, now, freshness_seconds, 1)
        if type(audit) is not CodexRuntimeAudit:
            return self._record(role, profile_identity, contract_identity, _unknown_runtime_fingerprint(), CodexFailure.MALFORMED_RESPONSE, now, freshness_seconds, 1)
        if not self._contract.accepts(audit):
            return self._record(role, profile_identity, contract_identity, audit.fingerprint, CodexFailure.SDK_INCOMPATIBLE, now, freshness_seconds, 1)
        if not audit.supports(profile):
            return self._record(role, profile_identity, contract_identity, audit.fingerprint, CodexFailure.MODEL_UNAVAILABLE, now, freshness_seconds, 1)
        request = ReadOnlyQualification(role, profile.model, profile.reasoning_effort.value)
        failure: CodexFailure | None = None
        attempts = 0
        for attempts in range(1, max_attempts + 1):
            try:
                outcome = channel.qualify_read_only(request)
                if type(outcome) is not ProbeOutcome:
                    failure = CodexFailure.MALFORMED_RESPONSE
                elif outcome.available:
                    return self._record(role, profile_identity, contract_identity, audit.fingerprint, None, now, freshness_seconds, attempts)
                else:
                    failure = outcome.failure
            except CodexAdapterError as error:
                failure = error.failure
            except Exception:
                failure = CodexFailure.UNKNOWN
            if failure not in {CodexFailure.QUOTA_OR_RATE_LIMIT, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE}:
                break
        return self._record(role, profile_identity, contract_identity, audit.fingerprint, failure or CodexFailure.UNKNOWN, now, freshness_seconds, attempts)

    def _record(self, role: ProviderRole, profile_identity: str, contract_identity: str, runtime_fingerprint: str, failure: CodexFailure | None, now: int, freshness_seconds: int, attempts: int) -> ProviderHealthObservation:
        observation = ProviderHealthObservation(
            role, profile_identity, contract_identity, runtime_fingerprint,
            HealthState.READY if failure is None else HealthState.BLOCKED,
            failure, now, now + freshness_seconds, attempts,
        )
        self._cache.put(observation)
        return observation


def _authorize_qualification_control(binding: CandidateBinding, control: ProviderQualificationControl, now: int) -> None:
    if type(binding) is not CandidateBinding or type(control) is not ProviderQualificationControl or type(now) is not int or control.binding != binding or control.now != now:
        raise ProviderHealthError("provider qualification control is invalid")
    try:
        control.dependency_control.require(binding, DependencyStage.PROVIDER_QUALIFICATION, now=now)
    except DependencyPolicyError as error:
        raise ProviderHealthError("provider qualification preflight blocked execution") from error


def _audit_runtime_under_control(
    channel: CodexRoleChannel, binding: CandidateBinding, control: ProviderQualificationControl, now: int,
) -> CodexRuntimeAudit:
    """Ensure every direct runtime-audit callback is preceded by the sealed gate."""

    _authorize_qualification_control(binding, control, now)
    return channel.audit_runtime()


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


def _commit(value: object) -> bool:
    return type(value) is str and _COMMIT.fullmatch(value) is not None


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _unknown_runtime_fingerprint() -> str:
    return _digest({"runtime": "unavailable"})
