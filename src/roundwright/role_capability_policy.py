"""Typed, non-dispatching contracts for bounded advisory roles.

Recovery advice and owner-intent interpretation are deliberately *not*
orchestrators.  This module only validates public-safe, source-attributed
guidance and proves a request was scoped to one dedicated role instance.  It
does not open a provider session, retain prompt text, invoke a callback, or
grant repository, scheduler, GitHub, or lifecycle authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum

from .configuration import ProviderProfile


class RoleCapabilityError(ValueError):
    """Raised when an advisory-role boundary is incomplete or unsafe."""


class AdvisoryRole(str, Enum):
    RECOVERY_ADVISOR = "recovery-advisor"
    OWNER_INTENT_INTERPRETER = "owner-intent-interpreter"


class RoleCapability(str, Enum):
    READ_TRUSTED_GUIDANCE = "read-trusted-guidance"
    RENDER_OWNER_SAFE_ADVICE = "render-owner-safe-advice"


class AdvisoryRoleStatus(str, Enum):
    DISABLED = "disabled"
    READY = "ready"


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


def _require_identity(value: object, label: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class TrustedGuidance:
    """Digest-only guidance provenance accepted from an independent source."""

    source_identity: str
    guidance_digest: str
    accepted_baseline_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.source_identity, "guidance source identity")
        _require_digest(self.guidance_digest, "guidance digest")
        _require_digest(self.accepted_baseline_digest, "accepted baseline digest")

    @property
    def receipt_digest(self) -> str:
        return _digest({
            "schema": "roundwright-trusted-guidance-receipt/v1",
            "source_identity": self.source_identity,
            "guidance_digest": self.guidance_digest,
            "accepted_baseline_digest": self.accepted_baseline_digest,
        })


@dataclass(frozen=True)
class RoleCapabilityProfile:
    """A narrow capability declaration, independent from effective authority."""

    role: AdvisoryRole
    provider_profile: ProviderProfile
    capabilities: frozenset[RoleCapability]
    dedicated_instance_required: bool = True
    always_on: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.role) is not AdvisoryRole
            or type(self.provider_profile) is not ProviderProfile
            or type(self.capabilities) is not frozenset
            or not self.capabilities
            or any(type(item) is not RoleCapability for item in self.capabilities)
            or self.dedicated_instance_required is not True
            or self.always_on is not False
        ):
            raise RoleCapabilityError("role capability profile is invalid")

    @property
    def profile_identity(self) -> str:
        return _digest({
            "schema": "roundwright-advisory-role-capability-profile/v1",
            "role": self.role.value,
            "model": self.provider_profile.model,
            "reasoning_effort": self.provider_profile.reasoning_effort.value,
            "capabilities": sorted(item.value for item in self.capabilities),
            "dedicated_instance_required": self.dedicated_instance_required,
            "always_on": self.always_on,
        })


@dataclass(frozen=True)
class DedicatedRoleInstance:
    """One bounded request target; it cannot be reused for another role."""

    instance_identity: str
    role: AdvisoryRole
    profile_identity: str
    guidance_receipt_digest: str
    candidate_sha: str

    def __post_init__(self) -> None:
        _require_identity(self.instance_identity, "dedicated instance identity")
        _require_digest(self.profile_identity, "profile identity")
        _require_digest(self.guidance_receipt_digest, "guidance receipt")
        if type(self.candidate_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha) is None:
            raise RoleCapabilityError("candidate identity is invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({
            "schema": "roundwright-dedicated-advisory-role-instance/v1",
            "instance_identity": self.instance_identity,
            "role": self.role.value,
            "profile_identity": self.profile_identity,
            "guidance_receipt_digest": self.guidance_receipt_digest,
            "candidate_sha": self.candidate_sha,
        })


@dataclass(frozen=True)
class RoleCapabilityGrant:
    """A caller supplied receipt for an advisory capability intersection.

    A grant never represents effective repository authority.  The caller must
    explicitly establish that separate authority at the production boundary.
    """

    issuer_identity: str
    instance_receipt_digest: str
    granted_capabilities: frozenset[RoleCapability]

    def __post_init__(self) -> None:
        _require_digest(self.issuer_identity, "grant issuer identity")
        _require_digest(self.instance_receipt_digest, "instance receipt")
        if type(self.granted_capabilities) is not frozenset or not self.granted_capabilities or any(type(item) is not RoleCapability for item in self.granted_capabilities):
            raise RoleCapabilityError("granted capabilities are invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({
            "schema": "roundwright-advisory-role-capability-grant/v1",
            "issuer_identity": self.issuer_identity,
            "instance_receipt_digest": self.instance_receipt_digest,
            "granted_capabilities": sorted(item.value for item in self.granted_capabilities),
        })


@dataclass(frozen=True)
class AdvisoryRoleContract:
    """Validated public-safe capability evidence for one explicit request."""

    profile: RoleCapabilityProfile
    guidance: TrustedGuidance
    instance: DedicatedRoleInstance
    grant: RoleCapabilityGrant | None = None

    def status(self) -> AdvisoryRoleStatus:
        if self.grant is None:
            return AdvisoryRoleStatus.DISABLED
        if (
            self.instance.role is not self.profile.role
            or self.instance.profile_identity != self.profile.profile_identity
            or self.instance.guidance_receipt_digest != self.guidance.receipt_digest
            or self.grant.instance_receipt_digest != self.instance.receipt_digest
            or not self.grant.granted_capabilities <= self.profile.capabilities
        ):
            raise RoleCapabilityError("role capability grant does not match its dedicated instance")
        return AdvisoryRoleStatus.READY

    def public_receipt(self) -> dict[str, object]:
        status = self.status()
        return {
            "schema": "roundwright-advisory-role-contract-receipt/v1",
            "role": self.profile.role.value,
            "profile_identity": self.profile.profile_identity,
            "guidance_receipt_digest": self.guidance.receipt_digest,
            "instance_receipt_digest": self.instance.receipt_digest,
            "grant_receipt_digest": None if self.grant is None else self.grant.receipt_digest,
            "capabilities": sorted(item.value for item in self.profile.capabilities),
            "status": status.value,
            "effective_authority": "disabled",
        }


def default_advisory_profiles(*, recovery_advisor: ProviderProfile, owner_intent_interpreter: ProviderProfile) -> tuple[RoleCapabilityProfile, RoleCapabilityProfile]:
    """Build the two bounded defaults from resolved configuration only."""

    return (
        RoleCapabilityProfile(AdvisoryRole.RECOVERY_ADVISOR, recovery_advisor, frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE})),
        RoleCapabilityProfile(AdvisoryRole.OWNER_INTENT_INTERPRETER, owner_intent_interpreter, frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE})),
    )


def require_non_dispatching_production_entrypoint(contract: AdvisoryRoleContract) -> dict[str, object]:
    """Return a receipt only; provider or orchestration execution is prohibited."""

    receipt = contract.public_receipt()
    if receipt["status"] != AdvisoryRoleStatus.READY.value:
        raise RoleCapabilityError("advisory role is disabled without an explicit capability grant")
    return receipt
