"""Fail-closed, non-dispatching contracts for bounded advisory roles.

The types validate evidence supplied by an independent control plane. They do
not create authority, discover a provider, or perform an action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping

from .configuration import ProviderProfile


class RoleCapabilityError(ValueError):
    """Raised when role evidence is incomplete, stale, or outside its scope."""


class AdvisoryRole(str, Enum):
    RECOVERY_ADVISOR = "recovery-advisor"
    OWNER_INTENT_INTERPRETER = "owner-intent-interpreter"


class RoleCapability(str, Enum):
    READ_TRUSTED_GUIDANCE = "read-trusted-guidance"
    RENDER_OWNER_SAFE_ADVICE = "render-owner-safe-advice"
    BOUNDED_CODING = "bounded-coding"
    READ_ONLY_REVIEW = "read-only-review"
    OWNER_COMMAND_INTERPRETATION = "owner-command-interpretation"


class AdvisoryRoleStatus(str, Enum):
    DISABLED = "disabled"
    READY = "ready"


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


def _require_identity(value: object, label: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class RoleBudget:
    max_calls: int
    max_duration_seconds: int
    max_tokens: int

    def __post_init__(self) -> None:
        if any(type(item) is not int or not 1 <= item <= limit for item, limit in ((self.max_calls, 3), (self.max_duration_seconds, 300), (self.max_tokens, 8000))):
            raise RoleCapabilityError("role budget is invalid")

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-advisory-role-budget/v1", "calls": self.max_calls, "seconds": self.max_duration_seconds, "tokens": self.max_tokens})


@dataclass(frozen=True)
class SdkAdapterMapping:
    sdk_version: str
    adapter_identity: str
    supported_capabilities: frozenset[RoleCapability]

    def __post_init__(self) -> None:
        if type(self.sdk_version) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.sdk_version) or not _DIGEST.fullmatch(self.adapter_identity) or type(self.supported_capabilities) is not frozenset or not self.supported_capabilities or any(type(item) is not RoleCapability for item in self.supported_capabilities):
            raise RoleCapabilityError("SDK adapter mapping is invalid")

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-advisory-sdk-mapping/v1", "sdk_version": self.sdk_version, "adapter_identity": self.adapter_identity, "capabilities": sorted(item.value for item in self.supported_capabilities)})


@dataclass(frozen=True)
class RoleCapabilityProfile:
    role: AdvisoryRole
    provider_profile: ProviderProfile
    capabilities: frozenset[RoleCapability]
    budget: RoleBudget
    sdk_mapping: SdkAdapterMapping
    dedicated_instance_required: bool = True
    always_on: bool = False

    def __post_init__(self) -> None:
        if (type(self.role) is not AdvisoryRole or type(self.provider_profile) is not ProviderProfile or type(self.capabilities) is not frozenset or not self.capabilities or any(type(item) is not RoleCapability for item in self.capabilities) or type(self.budget) is not RoleBudget or type(self.sdk_mapping) is not SdkAdapterMapping or not self.capabilities <= self.sdk_mapping.supported_capabilities or self.dedicated_instance_required is not True or self.always_on is not False):
            raise RoleCapabilityError("role capability profile is invalid")

    @property
    def profile_identity(self) -> str:
        return _digest({"schema": "roundwright-advisory-role-capability-profile/v2", "role": self.role.value, "model": self.provider_profile.model, "reasoning_effort": self.provider_profile.reasoning_effort.value, "capabilities": sorted(item.value for item in self.capabilities), "budget": self.budget.identity, "sdk_mapping": self.sdk_mapping.identity, "dedicated": True, "always_on": False})


@dataclass(frozen=True)
class GuidanceManifest:
    repository_identity: str
    trusted_revision: str
    files: Mapping[str, str]

    def __post_init__(self) -> None:
        _require_digest(self.repository_identity, "guidance repository identity")
        if type(self.trusted_revision) is not str or _SHA.fullmatch(self.trusted_revision) is None or type(self.files) is not dict or not self.files:
            raise RoleCapabilityError("guidance manifest is invalid")
        for path, digest in self.files.items():
            if type(path) is not str or _SAFE_PATH.fullmatch(path) is None or path.startswith(".") or ".." in path.split("/") or _DIGEST.fullmatch(digest) is None:
                raise RoleCapabilityError("guidance manifest is invalid")

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-accepted-guidance-manifest/v1", "repository_identity": self.repository_identity, "trusted_revision": self.trusted_revision, "files": dict(sorted(self.files.items()))})


@dataclass(frozen=True)
class TrustedGuidance:
    manifest_identity: str
    role: AdvisoryRole
    selected_paths: tuple[str, ...]
    guidance_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.manifest_identity, "guidance manifest identity")
        if type(self.role) is not AdvisoryRole or type(self.selected_paths) is not tuple or not self.selected_paths or any(type(path) is not str or _SAFE_PATH.fullmatch(path) is None for path in self.selected_paths) or tuple(sorted(set(self.selected_paths))) != self.selected_paths:
            raise RoleCapabilityError("trusted guidance selection is invalid")
        _require_digest(self.guidance_digest, "guidance digest")

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-trusted-guidance-receipt/v2", "manifest_identity": self.manifest_identity, "role": self.role.value, "selected_paths": self.selected_paths, "guidance_digest": self.guidance_digest})


def resolve_accepted_guidance(*, root: Path, manifest: GuidanceManifest, role: AdvisoryRole, requested_paths: tuple[str, ...], explicit_context: bool, implicit_working_directory: bool = False) -> TrustedGuidance:
    """Resolve exact allowlisted files from an explicit trusted root only."""
    if explicit_context is not True or implicit_working_directory is not False or not isinstance(root, Path) or type(manifest) is not GuidanceManifest or type(role) is not AdvisoryRole or type(requested_paths) is not tuple or not requested_paths:
        raise RoleCapabilityError("accepted guidance context is invalid")
    selected = tuple(sorted(set(requested_paths), key=lambda item: (item.count("/"), item)))
    if selected != requested_paths:
        raise RoleCapabilityError("accepted guidance precedence is invalid")
    material: list[dict[str, str]] = []
    try:
        trusted_root = root.resolve(strict=True)
    except OSError as error:
        raise RoleCapabilityError("accepted guidance is unavailable") from error
    for relative in selected:
        if relative not in manifest.files or _SAFE_PATH.fullmatch(relative) is None:
            raise RoleCapabilityError("accepted guidance path is not allowlisted")
        try:
            candidate = (trusted_root / relative).resolve(strict=True)
            candidate.relative_to(trusted_root)
            digest = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        except (OSError, ValueError) as error:
            raise RoleCapabilityError("accepted guidance is unavailable") from error
        if digest != manifest.files[relative]:
            raise RoleCapabilityError("accepted guidance content has drifted")
        material.append({"path": relative, "digest": digest})
    return TrustedGuidance(manifest.identity, role, selected, _digest(material))


@dataclass(frozen=True)
class DedicatedRoleInstance:
    instance_identity: str
    role: AdvisoryRole
    profile_identity: str
    guidance_receipt_digest: str
    repository_identity: str
    task_identity: str
    state_identity: str
    deployment_identity: str
    host_identity: str
    authority_epoch: int
    replacement_fence: str
    candidate_sha: str

    def __post_init__(self) -> None:
        for value, label in ((self.profile_identity, "profile identity"), (self.guidance_receipt_digest, "guidance receipt"), (self.repository_identity, "repository identity"), (self.state_identity, "state identity"), (self.deployment_identity, "deployment identity"), (self.host_identity, "host identity")):
            _require_digest(value, label)
        _require_identity(self.instance_identity, "dedicated instance identity")
        _require_identity(self.task_identity, "task identity")
        _require_identity(self.replacement_fence, "replacement fence")
        if type(self.role) is not AdvisoryRole or type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.candidate_sha) is not str or _SHA.fullmatch(self.candidate_sha) is None:
            raise RoleCapabilityError("dedicated instance admission is invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-dedicated-advisory-role-instance/v2", "instance": self.instance_identity, "role": self.role.value, "profile": self.profile_identity, "guidance": self.guidance_receipt_digest, "repository": self.repository_identity, "task": self.task_identity, "state": self.state_identity, "deployment": self.deployment_identity, "host": self.host_identity, "epoch": self.authority_epoch, "fence": self.replacement_fence, "candidate": self.candidate_sha})


def validate_instance_continuity(previous: DedicatedRoleInstance, current: DedicatedRoleInstance) -> str:
    """Permit an exact restart or one fenced replacement, never reassignment."""
    if type(previous) is not DedicatedRoleInstance or type(current) is not DedicatedRoleInstance:
        raise RoleCapabilityError("role instance continuity is invalid")
    if current.receipt_digest == previous.receipt_digest:
        return "same-instance-restart"
    stable = ("role", "profile_identity", "guidance_receipt_digest", "repository_identity", "state_identity", "deployment_identity", "host_identity", "candidate_sha")
    if (any(getattr(previous, name) != getattr(current, name) for name in stable) or current.instance_identity == previous.instance_identity or current.task_identity == previous.task_identity or current.replacement_fence == previous.replacement_fence or current.authority_epoch != previous.authority_epoch + 1):
        raise RoleCapabilityError("role generation replacement is invalid")
    return "fenced-generation-replacement"


@dataclass(frozen=True)
class RoleScope:
    actions: frozenset[RoleCapability]
    paths: tuple[str, ...]
    tests: tuple[str, ...]
    processes: tuple[str, ...]
    networks: tuple[str, ...]
    resources: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.actions) is not frozenset or not self.actions or any(type(item) is not RoleCapability for item in self.actions):
            raise RoleCapabilityError("role action scope is invalid")
        for values, label in ((self.paths, "path"), (self.tests, "test"), (self.processes, "process"), (self.networks, "network"), (self.resources, "resource")):
            if type(values) is not tuple or any(type(item) is not str or _SAFE_PATH.fullmatch(item) is None for item in values) or tuple(sorted(set(values))) != values:
                raise RoleCapabilityError(f"role {label} scope is invalid")

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-role-capability-scope/v1", "actions": sorted(item.value for item in self.actions), "paths": self.paths, "tests": self.tests, "processes": self.processes, "networks": self.networks, "resources": self.resources})


@dataclass(frozen=True)
class TrustedRoleAuthorityReceipt:
    repository_identity: str
    task_identity: str
    deployment_identity: str
    authority_epoch: int
    issuer_identity: str
    expires_at: int
    revocation_identity: str

    def __post_init__(self) -> None:
        for value, label in ((self.repository_identity, "authority repository"), (self.deployment_identity, "authority deployment"), (self.issuer_identity, "authority issuer"), (self.revocation_identity, "authority revocation")):
            _require_digest(value, label)
        _require_identity(self.task_identity, "authority task")
        if type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.expires_at) is not int or self.expires_at < 1:
            raise RoleCapabilityError("authority receipt is invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-trusted-role-authority/v1", "repository": self.repository_identity, "task": self.task_identity, "deployment": self.deployment_identity, "epoch": self.authority_epoch, "issuer": self.issuer_identity, "expires_at": self.expires_at, "revocation": self.revocation_identity})


@dataclass(frozen=True)
class RoleCapabilityGrant:
    authority_receipt_digest: str
    instance_receipt_digest: str
    scope_identity: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value, label in ((self.authority_receipt_digest, "grant authority receipt"), (self.instance_receipt_digest, "grant instance receipt"), (self.scope_identity, "grant scope")):
            _require_digest(value, label)
        if type(self.issued_at) is not int or type(self.expires_at) is not int or self.issued_at < 0 or self.expires_at < self.issued_at:
            raise RoleCapabilityError("role capability grant is invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-advisory-role-capability-grant/v2", "authority": self.authority_receipt_digest, "instance": self.instance_receipt_digest, "scope": self.scope_identity, "issued_at": self.issued_at, "expires_at": self.expires_at})


@dataclass(frozen=True)
class VerifiedRoleAdmission:
    authority_receipt: TrustedRoleAuthorityReceipt
    grant: RoleCapabilityGrant
    scope: RoleScope
    evidence_time: int
    revoked: bool


@dataclass(frozen=True)
class AdvisoryRoleContract:
    profile: RoleCapabilityProfile
    guidance: TrustedGuidance
    instance: DedicatedRoleInstance
    admission: VerifiedRoleAdmission | None = None

    def status(self) -> AdvisoryRoleStatus:
        if self.admission is None:
            return AdvisoryRoleStatus.DISABLED
        authority, grant, scope = self.admission.authority_receipt, self.admission.grant, self.admission.scope
        if (type(self.admission) is not VerifiedRoleAdmission or self.admission.revoked or not grant.issued_at <= self.admission.evidence_time <= grant.expires_at or self.admission.evidence_time > authority.expires_at or self.instance.role is not self.profile.role or self.guidance.role is not self.profile.role or self.instance.profile_identity != self.profile.profile_identity or self.instance.guidance_receipt_digest != self.guidance.receipt_digest or grant.authority_receipt_digest != authority.receipt_digest or grant.instance_receipt_digest != self.instance.receipt_digest or grant.scope_identity != scope.identity or not scope.actions <= self.profile.capabilities or (self.instance.repository_identity, self.instance.task_identity, self.instance.deployment_identity, self.instance.authority_epoch) != (authority.repository_identity, authority.task_identity, authority.deployment_identity, authority.authority_epoch)):
            raise RoleCapabilityError("role admission is missing, stale, revoked, or mismatched")
        return AdvisoryRoleStatus.READY

    def public_receipt(self) -> dict[str, object]:
        return {"schema": "roundwright-advisory-role-contract-receipt/v2", "role": self.profile.role.value, "profile_identity": self.profile.profile_identity, "guidance_receipt_digest": self.guidance.receipt_digest, "instance_receipt_digest": self.instance.receipt_digest, "admission_receipt_digest": None if self.admission is None else self.admission.grant.receipt_digest, "capabilities": sorted(item.value for item in self.profile.capabilities), "status": self.status().value, "effective_authority": "disabled"}


def default_advisory_profiles(*, recovery_advisor: ProviderProfile, owner_intent_interpreter: ProviderProfile) -> tuple[RoleCapabilityProfile, RoleCapabilityProfile]:
    mapping = SdkAdapterMapping("1.0.0", _digest("roundwright-advisory-sdk-adapter/v1"), frozenset(RoleCapability))
    shared = frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE})
    return (
        RoleCapabilityProfile(AdvisoryRole.RECOVERY_ADVISOR, recovery_advisor, shared | {RoleCapability.READ_ONLY_REVIEW}, RoleBudget(1, 60, 4000), mapping),
        RoleCapabilityProfile(AdvisoryRole.OWNER_INTENT_INTERPRETER, owner_intent_interpreter, shared | {RoleCapability.OWNER_COMMAND_INTERPRETATION}, RoleBudget(1, 60, 4000), mapping),
    )


def require_non_dispatching_production_entrypoint(contract: AdvisoryRoleContract) -> dict[str, object]:
    receipt = contract.public_receipt()
    if receipt["status"] != AdvisoryRoleStatus.READY.value:
        raise RoleCapabilityError("advisory role is disabled without verified admission")
    return receipt
