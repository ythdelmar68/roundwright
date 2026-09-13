"""Fail-closed, read-only admission contracts for bounded advisory roles.

The candidate can prepare a draft, but cannot manufacture admission: a grant is
read from an independently selected record and checked against a pinned
expectation.  This module never discovers a provider or dispatches an action.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Mapping

from .configuration import ProviderProfile


class RoleCapabilityError(ValueError):
    """Raised when evidence is incomplete, stale, or outside its scope."""


class AdvisoryRole(str, Enum):
    RECOVERY_ADVISOR = "recovery-advisor"
    OWNER_INTENT_INTERPRETER = "owner-intent-interpreter"


class GuidanceView(str, Enum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    DEPENDENCY_REVIEW = "dependency-review"
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


class ScopeKind(str, Enum):
    PATH = "path"
    TEST = "test"
    PROCESS = "process"
    NETWORK = "network"
    RESOURCE = "resource"


class RoleExecutionSeam(str, Enum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    DEPENDENCY_REVIEW = "dependency-review"
    RECOVERY_ADVISOR = "recovery-advisor"
    OWNER_INTENT_INTERPRETER = "owner-intent-interpreter"


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ADMISSION_SEAL = object()
_REVIEWED_SDK_CODES = {
    RoleCapability.READ_TRUSTED_GUIDANCE: "guidance.read/v1",
    RoleCapability.RENDER_OWNER_SAFE_ADVICE: "advice.render-owner-safe/v1",
    RoleCapability.BOUNDED_CODING: "coding.bounded/v1",
    RoleCapability.READ_ONLY_REVIEW: "review.read-only/v1",
    RoleCapability.OWNER_COMMAND_INTERPRETATION: "intent.interpret-owner-command/v1",
}


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _require_digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


def _require_identity(value: object, label: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise RoleCapabilityError(f"{label} is invalid")
    return value


def _canonical_record(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RoleCapabilityError("admission record is not canonical JSON") from error


def _relative_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise RoleCapabilityError("relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RoleCapabilityError("relative path is invalid")
    return path.as_posix()


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
class SdkAdapterExpectation:
    sdk_version: str
    adapter_identity: str
    mapping_digest: str
    capability_codes: Mapping[RoleCapability, str]

    def __post_init__(self) -> None:
        if (type(self.sdk_version) is not str or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.sdk_version) is None or _DIGEST.fullmatch(self.adapter_identity) is None or _DIGEST.fullmatch(self.mapping_digest) is None or type(self.capability_codes) is not dict or self.capability_codes != _REVIEWED_SDK_CODES):
            raise RoleCapabilityError("SDK adapter expectation is invalid")


def reviewed_sdk_expectation() -> SdkAdapterExpectation:
    adapter = _digest("roundwright-advisory-sdk-adapter/v1")
    codes = dict(_REVIEWED_SDK_CODES)
    return SdkAdapterExpectation("1.0.0", adapter, _digest({"sdk_version": "1.0.0", "adapter": adapter, "codes": {item.value: code for item, code in codes.items()}}), codes)


@dataclass(frozen=True)
class SdkAdapterMapping:
    sdk_version: str
    adapter_identity: str
    capability_codes: Mapping[RoleCapability, str]
    mapping_digest: str

    def __post_init__(self) -> None:
        expected = reviewed_sdk_expectation()
        if type(self.capability_codes) is not dict or (self.sdk_version, self.adapter_identity, self.capability_codes, self.mapping_digest) != (expected.sdk_version, expected.adapter_identity, expected.capability_codes, expected.mapping_digest):
            raise RoleCapabilityError("SDK adapter mapping differs from the reviewed expectation")

    @property
    def supported_capabilities(self) -> frozenset[RoleCapability]:
        return frozenset(self.capability_codes)

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-advisory-sdk-mapping/v2", "sdk_version": self.sdk_version, "adapter_identity": self.adapter_identity, "mapping_digest": self.mapping_digest})


def reviewed_sdk_mapping() -> SdkAdapterMapping:
    value = reviewed_sdk_expectation()
    return SdkAdapterMapping(value.sdk_version, value.adapter_identity, dict(value.capability_codes), value.mapping_digest)


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
        return _digest({"schema": "roundwright-advisory-role-capability-profile/v3", "role": self.role.value, "model": self.provider_profile.model, "reasoning_effort": self.provider_profile.reasoning_effort.value, "capabilities": sorted(item.value for item in self.capabilities), "budget": self.budget.identity, "sdk_mapping": self.sdk_mapping.identity, "dedicated": True, "always_on": False})


@dataclass(frozen=True)
class AuthoritativeGuidanceExpectation:
    repository_identity: str
    authoritative_root: Path
    trusted_revision: str
    tree_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.repository_identity, "guidance repository identity")
        _require_digest(self.tree_digest, "guidance tree digest")
        if not isinstance(self.authoritative_root, Path) or type(self.trusted_revision) is not str or _SHA.fullmatch(self.trusted_revision) is None:
            raise RoleCapabilityError("guidance expectation is invalid")


@dataclass(frozen=True)
class TrustedGuidance:
    expectation_identity: str
    view: GuidanceView
    selected_paths: tuple[str, ...]
    guidance_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.expectation_identity, "guidance expectation identity")
        _require_digest(self.guidance_digest, "guidance digest")
        if type(self.view) is not GuidanceView or type(self.selected_paths) is not tuple or not self.selected_paths or tuple(sorted(set(self.selected_paths), key=lambda item: (item.count("/"), item))) != self.selected_paths:
            raise RoleCapabilityError("trusted guidance selection is invalid")
        for path in self.selected_paths:
            _relative_path(path)

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-trusted-guidance-receipt/v3", "expectation": self.expectation_identity, "view": self.view.value, "selected_paths": self.selected_paths, "guidance_digest": self.guidance_digest})


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(("git", "-C", str(root), *arguments), check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RoleCapabilityError("authoritative guidance read-back is unavailable") from error


def resolve_authoritative_guidance(*, expectation: AuthoritativeGuidanceExpectation, view: GuidanceView, task_relative_path: str) -> TrustedGuidance:
    """Read just the root-to-task ``AGENTS.md`` chain from a pinned Git tree."""
    if type(expectation) is not AuthoritativeGuidanceExpectation or type(view) is not GuidanceView:
        raise RoleCapabilityError("guidance context is invalid")
    relative = _relative_path(task_relative_path)
    try:
        root = expectation.authoritative_root.resolve(strict=True)
    except OSError as error:
        raise RoleCapabilityError("authoritative guidance root is unavailable") from error
    shown_root = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if shown_root != root or _git(root, "rev-parse", "HEAD").decode().strip() != expectation.trusted_revision:
        raise RoleCapabilityError("authoritative guidance revision does not match expectation")
    tree = _git(root, "rev-parse", f"{expectation.trusted_revision}^{{tree}}").decode().strip()
    if _digest({"tree": tree, "repository": expectation.repository_identity}) != expectation.tree_digest:
        raise RoleCapabilityError("authoritative guidance tree does not match expectation")
    parents = [PurePosixPath()]
    directory = PurePosixPath(relative).parent
    while directory != PurePosixPath():
        parents.append(directory); directory = directory.parent
    candidates = tuple((parent / "AGENTS.md").as_posix() if parent.parts else "AGENTS.md" for parent in parents)
    material: list[dict[str, str]] = []
    for path in candidates:
        exists = subprocess.run(("git", "-C", str(root), "cat-file", "-e", f"{expectation.trusted_revision}:{path}"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if exists:
            content = _git(root, "show", f"{expectation.trusted_revision}:{path}")
            material.append({"path": path, "digest": "sha256:" + hashlib.sha256(content).hexdigest()})
    if not material:
        raise RoleCapabilityError("no authoritative AGENTS.md guidance applies")
    identity = _digest({"schema": "roundwright-authoritative-guidance-expectation/v1", "repository": expectation.repository_identity, "revision": expectation.trusted_revision, "tree": expectation.tree_digest})
    return TrustedGuidance(identity, view, tuple(item["path"] for item in material), _digest(material))


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
        _require_identity(self.instance_identity, "dedicated instance identity"); _require_identity(self.task_identity, "task identity"); _require_identity(self.replacement_fence, "replacement fence")
        if type(self.role) is not AdvisoryRole or type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.candidate_sha) is not str or _SHA.fullmatch(self.candidate_sha) is None:
            raise RoleCapabilityError("dedicated instance admission is invalid")

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-dedicated-advisory-role-instance/v3", "instance": self.instance_identity, "role": self.role.value, "profile": self.profile_identity, "guidance": self.guidance_receipt_digest, "repository": self.repository_identity, "task": self.task_identity, "state": self.state_identity, "deployment": self.deployment_identity, "host": self.host_identity, "epoch": self.authority_epoch, "fence": self.replacement_fence, "candidate": self.candidate_sha})


def validate_instance_continuity(previous: DedicatedRoleInstance, current: DedicatedRoleInstance) -> str:
    if type(previous) is not DedicatedRoleInstance or type(current) is not DedicatedRoleInstance:
        raise RoleCapabilityError("role instance continuity is invalid")
    if current.receipt_digest == previous.receipt_digest:
        return "same-instance-restart"
    stable = ("role", "profile_identity", "guidance_receipt_digest", "repository_identity", "task_identity", "state_identity", "deployment_identity", "host_identity", "candidate_sha")
    if any(getattr(previous, name) != getattr(current, name) for name in stable) or current.instance_identity == previous.instance_identity or current.replacement_fence == previous.replacement_fence or current.authority_epoch != previous.authority_epoch + 1:
        raise RoleCapabilityError("role generation replacement is invalid")
    return "fenced-generation-replacement"


@dataclass(frozen=True)
class ScopedDescriptor:
    kind: ScopeKind
    root_identity: str
    value: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ScopeKind:
            raise RoleCapabilityError("scope descriptor kind is unknown")
        _require_digest(self.root_identity, "scope root identity")
        if self.kind is ScopeKind.PATH:
            _relative_path(self.value)
        elif type(self.value) is not str or _SAFE_NAME.fullmatch(self.value) is None:
            raise RoleCapabilityError("scope descriptor value is invalid")


@dataclass(frozen=True)
class RoleScope:
    actions: frozenset[RoleCapability]
    descriptors: tuple[ScopedDescriptor, ...]

    def __post_init__(self) -> None:
        if type(self.actions) is not frozenset or not self.actions or any(type(item) is not RoleCapability for item in self.actions) or type(self.descriptors) is not tuple or any(type(item) is not ScopedDescriptor for item in self.descriptors):
            raise RoleCapabilityError("role scope is invalid")
        serialized = tuple((item.kind.value, item.root_identity, item.value) for item in self.descriptors)
        if tuple(sorted(set(serialized))) != serialized:
            raise RoleCapabilityError("role scope descriptors are not canonical")

    @property
    def identity(self) -> str:
        return _digest({"schema": "roundwright-role-capability-scope/v2", "actions": sorted(item.value for item in self.actions), "descriptors": tuple((item.kind.value, item.root_identity, item.value) for item in self.descriptors)})


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
class RoleAdmissionExpectation:
    store_identity: str
    record_digest: str
    grant_reference: str
    authority_receipt_digest: str
    instance_receipt_digest: str
    repository_identity: str
    task_identity: str
    state_identity: str
    deployment_identity: str
    host_identity: str
    authority_epoch: int
    scope_identity: str
    actions: frozenset[RoleCapability]
    valid_from: int
    valid_until: int
    revocation_readback_digest: str

    def __post_init__(self) -> None:
        for value, label in ((self.store_identity, "admission store"), (self.record_digest, "admission record"), (self.authority_receipt_digest, "expected authority"), (self.instance_receipt_digest, "expected instance"), (self.repository_identity, "expected repository"), (self.state_identity, "expected state"), (self.deployment_identity, "expected deployment"), (self.host_identity, "expected host"), (self.scope_identity, "expected scope"), (self.revocation_readback_digest, "expected revocation read-back")):
            _require_digest(value, label)
        _require_identity(self.grant_reference, "grant reference"); _require_identity(self.task_identity, "expected task")
        if type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.actions) is not frozenset or not self.actions or any(type(item) is not RoleCapability for item in self.actions) or type(self.valid_from) is not int or type(self.valid_until) is not int or self.valid_until < self.valid_from:
            raise RoleCapabilityError("role admission expectation is invalid")


class FileRoleAdmissionStore:
    """Read-only boundary for an owner/deployment-produced admission record."""
    def __init__(self, *, root: Path, record_relative_path: str, store_identity: str) -> None:
        _require_digest(store_identity, "admission store identity")
        self._root = root.resolve(strict=True); self._relative = _relative_path(record_relative_path); self.store_identity = store_identity

    def read(self) -> Mapping[str, object]:
        try:
            path = (self._root / self._relative).resolve(strict=True); path.relative_to(self._root)
            raw = path.read_bytes(); parsed = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise RoleCapabilityError("independent admission record is unavailable") from error
        if type(parsed) is not dict or _canonical_record(parsed) != raw:
            raise RoleCapabilityError("independent admission record is not canonical")
        return parsed


class VerifiedRoleAdmission:
    """A verified result; direct construction is intentionally rejected."""
    __slots__ = ("authority_receipt", "grant", "scope", "evidence_time", "revoked", "grant_reference", "_seal")
    def __init__(self, authority_receipt: TrustedRoleAuthorityReceipt, grant: RoleCapabilityGrant, scope: RoleScope, evidence_time: int, revoked: bool, grant_reference: str, *, _seal: object | None = None) -> None:
        if _seal is not _ADMISSION_SEAL:
            raise RoleCapabilityError("verified admission must come from the independent store")
        self.authority_receipt, self.grant, self.scope = authority_receipt, grant, scope
        self.evidence_time, self.revoked, self.grant_reference, self._seal = evidence_time, revoked, grant_reference, _seal


def _parse_record(record: Mapping[str, object]) -> tuple[TrustedRoleAuthorityReceipt, DedicatedRoleInstance, RoleScope, RoleCapabilityGrant, bool, str, str]:
    required = {"schema", "grant_reference", "authority", "instance", "scope", "grant", "revoked", "revocation_readback_digest"}
    if type(record) is not dict or set(record) != required or record["schema"] != "roundwright-independent-role-admission/v1" or type(record["authority"]) is not dict or type(record["instance"]) is not dict or type(record["scope"]) is not dict or type(record["grant"]) is not dict or type(record["revoked"]) is not bool:
        raise RoleCapabilityError("independent admission record has an invalid schema")
    try:
        authority = TrustedRoleAuthorityReceipt(**record["authority"])
        raw_instance = dict(record["instance"])
        raw_instance["role"] = AdvisoryRole(raw_instance["role"])
        instance = DedicatedRoleInstance(**raw_instance)
        raw_scope = record["scope"]
        descriptors = tuple(ScopedDescriptor(ScopeKind(item["kind"]), item["root_identity"], item["value"]) for item in raw_scope["descriptors"])
        scope = RoleScope(frozenset(RoleCapability(item) for item in raw_scope["actions"]), descriptors)
        grant = RoleCapabilityGrant(**record["grant"]); reference = _require_identity(record["grant_reference"], "grant reference"); revocation = _require_digest(record["revocation_readback_digest"], "revocation read-back")
    except (KeyError, TypeError, ValueError) as error:
        raise RoleCapabilityError("independent admission record has invalid values") from error
    return authority, instance, scope, grant, record["revoked"], reference, revocation


def read_verified_admission(*, expectation: RoleAdmissionExpectation, store: FileRoleAdmissionStore, evidence_time: int) -> tuple[VerifiedRoleAdmission, DedicatedRoleInstance]:
    """Authenticate a pre-existing pinned grant; never write or mint one."""
    if type(expectation) is not RoleAdmissionExpectation or type(store) is not FileRoleAdmissionStore or type(evidence_time) is not int or store.store_identity != expectation.store_identity:
        raise RoleCapabilityError("admission read-back context is invalid")
    record = store.read()
    if "sha256:" + hashlib.sha256(_canonical_record(record)).hexdigest() != expectation.record_digest:
        raise RoleCapabilityError("independent admission record digest has drifted")
    authority, instance, scope, grant, revoked, reference, revocation = _parse_record(record)
    if (reference != expectation.grant_reference or authority.receipt_digest != expectation.authority_receipt_digest or instance.receipt_digest != expectation.instance_receipt_digest or grant.authority_receipt_digest != authority.receipt_digest or grant.instance_receipt_digest != instance.receipt_digest or grant.scope_identity != scope.identity or scope.identity != expectation.scope_identity or scope.actions != expectation.actions or revocation != expectation.revocation_readback_digest or authority.revocation_identity != revocation or (instance.repository_identity, instance.task_identity, instance.state_identity, instance.deployment_identity, instance.host_identity, instance.authority_epoch) != (expectation.repository_identity, expectation.task_identity, expectation.state_identity, expectation.deployment_identity, expectation.host_identity, expectation.authority_epoch) or (authority.repository_identity, authority.task_identity, authority.deployment_identity, authority.authority_epoch) != (expectation.repository_identity, expectation.task_identity, expectation.deployment_identity, expectation.authority_epoch) or grant.issued_at != expectation.valid_from or grant.expires_at != expectation.valid_until or not grant.issued_at <= evidence_time <= grant.expires_at or evidence_time > authority.expires_at or revoked):
        raise RoleCapabilityError("independent role admission does not match its pinned expectation")
    return VerifiedRoleAdmission(authority, grant, scope, evidence_time, revoked, reference, _seal=_ADMISSION_SEAL), instance


@dataclass(frozen=True)
class AdvisoryRoleContract:
    profile: RoleCapabilityProfile
    guidance: TrustedGuidance
    instance: DedicatedRoleInstance
    admission: VerifiedRoleAdmission | None = None

    def status(self) -> AdvisoryRoleStatus:
        if self.admission is None: return AdvisoryRoleStatus.DISABLED
        admission = self.admission
        if type(admission) is not VerifiedRoleAdmission or admission._seal is not _ADMISSION_SEAL:
            raise RoleCapabilityError("role admission is not independently verified")
        authority, grant, scope = admission.authority_receipt, admission.grant, admission.scope
        if admission.revoked or not grant.issued_at <= admission.evidence_time <= grant.expires_at or admission.evidence_time > authority.expires_at or self.instance.role is not self.profile.role or self.instance.profile_identity != self.profile.profile_identity or self.instance.guidance_receipt_digest != self.guidance.receipt_digest or grant.instance_receipt_digest != self.instance.receipt_digest or grant.authority_receipt_digest != authority.receipt_digest or grant.scope_identity != scope.identity or not scope.actions <= self.profile.capabilities:
            raise RoleCapabilityError("role admission is missing, stale, revoked, or mismatched")
        return AdvisoryRoleStatus.READY

    def public_receipt(self) -> dict[str, object]:
        status = self.status(); effective = [] if self.admission is None else sorted(item.value for item in self.admission.scope.actions)
        return {"schema": "roundwright-advisory-role-contract-receipt/v3", "role": self.profile.role.value, "profile_identity": self.profile.profile_identity, "guidance_receipt_digest": self.guidance.receipt_digest, "instance_receipt_digest": self.instance.receipt_digest, "admission_receipt_digest": None if self.admission is None else self.admission.grant.receipt_digest, "capabilities": effective, "status": status.value, "effective_authority": "disabled"}


def render_grant_draft(*, instance: DedicatedRoleInstance, scope: RoleScope, owner_readable_reason: str) -> dict[str, object]:
    if type(instance) is not DedicatedRoleInstance or type(scope) is not RoleScope or type(owner_readable_reason) is not str or not owner_readable_reason.strip():
        raise RoleCapabilityError("grant draft is invalid")
    return {"schema": "roundwright-advisory-grant-draft/v1", "role": instance.role.value, "task": instance.task_identity, "instance": instance.instance_identity, "requested_actions": sorted(item.value for item in scope.actions), "reason": owner_readable_reason.strip(), "owner_action": "Select an existing independent grant reference and provide its read-back expectation."}


def require_verified_role_admission(contract: AdvisoryRoleContract, seam: RoleExecutionSeam) -> dict[str, object]:
    if type(contract) is not AdvisoryRoleContract or type(seam) is not RoleExecutionSeam:
        raise RoleCapabilityError("role execution seam is invalid")
    receipt = contract.public_receipt()
    if receipt["status"] != AdvisoryRoleStatus.READY.value:
        raise RoleCapabilityError("advisory role is disabled without verified admission")
    return receipt


def default_advisory_profiles(*, recovery_advisor: ProviderProfile, owner_intent_interpreter: ProviderProfile) -> tuple[RoleCapabilityProfile, RoleCapabilityProfile]:
    mapping = reviewed_sdk_mapping(); shared = frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE})
    return (RoleCapabilityProfile(AdvisoryRole.RECOVERY_ADVISOR, recovery_advisor, shared | {RoleCapability.READ_ONLY_REVIEW}, RoleBudget(1, 60, 4000), mapping), RoleCapabilityProfile(AdvisoryRole.OWNER_INTENT_INTERPRETER, owner_intent_interpreter, shared | {RoleCapability.OWNER_COMMAND_INTERPRETATION}, RoleBudget(1, 60, 4000), mapping))


def require_non_dispatching_production_entrypoint(contract: AdvisoryRoleContract) -> dict[str, object]:
    return require_verified_role_admission(contract, RoleExecutionSeam.RECOVERY_ADVISOR)
