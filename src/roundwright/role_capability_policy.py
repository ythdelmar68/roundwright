"""Fail-closed, read-only admission contracts for bounded advisory roles.

The candidate can prepare a draft, but cannot manufacture admission: a grant is
read from an independently selected record and checked against a pinned
expectation.  This module never discovers a provider or dispatches an action.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import subprocess
import threading
import time
import unicodedata
import weakref
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Mapping

from .configuration import ProviderProfile
from .configuration import _validated_authoritative_repository
from .dependency_policy import CandidateBinding
from .git_identity import GitEntrypointControl


class RoleCapabilityError(ValueError):
    """Raised when evidence is incomplete, stale, or outside its scope."""


class AdvisoryRole(str, Enum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    DEPENDENCY_REVIEW = "dependency-review"
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


class ExternalActivationStatus(str, Enum):
    """The only production authority state available to this candidate."""

    NOT_ACTIVATED = "not-activated"


class ScopeKind(str, Enum):
    PATH = "path"
    PROCESS = "process"
    TEST_INPUT_SET = "test-input-set"
    NETWORK = "network"
    RESOURCE = "resource"


class RoleExecutionSeam(str, Enum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    DEPENDENCY_REVIEW = "dependency-review"
    RECOVERY_ADVISOR = "recovery-advisor"
    OWNER_INTENT_INTERPRETER = "owner-intent-interpreter"


_SEAM_CAPABILITIES = {
    RoleExecutionSeam.WORKER: RoleCapability.BOUNDED_CODING,
    RoleExecutionSeam.SUPERVISOR: RoleCapability.READ_ONLY_REVIEW,
    RoleExecutionSeam.DEPENDENCY_REVIEW: RoleCapability.READ_ONLY_REVIEW,
    RoleExecutionSeam.RECOVERY_ADVISOR: RoleCapability.READ_ONLY_REVIEW,
    RoleExecutionSeam.OWNER_INTENT_INTERPRETER: RoleCapability.OWNER_COMMAND_INTERPRETATION,
}


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[a-z][a-z0-9._/-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
# Win32 reserves these device stems irrespective of extension and treats
# compatibility characters, trailing spaces, and trailing dots as aliases.
# Keep this table explicit: accepting an alias here would make a path scope
# mean something different to the Git reader and to the eventual Windows host.
_WINDOWS_RESERVED = frozenset({
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
})
_ADMISSION_SEAL = object()
_RUNTIME_SEAL = object()
_EXECUTION_SEAL = object()
_LAUNCH_PAYLOADS: "weakref.WeakKeyDictionary[TrustedProviderLaunchContext, Mapping[str, object]]" = weakref.WeakKeyDictionary()


def require_external_production_activation() -> None:
    """Deny real SDK effects until an external promotion supplies a verifier.

    This candidate intentionally contains no owner/deployment verifier and no
    caller-supplied verifier seam.  A local record, importable composition
    helper, or synthetic Git repository can qualify a hermetic contract test,
    but cannot activate a native/provider effect.
    """

    raise RoleCapabilityError(
        "external production authority is not activated for this candidate"
    )
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
    if type(value) is not str or not value or "\\" in value or "//" in value:
        raise RoleCapabilityError("relative path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", value) or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != value:
        raise RoleCapabilityError("relative path is invalid")
    for part in path.parts:
        # NFKC maps e.g. COM¹ to COM1.  Windows treats the latter as a device
        # alias, so reject compatibility spellings rather than normalising and
        # accidentally widening a caller-selected scope.
        normalized = unicodedata.normalize("NFKC", part)
        stem = normalized.split(".", 1)[0].rstrip(". ").casefold()
        if (normalized != part or ":" in part or any(character in part for character in '*?<>|"')
                or any(ord(character) < 32 for character in part)
                or part.endswith((".", " ")) or stem in _WINDOWS_RESERVED):
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
        if (type(self.sdk_version) is not str or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.sdk_version) is None or _DIGEST.fullmatch(self.adapter_identity) is None or _DIGEST.fullmatch(self.mapping_digest) is None or not isinstance(self.capability_codes, Mapping) or dict(self.capability_codes) != _REVIEWED_SDK_CODES):
            raise RoleCapabilityError("SDK adapter expectation is invalid")
        object.__setattr__(self, "capability_codes", MappingProxyType(dict(self.capability_codes)))


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
        if not isinstance(self.capability_codes, Mapping) or (self.sdk_version, self.adapter_identity, dict(self.capability_codes), self.mapping_digest) != (expected.sdk_version, expected.adapter_identity, dict(expected.capability_codes), expected.mapping_digest):
            raise RoleCapabilityError("SDK adapter mapping differs from the reviewed expectation")
        object.__setattr__(self, "capability_codes", MappingProxyType(dict(self.capability_codes)))

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
    # These are the exact immutable bytes read from the accepted-main tree.
    # They are intentionally retained only in the sealed in-process value;
    # public receipts continue to contain digests, never instruction text.
    accepted_main_guidance_bytes: bytes = b""

    def __post_init__(self) -> None:
        _require_digest(self.expectation_identity, "guidance expectation identity")
        _require_digest(self.guidance_digest, "guidance digest")
        if type(self.view) is not GuidanceView or type(self.accepted_main_guidance_bytes) is not bytes or type(self.selected_paths) is not tuple or not self.selected_paths or tuple(sorted(set(self.selected_paths), key=lambda item: (item.count("/"), item))) != self.selected_paths:
            raise RoleCapabilityError("trusted guidance selection is invalid")
        for path in self.selected_paths:
            _relative_path(path)

    @property
    def receipt_digest(self) -> str:
        return _digest({"schema": "roundwright-trusted-guidance-receipt/v3", "expectation": self.expectation_identity, "view": self.view.value, "selected_paths": self.selected_paths, "guidance_digest": self.guidance_digest})


@dataclass(frozen=True)
class ProviderGuidanceEvidence:
    """Immutable provider-side instruction boundary, checked before a turn."""
    view: GuidanceView
    provider_cwd_identity: str
    implicit_discovery_disabled: bool
    injected_context_digest: str
    guidance_receipt_digest: str
    accepted_main_sha: str
    task_candidate_sha: str

    def __post_init__(self) -> None:
        _require_digest(self.provider_cwd_identity, "provider guidance cwd")
        _require_digest(self.injected_context_digest, "provider injected guidance")
        _require_digest(self.guidance_receipt_digest, "provider guidance receipt")
        if type(self.view) is not GuidanceView or self.implicit_discovery_disabled is not True or type(self.accepted_main_sha) is not str or _SHA.fullmatch(self.accepted_main_sha) is None or type(self.task_candidate_sha) is not str or _SHA.fullmatch(self.task_candidate_sha) is None:
            raise RoleCapabilityError("provider guidance evidence is invalid")


_LAUNCH_CONTEXT_SEAL = object()


class TrustedProviderLaunchContext:
    """Opaque native-launch facts derived only from a sealed role admission."""

    __slots__ = (
        "cwd", "execution_binding", "guidance_receipt_digest",
        "injected_context_digest", "implicit_discovery_disabled",
        "developer_instructions", "accepted_main_guidance_digest", "accepted_main_guidance_bytes",
        "role_injected_bytes", "cwd_identity", "sdk_mapping_identity", "_authenticated_payload", "_seal", "__weakref__",
    )

    def __init__(
        self, cwd: Path, execution_binding: ExecutionInstanceBinding,
        guidance_receipt_digest: str, injected_context_digest: str,
        developer_instructions: str, *, accepted_main_guidance_bytes: bytes,
        sdk_mapping_identity: str, _seal: object | None = None,
    ) -> None:
        if (
            _seal is not _LAUNCH_CONTEXT_SEAL or not isinstance(cwd, Path)
            or type(execution_binding) is not ExecutionInstanceBinding
            or _DIGEST.fullmatch(guidance_receipt_digest) is None
            or _DIGEST.fullmatch(injected_context_digest) is None
            or type(developer_instructions) is not str or not developer_instructions
            or type(accepted_main_guidance_bytes) is not bytes
            or _DIGEST.fullmatch(sdk_mapping_identity) is None
        ):
            raise RoleCapabilityError("trusted provider launch context is invalid")
        resolved_cwd = cwd.resolve(strict=False)
        injected_bytes = developer_instructions.encode("utf-8")
        accepted_digest = "sha256:" + hashlib.sha256(accepted_main_guidance_bytes).hexdigest()
        cwd_identity = _digest({"schema": "roundwright-provider-sdk-cwd/v1", "cwd": str(resolved_cwd)})
        # Retain one private, complete authenticated payload.  Verification
        # compares every public launch field against it, so coordinated edits
        # to formerly mutable slots cannot manufacture self-consistency.
        payload = {
            "cwd": resolved_cwd, "execution_binding": execution_binding,
            "guidance_receipt_digest": guidance_receipt_digest,
            "injected_context_digest": injected_context_digest,
            "implicit_discovery_disabled": True,
            "developer_instructions": developer_instructions,
            "role_injected_bytes": injected_bytes,
            "accepted_main_guidance_bytes": accepted_main_guidance_bytes,
            "accepted_main_guidance_digest": accepted_digest,
            "cwd_identity": cwd_identity,
            "sdk_mapping_identity": sdk_mapping_identity,
        }
        for name, value in payload.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_authenticated_payload", MappingProxyType(payload))
        _LAUNCH_PAYLOADS[self] = MappingProxyType(payload)
        object.__setattr__(self, "_seal", _seal)

    def __setattr__(self, name: str, value: object) -> None:
        # Normal callers cannot mutate a sealed launch context.  ``verify``
        # still authenticates against the private payload for adversarial
        # object-level slot mutation in an embedding process.
        if getattr(self, "_seal", None) is _LAUNCH_CONTEXT_SEAL:
            raise RoleCapabilityError("trusted provider launch context is immutable")
        object.__setattr__(self, name, value)

    def verify(self, *, cwd: Path, profile: ProviderProfile,
               required_capability: RoleCapability | None = None) -> None:
        # The authority anchor is deliberately outside the mutable instance.
        # Object-level slot replacement cannot replace this module-owned
        # identity binding.
        try:
            payload = _LAUNCH_PAYLOADS[self]
        except (KeyError, TypeError) as error:
            raise RoleCapabilityError("trusted provider launch context anchor is unavailable") from error
        expected_instructions = (
            "Use only the explicitly injected Roundwright guidance boundary. "
            "Do not discover ambient, global, or repository instruction files. "
            f"Guidance receipt: {payload['guidance_receipt_digest']}. Role view: {payload['execution_binding'].role.value}.\n"
            + payload["accepted_main_guidance_bytes"].decode("utf-8", errors="strict")
        )
        if (
            self._seal is not _LAUNCH_CONTEXT_SEAL
            or type(payload) is not MappingProxyType
            or self._authenticated_payload is not payload
            or not isinstance(cwd, Path) or cwd.resolve(strict=False) != self.cwd
            or type(profile) is not ProviderProfile
            or self.execution_binding.provider_profile != profile
            or any(getattr(self, name) != value for name, value in payload.items())
            or self.implicit_discovery_disabled is not True
            or self.cwd_identity != _digest({"schema": "roundwright-provider-sdk-cwd/v1", "cwd": str(self.cwd)})
            or self.injected_context_digest != ("sha256:" + hashlib.sha256(self.role_injected_bytes).hexdigest())
            or self.developer_instructions.encode("utf-8") != self.role_injected_bytes
            or self.developer_instructions != expected_instructions
            or self.accepted_main_guidance_digest != ("sha256:" + hashlib.sha256(self.accepted_main_guidance_bytes).hexdigest())
            or self.sdk_mapping_identity != reviewed_sdk_mapping().identity
            or (required_capability is not None and (
                type(required_capability) is not RoleCapability
                or required_capability not in reviewed_sdk_mapping().supported_capabilities
            ))
        ):
            raise RoleCapabilityError("trusted provider launch context has drifted")

    def for_ephemeral_cwd(self, cwd: Path) -> "TrustedProviderLaunchContext":
        """Seal the actual per-attempt empty workspace before SDK creation."""

        if self._seal is not _LAUNCH_CONTEXT_SEAL or not isinstance(cwd, Path):
            raise RoleCapabilityError("trusted provider ephemeral cwd is invalid")
        return TrustedProviderLaunchContext(
            cwd, self.execution_binding, self.guidance_receipt_digest,
            self.injected_context_digest, self.developer_instructions,
            accepted_main_guidance_bytes=self.accepted_main_guidance_bytes,
            sdk_mapping_identity=self.sdk_mapping_identity,
            _seal=_LAUNCH_CONTEXT_SEAL,
        )


def trusted_provider_launch_context(
    execution: "SealedRoleExecution", *, cwd: Path,
) -> TrustedProviderLaunchContext:
    """Create the only native SDK launch envelope from verified host state."""

    if type(execution) is not SealedRoleExecution or not isinstance(cwd, Path):
        raise RoleCapabilityError("trusted provider launch context is invalid")
    expected_execution = execution.execution_binding
    require_independent_execution(execution, expected_execution)
    evidence = execution.guidance_evidence
    receipt = execution.contract.guidance.receipt_digest
    if evidence.guidance_receipt_digest != receipt or evidence.implicit_discovery_disabled is not True:
        raise RoleCapabilityError("trusted provider guidance has drifted")
    accepted_bytes = execution.contract.guidance.accepted_main_guidance_bytes
    instructions = (
        "Use only the explicitly injected Roundwright guidance boundary. "
        "Do not discover ambient, global, or repository instruction files. "
        f"Guidance receipt: {receipt}. Role view: {evidence.view.value}.\n"
        + accepted_bytes.decode("utf-8", errors="strict")
    )
    injected_digest = "sha256:" + hashlib.sha256(instructions.encode("utf-8")).hexdigest()
    return TrustedProviderLaunchContext(
        cwd, expected_execution, receipt, injected_digest, instructions,
        accepted_main_guidance_bytes=accepted_bytes,
        sdk_mapping_identity=execution.contract.profile.sdk_mapping.identity,
        _seal=_LAUNCH_CONTEXT_SEAL,
    )


def _git(root: Path, *arguments: str) -> bytes:
    try:
        return subprocess.run(("git", "-C", str(root), *arguments), check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RoleCapabilityError("authoritative guidance read-back is unavailable") from error


def resolve_authoritative_guidance(*, expectation: AuthoritativeGuidanceExpectation, view: GuidanceView, task_relative_path: str, runtime: "SealedRoleRuntimeContext") -> TrustedGuidance:
    """Read just the root-to-task ``AGENTS.md`` chain from a pinned Git tree."""
    if type(expectation) is not AuthoritativeGuidanceExpectation or type(view) is not GuidanceView or type(runtime) is not SealedRoleRuntimeContext:
        raise RoleCapabilityError("guidance context is invalid")
    relative = _relative_path(task_relative_path)
    try:
        root = _validated_authoritative_repository(expectation.authoritative_root, binding=runtime.binding, control=runtime.git_entrypoint_control)
    except Exception as error:
        raise RoleCapabilityError("authoritative guidance root is unavailable") from error
    shown_root = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if shown_root != root or expectation.trusted_revision != runtime.binding.candidate_sha or expectation.authoritative_root.resolve() != runtime.root:
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
    accepted_bytes: list[bytes] = []
    for path in candidates:
        exists = subprocess.run(("git", "-C", str(root), "cat-file", "-e", f"{expectation.trusted_revision}:{path}"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if exists:
            content = _git(root, "show", f"{expectation.trusted_revision}:{path}")
            material.append({"path": path, "digest": "sha256:" + hashlib.sha256(content).hexdigest()})
            # Length-prefixing preserves the exact selected files and prevents
            # an ambiguous concatenation from becoming an instruction source.
            accepted_bytes.append(path.encode("utf-8") + b"\0" + str(len(content)).encode("ascii") + b"\0" + content)
    if not material:
        raise RoleCapabilityError("no authoritative AGENTS.md guidance applies")
    identity = _digest({"schema": "roundwright-authoritative-guidance-expectation/v1", "repository": expectation.repository_identity, "revision": expectation.trusted_revision, "tree": expectation.tree_digest})
    return TrustedGuidance(identity, view, tuple(item["path"] for item in material), _digest(material), b"".join(accepted_bytes))


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
        elif self.kind in {ScopeKind.PROCESS, ScopeKind.TEST_INPUT_SET, ScopeKind.RESOURCE}:
            if type(self.value) is not str or re.fullmatch(r"[0-9a-f]{64}", self.value) is None:
                raise RoleCapabilityError("scope descriptor value is invalid")
        elif self.kind is ScopeKind.NETWORK:
            if self.value != "network-disabled":
                raise RoleCapabilityError("scope descriptor value is invalid")
        else:
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

    def require(self, action: RoleCapability, descriptors: tuple[ScopedDescriptor, ...] = ()) -> None:
        """Enforce an exact admitted operation and its canonical bounds.

        A descriptor is an allowlist entry, not a hint or a directory prefix:
        callers must derive its exact kind/root/value from the concrete effect
        immediately before performing that effect.  This makes a reused scope
        reject cross-root, cross-tool, and A-to-B path replay.
        """

        if type(action) is not RoleCapability or type(descriptors) is not tuple:
            raise RoleCapabilityError("role scope request is invalid")
        if action not in self.actions or any(type(item) is not ScopedDescriptor for item in descriptors):
            raise RoleCapabilityError("role scope denies the requested action")
        admitted = {(item.kind, item.root_identity, item.value) for item in self.descriptors}
        if any((item.kind, item.root_identity, item.value) not in admitted for item in descriptors):
            raise RoleCapabilityError("role scope denies the requested bound")


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
    candidate_sha: str
    scope_identity: str
    actions: frozenset[RoleCapability]
    valid_from: int
    valid_until: int
    revocation_readback_digest: str

    def __post_init__(self) -> None:
        for value, label in ((self.store_identity, "admission store"), (self.record_digest, "admission record"), (self.authority_receipt_digest, "expected authority"), (self.instance_receipt_digest, "expected instance"), (self.repository_identity, "expected repository"), (self.state_identity, "expected state"), (self.deployment_identity, "expected deployment"), (self.host_identity, "expected host"), (self.scope_identity, "expected scope"), (self.revocation_readback_digest, "expected revocation read-back")):
            _require_digest(value, label)
        _require_identity(self.grant_reference, "grant reference"); _require_identity(self.task_identity, "expected task")
        if type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.candidate_sha) is not str or _SHA.fullmatch(self.candidate_sha) is None or type(self.actions) is not frozenset or not self.actions or any(type(item) is not RoleCapability for item in self.actions) or type(self.valid_from) is not int or type(self.valid_until) is not int or self.valid_until < self.valid_from:
            raise RoleCapabilityError("role admission expectation is invalid")


@dataclass(frozen=True)
class ExecutionInstanceBinding:
    """Canonical identity for one inert, pre-authorized role execution."""
    repository_identity: str; task_identity: str; candidate_sha: str; instance_receipt_digest: str
    host_identity: str; deployment_identity: str; authority_epoch: int; replacement_fence: str
    role: AdvisoryRole; provider_profile: ProviderProfile; execution_identity: str; preflight_identity: str

    def __post_init__(self) -> None:
        for value in (self.repository_identity, self.instance_receipt_digest, self.host_identity, self.deployment_identity, self.preflight_identity): _require_digest(value, "execution binding")
        if (type(self.task_identity) is not str or _IDENTITY.fullmatch(self.task_identity) is None or type(self.candidate_sha) is not str or _SHA.fullmatch(self.candidate_sha) is None or type(self.authority_epoch) is not int or self.authority_epoch < 1 or type(self.replacement_fence) is not str or _IDENTITY.fullmatch(self.replacement_fence) is None or type(self.role) is not AdvisoryRole or type(self.provider_profile) is not ProviderProfile or type(self.execution_identity) is not str or _IDENTITY.fullmatch(self.execution_identity) is None): raise RoleCapabilityError("execution binding is invalid")

    @property
    def digest(self) -> str:
        return _digest({"schema":"roundwright-execution-instance-binding/v1","repository":self.repository_identity,"task":self.task_identity,"candidate":self.candidate_sha,"instance":self.instance_receipt_digest,"host":self.host_identity,"deployment":self.deployment_identity,"epoch":self.authority_epoch,"fence":self.replacement_fence,"role":self.role.value,"profile":{"model":self.provider_profile.model,"reasoning_effort":self.provider_profile.reasoning_effort.value,"name":self.provider_profile.name},"execution":self.execution_identity,"preflight":self.preflight_identity})


@dataclass(frozen=True)
class TrustedExecutionHostInputs:
    """Host-owned, immutable inputs from which one effect binding is derived.

    This deliberately does not accept a :class:`SealedRoleExecution`.  A
    composition root must retain these independently verified repository,
    deployment and fencing values and use the actual request or attempt id
    when deriving the expected binding immediately before an effect.
    """

    repository_identity: str; task_identity: str; candidate_sha: str
    instance_receipt_digest: str; host_identity: str; deployment_identity: str
    authority_epoch: int; replacement_fence: str

    def __post_init__(self) -> None:
        for value in (self.repository_identity, self.instance_receipt_digest,
                      self.host_identity, self.deployment_identity):
            _require_digest(value, "trusted execution host input")
        if (type(self.task_identity) is not str or _IDENTITY.fullmatch(self.task_identity) is None
                or type(self.candidate_sha) is not str or _SHA.fullmatch(self.candidate_sha) is None
                or type(self.authority_epoch) is not int or self.authority_epoch < 1
                or type(self.replacement_fence) is not str
                or _IDENTITY.fullmatch(self.replacement_fence) is None):
            raise RoleCapabilityError("trusted execution host input is invalid")

    @property
    def identity(self) -> str:
        return _digest({
            "schema": "roundwright-trusted-execution-host/v1",
            "repository": self.repository_identity, "task": self.task_identity,
            "candidate": self.candidate_sha, "instance": self.instance_receipt_digest,
            "host": self.host_identity, "deployment": self.deployment_identity,
            "epoch": self.authority_epoch, "fence": self.replacement_fence,
        })

    def derive(
        self, *, role: AdvisoryRole, provider_profile: ProviderProfile,
        execution_identity: str, preflight_identity: str,
    ) -> ExecutionInstanceBinding:
        """Bind one native effect to the actual typed request/attempt identity."""

        return ExecutionInstanceBinding(
            self.repository_identity, self.task_identity, self.candidate_sha,
            self.instance_receipt_digest, self.host_identity,
            self.deployment_identity, self.authority_epoch,
            self.replacement_fence, role, provider_profile,
            execution_identity, preflight_identity,
        )

    def derive_for_effect(
        self, *, role: AdvisoryRole, provider_profile: ProviderProfile,
        request_or_attempt_identity: str, request_material: Mapping[str, object],
        preflight_material: Mapping[str, object],
    ) -> ExecutionInstanceBinding:
        """Derive a non-replayable binding from the concrete effect inputs.

        A caller-owned ``ExecutionInstanceBinding`` is only an admission
        comparison value; it cannot be used as this method's source.  The
        request/attempt identity, canonical request material, and the exact
        preflight facts are all folded into independent values immediately
        before the SDK or local-tool boundary.
        """

        _require_identity(request_or_attempt_identity, "effect request identity")
        if (type(role) is not AdvisoryRole or type(provider_profile) is not ProviderProfile
                or not isinstance(request_material, Mapping)
                or not isinstance(preflight_material, Mapping)):
            raise RoleCapabilityError("effect binding material is invalid")
        request_digest = _digest({"schema": "roundwright-effect-request/v1", "identity": request_or_attempt_identity, "request": dict(request_material)})
        preflight_digest = _digest({"schema": "roundwright-effect-preflight/v1", "request": request_digest, "preflight": dict(preflight_material)})
        # The external identity remains safe for persisted admission records;
        # the complete request data stays inside the digest only.
        execution_identity = "effect-" + hashlib.sha256(request_digest.encode("ascii")).hexdigest()[:32]
        return self.derive(
            role=role, provider_profile=provider_profile,
            execution_identity=execution_identity, preflight_identity=preflight_digest,
        )


def require_independent_execution(
    execution: "SealedRoleExecution", expected_execution: ExecutionInstanceBinding,
) -> dict[str, object]:
    """Consume a capsule only after a host-derived binding exactly matches it."""

    if type(execution) is not SealedRoleExecution or type(expected_execution) is not ExecutionInstanceBinding:
        raise RoleCapabilityError("trusted execution expectation is invalid")
    return execution.require_before_effect(expected_execution=expected_execution)


def derive_and_require_execution_for_effect(
    execution: "SealedRoleExecution", *, host_inputs: TrustedExecutionHostInputs,
    profile: ProviderProfile,
    request_or_attempt_identity: str, request_material: Mapping[str, object],
    preflight_material: Mapping[str, object],
) -> tuple[dict[str, object], ExecutionInstanceBinding]:
    """Derive and consume the exact binding at an effect wrapper.

    An adapter receives only the sealed admission capsule and the concrete
    request that it is about to hand to its backend.  It never accepts an
    ``ExecutionInstanceBinding`` from its caller.  The host facts originate in
    the sealed composition result, while every mutable/effect-local input is
    digested immediately before the effect.  The resulting identity is ready
    for a durable one-effect reservation at the outer host boundary.
    """

    if (
        type(execution) is not SealedRoleExecution
        or type(host_inputs) is not TrustedExecutionHostInputs
        or type(profile) is not ProviderProfile
        or execution.execution_binding.provider_profile != profile
    ):
        raise RoleCapabilityError("trusted effect execution is invalid")
    derived = host_inputs.derive_for_effect(
        role=execution.contract.profile.role, provider_profile=profile,
        request_or_attempt_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
    )
    return execution.require_before_effect(expected_execution=derived), derived


@dataclass(frozen=True)
class RoleBudgetUsage:
    calls: int; duration_seconds: int; tokens: int


class DurableRoleBudgetLedger:
    """SQLite-backed, fail-closed consumption for one admitted grant/instance.

    The row key includes the immutable grant receipt and execution-instance
    digest.  ``BEGIN IMMEDIATE`` makes concurrent admissions serialize across
    reconstructed ledger objects and processes.  Any malformed or ambiguous
    persisted state rejects the next effect instead of resetting a budget.
    """

    _schema = "roundwright-role-budget-ledger/v1"

    def __init__(self, path: Path, *, grant_receipt_digest: str,
                 execution_binding: ExecutionInstanceBinding, budget: RoleBudget) -> None:
        if (not isinstance(path, Path) or type(execution_binding) is not ExecutionInstanceBinding
                or type(budget) is not RoleBudget):
            raise RoleCapabilityError("role budget ledger inputs are invalid")
        _require_digest(grant_receipt_digest, "role budget grant")
        self._path = path
        self._grant = grant_receipt_digest
        self._binding = execution_binding.digest
        self._budget = budget
        self._lock = threading.RLock()

    @property
    def key(self) -> str:
        return _digest({"schema": self._schema, "grant": self._grant, "binding": self._binding})

    def matches(self, *, grant_receipt_digest: str,
                execution_binding: ExecutionInstanceBinding,
                budget: RoleBudget) -> bool:
        """Confirm that a host cannot substitute a ledger from another effect."""

        return (
            type(execution_binding) is ExecutionInstanceBinding
            and type(budget) is RoleBudget
            and type(grant_receipt_digest) is str
            and grant_receipt_digest == self._grant
            and execution_binding.digest == self._binding
            and budget == self._budget
        )

    def reserve_effect(self, *, exposure: RoleBudget | None = None) -> RoleBudgetUsage:
        """Durably reserve the admitted worst-case provider effect up front.

        The caller must reserve the admitted worst case, not a nominal one
        call/second/token.  Omitting ``exposure`` is retained only for a
        one-unit fixture allocation; production paths pass their exact sealed
        role budget.  A crash, reconstruction, or failover therefore cannot
        reset or understate any part of the grant budget.
        """

        if exposure is None:
            exposure = RoleBudget(1, 1, 1)
        if type(exposure) is not RoleBudget:
            raise RoleCapabilityError("role budget exposure is invalid")
        if (exposure.max_calls > self._budget.max_calls
                or exposure.max_duration_seconds > self._budget.max_duration_seconds
                or exposure.max_tokens > self._budget.max_tokens):
            raise RoleCapabilityError("role budget exposure exceeds admission")
        return self.consume(calls=exposure.max_calls,
                            duration_seconds=exposure.max_duration_seconds,
                            tokens=exposure.max_tokens)

    def consume(self, *, calls: int = 1, duration_seconds: int = 0,
                tokens: int = 0) -> RoleBudgetUsage:
        if (type(calls) is not int or type(duration_seconds) is not int
                or type(tokens) is not int or calls < 0 or duration_seconds < 0
                or tokens < 0 or calls == duration_seconds == tokens == 0):
            raise RoleCapabilityError("role budget consumption is invalid")
        connection: sqlite3.Connection | None = None
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
            with self._lock:
                connection.execute("PRAGMA busy_timeout=5000")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS role_budget_usage ("
                    "schema TEXT NOT NULL, ledger_key TEXT PRIMARY KEY, "
                    "grant_digest TEXT NOT NULL, binding_digest TEXT NOT NULL, "
                    "calls INTEGER NOT NULL, duration_seconds INTEGER NOT NULL, "
                    "tokens INTEGER NOT NULL)"
                )
                row = connection.execute(
                    "SELECT schema, grant_digest, binding_digest, calls, "
                    "duration_seconds, tokens FROM role_budget_usage WHERE ledger_key=?",
                    (self.key,),
                ).fetchone()
                if row is None:
                    used = RoleBudgetUsage(0, 0, 0)
                elif (len(row) != 6 or row[0] != self._schema or row[1] != self._grant
                      or row[2] != self._binding or any(type(value) is not int or value < 0 for value in row[3:])):
                    raise RoleCapabilityError("role budget persistence is ambiguous")
                else:
                    used = RoleBudgetUsage(row[3], row[4], row[5])
                next_usage = RoleBudgetUsage(
                    used.calls + calls, used.duration_seconds + duration_seconds,
                    used.tokens + tokens,
                )
                if (next_usage.calls > self._budget.max_calls
                        or next_usage.duration_seconds > self._budget.max_duration_seconds
                        or next_usage.tokens > self._budget.max_tokens):
                    raise RoleCapabilityError("role budget is exhausted")
                connection.execute(
                    "INSERT INTO role_budget_usage(schema, ledger_key, grant_digest, binding_digest, calls, duration_seconds, tokens) "
                    "VALUES(?,?,?,?,?,?,?) ON CONFLICT(ledger_key) DO UPDATE SET "
                    "calls=excluded.calls, duration_seconds=excluded.duration_seconds, tokens=excluded.tokens",
                    (self._schema, self.key, self._grant, self._binding,
                     next_usage.calls, next_usage.duration_seconds, next_usage.tokens),
                )
                connection.execute("COMMIT")
                return next_usage
        except RoleCapabilityError:
            raise
        except (OSError, sqlite3.DatabaseError, sqlite3.OperationalError) as error:
            raise RoleCapabilityError("role budget persistence is unavailable") from error
        finally:
            if connection is not None:
                connection.close()

    def require_reserved(self, *, exposure: RoleBudget) -> RoleBudgetUsage:
        """Read back the exact durable reservation without consuming again."""

        if type(exposure) is not RoleBudget or not self._path.is_file():
            raise RoleCapabilityError("role budget reservation is unavailable")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{self._path.resolve().as_posix()}?mode=ro", uri=True,
                timeout=5, isolation_level=None,
            )
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT schema, grant_digest, binding_digest, calls, "
                "duration_seconds, tokens FROM role_budget_usage WHERE ledger_key=?",
                (self.key,),
            ).fetchone()
            if (row is None or len(row) != 6 or row[0] != self._schema
                    or row[1] != self._grant or row[2] != self._binding
                    or any(type(value) is not int or value < 0 for value in row[3:])):
                raise RoleCapabilityError("role budget reservation is ambiguous")
            usage = RoleBudgetUsage(row[3], row[4], row[5])
            expected = RoleBudgetUsage(
                exposure.max_calls, exposure.max_duration_seconds,
                exposure.max_tokens,
            )
            if usage != expected:
                raise RoleCapabilityError("role budget reservation has drifted")
            connection.execute("COMMIT")
            return usage
        except RoleCapabilityError:
            raise
        except (OSError, sqlite3.DatabaseError, sqlite3.OperationalError) as error:
            raise RoleCapabilityError("role budget reservation is unavailable") from error
        finally:
            if connection is not None:
                connection.close()

    def release_exact_reservation(self, *, exposure: RoleBudget) -> None:
        """Undo an unconsumed successor reservation after route rejection.

        The ledger key includes the exact execution binding, so this removes
        only the reservation being rejected; it cannot refund a different
        provider effect or a partially consumed budget.
        """

        if type(exposure) is not RoleBudget:
            raise RoleCapabilityError("role budget exposure is invalid")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
            with self._lock:
                connection.execute("PRAGMA busy_timeout=5000")
                connection.execute("BEGIN IMMEDIATE")
                expected = (self._schema, self._grant, self._binding,
                            exposure.max_calls, exposure.max_duration_seconds,
                            exposure.max_tokens)
                row = connection.execute(
                    "SELECT schema, grant_digest, binding_digest, calls, duration_seconds, tokens "
                    "FROM role_budget_usage WHERE ledger_key=?", (self.key,),
                ).fetchone()
                if row != expected:
                    raise RoleCapabilityError("role budget reservation cannot be released")
                if connection.execute(
                    "DELETE FROM role_budget_usage WHERE ledger_key=?", (self.key,),
                ).rowcount != 1:
                    raise RoleCapabilityError("role budget reservation cannot be released")
                connection.execute("COMMIT")
        except RoleCapabilityError:
            raise
        except (OSError, sqlite3.DatabaseError, sqlite3.OperationalError) as error:
            raise RoleCapabilityError("role budget reservation cannot be released") from error
        finally:
            if connection is not None:
                connection.close()


_EFFECT_RESERVATION_SEAL = object()


class TrustedRoleEffectReservation:
    """Opaque proof of one exact, durable, worst-case effect reservation."""

    __slots__ = (
        "_host_inputs", "_ledger", "_binding", "_exposure", "_profile",
        "_request_identity", "_request_digest", "_preflight_digest", "_seal",
    )

    def __init__(
        self, *, host_inputs: TrustedExecutionHostInputs,
        ledger: DurableRoleBudgetLedger, binding: ExecutionInstanceBinding,
        exposure: RoleBudget, profile: ProviderProfile, request_identity: str,
        request_material: Mapping[str, object], preflight_material: Mapping[str, object],
        _seal: object | None = None,
    ) -> None:
        if (_seal is not _EFFECT_RESERVATION_SEAL
                or type(host_inputs) is not TrustedExecutionHostInputs
                or type(ledger) is not DurableRoleBudgetLedger
                or type(binding) is not ExecutionInstanceBinding
                or type(exposure) is not RoleBudget
                or type(profile) is not ProviderProfile):
            raise RoleCapabilityError("trusted role effect reservation is invalid")
        self._host_inputs = host_inputs
        self._ledger = ledger
        self._binding = binding
        self._exposure = exposure
        self._profile = profile
        self._request_identity = request_identity
        # Keep only canonical digests.  A shallow mapping copy would still
        # alias nested caller-owned objects and could make a later mutation
        # appear to match the originally reserved effect.
        self._request_digest = _digest({
            "schema": "roundwright-reserved-effect-request/v1",
            "material": dict(request_material),
        })
        self._preflight_digest = _digest({
            "schema": "roundwright-reserved-effect-preflight/v1",
            "material": dict(preflight_material),
        })
        self._seal = _seal

    @property
    def execution_binding(self) -> ExecutionInstanceBinding:
        return self._binding

    @property
    def recovery_digest(self) -> str:
        """A sealed identity for this exact reserved successor effect."""

        if self._seal is not _EFFECT_RESERVATION_SEAL:
            raise RoleCapabilityError("trusted role effect reservation is invalid")
        return _recovery_reservation_digest(
            self._binding, self._exposure, self._profile,
            self._request_identity, self._request_digest, self._preflight_digest,
        )

    def require_before_effect(
        self, execution: "SealedRoleExecution", *, profile: ProviderProfile,
        request_or_attempt_identity: str, request_material: Mapping[str, object],
        preflight_material: Mapping[str, object],
    ) -> dict[str, object]:
        if (self._seal is not _EFFECT_RESERVATION_SEAL
                or type(profile) is not ProviderProfile
                or profile != self._profile
                or request_or_attempt_identity != self._request_identity
                or _digest({"schema": "roundwright-reserved-effect-request/v1",
                            "material": dict(request_material)}) != self._request_digest
                or _digest({"schema": "roundwright-reserved-effect-preflight/v1",
                            "material": dict(preflight_material)}) != self._preflight_digest):
            raise RoleCapabilityError("trusted role effect reservation has drifted")
        receipt, binding = derive_and_require_execution_for_effect(
            execution, host_inputs=self._host_inputs, profile=profile,
            request_or_attempt_identity=request_or_attempt_identity,
            request_material=request_material, preflight_material=preflight_material,
        )
        if binding.digest != self._binding.digest:
            raise RoleCapabilityError("trusted role effect binding has drifted")
        self._ledger.require_reserved(exposure=self._exposure)
        return receipt

    def require_recovery_route(self, execution: "SealedRoleExecution") -> ExecutionInstanceBinding:
        """Revalidate the exact reservation before it can authorize a retry route.

        Recovery must not treat a previously returned admission receipt as a
        transferable fallback grant.  The target effect remains tied to this
        reservation's sealed execution binding and its already-reserved
        worst-case budget.
        """

        if self._seal is not _EFFECT_RESERVATION_SEAL or type(execution) is not SealedRoleExecution:
            raise RoleCapabilityError("trusted recovery route reservation is invalid")
        execution.require_before_effect(expected_execution=self._binding)
        self._ledger.require_reserved(exposure=self._exposure)
        return self._binding

    def reject_recovery_route(self) -> None:
        """Remove a reservation that never acquired its durable route."""

        if self._seal is not _EFFECT_RESERVATION_SEAL:
            raise RoleCapabilityError("trusted role effect reservation is invalid")
        self._ledger.release_exact_reservation(exposure=self._exposure)


def _recovery_reservation_digest(
    binding: ExecutionInstanceBinding, exposure: RoleBudget, profile: ProviderProfile,
    request_identity: str, request_digest: str, preflight_digest: str,
) -> str:
    return _digest({
        "schema": "roundwright-recovery-effect-reservation/v1",
        "execution_binding": binding.digest,
        "budget": exposure.__dict__, "profile": profile.__dict__,
        "request_identity": request_identity, "request_digest": request_digest,
        "preflight_digest": preflight_digest,
    })


def recovery_reservation_digest(
    execution: "SealedRoleExecution", *, host_inputs: TrustedExecutionHostInputs,
    profile: ProviderProfile, request_or_attempt_identity: str,
    request_material: Mapping[str, object], preflight_material: Mapping[str, object],
) -> str:
    """Derive the future sealed reservation identity without reserving it.

    A recovery route can name this value before a successor is admitted, but
    route consumption later accepts only a real reservation that re-derives
    exactly this digest.
    """

    _receipt, binding = derive_and_require_execution_for_effect(
        execution, host_inputs=host_inputs, profile=profile,
        request_or_attempt_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
    )
    return _recovery_reservation_digest(
        binding, execution.contract.profile.budget, profile,
        request_or_attempt_identity,
        _digest({"schema": "roundwright-reserved-effect-request/v1", "material": dict(request_material)}),
        _digest({"schema": "roundwright-reserved-effect-preflight/v1", "material": dict(preflight_material)}),
    )


def reserve_role_effect(
    execution: "SealedRoleExecution", *, host_inputs: TrustedExecutionHostInputs,
    ledger_path: Path, profile: ProviderProfile,
    request_or_attempt_identity: str, request_material: Mapping[str, object],
    preflight_material: Mapping[str, object],
) -> TrustedRoleEffectReservation:
    """Reserve the exact declared worst case before any effectful boundary."""

    if not isinstance(ledger_path, Path):
        raise RoleCapabilityError("role budget ledger path is invalid")
    receipt, binding = derive_and_require_execution_for_effect(
        execution, host_inputs=host_inputs, profile=profile,
        request_or_attempt_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
    )
    if receipt.get("status") != AdvisoryRoleStatus.READY.value:
        raise RoleCapabilityError("role effect admission is unavailable")
    admission = execution.contract.admission
    if admission is None:
        raise RoleCapabilityError("role effect admission is unavailable")
    # Provider-facing seams do not get to treat a broad action grant as a
    # network or resource grant.  These are closed, static descriptors of the
    # accepted input, the deny-network posture, and the admitted instance;
    # the request/preflight remain separately bound by ``binding`` above.
    try:
        admission.scope.require(
            _SEAM_CAPABILITIES[execution.seam],
            (
                ScopedDescriptor(ScopeKind.TEST_INPUT_SET, execution.contract.instance.repository_identity, execution.contract.guidance.receipt_digest[7:]),
                ScopedDescriptor(ScopeKind.NETWORK, execution.contract.instance.repository_identity, "network-disabled"),
                ScopedDescriptor(ScopeKind.RESOURCE, execution.contract.instance.repository_identity, execution.contract.instance.receipt_digest[7:]),
            ),
        )
    except RoleCapabilityError as error:
        raise RoleCapabilityError("role effect descriptors are not admitted") from error
    exposure = execution.contract.profile.budget
    ledger = DurableRoleBudgetLedger(
        ledger_path, grant_receipt_digest=admission.grant.receipt_digest,
        execution_binding=binding, budget=exposure,
    )
    ledger.reserve_effect(exposure=exposure)
    return TrustedRoleEffectReservation(
        host_inputs=host_inputs, ledger=ledger, binding=binding,
        exposure=exposure, profile=profile,
        request_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
        _seal=_EFFECT_RESERVATION_SEAL,
    )


def recover_role_effect_reservation(
    execution: "SealedRoleExecution", *, host_inputs: TrustedExecutionHostInputs,
    ledger_path: Path, profile: ProviderProfile,
    request_or_attempt_identity: str, request_material: Mapping[str, object],
    preflight_material: Mapping[str, object],
) -> TrustedRoleEffectReservation:
    """Reconstruct one exact already-reserved effect without spending again.

    The caller must first authenticate a durable recovery route or an exact
    prepared, unclaimed physical correction. This function authenticates and
    reads that exact budget row; it neither admits a dispatch nor resets cost.
    """

    if not isinstance(ledger_path, Path):
        raise RoleCapabilityError("role budget ledger path is invalid")
    receipt, binding = derive_and_require_execution_for_effect(
        execution, host_inputs=host_inputs, profile=profile,
        request_or_attempt_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
    )
    if receipt.get("status") != AdvisoryRoleStatus.READY.value or execution.contract.admission is None:
        raise RoleCapabilityError("role effect admission is unavailable")
    exposure = execution.contract.profile.budget
    ledger = DurableRoleBudgetLedger(
        ledger_path, grant_receipt_digest=execution.contract.admission.grant.receipt_digest,
        execution_binding=binding, budget=exposure,
    )
    ledger.require_reserved(exposure=exposure)
    return TrustedRoleEffectReservation(
        host_inputs=host_inputs, ledger=ledger, binding=binding,
        exposure=exposure, profile=profile,
        request_identity=request_or_attempt_identity,
        request_material=request_material, preflight_material=preflight_material,
        _seal=_EFFECT_RESERVATION_SEAL,
    )

class SealedRoleRuntimeContext:
    """Factory-sealed authoritative Git/control context for advisory admission."""
    __slots__ = ("root", "common_dir", "binding", "git_entrypoint_control", "tree", "task_candidate_sha", "_seal")

    def __init__(self, root: Path, common_dir: Path, binding: CandidateBinding, git_entrypoint_control: GitEntrypointControl, tree: str, task_candidate_sha: str, *, _seal: object | None = None) -> None:
        if _seal is not _RUNTIME_SEAL:
            raise RoleCapabilityError("role runtime context must be resolved by authoritative control")
        self.root, self.common_dir, self.binding, self.git_entrypoint_control, self.tree, self.task_candidate_sha, self._seal = root, common_dir, binding, git_entrypoint_control, tree, task_candidate_sha, _seal


def resolve_sealed_role_runtime_context(**_caller_values: object) -> SealedRoleRuntimeContext:
    """Public callers cannot assemble trusted owner/deployment admission state."""

    raise RoleCapabilityError("role runtime context is available only from trusted composition")


def _resolve_sealed_role_runtime_context(*, root: Path, binding: CandidateBinding, git_entrypoint_control: GitEntrypointControl, task_candidate_sha: str) -> SealedRoleRuntimeContext:
    if type(binding) is not CandidateBinding or type(git_entrypoint_control) is not GitEntrypointControl or type(task_candidate_sha) is not str or _SHA.fullmatch(task_candidate_sha) is None or task_candidate_sha == binding.candidate_sha:
        raise RoleCapabilityError("role runtime control is invalid")
    try:
        authoritative = _validated_authoritative_repository(root, binding=binding, control=git_entrypoint_control)
        common_dir = Path(_git(authoritative, "rev-parse", "--git-common-dir").decode().strip()).resolve(strict=True)
        tree = _git(authoritative, "rev-parse", f"{binding.candidate_sha}^{{tree}}").decode().strip()
    except Exception as error:
        raise RoleCapabilityError("role runtime control is unavailable") from error
    return SealedRoleRuntimeContext(authoritative, common_dir, binding, git_entrypoint_control, tree, task_candidate_sha, _seal=_RUNTIME_SEAL)


class FileRoleAdmissionStore:
    """Read-only boundary for an owner/deployment-produced admission record."""
    def __init__(self, *, runtime: SealedRoleRuntimeContext, record_relative_path: str, store_identity: str) -> None:
        _require_digest(store_identity, "admission store identity")
        if type(runtime) is not SealedRoleRuntimeContext or runtime._seal is not _RUNTIME_SEAL:
            raise RoleCapabilityError("admission store lacks authoritative Git control")
        self._runtime = runtime; self._relative = _relative_path(record_relative_path); self.store_identity = store_identity

    def read(self) -> Mapping[str, object]:
        try:
            runtime = _resolve_sealed_role_runtime_context(root=self._runtime.root, binding=self._runtime.binding, git_entrypoint_control=self._runtime.git_entrypoint_control, task_candidate_sha=self._runtime.task_candidate_sha)
            if runtime.common_dir != self._runtime.common_dir or runtime.tree != self._runtime.tree or runtime.task_candidate_sha != self._runtime.task_candidate_sha:
                raise RoleCapabilityError("authoritative role runtime has drifted")
            raw = _git(runtime.root, "show", f"{runtime.binding.candidate_sha}:{self._relative}")
            parsed = json.loads(raw)
        except (OSError, ValueError, json.JSONDecodeError, RoleCapabilityError) as error:
            raise RoleCapabilityError("independent admission record is unavailable") from error
        if type(parsed) is not dict or _canonical_record(parsed) != raw:
            raise RoleCapabilityError("independent admission record is not canonical")
        return parsed


class VerifiedRoleAdmission:
    """A verified result; direct construction is intentionally rejected."""
    __slots__ = ("authority_receipt", "grant", "scope", "evidence_time", "revoked", "grant_reference", "_seal", "_locked")
    def __init__(self, authority_receipt: TrustedRoleAuthorityReceipt, grant: RoleCapabilityGrant, scope: RoleScope, evidence_time: int, revoked: bool, grant_reference: str, *, _seal: object | None = None) -> None:
        if _seal is not _ADMISSION_SEAL:
            raise RoleCapabilityError("verified admission must come from the independent store")
        object.__setattr__(self, "authority_receipt", authority_receipt); object.__setattr__(self, "grant", grant); object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "evidence_time", evidence_time); object.__setattr__(self, "revoked", revoked); object.__setattr__(self, "grant_reference", grant_reference); object.__setattr__(self, "_seal", _seal); object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise RoleCapabilityError("verified admission is immutable")
        object.__setattr__(self, name, value)


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


def read_verified_admission(*, expectation: RoleAdmissionExpectation, store: FileRoleAdmissionStore) -> tuple[VerifiedRoleAdmission, DedicatedRoleInstance]:
    """Authenticate a pre-existing pinned grant; never write or mint one."""
    evidence_time = int(time.time())
    if type(expectation) is not RoleAdmissionExpectation or type(store) is not FileRoleAdmissionStore or store.store_identity != expectation.store_identity:
        raise RoleCapabilityError("admission read-back context is invalid")
    record = store.read()
    if "sha256:" + hashlib.sha256(_canonical_record(record)).hexdigest() != expectation.record_digest:
        raise RoleCapabilityError("independent admission record digest has drifted")
    authority, instance, scope, grant, revoked, reference, revocation = _parse_record(record)
    if (reference != expectation.grant_reference or authority.receipt_digest != expectation.authority_receipt_digest or instance.receipt_digest != expectation.instance_receipt_digest or instance.candidate_sha != expectation.candidate_sha or instance.candidate_sha != store._runtime.task_candidate_sha or grant.authority_receipt_digest != authority.receipt_digest or grant.instance_receipt_digest != instance.receipt_digest or grant.scope_identity != scope.identity or scope.identity != expectation.scope_identity or scope.actions != expectation.actions or revocation != expectation.revocation_readback_digest or authority.revocation_identity != revocation or (instance.repository_identity, instance.task_identity, instance.state_identity, instance.deployment_identity, instance.host_identity, instance.authority_epoch) != (expectation.repository_identity, expectation.task_identity, expectation.state_identity, expectation.deployment_identity, expectation.host_identity, expectation.authority_epoch) or (authority.repository_identity, authority.task_identity, authority.deployment_identity, authority.authority_epoch) != (expectation.repository_identity, expectation.task_identity, expectation.deployment_identity, expectation.authority_epoch) or grant.issued_at != expectation.valid_from or grant.expires_at != expectation.valid_until or not grant.issued_at <= evidence_time <= grant.expires_at or evidence_time > authority.expires_at or revoked):
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


@dataclass(frozen=True)
class SealedRoleExecution:
    """Typed pre-effect capsule carried only to a matching production seam."""
    contract: AdvisoryRoleContract
    seam: RoleExecutionSeam
    store: FileRoleAdmissionStore
    expectation: RoleAdmissionExpectation
    guidance_evidence: ProviderGuidanceEvidence
    execution_binding: ExecutionInstanceBinding
    _seal: object | None = None

    def __post_init__(self) -> None:
        if self._seal is not _EXECUTION_SEAL or type(self.execution_binding) is not ExecutionInstanceBinding:
            raise RoleCapabilityError("sealed role execution is available only from trusted composition")

    def require_before_effect(self, *, expected_execution: ExecutionInstanceBinding | None = None) -> dict[str, object]:
        """Re-read admission before an effect and reject every binding drift.

        ``expected_execution`` is supplied by a production wrapper when it has
        independently derived the one attempt it is about to perform.  The
        capsule is never a wildcard: omitting that extra comparison still
        verifies the sealed binding carried by the composition root.
        """
        expected_views = {RoleExecutionSeam.WORKER: GuidanceView.WORKER, RoleExecutionSeam.SUPERVISOR: GuidanceView.SUPERVISOR, RoleExecutionSeam.DEPENDENCY_REVIEW: GuidanceView.DEPENDENCY_REVIEW, RoleExecutionSeam.RECOVERY_ADVISOR: GuidanceView.RECOVERY_ADVISOR, RoleExecutionSeam.OWNER_INTENT_INTERPRETER: GuidanceView.OWNER_INTENT_INTERPRETER}
        runtime = self.store._runtime
        binding = self.execution_binding
        if (self.guidance_evidence.view is not expected_views[self.seam]
                or self.guidance_evidence.guidance_receipt_digest != self.contract.guidance.receipt_digest
                or self.guidance_evidence.accepted_main_sha != runtime.binding.candidate_sha
                or self.guidance_evidence.task_candidate_sha != runtime.task_candidate_sha
                or self.expectation.candidate_sha != runtime.task_candidate_sha
                or (binding.repository_identity, binding.task_identity, binding.candidate_sha,
                    binding.instance_receipt_digest, binding.host_identity,
                    binding.deployment_identity, binding.authority_epoch,
                    binding.replacement_fence, binding.role,
                    binding.provider_profile)
                != (self.expectation.repository_identity, self.expectation.task_identity,
                    runtime.task_candidate_sha, self.contract.instance.receipt_digest,
                    self.expectation.host_identity, self.expectation.deployment_identity,
                    self.expectation.authority_epoch, self.contract.instance.replacement_fence,
                    self.contract.profile.role, self.contract.profile.provider_profile)
                or (expected_execution is not None and (
                    type(expected_execution) is not ExecutionInstanceBinding
                    or expected_execution.digest != binding.digest))):
            raise RoleCapabilityError("provider guidance evidence does not match the role seam")
        return require_verified_role_admission(self.contract, self.seam, store=self.store, expectation=self.expectation)


def _compose_sealed_role_execution(
    contract: AdvisoryRoleContract,
    seam: RoleExecutionSeam,
    store: FileRoleAdmissionStore,
    expectation: RoleAdmissionExpectation,
    guidance_evidence: ProviderGuidanceEvidence,
    execution_binding: ExecutionInstanceBinding,
) -> SealedRoleExecution:
    """Composition-root-only constructor; production defaults install none."""

    if (type(contract) is not AdvisoryRoleContract or type(seam) is not RoleExecutionSeam
            or type(store) is not FileRoleAdmissionStore or type(expectation) is not RoleAdmissionExpectation
            or type(guidance_evidence) is not ProviderGuidanceEvidence
            or type(execution_binding) is not ExecutionInstanceBinding):
        raise RoleCapabilityError("trusted role composition is invalid")
    return SealedRoleExecution(contract, seam, store, expectation, guidance_evidence, execution_binding, _seal=_EXECUTION_SEAL)


def require_execution_for_profile(
    execution: SealedRoleExecution, profile: ProviderProfile,
) -> dict[str, object]:
    """Consume one sealed admission only at its exact provider boundary.

    Callers must pass the profile they are about to hand to the native
    backend.  This prevents a capsule from being replayed through an adapter
    whose otherwise-qualified profile is different from the one sealed in the
    execution binding.  The binding is deliberately passed back as the
    expected value, rather than treating its existence as sufficient.
    """

    if (type(execution) is not SealedRoleExecution
            or type(profile) is not ProviderProfile
            or execution.execution_binding.provider_profile != profile):
        raise RoleCapabilityError("sealed execution profile does not match the provider effect")
    return execution.require_before_effect(expected_execution=execution.execution_binding)


def require_worker_tool_capability(
    admission_receipt: Mapping[str, object], *, tool: object,
) -> None:
    """Map the only Worker tool surface to its concrete admitted action.

    Importing ``WorkerTool`` here would create a policy/adapter cycle, so the
    public enum value is checked structurally.  Unknown values, including
    platform-invalid spellings that never reach the native request parser,
    fail closed.
    """

    value = getattr(tool, "value", None)
    if (not isinstance(admission_receipt, Mapping)
            or value not in {"workspace-read", "workspace-write", "validation-execute"}
            or RoleCapability.BOUNDED_CODING.value not in admission_receipt.get("capabilities", ())):
        raise RoleCapabilityError("Worker tool action is not granted")


def render_grant_draft(*, instance: DedicatedRoleInstance, scope: RoleScope, expectation: RoleAdmissionExpectation, owner_readable_reason: str, budget: RoleBudget, valid_from: int, valid_until: int, revocation_readback_digest: str) -> dict[str, object]:
    if type(instance) is not DedicatedRoleInstance or type(scope) is not RoleScope or type(expectation) is not RoleAdmissionExpectation or type(owner_readable_reason) is not str or not owner_readable_reason.strip():
        raise RoleCapabilityError("grant draft is invalid")
    if (type(budget) is not RoleBudget or type(valid_from) is not int or type(valid_until) is not int or valid_until < valid_from or _DIGEST.fullmatch(revocation_readback_digest) is None
            or (valid_from, valid_until, revocation_readback_digest) != (expectation.valid_from, expectation.valid_until, expectation.revocation_readback_digest)
            or instance.receipt_digest != expectation.instance_receipt_digest or instance.candidate_sha != expectation.candidate_sha
            or (instance.repository_identity, instance.task_identity, instance.state_identity, instance.deployment_identity, instance.host_identity, instance.authority_epoch) != (expectation.repository_identity, expectation.task_identity, expectation.state_identity, expectation.deployment_identity, expectation.host_identity, expectation.authority_epoch)
            or scope.identity != expectation.scope_identity or scope.actions != expectation.actions):
        raise RoleCapabilityError("grant draft bindings are invalid")
    return {"schema": "roundwright-advisory-grant-draft/v3", "role": instance.role.value, "task": instance.task_identity, "instance": instance.instance_identity, "repository": instance.repository_identity, "state": instance.state_identity, "deployment": instance.deployment_identity, "host": instance.host_identity, "epoch": instance.authority_epoch, "fence": instance.replacement_fence, "candidate": instance.candidate_sha, "profile": instance.profile_identity, "guidance": instance.guidance_receipt_digest, "requested_actions": sorted(item.value for item in scope.actions), "scope": [{"kind": item.kind.value, "root": item.root_identity, "value": item.value} for item in scope.descriptors], "budget": {"max_calls": budget.max_calls, "max_duration_seconds": budget.max_duration_seconds, "max_tokens": budget.max_tokens}, "validity": {"not_before": valid_from, "not_after": valid_until}, "authority": expectation.authority_receipt_digest, "grant": expectation.grant_reference, "store": expectation.store_identity, "record": expectation.record_digest, "revocation_readback": revocation_readback_digest, "evidence": "independent owner/deployment record required", "reason": owner_readable_reason.strip(), "owner_action": "Select the listed existing grant reference; do not calculate replacement identifiers."}


def require_verified_role_admission(contract: AdvisoryRoleContract, seam: RoleExecutionSeam, *, store: FileRoleAdmissionStore, expectation: RoleAdmissionExpectation) -> dict[str, object]:
    if type(contract) is not AdvisoryRoleContract or type(seam) is not RoleExecutionSeam:
        raise RoleCapabilityError("role execution seam is invalid")
    allowed = {RoleExecutionSeam.WORKER: AdvisoryRole.WORKER, RoleExecutionSeam.SUPERVISOR: AdvisoryRole.SUPERVISOR, RoleExecutionSeam.DEPENDENCY_REVIEW: AdvisoryRole.DEPENDENCY_REVIEW, RoleExecutionSeam.RECOVERY_ADVISOR: AdvisoryRole.RECOVERY_ADVISOR, RoleExecutionSeam.OWNER_INTENT_INTERPRETER: AdvisoryRole.OWNER_INTENT_INTERPRETER}
    if seam not in allowed or allowed[seam] is not contract.profile.role:
        raise RoleCapabilityError("role is not admitted for this execution seam")
    fresh, instance = read_verified_admission(expectation=expectation, store=store)
    if (type(contract.admission) is not VerifiedRoleAdmission
            or contract.admission._seal is not _ADMISSION_SEAL
            or instance != contract.instance
            or fresh.grant.receipt_digest != contract.admission.grant.receipt_digest):
        raise RoleCapabilityError("role admission changed after contract construction")
    receipt = contract.public_receipt()
    if receipt["status"] != AdvisoryRoleStatus.READY.value:
        raise RoleCapabilityError("advisory role is disabled without verified admission")
    # READY is an admission state, not a wildcard.  Each executable seam must
    # consume the concrete capability it is about to exercise; a grant for an
    # unrelated subset cannot open a provider or local-effect path.
    seam_capability = _SEAM_CAPABILITIES[seam]
    if seam_capability not in contract.profile.capabilities:
        raise RoleCapabilityError("role profile does not support its execution seam")
    assert contract.admission is not None
    contract.admission.scope.require(seam_capability)
    return receipt


def default_advisory_profiles(*, recovery_advisor: ProviderProfile, owner_intent_interpreter: ProviderProfile) -> tuple[RoleCapabilityProfile, RoleCapabilityProfile]:
    mapping = reviewed_sdk_mapping(); shared = frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE})
    return (RoleCapabilityProfile(AdvisoryRole.RECOVERY_ADVISOR, recovery_advisor, shared | {RoleCapability.READ_ONLY_REVIEW}, RoleBudget(1, 60, 4000), mapping), RoleCapabilityProfile(AdvisoryRole.OWNER_INTENT_INTERPRETER, owner_intent_interpreter, shared | {RoleCapability.OWNER_COMMAND_INTERPRETATION}, RoleBudget(1, 60, 4000), mapping))


def require_non_dispatching_production_entrypoint(contract: AdvisoryRoleContract, *, store: FileRoleAdmissionStore, expectation: RoleAdmissionExpectation) -> dict[str, object]:
    return require_verified_role_admission(contract, RoleExecutionSeam.RECOVERY_ADVISOR, store=store, expectation=expectation)


def require_non_dispatching_owner_intent_entrypoint(contract: AdvisoryRoleContract, *, store: FileRoleAdmissionStore, expectation: RoleAdmissionExpectation) -> dict[str, object]:
    """Typed, read-only boundary retained until an Interpreter provider exists."""
    return require_verified_role_admission(contract, RoleExecutionSeam.OWNER_INTENT_INTERPRETER, store=store, expectation=expectation)
