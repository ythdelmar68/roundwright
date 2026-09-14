"""Hermetic owner-record fixtures for production role-admission tests.

The helper deliberately creates a real temporary Git canonical owner record and
returns only the verified capsule read from it.  Tests cannot mint a ready
capsule from caller-owned dataclasses.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import subprocess
import tempfile
import time
from pathlib import Path

from roundwright.configuration import ProviderProfile
from roundwright.dependency_policy import (
    BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy,
    DependencyComponent, DependencyExecutionControl, DependencyPolicy,
    ObservedDependency, PolicyTransition, PolicyTransitionKind,
    TrustedDependencyAdmission, VersionRange,
)
from roundwright.git_identity import GitEntrypointControl
from roundwright.role_capability_policy import (
    AdvisoryRole, AdvisoryRoleContract, AuthoritativeGuidanceExpectation,
    DedicatedRoleInstance, FileRoleAdmissionStore, GuidanceView,
    ExecutionInstanceBinding, ProviderGuidanceEvidence, RoleAdmissionExpectation, RoleBudget,
    RoleCapability, RoleCapabilityGrant, RoleCapabilityProfile,
    RoleExecutionSeam, RoleScope, SealedRoleExecution,
    TrustedRoleAuthorityReceipt, read_verified_admission,
    _compose_sealed_role_execution, _resolve_sealed_role_runtime_context, resolve_authoritative_guidance,
    reviewed_sdk_mapping,
)


_TEMPS: list[tempfile.TemporaryDirectory[str]] = []
_EXECUTIONS: dict[tuple[AdvisoryRole, ProviderProfile], SealedRoleExecution] = {}
_EXPECTED_EXECUTIONS: dict[tuple[AdvisoryRole, ProviderProfile], ExecutionInstanceBinding] = {}


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _cleanup() -> None:
    for temporary in _TEMPS:
        temporary.cleanup()


atexit.register(_cleanup)


def sealed_execution(role: AdvisoryRole, profile: ProviderProfile) -> SealedRoleExecution:
    """Return a verified, role-specific capsule backed by a temporary Git repo."""

    cached = _EXECUTIONS.get((role, profile))
    if cached is not None:
        return cached

    temporary = tempfile.TemporaryDirectory()
    _TEMPS.append(temporary)
    root = Path(temporary.name)

    def git(*arguments: str) -> str:
        return subprocess.run(
            ("git", "-C", str(root), *arguments), check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        ).stdout.strip()

    root.joinpath("AGENTS.md").write_text("test-owned guidance", encoding="utf-8")
    root.joinpath("src").mkdir()
    root.joinpath("src", "task.py").write_text("# fixture\n", encoding="utf-8")
    git("init", "-q")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Role Admission Test")
    git("add", ".")
    git("commit", "-qm", "fixture")
    git("branch", "-M", "main")
    revision = git("rev-parse", "HEAD")
    git("remote", "add", "origin", "https://github.com/ythdelmar68/roundwright.git")
    git("update-ref", "refs/remotes/origin/main", revision)

    repository_identity = _digest("fixture-repository")
    task_candidate = "a" * 40

    def control(current_revision: str) -> tuple[CandidateBinding, GitEntrypointControl]:
        binding = CandidateBinding("ythdelmar68/roundwright", "issue-136", current_revision)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", _digest("package-artifact"), _digest("package-executable")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-scm/git", _digest("git-artifact"), _digest("git-executable")),
        )
        policy = DependencyPolicy(binding, _digest("policy-source"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=_digest("reviewer"), authority_digest=_digest("authority"))
        policy = DependencyPolicy(binding, _digest("policy-source"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 100, policy.policy_digest) for item in components)
        return binding, GitEntrypointControl(binding, DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, _digest("reviewer"), _digest("authority"))), 100)

    binding, entrypoint_control = control(revision)
    tree = git("rev-parse", "HEAD^{tree}")
    runtime = _resolve_sealed_role_runtime_context(
        root=root, binding=binding, git_entrypoint_control=entrypoint_control,
        task_candidate_sha=task_candidate,
    )
    view = GuidanceView(role.value)
    guidance = resolve_authoritative_guidance(
        expectation=AuthoritativeGuidanceExpectation(
            repository_identity, root, revision,
            _digest({"tree": tree, "repository": repository_identity}),
        ),
        view=view, task_relative_path="src/task.py", runtime=runtime,
    )
    capabilities = frozenset(RoleCapability)
    role_profile = RoleCapabilityProfile(role, profile, capabilities, RoleBudget(1, 60, 4000), reviewed_sdk_mapping())
    now = int(time.time())
    instance = DedicatedRoleInstance(
        f"{role.value}-fixture", role, role_profile.profile_identity,
        guidance.receipt_digest, repository_identity, "task-136",
        _digest("state"), _digest("deployment"), _digest("host"), 1,
        "fixture-generation", task_candidate,
    )
    scope = RoleScope(capabilities, ())
    authority = TrustedRoleAuthorityReceipt(
        repository_identity, "task-136", _digest("deployment"), 1,
        _digest("issuer"), now + 3600, _digest("revocation"),
    )
    grant = RoleCapabilityGrant(authority.receipt_digest, instance.receipt_digest, scope.identity, now - 1, now + 3600)
    record = {
        "schema": "roundwright-independent-role-admission/v1", "grant_reference": "fixture-grant",
        "authority": authority.__dict__, "instance": instance.__dict__,
        "scope": {"actions": sorted(item.value for item in scope.actions), "descriptors": []},
        "grant": grant.__dict__, "revoked": False,
        "revocation_readback_digest": _digest("revocation"),
    }
    root.joinpath("admission.json").write_bytes(_canonical(record))
    git("add", "admission.json")
    git("commit", "-qm", "admission")
    revision = git("rev-parse", "HEAD")
    git("update-ref", "refs/remotes/origin/main", revision)
    binding, entrypoint_control = control(revision)
    final_runtime = _resolve_sealed_role_runtime_context(
        root=root, binding=binding, git_entrypoint_control=entrypoint_control,
        task_candidate_sha=task_candidate,
    )
    expectation = RoleAdmissionExpectation(
        _digest("admission-store"), "sha256:" + hashlib.sha256(_canonical(record)).hexdigest(),
        "fixture-grant", authority.receipt_digest, instance.receipt_digest,
        repository_identity, "task-136", _digest("state"), _digest("deployment"),
        _digest("host"), 1, task_candidate, scope.identity, scope.actions,
        now - 1, now + 3600, _digest("revocation"),
    )
    store = FileRoleAdmissionStore(runtime=final_runtime, record_relative_path="admission.json", store_identity=_digest("admission-store"))
    admission, verified_instance = read_verified_admission(expectation=expectation, store=store)
    contract = AdvisoryRoleContract(role_profile, guidance, verified_instance, admission)
    expected_execution = ExecutionInstanceBinding(
        repository_identity, "task-136", task_candidate, instance.receipt_digest,
        _digest("host"), _digest("deployment"), 1, "fixture-generation", role,
        role_profile.provider_profile, "fixture-execution", _digest("fixture-preflight"),
    )
    execution = _compose_sealed_role_execution(
        contract, RoleExecutionSeam(role.value), store, expectation,
        ProviderGuidanceEvidence(view, _digest("provider-cwd"), True, _digest("injected-guidance"), guidance.receipt_digest, binding.candidate_sha, task_candidate),
        expected_execution,
    )
    _EXECUTIONS[(role, profile)] = execution
    _EXPECTED_EXECUTIONS[(role, profile)] = expected_execution
    return execution


def independent_execution(role: AdvisoryRole, profile: ProviderProfile) -> ExecutionInstanceBinding:
    """Reconstruct the fixture host expectation without reading a capsule."""

    sealed_execution(role, profile)
    expected = _EXPECTED_EXECUTIONS[(role, profile)]
    return ExecutionInstanceBinding(
        expected.repository_identity, expected.task_identity, expected.candidate_sha,
        expected.instance_receipt_digest, expected.host_identity,
        expected.deployment_identity, expected.authority_epoch,
        expected.replacement_fence, expected.role, expected.provider_profile,
        expected.execution_identity, expected.preflight_identity,
    )
