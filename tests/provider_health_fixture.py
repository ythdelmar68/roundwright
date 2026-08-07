"""Canonical, hermetic provider-health evidence for dispatch integration tests."""

from __future__ import annotations

from dataclasses import replace

from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import (
    CodexCapability,
    CodexHealthContract,
    CodexRuntimeAudit,
    HealthState,
    ProviderHealthAuditIdentity,
    ProviderHealthObservation,
    ProviderHealthReceipt,
    profile_fingerprint,
)
from roundwright.provider_recovery import ProviderRole, RecoveryContext
from roundwright.runtime_binding import RuntimeBinding
from roundwright.state import TaskIdentity


WORKER_PROFILE = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
SUPERVISOR_PROFILES = (
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.LOW),
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.MEDIUM),
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.HIGH),
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH),
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.MAX),
    ProviderProfile("gpt-5.6-sol", ReasoningEffort.ULTRA),
)
_PROFILES = (WORKER_PROFILE, *SUPERVISOR_PROFILES)
_BY_IDENTITY = {profile_fingerprint(profile): profile for profile in _PROFILES}


def runtime_binding(
    supervisor_count: int = 3,
    *,
    complete_rounds: int | None = None,
    max_rounds: int | None = None,
    final_policy: str | None = None,
    policy_digest: str | None = None,
) -> RuntimeBinding:
    """Return a binding whose profile identities have reconstructable profiles."""

    supervisors = tuple(profile_fingerprint(profile) for profile in SUPERVISOR_PROFILES[:supervisor_count])
    values: tuple[object, ...] = ()
    if complete_rounds is not None:
        assert max_rounds is not None and final_policy is not None and policy_digest is not None
        values = (complete_rounds, max_rounds, supervisor_count, final_policy, policy_digest)
    return RuntimeBinding(
        "roundwright-runtime/v1", "sha256:" + "a" * 64,
        profile_fingerprint(WORKER_PROFILE), supervisors, *values,
    )


def provider_context(
    context: RecoveryContext,
    identity: TaskIdentity,
    role: ProviderRole,
    *,
    selected_profile_identity: str | None = None,
) -> RecoveryContext:
    """Attach one fresh exact receipt for the role and selected profile only."""

    profile_identity = selected_profile_identity
    if profile_identity is None:
        profile_identity = (
            context.runtime_binding.supervisor_profile_identities[0]
            if role is ProviderRole.SUPERVISOR
            else context.runtime_binding.worker_profile_identity
        )
    profile = _BY_IDENTITY[profile_identity]
    audit = CodexRuntimeAudit(
        "1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)
    )
    contract = CodexHealthContract(audit.sdk_version, audit.runtime_version, identity.base_sha)
    observation = ProviderHealthObservation(
        role, profile_identity, contract.fingerprint, audit.fingerprint,
        HealthState.READY, None, 0, 2_000_000_000, 1,
    )
    ordinal = 0 if role is ProviderRole.PLANNING else 1 if role is ProviderRole.WORKER else 2 + context.runtime_binding.supervisor_profile_identities.index(profile_identity)
    receipt = ProviderHealthReceipt(
        identity.base_sha, context.candidate_sha, "test-provider-health", ordinal,
        context.runtime_binding, role, profile_identity, observation,
        ProviderHealthAuditIdentity(audit, profile),
    )
    return replace(
        context,
        health_contract_commit=identity.base_sha,
        shadow_case_id="test-provider-health",
        health_receipt=receipt,
    )
