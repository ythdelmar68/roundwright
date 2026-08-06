"""Hermetic coverage for the Codex-only provider qualification boundary."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace

from pathlib import Path

from roundwright.configuration import ProviderProfile, ReasoningEffort, load_configuration
from roundwright.provider_health import (
    CodexAdapterError, CodexCapability, CodexFailure, CodexHealthContract,
    CodexProviderHealth, CodexRuntimeAudit, CredentialIsolationEvidence, HealthState, ProbeOutcome,
    ProviderHealthCache, ProviderHealthError, ProviderQualificationReport, ReadOnlyQualification,
    ProviderHealthReceipt,
    ProviderHealthAuditIdentity,
    RoleBoundCredentialIdentity,
    RoleBoundCodexCredentialStore, RoleBoundCodexChannel,
    profile_fingerprint, render_health_diagnostic,
)
from roundwright.provider_recovery import ProviderRole
from roundwright.runtime_binding import RuntimeBinding


class FakeChannel:
    def __init__(self, audit, outcomes=()):
        self.audit = audit
        self.outcomes = list(outcomes)
        self.requests = []
        self.audit_calls = 0
        self.identity = None
        self.identity_response = None
        self.identity_reads = 0

    def credential_identity(self):
        self.identity_reads += 1
        value = self.identity if self.identity_response is None else self.identity_response
        if isinstance(value, Exception): raise value
        return value

    def audit_runtime(self):
        self.audit_calls += 1
        if isinstance(self.audit, Exception):
            raise self.audit
        return self.audit

    def qualify_read_only(self, request):
        self.requests.append(request)
        result = self.outcomes.pop(0) if self.outcomes else ProbeOutcome(True)
        if isinstance(result, Exception):
            raise result
        return result


class FakeStore:
    def __init__(self, channel, isolation=None):
        self.channel = channel
        self.isolation = isolation
        self.channel_identity = None
        self.roles = []
        self.store_response = None
        self.isolation_response = None
        self.store_reads = self.isolation_reads = 0

    def open_role_channel(self, role):
        self.roles.append(role)
        return self.channel

    def credential_isolation(self, role):
        self.isolation_reads += 1
        if isinstance(self.isolation_response, Exception): raise self.isolation_response
        if isinstance(self.isolation, Exception):
            raise self.isolation
        identity = RoleBoundCredentialIdentity("sha256:" + "a" * 64, role, "sha256:" + "b" * 64, tuple(item for item in ProviderRole if item is not role))
        self.channel.identity = identity if self.channel_identity is None else self.channel_identity
        return self.isolation_response if self.isolation_response is not None else (CredentialIsolationEvidence(role, identity) if self.isolation is None else self.isolation)

    def store_identity(self):
        self.store_reads += 1
        if isinstance(self.store_response, Exception): raise self.store_response
        return "sha256:" + "a" * 64 if self.store_response is None else self.store_response


class FakeNativeChannel:
    def __init__(self, audit): self.audit, self.audit_calls, self.requests = audit, 0, []
    def __repr__(self): return "token C:/private/path raw-payload"
    def audit_runtime(self): self.audit_calls += 1; return self.audit
    def qualify_read_only(self, request): self.requests.append(request); return ProbeOutcome(True)


class ProviderHealthTests(unittest.TestCase):
    def setUp(self):
        self.profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        self.audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability("gpt-5.6-terra", "high"),))
        self.contract = CodexHealthContract("1.2.3", "4.5.6", "a" * 40)

    def binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            return load_configuration(cwd=Path(temporary), environment={}).pin().runtime_binding()

    def service(self, outcomes=(), audit=None, cache=None, isolation=None):
        self.channel = FakeChannel(self.audit if audit is None else audit, outcomes)
        self.store = FakeStore(self.channel, isolation)
        return CodexProviderHealth(self.store, self.contract, cache=cache)

    def test_qualifies_exact_audited_profile_with_a_single_content_free_probe(self):
        result = self.service().qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual((result.state, result.failure, result.attempts), (HealthState.READY, None, 1))
        self.assertEqual(self.store.roles, [ProviderRole.WORKER])
        self.assertEqual(self.channel.requests, [ReadOnlyQualification(ProviderRole.WORKER, "gpt-5.6-terra", "high")])
        self.assertEqual(set(result.evidence()), {"role", "profile_identity", "health_contract_identity", "runtime_fingerprint", "state", "failure", "observed_at", "fresh_until", "attempts"})

    def test_version_and_model_mismatch_block_only_the_qualified_profile(self):
        incompatible = self.service(audit=CodexRuntimeAudit("1.2.4", "4.5.6", self.audit.capabilities)).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(incompatible.failure, CodexFailure.SDK_INCOMPATIBLE)
        other = ProviderProfile("gpt-5.6-sol", ReasoningEffort.XHIGH)
        unavailable = self.service().qualify(ProviderRole.SUPERVISOR, other, freshness_seconds=30, now=100)
        self.assertEqual(unavailable.failure, CodexFailure.MODEL_UNAVAILABLE)
        self.assertEqual(self.channel.requests, [])

    def test_only_typed_retryable_failures_retry_and_never_exceed_the_bound(self):
        service = self.service((
            ProbeOutcome(False, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE),
            ProbeOutcome(False, CodexFailure.QUOTA_OR_RATE_LIMIT),
            ProbeOutcome(True),
        ))
        result = service.qualify(ProviderRole.SUPERVISOR, self.profile, freshness_seconds=30, max_attempts=3, now=100)
        self.assertEqual((result.state, result.attempts), (HealthState.READY, 3))
        denied = self.service((ProbeOutcome(False, CodexFailure.SANDBOX_OR_APPROVAL_DENIED),)).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, max_attempts=3, now=100)
        self.assertEqual((denied.failure, denied.attempts), (CodexFailure.SANDBOX_OR_APPROVAL_DENIED, 1))

    def test_cache_has_an_explicit_boundary_and_force_refresh_is_bounded(self):
        cache = ProviderHealthCache()
        service = self.service(cache=cache)
        first = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=10, now=100)
        self.channel.outcomes = [ProbeOutcome(False, CodexFailure.AUTH_MISSING)]
        self.assertEqual(service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=10, now=109), first)
        refreshed = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=10, force_refresh=True, now=109)
        self.assertEqual(refreshed.failure, CodexFailure.AUTH_MISSING)
        self.assertEqual(len(self.channel.requests), 2)

    def test_cache_and_evidence_are_bound_to_the_exact_health_contract(self):
        cache = ProviderHealthCache()
        first_service = self.service(cache=cache)
        first = first_service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        changed_contract = CodexHealthContract("9.9.9", "9.9.9", "b" * 40)
        changed_channel = FakeChannel(self.audit, (ProbeOutcome(True),))
        changed_service = CodexProviderHealth(FakeStore(changed_channel), changed_contract, cache=cache)
        changed = changed_service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=101)
        self.assertIsNot(first, changed)
        self.assertEqual(changed.failure, CodexFailure.SDK_INCOMPATIBLE)
        self.assertNotEqual(first.health_contract_identity, changed.health_contract_identity)
        replayed = first.evidence()
        replayed["health_contract_identity"] = changed.health_contract_identity
        self.assertNotEqual(type(first).from_evidence(replayed).health_contract_identity, first.health_contract_identity)
        with self.assertRaises(ProviderHealthError):
            ProviderQualificationReport(changed.health_contract_identity, self.binding(), ((0, first.role, first.profile_identity),), (first,))

    def test_configuration_preflight_and_replay_keep_profile_blockers_independent(self):
        with tempfile.TemporaryDirectory() as temporary:
            configuration = load_configuration(cwd=Path(temporary), environment={})
        capability_audit = CodexRuntimeAudit(
            "1.2.3", "4.5.6", (
                CodexCapability("gpt-5.6-terra", "high"),
                CodexCapability("gpt-5.6-sol", "xhigh"),
            ),
        )
        service = self.service((
            ProbeOutcome(True), ProbeOutcome(True),
            ProbeOutcome(False, CodexFailure.AUTH_MISSING), ProbeOutcome(True),
        ), audit=capability_audit)
        report = service.qualify_configuration(configuration, freshness_seconds=30, now=100)
        self.assertFalse(report.ready)
        self.assertFalse(report.ready_at(100))
        worker = configuration.worker.value
        self.assertIsNone(report.blocker_for(ProviderRole.WORKER, worker, now=100))
        profiles = (configuration.worker.value, configuration.worker.value, *configuration.supervisor_attempt_profiles.value)
        blocked_index = next(index for index, observation in enumerate(report.observations) if observation.failure is not None)
        blocked = report.observations[blocked_index]
        self.assertEqual(report.blocker_for(blocked.role, profiles[blocked_index], now=100, ordinal=blocked_index), blocked.failure)
        replayed = type(report.observations[0]).from_evidence(report.observations[0].evidence())
        self.assertEqual(replayed, report.observations[0])
        self.assertIsNone(service.qualify(ProviderRole.WORKER, worker, freshness_seconds=30, now=101).failure)

    def test_configuration_report_requires_complete_ordered_dispatch_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            configuration = load_configuration(cwd=Path(temporary), environment={})
        profiles = (configuration.worker.value, *configuration.supervisor_attempt_profiles.value)
        audit = CodexRuntimeAudit("1.2.3", "4.5.6", tuple(CodexCapability(model, effort) for model, effort in dict.fromkeys((profile.model, profile.reasoning_effort.value) for profile in profiles)))
        report = self.service(audit=audit).qualify_configuration(configuration, freshness_seconds=30, now=100)
        self.assertEqual([role for _, role, _ in report.selections[:2]], [ProviderRole.PLANNING, ProviderRole.WORKER])
        self.assertTrue(report.ready_at(100))
        for selections, observations in (
            (report.selections[:-1], report.observations[:-1]),
            (report.selections + (report.selections[0],), report.observations + (report.observations[0],)),
            (tuple(reversed(report.selections)), tuple(reversed(report.observations))),
        ):
            with self.assertRaises(ProviderHealthError):
                ProviderQualificationReport(report.health_contract_identity, report.configuration, selections, observations)

    def test_stale_report_is_not_ready_and_blocks_only_the_stale_profile(self):
        service = self.service()
        planning = service.qualify(ProviderRole.PLANNING, self.profile, freshness_seconds=30, now=100)
        worker = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        supervisor = service.qualify(ProviderRole.SUPERVISOR, self.profile, freshness_seconds=30, now=110)
        binding = RuntimeBinding("roundwright-runtime/v1", "sha256:" + "a" * 64, worker.profile_identity, (worker.profile_identity,))
        report = ProviderQualificationReport(self.contract.fingerprint, binding, (
            (0, planning.role, planning.profile_identity), (1, worker.role, worker.profile_identity), (2, supervisor.role, supervisor.profile_identity),
        ), (planning, worker, supervisor))
        self.assertTrue(report.ready_at(129))
        self.assertFalse(report.ready_at(130))
        self.assertEqual(report.blocker_for(ProviderRole.WORKER, self.profile, now=130), CodexFailure.UNKNOWN)
        self.assertIsNone(report.blocker_for(ProviderRole.SUPERVISOR, self.profile, now=130, ordinal=2))

    def test_canonical_receipt_rejects_digest_and_dispatch_identity_substitution(self):
        binding = load_configuration(cwd=Path(tempfile.gettempdir()), environment={}).pin().runtime_binding()
        observation = self.service().qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        receipt = ProviderHealthReceipt("a" * 40, None, "case-42", 0, binding, ProviderRole.WORKER, observation.profile_identity, observation, ProviderHealthAuditIdentity(self.audit, self.profile))
        receipt.authorize(binding, ProviderRole.WORKER, observation.profile_identity, contract_commit="a" * 40, candidate_sha=None, case_id="case-42", now=101)
        self.assertEqual(ProviderHealthReceipt.from_evidence(receipt.evidence()), receipt)
        tampered = receipt.evidence()
        tampered["case_id"] = "case-43"
        with self.assertRaises(ProviderHealthError):
            ProviderHealthReceipt.from_evidence(tampered)
        with self.assertRaises(ProviderHealthError):
            receipt.authorize(binding, ProviderRole.WORKER, observation.profile_identity, contract_commit="b" * 40, candidate_sha=None, case_id="case-42", now=101)
        with self.assertRaises(ProviderHealthError):
            ProviderHealthReceipt("a" * 40, None, "case-42", 0, binding, ProviderRole.WORKER, observation.profile_identity, observation, ProviderHealthAuditIdentity(self.audit, self.profile), receipt_digest="sha256:" + "0" * 64)
        for field, value in (("review_complete_rounds", 99), ("review_max_rounds", 99), ("review_max_supervisor_attempts_per_round", 99), ("review_on_final_findings", "drift"), ("review_policy_digest", "0" * 64)):
            drifted = replace(binding)
            object.__setattr__(drifted, field, value)
            with self.subTest(field=field), self.assertRaises(ProviderHealthError):
                receipt.authorize(drifted, ProviderRole.WORKER, observation.profile_identity, contract_commit="a" * 40, candidate_sha=None, case_id="case-42", now=101)

    def test_untyped_exception_and_malformed_response_never_use_message_text_for_classification(self):
        unknown = self.service((RuntimeError("token at C:/private/path is denied"),)).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(unknown.failure, CodexFailure.UNKNOWN)
        malformed = self.service((object(),)).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(malformed.failure, CodexFailure.MALFORMED_RESPONSE)
        self.assertNotIn("private", render_health_diagnostic(unknown))

    def test_role_credential_projection_has_no_secret_access_and_diagnostics_are_redacted(self):
        service = self.service((ProbeOutcome(False, CodexFailure.AUTH_EXPIRED),))
        isolation = service.credential_isolation(ProviderRole.WORKER)
        self.assertTrue(all(value is False for name, value in vars(isolation).items() if name not in {"role", "credential_identity"}))
        result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        diagnostic = render_health_diagnostic(result)
        self.assertIn("authentication renewal required", diagnostic)
        for forbidden in ("token", "path", "payload", "gpt-5.6-terra", profile_fingerprint(self.profile)):
            self.assertNotIn(forbidden, diagnostic)

    def test_missing_or_wrong_role_credential_evidence_blocks_before_the_adapter_is_opened(self):
        blocked = self.service(isolation=RuntimeError("secret path unavailable")).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(blocked.failure, CodexFailure.MALFORMED_RESPONSE)
        self.assertEqual(self.store.roles, [])
        with self.assertRaises(ProviderHealthError):
            self.service(isolation=CredentialIsolationEvidence(ProviderRole.SUPERVISOR, RoleBoundCredentialIdentity("sha256:" + "a" * 64, ProviderRole.SUPERVISOR, "sha256:" + "b" * 64, tuple(item for item in ProviderRole if item is not ProviderRole.SUPERVISOR)))).credential_isolation(ProviderRole.WORKER)

    def test_rejects_invalid_inputs_and_typed_adapter_failures_stay_classified(self):
        with self.assertRaises(ProviderHealthError):
            CodexRuntimeAudit("bad", "4.5.6", self.audit.capabilities)
        with self.assertRaises(ProviderHealthError):
            ProbeOutcome(True, CodexFailure.UNKNOWN)
        with self.assertRaises(ProviderHealthError):
            self.service().qualify(ProviderRole.WORKER, self.profile, freshness_seconds=0, now=100)
        result = self.service((CodexAdapterError(CodexFailure.AUTH_MISSING),)).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(result.failure, CodexFailure.AUTH_MISSING)
        service = self.service(); self.store.store_response = CodexAdapterError(CodexFailure.AUTH_EXPIRED)
        self.assertEqual(service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100).failure, CodexFailure.AUTH_EXPIRED)

    def test_malformed_adapter_values_are_classified_without_reading_their_properties(self):
        class Trap:
            @property
            def value(self):
                raise AssertionError("private-token")
        malformed_audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability("gpt-5.6-terra", "high"),))
        service = self.service((Trap(),), audit=malformed_audit)
        result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(result.failure, CodexFailure.MALFORMED_RESPONSE)
        self.assertNotIn("private-token", render_health_diagnostic(result))
        with self.assertRaises(ProviderHealthError):
            CodexRuntimeAudit("1.2.3", "4.5.6", [CodexCapability("gpt-5.6-terra", "high")])
        with self.assertRaises(ProviderHealthError):
            ProbeOutcome(False, "auth-missing")

    def test_audit_identity_round_trip_and_fingerprint_substitution_fail_closed(self):
        identity = ProviderHealthAuditIdentity(self.audit, self.profile)
        self.assertEqual(ProviderHealthAuditIdentity.from_evidence(identity.evidence()), identity)
        tampered = identity.evidence()
        tampered["runtime_fingerprint"] = "sha256:" + "0" * 64
        with self.assertRaises(ProviderHealthError):
            ProviderHealthAuditIdentity.from_evidence(tampered)

    def test_audit_evidence_excludes_profile_names_and_rejects_private_capabilities(self):
        named = ProviderHealthAuditIdentity(self.audit, ProviderProfile(self.profile.model, self.profile.reasoning_effort, "secret-token C:/private/payload"))
        rendered = repr(named.evidence()).lower()
        self.assertFalse(any(value in rendered for value in ("secret-token", "c:/private", "payload")))
        unsafe_audit = CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(self.profile.model, "high"), CodexCapability("secret-token", "high")))
        with self.assertRaises(ProviderHealthError):
            ProviderHealthAuditIdentity(unsafe_audit, self.profile)

    def test_role_bound_credential_identity_denies_every_other_role(self):
        identity = RoleBoundCredentialIdentity("sha256:" + "a" * 64, ProviderRole.WORKER, "sha256:" + "b" * 64, tuple(item for item in ProviderRole if item is not ProviderRole.WORKER))
        self.assertEqual(RoleBoundCredentialIdentity.from_evidence(identity.evidence()), identity)
        identity.authorize_channel(ProviderRole.WORKER, identity.store_identity, identity.channel_identity)
        with self.assertRaises(ProviderHealthError):
            identity.authorize_channel(ProviderRole.SUPERVISOR, identity.store_identity, identity.channel_identity)
        malformed = identity.evidence(); malformed["denied_roles"] = tuple(reversed(malformed["denied_roles"]))
        with self.assertRaises(ProviderHealthError):
            RoleBoundCredentialIdentity.from_evidence(malformed)

    def test_channel_identity_failures_block_before_audit_or_probe(self):
        service = self.service()
        result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual((result.state, self.channel.audit_calls, len(self.channel.requests)), (HealthState.READY, 1, 1))
        for replacement in (
            RoleBoundCredentialIdentity("sha256:" + "c" * 64, ProviderRole.WORKER, "sha256:" + "b" * 64, tuple(item for item in ProviderRole if item is not ProviderRole.WORKER)),
            RoleBoundCredentialIdentity("sha256:" + "a" * 64, ProviderRole.SUPERVISOR, "sha256:" + "b" * 64, tuple(item for item in ProviderRole if item is not ProviderRole.SUPERVISOR)),
        ):
            with self.subTest(identity=replacement.role):
                service = self.service()
                self.store.channel_identity = replacement
                result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
                self.assertEqual(result.failure, CodexFailure.MALFORMED_RESPONSE)
                self.assertEqual((self.channel.audit_calls, self.channel.requests), (0, []))

    def test_malformed_and_throwing_identity_boundaries_are_redacted_and_single_read(self):
        for boundary, value in (("store_response", object()), ("store_response", RuntimeError("private-token")), ("isolation_response", object()), ("isolation_response", RuntimeError("private-token")), ("identity_response", object()), ("identity_response", RuntimeError("private-token"))):
            with self.subTest(boundary=boundary, kind=type(value).__name__):
                service = self.service(); setattr(self.store if boundary != "identity_response" else self.channel, boundary, value)
                result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, force_refresh=True, now=100)
                self.assertEqual(result.failure, CodexFailure.MALFORMED_RESPONSE)
                self.assertEqual((self.channel.audit_calls, self.channel.requests), (0, []))
                self.assertNotIn("private-token", render_health_diagnostic(result))
        service = self.service(); result = service.qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, force_refresh=True, now=100)
        self.assertEqual(result.state, HealthState.READY)
        self.assertEqual((self.store.store_reads, self.store.isolation_reads, self.channel.identity_reads), (1, 1, 1))

    def test_role_bound_native_store_surface_and_qualification(self):
        native = {role: ("sha256:" + f"{index:x}" * 64, FakeNativeChannel(self.audit)) for index, role in enumerate(ProviderRole)}
        store = RoleBoundCodexCredentialStore("sha256:" + "a" * 64, native)
        for role in ProviderRole:
            channel, evidence = store.open_role_channel(role), store.credential_isolation(role)
            self.assertIs(type(channel), RoleBoundCodexChannel)
            self.assertEqual(evidence.credential_identity.denied_roles, tuple(item for item in ProviderRole if item is not role))
            self.assertTrue(all(value is False for name, value in vars(evidence).items() if name not in {"role", "credential_identity"}))
        result = CodexProviderHealth(store, self.contract).qualify(ProviderRole.WORKER, self.profile, freshness_seconds=30, now=100)
        self.assertEqual(result.state, HealthState.READY)
        self.assertEqual((native[ProviderRole.WORKER][1].audit_calls, len(native[ProviderRole.WORKER][1].requests)), (1, 1))
        self.assertEqual({name for name in dir(store.open_role_channel(ProviderRole.WORKER)) if not name.startswith("_")}, {"audit_runtime", "credential_identity", "qualify_read_only"})

    def test_role_bound_channel_rejects_cross_role_requests_and_reused_backend(self):
        native = {role: ("sha256:" + f"{index:x}" * 64, FakeNativeChannel(self.audit)) for index, role in enumerate(ProviderRole)}
        store = RoleBoundCodexCredentialStore("sha256:" + "a" * 64, native)
        channel = store.open_role_channel(ProviderRole.WORKER)
        with self.assertRaises(ProviderHealthError):
            channel.qualify_read_only(ReadOnlyQualification(ProviderRole.SUPERVISOR, self.profile.model, self.profile.reasoning_effort.value))
        self.assertEqual(native[ProviderRole.WORKER][1].requests, [])
        shared = FakeNativeChannel(self.audit)
        reused = {role: ("sha256:" + f"{index:x}" * 64, shared) for index, role in enumerate(ProviderRole)}
        with self.assertRaises(ProviderHealthError):
            RoleBoundCodexCredentialStore("sha256:" + "a" * 64, reused)
        self.assertEqual((shared.audit_calls, shared.requests), (0, []))

    def test_role_bound_native_store_constructor_rejects_invalid_registry(self):
        native = {role: ("sha256:" + f"{index:x}" * 64, FakeNativeChannel(self.audit)) for index, role in enumerate(ProviderRole)}
        cases = [
            ({},), ({**native, "wrong": native[ProviderRole.WORKER]},),
            ({role: ("sha256:" + "a" * 64, value[1]) for role, value in native.items()},),
            ({**native, ProviderRole.WORKER: "bad"},), ({**native, ProviderRole.WORKER: ("bad", native[ProviderRole.WORKER][1])},),
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ProviderHealthError): RoleBoundCodexCredentialStore("sha256:" + "a" * 64, *arguments)
        store = RoleBoundCodexCredentialStore("sha256:" + "a" * 64, native)
        with self.assertRaises(ProviderHealthError): store.open_role_channel("worker")


if __name__ == "__main__":
    unittest.main()
