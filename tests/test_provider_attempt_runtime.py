"""Provider-attempt V2 descriptor and opaque-resource boundary coverage."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
import unittest
from pathlib import Path
from dataclasses import replace
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright import external_validation
from roundwright.candidate_review import CandidateVerification, VerificationKind, VerificationOutcome
from roundwright.codex_supervisor import NativeSupervisorResponse, SupervisorDiagnostic, SupervisorResultKind
from roundwright.dependency_policy import CandidateBinding
from roundwright.git_identity import CandidateSeal, TransitionLease, WorktreeBinding
from roundwright.provider_attempt_runtime import (
    DiffReviewSelection, DurableDiffReviewRunner, MaterializedProviderAttemptContext,
    ProviderAttemptHostInputs, ProviderAttemptRuntimeDescriptor, ProviderAttemptRuntimeError,
    ProviderAttemptRuntimeResources, install_host_runtime,
)
from roundwright.provider_recovery import AttemptState, ProviderRole, RecoveryContext, read_attempt
from roundwright.runtime_binding import RuntimeBinding
from roundwright.state import TaskIdentity
from tests.provider_health_fixture import provider_context
import tests.test_candidate_review as _candidate_test_module
from tests.test_codex_supervisor import Backend
from tests.test_external_validation import fake_harness


def digest(character: str) -> str:
    return "sha256:" + character * 64


class _Runner:
    def execute(self) -> tuple[str, ...]:
        return ("attempt-1",)


class ProviderAttemptRuntimeTests(unittest.TestCase):
    def descriptor_payload(self) -> dict[str, object]:
        policy = {
            "complete_rounds": 1,
            "max_rounds": 2,
            "max_supervisor_attempts_per_round": 1,
            "on_final_findings": "worker-final-repair-then-merge",
        }
        binding = RuntimeBinding(
            "roundwright-runtime/v1", digest("1"), digest("2"), (digest("3"),),
            1, 2, 1, "worker-final-repair-then-merge",
            hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        )
        return {
            "schema": "roundwright-provider-attempt-runtime/v2",
            "resource_id": "runtime-45",
            "repository_id": "ythdelmar68/roundwright",
            "task_id": "task-45",
            "source_digest": digest("5"),
            "base_sha": "a" * 40,
            "candidate_sha": "b" * 40,
            "case_id": "provider-case-45",
            "ready_at": 17,
            "capture_plan_digest": digest("6"),
            "runtime_binding": binding.canonical_material(),
            "provider_profile_identity": digest("3"),
            "review_epoch": 1,
            "review_round": 1,
        }

    def resources(self, descriptor: ProviderAttemptRuntimeDescriptor) -> ProviderAttemptRuntimeResources:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", ROOT)
        identity = TaskIdentity("task-45", "source-45", "ythdelmar68/roundwright", "codex/task-45", str(ROOT), "a" * 40)
        binding = RuntimeBinding.from_canonical(descriptor.runtime_binding)
        recovery = RecoveryContext.for_task(
            identity, candidate_sha="b" * 40, policy_fingerprint="7" * 64,
            deployment_fingerprint="8" * 64, runtime_binding=binding,
        )
        lease = TransitionLease(identity.repository_id, "state-45", "worker-45", 1, 2**31)
        return ProviderAttemptRuntimeResources(
            repository, identity, recovery, lease,
            CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity),
            WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, ROOT, identity.base_sha, lease.state_identity),
            descriptor.source_digest, descriptor.case_id, descriptor.ready_at, descriptor.capture_plan_digest,
            descriptor.provider_profile_identity, descriptor.review_epoch, descriptor.review_round, _Runner(),
        )

    def durable_runner(self, root: Path, response: NativeSupervisorResponse, *, suffix: str = "one"):
        helper = _candidate_test_module.CandidateReviewTests()
        values = helper.ready_task(root)
        repository, identity, lease, initial, binding, now = values
        implementation, seal = helper.implement(values)
        recovery = provider_context(helper.review_context(identity, initial, seal), identity, ProviderRole.SUPERVISOR)
        for verification in (
            CandidateVerification(f"runtime-{suffix}-tests", VerificationKind.TEST, VerificationOutcome.PASS, "a" * 64),
            CandidateVerification(f"runtime-{suffix}-build", VerificationKind.BUILD, VerificationOutcome.PASS, "b" * 64),
        ):
            _candidate_test_module.record_candidate_verification(repository, identity, binding, seal, verification, lease=lease, now=now)
        dependency_binding, control = _candidate_test_module._dispatch_control(identity, recovery, now, seal.candidate_sha)
        audit = recovery.health_receipt.audit_identity
        backend = Backend(f"runtime-{suffix}", response, [])
        runner = DurableDiffReviewRunner(
            repository, identity, recovery, binding, seal, lease, dependency_binding, control, audit, backend,
            digest("7"), 1, 1,
            DiffReviewSelection(
                f"runtime-review-{suffix}", implementation.implementation_attempt_id,
                f"runtime-provider-{suffix}", f"runtime-message-{suffix}", f"runtime-lease-{suffix}",
                now + 60, "Review the immutable candidate.", ("Return a strict verdict.",),
            ),
        )
        return runner, backend, repository, identity, recovery, seal

    def test_descriptor_accepts_only_the_closed_json_shape_and_real_anchors(self) -> None:
        descriptor = ProviderAttemptRuntimeDescriptor.parse(self.descriptor_payload())
        self.assertEqual(descriptor.candidate_sha, "b" * 40)
        self.assertEqual(descriptor.capture_plan_digest, digest("6"))
        for field, value in (("candidate_sha", "b" * 40 + "x"), ("capture_plan_digest", digest("6") + "x"), ("resource_id", "runtime\\45"), ("ready_at", True)):
            payload = self.descriptor_payload()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ProviderAttemptRuntimeError):
                ProviderAttemptRuntimeDescriptor.parse(payload)
        for forbidden in ("provider_outcomes", "event_history", "provider_output", "factory"):
            payload = self.descriptor_payload()
            payload[forbidden] = "not-allowed"
            with self.subTest(forbidden=forbidden), self.assertRaises(ProviderAttemptRuntimeError):
                ProviderAttemptRuntimeDescriptor.parse(payload)

    def test_every_descriptor_and_resource_binding_drifts_before_store_access(self) -> None:
        descriptor = ProviderAttemptRuntimeDescriptor.parse(self.descriptor_payload())
        resources = self.resources(descriptor)
        replacements = {
            "repository_id": "ythdelmar68/other", "task_id": "task-46", "source_digest": digest("9"),
            "base_sha": "c" * 40, "candidate_sha": "d" * 40, "case_id": "provider-case-46",
            "ready_at": 18, "capture_plan_digest": digest("a"),
            "review_epoch": 2, "review_round": 2,
        }
        for field, replacement in replacements.items():
            payload = self.descriptor_payload()
            payload[field] = replacement
            drifted = ProviderAttemptRuntimeDescriptor.parse(payload)
            with self.subTest(field=field), self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
                resources.validate(drifted)
        payload = self.descriptor_payload()
        alternate = RuntimeBinding.from_canonical(payload["runtime_binding"])
        payload["runtime_binding"] = RuntimeBinding(
            alternate.schema_version, alternate.resolved_digest, alternate.worker_profile_identity, (digest("2"),),
            alternate.review_complete_rounds, alternate.review_max_rounds,
            alternate.review_max_supervisor_attempts_per_round, alternate.review_on_final_findings,
            alternate.review_policy_digest,
        ).canonical_material()
        payload["provider_profile_identity"] = digest("2")
        with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
            resources.validate(ProviderAttemptRuntimeDescriptor.parse(payload))
        payload = self.descriptor_payload()
        payload["runtime_binding"] = payload["runtime_binding"].replace(digest("1"), digest("f"))
        with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
            resources.validate(ProviderAttemptRuntimeDescriptor.parse(payload))

    def test_concrete_runner_persists_one_accepted_attempt_and_restart_readback(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            self.assertEqual(runner.execute(), ("runtime-provider-one",))
            stored = read_attempt(repository, identity, "runtime-provider-one", context=recovery)
            self.assertEqual(stored.state, AttemptState.ACCEPTED)
            self.assertEqual(backend.calls, 1)
            # Re-execution is a durable read-back: no fresh native dispatch and
            # no second formal acceptance can be created.
            self.assertEqual(runner.execute(), ("runtime-provider-one",))
            self.assertEqual(backend.calls, 1)

    def test_invalid_then_later_accepted_result_uses_durable_recovery_without_formal_consumption(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                root, NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX),
            )
            self.assertEqual(runner.execute(), ("runtime-provider-one",))
            self.assertNotEqual(read_attempt(repository, identity, "runtime-provider-one", context=recovery).state, AttemptState.ACCEPTED)
            # Reuse the same actual repository lifecycle with a fresh selected
            # provider identity; the accepted result is created only by its
            # observed typed native response.
            accepted = replace(
                runner,
                recovery=provider_context(
                    recovery, identity, ProviderRole.SUPERVISOR,
                    selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
                ),
                backend=Backend("runtime-two", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), []),
                selection=DiffReviewSelection(
                    "runtime-review-two", runner.selection.implementation_attempt_id,
                    "runtime-provider-two", "runtime-message-two", "runtime-lease-two",
                    runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 2,
                ),
            )
            dependency_binding, control = _candidate_test_module._dispatch_control(identity, accepted.recovery, runner.dispatch_control.now, accepted.seal.candidate_sha)
            accepted = replace(accepted, dependency_binding=dependency_binding, dispatch_control=control, audit=accepted.recovery.health_receipt.audit_identity)
            self.assertEqual(accepted.execute(), ("runtime-provider-two",))
            self.assertEqual(read_attempt(repository, identity, "runtime-provider-two", context=recovery).state, AttemptState.ACCEPTED)

    def test_runner_context_drift_blocks_before_the_native_backend(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, _, _, _, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            drifted = replace(runner, dependency_binding=CandidateBinding("ythdelmar68/roundwright", "task-25", "f" * 40))
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
                drifted.execute()
            self.assertEqual(backend.calls, 0)

    def test_host_materializer_runs_the_same_v2_adapter_flow_with_only_a_native_backend_fake(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            resource_id, plan_digest, case_id = "runtime-host-45", digest("c"), "runtime-case-45"
            descriptor = {
                "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": resource_id,
                "repository_id": identity.repository_id, "task_id": identity.task_id,
                "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                "candidate_sha": seal.candidate_sha, "case_id": case_id, "ready_at": 17,
                "capture_plan_digest": plan_digest, "runtime_binding": recovery.runtime_binding.canonical_material(),
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1,
            }
            context = install_host_runtime(descriptor, ProviderAttemptHostInputs(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection, backend,
            ))
            prior_package, prior_module = fake_harness()
            try:
                adapter = external_validation.ProviderAttemptAccountingAdapter()
                producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
                binding = type("Binding", (), {
                    "profile": external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
                    "case_id": case_id, "candidate_sha": seal.candidate_sha, "ready_at": 17,
                    "plan": type("Plan", (), {"plan_digest": plan_digest})(),
                    "components": type("Components", (), {"producer_identity": producer, "exporter_identity": exporter, "comparator_identity": comparator})(),
                    "execution_context": type("Context", (), {"value": context})(),
                    "execution_context_input_digest": digest("d"),
                })()
                adapter.validate(binding)
                execution = adapter.execute(binding)
                evidence = adapter.project(binding, execution)
                self.assertEqual(adapter.compare(binding, evidence).status, "pass")
                self.assertEqual(backend.calls, 1)
            finally:
                for name, value in (("roundwright_harness", prior_package), ("roundwright_harness.executor", prior_module)):
                    if value is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = value

    def test_hosted_entrypoint_runs_reviewed_harness_validate_then_execute(self) -> None:
        """Exercise the documented V2 host shape against the reviewed library.

        The package is intentionally supplied by the selected Harness
        environment, not by Roundwright's locked local test environment.  The
        candidate validation job sets ``ROUNDWRIGHT_HARNESS_SOURCE`` to the
        exact checked-out Harness ``src`` directory; ordinary unit runs retain
        their provider-free product-only boundary.
        """

        harness_source = os.environ.get("ROUNDWRIGHT_HARNESS_SOURCE")
        if harness_source is None:
            self.skipTest("reviewed Harness source is not supplied")
        source = Path(harness_source)
        if not (source / "roundwright_harness" / "executor.py").is_file():
            self.fail("reviewed Harness source is invalid")
        prior_modules = {
            name: value for name, value in sys.modules.items()
            if name == "roundwright_harness" or name.startswith("roundwright_harness.")
        }
        sys.path.insert(0, str(source))
        for name in tuple(prior_modules):
            sys.modules.pop(name, None)
        try:
            harness = importlib.import_module("roundwright_harness.executor")
            with TemporaryDirectory() as temporary:
                runner, backend, repository, identity, recovery, seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                )
                producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
                plan = {
                    "schema": "roundwright-harness-capture-plan/v1",
                    "profile": external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
                    "ready_at": 17,
                    "case_id": "runtime-hosted-case-45",
                    "candidate_sha": seal.candidate_sha,
                    "producer_identity": producer,
                    "exporter_identity": exporter,
                    "comparator_identity": comparator,
                    "recorder_identity": digest("8"),
                    "store_identity": digest("9"),
                    "observation_identity": digest("a"),
                }
                plan_digest = harness.prepare_capture(plan).plan_digest
                descriptor = {
                    "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-hosted-45",
                    "repository_id": identity.repository_id, "task_id": identity.task_id,
                    "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                    "candidate_sha": seal.candidate_sha, "case_id": plan["case_id"], "ready_at": plan["ready_at"],
                    "capture_plan_digest": plan_digest, "runtime_binding": recovery.runtime_binding.canonical_material(),
                    "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1,
                }
                request = {
                    "schema": "roundwright-harness-profile-executor-request/v2",
                    "capture_plan": plan,
                    "execution_context": descriptor,
                }
                host = ProviderAttemptHostInputs(
                    repository, identity, recovery, runner.lease, seal, runner.binding,
                    runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection, backend,
                )
                store = Path(temporary) / "recorder"
                parsed = harness.ExecutorRequest.parse(request)
                self.assertEqual(parsed.schema, "roundwright-harness-profile-executor-request/v2")
                self.assertEqual(parsed.capture_plan["profile"], external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE)
                self.assertIsNotNone(parsed.execution_context)
                readiness = external_validation.run_provider_attempt_accounting_profile(
                    "validate", request, store, host,
                )
                self.assertEqual(readiness.as_dict()["dispatch_count"], 0)
                self.assertEqual(backend.calls, 0)
                result = external_validation.run_provider_attempt_accounting_profile(
                    "execute", request, store, host,
                    expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                )
                receipt = result.as_dict()
                self.assertEqual((receipt["status"], receipt["mutation_count"]), ("pass", 0))
                self.assertEqual(backend.calls, 1)
                self.assertEqual(read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery).state, AttemptState.ACCEPTED)
                # A separate hosted invocation reads the same durable accepted
                # record; it cannot dispatch or accept a second formal result.
                repeated = external_validation.run_provider_attempt_accounting_profile(
                    "execute", request, store, host,
                    expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                )
                self.assertEqual(repeated.as_dict()["bundle_digest"], receipt["bundle_digest"])
                self.assertEqual(backend.calls, 1)
        finally:
            sys.path.remove(str(source))
            for name in tuple(sys.modules):
                if name == "roundwright_harness" or name.startswith("roundwright_harness."):
                    sys.modules.pop(name, None)
            sys.modules.update(prior_modules)


if __name__ == "__main__":
    unittest.main()
