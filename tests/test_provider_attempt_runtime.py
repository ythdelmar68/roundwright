"""Provider-attempt V2 descriptor and opaque-resource boundary coverage."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sqlite3
import sys
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from dataclasses import replace
from tempfile import TemporaryDirectory
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright import external_validation
from roundwright.candidate_review import CandidateVerification, VerificationKind, VerificationOutcome
from roundwright.codex_supervisor import (
    NativeSupervisorResponse, SupervisorDiagnostic, SupervisorOutcomeSource,
    SupervisorResultKind, SupervisorSdkTurnErrorCategory, canonical_supervisor_review_material, supervisor_request_digest,
)
from roundwright.dependency_policy import CandidateBinding
from roundwright.git_identity import CandidateSeal, TransitionLease, WorktreeBinding
from roundwright.provider_attempt_runtime import (
    DiffReviewSelection, DiffReviewSequenceEntry, DurableDiffReviewRunner, MaterializedProviderAttemptContext,
    ProviderAttemptCheckpointFailure, ProviderAttemptHostInputs, ProviderAttemptRuntimeDescriptor, ProviderAttemptRuntimeError,
    ProviderAttemptRuntimeResources, ProviderAttemptCompletionPolicy, PRODUCTION_COMPLETION_POLICY,
    install_host_runtime, provider_attempt_effect_material,
)
import roundwright.provider_attempt_runtime as provider_attempt_runtime
from roundwright.provider_health import CodexAdapterError, CodexFailure
from roundwright.role_capability_policy import AdvisoryRole, DurableRoleBudgetLedger, RoleBudget, RoleCapabilityError, trusted_provider_launch_context
from roundwright.provider_recovery import (
    AttemptState, ProviderRecoveryError, ProviderRole, RecoveryContext, SupervisorAccountingSnapshot,
    SupervisorTerminalFailure, claim_supervisor_dispatch, prepare_attempt, read_supervisor_dispatch_claim, read_attempt, read_supervisor_terminal_failure,
    record_supervisor_terminal_failure,
    SupervisorTerminalFailureClass, SupervisorTerminalFailureSource, SupervisorTerminalFailureSdkCategory,
)
from roundwright.runtime_binding import RuntimeBinding
from roundwright.state import TaskIdentity, database_path
from roundwright.supervisor_toolbox import HarnessNativeCodexSupervisorBackend
from roundwright.worker_toolbox import CompletionDeadline
from tests.provider_health_fixture import provider_context
import tests.test_candidate_review as _candidate_test_module
from tests.test_codex_supervisor import Backend
from tests.test_external_validation import fake_harness
from tests.role_admission_fixture import sealed_execution, sealed_execution_for_effect, trusted_execution_host


def digest(character: str) -> str:
    return "sha256:" + character * 64


class _Runner:
    def preflight_checkpoint_prerequisites(self) -> tuple[object, ...]:
        return ()

    def execute(self) -> tuple[str, ...]:
        return ("attempt-1",)

    def materialize_prepared_snapshot(self, _entries: tuple[object, ...]) -> object:
        return object()


class ProviderAttemptRuntimeTests(unittest.TestCase):
    def effect_trust(self, *, identity, recovery, seal, source_digest, review_epoch, review_round, selection, audit):
        _context, request_material, preflight_material = provider_attempt_effect_material(
            identity=identity, recovery=recovery, seal=seal, source_digest=source_digest,
            review_epoch=review_epoch, review_round=review_round,
            selection=selection, audit=audit,
        )
        return (
            sealed_execution_for_effect(
                AdvisoryRole.SUPERVISOR, audit.profile,
                request_identity=selection.provider_attempt_id,
                request_material=request_material,
                preflight_material=preflight_material,
            ),
            trusted_execution_host(AdvisoryRole.SUPERVISOR, audit.profile),
        )

    def sequence_entry(self, runner, *, selection=None, recovery=None, audit=None, backend=None):
        selection = runner.selection if selection is None else selection
        recovery = runner.recovery if recovery is None else recovery
        audit = runner.audit if audit is None else audit
        backend = runner.backend if backend is None else backend
        execution, host = self.effect_trust(
            identity=runner.identity, recovery=recovery, seal=runner.seal,
            source_digest=runner.source_digest, review_epoch=runner.review_epoch,
            review_round=runner.review_round, selection=selection, audit=audit,
        )
        return DiffReviewSequenceEntry(selection, execution, recovery, audit, backend, host)

    def budget_ledger(
        self, repository: RepositoryIdentity, execution: object, *, budget: RoleBudget | None = None,
        filename: str = "provider-attempt-budget.sqlite",
    ) -> DurableRoleBudgetLedger:
        assert execution is not None
        return DurableRoleBudgetLedger(
            repository.root / filename,
            grant_receipt_digest=execution.contract.admission.grant.receipt_digest,
            execution_binding=execution.execution_binding,
            budget=execution.contract.profile.budget if budget is None else budget,
        )

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
            "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
        }

    def test_public_hosted_provider_entrypoint_is_not_activated_before_harness_or_store_access(self) -> None:
        with patch("roundwright.external_validation._harness_executor") as harness:
            with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "production activation"):
                external_validation.run_provider_attempt_accounting_profile(
                    "execute", {}, Path("unreachable-recorder"), object(),
                )
            harness.assert_not_called()

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
        selection = DiffReviewSelection(
            f"runtime-review-{suffix}", implementation.implementation_attempt_id,
            f"runtime-provider-{suffix}", f"runtime-message-{suffix}", f"runtime-lease-{suffix}",
            now + 60, "Review the immutable candidate.", ("Return a strict verdict.",),
        )
        execution, execution_host = self.effect_trust(
            identity=identity, recovery=recovery, seal=seal, source_digest=digest("7"),
            review_epoch=1, review_round=1, selection=selection, audit=audit,
        )
        runner = DurableDiffReviewRunner(
            repository, identity, recovery, binding, seal, lease, dependency_binding, control, audit, backend,
            digest("7"), 1, 1,
            selection,
            advisory_execution=execution,
            execution_host=execution_host,
            budget_ledger_path=repository.root / "provider-attempt-budget.sqlite",
            case_id=f"runtime-case-{suffix}", ready_at=now,
        )
        return runner, backend, repository, identity, recovery, seal

    def test_sequence_entry_rejects_missing_or_wrong_role_capsule_before_effects(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, _repository, _identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            with self.assertRaises(ProviderAttemptRuntimeError):
                DiffReviewSequenceEntry(runner.selection, None, recovery, runner.audit, backend, trusted_execution_host(AdvisoryRole.SUPERVISOR, runner.audit.profile))  # type: ignore[arg-type]
            with self.assertRaises(ProviderAttemptRuntimeError):
                DiffReviewSequenceEntry(
                    runner.selection, sealed_execution(AdvisoryRole.WORKER, runner.audit.profile),
                    recovery, runner.audit, backend, trusted_execution_host(AdvisoryRole.SUPERVISOR, runner.audit.profile),
                )
            self.assertEqual(backend.calls, 0)

    def test_sequence_entry_refuses_primary_capsule_for_a_fallback_profile(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, _repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            fallback = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            with self.assertRaises(ProviderAttemptRuntimeError):
                DiffReviewSequenceEntry(
                    runner.selection, sealed_execution(AdvisoryRole.SUPERVISOR, runner.audit.profile),
                    fallback, fallback.health_receipt.audit_identity, backend, trusted_execution_host(AdvisoryRole.SUPERVISOR, fallback.health_receipt.audit_identity.profile),
                )
            self.assertEqual(backend.calls, 0)

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

    def test_completion_policy_is_closed_production_identity_material(self) -> None:
        """Test-scale deadlines cannot become armed product host inputs."""

        self.assertEqual(
            PRODUCTION_COMPLETION_POLICY.receipt(),
            {
                "schema": "roundwright-provider-attempt-completion-policy/v1",
                "application_timeout_ms": 100_000,
                "host_timeout_ms": 600_000,
            },
        )
        self.assertEqual(
            PRODUCTION_COMPLETION_POLICY.deadline(),
            CompletionDeadline(100_000, 600_000),
        )
        for policy in (
            None,
            {"schema": "roundwright-provider-attempt-completion-policy/v1", "application_timeout_ms": 100, "host_timeout_ms": 600},
            {"schema": "roundwright-provider-attempt-completion-policy/v1", "application_timeout_ms": 100_000, "host_timeout_ms": 600},
            {"schema": "roundwright-provider-attempt-completion-policy/v0", "application_timeout_ms": 100_000, "host_timeout_ms": 600_000},
        ):
            payload = self.descriptor_payload()
            payload["completion_policy"] = policy
            with self.subTest(policy=policy), self.assertRaisesRegex(ProviderAttemptRuntimeError, "completion policy"):
                ProviderAttemptRuntimeDescriptor.parse(payload)

    def test_frozen_completion_policy_has_owned_plain_descriptor_identity_parity(self) -> None:
        plain_payload = self.descriptor_payload()
        frozen_payload = dict(plain_payload)
        source_receipt = dict(PRODUCTION_COMPLETION_POLICY.receipt())
        frozen_payload["completion_policy"] = MappingProxyType(source_receipt)
        plain = ProviderAttemptRuntimeDescriptor.parse(plain_payload)
        frozen = ProviderAttemptRuntimeDescriptor.parse(frozen_payload)
        self.assertEqual(frozen.payload(), plain.payload())
        self.assertIs(type(frozen.completion_policy), dict)
        source_receipt["application_timeout_ms"] = 100
        self.assertEqual(
            frozen.payload()["completion_policy"],
            PRODUCTION_COMPLETION_POLICY.receipt(),
        )
        self.assertEqual(
            MaterializedProviderAttemptContext(plain, self.resources(plain)).identity,
            MaterializedProviderAttemptContext(frozen, self.resources(frozen)).identity,
        )
        for value in (
            MappingProxyType({"schema": "roundwright-provider-attempt-completion-policy/v1", "application_timeout_ms": 100, "host_timeout_ms": 600}),
            MappingProxyType({"schema": "roundwright-provider-attempt-completion-policy/v1", "application_timeout_ms": True, "host_timeout_ms": 600_000}),
            MappingProxyType({"schema": "roundwright-provider-attempt-completion-policy/v1", "application_timeout_ms": 100_000, "host_timeout_ms": 600_000, "path": "C:/private"}),
            "not-a-json-mapping",
        ):
            payload = self.descriptor_payload()
            payload["completion_policy"] = value
            with self.subTest(value=repr(value)), self.assertRaises(ProviderAttemptRuntimeError):
                ProviderAttemptRuntimeDescriptor.parse(payload)

    def test_host_rejects_a_test_scale_native_deadline_before_lifecycle_access(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            descriptor = {
                "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-short-deadline-45",
                "repository_id": identity.repository_id, "task_id": identity.task_id,
                "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                "candidate_sha": seal.candidate_sha, "case_id": "runtime-short-deadline-case-45", "ready_at": 17,
                "capture_plan_digest": digest("f"), "runtime_binding": recovery.runtime_binding.canonical_material(),
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1,
                "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
            }
            short_native = HarnessNativeCodexSupervisorBackend(
                cwd=repository.root, completion=CompletionDeadline(100, 600),
                launch_context=trusted_provider_launch_context(
                    sealed_execution(AdvisoryRole.SUPERVISOR, runner.audit.profile),
                    cwd=repository.root,
                ),
            )
            host = ProviderAttemptHostInputs(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection,
                short_native,
                advisory_execution=runner.advisory_execution,
                execution_host=runner.execution_host,
                budget_ledger_path=runner.budget_ledger_path,
            )
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "completion policy"):
                install_host_runtime(descriptor, host)
            self.assertEqual(backend.calls, 0)
            # Native SDK discovery remains fail-closed until a separately
            # reviewed discovery-off production control is activated.
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "not activated"):
                install_host_runtime(
                    dict(descriptor, resource_id="runtime-production-deadline-45"),
                    replace(host, backend=None),
                )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM provider_attempts WHERE attempt_id = ?",
                        (runner.selection.provider_attempt_id,),
                    ).fetchone()[0],
                    0,
                )
            finally:
                connection.close()

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

    def test_scope_stop_during_response_read_cannot_commit_accepted_review(self) -> None:
        """Completion evidence and scope admission linearize at acceptance."""

        from roundwright.failure_recovery import EvidenceSource, FailureBinding, FailureClass, FailureRole, classify, record_durable_failure

        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )

            class DenyingTurn:
                def identity(inner): return "runtime-denial-turn"
                def abort(inner): return None
                def read_response(inner):
                    record_durable_failure(
                        repository, identity,
                        classify(FailureBinding(
                            recovery.candidate_sha, "sha256:" + recovery.policy_fingerprint,
                            recovery.runtime_binding.resolved_digest, "supervisor:" + identity.task_id,
                            FailureRole.SUPERVISOR, runner.audit.profile_identity,
                            "runtime-denial-session", runner.selection.provider_attempt_id,
                        ), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST),
                        now=runner.dispatch_control.now,
                    )
                    return NativeSupervisorResponse(
                        SupervisorResultKind.ACCEPTED,
                        {"status": "complete", "action": "accept-formal-review", "blocker": None},
                    )

            class DenyingSession:
                def identity(inner): return "runtime-denial-session"
                def close(inner): return None
                def start_turn(inner, _request): return DenyingTurn()

            class DenyingBackend:
                def __init__(inner): inner.calls = 0
                def open_fresh_session(inner, _profile):
                    inner.calls += 1
                    return DenyingSession()

            backend = DenyingBackend()
            denied = replace(runner, backend=backend, sequence=(self.sequence_entry(runner, backend=backend),))
            with self.assertRaises(Exception):
                denied.execute()
            stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual((stored.state, stored.accepted_review_identity, backend.calls), (AttemptState.COMPLETED, None, 1))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT state, accepted_review_identity FROM diff_review_attempts WHERE provider_attempt_id=?",
                    (runner.selection.provider_attempt_id,),
                ).fetchone(), ("recorded", None))
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM accepted_provider_reviews WHERE attempt_id=?",
                    (runner.selection.provider_attempt_id,),
                ).fetchone(), (0,))

    def test_scope_denial_before_session_or_turn_is_durable_without_invented_turn(self) -> None:
        """Each pre-turn scope stop closes the claim with only authentic identity."""

        from roundwright.failure_recovery import FailureRecoveryError, FailureRole, ScopeAdmissionDenied, require_scope_open

        for stage, denied_call, expected_session in (
            ("before-session", 2, None),
            ("before-session-checkpoint", 4, None),
            ("before-turn", 5, "session-runtime-before-turn"),
            ("before-turn-checkpoint", 6, "session-runtime-before-turn-checkpoint"),
        ):
            with self.subTest(stage=stage), TemporaryDirectory() as temporary:
                runner, backend, repository, identity, recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(
                        SupervisorResultKind.ACCEPTED,
                        {"verdict": "pass", "findings": []},
                    ),
                    suffix=stage,
                )
                original = provider_attempt_runtime.require_scope_effect_admission
                calls = 0

                def deny_at_boundary(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == denied_call:
                        raise ScopeAdmissionDenied("injected authoritative scope stop")
                    return original(*args, **kwargs)

                with patch.object(
                    provider_attempt_runtime, "require_scope_effect_admission",
                    side_effect=deny_at_boundary,
                ), self.assertRaisesRegex(ProviderAttemptRuntimeError, "scope is stopped"):
                    runner.execute()
                stored = read_attempt(
                    repository, identity, runner.selection.provider_attempt_id,
                    context=recovery,
                )
                self.assertEqual(
                    (stored.state, stored.session_identity, stored.external_turn_identity),
                    (AttemptState.BLOCKED, expected_session, None),
                )
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    record = connection.execute(
                        "SELECT record_json FROM failure_recovery_records WHERE task_id=?",
                        (identity.task_id,),
                    ).fetchone()
                    self.assertIsNotNone(record)
                    payload = json.loads(record[0])
                    self.assertEqual(payload["action"], "stop-scope")
                    self.assertEqual(
                        payload["binding"]["session_identity"],
                        expected_session or provider_attempt_runtime.pre_dispatch_failure_identity(
                            FailureRole.SUPERVISOR, runner.selection.provider_attempt_id,
                        ),
                    )
                    with self.assertRaisesRegex(FailureRecoveryError, "scope remains stopped"):
                        require_scope_open(
                            connection, identity.task_id, "supervisor:" + identity.task_id,
                        )
                calls_before_restart = backend.calls
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "scope is stopped"):
                    runner.execute()
                self.assertEqual(backend.calls, calls_before_restart)

    def test_scope_storage_failure_never_becomes_verified_host_denial(self) -> None:
        """A locked scope ledger remains a storage failure with zero provider calls."""

        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(
                    SupervisorResultKind.ACCEPTED,
                    {"verdict": "pass", "findings": []},
                ),
                suffix="scope-storage",
            )
            original = provider_attempt_runtime.require_scope_effect_admission
            calls = 0

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise sqlite3.OperationalError("database is locked")
                return original(*args, **kwargs)

            with patch.object(
                provider_attempt_runtime, "require_scope_effect_admission",
                side_effect=fail_second,
            ), self.assertRaisesRegex(
                ProviderAttemptRuntimeError, "scope reconciliation is unavailable",
            ):
                runner.execute()
            self.assertEqual(backend.calls, 0)
            stored = read_attempt(
                repository, identity, runner.selection.provider_attempt_id,
                context=recovery,
            )
            self.assertEqual(stored.state, AttemptState.PREPARED)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM failure_recovery_records WHERE task_id=?",
                    (identity.task_id,),
                ).fetchone(), (0,))
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM provider_recovery_outcomes WHERE attempt_id=?",
                    (runner.selection.provider_attempt_id,),
                ).fetchone(), (0,))

    def test_native_security_denial_before_session_or_turn_is_durable(self) -> None:
        """Authenticated SDK denial outranks generic missing-checkpoint recovery."""

        from roundwright.failure_recovery import FailureRole

        for stage in ("open-session", "start-turn"):
            with self.subTest(stage=stage), TemporaryDirectory() as temporary:
                runner, _backend, repository, identity, recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(
                        SupervisorResultKind.ACCEPTED,
                        {"verdict": "pass", "findings": []},
                    ),
                    suffix="native-" + stage,
                )

                class DeniedSession:
                    def identity(self) -> str:
                        return "session-native-start-turn"
                    def close(self) -> None:
                        return None
                    def start_turn(self, _request: object) -> object:
                        raise CodexAdapterError(CodexFailure.SANDBOX_OR_APPROVAL_DENIED)

                class DeniedBackend:
                    def __init__(self) -> None:
                        self.calls = 0
                    def open_fresh_session(self, _profile: object) -> object:
                        self.calls += 1
                        if stage == "open-session":
                            raise CodexAdapterError(CodexFailure.SANDBOX_OR_APPROVAL_DENIED)
                        return DeniedSession()

                backend = DeniedBackend()
                denied = replace(
                    runner, backend=backend,
                    sequence=(self.sequence_entry(runner, backend=backend),),
                )
                with self.assertRaisesRegex(
                    ProviderAttemptRuntimeError, "native security denial",
                ):
                    denied.execute()
                stored = read_attempt(
                    repository, identity, runner.selection.provider_attempt_id,
                    context=recovery,
                )
                expected_session = (
                    None if stage == "open-session" else "session-native-start-turn"
                )
                self.assertEqual(
                    (stored.state, stored.session_identity, stored.external_turn_identity),
                    (AttemptState.BLOCKED, expected_session, None),
                )
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    payload = json.loads(connection.execute(
                        "SELECT record_json FROM failure_recovery_records WHERE task_id=?",
                        (identity.task_id,),
                    ).fetchone()[0])
                    self.assertEqual(
                        (payload["failure"], payload["evidence"], payload["action"]),
                        ("host-security-denial", "verified-host", "stop-scope"),
                    )
                    self.assertEqual(
                        payload["binding"]["session_identity"],
                        expected_session or provider_attempt_runtime.pre_dispatch_failure_identity(
                            FailureRole.SUPERVISOR,
                            runner.selection.provider_attempt_id,
                        ),
                    )
                    self.assertEqual(connection.execute(
                        "SELECT recovery_action, blocker FROM provider_recovery_outcomes "
                        "WHERE attempt_id=?", (runner.selection.provider_attempt_id,),
                    ).fetchone(), ("blocked-ambiguous-turn", "scope-stopped"))
                self.assertEqual(backend.calls, 1)

    def test_readiness_and_execution_share_complete_accepted_state_validation(self) -> None:
        """Claims, coordinates, and formal acceptance are all mandatory."""

        mutations = {
            "dispatch-claim": ("DELETE FROM provider_dispatch_claims WHERE attempt_id=?",),
            "coordinate": ("DELETE FROM supervisor_attempt_coordinates WHERE attempt_id=?",),
            "formal-acceptance": ("DELETE FROM accepted_provider_reviews WHERE attempt_id=?",),
            "session-checkpoint": ("DELETE FROM provider_session_checkpoints WHERE attempt_id=?",),
            "formal-turn": ("UPDATE diff_review_attempts SET external_turn_identity='substituted-turn' WHERE provider_attempt_id=?",),
        }
        for name, (statement,) in mutations.items():
            with self.subTest(drift=name), TemporaryDirectory() as temporary:
                runner, backend, repository, _identity, _recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                    suffix=name,
                )
                self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))
                with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                    connection.execute(statement, (runner.selection.provider_attempt_id,))
                with self.assertRaises(ProviderAttemptRuntimeError):
                    runner.validate_accounting_checkpoint()
                with self.assertRaises(ProviderAttemptRuntimeError):
                    runner.execute()
                self.assertEqual(backend.calls, 1)

    def test_host_supervisor_execution_drift_blocks_before_attempt_or_backend(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, _recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            drifted = replace(runner, execution_host=replace(
                runner.execution_host, candidate_sha="c" * 40,
            ))
            connection = sqlite3.connect(database_path(repository))
            try:
                before = connection.execute(
                    "SELECT COUNT(*) FROM provider_attempts WHERE task_id = ?", (identity.task_id,),
                ).fetchone()[0]
            finally:
                connection.close()
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "context has drifted"):
                drifted.execute()
            self.assertEqual(backend.calls, 0)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM provider_attempts WHERE task_id = ?", (identity.task_id,),
                ).fetchone()[0], before)
            finally:
                connection.close()

    def test_invalid_then_later_accepted_result_uses_durable_recovery_without_formal_consumption(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                root, NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX),
            )
            self.assertEqual(runner.execute(), ("runtime-provider-one",))
            self.assertNotEqual(read_attempt(repository, identity, "runtime-provider-one", context=recovery).state, AttemptState.ACCEPTED)
            # Reuse the same actual repository lifecycle with a fresh selected
            # same-profile physical ordinal; the accepted result is created only by its
            # observed typed native response.
            second_recovery = recovery
            second_backend = Backend("runtime-two", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), [])
            second_selection = DiffReviewSelection(
                "runtime-review-two", runner.selection.implementation_attempt_id,
                "runtime-provider-two", "runtime-message-two", "runtime-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 1, physical_format_output_ordinal=1,
            )
            accepted = replace(runner, sequence=(
                self.sequence_entry(runner),
                self.sequence_entry(
                    runner, selection=second_selection, recovery=second_recovery,
                    audit=second_recovery.health_receipt.audit_identity,
                    backend=second_backend,
                ),
            ))
            self.assertEqual(accepted.execute(), ("runtime-provider-one", "runtime-provider-two"))
            self.assertEqual(read_attempt(repository, identity, "runtime-provider-two", context=recovery).state, AttemptState.ACCEPTED)

    def test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            entries = []
            for ordinal in range(3):
                selection = runner.selection if ordinal == 0 else DiffReviewSelection(
                    f"runtime-format-review-{ordinal}", runner.selection.implementation_attempt_id,
                    f"runtime-format-provider-{ordinal}", f"runtime-format-message-{ordinal}",
                    f"runtime-format-lease-{ordinal}", runner.selection.process_lease_expires_at,
                    "Review the immutable candidate.", ("Return a strict verdict.",), 1,
                    logical_profile_position=1, physical_format_output_ordinal=ordinal,
                )
                backend = Backend(f"runtime-format-{ordinal}", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE), [])
                entries.append(self.sequence_entry(runner, selection=selection, backend=backend))
            exhausted = replace(runner, sequence=tuple(entries))
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "format correction allowance is exhausted"):
                exhausted.execute()
            calls = tuple(entry.backend.calls for entry in entries)
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "format correction allowance is exhausted"):
                exhausted.execute()
            self.assertEqual(tuple(entry.backend.calls for entry in entries), calls)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT logical_profile_position, physical_format_output_ordinal FROM provider_attempts WHERE task_id = ? AND (attempt_id = ? OR attempt_id LIKE 'runtime-format-provider-%') ORDER BY attempt_number", (identity.task_id, runner.selection.provider_attempt_id)).fetchall(), [(1, 0), (1, 1), (1, 2)])
                self.assertEqual(connection.execute("SELECT review_epoch, review_round, logical_profile_position, physical_format_output_ordinal FROM supervisor_attempt_coordinates WHERE task_id = ? ORDER BY logical_profile_position, physical_format_output_ordinal", (identity.task_id,)).fetchall(), [(1, 1, 1, 0), (1, 1, 1, 1), (1, 1, 1, 2)])
            finally:
                connection.close()

    def test_restart_continues_same_profile_at_next_physical_format_ordinal(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            first = self.sequence_entry(runner, backend=Backend("runtime-restart-zero", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE), []))
            self.assertEqual(replace(runner, sequence=(first,)).execute(), (runner.selection.provider_attempt_id,))
            next_selection = DiffReviewSelection("runtime-restart-one", runner.selection.implementation_attempt_id, "runtime-restart-provider-one", "runtime-restart-message-one", "runtime-restart-lease-one", runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 1, logical_profile_position=1, physical_format_output_ordinal=1)
            second = self.sequence_entry(runner, selection=next_selection, backend=Backend("runtime-restart-one", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE), []))
            restarted = replace(runner, sequence=(first, second))
            self.assertEqual(restarted.execute(), (runner.selection.provider_attempt_id, next_selection.provider_attempt_id))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT attempt_id, logical_profile_position, physical_format_output_ordinal FROM provider_attempts WHERE attempt_id IN (?, ?) ORDER BY attempt_number", (runner.selection.provider_attempt_id, next_selection.provider_attempt_id)).fetchall(), [(runner.selection.provider_attempt_id, 1, 0), (next_selection.provider_attempt_id, 1, 1)])
                self.assertEqual(connection.execute("SELECT attempt_id, review_epoch, review_round, logical_profile_position, physical_format_output_ordinal FROM supervisor_attempt_coordinates WHERE attempt_id IN (?, ?) ORDER BY logical_profile_position, physical_format_output_ordinal", (runner.selection.provider_attempt_id, next_selection.provider_attempt_id)).fetchall(), [(runner.selection.provider_attempt_id, 1, 1, 1, 0), (next_selection.provider_attempt_id, 1, 1, 1, 1)])
            finally:
                connection.close()

    def test_restarted_format_correction_authenticates_complete_predecessor_before_debit(self) -> None:
        """A durable INVALID row is not authority without its complete source chain."""

        mutations = {
            "dispatch-claim": "DELETE FROM provider_dispatch_claims WHERE attempt_id=?",
            "session-checkpoint": "DELETE FROM provider_session_checkpoints WHERE attempt_id=?",
            "failure-admission": "DELETE FROM provider_failure_admissions WHERE attempt_id=?",
        }
        for name, statement in mutations.items():
            with self.subTest(binding=name), TemporaryDirectory() as temporary:
                runner, _, repository, _identity, recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
                    suffix="correction-auth-" + name,
                )
                first = self.sequence_entry(runner)
                self.assertEqual(replace(runner, sequence=(first,)).execute(), (runner.selection.provider_attempt_id,))
                successor = replace(
                    runner.selection, diff_review_attempt_id="correction-auth-review",
                    provider_attempt_id="correction-auth-provider",
                    message_identity="correction-auth-message",
                    process_lease_id="correction-auth-lease",
                    physical_format_output_ordinal=1,
                )
                backend = Backend(
                    "correction-auth-successor",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                    [],
                )
                restarted = replace(runner, sequence=(
                    first,
                    self.sequence_entry(runner, selection=successor, recovery=recovery, backend=backend),
                ))
                with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                    connection.execute(statement, (runner.selection.provider_attempt_id,))
                with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                    before = connection.execute("SELECT COUNT(*) FROM role_budget_usage").fetchone()
                with self.assertRaises(ProviderAttemptRuntimeError):
                    restarted.validate_accounting_checkpoint()
                with self.assertRaises(ProviderAttemptRuntimeError):
                    restarted.execute()
                self.assertEqual(backend.calls, 0)
                with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM role_budget_usage").fetchone(), before)
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    self.assertIsNone(connection.execute(
                        "SELECT 1 FROM provider_attempts WHERE attempt_id=?", (successor.provider_attempt_id,),
                    ).fetchone())

    def test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, _ = self.durable_runner(Path(temporary) / "repository", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE))
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))
            self.assertEqual(backend.calls, 1)
            with self.assertRaisesRegex(ProviderRecoveryError, "replay conflicts"):
                prepare_attempt(repository, identity, recovery, attempt_id=runner.selection.provider_attempt_id, role=ProviderRole.SUPERVISOR, process_lease_id=runner.selection.process_lease_id, process_lease_expires_at=runner.selection.process_lease_expires_at, input_fingerprint="c" * 64, selected_profile_identity=runner.audit.profile_identity, logical_profile_position=1, physical_format_output_ordinal=0, lease=runner.lease, now=runner.dispatch_control.now)
            self.assertEqual(backend.calls, 1)

    def test_prepared_format_correction_reuses_exact_reservation_after_crash(self) -> None:
        import roundwright.provider_attempt_runtime as runtime_module
        class ProcessDeath(BaseException): pass
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE))
            first = self.sequence_entry(runner)
            selection = replace(runner.selection, diff_review_attempt_id="crash-review", provider_attempt_id="crash-provider",
                                message_identity="crash-message", process_lease_id="crash-lease", physical_format_output_ordinal=1)
            second = self.sequence_entry(runner, selection=selection,
                                         backend=Backend("crash-correction", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE), []))
            restarted = replace(runner, sequence=(first, second))
            original = runtime_module.prepare_attempt
            def interrupt(*args, **kwargs):
                result = original(*args, **kwargs)
                if kwargs["attempt_id"] == selection.provider_attempt_id:
                    raise ProcessDeath
                return result
            with patch.object(runtime_module, "prepare_attempt", side_effect=interrupt):
                with self.assertRaises(ProcessDeath): restarted.execute()
            self.assertEqual((first.backend.calls, second.backend.calls), (1, 0))
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                before = connection.execute("SELECT * FROM role_budget_usage").fetchall()
            self.assertEqual(len(before), 2)
            for changed in (
                replace(selection, provider_attempt_id="substituted-provider"),
                replace(selection, message_identity="substituted-message"),
                replace(selection, process_lease_id="substituted-lease"),
                replace(selection, physical_format_output_ordinal=2),
                replace(selection, logical_profile_position=2, within_round_attempt=2),
            ):
                with self.subTest(selection=changed):
                    with self.assertRaises((ProviderAttemptRuntimeError, ProviderRecoveryError, RoleCapabilityError)):
                        drifted = self.sequence_entry(runner, selection=changed, backend=second.backend)
                        replace(runner, sequence=(first, drifted)).execute()
                    self.assertEqual((first.backend.calls, second.backend.calls), (1, 0))
                    with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                        self.assertEqual(connection.execute("SELECT * FROM role_budget_usage").fetchall(), before)
            self.assertEqual(replace(restarted).execute(), (first.selection.provider_attempt_id, selection.provider_attempt_id))
            self.assertEqual((first.backend.calls, second.backend.calls), (1, 1))
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute("SELECT * FROM role_budget_usage").fetchall(), before)
            self.assertEqual(replace(restarted).execute(), (first.selection.provider_attempt_id, selection.provider_attempt_id))
            self.assertEqual((first.backend.calls, second.backend.calls), (1, 1))

    def test_readiness_accepts_only_exact_unclaimed_prepared_correction(self) -> None:
        """Validate resumes the same debit/checkpoint but rejects claim or binding drift."""

        import roundwright.provider_attempt_runtime as runtime_module
        class ProcessDeath(BaseException): pass
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            first = self.sequence_entry(runner)
            selection = replace(
                runner.selection, diff_review_attempt_id="readiness-review",
                provider_attempt_id="readiness-provider", message_identity="readiness-message",
                process_lease_id="readiness-lease", physical_format_output_ordinal=1,
            )
            second = self.sequence_entry(
                runner, selection=selection,
                backend=Backend("readiness-correction", NativeSupervisorResponse(
                    SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE,
                ), []),
            )
            restarted = replace(runner, sequence=(first, second))
            original = runtime_module.prepare_attempt
            def interrupt(*args, **kwargs):
                result = original(*args, **kwargs)
                if kwargs["attempt_id"] == selection.provider_attempt_id:
                    raise ProcessDeath
                return result
            with patch.object(runtime_module, "prepare_attempt", side_effect=interrupt), self.assertRaises(ProcessDeath):
                restarted.execute()
            before = read_attempt(repository, identity, selection.provider_attempt_id, context=recovery)
            self.assertEqual((before.state, read_supervisor_dispatch_claim(
                repository, identity, recovery, attempt_id=selection.provider_attempt_id,
            )), (AttemptState.PREPARED, "unclaimed"))
            self.assertEqual(restarted.validate_accounting_checkpoint(), before)
            drifted = replace(
                restarted, sequence=(first, replace(second, selection=replace(
                    selection, message_identity="readiness-message-drift",
                ))),
            )
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
                drifted.validate_accounting_checkpoint()
            claim_supervisor_dispatch(
                repository, identity, recovery, attempt_id=selection.provider_attempt_id,
                lease=runner.lease, now=runner.dispatch_control.now,
            )
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
                restarted.validate_accounting_checkpoint()

    def test_initial_prepared_reservation_resumes_after_crash_without_double_debit(self) -> None:
        """Physical ordinal zero reuses an exact untouched sealed debit."""

        class ProcessDeath(BaseException): pass
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            runner.validate_accounting_checkpoint()
            original = provider_attempt_runtime.prepare_attempt
            reserved_usage = []

            def interrupt(*args, **kwargs):
                result = original(*args, **kwargs)
                if not runner.budget_ledger_path.is_file():
                    return result
                with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                    reserved_usage.extend(connection.execute(
                        "SELECT calls, duration_seconds, tokens FROM role_budget_usage"
                    ).fetchall())
                raise ProcessDeath

            with patch.object(provider_attempt_runtime, "prepare_attempt", side_effect=interrupt), self.assertRaises(ProcessDeath):
                runner.execute()
            self.assertEqual(backend.calls, 0)
            before = reserved_usage
            self.assertEqual(before, [(1, 60, 4000)])
            self.assertEqual(runner.validate_accounting_checkpoint().state, AttemptState.PREPARED)
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))
            self.assertEqual(backend.calls, 1)
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute("SELECT calls, duration_seconds, tokens FROM role_budget_usage").fetchall(), before)

    def test_process_death_after_correction_debit_before_prepare_recovers_exact_intent(self) -> None:
        """A real interruption boundary neither strands nor repeats the correction debit."""

        class ProcessDeath(BaseException):
            pass

        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(
                    SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE,
                ),
            )
            first = self.sequence_entry(runner)
            self.assertEqual(
                replace(runner, sequence=(first,)).execute(),
                (first.selection.provider_attempt_id,),
            )
            selection = replace(
                runner.selection, diff_review_attempt_id="intent-review",
                provider_attempt_id="intent-provider", message_identity="intent-message",
                process_lease_id="intent-lease", physical_format_output_ordinal=1,
            )
            backend = Backend(
                "intent-correction",
                NativeSupervisorResponse(
                    SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
                ), [],
            )
            correction = self.sequence_entry(runner, selection=selection, backend=backend)
            restarted = replace(runner, sequence=(first, correction))
            original = provider_attempt_runtime.prepare_attempt

            def die_before_prepare(*args, **kwargs):
                if kwargs["attempt_id"] == selection.provider_attempt_id:
                    raise ProcessDeath
                return original(*args, **kwargs)

            with patch.object(
                provider_attempt_runtime, "prepare_attempt", side_effect=die_before_prepare,
            ), self.assertRaises(ProcessDeath):
                restarted.execute()
            self.assertEqual(backend.calls, 0)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM provider_attempts WHERE attempt_id = ?",
                    (selection.provider_attempt_id,),
                ).fetchone())
                self.assertEqual(connection.execute(
                    "SELECT task_id, authority_scope, provider_role, state "
                    "FROM provider_effect_reservation_intents WHERE attempt_id = ?",
                    (selection.provider_attempt_id,),
                ).fetchone(), (
                    identity.task_id, "supervisor:" + identity.task_id,
                    "supervisor", "reserving",
                ))
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                before = connection.execute(
                    "SELECT ledger_key, calls, duration_seconds, tokens "
                    "FROM role_budget_usage ORDER BY ledger_key"
                ).fetchall()
            self.assertEqual(len(before), 2)
            self.assertEqual(restarted.execute(), (
                first.selection.provider_attempt_id, selection.provider_attempt_id,
            ))
            self.assertEqual(backend.calls, 1)
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT ledger_key, calls, duration_seconds, tokens "
                    "FROM role_budget_usage ORDER BY ledger_key"
                ).fetchall(), before)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM provider_effect_reservation_intents WHERE attempt_id = ?",
                    (selection.provider_attempt_id,),
                ).fetchone())
            self.assertEqual(read_attempt(
                repository, identity, selection.provider_attempt_id, context=recovery,
            ).state, AttemptState.ACCEPTED)

    def test_unused_correction_debit_is_recovered_when_preparation_fails(self) -> None:
        """No attempt, claim, or call means the scoped debit is recoverable."""

        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            first = self.sequence_entry(runner)
            self.assertEqual(replace(runner, sequence=(first,)).execute(), (runner.selection.provider_attempt_id,))
            selection = replace(
                runner.selection, diff_review_attempt_id="unused-review",
                provider_attempt_id="unused-provider", message_identity="unused-message",
                process_lease_id="unused-lease", physical_format_output_ordinal=1,
            )
            correction = replace(runner, sequence=(first, self.sequence_entry(
                runner, selection=selection,
                backend=Backend("unused-correction", NativeSupervisorResponse(
                    SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
                ), []),
            )))
            original = provider_attempt_runtime.prepare_attempt

            def reject_new_attempt(*args, **kwargs):
                if kwargs["attempt_id"] == selection.provider_attempt_id:
                    raise ProviderRecoveryError("injected preparation rejection")
                return original(*args, **kwargs)

            with patch.object(provider_attempt_runtime, "prepare_attempt", side_effect=reject_new_attempt), self.assertRaises(ProviderRecoveryError):
                correction.execute()
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM provider_attempts WHERE attempt_id=?", (selection.provider_attempt_id,),
                ).fetchone())
            with closing(sqlite3.connect(correction.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT sum(calls), sum(duration_seconds), sum(tokens) FROM role_budget_usage"
                ).fetchone(), (1, 60, 4000))

    def test_unused_correction_refund_rejects_foreign_reservation_owner(self) -> None:
        """A product intent cannot refund a debit rebound to another repository."""

        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, _recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            first = self.sequence_entry(runner)
            self.assertEqual(replace(runner, sequence=(first,)).execute(), (runner.selection.provider_attempt_id,))
            selection = replace(
                runner.selection, diff_review_attempt_id="foreign-refund-review",
                provider_attempt_id="foreign-refund-provider", message_identity="foreign-refund-message",
                process_lease_id="foreign-refund-lease", physical_format_output_ordinal=1,
            )
            correction = replace(runner, sequence=(first, self.sequence_entry(
                runner, selection=selection,
                backend=Backend("foreign-refund-correction", NativeSupervisorResponse(
                    SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
                ), []),
            )))
            original = provider_attempt_runtime.prepare_attempt

            def reject_after_owner_substitution(*args, **kwargs):
                if kwargs["attempt_id"] == selection.provider_attempt_id:
                    with closing(sqlite3.connect(database_path(repository))) as connection:
                        connection.execute(
                            "UPDATE provider_effect_reservation_intents "
                            "SET reservation_repository_identity=? WHERE attempt_id=?",
                            (digest("foreign-repository"), selection.provider_attempt_id),
                        )
                        connection.commit()
                    raise ProviderRecoveryError("injected preparation rejection")
                return original(*args, **kwargs)

            with patch.object(
                provider_attempt_runtime, "prepare_attempt",
                side_effect=reject_after_owner_substitution,
            ), self.assertRaisesRegex(
                ProviderAttemptRuntimeError, "unused provider reservation recovery failed",
            ):
                correction.execute()
            with closing(sqlite3.connect(correction.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute(
                    "SELECT sum(calls), sum(duration_seconds), sum(tokens) FROM role_budget_usage"
                ).fetchone(), (2, 120, 8000))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual(connection.execute(
                    "SELECT reservation_repository_identity FROM provider_effect_reservation_intents "
                    "WHERE attempt_id=?", (selection.provider_attempt_id,),
                ).fetchone(), (digest("foreign-repository"),))

    def test_stopped_scope_rejects_correction_before_any_state_or_budget_change(self) -> None:
        """A denied correction is inert across product and budget ledgers."""

        from roundwright.failure_recovery import (
            EvidenceSource, FailureBinding, FailureClass, FailureRole, classify,
            record_durable_failure,
        )
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            first = self.sequence_entry(runner)
            self.assertEqual(replace(runner, sequence=(first,)).execute(), (runner.selection.provider_attempt_id,))
            source = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            assert source.session_identity is not None
            record_durable_failure(
                repository, identity,
                classify(FailureBinding(
                    recovery.candidate_sha, "sha256:" + recovery.policy_fingerprint,
                    recovery.runtime_binding.resolved_digest, "supervisor:" + identity.task_id,
                    FailureRole.SUPERVISOR, first.audit.profile_identity,
                    source.session_identity, source.attempt_id,
                ), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST),
            )
            selection = replace(
                runner.selection, diff_review_attempt_id="denied-review",
                provider_attempt_id="denied-provider", message_identity="denied-message",
                process_lease_id="denied-lease", physical_format_output_ordinal=1,
            )
            backend = Backend("denied-correction", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), [])
            denied = replace(runner, sequence=(first, self.sequence_entry(
                runner, selection=selection, backend=backend,
            )))
            with closing(sqlite3.connect(database_path(repository))) as connection:
                product_before = {
                    table: connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                    for table in (
                        "provider_attempts", "supervisor_attempt_coordinates",
                        "provider_dispatch_claims", "recovery_route_authorizations",
                        "provider_invalid_outputs",
                    )
                }
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                budget_before = connection.execute("SELECT * FROM role_budget_usage ORDER BY 1").fetchall()
            def denied_writer(_index):
                try:
                    denied.execute()
                except ProviderAttemptRuntimeError as error:
                    return str(error)
                return "unexpected-success"
            with ThreadPoolExecutor(max_workers=4) as pool:
                outcomes = tuple(pool.map(denied_writer, range(4)))
            self.assertTrue(all("scope is stopped" in outcome for outcome in outcomes), outcomes)
            with closing(sqlite3.connect(database_path(repository))) as connection:
                self.assertEqual({
                    table: connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                    for table in product_before
                }, product_before)
            with closing(sqlite3.connect(runner.budget_ledger_path)) as connection:
                self.assertEqual(connection.execute("SELECT * FROM role_budget_usage ORDER BY 1").fetchall(), budget_before)
            self.assertEqual(backend.calls, 0)

    def test_fallback_reserves_its_own_exact_binding_and_reconstructs_without_redispatch(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, primary, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(
                    SupervisorResultKind.BLOCKED,
                    failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                    outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
                    sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD,
                ),
            )
            second_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            fallback = Backend("runtime-budget-fallback", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), [])
            second = DiffReviewSelection(
                "runtime-budget-review-two", runner.selection.implementation_attempt_id,
                "runtime-budget-provider-two", "runtime-budget-message-two", "runtime-budget-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.",
                ("Return a strict verdict.",), 2,
            )
            shared_path = repository.root / "shared-provider-attempt-budget.sqlite"
            shared = replace(runner, budget_ledger_path=shared_path, sequence=(
                self.sequence_entry(runner, backend=primary),
                self.sequence_entry(
                    runner, selection=second, recovery=second_recovery,
                    audit=second_recovery.health_receipt.audit_identity,
                    backend=fallback,
                ),
            ))
            self.assertEqual(shared.execute(), (runner.selection.provider_attempt_id, second.provider_attempt_id))
            self.assertEqual((primary.calls, fallback.calls), (1, 1))
            connection = sqlite3.connect(shared_path)
            try:
                rows = connection.execute(
                    "SELECT binding_digest, calls, duration_seconds, tokens FROM role_budget_usage"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(len(rows), 2)
            self.assertEqual(len({row[0] for row in rows}), 2)
            self.assertEqual({row[1:] for row in rows}, {(1, 60, 4_000)})
            self.assertEqual(shared.execute(), (runner.selection.provider_attempt_id, second.provider_attempt_id))
            self.assertEqual((primary.calls, fallback.calls), (1, 1))

    def test_format_correction_then_verified_outage_falls_back_without_stranding(self) -> None:
        from roundwright.failure_recovery import (
            FailureRecoveryError, abandon_durable_recovery_route_reservation,
            read_durable_recovery_route_authorization,
        )
        for interruption in (None, "prepared", "route-committed"):
            with self.subTest(interruption=interruption), TemporaryDirectory() as temporary:
                runner, primary, repository, identity, recovery, _ = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
                )
                correction = replace(runner.selection, diff_review_attempt_id="correction-review", provider_attempt_id="correction-provider", message_identity="correction-message", process_lease_id="correction-lease", physical_format_output_ordinal=1)
                outage = Backend("correction", NativeSupervisorResponse(SupervisorResultKind.BLOCKED, failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED, sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD), [])
                successor = replace(runner.selection, diff_review_attempt_id="fallback-review", provider_attempt_id="fallback-provider", message_identity="fallback-message", process_lease_id="fallback-lease", within_round_attempt=2)
                successor_recovery = provider_context(recovery, identity, ProviderRole.SUPERVISOR, selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1])
                fallback = Backend("fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), [])
                sequence = replace(runner, sequence=(
                    self.sequence_entry(runner, backend=primary),
                    self.sequence_entry(runner, selection=correction, backend=outage),
                    self.sequence_entry(runner, selection=successor, recovery=successor_recovery, audit=successor_recovery.health_receipt.audit_identity, backend=fallback),
                ))
                if interruption == "prepared":
                    original = provider_attempt_runtime.read_supervisor_accounting_snapshot
                    def invalid_snapshot(*args, **kwargs):
                        if kwargs["current_attempt_id"] == successor.provider_attempt_id:
                            raise ProviderRecoveryError("injected deterministic accounting rejection")
                        return original(*args, **kwargs)
                    with patch.object(provider_attempt_runtime, "read_supervisor_accounting_snapshot", side_effect=invalid_snapshot), self.assertRaisesRegex(ProviderAttemptRuntimeError, "accounting snapshot is unavailable"):
                        sequence.execute()
                elif interruption == "route-committed":
                    original = provider_attempt_runtime.commit_durable_recovery_route_reservation
                    def interrupt_after_commit(*args, **kwargs):
                        original(*args, **kwargs)
                        raise ProviderRecoveryError("injected post-commit interruption")
                    with patch.object(provider_attempt_runtime, "commit_durable_recovery_route_reservation", side_effect=interrupt_after_commit), self.assertRaisesRegex(ProviderAttemptRuntimeError, "recovery route is unavailable"):
                        sequence.execute()
                if interruption is not None:
                    self.assertEqual((primary.calls, outage.calls, fallback.calls), (1, 1, 0))
                    with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                        route_id, reservation, route_state = connection.execute("SELECT route_digest, reservation_digest, state FROM recovery_route_authorizations").fetchone()
                        self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_dispatch_claims WHERE attempt_id=?", (successor.provider_attempt_id,)).fetchone(), (0,))
                        self.assertEqual(connection.execute("SELECT state FROM provider_attempts WHERE attempt_id=?", (successor.provider_attempt_id,)).fetchone(), ("prepared",))
                    self.assertEqual(route_state, "reserving" if interruption == "prepared" else "consumed")
                    self.assertEqual(sequence.validate_accounting_checkpoint().state, AttemptState.PREPARED)
                    route = read_durable_recovery_route_authorization(repository, identity, route_id)
                    with self.assertRaisesRegex(FailureRecoveryError, "successor is already admitted|route abandonment has drifted"):
                        abandon_durable_recovery_route_reservation(repository, identity, route, reservation_digest=reservation)
                    with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                        self.assertEqual(connection.execute("SELECT state, reservation_digest FROM recovery_route_authorizations WHERE route_digest=?", (route_id,)).fetchone(), (route_state, reservation))
                expected = (runner.selection.provider_attempt_id, correction.provider_attempt_id, successor.provider_attempt_id)
                self.assertEqual(sequence.execute(), expected)
                self.assertEqual(sequence.execute(), expected)
                self.assertEqual((primary.calls, outage.calls, fallback.calls), (1, 1, 1))
                with closing(sqlite3.connect(sequence.budget_ledger_path)) as connection, connection:
                    self.assertEqual(connection.execute("SELECT sum(calls), sum(duration_seconds), sum(tokens) FROM role_budget_usage").fetchone(), (3, 180, 12000))

    def test_prepared_fallback_readiness_rejects_route_identity_claim_and_reservation_drift(self) -> None:
        """The shared PREPARED fallback classifier fails closed on every binding."""

        for drift in ("route", "identity", "claim", "reservation"):
            with self.subTest(drift=drift), TemporaryDirectory() as temporary:
                runner, primary, repository, identity, recovery, _ = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(
                        SupervisorResultKind.BLOCKED,
                        failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                        outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
                        sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD,
                    ),
                    suffix="prepared-" + drift,
                )
                successor_recovery = provider_context(
                    recovery, identity, ProviderRole.SUPERVISOR,
                    selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
                )
                successor = replace(
                    runner.selection, diff_review_attempt_id="prepared-review-" + drift,
                    provider_attempt_id="prepared-provider-" + drift,
                    message_identity="prepared-message-" + drift,
                    process_lease_id="prepared-lease-" + drift,
                    within_round_attempt=2,
                )
                fallback = Backend("prepared-fallback-" + drift, NativeSupervisorResponse(
                    SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
                ), [])
                sequence = replace(runner, sequence=(
                    self.sequence_entry(runner, backend=primary),
                    self.sequence_entry(
                        runner, selection=successor, recovery=successor_recovery,
                        audit=successor_recovery.health_receipt.audit_identity,
                        backend=fallback,
                    ),
                ))
                original = provider_attempt_runtime.read_supervisor_accounting_snapshot
                def interrupt_prepared(*args, **kwargs):
                    if kwargs["current_attempt_id"] == successor.provider_attempt_id:
                        raise ProviderRecoveryError("injected prepared fallback interruption")
                    return original(*args, **kwargs)
                with patch.object(provider_attempt_runtime, "read_supervisor_accounting_snapshot", side_effect=interrupt_prepared), self.assertRaises(ProviderAttemptRuntimeError):
                    sequence.execute()
                self.assertEqual(sequence.validate_accounting_checkpoint().state, AttemptState.PREPARED)
                if drift == "claim":
                    claim_supervisor_dispatch(
                        repository, identity, successor_recovery,
                        attempt_id=successor.provider_attempt_id,
                        lease=sequence.lease, now=sequence.dispatch_control.now,
                    )
                else:
                    statements = {
                        "route": "UPDATE recovery_route_authorizations SET target_route_digest='sha256:" + "e" * 64 + "'",
                        "identity": "UPDATE provider_attempts SET selected_profile_identity='sha256:" + "e" * 64 + "' WHERE attempt_id='" + successor.provider_attempt_id + "'",
                        "reservation": "UPDATE recovery_route_authorizations SET reservation_digest='sha256:" + "e" * 64 + "'",
                    }
                    with closing(sqlite3.connect(database_path(repository))) as connection, connection:
                        connection.execute(statements[drift])
                with self.assertRaises(ProviderAttemptRuntimeError):
                    sequence.validate_accounting_checkpoint()
                with self.assertRaises(ProviderAttemptRuntimeError):
                    sequence.execute()
                self.assertEqual(fallback.calls, 0)

    def test_format_invalid_cannot_jump_profiles_before_or_after_restart(self) -> None:
        for ordinal in (0, 2):
            with self.subTest(physical_ordinal=ordinal), TemporaryDirectory() as temporary:
                runner, primary, repository, identity, recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
                )
                entries = [self.sequence_entry(runner, backend=primary)]
                for physical in range(1, ordinal + 1):
                    selection = replace(runner.selection, diff_review_attempt_id=f"format-review-{physical}", provider_attempt_id=f"format-provider-{physical}", message_identity=f"format-message-{physical}", process_lease_id=f"format-lease-{physical}", physical_format_output_ordinal=physical)
                    backend = Backend(f"format-{physical}", NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE), [])
                    entries.append(self.sequence_entry(runner, selection=selection, backend=backend))
                next_recovery = provider_context(recovery, identity, ProviderRole.SUPERVISOR, selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1])
                target = replace(runner.selection, diff_review_attempt_id="jump-review", provider_attempt_id="jump-provider", message_identity="jump-message", process_lease_id="jump-lease", within_round_attempt=2)
                fallback = Backend("jump-fallback", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), [])
                entries.append(self.sequence_entry(runner, selection=target, recovery=next_recovery, audit=next_recovery.health_receipt.audit_identity, backend=fallback))
                sequence = replace(runner, sequence=tuple(entries))
                for restart in (False, True):
                    expected_error = "profile transition has no terminal recovery route" if ordinal == 0 else "format correction allowance is exhausted"
                    with self.subTest(restart=restart), self.assertRaisesRegex(ProviderAttemptRuntimeError, expected_error):
                        sequence.execute()
                    self.assertEqual(fallback.calls, 0)
                    self.assertEqual(primary.calls, 1)
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertIsNone(connection.execute("SELECT 1 FROM provider_attempts WHERE attempt_id=?", (target.provider_attempt_id,)).fetchone())
                finally:
                    connection.close()

    def test_recovery_route_fence_interruption_reconciles_before_successor_dispatch(self) -> None:
        """A crash after the route fence cannot strand or duplicate a successor."""

        with TemporaryDirectory() as temporary:
            runner, primary, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(
                    SupervisorResultKind.BLOCKED,
                    failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                    outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
                    sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD,
                ),
            )
            successor_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            successor = DiffReviewSelection(
                "runtime-fence-review-two", runner.selection.implementation_attempt_id,
                "runtime-fence-provider-two", "runtime-fence-message-two", "runtime-fence-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.",
                ("Return a strict verdict.",), 2,
            )
            fallback = Backend("runtime-fence-two", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), [])
            restarted = replace(runner, sequence=(
                self.sequence_entry(runner, backend=primary),
                self.sequence_entry(
                    runner, selection=successor, recovery=successor_recovery,
                    audit=successor_recovery.health_receipt.audit_identity, backend=fallback,
                ),
            ))
            original_begin = provider_attempt_runtime.begin_durable_recovery_route_reservation

            def interrupt_after_fence(*args, **kwargs):
                original_begin(*args, **kwargs)
                raise RuntimeError("injected interruption after durable route fence")

            with patch("roundwright.provider_attempt_runtime.begin_durable_recovery_route_reservation", side_effect=interrupt_after_fence):
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "recovery route is unavailable"):
                    restarted.execute()
            self.assertEqual((primary.calls, fallback.calls), (1, 0))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT state FROM recovery_route_authorizations"
                ).fetchall(), [("reserving",)])
                self.assertEqual(connection.execute(
                    "SELECT state FROM provider_attempts WHERE attempt_id = ?",
                    (successor.provider_attempt_id,),
                ).fetchall(), [])
            finally:
                connection.close()
            connection = sqlite3.connect(restarted.budget_ledger_path)
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM role_budget_usage"
                ).fetchone(), (1,))
            finally:
                connection.close()
            # Restart first abandons the fence with no matching budget row,
            # then admits exactly one prepared successor and commits the route.
            self.assertEqual(restarted.execute(), (runner.selection.provider_attempt_id, successor.provider_attempt_id))
            self.assertEqual((primary.calls, fallback.calls), (1, 1))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT state FROM recovery_route_authorizations"
                ).fetchall(), [("consumed",)])
                self.assertEqual(connection.execute(
                    "SELECT state FROM provider_attempts WHERE attempt_id = ?",
                    (successor.provider_attempt_id,),
                ).fetchall(), [("accepted",)])
            finally:
                connection.close()
            connection = sqlite3.connect(restarted.budget_ledger_path)
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM role_budget_usage"
                ).fetchone(), (2,))
            finally:
                connection.close()

    def test_shared_budget_final_slot_reservations_serialize(self) -> None:
        with TemporaryDirectory() as temporary:
            execution = sealed_execution(AdvisoryRole.SUPERVISOR, self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )[0].audit.profile)
            path = Path(temporary) / "concurrent-budget.sqlite"
            ledgers = (
                DurableRoleBudgetLedger(path, grant_receipt_digest=execution.contract.admission.grant.receipt_digest,
                    execution_binding=execution.execution_binding, budget=RoleBudget(1, 1, 1)),
                DurableRoleBudgetLedger(path, grant_receipt_digest=execution.contract.admission.grant.receipt_digest,
                    execution_binding=execution.execution_binding, budget=RoleBudget(1, 1, 1)),
            )
            def reserve(ledger: DurableRoleBudgetLedger) -> bool:
                try:
                    ledger.reserve_effect()
                    return True
                except RoleCapabilityError:
                    return False
            with ThreadPoolExecutor(max_workers=2) as pool:
                self.assertEqual(sum(pool.map(reserve, ledgers)), 1)

    def test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            runner, first_backend, repository, identity, recovery, seal = self.durable_runner(
                root,
                NativeSupervisorResponse(
                    SupervisorResultKind.BLOCKED, failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                    outcome_source=SupervisorOutcomeSource.SDK_TURN_FAILED,
                    sdk_error_category=SupervisorSdkTurnErrorCategory.OVERLOAD,
                ),
            )
            second_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            second_backend = Backend("runtime-terminal-two", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), [])
            second_selection = DiffReviewSelection(
                "runtime-terminal-review-two", runner.selection.implementation_attempt_id,
                "runtime-terminal-provider-two", "runtime-terminal-message-two", "runtime-terminal-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.",
                ("Return a strict verdict.",), 2,
            )
            runner = replace(runner, sequence=(
                self.sequence_entry(runner, backend=first_backend),
                self.sequence_entry(runner, selection=second_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second_backend),
            ))
            first_only = replace(runner, sequence=(runner.sequence[0],))
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "no pre-bound fallback"):
                first_only.execute()
            first = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(first.state, AttemptState.INVALIDATED)
            checkpoint_failure = read_supervisor_terminal_failure(repository, identity, first.attempt_id)
            self.assertIsNotNone(checkpoint_failure)
            self.assertEqual(
                (first.attempt_id, checkpoint_failure.failure_class, first_backend.calls, second_backend.calls),
                (runner.selection.provider_attempt_id, SupervisorTerminalFailureClass.TRANSPORT_OR_PROVIDER_OUTAGE, 1, 0),
            )
            self.assertEqual((first_backend.calls, second_backend.calls), (1, 0))
            # A restart resumes only the already-selected successor profile.
            restarted_attempts = runner.execute()
            self.assertEqual(restarted_attempts, (runner.selection.provider_attempt_id, second_selection.provider_attempt_id))
            self.assertEqual((len(restarted_attempts), len(set(restarted_attempts))), (2, 2))
            first = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(first.state, AttemptState.INVALIDATED)
            terminal = read_supervisor_terminal_failure(repository, identity, first.attempt_id)
            self.assertIsNotNone(terminal)
            assert terminal is not None
            self.assertEqual(
                (terminal.failure_class, terminal.outcome_source, terminal.sdk_error_category),
                (SupervisorTerminalFailureClass.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorTerminalFailureSource.SDK_TURN_FAILED, SupervisorTerminalFailureSdkCategory.OVERLOAD),
            )
            self.assertEqual(
                read_attempt(repository, identity, second_selection.provider_attempt_id, context=second_recovery).state,
                AttemptState.ACCEPTED,
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM provider_invalid_outputs WHERE attempt_id = ?", (first.attempt_id,),
                ).fetchone()[0], 0)
                self.assertEqual(connection.execute(
                    "SELECT logical_profile_position, physical_format_output_ordinal FROM provider_attempts WHERE attempt_id = ?", (first.attempt_id,),
                ).fetchone(), (1, 0))
            finally:
                connection.close()
            self.assertEqual((first_backend.calls, second_backend.calls), (1, 1))
            descriptor = ProviderAttemptRuntimeDescriptor.parse({
                "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-terminal-45",
                "repository_id": identity.repository_id, "task_id": identity.task_id,
                "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                "candidate_sha": seal.candidate_sha, "case_id": "runtime-terminal-case-45", "ready_at": 17,
                "capture_plan_digest": digest("c"), "runtime_binding": recovery.runtime_binding.canonical_material(),
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
            })
            resources = ProviderAttemptRuntimeResources(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.source_digest, descriptor.case_id, descriptor.ready_at, descriptor.capture_plan_digest,
                descriptor.provider_profile_identity, 1, 1, runner,
            )
            self.assertIsNone(MaterializedProviderAttemptContext(descriptor, resources).snapshot(
                (runner.selection.provider_attempt_id,),
            )["event_graph"])

    def test_provider_outage_before_session_or_turn_checkpoint_is_durable_and_falls_back_after_restart(self) -> None:
        """Typed pre-checkpoint outages retain classification and the pre-bound route."""

        for stage in ("open-session", "start-turn"):
            with self.subTest(stage=stage), TemporaryDirectory() as temporary:
                runner, _backend, repository, identity, recovery, _seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                    suffix="outage-" + stage,
                )

                class OutageSession:
                    def identity(self):
                        return "session-provider-outage"
                    def close(self):
                        return None
                    def start_turn(self, _request):
                        raise CodexAdapterError(CodexFailure.PROVIDER_OUTAGE)

                class OutageBackend:
                    def __init__(self):
                        self.calls = 0
                    def open_fresh_session(self, _profile):
                        self.calls += 1
                        if stage == "open-session":
                            raise CodexAdapterError(CodexFailure.PROVIDER_OUTAGE)
                        return OutageSession()

                outage = OutageBackend()
                first = self.sequence_entry(runner, backend=outage)
                first_only = replace(runner, backend=outage, sequence=(first,))
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "no pre-bound fallback"):
                    first_only.execute()
                stored = read_attempt(
                    repository, identity, runner.selection.provider_attempt_id, context=recovery,
                )
                self.assertEqual(
                    (stored.state, stored.session_identity, stored.external_turn_identity),
                    (AttemptState.INVALIDATED, None if stage == "open-session" else "session-provider-outage", None),
                )
                terminal = read_supervisor_terminal_failure(repository, identity, stored.attempt_id)
                self.assertEqual(
                    terminal,
                    SupervisorTerminalFailure(
                        SupervisorTerminalFailureClass.PROVIDER_OUTAGE,
                        SupervisorTerminalFailureSource.SDK_TURN_FAILED,
                        SupervisorTerminalFailureSdkCategory.CONNECTION,
                    ),
                )
                second_recovery = provider_context(
                    recovery, identity, ProviderRole.SUPERVISOR,
                    selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
                )
                fallback = Backend(
                    "provider-outage-fallback",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                    [],
                )
                second_selection = DiffReviewSelection(
                    "provider-outage-review-two", runner.selection.implementation_attempt_id,
                    "provider-outage-attempt-two", "provider-outage-message-two",
                    "provider-outage-lease-two", runner.selection.process_lease_expires_at,
                    "Review the immutable candidate.", ("Return a strict verdict.",), 2,
                )
                restarted = replace(runner, backend=outage, sequence=(
                    first,
                    self.sequence_entry(
                        runner, selection=second_selection, recovery=second_recovery,
                        audit=second_recovery.health_receipt.audit_identity, backend=fallback,
                    ),
                ))
                self.assertEqual(
                    restarted.execute(),
                    (runner.selection.provider_attempt_id, second_selection.provider_attempt_id),
                )
                self.assertEqual((outage.calls, fallback.calls), (1, 1))
                with closing(sqlite3.connect(database_path(repository))) as connection:
                    payload = json.loads(connection.execute(
                        "SELECT record_json FROM failure_recovery_records WHERE task_id=?",
                        (identity.task_id,),
                    ).fetchone()[0])
                    self.assertEqual(
                        (payload["failure"], payload["evidence"], payload["action"]),
                        ("transient-service", "verified-service", "prebound-fallback"),
                    )

    def test_accounting_terminal_blocker_is_durable_and_never_fails_over(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )

            class Turn:
                def identity(self) -> str: return "turn-accounting-blocked"
                def abort(self) -> None: return None
                def read_response(self) -> NativeSupervisorResponse:
                    return NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {
                        "status": "blocked", "action": "retain-terminal-product-block",
                        "blocker": "provider-accounting-incomplete",
                    })

            class Session:
                def identity(self) -> str: return "session-accounting-blocked"
                def close(self) -> None: return None
                def start_turn(self, _request: object) -> Turn: return Turn()

            class BlockedBackend:
                def __init__(self) -> None: self.calls = 0
                def open_fresh_session(self, _profile: object) -> Session:
                    self.calls += 1
                    return Session()

            blocked = BlockedBackend()
            second_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            fallback = Backend("runtime-accounting-fallback", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), [])
            second = DiffReviewSelection(
                "runtime-accounting-review-two", runner.selection.implementation_attempt_id,
                "runtime-accounting-provider-two", "runtime-accounting-message-two", "runtime-accounting-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 2,
            )
            runner = replace(runner, backend=blocked, sequence=(
                self.sequence_entry(runner, backend=blocked),
                self.sequence_entry(runner, selection=second, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=fallback),
            ))
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "accounting decision is terminal"):
                runner.execute()
            stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(stored.state, AttemptState.BLOCKED)
            self.assertEqual((blocked.calls, fallback.calls), (1, 0))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM provider_invalid_outputs WHERE attempt_id = ?",
                    (runner.selection.provider_attempt_id,),
                ).fetchone()[0], 0)
                self.assertEqual(connection.execute(
                    "SELECT recovery_action, blocker FROM provider_recovery_outcomes WHERE attempt_id = ?",
                    (runner.selection.provider_attempt_id,),
                ).fetchone(), ("blocked-ambiguous-turn", "provider-accounting-incomplete"))
            finally:
                connection.close()
            with self.assertRaises(ProviderAttemptRuntimeError):
                runner.execute()
            self.assertEqual((blocked.calls, fallback.calls), (1, 0))

    def test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, first, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SHAPE),
            )
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))

            class Turn:
                def __init__(self, request: object) -> None: self._request = request
                def identity(self) -> str: return "turn-accounting-later"
                def abort(self) -> None: return None
                def read_response(self) -> NativeSupervisorResponse:
                    return NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {
                        "status": "complete", "action": "accept-formal-review", "blocker": None,
                    })

            class Session:
                def __init__(self, backend: object) -> None: self._backend = backend
                def identity(self) -> str: return "session-accounting-later"
                def close(self) -> None: return None
                def start_turn(self, request: object) -> Turn:
                    self._backend.request = request
                    return Turn(request)

            class Backend:
                def __init__(self) -> None: self.calls, self.request = 0, None
                def open_fresh_session(self, _profile: object) -> Session:
                    self.calls += 1
                    return Session(self)

            second_backend = Backend()
            second_recovery = recovery
            second = DiffReviewSelection(
                "runtime-material-review-two", runner.selection.implementation_attempt_id,
                "runtime-material-provider-two", "runtime-material-message-two", "runtime-material-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 1, physical_format_output_ordinal=1,
            )
            runner = replace(runner, sequence=(
                self.sequence_entry(runner, backend=first),
                self.sequence_entry(runner, selection=second, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second_backend),
            ))
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id, second.provider_attempt_id))
            request = second_backend.request
            self.assertIsNotNone(request)
            assert request is not None
            self.assertIs(type(request.decision_material), SupervisorAccountingSnapshot)
            material = request.decision_material.canonical_material()
            self.assertEqual(set(material), {"schema", "binding", "candidate", "review_policy", "formal_review", "dispatch_claim", "current_attempt", "prior_attempts"})
            self.assertEqual(material["schema"], "roundwright-provider-attempt-accounting-decision/v3")
            self.assertEqual(material["dispatch_claim"], "claimed")
            self.assertEqual(material["binding"]["case_id"], runner.case_id)
            self.assertEqual(material["binding"]["ready_at"], runner.ready_at)
            self.assertEqual(material["current_attempt"]["state"], "prepared")
            self.assertFalse(material["current_attempt"]["session_present"])
            self.assertEqual(material["formal_review"]["accepted_count"], 0)
            self.assertEqual(material["prior_attempts"][0]["state"], "invalidated")
            self.assertEqual(material["prior_attempts"][0]["recovery_action"], "fresh-supervisor-session")
            self.assertTrue(material["prior_attempts"][0]["session_present"])
            self.assertTrue(material["prior_attempts"][0]["turn_present"])
            self.assertNotIn("C:/", json.dumps(material, sort_keys=True))
            self.assertNotIn("findings", json.dumps(material, sort_keys=True))
            native = canonical_supervisor_review_material(request)
            self.assertEqual(native["schema"], "roundwright-provider-attempt-accounting-material/v3")
            self.assertEqual(native["decision_semantic"], "pre-dispatch-transition-eligibility/v2")
            self.assertIn("pre-dispatch eligibility", native["decision_rule"])
            self.assertIn("does not assert", native["decision_rule"])
            self.assertNotIn("PASS", json.dumps(native, sort_keys=True))
            self.assertNotIn("FINDINGS", json.dumps(native, sort_keys=True))
            self.assertNotEqual(request.input_digest, supervisor_request_digest(
                review_attempt_id=request.review_attempt_id, provider_attempt_id=request.provider_attempt_id,
                selected_profile_identity=request.selected_profile_identity,
                within_round_attempt=request.within_round_attempt, context=request.context,
                objective=request.objective, acceptance_criteria=request.acceptance_criteria,
                response_contract=request.response_contract, decision_material=request.decision_material,
                decision_semantic=None,
            ))

    def test_accounting_runtime_has_no_direct_sql_dependency(self) -> None:
        source = (ROOT / "src" / "roundwright" / "provider_attempt_runtime.py").read_text(encoding="utf-8")
        self.assertNotIn("import sqlite3", source)
        self.assertNotIn("database_path", source)
        self.assertNotIn("provider_attempts WHERE", source)

    def test_terminal_failure_projection_is_closed_and_rejects_untrusted_strings_before_mutation(self) -> None:
        self.assertEqual(tuple(item.value for item in SupervisorTerminalFailureClass), tuple(item.value for item in CodexFailure))
        self.assertEqual(tuple(item.value for item in SupervisorTerminalFailureSdkCategory), tuple(item.value for item in SupervisorSdkTurnErrorCategory))
        self.assertEqual(tuple(item.value for item in SupervisorTerminalFailureSource), tuple(item.value for item in SupervisorOutcomeSource))
        for failure in SupervisorTerminalFailureClass:
            for category in SupervisorTerminalFailureSdkCategory:
                value = SupervisorTerminalFailure(failure, SupervisorTerminalFailureSource.SDK_TURN_FAILED, category)
                self.assertEqual((value.failure_class, value.outcome_source, value.sdk_error_category), (failure, SupervisorTerminalFailureSource.SDK_TURN_FAILED, category))
        with TemporaryDirectory() as temporary:
            runner, _backend, repository, identity, recovery, _seal = self.durable_runner(
                Path(temporary) / "repository", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            connection = sqlite3.connect(database_path(repository))
            try:
                before = connection.execute("SELECT COUNT(*) FROM provider_recovery_outcomes").fetchone()[0]
            finally:
                connection.close()
            for raw in ("C:/private/path", "private:error", "raw provider error", "C:\\private\\error"):
                with self.subTest(raw=raw):
                    with self.assertRaises(ProviderRecoveryError) as raised:
                        record_supervisor_terminal_failure(
                            repository, identity, recovery, attempt_id=runner.selection.provider_attempt_id,
                            failure_class=raw, outcome_source=raw, sdk_error_category=raw, lease=runner.lease,
                        )  # type: ignore[arg-type]
                    self.assertNotIn("private", str(raised.exception))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_recovery_outcomes").fetchone()[0], before)
            finally:
                connection.close()

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

    def test_prepared_snapshot_and_claim_failures_are_public_safe(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, _, _, _, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            with patch("roundwright.provider_attempt_runtime.prepare_attempt", side_effect=ProviderRecoveryError("C:/private/checkpoint")):
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "prepared checkpoint is unavailable") as raised:
                    runner.materialize_prepared_snapshot()
            self.assertNotIn("private", str(raised.exception))
            self.assertEqual(backend.calls, 0)
            runner.materialize_prepared_snapshot()
            with patch("roundwright.provider_attempt_runtime.read_supervisor_dispatch_claim", side_effect=ProviderRecoveryError("C:/private/claim")):
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "dispatch claim is unavailable") as raised:
                    runner.execute()
            self.assertNotIn("private", str(raised.exception))
            self.assertEqual(backend.calls, 0)

    def test_unclaimed_dispatch_snapshot_cannot_open_a_native_turn(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, _, _, _, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            unclaimed = runner.materialize_prepared_snapshot()
            with patch("roundwright.provider_attempt_runtime.read_supervisor_accounting_snapshot", return_value=unclaimed):
                with self.assertRaisesRegex(ProviderAttemptRuntimeError, "dispatch claim has drifted"):
                    runner.execute()
            self.assertEqual(backend.calls, 0)

    def test_claim_fingerprint_drift_fails_closed_before_native_dispatch(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            runner.materialize_prepared_snapshot()
            claim_supervisor_dispatch(repository, identity, recovery, attempt_id=runner.selection.provider_attempt_id, lease=runner.lease, now=runner.dispatch_control.now)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute("UPDATE provider_dispatch_claims SET claim_fingerprint=? WHERE attempt_id=?", (digest("f"), runner.selection.provider_attempt_id))
                connection.commit()
            finally:
                connection.close()
            with self.assertRaises(ProviderRecoveryError) as raised:
                read_supervisor_dispatch_claim(repository, identity, recovery, attempt_id=runner.selection.provider_attempt_id)
            self.assertNotIn("f" * 64, str(raised.exception))
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "dispatch claim is unavailable"):
                runner.execute()
            self.assertEqual(backend.calls, 0)

    def test_missing_session_identity_retains_a_prepared_attempt_without_redispatch(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            class NoSessionBackend:
                def __init__(self) -> None:
                    self.calls = 0
                def open_fresh_session(self, _profile: object) -> object:
                    self.calls += 1
                    raise RuntimeError("session unavailable")

            backend = NoSessionBackend()
            runner = replace(runner, backend=backend)
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "session checkpoint"):
                runner.execute()
            self.assertEqual(backend.calls, 1)
            stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(stored.state, AttemptState.PREPARED)
            self.assertIsNone(stored.session_identity)
            self.assertIsNone(stored.external_turn_identity)
            self.assertIsNone(stored.output_pointer)
            self.assertIsNone(stored.accepted_review_identity)
            with self.assertRaises(ProviderAttemptRuntimeError):
                runner.execute()
            self.assertEqual(backend.calls, 1)

    def test_local_session_checkpoint_failure_is_not_a_native_provider_outcome(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            events: list[object] = []
            first = Backend("runtime-local-session", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), events)
            second_recovery = provider_context(recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1])
            second = Backend("runtime-local-session-two", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), events)
            second_selection = replace(runner.selection,
                diff_review_attempt_id="runtime-local-session-review-two",
                provider_attempt_id="runtime-local-session-provider-two",
                message_identity="runtime-local-session-message-two",
                process_lease_id="runtime-local-session-lease-two", within_round_attempt=2)
            runner = replace(runner, backend=first, sequence=(
                self.sequence_entry(runner, backend=first),
                self.sequence_entry(runner, selection=second_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second),
            ))
            with patch("roundwright.provider_attempt_runtime.checkpoint_diff_review_session", side_effect=RuntimeError("private callback detail")):
                with self.assertRaises(ProviderAttemptCheckpointFailure) as raised:
                    runner.execute()
            failure = raised.exception
            self.assertEqual((failure.stage, failure.session_present, failure.turn_present), ("session-checkpoint", True, False))
            self.assertIn("session-present=true; turn-present=false", str(failure))
            self.assertNotIn("private", str(failure))
            self.assertEqual((first.calls, second.calls), (1, 0))
            self.assertTrue(any(item[0] == "close" for item in events))
            stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(stored.state, AttemptState.PREPARED)
            self.assertIsNone(stored.session_identity)
            self.assertIsNone(stored.external_turn_identity)
            self.assertIsNone(stored.output_pointer)
            self.assertIsNone(stored.accepted_review_identity)
            with self.assertRaises(ProviderAttemptRuntimeError):
                runner.execute()
            self.assertEqual((first.calls, second.calls), (1, 0))

    def test_local_turn_checkpoint_failure_preserves_only_the_session_checkpoint(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, _ = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            events: list[object] = []
            first = Backend("runtime-local-turn", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), events)
            second_recovery = provider_context(recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1])
            second = Backend("runtime-local-turn-two", NativeSupervisorResponse(
                SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []},
            ), events)
            second_selection = replace(runner.selection,
                diff_review_attempt_id="runtime-local-turn-review-two",
                provider_attempt_id="runtime-local-turn-provider-two",
                message_identity="runtime-local-turn-message-two",
                process_lease_id="runtime-local-turn-lease-two", within_round_attempt=2)
            runner = replace(runner, backend=first, sequence=(
                self.sequence_entry(runner, backend=first),
                self.sequence_entry(runner, selection=second_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second),
            ))
            with patch("roundwright.provider_attempt_runtime.dispatch_diff_review", side_effect=RuntimeError("private callback detail")):
                with self.assertRaises(ProviderAttemptCheckpointFailure) as raised:
                    runner.execute()
            failure = raised.exception
            self.assertEqual((failure.stage, failure.session_present, failure.turn_present), ("turn-checkpoint", True, True))
            self.assertIn("session-present=true; turn-present=true", str(failure))
            self.assertNotIn("private", str(failure))
            self.assertEqual((first.calls, second.calls), (1, 0))
            stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(stored.state, AttemptState.PREPARED)
            self.assertIsNotNone(stored.session_identity)
            self.assertIsNone(stored.external_turn_identity)
            self.assertIsNone(stored.output_pointer)
            self.assertIsNone(stored.accepted_review_identity)
            with self.assertRaises(ProviderAttemptRuntimeError):
                runner.execute()
            self.assertEqual((first.calls, second.calls), (1, 0))

    def test_projection_binds_non_first_epoch_and_formal_round(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, _, repository, identity, recovery, seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            execution, execution_host = self.effect_trust(
                identity=identity, recovery=recovery, seal=seal,
                source_digest=runner.source_digest, review_epoch=2, review_round=4,
                selection=runner.selection, audit=runner.audit,
            )
            runner = replace(
                runner, review_epoch=2, review_round=4,
                advisory_execution=execution, execution_host=execution_host,
            )
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id,))
            descriptor = ProviderAttemptRuntimeDescriptor.parse({
                "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-round-45",
                "repository_id": identity.repository_id, "task_id": identity.task_id,
                "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                "candidate_sha": seal.candidate_sha, "case_id": "runtime-round-case-45", "ready_at": 17,
                "capture_plan_digest": digest("b"), "runtime_binding": recovery.runtime_binding.canonical_material(),
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 2, "review_round": 4, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
            })
            resources = ProviderAttemptRuntimeResources(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.source_digest, descriptor.case_id, descriptor.ready_at, descriptor.capture_plan_digest,
                descriptor.provider_profile_identity, 2, 4, runner,
            )
            snapshot = MaterializedProviderAttemptContext(descriptor, resources).snapshot((runner.selection.provider_attempt_id,))
            graph = snapshot["event_graph"]
            self.assertEqual((snapshot["review_epoch"], snapshot["review_round"], snapshot["review_mode"]), (2, 4, "CONVERGING"))
            assert graph is not None
            self.assertEqual(graph.review_rounds[0].ordinal, 1)  # graph-local ordinal
            self.assertTrue(all("e2-r4-" in value for value in (
                graph.review_rounds[0].review_round_id,
                graph.accepted_results[0].result_id,
                graph.accepted_results[0].event_id,
            )))
            self.assertTrue(all(item.review_round_id == graph.review_rounds[0].review_round_id for item in graph.attempts))

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
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
            }
            context = install_host_runtime(descriptor, ProviderAttemptHostInputs(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection, backend,
                advisory_execution=runner.advisory_execution,
                execution_host=runner.execution_host,
                budget_ledger_path=runner.budget_ledger_path,
            ))
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE task_id=? AND attempt_id=?", (identity.task_id, runner.selection.provider_attempt_id)).fetchone()[0], 0)
            finally:
                connection.close()
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
                prepared = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
                self.assertEqual(prepared.state, AttemptState.PREPARED)
                self.assertEqual((prepared.session_identity, prepared.external_turn_identity, prepared.output_pointer, prepared.accepted_review_identity), (None, None, None, None))
                self.assertEqual(backend.calls, 0)
                adapter.validate(binding)
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE task_id=? AND attempt_id=?", (identity.task_id, runner.selection.provider_attempt_id)).fetchone()[0], 1)
                finally:
                    connection.close()
                execution = adapter.execute(binding)
                evidence = adapter.project(binding, execution)
                self.assertEqual(adapter.compare(binding, evidence).status, "pass")
                self.assertEqual(backend.calls, 1)
                adapter.validate(binding)
                restarted = adapter.execute(binding)
                self.assertEqual(adapter.project(binding, restarted), evidence)
                self.assertEqual(backend.calls, 1)
                connection = sqlite3.connect(database_path(repository))
                try:
                    connection.execute("UPDATE provider_dispatch_claims SET claim_fingerprint=? WHERE attempt_id=?", (digest("e"), runner.selection.provider_attempt_id))
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaises(external_validation.ExternalValidationAdapterError):
                    adapter.validate(binding)
                self.assertEqual(backend.calls, 1)
            finally:
                for name, value in (("roundwright_harness", prior_package), ("roundwright_harness.executor", prior_module)):
                    if value is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = value

    def test_hosted_validate_blocks_checkpoint_prerequisite_drift_without_dispatch(self) -> None:
        with TemporaryDirectory() as temporary:
            runner, backend, repository, identity, recovery, seal = self.durable_runner(
                Path(temporary) / "repository",
                NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
            )
            descriptor = {
                "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-preflight-45",
                "repository_id": identity.repository_id, "task_id": identity.task_id,
                "source_digest": runner.source_digest, "base_sha": identity.base_sha,
                "candidate_sha": seal.candidate_sha, "case_id": "runtime-preflight-case-45", "ready_at": 17,
                "capture_plan_digest": digest("e"), "runtime_binding": recovery.runtime_binding.canonical_material(),
                "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
            }
            context = install_host_runtime(descriptor, ProviderAttemptHostInputs(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection, backend,
                advisory_execution=runner.advisory_execution,
                execution_host=runner.execution_host,
                budget_ledger_path=runner.budget_ledger_path,
            ))
            drifted_runner = replace(context.resources.runner, selection=replace(
                runner.selection, implementation_attempt_id="runtime-preflight-missing-implementation",
            ))
            context = MaterializedProviderAttemptContext(context.descriptor, replace(context.resources, runner=drifted_runner))
            prior_package, prior_module = fake_harness()
            try:
                adapter = external_validation.ProviderAttemptAccountingAdapter()
                producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
                binding = type("Binding", (), {
                    "profile": external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
                    "case_id": descriptor["case_id"], "candidate_sha": seal.candidate_sha, "ready_at": 17,
                    "plan": type("Plan", (), {"plan_digest": descriptor["capture_plan_digest"]})(),
                    "components": type("Components", (), {"producer_identity": producer, "exporter_identity": exporter, "comparator_identity": comparator})(),
                    "execution_context": type("Context", (), {"value": context})(),
                    "execution_context_input_digest": digest("f"),
                })()
                with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "checkpoint preflight"):
                    adapter.validate(binding)
                dirty = runner.binding.worktree / "readiness-drift.txt"
                dirty.write_text("untracked", encoding="utf-8")
                connection = sqlite3.connect(database_path(repository))
                try:
                    before = connection.execute(
                        "SELECT (SELECT COUNT(*) FROM candidate_seals WHERE task_id = ?), "
                        "(SELECT COUNT(*) FROM candidate_evidence WHERE task_id = ?)",
                        (identity.task_id, identity.task_id),
                    ).fetchone()
                finally:
                    connection.close()
                with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "checkpoint preflight"):
                    adapter.validate(binding)
                connection = sqlite3.connect(database_path(repository))
                try:
                    after = connection.execute(
                        "SELECT (SELECT COUNT(*) FROM candidate_seals WHERE task_id = ?), "
                        "(SELECT COUNT(*) FROM candidate_evidence WHERE task_id = ?)",
                        (identity.task_id, identity.task_id),
                    ).fetchone()
                finally:
                    connection.close()
                self.assertEqual(after, before)
            finally:
                for name, value in (("roundwright_harness", prior_package), ("roundwright_harness.executor", prior_module)):
                    if value is None:
                        sys.modules.pop(name, None)
                    else:
                        sys.modules[name] = value
            self.assertEqual(backend.calls, 0)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM provider_attempts WHERE attempt_id = ?",
                        (runner.selection.provider_attempt_id,),
                    ).fetchone()[0],
                    0,
                )
            finally:
                connection.close()

    @unittest.skip("provider-attempt production activation intentionally unavailable")
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
                runner, first_backend, repository, identity, recovery, seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.INVALID, diagnostic=SupervisorDiagnostic.SYNTAX),
                )
                second_recovery = provider_context(
                    recovery, identity, ProviderRole.SUPERVISOR,
                    selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
                )
                second_backend = Backend(
                    "runtime-hosted-two",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                    [],
                )
                second_selection = DiffReviewSelection(
                    "runtime-hosted-review-two", runner.selection.implementation_attempt_id,
                    "runtime-hosted-provider-two", "runtime-hosted-message-two", "runtime-hosted-lease-two",
                    runner.selection.process_lease_expires_at, "Review the immutable candidate.",
                    ("Return a strict verdict.",), 2,
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
                    "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
                }
                request = {
                    "schema": "roundwright-harness-profile-executor-request/v2",
                    "capture_plan": plan,
                    "execution_context": descriptor,
                }
                sequence = (
                    self.sequence_entry(runner, backend=first_backend),
                    self.sequence_entry(runner, selection=second_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second_backend),
                )
                host = ProviderAttemptHostInputs(
                    repository, identity, recovery, runner.lease, seal, runner.binding,
                    runner.dependency_binding, runner.dispatch_control,
                    (runner.audit, second_recovery.health_receipt.audit_identity), runner.selection, first_backend,
                    execution_host=runner.execution_host,
                    budget_ledger_path=runner.budget_ledger_path,
                    sequence=sequence,
                    advisory_execution=runner.advisory_execution,
                )
                store = Path(temporary) / "recorder"
                parsed = harness.ExecutorRequest.parse(request)
                self.assertEqual(parsed.schema, "roundwright-harness-profile-executor-request/v2")
                self.assertEqual(parsed.capture_plan["profile"], external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE)
                self.assertIsNotNone(parsed.execution_context)
                assert parsed.execution_context is not None
                self.assertIs(type(parsed.execution_context["completion_policy"]), MappingProxyType)
                readiness = external_validation.run_provider_attempt_accounting_profile(
                    "validate", request, store, host,
                )
                self.assertEqual(readiness.as_dict()["dispatch_count"], 0)
                self.assertEqual((first_backend.calls, second_backend.calls), (0, 0))
                result = external_validation.run_provider_attempt_accounting_profile(
                    "execute", request, store, host,
                    expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                )
                receipt = result.as_dict()
                self.assertEqual((receipt["status"], receipt["mutation_count"]), ("pass", 0))
                self.assertEqual((first_backend.calls, second_backend.calls), (1, 1))
                self.assertEqual(read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery).state, AttemptState.INVALIDATED)
                self.assertEqual(read_attempt(repository, identity, second_selection.provider_attempt_id, context=recovery).state, AttemptState.ACCEPTED)
                context = install_host_runtime(descriptor, host)
                snapshot = context.snapshot((runner.selection.provider_attempt_id, second_selection.provider_attempt_id))
                self.assertEqual((snapshot["review_epoch"], snapshot["review_round"], snapshot["review_mode"]), (1, 1, "COMPLETE"))
                graph = snapshot["event_graph"]
                self.assertIsNotNone(graph)
                assert graph is not None
                self.assertEqual(len(graph.provider_attempts), 2)
                self.assertEqual(len(graph.review_rounds), 1)
                self.assertEqual((graph.attempts[0].kind.value, graph.attempts[1].kind.value), ("supervisor", "failover"))
                self.assertEqual(graph.attempts[1].parent_attempt_id, graph.attempts[0].attempt_id)
                self.assertEqual(snapshot["provider_identity"], graph.provider_attempts[1].provider_identity)
                self.assertIn("invalid-output", tuple(item.event_kind for item in graph.events))
                self.assertIn("recovery-attempt", tuple(item.event_kind for item in graph.events))
                self.assertEqual(sum(item.accepted_result_id is not None for item in graph.events), 1)
                # A separate hosted invocation reads the persisted bounded
                # sequence; it cannot dispatch or accept a second formal result.
                repeated = external_validation.run_provider_attempt_accounting_profile(
                    "execute", request, store, host,
                    expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                )
                self.assertEqual(repeated.as_dict()["bundle_digest"], receipt["bundle_digest"])
                self.assertEqual((first_backend.calls, second_backend.calls), (1, 1))
        finally:
            sys.path.remove(str(source))
            for name in tuple(sys.modules):
                if name == "roundwright_harness" or name.startswith("roundwright_harness."):
                    sys.modules.pop(name, None)
            sys.modules.update(prior_modules)

    @unittest.skip("provider-attempt production activation intentionally unavailable")
    def test_hosted_ambiguous_attempt_blocks_before_failover_dispatch(self) -> None:
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
                runner, _, repository, identity, recovery, seal = self.durable_runner(
                    Path(temporary) / "repository",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}),
                )
                class SessionWithoutTurn:
                    def identity(self) -> str:
                        return "runtime-hosted-preturn-session"
                    def close(self) -> None:
                        return None
                    def start_turn(self, _request: object) -> object:
                        raise RuntimeError("turn identity is unavailable")

                class SessionOnlyBackend:
                    def __init__(self) -> None:
                        self.calls = 0
                    def open_fresh_session(self, _profile: object) -> SessionWithoutTurn:
                        self.calls += 1
                        return SessionWithoutTurn()

                first_backend = SessionOnlyBackend()
                second_recovery = provider_context(
                    recovery, identity, ProviderRole.SUPERVISOR,
                    selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
                )
                second_backend = Backend(
                    "runtime-hosted-ambiguous-two",
                    NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), [],
                )
                second_selection = DiffReviewSelection(
                    "runtime-hosted-ambiguous-review-two", runner.selection.implementation_attempt_id,
                    "runtime-hosted-ambiguous-provider-two", "runtime-hosted-ambiguous-message-two", "runtime-hosted-ambiguous-lease-two",
                    runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 2,
                )
                producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
                plan = {
                    "schema": "roundwright-harness-capture-plan/v1", "profile": external_validation.PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
                    "ready_at": 17, "case_id": "runtime-hosted-ambiguous-case-45", "candidate_sha": seal.candidate_sha,
                    "producer_identity": producer, "exporter_identity": exporter, "comparator_identity": comparator,
                    "recorder_identity": digest("8"), "store_identity": digest("9"), "observation_identity": digest("a"),
                }
                descriptor = {
                    "schema": "roundwright-provider-attempt-runtime/v2", "resource_id": "runtime-hosted-ambiguous-45",
                    "repository_id": identity.repository_id, "task_id": identity.task_id, "source_digest": runner.source_digest,
                    "base_sha": identity.base_sha, "candidate_sha": seal.candidate_sha, "case_id": plan["case_id"], "ready_at": 17,
                    "capture_plan_digest": harness.prepare_capture(plan).plan_digest,
                    "runtime_binding": recovery.runtime_binding.canonical_material(),
                    "provider_profile_identity": runner.audit.profile_identity, "review_epoch": 1, "review_round": 1, "completion_policy": PRODUCTION_COMPLETION_POLICY.receipt(),
                }
                request = {"schema": "roundwright-harness-profile-executor-request/v2", "capture_plan": plan, "execution_context": descriptor}
                host = ProviderAttemptHostInputs(
                    repository, identity, recovery, runner.lease, seal, runner.binding,
                    runner.dependency_binding, runner.dispatch_control,
                    (runner.audit, second_recovery.health_receipt.audit_identity), runner.selection, first_backend,
                    execution_host=runner.execution_host,
                    budget_ledger_path=runner.budget_ledger_path,
                    sequence=(
                        self.sequence_entry(runner, backend=first_backend),
                        self.sequence_entry(runner, selection=second_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second_backend),
                    ),
                    advisory_execution=runner.advisory_execution,
                )
                preflight_descriptor = dict(descriptor, resource_id="runtime-hosted-ambiguous-preflight-45")
                preflight_request = dict(request, execution_context=preflight_descriptor)
                duplicate_selection = replace(second_selection, provider_attempt_id=runner.selection.provider_attempt_id)
                preflight_host = replace(host, sequence=(
                    self.sequence_entry(runner, backend=first_backend),
                    self.sequence_entry(runner, selection=duplicate_selection, recovery=second_recovery, audit=second_recovery.health_receipt.audit_identity, backend=second_backend),
                ))
                with self.assertRaises(external_validation.ExternalValidationAdapterError):
                    external_validation.run_provider_attempt_accounting_profile(
                        "validate", preflight_request, Path(temporary) / "preflight-recorder", preflight_host,
                    )
                self.assertEqual((first_backend.calls, second_backend.calls), (0, 0))
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM provider_attempts WHERE attempt_id IN (?, ?)",
                            (runner.selection.provider_attempt_id, duplicate_selection.provider_attempt_id),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    connection.close()
                readiness = external_validation.run_provider_attempt_accounting_profile("validate", request, Path(temporary) / "recorder", host)
                with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "durable turn checkpoint"):
                    external_validation.run_provider_attempt_accounting_profile(
                        "execute", request, Path(temporary) / "recorder", host,
                        expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                    )
                self.assertEqual((first_backend.calls, second_backend.calls), (1, 0))
                stored = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
                self.assertEqual(stored.state, AttemptState.BLOCKED)
                self.assertEqual(stored.session_identity, "runtime-hosted-preturn-session")
                self.assertIsNone(stored.external_turn_identity)
                self.assertIsNone(stored.accepted_review_identity)
                connection = sqlite3.connect(database_path(repository))
                try:
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM provider_invalid_outputs WHERE attempt_id = ?",
                            (runner.selection.provider_attempt_id,),
                        ).fetchone()[0],
                        0,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM diff_review_attempts WHERE provider_attempt_id = ?",
                            (runner.selection.provider_attempt_id,),
                        ).fetchone()[0],
                        0,
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM accepted_provider_reviews WHERE attempt_id = ?",
                            (runner.selection.provider_attempt_id,),
                        ).fetchone()[0],
                        0,
                    )
                finally:
                    connection.close()
                with self.assertRaisesRegex(external_validation.ExternalValidationAdapterError, "durable turn checkpoint"):
                    external_validation.run_provider_attempt_accounting_profile(
                        "execute", request, Path(temporary) / "recorder", host,
                        expected_readiness_digest=str(readiness.as_dict()["receipt_digest"]),
                    )
                self.assertEqual((first_backend.calls, second_backend.calls), (1, 0))
        finally:
            sys.path.remove(str(source))
            for name in tuple(sys.modules):
                if name == "roundwright_harness" or name.startswith("roundwright_harness."):
                    sys.modules.pop(name, None)
            sys.modules.update(prior_modules)


if __name__ == "__main__":
    unittest.main()
