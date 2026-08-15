"""Provider-attempt V2 descriptor and opaque-resource boundary coverage."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sqlite3
import sys
import unittest
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
    SupervisorResultKind, SupervisorSdkTurnErrorCategory,
)
from roundwright.dependency_policy import CandidateBinding
from roundwright.git_identity import CandidateSeal, TransitionLease, WorktreeBinding
from roundwright.provider_attempt_runtime import (
    DiffReviewSelection, DiffReviewSequenceEntry, DurableDiffReviewRunner, MaterializedProviderAttemptContext,
    ProviderAttemptCheckpointFailure, ProviderAttemptHostInputs, ProviderAttemptRuntimeDescriptor, ProviderAttemptRuntimeError,
    ProviderAttemptRuntimeResources, ProviderAttemptCompletionPolicy, PRODUCTION_COMPLETION_POLICY,
    install_host_runtime,
)
from roundwright.provider_health import CodexFailure
from roundwright.provider_recovery import (
    AttemptState, ProviderRecoveryError, ProviderRole, RecoveryContext, SupervisorAccountingSnapshot,
    SupervisorTerminalFailure, read_attempt, read_supervisor_terminal_failure,
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
            case_id=f"runtime-case-{suffix}", ready_at=now,
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
            )
            host = ProviderAttemptHostInputs(
                repository, identity, recovery, runner.lease, seal, runner.binding,
                runner.dependency_binding, runner.dispatch_control, (runner.audit,), runner.selection,
                short_native,
            )
            with self.assertRaisesRegex(ProviderAttemptRuntimeError, "completion policy"):
                install_host_runtime(descriptor, host)
            self.assertEqual(backend.calls, 0)
            # The production host chooses its closed native backend with the
            # descriptor-bound production deadline; it cannot retain the old
            # test-scale fallback when no test seam is supplied.
            materialized = install_host_runtime(
                dict(descriptor, resource_id="runtime-production-deadline-45"),
                replace(host, backend=None),
            )
            self.assertIsInstance(materialized.resources.runner.backend, HarnessNativeCodexSupervisorBackend)
            self.assertEqual(
                materialized.resources.runner.backend.completion,
                CompletionDeadline(100_000, 600_000),
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
            second_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            second_backend = Backend("runtime-two", NativeSupervisorResponse(SupervisorResultKind.ACCEPTED, {"verdict": "pass", "findings": []}), [])
            second_selection = DiffReviewSelection(
                "runtime-review-two", runner.selection.implementation_attempt_id,
                "runtime-provider-two", "runtime-message-two", "runtime-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 2,
            )
            accepted = replace(runner, sequence=(
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, runner.backend),
                DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
            ))
            self.assertEqual(accepted.execute(), ("runtime-provider-one", "runtime-provider-two"))
            self.assertEqual(read_attempt(repository, identity, "runtime-provider-two", context=recovery).state, AttemptState.ACCEPTED)

    def test_terminal_supervisor_failure_is_durable_and_fails_over_without_invalid_output(self) -> None:
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
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first_backend),
                DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
            ))
            first_only = replace(runner, sequence=(runner.sequence[0],))
            self.assertEqual(first_only.execute(), (runner.selection.provider_attempt_id,))
            first = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(first.state, AttemptState.INVALIDATED)
            checkpoint_failure = read_supervisor_terminal_failure(repository, identity, first.attempt_id)
            self.assertIsNotNone(checkpoint_failure)
            self.assertEqual((first_backend.calls, second_backend.calls), (1, 0))
            # Restart from the durable terminal-failure checkpoint may dispatch
            # only the still-unseen configured secondary; it must not replay
            # the first turn, failure record, or failover transition.
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id, second_selection.provider_attempt_id))
            first = read_attempt(repository, identity, runner.selection.provider_attempt_id, context=recovery)
            self.assertEqual(first.state, AttemptState.INVALIDATED)
            terminal = read_supervisor_terminal_failure(repository, identity, first.attempt_id)
            self.assertIsNotNone(terminal)
            assert terminal is not None
            self.assertEqual(
                (terminal.failure_class, terminal.outcome_source, terminal.sdk_error_category),
                (SupervisorTerminalFailureClass.TRANSPORT_OR_PROVIDER_OUTAGE, SupervisorTerminalFailureSource.SDK_TURN_FAILED, SupervisorTerminalFailureSdkCategory.OVERLOAD),
            )
            self.assertEqual(read_attempt(repository, identity, second_selection.provider_attempt_id, context=recovery).state, AttemptState.ACCEPTED)
            connection = sqlite3.connect(database_path(repository))
            try:
                self.assertEqual(connection.execute(
                    "SELECT COUNT(*) FROM provider_invalid_outputs WHERE attempt_id = ?", (first.attempt_id,),
                ).fetchone()[0], 0)
            finally:
                connection.close()
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id, second_selection.provider_attempt_id))
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
            graph = MaterializedProviderAttemptContext(descriptor, resources).snapshot(
                (runner.selection.provider_attempt_id, second_selection.provider_attempt_id),
            )["event_graph"]
            assert graph is not None
            self.assertIn("provider-terminal-failure", tuple(item.event_kind for item in graph.events))
            self.assertNotIn("invalid-output", tuple(item.event_kind for item in graph.events))

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
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, blocked),
                DiffReviewSequenceEntry(second, second_recovery, second_recovery.health_receipt.audit_identity, fallback),
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
            second_recovery = provider_context(
                recovery, identity, ProviderRole.SUPERVISOR,
                selected_profile_identity=recovery.runtime_binding.supervisor_profile_identities[1],
            )
            second = DiffReviewSelection(
                "runtime-material-review-two", runner.selection.implementation_attempt_id,
                "runtime-material-provider-two", "runtime-material-message-two", "runtime-material-lease-two",
                runner.selection.process_lease_expires_at, "Review the immutable candidate.", ("Return a strict verdict.",), 2,
            )
            runner = replace(runner, sequence=(
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first),
                DiffReviewSequenceEntry(second, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
            ))
            self.assertEqual(runner.execute(), (runner.selection.provider_attempt_id, second.provider_attempt_id))
            request = second_backend.request
            self.assertIsNotNone(request)
            assert request is not None
            self.assertIs(type(request.decision_material), SupervisorAccountingSnapshot)
            material = request.decision_material.canonical_material()
            self.assertEqual(set(material), {"schema", "binding", "candidate", "review_policy", "formal_review", "current_attempt", "prior_attempts"})
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
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first),
                DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second),
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
                DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first),
                DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second),
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
            runner = replace(runner, review_epoch=2, review_round=4)
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
                    DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first_backend),
                    DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
                )
                host = ProviderAttemptHostInputs(
                    repository, identity, recovery, runner.lease, seal, runner.binding,
                    runner.dependency_binding, runner.dispatch_control,
                    (runner.audit, second_recovery.health_receipt.audit_identity), runner.selection, first_backend, sequence,
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
                    (
                        DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first_backend),
                        DiffReviewSequenceEntry(second_selection, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
                    ),
                )
                preflight_descriptor = dict(descriptor, resource_id="runtime-hosted-ambiguous-preflight-45")
                preflight_request = dict(request, execution_context=preflight_descriptor)
                duplicate_selection = replace(second_selection, provider_attempt_id=runner.selection.provider_attempt_id)
                preflight_host = replace(host, sequence=(
                    DiffReviewSequenceEntry(runner.selection, recovery, runner.audit, first_backend),
                    DiffReviewSequenceEntry(duplicate_selection, second_recovery, second_recovery.health_receipt.audit_identity, second_backend),
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
