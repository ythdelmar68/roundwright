from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing, contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import BoundedWorkerToolSurface, CodexWorkerAdapter, CodexWorkerContext, CodexWorkerRequest, NativeWorkerResponse, NativeWorkerToolRequest, NativeWorkerTurnStep, WorkerAction, WorkerOutcomeSource, WorkerResultKind, WorkerSdkTurnErrorCategory, WorkerTool, worker_request_digest
from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools, CodingSandboxResult, ReviewedSandboxReceipt, ReviewedValidationSandbox
from roundwright.coding_worker_state import CodingToolEventStore
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_recovery import ProviderRole, prepare_attempt
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.role_capability_policy import AdvisoryRole, RoleCapability, RoleScope, ScopeKind, ScopedDescriptor
from tests.role_admission_fixture import sealed_execution_for_effect, trusted_execution_host
from roundwright.worker_toolbox import CODING_RUNTIME_REGISTRY, CodingDispatchReceipt, CodingWorkerRuntimeDescriptor, ProductionCodingWorkerEntrypointInputs, ProductionCodingWorkerRuntime, ProductionWorkerFailureLifecycle, run_production_coding_worker, run_registered_production_coding_worker
from roundwright.worker_shadow import WorkerShadowError
from tests.test_provider_recovery import ProviderRecoveryTests
from roundwright.failure_recovery import FailureClass, FailureRole, parse_failure_record
from roundwright.provider_recovery import AttemptState, read_attempt
from roundwright.state import database_path


def digest(value: str | bytes) -> str: return "sha256:" + hashlib.sha256(value.encode() if isinstance(value,str) else value).hexdigest()

class Turn:
    id = "turn-1"
    def __init__(self, events, steps): self.events, self.steps, self.submitted = events, iter(steps), []
    def identity(self): return self.id
    def abort(self): self.events.append("abort")
    def read_response(self): self.events.append("legacy"); return NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status":"done"})
    def read_step(self): self.events.append("step"); return next(self.steps)
    def submit_tool_result(self, result): self.events.append("submit"); self.submitted.append(result)

class Session:
    id = "session-1"
    def __init__(self, turn, events): self.turn, self.events = turn, events
    def identity(self): return self.id
    def close(self): self.events.append("close")
    def start_turn(self, *_): self.events.append("start"); return self.turn

class Backend:
    def __init__(self, session): self.session, self.calls = session, 0
    def open_session(self, *_args, **_kwargs): self.calls += 1; return self.session

class Sandbox(ReviewedValidationSandbox):
    def __init__(self, output=b""): self.output = output
    @property
    def identity(self): return digest("sandbox")
    @property
    def receipt(self):
        return ReviewedSandboxReceipt.seal(
            identity=self.identity, filesystem_policy_digest=digest("filesystem"),
            network_policy_digest=digest("network"), credential_policy_digest=digest("credentials"),
            executable_policy_digest=digest("executables"), child_cleanup_digest=digest("cleanup"),
        )
    def execute(self, **_kwargs): return CodingSandboxResult(0, self.output)

class ProductionRuntimeTests(unittest.TestCase):
    def coding_scope(self, root: Path, command: tuple[str, ...]):
        root_identity = digest(json.dumps({"schema": "roundwright-bounded-coding-root/v1", "root": str(root.resolve())}, sort_keys=True, separators=(",", ":")))
        process_identity = digest(json.dumps({"command": command}, sort_keys=True, separators=(",", ":")))[7:]
        resource_identity = digest(json.dumps({"sandbox_identity": digest("sandbox")}, sort_keys=True, separators=(",", ":")))[7:]
        descriptors = (
            ScopedDescriptor(ScopeKind.PATH, root_identity, "out.txt"),
            ScopedDescriptor(ScopeKind.PROCESS, root_identity, process_identity),
            ScopedDescriptor(ScopeKind.NETWORK, root_identity, "network-disabled"),
            ScopedDescriptor(ScopeKind.RESOURCE, root_identity, resource_identity),
            ScopedDescriptor(ScopeKind.TEST_INPUT_SET, root_identity, process_identity),
        )
        return RoleScope(frozenset({RoleCapability.BOUNDED_CODING}), tuple(sorted(descriptors, key=lambda item: (item.kind.value, item.root_identity, item.value)))), root_identity

    def recovery_fixture(self):
        fixture = ProviderRecoveryTests()
        identity = fixture.identity("coding-runtime")
        recovery = fixture.context(identity, candidate="a" * 40, role=ProviderRole.WORKER)
        return fixture, identity, recovery

    def request(self):
        _fixture, identity, recovery = self.recovery_fixture()
        context = CodexWorkerContext(
            identity.task_id, digest("source"),
            "sha256:" + recovery.repository_fingerprint,
            "sha256:" + recovery.worktree_fingerprint,
            "sha256:" + recovery.branch_fingerprint,
            "sha256:" + recovery.base_fingerprint,
            "sha256:" + (recovery.candidate_fingerprint or ""),
            "sha256:" + recovery.policy_fingerprint,
            recovery.runtime_binding.resolved_digest,
        )
        return CodexWorkerRequest("attempt-1", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-1", action=WorkerAction.IMPLEMENTATION, context=context, objective="write", constraints=("bounded",), acceptance_criteria=("write",), resume_session_identity=None), context, "write", ("bounded",), ("write",))

    def failure_lifecycle(self, root: Path, request: CodexWorkerRequest):
        fixture, identity, recovery = self.recovery_fixture()
        counter = getattr(self, "_failure_lifecycle_counter", 0) + 1
        self._failure_lifecycle_counter = counter
        state_root = root / f"worker-failure-state-{counter}"
        state_root.mkdir()
        repository = fixture.repository(state_root)
        from roundwright.state import initialize
        initialize(repository)
        lease = fixture.lease(repository)
        fixture.admit(repository, identity, lease)
        fixture.seal_candidate(repository, identity, lease, "a" * 40)
        prepare_attempt(
            repository, identity, recovery, attempt_id=request.attempt_id,
            role=ProviderRole.WORKER, process_lease_id="coding-runtime-lease",
            process_lease_expires_at=2_000_000_000,
            input_fingerprint=request.input_digest.removeprefix("sha256:"),
            lease=lease, now=101,
        )
        return ProductionWorkerFailureLifecycle(repository, identity, recovery, lease, 101)
    def inputs(self, root, turn, events, sandbox=None, output_limit=65_536):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        command = (sys.executable, "-c", "pass")
        scope, root_identity = self.coding_scope(root, command)
        tools = BoundedCodingTools(BoundedCodingCapability(root, ("out.txt",), ("out.txt",), (command,), output_limit=output_limit, sandbox_identity=digest("sandbox"), role_scope=scope, scope_root_identity=root_identity), validation_sandbox=sandbox or Sandbox())
        request = self.request()
        context = request.context
        receipt = CodingDispatchReceipt.seal(task_id=request.context.task_id, attempt_id=request.attempt_id, candidate_sha="a" * 40, candidate_fingerprint=context.candidate_fingerprint, policy_fingerprint=context.policy_fingerprint, configuration_digest=context.configuration_digest, worktree_fingerprint=context.worktree_fingerprint, validation_toolchain_receipt=digest("toolchain"), sandbox_identity=digest("sandbox"), capability_digest=tools.capability_digest)
        backend = Backend(Session(turn, events))
        adapter = CodexWorkerAdapter(
            backend, profile, audit,
            BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE)),
        )
        request_material, preflight_material = adapter.effect_material(request)
        execution = sealed_execution_for_effect(
            AdvisoryRole.WORKER, profile, request_identity=request.attempt_id,
            request_material=request_material, preflight_material=preflight_material,
        )
        return ProductionCodingWorkerEntrypointInputs(backend=backend, profile=profile, audit=audit, local_tools=tools, dispatch_receipt=receipt, event_store=CodingToolEventStore(root / "events.db"), failure_lifecycle=self.failure_lifecycle(root, request), candidate_probe=lambda: "a" * 40, toolchain_receipt_probe=lambda: digest("toolchain"), advisory_execution=execution, execution_host=trusted_execution_host(AdvisoryRole.WORKER, profile), budget_ledger_path=root / "role-budget.sqlite")
    def runtime(self, root, turn, events, **kwargs):
        values=self.inputs(root,turn,events,**kwargs)
        return ProductionCodingWorkerRuntime(backend=values.backend, profile=values.profile, audit=values.audit, local_tools=values.local_tools, dispatch_receipt=values.dispatch_receipt, event_store=values.event_store, failure_lifecycle=values.failure_lifecycle, candidate_probe=values.candidate_probe, toolchain_receipt_probe=values.toolchain_receipt_probe, advisory_execution=values.advisory_execution, execution_host=values.execution_host, budget_ledger_path=values.budget_ledger_path)

    @contextmanager
    def hermetic_runtime(self, root, turn, events, **kwargs):
        """Test-only activation seam; no installed package can obtain it."""
        with patch("roundwright.worker_toolbox.require_external_production_activation", lambda: None):
            yield self.runtime(root, turn, events, **kwargs)
    def test_direct_production_runtime_construction_denies_before_provider_or_local_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                self.runtime(Path(temp),turn,events)
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())

    def test_hermetic_production_runtime_persists_typed_terminal_failure_and_blocks_restart_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]
            turn=Turn(events, (
                NativeWorkerTurnStep(response=NativeWorkerResponse(
                    WorkerResultKind.BLOCKED,
                    failure=CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE,
                    blocker="provider-failed",
                    outcome_source=WorkerOutcomeSource.SDK_TURN_FAILED,
                    sdk_error_category=WorkerSdkTurnErrorCategory.CONNECTION,
                )),
            ))
            with self.hermetic_runtime(Path(temp), turn, events) as runtime:
                request = self.request()
                result = runtime.dispatch(request, checkpoint_session=lambda _session: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual((result.kind, result.failure, runtime._adapter._backend.calls), (WorkerResultKind.BLOCKED, CodexFailure.TRANSPORT_OR_PROVIDER_OUTAGE, 1))
                lifecycle = runtime._failure_lifecycle
                self.assertEqual(read_attempt(lifecycle.repository, lifecycle.task_identity, request.attempt_id, context=lifecycle.recovery, now=lifecycle.observed_at).state, AttemptState.AMBIGUOUS)
                connection = sqlite3.connect(lifecycle.repository.root / ".roundwright" / "state.sqlite3")
                try:
                    row = connection.execute("SELECT record_json FROM failure_recovery_records WHERE task_id = ?", (lifecycle.task_identity.task_id,)).fetchone()
                finally:
                    connection.close()
                self.assertIsNotNone(row)
                record = parse_failure_record(json.loads(row[0]))
                self.assertEqual((record.binding.role, record.binding.candidate_sha, record.binding.session_identity, record.binding.attempt_identity, record.failure), (FailureRole.WORKER, "a" * 40, "session-1", request.attempt_id, FailureClass.TRANSIENT_SERVICE))
                with self.assertRaisesRegex(WorkerShadowError, "not dispatchable"):
                    runtime.dispatch(request, checkpoint_session=lambda _session: None, checkpoint_turn=lambda _session, _turn: None)
                self.assertEqual(runtime._adapter._backend.calls, 1)

    def test_pre_session_worker_denial_is_typed_durable_and_stops_restart(self):
        class DeniedBackend:
            calls = 0
            def open_session(self, *_args, **_kwargs):
                self.calls += 1
                raise CodexAdapterError(CodexFailure.SANDBOX_OR_APPROVAL_DENIED)

        with tempfile.TemporaryDirectory() as temp:
            events = []
            turn = Turn(events, ())
            with self.hermetic_runtime(Path(temp), turn, events) as runtime:
                backend = DeniedBackend()
                runtime._adapter._backend = backend
                request = self.request()
                result = runtime.dispatch(
                    request, checkpoint_session=lambda _: None,
                    checkpoint_turn=lambda *_: None,
                )
                self.assertEqual((result.kind, result.failure, result.turn_identity, backend.calls), (
                    WorkerResultKind.BLOCKED, CodexFailure.SANDBOX_OR_APPROVAL_DENIED,
                    None, 1,
                ))
                assert result.session_identity is not None
                self.assertTrue(result.session_identity.startswith("pre-dispatch-worker-"))
                lifecycle = runtime._failure_lifecycle
                with closing(sqlite3.connect(database_path(lifecycle.repository))) as connection:
                    encoded = connection.execute(
                        "SELECT record_json FROM failure_recovery_records WHERE task_id=?",
                        (lifecycle.task_identity.task_id,),
                    ).fetchone()[0]
                record = parse_failure_record(json.loads(encoded))
                self.assertEqual((record.failure, record.binding.session_identity), (
                    FailureClass.HOST_SECURITY_DENIAL, result.session_identity,
                ))
                with self.assertRaisesRegex(WorkerShadowError, "scope is stopped|not dispatchable"):
                    runtime.dispatch(request, checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
                self.assertEqual(backend.calls, 1)

    def test_fabricated_direct_runtime_dispatch_denies_before_any_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]
            runtime = object.__new__(ProductionCodingWorkerRuntime)
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                runtime.dispatch(self.request(), checkpoint_session=lambda _: events.append("session"), checkpoint_turn=lambda *_: events.append("turn"))
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())

    def test_prepared_worker_rechecks_peer_denial_before_any_dispatch_effect(self):
        from dataclasses import replace
        from roundwright.failure_recovery import Clearance, ClearanceRevocation, EvidenceSource, FailureBinding, classify, record_durable_clearance, record_durable_clearance_revocation, record_durable_failure
        from roundwright.provider_recovery import record_session_identity
        with tempfile.TemporaryDirectory() as temp:
            events = []
            turn = Turn(events, (NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "done"})),))
            with self.hermetic_runtime(Path(temp), turn, events) as runtime:
                lifecycle = runtime._failure_lifecycle
                repository, identity, recovery = lifecycle.repository, lifecycle.task_identity, lifecycle.recovery
                prepare_attempt(repository, identity, recovery, attempt_id="peer-denial", role=ProviderRole.WORKER,
                                process_lease_id="peer-lease", process_lease_expires_at=2_000_000_000,
                                input_fingerprint="b" * 64, lease=lifecycle.lease, now=101)
                record_session_identity(repository, identity, recovery, attempt_id="peer-denial",
                                        session_identity="peer-session", lease=lifecycle.lease, now=101)
                record = classify(FailureBinding(recovery.candidate_sha, "sha256:" + recovery.policy_fingerprint,
                                  recovery.runtime_binding.resolved_digest, "worker:" + identity.task_id,
                                  FailureRole.WORKER, recovery.runtime_binding.worker_profile_identity,
                                  "peer-session", "peer-denial"), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
                record_durable_failure(repository, identity, record, now=101)
                def snapshot():
                    with closing(sqlite3.connect(repository.root / ".roundwright" / "state.sqlite3")) as connection:
                        return tuple(connection.execute("SELECT * FROM " + table).fetchall() for table in
                                     ("provider_attempts", "recovery_route_authorizations", "provider_dispatch_claims"))
                before = snapshot()
                for _ in range(2):
                    runtime._failure_lifecycle = replace(lifecycle)
                    with self.assertRaisesRegex(WorkerShadowError, "scope is stopped"):
                        runtime.dispatch(self.request(), checkpoint_session=lambda _: events.append("session"),
                                         checkpoint_turn=lambda *_: events.append("turn"))
                    self.assertEqual(snapshot(), before)
                    self.assertEqual(runtime._adapter._backend.calls, 0)
                    self.assertEqual(events, [])
                    self.assertFalse(Path(temp, "role-budget.sqlite").exists())
                fixture = ProviderRecoveryTests()
                fixture.denial_command(repository, identity, record, "worker-exact-clear", kind="clear")
                clearance = record_durable_clearance(repository, identity, Clearance(record.digest, record.binding, "worker-exact-clear"))
                runtime._failure_lifecycle.require_dispatchable(self.request(), runtime._dispatch_receipt)
                fixture.denial_command(repository, identity, record, "worker-exact-revoke", kind="revoke")
                record_durable_clearance_revocation(repository, identity, ClearanceRevocation(clearance, record.binding, "worker-exact-revoke"))
                with self.assertRaisesRegex(WorkerShadowError, "scope is stopped"):
                    runtime.dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
                self.assertEqual(snapshot(), before)
                self.assertEqual(runtime._adapter._backend.calls, 0)
                self.assertFalse(Path(temp, "role-budget.sqlite").exists())

    def test_stopped_unclaimed_worker_reuses_exact_unused_reservation_after_clearance(self):
        """A pre-effect stop cannot strand the Worker's only budget slot."""

        from roundwright.failure_recovery import Clearance, EvidenceSource, FailureBinding, classify, record_durable_clearance, record_durable_failure
        import roundwright.failure_recovery as recovery_module

        with tempfile.TemporaryDirectory() as temp:
            events = []
            turn = Turn(events, (NativeWorkerTurnStep(response=NativeWorkerResponse(
                WorkerResultKind.ACCEPTED, {"status": "done"},
            )),))
            with self.hermetic_runtime(Path(temp), turn, events) as runtime:
                lifecycle = runtime._failure_lifecycle
                repository, identity, recovery = lifecycle.repository, lifecycle.task_identity, lifecycle.recovery
                prepare_attempt(
                    repository, identity, recovery, attempt_id="reservation-stop-source",
                    role=ProviderRole.WORKER, process_lease_id="reservation-stop-lease",
                    process_lease_expires_at=2_000_000_000, input_fingerprint="c" * 64,
                    lease=lifecycle.lease, now=101,
                )
                from roundwright.provider_recovery import record_session_identity
                record_session_identity(
                    repository, identity, recovery, attempt_id="reservation-stop-source",
                    session_identity="reservation-stop-session", lease=lifecycle.lease, now=101,
                )
                denial = classify(FailureBinding(
                    recovery.candidate_sha, "sha256:" + recovery.policy_fingerprint,
                    recovery.runtime_binding.resolved_digest, "worker:" + identity.task_id,
                    FailureRole.WORKER, recovery.runtime_binding.worker_profile_identity,
                    "reservation-stop-session", "reservation-stop-source",
                ), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
                original = recovery_module.admit_scope_effect_reservation

                def stop_after_reservation(*args, **kwargs):
                    reservation = original(*args, **kwargs)
                    record_durable_failure(repository, identity, denial, now=101)
                    return reservation

                with patch.object(recovery_module, "admit_scope_effect_reservation", side_effect=stop_after_reservation), self.assertRaisesRegex(Exception, "scope admission"):
                    runtime.dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
                self.assertEqual(runtime._adapter._backend.calls, 0)
                with closing(sqlite3.connect(repository.root / ".roundwright" / "state.sqlite3")) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM provider_dispatch_claims WHERE attempt_id=?", (self.request().attempt_id,),
                    ).fetchone(), (0,))
                with closing(sqlite3.connect(Path(temp) / "role-budget.sqlite")) as connection:
                    reserved = connection.execute(
                        "SELECT calls, duration_seconds, tokens FROM role_budget_usage"
                    ).fetchall()
                    self.assertEqual(reserved, [(1, 60, 4000)])

                fixture = ProviderRecoveryTests()
                fixture.denial_command(repository, identity, denial, "reservation-stop-clear", kind="clear")
                record_durable_clearance(
                    repository, identity,
                    Clearance(denial.digest, denial.binding, "reservation-stop-clear"),
                )
                result = runtime.dispatch(
                    self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None,
                )
                self.assertEqual((result.kind, runtime._adapter._backend.calls), (WorkerResultKind.ACCEPTED, 1))
                with closing(sqlite3.connect(Path(temp) / "role-budget.sqlite")) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT calls, duration_seconds, tokens FROM role_budget_usage"
                    ).fetchall(), reserved)
                with closing(sqlite3.connect(repository.root / ".roundwright" / "state.sqlite3")) as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM provider_dispatch_claims WHERE attempt_id=?", (self.request().attempt_id,),
                    ).fetchone(), (1,))

    def test_test_only_harness_preserves_allowlisted_write_and_denial_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; allowed=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events,(NativeWorkerTurnStep(request=allowed),NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            with self.hermetic_runtime(Path(temp),turn,events) as runtime:
                self.assertEqual(runtime.dispatch(self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None).kind,WorkerResultKind.ACCEPTED)
            self.assertEqual(Path(temp,"out.txt").read_text(),"ok")
            denied=NativeWorkerToolRequest(1,WorkerTool.WORKSPACE_WRITE,path="no.txt",content="no")
            with self.hermetic_runtime(Path(temp),Turn([], (NativeWorkerTurnStep(request=denied),NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"})))),[]) as runtime:
                with self.assertRaises(WorkerShadowError): runtime.dispatch(self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            self.assertFalse(Path(temp,"no.txt").exists())

    def test_test_only_harness_preserves_drift_feedback_and_reconciliation_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; runtime_events=[]
            with self.hermetic_runtime(Path(temp),Turn(events,()),events) as runtime:
                runtime._candidate_probe=lambda: "b" * 40
                with self.assertRaises(WorkerShadowError): runtime.dispatch(self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            request=NativeWorkerToolRequest(1,WorkerTool.WORKSPACE_WRITE,path="out.txt",content="once")
            with self.hermetic_runtime(Path(temp),Turn(runtime_events,()),runtime_events) as runtime:
                result=runtime._execute_request(self.request(),{"session_identity":"s","turn_identity":"t"},request,frozenset())
                self.assertEqual(result.outcome,"allowed")
                with self.assertRaises(WorkerShadowError): runtime.dispatch(self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)

    def test_public_production_entrypoint_constructs_the_coding_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                run_production_coding_worker(inputs=self.inputs(Path(temp),turn,events), request=self.request(), checkpoint_session=lambda _:events.append("session"), checkpoint_turn=lambda *_:events.append("turn"))
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())

    def test_registered_public_lifecycle_requires_an_exact_installed_resource(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            inputs=self.inputs(Path(temp),turn,events); receipt=inputs.dispatch_receipt
            descriptor=CodingWorkerRuntimeDescriptor("coding-resource-1",receipt.task_id,receipt.attempt_id,receipt.candidate_sha,receipt.capability_digest,receipt.receipt_digest)
            with self.assertRaises(WorkerShadowError):
                run_registered_production_coding_worker(descriptor_value=descriptor.payload(),request=self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            CODING_RUNTIME_REGISTRY.install("coding-resource-1",inputs)
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                run_registered_production_coding_worker(descriptor_value=descriptor.payload(),request=self.request(),checkpoint_session=lambda _:events.append("session"),checkpoint_turn=lambda *_:events.append("turn"))
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())
if __name__ == "__main__": unittest.main()
