from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import BoundedWorkerToolSurface, CodexWorkerAdapter, CodexWorkerContext, CodexWorkerRequest, NativeWorkerResponse, NativeWorkerToolRequest, NativeWorkerTurnStep, WorkerAction, WorkerResultKind, WorkerTool, worker_request_digest
from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools, CodingSandboxResult, ReviewedSandboxReceipt, ReviewedValidationSandbox
from roundwright.coding_worker_state import CodingToolEventStore
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.role_capability_policy import AdvisoryRole, RoleCapability, RoleScope, ScopeKind, ScopedDescriptor
from tests.role_admission_fixture import sealed_execution_for_effect, trusted_execution_host
from roundwright.worker_toolbox import CODING_RUNTIME_REGISTRY, CodingDispatchReceipt, CodingWorkerRuntimeDescriptor, ProductionCodingWorkerEntrypointInputs, ProductionCodingWorkerRuntime, run_production_coding_worker, run_registered_production_coding_worker
from roundwright.worker_shadow import WorkerShadowError


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

    def request(self):
        context = CodexWorkerContext("task-1", *(digest(x) for x in ("s","r","w","b","base","candidate","p","c")))
        return CodexWorkerRequest("attempt-1", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-1", action=WorkerAction.IMPLEMENTATION, context=context, objective="write", constraints=("bounded",), acceptance_criteria=("write",), resume_session_identity=None), context, "write", ("bounded",), ("write",))
    def inputs(self, root, turn, events, sandbox=None, output_limit=65_536):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        command = (sys.executable, "-c", "pass")
        scope, root_identity = self.coding_scope(root, command)
        tools = BoundedCodingTools(BoundedCodingCapability(root, ("out.txt",), ("out.txt",), (command,), output_limit=output_limit, sandbox_identity=digest("sandbox"), role_scope=scope, scope_root_identity=root_identity), validation_sandbox=sandbox or Sandbox())
        context = self.request().context
        receipt = CodingDispatchReceipt.seal(task_id="task-1", attempt_id="attempt-1", candidate_sha="a" * 40, candidate_fingerprint=context.candidate_fingerprint, policy_fingerprint=context.policy_fingerprint, configuration_digest=context.configuration_digest, worktree_fingerprint=context.worktree_fingerprint, validation_toolchain_receipt=digest("toolchain"), sandbox_identity=digest("sandbox"), capability_digest=tools.capability_digest)
        backend = Backend(Session(turn, events))
        request = self.request()
        adapter = CodexWorkerAdapter(
            backend, profile, audit,
            BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE, WorkerTool.VALIDATION_EXECUTE)),
        )
        request_material, preflight_material = adapter.effect_material(request)
        execution = sealed_execution_for_effect(
            AdvisoryRole.WORKER, profile, request_identity=request.attempt_id,
            request_material=request_material, preflight_material=preflight_material,
        )
        return ProductionCodingWorkerEntrypointInputs(backend=backend, profile=profile, audit=audit, local_tools=tools, dispatch_receipt=receipt, event_store=CodingToolEventStore(root / "events.db"), candidate_probe=lambda: "a" * 40, toolchain_receipt_probe=lambda: digest("toolchain"), advisory_execution=execution, execution_host=trusted_execution_host(AdvisoryRole.WORKER, profile), budget_ledger_path=root / "role-budget.sqlite")
    def runtime(self, root, turn, events, **kwargs):
        values=self.inputs(root,turn,events,**kwargs)
        return ProductionCodingWorkerRuntime(backend=values.backend, profile=values.profile, audit=values.audit, local_tools=values.local_tools, dispatch_receipt=values.dispatch_receipt, event_store=values.event_store, candidate_probe=values.candidate_probe, toolchain_receipt_probe=values.toolchain_receipt_probe, advisory_execution=values.advisory_execution, execution_host=values.execution_host, budget_ledger_path=values.budget_ledger_path)
    def test_direct_production_runtime_construction_denies_before_provider_or_local_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                self.runtime(Path(temp),turn,events)
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())

    def test_fabricated_direct_runtime_dispatch_denies_before_any_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]
            runtime = object.__new__(ProductionCodingWorkerRuntime)
            with self.assertRaisesRegex(WorkerShadowError, "activation is unavailable"):
                runtime.dispatch(self.request(), checkpoint_session=lambda _: events.append("session"), checkpoint_turn=lambda *_: events.append("turn"))
            self.assertEqual(events, [])
            self.assertFalse(Path(temp, "out.txt").exists())

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
