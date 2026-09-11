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

from roundwright.codex_worker import CodexWorkerContext, CodexWorkerRequest, NativeWorkerResponse, NativeWorkerToolRequest, NativeWorkerTurnStep, WorkerAction, WorkerResultKind, WorkerTool, worker_request_digest
from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools, CodingSandboxResult, ReviewedSandboxReceipt, ReviewedValidationSandbox
from roundwright.coding_worker_state import CodingToolEventStore
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.worker_toolbox import CODING_RUNTIME_REGISTRY, CodingDispatchReceipt, CodingWorkerRuntimeDescriptor, ProductionCodingWorkerEntrypointInputs, ProductionCodingWorkerRuntime, run_production_coding_worker, run_registered_production_coding_worker
from roundwright.worker_shadow import WorkerShadowError


def digest(value: str) -> str: return "sha256:" + hashlib.sha256(value.encode()).hexdigest()

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
    def request(self):
        context = CodexWorkerContext("task-1", *(digest(x) for x in ("s","r","w","b","base","candidate","p","c")))
        return CodexWorkerRequest("attempt-1", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-1", action=WorkerAction.IMPLEMENTATION, context=context, objective="write", constraints=("bounded",), acceptance_criteria=("write",), resume_session_identity=None), context, "write", ("bounded",), ("write",))
    def inputs(self, root, turn, events, sandbox=None):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        tools = BoundedCodingTools(BoundedCodingCapability(root, ("out.txt",), ("out.txt",), ((sys.executable,"-c","pass"),), sandbox_identity=digest("sandbox")), validation_sandbox=sandbox or Sandbox())
        context = self.request().context
        receipt = CodingDispatchReceipt.seal(task_id="task-1", attempt_id="attempt-1", candidate_sha="a" * 40, candidate_fingerprint=context.candidate_fingerprint, policy_fingerprint=context.policy_fingerprint, configuration_digest=context.configuration_digest, worktree_fingerprint=context.worktree_fingerprint, validation_toolchain_receipt=digest("toolchain"), sandbox_identity=digest("sandbox"), capability_digest=tools.capability_digest)
        return ProductionCodingWorkerEntrypointInputs(backend=Backend(Session(turn, events)), profile=profile, audit=audit, local_tools=tools, dispatch_receipt=receipt, event_store=CodingToolEventStore(root / "events.db"), candidate_probe=lambda: "a" * 40, toolchain_receipt_probe=lambda: digest("toolchain"))
    def runtime(self, root, turn, events):
        values=self.inputs(root,turn,events)
        return ProductionCodingWorkerRuntime(backend=values.backend, profile=values.profile, audit=values.audit, local_tools=values.local_tools, dispatch_receipt=values.dispatch_receipt, event_store=values.event_store, candidate_probe=values.candidate_probe, toolchain_receipt_probe=values.toolchain_receipt_probe)
    def test_dispatch_writes_only_allowlisted_file_and_submits_closed_result(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            result=self.runtime(Path(temp),turn,events).dispatch(self.request(), checkpoint_session=lambda _: events.append("session"), checkpoint_turn=lambda *_: events.append("turn"))
            self.assertEqual((result.kind, Path(temp,"out.txt").read_text(), events[:5]), (WorkerResultKind.ACCEPTED,"ok",["session","start","turn","step","submit"]))
            self.assertTrue(turn.submitted[0].after_digest.startswith("sha256:"))
            self.assertFalse(hasattr(turn.submitted[0], "path"))

    def test_public_production_entrypoint_constructs_the_coding_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            result=run_production_coding_worker(inputs=self.inputs(Path(temp),turn,events), request=self.request(), checkpoint_session=lambda _:events.append("session"), checkpoint_turn=lambda *_:events.append("turn"))
            self.assertEqual((result.kind,Path(temp,"out.txt").read_text()),(WorkerResultKind.ACCEPTED,"ok"))

    def test_registered_public_lifecycle_requires_an_exact_installed_resource(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            inputs=self.inputs(Path(temp),turn,events); receipt=inputs.dispatch_receipt
            descriptor=CodingWorkerRuntimeDescriptor("coding-resource-1",receipt.task_id,receipt.attempt_id,receipt.candidate_sha,receipt.capability_digest,receipt.receipt_digest)
            with self.assertRaises(WorkerShadowError):
                run_registered_production_coding_worker(descriptor_value=descriptor.payload(),request=self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            CODING_RUNTIME_REGISTRY.install("coding-resource-1",inputs)
            result=run_registered_production_coding_worker(descriptor_value=descriptor.payload(),request=self.request(),checkpoint_session=lambda _:events.append("session"),checkpoint_turn=lambda *_:events.append("turn"))
            self.assertEqual((result.kind,Path(temp,"out.txt").read_text()),(WorkerResultKind.ACCEPTED,"ok"))
    def test_denied_write_has_no_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="no.txt", content="no")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            self.runtime(Path(temp),turn,events).dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
            self.assertEqual(turn.submitted[0].outcome,"denied"); self.assertFalse(Path(temp,"no.txt").exists())

    def test_candidate_drift_blocks_before_provider_or_tool_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; runtime=self.runtime(Path(temp),Turn(events,()),events); runtime._candidate_probe=lambda: "b" * 40
            with self.assertRaises(WorkerShadowError): runtime.dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
            self.assertEqual(events,[])

    def test_toolchain_receipt_drift_blocks_before_provider_or_tool_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; runtime=self.runtime(Path(temp),Turn(events,()),events); runtime._toolchain_receipt_probe=lambda: digest("other-toolchain")
            with self.assertRaises(WorkerShadowError): runtime.dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
            self.assertEqual(events,[])

    def test_read_feedback_is_transient_but_event_is_durable(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp,"out.txt").write_text("bounded",encoding="utf-8"); events=[]; request=NativeWorkerToolRequest(1,WorkerTool.WORKSPACE_READ,path="out.txt")
            turn=Turn(events,(NativeWorkerTurnStep(request=request),NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            runtime=self.runtime(Path(temp),turn,events); runtime.dispatch(self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            self.assertEqual(turn.submitted[0].feedback,"bounded")
            self.assertTrue((Path(temp,"events.db").exists()))

    def test_submission_binds_the_fresh_sdk_turn_before_a_terminal_result(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            class AdvancingTurn(Turn):
                def submit_tool_result(self, result):
                    super().submit_tool_result(result); self.id="turn-2"
            turn=AdvancingTurn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            runtime=self.runtime(Path(temp),turn,events)
            result=runtime.dispatch(self.request(), checkpoint_session=lambda _:None, checkpoint_turn=lambda *_:None)
            self.assertEqual((result.kind,result.turn_identity),(WorkerResultKind.ACCEPTED,"turn-2"))
            connection=sqlite3.connect(Path(temp,"events.db"))
            try:
                self.assertEqual(connection.execute("SELECT state,next_turn_identity FROM coding_tool_submissions").fetchall(),[("submitted","turn-2")])
            finally:
                connection.close()

    def test_non_utf8_feedback_at_the_raw_cap_is_a_durable_budget_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.VALIDATION_EXECUTE, command=(sys.executable,"-c","pass"))
            turn=Turn(events,(NativeWorkerTurnStep(request=request),NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            inputs=self.inputs(Path(temp),turn,events,Sandbox(b"\xff" * 65_536))
            result=run_production_coding_worker(inputs=inputs,request=self.request(),checkpoint_session=lambda _:None,checkpoint_turn=lambda *_:None)
            self.assertEqual(result.kind,WorkerResultKind.ACCEPTED)
            self.assertEqual(turn.submitted[0].outcome,"failed")
            self.assertIsNone(turn.submitted[0].feedback)
            connection=sqlite3.connect(Path(temp,"events.db"))
            try:
                payloads=connection.execute("SELECT payload_json FROM coding_tool_events").fetchall()
                self.assertEqual([json.loads(payload)["outcome"] for (payload,) in payloads],["failed"])
            finally:
                connection.close()

if __name__ == "__main__": unittest.main()
