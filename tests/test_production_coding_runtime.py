from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import CodexWorkerContext, CodexWorkerRequest, NativeWorkerResponse, NativeWorkerToolRequest, NativeWorkerTurnStep, WorkerAction, WorkerResultKind, WorkerTool, worker_request_digest
from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.worker_toolbox import ProductionCodingWorkerRuntime


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

class ProductionRuntimeTests(unittest.TestCase):
    def request(self):
        context = CodexWorkerContext("task-1", *(digest(x) for x in ("s","r","w","b","base","candidate","p","c")))
        return CodexWorkerRequest("attempt-1", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-1", action=WorkerAction.IMPLEMENTATION, context=context, objective="write", constraints=("bounded",), acceptance_criteria=("write",), resume_session_identity=None), context, "write", ("bounded",), ("write",))
    def runtime(self, root, turn, events):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        tools = BoundedCodingTools(BoundedCodingCapability(root, ("out.txt",), ("out.txt",), ((sys.executable,"-c","pass"),)))
        return ProductionCodingWorkerRuntime(backend=Backend(Session(turn, events)), profile=profile, audit=audit, local_tools=tools)
    def test_dispatch_writes_only_allowlisted_file_and_submits_closed_result(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="out.txt", content="ok")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            result=self.runtime(Path(temp),turn,events).dispatch(self.request(), checkpoint_session=lambda _: events.append("session"), checkpoint_turn=lambda *_: events.append("turn"))
            self.assertEqual((result.kind, Path(temp,"out.txt").read_text(), events[:5]), (WorkerResultKind.ACCEPTED,"ok",["session","start","turn","step","submit"]))
            self.assertTrue(turn.submitted[0].after_digest.startswith("sha256:"))
            self.assertFalse(hasattr(turn.submitted[0], "path"))
    def test_denied_write_has_no_effect(self):
        with tempfile.TemporaryDirectory() as temp:
            events=[]; request=NativeWorkerToolRequest(1, WorkerTool.WORKSPACE_WRITE, path="no.txt", content="no")
            turn=Turn(events, (NativeWorkerTurnStep(request=request), NativeWorkerTurnStep(response=NativeWorkerResponse(WorkerResultKind.ACCEPTED,{"status":"done"}))))
            self.runtime(Path(temp),turn,events).dispatch(self.request(), checkpoint_session=lambda _: None, checkpoint_turn=lambda *_: None)
            self.assertEqual(turn.submitted[0].outcome,"denied"); self.assertFalse(Path(temp,"no.txt").exists())

if __name__ == "__main__": unittest.main()
