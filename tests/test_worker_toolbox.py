"""Concrete bridge contracts: fake SDK, real temporary Recorder-store bytes."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import BoundedWorkerToolSurface, CodexWorkerContext, CodexWorkerRequest, WorkerAction, WorkerTool, worker_request_digest
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexCapability, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.shadow import RecorderBinding
from roundwright.worker_shadow import WorkerQualificationBinding, WorkerShadowMismatchError, require_worker_shadow_capture_readiness
from roundwright.worker_toolbox import CompletionDeadline, HarnessExternalWorkerRecorder, HarnessNativeCodexWorkerBackend, run_bounded_worker_adapter_qualification


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Receipt:
    def __init__(self, document):
        self.document = document
        self.evidence_digest = digest(document)
        self.manifest_digest = digest({"evidence": self.evidence_digest})
        self.bundle_digest = digest({"manifest": self.manifest_digest, "evidence": document})
        self.retention_identity = digest({"bundle": self.bundle_digest, "case": document["case_id"]})
    def as_dict(self):
        core = {"schema": "roundwright-harness-recording-receipt/v1", "status": "sealed", "evidence_schema": "roundwright-shadow-case/v2", "profile": self.document["profile"], "case_id": self.document["case_id"], "candidate_sha": self.document["candidate_sha"], "ready_at": self.document["ready_at"], "evidence_digest": self.evidence_digest, "manifest_digest": self.manifest_digest, "bundle_digest": self.bundle_digest, "retention_identity": self.retention_identity}
        return {**core, "receipt_digest": digest(core)}


class TemporaryReviewedRecorder:
    """A disk-backed reviewed-Recorder contract, not a protocol mock."""
    def __init__(self): self.calls = []
    def record_document(self, document, root):
        receipt = Receipt(document); root.mkdir(exist_ok=True)
        (root / (receipt.bundle_digest[7:] + ".json")).write_text(json.dumps(receipt.as_dict(), sort_keys=True), encoding="utf-8")
        self.calls.append("seal")
        return receipt
    def verify_recording(self, root, bundle_digest):
        self.calls.append("verify")
        value = json.loads((root / (bundle_digest[7:] + ".json")).read_text(encoding="utf-8"))
        document = self.last_document
        receipt = Receipt(document)
        if receipt.as_dict() != value: raise ValueError("read-back mismatch")
        return receipt
    @property
    def last_document(self):
        # The public document is reconstructed from sealed content in a real
        # Recorder; this test service preserves it only to exercise the driver.
        return self._last_document
    @last_document.setter
    def last_document(self, value): self._last_document = value


class FakeHandle:
    id = "turn-43"
    def __init__(self, events, text=None): self.events, self.text = events, text or ('{"status":"complete","action":"implementation","result_digest":"sha256:' + "c" * 64 + '"}')
    def stream(self):
        self.events.append("stream")
        item = SimpleNamespace(type="agentMessage", phase="final_answer", text=self.text)
        turn = SimpleNamespace(id=self.id, status="completed")
        class Stream(list):
            def close(inner): self.events.append("stream-close")
        return Stream((SimpleNamespace(payload=SimpleNamespace(item=item, turn_id=self.id)), SimpleNamespace(payload=SimpleNamespace(turn=turn))))


class FakeThread:
    id = "thread-43"
    def __init__(self, events, text=None): self.events, self.text = events, text
    def turn(self, prompt, **kwargs):
        self.events.append(("turn", prompt, kwargs)); return FakeHandle(self.events, self.text)


class FakeCodex:
    def __init__(self, events, text=None): self.events, self.text = events, text
    def __enter__(self): self.events.append("enter"); return self
    def __exit__(self, *_): self.events.append("exit")
    def thread_start(self, **kwargs): self.events.append(("start", kwargs)); return FakeThread(self.events, self.text)
    def thread_resume(self, identity, **kwargs): self.events.append(("resume", identity, kwargs)); return FakeThread(self.events, self.text)


class WorkerToolboxTests(unittest.TestCase):
    base, candidate = "a" * 40, "b" * 40

    def setUp(self):
        self.events = []
        self.profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        self.audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(self.profile.model, self.profile.reasoning_effort.value),)), self.profile)
        context = CodexWorkerContext("task-43", *(digest(value) for value in ("source", "repo", "worktree", "branch", "base", "candidate", "policy", "config")))
        self.request = CodexWorkerRequest("attempt-43", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="attempt-43", action=WorkerAction.IMPLEMENTATION, context=context, objective="qualify", constraints=("read-only",), acceptance_criteria=("structured",), resume_session_identity=None), context, "qualify", ("read-only",), ("structured",))
        self.recorder_binding = RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb")
        self.readiness = require_worker_shadow_capture_readiness(candidate_sha=self.candidate, ready_at=101, native_channel_producer_identity=digest("native"), exporter_identity=digest("exporter"), comparator_identity=digest("comparator"), recorder=self.recorder_binding, store_identity=digest("external-store"))
        self.binding = WorkerQualificationBinding("case-43", context.task_id, self.base, self.candidate, context.base_fingerprint, context.candidate_fingerprint, self.audit.profile_identity, context.configuration_digest, self.audit.runtime_fingerprint, self.readiness.native_channel_producer_identity, self.readiness.exporter_identity, self.readiness.comparator_identity, self.readiness.recorder_binding_digest, self.readiness.store_identity, "implementation-complete", None, "supervisor-review")

    def test_concrete_bridge_checkpoints_then_seals_and_readbacks_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "external-store"
            service = TemporaryReviewedRecorder()
            def record(document, store):
                service.last_document = document
                return service.record_document(document, store)
            recorder = HarnessExternalWorkerRecorder(store_root=root, store_identity=self.readiness.store_identity, recorder=self.recorder_binding, record_document=record, verify_recording=service.verify_recording)
            backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: "effort:" + value)
            result = run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: self.events.append(("checkpoint-session", value)), checkpoint_turn=lambda session, turn: self.events.append(("checkpoint-turn", session, turn)), checkpoint_result=lambda session, turn, kind: self.events.append(("checkpoint-result", session, turn, kind.value)))
        self.assertEqual(self.events[0], "enter")
        self.assertEqual(self.events[2], ("checkpoint-session", "thread-43"))
        self.assertEqual(self.events[4], ("checkpoint-turn", "thread-43", "turn-43"))
        self.assertIn(("checkpoint-result", "thread-43", "turn-43", "accepted"), self.events)
        self.assertFalse(self.events[1][1]["ephemeral"])
        payload = json.loads(self.events[3][1])
        self.assertEqual((payload["action"], payload["objective"], payload["constraints"], payload["acceptance_criteria"], payload["tools"]), ("implementation", "qualify", ["read-only"], ["structured"], ["workspace-read"]))
        self.assertEqual(payload["context"]["task_id"], "task-43")
        schema = self.events[3][2]["output_schema"]
        turn_options = self.events[3][2]
        self.assertEqual((turn_options["approval_mode"], turn_options["cwd"], turn_options["model"], turn_options["sandbox"]), ("deny-all", str(ROOT), "gpt-5.6-terra", "read-only"))
        self.assertEqual(schema["properties"]["action"]["enum"], ["implementation"])
        self.assertEqual(set(schema["properties"]), {"status", "action", "result_digest", "blocker"})
        self.assertNotIn("const", json.dumps(schema))
        self.assertEqual(service.calls, ["seal", "verify"])
        self.assertEqual((result.envelope.ready_at, result.record.receipt.ready_at), (101, 101))
        self.assertNotIn("qualify", json.dumps(result.record.receipt.__dict__))

    def test_preflight_drift_does_not_construct_or_call_provider(self):
        self.binding = WorkerQualificationBinding(self.binding.case_id, self.binding.task_id, self.binding.base_sha, self.binding.candidate_sha, self.binding.base_fingerprint, self.binding.candidate_fingerprint, self.binding.profile_identity, self.binding.configuration_digest, self.binding.runtime_fingerprint, self.binding.native_channel_producer_identity, self.binding.exporter_identity, self.binding.comparator_identity, self.binding.recorder_binding_digest, digest("other-store"), self.binding.deterministic_state, self.binding.blocker, self.binding.next_action)
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        with tempfile.TemporaryDirectory() as temporary:
            recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, record_document=lambda *_: None, verify_recording=lambda *_: None)
            with self.assertRaises(Exception):
                run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda _: None, checkpoint_turn=lambda _a, _b: None, checkpoint_result=lambda _a, _b, _c: None)
        self.assertEqual(self.events, [])

    def test_blocked_provider_output_cannot_become_accepted_evidence(self):
        from roundwright.worker_toolbox import _consume_public_result
        events = []
        response = _consume_public_result(FakeHandle(events, '{"status":"blocked","action":"implementation","blocker":"owner-input"}'), WorkerAction.IMPLEMENTATION)
        self.assertEqual((response.kind, response.structured_output, response.blocker), ("blocked", None, "owner-input"))

    def test_provider_lifecycle_fields_are_rejected_before_shadow_comparison(self):
        from roundwright.worker_toolbox import _consume_public_result
        response = _consume_public_result(FakeHandle([], '{"status":"complete","action":"repair","result_digest":"sha256:' + "c" * 64 + '","deterministic_state":"complete","next_action":"compare"}'), WorkerAction.REPAIR)
        self.assertEqual(response.kind, "invalid")

    def test_repair_projection_matches_the_live_contract_constants(self):
        from roundwright.worker_toolbox import _consume_public_result
        response = _consume_public_result(FakeHandle([], '{"status":"complete","action":"repair","result_digest":"sha256:' + "c" * 64 + '"}'), WorkerAction.REPAIR)
        self.assertEqual(response.kind, "accepted")

    def test_parser_uses_only_the_exact_turn_final_agent_message(self):
        from roundwright.worker_toolbox import _consume_public_result
        class Handle:
            id = "turn-43"
            def stream(self):
                final = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","result_digest":"sha256:' + "c" * 64 + '"}')
                wrong = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","result_digest":"sha256:' + "d" * 64 + '","deterministic_state":"wrong"}')
                class Stream(list):
                    def close(self): pass
                return Stream((SimpleNamespace(payload=SimpleNamespace(item=wrong, turn_id="other-turn")), SimpleNamespace(payload=SimpleNamespace(item=final, turn_id="turn-43")), SimpleNamespace(payload=SimpleNamespace(turn=SimpleNamespace(id="turn-43", status="completed")))))
        response = _consume_public_result(Handle(), WorkerAction.REPAIR)
        self.assertEqual(response.kind, "accepted")

    def test_resume_rebinds_full_runtime_on_a_new_client(self):
        events = []
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        session = backend.open_session(self.profile, resume_session_identity="thread-43")
        self.assertEqual(session.identity(), "thread-43")
        kind, identity, kwargs = events[1]
        self.assertEqual((kind, identity, kwargs["approval_mode"], kwargs["sandbox"], kwargs["model"]), ("resume", "thread-43", "deny-all", "read-only", "gpt-5.6-terra"))

    def test_deadline_returns_ambiguous_and_closes_the_exact_turn(self):
        from roundwright.worker_toolbox import _consume_public_result
        events, released = [], __import__("threading").Event()
        class Stream:
            def __iter__(self): return self
            def __next__(self): released.wait(); raise StopIteration
            def close(self): events.append("stream-close"); released.set()
        class Handle:
            id = "turn-43"
            def stream(self): return Stream()
            def interrupt(self): events.append("interrupt")
        started = time.monotonic()
        response = _consume_public_result(Handle(), WorkerAction.REPAIR, completion=CompletionDeadline(25, 600), cancel=lambda: events.append("cancel"))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(response.kind, "ambiguous")
        self.assertEqual(events, ["cancel", "stream-close"])

    def test_delayed_exact_turn_completion_before_deadline_is_accepted(self):
        from roundwright.worker_toolbox import _consume_public_result
        class Handle:
            id = "turn-43"
            def stream(self):
                item = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","result_digest":"sha256:' + "c" * 64 + '"}')
                class Stream:
                    def __init__(self): self.values = [SimpleNamespace(payload=SimpleNamespace(item=item, turn_id="turn-43")), SimpleNamespace(payload=SimpleNamespace(turn=SimpleNamespace(id="turn-43", status="completed")))]
                    def __iter__(self): return self
                    def __next__(self):
                        time.sleep(0.005)
                        if not self.values: raise StopIteration
                        return self.values.pop(0)
                    def close(self): pass
                return Stream()
        self.assertEqual(_consume_public_result(Handle(), WorkerAction.REPAIR, completion=CompletionDeadline(100, 600)).kind, "accepted")

    def test_timeout_is_result_checkpointed_before_recorder_and_never_retried(self):
        events, released = [], __import__("threading").Event()
        class Handle:
            id = "turn-43"
            def stream(self):
                class Stream:
                    def __iter__(self): return self
                    def __next__(self): released.wait(); raise StopIteration
                    def close(self): released.set()
                return Stream()
            def interrupt(self): events.append("interrupt")
        class Thread:
            id = "thread-43"
            def turn(self, *_args, **_kwargs): return Handle()
        class Codex:
            def __enter__(self): return self
            def __exit__(self, *_args): events.append("client-close")
            def thread_start(self, **_kwargs): return Thread()
        with tempfile.TemporaryDirectory() as temporary:
            service = TemporaryReviewedRecorder()
            recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, record_document=service.record_document, verify_recording=service.verify_recording)
            backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(25, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
            with self.assertRaises(WorkerShadowMismatchError):
                run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: events.append(("session", value)), checkpoint_turn=lambda session, turn: events.append(("turn", session, turn)), checkpoint_result=lambda session, turn, kind: events.append(("result", session, turn, kind.value)))
        self.assertEqual(events[:3], [("session", "thread-43"), ("turn", "thread-43", "turn-43"), "interrupt"])
        self.assertIn(("result", "thread-43", "turn-43", "ambiguous"), events)
        self.assertEqual(service.calls, [])
        self.assertEqual(events.count("interrupt"), 1)

    def test_completion_deadline_requires_operational_host_headroom(self):
        self.assertEqual(CompletionDeadline(9000, 10000).receipt()["headroom_ms"], 1000)
        with self.assertRaises(Exception): CompletionDeadline(10000, 10000)

    def test_operational_entrypoint_requires_and_reports_explicit_headroom(self):
        from roundwright.worker_toolbox import main
        import os
        prior = dict(os.environ)
        try:
            os.environ["ROUNDWRIGHT_RUN_LIVE_WORKER_ADAPTER"] = "1"
            os.environ["ROUNDWRIGHT_APPLICATION_TIMEOUT_MS"] = "9000"
            os.environ["ROUNDWRIGHT_HOST_TIMEOUT_MS"] = "10000"
            output = StringIO()
            with redirect_stdout(output): self.assertEqual(main(), 2)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["completion"], {"schema": "roundwright-worker-completion-timeout/v1", "application_timeout_ms": 9000, "host_timeout_ms": 10000, "headroom_ms": 1000})
        finally:
            os.environ.clear(); os.environ.update(prior)


if __name__ == "__main__": unittest.main()
