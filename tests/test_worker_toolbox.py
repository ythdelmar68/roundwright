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

from roundwright.codex_worker import BoundedWorkerToolSurface, CodexWorkerContext, CodexWorkerRequest, WorkerAction, WorkerCapabilityContract, WorkerOutcomeSource, WorkerParserDiagnostic, WorkerSdkTurnErrorCategory, WorkerTool, worker_request_digest
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexAdapterError, CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.shadow import RecorderBinding
from roundwright.worker_shadow import WorkerQualificationBinding, require_worker_shadow_capture_readiness
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


class PlanReceipt:
    def __init__(self, plan): self.plan, self.plan_digest = plan, digest(plan)
    def as_dict(self):
        core = {"schema": "roundwright-harness-capture-plan-receipt/v1", "status": "ready", "plan_digest": self.plan_digest, "profile": self.plan["profile"], "case_id": self.plan["case_id"], "candidate_sha": self.plan["candidate_sha"], "ready_at": self.plan["ready_at"]}
        return {**core, "receipt_digest": digest(core)}


class BoundReceipt:
    def __init__(self, plan, recording): self.plan, self.recording = PlanReceipt(plan), recording
    def as_dict(self):
        recorded = self.recording.as_dict()
        core = {"schema": "roundwright-harness-bound-capture-receipt/v1", "status": "sealed", "capture_plan_digest": self.plan.plan_digest, "profile": recorded["profile"], "case_id": recorded["case_id"], "candidate_sha": recorded["candidate_sha"], "ready_at": recorded["ready_at"], "evidence_digest": recorded["evidence_digest"], "manifest_digest": recorded["manifest_digest"], "bundle_digest": recorded["bundle_digest"], "retention_identity": recorded["retention_identity"], "recording_receipt_digest": recorded["receipt_digest"]}
        return {**core, "receipt_digest": digest(core)}


class TemporaryReviewedRecorder:
    """A disk-backed reviewed-Recorder contract, not a protocol mock."""
    def __init__(self): self.calls = []
    def prepare_capture(self, plan):
        self.calls.append("prepare")
        return PlanReceipt(plan)
    def record_capture(self, plan, document, root):
        if document["capture_plan_digest"] != digest(plan): raise ValueError("plan mismatch")
        receipt = Receipt(document); root.mkdir(exist_ok=True)
        (root / (receipt.bundle_digest[7:] + ".json")).write_text(json.dumps(receipt.as_dict(), sort_keys=True), encoding="utf-8")
        self.calls.append("seal")
        self._last_plan, self._last_document = plan, document
        return BoundReceipt(plan, receipt)
    def verify_capture(self, plan, root, bundle_digest):
        self.calls.append("verify")
        value = json.loads((root / (bundle_digest[7:] + ".json")).read_text(encoding="utf-8"))
        document = self.last_document
        receipt = Receipt(document)
        if plan != self._last_plan or receipt.as_dict() != value: raise ValueError("read-back mismatch")
        return BoundReceipt(plan, receipt)
    @property
    def last_document(self):
        # The public document is reconstructed from sealed content in a real
        # Recorder; this test service preserves it only to exercise the driver.
        return self._last_document
    @last_document.setter
    def last_document(self, value): self._last_document = value


class FakeHandle:
    id = "turn-43"
    def __init__(self, events, text=None): self.events, self.text = events, text or '{"status":"complete","action":"planning","blocker":null}'
    def stream(self):
        self.events.append("stream")
        item = SimpleNamespace(type="agentMessage", phase="final_answer", text=self.text)
        turn = SimpleNamespace(id=self.id, status="completed")
        class Stream(list):
            def close(inner): self.events.append("stream-close")
        return Stream((SimpleNamespace(method="item/completed", payload=SimpleNamespace(item=item, turn_id=self.id)), SimpleNamespace(method="turn/completed", payload=SimpleNamespace(turn=turn))))


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


def sdk_item(turn_id, text, *, phase="final_answer"):
    """Mirror 0.144.4 ``item/completed`` / ``AgentMessageThreadItem`` fields."""
    item = SimpleNamespace(root=SimpleNamespace(type="agentMessage", phase=SimpleNamespace(value=phase), text=text))
    return SimpleNamespace(method="item/completed", payload=SimpleNamespace(item=item, turn_id=turn_id))


def sdk_turn(turn_id, status="completed", error=None):
    """Mirror 0.144.4 ``turn/completed`` / ``Turn.status`` fields."""
    return SimpleNamespace(method="turn/completed", payload=SimpleNamespace(turn=SimpleNamespace(id=turn_id, status=SimpleNamespace(value=status), error=error)))


class ProtocolHandle:
    id = "turn-43"
    def __init__(self, *events): self._events = events
    def stream(self):
        class Stream(list):
            def close(self): pass
        return Stream(self._events)


class WorkerToolboxTests(unittest.TestCase):
    base, candidate = "a" * 40, "b" * 40

    def setUp(self):
        self.events = []
        self.profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        self.audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(self.profile.model, self.profile.reasoning_effort.value),)), self.profile)
        context = CodexWorkerContext("task-43", *(digest(value) for value in ("source", "repo", "worktree", "branch", "base", "candidate", "policy", "config")))
        self.request = CodexWorkerRequest("attempt-43", WorkerAction.PLANNING, worker_request_digest(attempt_id="attempt-43", action=WorkerAction.PLANNING, context=context, objective="Observe the supplied issue scope and plan a bounded repair.", constraints=("No provider tools or repository inspection.", "No GitHub or mutations."), acceptance_criteria=("Return the strict planning status and action.",), resume_session_identity=None), context, "Observe the supplied issue scope and plan a bounded repair.", ("No provider tools or repository inspection.", "No GitHub or mutations."), ("Return the strict planning status and action.",))
        self.recorder_binding = RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1")
        self.readiness = require_worker_shadow_capture_readiness(candidate_sha=self.candidate, ready_at=101, case_id="case-43", observation_identity=self.request.input_digest, native_channel_producer_identity=digest("native"), exporter_identity=digest("exporter"), comparator_identity=digest("comparator"), recorder=self.recorder_binding, store_identity=digest("external-store"))
        self.binding = WorkerQualificationBinding("case-43", context.task_id, self.request.attempt_id, self.request.input_digest, self.request.resume_session_identity, context.source_digest, context.repository_fingerprint, context.worktree_fingerprint, context.branch_fingerprint, context.policy_fingerprint, self.base, self.candidate, context.base_fingerprint, context.candidate_fingerprint, self.audit.profile_identity, context.configuration_digest, self.audit.runtime_fingerprint, self.readiness.native_channel_producer_identity, self.readiness.exporter_identity, self.readiness.comparator_identity, self.readiness.recorder_binding_digest, self.readiness.store_identity, self.readiness.capture_plan_digest, "planning-complete", None, "supervisor-review")

    def test_concrete_bridge_checkpoints_then_seals_and_readbacks_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "external-store"
            service = TemporaryReviewedRecorder()
            recorder = HarnessExternalWorkerRecorder(store_root=root, store_identity=self.readiness.store_identity, recorder=self.recorder_binding, prepare_capture=service.prepare_capture, record_capture=service.record_capture, verify_capture=service.verify_capture)
            backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: "effort:" + value)
            result = run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface(()), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: self.events.append(("checkpoint-session", value)), checkpoint_turn=lambda session, turn: self.events.append(("checkpoint-turn", session, turn)), checkpoint_result=lambda session, turn, kind, diagnostic, source, category: self.events.append(("checkpoint-result", session, turn, kind.value, None if diagnostic is None else diagnostic.value, None if source is None else source.value, None if category is None else category.value)))
        self.assertEqual(self.events[0], "enter")
        self.assertEqual(self.events[2], ("checkpoint-session", "thread-43"))
        self.assertEqual(self.events[4], ("checkpoint-turn", "thread-43", "turn-43"))
        self.assertIn(("checkpoint-result", "thread-43", "turn-43", "accepted", None, None, None), self.events)
        self.assertFalse(self.events[1][1]["ephemeral"])
        payload = json.loads(self.events[3][1])
        self.assertEqual((payload["action"], payload["tools"], payload["capability_contract"]), ("planning", [], "no-tools-self-contained/v1"))
        self.assertEqual(payload["provider_instruction"], "No provider tools or repository inspection are declared or required; decide only from this normalized public input.")
        self.assertEqual(payload["context"]["task_id"], "task-43")
        schema = self.events[3][2]["output_schema"]
        turn_options = self.events[3][2]
        self.assertEqual((turn_options["approval_mode"], turn_options["cwd"], turn_options["model"], turn_options["sandbox"]), ("deny-all", str(ROOT), "gpt-5.6-terra", "read-only"))
        self.assertEqual(schema["type"], "object")
        self.assertEqual(schema["properties"]["action"]["enum"], ["planning"])
        self.assertEqual(schema["required"], ["status", "action", "blocker"])
        self.assertEqual(schema["properties"]["blocker"], {"type": ["string", "null"], "enum": [None, "provider-blocked"]})
        self.assertTrue({"allOf", "anyOf", "oneOf", "if", "then", "else"}.isdisjoint(schema))
        self.assertNotIn("const", json.dumps(schema))
        self.assertEqual(service.calls, ["prepare", "seal", "verify"])
        self.assertEqual(result.record.receipt.capture_plan_digest, self.readiness.capture_plan_digest)
        self.assertEqual((result.envelope.ready_at, result.record.receipt.ready_at), (101, 101))
        self.assertEqual((result.result.kind, result.result.output_fingerprint), ("accepted", digest({"status": "complete", "action": "planning"})))
        self.assertNotIn("Observe", json.dumps(result.record.receipt.__dict__))

    def test_preflight_drift_does_not_construct_or_call_provider(self):
        self.binding = WorkerQualificationBinding(self.binding.case_id, self.binding.task_id, self.binding.attempt_id, self.binding.input_digest, self.binding.resume_session_identity, self.binding.source_digest, self.binding.repository_fingerprint, self.binding.worktree_fingerprint, self.binding.branch_fingerprint, self.binding.policy_fingerprint, self.binding.base_sha, self.binding.candidate_sha, self.binding.base_fingerprint, self.binding.candidate_fingerprint, self.binding.profile_identity, self.binding.configuration_digest, self.binding.runtime_fingerprint, self.binding.native_channel_producer_identity, self.binding.exporter_identity, self.binding.comparator_identity, self.binding.recorder_binding_digest, digest("other-store"), self.binding.capture_plan_digest, self.binding.deterministic_state, self.binding.blocker, self.binding.next_action)
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        with tempfile.TemporaryDirectory() as temporary:
            recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, prepare_capture=lambda *_: None, record_capture=lambda *_: None, verify_capture=lambda *_: None)
            with self.assertRaises(Exception):
                run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface(()), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda _: None, checkpoint_turn=lambda _a, _b: None, checkpoint_result=lambda _a, _b, _c, _d, _e, _f: None)
        self.assertEqual(self.events, [])

    def test_native_qualification_rejects_unenforceable_abstract_tool_labels(self):
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        session = backend.open_session(self.profile, resume_session_identity=None)
        with self.assertRaises(Exception):
            session.start_turn(self.request, BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)))
        self.assertEqual(self.events[0], "enter")

    def test_no_tool_contract_is_bound_at_adapter_readiness_and_prompt(self):
        self.assertEqual(BoundedWorkerToolSurface(()).capability_contract, WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED)
        self.assertEqual(BoundedWorkerToolSurface((WorkerTool.WORKSPACE_READ,)).capability_contract, WorkerCapabilityContract.ORCHESTRATION_DECLARED_ONLY)
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(1000, 2000), codex_factory=lambda: FakeCodex(self.events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        backend.open_session(self.profile, resume_session_identity=None)
        start = self.events[1][1]
        self.assertIn("No provider tools", start["developer_instructions"])
        self.assertNotIn("tools", start)

    def test_blocked_provider_output_cannot_become_accepted_evidence(self):
        from roundwright.worker_toolbox import _consume_public_result
        events = []
        response = _consume_public_result(FakeHandle(events, '{"status":"blocked","action":"implementation","blocker":"provider-blocked"}'), WorkerAction.IMPLEMENTATION)
        self.assertEqual((response.kind, response.structured_output, response.blocker, response.outcome_source), ("blocked", None, "provider-blocked", WorkerOutcomeSource.PROVIDER_STRUCTURED_BLOCKED))

    def test_provider_lifecycle_fields_are_rejected_before_shadow_comparison(self):
        from roundwright.worker_toolbox import _consume_public_result
        response = _consume_public_result(FakeHandle([], '{"status":"complete","action":"repair","deterministic_state":"complete","next_action":"compare"}'), WorkerAction.REPAIR)
        self.assertEqual(response.kind, "invalid")

    def test_repair_projection_matches_the_live_contract_constants(self):
        from roundwright.worker_toolbox import _consume_public_result
        response = _consume_public_result(FakeHandle([], '{"status":"complete","action":"repair","blocker":null}'), WorkerAction.REPAIR)
        self.assertEqual((response.kind, response.structured_output), ("accepted", {"status": "complete", "action": "repair"}))

    def test_realistic_provider_shapes_are_locally_validated_and_digestable(self):
        from roundwright.worker_toolbox import _consume_public_result
        valid = _consume_public_result(FakeHandle([], '{"action":"repair","status":"complete","blocker":null}'), WorkerAction.REPAIR)
        self.assertEqual(digest(valid.structured_output), digest({"status": "complete", "action": "repair"}))
        for response in ('{}', '{"status":"complete"}', '{"status":"complete","action":"implementation"}', '{"status":"other","action":"repair"}', '{"status":"complete","action":"repair","extra":"x"}'):
            with self.subTest(response=response):
                self.assertEqual(_consume_public_result(FakeHandle([], response), WorkerAction.REPAIR).kind, "invalid")

    def test_locked_sdk_item_completed_wire_language_and_diagnostics(self):
        from roundwright.worker_toolbox import _consume_public_result
        valid = _consume_public_result(ProtocolHandle(sdk_item("turn-43", '{"status":"complete","action":"repair","blocker":null}'), sdk_turn("turn-43")), WorkerAction.REPAIR)
        self.assertEqual((valid.kind, valid.structured_output), ("accepted", {"status": "complete", "action": "repair"}))
        cases = (
            ('```json\n{"status":"complete","action":"repair"}\n```', WorkerParserDiagnostic.SYNTAX),
            ('[]', WorkerParserDiagnostic.SHAPE),
            ('{"status":"complete","action":"repair"}', WorkerParserDiagnostic.SHAPE),
            ('{"status":"complete","action":"implementation","blocker":null}', WorkerParserDiagnostic.ACTION),
            ('{"status":1,"action":"repair","blocker":null}', WorkerParserDiagnostic.STATUS),
            ('{"status":"complete","action":"repair","blocker":"provider-blocked"}', WorkerParserDiagnostic.SHAPE),
            ('{"status":"blocked","action":"repair","blocker":null}', WorkerParserDiagnostic.BLOCKER),
            ('{"status":"blocked","action":"repair","blocker":""}', WorkerParserDiagnostic.BLOCKER),
            ('{"status":"blocked","action":"repair","blocker":"provider-blocked","extra":true}', WorkerParserDiagnostic.BLOCKER),
        )
        for text, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic):
                response = _consume_public_result(ProtocolHandle(sdk_item("turn-43", text), sdk_turn("turn-43")), WorkerAction.REPAIR)
                self.assertEqual((response.kind, response.diagnostic), ("invalid", diagnostic))

    def test_locked_sdk_parser_rejects_wrong_turn_nonfinal_multiple_and_unfinished_events(self):
        from roundwright.worker_toolbox import _consume_public_result
        wrong_turn = _consume_public_result(ProtocolHandle(sdk_item("other-turn", '{"status":"complete","action":"repair"}'), sdk_turn("turn-43")), WorkerAction.REPAIR)
        self.assertEqual((wrong_turn.kind, wrong_turn.diagnostic), ("invalid", WorkerParserDiagnostic.EXACT_TURN))
        non_final = _consume_public_result(ProtocolHandle(sdk_item("turn-43", '{"status":"complete","action":"repair"}', phase="commentary"), sdk_turn("turn-43")), WorkerAction.REPAIR)
        self.assertEqual((non_final.kind, non_final.diagnostic), ("invalid", WorkerParserDiagnostic.NON_FINAL))
        multiple = _consume_public_result(ProtocolHandle(sdk_item("turn-43", '{"status":"complete","action":"repair"}'), sdk_item("turn-43", '{"status":"complete","action":"repair"}'), sdk_turn("turn-43")), WorkerAction.REPAIR)
        self.assertEqual((multiple.kind, multiple.diagnostic), ("invalid", WorkerParserDiagnostic.SHAPE))
        self.assertEqual(_consume_public_result(ProtocolHandle(sdk_item("turn-43", '{"status":"complete","action":"repair"}'), sdk_turn("turn-43", "in_progress")), WorkerAction.REPAIR).kind, "ambiguous")
        failed = _consume_public_result(ProtocolHandle(sdk_turn("turn-43", "failed")), WorkerAction.REPAIR)
        self.assertEqual((failed.kind, failed.blocker, failed.outcome_source, failed.sdk_error_category), ("blocked", "provider-failed", WorkerOutcomeSource.SDK_TURN_FAILED, WorkerSdkTurnErrorCategory.MISSING_OR_UNKNOWN))

    def test_failed_turn_uses_only_typed_sdk_error_categories(self):
        from roundwright.worker_toolbox import _consume_public_result
        model_cases = (
            ("badRequest", WorkerSdkTurnErrorCategory.BAD_REQUEST),
            ("unauthorized", WorkerSdkTurnErrorCategory.UNAUTHORIZED),
            ("sandboxError", WorkerSdkTurnErrorCategory.SANDBOX),
            ("serverOverloaded", WorkerSdkTurnErrorCategory.OVERLOAD),
            ("other", WorkerSdkTurnErrorCategory.MISSING_OR_UNKNOWN),
        )
        for value, category in model_cases:
            with self.subTest(value=value):
                error = SimpleNamespace(message="private provider text", additional_details="private details", codex_error_info=SimpleNamespace(root=SimpleNamespace(value=value)))
                response = _consume_public_result(ProtocolHandle(sdk_turn("turn-43", "failed", error)), WorkerAction.REPAIR)
                self.assertEqual((response.kind, response.outcome_source, response.sdk_error_category), ("blocked", WorkerOutcomeSource.SDK_TURN_FAILED, category))
                self.assertNotIn("private", repr(response))
        mapping_cases = (
            ({"codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 503}, "message": "private"}}, WorkerSdkTurnErrorCategory.HTTP),
            ({"codexErrorInfo": {"responseStreamConnectionFailed": {"httpStatusCode": 503}}}, WorkerSdkTurnErrorCategory.CONNECTION),
            ({"codexErrorInfo": {"responseStreamDisconnected": {"httpStatusCode": 503}}}, WorkerSdkTurnErrorCategory.STREAM),
            ({"codexErrorInfo": {"responseTooManyFailedAttempts": {"httpStatusCode": 503}}}, WorkerSdkTurnErrorCategory.STREAM),
            ({}, WorkerSdkTurnErrorCategory.MISSING_OR_UNKNOWN),
        )
        for error, category in mapping_cases:
            with self.subTest(category=category):
                event = {"method": "turn/completed", "payload": {"threadId": "thread-43", "turn": {"id": "turn-43", "status": "failed", "error": error}}}
                response = _consume_public_result(ProtocolHandle(event), WorkerAction.REPAIR)
                self.assertEqual((response.kind, response.outcome_source, response.sdk_error_category), ("blocked", WorkerOutcomeSource.SDK_TURN_FAILED, category))

    def test_serialized_completed_turn_does_not_default_to_failed(self):
        from roundwright.worker_toolbox import _consume_public_result
        event = {"method": "turn/completed", "payload": {"threadId": "thread-43", "turn": {"id": "turn-43", "status": "completed", "error": None}}}
        item = {"method": "item/completed", "payload": {"turnId": "turn-43", "item": {"root": {"type": "agentMessage", "phase": "final_answer", "text": '{"status":"complete","action":"repair","blocker":null}'}}}}
        response = _consume_public_result(ProtocolHandle(item, event), WorkerAction.REPAIR)
        self.assertEqual((response.kind, response.structured_output), ("accepted", {"status": "complete", "action": "repair"}))

    def test_parser_uses_only_the_exact_turn_final_agent_message(self):
        from roundwright.worker_toolbox import _consume_public_result
        class Handle:
            id = "turn-43"
            def stream(self):
                final = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","blocker":null}')
                wrong = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","deterministic_state":"wrong"}')
                class Stream(list):
                    def close(self): pass
                return Stream((SimpleNamespace(method="item/completed", payload=SimpleNamespace(item=wrong, turn_id="other-turn")), SimpleNamespace(method="item/completed", payload=SimpleNamespace(item=final, turn_id="turn-43")), SimpleNamespace(method="turn/completed", payload=SimpleNamespace(turn=SimpleNamespace(id="turn-43", status="completed")))))
        response = _consume_public_result(Handle(), WorkerAction.REPAIR)
        self.assertEqual((response.kind, response.diagnostic), ("invalid", WorkerParserDiagnostic.EXACT_TURN))

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

    def test_stream_failure_is_ambiguous_not_a_fresh_attempt_input_error(self):
        from roundwright.worker_toolbox import _consume_public_result
        class Handle:
            id = "turn-43"
            def stream(self):
                class Stream:
                    def __iter__(self): return self
                    def __next__(self): raise OSError("transport is unavailable")
                    def close(self): pass
                return Stream()
        self.assertEqual(_consume_public_result(Handle(), WorkerAction.REPAIR).kind, "ambiguous")

    def test_delayed_exact_turn_completion_before_deadline_is_accepted(self):
        from roundwright.worker_toolbox import _consume_public_result
        class Handle:
            id = "turn-43"
            def stream(self):
                item = SimpleNamespace(type="agentMessage", phase="final_answer", text='{"status":"complete","action":"repair","blocker":null}')
                class Stream:
                    def __init__(self): self.values = [SimpleNamespace(method="item/completed", payload=SimpleNamespace(item=item, turn_id="turn-43")), SimpleNamespace(method="turn/completed", payload=SimpleNamespace(turn=SimpleNamespace(id="turn-43", status="completed")))]
                    def __iter__(self): return self
                    def __next__(self):
                        time.sleep(0.005)
                        if not self.values: raise StopIteration
                        return self.values.pop(0)
                    def close(self): pass
                return Stream()
        self.assertEqual(_consume_public_result(Handle(), WorkerAction.REPAIR, completion=CompletionDeadline(1000, 2000)).kind, "accepted")

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
            recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, prepare_capture=service.prepare_capture, record_capture=service.record_capture, verify_capture=service.verify_capture)
            backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(25, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
            result = run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface(()), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: events.append(("session", value)), checkpoint_turn=lambda session, turn: events.append(("turn", session, turn)), checkpoint_result=lambda session, turn, kind, diagnostic, source, category: events.append(("result", session, turn, kind.value, None if diagnostic is None else diagnostic.value, None if source is None else source.value, None if category is None else category.value)))
        self.assertEqual(events[:3], [("session", "thread-43"), ("turn", "thread-43", "turn-43"), "interrupt"])
        self.assertIn(("result", "thread-43", "turn-43", "ambiguous", None, None, None), events)
        self.assertEqual((result.result.kind, result.record, result.comparison.disposition), ("ambiguous", None, "match"))
        self.assertEqual(service.calls, ["prepare"])
        self.assertEqual(events.count("interrupt"), 1)
        self.assertEqual(events.count("client-close"), 1)
        self.assertLess(events.index("interrupt"), events.index("client-close"))

    def test_concrete_unverified_terminal_eof_requires_exact_turn_recovery(self):
        for name, values in (
            ("eof", ()),
            ("nonterminal", (sdk_item("turn-43", '{"status":"complete","action":"planning","blocker":null}'), sdk_turn("turn-43", "in_progress"))),
        ):
            with self.subTest(name=name):
                events, provider_calls = [], []

                class Handle:
                    id = "turn-43"
                    def stream(self):
                        class Stream(list):
                            def close(inner): events.append("stream-close")
                        return Stream(values)
                    def interrupt(self): events.append("interrupt")

                class Thread:
                    id = "thread-43"
                    def turn(self, *_args, **_kwargs):
                        provider_calls.append("turn")
                        return Handle()

                class Codex:
                    def __enter__(self): return self
                    def __exit__(self, *_args): events.append("client-close")
                    def thread_start(self, **_kwargs): return Thread()

                with tempfile.TemporaryDirectory() as temporary:
                    service = TemporaryReviewedRecorder()
                    recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, prepare_capture=service.prepare_capture, record_capture=service.record_capture, verify_capture=service.verify_capture)
                    backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
                    result = run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface(()), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: events.append(("session", value)), checkpoint_turn=lambda session, turn: events.append(("turn", session, turn)), checkpoint_result=lambda session, turn, kind, diagnostic, source, category: events.append(("result", session, turn, kind.value, None if diagnostic is None else diagnostic.value, None if source is None else source.value, None if category is None else category.value)))

                self.assertEqual(provider_calls, ["turn"])
                self.assertEqual((result.result.kind, result.result.session_identity, result.result.turn_identity), ("ambiguous", "thread-43", "turn-43"))
                self.assertEqual((result.envelope.blocker, result.envelope.next_action, result.record), ("exact-turn-recovery", "blocked-ambiguous-turn", None))
                self.assertEqual(result.comparison.disposition, "match")
                self.assertIn(("result", "thread-43", "turn-43", "ambiguous", None, None, None), events)
                self.assertEqual(events.count("interrupt"), 1)
                self.assertEqual(events.count("client-close"), 1)
                self.assertLess(events.index("interrupt"), events.index("client-close"))
                self.assertEqual(service.calls, ["prepare"])

    def test_concrete_read_failures_abort_then_close_once_without_evidence(self):
        for name, failure in (("typed", CodexAdapterError(CodexFailure.UNKNOWN)), ("generic", RuntimeError("closed"))):
            with self.subTest(name=name):
                events, calls = [], []

                class Handle:
                    id = "turn-43"
                    def stream(self):
                        calls.append("stream")
                        raise failure
                    def interrupt(self): events.append("interrupt")

                class Thread:
                    id = "thread-43"
                    def turn(self, *_args, **_kwargs):
                        calls.append("turn")
                        return Handle()

                class Codex:
                    def __enter__(self): return self
                    def __exit__(self, *_args): events.append("client-close")
                    def thread_start(self, **_kwargs): return Thread()

                with tempfile.TemporaryDirectory() as temporary:
                    service = TemporaryReviewedRecorder()
                    recorder = HarnessExternalWorkerRecorder(store_root=Path(temporary) / "store", store_identity=self.readiness.store_identity, recorder=self.recorder_binding, prepare_capture=service.prepare_capture, record_capture=service.record_capture, verify_capture=service.verify_capture)
                    backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
                    result = run_bounded_worker_adapter_qualification(backend=backend, profile=self.profile, audit=self.audit, tools=BoundedWorkerToolSurface(()), request=self.request, readiness=self.readiness, binding=self.binding, recorder=recorder, checkpoint_session=lambda value: events.append(("session", value)), checkpoint_turn=lambda session, turn: events.append(("turn", session, turn)), checkpoint_result=lambda session, turn, kind, diagnostic, source, category: events.append(("result", session, turn, kind.value, None if diagnostic is None else diagnostic.value, None if source is None else source.value, None if category is None else category.value)))

                self.assertEqual(calls, ["turn", "stream"])
                self.assertEqual(events[:4], [("session", "thread-43"), ("turn", "thread-43", "turn-43"), "interrupt", "client-close"])
                self.assertEqual(events.count("interrupt"), 1)
                self.assertEqual(events.count("client-close"), 1)
                self.assertLess(events.index("interrupt"), events.index("client-close"))
                self.assertIn(("result", "thread-43", "turn-43", "ambiguous", None, None, None), events)
                self.assertEqual((result.result.kind, result.record, result.comparison.disposition), ("ambiguous", None, "match"))
                self.assertEqual(service.calls, ["prepare"])

    def test_concrete_success_closes_once_without_interrupt(self):
        events = []
        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=lambda: FakeCodex(events), approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        session = backend.open_session(self.profile, resume_session_identity=None)
        turn = session.start_turn(self.request, BoundedWorkerToolSurface(()))
        self.assertEqual(turn.read_response().kind, "accepted")
        session.close()
        self.assertEqual(events.count("exit"), 1)
        self.assertNotIn("interrupt", events)

    def test_concrete_explicit_cancellation_is_idempotent_and_ordered(self):
        events = []

        class Handle:
            id = "turn-43"
            def stream(self): raise AssertionError("cancellation must not consume a response")
            def interrupt(self): events.append("interrupt")

        class Thread:
            id = "thread-43"
            def turn(self, *_args, **_kwargs):
                events.append("provider-turn")
                return Handle()

        class Codex:
            def __enter__(self): return self
            def __exit__(self, *_args): events.append("client-close")
            def thread_start(self, **_kwargs): return Thread()

        backend = HarnessNativeCodexWorkerBackend(cwd=ROOT, completion=CompletionDeadline(100, 600), codex_factory=Codex, approval_mode="deny-all", sandbox="read-only", effort_factory=lambda value: value)
        session = backend.open_session(self.profile, resume_session_identity=None)
        turn = session.start_turn(self.request, BoundedWorkerToolSurface(()))
        self.assertEqual((session.identity(), turn.identity()), ("thread-43", "turn-43"))
        turn.abort()
        session.close()
        turn.abort()
        session.close()
        self.assertEqual(events, ["provider-turn", "interrupt", "client-close"])

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
