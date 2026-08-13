"""Hermetic integration contracts for the operational Worker Shadow boundary."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from unittest.mock import patch
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import BoundedWorkerToolSurface, CodexWorkerAdapter, CodexWorkerContext, CodexWorkerRequest, NativeWorkerResponse, WorkerAction, WorkerParserDiagnostic, WorkerResultKind, WorkerTool, worker_request_digest
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.provider_health import CodexCapability, CodexFailure, CodexRuntimeAudit, ProviderHealthAuditIdentity
from roundwright.shadow import RecorderBinding
from roundwright.worker_shadow import ExternalRecorderReceipt, WORKER_ADAPTER_PROFILE, WorkerQualificationBinding, WorkerShadowDisposition, WorkerShadowError, WorkerShadowMismatchError, compare_worker_shadow_envelopes, qualify_worker_adapter, require_worker_shadow_capture_readiness, worker_adapter_shadow_profile


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Turn:
    def __init__(self, events, response): self.events, self.response = events, response
    def identity(self): return "turn-43"
    def read_response(self): self.events.append("read"); return self.response


class Session:
    def __init__(self, events, response): self.events, self.response = events, response
    def identity(self): return "thread-43"
    def start_turn(self, _request, _tools): self.events.append("turn-start"); return Turn(self.events, self.response)


class Backend:
    def __init__(self, events, response): self.events, self.calls, self.response = events, 0, response
    def open_session(self, _profile, *, resume_session_identity): self.calls += 1; self.events.append(f"open:{resume_session_identity}"); return Session(self.events, self.response)


class Recorder:
    def __init__(self, events, *, fail=False): self.events, self.fail, self.receipt = events, fail, None
    def prepare(self, *, store_identity):
        self.events.append(("prepare", store_identity))
        if self.fail: raise RuntimeError("unavailable")
    def seal(self, document, *, store_identity):
        self.events.append(("seal", document["ready_at"], store_identity))
        if self.fail: raise RuntimeError("unavailable")
        evidence = digest(document)
        self.receipt = ExternalRecorderReceipt(WORKER_ADAPTER_PROFILE, document["case_id"], document["candidate_sha"], document["ready_at"], evidence, digest("manifest"), digest("bundle"), digest({"store": store_identity}), digest("receipt"))
        return self.receipt
    def verify(self, bundle_digest, *, store_identity):
        self.events.append(("verify", bundle_digest, store_identity))
        if self.receipt is None or self.receipt.bundle_digest != bundle_digest: raise RuntimeError("missing")
        return self.receipt


class WorkerShadowTests(unittest.TestCase):
    base, candidate = "a" * 40, "b" * 40
    def setUp(self):
        self.events = []
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        audit = ProviderHealthAuditIdentity(CodexRuntimeAudit("1.2.3", "4.5.6", (CodexCapability(profile.model, profile.reasoning_effort.value),)), profile)
        self.backend = Backend(self.events, NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "complete", "action": "implementation"}))
        self.adapter = CodexWorkerAdapter(self.backend, profile, audit, BoundedWorkerToolSurface(()))
        context = CodexWorkerContext("task-43", *(digest(value) for value in ("source", "repo", "worktree", "branch", "base", "candidate", "policy", "configuration")))
        self.request = CodexWorkerRequest("provider-43", WorkerAction.IMPLEMENTATION, worker_request_digest(attempt_id="provider-43", action=WorkerAction.IMPLEMENTATION, context=context, objective="Qualify Worker", constraints=("No GitHub",), acceptance_criteria=("Structured result",), resume_session_identity=None), context, "Qualify Worker", ("No GitHub",), ("Structured result",))
        self.readiness = require_worker_shadow_capture_readiness(candidate_sha=self.candidate, ready_at=101, native_channel_producer_identity=digest("native"), exporter_identity=digest("exporter"), comparator_identity=digest("comparator"), recorder=RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"), store_identity=digest("external-store"))
        self.binding = WorkerQualificationBinding("case-43", context.task_id, self.base, self.candidate, context.base_fingerprint, context.candidate_fingerprint, audit.profile_identity, context.configuration_digest, audit.runtime_fingerprint, self.readiness.native_channel_producer_identity, self.readiness.exporter_identity, self.readiness.comparator_identity, self.readiness.recorder_binding_digest, self.readiness.store_identity, "implementation-complete", None, "supervisor-review")

    def qualify(self, readiness=None, binding=None, recorder=None):
        return qualify_worker_adapter(self.adapter, self.request, self.readiness if readiness is None else readiness, self.binding if binding is None else binding, Recorder(self.events) if recorder is None else recorder, checkpoint_session=lambda identity: self.events.append(f"session:{identity}"), checkpoint_turn=lambda session, turn: self.events.append(f"turn:{session}:{turn}"), checkpoint_result=lambda session, turn, kind, diagnostic: self.events.append(f"result:{session}:{turn}:{kind.value}:{'' if diagnostic is None else diagnostic.value}"))

    def test_profile_declares_arm_before_and_recapture(self):
        profile = worker_adapter_shadow_profile()
        self.assertEqual((profile.profile_id, profile.arm_before, profile.missing_history_recapture), (WORKER_ADAPTER_PROFILE, "before-first-selected-live-worker-provider-attempt", "fresh-bounded-attempt-recapture"))

    def test_pre_dispatch_arming_and_exact_time_flow_through_turn_envelope_seal_and_readback(self):
        result = self.qualify()
        self.assertEqual(self.events, [("prepare", self.readiness.store_identity), "open:None", "session:thread-43", "turn-start", "turn:thread-43:turn-43", "read", "result:thread-43:turn-43:accepted:", ("seal", 101, self.readiness.store_identity), ("verify", digest("bundle"), self.readiness.store_identity)])
        self.assertEqual((result.envelope.ready_at, result.record.receipt.ready_at, result.comparison.disposition), (101, 101, WorkerShadowDisposition.MATCH))
        self.assertNotIn("complete", json.dumps(result.record.receipt.__dict__))

    def test_readiness_or_identity_drift_blocks_before_provider_call(self):
        for invalid in (replace(self.readiness, candidate_sha="c" * 40, readiness_digest=""), replace(self.readiness, exporter_identity=digest("other"), readiness_digest=""), replace(self.binding, profile_identity=digest("other")), replace(self.binding, configuration_digest=digest("other"))):
            with self.subTest(invalid=invalid):
                self.events.clear(); self.backend.calls = 0
                if isinstance(invalid, type(self.readiness)):
                    with self.assertRaises(WorkerShadowError): self.qualify(readiness=invalid)
                else:
                    with self.assertRaises(WorkerShadowError): self.qualify(binding=invalid)
                self.assertEqual(self.backend.calls, 0)
                self.assertEqual(self.events, [])

    def test_external_recorder_failure_is_not_misreported_as_recorded(self):
        recorder = Recorder(self.events, fail=True)
        with self.assertRaisesRegex(WorkerShadowError, "pre-dispatch readiness"):
            self.qualify(recorder=recorder)
        self.assertEqual(self.events[-1][0], "prepare")
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "verify" for event in self.events))

    def test_same_thread_result_has_one_turn_and_deterministic_comparison(self):
        first = self.qualify()
        self.assertEqual((first.envelope.worker_thread_identity, first.envelope.provider_attempt_id, first.envelope.external_turn_identity), ("thread-43", "provider-43", "turn-43"))
        changed = replace(first.envelope, deterministic_state="diff-review", envelope_digest="")
        comparison = compare_worker_shadow_envelopes(first.envelope, changed)
        self.assertEqual((comparison.disposition, comparison.differing_fields), (WorkerShadowDisposition.MISMATCH, ("deterministic_state",)))

    def test_observed_lifecycle_mismatch_is_rejected_before_seal(self):
        with patch("roundwright.worker_shadow._observed_worker_transition", return_value=("different-state", None, "different-next")):
            with self.assertRaises(WorkerShadowMismatchError) as captured:
                self.qualify()
        self.assertEqual(captured.exception.comparison.diagnostic(), {"disposition": "mismatch", "differing_fields": ("deterministic_state", "next_action")})
        self.assertFalse(any(isinstance(event, tuple) and event[0] == "seal" for event in self.events))

    def test_provider_output_cannot_control_the_lifecycle_projection(self):
        self.backend.response = NativeWorkerResponse(WorkerResultKind.ACCEPTED, {"status": "complete", "action": "implementation", "result_digest": digest("result"), "deterministic_state": "provider-string", "next_action": "provider-action"})
        result = self.qualify()
        self.assertEqual((result.envelope.deterministic_state, result.envelope.next_action), ("implementation-complete", "supervisor-review"))

    def test_nonqualifying_categories_have_distinct_local_projections_and_no_recorder(self):
        cases = (
            (WorkerResultKind.INVALID, None, "invalid", "fresh-bounded-attempt-recapture"),
            (WorkerResultKind.INCOMPLETE, None, "incomplete", "fresh-bounded-attempt-recapture"),
            (WorkerResultKind.AMBIGUOUS, None, "ambiguous", "fresh-bounded-attempt-recapture"),
            (WorkerResultKind.BLOCKED, "owner-input", "blocked", "owner-input"),
        )
        for kind, blocker, state, next_action in cases:
            with self.subTest(kind=kind):
                self.events.clear()
                self.backend.response = NativeWorkerResponse(
                    kind,
                    failure=None if kind is not WorkerResultKind.BLOCKED else CodexFailure.UNKNOWN,
                    blocker=blocker,
                    diagnostic=WorkerParserDiagnostic.SHAPE if kind is WorkerResultKind.INVALID else None,
                )
                result = self.qualify()
                self.assertEqual((result.envelope.deterministic_state, result.envelope.next_action, result.record), (state, next_action, None))
                self.assertEqual(result.comparison.disposition, WorkerShadowDisposition.MATCH)
                self.assertTrue(any(type(event) is str and event.startswith(f"result:thread-43:turn-43:{kind.value}:") for event in self.events))
                if kind is WorkerResultKind.INVALID:
                    self.assertIn("result:thread-43:turn-43:invalid:shape", self.events)
                self.assertFalse(any(isinstance(event, tuple) and event[0] == "seal" for event in self.events))


if __name__ == "__main__": unittest.main()
