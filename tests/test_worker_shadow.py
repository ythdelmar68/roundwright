"""Hermetic contracts for the Worker-adapter Shadow capture boundary."""

from __future__ import annotations

import hashlib
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.codex_worker import CodexWorkerContext, CodexWorkerRequest, CodexWorkerResult, WorkerAction, WorkerResultKind
from roundwright.shadow import AppendOnlyEvidenceStore, RecorderBinding
from roundwright.worker_shadow import (
    WORKER_ADAPTER_PROFILE,
    WorkerShadowDisposition,
    WorkerShadowError,
    compare_worker_shadow_envelopes,
    export_worker_shadow_envelope,
    record_worker_shadow_envelope,
    require_worker_shadow_capture_readiness,
    worker_adapter_shadow_profile,
)


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class WorkerShadowTests(unittest.TestCase):
    candidate = "b" * 40

    def request(self) -> CodexWorkerRequest:
        context = CodexWorkerContext(
            "task-43", *(digest(value) for value in (
                "source", "repository", "worktree", "branch", "base", "candidate", "policy", "configuration",
            )),
        )
        return CodexWorkerRequest("provider-43", WorkerAction.IMPLEMENTATION, digest("request"), context, "Implement issue 43", ("No GitHub",), ("Structured output",))

    def result(self) -> CodexWorkerResult:
        output = {"status": "complete"}
        # The adapter's canonical result fingerprint is exactly this JSON hash.
        output_digest = "sha256:" + hashlib.sha256(b'{"status":"complete"}').hexdigest()
        return CodexWorkerResult(WorkerResultKind.ACCEPTED, "thread-43", "turn-43", output, output_digest, None)

    def envelope(self):
        return export_worker_shadow_envelope(
            self.request(), self.result(), provider_attempt_id="provider-43", external_turn_identity="turn-43",
            base_sha="a" * 40, candidate_sha=self.candidate, profile_identity=digest("profile"),
            runtime_fingerprint=digest("runtime"), deterministic_state="implementing", blocker=None,
            next_action="record-candidate", ready_at=101,
        )

    def readiness(self, store: AppendOnlyEvidenceStore, *, candidate: str | None = None, ready_at: int = 101):
        return require_worker_shadow_capture_readiness(
            candidate_sha=self.candidate if candidate is None else candidate, ready_at=ready_at,
            native_channel_producer_identity=digest("native-channel"), exporter_identity=digest("exporter"),
            comparator_identity=digest("comparator"),
            recorder=RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
            store=store,
        )

    def test_profile_declares_arm_before_and_recapture_contract(self) -> None:
        profile = worker_adapter_shadow_profile()
        self.assertEqual(profile.profile_id, WORKER_ADAPTER_PROFILE)
        self.assertEqual(profile.arm_before, "before-first-selected-live-worker-provider-attempt")
        self.assertEqual(profile.missing_history_recapture, "fresh-bounded-attempt-recapture")

    def test_exact_envelope_exports_no_provider_prose_and_comparison_is_deterministic(self) -> None:
        expected = self.envelope()
        replay = self.envelope()
        comparison = compare_worker_shadow_envelopes(expected, replay)
        self.assertEqual((comparison.disposition, comparison.differing_fields), (WorkerShadowDisposition.MATCH, ()))
        changed = replace(replay, deterministic_state="diff-review", envelope_digest="")
        mismatch = compare_worker_shadow_envelopes(expected, changed)
        self.assertEqual((mismatch.disposition, mismatch.differing_fields), (WorkerShadowDisposition.MISMATCH, ("deterministic_state",)))
        self.assertNotIn("complete", expected.canonical_bytes().decode("ascii"))

    def test_arming_rejects_candidate_and_capture_time_drift_before_recording(self) -> None:
        store = AppendOnlyEvidenceStore("worker-shadow-store")
        envelope = self.envelope()
        for readiness in (self.readiness(store, candidate="c" * 40), self.readiness(store, ready_at=102)):
            with self.subTest(readiness=readiness):
                with self.assertRaisesRegex(WorkerShadowError, "unarmed or stale"):
                    record_worker_shadow_envelope(readiness, envelope, store)

    def test_append_only_store_is_read_back_and_same_thread_replay_stays_one_identity(self) -> None:
        store = AppendOnlyEvidenceStore("worker-shadow-store")
        readiness = self.readiness(store)
        envelope = self.envelope()
        replay = self.envelope()
        self.assertEqual((envelope.worker_thread_identity, envelope.provider_attempt_id, envelope.envelope_digest), (replay.worker_thread_identity, replay.provider_attempt_id, replay.envelope_digest))
        record = record_worker_shadow_envelope(readiness, envelope, store)
        self.assertEqual((record.candidate_sha, record.ready_at, record.envelope_digest), (self.candidate, 101, envelope.envelope_digest))
        with self.assertRaisesRegex(WorkerShadowError, "read-back"):
            record_worker_shadow_envelope(readiness, replay, store)

    def test_turn_and_accepted_result_identity_drift_fails_closed(self) -> None:
        with self.assertRaisesRegex(WorkerShadowError, "turn identity"):
            export_worker_shadow_envelope(
                self.request(), self.result(), provider_attempt_id="provider-43", external_turn_identity="other-turn",
                base_sha="a" * 40, candidate_sha=self.candidate, profile_identity=digest("profile"), runtime_fingerprint=digest("runtime"),
                deterministic_state="implementing", blocker=None, next_action="record-candidate", ready_at=101,
            )
        with self.assertRaises(WorkerShadowError):
            replace(self.envelope(), accepted_result_digest=None)
        forged = CodexWorkerResult(WorkerResultKind.ACCEPTED, "thread-43", "turn-43", {"status": "complete"}, digest("forged"), None)
        with self.assertRaisesRegex(WorkerShadowError, "not bound"):
            export_worker_shadow_envelope(
                self.request(), forged, provider_attempt_id="provider-43", external_turn_identity="turn-43",
                base_sha="a" * 40, candidate_sha=self.candidate, profile_identity=digest("profile"), runtime_fingerprint=digest("runtime"),
                deterministic_state="implementing", blocker=None, next_action="record-candidate", ready_at=101,
            )


if __name__ == "__main__":
    unittest.main()
