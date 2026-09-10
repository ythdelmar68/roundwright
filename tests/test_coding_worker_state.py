import sys
import unittest
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from roundwright.coding_worker_state import SCHEMA, CodingProcessState, CodingCancellationState, CodingAmbiguityState, CodingToolEventRecord, CodingWorkerStateError
from roundwright.codex_worker import WorkerAction, WorkerTool

class CodingWorkerStateTests(unittest.TestCase):
    def test_public_values(self):
        self.assertEqual(SCHEMA, "roundwright-coding-tool-event/v1")
        self.assertEqual(tuple(CodingProcessState), ("started", "completed", "failed"))
        self.assertEqual(tuple(CodingCancellationState), ("not-requested", "requested", "confirmed"))
        self.assertEqual(tuple(CodingAmbiguityState), ("clear", "submission-uncertain", "terminal-uncertain"))
        record = CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
        self.assertEqual(record.sequence, 1)
        self.assertEqual(record.to_closed_dict()["schema"], SCHEMA)
        self.assertEqual(record.to_closed_dict()["tool"], "workspace-write")

    def test_denied_record_cannot_retain_effect(self):
        record = CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
        with self.assertRaises(CodingWorkerStateError): replace(record, outcome="denied")

    def test_tool_specific_metadata_is_closed(self):
        record = CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
        for change in (lambda: replace(record, output_digest="sha256:"+"e"*64), lambda: replace(record, exit_code=0), lambda: replace(record, tool=WorkerTool.WORKSPACE_READ, before_digest="sha256:"+"e"*64, after_digest=None)):
            with self.assertRaises(CodingWorkerStateError): change()

    def test_completed_record_requires_clear_uncancelled_lifecycle(self):
        record = CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
        for change in (lambda: replace(record, ambiguity_state=CodingAmbiguityState.SUBMISSION_UNCERTAIN), lambda: replace(record, ambiguity_state=CodingAmbiguityState.TERMINAL_UNCERTAIN), lambda: replace(record, cancellation_state=CodingCancellationState.REQUESTED), lambda: replace(record, cancellation_state=CodingCancellationState.CONFIRMED)):
            with self.assertRaises(CodingWorkerStateError): change()
