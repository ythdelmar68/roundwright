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

    def test_denied_record_cannot_retain_effect(self):
        record = CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
        with self.assertRaises(CodingWorkerStateError): replace(record, outcome="denied")
