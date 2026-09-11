import sys
import unittest
import sqlite3
import tempfile
import json
from dataclasses import replace
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from roundwright.coding_worker_state import SCHEMA, CodingProcessState, CodingCancellationState, CodingAmbiguityState, CodingToolEventRecord, CodingWorkerStateError, CodingToolEventStore
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
        self.assertTrue(record.record_digest.startswith("sha256:"))
        self.assertNotEqual(record.record_digest, replace(record, sequence=2).record_digest)
        self.assertEqual(CodingToolEventRecord.from_closed_dict(record.to_closed_dict()), record)

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

    def test_store_bootstrap_and_reopen(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"state.db"; CodingToolEventStore(path)
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(set(x[0] for x in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")), {"coding_tool_event_metadata","coding_tool_events","coding_effect_intents"})
                self.assertEqual(connection.execute("SELECT schema_name, schema_version FROM coding_tool_event_metadata").fetchall(), [("roundwright-coding-tool-event-store",1)])
            finally:
                connection.close()
            CodingToolEventStore(path)

    def test_store_appends_one_closed_record(self):
        with tempfile.TemporaryDirectory() as temp:
            store=CodingToolEventStore(Path(temp)/"state.db")
            record=CodingToolEventRecord(SCHEMA,"task","sha256:"+"a"*64,WorkerAction.IMPLEMENTATION,"attempt","session","turn","a"*40,1,WorkerTool.WORKSPACE_WRITE,"sha256:"+"b"*64,"sha256:"+"c"*64,"allowed",None,"sha256:"+"d"*64,None,None,CodingProcessState.COMPLETED,CodingCancellationState.NOT_REQUESTED,CodingAmbiguityState.CLEAR)
            self.assertEqual(store.append(record),record)
            connection=sqlite3.connect(Path(temp)/"state.db")
            try:
                row=connection.execute("SELECT task_id,sequence,record_digest,payload_json FROM coding_tool_events").fetchall(); self.assertEqual(len(row),1); self.assertEqual(row[0][:3],("task",1,record.record_digest)); self.assertEqual(json.loads(row[0][3]),record.to_closed_dict()); self.assertFalse(any(x in row[0][3] for x in ("raw_content","private_path","provider","error","credential")))
            finally: connection.close()

    def test_effect_intent_is_one_shot_and_conflicts_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store=CodingToolEventStore(Path(temp)/"state.db")
            first="sha256:" + "a" * 64; second="sha256:" + "b" * 64
            self.assertTrue(store.claim_effect("task-1","attempt-1","session-1","turn-1",1,first))
            self.assertFalse(store.claim_effect("task-1","attempt-1","session-1","turn-1",1,first))
            with self.assertRaises(CodingWorkerStateError):
                store.claim_effect("task-1","attempt-1","session-1","turn-1",1,second)
