"""Closed public states for persisted coding Worker events."""
from enum import StrEnum
from dataclasses import dataclass
import re
import hashlib
import json
import sqlite3
from pathlib import Path
from .codex_worker import WorkerAction, WorkerTool

SCHEMA = "roundwright-coding-tool-event/v1"

class CodingWorkerStateError(ValueError):
    pass

class CodingProcessState(StrEnum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"

class CodingCancellationState(StrEnum):
    NOT_REQUESTED = "not-requested"
    REQUESTED = "requested"
    CONFIRMED = "confirmed"

class CodingAmbiguityState(StrEnum):
    CLEAR = "clear"
    SUBMISSION_UNCERTAIN = "submission-uncertain"
    TERMINAL_UNCERTAIN = "terminal-uncertain"

@dataclass(frozen=True)
class CodingToolEventRecord:
    schema: str; task_id: str; objective_digest: str; action: WorkerAction; implementation_attempt_id: str; session_identity: str; external_turn_identity: str; candidate_sha: str; sequence: int; tool: WorkerTool; request_digest: str; result_digest: str; outcome: str; before_digest: str | None; after_digest: str | None; exit_code: int | None; output_digest: str | None; process_state: CodingProcessState; cancellation_state: CodingCancellationState; ambiguity_state: CodingAmbiguityState
    def __post_init__(self):
        token=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z"); digest=re.compile(r"sha256:[0-9a-f]{64}\Z")
        values=(self.objective_digest,self.request_digest,self.result_digest)
        optional=(self.before_digest,self.after_digest,self.output_digest)
        invalid_metadata = (self.tool is WorkerTool.VALIDATION_EXECUTE and (self.before_digest is not None or self.after_digest is not None)) or (self.tool in {WorkerTool.WORKSPACE_READ, WorkerTool.WORKSPACE_WRITE} and (self.exit_code is not None or self.output_digest is not None)) or (self.tool is WorkerTool.WORKSPACE_READ and self.before_digest is not None)
        invalid_lifecycle = self.process_state is CodingProcessState.COMPLETED and (self.ambiguity_state is not CodingAmbiguityState.CLEAR or self.cancellation_state is not CodingCancellationState.NOT_REQUESTED)
        if self.schema!=SCHEMA or any(type(x) is not str or not token.fullmatch(x) for x in (self.task_id,self.implementation_attempt_id,self.session_identity,self.external_turn_identity)) or any(type(x) is not str or not digest.fullmatch(x) for x in values) or any(x is not None and (type(x) is not str or not digest.fullmatch(x)) for x in optional) or not re.fullmatch(r"[0-9a-f]{40}",self.candidate_sha) or type(self.sequence) is not int or self.sequence<1 or type(self.action) is not WorkerAction or type(self.tool) is not WorkerTool or type(self.process_state) is not CodingProcessState or type(self.cancellation_state) is not CodingCancellationState or type(self.ambiguity_state) is not CodingAmbiguityState or self.outcome not in {"allowed","failed","denied","timed-out","cancelled","ambiguous"} or (self.exit_code is not None and type(self.exit_code) is not int) or (self.outcome in {"denied","timed-out","cancelled","ambiguous"} and any(x is not None for x in (self.before_digest,self.after_digest,self.exit_code,self.output_digest))) or invalid_metadata or invalid_lifecycle: raise CodingWorkerStateError("coding tool event is invalid")
    def to_closed_dict(self):
        return {**self.__dict__, "action": self.action.value, "tool": self.tool.value, "process_state": self.process_state.value, "cancellation_state": self.cancellation_state.value, "ambiguity_state": self.ambiguity_state.value}
    @property
    def record_digest(self):
        return "sha256:" + hashlib.sha256(json.dumps(self.to_closed_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
    @classmethod
    def from_closed_dict(cls, value):
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__): raise CodingWorkerStateError("coding tool event is invalid")
        try:
            copy=dict(value); copy["action"]=WorkerAction(copy["action"]); copy["tool"]=WorkerTool(copy["tool"]); copy["process_state"]=CodingProcessState(copy["process_state"]); copy["cancellation_state"]=CodingCancellationState(copy["cancellation_state"]); copy["ambiguity_state"]=CodingAmbiguityState(copy["ambiguity_state"]); return cls(**copy)
        except (KeyError, TypeError, ValueError) as error: raise CodingWorkerStateError("coding tool event is invalid") from error

class CodingToolEventStore:
    def __init__(self, database: Path):
        if not isinstance(database, Path) or not database.parent.is_dir(): raise CodingWorkerStateError("coding tool store is invalid")
        connection = sqlite3.connect(database)
        self._database = database
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS coding_tool_event_metadata(schema_name TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)")
            connection.execute("INSERT OR IGNORE INTO coding_tool_event_metadata VALUES (?, ?)", ("roundwright-coding-tool-event-store", 1))
            connection.execute("CREATE TABLE IF NOT EXISTS coding_tool_events(task_id TEXT NOT NULL, implementation_attempt_id TEXT NOT NULL, session_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, candidate_sha TEXT NOT NULL, sequence INTEGER NOT NULL, record_digest TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(task_id,implementation_attempt_id,session_identity,external_turn_identity,sequence))")
            connection.execute("CREATE TABLE IF NOT EXISTS coding_effect_intents(task_id TEXT NOT NULL, implementation_attempt_id TEXT NOT NULL, session_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, sequence INTEGER NOT NULL, request_digest TEXT NOT NULL, PRIMARY KEY(task_id,implementation_attempt_id,session_identity,external_turn_identity,sequence))")
            if connection.execute("SELECT schema_name, schema_version FROM coding_tool_event_metadata").fetchall() != [("roundwright-coding-tool-event-store", 1)]: raise CodingWorkerStateError("coding tool store is invalid")
            connection.commit()
        finally:
            connection.close()
    def claim_effect(self, task_id, implementation_attempt_id, session_identity, external_turn_identity, sequence, request_digest):
        """Durably reserve an effect before invoking the local capability.

        A replayed reservation is never treated as permission to repeat a
        potentially completed filesystem or process effect.  The caller must
        surface a typed ambiguous result instead.
        """
        token=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
        digest=re.compile(r"sha256:[0-9a-f]{64}\Z")
        if (any(type(value) is not str or not token.fullmatch(value) for value in (task_id,implementation_attempt_id,session_identity,external_turn_identity))
                or type(sequence) is not int or sequence < 1 or type(request_digest) is not str or not digest.fullmatch(request_digest)):
            raise CodingWorkerStateError("coding effect intent is invalid")
        connection=sqlite3.connect(self._database)
        try:
            existing=connection.execute("SELECT request_digest FROM coding_effect_intents WHERE task_id=? AND implementation_attempt_id=? AND session_identity=? AND external_turn_identity=? AND sequence=?",(task_id,implementation_attempt_id,session_identity,external_turn_identity,sequence)).fetchone()
            if existing is not None:
                if existing != (request_digest,): raise CodingWorkerStateError("coding effect intent replay conflicts")
                return False
            connection.execute("INSERT INTO coding_effect_intents VALUES (?, ?, ?, ?, ?, ?)",(task_id,implementation_attempt_id,session_identity,external_turn_identity,sequence,request_digest))
            connection.commit(); return True
        except sqlite3.Error as error:
            connection.rollback(); raise CodingWorkerStateError("coding effect intent checkpoint failed") from error
        finally: connection.close()
    def append(self, record):
        if type(record) is not CodingToolEventRecord: raise CodingWorkerStateError("coding tool event is invalid")
        payload=json.dumps(record.to_closed_dict(),sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)
        connection=sqlite3.connect(self._database)
        try:
            existing=connection.execute("SELECT record_digest,payload_json FROM coding_tool_events WHERE task_id=? AND implementation_attempt_id=? AND session_identity=? AND external_turn_identity=? AND sequence=?",(record.task_id,record.implementation_attempt_id,record.session_identity,record.external_turn_identity,record.sequence)).fetchone()
            if existing is not None:
                if existing != (record.record_digest,payload): raise CodingWorkerStateError("coding tool event replay conflicts")
                return CodingToolEventRecord.from_closed_dict(json.loads(existing[1]))
            connection.execute("INSERT INTO coding_tool_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",(record.task_id,record.implementation_attempt_id,record.session_identity,record.external_turn_identity,record.candidate_sha,record.sequence,record.record_digest,payload)); connection.commit(); return record
        except sqlite3.Error as error:
            connection.rollback(); raise CodingWorkerStateError("coding tool store append failed") from error
        finally: connection.close()
