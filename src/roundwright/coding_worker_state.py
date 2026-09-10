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
        if self.schema!=SCHEMA or any(type(x) is not str or not token.fullmatch(x) for x in (self.task_id,self.implementation_attempt_id,self.session_identity,self.external_turn_identity)) or any(type(x) is not str or not digest.fullmatch(x) for x in values) or any(x is not None and (type(x) is not str or not digest.fullmatch(x)) for x in optional) or not re.fullmatch(r"[0-9a-f]{40}",self.candidate_sha) or type(self.sequence) is not int or self.sequence<1 or type(self.action) is not WorkerAction or type(self.tool) is not WorkerTool or type(self.process_state) is not CodingProcessState or type(self.cancellation_state) is not CodingCancellationState or type(self.ambiguity_state) is not CodingAmbiguityState or self.outcome not in {"allowed","failed","denied"} or (self.exit_code is not None and type(self.exit_code) is not int) or (self.outcome == "denied" and any(x is not None for x in (self.before_digest,self.after_digest,self.exit_code,self.output_digest))) or invalid_metadata or invalid_lifecycle: raise CodingWorkerStateError("coding tool event is invalid")
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
        if type(database) is not Path or not database.parent.is_dir(): raise CodingWorkerStateError("coding tool store is invalid")
        with sqlite3.connect(database) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS coding_tool_event_metadata(schema_name TEXT PRIMARY KEY, schema_version INTEGER NOT NULL)")
            connection.execute("INSERT OR IGNORE INTO coding_tool_event_metadata VALUES (?, ?)", ("roundwright-coding-tool-event-store", 1))
            connection.execute("CREATE TABLE IF NOT EXISTS coding_tool_events(task_id TEXT NOT NULL, implementation_attempt_id TEXT NOT NULL, session_identity TEXT NOT NULL, external_turn_identity TEXT NOT NULL, candidate_sha TEXT NOT NULL, sequence INTEGER NOT NULL, record_digest TEXT NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(task_id,implementation_attempt_id,session_identity,external_turn_identity,sequence))")
            if connection.execute("SELECT schema_name, schema_version FROM coding_tool_event_metadata").fetchall() != [("roundwright-coding-tool-event-store", 1)]: raise CodingWorkerStateError("coding tool store is invalid")
