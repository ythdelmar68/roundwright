"""Closed public states for persisted coding Worker events."""
from enum import StrEnum
from dataclasses import dataclass
import re
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
        if self.schema!=SCHEMA or any(type(x) is not str or not token.fullmatch(x) for x in (self.task_id,self.implementation_attempt_id,self.session_identity,self.external_turn_identity)) or any(type(x) is not str or not digest.fullmatch(x) for x in values) or any(x is not None and (type(x) is not str or not digest.fullmatch(x)) for x in optional) or not re.fullmatch(r"[0-9a-f]{40}",self.candidate_sha) or type(self.sequence) is not int or self.sequence<1 or type(self.action) is not WorkerAction or type(self.tool) is not WorkerTool or type(self.process_state) is not CodingProcessState or type(self.cancellation_state) is not CodingCancellationState or type(self.ambiguity_state) is not CodingAmbiguityState or self.outcome not in {"allowed","failed","denied"} or (self.exit_code is not None and type(self.exit_code) is not int) or (self.outcome == "denied" and any(x is not None for x in (self.before_digest,self.after_digest,self.exit_code,self.output_digest))): raise CodingWorkerStateError("coding tool event is invalid")
