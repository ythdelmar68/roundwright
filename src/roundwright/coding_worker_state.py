"""Closed public states for persisted coding Worker events."""
from enum import StrEnum
from dataclasses import dataclass
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
