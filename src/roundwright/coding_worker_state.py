"""Closed public states for persisted coding Worker events."""
from enum import StrEnum

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
