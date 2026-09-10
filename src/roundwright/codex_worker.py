"""Bounded native Codex Worker adapter.

The lifecycle modules own durable state.  This adapter owns the narrow moment
between an already-authorized, persisted dispatch and a native Codex SDK turn:
it binds the exact profile and runtime audit, gives the SDK only normalized
Worker context and an explicit tool surface, then requires durable session and
turn checkpoints before reading any provider result.

The native SDK and credentials stay behind an injected backend (normally the
reviewed external harness).  Consequently this module never imports an SDK,
discovers credentials, accesses GitHub, or exposes provider prose.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .configuration import ProviderProfile
from .provider_health import CodexAdapterError, CodexFailure, ProviderHealthAuditIdentity
from .provider_recovery import ProviderRole


class CodexWorkerError(ValueError):
    """Raised when an adapter request would weaken the Worker boundary."""


class WorkerAction(StrEnum):
    PLANNING = "planning"
    IMPLEMENTATION = "implementation"
    REPAIR = "repair"


class WorkerTool(StrEnum):
    """The complete Worker tool vocabulary; authority stays outside it."""

    WORKSPACE_READ = "workspace-read"
    WORKSPACE_WRITE = "workspace-write"
    VALIDATION_EXECUTE = "validation-execute"


class WorkerCapabilityContract(StrEnum):
    """Truthful provider capability contracts, never inferred from labels."""

    NO_TOOLS_SELF_CONTAINED = "no-tools-self-contained/v1"
    ORCHESTRATION_DECLARED_ONLY = "orchestration-declared-only/v1"
    EXECUTABLE_BOUNDED_CODING = "executable-bounded-coding/v1"


class WorkerResultKind(StrEnum):
    ACCEPTED = "accepted"
    BLOCKED = "blocked"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"


class WorkerParserDiagnostic(StrEnum):
    """Bounded local reason for a rejected native structured result."""

    SYNTAX = "syntax"
    SHAPE = "shape"
    ACTION = "action"
    STATUS = "status"
    BLOCKER = "blocker"
    EXACT_TURN = "exact-turn"
    NON_FINAL = "non-final"


class WorkerOutcomeSource(StrEnum):
    """Bounded retained origin for non-success Worker outcomes."""

    SDK_TURN_FAILED = "sdk-turn-failed"
    PROVIDER_STRUCTURED_BLOCKED = "provider-structured-blocked"


class WorkerSdkTurnErrorCategory(StrEnum):
    """Closed, public-safe projection of a failed native SDK turn."""

    BAD_REQUEST = "bad-request"
    UNAUTHORIZED = "unauthorized"
    SANDBOX = "sandbox"
    OVERLOAD = "overload"
    HTTP = "http"
    STREAM = "stream"
    CONNECTION = "connection"
    MISSING_OR_UNKNOWN = "missing-or-unknown"


class WorkerToolRequestKind(StrEnum):
    READ = "read"
    WRITE = "write"
    VALIDATE = "validate"


@dataclass(frozen=True)
class NativeWorkerToolRequest:
    """One closed, ordered SDK request; never a shell or general payload."""
    sequence: int
    tool: WorkerTool
    path: str | None = None
    content: str | None = None
    command: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        token = lambda value: type(value) is str and bool(value) and len(value) <= 100_000
        valid = type(self.sequence) is int and self.sequence > 0 and type(self.tool) is WorkerTool
        if self.tool is WorkerTool.WORKSPACE_READ:
            valid = valid and token(self.path) and self.content is None and self.command is None
        elif self.tool is WorkerTool.WORKSPACE_WRITE:
            valid = valid and token(self.path) and token(self.content) and self.command is None
        elif self.tool is WorkerTool.VALIDATION_EXECUTE:
            valid = valid and self.path is None and self.content is None and type(self.command) is tuple and bool(self.command) and all(token(item) for item in self.command)
        if not valid:
            raise CodexWorkerError("native Worker tool request is invalid")


@dataclass(frozen=True)
class NativeWorkerToolResult:
    """Closed reply to exactly one native tool request."""
    sequence: int
    tool: WorkerTool
    outcome: str
    before_digest: str | None = None
    after_digest: str | None = None
    exit_code: int | None = None
    output_digest: str | None = None

    def __post_init__(self) -> None:
        valid = type(self.sequence) is int and self.sequence > 0 and type(self.tool) is WorkerTool and self.outcome in {"allowed", "failed", "denied"}
        for value in (self.before_digest, self.after_digest, self.output_digest):
            valid = valid and (value is None or (type(value) is str and _DIGEST.fullmatch(value)))
        valid = valid and (self.exit_code is None or type(self.exit_code) is int)
        if not valid:
            raise CodexWorkerError("native Worker tool result is invalid")


@dataclass(frozen=True)
class NativeWorkerTurnStep:
    """A stream step is exclusively a tool request or its terminal response."""
    request: NativeWorkerToolRequest | None = None
    response: "NativeWorkerResponse | None" = None

    def __post_init__(self) -> None:
        if (self.request is None) == (self.response is None) or (self.request is not None and type(self.request) is not NativeWorkerToolRequest) or (self.response is not None and type(self.response) is not NativeWorkerResponse):
            raise CodexWorkerError("native Worker turn step is invalid")


def expected_lifecycle(action: WorkerAction) -> tuple[str, str | None, str]:
    """The provider-neutral terminal projection for each Worker lifecycle role."""

    if type(action) is not WorkerAction:
        raise CodexWorkerError("Worker action is invalid")
    values = {
        WorkerAction.PLANNING: ("planning-complete", None, "supervisor-review"),
        WorkerAction.IMPLEMENTATION: ("implementation-complete", None, "supervisor-review"),
        WorkerAction.REPAIR: ("qualification-complete", None, "supervisor-review"),
    }
    return values[action]


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")


@dataclass(frozen=True)
class BoundedWorkerToolSurface:
    """Orchestrator-declared tools; non-empty labels are not SDK enforcement."""

    tools: tuple[WorkerTool, ...]

    def __post_init__(self) -> None:
        if (
            type(self.tools) is not tuple
            or any(type(tool) is not WorkerTool for tool in self.tools)
            or len(set(self.tools)) != len(self.tools)
        ):
            raise CodexWorkerError("Worker tool surface is invalid")

    @property
    def capability_contract(self) -> WorkerCapabilityContract:
        if not self.tools:
            return WorkerCapabilityContract.NO_TOOLS_SELF_CONTAINED
        return WorkerCapabilityContract.ORCHESTRATION_DECLARED_ONLY


@dataclass(frozen=True)
class CodexWorkerContext:
    """Path-free immutable values supplied to one native Worker turn."""

    task_id: str
    source_digest: str
    repository_fingerprint: str
    worktree_fingerprint: str
    branch_fingerprint: str
    base_fingerprint: str
    candidate_fingerprint: str | None
    policy_fingerprint: str
    configuration_digest: str

    def __post_init__(self) -> None:
        values = (
            self.source_digest,
            self.repository_fingerprint,
            self.worktree_fingerprint,
            self.branch_fingerprint,
            self.base_fingerprint,
            self.policy_fingerprint,
            self.configuration_digest,
        )
        if (
            type(self.task_id) is not str
            or not _TOKEN.fullmatch(self.task_id)
            or any(type(value) is not str or not _DIGEST.fullmatch(value) for value in values)
            or (self.candidate_fingerprint is not None and (type(self.candidate_fingerprint) is not str or not _DIGEST.fullmatch(self.candidate_fingerprint)))
        ):
            raise CodexWorkerError("Worker context is invalid")

    @property
    def digest(self) -> str:
        return _digest({
            "task_id": self.task_id,
            "source_digest": self.source_digest,
            "repository_fingerprint": self.repository_fingerprint,
            "worktree_fingerprint": self.worktree_fingerprint,
            "branch_fingerprint": self.branch_fingerprint,
            "base_fingerprint": self.base_fingerprint,
            "candidate_fingerprint": self.candidate_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "configuration_digest": self.configuration_digest,
        })


@dataclass(frozen=True)
class CodexWorkerRequest:
    """Normalized objective and context for one durable Worker attempt."""

    attempt_id: str
    action: WorkerAction
    input_digest: str
    context: CodexWorkerContext
    objective: str
    constraints: tuple[str, ...]
    acceptance_criteria: tuple[str, ...]
    resume_session_identity: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.attempt_id) is not str
            or not _TOKEN.fullmatch(self.attempt_id)
            or type(self.action) is not WorkerAction
            or type(self.input_digest) is not str
            or not _DIGEST.fullmatch(self.input_digest)
            or type(self.context) is not CodexWorkerContext
            or not _text(self.objective)
            or not _items(self.constraints)
            or not _items(self.acceptance_criteria)
            or (self.resume_session_identity is not None and (type(self.resume_session_identity) is not str or not _TOKEN.fullmatch(self.resume_session_identity)))
            or self.input_digest != worker_request_digest(
                attempt_id=self.attempt_id, action=self.action, context=self.context,
                objective=self.objective, constraints=self.constraints,
                acceptance_criteria=self.acceptance_criteria,
                resume_session_identity=self.resume_session_identity,
            )
        ):
            raise CodexWorkerError("Worker request is invalid")


@dataclass(frozen=True)
class NativeWorkerResponse:
    """Typed native response; no raw SDK payload or exception text crosses it."""

    kind: WorkerResultKind
    structured_output: Mapping[str, object] | None = None
    failure: CodexFailure | None = None
    blocker: str | None = None
    diagnostic: WorkerParserDiagnostic | None = None
    outcome_source: WorkerOutcomeSource | None = None
    sdk_error_category: WorkerSdkTurnErrorCategory | None = None

    def __post_init__(self) -> None:
        valid = (
            type(self.kind) is WorkerResultKind
            and (self.structured_output is None or type(self.structured_output) is dict)
            and (self.failure is None or type(self.failure) is CodexFailure)
            and (self.blocker is None or (type(self.blocker) is str and _TOKEN.fullmatch(self.blocker)))
            and (self.diagnostic is None or type(self.diagnostic) is WorkerParserDiagnostic)
            and (self.outcome_source is None or type(self.outcome_source) is WorkerOutcomeSource)
            and (self.sdk_error_category is None or type(self.sdk_error_category) is WorkerSdkTurnErrorCategory)
        )
        if self.kind is WorkerResultKind.ACCEPTED:
            valid = valid and self.structured_output is not None and self.failure is None and self.blocker is None and self.diagnostic is None and self.outcome_source is None and self.sdk_error_category is None
        elif self.kind is WorkerResultKind.BLOCKED:
            valid = valid and self.structured_output is None and self.failure is not None and self.blocker is not None and self.diagnostic is None and type(self.outcome_source) is WorkerOutcomeSource and ((self.outcome_source is WorkerOutcomeSource.SDK_TURN_FAILED and type(self.sdk_error_category) is WorkerSdkTurnErrorCategory) or (self.outcome_source is WorkerOutcomeSource.PROVIDER_STRUCTURED_BLOCKED and self.sdk_error_category is None))
        elif self.kind is WorkerResultKind.INVALID:
            valid = valid and self.structured_output is None and self.failure is None and self.blocker is None and type(self.diagnostic) is WorkerParserDiagnostic and self.outcome_source is None and self.sdk_error_category is None
        else:
            valid = valid and self.structured_output is None and self.failure is None and self.blocker is None and self.diagnostic is None and self.outcome_source is None and self.sdk_error_category is None
        if not valid:
            raise CodexWorkerError("native Worker response is invalid")


@dataclass(frozen=True)
class CodexWorkerResult:
    """Owner-safe outcome available only after both external IDs are durable."""

    kind: WorkerResultKind
    session_identity: str | None
    turn_identity: str | None
    output: Mapping[str, object] | None
    output_fingerprint: str | None
    failure: CodexFailure | None
    blocker: str | None = None
    diagnostic: WorkerParserDiagnostic | None = None
    outcome_source: WorkerOutcomeSource | None = None
    sdk_error_category: WorkerSdkTurnErrorCategory | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not WorkerResultKind or (self.session_identity is not None and (type(self.session_identity) is not str or not _TOKEN.fullmatch(self.session_identity))):
            raise CodexWorkerError("Worker result is invalid")
        if self.turn_identity is not None and (type(self.turn_identity) is not str or not _TOKEN.fullmatch(self.turn_identity)):
            raise CodexWorkerError("Worker result is invalid")
        if self.kind is WorkerResultKind.ACCEPTED:
            if type(self.output) is not dict or type(self.output_fingerprint) is not str or not _DIGEST.fullmatch(self.output_fingerprint) or self.failure is not None or self.blocker is not None or self.diagnostic is not None or self.outcome_source is not None or self.sdk_error_category is not None or self.session_identity is None or self.turn_identity is None:
                raise CodexWorkerError("Worker result is invalid")
        elif self.kind is WorkerResultKind.BLOCKED:
            if self.output is not None or self.output_fingerprint is not None or type(self.failure) is not CodexFailure or type(self.blocker) is not str or not _TOKEN.fullmatch(self.blocker) or self.diagnostic is not None or type(self.outcome_source) is not WorkerOutcomeSource or ((self.outcome_source is WorkerOutcomeSource.SDK_TURN_FAILED and type(self.sdk_error_category) is not WorkerSdkTurnErrorCategory) or (self.outcome_source is WorkerOutcomeSource.PROVIDER_STRUCTURED_BLOCKED and self.sdk_error_category is not None)) or self.session_identity is None or self.turn_identity is None:
                raise CodexWorkerError("Worker result is invalid")
        elif self.kind is WorkerResultKind.INVALID:
            if self.output is not None or self.output_fingerprint is not None or self.failure is not None or self.blocker is not None or type(self.diagnostic) is not WorkerParserDiagnostic or self.outcome_source is not None or self.sdk_error_category is not None or self.session_identity is None or self.turn_identity is None:
                raise CodexWorkerError("Worker result is invalid")
        elif self.kind is WorkerResultKind.INCOMPLETE:
            if self.output is not None or self.output_fingerprint is not None or self.failure is not None or self.blocker is not None or self.diagnostic is not None or self.outcome_source is not None or self.sdk_error_category is not None or self.session_identity is None or self.turn_identity is None:
                raise CodexWorkerError("Worker result is invalid")
        elif self.kind is WorkerResultKind.AMBIGUOUS:
            if self.output is not None or self.output_fingerprint is not None or self.failure is not None or self.blocker is not None or self.diagnostic is not None or self.outcome_source is not None or self.sdk_error_category is not None:
                raise CodexWorkerError("Worker result is invalid")


class NativeWorkerTurn(Protocol):
    def identity(self) -> str: ...
    def abort(self) -> None: ...
    def read_response(self) -> NativeWorkerResponse: ...
    def read_step(self) -> NativeWorkerTurnStep: ...
    def submit_tool_result(self, result: NativeWorkerToolResult) -> None: ...


class NativeWorkerSession(Protocol):
    def identity(self) -> str: ...
    def close(self) -> None: ...
    def start_turn(self, request: CodexWorkerRequest, tools: BoundedWorkerToolSurface) -> NativeWorkerTurn: ...


class NativeCodexWorkerBackend(Protocol):
    """SDK-facing seam implemented only by the reviewed native harness."""

    def open_session(self, profile: ProviderProfile, *, resume_session_identity: str | None) -> NativeWorkerSession: ...


class CodexWorkerAdapter:
    """Dispatch one bounded native Worker turn without weakening durable state."""

    def __init__(
        self,
        backend: NativeCodexWorkerBackend,
        profile: ProviderProfile,
        audit: ProviderHealthAuditIdentity,
        tools: BoundedWorkerToolSurface,
    ) -> None:
        if (
            not callable(getattr(backend, "open_session", None))
            or type(profile) is not ProviderProfile
            or type(audit) is not ProviderHealthAuditIdentity
            or type(tools) is not BoundedWorkerToolSurface
            or audit.profile != profile
            or not audit.audit.supports(profile)
        ):
            raise CodexWorkerError("Codex Worker adapter is not bound to its qualified profile")
        self._backend = backend
        self._profile = profile
        self._audit = audit
        self._tools = tools

    @property
    def runtime_identity(self) -> tuple[str, str, str]:
        """Return exact SDK/runtime/profile identities, never ambient versions."""

        return (self._audit.audit.sdk_version, self._audit.audit.runtime_version, self._audit.profile_identity)

    @property
    def profile_identity(self) -> str:
        return self._audit.profile_identity

    @property
    def runtime_fingerprint(self) -> str:
        return self._audit.runtime_fingerprint

    @property
    def capability_contract(self) -> WorkerCapabilityContract:
        return self._tools.capability_contract

    def dispatch(
        self,
        request: CodexWorkerRequest,
        *,
        checkpoint_session: Callable[[str], None],
        checkpoint_turn: Callable[[str, str], None],
        execute_tool_request: Callable[[NativeWorkerToolRequest], NativeWorkerToolResult] | None = None,
    ) -> CodexWorkerResult:
        """Start/resume, checkpoint IDs, then consume exactly one typed result.

        A checkpoint exception intentionally returns an ambiguous result instead
        of reading output, so recovery cannot mistake an unrecorded SDK turn for
        a completed one.
        """

        if type(request) is not CodexWorkerRequest or not callable(checkpoint_session) or not callable(checkpoint_turn):
            raise CodexWorkerError("Worker dispatch is invalid")
        session_identity: str | None = None
        turn_identity: str | None = None
        session: NativeWorkerSession | None = None
        turn: NativeWorkerTurn | None = None
        try:
            session = self._backend.open_session(self._profile, resume_session_identity=request.resume_session_identity)
            session_identity = _identity(session, "session")
            if request.resume_session_identity is not None and session_identity != request.resume_session_identity:
                _close_session(session)
                return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, None, None, None, None)
            checkpoint_session(session_identity)
        except CodexAdapterError:
            _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, None, None, None, None)
        except CodexWorkerError:
            _close_session(session)
            raise
        except Exception:
            _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, None, None, None, None)
        try:
            turn = session.start_turn(request, self._tools)
            turn_identity = _identity(turn, "turn")
            checkpoint_turn(session_identity, turn_identity)
        except CodexAdapterError:
            _abort_turn(turn); _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, turn_identity, None, None, None)
        except CodexWorkerError:
            _abort_turn(turn); _close_session(session)
            raise
        except Exception:
            # No response is read when session/turn creation or durable checkpoint
            # fails.  A caller must recover from the persisted lifecycle state.
            _abort_turn(turn); _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, turn_identity, None, None, None)
        try:
            if execute_tool_request is None:
                response = turn.read_response()
            else:
                response = _consume_steps(turn, execute_tool_request)
        except CodexAdapterError:
            _abort_turn(turn); _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, turn_identity, None, None, None)
        except Exception:
            _abort_turn(turn); _close_session(session)
            return CodexWorkerResult(WorkerResultKind.AMBIGUOUS, session_identity, turn_identity, None, None, None)
        if type(response) is not NativeWorkerResponse:
            return CodexWorkerResult(WorkerResultKind.INVALID, session_identity, turn_identity, None, None, None, diagnostic=WorkerParserDiagnostic.SHAPE)
        if response.kind is WorkerResultKind.ACCEPTED:
            try:
                output = _normalized_output(response.structured_output)
            except CodexWorkerError:
                return CodexWorkerResult(WorkerResultKind.INVALID, session_identity, turn_identity, None, None, None, diagnostic=WorkerParserDiagnostic.SHAPE)
            return CodexWorkerResult(WorkerResultKind.ACCEPTED, session_identity, turn_identity, output, _digest(output), None)
        return CodexWorkerResult(response.kind, session_identity, turn_identity, None, None, response.failure, response.blocker, response.diagnostic, response.outcome_source, response.sdk_error_category)


_MAX_TOOL_STEPS = 32


def _consume_steps(turn: NativeWorkerTurn, execute: Callable[[NativeWorkerToolRequest], NativeWorkerToolResult]) -> NativeWorkerResponse:
    """Consume one exact turn; malformed/uncertain tool exchange is ambiguous."""
    expected = 1
    while expected <= _MAX_TOOL_STEPS:
        step = turn.read_step()
        if step.response is not None:
            return step.response
        request = step.request
        if request is None or request.sequence != expected:
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        result = execute(request)
        if type(result) is not NativeWorkerToolResult or (result.sequence, result.tool) != (request.sequence, request.tool):
            raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)
        turn.submit_tool_result(result)
        expected += 1
    raise CodexAdapterError(CodexFailure.MALFORMED_RESPONSE)


def worker_request_digest(*, attempt_id: str, action: WorkerAction, context: CodexWorkerContext, objective: str, constraints: tuple[str, ...], acceptance_criteria: tuple[str, ...], resume_session_identity: str | None) -> str:
    """Canonical identity for every immutable field of a Worker request."""
    return _digest({"attempt_id": attempt_id, "action": action.value, "context_digest": context.digest, "objective": objective, "constraints": constraints, "acceptance_criteria": acceptance_criteria, "resume_session_identity": resume_session_identity})


def _identity(value: object, name: str) -> str:
    try:
        identity = value.identity()  # type: ignore[union-attr]
    except Exception as error:
        raise CodexWorkerError(f"native Worker {name} identity is unavailable") from error
    if type(identity) is not str or not _TOKEN.fullmatch(identity):
        raise CodexWorkerError(f"native Worker {name} identity is invalid")
    return identity


def _abort_turn(turn: NativeWorkerTurn | None) -> None:
    """Best-effort cleanup only; never read an uncheckpointed response."""
    if turn is not None:
        try: turn.abort()
        except Exception: pass


def _close_session(session: NativeWorkerSession | None) -> None:
    if session is not None:
        try: session.close()
        except Exception: pass


def _text(value: object) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 100_000


def _items(value: object) -> bool:
    return type(value) is tuple and bool(value) and len(value) <= 128 and all(_text(item) for item in value) and len(set(value)) == len(value)


def _normalized_output(value: object) -> dict[str, object]:
    if type(value) is not dict or not value:
        raise CodexWorkerError("Worker structured output is invalid")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise CodexWorkerError("Worker structured output is invalid") from error
    if type(decoded) is not dict or len(encoded) > 1_000_000:
        raise CodexWorkerError("Worker structured output is invalid")
    return decoded


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
