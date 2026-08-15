"""Bounded, read-only Codex Supervisor attempts and ordered failover.

This module deliberately has no SDK import.  The operational harness supplies
the tiny native-session seam; this layer owns the strict, path-free request and
result boundary.  A result is useful only when it is schema-valid and bound to
the exact candidate, review round, and configured profile that dispatched it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .configuration import ProviderProfile, ReviewMode
from .provider_health import CodexAdapterError, CodexFailure, ProviderHealthAuditIdentity
from .provider_recovery import SupervisorAccountingSnapshot, SupervisorDispatchClaimState


class CodexSupervisorError(ValueError):
    """Raised when a Supervisor boundary would lose identity or authority."""


class SupervisorCheckpointStage(StrEnum):
    """Public-safe local checkpoint stages, never provider outcome states."""

    SESSION = "session-checkpoint"
    TURN = "turn-checkpoint"


class CodexSupervisorCheckpointError(CodexSupervisorError):
    """A local durable callback failed after the indicated native identities."""

    def __init__(self, stage: SupervisorCheckpointStage, *, session_present: bool, turn_present: bool) -> None:
        if (
            type(stage) is not SupervisorCheckpointStage
            or type(session_present) is not bool
            or type(turn_present) is not bool
            or (stage is SupervisorCheckpointStage.SESSION and (not session_present or turn_present))
            or (stage is SupervisorCheckpointStage.TURN and (not session_present or not turn_present))
        ):
            raise CodexSupervisorError("Supervisor checkpoint classification is invalid")
        self.stage = stage
        self.session_present = session_present
        self.turn_present = turn_present
        super().__init__(
            f"local {stage.value} failed; session-present={str(session_present).lower()}; "
            f"turn-present={str(turn_present).lower()}"
        )


class _CandidateBindingDrift(CodexSupervisorError):
    """A schema-valid native result is bound to a different candidate."""


class SupervisorVerdict(StrEnum):
    PASS = "pass"
    FINDINGS = "findings"


class SupervisorResultKind(StrEnum):
    ACCEPTED = "accepted"
    BLOCKED = "blocked"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"


class SupervisorResponseContract(StrEnum):
    """Closed output contracts selected by the product-owned request."""

    VERDICT = "verdict-findings/v1"
    PROVIDER_ATTEMPT_ACCOUNTING = "provider-attempt-accounting/v1"


class SupervisorAccountingBlocker(StrEnum):
    """Public-safe terminal conclusion for the accounting-only contract."""

    INCOMPLETE_ACCOUNTING = "provider-accounting-incomplete"


class SupervisorAccountingDecisionSemantic(StrEnum):
    """Versioned prospective transition meaning for accounting responses."""

    PRE_DISPATCH_ELIGIBILITY_V2 = "pre-dispatch-transition-eligibility/v2"


ACCOUNTING_TRANSITION_OBJECTIVE = "Decide only whether this sealed accounting transition is eligible to record this one response."
ACCOUNTING_TRANSITION_CRITERIA = (
    "Require the current PREPARED attempt's one-shot dispatch claim to be consumed; its absent session, turn, completion, invalid, recovery, and acceptance fields remain expected pre-turn facts.",
    "Require accepted formal-review count zero before this response; complete authorizes this response to create exactly one completion and one accepted formal review after binding validation.",
    "Return blocked only when immutable eligibility facts are missing, contradictory, drifted, or insufficient; do not inspect a repository or assess broad candidate correctness.",
)


class SupervisorDiagnostic(StrEnum):
    SYNTAX = "syntax"
    SHAPE = "shape"
    CONTEXT = "context"
    CANDIDATE = "candidate"
    NON_FINAL = "non-final"


class SupervisorOutcomeSource(StrEnum):
    SDK_TURN_FAILED = "sdk-turn-failed"


class SupervisorSdkTurnErrorCategory(StrEnum):
    BAD_REQUEST = "bad-request"
    UNAUTHORIZED = "unauthorized"
    SANDBOX = "sandbox"
    OVERLOAD = "overload"
    HTTP = "http"
    STREAM = "stream"
    CONNECTION = "connection"
    MISSING_OR_UNKNOWN = "missing-or-unknown"


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _token(value: object) -> bool:
    return type(value) is str and bool(_TOKEN.fullmatch(value))


@dataclass(frozen=True)
class CodexSupervisorContext:
    """Immutable public-safe identity supplied to a single review attempt."""

    task_id: str
    source_digest: str
    repository_fingerprint: str
    worktree_fingerprint: str
    branch_fingerprint: str
    base_sha: str
    candidate_sha: str
    policy_digest: str
    configuration_digest: str
    review_epoch: int
    review_round: int
    review_mode: ReviewMode

    def __post_init__(self) -> None:
        if not _token(self.task_id) or not _SHA.fullmatch(self.base_sha) or not _SHA.fullmatch(self.candidate_sha) or type(self.review_epoch) is not int or self.review_epoch < 0 or type(self.review_round) is not int or self.review_round < 1 or type(self.review_mode) is not ReviewMode or not all(_DIGEST.fullmatch(item) for item in (self.source_digest, self.repository_fingerprint, self.worktree_fingerprint, self.branch_fingerprint, self.policy_digest, self.configuration_digest)):
            raise CodexSupervisorError("Supervisor context is invalid")


@dataclass(frozen=True)
class CodexSupervisorRequest:
    """A fresh review request.  Supervisor sessions are never resumed."""

    review_attempt_id: str
    provider_attempt_id: str
    selected_profile_identity: str
    within_round_attempt: int
    input_digest: str
    context: CodexSupervisorContext
    objective: str
    acceptance_criteria: tuple[str, ...]
    response_contract: SupervisorResponseContract = SupervisorResponseContract.VERDICT
    decision_material: SupervisorAccountingSnapshot | None = None
    decision_semantic: SupervisorAccountingDecisionSemantic | None = None

    def __post_init__(self) -> None:
        if not _token(self.review_attempt_id) or not _token(self.provider_attempt_id) or not _token(self.selected_profile_identity) or type(self.within_round_attempt) is not int or self.within_round_attempt < 1 or not _DIGEST.fullmatch(self.input_digest) or type(self.context) is not CodexSupervisorContext or not _text(self.objective) or not _items(self.acceptance_criteria) or type(self.response_contract) is not SupervisorResponseContract or (self.response_contract is SupervisorResponseContract.VERDICT and (self.decision_material is not None or self.decision_semantic is not None)) or (self.response_contract is SupervisorResponseContract.PROVIDER_ATTEMPT_ACCOUNTING and (not _accounting_material(self.decision_material) or self.decision_material.dispatch_claim is not SupervisorDispatchClaimState.CLAIMED or self.decision_semantic is not SupervisorAccountingDecisionSemantic.PRE_DISPATCH_ELIGIBILITY_V2 or self.objective != ACCOUNTING_TRANSITION_OBJECTIVE or self.acceptance_criteria != ACCOUNTING_TRANSITION_CRITERIA)) or self.input_digest != supervisor_request_digest(review_attempt_id=self.review_attempt_id, provider_attempt_id=self.provider_attempt_id, selected_profile_identity=self.selected_profile_identity, within_round_attempt=self.within_round_attempt, context=self.context, objective=self.objective, acceptance_criteria=self.acceptance_criteria, response_contract=self.response_contract, decision_material=self.decision_material, decision_semantic=self.decision_semantic):
            raise CodexSupervisorError("Supervisor request is invalid")


@dataclass(frozen=True)
class NativeSupervisorResponse:
    """Normalized native response; raw SDK payloads never cross this seam."""

    kind: SupervisorResultKind
    structured_output: Mapping[str, object] | None = None
    diagnostic: SupervisorDiagnostic | None = None
    failure: CodexFailure | None = None
    outcome_source: SupervisorOutcomeSource | None = None
    sdk_error_category: SupervisorSdkTurnErrorCategory | None = None

    def __post_init__(self) -> None:
        accepted = self.kind is SupervisorResultKind.ACCEPTED
        blocked = self.kind is SupervisorResultKind.BLOCKED
        if type(self.kind) is not SupervisorResultKind or (self.structured_output is not None and type(self.structured_output) is not dict) or (self.diagnostic is not None and type(self.diagnostic) is not SupervisorDiagnostic) or (self.failure is not None and type(self.failure) is not CodexFailure) or (self.outcome_source is not None and type(self.outcome_source) is not SupervisorOutcomeSource) or (self.sdk_error_category is not None and type(self.sdk_error_category) is not SupervisorSdkTurnErrorCategory) or (accepted and (self.structured_output is None or self.diagnostic is not None or self.failure is not None)) or (blocked and (self.structured_output is not None or self.diagnostic is not None or self.failure is None or self.outcome_source is None or self.sdk_error_category is None)) or (not accepted and not blocked and (self.structured_output is not None or self.failure is not None or self.outcome_source is not None or self.sdk_error_category is not None or (self.kind is SupervisorResultKind.INVALID and self.diagnostic is None) or (self.kind is not SupervisorResultKind.INVALID and self.diagnostic is not None))):
            raise CodexSupervisorError("native Supervisor response is invalid")


@dataclass(frozen=True)
class CodexSupervisorResult:
    kind: SupervisorResultKind
    session_identity: str | None
    turn_identity: str | None
    verdict: SupervisorVerdict | None = None
    findings: tuple[str, ...] = ()
    output_fingerprint: str | None = None
    diagnostic: SupervisorDiagnostic | None = None
    failure: CodexFailure | None = None
    outcome_source: SupervisorOutcomeSource | None = None
    sdk_error_category: SupervisorSdkTurnErrorCategory | None = None
    terminal_blocker: SupervisorAccountingBlocker | None = None

    def __post_init__(self) -> None:
        blocked = self.kind is SupervisorResultKind.BLOCKED
        if type(self.kind) is not SupervisorResultKind or (self.session_identity is not None and not _token(self.session_identity)) or (self.turn_identity is not None and not _token(self.turn_identity)) or (self.verdict is not None and type(self.verdict) is not SupervisorVerdict) or any(not _token(item) for item in self.findings) or (self.output_fingerprint is not None and not _DIGEST.fullmatch(self.output_fingerprint)) or (self.diagnostic is not None and type(self.diagnostic) is not SupervisorDiagnostic) or (self.failure is not None and type(self.failure) is not CodexFailure) or (self.outcome_source is not None and type(self.outcome_source) is not SupervisorOutcomeSource) or (self.sdk_error_category is not None and type(self.sdk_error_category) is not SupervisorSdkTurnErrorCategory) or (self.terminal_blocker is not None and type(self.terminal_blocker) is not SupervisorAccountingBlocker):
            raise CodexSupervisorError("Supervisor result is invalid")
        if self.kind is SupervisorResultKind.ACCEPTED:
            if self.session_identity is None or self.turn_identity is None or self.verdict is None or self.output_fingerprint is None or self.diagnostic is not None or (self.verdict is SupervisorVerdict.PASS and self.findings) or (self.verdict is SupervisorVerdict.FINDINGS and not self.findings):
                raise CodexSupervisorError("Supervisor result is invalid")
        elif blocked:
            if self.session_identity is None or self.turn_identity is None or self.verdict is not None or self.findings or self.output_fingerprint is not None or self.diagnostic is not None or self.failure is None or self.outcome_source is None or self.sdk_error_category is None:
                raise CodexSupervisorError("Supervisor result is invalid")
        elif self.kind is SupervisorResultKind.INCOMPLETE:
            if self.session_identity is None or self.turn_identity is None or self.verdict is not None or self.findings or self.output_fingerprint is not None or self.failure is not None or self.outcome_source is not None or self.sdk_error_category is not None or self.diagnostic is not None:
                raise CodexSupervisorError("Supervisor result is invalid")
        elif self.verdict is not None or self.findings or self.output_fingerprint is not None or self.failure is not None or self.outcome_source is not None or self.sdk_error_category is not None or self.terminal_blocker is not None or (self.kind is SupervisorResultKind.INVALID and self.diagnostic is None) or (self.kind is not SupervisorResultKind.INVALID and self.diagnostic is not None):
            raise CodexSupervisorError("Supervisor result is invalid")


class NativeSupervisorTurn(Protocol):
    def identity(self) -> str: ...
    def abort(self) -> None: ...
    def read_response(self) -> NativeSupervisorResponse: ...


class NativeSupervisorSession(Protocol):
    def identity(self) -> str: ...
    def close(self) -> None: ...
    def start_turn(self, request: CodexSupervisorRequest) -> NativeSupervisorTurn: ...


class NativeCodexSupervisorBackend(Protocol):
    def open_fresh_session(self, profile: ProviderProfile) -> NativeSupervisorSession: ...


class CodexSupervisorAdapter:
    """One fresh, deny-all/read-only Supervisor attempt for one profile."""

    def __init__(self, backend: NativeCodexSupervisorBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity) -> None:
        if not callable(getattr(backend, "open_fresh_session", None)) or type(profile) is not ProviderProfile or type(audit) is not ProviderHealthAuditIdentity or audit.profile != profile or not audit.audit.supports(profile):
            raise CodexSupervisorError("Codex Supervisor adapter is not bound to its qualified profile")
        self._backend, self._profile, self._audit = backend, profile, audit

    @property
    def profile_identity(self) -> str:
        return self._audit.profile_identity

    @property
    def runtime_fingerprint(self) -> str:
        return self._audit.runtime_fingerprint

    def dispatch(self, request: CodexSupervisorRequest, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> CodexSupervisorResult:
        if type(request) is not CodexSupervisorRequest or request.selected_profile_identity != self.profile_identity or not callable(checkpoint_session) or not callable(checkpoint_turn):
            raise CodexSupervisorError("Supervisor dispatch is invalid")
        session: NativeSupervisorSession | None = None
        turn: NativeSupervisorTurn | None = None
        session_identity: str | None = None
        turn_identity: str | None = None
        try:
            session = self._backend.open_fresh_session(self._profile)
            session_identity = _identity(session, "session")
            try:
                checkpoint_session(session_identity)
            except Exception:
                raise CodexSupervisorCheckpointError(
                    SupervisorCheckpointStage.SESSION, session_present=True, turn_present=False,
                ) from None
            turn = session.start_turn(request)
            turn_identity = _identity(turn, "turn")
            try:
                checkpoint_turn(session_identity, turn_identity)
            except Exception:
                raise CodexSupervisorCheckpointError(
                    SupervisorCheckpointStage.TURN, session_present=True, turn_present=True,
                ) from None
            response = turn.read_response()
        except CodexSupervisorError:
            _abort(turn); _close(session)
            raise
        except (CodexAdapterError, Exception):
            _abort(turn); _close(session)
            return CodexSupervisorResult(SupervisorResultKind.AMBIGUOUS, session_identity, turn_identity)
        finally:
            _close(session)
        if type(response) is not NativeSupervisorResponse:
            return CodexSupervisorResult(SupervisorResultKind.INVALID, session_identity, turn_identity, diagnostic=SupervisorDiagnostic.SHAPE)
        if response.kind is not SupervisorResultKind.ACCEPTED:
            return CodexSupervisorResult(response.kind, session_identity, turn_identity, diagnostic=response.diagnostic, failure=response.failure, outcome_source=response.outcome_source, sdk_error_category=response.sdk_error_category)
        try:
            if request.response_contract is SupervisorResponseContract.PROVIDER_ATTEMPT_ACCOUNTING:
                complete, blocker = _accounting_output(response.structured_output)
                if not complete:
                    return CodexSupervisorResult(SupervisorResultKind.INCOMPLETE, session_identity, turn_identity, terminal_blocker=blocker)
                verdict, findings = SupervisorVerdict.PASS, ()
            else:
                verdict, findings = _output(response.structured_output, request)
        except _CandidateBindingDrift:
            return CodexSupervisorResult(SupervisorResultKind.INVALID, session_identity, turn_identity, diagnostic=SupervisorDiagnostic.CANDIDATE)
        except CodexSupervisorError:
            return CodexSupervisorResult(SupervisorResultKind.INVALID, session_identity, turn_identity, diagnostic=SupervisorDiagnostic.SHAPE)
        # The native schema intentionally contains no ambient context.  Bind
        # its parsed verdict to the persisted request here, so identical prose
        # cannot be replayed across attempts, profiles, rounds, or candidates.
        return CodexSupervisorResult(SupervisorResultKind.ACCEPTED, session_identity, turn_identity, verdict, findings, _digest({"input_digest": request.input_digest, "profile_identity": request.selected_profile_identity, "within_round_attempt": request.within_round_attempt, "candidate_sha": request.context.candidate_sha, "review_epoch": request.context.review_epoch, "review_round": request.context.review_round, "review_mode": request.context.review_mode.value, "verdict": verdict.value, "findings": findings}))


@dataclass(frozen=True)
class SupervisorFailoverResult:
    result: CodexSupervisorResult | None
    attempted_profile_identities: tuple[str, ...]
    exhausted: bool


def dispatch_ordered_supervisor_attempts(requests: tuple[CodexSupervisorRequest, ...], adapters: tuple[CodexSupervisorAdapter, ...], *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None], checkpoint_result: Callable[[int, CodexSupervisorRequest, CodexSupervisorResult], None] | None = None) -> SupervisorFailoverResult:
    """Run a bounded configured sequence without retrying uncertain outcomes.

    Only a typed invalid result or a verified terminal provider failure can
    advance to the next pre-bound profile.  Ambiguous and incomplete outcomes
    remain terminal: dispatching a fallback would turn an uncertain external
    result into an unbounded second provider action.
    """
    if type(requests) is not tuple or type(adapters) is not tuple or not requests or len(requests) != len(adapters) or not callable(checkpoint_session) or not callable(checkpoint_turn) or (checkpoint_result is not None and not callable(checkpoint_result)):
        raise CodexSupervisorError("Supervisor failover inputs are invalid")
    seen: set[str] = set()
    attempted: list[str] = []
    first = requests[0].context
    for ordinal, (request, adapter) in enumerate(zip(requests, adapters), start=1):
        if type(request) is not CodexSupervisorRequest or type(adapter) is not CodexSupervisorAdapter or request.within_round_attempt != ordinal or request.selected_profile_identity != adapter.profile_identity or request.selected_profile_identity in seen or request.context != first:
            raise CodexSupervisorError("Supervisor failover profile mapping is invalid")
        seen.add(request.selected_profile_identity)
        attempted.append(request.selected_profile_identity)
        result = adapter.dispatch(request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)
        if checkpoint_result is not None:
            checkpoint_result(ordinal, request, result)
        if result.kind is SupervisorResultKind.ACCEPTED:
            return SupervisorFailoverResult(result, tuple(attempted), False)
        if result.kind not in (SupervisorResultKind.INVALID, SupervisorResultKind.BLOCKED):
            return SupervisorFailoverResult(result, tuple(attempted), False)
    return SupervisorFailoverResult(None, tuple(attempted), True)


def supervisor_request_digest(*, review_attempt_id: str, provider_attempt_id: str, selected_profile_identity: str, within_round_attempt: int, context: CodexSupervisorContext, objective: str, acceptance_criteria: tuple[str, ...], response_contract: SupervisorResponseContract = SupervisorResponseContract.VERDICT, decision_material: SupervisorAccountingSnapshot | None = None, decision_semantic: SupervisorAccountingDecisionSemantic | None = None) -> str:
    value: dict[str, object] = {"review_attempt_id": review_attempt_id, "provider_attempt_id": provider_attempt_id, "selected_profile_identity": selected_profile_identity, "within_round_attempt": within_round_attempt, "context": {"task_id": context.task_id, "source_digest": context.source_digest, "repository_fingerprint": context.repository_fingerprint, "worktree_fingerprint": context.worktree_fingerprint, "branch_fingerprint": context.branch_fingerprint, "base_sha": context.base_sha, "candidate_sha": context.candidate_sha, "policy_digest": context.policy_digest, "configuration_digest": context.configuration_digest, "review_epoch": context.review_epoch, "review_round": context.review_round, "review_mode": context.review_mode.value}, "objective": objective, "acceptance_criteria": acceptance_criteria}
    if response_contract is not SupervisorResponseContract.VERDICT:
        value["response_contract"] = response_contract.value
        value["decision_material"] = decision_material.canonical_material() if type(decision_material) is SupervisorAccountingSnapshot else decision_material
        value["decision_semantic"] = None if decision_semantic is None else decision_semantic.value
    return _digest(value)


def canonical_supervisor_review_material(request: CodexSupervisorRequest) -> dict[str, object]:
    if request.response_contract is SupervisorResponseContract.PROVIDER_ATTEMPT_ACCOUNTING:
        return {"schema": "roundwright-provider-attempt-accounting-material/v2", "input_digest": request.input_digest, "candidate_sha": request.context.candidate_sha, "within_round_attempt": request.within_round_attempt, "profile_identity": request.selected_profile_identity, "review_epoch": request.context.review_epoch, "review_round": request.context.review_round, "review_mode": request.context.review_mode.value, "objective": request.objective, "acceptance_criteria": list(request.acceptance_criteria), "decision_semantic": request.decision_semantic.value, "decision_rule": "pre-dispatch eligibility: complete authorizes this exact response to create one completion and accepted formal review; it does not assert either already exists", "decision_material": request.decision_material.canonical_material()}
    return {"schema": "roundwright-supervisor-review-material/v1", "input_digest": request.input_digest, "candidate_sha": request.context.candidate_sha, "within_round_attempt": request.within_round_attempt, "profile_identity": request.selected_profile_identity, "review_epoch": request.context.review_epoch, "review_round": request.context.review_round, "review_mode": request.context.review_mode.value, "objective": request.objective, "acceptance_criteria": list(request.acceptance_criteria)}


def _accounting_material(value: object) -> bool:
    return type(value) is SupervisorAccountingSnapshot


def _accounting_output(value: object) -> tuple[bool, SupervisorAccountingBlocker | None]:
    if type(value) is not dict or set(value) != {"status", "action", "blocker"}:
        raise CodexSupervisorError("Supervisor accounting output is malformed")
    if value == {"status": "complete", "action": "accept-formal-review", "blocker": None}:
        return True, None
    if value == {"status": "blocked", "action": "retain-terminal-product-block", "blocker": SupervisorAccountingBlocker.INCOMPLETE_ACCOUNTING.value}:
        return False, SupervisorAccountingBlocker.INCOMPLETE_ACCOUNTING
    raise CodexSupervisorError("Supervisor accounting output is malformed")


def _output(value: object, request: CodexSupervisorRequest) -> tuple[SupervisorVerdict, tuple[str, ...]]:
    binding = {"input_digest": request.input_digest, "candidate_sha": request.context.candidate_sha, "within_round_attempt": request.within_round_attempt, "profile_identity": request.selected_profile_identity}
    if type(value) is dict and set(value) == {"verdict", "findings", "binding"} and type(value.get("binding")) is dict and set(value["binding"]) == set(binding) and value["binding"].get("candidate_sha") != binding["candidate_sha"]:
        raise _CandidateBindingDrift("Supervisor output candidate has drifted")
    if type(value) is not dict or set(value) != {"verdict", "findings", "binding"} or type(value["verdict"]) is not str or type(value["findings"]) is not list or any(not _token(item) for item in value["findings"]) or value["binding"] != binding:
        raise CodexSupervisorError("Supervisor output is malformed")
    try:
        verdict = SupervisorVerdict(value["verdict"])
    except ValueError as error:
        raise CodexSupervisorError("Supervisor output is malformed") from error
    findings = tuple(value["findings"])
    if (verdict is SupervisorVerdict.PASS and findings) or (verdict is SupervisorVerdict.FINDINGS and not findings):
        raise CodexSupervisorError("Supervisor output is malformed")
    return verdict, findings


def _identity(value: object, name: str) -> str:
    identity = getattr(value, "identity", None)
    result = identity() if callable(identity) else None
    if not _token(result):
        raise CodexSupervisorError(f"Supervisor {name} identity is invalid")
    return result


def _abort(turn: NativeSupervisorTurn | None) -> None:
    if turn is not None:
        try: turn.abort()
        except Exception: pass


def _close(session: NativeSupervisorSession | None) -> None:
    if session is not None:
        try: session.close()
        except Exception: pass


def _text(value: object) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 4000


def _items(value: object) -> bool:
    return type(value) is tuple and bool(value) and all(_text(item) for item in value)
