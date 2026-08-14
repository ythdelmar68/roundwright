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
from .provider_health import CodexAdapterError, ProviderHealthAuditIdentity


class CodexSupervisorError(ValueError):
    """Raised when a Supervisor boundary would lose identity or authority."""


class SupervisorVerdict(StrEnum):
    PASS = "pass"
    FINDINGS = "findings"


class SupervisorResultKind(StrEnum):
    ACCEPTED = "accepted"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"


class SupervisorDiagnostic(StrEnum):
    SYNTAX = "syntax"
    SHAPE = "shape"
    CONTEXT = "context"
    CANDIDATE = "candidate"
    NON_FINAL = "non-final"


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

    def __post_init__(self) -> None:
        if not _token(self.review_attempt_id) or not _token(self.provider_attempt_id) or not _token(self.selected_profile_identity) or type(self.within_round_attempt) is not int or self.within_round_attempt < 1 or not _DIGEST.fullmatch(self.input_digest) or type(self.context) is not CodexSupervisorContext or not _text(self.objective) or not _items(self.acceptance_criteria) or self.input_digest != supervisor_request_digest(review_attempt_id=self.review_attempt_id, provider_attempt_id=self.provider_attempt_id, selected_profile_identity=self.selected_profile_identity, within_round_attempt=self.within_round_attempt, context=self.context, objective=self.objective, acceptance_criteria=self.acceptance_criteria):
            raise CodexSupervisorError("Supervisor request is invalid")


@dataclass(frozen=True)
class NativeSupervisorResponse:
    """Normalized native response; raw SDK payloads never cross this seam."""

    kind: SupervisorResultKind
    structured_output: Mapping[str, object] | None = None
    diagnostic: SupervisorDiagnostic | None = None

    def __post_init__(self) -> None:
        accepted = self.kind is SupervisorResultKind.ACCEPTED
        if type(self.kind) is not SupervisorResultKind or (self.structured_output is not None and type(self.structured_output) is not dict) or (self.diagnostic is not None and type(self.diagnostic) is not SupervisorDiagnostic) or (accepted and (self.structured_output is None or self.diagnostic is not None)) or (not accepted and (self.structured_output is not None or (self.kind is SupervisorResultKind.INVALID and self.diagnostic is None) or (self.kind is not SupervisorResultKind.INVALID and self.diagnostic is not None))):
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

    def __post_init__(self) -> None:
        if type(self.kind) is not SupervisorResultKind or (self.session_identity is not None and not _token(self.session_identity)) or (self.turn_identity is not None and not _token(self.turn_identity)) or (self.verdict is not None and type(self.verdict) is not SupervisorVerdict) or any(not _token(item) for item in self.findings) or (self.output_fingerprint is not None and not _DIGEST.fullmatch(self.output_fingerprint)) or (self.diagnostic is not None and type(self.diagnostic) is not SupervisorDiagnostic):
            raise CodexSupervisorError("Supervisor result is invalid")
        if self.kind is SupervisorResultKind.ACCEPTED:
            if self.session_identity is None or self.turn_identity is None or self.verdict is None or self.output_fingerprint is None or self.diagnostic is not None or (self.verdict is SupervisorVerdict.PASS and self.findings) or (self.verdict is SupervisorVerdict.FINDINGS and not self.findings):
                raise CodexSupervisorError("Supervisor result is invalid")
        elif self.verdict is not None or self.findings or self.output_fingerprint is not None or (self.kind is SupervisorResultKind.INVALID and self.diagnostic is None) or (self.kind is not SupervisorResultKind.INVALID and self.diagnostic is not None):
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
            checkpoint_session(session_identity)
            turn = session.start_turn(request)
            turn_identity = _identity(turn, "turn")
            checkpoint_turn(session_identity, turn_identity)
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
            return CodexSupervisorResult(response.kind, session_identity, turn_identity, diagnostic=response.diagnostic)
        try:
            verdict, findings = _output(response.structured_output)
        except CodexSupervisorError:
            return CodexSupervisorResult(SupervisorResultKind.INVALID, session_identity, turn_identity, diagnostic=SupervisorDiagnostic.SHAPE)
        return CodexSupervisorResult(SupervisorResultKind.ACCEPTED, session_identity, turn_identity, verdict, findings, _digest({"verdict": verdict.value, "findings": findings}))


@dataclass(frozen=True)
class SupervisorFailoverResult:
    result: CodexSupervisorResult | None
    attempted_profile_identities: tuple[str, ...]
    exhausted: bool


def dispatch_ordered_supervisor_attempts(requests: tuple[CodexSupervisorRequest, ...], adapters: tuple[CodexSupervisorAdapter, ...], *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None]) -> SupervisorFailoverResult:
    """Try each configured profile once; invalid output consumes no review round.

    The caller retains the review state.  This function intentionally reports
    only availability: it cannot convert a malformed, cancelled, or ambiguous
    result into PASS/FINDINGS, and it never parses provider display prose.
    """
    if type(requests) is not tuple or type(adapters) is not tuple or not requests or len(requests) != len(adapters) or not callable(checkpoint_session) or not callable(checkpoint_turn):
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
        if result.kind is SupervisorResultKind.ACCEPTED:
            return SupervisorFailoverResult(result, tuple(attempted), False)
    return SupervisorFailoverResult(None, tuple(attempted), True)


def supervisor_request_digest(*, review_attempt_id: str, provider_attempt_id: str, selected_profile_identity: str, within_round_attempt: int, context: CodexSupervisorContext, objective: str, acceptance_criteria: tuple[str, ...]) -> str:
    return _digest({"review_attempt_id": review_attempt_id, "provider_attempt_id": provider_attempt_id, "selected_profile_identity": selected_profile_identity, "within_round_attempt": within_round_attempt, "context": {"task_id": context.task_id, "source_digest": context.source_digest, "repository_fingerprint": context.repository_fingerprint, "worktree_fingerprint": context.worktree_fingerprint, "branch_fingerprint": context.branch_fingerprint, "base_sha": context.base_sha, "candidate_sha": context.candidate_sha, "policy_digest": context.policy_digest, "configuration_digest": context.configuration_digest, "review_epoch": context.review_epoch, "review_round": context.review_round, "review_mode": context.review_mode.value}, "objective": objective, "acceptance_criteria": acceptance_criteria})


def _output(value: object) -> tuple[SupervisorVerdict, tuple[str, ...]]:
    if type(value) is not dict or set(value) != {"verdict", "findings"} or type(value["verdict"]) is not str or type(value["findings"]) is not list or any(not _token(item) for item in value["findings"]):
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
