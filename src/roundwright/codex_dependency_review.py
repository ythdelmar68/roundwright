"""Fresh, deny-all Codex adapter for one dependency-review attempt.

The model-facing request contains only the normalized, digest-only subset from
``dependency_review``.  This adapter owns no repository, GitHub, scheduler,
or credential capability and deliberately has no session-resume API.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .configuration import ProviderProfile, RepositoryIdentity
from .dependency_review import (
    AffectedSubset, DependencyProposal, DependencyReviewBinding,
    DependencyReviewError, DependencyReviewStore, SourceOwnedRelation,
)
from .provider_health import CodexAdapterError, CodexFailure, ProviderHealthAuditIdentity


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class DependencyReviewDispatchError(ValueError):
    """A dependency-review dispatch violates the narrow role contract."""


class DependencyReviewResultKind(StrEnum):
    ACCEPTED = "accepted"
    INVALID = "invalid"
    BLOCKED = "blocked"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class DependencyReviewRequest:
    """One immutable, fresh-session request with no tool surface."""

    attempt_id: str
    input_material: Mapping[str, object]
    input_digest: str
    profile_identity: str

    def __post_init__(self) -> None:
        if (
            not _TOKEN.fullmatch(self.attempt_id)
            or type(self.input_material) is not dict
            or not _DIGEST.fullmatch(self.input_digest)
            or not _DIGEST.fullmatch(self.profile_identity)
            or self.input_digest != _digest(self.input_material)
        ):
            raise DependencyReviewDispatchError("dependency review request is invalid")


@dataclass(frozen=True)
class NativeDependencyReviewResponse:
    kind: DependencyReviewResultKind
    proposal: Mapping[str, object] | None = None
    failure: CodexFailure | None = None

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not DependencyReviewResultKind
            or (self.proposal is not None and type(self.proposal) is not dict)
            or (self.failure is not None and type(self.failure) is not CodexFailure)
            or (self.kind is DependencyReviewResultKind.ACCEPTED and (self.proposal is None or self.failure is not None))
            or (self.kind is DependencyReviewResultKind.BLOCKED and (self.proposal is not None or self.failure is None))
            or (self.kind in {DependencyReviewResultKind.INVALID, DependencyReviewResultKind.AMBIGUOUS} and (self.proposal is not None or self.failure is not None))
        ):
            raise DependencyReviewDispatchError("dependency review response is invalid")


class NativeDependencyReviewTurn(Protocol):
    def identity(self) -> str: ...
    def abort(self) -> None: ...
    def read_response(self) -> NativeDependencyReviewResponse: ...


class NativeDependencyReviewSession(Protocol):
    def identity(self) -> str: ...
    def close(self) -> None: ...
    def start_turn(self, request: DependencyReviewRequest) -> NativeDependencyReviewTurn: ...


class NativeCodexDependencyReviewBackend(Protocol):
    def open_fresh_session(self, profile: ProviderProfile) -> NativeDependencyReviewSession: ...


@dataclass(frozen=True)
class DependencyReviewDispatchResult:
    kind: DependencyReviewResultKind
    session_identity: str | None
    turn_identity: str | None
    proposal: DependencyProposal | None
    output_digest: str
    reason_code: str

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not DependencyReviewResultKind
            or (self.session_identity is not None and not _TOKEN.fullmatch(self.session_identity))
            or (self.turn_identity is not None and not _TOKEN.fullmatch(self.turn_identity))
            or (self.proposal is not None and type(self.proposal) is not DependencyProposal)
            or not _DIGEST.fullmatch(self.output_digest)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.reason_code)
            or (self.kind is DependencyReviewResultKind.ACCEPTED) != (self.proposal is not None)
        ):
            raise DependencyReviewDispatchError("dependency review result is invalid")


class CodexDependencyReviewAdapter:
    """Open exactly one fresh, no-tools session for the configured role."""

    def __init__(self, backend: NativeCodexDependencyReviewBackend, profile: ProviderProfile, audit: ProviderHealthAuditIdentity) -> None:
        if (
            not callable(getattr(backend, "open_fresh_session", None))
            or type(profile) is not ProviderProfile
            or type(audit) is not ProviderHealthAuditIdentity
            or audit.profile != profile
            or not audit.audit.supports(profile)
        ):
            raise DependencyReviewDispatchError("dependency review adapter is not bound to its qualified profile")
        self._backend, self._profile, self._audit = backend, profile, audit

    @property
    def profile_identity(self) -> str:
        return self._audit.profile_identity

    def dispatch(
        self, request: DependencyReviewRequest, *, checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None],
    ) -> DependencyReviewDispatchResult:
        if type(request) is not DependencyReviewRequest or request.profile_identity != self.profile_identity or not callable(checkpoint_session) or not callable(checkpoint_turn):
            raise DependencyReviewDispatchError("dependency review dispatch is invalid")
        session = None
        turn = None
        session_id = None
        turn_id = None
        try:
            session = self._backend.open_fresh_session(self._profile)
            session_id = _identity(session, "session")
            checkpoint_session(session_id)
            turn = session.start_turn(request)
            turn_id = _identity(turn, "turn")
            checkpoint_turn(session_id, turn_id)
            response = turn.read_response()
        except (CodexAdapterError, Exception):
            _abort(turn)
            return DependencyReviewDispatchResult(DependencyReviewResultKind.AMBIGUOUS, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "session": session_id, "turn": turn_id, "status": "ambiguous"}), "uncertain-provider-turn")
        finally:
            _close(session)
        if type(response) is not NativeDependencyReviewResponse:
            return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "status": "malformed-response"}), "malformed-response")
        if response.kind is DependencyReviewResultKind.ACCEPTED:
            try:
                proposal = DependencyProposal.parse(response.proposal)
                if proposal.attempt_id != request.attempt_id:
                    raise DependencyReviewError
            except (DependencyReviewError, TypeError, ValueError):
                return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, session_id, turn_id, None, _digest(response.proposal), "malformed-response")
            return DependencyReviewDispatchResult(response.kind, session_id, turn_id, proposal, proposal.proposal_digest, "schema-valid")
        reason = "provider-blocked" if response.kind is DependencyReviewResultKind.BLOCKED else "malformed-response"
        return DependencyReviewDispatchResult(response.kind, session_id, turn_id, None, _digest({"attempt_id": request.attempt_id, "status": response.kind.value, "failure": None if response.failure is None else response.failure.value}), reason)


class DependencyReviewService:
    """Persist one new attempt before dispatch and retain every terminal outcome."""

    def run(
        self, repository: RepositoryIdentity, subset: AffectedSubset, *, attempt_id: str,
        binding: DependencyReviewBinding, adapter: CodexDependencyReviewAdapter,
        checkpoint_session: Callable[[str], None], checkpoint_turn: Callable[[str, str], None],
        source_owned_relations: tuple[SourceOwnedRelation, ...] = (), supersedes_attempt_id: str | None = None,
    ) -> DependencyReviewDispatchResult:
        if type(adapter) is not CodexDependencyReviewAdapter or adapter.profile_identity != binding.profile_identity:
            raise DependencyReviewDispatchError("dependency review adapter profile has drifted")
        store = DependencyReviewStore()
        attempt = store.start_attempt(repository, subset, attempt_id=attempt_id, binding=binding, source_owned_relations=source_owned_relations, supersedes_attempt_id=supersedes_attempt_id)
        request = DependencyReviewRequest(attempt.attempt_id, store.model_input(subset, attempt_id=attempt.attempt_id, profile_identity=binding.profile_identity, source_owned_relations=source_owned_relations), attempt.input_digest, binding.profile_identity)
        result = adapter.dispatch(request, checkpoint_session=checkpoint_session, checkpoint_turn=checkpoint_turn)
        if result.kind is DependencyReviewResultKind.ACCEPTED:
            assert result.proposal is not None
            try:
                store.accept_proposal(repository, result.proposal, binding=binding)
            except DependencyReviewError:
                store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code="proposal-rejected")
                return DependencyReviewDispatchResult(DependencyReviewResultKind.INVALID, result.session_identity, result.turn_identity, None, result.output_digest, "proposal-rejected")
        elif result.kind is DependencyReviewResultKind.AMBIGUOUS:
            store.record_blocked(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code=result.reason_code)
        else:
            store.record_invalid(repository, attempt_id=attempt.attempt_id, output_digest=result.output_digest, reason_code=result.reason_code)
        return result


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _identity(value: object, name: str) -> str:
    identity = getattr(value, "identity", None)
    result = identity() if callable(identity) else None
    if not _TOKEN.fullmatch(result or ""):
        raise DependencyReviewDispatchError(f"dependency review {name} identity is invalid")
    return result


def _abort(turn: object) -> None:
    try:
        if turn is not None:
            turn.abort()
    except Exception:
        pass


def _close(session: object) -> None:
    try:
        if session is not None:
            session.close()
    except Exception:
        pass
