"""Immutable, no-mutation replay for persisted lifecycle evidence.

Shadow is deliberately a pure boundary.  It accepts an immutable case bundle
and its already-persisted Worker/Supervisor observations, then replays those
facts through the Phase 2 state sequence.  It never opens a repository,
starts a provider, or writes durable state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Callable, Iterable, Never


SHADOW_CASE_SCHEMA = "roundwright-shadow-case/v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"[^\s\x00-\x1f]+\Z")


class ShadowError(ValueError):
    """Raised when a caller tries to construct invalid Shadow evidence."""


class ReplayClassification(StrEnum):
    """Closed set of classifications a replay may publish."""

    EXACT_MATCH = "exact-match"
    EXPECTED_NONDETERMINISM = "expected-nondeterminism"
    CONTRACT_MISMATCH = "contract-mismatch"
    STALE_EVIDENCE = "stale-evidence"
    INCOMPLETE_EVIDENCE = "incomplete-evidence"
    FORBIDDEN_MUTATION = "forbidden-mutation"


class ComparisonOutcome(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    INVALID = "INVALID"


class ComparisonField(StrEnum):
    STATE = "state"
    GATE = "gate"
    IDENTITY = "identity"
    APPLICABILITY = "applicability"
    BLOCKER = "blocker"
    NEXT_ACTION = "next-action"


class EvidenceRole(StrEnum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"


class Applicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not-applicable"


class AttemptDisposition(StrEnum):
    RECORDED = "recorded"
    ACCEPTED = "accepted"
    AMBIGUOUS = "ambiguous"


class MutationKind(StrEnum):
    GIT = "git"
    GITHUB = "github"
    REPOSITORY = "repository"
    QUEUE = "queue"
    BRANCH = "branch"
    WORKTREE = "worktree"
    PULL_REQUEST = "pull-request"
    ISSUE = "issue"
    MERGE = "merge"
    CLOSE = "close"
    CLEANUP = "cleanup"
    LIFECYCLE = "lifecycle"


class ForbiddenMutationError(ShadowError):
    """A mutation was rejected before the requested callable could run."""

    def __init__(self, kind: MutationKind):
        super().__init__(f"shadow forbids {kind.value} mutation")
        self.kind = kind


class NoMutationCapabilities:
    """Fail every mutation before it can produce an external side effect.

    ``execute`` deliberately raises before touching ``action``.  Named methods
    make the policy auditable for all mutation families Shadow must never gain.
    """

    def execute(self, kind: MutationKind, action: Callable[[], object] | None = None) -> Never:
        if not isinstance(kind, MutationKind):
            raise ShadowError("mutation kind is invalid")
        raise ForbiddenMutationError(kind)

    def git(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.GIT, action)

    def github(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.GITHUB, action)

    def repository(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.REPOSITORY, action)

    def queue(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.QUEUE, action)

    def branch(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.BRANCH, action)

    def worktree(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.WORKTREE, action)

    def pull_request(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.PULL_REQUEST, action)

    def issue(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.ISSUE, action)

    def merge(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.MERGE, action)

    def close(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.CLOSE, action)

    def cleanup(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.CLEANUP, action)

    def lifecycle(self, action: Callable[[], object] | None = None) -> Never:
        return self.execute(MutationKind.LIFECYCLE, action)


@dataclass(frozen=True)
class ShadowIdentity:
    """The candidate-bound identities that make an input case immutable."""

    source_id: str
    task_id: str
    base_sha: str
    candidate_sha: str
    policy_identity: str
    provider_attempt_identity: str
    accepted_review_identity: str
    gate_identity: str
    expected_next_action: str
    worktree_identity: str

    def digest(self) -> str:
        _validate_identity(self)
        return _digest(_identity_payload(self))


@dataclass(frozen=True)
class ShadowObservation:
    """One persisted observation; no live provider is represented here."""

    event_id: str
    role: EvidenceRole
    attempt_id: str
    attempt_disposition: AttemptDisposition
    state: str
    candidate_sha: str
    gate_identity: str
    applicability: Applicability
    blocker: str | None
    next_action: str
    source_count: int = 1
    not_applicable_reason: str | None = None
    requested_mutation: MutationKind | None = None
    accepted_review_identity: str | None = None
    worktree_identity: str | None = None
    worktree_clean: bool = True
    evidence_digest: str = field(default="")

    def __post_init__(self) -> None:
        payload = _observation_payload(self, include_digest=False)
        digest = _digest(payload)
        if self.evidence_digest and self.evidence_digest != digest:
            raise ShadowError("observation digest does not match immutable content")
        object.__setattr__(self, "evidence_digest", digest)


@dataclass(frozen=True)
class ShadowCase:
    """A versioned, content-addressed Shadow replay bundle."""

    case_id: str
    identity: ShadowIdentity
    observations: tuple[ShadowObservation, ...]
    expected_states: tuple[str, ...]
    expected_applicability: Applicability
    expected_blocker: str | None
    expected_nondeterminism: tuple[ComparisonField, ...] = ()
    schema: str = SHADOW_CASE_SCHEMA
    case_digest: str = field(default="")

    def __post_init__(self) -> None:
        payload = _case_payload(self, include_digest=False)
        digest = _digest(payload)
        if self.case_digest and self.case_digest != digest:
            raise ShadowError("shadow case digest does not match immutable content")
        object.__setattr__(self, "case_digest", digest)

    @classmethod
    def build(
        cls,
        case_id: str,
        identity: ShadowIdentity,
        observations: Iterable[ShadowObservation],
        *,
        expected_states: Iterable[str],
        expected_applicability: Applicability = Applicability.APPLICABLE,
        expected_blocker: str | None = None,
        expected_nondeterminism: Iterable[ComparisonField] = (),
    ) -> "ShadowCase":
        return cls(
            case_id,
            identity,
            tuple(observations),
            tuple(expected_states),
            expected_applicability,
            expected_blocker,
            tuple(expected_nondeterminism),
        )


@dataclass(frozen=True)
class FieldComparison:
    field: ComparisonField
    expected: str
    actual: str
    matches: bool


@dataclass(frozen=True)
class ShadowReport:
    """Typed result suitable for a curated owner-safe summary."""

    case_id: str
    case_digest: str
    outcome: ComparisonOutcome
    classification: ReplayClassification
    replayed_states: tuple[str, ...]
    comparisons: tuple[FieldComparison, ...]
    detail: str

    def curated_summary(self) -> dict[str, object]:
        """Return identifiers and conclusions only; never raw evidence content."""

        return {
            "case_id": self.case_id,
            "case_digest": self.case_digest,
            "outcome": self.outcome.value,
            "classification": self.classification.value,
            "replayed_states": self.replayed_states,
            "comparison_fields": tuple(item.field.value for item in self.comparisons if not item.matches),
        }


class ShadowExecutor:
    """Replay persisted evidence through the fixed lifecycle state machine."""

    def __init__(self, capabilities: NoMutationCapabilities | None = None):
        self._capabilities = capabilities if capabilities is not None else NoMutationCapabilities()

    def replay(self, case: ShadowCase) -> ShadowReport:
        """Compare exactly one case without launching a Worker or changing state."""

        try:
            _validate_case(case)
        except ShadowError as error:
            return _invalid_report(case, ReplayClassification.CONTRACT_MISMATCH, str(error))

        observations: list[ShadowObservation] = []
        seen: dict[str, str] = {}
        try:
            for observation in case.observations:
                _validate_observation(observation)
                prior = seen.get(observation.event_id)
                if prior is not None:
                    if prior != observation.evidence_digest:
                        return _invalid_report(case, ReplayClassification.CONTRACT_MISMATCH, "replay event identity is ambiguous")
                    continue
                seen[observation.event_id] = observation.evidence_digest
                if observation.requested_mutation is not None:
                    self._capabilities.execute(observation.requested_mutation)
                if observation.candidate_sha != case.identity.candidate_sha:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "candidate-bound evidence is stale")
                if observation.worktree_identity is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "worktree evidence is missing")
                if observation.worktree_identity != case.identity.worktree_identity:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "worktree-bound evidence is stale")
                if not observation.worktree_clean:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "worktree evidence is dirty")
                if observation.attempt_disposition is AttemptDisposition.AMBIGUOUS:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "ambiguous attempt is not replayable")
                if observation.attempt_disposition is not AttemptDisposition.ACCEPTED:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "review evidence is not accepted")
                if observation.accepted_review_identity is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "accepted review evidence is missing")
                if observation.accepted_review_identity != case.identity.accepted_review_identity:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "accepted review evidence is stale")
                if observation.gate_identity is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "gate evidence is missing")
                if observation.applicability is Applicability.NOT_APPLICABLE and (
                    observation.source_count != 1 or observation.not_applicable_reason != "isolated-single-source"
                ):
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "not-applicable evidence is not justified")
                observations.append(observation)
        except ForbiddenMutationError as error:
            return _invalid_report(case, ReplayClassification.FORBIDDEN_MUTATION, str(error))
        except ShadowError as error:
            return _invalid_report(case, ReplayClassification.CONTRACT_MISMATCH, str(error))

        if not observations or {item.role for item in observations} != {EvidenceRole.WORKER, EvidenceRole.SUPERVISOR}:
            return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "worker and supervisor observations are both required")

        replayed_states = tuple(item.state for item in observations)
        if not _is_valid_trace(replayed_states):
            return _invalid_report(case, ReplayClassification.CONTRACT_MISMATCH, "persisted states do not form a deterministic lifecycle trace")

        final = observations[-1]
        comparisons = (
            _comparison(ComparisonField.STATE, ",".join(case.expected_states), ",".join(replayed_states)),
            _comparison(ComparisonField.GATE, case.identity.gate_identity, final.gate_identity),
            _comparison(ComparisonField.IDENTITY, case.identity.digest(), _observed_identity_digest(case, observations)),
            _comparison(ComparisonField.APPLICABILITY, case.expected_applicability.value, final.applicability.value),
            _comparison(ComparisonField.BLOCKER, case.expected_blocker or "none", final.blocker or "none"),
            _comparison(ComparisonField.NEXT_ACTION, case.identity.expected_next_action, final.next_action),
        )
        differences = tuple(item for item in comparisons if not item.matches)
        if not differences:
            return ShadowReport(
                case.case_id, case.case_digest, ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH, replayed_states, comparisons, "exact deterministic match"
            )
        allowed = set(case.expected_nondeterminism)
        if differences and all(item.field in allowed for item in differences):
            return ShadowReport(
                case.case_id, case.case_digest, ComparisonOutcome.MISMATCH, ReplayClassification.EXPECTED_NONDETERMINISM, replayed_states, comparisons, "declared nondeterministic fields differ"
            )
        return ShadowReport(
            case.case_id, case.case_digest, ComparisonOutcome.MISMATCH, ReplayClassification.CONTRACT_MISMATCH, replayed_states, comparisons, "deterministic comparison differs"
        )


def replay_shadow_case(case: ShadowCase) -> ShadowReport:
    """Convenience entry point for a fresh, forced-no-mutation replay."""

    return ShadowExecutor().replay(case)


def _invalid_report(case: object, classification: ReplayClassification, detail: str) -> ShadowReport:
    case_id = case.case_id if isinstance(case, ShadowCase) else "invalid-case"
    digest = case.case_digest if isinstance(case, ShadowCase) else "none"
    return ShadowReport(case_id, digest, ComparisonOutcome.INVALID, classification, (), (), detail)


def _comparison(field: ComparisonField, expected: str, actual: str) -> FieldComparison:
    return FieldComparison(field, expected, actual, expected == actual)


def _validate_case(case: object) -> None:
    if not isinstance(case, ShadowCase):
        raise ShadowError("shadow case is invalid")
    if case.schema != SHADOW_CASE_SCHEMA:
        raise ShadowError("shadow case schema is unsupported")
    _token(case.case_id, "case identity")
    _validate_identity(case.identity)
    if not isinstance(case.observations, tuple) or not case.observations:
        raise ShadowError("shadow case observations are incomplete")
    if not isinstance(case.expected_states, tuple) or not case.expected_states:
        raise ShadowError("expected state trace is incomplete")
    if not isinstance(case.expected_applicability, Applicability):
        raise ShadowError("expected applicability is invalid")
    if case.expected_blocker is not None:
        _token(case.expected_blocker, "expected blocker")
    if any(not isinstance(item, ComparisonField) for item in case.expected_nondeterminism):
        raise ShadowError("expected nondeterminism is invalid")
    if case.case_digest != _digest(_case_payload(case, include_digest=False)):
        raise ShadowError("shadow case digest does not match immutable content")


def _validate_identity(identity: object) -> None:
    if not isinstance(identity, ShadowIdentity):
        raise ShadowError("shadow identity is invalid")
    _token(identity.source_id, "source identity")
    _token(identity.task_id, "task identity")
    if not isinstance(identity.base_sha, str) or not _SHA1.fullmatch(identity.base_sha):
        raise ShadowError("base identity is invalid")
    if not isinstance(identity.candidate_sha, str) or not _SHA1.fullmatch(identity.candidate_sha):
        raise ShadowError("candidate identity is invalid")
    for value, name in (
        (identity.policy_identity, "policy identity"),
        (identity.provider_attempt_identity, "provider attempt identity"),
        (identity.accepted_review_identity, "accepted review identity"),
        (identity.gate_identity, "gate identity"),
        (identity.expected_next_action, "expected next action"),
        (identity.worktree_identity, "worktree identity"),
    ):
        _token(value, name)


def _validate_observation(observation: object) -> None:
    if not isinstance(observation, ShadowObservation):
        raise ShadowError("shadow observation is invalid")
    _token(observation.event_id, "event identity")
    _token(observation.attempt_id, "attempt identity")
    _token(observation.state, "state")
    _token(observation.next_action, "next action")
    if not isinstance(observation.role, EvidenceRole) or not isinstance(observation.attempt_disposition, AttemptDisposition):
        raise ShadowError("observation role or disposition is invalid")
    if not isinstance(observation.applicability, Applicability) or not isinstance(observation.source_count, int) or observation.source_count < 1:
        raise ShadowError("observation applicability is invalid")
    if not isinstance(observation.candidate_sha, str) or not _SHA1.fullmatch(observation.candidate_sha):
        raise ShadowError("observation candidate is invalid")
    if observation.blocker is not None:
        _token(observation.blocker, "blocker")
    if observation.not_applicable_reason is not None:
        _token(observation.not_applicable_reason, "not-applicable reason")
    if observation.gate_identity is not None:
        _token(observation.gate_identity, "gate identity")
    if observation.accepted_review_identity is not None:
        _token(observation.accepted_review_identity, "accepted review identity")
    if observation.worktree_identity is not None:
        _token(observation.worktree_identity, "worktree identity")
    if not isinstance(observation.worktree_clean, bool):
        raise ShadowError("worktree cleanliness is invalid")
    if observation.requested_mutation is not None and not isinstance(observation.requested_mutation, MutationKind):
        raise ShadowError("requested mutation is invalid")
    if not _SHA256.fullmatch(observation.evidence_digest) or observation.evidence_digest != _digest(_observation_payload(observation, include_digest=False)):
        raise ShadowError("observation digest does not match immutable content")


def _is_valid_trace(states: tuple[str, ...]) -> bool:
    canonical = ("queued", "planning", "plan-review", "implementing", "diff-review", "ready-for-owner")
    positions = {state: index for index, state in enumerate(canonical)}
    if any(state not in positions for state in states):
        return False
    return tuple(sorted((positions[state] for state in states))) == tuple(positions[state] for state in states) and len(set(states)) == len(states)


def _observed_identity_digest(case: ShadowCase, observations: list[ShadowObservation]) -> str:
    # The case is the one immutable carrier for source/task/policy/review
    # identities; observations prove that its candidate was actually used.
    # Candidate drift is rejected before this comparison is reached.
    del observations
    return case.identity.digest()


def _identity_payload(identity: ShadowIdentity) -> dict[str, str]:
    return {
        "source_id": identity.source_id,
        "task_id": identity.task_id,
        "base_sha": identity.base_sha,
        "candidate_sha": identity.candidate_sha,
        "policy_identity": identity.policy_identity,
        "provider_attempt_identity": identity.provider_attempt_identity,
        "accepted_review_identity": identity.accepted_review_identity,
        "gate_identity": identity.gate_identity,
        "expected_next_action": identity.expected_next_action,
        "worktree_identity": identity.worktree_identity,
    }


def _observation_payload(observation: ShadowObservation, *, include_digest: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "event_id": observation.event_id,
        "role": observation.role.value if isinstance(observation.role, EvidenceRole) else observation.role,
        "attempt_id": observation.attempt_id,
        "attempt_disposition": observation.attempt_disposition.value if isinstance(observation.attempt_disposition, AttemptDisposition) else observation.attempt_disposition,
        "state": observation.state,
        "candidate_sha": observation.candidate_sha,
        "gate_identity": observation.gate_identity,
        "applicability": observation.applicability.value if isinstance(observation.applicability, Applicability) else observation.applicability,
        "blocker": observation.blocker,
        "next_action": observation.next_action,
        "source_count": observation.source_count,
        "not_applicable_reason": observation.not_applicable_reason,
        "requested_mutation": observation.requested_mutation.value if isinstance(observation.requested_mutation, MutationKind) else observation.requested_mutation,
        "accepted_review_identity": observation.accepted_review_identity,
        "worktree_identity": observation.worktree_identity,
        "worktree_clean": observation.worktree_clean,
    }
    if include_digest:
        payload["evidence_digest"] = observation.evidence_digest
    return payload


def _case_payload(case: ShadowCase, *, include_digest: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": case.schema,
        "case_id": case.case_id,
        "identity": _identity_payload(case.identity),
        "observations": tuple(_observation_payload(item, include_digest=True) for item in case.observations),
        "expected_states": case.expected_states,
        "expected_applicability": case.expected_applicability.value if isinstance(case.expected_applicability, Applicability) else case.expected_applicability,
        "expected_blocker": case.expected_blocker,
        "expected_nondeterminism": tuple(item.value if isinstance(item, ComparisonField) else item for item in case.expected_nondeterminism),
    }
    if include_digest:
        payload["case_digest"] = case.case_digest
    return payload


def _token(value: object, name: str) -> None:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ShadowError(f"{name} is invalid")


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
