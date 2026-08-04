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
        return _forbid_mutation(kind)

    def git(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.GIT)

    def github(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.GITHUB)

    def repository(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.REPOSITORY)

    def queue(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.QUEUE)

    def branch(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.BRANCH)

    def worktree(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.WORKTREE)

    def pull_request(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.PULL_REQUEST)

    def issue(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.ISSUE)

    def merge(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.MERGE)

    def close(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.CLOSE)

    def cleanup(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.CLEANUP)

    def lifecycle(self, action: Callable[[], object] | None = None) -> Never:
        return _forbid_mutation(MutationKind.LIFECYCLE)


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
    source_id: str | None = None
    task_id: str | None = None
    base_sha: str | None = None
    policy_identity: str | None = None
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
                    _forbid_mutation(observation.requested_mutation)
                if observation.candidate_sha != case.identity.candidate_sha:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "candidate-bound evidence is stale")
                if any(value is None for value in (
                    observation.source_id, observation.task_id, observation.base_sha, observation.policy_identity,
                )):
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "bound identity evidence is missing")
                if observation.worktree_identity is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "worktree evidence is missing")
                if not observation.worktree_clean:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "worktree evidence is dirty")
                if observation.attempt_disposition is AttemptDisposition.AMBIGUOUS:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "ambiguous attempt is not replayable")
                if observation.attempt_disposition is not AttemptDisposition.ACCEPTED:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "review evidence is not accepted")
                if observation.accepted_review_identity is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "accepted review evidence is missing")
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
        trace_error = _trace_error(replayed_states)
        if trace_error is not None:
            return _invalid_report(case, trace_error[0], trace_error[1])

        final = observations[-1]
        comparisons = (
            _comparison(ComparisonField.STATE, ",".join(case.expected_states), ",".join(replayed_states)),
            _comparison(ComparisonField.GATE, case.identity.gate_identity, final.gate_identity),
            _comparison(ComparisonField.IDENTITY, _expected_identity_digest(case.identity, len(observations)), _observed_identity_digest(observations)),
            _comparison(ComparisonField.APPLICABILITY, case.expected_applicability.value, final.applicability.value),
            _comparison(ComparisonField.BLOCKER, case.expected_blocker or "none", final.blocker or "none"),
            _comparison(ComparisonField.NEXT_ACTION, case.identity.expected_next_action, final.next_action),
        )
        differences = tuple(item for item in comparisons if not item.matches)
        if not differences:
            return ShadowReport(
                case.case_id, case.case_digest, ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH, replayed_states, comparisons, "exact deterministic match"
            )
        if any(item.field in (ComparisonField.IDENTITY, ComparisonField.GATE) for item in differences):
            return ShadowReport(
                case.case_id, case.case_digest, ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH, replayed_states, comparisons, "bound identity evidence differs"
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
    case_id = case.case_id if type(case) is ShadowCase else "invalid-case"
    digest = case.case_digest if type(case) is ShadowCase else "none"
    return ShadowReport(case_id, digest, ComparisonOutcome.INVALID, classification, (), (), detail)


def _comparison(field: ComparisonField, expected: str, actual: str) -> FieldComparison:
    return FieldComparison(field, expected, actual, expected == actual)


def _validate_case(case: object) -> None:
    if type(case) is not ShadowCase:
        raise ShadowError("shadow case is invalid")
    if case.schema != SHADOW_CASE_SCHEMA:
        raise ShadowError("shadow case schema is unsupported")
    _token(case.case_id, "case identity")
    if type(case.identity) is not ShadowIdentity:
        raise ShadowError("shadow identity is invalid")
    if type(case.observations) is not tuple or not case.observations:
        raise ShadowError("shadow case observations are incomplete")
    if any(type(observation) is not ShadowObservation for observation in case.observations):
        raise ShadowError("shadow observation is invalid")
    _validate_identity(case.identity)
    if case.expected_states != _PHASE_TWO_STATES:
        raise ShadowError("expected state trace does not match the Phase 2 contract")
    if not isinstance(case.expected_applicability, Applicability):
        raise ShadowError("expected applicability is invalid")
    if case.expected_blocker is not None:
        _token(case.expected_blocker, "expected blocker")
    if any(type(item) is not ComparisonField for item in case.expected_nondeterminism):
        raise ShadowError("expected nondeterminism is invalid")
    if any(item is not ComparisonField.NEXT_ACTION for item in case.expected_nondeterminism):
        raise ShadowError("expected nondeterminism includes a semantic field")
    if case.case_digest != _digest(_case_payload(case, include_digest=False)):
        raise ShadowError("shadow case digest does not match immutable content")


def _validate_identity(identity: object) -> None:
    if type(identity) is not ShadowIdentity:
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
    if type(observation) is not ShadowObservation:
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
    for value, name in (
        (observation.source_id, "observation source identity"),
        (observation.task_id, "observation task identity"),
        (observation.policy_identity, "observation policy identity"),
    ):
        if value is not None:
            _token(value, name)
    if observation.base_sha is not None and (not isinstance(observation.base_sha, str) or not _SHA1.fullmatch(observation.base_sha)):
        raise ShadowError("observation base identity is invalid")
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


_PHASE_TWO_STATES = ("queued", "planning", "plan-review", "implementing", "diff-review", "ready-for-owner")


def _trace_error(states: tuple[str, ...]) -> tuple[ReplayClassification, str] | None:
    if any(state not in _PHASE_TWO_STATES for state in states) or len(set(states)) != len(states):
        return ReplayClassification.CONTRACT_MISMATCH, "persisted states do not form a deterministic lifecycle trace"
    if len(states) != len(_PHASE_TWO_STATES) or set(states) != set(_PHASE_TWO_STATES):
        return ReplayClassification.INCOMPLETE_EVIDENCE, "persisted lifecycle evidence omits a Phase 2 state"
    if states != _PHASE_TWO_STATES:
        return ReplayClassification.CONTRACT_MISMATCH, "persisted states are not in Phase 2 lifecycle order"
    return None


def _expected_identity_digest(identity: ShadowIdentity, observation_count: int) -> str:
    return _digest({
        "source_id": (identity.source_id,) * observation_count,
        "task_id": (identity.task_id,) * observation_count,
        "base_sha": (identity.base_sha,) * observation_count,
        "candidate_sha": (identity.candidate_sha,) * observation_count,
        "policy_identity": (identity.policy_identity,) * observation_count,
        "provider_attempt_identity": (identity.provider_attempt_identity,) * observation_count,
        "accepted_review_identity": (identity.accepted_review_identity,) * observation_count,
        "gate_identity": (identity.gate_identity,) * observation_count,
        "worktree_identity": (identity.worktree_identity,) * observation_count,
    })


def _observed_identity_digest(observations: list[ShadowObservation]) -> str:
    return _digest({
        "source_id": tuple(item.source_id for item in observations),
        "task_id": tuple(item.task_id for item in observations),
        "base_sha": tuple(item.base_sha for item in observations),
        "candidate_sha": tuple(item.candidate_sha for item in observations),
        "policy_identity": tuple(item.policy_identity for item in observations),
        "provider_attempt_identity": tuple(item.attempt_id for item in observations),
        "accepted_review_identity": tuple(item.accepted_review_identity for item in observations),
        "gate_identity": tuple(item.gate_identity for item in observations),
        "worktree_identity": tuple(item.worktree_identity for item in observations),
    })


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
        "source_id": observation.source_id,
        "task_id": observation.task_id,
        "base_sha": observation.base_sha,
        "policy_identity": observation.policy_identity,
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


def _forbid_mutation(kind: MutationKind) -> Never:
    if not isinstance(kind, MutationKind):
        raise ShadowError("mutation kind is invalid")
    raise ForbiddenMutationError(kind)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
