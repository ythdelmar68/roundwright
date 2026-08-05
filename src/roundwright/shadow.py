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
_CONFIG_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
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


class MismatchDisposition(StrEnum):
    INPUT_DRIFT = "INPUT_DRIFT"
    NORMALIZATION_DEFECT = "NORMALIZATION_DEFECT"
    DETERMINISM_DEFECT = "DETERMINISM_DEFECT"
    SEMANTIC_REGRESSION = "SEMANTIC_REGRESSION"
    EXPECTED_CHANGE = "EXPECTED_CHANGE"
    ENVIRONMENT_LIMITATION = "ENVIRONMENT_LIMITATION"


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
    reference_result_identity: str = ""
    input_digests: tuple[str, ...] = ()
    comparison_rules_identity: str = ""
    fixture_environment_identity: str = ""
    captured_at: str = ""
    retention_class: str = ""
    retention_reference: str = ""
    normalization_version: str = ""
    comparator_version: str = ""
    input_identities: tuple[str, ...] = ()
    reference_result_digest: str = ""
    input_payloads: tuple[bytes, ...] = ()
    reference_result_payload: bytes = b""
    configuration_digest: str = ""
    configuration_schema_version: str = ""
    worker_profile_identity: str = ""
    supervisor_profile_identities: tuple[str, ...] = ()
    selected_supervisor_profile_identity: str = ""

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
    input_identities: tuple[str, ...] = ()
    input_digests: tuple[str, ...] = ()
    reference_result_digest: str | None = None
    input_payloads: tuple[bytes, ...] = ()
    reference_result_payload: bytes | None = None
    evidence_digest: str = field(default="")
    configuration_digest: str = ""
    configuration_schema_version: str = ""
    worker_profile_identity: str = ""
    supervisor_profile_identities: tuple[str, ...] = ()
    selected_supervisor_profile_identity: str = ""

    def __post_init__(self) -> None:
        _validate_observation(self, verify_digest=False)
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
        _validate_case(self, verify_digest=False)
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
        observations: tuple[ShadowObservation, ...],
        *,
        expected_states: tuple[str, ...],
        expected_applicability: Applicability = Applicability.APPLICABLE,
        expected_blocker: str | None = None,
        expected_nondeterminism: tuple[ComparisonField, ...] = (),
    ) -> "ShadowCase":
        if type(observations) is not tuple or any(type(item) is not ShadowObservation for item in observations):
            raise ShadowError("shadow case observations are invalid")
        if type(expected_states) is not tuple or any(type(item) is not str for item in expected_states):
            raise ShadowError("expected state trace is invalid")
        if type(expected_nondeterminism) is not tuple or any(type(item) is not ComparisonField for item in expected_nondeterminism):
            raise ShadowError("expected nondeterminism is invalid")
        return cls(
            case_id,
            identity,
            observations,
            expected_states,
            expected_applicability,
            expected_blocker,
            expected_nondeterminism,
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
    disposition: MismatchDisposition | None = None
    public_identities: tuple[tuple[str, str], ...] = ()
    retention_reference: str = ""
    read_only: bool = True

    def __post_init__(self) -> None:
        if self.outcome is not ComparisonOutcome.MATCH and self.disposition is None:
            object.__setattr__(self, "disposition", _disposition_for(self.classification))

    def curated_summary(self) -> dict[str, object]:
        """Return identifiers and conclusions only; never raw evidence content."""

        return {
            "case_id": _public_identifier(self.case_id),
            "case_digest": self.case_digest,
            "outcome": self.outcome.value,
            "classification": self.classification.value,
            "replayed_states": self.replayed_states,
            "comparison_fields": tuple(item.field.value for item in self.comparisons if not item.matches),
            "identities": dict(self.public_identities),
            "retention_reference": self.retention_reference,
            "read_only": self.read_only,
            "mismatch_disposition": None if self.disposition is None else self.disposition.value,
        }


class ShadowExecutor:
    """Replay persisted evidence through the fixed lifecycle state machine."""

    def replay(self, case: ShadowCase) -> ShadowReport:
        """Compare exactly one case without launching a Worker or changing state."""

        try:
            _validate_case(case)
        except (ShadowError, AttributeError) as error:
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
                if (observation.configuration_schema_version, observation.configuration_digest) != (case.identity.configuration_schema_version, case.identity.configuration_digest):
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "resolved configuration evidence has drifted")
                if (observation.worker_profile_identity, observation.supervisor_profile_identities, observation.selected_supervisor_profile_identity) != (case.identity.worker_profile_identity, case.identity.supervisor_profile_identities, case.identity.selected_supervisor_profile_identity):
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "resolved configuration profile evidence has drifted")
                if any(value is None for value in (
                    observation.source_id, observation.task_id, observation.base_sha, observation.policy_identity,
                )):
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "bound identity evidence is missing")
                if observation.input_identities != case.identity.input_identities or observation.input_digests != case.identity.input_digests:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "immutable replay inputs have drifted")
                if observation.input_payloads != case.identity.input_payloads:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "immutable replay input content has drifted")
                if observation.reference_result_digest is None:
                    return _invalid_report(case, ReplayClassification.INCOMPLETE_EVIDENCE, "reference result content is missing")
                if observation.reference_result_digest != case.identity.reference_result_digest:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "reference result content has drifted")
                if observation.reference_result_payload != case.identity.reference_result_payload:
                    return _invalid_report(case, ReplayClassification.STALE_EVIDENCE, "reference result payload has drifted")
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
            return _report(case, ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH, replayed_states, comparisons, "exact deterministic match")
        if any(item.field in (ComparisonField.IDENTITY, ComparisonField.GATE) for item in differences):
            return _report(case, ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH, replayed_states, comparisons, "bound identity evidence differs")
        allowed = set(case.expected_nondeterminism)
        if differences and all(item.field in allowed for item in differences):
            return _report(case, ComparisonOutcome.MISMATCH, ReplayClassification.EXPECTED_NONDETERMINISM, replayed_states, comparisons, "declared nondeterministic fields differ")
        return _report(case, ComparisonOutcome.MISMATCH, ReplayClassification.CONTRACT_MISMATCH, replayed_states, comparisons, "deterministic comparison differs", MismatchDisposition.SEMANTIC_REGRESSION)


def replay_shadow_case(case: ShadowCase) -> ShadowReport:
    """Convenience entry point for a fresh, forced-no-mutation replay."""

    return ShadowExecutor().replay(case)


def _invalid_report(case: object, classification: ReplayClassification, detail: str) -> ShadowReport:
    try:
        _validate_case(case)
    except (ShadowError, AttributeError):
        pass
    else:
        return _report(case, ComparisonOutcome.INVALID, classification, (), (), detail)
    return ShadowReport("invalid-case", "none", ComparisonOutcome.INVALID, classification, (), (), detail)


def _report(case: ShadowCase, outcome: ComparisonOutcome, classification: ReplayClassification, replayed_states: tuple[str, ...], comparisons: tuple[FieldComparison, ...], detail: str, disposition: MismatchDisposition | None = None) -> ShadowReport:
    identity = case.identity
    pairs = tuple((name, _public_identifier(value)) for name, value in (
        ("source", identity.source_id), ("task", identity.task_id), ("base", identity.base_sha),
        ("candidate", identity.candidate_sha), ("policy", identity.policy_identity),
        ("provider_attempt", identity.provider_attempt_identity), ("accepted_review", identity.accepted_review_identity),
        ("gate", identity.gate_identity), ("worktree", identity.worktree_identity),
        ("reference_result", identity.reference_result_identity),
    ))
    return ShadowReport(case.case_id, case.case_digest, outcome, classification, replayed_states, comparisons, detail, disposition, pairs, _public_identifier(identity.retention_reference))


def _comparison(field: ComparisonField, expected: str, actual: str) -> FieldComparison:
    return FieldComparison(field, expected, actual, expected == actual)


def _validate_case(case: object, *, verify_digest: bool = True) -> None:
    if type(case) is not ShadowCase:
        raise ShadowError("shadow case is invalid")
    _token(case.schema, "shadow case schema")
    _token(case.case_id, "case identity")
    if case.schema != SHADOW_CASE_SCHEMA:
        raise ShadowError("shadow case schema is unsupported")
    if type(case.identity) is not ShadowIdentity:
        raise ShadowError("shadow identity is invalid")
    if type(case.observations) is not tuple or not case.observations:
        raise ShadowError("shadow case observations are incomplete")
    if any(type(observation) is not ShadowObservation for observation in case.observations):
        raise ShadowError("shadow observation is invalid")
    _validate_identity(case.identity)
    for observation in case.observations:
        _validate_observation(observation, verify_digest=verify_digest)
    if type(case.expected_states) is not tuple or any(type(state) is not str for state in case.expected_states) or case.expected_states != _PHASE_TWO_STATES:
        raise ShadowError("expected state trace does not match the Phase 2 contract")
    if not isinstance(case.expected_applicability, Applicability):
        raise ShadowError("expected applicability is invalid")
    if case.expected_blocker is not None:
        _token(case.expected_blocker, "expected blocker")
    if type(case.expected_nondeterminism) is not tuple or any(type(item) is not ComparisonField for item in case.expected_nondeterminism):
        raise ShadowError("expected nondeterminism is invalid")
    if any(item is not ComparisonField.NEXT_ACTION for item in case.expected_nondeterminism):
        raise ShadowError("expected nondeterminism includes a semantic field")
    if verify_digest and (type(case.case_digest) is not str or not _SHA256.fullmatch(case.case_digest) or case.case_digest != _digest(_case_payload(case, include_digest=False))):
        raise ShadowError("shadow case digest does not match immutable content")


def _validate_identity(identity: object) -> None:
    if type(identity) is not ShadowIdentity:
        raise ShadowError("shadow identity is invalid")
    _token(identity.source_id, "source identity")
    _token(identity.task_id, "task identity")
    if type(identity.base_sha) is not str or not _SHA1.fullmatch(identity.base_sha):
        raise ShadowError("base identity is invalid")
    if type(identity.candidate_sha) is not str or not _SHA1.fullmatch(identity.candidate_sha):
        raise ShadowError("candidate identity is invalid")
    for value, name in (
        (identity.policy_identity, "policy identity"),
        (identity.provider_attempt_identity, "provider attempt identity"),
        (identity.accepted_review_identity, "accepted review identity"),
        (identity.gate_identity, "gate identity"),
        (identity.expected_next_action, "expected next action"),
        (identity.worktree_identity, "worktree identity"),
        (identity.reference_result_identity, "reference result identity"),
        (identity.comparison_rules_identity, "comparison rules identity"),
        (identity.fixture_environment_identity, "fixture environment identity"),
        (identity.captured_at, "capture time"),
        (identity.retention_class, "retention class"),
        (identity.retention_reference, "retention reference"),
        (identity.normalization_version, "normalization version"),
        (identity.comparator_version, "comparator version"),
    ):
        _token(value, name)
    if type(identity.input_digests) is not tuple or not identity.input_digests:
        raise ShadowError("input digests are incomplete")
    if any(type(digest) is not str or not _SHA256.fullmatch(digest) for digest in identity.input_digests):
        raise ShadowError("input digest is invalid")
    if type(identity.input_identities) is not tuple or len(identity.input_identities) != len(identity.input_digests) or not identity.input_identities:
        raise ShadowError("input identities are incomplete")
    if any(type(value) is not str or not _TOKEN.fullmatch(value) for value in identity.input_identities) or len(set(identity.input_identities)) != len(identity.input_identities):
        raise ShadowError("input identity is invalid")
    if type(identity.reference_result_digest) is not str or not _SHA256.fullmatch(identity.reference_result_digest):
        raise ShadowError("reference result digest is invalid")
    if type(identity.input_payloads) is not tuple or len(identity.input_payloads) != len(identity.input_digests) or any(type(value) is not bytes for value in identity.input_payloads):
        raise ShadowError("input payload is invalid")
    if any(hashlib.sha256(payload).hexdigest() != digest for payload, digest in zip(identity.input_payloads, identity.input_digests, strict=True)):
        raise ShadowError("input digest does not match immutable content")
    if type(identity.reference_result_payload) is not bytes or hashlib.sha256(identity.reference_result_payload).hexdigest() != identity.reference_result_digest:
        raise ShadowError("reference result digest does not match immutable content")
    if type(identity.configuration_digest) is not str or not _CONFIG_DIGEST.fullmatch(identity.configuration_digest):
        raise ShadowError("resolved configuration digest is invalid")
    if identity.configuration_schema_version != "roundwright-runtime/v1":
        raise ShadowError("resolved configuration schema version is invalid")
    if type(identity.worker_profile_identity) is not str or not _CONFIG_DIGEST.fullmatch(identity.worker_profile_identity) or type(identity.supervisor_profile_identities) is not tuple or not identity.supervisor_profile_identities or any(type(value) is not str or not _CONFIG_DIGEST.fullmatch(value) for value in identity.supervisor_profile_identities):
        raise ShadowError("resolved configuration profile identity is invalid")
    if identity.selected_supervisor_profile_identity not in identity.supervisor_profile_identities:
        raise ShadowError("selected Supervisor profile identity is invalid")


def _validate_observation(observation: object, *, verify_digest: bool = True) -> None:
    if type(observation) is not ShadowObservation:
        raise ShadowError("shadow observation is invalid")
    _token(observation.event_id, "event identity")
    _token(observation.attempt_id, "attempt identity")
    _token(observation.state, "state")
    if type(observation.configuration_digest) is not str or not _CONFIG_DIGEST.fullmatch(observation.configuration_digest):
        raise ShadowError("resolved configuration digest is invalid")
    if observation.configuration_schema_version != "roundwright-runtime/v1":
        raise ShadowError("resolved configuration schema version is invalid")
    if type(observation.worker_profile_identity) is not str or not _CONFIG_DIGEST.fullmatch(observation.worker_profile_identity) or type(observation.supervisor_profile_identities) is not tuple or not observation.supervisor_profile_identities or any(type(value) is not str or not _CONFIG_DIGEST.fullmatch(value) for value in observation.supervisor_profile_identities):
        raise ShadowError("resolved configuration profile identity is invalid")
    if observation.selected_supervisor_profile_identity not in observation.supervisor_profile_identities:
        raise ShadowError("selected Supervisor profile identity is invalid")
    _token(observation.next_action, "next action")
    if not isinstance(observation.role, EvidenceRole) or not isinstance(observation.attempt_disposition, AttemptDisposition):
        raise ShadowError("observation role or disposition is invalid")
    if type(observation.applicability) is not Applicability or type(observation.source_count) is not int or observation.source_count < 1:
        raise ShadowError("observation applicability is invalid")
    if type(observation.candidate_sha) is not str or not _SHA1.fullmatch(observation.candidate_sha):
        raise ShadowError("observation candidate is invalid")
    for value, name in (
        (observation.source_id, "observation source identity"),
        (observation.task_id, "observation task identity"),
        (observation.policy_identity, "observation policy identity"),
    ):
        if value is not None:
            _token(value, name)
    if observation.base_sha is not None and (type(observation.base_sha) is not str or not _SHA1.fullmatch(observation.base_sha)):
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
    if type(observation.worktree_clean) is not bool:
        raise ShadowError("worktree cleanliness is invalid")
    if observation.requested_mutation is not None and not isinstance(observation.requested_mutation, MutationKind):
        raise ShadowError("requested mutation is invalid")
    if type(observation.input_identities) is not tuple or type(observation.input_digests) is not tuple or len(observation.input_identities) != len(observation.input_digests):
        raise ShadowError("observation inputs are invalid")
    if any(type(value) is not str or not _TOKEN.fullmatch(value) for value in observation.input_identities) or any(type(value) is not str or not _SHA256.fullmatch(value) for value in observation.input_digests):
        raise ShadowError("observation input is invalid")
    if observation.reference_result_digest is not None and (type(observation.reference_result_digest) is not str or not _SHA256.fullmatch(observation.reference_result_digest)):
        raise ShadowError("observation reference digest is invalid")
    if type(observation.input_payloads) is not tuple or len(observation.input_payloads) != len(observation.input_digests) or any(type(value) is not bytes for value in observation.input_payloads):
        raise ShadowError("observation input payload is invalid")
    if any(hashlib.sha256(payload).hexdigest() != digest for payload, digest in zip(observation.input_payloads, observation.input_digests, strict=True)):
        raise ShadowError("observation input digest does not match content")
    if observation.reference_result_payload is not None and (type(observation.reference_result_payload) is not bytes or observation.reference_result_digest is None or hashlib.sha256(observation.reference_result_payload).hexdigest() != observation.reference_result_digest):
        raise ShadowError("observation reference content is invalid")
    if verify_digest and (type(observation.evidence_digest) is not str or not _SHA256.fullmatch(observation.evidence_digest) or observation.evidence_digest != _digest(_observation_payload(observation, include_digest=False))):
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
        "reference_result_identity": identity.reference_result_identity,
        "input_digests": identity.input_digests,
        "comparison_rules_identity": identity.comparison_rules_identity,
        "fixture_environment_identity": identity.fixture_environment_identity,
        "captured_at": identity.captured_at,
        "retention_class": identity.retention_class,
        "retention_reference": identity.retention_reference,
        "normalization_version": identity.normalization_version,
        "comparator_version": identity.comparator_version,
        "input_identities": identity.input_identities,
        "reference_result_digest": identity.reference_result_digest,
        "input_payloads": tuple(value.hex() for value in identity.input_payloads),
        "reference_result_payload": identity.reference_result_payload.hex(),
        "configuration_digest": identity.configuration_digest,
        "configuration_schema_version": identity.configuration_schema_version,
        "worker_profile_identity": identity.worker_profile_identity,
        "supervisor_profile_identities": identity.supervisor_profile_identities,
        "selected_supervisor_profile_identity": identity.selected_supervisor_profile_identity,
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
        "input_identities": observation.input_identities,
        "input_digests": observation.input_digests,
        "reference_result_digest": observation.reference_result_digest,
        "input_payloads": tuple(value.hex() for value in observation.input_payloads),
        "reference_result_payload": None if observation.reference_result_payload is None else observation.reference_result_payload.hex(),
        "configuration_digest": observation.configuration_digest,
        "configuration_schema_version": observation.configuration_schema_version,
        "worker_profile_identity": observation.worker_profile_identity,
        "supervisor_profile_identities": observation.supervisor_profile_identities,
        "selected_supervisor_profile_identity": observation.selected_supervisor_profile_identity,
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
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise ShadowError(f"{name} is invalid")


def _forbid_mutation(kind: MutationKind) -> Never:
    if not isinstance(kind, MutationKind):
        raise ShadowError("mutation kind is invalid")
    raise ForbiddenMutationError(kind)


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _disposition_for(classification: ReplayClassification) -> MismatchDisposition:
    return {
        ReplayClassification.EXPECTED_NONDETERMINISM: MismatchDisposition.EXPECTED_CHANGE,
        ReplayClassification.STALE_EVIDENCE: MismatchDisposition.INPUT_DRIFT,
        ReplayClassification.INCOMPLETE_EVIDENCE: MismatchDisposition.ENVIRONMENT_LIMITATION,
        ReplayClassification.FORBIDDEN_MUTATION: MismatchDisposition.SEMANTIC_REGRESSION,
        ReplayClassification.CONTRACT_MISMATCH: MismatchDisposition.INPUT_DRIFT,
    }[classification]


def _public_identifier(value: str) -> str:
    return "sha256:" + _digest({"opaque": value})
