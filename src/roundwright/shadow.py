"""Immutable, no-mutation replay for persisted lifecycle evidence.

Shadow is deliberately a pure boundary.  It accepts an immutable case bundle
and its already-persisted Worker/Supervisor observations, then replays those
facts through the Phase 2 state sequence.  It never opens a repository,
starts a provider, or writes durable state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
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


@dataclass(frozen=True)
class ProviderHealthReceiptComparison:
    case_id: str
    outcome: ComparisonOutcome
    contract_commit: str
    candidate_sha: str | None
    profile_identity: str
    receipt_digest: str
    sdk_version: str = ""
    runtime_version: str = ""
    model: str = ""
    reasoning_effort: str = ""
    differing_fields: tuple[str, ...] = ()

    def curated_summary(self) -> dict[str, object]:
        return {"case_id": self.case_id, "outcome": self.outcome.value, "contract_commit": self.contract_commit,
                "candidate_sha": self.candidate_sha, "profile_identity": self.profile_identity, "receipt_digest": self.receipt_digest,
                "sdk_version": self.sdk_version, "runtime_version": self.runtime_version, "model": self.model,
                "reasoning_effort": self.reasoning_effort, "differing_fields": self.differing_fields}


def compare_provider_health_receipt(expected: object, observed: object, *, now: int) -> ProviderHealthReceiptComparison:
    """Rehydrate and compare redacted receipt evidence without any adapter hook."""
    try:
        from .provider_health import HealthState, ProviderHealthReceipt
        if type(expected) is not dict or type(observed) is not dict or type(now) is not int:
            raise ValueError
        left, right = ProviderHealthReceipt.from_evidence(expected), ProviderHealthReceipt.from_evidence(observed)
        identity = left.audit_identity
        result = ProviderHealthReceiptComparison(left.case_id, ComparisonOutcome.MATCH, left.contract_commit, left.candidate_sha, left.profile_identity, left.receipt_digest, identity.audit.sdk_version, identity.audit.runtime_version, identity.profile.model, identity.profile.reasoning_effort.value)
        if left.observation.state is not HealthState.READY or not left.observation.is_fresh_at(now) or right.observation.state is not HealthState.READY or not right.observation.is_fresh_at(now):
            return ProviderHealthReceiptComparison("invalid", ComparisonOutcome.INVALID, "", None, "", "", differing_fields=("invalid-evidence",))
        if left == right:
            return result
        fields = ("contract_commit", "candidate_sha", "case_id", "selection_ordinal", "configuration", "role", "profile_identity", "observation", "audit_identity", "receipt_digest")
        differing = tuple(name for name in fields if getattr(left, name) != getattr(right, name))
        return ProviderHealthReceiptComparison(left.case_id, ComparisonOutcome.MISMATCH, left.contract_commit, left.candidate_sha, left.profile_identity, left.receipt_digest, identity.audit.sdk_version, identity.audit.runtime_version, identity.profile.model, identity.profile.reasoning_effort.value, differing)
    except Exception:
        return ProviderHealthReceiptComparison("invalid", ComparisonOutcome.INVALID, "", None, "", "", differing_fields=("invalid-evidence",))


def rehydrate_live_provider_health_evidence(evidence: object) -> tuple["ProviderHealthReceipt", ...]:
    """Safely consume the exact JSON shape emitted by the opt-in fixture.

    JSON changes tuples to lists, so this boundary normalizes only built-in
    JSON containers before handing each immutable receipt to its canonical
    verifier.  It never invokes an adapter, hook, or provider.
    """

    def normalize(value: object) -> object:
        if type(value) is list:
            return tuple(normalize(item) for item in value)
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise ValueError
            return {key: normalize(item) for key, item in value.items()}
        if type(value) in {str, int, bool, type(None)}:
            return value
        raise ValueError

    try:
        from .provider_health import ProviderHealthReceipt, ProviderHealthObservation, required_provider_selections
        from .runtime_binding import RuntimeBinding
        required = {"schema", "ready_at", "ready", "status", "contract_commit", "candidate_sha", "case_id", "report", "receipts", "receipt_digests", "manifest"}
        if type(evidence) is not dict or set(evidence) != required or evidence["schema"] != "roundwright-live-provider-health/v1" or type(evidence["ready_at"]) is not int or evidence["ready"] is not True or evidence["status"] != "ready":
            raise ValueError
        value = normalize(evidence)
        if type(value) is not dict or type(value["report"]) is not dict or set(value["report"]) != {"health_contract_identity", "configuration", "selections", "observations"} or type(value["receipts"]) is not tuple or type(value["receipt_digests"]) is not tuple or type(value["manifest"]) is not dict:
            raise ValueError
        manifest = value["manifest"]
        manifest_keys = {"schema", "shadow_case_identity", "reference_identity", "comparator_version", "normalizer_version", "environment_identity", "retention_identity", "bundle_digest"}
        payload = {key: item for key, item in value.items() if key != "manifest"}
        frozen_manifest = {key: item for key, item in manifest.items() if key != "bundle_digest"}
        if set(manifest) != manifest_keys or manifest["schema"] != "roundwright-live-provider-health-manifest/v1" or manifest["comparator_version"] != "provider-health-receipt/v1" or manifest["normalizer_version"] != "roundwright-json-tuples/v1" or manifest["environment_identity"] != "native-read-only" or manifest["retention_identity"] != "orchestrator-capture-required" or type(manifest["bundle_digest"]) is not str or manifest["bundle_digest"] != _live_digest({"payload": payload, "manifest": frozen_manifest}):
            raise ValueError
        receipts = tuple(ProviderHealthReceipt.from_evidence(item) for item in value["receipts"])
        report = value["report"]
        selections, observations = report["selections"], report["observations"]
        columns = report["configuration"]
        if type(columns) is not tuple or len(columns) != 9 or type(columns[3]) is not str:
            raise ValueError
        supervisor_profiles = json.loads(columns[3])
        if type(supervisor_profiles) is not list or not supervisor_profiles or any(type(item) is not str for item in supervisor_profiles) or json.dumps(supervisor_profiles, separators=(",", ":")) != columns[3]:
            raise ValueError
        binding = RuntimeBinding(columns[0], columns[1], columns[2], tuple(supervisor_profiles), *columns[4:])
        shadow_case_identity = _live_digest({"contract_commit": value["contract_commit"], "candidate_sha": value["candidate_sha"], "case_id": value["case_id"], "configuration": binding.complete_columns()})
        reference_identity = _live_digest({"schema": "roundwright-live-provider-health-reference/v1", "contract_commit": value["contract_commit"], "candidate_sha": value["candidate_sha"], "case_id": value["case_id"], "report": report, "receipt_digests": value["receipt_digests"]})
        if manifest["shadow_case_identity"] != shadow_case_identity or manifest["reference_identity"] != reference_identity:
            raise ValueError
        if report["health_contract_identity"] != receipts[0].observation.health_contract_identity or tuple((item[0], item[1], item[2]) for item in selections) != tuple((ordinal, role.value, profile) for ordinal, role, profile in required_provider_selections(binding)):
            raise ValueError
        if not receipts or len(receipts) != len(selections) or len(receipts) != len(observations) or len(receipts) != len(value["receipt_digests"]):
            raise ValueError
        for ordinal, (selection, raw_observation, receipt, digest) in enumerate(zip(selections, observations, receipts, value["receipt_digests"], strict=True)):
            if type(selection) is not tuple or len(selection) != 3 or selection[0] != ordinal or type(digest) is not str or receipt.receipt_digest != digest:
                raise ValueError
            observation = ProviderHealthObservation.from_evidence(raw_observation)
            if (receipt.contract_commit, receipt.candidate_sha, receipt.case_id, receipt.selection_ordinal, receipt.role.value, receipt.profile_identity, receipt.observation) != (value["contract_commit"], value["candidate_sha"], value["case_id"], ordinal, selection[1], selection[2], observation) or observation.health_contract_identity != report["health_contract_identity"]:
                raise ValueError
            binding.require_matches(receipt.configuration)
            receipt.authorize(binding, receipt.role, receipt.profile_identity, contract_commit=value["contract_commit"], candidate_sha=value["candidate_sha"], case_id=value["case_id"], now=value["ready_at"])
        return receipts
    except Exception as error:
        raise ShadowError("live provider health evidence is invalid") from error


def _live_digest(value: object) -> str:
    return "sha256:" + _digest(value)


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


# Shadow v2 is deliberately isolated from the historical v1 state-machine
# replay above.  v1 continues to own the synthetic six-state fixtures used by
# already-retained evidence; a terminal snapshot must never be coerced into
# that older shape.
SHADOW_CASE_SCHEMA_V2 = "roundwright-shadow-case/v2"
PROVENANCE_DECISION_PROFILE = "roundwright-shadow-profile/provenance-decision/v1"
_V2_TOKEN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_V2_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_V2_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}\Z")
_ROUNDLET_RETENTION_ID = re.compile(r"roundlet-local:[0-9a-f]{32}/(?:rehearsal|final)-[0-9a-f]{40}\Z")


def _safe_v2_token(value: object) -> bool:
    if type(value) is not str or not _V2_TOKEN.fullmatch(value):
        return False
    lowered = value.lower()
    return not any(term in lowered for term in ("token", "secret", "credential", "password", "ghp_")) and not lowered.startswith("sk-")


def _safe_profile_id(value: object) -> bool:
    if type(value) is not str or not re.fullmatch(r"roundwright-shadow-profile/[a-z0-9][a-z0-9._-]{0,127}/v[1-9][0-9]*", value):
        return False
    return _safe_v2_token(value.replace("/", "-"))


def _safe_repository(value: object) -> bool:
    return type(value) is str and _V2_REPOSITORY.fullmatch(value) is not None


def _safe_roundlet_retention_identity(value: object) -> bool:
    return _parse_roundlet_retention_identity(value) is not None


def _parse_roundlet_retention_identity(value: object) -> tuple[str, str, str] | None:
    """Return the closed public-safe retention run, mode, and candidate tuple."""

    if type(value) is not str or _ROUNDLET_RETENTION_ID.fullmatch(value) is None:
        return None
    prefix, tail = value.removeprefix("roundlet-local:").split("/", 1)
    mode, candidate = tail.split("-", 1)
    return prefix, mode, candidate


def _is_v2_digest(value: object) -> bool:
    return type(value) is str and _V2_DIGEST.fullmatch(value) is not None


def _v2_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _strict_json_object(value: bytes, label: str) -> dict[str, object]:
    """Decode one external object without duplicate keys or non-finite constants."""

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise ValueError
            result[key] = item
        return result
    try:
        decoded = json.loads(
            value.decode("utf-8"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ProvenanceRecordError(f"{label} is invalid") from error
    if type(decoded) is not dict:
        raise ProvenanceRecordError(f"{label} is invalid")
    return decoded


class ShadowV2Error(ShadowError):
    """Raised when profile-defined terminal evidence is incomplete or mixed."""


class CaptureMode(StrEnum):
    TERMINAL_SNAPSHOT = "terminal-snapshot"
    LIFECYCLE_GRAPH = "lifecycle-graph"


class ShadowProducer(StrEnum):
    DURABLE_PROVENANCE = "durable-provenance"
    PROFILE_DEFINED = "profile-defined"


@dataclass(frozen=True)
class ShadowEvidenceProfile:
    """One closed Phase-3 evidence profile and its capture-readiness contract."""

    profile_id: str
    capture_mode: CaptureMode
    producer: ShadowProducer
    readiness_point: str
    arm_before: str
    retention_readback_contract: str
    missing_history_recapture: str
    event_kinds: tuple[str, ...]
    minimum_commits: int = 0
    maximum_commits: int = 0
    requires_accepted_result: bool = False

    def __post_init__(self) -> None:
        if (
            not _safe_profile_id(self.profile_id)
            or type(self.capture_mode) is not CaptureMode
            or type(self.producer) is not ShadowProducer
            or any(not _safe_v2_token(value) for value in (
                self.readiness_point,
                self.arm_before,
                self.retention_readback_contract,
                self.missing_history_recapture,
            ))
            or type(self.event_kinds) is not tuple
            or not self.event_kinds
            or any(not _safe_v2_token(value) for value in self.event_kinds)
            or len(set(self.event_kinds)) != len(self.event_kinds)
            or type(self.minimum_commits) is not int
            or type(self.maximum_commits) is not int
            or self.minimum_commits < 0
            or self.maximum_commits < self.minimum_commits
            or type(self.requires_accepted_result) is not bool
        ):
            raise ShadowV2Error("shadow evidence profile is invalid")
        if self.profile_id == PROVENANCE_DECISION_PROFILE and (
            self.capture_mode is not CaptureMode.TERMINAL_SNAPSHOT
            or self.producer is not ShadowProducer.DURABLE_PROVENANCE
            or self.event_kinds != ("provenance-decision",)
            or self.minimum_commits != 0
            or self.maximum_commits != 0
            or self.requires_accepted_result
        ):
            raise ShadowV2Error("provenance evidence profile is invalid")


_PROVENANCE_PROFILE = ShadowEvidenceProfile(
    PROVENANCE_DECISION_PROFILE,
    CaptureMode.TERMINAL_SNAPSHOT,
    ShadowProducer.DURABLE_PROVENANCE,
    "schema-profile-exporter-comparator-recorder-store-readback-bound",
    "before-terminal-provenance-export",
    "append-only-content-addressed-readback",
    "candidate-movement-requires-fresh-terminal-capture",
    ("provenance-decision",),
)


def shadow_evidence_profiles() -> tuple[ShadowEvidenceProfile, ...]:
    """Return the closed registry; later leaves cannot silently add a profile."""

    return (_PROVENANCE_PROFILE,)


def shadow_evidence_profile(profile_id: str) -> ShadowEvidenceProfile:
    if profile_id != PROVENANCE_DECISION_PROFILE:
        raise ShadowV2Error("shadow evidence profile is unavailable")
    return _PROVENANCE_PROFILE


@dataclass(frozen=True)
class PublicArtifactReference:
    """One path-free, content-addressed artifact or executable reference."""

    kind: str
    digest: str

    def __post_init__(self) -> None:
        if not _safe_v2_token(self.kind) or not _is_v2_digest(self.digest):
            raise ShadowV2Error("public artifact reference is invalid")


@dataclass(frozen=True)
class ProvenanceDecision:
    """Typed, public-safe export of a durable candidate provenance decision."""

    repository: str
    task_id: str
    base_sha: str
    candidate_sha: str
    policy_fingerprint: str
    dependency_fingerprint: str
    entrypoint_fingerprint: str
    artifacts: tuple[PublicArtifactReference, ...]
    gate_identity: str
    blocker: str | None
    next_action: str
    ready_at: int
    decision_digest: str = ""

    def __post_init__(self) -> None:
        if (
            not _safe_repository(self.repository)
            or not _safe_v2_token(self.task_id)
            or not _SHA1.fullmatch(self.base_sha)
            or not _SHA1.fullmatch(self.candidate_sha)
            or not all(_is_v2_digest(value) for value in (
                self.policy_fingerprint,
                self.dependency_fingerprint,
                self.entrypoint_fingerprint,
            ))
            or type(self.artifacts) is not tuple
            or not self.artifacts
            or any(type(item) is not PublicArtifactReference for item in self.artifacts)
            or len({item.kind for item in self.artifacts}) != len(self.artifacts)
            or not _safe_v2_token(self.gate_identity)
            or (self.blocker is not None and not _safe_v2_token(self.blocker))
            or not _safe_v2_token(self.next_action)
            or type(self.ready_at) is not int
            or self.ready_at < 0
        ):
            raise ShadowV2Error("provenance decision is invalid")
        digest = _v2_digest(self._payload())
        if self.decision_digest and self.decision_digest != digest:
            raise ShadowV2Error("provenance decision digest does not match immutable content")
        object.__setattr__(self, "decision_digest", digest)

    def _payload(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "task_id": self.task_id,
            "base_sha": self.base_sha,
            "candidate_sha": self.candidate_sha,
            "policy_fingerprint": self.policy_fingerprint,
            "dependency_fingerprint": self.dependency_fingerprint,
            "entrypoint_fingerprint": self.entrypoint_fingerprint,
            "artifacts": tuple((item.kind, item.digest) for item in self.artifacts),
            "gate_identity": self.gate_identity,
            "blocker": self.blocker,
            "next_action": self.next_action,
            "ready_at": self.ready_at,
        }

    def curated_summary(self) -> dict[str, object]:
        return {
            "repository": self.repository,
            "task": _public_identifier(self.task_id),
            "base": self.base_sha,
            "candidate": self.candidate_sha,
            "policy": self.policy_fingerprint,
            "dependency": self.dependency_fingerprint,
            "entrypoint": self.entrypoint_fingerprint,
            "artifacts": tuple((item.kind, item.digest) for item in self.artifacts),
            "gate": _public_identifier(self.gate_identity),
            "blocker": None if self.blocker is None else _public_identifier(self.blocker),
            "next_action": _public_identifier(self.next_action),
            "ready_at": self.ready_at,
            "decision_digest": self.decision_digest,
        }


PROVENANCE_RECORD_SCHEMA = "roundwright-provenance-record/v1"


class ProvenanceRecordError(ShadowV2Error):
    """Raised when production provenance cannot be sealed or read back."""


EXTERNAL_SELECTION_CONTROL_SCHEMA = "roundwright-provenance-selection-control/v1"
EXTERNAL_SELECTION_RECEIPT_SCHEMA = "roundwright-provenance-selection-control-receipt/v1"
_EXTERNAL_SELECTION_CONTROL_SEAL = object()
_VERIFIED_PROVENANCE_SELECTION_SEAL = object()


@dataclass(frozen=True)
class ExternalSelectionControlExpectation:
    run_id: str
    contract_id: str
    orchestrator_task: str
    repository: str
    task_id: str
    base_sha: str
    candidate_sha: str
    candidate_tree: str
    leaf: int
    route: str
    schema: str
    profile: str
    authority_agents_blob: str
    skill_blob: str
    qualification_blob: str
    payload_digest: str
    receipt_digest: str
    contract_digest: str
    origin_tree: str
    authority_block_digest: str
    live_leaf: tuple[object, ...]
    owner_instructions: tuple[tuple[object, ...], ...]


@dataclass(frozen=True, init=False)
class ExternalSelectionControl:
    """Loaded pinned control; seals prevent accidental API misuse, not process compromise."""

    payload_digest: str
    receipt_digest: str
    contract_digest: str
    retention_identity: str
    mode: str
    capture_ready: bool
    payload: bytes
    receipt: bytes
    expected: ExternalSelectionControlExpectation
    _load_fingerprint: str
    _load_seal: object

    def __init__(self, *arguments: object, **keywords: object) -> None:
        raise TypeError("external selection controls are loaded from pinned bytes only")

    @property
    def terminal_ready(self) -> bool:
        return getattr(self, "mode", None) == "FINAL" and getattr(self, "capture_ready", None) is True

    def verify_loaded(self) -> None:
        """Revalidate the load seal before a FINAL consumer can act."""

        if type(self) is not ExternalSelectionControl or getattr(self, "_load_seal", None) is not _EXTERNAL_SELECTION_CONTROL_SEAL:
            raise ProvenanceRecordError("external selection control was not loaded")
        if type(self.expected) is not ExternalSelectionControlExpectation:
            raise ProvenanceRecordError("external selection control seal is invalid")
        try:
            reloaded = ExternalSelectionControl.load(self.payload, self.receipt, self.expected)
        except (ProvenanceRecordError, TypeError) as error:
            raise ProvenanceRecordError("external selection control seal is invalid") from error
        if (
            (self.payload_digest, self.receipt_digest, self.contract_digest, self.retention_identity,
             self.mode, self.capture_ready, self.expected) !=
            (reloaded.payload_digest, reloaded.receipt_digest, reloaded.contract_digest, reloaded.retention_identity,
             reloaded.mode, reloaded.capture_ready, reloaded.expected)
            or self._load_fingerprint != reloaded._load_fingerprint
        ):
            raise ProvenanceRecordError("external selection control seal is invalid")

    @classmethod
    def load(cls, payload_bytes: bytes, receipt_bytes: bytes, expected: ExternalSelectionControlExpectation) -> "ExternalSelectionControl":
        if type(payload_bytes) is not bytes or type(receipt_bytes) is not bytes or type(expected) is not ExternalSelectionControlExpectation:
            raise ProvenanceRecordError("external selection control is invalid")
        payload = _strict_json_object(payload_bytes, "external selection control")
        receipt = _strict_json_object(receipt_bytes, "external selection control receipt")
        digest = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()
        receipt_digest = "sha256:" + hashlib.sha256(receipt_bytes).hexdigest()
        if digest != expected.payload_digest or receipt_digest != expected.receipt_digest:
            raise ProvenanceRecordError("external selection control bytes are not pinned")
        if set(receipt) != {"append_only", "capture_ready", "contract_sha256", "control_mode", "payload_bytes", "payload_sha256", "read_back", "retention_identity", "schema"}:
            raise ProvenanceRecordError("external selection control receipt is invalid")
        retention = _parse_roundlet_retention_identity(receipt.get("retention_identity"))
        if receipt.get("schema") != EXTERNAL_SELECTION_RECEIPT_SCHEMA or receipt.get("payload_sha256") != digest or receipt.get("payload_bytes") != len(payload_bytes) or receipt.get("contract_sha256") != expected.contract_digest or receipt.get("read_back") != "VERIFIED" or receipt.get("append_only") is not True or retention is None:
            raise ProvenanceRecordError("external selection control receipt is invalid")
        selection = payload.get("selection")
        authority = payload.get("authority")
        roundlet = payload.get("roundlet")
        if type(selection) is not dict or type(authority) is not dict or type(roundlet) is not dict or payload.get("schema") != EXTERNAL_SELECTION_CONTROL_SCHEMA:
            raise ProvenanceRecordError("external selection control is invalid")
        origin = authority.get("origin_main")
        external = authority.get("external_validation_contract")
        active = authority.get("active_roundlet_block")
        if type(origin) is not dict or type(external) is not dict or type(active) is not dict:
            raise ProvenanceRecordError("external selection control authority is invalid")
        leaf = authority.get("live_leaf")
        instructions = authority.get("owner_instructions")
        checks = (
            roundlet.get("run_id") == expected.run_id, roundlet.get("contract_id") == expected.contract_id, roundlet.get("orchestrator_task") == expected.orchestrator_task,
            selection.get("repository") == expected.repository, selection.get("worker_task") == expected.task_id,
            selection.get("base_sha") == expected.base_sha, selection.get("candidate_sha") == expected.candidate_sha,
            selection.get("candidate_tree") == expected.candidate_tree, selection.get("active_leaf") == expected.leaf,
            selection.get("route") == expected.route, selection.get("case_schema") == expected.schema,
            selection.get("evidence_profile") == expected.profile, origin.get("commit") == expected.base_sha, origin.get("tree") == expected.origin_tree,
            active.get("agents_blob") == expected.authority_agents_blob, active.get("block_sha256") == expected.authority_block_digest,
            external.get("skill_blob") == expected.skill_blob, external.get("qualification_blob") == expected.qualification_blob,
            type(leaf) is dict and tuple(leaf.get(key) for key in ("issue_database_id", "issue_node_id", "number", "updated_at", "body_sha256")) == expected.live_leaf,
            type(instructions) is list and all(type(item) is dict for item in instructions) and tuple(tuple(item.get(key) for key in ("comment_id", "comment_node_id", "body_sha256")) for item in instructions) == expected.owner_instructions,
        )
        if not all(checks):
            raise ProvenanceRecordError("external selection control binding is invalid")
        mode = payload.get("control_mode")
        ready = payload.get("capture_ready")
        if (
            mode not in {"REHEARSAL", "FINAL"}
            or type(ready) is not bool
            or not re.fullmatch(r"[0-9a-f]{32}", expected.run_id)
            or roundlet.get("run_id") != expected.run_id
            or receipt.get("control_mode") != mode
            or receipt.get("capture_ready") is not ready
            or retention != (expected.run_id, mode.lower(), selection["candidate_sha"])
        ):
            raise ProvenanceRecordError("external selection control mode is invalid")
        value = object.__new__(cls)
        for name, item in {
            "payload_digest": digest, "receipt_digest": receipt_digest,
            "contract_digest": expected.contract_digest, "retention_identity": receipt["retention_identity"],
            "mode": mode, "capture_ready": ready, "payload": bytes(payload_bytes),
            "receipt": bytes(receipt_bytes), "expected": expected,
        }.items():
            object.__setattr__(value, name, item)
        object.__setattr__(value, "_load_fingerprint", _v2_digest({
            "payload_digest": digest, "receipt_digest": receipt_digest,
            "contract_digest": expected.contract_digest, "retention_identity": receipt["retention_identity"],
            "mode": mode, "capture_ready": ready, "expected": expected.__dict__,
        }))
        object.__setattr__(value, "_load_seal", _EXTERNAL_SELECTION_CONTROL_SEAL)
        return value


@dataclass(frozen=True)
class NamedContentIdentity:
    """A path-free named digest from the strict receipt verifier output."""

    name: str
    digest: str
    version: str | None = None

    def __post_init__(self) -> None:
        if not _safe_v2_token(self.name) or not _is_v2_digest(self.digest) or (self.version is not None and not _safe_v2_token(self.version)):
            raise ProvenanceRecordError("named toolchain content identity is invalid")


def _canonical_named_identities(
    value: object, names: tuple[str, ...], *, tools: bool = False,
) -> tuple[NamedContentIdentity, ...]:
    if (
        type(value) is not tuple
        or len(value) != len(names)
        or any(type(item) is not NamedContentIdentity for item in value)
        or tuple(item.name for item in value) != names
        or any((item.version is None) if tools else (item.version is not None) for item in value)
    ):
        raise ProvenanceRecordError("named toolchain content identities are incomplete")
    return value


@dataclass(frozen=True)
class VerifiedValidationToolchainProjection:
    """Public-safe result already verified by the locked toolchain receipt verifier."""

    lock_digest: str
    cache_key: str
    receipt_digest: str
    requirements: tuple[NamedContentIdentity, ...]
    environments: tuple[NamedContentIdentity, ...]
    tools: tuple[NamedContentIdentity, ...]
    requirements_fingerprint: str = ""
    environments_fingerprint: str = ""
    tools_fingerprint: str = ""
    projection_fingerprint: str = ""

    def __post_init__(self) -> None:
        if not _is_v2_digest(self.lock_digest) or not _safe_v2_token(self.cache_key) or not _is_v2_digest(self.receipt_digest):
            raise ProvenanceRecordError("verified validation toolchain projection is invalid")
        requirements = _canonical_named_identities(self.requirements, ("build", "pipx"))
        environments = _canonical_named_identities(self.environments, ("python", "build", "pipx"))
        tools = _canonical_named_identities(self.tools, ("uv", "managed_python", "python", "pipx"), tools=True)
        requirement_fingerprint = _v2_digest(tuple((item.name, item.digest) for item in requirements))
        environment_fingerprint = _v2_digest(tuple((item.name, item.digest) for item in environments))
        tool_fingerprint = _v2_digest(tuple((item.name, item.version, item.digest) for item in tools))
        for supplied, derived in (
            (self.requirements_fingerprint, requirement_fingerprint),
            (self.environments_fingerprint, environment_fingerprint),
            (self.tools_fingerprint, tool_fingerprint),
        ):
            if supplied and supplied != derived:
                raise ProvenanceRecordError("verified validation toolchain projection fingerprint is invalid")
        payload = {
            "lock_digest": self.lock_digest,
            "cache_key": self.cache_key,
            "receipt_digest": self.receipt_digest,
            "requirements": tuple((item.name, item.digest) for item in requirements),
            "environments": tuple((item.name, item.digest) for item in environments),
            "tools": tuple((item.name, item.version, item.digest) for item in tools),
        }
        fingerprint = _v2_digest(payload)
        if self.projection_fingerprint and self.projection_fingerprint != fingerprint:
            raise ProvenanceRecordError("verified validation toolchain projection fingerprint is invalid")
        object.__setattr__(self, "requirements_fingerprint", requirement_fingerprint)
        object.__setattr__(self, "environments_fingerprint", environment_fingerprint)
        object.__setattr__(self, "tools_fingerprint", tool_fingerprint)
        object.__setattr__(self, "projection_fingerprint", fingerprint)

    def public_payload(self) -> dict[str, object]:
        return {
            "lock_digest": self.lock_digest,
            "cache_key": self.cache_key,
            "receipt_digest": self.receipt_digest,
            "requirements": {item.name: item.digest for item in self.requirements},
            "environments": {item.name: item.digest for item in self.environments},
            "tools": {item.name: {"version": item.version, "digest": item.digest} for item in self.tools},
        }


@dataclass(frozen=True)
class CandidateArtifactProjection:
    """Actual candidate source, package, and installed entrypoint identities."""

    repository: str
    task_id: str
    candidate_sha: str
    candidate_tree: str
    source_identity: str
    source_digest: str
    package_digest: str
    installed_entrypoint_digest: str
    projection_fingerprint: str = ""

    def __post_init__(self) -> None:
        if (
            not _safe_repository(self.repository)
            or not _safe_v2_token(self.task_id)
            or not _SHA1.fullmatch(self.candidate_sha)
            or not _SHA1.fullmatch(self.candidate_tree)
            or not _safe_v2_token(self.source_identity)
            or not all(_is_v2_digest(value) for value in (
                self.source_digest, self.package_digest,
                self.installed_entrypoint_digest,
            ))
        ):
            raise ProvenanceRecordError("candidate artifact projection is invalid")
        fingerprint = _v2_digest(self._payload())
        if self.projection_fingerprint and self.projection_fingerprint != fingerprint:
            raise ProvenanceRecordError("candidate artifact projection fingerprint is invalid")
        object.__setattr__(self, "projection_fingerprint", fingerprint)

    def _payload(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "task_id": self.task_id,
            "candidate_sha": self.candidate_sha,
            "candidate_tree": self.candidate_tree,
            "source_identity": self.source_identity,
            "source_digest": self.source_digest,
            "package_digest": self.package_digest,
            "installed_entrypoint_digest": self.installed_entrypoint_digest,
        }


@dataclass(frozen=True)
class ReviewedGitObservation:
    """Reviewed Git identity tied to the sealed Git entrypoint binding."""

    repository: str
    task_id: str
    candidate_sha: str
    binding_fingerprint: str
    identifier: str
    source_identity: str
    source_class: str
    normalized_version: str
    reported_version: str
    artifact_digest: str
    executable_digest: str
    control_fingerprint: str
    observation_fingerprint: str = ""

    def __post_init__(self) -> None:
        if (
            not _safe_repository(self.repository)
            or not _safe_v2_token(self.task_id)
            or not _SHA1.fullmatch(self.candidate_sha)
            or not all(_is_v2_digest(value) for value in (
                self.binding_fingerprint, self.executable_digest,
                self.artifact_digest, self.control_fingerprint,
            ))
            or not _safe_v2_token(self.identifier)
            or not _safe_v2_token(self.source_identity)
            or not _safe_v2_token(self.source_class)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.normalized_version)
            or not _safe_v2_token(self.reported_version)
        ):
            raise ProvenanceRecordError("reviewed Git observation is invalid")
        fingerprint = _v2_digest(self._payload())
        if self.observation_fingerprint and self.observation_fingerprint != fingerprint:
            raise ProvenanceRecordError("reviewed Git observation fingerprint is invalid")
        object.__setattr__(self, "observation_fingerprint", fingerprint)

    def _payload(self) -> dict[str, str]:
        return {
            "repository": self.repository,
            "task_id": self.task_id,
            "candidate_sha": self.candidate_sha,
            "binding_fingerprint": self.binding_fingerprint,
            "identifier": self.identifier,
            "source_identity": self.source_identity,
            "source_class": self.source_class,
            "normalized_version": self.normalized_version,
            "reported_version": self.reported_version,
            "artifact_digest": self.artifact_digest,
            "executable_digest": self.executable_digest,
            "control_fingerprint": self.control_fingerprint,
        }


@dataclass(frozen=True, init=False)
class VerifiedProvenanceSelection:
    """Immutable skeleton retained only after later FINAL-control reconciliation."""

    payload_digest: str
    receipt_digest: str
    contract_digest: str
    retention_identity: str
    selection_at: int
    candidate_fingerprint: str
    validation_fingerprint: str
    git_fingerprint: str
    control_fingerprint: str
    selection_fingerprint: str
    external_load_fingerprint: str
    _loaded_control: ExternalSelectionControl
    _reconciliation_fingerprint: str
    _reconciliation_seal: object

    def __init__(self, *arguments: object, **keywords: object) -> None:
        raise TypeError("verified provenance selections are produced by reconciliation only")

    @classmethod
    def _from_reconciliation(
        cls, *, payload_digest: str, receipt_digest: str, contract_digest: str,
        retention_identity: str, selection_at: int, candidate_fingerprint: str,
        validation_fingerprint: str, git_fingerprint: str, control_fingerprint: str,
        loaded_control: ExternalSelectionControl,
    ) -> "VerifiedProvenanceSelection":
        value = object.__new__(cls)
        for name, item in {
            "payload_digest": payload_digest,
            "receipt_digest": receipt_digest,
            "contract_digest": contract_digest,
            "retention_identity": retention_identity,
            "selection_at": selection_at,
            "candidate_fingerprint": candidate_fingerprint,
            "validation_fingerprint": validation_fingerprint,
            "git_fingerprint": git_fingerprint,
            "control_fingerprint": control_fingerprint,
        }.items():
            object.__setattr__(value, name, item)
        value._validate()
        object.__setattr__(value, "selection_fingerprint", _v2_digest(value._payload()))
        object.__setattr__(value, "external_load_fingerprint", loaded_control._load_fingerprint)
        object.__setattr__(value, "_loaded_control", loaded_control)
        object.__setattr__(value, "_reconciliation_fingerprint", _v2_digest({
            "selection": value.selection_fingerprint,
            "loaded_control": value.external_load_fingerprint,
        }))
        object.__setattr__(value, "_reconciliation_seal", _VERIFIED_PROVENANCE_SELECTION_SEAL)
        return value

    def _validate(self) -> None:
        if (
            not all(_is_v2_digest(value) for value in (
                self.payload_digest, self.receipt_digest, self.contract_digest,
                self.candidate_fingerprint, self.validation_fingerprint,
                self.git_fingerprint, self.control_fingerprint,
            ))
            or not _safe_roundlet_retention_identity(self.retention_identity)
            or type(self.selection_at) is not int
            or self.selection_at < 0
        ):
            raise ProvenanceRecordError("verified provenance selection is invalid")

    def verify_reconciliation(self) -> None:
        """Future durable consumers must reject naked or forged projections."""

        if type(self) is not VerifiedProvenanceSelection or getattr(self, "_reconciliation_seal", None) is not _VERIFIED_PROVENANCE_SELECTION_SEAL:
            raise ProvenanceRecordError("verified provenance selection is unsealed")
        self._validate()
        if (
            self.selection_fingerprint != _v2_digest(self._payload())
            or not _is_v2_digest(self.external_load_fingerprint)
            or self._reconciliation_fingerprint != _v2_digest({
                "selection": self.selection_fingerprint,
                "loaded_control": self.external_load_fingerprint,
            })
        ):
            raise ProvenanceRecordError("verified provenance selection is unsealed")

    def _payload(self) -> dict[str, object]:
        return {
            "payload_digest": self.payload_digest,
            "receipt_digest": self.receipt_digest,
            "contract_digest": self.contract_digest,
            "retention_identity": self.retention_identity,
            "selection_at": self.selection_at,
            "candidate_fingerprint": self.candidate_fingerprint,
            "validation_fingerprint": self.validation_fingerprint,
            "git_fingerprint": self.git_fingerprint,
            "control_fingerprint": self.control_fingerprint,
        }


def verify_selection_for_durable_record(
    loaded_control: object, selection: object,
) -> None:
    """Future durable storage must retain the original loaded external control."""

    if type(loaded_control) is not ExternalSelectionControl or type(selection) is not VerifiedProvenanceSelection:
        raise ProvenanceRecordError("durable provenance selection inputs are invalid")
    loaded_control.verify_loaded()
    selection.verify_reconciliation()
    if (
        selection._loaded_control is not loaded_control
        or selection.external_load_fingerprint != loaded_control._load_fingerprint
        or (selection.payload_digest, selection.receipt_digest, selection.contract_digest, selection.retention_identity) != (
            loaded_control.payload_digest, loaded_control.receipt_digest,
            loaded_control.contract_digest, loaded_control.retention_identity,
        )
    ):
        raise ProvenanceRecordError("durable provenance selection binding is invalid")


def _selection_payload(control: ExternalSelectionControl) -> dict[str, object]:
    return _strict_json_object(control.payload, "external selection control")


def _control_fingerprint(control: object, *, now: int) -> tuple[str, tuple[str, ...]]:
    from .dependency_policy import CandidateBinding, DependencyExecutionControl, DependencyPolicy, DependencyStage, ObservedDependency

    if type(control) is not DependencyExecutionControl or type(control.policy) is not DependencyPolicy:
        raise ProvenanceRecordError("dependency control is invalid")
    binding = control.policy.binding
    if type(binding) is not CandidateBinding or type(control.observations) is not tuple or not control.observations:
        raise ProvenanceRecordError("dependency control is invalid")
    observations = control.observations
    if (
        any(type(item) is not ObservedDependency or item.binding != binding or item.policy_digest != control.policy.policy_digest for item in observations)
        or len({item.component for item in observations}) != len(observations)
        or {item.component for item in observations} != {item.component for item in control.policy.components}
    ):
        raise ProvenanceRecordError("dependency observations are incomplete")
    try:
        control.require(binding, DependencyStage.GIT_ENTRYPOINT, now=now)
    except Exception as error:
        raise ProvenanceRecordError("dependency control is not admitted") from error
    canonical_observations = tuple(sorted(observations, key=lambda item: item.component.value))
    observation_fingerprints = tuple(item.fingerprint for item in canonical_observations)
    admission = control.admission
    fingerprint = _v2_digest({
        "binding": binding.fingerprint,
        "policy": control.policy.core_fingerprint,
        "observations": observation_fingerprints,
        "admission": (admission.policy_fingerprint, admission.receipt_digest, admission.reviewer_identity, admission.authority_digest),
    })
    return fingerprint, observation_fingerprints


def reconcile_final_provenance_selection(
    control: object,
    *,
    validation: object,
    artifacts: object,
    git_control: object,
    git_observation: object,
    dependency_control: object,
    now: int,
) -> VerifiedProvenanceSelection:
    """Reconcile one pinned FINAL external control without minting any authority."""

    from .dependency_policy import CandidateBinding, DependencyExecutionControl, DependencyStage
    from .git_identity import GitEntrypointControl

    if (
        type(control) is not ExternalSelectionControl
        or type(validation) is not VerifiedValidationToolchainProjection
        or type(artifacts) is not CandidateArtifactProjection
        or type(git_control) is not GitEntrypointControl
        or type(git_observation) is not ReviewedGitObservation
        or type(dependency_control) is not DependencyExecutionControl
        or type(now) is not int
        or now < 0
        or not control.terminal_ready
    ):
        raise ProvenanceRecordError("final provenance selection is unavailable")
    control.verify_loaded()
    payload = _selection_payload(control)
    selection = payload.get("selection")
    freshness = payload.get("freshness")
    if type(selection) is not dict or type(freshness) is not dict:
        raise ProvenanceRecordError("final provenance selection is invalid")
    expected_selection = {
        "repository", "worker_task", "base_sha", "candidate_sha", "candidate_tree", "active_leaf",
        "route", "case_schema", "evidence_profile", "capture_mode", "gate", "blocker", "next_action",
    }
    if set(selection) != expected_selection or set(freshness) != {"selection_at", "valid_until", "candidate_movement_invalidates"}:
        raise ProvenanceRecordError("final provenance selection is incomplete")
    if set(payload) != {
        "schema", "control_mode", "capture_ready", "roundlet", "selection", "authority",
        "control_contract_digest", "freshness", "validation_toolchain", "artifacts",
        "dependency_control", "public_safe_projection",
    }:
        raise ProvenanceRecordError("final provenance selection is incomplete")
    repository = selection["repository"]
    task_id = selection["worker_task"]
    base_sha = selection["base_sha"]
    candidate_sha = selection["candidate_sha"]
    candidate_tree = selection["candidate_tree"]
    selection_at = freshness["selection_at"]
    valid_until = freshness["valid_until"]
    if (
        not _safe_repository(repository) or not _safe_v2_token(task_id)
        or not all(_SHA1.fullmatch(value) for value in (base_sha, candidate_sha, candidate_tree))
        or (selection["repository"], selection["worker_task"], selection["base_sha"], selection["candidate_sha"],
            selection["candidate_tree"], selection["active_leaf"], selection["route"], selection["case_schema"],
            selection["evidence_profile"]) != (
            control.expected.repository, control.expected.task_id, control.expected.base_sha,
            control.expected.candidate_sha, control.expected.candidate_tree, control.expected.leaf,
            control.expected.route, control.expected.schema, control.expected.profile,
        )
        or selection["capture_mode"] != CaptureMode.TERMINAL_SNAPSHOT.value
        or selection["gate"] != "recorder-capture-readiness" or selection["blocker"] is not None
        or selection["next_action"] != "record-terminal-snapshot"
        or type(selection_at) is not int or type(valid_until) is not int or selection_at < 0 or valid_until < selection_at
        or freshness["candidate_movement_invalidates"] is not True or not selection_at <= now <= valid_until
    ):
        raise ProvenanceRecordError("final provenance selection is invalid")
    binding = dependency_control.policy.binding
    if (
        type(binding) is not CandidateBinding
        or (binding.repository, binding.task_id, binding.candidate_sha) != (repository, task_id, candidate_sha)
        or (artifacts.repository, artifacts.task_id, artifacts.candidate_sha, artifacts.candidate_tree) != (repository, task_id, candidate_sha, candidate_tree)
        or (git_control.binding.repository, git_control.binding.task_id, git_control.binding.candidate_sha) != (repository, task_id, candidate_sha)
        or git_control.dependency_control != dependency_control or git_control.now != selection_at
        or (git_observation.repository, git_observation.task_id, git_observation.candidate_sha) != (repository, task_id, candidate_sha)
        or git_observation.binding_fingerprint != binding.fingerprint
    ):
        raise ProvenanceRecordError("final provenance selection binding is invalid")
    try:
        git_control.dependency_control.require(git_control.binding, DependencyStage.GIT_ENTRYPOINT, now=selection_at)
    except Exception as error:
        raise ProvenanceRecordError("reviewed Git control is not admitted") from error
    dependency_fingerprint, observation_fingerprints = _control_fingerprint(dependency_control, now=selection_at)
    git_control_fingerprint = _v2_digest({
        "binding": git_control.binding.fingerprint,
        "dependency": dependency_fingerprint,
        "now": git_control.now,
    })
    if git_observation.control_fingerprint != git_control_fingerprint:
        raise ProvenanceRecordError("reviewed Git control does not match")
    package_observation = next((item for item in dependency_control.observations if item.component.value == "package"), None)
    git_dependency_observation = next((item for item in dependency_control.observations if item.component.value == "git-executable"), None)
    if (
        package_observation is None or git_dependency_observation is None
        or artifacts.source_identity != package_observation.source_identity
        or artifacts.package_digest != package_observation.artifact_digest
        or artifacts.installed_entrypoint_digest != package_observation.executable_digest
        or (git_observation.identifier, git_observation.source_identity, git_observation.normalized_version, git_observation.artifact_digest, git_observation.executable_digest) != (
            git_dependency_observation.identifier, git_dependency_observation.source_identity,
            git_dependency_observation.version, git_dependency_observation.artifact_digest,
            git_dependency_observation.executable_digest,
        )
    ):
        raise ProvenanceRecordError("reviewed dependency observations do not match")
    if payload.get("validation_toolchain") != validation.public_payload():
        raise ProvenanceRecordError("strict validation projection does not match")
    expected_artifacts = {
        "candidate_source": {"source_identity": artifacts.source_identity, "digest": artifacts.source_digest},
        "candidate_package": artifacts.package_digest,
        "installed_roundwright_entrypoint": artifacts.installed_entrypoint_digest,
        "reviewed_git_entrypoint": {
            "binding_fingerprint": git_observation.binding_fingerprint,
            "identifier": git_observation.identifier,
            "source_identity": git_observation.source_identity,
            "source_class": git_observation.source_class,
            "normalized_version": git_observation.normalized_version,
            "reported_version": git_observation.reported_version,
            "artifact_digest": git_observation.artifact_digest,
            "executable_digest": git_observation.executable_digest,
            "control_fingerprint": git_observation.control_fingerprint,
        },
    }
    if payload.get("artifacts") != expected_artifacts:
        raise ProvenanceRecordError("candidate artifact projection does not match")
    admission = dependency_control.admission
    expected_dependency = {
        "binding_fingerprint": binding.fingerprint,
        "policy_fingerprint": dependency_control.policy.core_fingerprint,
        "observations": [{"component": item.component.value, "fingerprint": item.fingerprint} for item in sorted(dependency_control.observations, key=lambda item: item.component.value)],
        "admission": {
            "policy_fingerprint": admission.policy_fingerprint,
            "receipt_digest": admission.receipt_digest,
            "reviewer_identity": admission.reviewer_identity,
            "authority_digest": admission.authority_digest,
        },
    }
    if payload.get("dependency_control") != expected_dependency:
        raise ProvenanceRecordError("dependency projection does not match")
    candidate_fingerprint = _v2_digest({
        "repository": repository, "task_id": task_id, "base_sha": base_sha,
        "candidate_sha": candidate_sha, "candidate_tree": candidate_tree,
        "artifacts": artifacts.projection_fingerprint,
    })
    expected_public = {
        "repository": repository, "task_id": task_id, "base_sha": base_sha,
        "candidate_sha": candidate_sha, "candidate_tree": candidate_tree,
        "route": selection["route"], "case_schema": selection["case_schema"],
        "evidence_profile": selection["evidence_profile"], "capture_mode": selection["capture_mode"],
        "gate": selection["gate"], "blocker": selection["blocker"], "next_action": selection["next_action"],
        "candidate_fingerprint": candidate_fingerprint, "validation_fingerprint": validation.projection_fingerprint,
        "dependency_fingerprint": dependency_fingerprint, "git_fingerprint": git_observation.observation_fingerprint,
    }
    if payload.get("public_safe_projection") != expected_public:
        raise ProvenanceRecordError("public-safe selection projection does not match")
    if payload.get("control_contract_digest") != control.contract_digest:
        raise ProvenanceRecordError("external control contract digest does not match")
    return VerifiedProvenanceSelection._from_reconciliation(
        payload_digest=control.payload_digest,
        receipt_digest=control.receipt_digest,
        contract_digest=control.contract_digest,
        retention_identity=control.retention_identity,
        selection_at=selection_at,
        candidate_fingerprint=candidate_fingerprint,
        validation_fingerprint=validation.projection_fingerprint,
        git_fingerprint=git_observation.observation_fingerprint,
        control_fingerprint=_v2_digest({"dependency": dependency_fingerprint, "git_control": git_control_fingerprint, "observations": observation_fingerprints}),
        loaded_control=control,
    )


@dataclass(frozen=True)
class DurableProvenanceRecord:
    """Legacy fixture-only record; never authority for the verified record store."""

    decision: ProvenanceDecision
    candidate_tree: str
    policy_fingerprint: str
    observation_fingerprints: tuple[str, ...]
    admission_digest: str
    record_digest: str = ""

    def __post_init__(self) -> None:
        if (
            type(self.decision) is not ProvenanceDecision
            or not _SHA1.fullmatch(self.candidate_tree)
            or not _is_v2_digest(self.policy_fingerprint)
            or type(self.observation_fingerprints) is not tuple
            or not self.observation_fingerprints
            or any(not _is_v2_digest(value) for value in self.observation_fingerprints)
            or len(set(self.observation_fingerprints)) != len(self.observation_fingerprints)
            or not _is_v2_digest(self.admission_digest)
        ):
            raise ProvenanceRecordError("durable provenance record is invalid")
        digest = _v2_digest(self.payload())
        if self.record_digest and self.record_digest != digest:
            raise ProvenanceRecordError("durable provenance record digest is invalid")
        object.__setattr__(self, "record_digest", digest)

    def payload(self) -> dict[str, object]:
        return {
            "schema": PROVENANCE_RECORD_SCHEMA,
            "decision": self.decision._payload(),
            "decision_digest": self.decision.decision_digest,
            "candidate_tree": self.candidate_tree,
            "policy_fingerprint": self.policy_fingerprint,
            "observation_fingerprints": self.observation_fingerprints,
            "admission_digest": self.admission_digest,
        }


VERIFIED_PROVENANCE_RECORD_SCHEMA = "roundwright-verified-provenance-record/v1"
_VERIFIED_PROVENANCE_RECORD_SEAL = object()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verified_record_document(payload: bytes) -> dict[str, object]:
    """Decode one closed, public-safe verified-record document."""

    value = _strict_json_object(payload, "verified provenance record")
    required = {
        "schema", "record_digest", "external", "selection", "fingerprints",
        "validation", "artifacts", "dependency",
    }
    if set(value) != required or value.get("schema") != VERIFIED_PROVENANCE_RECORD_SCHEMA:
        raise ProvenanceRecordError("verified provenance record is invalid")
    digest = value.get("record_digest")
    body = dict(value)
    body.pop("record_digest")
    if not _is_v2_digest(digest) or digest != _v2_digest(body) or _canonical_json_bytes(value) != payload:
        raise ProvenanceRecordError("verified provenance record is non-canonical")
    external = value["external"]
    selection = value["selection"]
    fingerprints = value["fingerprints"]
    validation = value["validation"]
    artifacts = value["artifacts"]
    dependency = value["dependency"]
    if not all(type(item) is dict for item in (external, selection, fingerprints, validation, artifacts, dependency)):
        raise ProvenanceRecordError("verified provenance record is invalid")
    if set(external) != {"payload_digest", "receipt_digest", "contract_digest", "retention_identity", "run_id", "contract_id", "orchestrator_task", "mode"} or set(selection) != {"repository", "task_id", "base_sha", "candidate_sha", "candidate_tree", "leaf", "route", "case_schema", "profile", "selection_at", "gate", "blocker", "next_action"} or set(fingerprints) != {"candidate", "validation", "artifacts", "dependency", "git", "control", "selection"}:
        raise ProvenanceRecordError("verified provenance record is incomplete")
    retention = _parse_roundlet_retention_identity(external.get("retention_identity"))
    if (
        retention is None
        or retention[0] != external.get("run_id")
        or retention[1] != external.get("mode")
        or external.get("mode") != "final"
        or retention[2] != selection.get("candidate_sha")
        or not all(_is_v2_digest(external.get(name)) for name in ("payload_digest", "receipt_digest", "contract_digest"))
        or not all(_is_v2_digest(fingerprints.get(name)) for name in fingerprints)
        or not _safe_v2_token(external.get("contract_id"))
        or not _safe_v2_token(external.get("orchestrator_task"))
        or not _safe_repository(selection.get("repository"))
        or not _safe_v2_token(selection.get("task_id"))
        or not all(_SHA1.fullmatch(selection.get(name, "")) for name in ("base_sha", "candidate_sha", "candidate_tree"))
        or type(selection.get("leaf")) is not int
        or selection["leaf"] <= 0
        or not _safe_v2_token(selection.get("route"))
        or selection.get("case_schema") != "roundwright-shadow-case/v2"
        or not _safe_profile_id(selection.get("profile"))
        or not all(_safe_v2_token(selection.get(name)) for name in ("gate", "next_action"))
        or selection.get("blocker") is not None
        or type(selection.get("selection_at")) is not int
        or selection["selection_at"] < 0
    ):
        raise ProvenanceRecordError("verified provenance record is invalid")
    if (
        set(validation) != {"lock_digest", "cache_key", "receipt_digest", "requirements", "environments", "tools"}
        or type(validation.get("requirements")) is not dict
        or type(validation.get("environments")) is not dict
        or type(validation.get("tools")) is not dict
        or set(validation["requirements"]) != {"build", "pipx"}
        or set(validation["environments"]) != {"python", "build", "pipx"}
        or set(validation["tools"]) != {"uv", "managed_python", "python", "pipx"}
        or set(artifacts) != {"candidate_source", "candidate_package", "installed_roundwright_entrypoint", "reviewed_git_entrypoint"}
        or type(artifacts.get("candidate_source")) is not dict
        or set(artifacts["candidate_source"]) != {"source_identity", "digest"}
        or type(artifacts.get("reviewed_git_entrypoint")) is not dict
        or set(artifacts["reviewed_git_entrypoint"]) != {"repository", "task_id", "candidate_sha", "binding_fingerprint", "identifier", "source_identity", "source_class", "normalized_version", "reported_version", "artifact_digest", "executable_digest", "control_fingerprint"}
    ):
        raise ProvenanceRecordError("verified provenance record is incomplete")
    try:
        verified_validation = VerifiedValidationToolchainProjection(
            validation["lock_digest"], validation["cache_key"], validation["receipt_digest"],
            tuple(NamedContentIdentity(name, validation["requirements"][name]) for name in ("build", "pipx")),
            tuple(NamedContentIdentity(name, validation["environments"][name]) for name in ("python", "build", "pipx")),
            tuple(NamedContentIdentity(name, validation["tools"][name]["digest"], validation["tools"][name]["version"]) for name in ("uv", "managed_python", "python", "pipx")),
        )
        verified_artifacts = CandidateArtifactProjection(
            selection["repository"], selection["task_id"], selection["candidate_sha"], selection["candidate_tree"],
            artifacts["candidate_source"]["source_identity"], artifacts["candidate_source"]["digest"],
            artifacts["candidate_package"], artifacts["installed_roundwright_entrypoint"],
        )
        reviewed = artifacts["reviewed_git_entrypoint"]
        verified_git = ReviewedGitObservation(
            reviewed["repository"], reviewed["task_id"], reviewed["candidate_sha"],
            reviewed["binding_fingerprint"], reviewed["identifier"], reviewed["source_identity"],
            reviewed["source_class"], reviewed["normalized_version"], reviewed["reported_version"],
            reviewed["artifact_digest"], reviewed["executable_digest"], reviewed["control_fingerprint"],
        )
    except (AttributeError, KeyError, TypeError, ValueError, ProvenanceRecordError) as error:
        raise ProvenanceRecordError("verified provenance record is invalid") from error
    if set(dependency) != {"binding_fingerprint", "policy_fingerprint", "policy_digest", "observations", "admission"} or not all(_is_v2_digest(dependency.get(name)) for name in ("binding_fingerprint", "policy_fingerprint", "policy_digest")) or type(dependency["observations"]) is not list or not dependency["observations"] or type(dependency["admission"]) is not dict or set(dependency["admission"]) != {"policy_fingerprint", "receipt_digest", "reviewer_identity", "authority_digest"} or not all(_is_v2_digest(value) for value in dependency["admission"].values()):
        raise ProvenanceRecordError("verified provenance record dependency is invalid")
    observation_keys = {"component", "identifier", "version", "source_identity", "artifact_digest", "executable_digest", "observed_at", "policy_digest", "fingerprint"}
    if any(type(item) is not dict or set(item) != observation_keys or not _safe_v2_token(item["component"]) or not _safe_v2_token(item["identifier"]) or not _safe_v2_token(item["source_identity"]) or not _safe_v2_token(item["version"]) or type(item["observed_at"]) is not int or item["observed_at"] < 0 or not all(_is_v2_digest(item[name]) for name in ("artifact_digest", "executable_digest", "policy_digest", "fingerprint")) for item in dependency["observations"]) or len({item["component"] for item in dependency["observations"]}) != len(dependency["observations"]):
        raise ProvenanceRecordError("verified provenance record observations are invalid")
    try:
        from .dependency_policy import CandidateBinding, DependencyComponent, DependencyPolicyError, ObservedDependency

        binding = CandidateBinding(selection["repository"], selection["task_id"], selection["candidate_sha"])
        observations = tuple(ObservedDependency(
            binding, DependencyComponent(item["component"]), item["identifier"], item["version"],
            item["source_identity"], item["artifact_digest"], item["executable_digest"],
            item["observed_at"], item["policy_digest"],
        ) for item in dependency["observations"])
    except (ValueError, TypeError, DependencyPolicyError) as error:
        raise ProvenanceRecordError("verified provenance record observations are invalid") from error
    canonical_observations = tuple(sorted(observations, key=lambda item: item.component.value))
    if (
        tuple(item.fingerprint for item in canonical_observations) != tuple(item["fingerprint"] for item in dependency["observations"])
        or any(item.policy_digest != dependency["policy_digest"] for item in observations)
        or dependency["binding_fingerprint"] != binding.fingerprint
        or dependency["admission"]["policy_fingerprint"] != dependency["policy_fingerprint"]
    ):
        raise ProvenanceRecordError("verified provenance record dependency is inconsistent")
    dependency_fingerprint = _v2_digest({"binding": binding.fingerprint, "policy": dependency["policy_fingerprint"], "observations": tuple(item.fingerprint for item in canonical_observations), "admission": tuple(dependency["admission"][name] for name in ("policy_fingerprint", "receipt_digest", "reviewer_identity", "authority_digest"))})
    git_control_fingerprint = _v2_digest({"binding": binding.fingerprint, "dependency": dependency_fingerprint, "now": selection["selection_at"]})
    package = next((item for item in observations if item.component.value == "package"), None)
    git_dependency = next((item for item in observations if item.component.value == "git-executable"), None)
    candidate_fingerprint = _v2_digest({"repository": selection["repository"], "task_id": selection["task_id"], "base_sha": selection["base_sha"], "candidate_sha": selection["candidate_sha"], "candidate_tree": selection["candidate_tree"], "artifacts": verified_artifacts.projection_fingerprint})
    selection_fingerprint = _v2_digest({"payload_digest": external["payload_digest"], "receipt_digest": external["receipt_digest"], "contract_digest": external["contract_digest"], "retention_identity": external["retention_identity"], "selection_at": selection["selection_at"], "candidate_fingerprint": candidate_fingerprint, "validation_fingerprint": verified_validation.projection_fingerprint, "git_fingerprint": verified_git.observation_fingerprint, "control_fingerprint": _v2_digest({"dependency": dependency_fingerprint, "git_control": git_control_fingerprint, "observations": tuple(item.fingerprint for item in canonical_observations)})})
    if (
        package is None or git_dependency is None
        or artifacts["candidate_source"] != {"source_identity": package.source_identity, "digest": verified_artifacts.source_digest}
        or artifacts["candidate_package"] != package.artifact_digest
        or artifacts["installed_roundwright_entrypoint"] != package.executable_digest
        or (verified_git.repository, verified_git.task_id, verified_git.candidate_sha, verified_git.binding_fingerprint, verified_git.identifier, verified_git.source_identity, verified_git.normalized_version, verified_git.artifact_digest, verified_git.executable_digest, verified_git.control_fingerprint) != (selection["repository"], selection["task_id"], selection["candidate_sha"], binding.fingerprint, git_dependency.identifier, git_dependency.source_identity, git_dependency.version, git_dependency.artifact_digest, git_dependency.executable_digest, git_control_fingerprint)
        or fingerprints != {"candidate": candidate_fingerprint, "validation": verified_validation.projection_fingerprint, "artifacts": verified_artifacts.projection_fingerprint, "dependency": dependency_fingerprint, "git": verified_git.observation_fingerprint, "control": _v2_digest({"dependency": dependency_fingerprint, "git_control": git_control_fingerprint, "observations": tuple(item.fingerprint for item in canonical_observations)}), "selection": selection_fingerprint}
    ):
        raise ProvenanceRecordError("verified provenance record projections are inconsistent")
    return value


@dataclass(frozen=True, init=False)
class VerifiedDurableProvenanceRecord:
    """A sealed public-safe projection produced only by FINAL reconciliation."""

    payload: bytes
    record_digest: str
    retention_identity: str
    candidate_sha: str
    _authority_fingerprint: str
    _materialization_seal: object

    def __init__(self, *arguments: object, **keywords: object) -> None:
        raise TypeError("verified durable records are materialized from a loaded control only")

    def verify(self) -> None:
        if type(self) is not VerifiedDurableProvenanceRecord or getattr(self, "_materialization_seal", None) is not _VERIFIED_PROVENANCE_RECORD_SEAL:
            raise ProvenanceRecordError("verified durable provenance record is unsealed")
        document = _verified_record_document(self.payload)
        if (self.record_digest, self.retention_identity, self.candidate_sha) != (document["record_digest"], document["external"]["retention_identity"], document["selection"]["candidate_sha"]):
            raise ProvenanceRecordError("verified durable provenance record is unsealed")
        if not _is_v2_digest(self._authority_fingerprint):
            raise ProvenanceRecordError("verified durable provenance record is unsealed")

    def public_projection(self) -> dict[str, object]:
        self.verify()
        return _strict_json_object(self.payload, "verified provenance record")


@dataclass(frozen=True, init=False)
class ReadBackVerifiedProvenanceRecord:
    """Canonical store projection; it is not authority until revalidated."""

    payload: bytes
    record_digest: str
    retention_identity: str
    candidate_sha: str

    def __init__(self, *arguments: object, **keywords: object) -> None:
        raise TypeError("read-back verified records are constructed by the store only")

    def public_projection(self) -> dict[str, object]:
        return _verified_record_document(self.payload)

    def verify_against(
        self, loaded_control: object, selection: object, *, validation: object, artifacts: object,
        git_control: object, git_observation: object, dependency_control: object, now: int,
    ) -> VerifiedDurableProvenanceRecord:
        rebuilt = materialize_verified_provenance_record(
            loaded_control, selection, validation=validation, artifacts=artifacts, git_control=git_control,
            git_observation=git_observation, dependency_control=dependency_control, now=now,
        )
        if rebuilt.payload != self.payload:
            raise ProvenanceRecordError("read-back provenance record does not match verified authority")
        return rebuilt


def _read_back_verified_record(payload: bytes) -> ReadBackVerifiedProvenanceRecord:
    document = _verified_record_document(payload)
    value = object.__new__(ReadBackVerifiedProvenanceRecord)
    object.__setattr__(value, "payload", bytes(payload))
    object.__setattr__(value, "record_digest", document["record_digest"])
    object.__setattr__(value, "retention_identity", document["external"]["retention_identity"])
    object.__setattr__(value, "candidate_sha", document["selection"]["candidate_sha"])
    return value


def materialize_verified_provenance_record(
    loaded_control: object, selection: object, *, validation: object, artifacts: object,
    git_control: object, git_observation: object, dependency_control: object, now: int,
) -> VerifiedDurableProvenanceRecord:
    """Re-run FINAL reconciliation, then seal only its canonical public projection."""

    verify_selection_for_durable_record(loaded_control, selection)
    rebuilt = reconcile_final_provenance_selection(
        loaded_control, validation=validation, artifacts=artifacts, git_control=git_control,
        git_observation=git_observation, dependency_control=dependency_control, now=now,
    )
    if rebuilt.selection_fingerprint != selection.selection_fingerprint or rebuilt._reconciliation_fingerprint != selection._reconciliation_fingerprint:
        raise ProvenanceRecordError("verified durable provenance selection is stale")
    payload = _selection_payload(loaded_control)
    selection_value = payload["selection"]
    binding = dependency_control.policy.binding
    document: dict[str, object] = {
        "schema": VERIFIED_PROVENANCE_RECORD_SCHEMA,
        "external": {
            "payload_digest": loaded_control.payload_digest, "receipt_digest": loaded_control.receipt_digest,
            "contract_digest": loaded_control.contract_digest, "retention_identity": loaded_control.retention_identity,
            "run_id": loaded_control.expected.run_id, "contract_id": loaded_control.expected.contract_id,
            "orchestrator_task": loaded_control.expected.orchestrator_task, "mode": loaded_control.mode.lower(),
        },
        "selection": {
            "repository": binding.repository, "task_id": binding.task_id,
            "base_sha": selection_value["base_sha"], "candidate_sha": binding.candidate_sha,
            "candidate_tree": selection_value["candidate_tree"], "leaf": selection_value["active_leaf"],
            "route": selection_value["route"], "case_schema": selection_value["case_schema"],
            "profile": selection_value["evidence_profile"], "selection_at": selection.selection_at,
            "gate": selection_value["gate"], "blocker": selection_value["blocker"], "next_action": selection_value["next_action"],
        },
        "fingerprints": {
            "candidate": selection.candidate_fingerprint,
            "validation": validation.projection_fingerprint, "artifacts": artifacts.projection_fingerprint,
            "dependency": _control_fingerprint(dependency_control, now=now)[0],
            "git": git_observation.observation_fingerprint, "control": selection.control_fingerprint,
            "selection": selection.selection_fingerprint,
        },
        "validation": validation.public_payload(),
        "artifacts": {
            "candidate_source": {"source_identity": artifacts.source_identity, "digest": artifacts.source_digest},
            "candidate_package": artifacts.package_digest,
            "installed_roundwright_entrypoint": artifacts.installed_entrypoint_digest,
            "reviewed_git_entrypoint": git_observation._payload(),
        },
        "dependency": {
            "binding_fingerprint": binding.fingerprint, "policy_fingerprint": dependency_control.policy.core_fingerprint,
            "policy_digest": dependency_control.policy.policy_digest,
            "observations": [{"component": item.component.value, "identifier": item.identifier, "version": item.version, "source_identity": item.source_identity, "artifact_digest": item.artifact_digest, "executable_digest": item.executable_digest, "observed_at": item.observed_at, "policy_digest": item.policy_digest, "fingerprint": item.fingerprint} for item in sorted(dependency_control.observations, key=lambda item: item.component.value)],
            "admission": {"policy_fingerprint": dependency_control.admission.policy_fingerprint, "receipt_digest": dependency_control.admission.receipt_digest, "reviewer_identity": dependency_control.admission.reviewer_identity, "authority_digest": dependency_control.admission.authority_digest},
        },
    }
    document["record_digest"] = _v2_digest(document)
    encoded = _canonical_json_bytes(document)
    # This allocation stays lexically inside the exact reconciliation boundary;
    # no class or module-level factory grants a materialization seal.
    checked = _verified_record_document(encoded)
    value = object.__new__(VerifiedDurableProvenanceRecord)
    object.__setattr__(value, "payload", encoded)
    object.__setattr__(value, "record_digest", checked["record_digest"])
    object.__setattr__(value, "retention_identity", checked["external"]["retention_identity"])
    object.__setattr__(value, "candidate_sha", checked["selection"]["candidate_sha"])
    object.__setattr__(value, "_authority_fingerprint", _v2_digest({
        "control": loaded_control._load_fingerprint,
        "selection": selection._reconciliation_fingerprint,
        "record": document["record_digest"],
    }))
    object.__setattr__(value, "_materialization_seal", _VERIFIED_PROVENANCE_RECORD_SEAL)
    return value


class VerifiedProvenanceRecordStore:
    """Append-only content-addressed retention for sealed verified records only."""

    def __init__(self, root: Path, retention_identity: str) -> None:
        if not isinstance(root, Path) or _parse_roundlet_retention_identity(retention_identity) is None:
            raise ProvenanceRecordError("verified provenance record store is invalid")
        self._root = root
        self._retention_identity = retention_identity

    @staticmethod
    def _require_safe_path(path: Path) -> None:
        """Reject every existing symlink or Windows junction in a store path."""

        current = path
        while True:
            if current.exists() and (current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction())):
                raise ProvenanceRecordError("verified provenance record path must not traverse a link")
            if current.parent == current:
                return
            current = current.parent

    def append(
        self, record: object, *, loaded_control: object, selection: object, validation: object,
        artifacts: object, git_control: object, git_observation: object,
        dependency_control: object, now: int,
    ) -> str:
        if type(record) is not VerifiedDurableProvenanceRecord:
            raise ProvenanceRecordError("verified provenance record is required")
        rebuilt = materialize_verified_provenance_record(
            loaded_control, selection, validation=validation, artifacts=artifacts,
            git_control=git_control, git_observation=git_observation,
            dependency_control=dependency_control, now=now,
        )
        try:
            record.verify()
        except (AttributeError, ProvenanceRecordError) as error:
            raise ProvenanceRecordError("verified provenance record is unsealed") from error
        if record.payload != rebuilt.payload:
            raise ProvenanceRecordError("verified provenance record authority does not match")
        self._require_safe_path(self._root)
        if record.retention_identity != self._retention_identity:
            raise ProvenanceRecordError("verified provenance record store binding is invalid")
        target_root = self._root / record.candidate_sha
        target_root.mkdir(parents=True, exist_ok=True)
        self._require_safe_path(target_root)
        path = target_root / f"{record.record_digest.removeprefix('sha256:')}.json"
        self._require_safe_path(path)
        try:
            with path.open("xb") as output:
                output.write(record.payload)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            if path.read_bytes() != record.payload:
                raise ProvenanceRecordError("verified provenance record overwrite is forbidden") from None
        return record.record_digest

    def read_back(self, candidate_sha: str, record_digest: str) -> ReadBackVerifiedProvenanceRecord:
        if not _SHA1.fullmatch(candidate_sha) or not _is_v2_digest(record_digest):
            raise ProvenanceRecordError("verified provenance read-back is invalid")
        path = self._root / candidate_sha / f"{record_digest.removeprefix('sha256:')}.json"
        self._require_safe_path(path)
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ProvenanceRecordError("verified provenance read-back is unavailable") from error
        record = _read_back_verified_record(payload)
        if record.record_digest != record_digest or record.candidate_sha != candidate_sha or record.retention_identity != self._retention_identity:
            raise ProvenanceRecordError("verified provenance read-back is invalid")
        return record


class ProvenanceRecordStore:
    """Legacy fixture-only store; it cannot satisfy the verified-store boundary."""

    def __init__(self, root: Path, retention_identity: str) -> None:
        if not isinstance(root, Path) or not _safe_v2_token(retention_identity):
            raise ProvenanceRecordError("provenance record store is invalid")
        self._root = root
        self._retention_identity = retention_identity

    @property
    def retention_identity(self) -> str:
        return self._retention_identity

    def append(self, record: DurableProvenanceRecord) -> str:
        if type(record) is not DurableProvenanceRecord:
            raise ProvenanceRecordError("durable provenance record is invalid")
        if self._root.is_symlink():
            raise ProvenanceRecordError("provenance record store must not be a symlink")
        self._root.mkdir(parents=True, exist_ok=True)
        value = json.dumps(record.payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        path = self._root / f"{record.record_digest.removeprefix('sha256:')}.json"
        if path.is_symlink():
            raise ProvenanceRecordError("provenance record target must not be a symlink")
        try:
            with path.open("xb") as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            if path.read_bytes() != value:
                raise ProvenanceRecordError("durable provenance record overwrite is forbidden") from None
        return record.record_digest

    def read_back(self, digest: str) -> DurableProvenanceRecord:
        if not _is_v2_digest(digest) or self._root.is_symlink():
            raise ProvenanceRecordError("durable provenance read-back is invalid")
        path = self._root / f"{digest.removeprefix('sha256:')}.json"
        if path.is_symlink():
            raise ProvenanceRecordError("provenance record target must not be a symlink")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ProvenanceRecordError("durable provenance read-back is unavailable") from error
        if type(value) is not dict or value.get("schema") != PROVENANCE_RECORD_SCHEMA:
            raise ProvenanceRecordError("durable provenance read-back is invalid")
        decision_value = value.get("decision")
        if type(decision_value) is not dict:
            raise ProvenanceRecordError("durable provenance read-back is invalid")
        try:
            artifacts = tuple(PublicArtifactReference(kind, artifact_digest) for kind, artifact_digest in decision_value["artifacts"])
            decision = ProvenanceDecision(
                decision_value["repository"], decision_value["task_id"], decision_value["base_sha"], decision_value["candidate_sha"],
                decision_value["policy_fingerprint"], decision_value["dependency_fingerprint"], decision_value["entrypoint_fingerprint"],
                artifacts, decision_value["gate_identity"], decision_value["blocker"], decision_value["next_action"], decision_value["ready_at"], value["decision_digest"],
            )
            record = DurableProvenanceRecord(
                decision, value["candidate_tree"], value["policy_fingerprint"], tuple(value["observation_fingerprints"]), value["admission_digest"], digest,
            )
        except (KeyError, TypeError, ShadowV2Error) as error:
            raise ProvenanceRecordError("durable provenance read-back is invalid") from error
        if json.dumps(record.payload(), sort_keys=True, separators=(",", ":")).encode("utf-8") != path.read_bytes():
            raise ProvenanceRecordError("durable provenance record is non-canonical")
        return record


def _materialize_provenance_record(
    control: object,
    *,
    base_sha: str,
    candidate_tree: str,
    entrypoint_fingerprint: str,
    gate_identity: str,
    blocker: str | None,
    next_action: str,
    now: int,
) -> DurableProvenanceRecord:
    """Materialize from the candidate's sealed execution control, never raw inputs."""

    from .dependency_policy import CandidateBinding, DependencyPolicy, ObservedDependency

    if (
        not _SHA1.fullmatch(base_sha)
        or not _SHA1.fullmatch(candidate_tree)
        or not _is_v2_digest(entrypoint_fingerprint)
        or type(now) is not int
        or now < 0
    ):
        raise ProvenanceRecordError("production provenance materialization is invalid")
    from .dependency_policy import DependencyExecutionControl, DependencyStage
    if type(control) is not DependencyExecutionControl:
        raise ProvenanceRecordError("production provenance control is unavailable")
    binding = control.policy.binding
    policy = control.policy
    observations = control.observations
    if (
        type(binding) is not CandidateBinding
        or type(policy) is not DependencyPolicy
        or policy.binding != binding
        or not _SHA1.fullmatch(base_sha)
        or type(observations) is not tuple
        or not observations
        or any(type(item) is not ObservedDependency or item.binding != binding for item in observations)
        or len({item.component for item in observations}) != len(observations)
    ):
        raise ProvenanceRecordError("production provenance materialization is invalid")
    try:
        control.require(binding, DependencyStage.GIT_ENTRYPOINT, now=now)
    except Exception as error:
        raise ProvenanceRecordError("production provenance admission is not authorized") from error
    artifacts = tuple(
        PublicArtifactReference(item.component.value + "-artifact", item.artifact_digest)
        for item in observations
    ) + tuple(
        PublicArtifactReference(item.component.value + "-executable", item.executable_digest)
        for item in observations
    )
    decision = ProvenanceDecision(
        binding.repository,
        binding.task_id,
        base_sha,
        binding.candidate_sha,
        policy.core_fingerprint,
        _v2_digest(tuple(item.fingerprint for item in observations)),
        entrypoint_fingerprint,
        artifacts,
        gate_identity,
        blocker,
        next_action,
        now,
    )
    return DurableProvenanceRecord(
        decision, candidate_tree, policy.core_fingerprint,
        tuple(item.fingerprint for item in observations), control.admission.receipt_digest,
    )


def export_provenance_decision(record: object) -> ProvenanceDecision:
    """Export only a verified durable record; callers cannot supply raw fields."""

    if type(record) is not DurableProvenanceRecord:
        raise ProvenanceRecordError("durable provenance record is required for export")
    return record.decision


@dataclass(frozen=True)
class RecorderBinding:
    """The reviewed Recorder identity required before an observation window opens."""

    harness_merge: str
    recorder_content: str
    harness_tree: str

    def __post_init__(self) -> None:
        if (
            self.harness_merge != "10265c35c9d01d1fd26bd767ca3c1b245e4e9c52"
            or self.recorder_content != "87094a4e780c692a00135421840c0e6713af5d35"
            or self.harness_tree != "0c594caa275262164fce1942ebd2142abe0e77bb"
        ):
            raise ShadowV2Error("reviewed Recorder binding is invalid")


@dataclass(frozen=True)
class RetentionReceipt:
    retention_identity: str
    content_digest: str
    receipt_digest: str = ""

    def __post_init__(self) -> None:
        if not _safe_v2_token(self.retention_identity) or not _is_v2_digest(self.content_digest):
            raise ShadowV2Error("retention receipt is invalid")
        digest = _v2_digest({"retention_identity": self.retention_identity, "content_digest": self.content_digest})
        if self.receipt_digest and self.receipt_digest != digest:
            raise ShadowV2Error("retention receipt digest is invalid")
        object.__setattr__(self, "receipt_digest", digest)


class AppendOnlyEvidenceStore:
    """In-memory Recorder store contract: content addressed, append-only, readable."""

    def __init__(self, retention_identity: str) -> None:
        if not _safe_v2_token(retention_identity):
            raise ShadowV2Error("retention store identity is invalid")
        self._retention_identity = retention_identity
        self._records: dict[str, bytes] = {}

    @property
    def retention_identity(self) -> str:
        return self._retention_identity

    def append(self, content: bytes) -> RetentionReceipt:
        if type(content) is not bytes or not content:
            raise ShadowV2Error("retention content is invalid")
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        if digest in self._records:
            raise ShadowV2Error("append-only retention rejects overwrite")
        self._records[digest] = content
        return RetentionReceipt(self._retention_identity, digest)

    def read_back(self, receipt: RetentionReceipt) -> bytes:
        if type(receipt) is not RetentionReceipt or receipt.retention_identity != self._retention_identity:
            raise ShadowV2Error("retention read-back identity is invalid")
        content = self._records.get(receipt.content_digest)
        if content is None or "sha256:" + hashlib.sha256(content).hexdigest() != receipt.content_digest:
            raise ShadowV2Error("retention read-back content is unavailable")
        return content


@dataclass(frozen=True)
class CaptureReadinessReceipt:
    profile_id: str
    candidate_sha: str
    ready_at: int
    recorder_binding_digest: str
    retention_identity: str
    readiness_digest: str = ""

    def __post_init__(self) -> None:
        if (
            not _safe_profile_id(self.profile_id)
            or not _SHA1.fullmatch(self.candidate_sha)
            or type(self.ready_at) is not int
            or self.ready_at < 0
            or not _is_v2_digest(self.recorder_binding_digest)
            or not _safe_v2_token(self.retention_identity)
        ):
            raise ShadowV2Error("capture readiness receipt is invalid")
        digest = _v2_digest({
            "profile_id": self.profile_id,
            "candidate_sha": self.candidate_sha,
            "ready_at": self.ready_at,
            "recorder_binding_digest": self.recorder_binding_digest,
            "retention_identity": self.retention_identity,
        })
        if self.readiness_digest and self.readiness_digest != digest:
            raise ShadowV2Error("capture readiness receipt digest is invalid")
        object.__setattr__(self, "readiness_digest", digest)


def require_capture_readiness(
    profile: ShadowEvidenceProfile,
    decision: ProvenanceDecision | DurableProvenanceRecord,
    recorder: RecorderBinding,
    store: AppendOnlyEvidenceStore,
    *,
    candidate_sha: str,
    ready_at: int,
) -> CaptureReadinessReceipt:
    """Preflight every terminal-snapshot prerequisite before Recorder use."""

    durable = decision if type(decision) is DurableProvenanceRecord else None
    effective_decision = durable.decision if durable is not None else decision
    if (
        type(profile) is not ShadowEvidenceProfile
        or type(effective_decision) is not ProvenanceDecision
        or type(recorder) is not RecorderBinding
        or type(store) is not AppendOnlyEvidenceStore
        or effective_decision.candidate_sha != candidate_sha
        or effective_decision.ready_at != ready_at
        or type(ready_at) is not int
        or ready_at < 0
        or (profile.profile_id == PROVENANCE_DECISION_PROFILE and durable is None)
    ):
        raise ShadowV2Error("capture readiness preflight is incomplete")
    recorder_digest = _v2_digest({
        "harness_merge": recorder.harness_merge,
        "recorder_content": recorder.recorder_content,
        "harness_tree": recorder.harness_tree,
    })
    return CaptureReadinessReceipt(profile.profile_id, candidate_sha, ready_at, recorder_digest, store.retention_identity)


@dataclass(frozen=True)
class ShadowV2Observation:
    sequence: int
    event_id: str
    lifecycle_correlation_id: str
    profile_id: str
    event_kind: str
    provider_attempt_id: str | None
    provider_call_made: bool
    candidate_sha: str
    decision_digest: str
    evidence_digest: str = ""

    def __post_init__(self) -> None:
        if (
            type(self.sequence) is not int
            or self.sequence != 1
            or not all(_safe_v2_token(value) for value in (
                self.event_id,
                self.lifecycle_correlation_id,
                self.event_kind,
            ))
            or self.profile_id != PROVENANCE_DECISION_PROFILE
            or self.event_kind != "provenance-decision"
            or self.provider_attempt_id is not None
            or self.provider_call_made is not False
            or not _SHA1.fullmatch(self.candidate_sha)
            or not _is_v2_digest(self.decision_digest)
        ):
            raise ShadowV2Error("profile observation is invalid")
        digest = _v2_digest(self._payload())
        if self.evidence_digest and self.evidence_digest != digest:
            raise ShadowV2Error("profile observation digest is invalid")
        object.__setattr__(self, "evidence_digest", digest)

    def _payload(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "lifecycle_correlation_id": self.lifecycle_correlation_id,
            "profile_id": self.profile_id,
            "event_kind": self.event_kind,
            "provider_attempt_id": self.provider_attempt_id,
            "provider_call_made": self.provider_call_made,
            "candidate_sha": self.candidate_sha,
            "decision_digest": self.decision_digest,
        }


class LifecycleAttemptKind(StrEnum):
    WORKER = "worker"
    SUPERVISOR = "supervisor"
    RETRY = "retry"
    FAILOVER = "failover"
    REPAIR = "repair"


@dataclass(frozen=True)
class LifecycleAttempt:
    """One durable lifecycle attempt, independent from its provider calls."""

    attempt_id: str
    ordinal: int
    kind: LifecycleAttemptKind
    role: EvidenceRole
    parent_attempt_id: str | None = None
    review_round_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not _safe_v2_token(self.attempt_id)
            or type(self.ordinal) is not int
            or self.ordinal < 1
            or type(self.kind) is not LifecycleAttemptKind
            or type(self.role) is not EvidenceRole
            or (self.parent_attempt_id is not None and not _safe_v2_token(self.parent_attempt_id))
            or (self.review_round_id is not None and not _safe_v2_token(self.review_round_id))
        ):
            raise ShadowV2Error("lifecycle attempt is invalid")


@dataclass(frozen=True)
class ProviderAttemptManifest:
    """One provider call attempt, never a lifecycle correlation surrogate."""

    provider_attempt_id: str
    lifecycle_attempt_id: str
    ordinal: int
    provider_identity: str
    outcome: str

    def __post_init__(self) -> None:
        if (
            not _safe_v2_token(self.provider_attempt_id)
            or not _safe_v2_token(self.lifecycle_attempt_id)
            or type(self.ordinal) is not int
            or self.ordinal < 1
            or not _safe_v2_token(self.provider_identity)
            or not _safe_v2_token(self.outcome)
        ):
            raise ShadowV2Error("provider attempt manifest is invalid")


@dataclass(frozen=True)
class FormalReviewRoundReference:
    review_round_id: str
    ordinal: int
    candidate_sha: str
    accepted_result_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not _safe_v2_token(self.review_round_id)
            or type(self.ordinal) is not int
            or self.ordinal < 1
            or not _SHA1.fullmatch(self.candidate_sha)
            or (self.accepted_result_id is not None and not _safe_v2_token(self.accepted_result_id))
        ):
            raise ShadowV2Error("review round reference is invalid")


@dataclass(frozen=True)
class CandidateCommitReference:
    commit_sha: str
    commit_identity: str

    def __post_init__(self) -> None:
        if not _SHA1.fullmatch(self.commit_sha) or not _safe_v2_token(self.commit_identity):
            raise ShadowV2Error("candidate commit reference is invalid")


@dataclass(frozen=True)
class AttemptCommitReference:
    """A typed many-to-many edge from a lifecycle attempt to a candidate commit."""

    lifecycle_attempt_id: str
    commit_sha: str

    def __post_init__(self) -> None:
        if not _safe_v2_token(self.lifecycle_attempt_id) or not _SHA1.fullmatch(self.commit_sha):
            raise ShadowV2Error("lifecycle attempt commit reference is invalid")


@dataclass(frozen=True)
class AcceptedResultReference:
    result_id: str
    review_round_id: str
    event_id: str
    candidate_sha: str

    def __post_init__(self) -> None:
        if not all(_safe_v2_token(value) for value in (self.result_id, self.review_round_id, self.event_id)) or not _SHA1.fullmatch(self.candidate_sha):
            raise ShadowV2Error("accepted result reference is invalid")


@dataclass(frozen=True)
class ShadowV2Event:
    """A profile-defined immutable event with explicit graph references."""

    event_id: str
    ordinal: int
    lifecycle_attempt_id: str
    event_kind: str
    provider_attempt_id: str | None
    provider_call_made: bool
    review_round_id: str | None = None
    commit_sha: str | None = None
    accepted_result_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not all(_safe_v2_token(value) for value in (self.event_id, self.lifecycle_attempt_id, self.event_kind))
            or type(self.ordinal) is not int
            or self.ordinal < 1
            or type(self.provider_call_made) is not bool
            or (self.provider_attempt_id is not None and not _safe_v2_token(self.provider_attempt_id))
            or (self.review_round_id is not None and not _safe_v2_token(self.review_round_id))
            or (self.commit_sha is not None and not _SHA1.fullmatch(self.commit_sha))
            or (self.accepted_result_id is not None and not _safe_v2_token(self.accepted_result_id))
            or (self.provider_call_made != (self.provider_attempt_id is not None))
        ):
            raise ShadowV2Error("profile-defined event is invalid")


@dataclass(frozen=True)
class ShadowV2EventGraph:
    """Reusable profile event graph; only profiles, not the core, choose events."""

    attempts: tuple[LifecycleAttempt, ...]
    provider_attempts: tuple[ProviderAttemptManifest, ...]
    review_rounds: tuple[FormalReviewRoundReference, ...]
    commits: tuple[CandidateCommitReference, ...]
    accepted_results: tuple[AcceptedResultReference, ...]
    events: tuple[ShadowV2Event, ...]
    attempt_commit_references: tuple[AttemptCommitReference, ...] = ()

    def validate(self, profile: ShadowEvidenceProfile, candidate_sha: str) -> None:
        if (
            type(profile) is not ShadowEvidenceProfile
            or not _SHA1.fullmatch(candidate_sha)
            or any(type(item) is not LifecycleAttempt for item in self.attempts)
            or any(type(item) is not ProviderAttemptManifest for item in self.provider_attempts)
            or any(type(item) is not FormalReviewRoundReference for item in self.review_rounds)
            or any(type(item) is not CandidateCommitReference for item in self.commits)
            or any(type(item) is not AcceptedResultReference for item in self.accepted_results)
            or any(type(item) is not ShadowV2Event for item in self.events)
            or any(type(item) is not AttemptCommitReference for item in self.attempt_commit_references)
            or not self.attempts
            or not self.events
        ):
            raise ShadowV2Error("Shadow v2 event graph is invalid")
        _require_ordered_unique(self.attempts, "attempt_id", "ordinal", "lifecycle attempts")
        _require_ordered_unique(self.provider_attempts, "provider_attempt_id", "ordinal", "provider attempts")
        _require_ordered_unique(self.review_rounds, "review_round_id", "ordinal", "review rounds")
        _require_ordered_unique(self.events, "event_id", "ordinal", "profile events")
        if len({item.commit_sha for item in self.commits}) != len(self.commits):
            raise ShadowV2Error("candidate commits are duplicate")
        if not profile.minimum_commits <= len(self.commits) <= profile.maximum_commits:
            raise ShadowV2Error("candidate commit cardinality is invalid")
        attempts = {item.attempt_id: item for item in self.attempts}
        providers = {item.provider_attempt_id: item for item in self.provider_attempts}
        rounds = {item.review_round_id: item for item in self.review_rounds}
        commits = {item.commit_sha for item in self.commits}
        results = {item.result_id: item for item in self.accepted_results}
        if len(results) != len(self.accepted_results):
            raise ShadowV2Error("accepted results are duplicate")
        edge_pairs = tuple((item.lifecycle_attempt_id, item.commit_sha) for item in self.attempt_commit_references)
        if len(set(edge_pairs)) != len(edge_pairs):
            raise ShadowV2Error("lifecycle attempt commit references are duplicate")
        for lifecycle_attempt_id, commit_sha in edge_pairs:
            if lifecycle_attempt_id not in attempts or commit_sha not in commits:
                raise ShadowV2Error("lifecycle attempt commit reference is unavailable")
        if any(commit not in {commit_sha for _, commit_sha in edge_pairs} for commit in commits):
            raise ShadowV2Error("candidate commit is orphaned from lifecycle attempts")
        for attempt in self.attempts:
            if attempt.parent_attempt_id is not None and attempt.parent_attempt_id not in attempts:
                raise ShadowV2Error("lifecycle attempt parent is unavailable")
            if attempt.review_round_id is not None and attempt.review_round_id not in rounds:
                raise ShadowV2Error("lifecycle attempt review round is unavailable")
        for provider in self.provider_attempts:
            if provider.lifecycle_attempt_id not in attempts:
                raise ShadowV2Error("provider attempt lifecycle reference is unavailable")
        for review in self.review_rounds:
            if review.candidate_sha != candidate_sha:
                raise ShadowV2Error("review round candidate is stale")
            if review.accepted_result_id is not None and review.accepted_result_id not in results:
                raise ShadowV2Error("accepted review result is unavailable")
        event_ids = {item.event_id for item in self.events}
        for result in self.accepted_results:
            if result.review_round_id not in rounds or result.event_id not in event_ids or result.candidate_sha != candidate_sha:
                raise ShadowV2Error("accepted result reference is invalid")
        for review in self.review_rounds:
            if review.accepted_result_id is not None:
                result = results[review.accepted_result_id]
                if result.review_round_id != review.review_round_id:
                    raise ShadowV2Error("accepted review result does not match round")
        for event in self.events:
            if event.lifecycle_attempt_id not in attempts or event.event_kind not in profile.event_kinds:
                raise ShadowV2Error("profile event reference is invalid")
            if event.provider_attempt_id is not None:
                provider = providers.get(event.provider_attempt_id)
                if provider is None or provider.lifecycle_attempt_id != event.lifecycle_attempt_id:
                    raise ShadowV2Error("provider event reference is invalid")
            if event.review_round_id is not None and event.review_round_id not in rounds:
                raise ShadowV2Error("event review round is unavailable")
            if event.commit_sha is not None and (event.commit_sha not in commits or (event.lifecycle_attempt_id, event.commit_sha) not in edge_pairs):
                raise ShadowV2Error("event commit is unavailable")
            if event.accepted_result_id is not None:
                result = results.get(event.accepted_result_id)
                if result is None or result.event_id != event.event_id:
                    raise ShadowV2Error("event accepted result is invalid")
        event_provider_ids = tuple(item.provider_attempt_id for item in self.events if item.provider_attempt_id is not None)
        if set(event_provider_ids) != set(providers) or len(event_provider_ids) != len(providers):
            raise ShadowV2Error("provider attempt references are missing or duplicate")
        if profile.requires_accepted_result:
            if len(self.accepted_results) != 1 or not self.review_rounds or self.review_rounds[-1].accepted_result_id is None:
                raise ShadowV2Error("profile requires one final accepted result")


def _require_ordered_unique(records: tuple[object, ...], identity: str, ordinal: str, label: str) -> None:
    values = tuple(getattr(item, ordinal) for item in records)
    identities = tuple(getattr(item, identity) for item in records)
    if values != tuple(range(1, len(records) + 1)) or len(set(identities)) != len(identities):
        raise ShadowV2Error(f"{label} are missing, duplicate, or out of order")


@dataclass(frozen=True)
class ShadowV2Case:
    case_id: str
    lifecycle_correlation_id: str
    profile: ShadowEvidenceProfile
    decision: ProvenanceDecision
    reference_decision: ProvenanceDecision
    readiness: CaptureReadinessReceipt
    observations: tuple[ShadowV2Observation, ...]
    retention_class: str
    retention_reference: str
    schema: str = SHADOW_CASE_SCHEMA_V2
    case_digest: str = ""
    event_graph: ShadowV2EventGraph | None = None

    def __post_init__(self) -> None:
        _validate_v2_case(self, verify_digest=False)
        digest = _v2_digest(self._payload())
        if self.case_digest and self.case_digest != digest:
            raise ShadowV2Error("Shadow v2 case digest is invalid")
        object.__setattr__(self, "case_digest", digest)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "case_id": self.case_id,
            "lifecycle_correlation_id": self.lifecycle_correlation_id,
            "profile_id": self.profile.profile_id,
            "decision_digest": self.decision.decision_digest,
            "reference_decision_digest": self.reference_decision.decision_digest,
            "readiness_digest": self.readiness.readiness_digest,
            "observations": tuple(item.evidence_digest for item in self.observations),
            "retention_class": self.retention_class,
            "retention_reference": self.retention_reference,
            "event_graph": None if self.event_graph is None else _v2_graph_payload(self.event_graph),
        }

    def retention_payload(self) -> bytes:
        """Canonical bytes for Recorder storage; no paths or provider payloads."""

        return json.dumps(self._payload() | {"case_digest": self.case_digest}, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ShadowV2Report:
    case_id: str
    case_digest: str
    outcome: ComparisonOutcome
    classification: ReplayClassification
    ready_at: int | None
    detail: str
    retention_reference: str
    read_only: bool = True

    def curated_summary(self) -> dict[str, object]:
        return {
            "case_id": _public_identifier(self.case_id),
            "case_digest": self.case_digest,
            "outcome": self.outcome.value,
            "classification": self.classification.value,
            "ready_at": self.ready_at,
            "retention_reference": _public_identifier(self.retention_reference),
            "read_only": self.read_only,
        }


def compare_provenance_decision(
    expected: ProvenanceDecision,
    observed: ProvenanceDecision,
    *,
    ready_at: int,
) -> ComparisonOutcome:
    """Compare only at the frozen bundle capture time, never wall-clock time."""

    if (
        type(expected) is not ProvenanceDecision
        or type(observed) is not ProvenanceDecision
        or type(ready_at) is not int
        or ready_at < 0
        or ready_at != expected.ready_at
        or ready_at != observed.ready_at
    ):
        return ComparisonOutcome.INVALID
    return ComparisonOutcome.MATCH if expected.decision_digest == observed.decision_digest else ComparisonOutcome.MISMATCH


def replay_shadow_v2_case(case: ShadowV2Case) -> ShadowV2Report:
    """Replay the profile-defined terminal snapshot without worker/provider access."""

    try:
        _validate_v2_case(case, verify_digest=True)
    except (ShadowV2Error, AttributeError):
        return ShadowV2Report("invalid-case", "none", ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH, None, "invalid-v2-case", "unavailable")
    outcome = compare_provenance_decision(case.reference_decision, case.decision, ready_at=case.readiness.ready_at)
    if outcome is ComparisonOutcome.MATCH:
        return ShadowV2Report(case.case_id, case.case_digest, outcome, ReplayClassification.EXACT_MATCH, case.readiness.ready_at, "exact-terminal-provenance-match", case.retention_reference)
    classification = ReplayClassification.CONTRACT_MISMATCH if outcome is ComparisonOutcome.MISMATCH else ReplayClassification.INCOMPLETE_EVIDENCE
    return ShadowV2Report(case.case_id, case.case_digest, outcome, classification, case.readiness.ready_at, "terminal-provenance-comparison-failed", case.retention_reference)


def replay_shadow_case(case: ShadowCase | ShadowV2Case) -> ShadowReport | ShadowV2Report:
    """Dispatch only explicit v1 or v2 evidence; mixing fails closed."""

    if type(case) is ShadowCase:
        return ShadowExecutor().replay(case)
    if type(case) is ShadowV2Case:
        return replay_shadow_v2_case(case)
    return ShadowV2Report("invalid-case", "none", ComparisonOutcome.INVALID, ReplayClassification.CONTRACT_MISMATCH, None, "mixed-or-unknown-shadow-case", "unavailable")


def _validate_v2_case(case: object, *, verify_digest: bool) -> None:
    if (
        type(case) is not ShadowV2Case
        or case.schema != SHADOW_CASE_SCHEMA_V2
        or not _safe_v2_token(case.case_id)
        or not _safe_v2_token(case.lifecycle_correlation_id)
        or type(case.profile) is not ShadowEvidenceProfile
        or type(case.decision) is not ProvenanceDecision
        or type(case.reference_decision) is not ProvenanceDecision
        or type(case.readiness) is not CaptureReadinessReceipt
        or type(case.observations) is not tuple
        or any(type(item) is not ShadowV2Observation for item in case.observations)
        or not _safe_v2_token(case.retention_class)
        or not _safe_v2_token(case.retention_reference)
    ):
        raise ShadowV2Error("Shadow v2 case is invalid")
    if case.profile.profile_id == PROVENANCE_DECISION_PROFILE:
        if len(case.observations) != 1 or any(type(item) is not ShadowV2Observation for item in case.observations):
            raise ShadowV2Error("provenance profile observation is invalid")
        observation = case.observations[0]
    elif case.observations:
        raise ShadowV2Error("generic profile observations must use event graph")
    else:
        observation = None
    if (
        case.decision.candidate_sha != case.readiness.candidate_sha
        or case.decision.ready_at != case.readiness.ready_at
        or case.reference_decision.candidate_sha != case.decision.candidate_sha
        or case.reference_decision.base_sha != case.decision.base_sha
    ):
        raise ShadowV2Error("Shadow v2 evidence is stale or mixed")
    if observation is not None and (
        observation.lifecycle_correlation_id != case.lifecycle_correlation_id
        or observation.candidate_sha != case.decision.candidate_sha
        or observation.decision_digest != case.decision.decision_digest
        or observation.profile_id != case.profile.profile_id
        or observation.event_kind not in case.profile.event_kinds
    ):
        raise ShadowV2Error("provenance terminal observation is stale or mixed")
    if case.event_graph is not None:
        if type(case.event_graph) is not ShadowV2EventGraph:
            raise ShadowV2Error("Shadow v2 event graph is invalid")
        case.event_graph.validate(case.profile, case.decision.candidate_sha)
    elif case.profile.capture_mode is CaptureMode.LIFECYCLE_GRAPH:
        raise ShadowV2Error("profile event graph is missing")
    if verify_digest and case.case_digest != _v2_digest(case._payload()):
        raise ShadowV2Error("Shadow v2 case digest is invalid")


def _v2_graph_payload(graph: ShadowV2EventGraph) -> dict[str, object]:
    return {
        "attempts": tuple((item.attempt_id, item.ordinal, item.kind.value, item.role.value, item.parent_attempt_id, item.review_round_id) for item in graph.attempts),
        "provider_attempts": tuple((item.provider_attempt_id, item.lifecycle_attempt_id, item.ordinal, item.provider_identity, item.outcome) for item in graph.provider_attempts),
        "review_rounds": tuple((item.review_round_id, item.ordinal, item.candidate_sha, item.accepted_result_id) for item in graph.review_rounds),
        "commits": tuple((item.commit_sha, item.commit_identity) for item in graph.commits),
        "attempt_commit_references": tuple((item.lifecycle_attempt_id, item.commit_sha) for item in graph.attempt_commit_references),
        "accepted_results": tuple((item.result_id, item.review_round_id, item.event_id, item.candidate_sha) for item in graph.accepted_results),
        "events": tuple((item.event_id, item.ordinal, item.lifecycle_attempt_id, item.event_kind, item.provider_attempt_id, item.provider_call_made, item.review_round_id, item.commit_sha, item.accepted_result_id) for item in graph.events),
    }
