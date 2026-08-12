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
import shutil
import subprocess
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


def _is_v2_digest(value: object) -> bool:
    return type(value) is str and _V2_DIGEST.fullmatch(value) is not None


def _v2_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


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


@dataclass(frozen=True)
class DurableProvenanceRecord:
    """A candidate-bound projection produced only after a sealed control passes."""

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


class ProvenanceRecordStore:
    """Append-only, content-addressed local retention for terminal provenance."""

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


def materialize_provenance_from_repository(
    root: Path,
    store: ProvenanceRecordStore,
    *,
    repository: str,
    task_id: str,
    base_sha: str,
    candidate_sha: str,
    candidate_tree: str,
    validation_receipt: Path,
    now: int,
) -> DurableProvenanceRecord:
    """Fixed production adapter; derive and seal provenance from verified bytes."""

    if (
        not isinstance(root, Path) or type(store) is not ProvenanceRecordStore
        or not _safe_repository(repository) or not _safe_v2_token(task_id)
        or not all(_SHA1.fullmatch(value) for value in (base_sha, candidate_sha, candidate_tree))
        or not isinstance(validation_receipt, Path) or type(now) is not int or now < 0
    ):
        raise ProvenanceRecordError("production provenance source is invalid")
    def git(*arguments: str) -> str:
        result = subprocess.run(("git", "-C", os.fspath(root), *arguments), text=True, capture_output=True, check=False)
        if result.returncode != 0:
            raise ProvenanceRecordError("production provenance Git source is unavailable")
        return result.stdout.strip()
    if git("rev-parse", "HEAD") != candidate_sha or git("rev-parse", "HEAD^{tree}") != candidate_tree:
        raise ProvenanceRecordError("production provenance candidate has moved")
    if git("merge-base", "--is-ancestor", base_sha, candidate_sha) != "":
        raise ProvenanceRecordError("production provenance base is unavailable")
    try:
        lock = (root / "ci" / "validation-toolchain.lock.toml").read_bytes()
        receipt = validation_receipt.read_bytes()
        if type(json.loads(receipt.decode("utf-8"))) is not dict:
            raise ValueError
        git_executable = shutil.which("git")
        if git_executable is None:
            raise ValueError
        executable = Path(git_executable).read_bytes()
        authority = git("show", f"{base_sha}:AGENTS.md").encode("utf-8")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ProvenanceRecordError("production provenance source is unavailable") from error
    from .dependency_policy import (
        BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent,
        DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition,
        PolicyTransitionKind, TrustedDependencyAdmission, VersionRange,
    )
    digest = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
    binding = CandidateBinding(repository, task_id, candidate_sha)
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, "roundwright-package", VersionRange("0.0.0", "1.0.0"), "validation-toolchain-lock", digest(lock), digest(lock)),
        ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "system-git", digest(executable), digest(executable)),
    )
    policy = DependencyPolicy(binding, digest(lock), now, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    authority_digest = digest(authority)
    receipt_digest = digest(receipt)
    bootstrap = BootstrapPolicyReceipt.create(policy, reviewer_identity=receipt_digest, authority_digest=authority_digest)
    policy = DependencyPolicy(binding, digest(lock), now, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP, bootstrap))
    observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, now, policy.policy_digest) for item in components)
    control = DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, bootstrap.receipt_digest, receipt_digest, authority_digest))
    record = _materialize_provenance_record(
        control, base_sha=base_sha, candidate_tree=candidate_tree,
        entrypoint_fingerprint=digest(candidate_tree.encode("ascii") + digest(executable).encode("ascii")),
        gate_identity="provenance-record-ready", blocker=None, next_action="record-terminal-snapshot", now=now,
    )
    store.append(record)
    return store.read_back(record.record_digest)


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
