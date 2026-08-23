"""Repository-owned adapter for sealed generic lifecycle observations.

Roundlet produces only closed, public-safe transition facts.  The reviewed
Harness validates and seals them.  This module is the product boundary that
assigns those generic facts Roundwright meaning and compares every retained
semantic field.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping, Sequence


LIFECYCLE_OBSERVATION_CONTRACT_SCHEMA = (
    "roundwright-lifecycle-observation-contract/v1"
)
LIFECYCLE_PROJECTION_SCHEMA = "roundwright-lifecycle-shadow-projection/v1"
LIFECYCLE_COMPARISON_SCHEMA = "roundwright-lifecycle-shadow-comparison/v1"
LIFECYCLE_SYNTHETIC_RECEIPT_SCHEMA = (
    "roundwright-lifecycle-observation-synthetic-receipt/v1"
)
LIVE_LIFECYCLE_SHADOW_PROFILE = (
    "roundwright-shadow-profile/live-lifecycle-shadow/v1"
)

HARNESS_REPOSITORY = "ythdelmar68/roundwright-harness"
HARNESS_MERGE_COMMIT = "f13065e7fae7e48c21398c551cf1b724a4b26070"
HARNESS_TREE = "ac6e3e21e7b2b559915b3cef0ce15648c5b22b1a"
HARNESS_LIFECYCLE_BLOB = "e61c8157973e315f3308b674ed55ef2f4e15fb43"
HARNESS_LIFECYCLE_PACKAGE_TREE = "2325174685e16b579e84e8771d96e85e6c7a253d"

ROUNDLET_REPOSITORY = "ythdelmar68/roundlet"
ROUNDLET_MERGE_COMMIT = "5169a4630de9c1a888e6f46254a5ef21e40c2b8b"
ROUNDLET_TREE = "e84ad8c582f2a5583af99b7a80cdc03249e2d5fa"
ROUNDLET_SKILL_BLOB = "3308a9a74e33f276bab6a5221e974f74a5cd0dc0"
ROUNDLET_SKILL_TREE = "63117b2418ce17d45d099ae6009522a6a83df8ce"

HARNESS_PLAN_SCHEMA = "roundwright-harness-lifecycle-plan/v1"
HARNESS_EVENT_SCHEMA = "roundwright-harness-lifecycle-event/v1"
HARNESS_SEAL_RECEIPT_SCHEMA = (
    "roundwright-harness-lifecycle-seal-receipt/v1"
)
HARNESS_BUNDLE_SCHEMA = "roundwright-harness-lifecycle-bundle/v1"

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_PLAN_FIELDS = {
    "schema",
    "window_identity",
    "repository_identity",
    "candidate_sha",
    "ready_at",
    "producer_identity",
    "store_identity",
    "capture_plan_digest",
    "review_epoch",
    "review_round",
    "review_mode",
}
_EVENT_FIELDS = {
    "schema",
    "window_identity",
    "repository_identity",
    "candidate_sha",
    "sequence",
    "occurred_at",
    "role",
    "task_identity",
    "attempt_identity",
    "review_epoch",
    "review_round",
    "review_mode",
    "review_attempt",
    "transition",
    "disposition",
    "accepted_result",
    "successor_candidate_sha",
    "predecessor_event_digest",
    "artifact_references",
}
_SEAL_RECEIPT_FIELDS = {
    "schema",
    "status",
    "event_schema",
    "plan_digest",
    "window_identity",
    "repository_identity",
    "candidate_sha",
    "ready_at",
    "event_count",
    "head_event_digest",
    "head_entry_digest",
    "manifest_digest",
    "ledger_digest",
    "retention_identity",
    "receipt_digest",
}
_TRANSITIONS = {
    "attempt_started",
    "attempt_completed",
    "result_accepted",
    "result_unaccepted",
    "candidate_moved",
    "formal_round_advanced",
}
_DISPOSITIONS = {
    "pending",
    "cancelled",
    "invalid_context",
    "pass",
    "findings",
    "failed",
    "accepted",
    "unaccepted",
    "stale",
}
SUPERVISOR_PROFILE_ARTIFACT_SCHEMA = "roundwright-supervisor-profile-artifact/v2"
_SUPERVISOR_PROFILES = (("sol", "xhigh"), ("terra", "high"))


class LifecycleObservationError(ValueError):
    """The lifecycle producer, binding, evidence, or comparison is invalid."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _safe_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _safe_token(value: object) -> bool:
    if type(value) is not str or _TOKEN.fullmatch(value) is None:
        return False
    lowered = value.lower()
    return not any(
        word in lowered
        for word in ("token", "secret", "credential", "password", "ghp_")
    ) and not lowered.startswith("sk-")


def supervisor_profile_artifact(model: str, reasoning: str) -> str:
    """Return the sealed identity for one exact public Supervisor profile.

    The generic Harness ledger retains artifact identities rather than raw
    provider records.  This fixed vocabulary makes the selected profile a
    typed, sealed lifecycle fact without exposing a provider payload.
    """

    if (model, reasoning) not in _SUPERVISOR_PROFILES:
        raise LifecycleObservationError("supervisor profile artifact is invalid")
    return _digest({
        "schema": SUPERVISOR_PROFILE_ARTIFACT_SCHEMA,
        "model": model,
        "reasoning": reasoning,
    })


@dataclass(frozen=True)
class ReviewedComponentPin:
    repository: str
    merge_commit: str
    tree: str
    content_blob: str
    component_tree: str

    def __post_init__(self) -> None:
        if (
            self.repository not in {HARNESS_REPOSITORY, ROUNDLET_REPOSITORY}
            or any(
                _SHA.fullmatch(value) is None
                for value in (
                    self.merge_commit,
                    self.tree,
                    self.content_blob,
                    self.component_tree,
                )
            )
        ):
            raise LifecycleObservationError("reviewed component pin is invalid")

    def payload(self) -> dict[str, str]:
        return asdict(self)


HARNESS_LIFECYCLE_PIN = ReviewedComponentPin(
    HARNESS_REPOSITORY,
    HARNESS_MERGE_COMMIT,
    HARNESS_TREE,
    HARNESS_LIFECYCLE_BLOB,
    HARNESS_LIFECYCLE_PACKAGE_TREE,
)
ROUNDLET_LIFECYCLE_PIN = ReviewedComponentPin(
    ROUNDLET_REPOSITORY,
    ROUNDLET_MERGE_COMMIT,
    ROUNDLET_TREE,
    ROUNDLET_SKILL_BLOB,
    ROUNDLET_SKILL_TREE,
)


def lifecycle_observation_contract() -> dict[str, object]:
    """Return the closed root-referenced sink contract consumed by Roundlet."""

    core: dict[str, object] = {
        "schema": LIFECYCLE_OBSERVATION_CONTRACT_SCHEMA,
        "status": "active",
        "selection": "leaf-explicit-opt-in",
        "target_profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
        "harness": HARNESS_LIFECYCLE_PIN.payload(),
        "roundlet": ROUNDLET_LIFECYCLE_PIN.payload(),
        "schemas": {
            "plan": HARNESS_PLAN_SCHEMA,
            "event": HARNESS_EVENT_SCHEMA,
            "bundle": HARNESS_BUNDLE_SCHEMA,
            "seal_receipt": HARNESS_SEAL_RECEIPT_SCHEMA,
            "projection": LIFECYCLE_PROJECTION_SCHEMA,
            "comparison": LIFECYCLE_COMPARISON_SCHEMA,
        },
        "entrypoints": {
            "prepare": "roundwright_harness.lifecycle:prepare_lifecycle",
            "append_readback": (
                "roundwright_harness.lifecycle:append_lifecycle_event"
            ),
            "seal": "roundwright_harness.lifecycle:seal_lifecycle",
            "verify": "roundwright_harness.lifecycle:verify_lifecycle",
            "project": (
                "roundwright.lifecycle_observation:project_verified_lifecycle"
            ),
            "compare": (
                "roundwright.lifecycle_observation:compare_lifecycle_projections"
            ),
        },
        "producer_identity": _digest(
            {
                "schema": "roundwright-generic-lifecycle-producer/v1",
                "roundlet": ROUNDLET_LIFECYCLE_PIN.payload(),
                "event_schema": HARNESS_EVENT_SCHEMA,
            }
        ),
        "repository_identity": _digest(
            {
                "schema": "roundwright-repository-identity/v1",
                "repository": "ythdelmar68/roundwright",
            }
        ),
        "privacy": "closed-public-safe-no-raw-output-or-paths",
        "mutation_mode": "provider-free-github-free-target-free-zero-mutation",
    }
    return {**core, "contract_identity": _digest(core)}


def validate_lifecycle_observation_contract(value: object) -> dict[str, object]:
    """Accept only the authoritative exact contract, never a candidate variant."""

    expected = lifecycle_observation_contract()
    if type(value) is not dict or value != expected:
        raise LifecycleObservationError("lifecycle observation contract drifted")
    return json.loads(_canonical_bytes(expected))


def _harness_lifecycle(module: ModuleType | None = None) -> ModuleType:
    if module is None:
        try:
            module = importlib.import_module("roundwright_harness.lifecycle")
        except (ImportError, ModuleNotFoundError) as error:
            raise LifecycleObservationError(
                "exact reviewed lifecycle Harness is unavailable"
            ) from error
    if type(module) is not ModuleType:
        raise LifecycleObservationError("lifecycle Harness module is invalid")
    source_value = getattr(module, "__file__", None)
    if type(source_value) is not str:
        raise LifecycleObservationError("lifecycle Harness source is unavailable")
    source = Path(source_value)
    try:
        source_bytes = source.read_bytes()
    except OSError as error:
        raise LifecycleObservationError(
            "lifecycle Harness source read-back failed"
        ) from error
    git_blob = hashlib.sha1(
        b"blob " + str(len(source_bytes)).encode("ascii") + b"\0" + source_bytes
    ).hexdigest()
    if source.suffix != ".py" or source.is_symlink() or git_blob != HARNESS_LIFECYCLE_BLOB:
        raise LifecycleObservationError("lifecycle Harness content identity drifted")
    expected_constants = {
        "LIFECYCLE_PLAN_SCHEMA": HARNESS_PLAN_SCHEMA,
        "LIFECYCLE_EVENT_SCHEMA": HARNESS_EVENT_SCHEMA,
        "LIFECYCLE_BUNDLE_SCHEMA": HARNESS_BUNDLE_SCHEMA,
        "LIFECYCLE_SEAL_RECEIPT_SCHEMA": HARNESS_SEAL_RECEIPT_SCHEMA,
    }
    if any(getattr(module, name, None) != value for name, value in expected_constants.items()):
        raise LifecycleObservationError("lifecycle Harness schema identity drifted")
    for name in (
        "prepare_lifecycle",
        "append_lifecycle_event",
        "seal_lifecycle",
        "verify_lifecycle",
        "load_verified_lifecycle",
    ):
        if not callable(getattr(module, name, None)):
            raise LifecycleObservationError("lifecycle Harness surface is incomplete")
    return module


def _validated_plan(plan_value: object) -> dict[str, Any]:
    contract = lifecycle_observation_contract()
    if type(plan_value) is not dict or set(plan_value) != _PLAN_FIELDS:
        raise LifecycleObservationError("lifecycle observation plan is incomplete")
    plan = json.loads(_canonical_bytes(plan_value))
    if (
        plan["schema"] != HARNESS_PLAN_SCHEMA
        or plan["producer_identity"] != contract["producer_identity"]
        or plan["repository_identity"] != contract["repository_identity"]
        or type(plan["candidate_sha"]) is not str
        or _SHA.fullmatch(plan["candidate_sha"]) is None
        or type(plan["ready_at"]) is not int
        or plan["ready_at"] < 0
        or type(plan["review_epoch"]) is not int
        or plan["review_epoch"] < 1
        or type(plan["review_round"]) is not int
        or plan["review_round"] < 1
        or plan["review_mode"] not in {"complete", "converging"}
        or any(
            not _safe_digest(plan[field])
            for field in (
                "window_identity",
                "repository_identity",
                "producer_identity",
                "store_identity",
                "capture_plan_digest",
            )
        )
    ):
        raise LifecycleObservationError("lifecycle observation plan is invalid")
    return plan


@dataclass(frozen=True)
class ProjectedLifecycleEvent:
    sequence: int
    occurred_at: int
    role: str
    task_identity: str
    attempt_identity: str
    review_attempt: int
    transition: str
    disposition: str
    accepted_result: bool
    successor_candidate_sha: str | None
    predecessor_event_digest: str | None
    artifact_references: tuple[str, ...]
    event_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.sequence) is not int
            or self.sequence < 0
            or type(self.occurred_at) is not int
            or self.occurred_at < 0
            or self.role not in {"worker", "supervisor"}
            or not _safe_digest(self.task_identity)
            or not _safe_digest(self.attempt_identity)
            or type(self.review_attempt) is not int
            or self.review_attempt < 1
            or self.transition not in _TRANSITIONS
            or self.disposition not in _DISPOSITIONS
            or type(self.accepted_result) is not bool
            or (
                self.successor_candidate_sha is not None
                and _SHA.fullmatch(self.successor_candidate_sha) is None
            )
            or (
                self.predecessor_event_digest is not None
                and not _safe_digest(self.predecessor_event_digest)
            )
            or type(self.artifact_references) is not tuple
            or any(not _safe_digest(item) for item in self.artifact_references)
            or not _safe_digest(self.event_digest)
        ):
            raise LifecycleObservationError("projected lifecycle event is invalid")

    def payload(self) -> dict[str, object]:
        value = asdict(self)
        value["artifact_references"] = list(self.artifact_references)
        return value


@dataclass(frozen=True)
class LifecycleShadowProjection:
    candidate_sha: str
    ready_at: int
    window_identity: str
    repository_identity: str
    producer_identity: str
    store_identity: str
    capture_plan_digest: str
    plan_digest: str
    review_epoch: int
    review_round: int
    review_mode: str
    events: tuple[ProjectedLifecycleEvent, ...]
    accepted_attempt_identity: str
    ledger_digest: str
    manifest_digest: str
    retention_identity: str
    head_event_digest: str
    head_entry_digest: str
    classified_differences: tuple[str, ...] = ()
    schema: str = LIFECYCLE_PROJECTION_SCHEMA
    profile: str = LIVE_LIFECYCLE_SHADOW_PROFILE

    def __post_init__(self) -> None:
        if (
            self.schema != LIFECYCLE_PROJECTION_SCHEMA
            or self.profile != LIVE_LIFECYCLE_SHADOW_PROFILE
            or _SHA.fullmatch(self.candidate_sha) is None
            or type(self.ready_at) is not int
            or self.ready_at < 0
            or any(
                not _safe_digest(value)
                for value in (
                    self.window_identity,
                    self.repository_identity,
                    self.producer_identity,
                    self.store_identity,
                    self.capture_plan_digest,
                    self.plan_digest,
                    self.accepted_attempt_identity,
                    self.ledger_digest,
                    self.manifest_digest,
                    self.retention_identity,
                    self.head_event_digest,
                    self.head_entry_digest,
                )
            )
            or type(self.review_epoch) is not int
            or self.review_epoch < 1
            or type(self.review_round) is not int
            or self.review_round < 1
            or self.review_mode not in {"complete", "converging"}
            or type(self.events) is not tuple
            or not self.events
            or any(type(item) is not ProjectedLifecycleEvent for item in self.events)
            or type(self.classified_differences) is not tuple
            or any(not _safe_token(item) for item in self.classified_differences)
            or len(set(self.classified_differences)) != len(
                self.classified_differences
            )
        ):
            raise LifecycleObservationError("lifecycle shadow projection is invalid")

    def semantic_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "profile": self.profile,
            "candidate_sha": self.candidate_sha,
            "ready_at": self.ready_at,
            "window_identity": self.window_identity,
            "repository_identity": self.repository_identity,
            "producer_identity": self.producer_identity,
            "store_identity": self.store_identity,
            "capture_plan_digest": self.capture_plan_digest,
            "plan_digest": self.plan_digest,
            "review_epoch": self.review_epoch,
            "review_round": self.review_round,
            "review_mode": self.review_mode,
            "events": [item.payload() for item in self.events],
            "accepted_attempt_identity": self.accepted_attempt_identity,
            "ledger_digest": self.ledger_digest,
            "manifest_digest": self.manifest_digest,
            "retention_identity": self.retention_identity,
            "head_event_digest": self.head_event_digest,
            "head_entry_digest": self.head_entry_digest,
            "classified_differences": list(self.classified_differences),
        }


@dataclass(frozen=True)
class LifecycleProjectionComparison:
    status: str
    classified_differences: tuple[str, ...]
    expected_identity: str
    observed_identity: str
    result_identity: str = ""
    schema: str = LIFECYCLE_COMPARISON_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != LIFECYCLE_COMPARISON_SCHEMA
            or self.status not in {"pass", "fail"}
            or type(self.classified_differences) is not tuple
            or any(not _safe_token(item) for item in self.classified_differences)
            or len(set(self.classified_differences)) != len(
                self.classified_differences
            )
            or self.status != (
                "pass" if not self.classified_differences else "fail"
            )
            or not _safe_digest(self.expected_identity)
            or not _safe_digest(self.observed_identity)
        ):
            raise LifecycleObservationError("lifecycle comparison is invalid")
        core = {
            "schema": self.schema,
            "status": self.status,
            "classified_differences": list(self.classified_differences),
            "expected_identity": self.expected_identity,
            "observed_identity": self.observed_identity,
        }
        identity = _digest(core)
        if self.result_identity and self.result_identity != identity:
            raise LifecycleObservationError("lifecycle comparison identity drifted")
        object.__setattr__(self, "result_identity", identity)

    def public_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "status": self.status,
            "classified_differences": list(self.classified_differences),
            "expected_identity": self.expected_identity,
            "observed_identity": self.observed_identity,
            "result_identity": self.result_identity,
        }


def _difference_paths(expected: object, observed: object, prefix: str = "root") -> list[str]:
    if type(expected) is not type(observed):
        return [prefix]
    if type(expected) is dict:
        expected_map = expected
        observed_map = observed
        paths: list[str] = []
        for key in sorted(set(expected_map) | set(observed_map)):
            child = f"{prefix}.{key}"
            if key not in expected_map or key not in observed_map:
                paths.append(child)
            else:
                paths.extend(
                    _difference_paths(expected_map[key], observed_map[key], child)
                )
        return paths
    if type(expected) in (list, tuple):
        paths = []
        if len(expected) != len(observed):
            paths.append(f"{prefix}.length")
        for index, (left, right) in enumerate(zip(expected, observed)):
            paths.extend(_difference_paths(left, right, f"{prefix}.{index}"))
        return paths
    return [] if expected == observed else [prefix]


def compare_lifecycle_projections(
    expected: LifecycleShadowProjection,
    observed: LifecycleShadowProjection,
) -> LifecycleProjectionComparison:
    """Compare every semantic field; any declared or observed drift blocks."""

    if type(expected) is not LifecycleShadowProjection or type(observed) is not LifecycleShadowProjection:
        raise LifecycleObservationError("lifecycle comparison inputs are invalid")
    expected_payload = expected.semantic_payload()
    observed_payload = observed.semantic_payload()
    differences = _difference_paths(expected_payload, observed_payload)
    differences.extend(
        f"expected.{item}" for item in expected.classified_differences
    )
    differences.extend(
        f"observed.{item}" for item in observed.classified_differences
    )
    classified = tuple(sorted(set(differences)))
    return LifecycleProjectionComparison(
        "pass" if not classified else "fail",
        classified,
        _digest(expected_payload),
        _digest(observed_payload),
    )


def _receipt_value(receipt: object) -> dict[str, Any]:
    try:
        value = receipt.as_dict()
    except AttributeError as error:
        raise LifecycleObservationError("lifecycle seal receipt is invalid") from error
    if type(value) is not dict or set(value) != _SEAL_RECEIPT_FIELDS:
        raise LifecycleObservationError("lifecycle seal receipt is invalid")
    core = {key: item for key, item in value.items() if key != "receipt_digest"}
    if (
        value["schema"] != HARNESS_SEAL_RECEIPT_SCHEMA
        or value["status"] != "sealed"
        or value["event_schema"] != HARNESS_EVENT_SCHEMA
        or type(value["candidate_sha"]) is not str
        or _SHA.fullmatch(value["candidate_sha"]) is None
        or type(value["ready_at"]) is not int
        or value["ready_at"] < 0
        or type(value["event_count"]) is not int
        or value["event_count"] < 1
        or any(
            not _safe_digest(value[field])
            for field in (
                "plan_digest",
                "window_identity",
                "repository_identity",
                "head_event_digest",
                "head_entry_digest",
                "manifest_digest",
                "ledger_digest",
                "retention_identity",
                "receipt_digest",
            )
        )
        or value["receipt_digest"] != _digest(core)
    ):
        raise LifecycleObservationError("lifecycle seal receipt is invalid")
    return value


def project_lifecycle_events(
    plan_value: Mapping[str, Any],
    event_values: Sequence[Mapping[str, Any]],
    seal_receipt: object,
) -> LifecycleShadowProjection:
    """Project one already verified generic chain into the #49 profile boundary."""

    plan = _validated_plan(plan_value)
    seal = _receipt_value(seal_receipt)
    if (
        seal.get("candidate_sha") != plan["candidate_sha"]
        or seal.get("ready_at") != plan["ready_at"]
        or seal.get("window_identity") != plan["window_identity"]
        or seal.get("repository_identity") != plan["repository_identity"]
        or seal.get("plan_digest") != _digest(plan)
        or seal.get("event_count") != len(event_values)
    ):
        raise LifecycleObservationError("sealed lifecycle binding drifted")

    projected: list[ProjectedLifecycleEvent] = []
    started: dict[str, Mapping[str, Any]] = {}
    completed: dict[str, str] = {}
    accepted_attempt: str | None = None
    accepted_count = 0
    formal_advance_count = 0
    predecessor: str | None = None
    for sequence, raw in enumerate(event_values):
        if type(raw) is not dict or set(raw) != _EVENT_FIELDS:
            raise LifecycleObservationError("lifecycle event is incomplete")
        event = json.loads(_canonical_bytes(raw))
        event_digest = _digest(event)
        if (
            event["schema"] != HARNESS_EVENT_SCHEMA
            or event["sequence"] != sequence
            or event["predecessor_event_digest"] != predecessor
            or any(event[field] != plan[field] for field in (
                "window_identity",
                "repository_identity",
                "candidate_sha",
                "review_epoch",
                "review_round",
                "review_mode",
            ))
            or event["occurred_at"] < plan["ready_at"]
        ):
            raise LifecycleObservationError("lifecycle event moved outside its binding")
        attempt = event["attempt_identity"]
        transition = event["transition"]
        if transition == "attempt_started":
            if attempt in started or event["disposition"] != "pending":
                raise LifecycleObservationError("lifecycle attempt start is invalid")
            started[attempt] = event
        elif transition == "attempt_completed":
            start = started.get(attempt)
            if (
                start is None
                or attempt in completed
                or event["disposition"] == "pending"
                or any(
                    event[field] != start[field]
                    for field in ("role", "task_identity", "review_attempt")
                )
            ):
                raise LifecycleObservationError("lifecycle attempt completion is invalid")
            completed[attempt] = event["disposition"]
        elif transition == "result_accepted":
            if (
                event["role"] != "supervisor"
                or completed.get(attempt) != "pass"
                or accepted_attempt is not None
                or event["disposition"] != "accepted"
                or not event["accepted_result"]
            ):
                raise LifecycleObservationError("accepted lifecycle result is invalid")
            accepted_attempt = attempt
            accepted_count += 1
        elif transition == "formal_round_advanced":
            if (
                attempt != accepted_attempt
                or event["role"] != "supervisor"
                or event["disposition"] != "accepted"
                or not event["accepted_result"]
            ):
                raise LifecycleObservationError("formal lifecycle advancement is invalid")
            formal_advance_count += 1
        projected.append(
            ProjectedLifecycleEvent(
                sequence,
                event["occurred_at"],
                event["role"],
                event["task_identity"],
                attempt,
                event["review_attempt"],
                transition,
                event["disposition"],
                event["accepted_result"],
                event["successor_candidate_sha"],
                predecessor,
                tuple(event["artifact_references"]),
                event_digest,
            )
        )
        predecessor = event_digest
    if (
        not projected
        or set(started) != set(completed)
        or accepted_attempt is None
        or accepted_count != 1
        or formal_advance_count != 1
        or seal.get("head_event_digest") != predecessor
    ):
        raise LifecycleObservationError("lifecycle semantic chain is incomplete")
    return LifecycleShadowProjection(
        plan["candidate_sha"],
        plan["ready_at"],
        plan["window_identity"],
        plan["repository_identity"],
        plan["producer_identity"],
        plan["store_identity"],
        plan["capture_plan_digest"],
        seal["plan_digest"],
        plan["review_epoch"],
        plan["review_round"],
        plan["review_mode"],
        tuple(projected),
        accepted_attempt,
        seal["ledger_digest"],
        seal["manifest_digest"],
        seal["retention_identity"],
        seal["head_event_digest"],
        seal["head_entry_digest"],
    )


def project_verified_lifecycle(
    plan_value: Mapping[str, Any],
    store_root: Path,
    ledger_digest: str,
    *,
    harness_module: ModuleType | None = None,
) -> LifecycleShadowProjection:
    """Read back a sealed Harness ledger, then perform product projection."""

    if not isinstance(store_root, Path) or not _safe_digest(ledger_digest):
        raise LifecycleObservationError("verified lifecycle request is invalid")
    harness = _harness_lifecycle(harness_module)
    try:
        verified = harness.verify_lifecycle(store_root, ledger_digest)
        seal, events = harness.load_verified_lifecycle(store_root, ledger_digest)
    except Exception as error:
        if isinstance(error, LifecycleObservationError):
            raise
        raise LifecycleObservationError("lifecycle retention read-back failed") from error
    if _receipt_value(verified) != _receipt_value(seal):
        raise LifecycleObservationError("lifecycle verification receipt drifted")
    return project_lifecycle_events(plan_value, events, seal)


def _synthetic_plan(candidate_sha: str, ready_at: int) -> dict[str, object]:
    contract = lifecycle_observation_contract()
    capture_plan_digest = _digest(
        {
            "schema": "roundwright-lifecycle-synthetic-capture-plan/v1",
            "candidate_sha": candidate_sha,
            "ready_at": ready_at,
            "profile": LIVE_LIFECYCLE_SHADOW_PROFILE,
            "sequence": ["cancelled", "invalid_context", "pass", "accepted"],
            "contract_identity": contract["contract_identity"],
        }
    )
    window_identity = _digest(
        {
            "schema": "roundwright-lifecycle-synthetic-window/v1",
            "candidate_sha": candidate_sha,
            "ready_at": ready_at,
            "capture_plan_digest": capture_plan_digest,
        }
    )
    return {
        "schema": HARNESS_PLAN_SCHEMA,
        "window_identity": window_identity,
        "repository_identity": contract["repository_identity"],
        "candidate_sha": candidate_sha,
        "ready_at": ready_at,
        "producer_identity": contract["producer_identity"],
        "store_identity": _digest(
            {
                "schema": "roundwright-lifecycle-synthetic-store/v1",
                "window_identity": window_identity,
                "candidate_sha": candidate_sha,
            }
        ),
        "capture_plan_digest": capture_plan_digest,
        "review_epoch": 1,
        "review_round": 1,
        "review_mode": "complete",
    }


def _synthetic_events(plan: Mapping[str, object]) -> list[dict[str, object]]:
    task = _digest(
        {
            "schema": "roundwright-lifecycle-synthetic-task/v1",
            "candidate_sha": plan["candidate_sha"],
        }
    )
    specs = (
        (1, "attempt_started", "pending", False),
        (1, "attempt_completed", "cancelled", False),
        (2, "attempt_started", "pending", False),
        (2, "attempt_completed", "invalid_context", False),
        (3, "attempt_started", "pending", False),
        (3, "attempt_completed", "pass", False),
        (3, "result_accepted", "accepted", True),
        (3, "formal_round_advanced", "accepted", True),
    )
    events: list[dict[str, object]] = []
    predecessor: str | None = None
    for sequence, (attempt, transition, disposition, accepted) in enumerate(specs):
        event: dict[str, object] = {
            "schema": HARNESS_EVENT_SCHEMA,
            "window_identity": plan["window_identity"],
            "repository_identity": plan["repository_identity"],
            "candidate_sha": plan["candidate_sha"],
            "sequence": sequence,
            "occurred_at": plan["ready_at"] + sequence,
            "role": "supervisor",
            "task_identity": task,
            "attempt_identity": _digest(
                {
                    "schema": "roundwright-lifecycle-synthetic-attempt/v1",
                    "candidate_sha": plan["candidate_sha"],
                    "attempt": attempt,
                }
            ),
            "review_epoch": plan["review_epoch"],
            "review_round": plan["review_round"],
            "review_mode": plan["review_mode"],
            "review_attempt": attempt,
            "transition": transition,
            "disposition": disposition,
            "accepted_result": accepted,
            "successor_candidate_sha": None,
            "predecessor_event_digest": predecessor,
            "artifact_references": [
                supervisor_profile_artifact("sol", "xhigh") if attempt == 1
                else supervisor_profile_artifact("terra", "high"),
            ],
        }
        events.append(event)
        predecessor = _digest(event)
    return events


@dataclass(frozen=True)
class SyntheticLifecycleGateReceipt:
    candidate_sha: str
    ready_at: int
    plan_digest: str
    ledger_digest: str
    retention_identity: str
    comparison_identity: str
    event_count: int
    status: str = "pass"
    provider_calls: int = 0
    github_mutations: int = 0
    target_mutations: int = 0
    schema: str = LIFECYCLE_SYNTHETIC_RECEIPT_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != LIFECYCLE_SYNTHETIC_RECEIPT_SCHEMA
            or self.status != "pass"
            or _SHA.fullmatch(self.candidate_sha) is None
            or type(self.ready_at) is not int
            or self.ready_at < 0
            or any(
                not _safe_digest(value)
                for value in (
                    self.plan_digest,
                    self.ledger_digest,
                    self.retention_identity,
                    self.comparison_identity,
                )
            )
            or type(self.event_count) is not int
            or self.event_count < 1
            or any(
                value != 0
                for value in (
                    self.provider_calls,
                    self.github_mutations,
                    self.target_mutations,
                )
            )
        ):
            raise LifecycleObservationError("synthetic lifecycle receipt is invalid")

    def public_payload(self) -> dict[str, object]:
        return asdict(self)


def run_synthetic_lifecycle_gate(
    candidate_sha: str,
    ready_at: int,
    store_root: Path,
    *,
    harness_module: ModuleType | None = None,
) -> SyntheticLifecycleGateReceipt:
    """Exercise prepare/append/read-back/seal/project/compare without I/O routes."""

    if _SHA.fullmatch(candidate_sha) is None or type(ready_at) is not int or ready_at < 0:
        raise LifecycleObservationError("synthetic lifecycle binding is invalid")
    harness = _harness_lifecycle(harness_module)
    plan = _synthetic_plan(candidate_sha, ready_at)
    events = _synthetic_events(plan)
    try:
        armed = harness.prepare_lifecycle(plan, store_root)
        if armed.as_dict().get("status") != "armed":
            raise LifecycleObservationError("synthetic lifecycle arm failed")
        predecessor: str | None = None
        for sequence, event in enumerate(events):
            receipt = harness.append_lifecycle_event(plan, event, store_root)
            value = receipt.as_dict()
            if (
                value.get("status") != "appended"
                or value.get("sequence") != sequence
                or value.get("predecessor_event_digest") != predecessor
                or value.get("event_digest") != _digest(event)
            ):
                raise LifecycleObservationError(
                    "synthetic lifecycle append read-back failed"
                )
            predecessor = value["event_digest"]
        seal = harness.seal_lifecycle(plan, store_root)
        verified = harness.verify_lifecycle(store_root, seal.ledger_digest)
    except LifecycleObservationError:
        raise
    except Exception as error:
        raise LifecycleObservationError("synthetic lifecycle execution failed") from error
    if _receipt_value(seal) != _receipt_value(verified):
        raise LifecycleObservationError("synthetic lifecycle seal read-back failed")
    expected = project_lifecycle_events(plan, events, seal)
    observed = project_verified_lifecycle(
        plan,
        store_root,
        seal.ledger_digest,
        harness_module=harness,
    )
    comparison = compare_lifecycle_projections(expected, observed)
    if comparison.status != "pass" or comparison.classified_differences:
        raise LifecycleObservationError("synthetic lifecycle comparison failed")
    value = _receipt_value(seal)
    return SyntheticLifecycleGateReceipt(
        candidate_sha,
        ready_at,
        value["plan_digest"],
        value["ledger_digest"],
        value["retention_identity"],
        comparison.result_identity,
        value["event_count"],
    )
