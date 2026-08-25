"""Pure Phase 3 qualification consumer for the owner-facing Canary decision.

The #51 gate consumes sealed #49 and #50 evidence without pretending that
their historical candidates are the new qualification candidate. It performs
no Harness, provider, forward-target, lifecycle, or cleanup action.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Literal

from .external_validation import EvidenceLaneReceipt
from .integrated_boundary import ComposedEvidenceManifest, ComposedEvidenceResult, IntegratedBoundaryInputs, verify_composed_evidence
from .shadow import LIVE_LIFECYCLE_SHADOW_PROFILE, PHASE_3_QUALIFICATION_PROFILE, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE


QUALIFICATION_DECISION_SCHEMA = "roundwright-phase-3-qualification-decision/v1"
PROMOTION_READY_FOR_CANARY_DECISION = "PROMOTION_READY_FOR_CANARY_DECISION"
QUALIFICATION_BLOCKED = "QUALIFICATION_BLOCKED"
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class QualificationGateError(ValueError):
    """Raised when a retained qualification package has drifted or mixed data."""


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST = "sha256:5046fd4eed52db54f6b797464bf4faf4082290ec9cf12d3de194f624f8ca8d8a"
VERIFIED_ISSUE_50_HARNESS_RESULT_RECEIPT_DIGEST = "sha256:856d1722e4072a355b01312dd60f5501b564e1f147e17082b953a229ffb38f0f"
VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST = "sha256:9ac20eb13933909e5689bd1e843abc61b7485d79659c1b40a17aaccad3675c91"
VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST = "sha256:2198caba23a2c0e2f0cb0deeeb64730c43c5bf0e3df6f65256da1c0fde21ed01"
STALE_ISSUE_50_TRACE_DIGEST = "sha256:5046fd4e0c805cefacbe92dd28f72c95be164baad0caa35e7414cab198478d8a"


def issue_51_selection_trace_correction() -> dict[str, str]:
    """Curated non-mutating disposition for the known #51 selection-trace drift."""

    return {
        "disposition": "ORCHESTRATOR_TRACE_CORRECTION_REQUIRED",
        "recorded_digest": STALE_ISSUE_50_TRACE_DIGEST,
        "verified_digest": VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST,
        "required_action": "publish-and-semantic-read-back-curated-trace-correction",
    }


class QualificationGateKind(StrEnum):
    FORMAL_REVIEW = "formal-review"
    HOSTED_CHECKS = "hosted-checks"
    POLICY = "policy"
    PROVENANCE = "provenance"


_GATE_RECEIPT_SCHEMAS = {
    QualificationGateKind.FORMAL_REVIEW: "roundwright-formal-review-receipt/v1",
    QualificationGateKind.HOSTED_CHECKS: "roundwright-exact-head-check-receipt/v1",
    QualificationGateKind.POLICY: "roundwright-policy-receipt/v1",
    QualificationGateKind.PROVENANCE: "roundwright-provenance-receipt/v1",
}


def _canonical_receipt(value: object, digest_key: str) -> dict[str, object]:
    if type(value) is not dict or type(value.get(digest_key)) is not str:
        raise QualificationGateError("qualification receipt is invalid")
    core = {key: item for key, item in value.items() if key != digest_key}
    if value[digest_key] != _digest(core):
        raise QualificationGateError("qualification receipt is invalid")
    return dict(value)


def _validated_gate_source_receipt(
    source_receipt: object,
    kind: QualificationGateKind,
    candidate_sha: str,
    case_id: str,
    review_epoch: int,
    review_round: int,
    review_mode: str,
) -> dict[str, object]:
    try:
        receipt = _canonical_receipt(source_receipt, "receipt_digest")
        common = {
            "candidate_sha": candidate_sha, "case_id": case_id,
            "review_epoch": review_epoch, "review_round": review_round,
            "review_mode": review_mode,
        }
        required = {
            QualificationGateKind.FORMAL_REVIEW: {
                "schema", "candidate_sha", "case_id", "review_epoch", "review_round", "review_mode",
                "formal_result", "supervisor_result_identity", "receipt_digest",
            },
            QualificationGateKind.HOSTED_CHECKS: {
                "schema", "candidate_sha", "case_id", "review_epoch", "review_round", "review_mode",
                "head_sha", "check_run_identity", "conclusion", "receipt_digest",
            },
            QualificationGateKind.POLICY: {
                "schema", "candidate_sha", "case_id", "review_epoch", "review_round", "review_mode",
                "policy_snapshot_digest", "policy_outcome", "receipt_digest",
            },
            QualificationGateKind.PROVENANCE: {
                "schema", "candidate_sha", "case_id", "review_epoch", "review_round", "review_mode",
                "source_sha", "provenance_manifest_digest", "verification", "receipt_digest",
            },
        }[kind]
        if set(receipt) != required or receipt["schema"] != _GATE_RECEIPT_SCHEMAS[kind] or any(receipt[key] != value for key, value in common.items()):
            raise ValueError
        if kind is QualificationGateKind.FORMAL_REVIEW:
            valid = receipt["formal_result"] == "accepted" and _DIGEST.fullmatch(str(receipt["supervisor_result_identity"])) is not None
        elif kind is QualificationGateKind.HOSTED_CHECKS:
            valid = receipt["head_sha"] == candidate_sha and receipt["conclusion"] == "success" and _DIGEST.fullmatch(str(receipt["check_run_identity"])) is not None
        elif kind is QualificationGateKind.POLICY:
            valid = receipt["policy_outcome"] == "pass" and _DIGEST.fullmatch(str(receipt["policy_snapshot_digest"])) is not None
        else:
            valid = receipt["source_sha"] == candidate_sha and receipt["verification"] == "pass" and _DIGEST.fullmatch(str(receipt["provenance_manifest_digest"])) is not None
        if not valid:
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError, QualificationGateError) as error:
        raise QualificationGateError("qualification gate source receipt is invalid or stale") from error
    if receipt["receipt_digest"] != _digest({key: value for key, value in receipt.items() if key != "receipt_digest"}):
        raise QualificationGateError("qualification gate source receipt is invalid or stale")
    return receipt


@dataclass(frozen=True, slots=True)
class QualificationGateReceipt:
    """One parsed, candidate-bound normal-gate read-back receipt."""

    kind: QualificationGateKind
    candidate_sha: str
    case_id: str
    review_epoch: int
    review_round: int
    review_mode: str
    result: Literal["pass"]
    source_receipt: dict[str, object]
    source_identity: str = field(init=False)
    receipt_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.kind) is not QualificationGateKind or _SHA.fullmatch(self.candidate_sha) is None
            or _TOKEN.fullmatch(self.case_id) is None or type(self.review_epoch) is not int or self.review_epoch < 0
            or type(self.review_round) is not int or self.review_round < 0 or self.review_mode != "COMPLETE"
            or self.result != "pass"):
            raise QualificationGateError("qualification gate receipt is invalid")
        source_receipt = _validated_gate_source_receipt(
            self.source_receipt, self.kind, self.candidate_sha, self.case_id,
            self.review_epoch, self.review_round, self.review_mode,
        )
        object.__setattr__(self, "source_identity", str(source_receipt["receipt_digest"]))
        object.__setattr__(self, "receipt_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"kind": self.kind.value, "candidate_sha": self.candidate_sha, "case_id": self.case_id,
            "review_epoch": self.review_epoch, "review_round": self.review_round, "review_mode": self.review_mode,
            "result": self.result, "source_receipt": self.source_receipt, "source_identity": self.source_identity}
        return value | ({"receipt_digest": self.receipt_digest} if include_digest else {})

    def validate(self) -> None:
        rebuilt = replace(self)
        if (rebuilt.source_identity, rebuilt.receipt_digest) != (self.source_identity, self.receipt_digest):
            raise QualificationGateError("qualification gate receipt has drifted")


@dataclass(frozen=True, slots=True)
class QualificationGateAuthority:
    """Immutable read-back copies of the four accepted gate authorities."""

    receipts: tuple[dict[str, object], ...]
    authority_digest: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            if type(self.receipts) is not tuple or len(self.receipts) != len(QualificationGateKind):
                raise ValueError
            for kind, receipt in zip(QualificationGateKind, self.receipts, strict=True):
                _validated_gate_source_receipt(
                    receipt, kind, str(receipt["candidate_sha"]), str(receipt["case_id"]),
                    receipt["review_epoch"], receipt["review_round"], str(receipt["review_mode"]),
                )
        except (AttributeError, KeyError, TypeError, ValueError, QualificationGateError) as error:
            raise QualificationGateError("qualification gate authorities are invalid") from error
        object.__setattr__(self, "authority_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"receipts": list(self.receipts)}
        return value | ({"authority_digest": self.authority_digest} if include_digest else {})

    def validate(self) -> None:
        rebuilt = QualificationGateAuthority(self.receipts)
        if rebuilt.authority_digest != self.authority_digest:
            raise QualificationGateError("qualification gate authorities have drifted")


@dataclass(frozen=True, slots=True)
class QualificationGateReceiptSet:
    """Exact four-gate read-back set, bound to independent authority payloads."""

    receipts: tuple[QualificationGateReceipt, ...]
    binding_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.receipts) is not tuple or any(type(item) is not QualificationGateReceipt for item in self.receipts)
            or tuple(item.kind for item in self.receipts) != tuple(QualificationGateKind)
            or len({item.receipt_digest for item in self.receipts}) != len(self.receipts)):
            raise QualificationGateError("qualification gate receipt set is invalid")
        object.__setattr__(self, "binding_digest", _digest(self.public_payload(include_digest=False)))

    def validate_for(self, candidate_sha: str, case_id: str, authorities: QualificationGateAuthority) -> None:
        try:
            if type(self) is not QualificationGateReceiptSet or type(authorities) is not QualificationGateAuthority:
                raise QualificationGateError
            authorities.validate()
            for item, authority_receipt in zip(self.receipts, authorities.receipts, strict=True):
                item.validate()
                if (item.candidate_sha, item.case_id) != (candidate_sha, case_id) or item.source_receipt != authority_receipt:
                    raise QualificationGateError
        except (AttributeError, TypeError, QualificationGateError) as error:
            raise QualificationGateError("qualification gate receipts have drifted") from error
        if self.binding_digest != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("qualification gate receipts have drifted")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"receipts": [item.public_payload() for item in self.receipts]}
        return value | ({"binding_digest": self.binding_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class RetainedIssue50ManifestIdentities:
    """The distinct immutable manifest identities consumed by #51."""

    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str

    def __post_init__(self) -> None:
        if (
            type(self) is not RetainedIssue50ManifestIdentities
            or (self.issue_49_retention_manifest_digest, self.issue_50_retention_manifest_digest)
            != (VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST, VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST)
        ):
            raise QualificationGateError("retained issue-50 manifest identities are invalid")

    def public_payload(self) -> dict[str, str]:
        return {
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
        }


@dataclass(frozen=True, slots=True)
class RetainedIssue50BundleReceipt:
    """Parsed retained #50 Harness result and its recording receipt."""

    harness_result: dict[str, object]
    recording_receipt: dict[str, object]
    bundle_bytes: bytes
    manifest_identities: RetainedIssue50ManifestIdentities = field(init=False)
    receipt_identity: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            result = _canonical_receipt(self.harness_result, "receipt_digest")
            recording = _canonical_receipt(self.recording_receipt, "receipt_digest")
            result_required = {
                "schema", "status", "state", "candidate_sha", "case_id", "ready_at", "profile", "plan_digest",
                "readiness_receipt_digest", "result_identity", "bundle_digest", "recording_receipt_digest", "retention_identity",
                "dispatch_count", "record_count", "verify_count", "mutation_count", "execution_context_input_digest",
                "execution_context_identity", "receipt_digest",
            }
            recording_required = {
                "schema", "status", "candidate_sha", "case_id", "ready_at", "profile", "evidence_digest", "evidence_schema",
                "manifest_digest", "bundle_digest", "retention_identity", "receipt_digest",
            }
            if (
                set(result) != result_required or set(recording) != recording_required
                or result["schema"] != "roundwright-harness-profile-executor-result/v2"
                or result["status"] != "pass" or result["state"] != "VERIFIED" or result["mutation_count"] != 0
                or (result["dispatch_count"], result["record_count"], result["verify_count"], result["mutation_count"]) != (1, 1, 1, 0)
                or recording["schema"] != "roundwright-harness-recording-receipt/v1" or recording["status"] != "sealed"
                or recording["evidence_schema"] != "roundwright-shadow-case/v2"
                or _SHA.fullmatch(str(result["candidate_sha"])) is None
                or type(result["ready_at"]) is not int or result["ready_at"] < 0
                or any(_DIGEST.fullmatch(str(result[key])) is None for key in ("plan_digest", "readiness_receipt_digest", "result_identity", "bundle_digest", "recording_receipt_digest", "retention_identity", "execution_context_input_digest", "execution_context_identity"))
                or any(_DIGEST.fullmatch(str(recording[key])) is None for key in ("evidence_digest", "manifest_digest", "bundle_digest", "retention_identity"))
                or any(result[key] != recording[key] for key in ("candidate_sha", "case_id", "ready_at", "profile", "bundle_digest", "retention_identity"))
                or result["recording_receipt_digest"] != recording["receipt_digest"]
                or result["bundle_digest"] != VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST
                or result["receipt_digest"] != VERIFIED_ISSUE_50_HARNESS_RESULT_RECEIPT_DIGEST
            ):
                raise ValueError
            if type(self.bundle_bytes) is not bytes:
                raise ValueError
            bundle = json.loads(self.bundle_bytes)
            canonical_bundle = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            if "sha256:" + hashlib.sha256(canonical_bundle).hexdigest() != result["bundle_digest"]:
                raise ValueError
            manifest = bundle["manifest"]
            evidence = bundle["evidence"]
            if (
                type(bundle) is not dict or set(bundle) != {"schema", "evidence", "manifest", "manifest_digest"}
                or bundle["schema"] != "roundwright-harness-recording-bundle/v1" or type(manifest) is not dict or type(evidence) is not dict
                or bundle["manifest_digest"] != recording["manifest_digest"] or _digest(manifest) != recording["manifest_digest"]
                or _digest(evidence) != recording["evidence_digest"]
                or set(manifest) != {"schema", "profile", "candidate_sha", "case_id", "ready_at", "evidence_schema", "evidence_digest"}
                or any(manifest[key] != recording[key] for key in ("profile", "candidate_sha", "case_id", "ready_at", "evidence_schema", "evidence_digest"))
                or evidence["integrated_boundary"]["manifest"]["retention_manifest_digest"] != VERIFIED_ISSUE_49_RETENTION_MANIFEST_DIGEST
            ):
                raise ValueError
        except (AttributeError, KeyError, TypeError, ValueError, QualificationGateError) as error:
            raise QualificationGateError("retained issue-50 bundle receipt is invalid") from error
        if _digest({"harness_result": result, "recording_receipt": recording}) != _digest({"harness_result": self.harness_result, "recording_receipt": self.recording_receipt}):
            raise QualificationGateError("retained issue-50 bundle receipt is invalid")
        object.__setattr__(self, "manifest_identities", RetainedIssue50ManifestIdentities(
            str(evidence["integrated_boundary"]["manifest"]["retention_manifest_digest"]),
            VERIFIED_ISSUE_50_RETENTION_MANIFEST_DIGEST,
        ))
        object.__setattr__(self, "receipt_identity", _digest(self.public_payload(include_identity=False)))

    @property
    def candidate_sha(self) -> str:
        return str(self.harness_result["candidate_sha"])

    @property
    def issue_49_retention_manifest_digest(self) -> str:
        """The #49 manifest embedded in the retained #50 composition."""

        return self.manifest_identities.issue_49_retention_manifest_digest

    @property
    def issue_50_retention_manifest_digest(self) -> str:
        """The separately retained #50 manifest bound to this exact receipt."""

        return self.manifest_identities.issue_50_retention_manifest_digest

    @property
    def composed_manifest_digest(self) -> str:
        return str(self.bundle_document["evidence"]["integrated_boundary"]["manifest"]["manifest_digest"])

    @property
    def composed_result_digest(self) -> str:
        return str(self.bundle_document["evidence"]["integrated_boundary"]["result"]["result_digest"])

    @property
    def bundle_digest(self) -> str:
        return str(self.harness_result["bundle_digest"])

    @property
    def bundle_document(self) -> dict[str, object]:
        return json.loads(self.bundle_bytes)

    def public_payload(self, *, include_identity: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "harness_result": self.harness_result,
            "recording_receipt": self.recording_receipt,
            "bundle_digest": self.bundle_digest,
            "manifest_identities": self.manifest_identities.public_payload(),
        }
        return value | ({"receipt_identity": self.receipt_identity} if include_identity else {})

    def validate(self) -> None:
        if type(self) is not RetainedIssue50BundleReceipt or self.receipt_identity != _digest(self.public_payload(include_identity=False)):
            raise QualificationGateError("retained issue-50 bundle receipt has drifted")
        try:
            RetainedIssue50BundleReceipt(self.harness_result, self.recording_receipt, self.bundle_bytes)
        except (TypeError, QualificationGateError) as error:
            raise QualificationGateError("retained issue-50 bundle receipt has drifted") from error


class TemporaryResourceKind(StrEnum):
    REPLAYABLE = "replayable"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


class TemporaryResourceDisposition(StrEnum):
    REMOVED = "removed"
    PRESERVED = "preserved"


@dataclass(frozen=True, slots=True)
class RetainedEvidencePins:
    """Selection-time expected identities from the immutable Roundlet contract."""

    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str
    issue_50_result_bundle_digest: str
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (any(_DIGEST.fullmatch(value) is None for value in self.payload().values())
            or self.issue_50_result_bundle_digest != VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST):
            raise QualificationGateError("retained evidence pins are invalid")
        object.__setattr__(self, "integrity_digest", _digest(self.payload()))

    def payload(self) -> dict[str, str]:
        return {
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
            "issue_50_result_bundle_digest": self.issue_50_result_bundle_digest,
        }

    def validate(self) -> None:
        if type(self) is not RetainedEvidencePins or self.integrity_digest != _digest(self.payload()):
            raise QualificationGateError("retained evidence pins have drifted")


@dataclass(frozen=True, slots=True)
class RetainedEvidenceObservations:
    """Read-back identities for the same three retained artifacts."""

    issue_49_retention_manifest_digest: str
    issue_50_retention_manifest_digest: str
    issue_50_result_bundle_digest: str
    integrity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (any(_DIGEST.fullmatch(value) is None for value in self.payload().values())
            or self.issue_50_result_bundle_digest != VERIFIED_ISSUE_50_RESULT_BUNDLE_DIGEST):
            raise QualificationGateError("retained evidence observations are invalid")
        object.__setattr__(self, "integrity_digest", _digest(self.payload()))

    def payload(self) -> dict[str, str]:
        return {
            "issue_49_retention_manifest_digest": self.issue_49_retention_manifest_digest,
            "issue_50_retention_manifest_digest": self.issue_50_retention_manifest_digest,
            "issue_50_result_bundle_digest": self.issue_50_result_bundle_digest,
        }

    def validate(self) -> None:
        if type(self) is not RetainedEvidenceObservations or self.integrity_digest != _digest(self.payload()):
            raise QualificationGateError("retained evidence observations have drifted")


@dataclass(frozen=True, slots=True)
class RetainedEvidenceBinding:
    """Closed expected-versus-observed binding; neither side may be substituted."""

    expected: RetainedEvidencePins
    observed: RetainedEvidenceObservations
    binding_digest: str = field(init=False)

    def __post_init__(self) -> None:
        self.validate()
        object.__setattr__(self, "binding_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        if type(self) is not RetainedEvidenceBinding or type(self.expected) is not RetainedEvidencePins or type(self.observed) is not RetainedEvidenceObservations:
            raise QualificationGateError("retained evidence binding is invalid")
        self.expected.validate(); self.observed.validate()
        if self.expected.payload() != self.observed.payload():
            raise QualificationGateError("retained evidence read-back does not match selection")
        current = getattr(self, "binding_digest", None)
        if current is not None and current != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("retained evidence binding has drifted")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "expected": self.expected.payload(), "expected_integrity_digest": self.expected.integrity_digest,
            "observed": self.observed.payload(), "observed_integrity_digest": self.observed.integrity_digest,
        }
        return value | ({"binding_digest": self.binding_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class TemporaryResourceEntry:
    """A path-free cleanup disposition; unique or ambiguous work is preserved."""

    resource_identity: str
    kind: TemporaryResourceKind
    disposition: TemporaryResourceDisposition

    def __post_init__(self) -> None:
        if (
            _DIGEST.fullmatch(self.resource_identity) is None
            or type(self.kind) is not TemporaryResourceKind
            or type(self.disposition) is not TemporaryResourceDisposition
            or (self.kind is TemporaryResourceKind.REPLAYABLE) != (self.disposition is TemporaryResourceDisposition.REMOVED)
        ):
            raise QualificationGateError("temporary resource disposition is invalid")

    def public_payload(self) -> dict[str, str]:
        return {"resource_identity": self.resource_identity, "kind": self.kind.value, "disposition": self.disposition.value}


@dataclass(frozen=True, slots=True)
class TemporaryResourceInventory:
    """Recomputed inventory identity, never an arbitrary digest or Boolean."""

    entries: tuple[TemporaryResourceEntry, ...]
    inventory_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(type(entry) is not TemporaryResourceEntry for entry in self.entries) or len({entry.resource_identity for entry in self.entries}) != len(self.entries):
            raise QualificationGateError("temporary resource inventory is invalid")
        object.__setattr__(self, "inventory_digest", _digest(self.public_payload(include_digest=False)))

    @property
    def fully_reconciled(self) -> bool:
        return all(
            (entry.kind is TemporaryResourceKind.REPLAYABLE and entry.disposition is TemporaryResourceDisposition.REMOVED)
            or (entry.kind in {TemporaryResourceKind.UNIQUE, TemporaryResourceKind.AMBIGUOUS} and entry.disposition is TemporaryResourceDisposition.PRESERVED)
            for entry in self.entries
        )

    @property
    def promotion_eligible(self) -> bool:
        """Preserved unique/ambiguous work is safe, but blocks promotion."""

        return self.fully_reconciled and not any(
            entry.kind in {TemporaryResourceKind.UNIQUE, TemporaryResourceKind.AMBIGUOUS}
            for entry in self.entries
        )

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {"entries": [entry.public_payload() for entry in self.entries]}
        return value | ({"inventory_digest": self.inventory_digest} if include_digest else {})

    def validate(self) -> None:
        if type(self) is not TemporaryResourceInventory:
            raise QualificationGateError("temporary resource inventory has drifted")
        try:
            for entry in self.entries:
                TemporaryResourceEntry(entry.resource_identity, entry.kind, entry.disposition)
        except (AttributeError, TypeError, QualificationGateError) as error:
            raise QualificationGateError("temporary resource inventory has drifted") from error
        if self.inventory_digest != _digest(self.public_payload(include_digest=False)):
            raise QualificationGateError("temporary resource inventory has drifted")


@dataclass(frozen=True, slots=True)
class Phase3QualificationInputs:
    """Closed #51 consumer inputs with distinct #49, #50, and #51 lineages."""

    base_sha: str
    qualification_candidate_sha: str
    qualification_case_id: str
    qualification_ready_at: int
    qualification_review_epoch: int
    qualification_review_round: int
    qualification_review_mode: str
    qualification_capture_plan_digest: str
    qualification_recorder_identity: str
    qualification_store_identity: str
    issue_49_candidate_sha: str
    issue_50_candidate_sha: str
    roundlet_commit: str
    harness_commit: str
    forward_target_commit: str
    rollback_proposal_digest: str
    kill_switch_proposal_digest: str
    retained_evidence: RetainedEvidenceBinding
    issue_50_bundle_receipt: RetainedIssue50BundleReceipt
    temporary_resources: TemporaryResourceInventory
    integrated_inputs: IntegratedBoundaryInputs
    composed_manifest: ComposedEvidenceManifest
    composed_result: ComposedEvidenceResult
    lane_a: EvidenceLaneReceipt
    lane_b: EvidenceLaneReceipt
    current_gate_receipts: QualificationGateReceiptSet
    unresolved_blockers: tuple[QualificationGateKind, ...] = ()
    input_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            any(_SHA.fullmatch(value) is None for value in (self.base_sha, self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha, self.roundlet_commit, self.harness_commit, self.forward_target_commit))
            or _TOKEN.fullmatch(self.qualification_case_id) is None or type(self.qualification_ready_at) is not int or self.qualification_ready_at < 0
            or type(self.qualification_review_epoch) is not int or self.qualification_review_epoch < 0 or type(self.qualification_review_round) is not int or self.qualification_review_round < 0 or self.qualification_review_mode != "COMPLETE"
            or any(_DIGEST.fullmatch(value) is None for value in (self.qualification_capture_plan_digest, self.qualification_recorder_identity, self.qualification_store_identity, self.rollback_proposal_digest, self.kill_switch_proposal_digest))
            or len({self.qualification_candidate_sha, self.issue_49_candidate_sha, self.issue_50_candidate_sha}) != 3
            or type(self.retained_evidence) is not RetainedEvidenceBinding or type(self.issue_50_bundle_receipt) is not RetainedIssue50BundleReceipt or type(self.temporary_resources) is not TemporaryResourceInventory
            or type(self.integrated_inputs) is not IntegratedBoundaryInputs or type(self.composed_manifest) is not ComposedEvidenceManifest or type(self.composed_result) is not ComposedEvidenceResult
            or type(self.lane_a) is not EvidenceLaneReceipt or type(self.lane_b) is not EvidenceLaneReceipt or type(self.current_gate_receipts) is not QualificationGateReceiptSet
            or type(self.unresolved_blockers) is not tuple or any(type(value) is not QualificationGateKind for value in self.unresolved_blockers) or len(set(self.unresolved_blockers)) != len(self.unresolved_blockers)
        ):
            raise QualificationGateError("phase-3 qualification evidence is invalid")
        self.retained_evidence.validate(); self.issue_50_bundle_receipt.validate(); self.temporary_resources.validate()
        if any((item.review_epoch, item.review_round, item.review_mode) != (self.qualification_review_epoch, self.qualification_review_round, self.qualification_review_mode) for item in self.current_gate_receipts.receipts):
            raise QualificationGateError("qualification gate receipts have a stale formal review binding")
        if (
            not verify_composed_evidence(self.composed_manifest, self.composed_result)
            or self.composed_manifest.inputs != self.integrated_inputs or self.composed_result.manifest != self.composed_manifest
            or self.integrated_inputs.expectation.retention_manifest_digest != self.retained_evidence.expected.issue_49_retention_manifest_digest
            or (self.issue_50_bundle_receipt.candidate_sha, self.issue_50_bundle_receipt.harness_result["case_id"], self.issue_50_bundle_receipt.issue_49_retention_manifest_digest, self.issue_50_bundle_receipt.composed_manifest_digest, self.issue_50_bundle_receipt.composed_result_digest, self.issue_50_bundle_receipt.bundle_digest)
            != (self.issue_50_candidate_sha, self.integrated_inputs.case_id, self.retained_evidence.expected.issue_49_retention_manifest_digest, self.composed_manifest.manifest_digest, self.composed_result.result_digest, self.retained_evidence.expected.issue_50_result_bundle_digest)
            or self.retained_evidence.expected.issue_50_retention_manifest_digest != self.issue_50_bundle_receipt.issue_50_retention_manifest_digest
            or self.composed_result.result != "pass"
            or self.composed_manifest.inputs.candidate_sha != self.issue_50_candidate_sha or self.composed_result.manifest.inputs.candidate_sha != self.issue_50_candidate_sha
            or self.integrated_inputs.lane_a.candidate_sha != self.issue_49_candidate_sha or self.integrated_inputs.lane_b.candidate_sha != self.issue_49_candidate_sha
            or self.lane_a.candidate_sha != self.issue_49_candidate_sha or self.lane_b.candidate_sha != self.issue_49_candidate_sha
            or self.lane_a.profile_id != READ_ONLY_EXTERNAL_OBSERVATION_PROFILE or self.lane_b.profile_id != LIVE_LIFECYCLE_SHADOW_PROFILE
        ):
            raise QualificationGateError("phase-3 qualification lineage is invalid")
        composed = self.composed_manifest.public_payload()
        if composed["new_provider_calls"] != 0 or composed["new_target_actions"] != 0 or composed["lifecycle_observation_sink"] != "NOT_SELECTED":
            raise QualificationGateError("phase-3 qualification evidence is not consumer-only")
        object.__setattr__(self, "input_digest", _digest(self.public_payload(include_digest=False)))

    def validate(self) -> None:
        """Reconstruct this closed input tuple to detect post-build drift."""

        try:
            rebuilt = replace(self)
        except (AttributeError, TypeError, ValueError, QualificationGateError) as error:
            raise QualificationGateError("phase-3 qualification evidence has drifted") from error
        if rebuilt.input_digest != self.input_digest:
            raise QualificationGateError("phase-3 qualification evidence has drifted")

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE,
            "base_sha": self.base_sha, "qualification_candidate_sha": self.qualification_candidate_sha,
            "qualification_case_id": self.qualification_case_id, "qualification_ready_at": self.qualification_ready_at,
            "qualification_review_epoch": self.qualification_review_epoch, "qualification_review_round": self.qualification_review_round, "qualification_review_mode": self.qualification_review_mode,
            "qualification_capture_plan_digest": self.qualification_capture_plan_digest,
            "qualification_recorder_identity": self.qualification_recorder_identity,
            "qualification_store_identity": self.qualification_store_identity,
            "issue_49_candidate_sha": self.issue_49_candidate_sha, "issue_50_candidate_sha": self.issue_50_candidate_sha,
            "roundlet_commit": self.roundlet_commit, "harness_commit": self.harness_commit, "forward_target_commit": self.forward_target_commit,
            "rollback_proposal_digest": self.rollback_proposal_digest, "kill_switch_proposal_digest": self.kill_switch_proposal_digest,
            "retained_evidence": self.retained_evidence.public_payload(), "temporary_resources": self.temporary_resources.public_payload(),
            "issue_50_bundle_receipt": self.issue_50_bundle_receipt.public_payload(), "current_gate_receipts": self.current_gate_receipts.public_payload(),
            "retained_issue_50_capture_plan_digest": self.integrated_inputs.capture_plan_digest,
            "composed_manifest_digest": self.composed_manifest.manifest_digest,
            "composed_result_digest": self.composed_result.result_digest,
            "retained_sources": [source.public_payload() | {"source_digest": source.source_digest} for source in (self.integrated_inputs.lane_a, self.integrated_inputs.lane_b, self.integrated_inputs.historical_reference, self.integrated_inputs.synthetic_reference)],
            "composed_manifest": self.composed_manifest.public_payload(), "composed_result": self.composed_result.public_payload(),
            "lane_a": {"state": self.lane_a.state, "result": self.lane_a.result}, "lane_b": {"state": self.lane_b.state, "result": self.lane_b.result},
            "unresolved_blockers": [item.value for item in self.unresolved_blockers], "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"input_digest": self.input_digest} if include_digest else {})


@dataclass(frozen=True, slots=True)
class CanaryEntryDecisionPackage:
    """Public-safe owner decision package; never an authority or action receipt."""

    inputs: Phase3QualificationInputs
    disposition: Literal["PROMOTION_READY_FOR_CANARY_DECISION", "QUALIFICATION_BLOCKED"]
    decision_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.inputs) is not Phase3QualificationInputs or self.disposition not in {PROMOTION_READY_FOR_CANARY_DECISION, QUALIFICATION_BLOCKED}:
            raise QualificationGateError("Canary-entry decision package is invalid")
        object.__setattr__(self, "decision_digest", _digest(self.public_payload(include_digest=False)))

    def public_payload(self, *, include_digest: bool = True) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": QUALIFICATION_DECISION_SCHEMA, "profile": PHASE_3_QUALIFICATION_PROFILE, "disposition": self.disposition,
            "input_digest": self.inputs.input_digest, "base_sha": self.inputs.base_sha,
            "qualification_candidate_sha": self.inputs.qualification_candidate_sha, "issue_49_candidate_sha": self.inputs.issue_49_candidate_sha,
            "issue_50_candidate_sha": self.inputs.issue_50_candidate_sha, "composed_manifest_digest": self.inputs.composed_manifest.manifest_digest,
            "composed_result_digest": self.inputs.composed_result.result_digest, "canary_action_authorized": False,
            "qualification": self.inputs.public_payload(),
            "runtime_activation_authorized": False, "roundlet_retirement_authorized": False,
            "new_provider_calls": 0, "new_target_actions": 0, "lifecycle_observation_sink": "NOT_SELECTED",
        }
        return value | ({"decision_digest": self.decision_digest} if include_digest else {})


def assess_phase_3_qualification(inputs: Phase3QualificationInputs, gate_authority: QualificationGateAuthority) -> CanaryEntryDecisionPackage:
    """Evaluate retained evidence without external calls, storage, or cleanup."""

    if type(inputs) is not Phase3QualificationInputs or type(gate_authority) is not QualificationGateAuthority:
        raise QualificationGateError("phase-3 qualification inputs are invalid")
    inputs.validate()
    inputs.current_gate_receipts.validate_for(inputs.qualification_candidate_sha, inputs.qualification_case_id, gate_authority)
    lanes_pass = (inputs.lane_a.state, inputs.lane_a.result, inputs.lane_b.state, inputs.lane_b.result) == ("verified", "pass", "verified", "pass")
    ready = lanes_pass and inputs.temporary_resources.promotion_eligible and not inputs.unresolved_blockers
    return CanaryEntryDecisionPackage(inputs, PROMOTION_READY_FOR_CANARY_DECISION if ready else QUALIFICATION_BLOCKED)
