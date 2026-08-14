"""Mandatory, public-safe identity for one resolved runtime configuration."""

from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass, field
from typing import Protocol


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCHEMA = "roundwright-runtime/v1"
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class RuntimeBindingError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeBinding:
    schema_version: str
    resolved_digest: str
    worker_profile_identity: str
    supervisor_profile_identities: tuple[str, ...]
    review_complete_rounds: int = field(default=0, compare=False)
    review_max_rounds: int = field(default=0, compare=False)
    review_max_supervisor_attempts_per_round: int = field(default=0, compare=False)
    review_on_final_findings: str = field(default="", compare=False)
    review_policy_digest: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA or not _DIGEST.fullmatch(self.resolved_digest):
            raise RuntimeBindingError("resolved configuration binding is invalid")
        if type(self.supervisor_profile_identities) is not tuple or not _DIGEST.fullmatch(self.worker_profile_identity) or not self.supervisor_profile_identities or len(set(self.supervisor_profile_identities)) != len(self.supervisor_profile_identities) or any(not _DIGEST.fullmatch(value) for value in self.supervisor_profile_identities):
            raise RuntimeBindingError("resolved configuration profile identity is invalid")
        policy_values = (
            self.review_complete_rounds, self.review_max_rounds,
            self.review_max_supervisor_attempts_per_round, self.review_on_final_findings,
            self.review_policy_digest,
        )
        if any(value != default for value, default in zip(policy_values, (0, 0, 0, "", ""), strict=True)):
            if (
                type(self.review_complete_rounds) is not int
                or type(self.review_max_rounds) is not int
                or type(self.review_max_supervisor_attempts_per_round) is not int
                or self.review_complete_rounds < 1
                or self.review_max_rounds < self.review_complete_rounds
                or self.review_max_supervisor_attempts_per_round != len(self.supervisor_profile_identities)
                or self.review_on_final_findings != "worker-final-repair-then-merge"
                or not _DIGEST.fullmatch("sha256:" + self.review_policy_digest)
            ):
                raise RuntimeBindingError("resolved review policy binding is invalid")

    def canonical_payload(self) -> dict[str, object]:
        return {"schema_version": self.schema_version, "resolved_digest": self.resolved_digest, "worker_profile_identity": self.worker_profile_identity, "supervisor_profile_identities": list(self.supervisor_profile_identities), "review_complete_rounds": self.review_complete_rounds, "review_max_rounds": self.review_max_rounds, "review_max_supervisor_attempts_per_round": self.review_max_supervisor_attempts_per_round, "review_on_final_findings": self.review_on_final_findings, "review_policy_digest": self.review_policy_digest}

    def canonical_material(self) -> str:
        return json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def from_canonical(cls, material: object) -> "RuntimeBinding":
        if type(material) is not str:
            raise RuntimeBindingError("runtime binding canonical material is invalid")
        try:
            payload = json.loads(material)
            expected = {"schema_version", "resolved_digest", "worker_profile_identity", "supervisor_profile_identities", "review_complete_rounds", "review_max_rounds", "review_max_supervisor_attempts_per_round", "review_on_final_findings", "review_policy_digest"}
            if type(payload) is not dict or set(payload) != expected or json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != material:
                raise ValueError
            binding = cls(payload["schema_version"], payload["resolved_digest"], payload["worker_profile_identity"], tuple(payload["supervisor_profile_identities"]), payload["review_complete_rounds"], payload["review_max_rounds"], payload["review_max_supervisor_attempts_per_round"], payload["review_on_final_findings"], payload["review_policy_digest"])
            policy = {"complete_rounds": binding.review_complete_rounds, "max_rounds": binding.review_max_rounds, "max_supervisor_attempts_per_round": binding.review_max_supervisor_attempts_per_round, "on_final_findings": binding.review_on_final_findings}
            if binding.review_policy_digest != hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest(): raise ValueError
            return binding
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeBindingError("runtime binding canonical material is invalid") from error

    def require_matches(self, other: object) -> None:
        if type(other) is not RuntimeBinding or (
            other.schema_version, other.resolved_digest, other.worker_profile_identity, other.supervisor_profile_identities,
            other.review_complete_rounds, other.review_max_rounds, other.review_max_supervisor_attempts_per_round,
            other.review_on_final_findings, other.review_policy_digest,
        ) != (
            self.schema_version, self.resolved_digest, self.worker_profile_identity, self.supervisor_profile_identities,
            self.review_complete_rounds, self.review_max_rounds, self.review_max_supervisor_attempts_per_round,
            self.review_on_final_findings, self.review_policy_digest,
        ):
            raise RuntimeBindingError("resolved configuration binding has drifted")

    @property
    def fingerprint(self) -> str:
        """Return an opaque identifier for carrying the full binding safely."""

        encoded = json.dumps(
            {
                "schema_version": self.schema_version,
                "resolved_digest": self.resolved_digest,
                "worker_profile_identity": self.worker_profile_identity,
                "supervisor_profile_identities": self.supervisor_profile_identities,
                "review_complete_rounds": self.review_complete_rounds,
                "review_max_rounds": self.review_max_rounds,
                "review_max_supervisor_attempts_per_round": self.review_max_supervisor_attempts_per_round,
                "review_on_final_findings": self.review_on_final_findings,
                "review_policy_digest": self.review_policy_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def columns(self) -> tuple[str, str, str, str]:
        """Stable SQLite representation, deliberately without configuration values."""

        return (
            self.schema_version,
            self.resolved_digest,
            self.worker_profile_identity,
            json.dumps(self.supervisor_profile_identities, separators=(",", ":")),
        )

    def complete_columns(self) -> tuple[str | int, ...]:
        """Return the complete durable identity, including review policy evidence."""

        return (
            *self.columns(),
            self.review_complete_rounds,
            self.review_max_rounds,
            self.review_max_supervisor_attempts_per_round,
            self.review_on_final_findings,
            self.review_policy_digest,
        )

    @property
    def has_review_policy(self) -> bool:
        return self.review_complete_rounds != 0

    def review_policy_columns(self) -> tuple[str, int, int, int, str, str]:
        if not self.has_review_policy:
            raise RuntimeBindingError("resolved review policy binding is unavailable")
        return (
            self.resolved_digest,
            self.review_complete_rounds,
            self.review_max_rounds,
            self.review_max_supervisor_attempts_per_round,
            self.review_on_final_findings,
            self.review_policy_digest,
        )


@dataclass(frozen=True)
class SupervisorRuntimeBindingReceipt:
    source_identity: str; record_identity: str; candidate_sha: str; context_identity: str; resolved_configuration_digest: str; runtime_content_digest: str; ready_at: int; freshness_until: int
    def __post_init__(self) -> None:
        if not all(_DIGEST.fullmatch(value) for value in (self.source_identity, self.record_identity, self.context_identity, self.resolved_configuration_digest, self.runtime_content_digest)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.ready_at < 0 or self.freshness_until < self.ready_at:
            raise RuntimeBindingError("supervisor runtime receipt is invalid")
    def payload(self) -> dict[str, object]: return self.__dict__.copy()
    @property
    def receipt_digest(self) -> str: return "sha256:" + hashlib.sha256(json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class ExternalSupervisorRuntimeStore(Protocol):
    def persist(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt: ...
    def read(self, receipt: SupervisorRuntimeBindingReceipt, *, evidence_time: int) -> RuntimeBinding: ...


class InMemorySupervisorRuntimeStore:
    def __init__(self, source_identity: str) -> None:
        if not _DIGEST.fullmatch(source_identity): raise RuntimeBindingError("supervisor runtime source is invalid")
        self._source_identity = source_identity; self._records: dict[str, str] = {}
    def persist(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt:
        if type(runtime) is not RuntimeBinding or not _SHA.fullmatch(candidate_sha) or not _DIGEST.fullmatch(context_identity) or type(ready_at) is not int or type(freshness_until) is not int or freshness_until < ready_at:
            raise RuntimeBindingError("supervisor runtime persist is invalid")
        material = runtime.canonical_material(); content = "sha256:" + hashlib.sha256(material.encode()).hexdigest()
        record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": self._source_identity, "candidate_sha": candidate_sha, "context_identity": context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": content, "ready_at": ready_at, "freshness_until": freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        receipt = SupervisorRuntimeBindingReceipt(self._source_identity, record, candidate_sha, context_identity, runtime.resolved_digest, content, ready_at, freshness_until)
        if record in self._records: raise RuntimeBindingError("supervisor runtime record already exists")
        self._records[record] = material; return receipt
    def read(self, receipt: SupervisorRuntimeBindingReceipt, *, evidence_time: int) -> RuntimeBinding:
        if type(receipt) is not SupervisorRuntimeBindingReceipt or type(evidence_time) is not int or not receipt.ready_at <= evidence_time <= receipt.freshness_until:
            raise RuntimeBindingError("supervisor runtime evidence time is invalid")
        material = self._records.get(receipt.record_identity)
        if material is None: raise RuntimeBindingError("supervisor runtime record is missing")
        runtime = RuntimeBinding.from_canonical(material); content = "sha256:" + hashlib.sha256(runtime.canonical_material().encode()).hexdigest()
        record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": self._source_identity, "candidate_sha": receipt.candidate_sha, "context_identity": receipt.context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": content, "ready_at": receipt.ready_at, "freshness_until": receipt.freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        expected = SupervisorRuntimeBindingReceipt(self._source_identity, record, receipt.candidate_sha, receipt.context_identity, runtime.resolved_digest, content, receipt.ready_at, receipt.freshness_until)
        if expected != receipt: raise RuntimeBindingError("supervisor runtime receipt drifted")
        return runtime
