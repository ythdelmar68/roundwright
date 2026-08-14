"""Mandatory, public-safe identity for one resolved runtime configuration."""

from __future__ import annotations

import re
import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCHEMA = "roundwright-runtime/v1"
_RECEIPT_SCHEMA = "roundwright-supervisor-runtime-receipt/v1"
def _reparse(value: Path) -> bool: return value.is_symlink() or bool(getattr(value, "is_junction", lambda: False)())
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
    source_identity: str; record_identity: str; candidate_sha: str; context_identity: str; resolved_configuration_digest: str; runtime_content_digest: str; ready_at: int; freshness_until: int; schema: str = _RECEIPT_SCHEMA; canonical_material_digest: str = ""
    def __post_init__(self) -> None:
        if self.schema != _RECEIPT_SCHEMA or not all(_DIGEST.fullmatch(value) for value in (self.source_identity, self.record_identity, self.context_identity, self.resolved_configuration_digest, self.runtime_content_digest)) or not _SHA.fullmatch(self.candidate_sha) or type(self.ready_at) is not int or type(self.freshness_until) is not int or self.ready_at < 0 or self.freshness_until < self.ready_at:
            raise RuntimeBindingError("supervisor runtime receipt is invalid")
        material = self.runtime_content_digest if not self.canonical_material_digest else self.canonical_material_digest
        if not _DIGEST.fullmatch(material): raise RuntimeBindingError("supervisor runtime receipt is invalid")
        object.__setattr__(self, "canonical_material_digest", material)
    def payload(self) -> dict[str, object]: return {"schema": self.schema, "source_identity": self.source_identity, "record_identity": self.record_identity, "candidate_sha": self.candidate_sha, "context_identity": self.context_identity, "resolved_configuration_digest": self.resolved_configuration_digest, "runtime_content_digest": self.runtime_content_digest, "canonical_material_digest": self.canonical_material_digest, "ready_at": self.ready_at, "freshness_until": self.freshness_until}
    @property
    def receipt_digest(self) -> str: return "sha256:" + hashlib.sha256(json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    @classmethod
    def from_canonical(cls, material: object) -> "SupervisorRuntimeBindingReceipt":
        if type(material) is not str: raise RuntimeBindingError("supervisor runtime receipt material is invalid")
        try:
            payload = json.loads(material); expected = {"schema", "source_identity", "record_identity", "candidate_sha", "context_identity", "resolved_configuration_digest", "runtime_content_digest", "canonical_material_digest", "ready_at", "freshness_until"}
            if type(payload) is not dict or set(payload) != expected or json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != material: raise ValueError
            return cls(payload["source_identity"], payload["record_identity"], payload["candidate_sha"], payload["context_identity"], payload["resolved_configuration_digest"], payload["runtime_content_digest"], payload["ready_at"], payload["freshness_until"], payload["schema"], payload["canonical_material_digest"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeBindingError("supervisor runtime receipt material is invalid") from error


class ExternalSupervisorRuntimeStore(Protocol):
    def persist(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt: ...
    def read(self, receipt: SupervisorRuntimeBindingReceipt, *, evidence_time: int) -> RuntimeBinding: ...


class InMemorySupervisorRuntimeStore:
    def __init__(self, source_identity: str) -> None:
        if not _DIGEST.fullmatch(source_identity): raise RuntimeBindingError("supervisor runtime source is invalid")
        self._source_identity = source_identity; self._records: dict[str, str] = {}
    @property
    def source_identity(self) -> str: return self._source_identity
    def persist(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt:
        if type(runtime) is not RuntimeBinding or not _SHA.fullmatch(candidate_sha) or not _DIGEST.fullmatch(context_identity) or type(ready_at) is not int or type(freshness_until) is not int or freshness_until < ready_at:
            raise RuntimeBindingError("supervisor runtime persist is invalid")
        material = runtime.canonical_material(); content = "sha256:" + hashlib.sha256(material.encode()).hexdigest()
        record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": self._source_identity, "candidate_sha": candidate_sha, "context_identity": context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": content, "canonical_material_digest": content, "ready_at": ready_at, "freshness_until": freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        receipt = SupervisorRuntimeBindingReceipt(self._source_identity, record, candidate_sha, context_identity, runtime.resolved_digest, content, ready_at, freshness_until, _RECEIPT_SCHEMA, content)
        if record in self._records: raise RuntimeBindingError("supervisor runtime record already exists")
        self._records[record] = material; return receipt
    def read(self, receipt: SupervisorRuntimeBindingReceipt, *, evidence_time: int) -> RuntimeBinding:
        if type(receipt) is not SupervisorRuntimeBindingReceipt or type(evidence_time) is not int or not receipt.ready_at <= evidence_time <= receipt.freshness_until:
            raise RuntimeBindingError("supervisor runtime evidence time is invalid")
        material = self._records.get(receipt.record_identity)
        if material is None: raise RuntimeBindingError("supervisor runtime record is missing")
        runtime = RuntimeBinding.from_canonical(material); content = "sha256:" + hashlib.sha256(runtime.canonical_material().encode()).hexdigest()
        record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": self._source_identity, "candidate_sha": receipt.candidate_sha, "context_identity": receipt.context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": content, "canonical_material_digest": content, "ready_at": receipt.ready_at, "freshness_until": receipt.freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        expected = SupervisorRuntimeBindingReceipt(self._source_identity, record, receipt.candidate_sha, receipt.context_identity, runtime.resolved_digest, content, receipt.ready_at, receipt.freshness_until, _RECEIPT_SCHEMA, content)
        if expected != receipt: raise RuntimeBindingError("supervisor runtime receipt drifted")
        return runtime


class FileSupervisorRuntimeStore:
    """Append-only canonical RuntimeBinding store with restart-safe receipt checks."""

    _RUNTIME_FILE = "runtime.json"; _RECEIPT_FILE = "receipt.json"

    def __init__(self, root: str | Path, source_identity: str) -> None:
        if not isinstance(root, (str, os.PathLike)) or not _DIGEST.fullmatch(source_identity): raise RuntimeBindingError("supervisor runtime source is invalid")
        candidate = Path(root)
        if candidate.is_symlink(): raise RuntimeBindingError("supervisor runtime root is invalid")
        candidate.mkdir(parents=True, exist_ok=True); resolved = candidate.resolve(strict=True)
        if candidate.is_symlink() or not resolved.is_dir(): raise RuntimeBindingError("supervisor runtime root is invalid")
        self._root = resolved; self._source_identity = source_identity
    @property
    def source_identity(self) -> str: return self._source_identity

    def _safe_path(self, path: Path) -> Path:
        try: relative = path.relative_to(self._root)
        except ValueError as error: raise RuntimeBindingError("supervisor runtime path escaped root") from error
        current = self._root
        for part in relative.parts:
            current = current / part
            if current.exists() and _reparse(current): raise RuntimeBindingError("supervisor runtime reparse path is invalid")
        return path

    @staticmethod
    def _digest_material(material: str) -> str: return "sha256:" + hashlib.sha256(material.encode()).hexdigest()
    def _record(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt:
        material = runtime.canonical_material(); content = self._digest_material(material)
        record = "sha256:" + hashlib.sha256(json.dumps({"source_identity": self._source_identity, "candidate_sha": candidate_sha, "context_identity": context_identity, "resolved_configuration_digest": runtime.resolved_digest, "runtime_content_digest": content, "canonical_material_digest": content, "ready_at": ready_at, "freshness_until": freshness_until}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return SupervisorRuntimeBindingReceipt(self._source_identity, record, candidate_sha, context_identity, runtime.resolved_digest, content, ready_at, freshness_until, _RECEIPT_SCHEMA, content)
    def _directory(self, record_identity: str) -> Path:
        if not _DIGEST.fullmatch(record_identity): raise RuntimeBindingError("supervisor runtime record is invalid")
        value = self._root / ("record-" + record_identity.removeprefix("sha256:"))
        try: value.resolve(strict=False).relative_to(self._root)
        except ValueError as error: raise RuntimeBindingError("supervisor runtime path escaped root") from error
        self._safe_path(value)
        if value.exists() and _reparse(value): raise RuntimeBindingError("supervisor runtime record is invalid")
        return value
    def _publish(self, path: Path, material: str) -> None:
        temporary = path.with_name(path.name + ".tmp")
        self._safe_path(path.parent); self._safe_path(path); self._safe_path(temporary)
        if _reparse(path.parent) or _reparse(path) or _reparse(temporary) or path.exists() or temporary.exists(): raise RuntimeBindingError("supervisor runtime collision")
        try:
            descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            with os.fdopen(descriptor, "wb") as handle: handle.write(material.encode()); handle.flush(); os.fsync(handle.fileno())
            if path.exists(): raise RuntimeBindingError("supervisor runtime collision")
            os.replace(temporary, path)
        except RuntimeBindingError: raise
        except OSError as error: raise RuntimeBindingError("supervisor runtime publication failed") from error
    @staticmethod
    def _read(path: Path) -> str:
        try: material = path.read_bytes().decode(); parsed = json.loads(material)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error: raise RuntimeBindingError("supervisor runtime material is invalid") from error
        if json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != material: raise RuntimeBindingError("supervisor runtime material is noncanonical")
        return material
    def persist(self, runtime: RuntimeBinding, *, candidate_sha: str, context_identity: str, ready_at: int, freshness_until: int) -> SupervisorRuntimeBindingReceipt:
        if type(runtime) is not RuntimeBinding or not _SHA.fullmatch(candidate_sha) or not _DIGEST.fullmatch(context_identity) or type(ready_at) is not int or type(freshness_until) is not int or freshness_until < ready_at: raise RuntimeBindingError("supervisor runtime persist is invalid")
        receipt = self._record(runtime, candidate_sha=candidate_sha, context_identity=context_identity, ready_at=ready_at, freshness_until=freshness_until); directory = self._directory(receipt.record_identity)
        try: directory.mkdir()
        except FileExistsError as error: raise RuntimeBindingError("supervisor runtime collision") from error
        except OSError as error: raise RuntimeBindingError("supervisor runtime publication failed") from error
        self._safe_path(directory)
        if _reparse(directory): raise RuntimeBindingError("supervisor runtime record is invalid")
        self._publish(directory / self._RUNTIME_FILE, runtime.canonical_material()); self._publish(directory / self._RECEIPT_FILE, json.dumps(receipt.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)); return receipt
    def read(self, receipt: SupervisorRuntimeBindingReceipt, *, evidence_time: int) -> RuntimeBinding:
        if type(receipt) is not SupervisorRuntimeBindingReceipt or type(evidence_time) is not int or not receipt.ready_at <= evidence_time <= receipt.freshness_until: raise RuntimeBindingError("supervisor runtime evidence time is invalid")
        directory = self._directory(receipt.record_identity)
        self._safe_path(directory)
        if not directory.exists() or _reparse(directory): raise RuntimeBindingError("supervisor runtime record is incomplete")
        entries = {item.name: item for item in directory.iterdir()}
        if set(entries) != {self._RUNTIME_FILE, self._RECEIPT_FILE} or any(_reparse(item) or not item.is_file() for item in entries.values()): raise RuntimeBindingError("supervisor runtime record is incomplete")
        runtime = RuntimeBinding.from_canonical(self._read(entries[self._RUNTIME_FILE])); stored = SupervisorRuntimeBindingReceipt.from_canonical(self._read(entries[self._RECEIPT_FILE]))
        expected = self._record(runtime, candidate_sha=receipt.candidate_sha, context_identity=receipt.context_identity, ready_at=receipt.ready_at, freshness_until=receipt.freshness_until)
        if stored != receipt or expected != receipt: raise RuntimeBindingError("supervisor runtime receipt drifted")
        return runtime
