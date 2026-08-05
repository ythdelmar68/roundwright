"""Mandatory, public-safe identity for one resolved runtime configuration."""

from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass, field


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SCHEMA = "roundwright-runtime/v1"


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
        if not _DIGEST.fullmatch(self.worker_profile_identity) or not self.supervisor_profile_identities or any(not _DIGEST.fullmatch(value) for value in self.supervisor_profile_identities):
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
