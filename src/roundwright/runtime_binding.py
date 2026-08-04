"""Mandatory, public-safe identity for one resolved runtime configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass


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

    def __post_init__(self) -> None:
        if self.schema_version != _SCHEMA or not _DIGEST.fullmatch(self.resolved_digest):
            raise RuntimeBindingError("resolved configuration binding is invalid")
        if not _DIGEST.fullmatch(self.worker_profile_identity) or not self.supervisor_profile_identities or any(not _DIGEST.fullmatch(value) for value in self.supervisor_profile_identities):
            raise RuntimeBindingError("resolved configuration profile identity is invalid")

    def require_matches(self, other: object) -> None:
        if type(other) is not RuntimeBinding or other != self:
            raise RuntimeBindingError("resolved configuration binding has drifted")
