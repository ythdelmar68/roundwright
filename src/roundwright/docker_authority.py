"""Fail-closed mounted authority adapter for the Docker consumer."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from uuid import UUID

from .deployment import (
    AuthorityReceiptStatus, AuthorityReceiptVerification, DeploymentAuthorityReceipt,
    DeploymentIdentity, DeploymentMode, evaluate_deployment_authority,
)
from .runtime_binding import RuntimeBinding


class DockerAuthorityAdapterError(ValueError):
    pass


def evaluate_mounted_authority(path: Path, *, candidate_sha: str, now: datetime):
    """Parse one canonical public-safe envelope and delegate typed evaluation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if type(payload) is not dict or set(payload) != {"candidate_sha", "identity", "receipt", "verification"} or payload["candidate_sha"] != candidate_sha:
            raise ValueError
        identity_data = payload["identity"]
        receipt_data = payload["receipt"]
        verification_data = payload["verification"]
        required_identity = {"repository_fingerprint", "canonical_checkout_fingerprint", "state_fingerprint", "state_id", "deployment_fingerprint", "runtime_binding"}
        if type(identity_data) is not dict or set(identity_data) != required_identity:
            raise ValueError
        binding = RuntimeBinding.from_canonical(identity_data["runtime_binding"])
        identity = DeploymentIdentity(
            identity_data["repository_fingerprint"], identity_data["canonical_checkout_fingerprint"],
            identity_data["state_fingerprint"], UUID(identity_data["state_id"]),
            identity_data["deployment_fingerprint"], binding,
        )
        receipt = DeploymentAuthorityReceipt(
            receipt_data["receipt_fingerprint"], identity, DeploymentMode(receipt_data["mode"]),
            datetime.fromisoformat(receipt_data["issued_at"]), datetime.fromisoformat(receipt_data["expires_at"]),
        )
        verification = AuthorityReceiptVerification(
            verification_data["receipt_fingerprint"], verification_data["receipt_binding_fingerprint"],
            verification_data["repository_fingerprint"], UUID(verification_data["state_id"]),
            verification_data["authoritative_deployment_fingerprint"], AuthorityReceiptStatus(verification_data["status"]),
            RuntimeBinding.from_canonical(verification_data["runtime_binding"]),
        )
        return evaluate_deployment_authority(identity, receipt, verification, mode=DeploymentMode.AUTHORITATIVE, now=now)
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        raise DockerAuthorityAdapterError("mounted authority evidence is invalid") from error
