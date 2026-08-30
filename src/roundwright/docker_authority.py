"""Fail-closed mounted authority adapter for the Docker consumer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from pathlib import Path
from uuid import UUID, NAMESPACE_URL, uuid5

from .deployment import (
    AuthorityReceiptStatus, AuthorityReceiptVerification, DeploymentAuthorityReceipt,
    DeploymentIdentity, DeploymentMode, evaluate_deployment_authority,
)
from .runtime_binding import RuntimeBinding


class DockerAuthorityAdapterError(ValueError):
    pass


def canonical_fixture_envelope(candidate_sha: str, *, now: datetime) -> dict[str, object]:
    """Build public-safe mounted evidence using the production typed models.

    The hosted Docker qualification needs a disposable authority fixture, but
    it must exercise the same receipt and runtime-binding evaluator as a real
    mounted authority observation.  This helper deliberately returns data
    only; it neither authorizes a deployment nor owns a receipt store.
    """

    if type(candidate_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise DockerAuthorityAdapterError("mounted authority fixture candidate is invalid")
    if type(now) is not datetime or now.tzinfo is not timezone.utc or now.utcoffset() is None:
        raise DockerAuthorityAdapterError("mounted authority fixture time is invalid")

    def fingerprint(label: str) -> str:
        return hashlib.sha256(f"roundwright-docker-fixture:{label}:{candidate_sha}".encode("utf-8")).hexdigest()

    review_policy = {
        "complete_rounds": 1,
        "max_rounds": 3,
        "max_supervisor_attempts_per_round": 1,
        "on_final_findings": "worker-final-repair-then-merge",
    }
    binding = RuntimeBinding(
        "roundwright-runtime/v1",
        "sha256:" + fingerprint("runtime"),
        "sha256:" + fingerprint("worker"),
        ("sha256:" + fingerprint("supervisor"),),
        review_policy["complete_rounds"], review_policy["max_rounds"],
        review_policy["max_supervisor_attempts_per_round"], review_policy["on_final_findings"],
        hashlib.sha256(json.dumps(review_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
    )
    identity = DeploymentIdentity(
        fingerprint("repository"), fingerprint("checkout"), fingerprint("state"),
        uuid5(NAMESPACE_URL, "roundwright-docker-fixture:" + candidate_sha),
        fingerprint("deployment"), binding,
    )
    issued_at = now.replace(microsecond=0)
    receipt = DeploymentAuthorityReceipt(
        fingerprint("receipt"), identity, DeploymentMode.AUTHORITATIVE,
        issued_at, issued_at + timedelta(minutes=15),
    )
    # This is the canonical typed receipt-binding identity computed by the
    # existing evaluator, not a Docker-specific parallel fingerprint.
    from .deployment import _receipt_binding_fingerprint

    verification = AuthorityReceiptVerification(
        receipt.receipt_fingerprint, _receipt_binding_fingerprint(receipt),
        identity.repository_fingerprint, identity.state_id,
        identity.deployment_fingerprint, AuthorityReceiptStatus.FRESH, binding,
    )
    return {
        "candidate_sha": candidate_sha,
        "identity": {
            "repository_fingerprint": identity.repository_fingerprint,
            "canonical_checkout_fingerprint": identity.canonical_checkout_fingerprint,
            "state_fingerprint": identity.state_fingerprint,
            "state_id": str(identity.state_id),
            "deployment_fingerprint": identity.deployment_fingerprint,
            "runtime_binding": binding.canonical_material(),
        },
        "receipt": {
            "receipt_fingerprint": receipt.receipt_fingerprint,
            "mode": receipt.mode.value,
            "issued_at": receipt.issued_at.isoformat(),
            "expires_at": receipt.expires_at.isoformat(),
        },
        "verification": {
            "receipt_fingerprint": verification.receipt_fingerprint,
            "receipt_binding_fingerprint": verification.receipt_binding_fingerprint,
            "repository_fingerprint": verification.repository_fingerprint,
            "state_id": str(verification.state_id),
            "authoritative_deployment_fingerprint": verification.authoritative_deployment_fingerprint,
            "status": verification.status.value,
            "runtime_binding": verification.runtime_binding.canonical_material(),
        },
    }


def evaluate_mounted_authority(path: Path, *, candidate_sha: str, now: datetime):
    """Parse one canonical public-safe envelope and delegate typed evaluation."""
    try:
        if type(candidate_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
            raise ValueError
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
