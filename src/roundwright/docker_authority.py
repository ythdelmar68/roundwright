"""Fail-closed mounted authority adapter for the Docker consumer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, NAMESPACE_URL, uuid5

from .deployment import (
    AuthorityReceiptStatus, AuthorityReceiptVerification, DeploymentAuthorityReceipt,
    DeploymentIdentity, DeploymentMode, evaluate_deployment_authority,
)
from .deployment_handoff import DeploymentAuthorityHandoffReceipt, DeploymentAuthorityIdentity
from .native_host import NativeHostInstallation
from .runtime_binding import RuntimeBinding


class DockerAuthorityAdapterError(ValueError):
    pass


_RUNTIME_ENVIRONMENT_KEYS = ("ROUNDWRIGHT_REPOSITORY_ROOT", "XDG_CONFIG_HOME", "XDG_STATE_HOME")


def runtime_environment_fingerprint(candidate_sha: str, environment: dict[str, str]) -> str:
    """Bind the mounted runtime paths to the candidate without exposing paths in diagnostics."""

    if type(candidate_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise DockerAuthorityAdapterError("mounted runtime candidate is invalid")
    if type(environment) is not dict or set(environment) != set(_RUNTIME_ENVIRONMENT_KEYS) or any(type(value) is not str or not value.startswith("/") for value in environment.values()):
        raise DockerAuthorityAdapterError("mounted runtime environment is invalid")
    return hashlib.sha256(json.dumps({"candidate_sha": candidate_sha, "environment": environment}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MountedAuthorityEvidence:
    """Strictly parsed, host-owned evidence consumed by the Docker adapter."""

    candidate_sha: str
    identity: DeploymentIdentity
    receipt: DeploymentAuthorityReceipt
    verification: AuthorityReceiptVerification
    native_host_installation: NativeHostInstallation
    authentication_identity: str
    runtime_environment: dict[str, str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.candidate_sha):
            raise DockerAuthorityAdapterError("mounted authority candidate is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.authentication_identity):
            raise DockerAuthorityAdapterError("mounted authentication identity is invalid")
        runtime_environment_fingerprint(self.candidate_sha, self.runtime_environment)


def _fixture_fingerprint(candidate_sha: str, label: str) -> str:
    return hashlib.sha256(f"roundwright-docker-fixture:{label}:{candidate_sha}".encode("utf-8")).hexdigest()


def _fixture_runtime_binding(candidate_sha: str) -> RuntimeBinding:
    review_policy = {
        "complete_rounds": 1,
        "max_rounds": 3,
        "max_supervisor_attempts_per_round": 1,
        "on_final_findings": "worker-final-repair-then-merge",
    }
    return RuntimeBinding(
        "roundwright-runtime/v1",
        "sha256:" + _fixture_fingerprint(candidate_sha, "runtime"),
        "sha256:" + _fixture_fingerprint(candidate_sha, "worker"),
        ("sha256:" + _fixture_fingerprint(candidate_sha, "supervisor"),),
        review_policy["complete_rounds"], review_policy["max_rounds"],
        review_policy["max_supervisor_attempts_per_round"], review_policy["on_final_findings"],
        hashlib.sha256(json.dumps(review_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
    )


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

    binding = _fixture_runtime_binding(candidate_sha)
    identity = DeploymentIdentity(
        _fixture_fingerprint(candidate_sha, "repository"), _fixture_fingerprint(candidate_sha, "checkout"), _fixture_fingerprint(candidate_sha, "state"),
        uuid5(NAMESPACE_URL, "roundwright-docker-fixture:" + candidate_sha),
        _fixture_fingerprint(candidate_sha, "deployment"), binding,
    )
    issued_at = now.replace(microsecond=0)
    receipt = DeploymentAuthorityReceipt(
        _fixture_fingerprint(candidate_sha, "receipt"), identity, DeploymentMode.AUTHORITATIVE,
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
    runtime_environment = {
        "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
        "XDG_CONFIG_HOME": "/etc",
        "XDG_STATE_HOME": "/var/lib",
    }
    native_host = canonical_native_host_installation(candidate_sha, now=issued_at)
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
        "native_host": {
            "installation_fingerprint": native_host.installation_fingerprint,
            "identity": {
                "repository_fingerprint": native_host.identity.repository_fingerprint,
                "canonical_checkout_fingerprint": native_host.identity.canonical_checkout_fingerprint,
                "state_store_fingerprint": native_host.identity.state_store_fingerprint,
                "state_id": str(native_host.identity.state_id),
                "deployment_fingerprint": native_host.identity.deployment_fingerprint,
                "candidate_sha": native_host.identity.candidate_sha,
                "environment_fingerprint": native_host.identity.environment_fingerprint,
                "runtime_binding": native_host.identity.runtime_binding.canonical_material(),
            },
            "receipt": {
                "receipt_fingerprint": native_host.receipt.receipt_fingerprint,
                "issued_at": native_host.receipt.issued_at.isoformat(),
                "expires_at": native_host.receipt.expires_at.isoformat(),
            },
        },
        "mounts": {
            "authentication_identity": _fixture_fingerprint(candidate_sha, "authentication"),
            "runtime_environment": runtime_environment,
        },
    }


def canonical_native_host_installation(candidate_sha: str, *, now: datetime) -> NativeHostInstallation:
    """Construct a handoff-bound native-host installation for disposable CI state."""

    if type(candidate_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
        raise DockerAuthorityAdapterError("mounted native-host fixture candidate is invalid")
    if type(now) is not datetime or now.tzinfo is not timezone.utc or now.utcoffset() is None:
        raise DockerAuthorityAdapterError("mounted native-host fixture time is invalid")
    binding = _fixture_runtime_binding(candidate_sha)
    identity = DeploymentAuthorityIdentity(
        _fixture_fingerprint(candidate_sha, "repository"),
        _fixture_fingerprint(candidate_sha, "checkout"),
        _fixture_fingerprint(candidate_sha, "state"),
        uuid5(NAMESPACE_URL, "roundwright-docker-fixture:" + candidate_sha),
        _fixture_fingerprint(candidate_sha, "deployment"), candidate_sha,
        runtime_environment_fingerprint(candidate_sha, {
            "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
            "XDG_CONFIG_HOME": "/etc",
            "XDG_STATE_HOME": "/var/lib",
        }), binding,
    )
    issued_at = now.replace(microsecond=0)
    receipt = DeploymentAuthorityHandoffReceipt(
        _fixture_fingerprint(candidate_sha, "native-host-receipt"), identity,
        issued_at, issued_at + timedelta(minutes=15),
    )
    return NativeHostInstallation(_fixture_fingerprint(candidate_sha, "native-host-installation"), identity, receipt)


def load_mounted_authority(path: Path, *, candidate_sha: str) -> MountedAuthorityEvidence:
    """Parse mounted typed authority and native-host material without trusting fixtures."""
    try:
        if type(candidate_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", candidate_sha):
            raise ValueError
        payload = json.loads(path.read_text(encoding="utf-8"))
        if type(payload) is not dict or set(payload) != {"candidate_sha", "identity", "receipt", "verification", "native_host", "mounts"} or payload["candidate_sha"] != candidate_sha:
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
        native_host_data = payload["native_host"]
        if type(native_host_data) is not dict or set(native_host_data) != {"installation_fingerprint", "identity", "receipt"}:
            raise ValueError
        native_identity_data = native_host_data["identity"]
        required_native_identity = {
            "repository_fingerprint", "canonical_checkout_fingerprint", "state_store_fingerprint", "state_id",
            "deployment_fingerprint", "candidate_sha", "environment_fingerprint", "runtime_binding",
        }
        if type(native_identity_data) is not dict or set(native_identity_data) != required_native_identity:
            raise ValueError
        native_identity = DeploymentAuthorityIdentity(
            native_identity_data["repository_fingerprint"], native_identity_data["canonical_checkout_fingerprint"],
            native_identity_data["state_store_fingerprint"], UUID(native_identity_data["state_id"]),
            native_identity_data["deployment_fingerprint"], native_identity_data["candidate_sha"],
            native_identity_data["environment_fingerprint"], RuntimeBinding.from_canonical(native_identity_data["runtime_binding"]),
        )
        native_receipt_data = native_host_data["receipt"]
        if type(native_receipt_data) is not dict or set(native_receipt_data) != {"receipt_fingerprint", "issued_at", "expires_at"}:
            raise ValueError
        native_receipt = DeploymentAuthorityHandoffReceipt(
            native_receipt_data["receipt_fingerprint"], native_identity,
            datetime.fromisoformat(native_receipt_data["issued_at"]), datetime.fromisoformat(native_receipt_data["expires_at"]),
        )
        mounts = payload["mounts"]
        if type(mounts) is not dict or set(mounts) != {"authentication_identity", "runtime_environment"}:
            raise ValueError
        runtime_environment = mounts["runtime_environment"]
        if type(runtime_environment) is not dict or set(runtime_environment) != set(_RUNTIME_ENVIRONMENT_KEYS) or any(type(value) is not str for value in runtime_environment.values()):
            raise ValueError
        if native_identity.environment_fingerprint != runtime_environment_fingerprint(candidate_sha, runtime_environment):
            raise ValueError
        return MountedAuthorityEvidence(
            candidate_sha, identity, receipt, verification,
            NativeHostInstallation(native_host_data["installation_fingerprint"], native_identity, native_receipt),
            mounts["authentication_identity"], runtime_environment,
        )
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        raise DockerAuthorityAdapterError("mounted authority evidence is invalid") from error


def evaluate_mounted_authority(path: Path, *, candidate_sha: str, now: datetime):
    """Delegate strict mounted evidence through the normative authority evaluator."""

    material = load_mounted_authority(path, candidate_sha=candidate_sha)
    return evaluate_deployment_authority(
        material.identity, material.receipt, material.verification,
        mode=DeploymentMode.AUTHORITATIVE, now=now,
    )
