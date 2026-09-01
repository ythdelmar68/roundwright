"""Qualify CI's non-dispatching default and one hermetic handoff fixture.

This script is intentionally a test fixture, not an authority adapter.  It
uses the in-memory handoff coordinator to prove the ordering that a separately
selected deployment authority service must enforce.  It never locates a real
receipt, opens deployment state, starts work, or contacts a provider.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.deployment import DeploymentMode, evaluate_deployment_authority
from roundwright.deployment_handoff import (
    AuthorityReceiptVerificationStatus,
    DeploymentAuthorityHandoffCoordinator,
    DeploymentAuthorityHandoffReceipt,
    DeploymentAuthorityIdentity,
    DeploymentAuthorityReceiptVerification,
    HandoffReconciliation,
    InMemoryDeploymentAuthorityStore,
)
from roundwright.runtime_binding import RuntimeBinding


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CANDIDATE = re.compile(r"[0-9a-f]{40}\Z")
_MODE = "read-only"
_NOW = datetime(2026, 9, 1, 0, 0, tzinfo=timezone.utc)
_STATE_ID = UUID("c1c1c1c1-c1c1-4c1c-8c1c-c1c1c1c1c1c1")


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _require_digest(value: object, description: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{description} is invalid")
    return value


def _require_candidate(value: object, description: str) -> str:
    if type(value) is not str or _CANDIDATE.fullmatch(value) is None:
        raise ValueError(f"{description} is invalid")
    return value


def package_digest(directory: Path) -> str:
    """Return one verified uploaded-wheel digest without trusting its manifest."""

    try:
        manifest = json.loads((directory / "package-digest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("package digest manifest is unavailable") from error
    if type(manifest) is not dict or set(manifest) != {"wheel", "sha256"}:
        raise ValueError("package digest manifest is invalid")
    wheel, expected = manifest["wheel"], manifest["sha256"]
    if type(wheel) is not str or Path(wheel).name != wheel or not wheel.startswith("roundwright-"):
        raise ValueError("package digest manifest is invalid")
    _require_digest(expected, "package digest")
    try:
        actual = hashlib.sha256((directory / wheel).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError("package artifact is unavailable") from error
    if actual != expected:
        raise ValueError("package digest does not match the uploaded artifact")
    return actual


def _binding(policy_digest: str) -> RuntimeBinding:
    return RuntimeBinding(
        "roundwright-runtime/v1",
        "sha256:" + _fingerprint("fixture configuration", policy_digest),
        "sha256:" + _fingerprint("fixture worker", policy_digest),
        ("sha256:" + _fingerprint("fixture supervisor", policy_digest),),
    )


def _identity(candidate: str, policy_digest: str, *, environment: str) -> DeploymentAuthorityIdentity:
    return DeploymentAuthorityIdentity(
        _fingerprint("repository", policy_digest),
        _fingerprint("checkout", policy_digest),
        _fingerprint("state store", policy_digest),
        _STATE_ID,
        _fingerprint("deployment", candidate, environment),
        candidate,
        _fingerprint("environment", environment),
        _binding(policy_digest),
    )


def _receipt(identity: DeploymentAuthorityIdentity, name: str) -> DeploymentAuthorityHandoffReceipt:
    return DeploymentAuthorityHandoffReceipt(
        _fingerprint("receipt", name, identity.candidate_sha, identity.environment_fingerprint),
        identity,
        _NOW - timedelta(minutes=1),
        _NOW + timedelta(minutes=1),
    )


def _verification(receipt: DeploymentAuthorityHandoffReceipt) -> DeploymentAuthorityReceiptVerification:
    identity = receipt.identity
    return DeploymentAuthorityReceiptVerification(
        _fingerprint("verification", receipt.binding_digest),
        receipt.receipt_fingerprint,
        receipt.binding_digest,
        identity.repository_fingerprint,
        identity.state_store_fingerprint,
        identity.state_id,
        identity.candidate_sha,
        identity.environment_fingerprint,
        # The coordinator permits only this exact canonical-store observation.
        AuthorityReceiptVerificationStatus.FRESH,
    )


def _reconciliation(handoff: str, receipt: DeploymentAuthorityHandoffReceipt) -> HandoffReconciliation:
    return HandoffReconciliation(
        handoff,
        receipt.receipt_fingerprint,
        receipt.identity.state_store_fingerprint,
        receipt.identity.state_id,
        True,
        True,
        True,
        _fingerprint("reconciliation", handoff, receipt.binding_digest),
    )


def qualify(candidate: str, checked_out_sha: str, package: str, policy: str, *, workflow_mode: str) -> dict[str, object]:
    """Run one complete in-memory handoff and return a public-safe receipt."""

    candidate = _require_candidate(candidate, "candidate SHA")
    if checked_out_sha != candidate:
        raise ValueError("checked-out SHA does not match the selected candidate")
    _require_digest(package, "package digest")
    _require_digest(policy, "policy digest")
    if workflow_mode != _MODE:
        raise ValueError("CI workflow mode must be read-only")
    default = evaluate_deployment_authority(None, mode=DeploymentMode.READ_ONLY, now=_NOW)
    if default.authorized or default.mode is not DeploymentMode.READ_ONLY:
        raise AssertionError("read-only default unexpectedly acquired authority")

    old_candidate = "b" * 40 if candidate == "a" * 40 else "a" * 40
    old_identity = _identity(old_candidate, policy, environment="previous")
    selected_identity = _identity(candidate, policy, environment="selected")
    teardown_identity = _identity(candidate, policy, environment="teardown")
    store = InMemoryDeploymentAuthorityStore(old_identity.state_store_fingerprint, old_identity.state_id)
    coordinator = DeploymentAuthorityHandoffCoordinator(store)
    old = _receipt(old_identity, "old")
    selected = _receipt(selected_identity, "selected")
    handoff = _fingerprint("selected handoff", old.binding_digest, selected.binding_digest)
    teardown = _fingerprint("teardown handoff", selected.binding_digest, teardown_identity.environment_fingerprint)

    if not coordinator.activate_initial(old, _verification(old), now=_NOW).authorized:
        raise AssertionError("fixture could not activate its synthetic old receipt")
    if not coordinator.claim_orchestrator(old, claim_fingerprint=_fingerprint("old claim", policy), now=_NOW).authorized:
        raise AssertionError("fixture could not claim its synthetic old receipt")
    if coordinator.issue_new_receipt(selected, _verification(selected), handoff_fingerprint=handoff, now=_NOW).authorized:
        raise AssertionError("new receipt issued before a complete handoff")
    if not coordinator.begin_handoff(old, selected_identity, handoff_fingerprint=handoff, now=_NOW).authorized:
        raise AssertionError("fixture could not stop the synthetic old authority")
    if coordinator.authorize(old_identity, old, now=_NOW).authorized:
        raise AssertionError("old authority remained dispatchable during handoff")
    if not coordinator.reconcile(_reconciliation(handoff, old)).authorized:
        raise AssertionError("fixture could not reconcile the synthetic old authority")
    if not coordinator.revoke_old_receipt(handoff_fingerprint=handoff).authorized:
        raise AssertionError("fixture could not revoke the synthetic old receipt")
    if not coordinator.issue_new_receipt(selected, _verification(selected), handoff_fingerprint=handoff, now=_NOW).authorized:
        raise AssertionError("fixture could not issue its selected receipt")
    if not coordinator.authorize(selected_identity, selected, now=_NOW).authorized:
        raise AssertionError("selected synthetic receipt was not exact and current")

    # The bounded work is represented solely by this ordered proof; CI never
    # calls a deployment, provider, or scheduler.  Teardown again stops,
    # reconciles, and revokes the selected receipt, leaving no active authority.
    if not coordinator.begin_handoff(selected, teardown_identity, handoff_fingerprint=teardown, now=_NOW).authorized:
        raise AssertionError("fixture could not begin teardown")
    if not coordinator.reconcile(_reconciliation(teardown, selected)).authorized:
        raise AssertionError("fixture could not reconcile teardown")
    if not coordinator.revoke_old_receipt(handoff_fingerprint=teardown).authorized:
        raise AssertionError("fixture could not revoke the selected receipt during teardown")
    if coordinator.active_receipt is not None or coordinator.authorize(selected_identity, selected, now=_NOW).authorized:
        raise AssertionError("teardown left a synthetic authority active")

    return {
        "schema": "roundwright-ci-read-only-handoff/v1",
        "candidate_sha": candidate,
        "checked_out_sha": checked_out_sha,
        "package_sha256": package,
        "policy_sha256": policy,
        "workflow_mode": workflow_mode,
        "default_dispatch": "denied",
        "selected_handoff": ["stop", "reconcile", "revoke-old", "issue-new", "bounded-work", "read-back"],
        "teardown": ["stop", "reconcile", "revoke-selected", "no-active-authority"],
        "result": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--workflow-mode", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        receipt = qualify(
            arguments.candidate,
            arguments.checked_out_sha,
            package_digest(arguments.dist),
            hashlib.sha256(arguments.policy.read_bytes()).hexdigest(),
            workflow_mode=arguments.workflow_mode,
        )
    except (AssertionError, OSError, ValueError) as error:
        print(f"CI read-only handoff qualification blocked: {error}", file=sys.stderr)
        return 2
    arguments.output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
