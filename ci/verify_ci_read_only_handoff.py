"""Qualify CI's non-dispatching default and one hermetic handoff fixture.

This script is intentionally a test fixture, not an authority adapter.  It
uses the in-memory handoff coordinator to prove the ordering that a separately
selected deployment authority service must enforce.  It never locates a real
receipt, opens deployment state, starts work, or contacts a provider.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
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
    HandoffDecision,
    HandoffReconciliation,
    HandoffTeardown,
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


@dataclass(frozen=True)
class SyntheticAction:
    """The one no-op action that CI may model after authority handoff."""

    action_fingerprint: str
    receipt_fingerprint: str
    candidate_sha: str
    budget: int

    def __post_init__(self) -> None:
        _require_digest(self.action_fingerprint, "synthetic action")
        _require_digest(self.receipt_fingerprint, "synthetic action receipt")
        _require_candidate(self.candidate_sha, "synthetic action candidate")
        if type(self.budget) is not int or self.budget != 1:
            raise ValueError("synthetic action budget is invalid")


@dataclass(frozen=True)
class SyntheticActionReadback:
    """Independent machine-state read-back for the bounded no-op action."""

    action_fingerprint: str
    receipt_fingerprint: str
    candidate_sha: str
    consumed_budget: int
    executions: int
    outcome: str

    def __post_init__(self) -> None:
        _require_digest(self.action_fingerprint, "synthetic action read-back")
        _require_digest(self.receipt_fingerprint, "synthetic action read-back receipt")
        _require_candidate(self.candidate_sha, "synthetic action read-back candidate")
        if type(self.consumed_budget) is not int or self.consumed_budget < 0 or type(self.executions) is not int or self.executions < 0:
            raise ValueError("synthetic action read-back is invalid")
        if self.outcome != "completed":
            raise ValueError("synthetic action read-back outcome is invalid")


class InMemorySyntheticActionStore:
    """One-shot action record kept distinct from the authority coordinator."""

    def __init__(self) -> None:
        self._readback: SyntheticActionReadback | None = None

    def execute(
        self,
        coordinator: DeploymentAuthorityHandoffCoordinator,
        identity: DeploymentAuthorityIdentity,
        action: SyntheticAction,
        receipt: DeploymentAuthorityHandoffReceipt,
        *,
        now: datetime,
    ) -> tuple[HandoffDecision, SyntheticActionReadback | None]:
        """Consume the fixture budget only inside the receipt-bound transition."""

        if (
            type(coordinator) is not DeploymentAuthorityHandoffCoordinator
            or type(identity) is not DeploymentAuthorityIdentity
            or type(action) is not SyntheticAction
            or type(receipt) is not DeploymentAuthorityHandoffReceipt
        ):
            raise ValueError("synthetic action is unavailable")
        if self._readback is not None:
            raise ValueError("synthetic action was replayed")
        if (
            identity != receipt.identity
            or action.receipt_fingerprint != receipt.receipt_fingerprint
            or action.candidate_sha != receipt.identity.candidate_sha
        ):
            raise ValueError("synthetic action does not match selected authority")

        def consume() -> SyntheticActionReadback:
            self._readback = SyntheticActionReadback(
                action.action_fingerprint, action.receipt_fingerprint, action.candidate_sha,
                action.budget, 1, "completed",
            )
            return self._readback

        authority, readback = coordinator.transition_if_authorized(
            identity, receipt, now=now, transition=consume,
        )
        if not authority.authorized:
            return authority, None
        if type(readback) is not SyntheticActionReadback:
            raise AssertionError("authorized synthetic action did not return an exact read-back")
        return authority, readback

    def read_back(self) -> SyntheticActionReadback | None:
        return self._readback


def verify_action_readback(action: SyntheticAction, readback: object) -> SyntheticActionReadback:
    """Reject absent, substituted, ambiguous, replayed, or over-budget results."""

    if type(action) is not SyntheticAction or type(readback) is not SyntheticActionReadback:
        raise ValueError("synthetic action read-back is absent or invalid")
    if (
        readback.action_fingerprint != action.action_fingerprint
        or readback.receipt_fingerprint != action.receipt_fingerprint
        or readback.candidate_sha != action.candidate_sha
        or readback.consumed_budget != action.budget
        or readback.executions != 1
        or readback.outcome != "completed"
    ):
        raise ValueError("synthetic action read-back is mismatched, ambiguous, replayed, or over budget")
    return readback


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


def _teardown(handoff: str, receipt: DeploymentAuthorityHandoffReceipt, *, resources_torn_down: bool = True) -> HandoffTeardown:
    return HandoffTeardown(
        handoff, receipt.receipt_fingerprint, receipt.identity.state_store_fingerprint, receipt.identity.state_id,
        resources_torn_down, _fingerprint("teardown", handoff, receipt.binding_digest),
    )


def qualify(
    candidate: str, checked_out_sha: str, package: str, policy: str, verifier: str, *,
    expected_policy: str, expected_verifier: str, workflow_mode: str,
) -> dict[str, object]:
    """Run one complete in-memory handoff and return a public-safe receipt."""

    candidate = _require_candidate(candidate, "candidate SHA")
    if checked_out_sha != candidate:
        raise ValueError("checked-out SHA does not match the selected candidate")
    _require_digest(package, "package digest")
    _require_digest(policy, "policy digest")
    _require_digest(verifier, "verifier digest")
    _require_digest(expected_policy, "expected policy digest")
    _require_digest(expected_verifier, "expected verifier digest")
    if policy != expected_policy or verifier != expected_verifier:
        raise ValueError("candidate policy or verifier bytes do not match the checked-out files")
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

    action = SyntheticAction(
        _fingerprint("bounded synthetic action", selected.binding_digest), selected.receipt_fingerprint, candidate, 1,
    )
    actions = InMemorySyntheticActionStore()
    action_authority, readback = actions.execute(coordinator, selected_identity, action, selected, now=_NOW)
    if not action_authority.authorized:
        raise AssertionError("selected synthetic receipt was not authorized for bounded work")
    verify_action_readback(action, readback)
    try:
        actions.execute(coordinator, selected_identity, action, selected, now=_NOW)
    except ValueError:
        pass
    else:
        raise AssertionError("synthetic action replay was accepted")

    # The bounded work is represented solely by this ordered proof; CI never
    # calls a deployment, provider, or scheduler.  Teardown again stops,
    # reconciles, and revokes the selected receipt, leaving no active authority.
    if not coordinator.begin_handoff(selected, teardown_identity, handoff_fingerprint=teardown, now=_NOW).authorized:
        raise AssertionError("fixture could not begin teardown")
    if not coordinator.reconcile(_reconciliation(teardown, selected)).authorized:
        raise AssertionError("fixture could not reconcile teardown")
    if not coordinator.revoke_old_receipt(handoff_fingerprint=teardown).authorized:
        raise AssertionError("fixture could not revoke the selected receipt during teardown")
    if not coordinator.complete_teardown(_teardown(teardown, selected)).authorized:
        raise AssertionError("fixture could not complete teardown")
    restarted = DeploymentAuthorityHandoffCoordinator(store)
    if (
        restarted.active_receipt is not None
        or restarted.progress is not None
        or restarted.authorize(selected_identity, selected, now=_NOW).authorized
    ):
        raise AssertionError("teardown left a synthetic authority active")

    return {
        "schema": "roundwright-ci-read-only-handoff/v1",
        "candidate_sha": candidate,
        "checked_out_sha": checked_out_sha,
        "package_sha256": package,
        "policy_sha256": policy,
        "verifier_sha256": verifier,
        "workflow_mode": workflow_mode,
        "default_dispatch": "denied",
        "selected_handoff": ["stop", "reconcile", "revoke-old", "issue-new", "bounded-work", "read-back"],
        "action_budget": 1,
        "action_read_back": "completed",
        "teardown": ["stop", "reconcile", "revoke-selected", "verify-cleanup", "clear-handoff", "no-active-authority"],
        "result": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--expected-verifier-sha256", required=True)
    parser.add_argument("--workflow-mode", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        receipt = qualify(
            arguments.candidate,
            arguments.checked_out_sha,
            package_digest(arguments.dist),
            arguments.expected_policy_sha256,
            arguments.expected_verifier_sha256,
            expected_policy=arguments.expected_policy_sha256,
            expected_verifier=arguments.expected_verifier_sha256,
            workflow_mode=arguments.workflow_mode,
        )
    except (AssertionError, OSError, ValueError) as error:
        print(f"CI read-only handoff qualification blocked: {error}", file=sys.stderr)
        return 2
    arguments.output.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
