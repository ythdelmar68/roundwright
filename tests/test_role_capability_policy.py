"""Adversarial coverage for trusted, bounded advisory role admission."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import load_configuration
from roundwright.role_capability_policy import (
    AdvisoryRole, AdvisoryRoleContract, AdvisoryRoleStatus, DedicatedRoleInstance,
    GuidanceManifest, RoleCapability, RoleCapabilityError, RoleCapabilityGrant,
    RoleScope, TrustedRoleAuthorityReceipt, VerifiedRoleAdmission,
    default_advisory_profiles, require_non_dispatching_production_entrypoint,
    resolve_accepted_guidance, validate_instance_continuity,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class RoleCapabilityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        configuration = load_configuration(cwd=ROOT, environment={}, home=ROOT / "missing-home")
        self.recovery, self.intent = default_advisory_profiles(
            recovery_advisor=configuration.recovery_advisor.value,
            owner_intent_interpreter=configuration.owner_intent_interpreter.value,
        )
        self.root = tempfile.TemporaryDirectory()
        path = Path(self.root.name, "guidance", "recovery.md")
        path.parent.mkdir(); path.write_text("accepted", encoding="utf-8")
        file_digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        self.guidance = resolve_accepted_guidance(
            root=Path(self.root.name), manifest=GuidanceManifest(digest("a"), "b" * 40, {"guidance/recovery.md": file_digest}),
            role=AdvisoryRole.RECOVERY_ADVISOR, requested_paths=("guidance/recovery.md",), explicit_context=True,
        )
        self.instance = DedicatedRoleInstance(
            "recovery-136", AdvisoryRole.RECOVERY_ADVISOR, self.recovery.profile_identity,
            self.guidance.receipt_digest, digest("c"), "task-136", digest("d"), digest("e"), digest("f"), 1, "generation-1", "0" * 40,
        )
        self.scope = RoleScope(self.recovery.capabilities, (), (), (), (), ())
        self.authority = TrustedRoleAuthorityReceipt(digest("c"), "task-136", digest("e"), 1, digest("1"), 200, digest("2"))
        self.grant = RoleCapabilityGrant(self.authority.receipt_digest, self.instance.receipt_digest, self.scope.identity, 100, 150)

    def tearDown(self) -> None:
        self.root.cleanup()

    def admission(self, **changes):
        return replace(VerifiedRoleAdmission(self.authority, self.grant, self.scope, 120, False), **changes)

    def test_defaults_are_finite_dedicated_profiles_with_no_implicit_fallback(self) -> None:
        self.assertEqual((self.recovery.budget.max_calls, self.recovery.budget.max_duration_seconds), (1, 60))
        self.assertFalse(self.recovery.always_on)
        self.assertTrue(self.recovery.dedicated_instance_required)
        self.assertIn(RoleCapability.READ_ONLY_REVIEW, self.recovery.capabilities)
        self.assertIn(RoleCapability.OWNER_COMMAND_INTERPRETATION, self.intent.capabilities)
        self.assertNotIn(RoleCapability.BOUNDED_CODING, self.recovery.capabilities)

    def test_guidance_requires_explicit_context_allowlisted_bytes_and_nested_order(self) -> None:
        with self.assertRaises(RoleCapabilityError):
            resolve_accepted_guidance(root=Path(self.root.name), manifest=GuidanceManifest(digest("a"), "b" * 40, {}), role=AdvisoryRole.RECOVERY_ADVISOR, requested_paths=("guidance/recovery.md",), explicit_context=False)
        with self.assertRaises(RoleCapabilityError):
            resolve_accepted_guidance(root=Path(self.root.name), manifest=GuidanceManifest(digest("a"), "b" * 40, {"guidance/recovery.md": digest("z")}), role=AdvisoryRole.RECOVERY_ADVISOR, requested_paths=("guidance/recovery.md",), explicit_context=True)
        with self.assertRaises(RoleCapabilityError):
            resolve_accepted_guidance(root=Path(self.root.name), manifest=GuidanceManifest(digest("a"), "b" * 40, {"guidance/recovery.md": digest("a")}), role=AdvisoryRole.RECOVERY_ADVISOR, requested_paths=("guidance/recovery.md",), explicit_context=True, implicit_working_directory=True)

    def test_grant_requires_independent_bound_authority_and_rejects_stale_revoked_or_copied_state(self) -> None:
        contract = AdvisoryRoleContract(self.recovery, self.guidance, self.instance, self.admission())
        self.assertEqual(contract.status(), AdvisoryRoleStatus.READY)
        self.assertEqual(require_non_dispatching_production_entrypoint(contract)["effective_authority"], "disabled")
        for admission in (self.admission(revoked=True), self.admission(evidence_time=151), self.admission(authority_receipt=replace(self.authority, authority_epoch=2))):
            with self.subTest(admission=admission), self.assertRaises(RoleCapabilityError):
                AdvisoryRoleContract(self.recovery, self.guidance, self.instance, admission).status()
        copied = replace(self.instance, state_identity=digest("3"))
        with self.assertRaises(RoleCapabilityError):
            AdvisoryRoleContract(self.recovery, self.guidance, copied, self.admission()).status()

    def test_scope_unknowns_and_cross_role_instance_reassignment_fail_closed(self) -> None:
        with self.assertRaises(RoleCapabilityError):
            RoleScope(frozenset({"unknown"}), (), (), (), (), ())
        foreign = replace(self.instance, role=AdvisoryRole.OWNER_INTENT_INTERPRETER)
        with self.assertRaises(RoleCapabilityError):
            AdvisoryRoleContract(self.recovery, self.guidance, foreign, self.admission()).status()
        expanded = RoleScope(frozenset(RoleCapability), (), (), (), (), ())
        expanded_grant = replace(self.grant, scope_identity=expanded.identity)
        with self.assertRaises(RoleCapabilityError):
            AdvisoryRoleContract(self.recovery, self.guidance, self.instance, replace(self.admission(), grant=expanded_grant, scope=expanded)).status()

    def test_instance_restart_and_fenced_generation_replacement_are_explicit(self) -> None:
        self.assertEqual(validate_instance_continuity(self.instance, self.instance), "same-instance-restart")
        replacement = replace(self.instance, instance_identity="recovery-136-replacement", task_identity="task-136-replacement", authority_epoch=2, replacement_fence="generation-2")
        self.assertEqual(validate_instance_continuity(self.instance, replacement), "fenced-generation-replacement")
        with self.assertRaises(RoleCapabilityError):
            validate_instance_continuity(self.instance, replace(replacement, host_identity=digest("4")))

    def test_public_receipt_contains_only_digests_and_never_authority(self) -> None:
        rendered = str(AdvisoryRoleContract(self.recovery, self.guidance, self.instance, self.admission()).public_receipt())
        for value in (self.root.name, "task-136", "recovery-136", "accepted", "0000000000000000000000000000000000000000"):
            self.assertNotIn(value, rendered)


if __name__ == "__main__":
    unittest.main()
