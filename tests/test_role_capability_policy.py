"""Adversarial coverage for bounded advisory-role contracts."""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import load_configuration
from roundwright.role_capability_policy import (
    AdvisoryRole,
    AdvisoryRoleContract,
    AdvisoryRoleStatus,
    DedicatedRoleInstance,
    RoleCapability,
    RoleCapabilityError,
    RoleCapabilityGrant,
    TrustedGuidance,
    default_advisory_profiles,
    require_non_dispatching_production_entrypoint,
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
        self.guidance = TrustedGuidance(digest("a"), digest("b"), digest("c"))
        self.instance = DedicatedRoleInstance(
            "recovery-136", AdvisoryRole.RECOVERY_ADVISOR, self.recovery.profile_identity,
            self.guidance.receipt_digest, "d" * 40,
        )

    def test_default_profiles_are_dedicated_and_non_always_on(self) -> None:
        self.assertEqual((self.recovery.role, self.intent.role), (AdvisoryRole.RECOVERY_ADVISOR, AdvisoryRole.OWNER_INTENT_INTERPRETER))
        self.assertFalse(self.recovery.always_on)
        self.assertTrue(self.recovery.dedicated_instance_required)
        self.assertEqual(self.recovery.capabilities, frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE}))

    def test_contract_is_disabled_without_a_grant_and_public_receipt_has_no_guidance_text(self) -> None:
        contract = AdvisoryRoleContract(self.recovery, self.guidance, self.instance)
        receipt = contract.public_receipt()
        self.assertEqual(contract.status(), AdvisoryRoleStatus.DISABLED)
        self.assertEqual(receipt["effective_authority"], "disabled")
        self.assertNotIn("source", str(receipt).lower())
        with self.assertRaisesRegex(RoleCapabilityError, "disabled"):
            require_non_dispatching_production_entrypoint(contract)

    def test_production_entrypoint_returns_only_a_receipt_for_a_matching_explicit_grant(self) -> None:
        grant = RoleCapabilityGrant(digest("e"), self.instance.receipt_digest, self.recovery.capabilities)
        receipt = require_non_dispatching_production_entrypoint(AdvisoryRoleContract(self.recovery, self.guidance, self.instance, grant))
        self.assertEqual((receipt["status"], receipt["effective_authority"]), ("ready", "disabled"))
        self.assertNotIn("candidate", str(receipt).lower())
        self.assertNotIn("recovery-136", str(receipt))

    def test_adversarial_grants_cannot_cross_role_instance_or_capability_boundaries(self) -> None:
        grant = RoleCapabilityGrant(digest("e"), self.instance.receipt_digest, self.recovery.capabilities)
        wrong_role = replace(self.instance, role=AdvisoryRole.OWNER_INTENT_INTERPRETER)
        with self.assertRaises(RoleCapabilityError):
            AdvisoryRoleContract(self.recovery, self.guidance, wrong_role, grant).status()
        excessive = RoleCapabilityGrant(digest("e"), self.instance.receipt_digest, frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.RENDER_OWNER_SAFE_ADVICE}))
        limited_profile = replace(self.recovery, capabilities=frozenset({RoleCapability.READ_TRUSTED_GUIDANCE}))
        with self.assertRaises(RoleCapabilityError):
            AdvisoryRoleContract(limited_profile, self.guidance, self.instance, excessive).status()

    def test_adversarial_inputs_reject_private_or_unbound_identifiers(self) -> None:
        with self.assertRaises(RoleCapabilityError):
            DedicatedRoleInstance("C:/private/path", AdvisoryRole.RECOVERY_ADVISOR, self.recovery.profile_identity, self.guidance.receipt_digest, "d" * 40)
        with self.assertRaises(RoleCapabilityError):
            TrustedGuidance("private guidance", digest("b"), digest("c"))


if __name__ == "__main__":
    unittest.main()
