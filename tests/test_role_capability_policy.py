"""Adversarial coverage for independently admitted advisory roles."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import load_configuration
from roundwright.role_capability_policy import (
    AdvisoryRole, AdvisoryRoleContract, AdvisoryRoleStatus,
    AuthoritativeGuidanceExpectation, DedicatedRoleInstance,
    FileRoleAdmissionStore, GuidanceView, RoleAdmissionExpectation,
    RoleCapability, RoleCapabilityError, RoleCapabilityGrant, RoleExecutionSeam,
    RoleScope, ScopeKind, ScopedDescriptor, SdkAdapterMapping,
    TrustedRoleAuthorityReceipt, default_advisory_profiles,
    read_verified_admission, render_grant_draft, require_verified_role_admission,
    resolve_authoritative_guidance, reviewed_sdk_expectation,
    validate_instance_continuity,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class RoleCapabilityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        configuration = load_configuration(cwd=ROOT, environment={}, home=ROOT / "missing-home")
        self.recovery, self.intent = default_advisory_profiles(recovery_advisor=configuration.recovery_advisor.value, owner_intent_interpreter=configuration.owner_intent_interpreter.value)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._git("init", "-q"); self._git("config", "user.email", "test@example.invalid"); self._git("config", "user.name", "Test")
        Path(self.root, "AGENTS.md").write_text("root guidance", encoding="utf-8")
        Path(self.root, "src", "nested").mkdir(parents=True)
        Path(self.root, "src", "AGENTS.md").write_text("nested guidance", encoding="utf-8")
        Path(self.root, "global.md").write_text("ambient global guidance", encoding="utf-8")
        self._git("add", "."); self._git("commit", "-qm", "fixture")
        self.revision = self._git("rev-parse", "HEAD").decode().strip()
        tree = self._git("rev-parse", "HEAD^{tree}").decode().strip()
        self.guidance_expectation = AuthoritativeGuidanceExpectation(digest("a"), self.root, self.revision, self._digest({"tree": tree, "repository": digest("a")}))
        self.guidance = resolve_authoritative_guidance(expectation=self.guidance_expectation, view=GuidanceView.RECOVERY_ADVISOR, task_relative_path="src/nested/task.py")
        self.instance = DedicatedRoleInstance("recovery-136", AdvisoryRole.RECOVERY_ADVISOR, self.recovery.profile_identity, self.guidance.receipt_digest, digest("c"), "task-136", digest("d"), digest("e"), digest("f"), 1, "generation-1", "0" * 40)
        self.scope = RoleScope(frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.READ_ONLY_REVIEW}), (ScopedDescriptor(ScopeKind.PATH, digest("c"), "src/nested"),))
        self.authority = TrustedRoleAuthorityReceipt(digest("c"), "task-136", digest("e"), 1, digest("1"), 200, digest("2"))
        self.grant = RoleCapabilityGrant(self.authority.receipt_digest, self.instance.receipt_digest, self.scope.identity, 100, 150)
        self.record = {"schema": "roundwright-independent-role-admission/v1", "grant_reference": "grant-136", "authority": self.authority.__dict__, "instance": self.instance.__dict__, "scope": {"actions": sorted(item.value for item in self.scope.actions), "descriptors": [{"kind": item.kind.value, "root_identity": item.root_identity, "value": item.value} for item in self.scope.descriptors]}, "grant": self.grant.__dict__, "revoked": False, "revocation_readback_digest": digest("2")}
        Path(self.root, "admission.json").write_bytes(canonical(self.record))
        self.expectation = RoleAdmissionExpectation(digest("3"), "sha256:" + hashlib.sha256(canonical(self.record)).hexdigest(), "grant-136", self.authority.receipt_digest, self.instance.receipt_digest, digest("c"), "task-136", digest("d"), digest("e"), digest("f"), 1, self.scope.identity, self.scope.actions, 100, 150, digest("2"))
        self.store = FileRoleAdmissionStore(root=self.root, record_relative_path="admission.json", store_identity=digest("3"))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *arguments: str) -> bytes:
        return subprocess.run(("git", "-C", str(self.root), *arguments), check=True, stdout=subprocess.PIPE).stdout

    @staticmethod
    def _digest(value: object) -> str:
        return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def verified_contract(self) -> AdvisoryRoleContract:
        admission, instance = read_verified_admission(expectation=self.expectation, store=self.store, evidence_time=120)
        self.assertEqual(instance, self.instance)
        return AdvisoryRoleContract(self.recovery, self.guidance, instance, admission)

    def test_defaults_are_finite_dedicated_profiles_with_explicit_sdk_mapping(self) -> None:
        self.assertEqual((self.recovery.budget.max_calls, self.recovery.budget.max_duration_seconds), (1, 60))
        self.assertFalse(self.recovery.always_on); self.assertIn(RoleCapability.READ_ONLY_REVIEW, self.recovery.capabilities)
        expected = reviewed_sdk_expectation()
        with self.assertRaises(RoleCapabilityError):
            SdkAdapterMapping(expected.sdk_version, expected.adapter_identity, {RoleCapability.READ_TRUSTED_GUIDANCE: "changed"}, expected.mapping_digest)

    def test_authoritative_guidance_derives_only_root_to_nested_agents_chain(self) -> None:
        self.assertEqual(self.guidance.selected_paths, ("AGENTS.md", "src/AGENTS.md"))
        self.assertNotIn("global.md", self.guidance.selected_paths)
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=self.guidance_expectation, view=GuidanceView.WORKER, task_relative_path="safe/../outside.py")
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=replace(self.guidance_expectation, trusted_revision="0" * 40), view=GuidanceView.SUPERVISOR, task_relative_path="src/task.py")
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=replace(self.guidance_expectation, tree_digest=digest("9")), view=GuidanceView.DEPENDENCY_REVIEW, task_relative_path="src/task.py")

    def test_admission_requires_existing_pinned_record_not_coherent_caller_objects(self) -> None:
        contract = self.verified_contract()
        self.assertEqual(contract.status(), AdvisoryRoleStatus.READY)
        for seam in RoleExecutionSeam:
            self.assertEqual(require_verified_role_admission(contract, seam)["capabilities"], sorted(item.value for item in self.scope.actions))
        with self.assertRaises(RoleCapabilityError):
            # A caller can make coherent pieces but cannot directly construct verified admission.
            from roundwright.role_capability_policy import VerifiedRoleAdmission
            VerifiedRoleAdmission(self.authority, self.grant, self.scope, 120, False, "grant-136")
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=replace(self.expectation, grant_reference="other-grant"), store=self.store, evidence_time=120)
        self.record["grant"]["expires_at"] = 151
        Path(self.root, "admission.json").write_bytes(canonical(self.record))
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=self.expectation, store=self.store, evidence_time=120)

    def test_scope_traversal_unknown_descriptors_and_capability_expansion_fail_closed(self) -> None:
        with self.assertRaises(RoleCapabilityError):
            ScopedDescriptor(ScopeKind.PATH, digest("c"), "safe/../outside")
        with self.assertRaises(RoleCapabilityError):
            ScopedDescriptor("unknown", digest("c"), "anything")  # type: ignore[arg-type]
        expanded = RoleScope(frozenset(RoleCapability), ())
        bad = replace(self.expectation, actions=expanded.actions, scope_identity=expanded.identity)
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=bad, store=self.store, evidence_time=120)

    def test_instance_restart_and_fenced_generation_replacement_preserve_task_binding(self) -> None:
        self.assertEqual(validate_instance_continuity(self.instance, self.instance), "same-instance-restart")
        replacement = replace(self.instance, instance_identity="recovery-136-replacement", authority_epoch=2, replacement_fence="generation-2")
        self.assertEqual(validate_instance_continuity(self.instance, replacement), "fenced-generation-replacement")
        with self.assertRaises(RoleCapabilityError):
            validate_instance_continuity(self.instance, replace(replacement, task_identity="other-task"))

    def test_public_receipt_projects_only_granted_actions_and_draft_is_owner_readable(self) -> None:
        receipt = self.verified_contract().public_receipt()
        self.assertNotIn(RoleCapability.RENDER_OWNER_SAFE_ADVICE.value, receipt["capabilities"])
        rendered = json.dumps(receipt)
        for private_value in (str(self.root), self.instance.instance_identity, self.instance.task_identity, self.revision):
            self.assertNotIn(private_value, rendered)
        draft = render_grant_draft(instance=self.instance, scope=self.scope, owner_readable_reason="Read current recovery state.")
        self.assertEqual(draft["requested_actions"], sorted(item.value for item in self.scope.actions))
        self.assertNotIn("sha256", json.dumps(draft))


if __name__ == "__main__":
    unittest.main()
