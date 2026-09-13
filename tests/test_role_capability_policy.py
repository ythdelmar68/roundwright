"""Adversarial coverage for independently admitted advisory roles."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import load_configuration
from roundwright.dependency_policy import (
    BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent,
    DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition,
    PolicyTransitionKind, TrustedDependencyAdmission, VersionRange,
)
from roundwright.git_identity import GitEntrypointControl
from roundwright.role_capability_policy import (
    AdvisoryRole, AdvisoryRoleContract, AdvisoryRoleStatus,
    AuthoritativeGuidanceExpectation, DedicatedRoleInstance,
    FileRoleAdmissionStore, GuidanceView, ProviderGuidanceEvidence, RoleAdmissionExpectation, SealedRoleExecution, SealedRoleRuntimeContext,
    RoleCapability, RoleCapabilityError, RoleCapabilityGrant, RoleExecutionSeam,
    RoleScope, ScopeKind, ScopedDescriptor, SdkAdapterMapping,
    TrustedRoleAuthorityReceipt, default_advisory_profiles,
    read_verified_admission, render_grant_draft, require_verified_role_admission,
    resolve_sealed_role_runtime_context,
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
        self._git("add", "."); self._git("commit", "-qm", "fixture"); self._git("branch", "-M", "main")
        self.revision = self._git("rev-parse", "HEAD").decode().strip()
        self._git("remote", "add", "origin", "https://github.com/ythdelmar68/roundwright.git"); self._git("update-ref", "refs/remotes/origin/main", self.revision)
        preliminary_binding, preliminary_control = self._control()
        tree = self._git("rev-parse", "HEAD^{tree}").decode().strip()
        preliminary_expectation = AuthoritativeGuidanceExpectation(digest("a"), self.root, self.revision, self._digest({"tree": tree, "repository": digest("a")}))
        self.task_candidate = "a" * 40
        preliminary_runtime = resolve_sealed_role_runtime_context(root=self.root, binding=preliminary_binding, git_entrypoint_control=preliminary_control, task_candidate_sha=self.task_candidate)
        self.guidance = resolve_authoritative_guidance(expectation=preliminary_expectation, view=GuidanceView.RECOVERY_ADVISOR, task_relative_path="src/nested/task.py", runtime=preliminary_runtime)
        self.instance = DedicatedRoleInstance("recovery-136", AdvisoryRole.RECOVERY_ADVISOR, self.recovery.profile_identity, self.guidance.receipt_digest, digest("c"), "task-136", digest("d"), digest("e"), digest("f"), 1, "generation-1", self.task_candidate)
        self.scope = RoleScope(frozenset({RoleCapability.READ_TRUSTED_GUIDANCE, RoleCapability.READ_ONLY_REVIEW}), (ScopedDescriptor(ScopeKind.PATH, digest("c"), "src/nested"),))
        self.now = int(time.time())
        self.authority = TrustedRoleAuthorityReceipt(digest("c"), "task-136", digest("e"), 1, digest("1"), self.now + 120, digest("2"))
        self.grant = RoleCapabilityGrant(self.authority.receipt_digest, self.instance.receipt_digest, self.scope.identity, self.now - 10, self.now + 60)
        self.record = {"schema": "roundwright-independent-role-admission/v1", "grant_reference": "grant-136", "authority": self.authority.__dict__, "instance": self.instance.__dict__, "scope": {"actions": sorted(item.value for item in self.scope.actions), "descriptors": [{"kind": item.kind.value, "root_identity": item.root_identity, "value": item.value} for item in self.scope.descriptors]}, "grant": self.grant.__dict__, "revoked": False, "revocation_readback_digest": digest("2")}
        Path(self.root, "admission.json").write_bytes(canonical(self.record)); self._git("add", "admission.json"); self._git("commit", "-qm", "admission")
        self.revision = self._git("rev-parse", "HEAD").decode().strip(); self._git("update-ref", "refs/remotes/origin/main", self.revision)
        self.expectation = RoleAdmissionExpectation(digest("3"), "sha256:" + hashlib.sha256(canonical(self.record)).hexdigest(), "grant-136", self.authority.receipt_digest, self.instance.receipt_digest, digest("c"), "task-136", digest("d"), digest("e"), digest("f"), 1, self.task_candidate, self.scope.identity, self.scope.actions, self.now - 10, self.now + 60, digest("2"))
        self.binding, self.control = self._control()
        self.runtime = resolve_sealed_role_runtime_context(root=self.root, binding=self.binding, git_entrypoint_control=self.control, task_candidate_sha=self.task_candidate)
        self.store = FileRoleAdmissionStore(runtime=self.runtime, record_relative_path="admission.json", store_identity=digest("3"))
        tree = self._git("rev-parse", "HEAD^{tree}").decode().strip()
        self.guidance_expectation = AuthoritativeGuidanceExpectation(digest("a"), self.root, self.revision, self._digest({"tree": tree, "repository": digest("a")}))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _git(self, *arguments: str) -> bytes:
        return subprocess.run(("git", "-C", str(self.root), *arguments), check=True, stdout=subprocess.PIPE).stdout

    @staticmethod
    def _digest(value: object) -> str:
        return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _control(self) -> tuple[CandidateBinding, GitEntrypointControl]:
        binding = CandidateBinding("ythdelmar68/roundwright", "issue-136", self.revision)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-scm/git", digest("3"), digest("4")),
        )
        policy = DependencyPolicy(binding, digest("5"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("6"), authority_digest=digest("7"))
        policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 100, policy.policy_digest) for item in components)
        return binding, GitEntrypointControl(binding, DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, digest("6"), digest("7"))), 100)

    def verified_contract(self) -> AdvisoryRoleContract:
        admission, instance = read_verified_admission(expectation=self.expectation, store=self.store)
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
            resolve_authoritative_guidance(expectation=self.guidance_expectation, view=GuidanceView.WORKER, task_relative_path="safe/../outside.py", runtime=self.runtime)
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=replace(self.guidance_expectation, trusted_revision="0" * 40), view=GuidanceView.SUPERVISOR, task_relative_path="src/task.py", runtime=self.runtime)
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=replace(self.guidance_expectation, tree_digest=digest("9")), view=GuidanceView.DEPENDENCY_REVIEW, task_relative_path="src/task.py", runtime=self.runtime)
        self._git("remote", "remove", "origin")
        with self.assertRaises(RoleCapabilityError):
            resolve_authoritative_guidance(expectation=self.guidance_expectation, view=GuidanceView.RECOVERY_ADVISOR, task_relative_path="src/task.py", runtime=self.runtime)

    def test_admission_requires_existing_pinned_record_not_coherent_caller_objects(self) -> None:
        contract = self.verified_contract()
        self.assertEqual(contract.status(), AdvisoryRoleStatus.READY)
        self.assertEqual(require_verified_role_admission(contract, RoleExecutionSeam.RECOVERY_ADVISOR, store=self.store, expectation=self.expectation)["capabilities"], sorted(item.value for item in self.scope.actions))
        for seam in (RoleExecutionSeam.WORKER, RoleExecutionSeam.SUPERVISOR, RoleExecutionSeam.DEPENDENCY_REVIEW, RoleExecutionSeam.OWNER_INTENT_INTERPRETER):
            with self.assertRaises(RoleCapabilityError):
                require_verified_role_admission(contract, seam, store=self.store, expectation=self.expectation)
        with self.assertRaises(RoleCapabilityError):
            # A caller can make coherent pieces but cannot directly construct verified admission.
            from roundwright.role_capability_policy import VerifiedRoleAdmission
            VerifiedRoleAdmission(self.authority, self.grant, self.scope, 120, False, "grant-136")
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=replace(self.expectation, grant_reference="other-grant"), store=self.store)
        with self.assertRaises(RoleCapabilityError):
            FileRoleAdmissionStore(runtime=object(), record_relative_path="admission.json", store_identity=digest("3"))  # type: ignore[arg-type]
        with self.assertRaises(RoleCapabilityError):
            SealedRoleRuntimeContext(self.root, self.root, self.binding, self.control, "0" * 40, self.task_candidate)
        self.record["grant"]["expires_at"] = 151
        Path(self.root, "admission.json").write_bytes(canonical(self.record))
        # Checkout mutation cannot replace the Git-blob-backed independent record.
        self.assertEqual(read_verified_admission(expectation=self.expectation, store=self.store)[0].grant.expires_at, self.now + 60)
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=replace(self.expectation, valid_until=self.now - 1), store=self.store)

    def test_scope_traversal_unknown_descriptors_and_capability_expansion_fail_closed(self) -> None:
        with self.assertRaises(RoleCapabilityError):
            ScopedDescriptor(ScopeKind.PATH, digest("c"), "safe/../outside")
        for unsafe in ("C:/outside", "//server/share", "safe//nested", "/outside", "CON", "nul.txt", "NUL .txt", "aux ", "COM1.log", "COM¹.log", "LPT²", "CONIN$", "CONOUT$", "CLOCK$", "safe/item:stream", "safe/item."):
            with self.subTest(unsafe=unsafe), self.assertRaises(RoleCapabilityError):
                ScopedDescriptor(ScopeKind.PATH, digest("c"), unsafe)
        with self.assertRaises(RoleCapabilityError):
            ScopedDescriptor("unknown", digest("c"), "anything")  # type: ignore[arg-type]
        expanded = RoleScope(frozenset(RoleCapability), ())
        bad = replace(self.expectation, actions=expanded.actions, scope_identity=expanded.identity)
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=bad, store=self.store)
        with self.assertRaises(RoleCapabilityError):
            read_verified_admission(expectation=replace(self.expectation, candidate_sha="b" * 40), store=self.store)

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
        draft = render_grant_draft(instance=self.instance, scope=self.scope, expectation=self.expectation, owner_readable_reason="Read current recovery state.", budget=self.recovery.budget, valid_from=self.now - 10, valid_until=self.now + 60, revocation_readback_digest=digest("2"))
        self.assertEqual(draft["requested_actions"], sorted(item.value for item in self.scope.actions))
        self.assertEqual(draft["validity"], {"not_before": self.now - 10, "not_after": self.now + 60})
        self.assertEqual(draft["owner_action"], "Select the listed existing grant reference; do not calculate replacement identifiers.")
        with self.assertRaises(RoleCapabilityError):
            render_grant_draft(instance=self.instance, scope=self.scope, expectation=replace(self.expectation, scope_identity=digest("9")), owner_readable_reason="Read current recovery state.", budget=self.recovery.budget, valid_from=self.now - 10, valid_until=self.now + 60, revocation_readback_digest=digest("2"))

    def test_execution_evidence_binds_accepted_main_and_task_candidate_separately(self) -> None:
        contract = self.verified_contract()
        evidence = ProviderGuidanceEvidence(GuidanceView.RECOVERY_ADVISOR, digest("a"), True, digest("b"), self.guidance.receipt_digest, self.binding.candidate_sha, self.task_candidate)
        sealed = SealedRoleExecution(contract, RoleExecutionSeam.RECOVERY_ADVISOR, self.store, self.expectation, evidence)
        self.assertEqual(sealed.require_before_effect()["status"], "ready")
        with self.assertRaises(RoleCapabilityError):
            SealedRoleExecution(contract, RoleExecutionSeam.RECOVERY_ADVISOR, self.store, self.expectation, replace(evidence, task_candidate_sha="b" * 40)).require_before_effect()

    def test_verified_admission_and_sdk_mapping_cannot_be_mutated_after_readback(self) -> None:
        contract = self.verified_contract()
        with self.assertRaises(RoleCapabilityError):
            contract.admission.revoked = True  # type: ignore[misc]
        with self.assertRaises(TypeError):
            self.recovery.sdk_mapping.capability_codes[RoleCapability.READ_ONLY_REVIEW] = "changed"  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
