"""Terminal-snapshot Shadow v2 provenance contracts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.dependency_policy import (
    BootstrapPolicyReceipt,
    CandidateBinding,
    ComponentPolicy,
    DependencyComponent,
    DependencyExecutionControl,
    DependencyPolicy,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    TrustedDependencyAdmission,
    VersionRange,
    DependencyPolicyError,
)
from roundwright.git_identity import GitEntrypointControl, GitIdentityError
from roundwright.shadow import (
    AppendOnlyEvidenceStore,
    AttemptCommitReference,
    CaptureMode,
    CandidateCommitReference,
    ComparisonOutcome,
    CandidateArtifactProjection,
    ExternalSelectionControl,
    ExternalSelectionControlExpectation,
    ProvenanceRecordError,
    ProvenanceRecordStore,
    EvidenceRole,
    FormalReviewRoundReference,
    LifecycleAttempt,
    LifecycleAttemptKind,
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    HOSTED_CHECK_PROFILE,
    INTEGRATED_BOUNDARY_PROFILE,
    PROVENANCE_DECISION_PROFILE,
    READ_ONLY_EXTERNAL_OBSERVATION_PROFILE,
    ProviderAttemptManifest,
    RecorderBinding,
    ReviewedGitObservation,
    ReplayClassification,
    ShadowEvidenceProfile,
    ShadowProducer,
    ShadowV2Case,
    ShadowV2Error,
    ShadowV2Event,
    ShadowV2EventGraph,
    ShadowV2Observation,
    VerifiedProvenanceSelection,
    VerifiedDurableProvenanceRecord,
    VerifiedProvenanceRecordStore,
    VerifiedCaptureReadinessReceipt,
    VerifiedValidationToolchainProjection,
    NamedContentIdentity,
    AcceptedResultReference,
    compare_provenance_decision,
    export_provenance_decision,
    reconcile_final_provenance_selection,
    verify_selection_for_durable_record,
    materialize_verified_provenance_record,
    _materialize_provenance_record,
    _export_legacy_provenance_decision,
    replay_shadow_case,
    replay_shadow_v2_case,
    require_capture_readiness,
    _require_legacy_capture_readiness,
    require_verified_provenance_capture_readiness,
    shadow_evidence_profile,
    shadow_evidence_profiles,
)


def digest(value: str) -> str:
    return "sha256:" + value * 64


class ShadowV2Tests(unittest.TestCase):
    @staticmethod
    def canonical_test_store_root(temporary: str, *parts: str) -> Path:
        """Use the physical ordinary temp root, not a platform lexical alias."""

        return Path(temporary).resolve(strict=True).joinpath(*parts)

    def external_control_bytes(self):
        recorder_digest = digest("6")
        store_identity = "sha256:" + hashlib.sha256(json.dumps({
            "run_id": "ab8aea71a95647bdbe1e00e9d915d557", "contract_id": "contract-47",
            "candidate_sha": "b" * 40,
            "profile": "roundwright-shadow-profile/provenance-decision/v1",
            "recorder_binding_digest": recorder_digest,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        payload = {
            "schema": "roundwright-provenance-selection-control/v1", "control_mode": "REHEARSAL", "capture_ready": False,
            "roundlet": {"run_id": "ab8aea71a95647bdbe1e00e9d915d557", "contract_id": "contract-47", "orchestrator_task": "orchestrator-47"},
            "selection": {"repository": "ythdelmar68/roundwright", "worker_task": "task-47", "base_sha": "a" * 40, "candidate_sha": "b" * 40, "candidate_tree": "c" * 40, "active_leaf": 47, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1"},
            "authority": {"origin_main": {"commit": "a" * 40, "tree": "1" * 40}, "active_roundlet_block": {"agents_blob": "d" * 40, "block_sha256": digest("2")}, "external_validation_contract": {"skill_blob": "e" * 40, "qualification_blob": "f" * 40}, "live_leaf": {"issue_database_id": 1, "issue_node_id": "node-47", "number": 47, "updated_at": "now", "body_sha256": digest("3")}, "owner_instructions": [{"comment_id": 2, "comment_node_id": "node-2", "body_sha256": digest("4")}, {"comment_id": 3, "comment_node_id": "node-3", "body_sha256": digest("5")}]},
        }
        content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        receipt = {"schema": "roundwright-provenance-selection-control-receipt/v1", "append_only": True, "capture_ready": False, "contract_sha256": digest("1"), "control_mode": "REHEARSAL", "payload_bytes": len(content), "payload_sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "read_back": "VERIFIED", "retention_identity": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/rehearsal-" + "b" * 40}
        receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        expected = ExternalSelectionControlExpectation("ab8aea71a95647bdbe1e00e9d915d557", "contract-47", "orchestrator-47", "ythdelmar68/roundwright", "task-47", "a" * 40, "b" * 40, "c" * 40, 47, "toolbox", "roundwright-shadow-case/v2", "roundwright-shadow-profile/provenance-decision/v1", "d" * 40, "e" * 40, "f" * 40, "sha256:" + hashlib.sha256(content).hexdigest(), "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(), digest("1"), "1" * 40, digest("2"), (1, "node-47", 47, "now", digest("3")), ((2, "node-2", digest("4")), (3, "node-3", digest("5"))), store_identity, "append-only-content-addressed-readback", recorder_digest)
        return content, receipt_bytes, expected

    def test_external_rehearsal_control_is_bound_but_never_terminal_ready(self) -> None:
        payload, receipt, expected = self.external_control_bytes()
        control = ExternalSelectionControl.load(payload, receipt, expected)
        self.assertEqual(control.mode, "REHEARSAL")
        self.assertFalse(control.terminal_ready)
        self.assertEqual(control.retention_identity, "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/rehearsal-" + "b" * 40)
        for bad_payload, bad_receipt, bad_expected in ((payload + b" ", receipt, expected), (payload, b"{}", expected), (payload, receipt, replace(expected, candidate_sha="d" * 40))):
            with self.subTest():
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(bad_payload, bad_receipt, bad_expected)

        payload_value, receipt_value = json.loads(payload), json.loads(receipt)
        def rebased(value, receipt_update=None):
            content = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            current_receipt = dict(receipt_value)
            current_receipt.update(receipt_update or {})
            current_receipt["payload_bytes"] = len(content)
            current_receipt["payload_sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
            receipt_bytes = json.dumps(current_receipt, sort_keys=True, separators=(",", ":")).encode()
            return content, receipt_bytes, replace(expected, payload_digest="sha256:" + hashlib.sha256(content).hexdigest(), receipt_digest="sha256:" + hashlib.sha256(receipt_bytes).hexdigest())
        changed = json.loads(payload)
        changed["selection"]["candidate_sha"] = "d" * 40
        together = rebased(changed)
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(together[0], together[1], expected)
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(*together)
        bad_contract = rebased(payload_value, {"contract_sha256": digest("9")})
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(*bad_contract)
        for mutate in (
            lambda value: value["authority"]["origin_main"].update(tree="9" * 40),
            lambda value: value["authority"]["active_roundlet_block"].update(block_sha256=digest("9")),
            lambda value: value["authority"]["live_leaf"].update(issue_database_id=9),
            lambda value: value["authority"]["live_leaf"].update(number=9),
            lambda value: value["authority"]["live_leaf"].update(issue_node_id="wrong"),
            lambda value: value["authority"]["live_leaf"].update(updated_at="later"),
            lambda value: value["authority"]["live_leaf"].update(body_sha256=digest("9")),
            lambda value: value["authority"].update(owner_instructions=[]),
            lambda value: value["authority"].update(owner_instructions=value["authority"]["owner_instructions"] * 2),
            lambda value: value["authority"]["owner_instructions"].reverse(),
            lambda value: value["authority"]["owner_instructions"][0].update(comment_id=9),
            lambda value: value["authority"]["owner_instructions"][0].update(comment_node_id="wrong"),
            lambda value: value["authority"]["owner_instructions"][0].update(body_sha256=digest("9")),
            lambda value: value["authority"].update(owner_instructions=["invalid"]),
            lambda value: value["roundlet"].update(orchestrator_task="wrong"),
        ):
            value = json.loads(payload)
            mutate(value)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(*rebased(value))
        retained = ExternalSelectionControl.load(payload, receipt, expected)
        self.assertIs(type(retained.payload), bytes)
        self.assertEqual(retained.payload, payload)
        for retention in ("C:/private/control", "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/../final-" + "b" * 40, "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/final-token"):
            with self.subTest(retention=retention):
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(*rebased(payload_value, {"retention_identity": retention}))
        for name, retention in {
            "wrong-run": "roundlet-local:" + "0" * 32 + "/rehearsal-" + "b" * 40,
            "wrong-mode": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/final-" + "b" * 40,
            "wrong-candidate": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/rehearsal-" + "c" * 40,
        }.items():
            with self.subTest(retention=name):
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(*rebased(payload_value, {"retention_identity": retention}))

    def test_reconciliation_projection_types_are_exact_and_public_safe(self) -> None:
        toolchain = VerifiedValidationToolchainProjection(
            digest("1"), "windows-x86_64-cpython-3.12.13", digest("2"),
            (NamedContentIdentity("build", digest("3")), NamedContentIdentity("pipx", digest("4"))),
            (NamedContentIdentity("python", digest("5")), NamedContentIdentity("build", digest("6")), NamedContentIdentity("pipx", digest("7"))),
            (NamedContentIdentity("uv", digest("8"), "0.12.3"), NamedContentIdentity("managed_python", digest("9"), "3.12.13"), NamedContentIdentity("python", digest("a"), "3.12.13"), NamedContentIdentity("pipx", digest("b"), "1.16.6")),
        )
        artifacts = CandidateArtifactProjection(
            "ythdelmar68/roundwright", "task-47", "b" * 40, "c" * 40,
            "roundwright-source", digest("c"), digest("d"), digest("e"),
        )
        git = ReviewedGitObservation(
            "ythdelmar68/roundwright", "task-47", "b" * 40, digest("f"), "git", "git-source",
            "bundled-native-git", "2.53.0", "2.53.0.windows.3", digest("0"), digest("1"), digest("2"),
        )
        self.assertTrue(all(value.startswith("sha256:") for value in (
            toolchain.projection_fingerprint, artifacts.projection_fingerprint,
            git.observation_fingerprint,
        )))
        for invalid in (
            lambda: replace(toolchain, cache_key="secret-cache"),
            lambda: VerifiedValidationToolchainProjection(digest("1"), "cache", digest("2"), (), toolchain.environments, toolchain.tools),
            lambda: VerifiedValidationToolchainProjection(digest("1"), "cache", digest("2"), (*toolchain.requirements, NamedContentIdentity("extra", digest("f"))), toolchain.environments, toolchain.tools),
            lambda: VerifiedValidationToolchainProjection(digest("1"), "cache", digest("2"), (NamedContentIdentity("pipx", digest("3")), NamedContentIdentity("build", digest("4"))), toolchain.environments, toolchain.tools),
            lambda: replace(artifacts, task_id="private-token"),
            lambda: replace(artifacts, candidate_tree="not-a-tree"),
            lambda: replace(git, repository="Wrong/roundwright"),
            lambda: replace(git, source_class="credentialed-git"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ProvenanceRecordError):
                    invalid()
        with self.assertRaises(ProvenanceRecordError):
            replace(artifacts, projection_fingerprint=digest("0"))
        with self.assertRaises(ProvenanceRecordError):
            replace(git, candidate_sha="d" * 40, observation_fingerprint=git.observation_fingerprint)

    def dependency_control(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        binding = CandidateBinding("ythdelmar68/roundwright", "task-47", candidate)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright-package", VersionRange("1.0.0", "2.0.0"), "roundwright-source", digest("a"), digest("c")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.53.0", "3.0.0"), "git-source", digest("e"), digest("f")),
        )
        policy = DependencyPolicy(
            binding, digest("d"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP),
        )
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("1"), authority_digest=digest("2"))
        policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(
            ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, ready_at, policy.policy_digest)
            for item in components
        )
        return DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, receipt.reviewer_identity, receipt.authority_digest))

    def final_reconciliation_fixture(
        self, mutate=None, *, receipt_mutate=None, leaf=47, candidate="b" * 40, source_class="bundled-native-git", reported_version="2.53.0.windows.3",
    ):
        dependency = self.dependency_control(candidate=candidate)
        binding = dependency.policy.binding
        git_control = GitEntrypointControl(binding, dependency, 101)
        validation = VerifiedValidationToolchainProjection(
            digest("1"), "windows-x86_64-cpython-3.12.13", digest("2"),
            (NamedContentIdentity("build", digest("3")), NamedContentIdentity("pipx", digest("4"))),
            (NamedContentIdentity("python", digest("5")), NamedContentIdentity("build", digest("6")), NamedContentIdentity("pipx", digest("7"))),
            (NamedContentIdentity("uv", digest("8"), "0.12.3"), NamedContentIdentity("managed_python", digest("9"), "3.12.13"), NamedContentIdentity("python", digest("a"), "3.12.13"), NamedContentIdentity("pipx", digest("b"), "1.16.6")),
        )
        artifacts = CandidateArtifactProjection(binding.repository, binding.task_id, binding.candidate_sha, "c" * 40, "roundwright-source", digest("3"), digest("a"), digest("c"))
        observations = tuple(item.fingerprint for item in sorted(dependency.observations, key=lambda item: item.component.value))
        dependency_fingerprint = "sha256:" + hashlib.sha256(json.dumps({"binding": binding.fingerprint, "policy": dependency.policy.core_fingerprint, "observations": observations, "admission": (dependency.admission.policy_fingerprint, dependency.admission.receipt_digest, dependency.admission.reviewer_identity, dependency.admission.authority_digest)}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        git_control_fingerprint = "sha256:" + hashlib.sha256(json.dumps({"binding": binding.fingerprint, "dependency": dependency_fingerprint, "now": 101}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        git = ReviewedGitObservation(binding.repository, binding.task_id, binding.candidate_sha, binding.fingerprint, "git", "git-source", source_class, "2.53.0", reported_version, digest("e"), digest("f"), git_control_fingerprint)
        candidate_fingerprint = "sha256:" + hashlib.sha256(json.dumps({"repository": binding.repository, "task_id": binding.task_id, "base_sha": "a" * 40, "candidate_sha": binding.candidate_sha, "candidate_tree": "c" * 40, "artifacts": artifacts.projection_fingerprint}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        payload, receipt, expected = self.external_control_bytes()
        value = json.loads(payload)
        value["control_mode"] = "FINAL"
        value["capture_ready"] = True
        value["control_contract_digest"] = expected.contract_digest
        value["selection"] = {"repository": binding.repository, "worker_task": binding.task_id, "base_sha": "a" * 40, "candidate_sha": binding.candidate_sha, "candidate_tree": "c" * 40, "active_leaf": leaf, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1", "capture_mode": "terminal-snapshot", "gate": "recorder-capture-readiness", "blocker": None, "next_action": "record-terminal-snapshot"}
        value["freshness"] = {"selection_at": 101, "valid_until": 120, "candidate_movement_invalidates": True}
        value["validation_toolchain"] = validation.public_payload()
        value["artifacts"] = {"candidate_source": {"source_identity": artifacts.source_identity, "digest": artifacts.source_digest}, "candidate_package": artifacts.package_digest, "installed_roundwright_entrypoint": artifacts.installed_entrypoint_digest, "reviewed_git_entrypoint": {"binding_fingerprint": git.binding_fingerprint, "identifier": git.identifier, "source_identity": git.source_identity, "source_class": git.source_class, "normalized_version": git.normalized_version, "reported_version": git.reported_version, "artifact_digest": git.artifact_digest, "executable_digest": git.executable_digest, "control_fingerprint": git.control_fingerprint}, "export_artifact_kinds": ["candidate-source", "candidate-package", "installed-roundwright-entrypoint", "reviewed-git-artifact", "reviewed-git-executable"]}
        value["dependency_control"] = {"binding_fingerprint": binding.fingerprint, "policy_fingerprint": dependency.policy.core_fingerprint, "observations": [{"component": item.component.value, "fingerprint": item.fingerprint} for item in sorted(dependency.observations, key=lambda item: item.component.value)], "admission": {"policy_fingerprint": dependency.admission.policy_fingerprint, "receipt_digest": dependency.admission.receipt_digest, "reviewer_identity": dependency.admission.reviewer_identity, "authority_digest": dependency.admission.authority_digest}}
        recorder_digest = "sha256:" + hashlib.sha256(json.dumps({"harness_merge": "1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "recorder_content": "cf669e186a739a8597cfaf9f050ce3bdcadda334", "harness_tree": "632dcc3ecb3b8664de860844af2215ad5ade83e1"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        store_identity = "sha256:" + hashlib.sha256(json.dumps({"run_id": "ab8aea71a95647bdbe1e00e9d915d557", "contract_id": "contract-47", "candidate_sha": binding.candidate_sha, "profile": "roundwright-shadow-profile/provenance-decision/v1", "recorder_binding_digest": recorder_digest}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        value["recorder_store"] = {"profile": "roundwright-shadow-profile/provenance-decision/v1", "candidate_sha": binding.candidate_sha, "recorder_binding_digest": recorder_digest, "store_identity": store_identity, "retention_contract": "append-only-content-addressed-readback"}
        value["public_safe_projection"] = {"repository": binding.repository, "task_id": binding.task_id, "base_sha": "a" * 40, "candidate_sha": binding.candidate_sha, "candidate_tree": "c" * 40, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1", "capture_mode": "terminal-snapshot", "gate": "recorder-capture-readiness", "blocker": None, "next_action": "record-terminal-snapshot", "candidate_fingerprint": candidate_fingerprint, "validation_fingerprint": validation.projection_fingerprint, "dependency_fingerprint": dependency_fingerprint, "git_fingerprint": git.observation_fingerprint, "recorder_store_fingerprint": "sha256:" + hashlib.sha256(json.dumps(value["recorder_store"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        if mutate is not None:
            mutate(value)
            value["public_safe_projection"]["recorder_store_fingerprint"] = "sha256:" + hashlib.sha256(json.dumps(value["recorder_store"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        value["authority"]["live_leaf"]["number"] = leaf
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        receipt_value = json.loads(receipt)
        receipt_value.update({"control_mode": "FINAL", "capture_ready": True, "retention_identity": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/final-" + binding.candidate_sha, "payload_bytes": len(payload), "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest()})
        if receipt_mutate is not None:
            receipt_mutate(receipt_value)
        receipt = json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode()
        expected = replace(expected, leaf=leaf, candidate_sha=candidate, live_leaf=(1, "node-47", leaf, "now", digest("3")), recorder_store_identity=store_identity, recorder_binding_digest=recorder_digest, payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(), receipt_digest="sha256:" + hashlib.sha256(receipt).hexdigest())
        return ExternalSelectionControl.load(payload, receipt, expected), validation, artifacts, git_control, git, dependency

    def test_final_reconciliation_derives_all_fingerprints_from_verified_inputs(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        selection = reconcile_final_provenance_selection(control, validation=validation, artifacts=artifacts, git_control=git_control, git_observation=git, dependency_control=dependency, now=101)
        self.assertEqual(selection.payload_digest, control.payload_digest)
        self.assertEqual(selection.receipt_digest, control.receipt_digest)
        self.assertEqual(selection.contract_digest, control.contract_digest)
        self.assertEqual(selection.validation_fingerprint, validation.projection_fingerprint)
        self.assertEqual(selection.git_fingerprint, git.observation_fingerprint)
        self.assertEqual(selection.recorder_store_fingerprint, "sha256:" + hashlib.sha256(json.dumps(json.loads(control.payload)["recorder_store"], sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        selection.verify_reconciliation()
        verify_selection_for_durable_record(control, selection)
        with self.assertRaises(TypeError):
            VerifiedProvenanceSelection()

    def test_final_reconciliation_preserves_pinned_cross_platform_git_reporting(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture(reported_version="2.53.0")
        selection = reconcile_final_provenance_selection(control, validation=validation, artifacts=artifacts, git_control=git_control, git_observation=git, dependency_control=dependency, now=101)
        self.assertEqual(selection.git_fingerprint, git.observation_fingerprint)

    def test_reconciliation_requires_loaded_control_and_observation_bound_inputs(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        with self.assertRaises(TypeError):
            ExternalSelectionControl()
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(object.__new__(ExternalSelectionControl), **arguments)
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(
                control.payload, control.receipt,
                replace(control.expected, recorder_store_identity="not-a-content-digest"),
            )
        for invalid in (
            lambda: (self.final_reconciliation_fixture(lambda value: value.update(control_contract_digest=digest("9")))[0], arguments),
            lambda: (control, {**arguments, "git_observation": replace(git, executable_digest=digest("9"), observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, source_class="other-git", observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, normalized_version="2.53.1", observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, reported_version="2.53.0.windows.4", observation_fingerprint="")}),
            lambda: (control, {**arguments, "artifacts": replace(artifacts, package_digest=digest("9"), projection_fingerprint="")}),
            lambda: (self.final_reconciliation_fixture(lambda value: value["selection"].update(gate="another-gate"))[0], arguments),
            lambda: (self.final_reconciliation_fixture(lambda value: value["recorder_store"].update(store_identity=digest("9")))[0], arguments),
            lambda: (self.final_reconciliation_fixture(lambda value: value["recorder_store"].update(store_identity="not-a-content-digest"))[0], arguments),
            lambda: (self.final_reconciliation_fixture(lambda value: value["recorder_store"].update(retention_contract="other-contract"))[0], arguments),
            lambda: (self.final_reconciliation_fixture(lambda value: value["recorder_store"].update(recorder_binding_digest=digest("a")))[0], arguments),
        ):
            invalid_control, invalid_arguments = invalid()
            with self.subTest(invalid=invalid):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(invalid_control, **invalid_arguments)
        selection = reconcile_final_provenance_selection(control, **arguments)
        with self.assertRaises(ProvenanceRecordError):
            object.__new__(VerifiedProvenanceSelection).verify_reconciliation()
        selection.verify_reconciliation()

    def test_final_boundary_reuses_retained_leaf_and_rechecks_loaded_bytes(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture(leaf=99)
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        selection = reconcile_final_provenance_selection(control, **arguments)
        verify_selection_for_durable_record(control, selection)
        self.assertFalse(hasattr(ExternalSelectionControl, "_from_load"))
        for field, value in (("receipt", b"{}"), ("mode", "REHEARSAL"), ("retention_identity", "other-retention")):
            changed, *_ = self.final_reconciliation_fixture(leaf=99)
            object.__setattr__(changed, field, value)
            with self.subTest(field=field):
                with self.assertRaises(ProvenanceRecordError):
                    changed.verify_loaded()

    def test_final_reconciliation_denies_mode_freshness_and_final_shape(self) -> None:
        rehearsal, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        payload, receipt, expected = self.external_control_bytes()
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(ExternalSelectionControl.load(payload, receipt, expected), **arguments)
        for mutate, now in (
            (lambda value: value["freshness"].update(selection_at=102), 101),
            (lambda value: value["freshness"].update(valid_until=100), 101),
            (lambda value: value["freshness"].update(candidate_movement_invalidates=False), 101),
            (lambda value: value.update(extra="forbidden"), 101),
            (lambda value: value["public_safe_projection"].update(extra="private-path"), 101),
            (lambda value: value["public_safe_projection"].update(gate="wrong-gate"), 101),
        ):
            control, *_ = self.final_reconciliation_fixture(mutate)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(control, **{**arguments, "now": now})
        for now in (100, 121):
            with self.subTest(now=now):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(rehearsal, **{**arguments, "now": now})
        not_ready, *_ = self.final_reconciliation_fixture()
        object.__setattr__(not_ready, "capture_ready", False)
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(not_ready, **arguments)

    def test_final_reconciliation_denies_projection_and_dependency_drift(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        mutations = (
            lambda value: value["validation_toolchain"].update(lock_digest=digest("9")),
            lambda value: value["validation_toolchain"]["requirements"].update(build=digest("9")),
            lambda value: value["validation_toolchain"]["environments"].update(python=digest("9")),
            lambda value: value["validation_toolchain"]["tools"]["uv"].update(version="9.9.9"),
            lambda value: value["dependency_control"].update(policy_fingerprint=digest("9")),
            lambda value: value["dependency_control"]["observations"].pop(),
            lambda value: value["dependency_control"]["admission"].update(authority_digest=digest("9")),
            lambda value: value["artifacts"].update(candidate_package=digest("9")),
            lambda value: value["artifacts"]["reviewed_git_entrypoint"].update(reported_version="2.53.0.other"),
        )
        for mutate in mutations:
            changed, *_ = self.final_reconciliation_fixture(mutate)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(changed, **arguments)
        other, *_ = self.final_reconciliation_fixture()
        selection = reconcile_final_provenance_selection(control, **arguments)
        with self.assertRaises(ProvenanceRecordError):
            verify_selection_for_durable_record(other, selection)
        with self.assertRaises(ProvenanceRecordError):
            verify_selection_for_durable_record(control, object.__new__(VerifiedProvenanceSelection))
        object.__setattr__(selection, "candidate_fingerprint", digest("9"))
        with self.assertRaises(ProvenanceRecordError):
            verify_selection_for_durable_record(control, selection)

    def test_external_control_rejects_duplicate_and_nonfinite_json(self) -> None:
        payload, receipt, expected = self.external_control_bytes()
        duplicate = payload.removesuffix(b"}") + b',"schema":"shadow"}'
        for invalid_payload, invalid_receipt in ((duplicate, receipt), (b'{"value":NaN}', receipt), (payload, b'{"value":Infinity}')):
            with self.subTest():
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(invalid_payload, invalid_receipt, expected)

    def test_final_control_denies_pinned_receipt_and_json_shape_variants(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        for name, receipt_mutate in {
            "capture-ready": lambda value: value.update(capture_ready=False),
            "rehearsal-mode": lambda value: value.update(control_mode="REHEARSAL"),
            "read-back": lambda value: value.update(read_back="PENDING"),
            "append-only": lambda value: value.update(append_only=False),
            "schema": lambda value: value.update(schema="other"),
            "retention": lambda value: value.update(retention_identity="roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/rehearsal-" + "b" * 40),
        }.items():
            with self.subTest(receipt=name):
                with self.assertRaises(ProvenanceRecordError):
                    self.final_reconciliation_fixture(receipt_mutate=receipt_mutate)
        for mutate in (
            lambda value: value.pop("read_back"),
            lambda value: value.update(extra="forbidden"),
        ):
            with self.subTest(receipt=mutate):
                with self.assertRaises(ProvenanceRecordError):
                    self.final_reconciliation_fixture(receipt_mutate=mutate)
        duplicate_receipt = control.receipt.removesuffix(b"}") + b',"schema":"other"}'
        duplicate_expectation = replace(control.expected, receipt_digest="sha256:" + hashlib.sha256(duplicate_receipt).hexdigest())
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(control.payload, duplicate_receipt, duplicate_expectation)
        duplicate_payload = control.payload.removesuffix(b"}") + b',"schema":"other"}'
        receipt_value = json.loads(control.receipt)
        receipt_value.update(payload_bytes=len(duplicate_payload), payload_sha256="sha256:" + hashlib.sha256(duplicate_payload).hexdigest())
        duplicate_payload_receipt = json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode()
        duplicate_payload_expected = replace(
            control.expected,
            payload_digest="sha256:" + hashlib.sha256(duplicate_payload).hexdigest(),
            receipt_digest="sha256:" + hashlib.sha256(duplicate_payload_receipt).hexdigest(),
        )
        with self.assertRaises(ProvenanceRecordError):
            ExternalSelectionControl.load(duplicate_payload, duplicate_payload_receipt, duplicate_payload_expected)
        self.assertIsNotNone(reconcile_final_provenance_selection(control, **arguments))

    def test_final_reconciliation_denies_actual_validation_projection_drift(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        def revised_validation(**changes):
            return replace(
                validation,
                requirements_fingerprint="", environments_fingerprint="", tools_fingerprint="",
                projection_fingerprint="", **changes,
            )
        for name, changed in {
            "lock": revised_validation(lock_digest=digest("9")),
            "cache": revised_validation(cache_key="other-cache"),
            "receipt": revised_validation(receipt_digest=digest("9")),
        }.items():
            with self.subTest(identity=name):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(control, **{**arguments, "validation": changed})
        for family, values in (("requirements", validation.requirements), ("environments", validation.environments), ("tools", validation.tools)):
            for index, item in enumerate(values):
                changed_values = list(values)
                changed_values[index] = replace(item, digest=digest("f"))
                changed = revised_validation(**{family: tuple(changed_values)})
                with self.subTest(family=family, name=item.name, field="digest"):
                    with self.assertRaises(ProvenanceRecordError):
                        reconcile_final_provenance_selection(control, **{**arguments, "validation": changed})
                if family == "tools":
                    changed_values = list(values)
                    changed_values[index] = replace(item, version="9.9.9")
                    changed = revised_validation(**{family: tuple(changed_values)})
                    with self.subTest(family=family, name=item.name, field="version"):
                        with self.assertRaises(ProvenanceRecordError):
                            reconcile_final_provenance_selection(control, **{**arguments, "validation": changed})
            for shape in (values[:-1], values + (values[0],), tuple(reversed(values))):
                with self.subTest(family=family, shape=tuple(item.name for item in shape)):
                    with self.assertRaises(ProvenanceRecordError):
                        revised_validation(**{family: shape})

    def test_final_reconciliation_denies_public_schema_and_terminal_projection_drift(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        for name, mutate in {
            "route": lambda value: value["selection"].update(route="none"),
            "case-schema": lambda value: value["selection"].update(case_schema="other"),
            "profile": lambda value: value["selection"].update(evidence_profile="other"),
            "capture-mode": lambda value: value["selection"].update(capture_mode="other"),
            "gate": lambda value: value["selection"].update(gate="other"),
            "blocker": lambda value: value["selection"].update(blocker="private"),
            "next-action": lambda value: value["selection"].update(next_action="other"),
            "public-extra": lambda value: value["public_safe_projection"].update(extra="private"),
            "public-missing": lambda value: value["public_safe_projection"].pop("repository"),
            "public-private": lambda value: value["public_safe_projection"].update(repository="C:/secret/token"),
            "public-credential": lambda value: value["public_safe_projection"].update(route="token=secret"),
        }.items():
            with self.subTest(projection=name):
                with self.assertRaises(ProvenanceRecordError):
                    changed, *_ = self.final_reconciliation_fixture(mutate)
                    reconcile_final_provenance_selection(changed, **arguments)

    def test_final_reconciliation_denies_typed_dependency_and_admission_inputs(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        package, git_dependency = dependency.observations
        forged_observations = {
            "missing-package": (git_dependency,),
            "missing-git": (package,),
            "duplicate-component": (package, package),
            "wrong-policy-digest": (replace(package, policy_digest=digest("9")), git_dependency),
            "future-observation": (replace(package, observed_at=102), git_dependency),
            "identifier-drift": (replace(package, identifier="other-package"), git_dependency),
            "source-drift": (replace(package, source_identity="other-source"), git_dependency),
            "version-drift": (replace(package, version="1.0.1"), git_dependency),
            "artifact-drift": (replace(package, artifact_digest=digest("9")), git_dependency),
            "executable-drift": (replace(package, executable_digest=digest("9")), git_dependency),
            "wrong-binding": (replace(package, binding=CandidateBinding("ythdelmar68/roundwright", "task-47", "c" * 40)), git_dependency),
            "stale-observation": (replace(package, observed_at=0), git_dependency),
        }
        def deny_at_matching_git_boundary(name, forged):
            with self.subTest(name=name):
                # The Git control must point at the forged dependency control: using
                # the original control would only prove an unrelated mismatch.
                try:
                    forged_git = GitEntrypointControl(forged.policy.binding, forged, 101)
                except GitIdentityError:
                    return
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(
                        control,
                        **{**arguments, "dependency_control": forged, "git_control": forged_git},
                    )
        for name, observations in forged_observations.items():
            deny_at_matching_git_boundary(name, replace(dependency, observations=observations))
        for name, admission in {
            "policy": replace(dependency.admission, policy_fingerprint=digest("9")),
            "receipt": replace(dependency.admission, receipt_digest=digest("9")),
            "reviewer": replace(dependency.admission, reviewer_identity=digest("9")),
            "authority": replace(dependency.admission, authority_digest=digest("9")),
        }.items():
            deny_at_matching_git_boundary("admission-" + name, replace(dependency, admission=admission))
        with self.assertRaises(DependencyPolicyError):
            replace(
                dependency,
                admission=replace(
                    dependency.admission,
                    binding=CandidateBinding("ythdelmar68/roundwright", "task-47", "c" * 40),
                ),
            )
        stale_policy = replace(dependency.policy, issued_at=0)
        deny_at_matching_git_boundary("stale-policy", replace(dependency, policy=stale_policy))
        conflicting = replace(dependency.admission, previous_policy=dependency.policy)
        deny_at_matching_git_boundary("conflicting-previous-policy", replace(dependency, admission=conflicting))
        reversed_control = replace(dependency, observations=tuple(reversed(dependency.observations)))
        reversed_git_control = GitEntrypointControl(reversed_control.policy.binding, reversed_control, 101)
        self.assertEqual(
            reconcile_final_provenance_selection(
                control,
                **{**arguments, "dependency_control": reversed_control, "git_control": reversed_git_control},
            ).control_fingerprint,
            reconcile_final_provenance_selection(control, **arguments).control_fingerprint,
        )

    def test_final_reconciliation_denies_typed_git_control_boundaries(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        wrong_binding = CandidateBinding("ythdelmar68/roundwright", "task-47", "c" * 40)
        with self.assertRaises(GitIdentityError):
            GitEntrypointControl(wrong_binding, dependency, 101)
        moved_dependency = self.dependency_control(candidate="c" * 40)
        moved_git = GitEntrypointControl(moved_dependency.policy.binding, moved_dependency, 101)
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(
                control,
                **{**arguments, "dependency_control": moved_dependency, "git_control": moved_git},
            )
        different_now = GitEntrypointControl(dependency.policy.binding, dependency, 102)
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(control, **{**arguments, "git_control": different_now})

    def test_final_reconciliation_denies_typed_git_artifact_and_candidate_drift(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        arguments = {"validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        git_changes = {
            "binding": replace(git, binding_fingerprint=digest("9"), observation_fingerprint=""),
            "identifier": replace(git, identifier="other-git", observation_fingerprint=""),
            "source": replace(git, source_identity="other-source", observation_fingerprint=""),
            "source-class": replace(git, source_class="other-class", observation_fingerprint=""),
            "normalized-version": replace(git, normalized_version="2.53.1", observation_fingerprint=""),
            "reported-version": replace(git, reported_version="2.53.1.windows.3", observation_fingerprint=""),
            "artifact": replace(git, artifact_digest=digest("9"), observation_fingerprint=""),
            "executable": replace(git, executable_digest=digest("9"), observation_fingerprint=""),
            "control": replace(git, control_fingerprint=digest("9"), observation_fingerprint=""),
        }
        for name, observation in git_changes.items():
            with self.subTest(git=name):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(control, **{**arguments, "git_observation": observation})
        for name, artifact in {
            "repository": replace(artifacts, repository="other/roundwright", projection_fingerprint=""),
            "task": replace(artifacts, task_id="other-task", projection_fingerprint=""),
            "candidate": replace(artifacts, candidate_sha="c" * 40, projection_fingerprint=""),
            "tree": replace(artifacts, candidate_tree="d" * 40, projection_fingerprint=""),
            "source-identity": replace(artifacts, source_identity="other-source", projection_fingerprint=""),
            "source-digest": replace(artifacts, source_digest=digest("9"), projection_fingerprint=""),
            "package": replace(artifacts, package_digest=digest("9"), projection_fingerprint=""),
            "entrypoint": replace(artifacts, installed_entrypoint_digest=digest("9"), projection_fingerprint=""),
        }.items():
            with self.subTest(artifact=name):
                with self.assertRaises(ProvenanceRecordError):
                    reconcile_final_provenance_selection(control, **{**arguments, "artifacts": artifact})
        _, other_validation, other_artifacts, other_git, other_observation, other_dependency = self.final_reconciliation_fixture(candidate="c" * 40)
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(control, validation=other_validation, artifacts=other_artifacts, git_control=other_git, git_observation=other_observation, dependency_control=other_dependency, now=101)
        with self.assertRaises(ProvenanceRecordError):
            reconcile_final_provenance_selection(control, **{**arguments, "git_control": other_git})

    def verified_record_fixture(self):
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        selection = reconcile_final_provenance_selection(
            control, validation=validation, artifacts=artifacts, git_control=git_control,
            git_observation=git, dependency_control=dependency, now=101,
        )
        record = materialize_verified_provenance_record(
            control, selection, validation=validation, artifacts=artifacts, git_control=git_control,
            git_observation=git, dependency_control=dependency, now=101,
        )
        return record, control, selection, validation, artifacts, git_control, git, dependency

    def test_verified_durable_record_materializes_only_from_reconciled_inputs(self) -> None:
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        record.verify()
        projection = record.public_projection()
        self.assertEqual(projection["schema"], "roundwright-verified-provenance-record/v1")
        self.assertEqual(projection["external"]["retention_identity"], control.retention_identity)
        self.assertEqual(projection["selection"]["candidate_sha"], dependency.policy.binding.candidate_sha)
        self.assertNotIn("payload", projection)
        self.assertNotIn("receipt", projection)
        with self.assertRaises(TypeError):
            VerifiedDurableProvenanceRecord()
        self.assertFalse(hasattr(VerifiedDurableProvenanceRecord, "_from_document"))
        with self.assertRaises(ProvenanceRecordError):
            materialize_verified_provenance_record(
                control, object.__new__(VerifiedProvenanceSelection), validation=validation, artifacts=artifacts,
                git_control=git_control, git_observation=git, dependency_control=dependency, now=101,
            )
        other, *_ = self.final_reconciliation_fixture()
        with self.assertRaises(ProvenanceRecordError):
            materialize_verified_provenance_record(
                other, selection, validation=validation, artifacts=artifacts, git_control=git_control,
                git_observation=git, dependency_control=dependency, now=101,
            )
        with self.assertRaises(ProvenanceRecordError):
            materialize_verified_provenance_record(
                control, selection, validation=validation, artifacts=replace(artifacts, package_digest=digest("9"), projection_fingerprint=""),
                git_control=git_control, git_observation=git, dependency_control=dependency, now=101,
            )

    def test_verified_durable_record_store_is_append_only_and_read_back_verified(self) -> None:
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        authority = {"loaded_control": control, "selection": selection, "validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        with TemporaryDirectory() as temporary:
            root = self.canonical_test_store_root(temporary)
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            self.assertEqual(store.append(record, **authority), record.record_digest)
            read_back = store.read_back(record.candidate_sha, record.record_digest)
            self.assertEqual(read_back.public_projection(), record.public_projection())
            self.assertEqual(read_back.verify_against(**authority).payload, record.payload)
            self.assertEqual(store.append(record, **authority), record.record_digest)
            with self.assertRaises(TypeError):
                store.append(record)
            with self.assertRaises(ProvenanceRecordError):
                store.append(object.__new__(VerifiedDurableProvenanceRecord), **authority)
            wrong_control, *_ = self.final_reconciliation_fixture(candidate="c" * 40)
            with self.assertRaises(ProvenanceRecordError):
                store.append(record, **{**authority, "loaded_control": wrong_control})
            with self.assertRaises(ProvenanceRecordError):
                VerifiedProvenanceRecordStore(root, "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/final-" + "c" * 40).append(record, **authority)
            path = root / record.candidate_sha / f"{record.record_digest.removeprefix('sha256:')}.json"
            path.write_bytes(b"{}")
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(record.candidate_sha, record.record_digest)
            with self.assertRaises(ProvenanceRecordError):
                store.append(record, **authority)
        with TemporaryDirectory() as temporary:
            root = self.canonical_test_store_root(temporary)
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            value = record.public_projection()
            value["validation"]["lock_digest"] = digest("9")
            value.pop("record_digest")
            value["record_digest"] = "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
            payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            path = root / record.candidate_sha / f"{value['record_digest'].removeprefix('sha256:')}.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(payload)
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(record.candidate_sha, value["record_digest"])
            for family, replacement in (
                ("requirements", {"build": digest("3")} ),
                ("environments", {"python": digest("5"), "build": digest("6"), "pipx": digest("7"), "extra": digest("8")} ),
                ("tools", {"uv": {"version": "0.12.3", "digest": digest("8")}}),
            ):
                malformed = record.public_projection()
                malformed["validation"][family] = replacement
                malformed.pop("record_digest")
                malformed["record_digest"] = "sha256:" + hashlib.sha256(json.dumps(malformed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
                malformed_bytes = json.dumps(malformed, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
                malformed_path = root / record.candidate_sha / f"{malformed['record_digest'].removeprefix('sha256:')}.json"
                malformed_path.write_bytes(malformed_bytes)
                with self.subTest(family=family):
                    with self.assertRaises(ProvenanceRecordError):
                        store.read_back(record.candidate_sha, malformed["record_digest"])

    def test_verified_durable_record_readback_denies_parser_store_and_link_bypasses(self) -> None:
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        authority = {"loaded_control": control, "selection": selection, "validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        with TemporaryDirectory() as temporary:
            root = self.canonical_test_store_root(temporary)
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            def write(digest_value, payload):
                path = root / record.candidate_sha / f"{digest_value.removeprefix('sha256:')}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
                return path
            for name, payload in {
                "duplicate-top": b'{"schema":"x","schema":"y"}',
                "duplicate-nested": b'{"external":{"run_id":"a","run_id":"b"}}',
                "non-finite": b'{"value":NaN}',
                "infinite": b'{"value":Infinity}',
                "noncanonical": record.payload + b" ",
                "truncated": record.payload[:-1],
            }.items():
                digest_value = digest("f")
                write(digest_value, payload)
                with self.subTest(parser=name):
                    with self.assertRaises(ProvenanceRecordError):
                        store.read_back(record.candidate_sha, digest_value)
            for name, mutate in {
                "missing-top": lambda value: value.pop("external"),
                "extra-top": lambda value: value.update(extra="x"),
                "missing-nested": lambda value: value["external"].pop("run_id"),
                "extra-nested": lambda value: value["artifacts"].update(extra="x"),
                "unsafe-public": lambda value: value["selection"].update(route="C:/secret/token"),
            }.items():
                value = record.public_projection()
                mutate(value)
                value.pop("record_digest")
                value["record_digest"] = "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
                write(value["record_digest"], json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
                with self.subTest(shape=name):
                    with self.assertRaises(ProvenanceRecordError):
                        store.read_back(record.candidate_sha, value["record_digest"])
            self.assertEqual(store.append(record, **authority), record.record_digest)
            parsed = store.read_back(record.candidate_sha, record.record_digest)
            with self.assertRaises(ProvenanceRecordError):
                store.read_back("c" * 40, record.record_digest)
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(record.candidate_sha, digest("e"))
            with self.assertRaises(ProvenanceRecordError):
                store.append(parsed, **authority)
            other_control, *_ = self.final_reconciliation_fixture(candidate="c" * 40)
            with self.assertRaises(ProvenanceRecordError):
                parsed.verify_against(**{**authority, "loaded_control": other_control})
            with self.assertRaises(ProvenanceRecordError):
                store.append(parsed, **authority)
        with TemporaryDirectory() as temporary:
            root = self.canonical_test_store_root(temporary, "verified-store")
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            with self.assertRaises(ProvenanceRecordError):
                store.append(record, **{**authority, "now": 121})
            self.assertFalse(root.exists())
            self.assertFalse((root / record.candidate_sha).exists())
            with patch.object(type(root), "is_symlink", return_value=True):
                with self.assertRaises(ProvenanceRecordError):
                    store.append(record, **authority)
            self.assertFalse((root / record.candidate_sha).exists())
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            store = VerifiedProvenanceRecordStore(self.canonical_test_store_root(first), record.retention_identity)
            store.append(record, **authority)
            wrong_store = VerifiedProvenanceRecordStore(self.canonical_test_store_root(second), record.retention_identity)
            with self.assertRaises(ProvenanceRecordError):
                wrong_store.read_back(record.candidate_sha, record.record_digest)

    def test_verified_durable_record_store_denies_real_link_traversal_when_supported(self) -> None:
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        authority = {"loaded_control": control, "selection": selection, "validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        with TemporaryDirectory() as temporary, TemporaryDirectory() as target:
            root = self.canonical_test_store_root(temporary, "store-link")
            try:
                root.symlink_to(Path(target), target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("the host cannot create a directory symlink")
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            with self.assertRaises(ProvenanceRecordError):
                store.append(record, **authority)
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(record.candidate_sha, record.record_digest)
        with TemporaryDirectory() as temporary, TemporaryDirectory() as target:
            base = self.canonical_test_store_root(temporary)
            link = base / "linked-parent"
            try:
                link.symlink_to(Path(target), target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("the host cannot create an intermediate directory symlink")
            store = VerifiedProvenanceRecordStore(link / "child", record.retention_identity)
            with self.assertRaises(ProvenanceRecordError):
                store.append(record, **authority)
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(record.candidate_sha, record.record_digest)

    def test_verified_store_accepts_canonical_ordinary_temp_root(self) -> None:
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        authority = {"loaded_control": control, "selection": selection, "validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        with TemporaryDirectory() as temporary:
            root = self.canonical_test_store_root(temporary)
            store = VerifiedProvenanceRecordStore(root, record.retention_identity)
            self.assertEqual(store.append(record, **authority), record.record_digest)
            self.assertEqual(store.read_back(record.candidate_sha, record.record_digest).record_digest, record.record_digest)

    def verified_readback_fixture(self):
        record, control, selection, validation, artifacts, git_control, git, dependency = self.verified_record_fixture()
        authority = {"loaded_control": control, "selection": selection, "validation": validation, "artifacts": artifacts, "git_control": git_control, "git_observation": git, "dependency_control": dependency, "now": 101}
        temporary = TemporaryDirectory()
        store = VerifiedProvenanceRecordStore(self.canonical_test_store_root(temporary.name), record.retention_identity)
        store.append(record, **authority)
        return temporary, store, store.read_back(record.candidate_sha, record.record_digest), record, authority

    @staticmethod
    def export_authority(authority):
        return {name: value for name, value in authority.items() if name != "now"}

    @staticmethod
    def verified_store_snapshot(store):
        if not store._root.exists():
            return ()
        return tuple(sorted(
            (str(path.relative_to(store._root)), "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest())
            for path in store._root.rglob("*") if path.is_file()
        ))

    @staticmethod
    def write_rebased_verified_document(store, candidate_sha, document):
        document.pop("record_digest", None)
        document["record_digest"] = "sha256:" + hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        path = store._root / candidate_sha / f"{document['record_digest'].removeprefix('sha256:')}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return document["record_digest"]

    def test_verified_terminal_export_and_readiness_require_readback_authority(self) -> None:
        temporary, store, read_back, record, authority = self.verified_readback_fixture()
        self.addCleanup(temporary.cleanup)
        export_authority = self.export_authority(authority)
        decision = export_provenance_decision(store, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority)
        self.assertEqual((decision.candidate_sha, decision.ready_at), ("b" * 40, 101))
        self.assertEqual(tuple(item.kind for item in decision.artifacts), (
            "candidate-source", "candidate-package", "installed-roundwright-entrypoint",
            "reviewed-git-artifact", "reviewed-git-executable",
        ))
        before_success = self.verified_store_snapshot(store)
        readiness = require_verified_provenance_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, decision,
            RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
            candidate_sha=decision.candidate_sha, record_digest=record.record_digest, ready_at=101, **export_authority,
        )
        self.assertIs(type(readiness), VerifiedCaptureReadinessReceipt)
        self.assertEqual(readiness.durable_record_digest, record.record_digest)
        self.assertEqual(readiness.ready_at, 101)
        self.assertEqual(readiness.evidence_store_identity, authority["loaded_control"].expected.recorder_store_identity)
        readiness.verify()
        self.assertEqual(self.verified_store_snapshot(store), before_success)
        readiness.verify_against(
            store, recorder=RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
            **export_authority,
        )
        with self.assertRaises(TypeError):
            VerifiedCaptureReadinessReceipt()
        with self.assertRaises(ShadowV2Error):
            require_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), self.record(),
                RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
                AppendOnlyEvidenceStore("fixture-store"), candidate_sha=record.candidate_sha, ready_at=101,
            )
        before = self.verified_store_snapshot(store)
        with self.assertRaises(ProvenanceRecordError):
            require_verified_provenance_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, decision,
                RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
                candidate_sha=decision.candidate_sha, record_digest=record.record_digest, ready_at=102,
                **export_authority,
            )
        self.assertEqual(self.verified_store_snapshot(store), before)
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(record, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority)
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(read_back, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority)

    def test_verified_export_denies_persisted_artifact_vocabulary_and_store_tampering(self) -> None:
        temporary, store, _, record, authority = self.verified_readback_fixture()
        self.addCleanup(temporary.cleanup)
        export_authority = self.export_authority(authority)
        for name, mutate in (
            ("missing", lambda value: value.pop()),
            ("extra", lambda value: value.append("extra-artifact")),
            ("reordered", lambda value: value.reverse()),
            ("duplicate", lambda value: value.append(value[-1])),
        ):
            document = record.public_projection()
            mutate(document["artifacts"]["export_artifact_kinds"])
            rebased_digest = self.write_rebased_verified_document(store, record.candidate_sha, document)
            with self.subTest(vocabulary=name):
                with self.assertRaises(ProvenanceRecordError):
                    export_provenance_decision(
                        store, candidate_sha=record.candidate_sha, record_digest=rebased_digest,
                        **export_authority,
                    )
        path = store._root / record.candidate_sha / f"{record.record_digest.removeprefix('sha256:')}.json"
        path.write_bytes(b"{}")
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(
                store, candidate_sha=record.candidate_sha, record_digest=record.record_digest,
                **export_authority,
            )

    def test_verified_readiness_denies_forged_decision_and_receipt_against_valid_store(self) -> None:
        temporary, store, _, record, authority = self.verified_readback_fixture()
        self.addCleanup(temporary.cleanup)
        export_authority = self.export_authority(authority)
        recorder = RecorderBinding(
            "1bb063d3f8f1fef9a24b3147b8bc99794e4637a7",
            "cf669e186a739a8597cfaf9f050ce3bdcadda334",
            "632dcc3ecb3b8664de860844af2215ad5ade83e1",
        )
        decision = export_provenance_decision(
            store, candidate_sha=record.candidate_sha, record_digest=record.record_digest,
            **export_authority,
        )
        forged_decision = replace(decision, next_action="another-action", decision_digest="")
        with self.assertRaises(ProvenanceRecordError):
            require_verified_provenance_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, forged_decision, recorder,
                candidate_sha=record.candidate_sha, record_digest=record.record_digest, ready_at=101,
                **export_authority,
            )
        with self.assertRaises(ProvenanceRecordError):
            require_verified_provenance_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, decision,
                recorder,
                candidate_sha=decision.candidate_sha, record_digest=record.record_digest, ready_at=102, **export_authority,
            )
        valid = require_verified_provenance_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, decision, recorder,
            candidate_sha=decision.candidate_sha, record_digest=record.record_digest, ready_at=101,
            **export_authority,
        )
        with self.assertRaises(ProvenanceRecordError):
            object.__new__(VerifiedCaptureReadinessReceipt).verify()
        forged = object.__new__(VerifiedCaptureReadinessReceipt)
        for name in valid.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(valid, name))
        forged.verify()
        wrong_recorder = object.__new__(RecorderBinding)
        object.__setattr__(wrong_recorder, "harness_merge", "0" * 40)
        object.__setattr__(wrong_recorder, "recorder_content", recorder.recorder_content)
        object.__setattr__(wrong_recorder, "harness_tree", recorder.harness_tree)
        with self.assertRaises(ProvenanceRecordError):
            forged.verify_against(store, recorder=wrong_recorder, **export_authority)
        with self.assertRaises(ProvenanceRecordError):
            require_verified_provenance_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), store, decision,
                wrong_recorder,
                candidate_sha=decision.candidate_sha, record_digest=record.record_digest, ready_at=101, **export_authority,
            )

    def test_verified_terminal_export_denies_legacy_moved_and_tampered_inputs(self) -> None:
        temporary, store, read_back, record, authority = self.verified_readback_fixture()
        self.addCleanup(temporary.cleanup)
        export_authority = self.export_authority(authority)
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(self.record(), candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority)
        moved_control, moved_validation, moved_artifacts, moved_git_control, moved_git, moved_dependency = self.final_reconciliation_fixture(candidate="c" * 40)
        moved_selection = reconcile_final_provenance_selection(moved_control, validation=moved_validation, artifacts=moved_artifacts, git_control=moved_git_control, git_observation=moved_git, dependency_control=moved_dependency, now=101)
        moved_authority = {"loaded_control": moved_control, "selection": moved_selection, "validation": moved_validation, "artifacts": moved_artifacts, "git_control": moved_git_control, "git_observation": moved_git, "dependency_control": moved_dependency}
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(store, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **moved_authority)
        self.assertEqual(export_provenance_decision(store, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority).ready_at, 101)
        object.__setattr__(read_back, "payload", b"{}")
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(read_back, candidate_sha=record.candidate_sha, record_digest=record.record_digest, **export_authority)

    def record(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        control = self.dependency_control(candidate=candidate, ready_at=ready_at)
        return _materialize_provenance_record(
            control,
            base_sha="a" * 40,
            candidate_tree="d" * 40,
            entrypoint_fingerprint=digest("e"),
            gate_identity="provenance-gate-pass",
            blocker=None,
            next_action="record-terminal-snapshot",
            now=ready_at,
        )

    def decision(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        return _export_legacy_provenance_decision(self.record(candidate=candidate, ready_at=ready_at))

    def case(self, *, candidate: str = "b" * 40, ready_at: int = 101) -> ShadowV2Case:
        decision = self.decision(candidate=candidate, ready_at=ready_at)
        readiness = _require_legacy_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            self.record(candidate=candidate, ready_at=ready_at),
            RecorderBinding(
                "1bb063d3f8f1fef9a24b3147b8bc99794e4637a7",
                "cf669e186a739a8597cfaf9f050ce3bdcadda334",
                "632dcc3ecb3b8664de860844af2215ad5ade83e1",
            ),
            AppendOnlyEvidenceStore("roundlet-provenance-retention"),
            candidate_sha=candidate,
            ready_at=ready_at,
        )
        event = ShadowV2Observation(
            1,
            "terminal-provenance-decision",
            "lifecycle-47-terminal",
            PROVENANCE_DECISION_PROFILE,
            "provenance-decision",
            None,
            False,
            candidate,
            decision.decision_digest,
        )
        return ShadowV2Case(
            "shadow-47-terminal",
            "lifecycle-47-terminal",
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            decision,
            decision,
            readiness,
            (event,),
            "phase-3-terminal-snapshot",
            "roundlet-provenance-retention",
        )

    def test_closed_profile_declares_every_capture_readiness_field(self) -> None:
        profile = shadow_evidence_profile(PROVENANCE_DECISION_PROFILE)
        worker = shadow_evidence_profile("roundwright-shadow-profile/worker-adapter/v1")
        synthetic = shadow_evidence_profile(EXECUTOR_CONTRACT_SYNTHETIC_PROFILE)
        provider_attempts = shadow_evidence_profile("roundwright-shadow-profile/provider-attempt-accounting/v1")
        hosted_checks = shadow_evidence_profile(HOSTED_CHECK_PROFILE)
        live_lifecycle = shadow_evidence_profile("roundwright-shadow-profile/live-lifecycle-shadow/v1")
        read_only_external_observation = shadow_evidence_profile(READ_ONLY_EXTERNAL_OBSERVATION_PROFILE)
        integrated_boundary = shadow_evidence_profile(INTEGRATED_BOUNDARY_PROFILE)
        qualification_consumer = shadow_evidence_profile("roundwright-shadow-profile/phase-3-qualification/v1")
        cross_environment = shadow_evidence_profile("roundwright-shadow-profile/cross-environment-canary/v1")
        self.assertEqual(hosted_checks.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(
            shadow_evidence_profiles(),
            (profile, worker, synthetic, provider_attempts, hosted_checks, live_lifecycle, read_only_external_observation, integrated_boundary, qualification_consumer, cross_environment),
        )
        self.assertEqual(profile.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(profile.event_kinds, ("provenance-decision",))
        self.assertEqual(worker.capture_mode, CaptureMode.LIFECYCLE_GRAPH)
        self.assertEqual(worker.event_kinds, ("worker-request-response-envelope",))
        self.assertEqual(synthetic.capture_mode, CaptureMode.SYNTHETIC_ONE_SHOT)
        self.assertEqual(synthetic.event_kinds, ("executor-contract-result",))
        self.assertEqual(provider_attempts.capture_mode, CaptureMode.LIFECYCLE_GRAPH)
        self.assertEqual(provider_attempts.arm_before, "before-first-selected-provider-attempt")
        self.assertEqual(live_lifecycle.capture_mode, CaptureMode.ARMED_LIVE_EVENTS)
        self.assertEqual(live_lifecycle.arm_before, "before-first-live-lifecycle-event")
        self.assertEqual(read_only_external_observation.profile_id, READ_ONLY_EXTERNAL_OBSERVATION_PROFILE)
        self.assertEqual(read_only_external_observation.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(read_only_external_observation.arm_before, "before-supervisor-dispatch")
        self.assertEqual(read_only_external_observation.event_kinds, ("read-only-external-observation",))
        self.assertEqual(integrated_boundary.capture_mode, CaptureMode.COMPOSED_EVIDENCE)
        self.assertEqual(integrated_boundary.event_kinds, ("composed-evidence-manifest", "composed-evidence-result"))
        self.assertEqual(qualification_consumer.capture_mode, CaptureMode.COMPOSED_EVIDENCE)
        self.assertEqual(qualification_consumer.event_kinds, ("qualification-inventory", "qualification-decision"))
        self.assertEqual(cross_environment.capture_mode, CaptureMode.SYNTHETIC_ONE_SHOT)
        self.assertEqual(cross_environment.event_kinds, ("cross-environment-profile-qualification",))
        with self.assertRaises(ShadowV2Error):
            shadow_evidence_profile("roundwright-shadow-profile/future/v1")

    def test_terminal_snapshot_replays_without_provider_attempt_or_six_state_trace(self) -> None:
        case = self.case()
        report = replay_shadow_v2_case(case)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH))
        self.assertTrue(report.curated_summary()["read_only"])
        self.assertEqual(replay_shadow_case(case).case_digest, case.case_digest)

    def test_capture_time_is_immutable_and_candidate_movement_requires_recapture(self) -> None:
        decision = self.decision()
        self.assertEqual(compare_provenance_decision(decision, decision, ready_at=101), ComparisonOutcome.MATCH)
        self.assertEqual(compare_provenance_decision(decision, decision, ready_at=102), ComparisonOutcome.INVALID)
        with self.assertRaises(ShadowV2Error):
            _require_legacy_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), self.record(),
                RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
                AppendOnlyEvidenceStore("roundlet-provenance-retention"),
                candidate_sha="c" * 40, ready_at=101,
            )

    def test_terminal_export_requires_durable_record_and_store_readback_rejects_tampering(self) -> None:
        record = self.record()
        with self.assertRaises(ProvenanceRecordError):
            _export_legacy_provenance_decision(record.decision)
        with TemporaryDirectory() as temporary:
            store = ProvenanceRecordStore(Path(temporary), "roundlet-provenance-records")
            digest = store.append(record)
            self.assertEqual(store.read_back(digest), record)
            self.assertEqual(store.append(record), digest)
            (Path(temporary) / f"{digest.removeprefix('sha256:')}.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(digest)

    def test_v2_rejects_provider_attempt_and_wrong_profile_event(self) -> None:
        case = self.case()
        with self.assertRaises(ShadowV2Error):
            ShadowV2Observation(1, "event", "lifecycle", PROVENANCE_DECISION_PROFILE, "provenance-decision", "provider-attempt", False, "b" * 40, case.decision.decision_digest)
        with self.assertRaises(ShadowV2Error):
            ShadowV2Observation(1, "event", "lifecycle", PROVENANCE_DECISION_PROFILE, "worker-loop", None, False, "b" * 40, case.decision.decision_digest)

    def test_append_only_retention_rejects_overwrite_and_reads_exact_bytes(self) -> None:
        case = self.case()
        store = AppendOnlyEvidenceStore("roundlet-provenance-retention")
        receipt = store.append(case.retention_payload())
        self.assertEqual(store.read_back(receipt), case.retention_payload())
        with self.assertRaisesRegex(ShadowV2Error, "overwrite"):
            store.append(case.retention_payload())

    def lifecycle_profile(self) -> ShadowEvidenceProfile:
        return ShadowEvidenceProfile(
            "roundwright-shadow-profile/test-lifecycle/v1",
            CaptureMode.LIFECYCLE_GRAPH,
            ShadowProducer.PROFILE_DEFINED,
            "typed-graph-ready",
            "before-profile-events",
            "append-only-readback",
            "fresh-candidate-recapture",
            ("worker-dispatch", "supervisor-review", "worker-repair", "accepted-result", "lifecycle-note"),
            1,
            1,
            True,
        )

    def lifecycle_graph(self) -> ShadowV2EventGraph:
        candidate = "b" * 40
        return ShadowV2EventGraph(
            (
                LifecycleAttempt("worker-1", 1, LifecycleAttemptKind.WORKER, EvidenceRole.WORKER),
                LifecycleAttempt("supervisor-1", 2, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-1", "round-1"),
                LifecycleAttempt("worker-repair-2", 3, LifecycleAttemptKind.REPAIR, EvidenceRole.WORKER, "supervisor-1"),
                LifecycleAttempt("supervisor-2", 4, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-repair-2", "round-2"),
            ),
            (
                ProviderAttemptManifest("provider-primary-1", "worker-1", 1, "provider-primary", "failed"),
                ProviderAttemptManifest("provider-failover-1", "worker-1", 2, "provider-failover", "ready"),
            ),
            (
                FormalReviewRoundReference("round-1", 1, candidate),
                FormalReviewRoundReference("round-2", 2, candidate, "accepted-2"),
            ),
            (CandidateCommitReference(candidate, "worker-repair-commit"),),
            (AcceptedResultReference("accepted-2", "round-2", "event-5", candidate),),
            (
                ShadowV2Event("event-1", 1, "worker-1", "worker-dispatch", "provider-primary-1", True),
                ShadowV2Event("event-2", 2, "worker-1", "worker-dispatch", "provider-failover-1", True),
                ShadowV2Event("event-3", 3, "supervisor-1", "supervisor-review", None, False, "round-1"),
                ShadowV2Event("event-4", 4, "worker-repair-2", "worker-repair", None, False, None, candidate),
                ShadowV2Event("event-5", 5, "supervisor-2", "accepted-result", None, False, "round-2", None, "accepted-2"),
                ShadowV2Event("event-6", 6, "supervisor-2", "lifecycle-note", None, False),
            ),
            (AttemptCommitReference("worker-repair-2", candidate),),
        )

    def lifecycle_case(self, graph: ShadowV2EventGraph | None = None, *, profile: ShadowEvidenceProfile | None = None) -> ShadowV2Case:
        decision = self.decision()
        profile = self.lifecycle_profile() if profile is None else profile
        readiness = _require_legacy_capture_readiness(
            profile, decision,
            RecorderBinding("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", "cf669e186a739a8597cfaf9f050ce3bdcadda334", "632dcc3ecb3b8664de860844af2215ad5ade83e1"),
            AppendOnlyEvidenceStore("roundlet-provenance-retention"), candidate_sha="b" * 40, ready_at=101,
        )
        return ShadowV2Case(
            "shadow-47-lifecycle", "lifecycle-47", profile, decision, decision, readiness,
            (), "phase-3-lifecycle", "roundlet-provenance-retention", event_graph=self.lifecycle_graph() if graph is None else graph,
        )

    def test_generic_graph_separates_lifecycle_provider_review_commit_and_result(self) -> None:
        case = self.lifecycle_case()
        graph = case.event_graph
        self.assertIsNotNone(graph)
        self.assertEqual([item.attempt_id for item in graph.attempts], ["worker-1", "supervisor-1", "worker-repair-2", "supervisor-2"])
        self.assertEqual(graph.provider_attempts[1].provider_identity, "provider-failover")
        report = replay_shadow_v2_case(case)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH))

    def test_graph_rejects_missing_duplicate_out_of_order_and_wrong_attempt_references(self) -> None:
        graph = self.lifecycle_graph()
        missing = replace(graph, events=(*graph.events[:-1], replace(graph.events[-1], provider_attempt_id="provider-missing", provider_call_made=True)))
        wrong = replace(graph, events=(replace(graph.events[0], lifecycle_attempt_id="supervisor-1"), *graph.events[1:]))
        duplicate = replace(graph, provider_attempts=(graph.provider_attempts[0], graph.provider_attempts[0]))
        duplicate_event = replace(graph, events=(*graph.events, ShadowV2Event("event-7", 7, "worker-1", "worker-dispatch", "provider-primary-1", True)))
        out_of_order = replace(graph, attempts=(graph.attempts[1], graph.attempts[0], *graph.attempts[2:]))
        parent = replace(graph, attempts=(replace(graph.attempts[0], parent_attempt_id="missing-parent"), *graph.attempts[1:]))
        for invalid in (missing, wrong, duplicate, duplicate_event, out_of_order, parent):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ShadowV2Error):
                    self.lifecycle_case(invalid)

    def test_graph_rejects_parent_order_and_accepted_result_cross_links(self) -> None:
        graph = self.lifecycle_graph()
        self_parent = replace(graph, attempts=(replace(graph.attempts[0], parent_attempt_id="worker-1"), *graph.attempts[1:]))
        forward_parent = replace(graph, attempts=(replace(graph.attempts[0], parent_attempt_id="supervisor-1"), *graph.attempts[1:]))
        multi_node_cycle = replace(
            graph,
            attempts=(
                replace(graph.attempts[0], parent_attempt_id="supervisor-1"),
                replace(graph.attempts[1], parent_attempt_id="worker-1"),
                *graph.attempts[2:],
            ),
        )
        missing_result_round = replace(graph, events=(*graph.events[:4], replace(graph.events[4], review_round_id=None), *graph.events[5:]))
        event_result_round_mismatch = replace(graph, events=(*graph.events[:4], replace(graph.events[4], review_round_id="round-1"), *graph.events[5:]))
        attempt_result_round_mismatch = replace(graph, attempts=(*graph.attempts[:3], replace(graph.attempts[3], review_round_id="round-1")))
        result_round_mismatch = replace(graph, accepted_results=(replace(graph.accepted_results[0], review_round_id="round-1"),))
        review_result_cross_link = replace(graph, review_rounds=(graph.review_rounds[0], replace(graph.review_rounds[1], accepted_result_id=None)))
        # These are new immutable graph instances, so their enclosing case is
        # coherently re-digested before validation rather than reusing a prior case.
        for name, invalid in (
            ("self-parent", self_parent),
            ("forward-parent", forward_parent),
            ("multi-node-cycle", multi_node_cycle),
            ("missing-result-round", missing_result_round),
            ("event-result-round-mismatch", event_result_round_mismatch),
            ("attempt-result-round-mismatch", attempt_result_round_mismatch),
            ("result-round-mismatch", result_round_mismatch),
            ("review-result-cross-link", review_result_cross_link),
        ):
            with self.subTest(invalid=name):
                with self.assertRaises(ShadowV2Error):
                    self.lifecycle_case(invalid)

    def test_graph_core_supports_many_to_many_attempt_commit_cardinality(self) -> None:
        graph = self.lifecycle_graph()
        flexible = replace(self.lifecycle_profile(), minimum_commits=0, maximum_commits=3)
        no_commit_events = (*graph.events[:3], replace(graph.events[3], commit_sha=None), *graph.events[4:])
        no_commit = replace(graph, commits=(), events=no_commit_events, attempt_commit_references=())
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(no_commit, profile=flexible)).outcome, ComparisonOutcome.MATCH)

        second_commit = CandidateCommitReference("c" * 40, "follow-up-commit")
        one_attempt_many_commits = replace(
            graph,
            commits=(*graph.commits, second_commit),
            attempt_commit_references=(*graph.attempt_commit_references, AttemptCommitReference("worker-repair-2", second_commit.commit_sha)),
        )
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(one_attempt_many_commits, profile=flexible)).outcome, ComparisonOutcome.MATCH)

        many_attempts_one_commit = replace(
            graph,
            attempt_commit_references=(
                AttemptCommitReference("worker-1", "b" * 40),
                AttemptCommitReference("worker-repair-2", "b" * 40),
            ),
        )
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(many_attempts_one_commit)).outcome, ComparisonOutcome.MATCH)

    def test_graph_rejects_invalid_attempt_commit_relation_edges(self) -> None:
        graph = self.lifecycle_graph()
        edge = graph.attempt_commit_references[0]
        extra = CandidateCommitReference("c" * 40, "orphaned-commit")
        wrong_attempt = replace(graph, attempt_commit_references=(AttemptCommitReference("missing-attempt", edge.commit_sha),))
        missing_commit = replace(graph, attempt_commit_references=(AttemptCommitReference(edge.lifecycle_attempt_id, "c" * 40),))
        duplicate_edge = replace(graph, attempt_commit_references=(edge, edge))
        orphaned_commit = replace(graph, commits=(*graph.commits, extra))
        wrong_event_edge = replace(graph, events=(*graph.events[:3], replace(graph.events[3], commit_sha="c" * 40), *graph.events[4:]))
        for invalid in (wrong_attempt, missing_commit, duplicate_edge, orphaned_commit, wrong_event_edge):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ShadowV2Error):
                    self.lifecycle_case(invalid)

    def test_graph_rejects_missing_accepted_result_and_accepts_non_provider_events(self) -> None:
        graph = self.lifecycle_graph()
        missing = replace(graph, accepted_results=())
        with self.assertRaises(ShadowV2Error):
            self.lifecycle_case(missing)
        self.assertFalse(graph.events[-1].provider_call_made)
        self.assertIsNone(graph.events[-1].provider_attempt_id)

    def test_graph_core_can_represent_retry_failover_and_repair_attempt_kinds(self) -> None:
        graph = self.lifecycle_graph()
        for kind in (LifecycleAttemptKind.RETRY, LifecycleAttemptKind.FAILOVER):
            attempts = (*graph.attempts[:2], replace(graph.attempts[2], kind=kind), graph.attempts[3])
            with self.subTest(kind=kind):
                self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(replace(graph, attempts=attempts))).outcome, ComparisonOutcome.MATCH)


if __name__ == "__main__":
    unittest.main()
