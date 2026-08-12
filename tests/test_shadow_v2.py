"""Terminal-snapshot Shadow v2 provenance contracts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory

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
)
from roundwright.git_identity import GitEntrypointControl
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
    PROVENANCE_DECISION_PROFILE,
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
    VerifiedValidationToolchainProjection,
    NamedContentIdentity,
    AcceptedResultReference,
    compare_provenance_decision,
    export_provenance_decision,
    reconcile_final_provenance_selection,
    verify_selection_for_durable_record,
    _materialize_provenance_record,
    replay_shadow_case,
    replay_shadow_v2_case,
    require_capture_readiness,
    shadow_evidence_profile,
    shadow_evidence_profiles,
)


def digest(value: str) -> str:
    return "sha256:" + value * 64


class ShadowV2Tests(unittest.TestCase):
    def external_control_bytes(self):
        payload = {
            "schema": "roundwright-provenance-selection-control/v1", "control_mode": "REHEARSAL", "capture_ready": False,
            "roundlet": {"run_id": "run-47", "contract_id": "contract-47", "orchestrator_task": "orchestrator-47"},
            "selection": {"repository": "ythdelmar68/roundwright", "worker_task": "task-47", "base_sha": "a" * 40, "candidate_sha": "b" * 40, "candidate_tree": "c" * 40, "active_leaf": 47, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1"},
            "authority": {"origin_main": {"commit": "a" * 40, "tree": "1" * 40}, "active_roundlet_block": {"agents_blob": "d" * 40, "block_sha256": digest("2")}, "external_validation_contract": {"skill_blob": "e" * 40, "qualification_blob": "f" * 40}, "live_leaf": {"issue_database_id": 1, "issue_node_id": "node-47", "number": 47, "updated_at": "now", "body_sha256": digest("3")}, "owner_instructions": [{"comment_id": 2, "comment_node_id": "node-2", "body_sha256": digest("4")}, {"comment_id": 3, "comment_node_id": "node-3", "body_sha256": digest("5")}]},
        }
        content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        receipt = {"schema": "roundwright-provenance-selection-control-receipt/v1", "append_only": True, "capture_ready": False, "contract_sha256": digest("1"), "control_mode": "REHEARSAL", "payload_bytes": len(content), "payload_sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "read_back": "VERIFIED", "retention_identity": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/rehearsal-" + "b" * 40}
        receipt_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
        expected = ExternalSelectionControlExpectation("run-47", "contract-47", "orchestrator-47", "ythdelmar68/roundwright", "task-47", "a" * 40, "b" * 40, "c" * 40, 47, "toolbox", "roundwright-shadow-case/v2", "roundwright-shadow-profile/provenance-decision/v1", "d" * 40, "e" * 40, "f" * 40, "sha256:" + hashlib.sha256(content).hexdigest(), "sha256:" + hashlib.sha256(receipt_bytes).hexdigest(), digest("1"), "1" * 40, digest("2"), (1, "node-47", 47, "now", digest("3")), ((2, "node-2", digest("4")), (3, "node-3", digest("5"))))
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
        self, mutate=None, *, leaf=47, source_class="bundled-native-git", reported_version="2.53.0.windows.3",
    ):
        dependency = self.dependency_control()
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
        value["artifacts"] = {"candidate_source": {"source_identity": artifacts.source_identity, "digest": artifacts.source_digest}, "candidate_package": artifacts.package_digest, "installed_roundwright_entrypoint": artifacts.installed_entrypoint_digest, "reviewed_git_entrypoint": {"binding_fingerprint": git.binding_fingerprint, "identifier": git.identifier, "source_identity": git.source_identity, "source_class": git.source_class, "normalized_version": git.normalized_version, "reported_version": git.reported_version, "artifact_digest": git.artifact_digest, "executable_digest": git.executable_digest, "control_fingerprint": git.control_fingerprint}}
        value["dependency_control"] = {"binding_fingerprint": binding.fingerprint, "policy_fingerprint": dependency.policy.core_fingerprint, "observations": [{"component": item.component.value, "fingerprint": item.fingerprint} for item in sorted(dependency.observations, key=lambda item: item.component.value)], "admission": {"policy_fingerprint": dependency.admission.policy_fingerprint, "receipt_digest": dependency.admission.receipt_digest, "reviewer_identity": dependency.admission.reviewer_identity, "authority_digest": dependency.admission.authority_digest}}
        value["public_safe_projection"] = {"repository": binding.repository, "task_id": binding.task_id, "base_sha": "a" * 40, "candidate_sha": binding.candidate_sha, "candidate_tree": "c" * 40, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1", "capture_mode": "terminal-snapshot", "gate": "recorder-capture-readiness", "blocker": None, "next_action": "record-terminal-snapshot", "candidate_fingerprint": candidate_fingerprint, "validation_fingerprint": validation.projection_fingerprint, "dependency_fingerprint": dependency_fingerprint, "git_fingerprint": git.observation_fingerprint}
        if mutate is not None:
            mutate(value)
        value["authority"]["live_leaf"]["number"] = leaf
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        receipt_value = json.loads(receipt)
        receipt_value.update({"control_mode": "FINAL", "capture_ready": True, "retention_identity": "roundlet-local:ab8aea71a95647bdbe1e00e9d915d557/final-" + binding.candidate_sha, "payload_bytes": len(payload), "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest()})
        receipt = json.dumps(receipt_value, sort_keys=True, separators=(",", ":")).encode()
        expected = replace(expected, leaf=leaf, live_leaf=(1, "node-47", leaf, "now", digest("3")), payload_digest="sha256:" + hashlib.sha256(payload).hexdigest(), receipt_digest="sha256:" + hashlib.sha256(receipt).hexdigest())
        return ExternalSelectionControl.load(payload, receipt, expected), validation, artifacts, git_control, git, dependency

    def test_final_reconciliation_derives_all_fingerprints_from_verified_inputs(self) -> None:
        control, validation, artifacts, git_control, git, dependency = self.final_reconciliation_fixture()
        selection = reconcile_final_provenance_selection(control, validation=validation, artifacts=artifacts, git_control=git_control, git_observation=git, dependency_control=dependency, now=101)
        self.assertEqual(selection.payload_digest, control.payload_digest)
        self.assertEqual(selection.receipt_digest, control.receipt_digest)
        self.assertEqual(selection.contract_digest, control.contract_digest)
        self.assertEqual(selection.validation_fingerprint, validation.projection_fingerprint)
        self.assertEqual(selection.git_fingerprint, git.observation_fingerprint)
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
        for invalid in (
            lambda: (self.final_reconciliation_fixture(lambda value: value.update(control_contract_digest=digest("9")))[0], arguments),
            lambda: (control, {**arguments, "git_observation": replace(git, executable_digest=digest("9"), observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, source_class="other-git", observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, normalized_version="2.53.1", observation_fingerprint="")}),
            lambda: (control, {**arguments, "git_observation": replace(git, reported_version="2.53.0.windows.4", observation_fingerprint="")}),
            lambda: (control, {**arguments, "artifacts": replace(artifacts, package_digest=digest("9"), projection_fingerprint="")}),
            lambda: (self.final_reconciliation_fixture(lambda value: value["selection"].update(gate="another-gate"))[0], arguments),
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

    def test_external_control_rejects_duplicate_and_nonfinite_json(self) -> None:
        payload, receipt, expected = self.external_control_bytes()
        duplicate = payload.removesuffix(b"}") + b',"schema":"shadow"}'
        for invalid_payload, invalid_receipt in ((duplicate, receipt), (b'{"value":NaN}', receipt), (payload, b'{"value":Infinity}')):
            with self.subTest():
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(invalid_payload, invalid_receipt, expected)

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
        return export_provenance_decision(self.record(candidate=candidate, ready_at=ready_at))

    def case(self, *, candidate: str = "b" * 40, ready_at: int = 101) -> ShadowV2Case:
        decision = self.decision(candidate=candidate, ready_at=ready_at)
        readiness = require_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            self.record(candidate=candidate, ready_at=ready_at),
            RecorderBinding(
                "10265c35c9d01d1fd26bd767ca3c1b245e4e9c52",
                "87094a4e780c692a00135421840c0e6713af5d35",
                "0c594caa275262164fce1942ebd2142abe0e77bb",
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
        self.assertEqual(shadow_evidence_profiles(), (profile,))
        self.assertEqual(profile.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(profile.event_kinds, ("provenance-decision",))
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
            require_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), self.record(),
                RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
                AppendOnlyEvidenceStore("roundlet-provenance-retention"),
                candidate_sha="c" * 40, ready_at=101,
            )

    def test_terminal_export_requires_durable_record_and_store_readback_rejects_tampering(self) -> None:
        record = self.record()
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(record.decision)
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
        readiness = require_capture_readiness(
            profile, decision,
            RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
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
