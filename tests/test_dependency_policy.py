"""Contract coverage for Phase 3 candidate-bound dependency trust gates."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.dependency_policy import (
    CandidateBinding,
    BootstrapPolicyReceipt,
    ComponentPolicy,
    DependencyComponent,
    DependencyDecisionCode,
    DependencyDecisionOutcome,
    DependencyPolicy,
    DependencyPolicyError,
    DependencyStage,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    PolicyTransitionReview,
    TrustedDependencyAuthority,
    VersionRange,
    canonical_stage_requirements,
    evaluate_dependency_preflight,
    execute_after_dependency_preflight,
    render_dependency_decision,
    verify_policy_admission,
    verify_policy_transition,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class DependencyPolicyTests(unittest.TestCase):
    def binding(self, candidate: str = "a") -> CandidateBinding:
        return CandidateBinding("ythdelmar68/roundwright", "issue-47", candidate * 40)

    def policy(self, *, binding: CandidateBinding | None = None, revision: str = "a", provider_minimum: str = "1.2.0", transition: PolicyTransition | None = None) -> DependencyPolicy:
        policy = DependencyPolicy(
            binding or self.binding(), digest(revision), 100, 30,
            (
                ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("b"), digest("1")),
                ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME, "codex-sdk", VersionRange(provider_minimum, "2.0.0"), "registry/codex-sdk", digest("c"), digest("2")),
                ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", digest("d"), digest("3")),
                ComponentPolicy(DependencyComponent.BUILD_BACKEND, "setuptools", VersionRange("69.0.0", "70.0.0"), "pypi/setuptools", digest("e"), digest("4")),
                ComponentPolicy(DependencyComponent.OPTIONAL_ADAPTER, "jira-adapter", VersionRange("1.0.0", "2.0.0"), "pypi/jira-adapter", digest("f"), digest("5")),
            ),
            transition or PolicyTransition(PolicyTransitionKind.BOOTSTRAP),
        )
        if transition is not None:
            return policy
        return replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("a"), authority_digest=digest("b"))))

    def observation(self, policy: DependencyPolicy, component: DependencyComponent, *, binding: CandidateBinding | None = None, version: str | None = None, observed_at: int = 100, policy_digest: str | None = None, artifact: str | None = None, executable: str | None = None) -> ObservedDependency:
        expected = policy.component(component); assert expected is not None
        return ObservedDependency(binding or policy.binding, component, expected.identifier, version or expected.versions.minimum, expected.source_identity, artifact or expected.artifact_digest, executable or expected.executable_digest, observed_at, policy_digest or policy.policy_digest)

    def records_for(self, policy: DependencyPolicy, stage: DependencyStage) -> tuple[ObservedDependency, ...]:
        return tuple(self.observation(policy, component) for component in canonical_stage_requirements(stage))

    def authority(self, policy: DependencyPolicy, *, reviewer: str = "a", authority: str = "b") -> TrustedDependencyAuthority:
        return TrustedDependencyAuthority(policy.binding, digest(reviewer), digest(authority))

    def test_dispatch_uses_all_four_non_optional_components(self) -> None:
        self.assertEqual(canonical_stage_requirements(DependencyStage.DISPATCH), (DependencyComponent.PACKAGE, DependencyComponent.PROVIDER_RUNTIME, DependencyComponent.GITHUB_CLI, DependencyComponent.BUILD_BACKEND))
        policy = self.policy()
        decision = evaluate_dependency_preflight(policy.binding, policy, self.records_for(policy, DependencyStage.DISPATCH), DependencyStage.DISPATCH, now=120, trusted_authority=self.authority(policy))
        self.assertEqual((decision.outcome, decision.code, len(decision.observation_fingerprints)), (DependencyDecisionOutcome.PASS, DependencyDecisionCode.AUTHORIZED, 4))

    def test_canonical_helper_cannot_omit_required_checks(self) -> None:
        policy = self.policy(); calls: list[bool] = []
        with self.assertRaises(DependencyPolicyError):
            execute_after_dependency_preflight(policy.binding, policy, (self.observation(policy, DependencyComponent.GITHUB_CLI),), DependencyStage.DISPATCH, now=100, action=lambda: calls.append(True), trusted_authority=self.authority(policy))
        self.assertEqual(calls, [])

    def test_each_helper_stage_has_closed_relevant_requirements(self) -> None:
        expected = {
            DependencyStage.GITHUB_MUTATION: (DependencyComponent.PACKAGE, DependencyComponent.GITHUB_CLI),
            DependencyStage.PACKAGE_BUILD: (DependencyComponent.PACKAGE, DependencyComponent.BUILD_BACKEND),
            DependencyStage.PROVIDER_QUALIFICATION: (DependencyComponent.PACKAGE, DependencyComponent.PROVIDER_RUNTIME),
            DependencyStage.OPTIONAL_ADAPTER: (DependencyComponent.PACKAGE, DependencyComponent.OPTIONAL_ADAPTER),
        }
        self.assertEqual({stage: canonical_stage_requirements(stage) for stage in expected}, expected)

    def test_policy_observation_and_decision_are_candidate_bound(self) -> None:
        policy = self.policy(); other = self.binding("b")
        decision = evaluate_dependency_preflight(other, policy, self.records_for(policy, DependencyStage.PACKAGE_BUILD), DependencyStage.PACKAGE_BUILD, now=100, trusted_authority=self.authority(policy))
        self.assertEqual((decision.outcome, decision.code), (DependencyDecisionOutcome.BLOCKED, DependencyDecisionCode.CANDIDATE_MISMATCH))
        wrong_observation = self.observation(policy, DependencyComponent.PACKAGE, binding=other)
        decision = evaluate_dependency_preflight(policy.binding, policy, (wrong_observation, self.observation(policy, DependencyComponent.BUILD_BACKEND)), DependencyStage.PACKAGE_BUILD, now=100, trusted_authority=self.authority(policy))
        self.assertEqual(decision.code, DependencyDecisionCode.CANDIDATE_MISMATCH)

    def test_policy_and_observation_freshness_fail_closed(self) -> None:
        policy = self.policy(); stage = DependencyStage.PACKAGE_BUILD
        stale_policy = replace(policy, issued_at=69)
        self.assertEqual(evaluate_dependency_preflight(policy.binding, stale_policy, self.records_for(stale_policy, stage), stage, now=100, trusted_authority=self.authority(stale_policy)).code, DependencyDecisionCode.POLICY_STALE)
        records = (self.observation(policy, DependencyComponent.PACKAGE, observed_at=69), self.observation(policy, DependencyComponent.BUILD_BACKEND))
        self.assertEqual(evaluate_dependency_preflight(policy.binding, policy, records, stage, now=100, trusted_authority=self.authority(policy)).code, DependencyDecisionCode.PROVENANCE_STALE)

    def test_identity_version_and_executable_drift_have_closed_codes(self) -> None:
        policy = self.policy(); stage = DependencyStage.GITHUB_MUTATION
        cases = (
            (self.observation(policy, DependencyComponent.PACKAGE, artifact=digest("0")), DependencyDecisionCode.IDENTITY_MISMATCH),
            (self.observation(policy, DependencyComponent.GITHUB_CLI, executable=digest("0")), DependencyDecisionCode.EXECUTABLE_MISMATCH),
            (self.observation(policy, DependencyComponent.GITHUB_CLI, version="3.0.0"), DependencyDecisionCode.VERSION_UNSUPPORTED),
        )
        for changed, code in cases:
            records = [self.observation(policy, item) for item in canonical_stage_requirements(stage)]
            records[[item.component for item in records].index(changed.component)] = changed
            with self.subTest(code=code):
                self.assertEqual(evaluate_dependency_preflight(policy.binding, policy, tuple(records), stage, now=100, trusted_authority=self.authority(policy)).code, code)

    def test_transition_review_binds_complete_delta_and_authority(self) -> None:
        previous = self.policy(revision="a", provider_minimum="1.2.0")
        draft = self.policy(revision="b", provider_minimum="1.3.0")
        review = PolicyTransitionReview.create(previous, draft, reviewer_identity=digest("6"), authority_digest=digest("7"))
        upgraded = replace(draft, transition=PolicyTransition(PolicyTransitionKind.UPGRADE, review))
        self.assertTrue(verify_policy_transition(previous, upgraded))
        changed_component = replace(upgraded.components[2], executable_digest=digest("0"))
        tampered = replace(upgraded, components=(*upgraded.components[:2], changed_component, *upgraded.components[3:]))
        self.assertFalse(verify_policy_transition(previous, tampered))
        self.assertFalse(verify_policy_transition(previous, replace(upgraded, transition=PolicyTransition(PolicyTransitionKind.ROLLBACK, review))))

    def test_transition_review_rejects_arbitrary_or_incomplete_digest(self) -> None:
        previous = self.policy(); draft = self.policy(revision="b", provider_minimum="1.3.0")
        review = PolicyTransitionReview.create(previous, draft, reviewer_identity=digest("6"), authority_digest=digest("7"))
        with self.assertRaises(DependencyPolicyError):
            replace(review, review_digest=digest("0"))
        with self.assertRaises(DependencyPolicyError):
            PolicyTransition(PolicyTransitionKind.UPGRADE)

    def test_trusted_authority_identity_is_required_for_bootstrap_and_every_stage(self) -> None:
        policy = self.policy()
        calls: list[bool] = []
        self.assertFalse(verify_policy_admission(policy, None))
        self.assertFalse(verify_policy_admission(policy, None, self.authority(policy, reviewer="0")))
        for stage in DependencyStage:
            with self.subTest(stage=stage):
                decision = evaluate_dependency_preflight(policy.binding, policy, self.records_for(policy, stage), stage, now=100, trusted_authority=self.authority(policy, reviewer="0"))
                self.assertEqual(decision.code, DependencyDecisionCode.POLICY_TRANSITION_INVALID)
                with self.assertRaises(DependencyPolicyError):
                    execute_after_dependency_preflight(policy.binding, policy, self.records_for(policy, stage), stage, now=100, action=lambda: calls.append(True), trusted_authority=self.authority(policy, authority="0"))
        self.assertEqual(calls, [])

    def test_trusted_authority_identity_is_required_for_policy_changes(self) -> None:
        previous = self.policy(revision="a", provider_minimum="1.2.0")
        draft = self.policy(revision="b", provider_minimum="1.3.0")
        review = PolicyTransitionReview.create(previous, draft, reviewer_identity=digest("6"), authority_digest=digest("7"))
        upgraded = replace(draft, transition=PolicyTransition(PolicyTransitionKind.UPGRADE, review))
        records = self.records_for(upgraded, DependencyStage.PACKAGE_BUILD)
        self.assertEqual(
            evaluate_dependency_preflight(upgraded.binding, upgraded, records, DependencyStage.PACKAGE_BUILD, now=100, previous_policy=previous, trusted_authority=self.authority(upgraded, reviewer="6", authority="7")).code,
            DependencyDecisionCode.AUTHORIZED,
        )
        self.assertEqual(
            evaluate_dependency_preflight(upgraded.binding, upgraded, records, DependencyStage.PACKAGE_BUILD, now=100, previous_policy=previous, trusted_authority=self.authority(upgraded, reviewer="6", authority="0")).code,
            DependencyDecisionCode.POLICY_TRANSITION_INVALID,
        )

    def test_diagnostics_cannot_render_attacker_supplied_reason_text(self) -> None:
        policy = self.policy(); decision = evaluate_dependency_preflight(policy.binding, policy, (), DependencyStage.GITHUB_MUTATION, now=100, trusted_authority=self.authority(policy))
        rendered = render_dependency_decision(decision)
        self.assertEqual(decision.code, DependencyDecisionCode.PROVENANCE_MISSING)
        self.assertNotIn("C:\\private", rendered)
        self.assertNotIn("gh --token", rendered)
        self.assertNotIn("secret-token", rendered)
        self.assertIn("code=provenance-missing", rendered)

    def test_copilot_and_invalid_context_are_rejected_without_private_echo(self) -> None:
        with self.assertRaises(DependencyPolicyError):
            ComponentPolicy(DependencyComponent.OPTIONAL_ADAPTER, "copilot-sdk", VersionRange("1.0.0", "2.0.0"), "registry/copilot", digest("a"), digest("b"))
        decision = evaluate_dependency_preflight(None, None, None, None, now=-1)  # type: ignore[arg-type]
        self.assertEqual(decision.code, DependencyDecisionCode.INVALID_CONTEXT)
        self.assertNotIn("private", render_dependency_decision(decision))


if __name__ == "__main__":
    unittest.main()
