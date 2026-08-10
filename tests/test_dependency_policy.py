"""Contract coverage for Phase 3 dependency and entrypoint trust gates."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

# Keep this contract test independently runnable from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.dependency_policy import (
    ComponentPolicy,
    DependencyComponent,
    DependencyDecisionOutcome,
    DependencyPolicy,
    DependencyPolicyError,
    DependencyStage,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    StageRequirement,
    VersionRange,
    evaluate_dependency_preflight,
    execute_after_dependency_preflight,
    render_dependency_decision,
    verify_policy_transition,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class DependencyPolicyTests(unittest.TestCase):
    def policy(self, *, revision: str = "a", transition: PolicyTransition | None = None, provider_minimum: str = "1.2.0") -> DependencyPolicy:
        return DependencyPolicy(
            digest(revision), 30,
            (
                ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("b"), digest("1")),
                ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME, "codex-sdk", VersionRange(provider_minimum, "2.0.0"), "registry/codex-sdk", digest("c"), digest("2")),
                ComponentPolicy(DependencyComponent.GITHUB_CLI, "gh", VersionRange("2.0.0", "3.0.0"), "github/gh", digest("d"), digest("3")),
                ComponentPolicy(DependencyComponent.BUILD_BACKEND, "setuptools", VersionRange("69.0.0", "70.0.0"), "pypi/setuptools", digest("e"), digest("4")),
                ComponentPolicy(DependencyComponent.OPTIONAL_ADAPTER, "jira-adapter", VersionRange("1.0.0", "2.0.0"), "pypi/jira-adapter", digest("f"), digest("5")),
            ),
            transition or PolicyTransition(PolicyTransitionKind.INITIAL, None, None),
        )

    def observation(self, policy: DependencyPolicy, component: DependencyComponent, *, version: str | None = None, observed_at: int = 100, policy_digest: str | None = None, artifact: str | None = None, executable: str | None = None) -> ObservedDependency:
        expected = policy.component(component)
        assert expected is not None
        return ObservedDependency(component, expected.identifier, version or expected.versions.minimum, expected.source_identity, artifact or expected.artifact_digest, executable or expected.executable_digest, observed_at, policy_digest or policy.policy_digest)

    def requirement(self, *components: DependencyComponent, stage: DependencyStage = DependencyStage.DISPATCH) -> StageRequirement:
        return StageRequirement(stage, components)

    def test_current_exact_observations_authorize_dispatch(self) -> None:
        policy = self.policy()
        required = self.requirement(DependencyComponent.PACKAGE, DependencyComponent.PROVIDER_RUNTIME, DependencyComponent.GITHUB_CLI)
        decision = evaluate_dependency_preflight(policy, tuple(self.observation(policy, item) for item in required.components), required, now=120)
        self.assertEqual(decision.outcome, DependencyDecisionOutcome.PASS)
        self.assertEqual(len(decision.observation_fingerprints), 3)

    def test_missing_policy_or_provenance_fails_closed(self) -> None:
        required = self.requirement(DependencyComponent.PACKAGE)
        self.assertEqual(evaluate_dependency_preflight(None, (), required, now=100).outcome, DependencyDecisionOutcome.BLOCKED)
        self.assertEqual(evaluate_dependency_preflight(self.policy(), None, required, now=100).outcome, DependencyDecisionOutcome.BLOCKED)

    def test_identity_checksum_policy_and_freshness_drift_block(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.PACKAGE)
        cases = (
            self.observation(policy, DependencyComponent.PACKAGE, artifact=digest("0")),
            self.observation(policy, DependencyComponent.PACKAGE, policy_digest=digest("0")),
            self.observation(policy, DependencyComponent.PACKAGE, observed_at=69),
            self.observation(policy, DependencyComponent.PACKAGE, observed_at=101),
        )
        for observation in cases:
            with self.subTest(observation=observation.observed_at):
                self.assertEqual(evaluate_dependency_preflight(policy, (observation,), required, now=100).outcome, DependencyDecisionOutcome.BLOCKED)

    def test_unsupported_future_version_blocks(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.PROVIDER_RUNTIME)
        decision = evaluate_dependency_preflight(policy, (self.observation(policy, DependencyComponent.PROVIDER_RUNTIME, version="2.0.0"),), required, now=100)
        self.assertEqual((decision.outcome, decision.reason), (DependencyDecisionOutcome.BLOCKED, "dependency version is unsupported"))

    def test_changed_executable_digest_blocks_even_when_all_other_identity_is_current(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.GITHUB_CLI)
        changed = self.observation(policy, DependencyComponent.GITHUB_CLI, executable=digest("0"))
        decision = evaluate_dependency_preflight(policy, (changed,), required, now=100)
        self.assertEqual((decision.outcome, decision.reason), (DependencyDecisionOutcome.BLOCKED, "dependency executable identity does not match policy"))

    def test_duplicate_component_records_fail_closed(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.PACKAGE)
        record = self.observation(policy, DependencyComponent.PACKAGE)
        self.assertEqual(evaluate_dependency_preflight(policy, (record, record), required, now=100).outcome, DependencyDecisionOutcome.BLOCKED)

    def test_optional_adapter_only_blocks_its_own_stage(self) -> None:
        policy = self.policy()
        dispatch = self.requirement(DependencyComponent.PACKAGE)
        optional = self.requirement(DependencyComponent.OPTIONAL_ADAPTER, stage=DependencyStage.OPTIONAL_ADAPTER)
        package = self.observation(policy, DependencyComponent.PACKAGE)
        self.assertEqual(evaluate_dependency_preflight(policy, (package,), dispatch, now=100).outcome, DependencyDecisionOutcome.PASS)
        self.assertEqual(evaluate_dependency_preflight(policy, (package,), optional, now=100).outcome, DependencyDecisionOutcome.BLOCKED)

    def test_action_is_never_called_before_failed_preflight(self) -> None:
        calls: list[bool] = []
        with self.assertRaises(DependencyPolicyError):
            execute_after_dependency_preflight(self.policy(), (), self.requirement(DependencyComponent.GITHUB_CLI, stage=DependencyStage.GITHUB_MUTATION), now=100, action=lambda: calls.append(True))
        self.assertEqual(calls, [])

    def test_action_runs_after_exact_preflight(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.GITHUB_CLI, stage=DependencyStage.GITHUB_MUTATION)
        self.assertEqual(execute_after_dependency_preflight(policy, (self.observation(policy, DependencyComponent.GITHUB_CLI),), required, now=100, action=lambda: "ran"), "ran")

    def test_fingerprints_are_path_independent_and_diagnostics_are_owner_safe(self) -> None:
        policy = self.policy(); required = self.requirement(DependencyComponent.PACKAGE)
        observation = self.observation(policy, DependencyComponent.PACKAGE)
        decision = evaluate_dependency_preflight(policy, (observation,), required, now=100)
        self.assertTrue(observation.fingerprint.startswith("sha256:"))
        rendered = render_dependency_decision(decision)
        self.assertNotIn("C:\\", rendered)
        self.assertNotIn("command", rendered)

    def test_copilot_is_neither_a_policy_component_nor_runtime_probe(self) -> None:
        with self.assertRaises(DependencyPolicyError):
            ComponentPolicy(DependencyComponent.OPTIONAL_ADAPTER, "copilot-sdk", VersionRange("1.0.0", "2.0.0"), "registry/copilot", digest("a"), digest("b"))

    def test_reviewed_upgrade_and_rollback_are_independent(self) -> None:
        previous = self.policy(revision="a", provider_minimum="1.2.0")
        upgrade = self.policy(revision="b", provider_minimum="1.3.0", transition=PolicyTransition(PolicyTransitionKind.UPGRADE, previous.policy_digest, digest("1")))
        rollback = self.policy(revision="c", provider_minimum="1.1.0", transition=PolicyTransition(PolicyTransitionKind.ROLLBACK, previous.policy_digest, digest("2")))
        self.assertTrue(verify_policy_transition(previous, upgrade))
        self.assertTrue(verify_policy_transition(previous, rollback))
        wrong_kind = self.policy(revision="d", provider_minimum="1.1.0", transition=PolicyTransition(PolicyTransitionKind.UPGRADE, previous.policy_digest, digest("3")))
        self.assertFalse(verify_policy_transition(previous, wrong_kind))


if __name__ == "__main__":
    unittest.main()
