from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright import external_validation
from roundwright.shadow import (
    AcceptedResultReference,
    AttemptCommitReference,
    CandidateCommitReference,
    EvidenceRole,
    EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
    FormalReviewRoundReference,
    LifecycleAttempt,
    LifecycleAttemptKind,
    PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
    ProviderAttemptManifest,
    ShadowV2Event,
    ShadowV2EventGraph,
)


@dataclass(frozen=True)
class ProfileComponentIdentities:
    producer_identity: str
    exporter_identity: str
    comparator_identity: str


@dataclass(frozen=True)
class ProfileExecution:
    value: object
    mutation_count: int = 0


@dataclass(frozen=True)
class ProfileComparison:
    status: str
    result_identity: str


def fake_harness() -> tuple[object | None, object | None]:
    prior_package = sys.modules.get("roundwright_harness")
    prior_module = sys.modules.get("roundwright_harness.executor")
    package = ModuleType("roundwright_harness")
    package.__path__ = []  # type: ignore[attr-defined]
    module = ModuleType("roundwright_harness.executor")
    module.ProfileComponentIdentities = ProfileComponentIdentities  # type: ignore[attr-defined]
    module.ProfileExecution = ProfileExecution  # type: ignore[attr-defined]
    module.ProfileComparison = ProfileComparison  # type: ignore[attr-defined]
    sys.modules["roundwright_harness"] = package
    sys.modules["roundwright_harness.executor"] = module
    return prior_package, prior_module


def binding(**updates: object) -> SimpleNamespace:
    producer, exporter, comparator = external_validation.synthetic_component_identities()
    values: dict[str, object] = {
        "profile": EXECUTOR_CONTRACT_SYNTHETIC_PROFILE,
        "case_id": "contract-synthetic",
        "candidate_sha": "a" * 40,
        "ready_at": 17,
        "plan": SimpleNamespace(plan_digest="sha256:" + "1" * 64),
        "components": SimpleNamespace(
            producer_identity=producer,
            exporter_identity=exporter,
            comparator_identity=comparator,
        ),
    }
    values.update(updates)
    return SimpleNamespace(**values)


def provider_binding(**updates: object) -> SimpleNamespace:
    producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
    values: dict[str, object] = {
        "profile": PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
        "case_id": "provider-attempt-case",
        "candidate_sha": "a" * 40,
        "ready_at": 17,
        "plan": SimpleNamespace(plan_digest="sha256:" + "3" * 64),
        "components": SimpleNamespace(
            producer_identity=producer,
            exporter_identity=exporter,
            comparator_identity=comparator,
        ),
    }
    values.update(updates)
    return SimpleNamespace(**values)


class ExternalValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._prior_package, self._prior_module = fake_harness()

    def tearDown(self) -> None:
        for name, value in (
            ("roundwright_harness", self._prior_package),
            ("roundwright_harness.executor", self._prior_module),
        ):
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    def test_public_factory_exposes_stable_typed_components(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            EXECUTOR_CONTRACT_SYNTHETIC_PROFILE
        )

        self.assertEqual(
            adapter.component_identities,
            ProfileComponentIdentities(*external_validation.synthetic_component_identities()),
        )
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            external_validation.roundwright_profile_adapter_factory(
                "roundwright-shadow-profile/unknown/v1"
            )

    def test_synthetic_adapter_executes_projects_and_compares_at_capture_time(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        exact = binding(ready_at=7)
        adapter.validate(exact)

        execution = adapter.execute(exact)
        evidence = adapter.project(exact, execution)
        comparison = adapter.compare(exact, evidence)

        self.assertEqual(execution.mutation_count, 0)
        self.assertEqual(evidence["ready_at"], 7)
        self.assertEqual(evidence["executor_contract"]["mutation_count"], 0)
        self.assertEqual(comparison.status, "pass")
        self.assertTrue(comparison.result_identity.startswith("sha256:"))

    def test_adapter_rejects_binding_or_component_drift_before_execution(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        wrong_components = SimpleNamespace(
            producer_identity="sha256:" + "2" * 64,
            exporter_identity=external_validation.SYNTHETIC_EXPORTER_IDENTITY,
            comparator_identity=external_validation.SYNTHETIC_COMPARATOR_IDENTITY,
        )

        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(binding(components=wrong_components))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(binding(candidate_sha="main"))

    def test_comparator_returns_typed_failure_without_exposing_payload(self) -> None:
        adapter = external_validation.SyntheticExecutorAdapter()
        exact = binding()
        evidence = dict(adapter.project(exact, adapter.execute(exact)))
        evidence["ready_at"] = 18

        comparison = adapter.compare(exact, evidence)

        self.assertEqual(comparison.status, "fail")
        self.assertTrue(comparison.result_identity.startswith("sha256:"))

    def test_provider_attempt_profile_is_armed_without_inventing_history(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        adapter.validate(exact)

        evidence = adapter.project(exact, adapter.execute(exact))
        comparison = adapter.compare(exact, evidence)

        accounting = evidence["provider_attempt_accounting"]
        self.assertEqual(
            adapter.component_identities,
            ProfileComponentIdentities(*external_validation.provider_attempt_accounting_component_identities()),
        )
        self.assertEqual(accounting["capture_mode"], "armed-live-events")
        self.assertEqual(accounting["history"], "missing-recapture-required")
        self.assertIsNone(accounting["snapshot"])
        self.assertEqual(accounting["mutation_count"], 0)
        self.assertEqual(comparison.status, "pass")

    def test_provider_attempt_profile_binds_v2_graph_and_rejects_context_drift(self) -> None:
        candidate = "a" * 40
        graph = ShadowV2EventGraph(
            (
                LifecycleAttempt("worker-1", 1, LifecycleAttemptKind.WORKER, EvidenceRole.WORKER),
                LifecycleAttempt("supervisor-1", 2, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-1", "round-1"),
            ),
            (
                ProviderAttemptManifest("provider-invalid-1", "worker-1", 1, "codex-primary", "invalid"),
                ProviderAttemptManifest("provider-retry-2", "worker-1", 2, "codex-primary", "completed"),
            ),
            (FormalReviewRoundReference("round-1", 1, candidate, "accepted-1"),),
            (CandidateCommitReference(candidate, "worker-commit"),),
            (AcceptedResultReference("accepted-1", "round-1", "event-4", candidate),),
            (
                ShadowV2Event("event-1", 1, "worker-1", "provider-attempt", "provider-invalid-1", True),
                ShadowV2Event("event-2", 2, "worker-1", "invalid-output", None, False),
                ShadowV2Event("event-3", 3, "worker-1", "recovery-attempt", "provider-retry-2", True),
                ShadowV2Event("event-4", 4, "supervisor-1", "formal-review-accepted", None, False, "round-1", None, "accepted-1"),
            ),
            (AttemptCommitReference("worker-1", candidate),),
        )
        snapshot = external_validation.ProviderAttemptAccountingSnapshot(
            "task-45", "b" * 40, candidate, "sha256:" + "3" * 64, 17, 1, 1, "COMPLETE", 3, 10, 3,
            "sha256:" + "4" * 64, "diff-review", None, "candidate-gates", True, graph,
        )
        adapter = external_validation.ProviderAttemptAccountingAdapter()
        exact = provider_binding(provider_attempt_accounting=snapshot)
        adapter.validate(exact)
        evidence = adapter.project(exact, adapter.execute(exact))
        accounting = evidence["provider_attempt_accounting"]
        self.assertEqual(accounting["history"], "complete")
        self.assertEqual(accounting["snapshot"]["review_mode"], "COMPLETE")
        self.assertEqual(len(accounting["snapshot"]["event_graph"]["provider_attempts"]), 2)
        self.assertEqual(adapter.compare(exact, evidence).status, "pass")
        self.assertEqual(adapter.compare(exact, {**evidence, "ready_at": 18}).status, "fail")
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(candidate_sha="c" * 40, provider_attempt_accounting=snapshot))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(ready_at=True))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(plan=SimpleNamespace(plan_digest="sha256:" + "f" * 64), provider_attempt_accounting=snapshot))
