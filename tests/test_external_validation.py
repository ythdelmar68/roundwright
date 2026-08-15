from __future__ import annotations

import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright import external_validation
from roundwright.shadow import EXECUTOR_CONTRACT_SYNTHETIC_PROFILE, PROVIDER_ATTEMPT_ACCOUNTING_PROFILE


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


@dataclass(frozen=True)
class CapturePlanReceipt:
    plan_digest: str
    profile: str
    case_id: str
    candidate_sha: str
    ready_at: int


@dataclass(frozen=True)
class ExecutorBinding:
    """The public reviewed Harness binding shape, without candidate extensions."""

    plan: CapturePlanReceipt
    components: ProfileComponentIdentities

    @property
    def profile(self) -> str:
        return self.plan.profile

    @property
    def case_id(self) -> str:
        return self.plan.case_id

    @property
    def candidate_sha(self) -> str:
        return self.plan.candidate_sha

    @property
    def ready_at(self) -> int:
        return self.plan.ready_at


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


def provider_binding(**updates: object) -> ExecutorBinding:
    producer, exporter, comparator = external_validation.provider_attempt_accounting_component_identities()
    values: dict[str, object] = {
        "profile": PROVIDER_ATTEMPT_ACCOUNTING_PROFILE,
        "case_id": "provider-attempt-case",
        "candidate_sha": "a" * 40,
        "ready_at": 17,
        "plan_digest": "sha256:" + "3" * 64,
        "components": ProfileComponentIdentities(
            producer_identity=producer,
            exporter_identity=exporter,
            comparator_identity=comparator,
        ),
    }
    values.update(updates)
    return ExecutorBinding(
        CapturePlanReceipt(
            values["plan_digest"], values["profile"], values["case_id"],
            values["candidate_sha"], values["ready_at"],
        ),
        values["components"],
    )


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

    def test_provider_attempt_profile_executes_a_complete_public_bound_sequence(self) -> None:
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
        self.assertEqual(accounting["history"], "complete")
        self.assertEqual(accounting["snapshot"]["candidate_sha"], exact.candidate_sha)
        self.assertEqual(accounting["snapshot"]["capture_plan_digest"], exact.plan.plan_digest)
        self.assertEqual(accounting["snapshot"]["ready_at"], exact.ready_at)
        self.assertEqual(accounting["snapshot"]["review_mode"], "COMPLETE")
        self.assertEqual(accounting["snapshot"]["complete_rounds"], 3)
        self.assertEqual(accounting["snapshot"]["lifecycle_state"], "accepted-review")
        self.assertEqual(accounting["snapshot"]["next_action"], "candidate-gates")
        graph = accounting["snapshot"]["event_graph"]
        self.assertEqual(len(graph["provider_attempts"]), 3)
        self.assertEqual(
            [attempt[4] for attempt in graph["provider_attempts"]],
            ["invalid", "completed", "accepted"],
        )
        self.assertEqual(len(graph["review_rounds"]), 1)
        self.assertEqual(len(graph["accepted_results"]), 1)
        self.assertEqual(accounting["mutation_count"], 0)
        self.assertEqual(comparison.status, "pass")

    def test_provider_attempt_profile_fails_closed_for_missing_history_or_drift(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        adapter.validate(exact)
        evidence = adapter.project(exact, adapter.execute(exact))
        self.assertEqual(adapter.compare(exact, evidence).status, "pass")

        missing_history = deepcopy(evidence)
        missing_history["provider_attempt_accounting"]["history"] = "missing-recapture-required"
        missing_history["provider_attempt_accounting"]["snapshot"] = None
        self.assertEqual(adapter.compare(exact, missing_history).status, "fail")

        incomplete_history = deepcopy(evidence)
        incomplete_history["provider_attempt_accounting"]["snapshot"] = None
        self.assertEqual(adapter.compare(exact, incomplete_history).status, "fail")

        duplicate_acceptance = deepcopy(evidence)
        accepted = duplicate_acceptance["provider_attempt_accounting"]["snapshot"]["event_graph"]["accepted_results"]
        accepted.append(accepted[0])
        self.assertEqual(adapter.compare(exact, duplicate_acceptance).status, "fail")

        self.assertEqual(adapter.compare(provider_binding(candidate_sha="c" * 40), evidence).status, "fail")
        self.assertEqual(adapter.compare(provider_binding(ready_at=18), evidence).status, "fail")
        self.assertEqual(adapter.compare(provider_binding(plan_digest="sha256:" + "f" * 64), evidence).status, "fail")
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(ready_at=True))
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            adapter.validate(provider_binding(components=ProfileComponentIdentities(
                "sha256:" + "f" * 64,
                external_validation.PROVIDER_ATTEMPT_EXPORTER_IDENTITY,
                external_validation.PROVIDER_ATTEMPT_COMPARATOR_IDENTITY,
            )))
