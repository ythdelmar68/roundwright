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

    def test_provider_attempt_profile_bare_public_binding_blocks_before_dispatch(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        self.assertEqual(
            adapter.component_identities,
            ProfileComponentIdentities(*external_validation.provider_attempt_accounting_component_identities()),
        )
        with self.assertRaisesRegex(
            external_validation.ExternalValidationAdapterError,
            external_validation.PROVIDER_ATTEMPT_HISTORY_BLOCKER,
        ):
            adapter.validate(exact)

        # The reviewed Harness never calls execute after validate blocks.  If a
        # caller attempts to bypass that boundary, the projection is explicit
        # non-qualifying evidence rather than an inferred event sequence.
        evidence = adapter.project(exact, adapter.execute(exact))
        accounting = evidence["provider_attempt_accounting"]
        self.assertEqual(accounting["capture_mode"], "armed-live-events")
        self.assertEqual(accounting["history"], "unavailable-public-binding")
        self.assertIsNone(accounting["snapshot"])
        self.assertEqual(
            accounting["blocker"]["code"],
            external_validation.PROVIDER_ATTEMPT_HISTORY_BLOCKER,
        )
        self.assertEqual(
            accounting["blocker"]["required_public_contract"],
            "plan-bound-product-execution-context/v1",
        )
        self.assertIn(
            "bounded-provider-backend-and-durable-lifecycle-store",
            accounting["blocker"]["missing_runtime_capabilities"],
        )
        self.assertEqual(accounting["mutation_count"], 0)
        self.assertEqual(adapter.compare(exact, evidence).status, "fail")

    def test_provider_attempt_profile_rejects_fabricated_history_and_context_drift(self) -> None:
        adapter = external_validation.roundwright_profile_adapter_factory(
            PROVIDER_ATTEMPT_ACCOUNTING_PROFILE
        )
        exact = provider_binding()
        evidence = adapter.project(exact, adapter.execute(exact))

        fabricated = deepcopy(evidence)
        fabricated["provider_attempt_accounting"]["history"] = "complete"
        fabricated["provider_attempt_accounting"]["snapshot"] = {
            "review_round": 1,
            "lifecycle_state": "accepted-review",
            "event_graph": {"provider_attempts": ["invented"]},
        }
        self.assertEqual(adapter.compare(exact, fabricated).status, "fail")

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

    def test_durable_snapshot_requires_base_and_context_bindings(self) -> None:
        candidate = "a" * 40
        with self.assertRaises(external_validation.ExternalValidationAdapterError):
            external_validation.ProviderAttemptAccountingSnapshot(
                "task-45", "sha256:" + "2" * 64, "not-a-sha", candidate, "sha256:" + "3" * 64, 17,
                1, 1, "COMPLETE", 1, 10, 1, "sha256:" + "4" * 64,
                "sha256:" + "5" * 64, "selected-provider", "sha256:" + "6" * 64,
                "accepted-review", None, "candidate-gates", False,
            )
