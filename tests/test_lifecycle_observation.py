from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright import lifecycle_observation as lifecycle


class LifecycleObservationTests(unittest.TestCase):
    candidate = "a" * 40
    ready_at = 1_700_000_000

    @staticmethod
    def seal(plan: dict[str, object], events: list[dict[str, object]]) -> object:
        core = {
            "schema": lifecycle.HARNESS_SEAL_RECEIPT_SCHEMA,
            "status": "sealed",
            "event_schema": lifecycle.HARNESS_EVENT_SCHEMA,
            "plan_digest": lifecycle._digest(plan),
            "window_identity": plan["window_identity"],
            "repository_identity": plan["repository_identity"],
            "candidate_sha": plan["candidate_sha"],
            "ready_at": plan["ready_at"],
            "event_count": len(events),
            "head_event_digest": lifecycle._digest(events[-1]),
            "head_entry_digest": "sha256:" + "1" * 64,
            "manifest_digest": "sha256:" + "2" * 64,
            "ledger_digest": "sha256:" + "3" * 64,
            "retention_identity": "sha256:" + "4" * 64,
        }
        return SimpleNamespace(as_dict=lambda: {**core, "receipt_digest": lifecycle._digest(core)})

    @staticmethod
    def rechain(events: list[dict[str, object]]) -> None:
        predecessor = None
        for event in events:
            event["predecessor_event_digest"] = predecessor
            predecessor = lifecycle._digest(event)

    def projection(self) -> lifecycle.LifecycleShadowProjection:
        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        events = lifecycle._synthetic_events(plan)
        return lifecycle.project_lifecycle_events(plan, events, self.seal(plan, events))

    def test_authoritative_contract_pins_reviewed_external_identities(self) -> None:
        contract = lifecycle.lifecycle_observation_contract()

        self.assertEqual(contract["harness"]["merge_commit"], lifecycle.HARNESS_MERGE_COMMIT)
        self.assertEqual(contract["harness"]["tree"], lifecycle.HARNESS_TREE)
        self.assertEqual(contract["roundlet"]["merge_commit"], lifecycle.ROUNDLET_MERGE_COMMIT)
        self.assertEqual(contract["roundlet"]["content_blob"], lifecycle.ROUNDLET_SKILL_BLOB)
        self.assertEqual(contract["schemas"]["event"], lifecycle.HARNESS_EVENT_SCHEMA)
        self.assertEqual(contract["target_profile"], lifecycle.LIVE_LIFECYCLE_SHADOW_PROFILE)
        self.assertEqual(
            lifecycle.validate_lifecycle_observation_contract(dict(contract)),
            contract,
        )
        drifted = dict(contract)
        drifted["roundlet"] = {**contract["roundlet"], "tree": "0" * 40}
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "drifted"):
            lifecycle.validate_lifecycle_observation_contract(drifted)
        tracked = json.loads(
            (ROOT / "docs" / "operations" / "lifecycle-observation-contract.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(tracked, contract)

    def test_generic_sequence_projects_cancel_invalid_pass_and_one_round(self) -> None:
        projection = self.projection()

        completed = tuple(
            event.disposition
            for event in projection.events
            if event.transition == "attempt_completed"
        )
        self.assertEqual(completed, ("cancelled", "invalid_context", "pass"))
        self.assertEqual(
            tuple(event.transition for event in projection.events[-2:]),
            ("result_accepted", "formal_round_advanced"),
        )
        self.assertEqual(projection.review_epoch, 1)
        self.assertEqual(projection.review_round, 1)
        self.assertEqual(projection.review_mode, "complete")
        self.assertEqual(projection.candidate_sha, self.candidate)
        self.assertEqual(projection.ready_at, self.ready_at)
        self.assertEqual(projection.classified_differences, ())

    def test_supervisor_profile_artifacts_bind_model_and_reasoning(self) -> None:
        projection = self.projection()
        completed = tuple(
            (event.model_profile, event.reasoning_profile, event.disposition)
            for event in projection.events if event.transition == "attempt_completed"
        )
        self.assertEqual(
            completed,
            (("sol", "xhigh", "cancelled"), ("terra", "high", "invalid_context"), ("terra", "high", "pass")),
        )
        self.assertTrue(lifecycle.supervisor_profile_artifact("sol", "xhigh").startswith("sha256:"))
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "profile artifact"):
            lifecycle.supervisor_profile_artifact("sol", "high")

        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        legacy_events = lifecycle._synthetic_events(plan)
        legacy_events[1]["artifact_references"] = [
            lifecycle._digest({
                "schema": "roundwright-supervisor-model-artifact/v1",
                "model": "sol",
            }),
        ]
        self.rechain(legacy_events)
        legacy = lifecycle.project_lifecycle_events(plan, legacy_events, self.seal(plan, legacy_events))
        self.assertEqual(legacy.events[1].model_profile, "missing")
        self.assertEqual(legacy.events[1].reasoning_profile, "missing")

        duplicate_events = lifecycle._synthetic_events(plan)
        duplicate_events[1]["artifact_references"] *= 2
        self.rechain(duplicate_events)
        duplicate = lifecycle.project_lifecycle_events(
            plan, duplicate_events, self.seal(plan, duplicate_events),
        )
        self.assertEqual(
            (duplicate.events[1].model_profile, duplicate.events[1].reasoning_profile),
            ("missing", "missing"),
        )

    def test_comparator_checks_every_field_and_rejects_declared_difference(self) -> None:
        expected = self.projection()
        changed_event = replace(expected.events[1], disposition="failed")
        changed = replace(expected, events=(expected.events[0], changed_event, *expected.events[2:]))

        comparison = lifecycle.compare_lifecycle_projections(expected, changed)

        self.assertEqual(comparison.status, "fail")
        self.assertIn("root.events.1.disposition", comparison.classified_differences)
        declared = replace(expected, classified_differences=("provider-outcome",))
        declared_comparison = lifecycle.compare_lifecycle_projections(expected, declared)
        self.assertEqual(declared_comparison.status, "fail")
        self.assertIn("observed.provider-outcome", declared_comparison.classified_differences)

    def test_missing_completion_wrong_predecessor_and_time_drift_fail(self) -> None:
        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        events = lifecycle._synthetic_events(plan)
        with self.assertRaises(lifecycle.LifecycleObservationError):
            lifecycle.project_lifecycle_events(plan, events[:-1], self.seal(plan, events[:-1]))

        wrong_predecessor = [dict(event) for event in events]
        wrong_predecessor[1]["predecessor_event_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "binding"):
            lifecycle.project_lifecycle_events(
                plan,
                wrong_predecessor,
                self.seal(plan, wrong_predecessor),
            )

        changed_time = dict(plan)
        changed_time["ready_at"] = self.ready_at + 1
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "drifted"):
            lifecycle.project_lifecycle_events(changed_time, events, self.seal(plan, events))

    def test_provider_free_exact_harness_synthetic_gate_when_source_is_bound(self) -> None:
        source_value = os.environ.get("ROUNDWRIGHT_HARNESS_SOURCE")
        if source_value is None:
            self.skipTest("set ROUNDWRIGHT_HARNESS_SOURCE to the exact reviewed Harness src")
        source = Path(source_value)
        if not (source / "roundwright_harness" / "lifecycle.py").is_file():
            self.skipTest("exact reviewed Harness lifecycle module is unavailable")
        prior_path = list(sys.path)
        prior_modules = {
            name: value
            for name, value in sys.modules.items()
            if name == "roundwright_harness" or name.startswith("roundwright_harness.")
        }
        for name in tuple(prior_modules):
            sys.modules.pop(name, None)
        sys.path.insert(0, str(source))
        try:
            module = importlib.import_module("roundwright_harness.lifecycle")
            with tempfile.TemporaryDirectory() as directory:
                receipt = lifecycle.run_synthetic_lifecycle_gate(
                    self.candidate,
                    self.ready_at,
                    Path(directory),
                    harness_module=module,
                )
            self.assertEqual(receipt.status, "pass")
            self.assertEqual(receipt.event_count, 8)
            self.assertEqual(receipt.provider_calls, 0)
            self.assertEqual(receipt.github_mutations, 0)
            self.assertEqual(receipt.target_mutations, 0)
            self.assertNotIn(str(source), str(receipt.public_payload()))
        finally:
            sys.path[:] = prior_path
            for name in tuple(sys.modules):
                if name == "roundwright_harness" or name.startswith("roundwright_harness."):
                    sys.modules.pop(name, None)
            sys.modules.update(prior_modules)

    def test_harness_module_requires_the_exact_reviewed_source_blob(self) -> None:
        source_value = os.environ.get("ROUNDWRIGHT_HARNESS_SOURCE")
        if source_value is None:
            self.skipTest("set ROUNDWRIGHT_HARNESS_SOURCE to the exact reviewed Harness src")
        source = Path(source_value)
        prior_path = list(sys.path)
        prior_modules = {
            name: value
            for name, value in sys.modules.items()
            if name == "roundwright_harness" or name.startswith("roundwright_harness.")
        }
        for name in tuple(prior_modules):
            sys.modules.pop(name, None)
        sys.path.insert(0, str(source))
        try:
            module = importlib.import_module("roundwright_harness.lifecycle")
            self.assertIs(lifecycle._harness_lifecycle(module), module)
            with tempfile.TemporaryDirectory() as directory:
                drifted_source = Path(directory) / "lifecycle.py"
                drifted_source.write_bytes(Path(module.__file__).read_bytes() + b"\n")
                original = module.__file__
                module.__file__ = str(drifted_source)
                try:
                    with self.assertRaisesRegex(
                        lifecycle.LifecycleObservationError,
                        "content identity drifted",
                    ):
                        lifecycle._harness_lifecycle(module)
                finally:
                    module.__file__ = original
        finally:
            sys.path[:] = prior_path
            for name in tuple(sys.modules):
                if name == "roundwright_harness" or name.startswith("roundwright_harness."):
                    sys.modules.pop(name, None)
            sys.modules.update(prior_modules)


if __name__ == "__main__":
    unittest.main()
