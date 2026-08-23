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

        self.assertEqual(
            contract["contract_identity"],
            "sha256:6752833ae7cabd0ce7e3c45a9bf964f068a3df8728d77e3cfa6fbe126faa8ed8",
        )
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
        profile_registry_drift = dict(contract)
        profile_registry_drift["schemas"] = {
            **contract["schemas"],
            "supervisor_profile_artifact": lifecycle.SUPERVISOR_PROFILE_ARTIFACT_SCHEMA,
        }
        profile_registry_drift["contract_identity"] = lifecycle._digest({
            key: value for key, value in profile_registry_drift.items()
            if key != "contract_identity"
        })
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "drifted"):
            lifecycle.validate_lifecycle_observation_contract(profile_registry_drift)
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

    def test_live_projection_preserves_findings_and_unaccepted_invalid_context(self) -> None:
        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        findings = lifecycle._synthetic_events(plan)
        findings[-3]["disposition"] = "findings"
        findings.pop()
        self.rechain(findings)
        accepted = lifecycle.project_lifecycle_events(plan, findings, self.seal(plan, findings))
        self.assertEqual(accepted.events[-2].disposition, "findings")
        self.assertEqual(accepted.events[-1].transition, "result_accepted")
        self.assertTrue(accepted.events[-1].accepted_result)

        invalid = findings[:4]
        invalid.append({**invalid[-1], "transition": "result_unaccepted", "disposition": "unaccepted", "accepted_result": False})
        for sequence, event in enumerate(invalid):
            event["sequence"] = sequence
        self.rechain(invalid)
        unaccepted = lifecycle.project_lifecycle_events(plan, invalid, self.seal(plan, invalid))
        self.assertFalse(unaccepted.events[-1].accepted_result)

    def test_invalid_context_requires_one_unaccepted_result_before_failover(self) -> None:
        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        events = lifecycle._synthetic_events(plan)
        unaccepted_index = next(index for index, event in enumerate(events) if event["transition"] == "result_unaccepted")

        missing = [dict(event) for index, event in enumerate(events) if index != unaccepted_index]
        for sequence, event in enumerate(missing):
            event["sequence"] = sequence
        self.rechain(missing)
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "attempt start"):
            lifecycle.project_lifecycle_events(plan, missing, self.seal(plan, missing))

        duplicate = [dict(event) for event in events]
        duplicate.insert(unaccepted_index + 1, dict(duplicate[unaccepted_index]))
        for sequence, event in enumerate(duplicate):
            event["sequence"] = sequence
        self.rechain(duplicate)
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "unaccepted"):
            lifecycle.project_lifecycle_events(plan, duplicate, self.seal(plan, duplicate))

        cross_attempt = [dict(event) for event in events]
        third_attempt = next(event for event in cross_attempt if event["review_attempt"] == 3)
        cross_attempt[unaccepted_index]["attempt_identity"] = third_attempt["attempt_identity"]
        cross_attempt[unaccepted_index]["review_attempt"] = 3
        self.rechain(cross_attempt)
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "unaccepted"):
            lifecycle.project_lifecycle_events(plan, cross_attempt, self.seal(plan, cross_attempt))

    def test_v1_projection_keeps_its_pre_candidate_semantic_shape_and_identity(self) -> None:
        plan = lifecycle._synthetic_plan(self.candidate, self.ready_at)
        events = lifecycle._synthetic_events(plan)
        for event in events:
            event["artifact_references"] = []
        self.rechain(events)
        projection = lifecycle.project_lifecycle_events(plan, events, self.seal(plan, events))
        payload = projection.semantic_payload()
        self.assertEqual(
            tuple(payload["events"][1]),
            (
                "sequence", "occurred_at", "role", "task_identity", "attempt_identity",
                "review_attempt", "transition", "disposition", "accepted_result",
                "successor_candidate_sha", "predecessor_event_digest", "artifact_references",
                "event_digest",
            ),
        )
        # This digest was captured from the independently reviewed v1 ledger
        # fixture before profile-private decoding was introduced.
        self.assertEqual(
            lifecycle._digest(payload),
            "sha256:ae4a7582dbda6b3c35ebf3fb92c9259ab7f89199415c02ff24d1994ed62c8cb3",
        )
        self.assertTrue(lifecycle.supervisor_profile_artifact("sol", "xhigh").startswith("sha256:"))
        with self.assertRaisesRegex(lifecycle.LifecycleObservationError, "profile artifact"):
            lifecycle.supervisor_profile_artifact("sol", "high")

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
