"""Regression coverage for the Phase 5 public-safe coverage map."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase5_coverage", ROOT / "ci" / "validate_phase5_coverage.py")
assert SPEC and SPEC.loader
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


class Phase5CoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "map.json"
        self.ledger = self.directory / "ledger.md"
        self.tests = self.directory / "tests.md"
        self.semantic = self.directory / "semantic.json"
        shutil.copy2(ROOT / "docs" / "migration" / "phase5-coverage-map.json", self.source)
        shutil.copy2(ROOT / "docs" / "migration" / "legacy-decision-ledger.md", self.ledger)
        shutil.copy2(ROOT / "docs" / "migration" / "test-disposition.md", self.tests)
        candidate = coverage.current_candidate(); payload={"schema":"roundwright-phase5-semantic-execution/v1","candidate_sha":candidate,"tests":coverage._SEMANTIC_TESTS,"status":"passed"}
        self.semantic.write_text(json.dumps({**payload,"receipt_digest":"sha256:" + coverage._digest(coverage._canonical(payload))}),encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def document(self) -> dict[str, object]:
        return json.loads(self.source.read_text(encoding="utf-8"))

    def write_document(self, document: dict[str, object]) -> None:
        self.source.write_text(json.dumps(document, sort_keys=True) + "\n", encoding="utf-8")

    def test_validates_exact_inventory_and_renders_candidate_bound_readback(self) -> None:
        document = coverage.validate(self.source, self.ledger, self.tests)
        self.assertEqual(len(document["items"]), len(coverage.EXPECTED_OWNERS))
        manifest = self.directory / "readback.json"
        candidate = coverage.current_candidate()
        coverage.render(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)
        coverage.verify(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)

    def test_rejects_duplicate_unknown_and_owner_drift(self) -> None:
        document = self.document()
        items = document["items"]
        items.append(items[0].copy())
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "duplicate"):
            coverage.validate(self.source, self.ledger, self.tests)
        items.pop()
        items[0]["id"] = "EV-FFFFFFFFFFFF"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "owner issue"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_public_safe_destination_drift(self) -> None:
        document = self.document()
        document["items"][0]["destination"] = "another-public-safe-target"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "destination has drifted"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_issue_136_requirement_omission_or_drift(self) -> None:
        document = self.document()
        document["implementation_requirements"]["destinations"].pop()
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "issue 136"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_issue_136_concrete_artifact_digest_drift(self) -> None:
        document = self.document()
        document["implementation_requirements"]["artifacts"][0]["sha256"] = "0" * 64
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "artifact digest"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_issue_132_requirement_and_artifact_drift(self) -> None:
        baseline = self.document()
        document = json.loads(json.dumps(baseline))
        document["issue_132_requirements"]["destinations"].pop()
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "issue 132"):
            coverage.validate(self.source, self.ledger, self.tests)
        document = json.loads(json.dumps(baseline))
        document["issue_132_requirements"]["artifacts"][0]["sha256"] = "0" * 64
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "artifact digest"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_semantic_boundary_contract_drift(self) -> None:
        contracts = dict(coverage.SEMANTIC_CONTRACTS)
        contracts["src/roundwright/worker_toolbox.py"] = ("missing-required-production-boundary",)
        with patch.object(coverage, "SEMANTIC_CONTRACTS", contracts), self.assertRaisesRegex(coverage.CoverageError, "semantic contract"):
            coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_verification_drift_and_unsafe_verification_values(self) -> None:
        document = self.document()
        for verification, expected_error in (
            ("another-public-safe-contract", "verification has drifted"),
            ("ythdelmar68/roundwright", "unsafe"),
            ("/private/roundwright/evidence", "unsafe"),
            ("raw-internal-evidence", "unsafe"),
            ("owner-reasoning", "unsafe"),
        ):
            document["items"][0]["verification"] = verification
            self.write_document(document)
            with self.subTest(verification=verification), self.assertRaisesRegex(coverage.CoverageError, expected_error):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_disposition_prerequisite_confidence_and_status_drift(self) -> None:
        baseline = self.document()
        for field, value, expected_error in (
            ("disposition", "adopt", "disposition has drifted"),
            ("prerequisites", ["#118"], "prerequisites have drifted"),
            ("confidence", "low", "confidence has drifted"),
            ("status", "blocked", "status has drifted"),
        ):
            document = json.loads(json.dumps(baseline))
            item = next(item for item in document["items"] if item["id"] == "EV-0F91CDC81DEA")
            item[field] = value
            self.write_document(document)
            with self.subTest(field=field), self.assertRaisesRegex(coverage.CoverageError, expected_error):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_required_source_selection_survives_map_and_binding_omission(self) -> None:
        identifier = "TS-856DFB0B5E51"
        document = self.document()
        document["items"] = [item for item in document["items"] if item["id"] != identifier]
        self.write_document(document)
        tables = (
            "EXPECTED_OWNERS", "EXPECTED_DESTINATIONS", "EXPECTED_VERIFICATIONS", "EXPECTED_DISPOSITIONS",
            "EXPECTED_PREREQUISITES", "EXPECTED_CONFIDENCES", "EXPECTED_STATUSES",
        )
        with ExitStack() as stack:
            for name in tables:
                values = getattr(coverage, name)
                stack.enter_context(patch.object(coverage, name, {key: value for key, value in values.items() if key != identifier}))
            with self.assertRaisesRegex(coverage.CoverageError, "required Phase 5 source inventory is omitted"):
                coverage.validate(self.source, self.ledger, self.tests)

    def test_rejects_stale_sources_unsafe_text_and_candidate_drift(self) -> None:
        document = self.document()
        document["items"][0]["destination"] = "C:/private/source"
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "unsafe"):
            coverage.validate(self.source, self.ledger, self.tests)
        document["items"][0]["destination"] = "promotion-evaluation"
        document["sources"]["ledger_sha256"] = "a" * 64
        self.write_document(document)
        with self.assertRaisesRegex(coverage.CoverageError, "drifted"):
            coverage.validate(self.source, self.ledger, self.tests)
        shutil.copy2(ROOT / "docs" / "migration" / "phase5-coverage-map.json", self.source)
        manifest = self.directory / "readback.json"
        candidate = coverage.current_candidate()
        coverage.render(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)
        other_candidate = "0" * 40 if candidate != "0" * 40 else "1" * 40
        with self.assertRaisesRegex(coverage.CoverageError, "does not match checked-out HEAD"):
            coverage.verify(self.source, self.ledger, self.tests, other_candidate, manifest, self.semantic)

    def test_rejects_missing_stale_and_inconsistent_semantic_execution_receipts(self) -> None:
        candidate = coverage.current_candidate()
        manifest = self.directory / "readback.json"
        self.semantic.unlink()
        with self.assertRaisesRegex(coverage.CoverageError, "semantic execution receipt is unavailable"):
            coverage.render(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)
        for payload in (
            {"schema": "roundwright-phase5-semantic-execution/v1", "candidate_sha": "0" * 40, "tests": coverage._SEMANTIC_TESTS, "status": "passed"},
            {"schema": "roundwright-phase5-semantic-execution/v1", "candidate_sha": candidate, "tests": coverage._SEMANTIC_TESTS[:-1], "status": "passed"},
            {"schema": "roundwright-phase5-semantic-execution/v1", "candidate_sha": candidate, "tests": coverage._SEMANTIC_TESTS, "status": "failed"},
        ):
            self.semantic.write_text(json.dumps({**payload, "receipt_digest": "sha256:" + coverage._digest(coverage._canonical(payload))}), encoding="utf-8")
            with self.subTest(payload=payload), self.assertRaisesRegex(coverage.CoverageError, "stale or forged"):
                coverage.render(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)

    def test_issue_132_semantic_inventory_is_independently_pinned_and_ordered(self) -> None:
        required = (
            "tests.test_failure_recovery.FailureRecoveryTests.test_denial_blocks_same_scope_across_restart_until_exact_clearance",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
            "tests.test_codex_supervisor.SupervisorTests.test_ambiguous_and_incomplete_results_stop_before_fallback",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_terminal_supervisor_failure_is_durable_and_never_fails_over_without_invalid_output",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_later_accounting_request_reads_prior_invalid_recovery_without_disclosure",
        )
        self.assertEqual(coverage.ISSUE_132_SEMANTIC_TESTS, required)
        self.assertEqual(tuple(test for test in coverage._SEMANTIC_TESTS if test in required), required)

    def test_issue_132_semantic_inventory_rejects_omission_and_reordering(self) -> None:
        required = coverage.ISSUE_132_SEMANTIC_TESTS
        variants = (
            tuple(test for test in coverage._SEMANTIC_TESTS if test != required[-1]),
            (*coverage._SEMANTIC_TESTS[:3], required[4], required[3], *coverage._SEMANTIC_TESTS[5:]),
        )
        candidate = coverage.current_candidate()
        payload = {"schema": "roundwright-phase5-semantic-execution/v1", "candidate_sha": candidate, "tests": list(coverage._SEMANTIC_TESTS), "status": "passed"}
        self.semantic.write_text(json.dumps({**payload, "receipt_digest": "sha256:" + coverage._digest(coverage._canonical(payload))}), encoding="utf-8")
        for semantic_tests in variants:
            with self.subTest(semantic_tests=semantic_tests), patch.object(coverage, "_SEMANTIC_TESTS", semantic_tests), self.assertRaisesRegex(coverage.CoverageError, "Issue 132 semantic test inventory"):
                coverage._semantic_execution(self.semantic, candidate)
