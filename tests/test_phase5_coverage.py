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


def semantic_payload(candidate, *, tests=None, executed=None, skipped=None, status="passed"):
    tests = coverage.SEMANTIC_TESTS if tests is None else tests
    return {
        "schema": "roundwright-phase5-semantic-execution/v3",
        "candidate_sha": candidate,
        "tests": tests,
        "executed_tests": tests if executed is None else executed,
        "skipped_tests": () if skipped is None else skipped,
        "windows_declared_skips": coverage.WINDOWS_DECLARED_SKIPS,
        "status": status,
    }


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
        candidate = coverage.current_candidate(); payload=semantic_payload(candidate)
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
            semantic_payload("0" * 40),
            semantic_payload(candidate, tests=coverage.SEMANTIC_TESTS[:-1]),
            semantic_payload(candidate, executed=coverage.SEMANTIC_TESTS[:-1]),
            semantic_payload(candidate, executed=(*coverage.SEMANTIC_TESTS, coverage.SEMANTIC_TESTS[0])),
            semantic_payload(candidate, skipped=(coverage.SEMANTIC_TESTS[0],)),
            semantic_payload(candidate, status="failed"),
        ):
            self.semantic.write_text(json.dumps({**payload, "receipt_digest": "sha256:" + coverage._digest(coverage._canonical(payload))}), encoding="utf-8")
            with self.subTest(payload=payload), self.assertRaisesRegex(coverage.CoverageError, "stale or forged"):
                coverage.render(self.source, self.ledger, self.tests, candidate, manifest, self.semantic)

    def test_issue_132_semantic_inventory_is_independently_pinned_and_ordered(self) -> None:
        required = (
            "tests.test_codex_worker.CodexWorkerAdapterTests.test_typed_denial_and_transport_failure_remain_typed",
            "tests.test_codex_supervisor.SupervisorTests.test_security_denial_stops_before_a_prebound_profile_fallback",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_scope_denial_blocks_before_dependency_provider_session",
            "tests.test_failure_recovery.FailureRecoveryTests.test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route",
            "tests.test_failure_recovery.FailureRecoveryTests.test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_failure_readback_revalidates_current_admission_authority",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_clearance_and_revocation_are_append_only_and_restart_verified",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_supervisor_coordinates_are_unique_and_strictly_monotonic",
            "tests.test_candidate_review.CandidateReviewTests.test_diff_dispatch_requires_the_exact_within_round_profile",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_terminal_block_and_invalid_output_replays_keep_their_original_classification",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_profile_format_ordinals_are_durable_and_exhaust_before_a_fourth_dispatch",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_restart_continues_same_profile_at_next_physical_format_ordinal",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_same_format_ordinal_replay_is_inert_but_changed_attempt_identity_is_rejected",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_format_invalid_cannot_jump_profiles_before_or_after_restart",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_invalid_predecessor_cannot_mint_a_successor_session_or_budget",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_after_pre_dispatch_claim_blocks_before_native_session_open",
            "tests.test_production_coding_runtime.ProductionRuntimeTests.test_hermetic_production_runtime_persists_typed_terminal_failure_and_blocks_restart_before_dispatch",
            "tests.test_codex_supervisor.SupervisorTests.test_sequence_advances_invalid_primary_to_valid_fallback",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_typed_blocked_turn_records_a_shared_durable_failure_from_the_session_claim",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_restart_of_an_authoritative_session_claim_has_zero_later_provider_or_budget_effects",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_unknown_predecessor_requires_reconciliation_before_successor_effect",
            "tests.test_codex_supervisor.SupervisorTests.test_every_non_format_invalid_stops_before_successor",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_recovery_route_is_exact_single_use_and_restart_safe",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_recovery_route_fence_interruption_reconciles_before_successor_dispatch",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_recovery_route_fence_interruption_reconciles_before_successor_session",
            "tests.test_codex_supervisor.SupervisorTests.test_qualification_restarts_exact_successor_after_each_durable_crash_boundary",
            "tests.test_codex_supervisor.SupervisorTests.test_format_exhaustion_never_authorizes_the_next_profile",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_format_correction_then_verified_outage_falls_back_without_stranding",
            "tests.test_candidate_review.CandidateReviewTests.test_legacy_populated_reviews_preserve_authenticated_identity_on_migration",
            "tests.test_codex_supervisor.SupervisorTests.test_native_corrections_cross_schema_parser_adapter_and_durable_lifecycle",
            "tests.test_codex_supervisor.SupervisorTests.test_native_denial_persists_scope_stop_before_terminal_and_restart",
            "tests.test_provider_recovery.ProviderRecoveryTests.test_durable_routes_reject_legacy_and_unavailable_sources_before_any_effect",
            "tests.test_codex_supervisor.SupervisorTests.test_historical_v2_inflight_and_accepted_file_records_retain_exact_identities",
            "tests.test_production_coding_runtime.ProductionRuntimeTests.test_prepared_worker_rechecks_peer_denial_before_any_dispatch_effect",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_prepared_dependency_retry_denial_is_inert_across_restart",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_prepared_format_correction_reuses_exact_reservation_after_crash",
            "tests.test_codex_supervisor.SupervisorTests.test_one_logical_profile_allows_bounded_physical_corrections_and_replay",
            "tests.test_codex_supervisor.SupervisorTests.test_generic_sequence_rejects_profile_jump_before_correction_coordinates",
            "tests.test_worker_toolbox.WorkerToolboxTests.test_scope_fence_rechecks_after_reservation_before_worker_session",
            "tests.test_codex_dependency_review.DependencyReviewServiceTests.test_scope_denial_after_initial_check_blocks_before_reservation_and_session",
            "tests.test_worker_toolbox.WorkerToolboxTests.test_completed_worker_reservation_cannot_be_publicly_refunded",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_stopped_scope_rejects_correction_before_any_state_or_budget_change",
            "tests.test_provider_attempt_runtime.ProviderAttemptRuntimeTests.test_readiness_accepts_only_exact_unclaimed_prepared_correction",
        )
        self.assertEqual(coverage.ISSUE_132_SEMANTIC_TESTS, required)
        self.assertEqual(tuple(test for test in coverage.SEMANTIC_TESTS if test in required), required)
        self.assertEqual(tuple(coverage.ISSUE_132_FINDING_REQUIREMENTS), tuple(f"E1R2-{number:02d}" for number in range(1, 9)))
        self.assertEqual(
            tuple(coverage.ISSUE_132_E1R3_FINDING_REQUIREMENTS),
            ("RW132-PROD-001", "RW132-RECOVERY-002", "RW132-BINDING-003", "RW132-DURABLE-004", "RW132-EVIDENCE-005", "RW132-TAXONOMY-006", "RW132-ACCOUNTING-007", "RW132-QUALIFICATION-008", "RW132-ROUTE-FENCE-009", "RW132-DEPENDENCY-FENCE-010", "RW132-SUPERVISOR-FENCE-011"),
        )
        self.assertEqual(
            tuple(coverage.ISSUE_132_E1R11_FINDING_REQUIREMENTS),
            ("E1R11-01", "E1R11-02", "E1R11-03", "E1R11-04"),
        )

    def test_issue_132_semantic_inventory_rejects_omission_and_reordering(self) -> None:
        required = coverage.ISSUE_132_SEMANTIC_TESTS
        variants = (
            tuple(test for test in coverage.SEMANTIC_TESTS if test != required[-1]),
            (*coverage.SEMANTIC_TESTS[:5], required[4], required[3], *coverage.SEMANTIC_TESTS[6:]),
        )
        candidate = coverage.current_candidate()
        payload = semantic_payload(candidate)
        self.semantic.write_text(json.dumps({**payload, "receipt_digest": "sha256:" + coverage._digest(coverage._canonical(payload))}), encoding="utf-8")
        for semantic_tests in variants:
            with self.subTest(semantic_tests=semantic_tests), patch.object(coverage, "SEMANTIC_TESTS", semantic_tests), self.assertRaisesRegex(coverage.CoverageError, "Issue 132 semantic test inventory"):
                coverage._semantic_execution(self.semantic, candidate)

    def test_issue_132_finding_mapping_rejects_omitted_code_or_test(self) -> None:
        requirements = dict(coverage.ISSUE_132_FINDING_REQUIREMENTS)
        requirements.pop("E1R2-08")
        with patch.object(coverage, "ISSUE_132_FINDING_REQUIREMENTS", requirements), self.assertRaisesRegex(coverage.CoverageError, "E1R2 finding inventory"):
            coverage._validate_issue_132_semantic_tests()
        requirements = dict(coverage.ISSUE_132_FINDING_REQUIREMENTS)
        requirements["E1R2-08"] = ("src/roundwright/missing.py", requirements["E1R2-08"][1])
        with patch.object(coverage, "ISSUE_132_FINDING_REQUIREMENTS", requirements), self.assertRaisesRegex(coverage.CoverageError, "E1R2 finding mapping"):
            coverage._validate_issue_132_semantic_tests()
        e1r3 = dict(coverage.ISSUE_132_E1R3_FINDING_REQUIREMENTS)
        e1r3.pop("RW132-QUALIFICATION-008")
        with patch.object(coverage, "ISSUE_132_E1R3_FINDING_REQUIREMENTS", e1r3), self.assertRaisesRegex(coverage.CoverageError, "E1R3 stable finding mapping"):
            coverage._validate_issue_132_semantic_tests()
        e1r11 = dict(coverage.ISSUE_132_E1R11_FINDING_REQUIREMENTS)
        e1r11.pop("E1R11-04")
        with patch.object(coverage, "ISSUE_132_E1R11_FINDING_REQUIREMENTS", e1r11), self.assertRaisesRegex(coverage.CoverageError, "E1R11 finding mapping"):
            coverage._validate_issue_132_semantic_tests()

    def test_issue_132_affected_module_inventory_rejects_candidate_review_omission(self) -> None:
        with patch.object(coverage, "ISSUE_132_AFFECTED_MODULE_TESTS", {}), self.assertRaisesRegex(coverage.CoverageError, "affected-module regression inventory"):
            coverage._validate_issue_132_semantic_tests()
