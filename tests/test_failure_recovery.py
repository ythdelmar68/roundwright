import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.failure_recovery import (
    Clearance, EvidenceConfidence, EvidenceSource, FailureBinding, FailureClass, FailureEvidence, FailureRecoveryError,
    FailureRecord, FailureRole, RecoveryAction, admit_recovery, classify,
    RecoveryRouteAdmission, issue_recovery_route_admission,
    failure_compatibility_matrix, parse_failure_record,
)
from roundwright.codex_worker import classify_worker_failure
from roundwright.codex_supervisor import classify_supervisor_failure
from roundwright.codex_dependency_review import classify_dependency_review_failure
from roundwright.configuration import ProviderProfile, ReasoningEffort
from roundwright.role_capability_policy import AdvisoryRole, reserve_role_effect
from tests.role_admission_fixture import sealed_execution_for_effect, trusted_execution_host


class FailureRecoveryTests(unittest.TestCase):
    def binding(self, *, role=FailureRole.WORKER, session="session-1"):
        return FailureBinding("a" * 40, "sha256:" + "b" * 64, "sha256:" + "c" * 64, "workspace-write", role, "sha256:" + "d" * 64, session, "attempt-1")

    def live_route(self, role=FailureRole.WORKER):
        profile = ProviderProfile("gpt-5.6-terra", ReasoningEffort.HIGH)
        material = {"route": "recovery", "role": role.value}
        execution = sealed_execution_for_effect(
            AdvisoryRole(role.value), profile, request_identity="attempt-1",
            request_material=material, preflight_material=material,
        )
        binding = FailureBinding(
            execution.execution_binding.candidate_sha, "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
            f"{role.value}:{execution.execution_binding.task_identity}", role,
            execution.contract.profile.profile_identity, "session-1", "attempt-1",
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        reservation = reserve_role_effect(
            execution, host_inputs=trusted_execution_host(AdvisoryRole(role.value), profile),
            ledger_path=Path(temporary.name) / "route-budget.sqlite", profile=profile,
            request_or_attempt_identity="attempt-1", request_material=material,
            preflight_material=material,
        )
        return binding, issue_recovery_route_admission(
            binding, source_execution=execution, target_execution=execution,
            target_reservation=reservation,
        )

    def test_denial_blocks_same_scope_across_restart_until_exact_clearance(self):
        binding, route = self.live_route(FailureRole.SUPERVISOR)
        record = classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
        self.assertEqual(admit_recovery(record, binding, route=route), RecoveryAction.STOP_SCOPE)
        self.assertEqual(admit_recovery(record, binding, route=route, clearance=Clearance(record.digest, binding, "command-1")), RecoveryAction.STOP_SCOPE)
        with self.assertRaises(FailureRecoveryError):
            replacement = FailureBinding(
                binding.candidate_sha, binding.policy_digest, binding.configuration_digest,
                binding.authority_scope, binding.role, binding.profile_identity,
                "replacement", binding.attempt_identity,
            )
            admit_recovery(record, replacement, route=route)

    def test_prose_missing_output_and_partial_work_do_not_mint_fallback(self):
        binding = self.binding(role=FailureRole.DEPENDENCY_REVIEW)
        self.assertEqual(classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.MODEL_SELF_REPORT).action, RecoveryAction.RECONCILE)
        self.assertEqual(classify(binding, FailureClass.MISSING_OUTPUT, EvidenceSource.UNAVAILABLE).action, RecoveryAction.RECONCILE)
        self.assertEqual(classify(binding, FailureClass.PARTIAL_INCREMENT, EvidenceSource.VERIFIED_OUTPUT).action, RecoveryAction.CONTINUE_SAME_SESSION)

    def test_missing_owner_scope_stops_and_persists_confidence_independently(self):
        record = classify(
            self.binding(), FailureClass.MISSING_OWNER_SCOPE,
            FailureEvidence(EvidenceSource.VERIFIED_LIFECYCLE, EvidenceConfidence.VERIFIED),
        )
        self.assertEqual((record.action, record.clearance_required, record.evidence_confidence), (RecoveryAction.STOP_SCOPE, True, EvidenceConfidence.VERIFIED))
        unverified = classify(
            self.binding(), FailureClass.HOST_SECURITY_DENIAL,
            FailureEvidence(EvidenceSource.VERIFIED_HOST, EvidenceConfidence.UNAVAILABLE),
        )
        self.assertEqual((unverified.failure, unverified.evidence, unverified.evidence_confidence), (FailureClass.UNKNOWN, EvidenceSource.VERIFIED_HOST, EvidenceConfidence.UNAVAILABLE))

    def test_closed_matrix_allows_only_canonical_evidence_and_recovery_categories(self):
        matrix = failure_compatibility_matrix()
        self.assertEqual(set(matrix), set(FailureClass))
        for failure, expected in matrix.items():
            if failure is FailureClass.UNKNOWN:
                continue
            with self.subTest(failure=failure.value):
                evidence = next(iter(expected.evidence_sources))
                record = classify(self.binding(), failure, evidence)
                self.assertEqual((record.failure, record.action, record.retryable, record.clearance_required), (failure, expected.action, expected.retryable, expected.clearance_required))
        incompatible = classify(self.binding(), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_SERVICE)
        self.assertEqual((incompatible.failure, incompatible.action), (FailureClass.UNKNOWN, RecoveryAction.RECONCILE))
        with self.assertRaisesRegex(FailureRecoveryError, "taxonomy is incompatible"):
            FailureRecord(self.binding(), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_SERVICE, False, RecoveryAction.STOP_SCOPE, True)

    def test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route(self):
        binding, route = self.live_route()
        ended = classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.VERIFIED_LIFECYCLE)
        transient = classify(binding, FailureClass.TRANSIENT_SERVICE, EvidenceSource.VERIFIED_SERVICE)
        self.assertEqual(admit_recovery(ended, binding, route=route), RecoveryAction.PREBOUND_FALLBACK)
        self.assertEqual(admit_recovery(transient, binding, route=route), RecoveryAction.PREBOUND_FALLBACK)

    def test_route_admission_cannot_be_caller_constructed(self):
        binding = self.binding()
        with self.assertRaises(FailureRecoveryError):
            RecoveryRouteAdmission(
                binding, "sha256:" + "e" * 64, "sha256:" + "f" * 64,
                "sha256:" + "1" * 64, "sha256:" + "2" * 64,
            )

    def test_all_production_role_seams_reject_cross_role_fallback(self):
        for role, seam in ((FailureRole.WORKER, classify_worker_failure), (FailureRole.SUPERVISOR, classify_supervisor_failure), (FailureRole.DEPENDENCY_REVIEW, classify_dependency_review_failure)):
            self.assertEqual(seam(self.binding(role=role), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST).action, RecoveryAction.STOP_SCOPE)
        with self.assertRaises(FailureRecoveryError):
            classify_supervisor_failure(self.binding(), FailureClass.TRANSIENT_SERVICE, EvidenceSource.VERIFIED_SERVICE)

    def test_closed_record_parser_rejects_tampered_or_unknown_payload(self):
        record = classify(self.binding(), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
        payload = {"schema": "roundwright-failure-recovery/v2", "binding": {**record.binding.__dict__, "role": record.binding.role.value}, "failure": record.failure.value, "evidence": record.evidence.value, "evidence_confidence": record.evidence_confidence.value, "retryable": record.retryable, "action": record.action.value, "clearance_required": record.clearance_required}
        self.assertEqual(parse_failure_record(payload), record)
        legacy = {key: value for key, value in payload.items() if key != "evidence_confidence"}
        legacy["schema"] = "roundwright-failure-recovery/v1"
        migrated = parse_failure_record(legacy)
        self.assertEqual((migrated.record_schema, migrated.evidence_confidence), ("roundwright-failure-recovery/v1", EvidenceConfidence.UNAVAILABLE))
        payload["evidence"] = EvidenceSource.VERIFIED_SERVICE.value
        with self.assertRaisesRegex(FailureRecoveryError, "malformed"):
            parse_failure_record(payload)
        payload["evidence"] = "future-evidence"
        with self.assertRaisesRegex(FailureRecoveryError, "malformed"):
            parse_failure_record(payload)
        payload["extra"] = True
        with self.assertRaises(FailureRecoveryError):
            parse_failure_record(payload)
