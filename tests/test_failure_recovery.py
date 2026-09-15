import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.failure_recovery import (
    Clearance, EvidenceSource, FailureBinding, FailureClass, FailureRecoveryError,
    FailureRole, RecoveryAction, admit_recovery, classify,
    RecoveryRouteAdmission,
)
from roundwright.codex_worker import classify_worker_failure
from roundwright.codex_supervisor import classify_supervisor_failure
from roundwright.codex_dependency_review import classify_dependency_review_failure


class FailureRecoveryTests(unittest.TestCase):
    def binding(self, *, role=FailureRole.WORKER, session="session-1"):
        return FailureBinding("a" * 40, "sha256:" + "b" * 64, "sha256:" + "c" * 64, "workspace-write", role, "sha256:" + "d" * 64, session, "attempt-1")

    def route(self, binding):
        return RecoveryRouteAdmission(binding, "sha256:" + "e" * 64, "same-prebound-target")

    def test_denial_blocks_same_scope_across_restart_until_exact_clearance(self):
        binding = self.binding(role=FailureRole.SUPERVISOR)
        record = classify(binding, FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST)
        self.assertEqual(admit_recovery(record, binding, route=self.route(binding)), RecoveryAction.STOP_SCOPE)
        self.assertEqual(admit_recovery(record, binding, route=self.route(binding), clearance=Clearance(record.digest, binding, EvidenceSource.VERIFIED_HOST)), RecoveryAction.PREBOUND_FALLBACK)
        with self.assertRaises(FailureRecoveryError):
            admit_recovery(record, self.binding(role=FailureRole.SUPERVISOR, session="replacement"), route_equivalent=True)

    def test_prose_missing_output_and_partial_work_do_not_mint_fallback(self):
        binding = self.binding(role=FailureRole.DEPENDENCY_REVIEW)
        self.assertEqual(classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.MODEL_SELF_REPORT).action, RecoveryAction.RECONCILE)
        self.assertEqual(classify(binding, FailureClass.MISSING_OUTPUT, EvidenceSource.UNAVAILABLE).action, RecoveryAction.RECONCILE)
        self.assertEqual(classify(binding, FailureClass.PARTIAL_INCREMENT, EvidenceSource.VERIFIED_OUTPUT).action, RecoveryAction.CONTINUE_SAME_SESSION)

    def test_only_verified_terminal_or_transient_fault_uses_prebound_equivalent_route(self):
        binding = self.binding()
        ended = classify(binding, FailureClass.SESSION_TERMINATED, EvidenceSource.VERIFIED_LIFECYCLE)
        transient = classify(binding, FailureClass.TRANSIENT_SERVICE, EvidenceSource.VERIFIED_SERVICE)
        self.assertEqual(admit_recovery(ended, binding, route=self.route(binding)), RecoveryAction.PREBOUND_FALLBACK)
        self.assertEqual(admit_recovery(transient, binding, route=self.route(binding)), RecoveryAction.PREBOUND_FALLBACK)

    def test_all_production_role_seams_reject_cross_role_fallback(self):
        for role, seam in ((FailureRole.WORKER, classify_worker_failure), (FailureRole.SUPERVISOR, classify_supervisor_failure), (FailureRole.DEPENDENCY_REVIEW, classify_dependency_review_failure)):
            self.assertEqual(seam(self.binding(role=role), FailureClass.HOST_SECURITY_DENIAL, EvidenceSource.VERIFIED_HOST).action, RecoveryAction.STOP_SCOPE)
        with self.assertRaises(FailureRecoveryError):
            classify_supervisor_failure(self.binding(), FailureClass.TRANSIENT_SERVICE, EvidenceSource.VERIFIED_SERVICE)
