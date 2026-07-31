import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import roundwright.plan_review as plan_review
from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import acquire_transition_lease
from roundwright.plan_review import (
    PlanReviewError,
    PlanReviewOutput,
    PlanReviewState,
    PlanReviewVerdict,
    dispatch_plan_review,
    read_plan_review,
    record_plan_review,
    recover_plan_review,
)
from roundwright.provider_recovery import AttemptState, RecoveryContext, read_attempt
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize, task_projection
from roundwright.worker_planning import (
    PlanReviewReceipt,
    PlanningInput,
    WorkerPlan,
    WorkerPlanOutput,
    accept_plan_review_and_begin_implementation,
    begin_planning,
    dispatch_plan,
    record_plan,
    submit_plan_for_review,
)


class PlanReviewTests(unittest.TestCase):
    def repository(self, root):
        identity = object.__new__(RepositoryIdentity)
        object.__setattr__(identity, "root", root.resolve())
        return identity

    def setup(self, root):
        repository = self.repository(root)
        initialize(repository)
        identity = TaskIdentity("task-24", "source-24", "ythdelmar68/roundwright", "codex/issue-24", "C:/private/issue-24", "a" * 40)
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="review-tests", ttl_seconds=120)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        begin_planning(repository, identity, evidence_fingerprint="c" * 64, lease=lease)
        context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="d" * 64, deployment_fingerprint="e" * 64)
        now = int(time.time())
        input_value = PlanningInput("Review plan", (), ("Persist review",), (), ("Run tests",), (), ())
        plan = WorkerPlan("Review plan", (), (), ("Persist review",), ("Run tests",), (), (), ())
        dispatch_plan(repository, identity, context, input_value, plan_attempt_id="plan-one", provider_attempt_id="worker-one", worker_thread_identity="worker-thread-24", external_turn_identity="worker-turn-one", process_lease_id="worker-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        persisted = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=WorkerPlanOutput("plan-one", "worker-one", "worker-thread-24", "worker-turn-one", input_value.digest, "b" * 64, plan), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
        submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
        return repository, identity, lease, context, now, persisted

    def dispatch(self, repository, identity, lease, context, now, persisted, *, review="review-one", provider="supervisor-one", session="supervisor-session-one"):
        return dispatch_plan_review(repository, identity, context, review_attempt_id=review, provider_attempt_id=provider, supervisor_session_identity=session, external_turn_identity=f"turn-{provider}", plan_attempt_id=persisted.plan_attempt_id, process_lease_id=f"lease-{provider}", process_lease_expires_at=now + 60, lease=lease, now=now)

    def output(self, dispatch, *, verdict=PlanReviewVerdict.PASS, plan_digest=None, findings=(), missing=(), ambiguous=(), risks=()):
        return PlanReviewOutput(dispatch.review_attempt_id, dispatch.provider_attempt_id, dispatch.supervisor_session_identity, dispatch.external_turn_identity, dispatch.plan_attempt_id, dispatch.source_digest, plan_digest or dispatch.plan_digest, verdict, findings, missing, ambiguous, risks)

    def test_pass_is_identity_bound_and_only_accepted_pass_enters_implementation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            review = record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            self.assertEqual(review.verdict, PlanReviewVerdict.PASS)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.ACCEPTED)
            completion = accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-one", receipt=PlanReviewReceipt("review-one", persisted.content_digest, True), evidence_fingerprint="3" * 64, lease=lease)
            self.assertEqual(completion.plan_digest, persisted.content_digest)
            self.assertEqual(task_projection(repository, identity).state, "implementing")

    def test_findings_route_to_the_same_worker_thread_and_pass_cannot_contain_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            review = record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch, verdict=PlanReviewVerdict.FINDINGS, findings=("Clarify scope",), missing=("Exercise drift",), risks=("Stale pass",)), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            self.assertEqual(review.routed_finding_ids.__len__(), 3)
            self.assertEqual(task_projection(repository, identity).state, "planning")
            with self.assertRaises(PlanReviewError):
                self.output(dispatch, findings=("unexpected",)).normalized()

    def test_malformed_or_stale_output_is_an_invalid_provider_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            with self.assertRaisesRegex(PlanReviewError, "identity"):
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch, plan_digest="0" * 64), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.AMBIGUOUS)

    def test_restart_invalidates_partial_pass_and_requires_a_fresh_session(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            with mock.patch.object(plan_review, "accept_supervisor_review"):
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            recovered = recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            self.assertEqual(recovered.state, PlanReviewState.INVALIDATED)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.INVALIDATED)
            next_dispatch = self.dispatch(repository, identity, lease, context, now, persisted, review="review-two", provider="supervisor-two", session="supervisor-session-two")
            self.assertNotEqual(next_dispatch.supervisor_session_identity, dispatch.supervisor_session_identity)


if __name__ == "__main__":
    unittest.main()
