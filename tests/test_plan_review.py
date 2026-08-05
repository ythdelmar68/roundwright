import os
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import roundwright.plan_review as plan_review
from roundwright.configuration import RepositoryIdentity
from roundwright.runtime_binding import RuntimeBinding
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
from roundwright.provider_recovery import AttemptState, ProviderRole, RecoveryContext, read_attempt
from roundwright.state import SourceSnapshot, TaskIdentity, _open_writable_connection, admit_task, initialize, task_projection
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
from tests.provider_health_fixture import provider_context, runtime_binding


class PlanReviewTests(unittest.TestCase):
    def runtime_binding(self) -> RuntimeBinding:
        return runtime_binding()

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
        context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="d" * 64, deployment_fingerprint="e" * 64, runtime_binding=self.runtime_binding())
        now = int(time.time())
        input_value = PlanningInput("Review plan", (), ("Persist review",), (), ("Run tests",), (), ())
        plan = WorkerPlan("Review plan", (), (), ("Persist review",), ("Run tests",), (), (), ())
        dispatch_plan(repository, identity, provider_context(context, identity, ProviderRole.PLANNING), input_value, plan_attempt_id="plan-one", provider_attempt_id="worker-one", worker_thread_identity="worker-thread-24", external_turn_identity="worker-turn-one", process_lease_id="worker-lease", process_lease_expires_at=now + 60, lease=lease, now=now)
        persisted = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=WorkerPlanOutput("plan-one", "worker-one", "worker-thread-24", "worker-turn-one", input_value.digest, "b" * 64, plan), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
        submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
        return repository, identity, lease, context, now, persisted

    def dispatch(self, repository, identity, lease, context, now, persisted, *, review="review-one", provider="supervisor-one", session="supervisor-session-one"):
        return dispatch_plan_review(repository, identity, provider_context(context, identity, ProviderRole.SUPERVISOR), review_attempt_id=review, provider_attempt_id=provider, supervisor_session_identity=session, external_turn_identity=f"turn-{provider}", plan_attempt_id=persisted.plan_attempt_id, process_lease_id=f"lease-{provider}", process_lease_expires_at=now + 60, lease=lease, now=now)

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
            with mock.patch.object(plan_review, "_accept_pass_atomically"):
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            connection = _open_writable_connection(repository)
            try:
                evidence = connection.execute("SELECT completion_evidence_fingerprint FROM provider_attempts WHERE attempt_id = ?", (dispatch.provider_attempt_id,)).fetchone()[0]
                connection.execute("UPDATE provider_attempts SET accepted_review_identity = ?, state = 'accepted' WHERE attempt_id = ?", (dispatch.review_attempt_id, dispatch.provider_attempt_id))
                connection.execute("INSERT INTO accepted_provider_reviews(accepted_review_identity, task_id, attempt_id, completion_evidence_fingerprint, configuration_schema_version, configuration_digest, worker_profile_identity, supervisor_profile_identities) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (dispatch.review_attempt_id, identity.task_id, dispatch.provider_attempt_id, evidence, *context.runtime_binding.columns()))
                connection.commit()
            finally:
                connection.close()
            for field, value in (
                ("repository_fingerprint", "0" * 64), ("worktree_fingerprint", "1" * 64),
                ("branch_fingerprint", "2" * 64), ("base_fingerprint", "3" * 64),
                ("candidate_fingerprint", "4" * 64), ("policy_fingerprint", "5" * 64),
                ("deployment_fingerprint", "6" * 64),
            ):
                with self.subTest(field=field), self.assertRaisesRegex(PlanReviewError, "context has drifted"):
                    recover_plan_review(repository, identity, replace(context, **{field: value}), review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            recovered = recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            self.assertEqual(recovered.state, PlanReviewState.RECORDED)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.ACCEPTED)
            completion = accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-one", receipt=PlanReviewReceipt("review-one", persisted.content_digest, True), evidence_fingerprint="3" * 64, lease=lease)
            self.assertEqual(completion.plan_attempt_id, "plan-one")

    def test_dispatch_replay_finishes_after_the_provider_turn_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            with mock.patch.object(plan_review, "_persist_dispatch", side_effect=RuntimeError("crash after turn")):
                with self.assertRaisesRegex(RuntimeError, "crash after turn"):
                    self.dispatch(repository, identity, lease, context, now, persisted)
            self.assertEqual(task_projection(repository, identity).state, "plan-review")
            connection = _open_writable_connection(repository)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT state, external_turn_identity FROM provider_attempts WHERE attempt_id = ?",
                        ("supervisor-one",),
                    ).fetchone(),
                    ("dispatched", "turn-supervisor-one"),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM plan_review_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (0,),
                )
            finally:
                connection.close()
            replay = self.dispatch(repository, identity, lease, context, now, persisted)
            attempt = read_attempt(repository, identity, replay.provider_attempt_id)
            self.assertEqual(attempt.state, AttemptState.DISPATCHED)
            self.assertEqual((attempt.session_identity, attempt.external_turn_identity), (replay.supervisor_session_identity, replay.external_turn_identity))
            connection = _open_writable_connection(repository)
            try:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM provider_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (2,),
                )
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM plan_review_attempts WHERE task_id = ?", (identity.task_id,)).fetchone(),
                    (1,),
                )
            finally:
                connection.close()

    def test_findings_recovery_replays_only_missing_routing_checkpoints(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            output = self.output(dispatch, verdict=PlanReviewVerdict.FINDINGS, findings=("  Zulu   Item  ", "Zulu Item", "  Alpha  "))
            with mock.patch.object(plan_review, "route_plan_findings", side_effect=RuntimeError("crash before transition")):
                with self.assertRaisesRegex(RuntimeError, "crash before transition"):
                    record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=output, completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            recovered = recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            self.assertEqual(recovered.verdict, PlanReviewVerdict.FINDINGS)
            self.assertEqual(task_projection(repository, identity).state, "planning")
            self.assertEqual(recovered.routed_finding_ids, plan_review._finding_ids(identity, "plan-one", ("finding:Alpha", "finding:Zulu Item")))

        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            output = self.output(dispatch, verdict=PlanReviewVerdict.FINDINGS, findings=("  Zulu   Item  ", "Zulu Item", "  Alpha  "))
            with mock.patch.object(plan_review, "_persist_route", side_effect=RuntimeError("crash after transition")):
                with self.assertRaisesRegex(RuntimeError, "crash after transition"):
                    record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=output, completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            recovered = recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            self.assertEqual(recovered.verdict, PlanReviewVerdict.FINDINGS)
            self.assertEqual(recovered.routed_finding_ids, plan_review._finding_ids(identity, "plan-one", ("finding:Alpha", "finding:Zulu Item")))

    def test_oversized_tagged_finding_is_rejected_before_completion_or_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            output = self.output(dispatch, verdict=PlanReviewVerdict.FINDINGS, findings=("x" * 2000,))
            with self.assertRaisesRegex(PlanReviewError, "routing data is invalid"):
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=output, completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.AMBIGUOUS)
            connection = _open_writable_connection(repository)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM plan_review_artifacts WHERE review_attempt_id = ?", (dispatch.review_attempt_id,)).fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT state FROM plan_review_attempts WHERE review_attempt_id = ?", (dispatch.review_attempt_id,)).fetchone()[0], PlanReviewState.INVALIDATED.value)
            finally:
                connection.close()

    def test_findings_recovery_requires_the_exact_completed_output_binding(self):
        for binding in (None, "0" * 64):
            with self.subTest(binding=binding), tempfile.TemporaryDirectory() as temporary:
                repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
                dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
                output = self.output(dispatch, verdict=PlanReviewVerdict.FINDINGS, findings=("Zulu", "Alpha"))
                with mock.patch.object(plan_review, "route_plan_findings", side_effect=RuntimeError("crash before transition")):
                    with self.assertRaisesRegex(RuntimeError, "crash before transition"):
                        record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=output, completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
                connection = _open_writable_connection(repository)
                try:
                    if binding is None:
                        connection.execute("DELETE FROM provider_completion_outputs WHERE attempt_id = ?", (dispatch.provider_attempt_id,))
                    else:
                        connection.execute("UPDATE provider_completion_outputs SET output_fingerprint = ? WHERE attempt_id = ?", (binding, dispatch.provider_attempt_id))
                    connection.commit()
                finally:
                    connection.close()
                with self.assertRaisesRegex(PlanReviewError, "output binding"):
                    recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
                self.assertEqual(task_projection(repository, identity).state, "plan-review")

    def test_restart_invalidates_an_unaccepted_partial_pass_before_fresh_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
            with mock.patch.object(plan_review, "_accept_pass_atomically"):
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            recovered = recover_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, lease=lease, now=now)
            self.assertEqual(recovered.state, PlanReviewState.INVALIDATED)
            self.assertEqual(read_attempt(repository, identity, dispatch.provider_attempt_id).state, AttemptState.INVALIDATED)
            next_dispatch = self.dispatch(repository, identity, lease, context, now, persisted, review="review-two", provider="supervisor-two", session="supervisor-session-two")
            self.assertNotEqual(next_dispatch.supervisor_session_identity, dispatch.supervisor_session_identity)

    def test_review_path_uses_no_process_or_credential_access_and_cannot_implement(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now, persisted = self.setup(Path(temporary))
            with mock.patch.dict(os.environ, {"SUPERVISOR_TEST_CREDENTIAL": "secret"}, clear=True), \
                 mock.patch("os.getenv", side_effect=AssertionError("credential access")), \
                 mock.patch.object(subprocess, "run", side_effect=AssertionError("process access")):
                dispatch = self.dispatch(repository, identity, lease, context, now, persisted)
                record_plan_review(repository, identity, context, review_attempt_id=dispatch.review_attempt_id, output=self.output(dispatch), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            self.assertEqual(task_projection(repository, identity).state, "plan-review")


if __name__ == "__main__":
    unittest.main()
