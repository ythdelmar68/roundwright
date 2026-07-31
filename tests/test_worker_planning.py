"""Hermetic coverage for the bounded Phase 2 Worker planning path."""

from __future__ import annotations

import time
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
import roundwright.worker_planning as worker_planning
from roundwright.git_identity import acquire_transition_lease
from roundwright.provider_recovery import RecoveryContext, record_completed_output
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, initialize, task_projection
from roundwright.worker_planning import (
    PlanReviewReceipt,
    PlanningInput,
    WorkerPlan,
    WorkerPlanOutput,
    WorkerPlanningError,
    accept_plan_review_and_begin_implementation,
    begin_planning,
    dispatch_plan,
    read_plan,
    record_plan,
    route_plan_findings,
    submit_plan_for_review,
)


class WorkerPlanningTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        identity = object.__new__(RepositoryIdentity)
        object.__setattr__(identity, "root", root.resolve())
        return identity

    def identity(self) -> TaskIdentity:
        return TaskIdentity("task-23", "source-23", "ythdelmar68/roundwright", "codex/issue-23", "C:/private/issue-23", "a" * 40)

    def input(self) -> PlanningInput:
        return PlanningInput("Worker planning", ("No SDK",), ("Persist plan",), ("src/roundwright/worker_planning.py",), ("Run hermetic tests",), ("Schema drift",), ("Retry same thread",))

    def plan(self, *, blockers: tuple[str, ...] = ()) -> WorkerPlan:
        return WorkerPlan("Worker planning", ("No SDK",), ("src/roundwright/worker_planning.py",), ("Persist plan",), ("Run hermetic tests",), ("Schema drift",), ("Retry same thread",), blockers)

    def output(self, *, plan_attempt: str = "plan-one", provider_attempt: str = "provider-one", thread: str = "worker-thread-23", turn: str | None = None, plan: WorkerPlan | None = None) -> WorkerPlanOutput:
        return WorkerPlanOutput(plan_attempt, provider_attempt, thread, turn or f"turn-{provider_attempt}", self.input().digest, "b" * 64, self.plan() if plan is None else plan)

    def setup_task(self, root: Path):
        repository = self.repository(root)
        initialize(repository)
        identity = self.identity()
        now = int(time.time())
        lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="planning-tests", ttl_seconds=120)
        admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "b" * 64),), lease=lease)
        begin_planning(repository, identity, evidence_fingerprint="c" * 64, lease=lease)
        context = RecoveryContext.for_task(identity, candidate_sha=None, policy_fingerprint="d" * 64, deployment_fingerprint="e" * 64)
        return repository, identity, lease, context, now

    def dispatch(self, repository, identity, lease, context, now, *, plan_attempt: str = "plan-one", provider_attempt: str = "provider-one", thread: str = "worker-thread-23", parent: str | None = None, planning_input: PlanningInput | None = None):
        return dispatch_plan(
            repository, identity, context, self.input() if planning_input is None else planning_input, plan_attempt_id=plan_attempt, provider_attempt_id=provider_attempt,
            worker_thread_identity=thread, external_turn_identity=f"turn-{provider_attempt}", process_lease_id=f"lease-{provider_attempt}",
            process_lease_expires_at=now + 60, parent_plan_attempt_id=parent, lease=lease, now=now,
        )

    def test_plan_is_bound_to_source_input_attempt_and_persistent_thread(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            dispatched = self.dispatch(repository, identity, lease, context, now)
            persisted = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            self.assertEqual((dispatched.input_digest, persisted.input_digest), (self.input().digest, self.input().digest))
            self.assertEqual(persisted.source_digest, "b" * 64)
            self.assertEqual(persisted.worker_thread_identity, "worker-thread-23")
            self.assertFalse(persisted.has_true_blockers)
            self.assertEqual(read_plan(repository, identity, "plan-one"), persisted)

    def test_pid_and_pending_values_are_not_worker_thread_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            for thread in ("2345", "pid-2345", "pending", "pending-thread"):
                with self.subTest(thread=thread), self.assertRaises(WorkerPlanningError):
                    self.dispatch(repository, identity, lease, context, now, plan_attempt=f"plan-{thread}", provider_attempt=f"provider-{thread}", thread=thread)

    def test_findings_revision_keeps_the_same_worker_thread_and_each_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
            findings = route_plan_findings(repository, identity, plan_attempt_id="plan-one", findings=("Clarify tests",), lease=lease, now=now)
            self.assertEqual(len(findings), 1)
            revision = self.dispatch(repository, identity, lease, context, now, plan_attempt="plan-two", provider_attempt="provider-two", parent="plan-one")
            self.assertEqual(revision.worker_thread_identity, "worker-thread-23")
            with self.assertRaises(WorkerPlanningError):
                self.dispatch(repository, identity, lease, context, now, plan_attempt="plan-three", provider_attempt="provider-three", thread="different-thread", parent="plan-one")

    def test_revisions_reject_scope_drift_and_repeated_findings_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
            first = route_plan_findings(repository, identity, plan_attempt_id="plan-one", findings=("Clarify tests",), lease=lease, now=now)
            unrelated = PlanningInput("Unrelated scope", (), ("Other criterion",), (), ("Other test",), (), ())
            with self.assertRaisesRegex(WorkerPlanningError, "immutable task scope"):
                self.dispatch(repository, identity, lease, context, now, plan_attempt="plan-two", provider_attempt="provider-two", parent="plan-one", planning_input=unrelated)
            self.dispatch(repository, identity, lease, context, now, plan_attempt="plan-two", provider_attempt="provider-two", parent="plan-one")
            record_plan(repository, identity, context, plan_attempt_id="plan-two", output=self.output(plan_attempt="plan-two", provider_attempt="provider-two"), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-two", evidence_fingerprint="3" * 64, lease=lease)
            second = route_plan_findings(repository, identity, plan_attempt_id="plan-two", findings=("Clarify tests",), lease=lease, now=now)
            self.assertNotEqual(first, second)

    def test_owner_blocker_never_becomes_a_reviewable_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            with self.assertRaisesRegex(WorkerPlanningError, "owner input"):
                record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(plan=self.plan(blockers=("owner-security-decision",))), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            with self.assertRaises(WorkerPlanningError):
                submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)

    def test_only_an_accepted_pass_derives_done_criteria_and_enters_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            persisted = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
            with self.assertRaises(WorkerPlanningError):
                accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-one", receipt=PlanReviewReceipt("review-one", persisted.content_digest, False), evidence_fingerprint="2" * 64, lease=lease)
            completion = accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-one", receipt=PlanReviewReceipt("review-one", persisted.content_digest, True), evidence_fingerprint="3" * 64, lease=lease)
            self.assertEqual(completion.criteria, ("acceptance:Persist plan", "test:Run hermetic tests"))
            self.assertEqual(task_projection(repository, identity).state, "implementing")

    def test_accepted_pass_cannot_target_an_older_submitted_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            first = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
            route_plan_findings(repository, identity, plan_attempt_id="plan-one", findings=("Clarify tests",), lease=lease, now=now)
            self.dispatch(repository, identity, lease, context, now, plan_attempt="plan-two", provider_attempt="provider-two", parent="plan-one")
            second = record_plan(repository, identity, context, plan_attempt_id="plan-two", output=self.output(plan_attempt="plan-two", provider_attempt="provider-two"), completion_evidence_fingerprint="2" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-two", evidence_fingerprint="3" * 64, lease=lease)
            with self.assertRaisesRegex(WorkerPlanningError, "submitted review target"):
                accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-one", receipt=PlanReviewReceipt("review-one", first.content_digest, True), evidence_fingerprint="4" * 64, lease=lease)
            accepted = accept_plan_review_and_begin_implementation(repository, identity, plan_attempt_id="plan-two", receipt=PlanReviewReceipt("review-two", second.content_digest, True), evidence_fingerprint="5" * 64, lease=lease)
            self.assertEqual(accepted.plan_attempt_id, "plan-two")

    def test_dispatch_replays_an_exact_turn_after_a_post_dispatch_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            original = worker_planning.record_external_turn

            def crash_after_record(*args, **kwargs):
                original(*args, **kwargs)
                raise RuntimeError("simulated post-dispatch crash")

            with mock.patch.object(worker_planning, "record_external_turn", side_effect=crash_after_record):
                with self.assertRaisesRegex(RuntimeError, "post-dispatch crash"):
                    self.dispatch(repository, identity, lease, context, now)
            replayed = self.dispatch(repository, identity, lease, context, now)
            self.assertEqual(replayed.provider_attempt_id, "provider-one")
            self.assertEqual(self.dispatch(repository, identity, lease, context, now), replayed)
            with self.assertRaises(WorkerPlanningError):
                dispatch_plan(
                    repository, identity, context, self.input(), plan_attempt_id="plan-one", provider_attempt_id="provider-one",
                    worker_thread_identity="worker-thread-23", external_turn_identity="turn-two", process_lease_id="lease-provider-one",
                    process_lease_expires_at=now + 60, lease=lease, now=now,
                )

    def test_completed_output_binding_recovers_only_the_same_plan_after_artifact_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            output = self.output()
            # This is the durable state left by a crash after provider completion
            # commits and before the artifact transaction begins.
            record_completed_output(
                repository, identity, context, attempt_id="provider-one", output_pointer="plan:plan-one",
                completion_evidence_fingerprint="f" * 64, output_fingerprint=output.plan.digest,
                lease=lease, now=now,
            )
            recovered = record_plan(
                repository, identity, context, plan_attempt_id="plan-one", output=output,
                completion_evidence_fingerprint="f" * 64, lease=lease, now=now,
            )
            self.assertEqual(recovered.content_digest, output.plan.digest)
            with self.assertRaisesRegex(WorkerPlanningError, "committed content"):
                record_plan(
                    repository, identity, context, plan_attempt_id="plan-one",
                    output=self.output(plan=self.plan(blockers=("owner-different-decision",))),
                    completion_evidence_fingerprint="f" * 64, lease=lease, now=now,
                )

    def test_findings_routing_is_atomic_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            submit_plan_for_review(repository, identity, plan_attempt_id="plan-one", evidence_fingerprint="1" * 64, lease=lease)
            routed = route_plan_findings(repository, identity, plan_attempt_id="plan-one", findings=("Clarify tests",), lease=lease, now=now)
            self.assertEqual(task_projection(repository, identity).state, "planning")
            self.assertEqual(
                route_plan_findings(repository, identity, plan_attempt_id="plan-one", findings=("Clarify tests",), lease=lease, now=now),
                routed,
            )

    def test_output_envelope_and_recorded_replays_are_identity_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            with self.assertRaisesRegex(WorkerPlanningError, "output identity"):
                record_plan(
                    repository, identity, context, plan_attempt_id="plan-one",
                    output=self.output(turn="turn-other"), completion_evidence_fingerprint="f" * 64,
                    lease=lease, now=now,
                )
            first = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            replay = record_plan(repository, identity, context, plan_attempt_id="plan-one", output=self.output(), completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            self.assertEqual(replay, first)
            with self.assertRaisesRegex(WorkerPlanningError, "conflicts with committed content"):
                record_plan(
                    repository, identity, context, plan_attempt_id="plan-one",
                    output=self.output(plan=self.plan(blockers=("owner-security-decision",))), completion_evidence_fingerprint="f" * 64,
                    lease=lease, now=now,
                )

    def test_owner_blocker_replay_does_not_mutate_the_committed_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, identity, lease, context, now = self.setup_task(Path(temporary))
            self.dispatch(repository, identity, lease, context, now)
            blocked = self.output(plan=self.plan(blockers=("owner-security-decision",)))
            for _ in range(2):
                with self.assertRaisesRegex(WorkerPlanningError, "owner input"):
                    record_plan(repository, identity, context, plan_attempt_id="plan-one", output=blocked, completion_evidence_fingerprint="f" * 64, lease=lease, now=now)
            with self.assertRaisesRegex(WorkerPlanningError, "conflicts with committed output"):
                record_plan(
                    repository, identity, context, plan_attempt_id="plan-one",
                    output=self.output(plan=self.plan(blockers=("owner-different-decision",))), completion_evidence_fingerprint="f" * 64,
                    lease=lease, now=now,
                )


if __name__ == "__main__":
    unittest.main()
