"""Exact-candidate hosted evidence acceptance and rejection coverage."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.hosted_evidence import (
    FakeHostedCheckAdapter,
    HostedCheck,
    HostedCheckAdapter,
    HostedCheckEvidence,
    HostedCheckPolicy,
    HostedCheckState,
    HostedEvidence,
    HostedEvidenceError,
    HostedEvidenceOutcome,
    HostedWorkflowJob,
    HostedWorkflowRun,
    evaluate_hosted_check_evidence,
    validate_hosted_evidence,
)


class HostedEvidenceTests(unittest.TestCase):
    repository = "ythdelmar68/roundwright"
    workflow = "CI"
    head = "a" * 40
    branch = "codex/issue-10-cross-platform-install-verification"

    def record(self, **changes: object) -> HostedEvidence:
        values: dict[str, object] = {
            "repository": self.repository,
            "workflow": self.workflow,
            "head_sha": self.head,
            "ref": f"refs/heads/{self.branch}",
            "artifacts": (("roundwright-0.0.0-py3-none-any.whl", "b" * 64), ("roundwright-0.0.0.tar.gz", "c" * 64)),
        }
        values.update(changes)
        return HostedEvidence(**values)  # type: ignore[arg-type]

    def validate(self, *records: HostedEvidence) -> HostedEvidence:
        return validate_hosted_evidence(records, repository=self.repository, workflow=self.workflow, head_sha=self.head, branch=self.branch)

    def test_exact_branch_candidate_and_artifacts_are_accepted(self) -> None:
        self.assertEqual(self.validate(self.record()).head_sha, self.head)

    def test_missing_duplicate_merge_ref_wrong_repository_workflow_and_stale_head_fail_closed(self) -> None:
        cases = (
            ((), "missing"),
            ((self.record(), self.record()), "duplicate"),
            ((self.record(ref="refs/pull/10/merge"),), "branch"),
            ((self.record(repository="other/repository"),), "different repository"),
            ((self.record(workflow="release"),), "different workflow"),
            ((self.record(head_sha="d" * 40),), "stale"),
        )
        for records, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(HostedEvidenceError, message):
                self.validate(*records)

    def test_duplicate_names_and_invalid_artifact_digest_fail_closed(self) -> None:
        for artifacts in (
            (("wheel", "b" * 64), ("wheel", "c" * 64)),
            (("wheel", "not-a-digest"),),
            (("roundwright-0.0.0-py3-none-any.whl", "b" * 64),),
        ):
            with self.subTest(artifacts=artifacts), self.assertRaisesRegex(HostedEvidenceError, "artifact"):
                self.validate(self.record(artifacts=artifacts))

    def test_malformed_untrusted_record_values_fail_closed(self) -> None:
        for changes in (
            {"ref": None},
            {"artifacts": (("wheel",),)},
            {"artifacts": "not-artifacts"},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(HostedEvidenceError, "invalid"):
                self.validate(self.record(**changes))


class HostedCheckEvidenceTests(unittest.TestCase):
    repository = "ythdelmar68/roundwright"
    workflow = "CI"
    candidate = "a" * 40
    branch = "codex/issue-48-hosted-check-evidence"
    now = 2_000

    def evidence(self, **changes: object) -> HostedCheckEvidence:
        values: dict[str, object] = {
            "repository": self.repository,
            "workflow": self.workflow,
            "candidate_sha": self.candidate,
            "branch": self.branch,
            "observed_at": self.now,
            "checks": (HostedCheck("check-1", "suite-1", "unit", HostedCheckState.SUCCESS, self.candidate, self.candidate),),
            "workflow_runs": (HostedWorkflowRun("run-1", self.workflow, HostedCheckState.SUCCESS, self.candidate, f"refs/heads/{self.branch}", (HostedWorkflowJob("job-1", "unit", HostedCheckState.SUCCESS, self.candidate),)),),
            "artifacts": (("build-manifest", "b" * 64),),
        }
        values.update(changes)
        return HostedCheckEvidence(**values)  # type: ignore[arg-type]

    def policy(self, **changes: object) -> HostedCheckPolicy:
        values: dict[str, object] = {
            "required_checks": ("unit",), "required_artifacts": ("build-manifest",), "max_age_seconds": 60,
        }
        values.update(changes)
        return HostedCheckPolicy(**values)  # type: ignore[arg-type]

    def evaluate(self, evidence: HostedCheckEvidence, **changes: object):
        values: dict[str, object] = {"repository": self.repository, "workflow": self.workflow, "candidate_sha": self.candidate, "branch": self.branch, "policy": self.policy(), "now": self.now}
        values.update(changes)
        return evaluate_hosted_check_evidence(evidence, **values)  # type: ignore[arg-type]

    def test_exact_candidate_workflow_jobs_and_artifacts_pass(self) -> None:
        result = self.evaluate(self.evidence())
        self.assertEqual(result.outcome, HostedEvidenceOutcome.PASS)
        self.assertEqual(result.observed_checks, ("unit",))
        self.assertRegex(result.evidence_digest, r"^[0-9a-f]{64}$")

    def test_non_terminal_and_terminal_check_states_are_distinct(self) -> None:
        outcomes = {
            HostedCheckState.QUEUED: HostedEvidenceOutcome.QUEUED,
            HostedCheckState.IN_PROGRESS: HostedEvidenceOutcome.IN_PROGRESS,
            HostedCheckState.FAILURE: HostedEvidenceOutcome.FAILURE,
            HostedCheckState.CANCELLED: HostedEvidenceOutcome.CANCELLED,
            HostedCheckState.SKIPPED: HostedEvidenceOutcome.SKIPPED,
            HostedCheckState.NEUTRAL: HostedEvidenceOutcome.NEUTRAL,
        }
        for state, expected in outcomes.items():
            with self.subTest(state=state):
                check = HostedCheck("check-1", "suite-1", "unit", state, self.candidate, self.candidate)
                self.assertEqual(self.evaluate(self.evidence(checks=(check,))).outcome, expected)

    def test_missing_required_check_is_a_typed_non_pass_result(self) -> None:
        result = self.evaluate(self.evidence(), policy=self.policy(required_checks=("lint",)))
        self.assertEqual(result.outcome, HostedEvidenceOutcome.MISSING)

    def test_wrong_identity_staleness_merge_ref_and_checkout_attestations_fail_closed(self) -> None:
        invalid = (
            ("repository", "other/repository", "different repository"),
            ("workflow", "release", "different workflow"),
            ("candidate_sha", "d" * 40, "stale for the candidate"),
            ("branch", "refs/pull/48/merge", "candidate branch"),
            ("observed_at", self.now - 61, "stale"),
        )
        for field, value, message in invalid:
            with self.subTest(field=field), self.assertRaisesRegex(HostedEvidenceError, message):
                self.evaluate(self.evidence(**{field: value}))
        bad_check = HostedCheck("check-1", "suite-1", "unit", HostedCheckState.SUCCESS, self.candidate, "b" * 40)
        with self.assertRaisesRegex(HostedEvidenceError, "malformed"):
            self.evaluate(self.evidence(checks=(bad_check,)))
        bad_job = HostedWorkflowJob("job-1", "unit", HostedCheckState.SUCCESS, "b" * 40)
        bad_run = HostedWorkflowRun("run-1", self.workflow, HostedCheckState.SUCCESS, self.candidate, f"refs/heads/{self.branch}", (bad_job,))
        with self.assertRaisesRegex(HostedEvidenceError, "malformed"):
            self.evaluate(self.evidence(workflow_runs=(bad_run,)))

    def test_shared_suites_are_allowed_but_duplicate_runs_names_jobs_and_artifacts_fail_closed(self) -> None:
        duplicate_suite = HostedCheck("check-2", "suite-1", "lint", HostedCheckState.SUCCESS, self.candidate, self.candidate)
        self.assertEqual(self.evaluate(self.evidence(checks=(self.evidence().checks[0], duplicate_suite)), policy=self.policy(required_checks=("lint", "unit"))).outcome, HostedEvidenceOutcome.PASS)
        duplicate_name = HostedCheck("check-3", "suite-1", "unit", HostedCheckState.SUCCESS, self.candidate, self.candidate)
        with self.assertRaisesRegex(HostedEvidenceError, "duplicate"):
            self.evaluate(self.evidence(checks=(self.evidence().checks[0], duplicate_name)))
        duplicate_run = self.evidence().workflow_runs[0]
        with self.assertRaisesRegex(HostedEvidenceError, "duplicate"):
            self.evaluate(self.evidence(workflow_runs=(duplicate_run, duplicate_run)))
        duplicate_job = HostedWorkflowJob("job-2", "unit", HostedCheckState.SUCCESS, self.candidate)
        duplicate_job_run = HostedWorkflowRun("run-1", self.workflow, HostedCheckState.SUCCESS, self.candidate, f"refs/heads/{self.branch}", (self.evidence().workflow_runs[0].jobs[0], duplicate_job))
        with self.assertRaisesRegex(HostedEvidenceError, "duplicate"):
            self.evaluate(self.evidence(workflow_runs=(duplicate_job_run,)))
        with self.assertRaisesRegex(HostedEvidenceError, "duplicate"):
            self.evaluate(self.evidence(artifacts=(("build-manifest", "b" * 64), ("build-manifest", "c" * 64))))

    def test_every_non_success_job_state_prevents_pass_and_terminal_conflicts_fail_closed(self) -> None:
        outcomes = {
            HostedCheckState.QUEUED: HostedEvidenceOutcome.QUEUED,
            HostedCheckState.IN_PROGRESS: HostedEvidenceOutcome.IN_PROGRESS,
            HostedCheckState.FAILURE: HostedEvidenceOutcome.FAILURE,
            HostedCheckState.CANCELLED: HostedEvidenceOutcome.CANCELLED,
            HostedCheckState.SKIPPED: HostedEvidenceOutcome.SKIPPED,
            HostedCheckState.NEUTRAL: HostedEvidenceOutcome.NEUTRAL,
        }
        for state, expected in outcomes.items():
            with self.subTest(state=state):
                job = HostedWorkflowJob("job-1", "unit", state, self.candidate)
                run = HostedWorkflowRun("run-1", self.workflow, state, self.candidate, f"refs/heads/{self.branch}", (job,))
                self.assertEqual(self.evaluate(self.evidence(workflow_runs=(run,))).outcome, expected)
        conflicting = HostedWorkflowRun("run-1", self.workflow, HostedCheckState.SUCCESS, self.candidate, f"refs/heads/{self.branch}", (HostedWorkflowJob("job-1", "unit", HostedCheckState.FAILURE, self.candidate),))
        with self.assertRaisesRegex(HostedEvidenceError, "conflict"):
            self.evaluate(self.evidence(workflow_runs=(conflicting,)))

    def test_fake_adapter_is_deterministic_and_real_adapter_is_disabled_by_default(self) -> None:
        evidence = self.evidence()
        fake = FakeHostedCheckAdapter(evidence)
        self.assertIs(fake.read(repository=self.repository, workflow=self.workflow, candidate_sha=self.candidate, branch=self.branch), evidence)
        self.assertEqual(fake.calls, [(self.repository, self.workflow, self.candidate, self.branch)])
        with self.assertRaisesRegex(HostedEvidenceError, "disabled"):
            HostedCheckAdapter().read(repository=self.repository, workflow=self.workflow, candidate_sha=self.candidate, branch=self.branch)
