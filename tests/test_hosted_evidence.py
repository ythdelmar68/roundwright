"""Exact-candidate hosted evidence acceptance and rejection coverage."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.hosted_evidence import HostedEvidence, HostedEvidenceError, validate_hosted_evidence


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
