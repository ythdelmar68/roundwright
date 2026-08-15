"""Provider-attempt V2 descriptor and opaque-resource boundary coverage."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import CandidateSeal, TransitionLease, WorktreeBinding
from roundwright.provider_attempt_runtime import (
    ProviderAttemptRuntimeDescriptor, ProviderAttemptRuntimeError,
    ProviderAttemptRuntimeResources,
)
from roundwright.provider_recovery import RecoveryContext
from roundwright.runtime_binding import RuntimeBinding
from roundwright.state import TaskIdentity


def digest(character: str) -> str:
    return "sha256:" + character * 64


class _Runner:
    def execute(self) -> tuple[str, ...]:
        return ("attempt-1",)


class ProviderAttemptRuntimeTests(unittest.TestCase):
    def descriptor_payload(self) -> dict[str, object]:
        policy = {
            "complete_rounds": 1,
            "max_rounds": 2,
            "max_supervisor_attempts_per_round": 1,
            "on_final_findings": "worker-final-repair-then-merge",
        }
        binding = RuntimeBinding(
            "roundwright-runtime/v1", digest("1"), digest("2"), (digest("3"),),
            1, 2, 1, "worker-final-repair-then-merge",
            hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        )
        return {
            "schema": "roundwright-provider-attempt-runtime/v2",
            "resource_id": "runtime-45",
            "repository_id": "ythdelmar68/roundwright",
            "task_id": "task-45",
            "source_digest": digest("5"),
            "base_sha": "a" * 40,
            "candidate_sha": "b" * 40,
            "case_id": "provider-case-45",
            "ready_at": 17,
            "capture_plan_digest": digest("6"),
            "runtime_binding": binding.canonical_material(),
            "provider_profile_identity": digest("3"),
            "review_epoch": 1,
            "review_round": 1,
        }

    def resources(self, descriptor: ProviderAttemptRuntimeDescriptor) -> ProviderAttemptRuntimeResources:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", ROOT)
        identity = TaskIdentity("task-45", "source-45", "ythdelmar68/roundwright", "codex/task-45", str(ROOT), "a" * 40)
        binding = RuntimeBinding.from_canonical(descriptor.runtime_binding)
        recovery = RecoveryContext.for_task(
            identity, candidate_sha="b" * 40, policy_fingerprint="7" * 64,
            deployment_fingerprint="8" * 64, runtime_binding=binding,
        )
        lease = TransitionLease(identity.repository_id, "state-45", "worker-45", 1, 2**31)
        return ProviderAttemptRuntimeResources(
            repository, identity, recovery, lease,
            CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity),
            WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, ROOT, identity.base_sha, lease.state_identity),
            descriptor.source_digest, descriptor.case_id, descriptor.ready_at, descriptor.capture_plan_digest,
            descriptor.provider_profile_identity, descriptor.review_epoch, descriptor.review_round, _Runner(),
        )

    def test_descriptor_accepts_only_the_closed_json_shape_and_real_anchors(self) -> None:
        descriptor = ProviderAttemptRuntimeDescriptor.parse(self.descriptor_payload())
        self.assertEqual(descriptor.candidate_sha, "b" * 40)
        self.assertEqual(descriptor.capture_plan_digest, digest("6"))
        for field, value in (("candidate_sha", "b" * 40 + "x"), ("capture_plan_digest", digest("6") + "x"), ("resource_id", "runtime\\45"), ("ready_at", True)):
            payload = self.descriptor_payload()
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(ProviderAttemptRuntimeError):
                ProviderAttemptRuntimeDescriptor.parse(payload)
        for forbidden in ("provider_outcomes", "event_history", "provider_output", "factory"):
            payload = self.descriptor_payload()
            payload[forbidden] = "not-allowed"
            with self.subTest(forbidden=forbidden), self.assertRaises(ProviderAttemptRuntimeError):
                ProviderAttemptRuntimeDescriptor.parse(payload)

    def test_every_descriptor_and_resource_binding_drifts_before_store_access(self) -> None:
        descriptor = ProviderAttemptRuntimeDescriptor.parse(self.descriptor_payload())
        resources = self.resources(descriptor)
        replacements = {
            "repository_id": "ythdelmar68/other", "task_id": "task-46", "source_digest": digest("9"),
            "base_sha": "c" * 40, "candidate_sha": "d" * 40, "case_id": "provider-case-46",
            "ready_at": 18, "capture_plan_digest": digest("a"),
            "review_epoch": 2, "review_round": 2,
        }
        for field, replacement in replacements.items():
            payload = self.descriptor_payload()
            payload[field] = replacement
            drifted = ProviderAttemptRuntimeDescriptor.parse(payload)
            with self.subTest(field=field), self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
                resources.validate(drifted)
        payload = self.descriptor_payload()
        alternate = RuntimeBinding.from_canonical(payload["runtime_binding"])
        payload["runtime_binding"] = RuntimeBinding(
            alternate.schema_version, alternate.resolved_digest, alternate.worker_profile_identity, (digest("2"),),
            alternate.review_complete_rounds, alternate.review_max_rounds,
            alternate.review_max_supervisor_attempts_per_round, alternate.review_on_final_findings,
            alternate.review_policy_digest,
        ).canonical_material()
        payload["provider_profile_identity"] = digest("2")
        with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
            resources.validate(ProviderAttemptRuntimeDescriptor.parse(payload))
        payload = self.descriptor_payload()
        payload["runtime_binding"] = payload["runtime_binding"].replace(digest("1"), digest("f"))
        with self.assertRaisesRegex(ProviderAttemptRuntimeError, "drifted"):
            resources.validate(ProviderAttemptRuntimeDescriptor.parse(payload))


if __name__ == "__main__":
    unittest.main()
