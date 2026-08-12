"""Terminal-snapshot Shadow v2 provenance contracts."""

from __future__ import annotations

import unittest

from roundwright.dependency_policy import (
    CandidateBinding,
    ComponentPolicy,
    DependencyComponent,
    DependencyPolicy,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    VersionRange,
)
from roundwright.shadow import (
    AppendOnlyEvidenceStore,
    CaptureMode,
    ComparisonOutcome,
    PROVENANCE_DECISION_PROFILE,
    RecorderBinding,
    ReplayClassification,
    ShadowV2Case,
    ShadowV2Error,
    ShadowV2Observation,
    compare_provenance_decision,
    export_provenance_decision,
    replay_shadow_case,
    replay_shadow_v2_case,
    require_capture_readiness,
    shadow_evidence_profile,
    shadow_evidence_profiles,
)


def digest(value: str) -> str:
    return "sha256:" + value * 64


class ShadowV2Tests(unittest.TestCase):
    def decision(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        binding = CandidateBinding("ythdelmar68/roundwright", "task-47", candidate)
        component = ComponentPolicy(
            DependencyComponent.PACKAGE,
            "roundwright-package",
            VersionRange("1.0.0", "2.0.0"),
            "roundwright-source",
            digest("a"),
            digest("c"),
        )
        policy = DependencyPolicy(
            binding,
            digest("d"),
            100,
            60,
            (component,),
            PolicyTransition(PolicyTransitionKind.BOOTSTRAP),
        )
        observation = ObservedDependency(
            binding,
            DependencyComponent.PACKAGE,
            "roundwright-package",
            "1.0.0",
            "roundwright-source",
            digest("a"),
            digest("c"),
            101,
            digest("d"),
        )
        return export_provenance_decision(
            binding,
            policy,
            (observation,),
            base_sha="a" * 40,
            entrypoint_fingerprint=digest("e"),
            gate_identity="provenance-gate-pass",
            blocker=None,
            next_action="record-terminal-snapshot",
            ready_at=ready_at,
        )

    def case(self, *, candidate: str = "b" * 40, ready_at: int = 101) -> ShadowV2Case:
        decision = self.decision(candidate=candidate, ready_at=ready_at)
        readiness = require_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            decision,
            RecorderBinding(
                "10265c35c9d01d1fd26bd767ca3c1b245e4e9c52",
                "87094a4e780c692a00135421840c0e6713af5d35",
                "0c594caa275262164fce1942ebd2142abe0e77bb",
            ),
            AppendOnlyEvidenceStore("roundlet-provenance-retention"),
            candidate_sha=candidate,
            ready_at=ready_at,
        )
        event = ShadowV2Observation(
            1,
            "terminal-provenance-decision",
            "lifecycle-47-terminal",
            PROVENANCE_DECISION_PROFILE,
            "provenance-decision",
            None,
            False,
            candidate,
            decision.decision_digest,
        )
        return ShadowV2Case(
            "shadow-47-terminal",
            "lifecycle-47-terminal",
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            decision,
            decision,
            readiness,
            (event,),
            "phase-3-terminal-snapshot",
            "roundlet-provenance-retention",
        )

    def test_closed_profile_declares_every_capture_readiness_field(self) -> None:
        profile = shadow_evidence_profile(PROVENANCE_DECISION_PROFILE)
        self.assertEqual(shadow_evidence_profiles(), (profile,))
        self.assertEqual(profile.capture_mode, CaptureMode.TERMINAL_SNAPSHOT)
        self.assertEqual(profile.event_kinds, ("provenance-decision",))
        with self.assertRaises(ShadowV2Error):
            shadow_evidence_profile("roundwright-shadow-profile/future/v1")

    def test_terminal_snapshot_replays_without_provider_attempt_or_six_state_trace(self) -> None:
        case = self.case()
        report = replay_shadow_v2_case(case)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH))
        self.assertTrue(report.curated_summary()["read_only"])
        self.assertEqual(replay_shadow_case(case).case_digest, case.case_digest)

    def test_capture_time_is_immutable_and_candidate_movement_requires_recapture(self) -> None:
        decision = self.decision()
        self.assertEqual(compare_provenance_decision(decision, decision, ready_at=101), ComparisonOutcome.MATCH)
        self.assertEqual(compare_provenance_decision(decision, decision, ready_at=102), ComparisonOutcome.INVALID)
        with self.assertRaises(ShadowV2Error):
            require_capture_readiness(
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), decision,
                RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
                AppendOnlyEvidenceStore("roundlet-provenance-retention"),
                candidate_sha="c" * 40, ready_at=101,
            )

    def test_v2_rejects_provider_attempt_and_wrong_profile_event(self) -> None:
        case = self.case()
        with self.assertRaises(ShadowV2Error):
            ShadowV2Observation(1, "event", "lifecycle", PROVENANCE_DECISION_PROFILE, "provenance-decision", "provider-attempt", False, "b" * 40, case.decision.decision_digest)
        with self.assertRaises(ShadowV2Error):
            ShadowV2Observation(1, "event", "lifecycle", PROVENANCE_DECISION_PROFILE, "worker-loop", None, False, "b" * 40, case.decision.decision_digest)

    def test_append_only_retention_rejects_overwrite_and_reads_exact_bytes(self) -> None:
        case = self.case()
        store = AppendOnlyEvidenceStore("roundlet-provenance-retention")
        receipt = store.append(case.retention_payload())
        self.assertEqual(store.read_back(receipt), case.retention_payload())
        with self.assertRaisesRegex(ShadowV2Error, "overwrite"):
            store.append(case.retention_payload())


if __name__ == "__main__":
    unittest.main()
