"""Terminal-snapshot Shadow v2 provenance contracts."""

from __future__ import annotations

import unittest
from dataclasses import replace

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
    CandidateCommitReference,
    ComparisonOutcome,
    EvidenceRole,
    FormalReviewRoundReference,
    LifecycleAttempt,
    LifecycleAttemptKind,
    PROVENANCE_DECISION_PROFILE,
    ProviderAttemptManifest,
    RecorderBinding,
    ReplayClassification,
    ShadowEvidenceProfile,
    ShadowProducer,
    ShadowV2Case,
    ShadowV2Error,
    ShadowV2Event,
    ShadowV2EventGraph,
    ShadowV2Observation,
    AcceptedResultReference,
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

    def lifecycle_profile(self) -> ShadowEvidenceProfile:
        return ShadowEvidenceProfile(
            "roundwright-shadow-profile/test-lifecycle/v1",
            CaptureMode.LIFECYCLE_GRAPH,
            ShadowProducer.PROFILE_DEFINED,
            "typed-graph-ready",
            "before-profile-events",
            "append-only-readback",
            "fresh-candidate-recapture",
            ("worker-dispatch", "supervisor-review", "worker-repair", "accepted-result", "lifecycle-note"),
            1,
            1,
            True,
        )

    def lifecycle_graph(self) -> ShadowV2EventGraph:
        candidate = "b" * 40
        return ShadowV2EventGraph(
            (
                LifecycleAttempt("worker-1", 1, LifecycleAttemptKind.WORKER, EvidenceRole.WORKER),
                LifecycleAttempt("supervisor-1", 2, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-1", "round-1"),
                LifecycleAttempt("worker-repair-2", 3, LifecycleAttemptKind.REPAIR, EvidenceRole.WORKER, "supervisor-1", None, candidate),
                LifecycleAttempt("supervisor-2", 4, LifecycleAttemptKind.SUPERVISOR, EvidenceRole.SUPERVISOR, "worker-repair-2", "round-2"),
            ),
            (
                ProviderAttemptManifest("provider-primary-1", "worker-1", 1, "provider-primary", "failed"),
                ProviderAttemptManifest("provider-failover-1", "worker-1", 2, "provider-failover", "ready"),
            ),
            (
                FormalReviewRoundReference("round-1", 1, candidate),
                FormalReviewRoundReference("round-2", 2, candidate, "accepted-2"),
            ),
            (CandidateCommitReference(candidate, "worker-repair-commit"),),
            (AcceptedResultReference("accepted-2", "round-2", "event-5", candidate),),
            (
                ShadowV2Event("event-1", 1, "worker-1", "worker-dispatch", "provider-primary-1", True),
                ShadowV2Event("event-2", 2, "worker-1", "worker-dispatch", "provider-failover-1", True),
                ShadowV2Event("event-3", 3, "supervisor-1", "supervisor-review", None, False, "round-1"),
                ShadowV2Event("event-4", 4, "worker-repair-2", "worker-repair", None, False, None, candidate),
                ShadowV2Event("event-5", 5, "supervisor-2", "accepted-result", None, False, "round-2", None, "accepted-2"),
                ShadowV2Event("event-6", 6, "supervisor-2", "lifecycle-note", None, False),
            ),
        )

    def lifecycle_case(self, graph: ShadowV2EventGraph | None = None) -> ShadowV2Case:
        decision = self.decision()
        profile = self.lifecycle_profile()
        readiness = require_capture_readiness(
            profile, decision,
            RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
            AppendOnlyEvidenceStore("roundlet-provenance-retention"), candidate_sha="b" * 40, ready_at=101,
        )
        return ShadowV2Case(
            "shadow-47-lifecycle", "lifecycle-47", profile, decision, decision, readiness,
            (), "phase-3-lifecycle", "roundlet-provenance-retention", event_graph=self.lifecycle_graph() if graph is None else graph,
        )

    def test_generic_graph_separates_lifecycle_provider_review_commit_and_result(self) -> None:
        case = self.lifecycle_case()
        graph = case.event_graph
        self.assertIsNotNone(graph)
        self.assertEqual([item.attempt_id for item in graph.attempts], ["worker-1", "supervisor-1", "worker-repair-2", "supervisor-2"])
        self.assertEqual(graph.provider_attempts[1].provider_identity, "provider-failover")
        report = replay_shadow_v2_case(case)
        self.assertEqual((report.outcome, report.classification), (ComparisonOutcome.MATCH, ReplayClassification.EXACT_MATCH))

    def test_graph_rejects_missing_duplicate_out_of_order_and_wrong_attempt_references(self) -> None:
        graph = self.lifecycle_graph()
        missing = replace(graph, events=(*graph.events[:-1], replace(graph.events[-1], provider_attempt_id="provider-missing", provider_call_made=True)))
        wrong = replace(graph, events=(replace(graph.events[0], lifecycle_attempt_id="supervisor-1"), *graph.events[1:]))
        duplicate = replace(graph, provider_attempts=(graph.provider_attempts[0], graph.provider_attempts[0]))
        duplicate_event = replace(graph, events=(*graph.events, ShadowV2Event("event-7", 7, "worker-1", "worker-dispatch", "provider-primary-1", True)))
        out_of_order = replace(graph, attempts=(graph.attempts[1], graph.attempts[0], *graph.attempts[2:]))
        parent = replace(graph, attempts=(replace(graph.attempts[0], parent_attempt_id="missing-parent"), *graph.attempts[1:]))
        for invalid in (missing, wrong, duplicate, duplicate_event, out_of_order, parent):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ShadowV2Error):
                    self.lifecycle_case(invalid)

    def test_graph_enforces_commit_cardinality_and_one_attempt_per_commit(self) -> None:
        graph = self.lifecycle_graph()
        no_commit = replace(graph, commits=())
        many_commits = replace(graph, commits=(*graph.commits, CandidateCommitReference("c" * 40, "extra-commit")))
        multiple_attempts = replace(graph, attempts=(replace(graph.attempts[0], commit_sha="b" * 40), *graph.attempts[1:]))
        for invalid in (no_commit, many_commits, multiple_attempts):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ShadowV2Error):
                    self.lifecycle_case(invalid)

    def test_graph_rejects_missing_accepted_result_and_accepts_non_provider_events(self) -> None:
        graph = self.lifecycle_graph()
        missing = replace(graph, accepted_results=())
        with self.assertRaises(ShadowV2Error):
            self.lifecycle_case(missing)
        self.assertFalse(graph.events[-1].provider_call_made)
        self.assertIsNone(graph.events[-1].provider_attempt_id)

    def test_graph_core_can_represent_retry_failover_and_repair_attempt_kinds(self) -> None:
        graph = self.lifecycle_graph()
        for kind in (LifecycleAttemptKind.RETRY, LifecycleAttemptKind.FAILOVER):
            attempts = (*graph.attempts[:2], replace(graph.attempts[2], kind=kind), graph.attempts[3])
            with self.subTest(kind=kind):
                self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(replace(graph, attempts=attempts))).outcome, ComparisonOutcome.MATCH)


if __name__ == "__main__":
    unittest.main()
