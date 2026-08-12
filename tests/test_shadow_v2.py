"""Terminal-snapshot Shadow v2 provenance contracts."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from roundwright.dependency_policy import (
    BootstrapPolicyReceipt,
    CandidateBinding,
    ComponentPolicy,
    DependencyComponent,
    DependencyExecutionControl,
    DependencyPolicy,
    ObservedDependency,
    PolicyTransition,
    PolicyTransitionKind,
    TrustedDependencyAdmission,
    VersionRange,
)
from roundwright.shadow import (
    AppendOnlyEvidenceStore,
    AttemptCommitReference,
    CaptureMode,
    CandidateCommitReference,
    ComparisonOutcome,
    ExternalSelectionControl,
    ExternalSelectionControlExpectation,
    ProvenanceRecordError,
    ProvenanceRecordStore,
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
    _materialize_provenance_record,
    replay_shadow_case,
    replay_shadow_v2_case,
    require_capture_readiness,
    shadow_evidence_profile,
    shadow_evidence_profiles,
)


def digest(value: str) -> str:
    return "sha256:" + value * 64


class ShadowV2Tests(unittest.TestCase):
    def external_control_bytes(self):
        payload = {
            "schema": "roundwright-provenance-selection-control/v1", "control_mode": "REHEARSAL", "capture_ready": False,
            "roundlet": {"run_id": "run-47", "contract_id": "contract-47"},
            "selection": {"repository": "ythdelmar68/roundwright", "worker_task": "task-47", "base_sha": "a" * 40, "candidate_sha": "b" * 40, "candidate_tree": "c" * 40, "active_leaf": 47, "route": "toolbox", "case_schema": "roundwright-shadow-case/v2", "evidence_profile": "roundwright-shadow-profile/provenance-decision/v1"},
            "authority": {"origin_main": {"commit": "a" * 40}, "active_roundlet_block": {"agents_blob": "d" * 40}, "external_validation_contract": {"skill_blob": "e" * 40, "qualification_blob": "f" * 40}},
        }
        content = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        receipt = {"schema": "roundwright-provenance-selection-control-receipt/v1", "append_only": True, "capture_ready": False, "contract_sha256": digest("1"), "control_mode": "REHEARSAL", "payload_bytes": len(content), "payload_sha256": "sha256:" + hashlib.sha256(content).hexdigest(), "read_back": "VERIFIED", "retention_identity": "roundlet-control-47"}
        expected = ExternalSelectionControlExpectation("run-47", "contract-47", "ythdelmar68/roundwright", "task-47", "a" * 40, "b" * 40, "c" * 40, 47, "toolbox", "roundwright-shadow-case/v2", "roundwright-shadow-profile/provenance-decision/v1", "d" * 40, "e" * 40, "f" * 40)
        return content, json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(), expected

    def test_external_rehearsal_control_is_bound_but_never_terminal_ready(self) -> None:
        payload, receipt, expected = self.external_control_bytes()
        control = ExternalSelectionControl.load(payload, receipt, expected)
        self.assertEqual(control.mode, "REHEARSAL")
        self.assertFalse(control.terminal_ready)
        for bad_payload, bad_receipt, bad_expected in ((payload + b" ", receipt, expected), (payload, b"{}", expected), (payload, receipt, replace(expected, candidate_sha="d" * 40))):
            with self.subTest():
                with self.assertRaises(ProvenanceRecordError):
                    ExternalSelectionControl.load(bad_payload, bad_receipt, bad_expected)

    def record(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        binding = CandidateBinding("ythdelmar68/roundwright", "task-47", candidate)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright-package", VersionRange("1.0.0", "2.0.0"), "roundwright-source", digest("a"), digest("c")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-source", digest("e"), digest("f")),
        )
        policy = DependencyPolicy(
            binding,
            digest("d"),
            100,
            60,
            components,
            PolicyTransition(PolicyTransitionKind.BOOTSTRAP),
        )
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("1"), authority_digest=digest("2"))
        policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(
            ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 101, policy.policy_digest)
            for item in components
        )
        control = DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, receipt.reviewer_identity, receipt.authority_digest))
        return _materialize_provenance_record(
            control,
            base_sha="a" * 40,
            candidate_tree="d" * 40,
            entrypoint_fingerprint=digest("e"),
            gate_identity="provenance-gate-pass",
            blocker=None,
            next_action="record-terminal-snapshot",
            now=ready_at,
        )

    def decision(self, *, candidate: str = "b" * 40, ready_at: int = 101):
        return export_provenance_decision(self.record(candidate=candidate, ready_at=ready_at))

    def case(self, *, candidate: str = "b" * 40, ready_at: int = 101) -> ShadowV2Case:
        decision = self.decision(candidate=candidate, ready_at=ready_at)
        readiness = require_capture_readiness(
            shadow_evidence_profile(PROVENANCE_DECISION_PROFILE),
            self.record(candidate=candidate, ready_at=ready_at),
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
                shadow_evidence_profile(PROVENANCE_DECISION_PROFILE), self.record(),
                RecorderBinding("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", "87094a4e780c692a00135421840c0e6713af5d35", "0c594caa275262164fce1942ebd2142abe0e77bb"),
                AppendOnlyEvidenceStore("roundlet-provenance-retention"),
                candidate_sha="c" * 40, ready_at=101,
            )

    def test_terminal_export_requires_durable_record_and_store_readback_rejects_tampering(self) -> None:
        record = self.record()
        with self.assertRaises(ProvenanceRecordError):
            export_provenance_decision(record.decision)
        with TemporaryDirectory() as temporary:
            store = ProvenanceRecordStore(Path(temporary), "roundlet-provenance-records")
            digest = store.append(record)
            self.assertEqual(store.read_back(digest), record)
            self.assertEqual(store.append(record), digest)
            (Path(temporary) / f"{digest.removeprefix('sha256:')}.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ProvenanceRecordError):
                store.read_back(digest)

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
                LifecycleAttempt("worker-repair-2", 3, LifecycleAttemptKind.REPAIR, EvidenceRole.WORKER, "supervisor-1"),
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
            (AttemptCommitReference("worker-repair-2", candidate),),
        )

    def lifecycle_case(self, graph: ShadowV2EventGraph | None = None, *, profile: ShadowEvidenceProfile | None = None) -> ShadowV2Case:
        decision = self.decision()
        profile = self.lifecycle_profile() if profile is None else profile
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

    def test_graph_core_supports_many_to_many_attempt_commit_cardinality(self) -> None:
        graph = self.lifecycle_graph()
        flexible = replace(self.lifecycle_profile(), minimum_commits=0, maximum_commits=3)
        no_commit_events = (*graph.events[:3], replace(graph.events[3], commit_sha=None), *graph.events[4:])
        no_commit = replace(graph, commits=(), events=no_commit_events, attempt_commit_references=())
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(no_commit, profile=flexible)).outcome, ComparisonOutcome.MATCH)

        second_commit = CandidateCommitReference("c" * 40, "follow-up-commit")
        one_attempt_many_commits = replace(
            graph,
            commits=(*graph.commits, second_commit),
            attempt_commit_references=(*graph.attempt_commit_references, AttemptCommitReference("worker-repair-2", second_commit.commit_sha)),
        )
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(one_attempt_many_commits, profile=flexible)).outcome, ComparisonOutcome.MATCH)

        many_attempts_one_commit = replace(
            graph,
            attempt_commit_references=(
                AttemptCommitReference("worker-1", "b" * 40),
                AttemptCommitReference("worker-repair-2", "b" * 40),
            ),
        )
        self.assertEqual(replay_shadow_v2_case(self.lifecycle_case(many_attempts_one_commit)).outcome, ComparisonOutcome.MATCH)

    def test_graph_rejects_invalid_attempt_commit_relation_edges(self) -> None:
        graph = self.lifecycle_graph()
        edge = graph.attempt_commit_references[0]
        extra = CandidateCommitReference("c" * 40, "orphaned-commit")
        wrong_attempt = replace(graph, attempt_commit_references=(AttemptCommitReference("missing-attempt", edge.commit_sha),))
        missing_commit = replace(graph, attempt_commit_references=(AttemptCommitReference(edge.lifecycle_attempt_id, "c" * 40),))
        duplicate_edge = replace(graph, attempt_commit_references=(edge, edge))
        orphaned_commit = replace(graph, commits=(*graph.commits, extra))
        wrong_event_edge = replace(graph, events=(*graph.events[:3], replace(graph.events[3], commit_sha="c" * 40), *graph.events[4:]))
        for invalid in (wrong_attempt, missing_commit, duplicate_edge, orphaned_commit, wrong_event_edge):
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
