"""Table-driven contracts for the centralized Phase 2 gate decision."""

from __future__ import annotations

import sys
import tempfile
import unittest
import sqlite3
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.gates import (
    EvidenceOutcome,
    GATE_REGISTRY,
    GateContext,
    GateDecision,
    GateEvidence,
    GateKey,
    GateOutcome,
    decide_gates,
    render_gate_decision,
    read_gate_evidence,
    record_gate_evidence,
)
from roundwright.configuration import RepositoryIdentity
from roundwright.git_identity import CandidateSeal, WorktreeBinding, acquire_transition_lease
from roundwright.state import SourceSnapshot, TaskIdentity, admit_task, database_path, initialize


class GateDecisionTests(unittest.TestCase):
    task_id = "issue-21"
    candidate = "a" * 40

    def context(self, *, sources: int = 1, isolated: bool = True) -> GateContext:
        return GateContext(self.task_id, self.candidate, sources, isolated)

    def evidence(
        self,
        key: GateKey,
        outcome: EvidenceOutcome = EvidenceOutcome.PASS,
        *,
        fingerprint: str = "1" * 64,
        candidate: str | None = None,
        boundary: str | None = None,
        reason: str | None = None,
    ) -> GateEvidence:
        return GateEvidence(
            self.task_id,
            self.candidate if candidate is None else candidate,
            key,
            outcome,
            "deterministic-validator",
            1,
            fingerprint,
            boundary,
            reason,
        )

    def accepted_evidence(self) -> tuple[GateEvidence, ...]:
        entries = []
        for index, requirement in enumerate(GATE_REGISTRY, 1):
            fingerprint = f"{index:064x}"
            if requirement.permits_phase_two_local_na:
                entries.append(
                    self.evidence(
                        requirement.key,
                        EvidenceOutcome.NOT_APPLICABLE,
                        fingerprint=fingerprint,
                        boundary="phase-2 isolated local task",
                        reason="the provider-neutral local slice has no external adapter",
                    )
                )
            else:
                entries.append(self.evidence(requirement.key, fingerprint=fingerprint))
        return tuple(entries)

    def test_every_registered_gate_accepts_structured_evidence(self) -> None:
        decision = decide_gates(self.context(), self.accepted_evidence())
        self.assertEqual(decision.outcome, GateOutcome.PASS)
        self.assertEqual(tuple(result.gate_key for result in decision.results), tuple(item.key.value for item in GATE_REGISTRY))
        self.assertEqual(render_gate_decision(decision).splitlines()[0], "decision=PASS")

    def test_each_registered_gate_is_required(self) -> None:
        accepted = self.accepted_evidence()
        for omitted in GATE_REGISTRY:
            with self.subTest(gate=omitted.key):
                decision = decide_gates(self.context(), tuple(item for item in accepted if item.gate_key != omitted.key))
                self.assertEqual(decision.outcome, GateOutcome.PENDING)
                result = next(item for item in decision.results if item.gate_key == omitted.key.value)
                self.assertEqual(result.outcome, GateOutcome.PENDING)

    def test_unjustified_or_multi_source_not_applicable_fails_closed(self) -> None:
        accepted = list(self.accepted_evidence())
        external = next(item for item in GATE_REGISTRY if item.permits_phase_two_local_na).key
        accepted = [item for item in accepted if item.gate_key != external]
        accepted.append(self.evidence(external, EvidenceOutcome.NOT_APPLICABLE, boundary=None, reason=None))
        self.assertEqual(decide_gates(self.context(), tuple(accepted)).outcome, GateOutcome.BLOCKED)
        accepted[-1] = self.evidence(
            external,
            EvidenceOutcome.NOT_APPLICABLE,
            boundary="isolated local boundary",
            reason="no adapter in Phase 2",
        )
        self.assertEqual(decide_gates(self.context(sources=2), tuple(accepted)).outcome, GateOutcome.BLOCKED)

    def test_findings_unknown_invalid_conflict_and_candidate_mismatch_never_pass(self) -> None:
        cases = (
            (self.evidence(GateKey.BUILD, EvidenceOutcome.FINDINGS), GateOutcome.BLOCKED),
            (self.evidence(GateKey.BUILD, EvidenceOutcome.UNKNOWN), GateOutcome.BLOCKED),
            (self.evidence(GateKey.BUILD, EvidenceOutcome.PASS, fingerprint=""), GateOutcome.BLOCKED),
            (
                self.evidence(GateKey.BUILD, EvidenceOutcome.PASS, candidate="b" * 40),
                GateOutcome.BLOCKED,
            ),
        )
        for replacement, expected in cases:
            with self.subTest(replacement=replacement):
                evidence = [item for item in self.accepted_evidence() if item.gate_key != GateKey.BUILD]
                evidence.append(replacement)
                self.assertEqual(decide_gates(self.context(), tuple(evidence)).outcome, expected)

        conflict = list(self.accepted_evidence())
        conflict.append(self.evidence(GateKey.BUILD, EvidenceOutcome.FINDINGS, fingerprint="f" * 64))
        self.assertEqual(decide_gates(self.context(), tuple(conflict)).outcome, GateOutcome.BLOCKED)

    def test_candidate_movement_requires_fresh_evidence(self) -> None:
        moved = GateContext(self.task_id, "b" * 40, 1, True)
        self.assertEqual(decide_gates(moved, self.accepted_evidence()).outcome, GateOutcome.BLOCKED)
        self.assertEqual(decide_gates(moved, ()).outcome, GateOutcome.PENDING)

    def test_status_rendering_is_deterministic_for_all_decisions(self) -> None:
        pass_render = render_gate_decision(decide_gates(self.context(), self.accepted_evidence()))
        pending_render = render_gate_decision(decide_gates(self.context(), ()))
        blocked_render = render_gate_decision(
            GateDecision(GateOutcome.BLOCKED, decide_gates(self.context(), ()).results)
        )
        self.assertTrue(pass_render.startswith("decision=PASS\n"))
        self.assertTrue(pending_render.startswith("decision=PENDING\n"))
        self.assertTrue(blocked_render.startswith("decision=BLOCKED\n"))


class SQLiteGateEvidenceTests(unittest.TestCase):
    def repository(self, root: Path) -> RepositoryIdentity:
        repository = object.__new__(RepositoryIdentity)
        object.__setattr__(repository, "root", root.resolve())
        return repository

    def test_sqlite_evidence_is_candidate_bound_and_uses_the_current_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository(Path(temporary))
            initialize(repository)
            identity = TaskIdentity("issue-21", "source-21", "ythdelmar68/roundwright", "codex/issue-21", "C:/private/issue-21", "a" * 40)
            lease = acquire_transition_lease(repository, repository_id=identity.repository_id, owner="gate-tests", ttl_seconds=60)
            admit_task(repository, identity, (SourceSnapshot(identity.source_id, identity.repository_id, "1" * 64),), lease=lease)
            binding = WorktreeBinding(identity.task_id, identity.repository_id, identity.branch, Path(identity.worktree), identity.base_sha, lease.state_identity)
            seal = CandidateSeal(identity.task_id, identity.base_sha, "b" * 40, lease.state_identity)
            connection = sqlite3.connect(database_path(repository))
            try:
                connection.execute(
                    "INSERT INTO candidate_seals(task_id, base_sha, candidate_sha, state_identity) VALUES (?, ?, ?, ?)",
                    (seal.task_id, seal.base_sha, seal.candidate_sha, seal.state_identity),
                )
                connection.commit()
            finally:
                connection.close()
            evidence = GateEvidence(identity.task_id, seal.candidate_sha, GateKey.BUILD, EvidenceOutcome.PASS, "validator", 1, "2" * 64)
            with mock.patch("roundwright.gates.bind_candidate_evidence") as bind:
                record_gate_evidence(repository, binding, seal, evidence, lease=lease)
            bind.assert_called_once()
            with mock.patch("roundwright.gates.candidate_evidence", return_value=(evidence.evidence_fingerprint,)):
                self.assertEqual(read_gate_evidence(repository, binding, seal, lease=lease), (evidence,))
            moved = CandidateSeal(identity.task_id, identity.base_sha, "c" * 40, lease.state_identity)
            with mock.patch("roundwright.gates.candidate_evidence", return_value=(evidence.evidence_fingerprint,)):
                self.assertEqual(read_gate_evidence(repository, binding, moved, lease=lease), ())


if __name__ == "__main__":
    unittest.main()
