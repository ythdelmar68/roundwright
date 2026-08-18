"""Repository-contract coverage for Roundlet external validation."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.repository_policy import (
    parse_roundlet_authority_state,
    parse_roundwright_authority_block,
)


SKILL_NAME = "run-roundwright-external-validation"


class ExternalValidationContractTests(unittest.TestCase):
    def test_root_policy_grants_independent_standing_switches_only_to_roundlet(self) -> None:
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        roundlet_start = instructions.index("# roundlet:repository-authority")
        roundlet_end = instructions.index("# roundlet:end-repository-authority")
        roundwright_start = instructions.index("# roundwright:repository-authority")
        roundwright_end = instructions.index("# roundwright:end-repository-authority")
        roundlet = instructions[roundlet_start:roundlet_end]
        roundwright = instructions[roundwright_start:roundwright_end]

        self.assertIn("allow_external_validation_read_only: true", roundlet)
        self.assertIn(
            "allow_external_validation_disposable_target_mutation: true",
            roundlet,
        )
        self.assertNotIn("allow_external_validation_", roundwright)
        self.assertTrue(parse_roundlet_authority_state(instructions).enabled)
        self.assertFalse(parse_roundwright_authority_block(instructions).enabled)
        normalized = " ".join(instructions.split())
        self.assertIn("curated public-safe GitHub trace publication", normalized)
        self.assertIn("neither action needs fresh per-candidate owner approval", normalized)

    def test_agents_only_routes_execution_to_the_repository_skill(self) -> None:
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        section = instructions.split("## Roundwright external validation", 1)[1].split(
            "## ", 1
        )[0]
        self.assertIn(f"${SKILL_NAME}", section)
        self.assertNotIn("roundwright-harness", section)
        self.assertNotIn("roundlet-forward-test", section)
        self.assertNotIn("ready_at", section)

    def test_execution_skill_binds_routes_pins_phase_and_evidence_time(self) -> None:
        skill = (
            ROOT / ".agents" / "skills" / SKILL_NAME / "SKILL.md"
        ).read_text(encoding="utf-8")
        normalized_skill = " ".join(skill.split())
        metadata = (
            ROOT / ".agents" / "skills" / SKILL_NAME / "agents" / "openai.yaml"
        ).read_text(encoding="utf-8")
        for value in (
            "`none`/`none`",
            "`harness`/`toolbox`",
            "`harness+forward-test`/`toolbox+disposable-target`",
            "1004cf0143aef9a777a64a3a0703b10a5680e959",
            "985b49fade4be8dec1355d183ad824cf9d67a354",
            "8df4fd5e58dd41de54aeae53ce66a5c49ab0f040",
            "0154817a6fba345b78af25017eb312a1b2349cd6",
            "0f980f75a05ec616395b2cbfed9724417d00d335",
            "cf669e186a739a8597cfaf9f050ce3bdcadda334",
            "d9fba0facfe561850c0dbff913e8021541b98ca5",
            "4f39ef0e4e616eb896950d3756c433b624771a97",
            "allow_external_validation_read_only: true",
            "allow_external_validation_disposable_target_mutation: true",
            "Phase 3 never mutates",
            "Phase 4-or-later",
            "ready_at",
            "Never pass the replay execution time",
            "roundwright-harness-profile-executor-request/v2",
            "roundwright-harness-capture-plan/v1",
            "run-profile --mode validate",
            "--mode execute",
            "roundwright.external_validation:roundwright_profile_adapter_factory",
            "ordinary curated public-safe GitHub lifecycle trace",
            "readiness, result, and handoff GitHub trace events",
            "blocks before `ARMED` with zero external action",
        ):
            self.assertIn(value, normalized_skill)
        self.assertIn("Roundlet PR #80", skill)
        self.assertIn("historical predecessor", normalized_skill)
        self.assertNotIn("TODO", skill)
        self.assertIn(f"${SKILL_NAME}", metadata)

    def test_planning_contract_emits_execution_and_historical_time_fields(self) -> None:
        planning_skill = (
            ROOT / ".agents" / "skills" / "create-roundwright-leaf" / "SKILL.md"
        ).read_text(encoding="utf-8")
        tracked_template = (
            ROOT / ".github" / "ISSUE_TEMPLATE" / "roundwright-leaf.md"
        ).read_text(encoding="utf-8")
        reference = (
            ROOT / "docs" / "operations" / "leaf-issue-template.md"
        ).read_text(encoding="utf-8")
        for value in (f"${SKILL_NAME}", "ready_at"):
            self.assertIn(value, planning_skill)
            self.assertIn(value, tracked_template)
            self.assertIn(value, reference)

    def test_operations_contract_uses_standing_not_per_attempt_authority(self) -> None:
        contract = (
            ROOT / "docs" / "operations" / "qualification-test-infrastructure.md"
        ).read_text(encoding="utf-8")
        self.assertIn("Do not request repetitive owner approval", contract)
        self.assertIn("Phase 3 never mutates the forward-test target", contract)
        self.assertIn("top-level integer `ready_at`", contract)
        self.assertIn("Harness PR #4", contract)
        self.assertIn("Harness PR #6", contract)
        self.assertIn("Harness PR #10", contract)
        self.assertIn("Roundlet PR #82", contract)
        self.assertIn("Roundlet PR #80", contract)
        active_row = next(
            line for line in contract.splitlines() if "| Generic Orchestrator |" in line
        )
        self.assertIn("1004cf0143aef9a777a64a3a0703b10a5680e959", active_row)
        self.assertIn("985b49fade4be8dec1355d183ad824cf9d67a354", active_row)
        self.assertIn("8df4fd5e58dd41de54aeae53ce66a5c49ab0f040", active_row)
        self.assertNotIn("96772438b251e56d483733179939245565b1374a", active_row)
        normalized = " ".join(contract.split())
        self.assertIn("historical predecessor", normalized)
        self.assertIn("0154817a6fba345b78af25017eb312a1b2349cd6", contract)
        self.assertIn("1bb063d3f8f1fef9a24b3147b8bc99794e4637a7", contract)
        self.assertIn("cf669e186a739a8597cfaf9f050ce3bdcadda334", contract)
        self.assertIn("632dcc3ecb3b8664de860844af2215ad5ade83e1", contract)
        self.assertNotIn("fresh authenticated owner approval", contract)
        self.assertIn(
            "Profile readiness, dispatch, typed export/comparison, recording, and "
            "read-back therefore use one entrypoint and one plan",
            normalized,
        )
        self.assertIn(
            "Validate and execute use the same request, parser, adapter factory, "
            "plan, store, and entrypoint",
            normalized,
        )

    def test_dogfood_order_places_reviewed_roundlet_binding_before_p2(self) -> None:
        roadmap = (
            ROOT / "docs" / "operations" / "dogfood-promotion-roadmap.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(roadmap.split())
        self.assertIn(
            "#75, #45, reviewed-Runlet binding correction #78, then #48–#51",
            normalized,
        )
        self.assertIn("1004cf0143aef9a777a64a3a0703b10a5680e959", roadmap)
        self.assertIn("fresh post-merge provider-free synthetic receipt", normalized)

    def test_capture_readiness_contract_is_synchronized_and_root_only_routes(self) -> None:
        paths = (
            ROOT / ".agents" / "skills" / SKILL_NAME / "SKILL.md",
            ROOT / "docs" / "operations" / "qualification-test-infrastructure.md",
            ROOT / ".agents" / "skills" / "create-roundwright-leaf" / "SKILL.md",
            ROOT / "docs" / "operations" / "leaf-issue-template.md",
            ROOT / ".github" / "ISSUE_TEMPLATE" / "roundwright-leaf.md",
        )
        required = (
            "capture mode",
            "producer",
            "readiness point",
            "arm-before boundary",
            "retention/read-back contract",
            "missing-history/recapture behavior",
        )
        for path in paths:
            with self.subTest(path=path):
                value = " ".join(path.read_text(encoding="utf-8").lower().split())
                self.assertIn("capture-readiness", value)
                for field in required:
                    self.assertIn(field, value)
        root = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertNotIn("Capture-readiness preflight", root)
        self.assertNotIn("terminal-snapshot", root)


if __name__ == "__main__":
    unittest.main()
