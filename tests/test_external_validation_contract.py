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
            "10265c35c9d01d1fd26bd767ca3c1b245e4e9c52",
            "87094a4e780c692a00135421840c0e6713af5d35",
            "0c594caa275262164fce1942ebd2142abe0e77bb",
            "4f39ef0e4e616eb896950d3756c433b624771a97",
            "allow_external_validation_read_only: true",
            "allow_external_validation_disposable_target_mutation: true",
            "Phase 3 never mutates",
            "Phase 4-or-later",
            "ready_at",
            "Never pass the replay execution time",
        ):
            self.assertIn(value, normalized_skill)
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
        self.assertIn("10265c35c9d01d1fd26bd767ca3c1b245e4e9c52", contract)
        self.assertIn("87094a4e780c692a00135421840c0e6713af5d35", contract)
        self.assertIn("0c594caa275262164fce1942ebd2142abe0e77bb", contract)
        self.assertNotIn("fresh authenticated owner approval", contract)


if __name__ == "__main__":
    unittest.main()
