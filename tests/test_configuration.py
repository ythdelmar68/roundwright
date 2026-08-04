"""Regression coverage for the Phase 3 runtime configuration boundary."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from roundwright.configuration import (
    ConfigurationError,
    ConfigurationSource,
    FinalFindingsPolicy,
    RepositoryIdentity,
    ReviewMode,
    load_configuration,
    parse_cli_overrides,
)


class ConfigurationTests(unittest.TestCase):
    def write(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")

    def test_packaged_defaults_are_exact_and_config_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            configuration = load_configuration(cwd=Path(temporary), environment={}, home=Path(temporary) / "home")
        self.assertEqual(configuration.schema_version, "roundwright-runtime/v1")
        self.assertEqual((configuration.worker.value.model, configuration.worker.value.reasoning_effort.value), ("gpt-5.6-terra", "high"))
        self.assertEqual([(item.name, item.model, item.reasoning_effort.value) for item in configuration.supervisor_attempt_profiles.value], [
            ("primary", "gpt-5.6-sol", "xhigh"), ("fallback", "gpt-5.6-terra", "high"), ("fallback-retry", "gpt-5.6-terra", "high"),
        ])
        self.assertEqual(configuration.review_policy.on_final_findings, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        self.assertEqual(configuration.review_policy.mode_for_round(3), ReviewMode.COMPLETE)
        self.assertEqual(configuration.review_policy.mode_for_round(4), ReviewMode.CONVERGING)
        self.assertTrue(configuration.resolved_digest.startswith("sha256:"))
        self.assertEqual(configuration.worker.source, ConfigurationSource.DEFAULT)

    def test_user_repository_environment_and_cli_precedence_have_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            user = root / "user.toml"
            self.write(user, "[review]\nmax_rounds = 5\n")
            self.write(root / ".roundwright.toml", "[review]\nmax_rounds = 6\n")
            with mock.patch("roundwright.configuration._validated_authoritative_repository", return_value=root):
                configuration = load_configuration(
                    cwd=root, user_config=user,
                    environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "7"},
                    cli_values={"review.max_rounds": "8"},
                    authoritative_repository_root=root,
                )
        self.assertEqual(configuration.review_policy.max_rounds, 8)
        self.assertEqual(configuration.sources["review.max_rounds"], ConfigurationSource.COMMAND_LINE)

    def test_candidate_configuration_is_ignored_and_an_explicit_non_main_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write(root / ".roundwright.toml", "[review]\nmax_rounds = 1\n")
            candidate = load_configuration(cwd=root, environment={})
            self.assertEqual(candidate.review_policy.max_rounds, 10)
            with mock.patch("roundwright.configuration._validated_authoritative_repository", side_effect=ConfigurationError("repository configuration is not from authoritative main")):
                with self.assertRaisesRegex(ConfigurationError, "authoritative main"):
                    load_configuration(cwd=root, environment={}, authoritative_repository_root=root)

    def test_profile_replacement_is_atomic_and_attempt_budget_must_match(self) -> None:
        profiles = [
            {"name": "one", "model": "gpt-5.6-sol", "reasoning_effort": "xhigh"},
            {"name": "two", "model": "gpt-5.6-terra", "reasoning_effort": "high"},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            configuration = load_configuration(cwd=root, environment={}, cli_values={
                "review.max_supervisor_attempts_per_round": "2",
                "roles.supervisor.attempt_profiles": profiles,
            })
            self.assertEqual([profile.name for profile in configuration.supervisor_attempt_profiles.value], ["one", "two"])
            with self.assertRaisesRegex(ConfigurationError, "atomic|partial|unsupported"):
                load_configuration(cwd=root, environment={}, cli_values={"roles.supervisor.attempt_profiles": [{"name": "one", "model": "gpt-5.6-sol"}]})
            with self.assertRaisesRegex(ConfigurationError, "count"):
                load_configuration(cwd=root, environment={}, cli_values={"roles.supervisor.attempt_profiles": profiles})

    def test_invalid_review_combinations_and_unknown_policy_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for values in (
                {"review.max_rounds": "0"},
                {"review.complete_rounds": "11"},
                {"review.on_final_findings": "pass-anyway"},
                {"model": "gpt-5.6-sol"},
            ):
                with self.subTest(values=values), self.assertRaises(ConfigurationError):
                    load_configuration(cwd=root, environment={}, cli_values=values)

    def test_cli_whole_structure_is_json_and_duplicate_or_partial_environment_is_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            parse_cli_overrides(["review.max_rounds=9", "review.max_rounds=10"])
        with self.assertRaises(ConfigurationError):
            parse_cli_overrides(["roles.supervisor.attempt_profiles=not-json"])
        with tempfile.TemporaryDirectory() as temporary:
            configuration = load_configuration(cwd=Path(temporary), environment={"ROUNDWRIGHT_MODEL": "gpt-5.6-sol"})
        self.assertEqual(configuration.worker.value.model, "gpt-5.6-terra")

    def test_digest_pins_values_and_sources_without_path_or_secret_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = load_configuration(cwd=root, environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "9"})
            second = load_configuration(cwd=root, environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "10"})
        self.assertNotEqual(first.pin().digest, second.pin().digest)
        self.assertEqual(first.pin().digest, first.resolved_digest)
        self.assertNotIn(str(root), str(first.sources))
        with self.assertRaises(ConfigurationError) as raised:
            load_configuration(cwd=root, environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "private-token"})
        self.assertNotIn("private-token", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
