"""Regression coverage for the Phase 3 runtime configuration boundary."""

from __future__ import annotations

import tempfile
import unittest
import io
import os
import subprocess
import contextlib
from pathlib import Path
from unittest import mock

from roundwright.configuration import (
    ConfigurationError,
    ConfigurationSource,
    FinalFindingsPolicy,
    RepositoryIdentity,
    ReviewDisposition,
    ReviewMode,
    ReviewOutcome,
    load_configuration,
    parse_cli_overrides,
)
from roundwright import cli


class ConfigurationTests(unittest.TestCase):
    def write(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")

    def git(self, directory: Path, *arguments: str) -> None:
        subprocess.run(["git", "-C", os.fspath(directory), *arguments], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def authoritative_worktrees(self, root: Path) -> tuple[Path, Path]:
        remote, main, candidate = root / "remote.git", root / "main", root / "candidate"
        subprocess.run(["git", "init", "--bare", os.fspath(remote)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.git(root, "init", os.fspath(main))
        self.git(main, "config", "user.email", "tests@example.invalid")
        self.git(main, "config", "user.name", "Tests")
        self.write(main / "README.md", "fixture\n")
        self.write(main / ".roundwright.toml", "[review]\nmax_rounds = 6\n")
        self.git(main, "add", "README.md", ".roundwright.toml")
        self.git(main, "commit", "-m", "fixture")
        self.git(main, "branch", "-M", "main")
        self.git(main, "remote", "add", "origin", os.fspath(remote))
        self.git(main, "push", "-u", "origin", "main")
        self.git(main, "remote", "set-url", "origin", "https://github.com/ythdelmar68/roundwright.git")
        self.git(main, "worktree", "add", "-b", "candidate", os.fspath(candidate), "main")
        return main, candidate

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
            with mock.patch("roundwright.configuration._validated_authoritative_repository", return_value=root), mock.patch(
                "roundwright.configuration._read_authoritative_runtime_toml", return_value={"review": {"max_rounds": 6}}
            ):
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

    def test_real_authoritative_main_blob_wins_over_candidate_bytes_and_cli_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            main, candidate = self.authoritative_worktrees(Path(temporary))
            self.write(candidate / ".roundwright.toml", "[review]\nmax_rounds = 1\n")
            user = candidate / "user.toml"
            self.write(user, "[review]\nmax_rounds = 5\n")
            configuration = load_configuration(
                cwd=candidate, user_config=user,
                environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "7"},
                cli_values={"review.max_rounds": "8"},
            )
            self.assertEqual(configuration.review_policy.max_rounds, 8)
            self.assertEqual(configuration.sources["review.max_rounds"], ConfigurationSource.COMMAND_LINE)
            without_overrides = load_configuration(cwd=candidate, environment={})
            self.assertEqual(without_overrides.review_policy.max_rounds, 6)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch("roundwright.cli.Path.cwd", return_value=candidate):
                self.assertEqual(cli.main(["config", "validate"]), 0)
                self.assertEqual(cli.main(["config", "show", "--sources"]), 0)
                with mock.patch("roundwright.cli.require_safe_entrypoint_identity"):
                    self.assertEqual(cli.main(["init"]), 0)
            self.assertTrue((main / ".roundwright.toml").is_file())
            self.assertTrue((main / ".roundwright" / "state.sqlite3").is_file())
            self.assertFalse((candidate / ".roundwright" / "state.sqlite3").exists())
            self.assertIn("review.max_rounds: repository configuration", output.getvalue())

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
        self.assertTrue(first.pin().worker_profile_identity.startswith("sha256:"))
        self.assertEqual(len(first.pin().supervisor_profile_identities), 3)
        self.assertNotIn(str(root), str(first.sources))
        with self.assertRaises(ConfigurationError) as raised:
            load_configuration(cwd=root, environment={"ROUNDWRIGHT_REVIEW_MAX_ROUNDS": "private-token"})
        self.assertNotIn("private-token", str(raised.exception))

    def test_path_layers_are_source_auditable_and_digest_paths_without_disclosing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            configuration = load_configuration(
                cwd=root, environment={"ROUNDWRIGHT_CACHE_DIRECTORY": str(cache)},
                cli_values={"cache_directory": root / "cli-cache"},
            )
        self.assertEqual(configuration.cache_directory.value, root / "cli-cache")
        self.assertEqual(configuration.sources["cache_directory"], ConfigurationSource.COMMAND_LINE)
        self.assertNotIn(str(root), configuration.resolved_digest)

    def test_review_policy_contract_covers_early_pass_final_repair_and_trusted_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            policy = load_configuration(cwd=Path(temporary), environment={}).review_policy
        self.assertEqual(policy.disposition(1, ReviewOutcome.PASS), ReviewDisposition.EARLY_PASS)
        self.assertEqual(policy.disposition(9, ReviewOutcome.FINDINGS), ReviewDisposition.NEXT_ROUND)
        self.assertEqual(policy.disposition(10, ReviewOutcome.FINDINGS), ReviewDisposition.WORKER_FINAL_REPAIR)
        self.assertEqual(policy.disposition(10, ReviewOutcome.FINDINGS, worker_finalized=True), ReviewDisposition.REVIEW_LIMIT_REACHED_WORKER_FINALIZED)
        with self.assertRaisesRegex(ConfigurationError, "floor"):
            policy.__class__(2, 10, 3, policy.on_final_findings).enforce_floor(policy)


if __name__ == "__main__":
    unittest.main()
