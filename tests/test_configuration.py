"""Regression coverage for the Phase 3 runtime configuration boundary."""

from __future__ import annotations

import tempfile
import unittest
import io
import os
import shutil
import subprocess
import contextlib
from pathlib import Path
from unittest import mock

import roundwright.configuration as configuration_module

from roundwright.configuration import (
    ConfigurationError,
    ConfigurationSource,
    FinalFindingsPolicy,
    RepositoryIdentity,
    ReviewDisposition,
    ReviewMode,
    ReviewOutcome,
    ReviewPolicy,
    FileReviewAuthorityStore,
    ReviewAuthorityEvidenceReceipt,
    ReviewAuthorityExpectation,
    TrustedReviewAuthorityReceipt,
    load_configuration,
    parse_cli_overrides,
    resolve_dispatch_configuration,
)
from roundwright import cli
from roundwright.policy import PolicyAction, PolicyDocument, TrustedControlSource, TrustedPolicySnapshot
from roundwright.dependency_policy import (
    BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent,
    DependencyExecutionControl, DependencyPolicy, ObservedDependency, PolicyTransition,
    PolicyTransitionKind, TrustedDependencyAdmission, VersionRange,
)
from roundwright.git_identity import GitEntrypointControl


class ConfigurationTests(unittest.TestCase):
    def write(self, path: Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")

    def git(self, directory: Path, *arguments: str) -> None:
        subprocess.run(["git", "-C", os.fspath(directory), *arguments], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def git_input(self, directory: Path, *arguments: str, input: str) -> None:
        subprocess.run(
            ["git", "-C", os.fspath(directory), *arguments], input=input.encode("utf-8"),
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def git_control(self, root: Path) -> tuple[CandidateBinding, GitEntrypointControl]:
        """Create only fixture-side, pre-materialized Git authority."""

        candidate = subprocess.run(
            ["git", "-C", os.fspath(root), "rev-parse", "refs/remotes/origin/main"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout.strip()
        digest = lambda value: "sha256:" + value * 64
        binding = CandidateBinding("ythdelmar68/roundwright", "issue-47", candidate)
        components = (
            ComponentPolicy(DependencyComponent.PACKAGE, "roundwright", VersionRange("0.0.0", "1.0.0"), "pypi/roundwright", digest("1"), digest("2")),
            ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, "git", VersionRange("2.0.0", "3.0.0"), "git-scm/git", digest("3"), digest("4")),
        )
        policy = DependencyPolicy(binding, digest("5"), 100, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
        receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=digest("6"), authority_digest=digest("7"))
        policy = __import__("dataclasses").replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
        observations = tuple(
            ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 100, policy.policy_digest)
            for item in components
        )
        control = GitEntrypointControl(
            binding, DependencyExecutionControl(policy, observations, TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, digest("6"), digest("7"))), 100,
        )
        return binding, control

    def authoritative_worktrees(self, root: Path, configuration: str | None = "[review]\nmax_rounds = 6\n") -> tuple[Path, Path]:
        root.mkdir(parents=True, exist_ok=True)
        remote, main, candidate = root / "remote.git", root / "main", root / "candidate"
        subprocess.run(["git", "init", "--bare", os.fspath(remote)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.git(root, "init", os.fspath(main))
        self.git(main, "config", "user.email", "tests@example.invalid")
        self.git(main, "config", "user.name", "Tests")
        self.write(main / "README.md", "fixture\n")
        if configuration is not None:
            self.write(main / ".roundwright.toml", configuration)
            self.git(main, "add", "README.md", ".roundwright.toml")
        else:
            self.git(main, "add", "README.md")
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
            self.assertEqual(without_overrides.review_policy.max_rounds, 10)
            binding, control = self.git_control(main)
            authorized = load_configuration(
                cwd=candidate, environment={}, git_binding=binding, git_entrypoint_control=control,
            )
            self.assertEqual(authorized.review_policy.max_rounds, 6)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch("roundwright.cli.Path.cwd", return_value=candidate):
                self.assertEqual(cli.main(["config", "validate"]), 0)
                self.assertEqual(cli.main(["config", "show", "--sources"]), 0)
                with mock.patch("roundwright.cli.require_safe_entrypoint_identity"):
                    self.assertEqual(cli.main(["init"]), 2)
            self.assertTrue((main / ".roundwright.toml").is_file())
            self.assertFalse((main / ".roundwright" / "state.sqlite3").exists())
            self.assertFalse((candidate / ".roundwright" / "state.sqlite3").exists())
            self.assertIn("review.max_rounds: default", output.getvalue())

    def test_config_free_authoritative_main_remains_the_init_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            main, candidate = self.authoritative_worktrees(Path(temporary), configuration=None)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch("roundwright.cli.Path.cwd", return_value=candidate), mock.patch("roundwright.cli.require_safe_entrypoint_identity"):
                self.assertEqual(cli.main(["init"]), 2)
            self.assertFalse((main / ".roundwright" / "state.sqlite3").exists())
            self.assertFalse((candidate / ".roundwright" / "state.sqlite3").exists())

    def test_authoritative_configuration_accepts_only_absent_or_one_ordinary_stage_zero_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_free_main, _ = self.authoritative_worktrees(Path(temporary) / "config-free", configuration=None)
            binding, control = self.git_control(config_free_main)
            self.assertEqual(configuration_module._validated_authoritative_repository(config_free_main, binding=binding, control=control), config_free_main.resolve())
            self.assertEqual(configuration_module._read_authoritative_runtime_toml(config_free_main, binding=binding, control=control), {})
            main, _ = self.authoritative_worktrees(Path(temporary) / "tracked")
            binding, control = self.git_control(main)
            self.assertEqual(configuration_module._validated_authoritative_repository(main, binding=binding, control=control), main.resolve())
            self.assertEqual(configuration_module._read_authoritative_runtime_toml(main, binding=binding, control=control)["review"]["max_rounds"], 6)

    def test_authoritative_git_reads_reject_unsealed_or_mismatched_control_before_subprocess(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            main, _ = self.authoritative_worktrees(Path(temporary))
            binding, control = self.git_control(main)
            def forged(candidate_binding: CandidateBinding, now: int) -> GitEntrypointControl:
                value = object.__new__(GitEntrypointControl)
                object.__setattr__(value, "binding", candidate_binding)
                object.__setattr__(value, "dependency_control", control.dependency_control)
                object.__setattr__(value, "now", now)
                return value

            with mock.patch("roundwright.configuration.subprocess.run") as runner:
                for supplied_binding, supplied_control in (
                    (None, None),
                    (binding, object()),
                    (CandidateBinding(binding.repository, "other-task", binding.candidate_sha), control),
                    (CandidateBinding("other/repository", binding.task_id, binding.candidate_sha), control),
                    (CandidateBinding(binding.repository, binding.task_id, "f" * 40), control),
                    (binding, forged(binding, 1_000)),
                ):
                    with self.subTest(control=type(supplied_control).__name__):
                        with self.assertRaises(ConfigurationError):
                            configuration_module._validated_authoritative_repository(
                                main, binding=supplied_binding, control=supplied_control,
                            )
            runner.assert_not_called()

    def test_authoritative_configuration_rejects_hidden_or_nonordinary_index_entries(self) -> None:
        def assert_rejected(mutate) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                main, _ = self.authoritative_worktrees(Path(temporary))
                mutate(main)
                binding, control = self.git_control(main)
                with self.assertRaisesRegex(ConfigurationError, "authoritative main"):
                    configuration_module._validated_authoritative_repository(main, binding=binding, control=control)

        def assume_unchanged(main: Path) -> None:
            self.git(main, "update-index", "--assume-unchanged", ".roundwright.toml")

        def skip_worktree(main: Path) -> None:
            self.git(main, "update-index", "--skip-worktree", ".roundwright.toml")

        def nonordinary_mode(main: Path) -> None:
            self.git(main, "update-index", "--chmod=+x", ".roundwright.toml")

        def multi_stage(main: Path) -> None:
            line = subprocess.run(
                ["git", "-C", os.fspath(main), "ls-files", "--stage", "--", ".roundwright.toml"],
                check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            ).stdout.strip()
            object_id = line.split()[1]
            self.git_input(
                main,
                "update-index",
                "--index-info",
                input=(
                    f"0 {'0' * len(object_id)} 0\t.roundwright.toml\n"
                    f"100644 {object_id} 1\t.roundwright.toml\n"
                    f"100644 {object_id} 2\t.roundwright.toml\n"
                    f"100644 {object_id} 3\t.roundwright.toml\n"
                ),
            )
            self.assertEqual(
                len(
                    subprocess.run(
                        ["git", "-C", os.fspath(main), "ls-files", "--stage", "--unmerged", "--", ".roundwright.toml"],
                        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    ).stdout.splitlines()
                ),
                3,
            )

        for label, mutation in (
            ("assume-unchanged", assume_unchanged),
            ("skip-worktree", skip_worktree),
            ("nonordinary", nonordinary_mode),
            ("multi-stage", multi_stage),
        ):
            with self.subTest(case=label):
                assert_rejected(mutation)

    def test_authoritative_configuration_rejects_foreign_identity_and_modified_sources(self) -> None:
        def assert_rejected(mutate) -> None:
            with tempfile.TemporaryDirectory() as temporary:
                main, _ = self.authoritative_worktrees(Path(temporary))
                mutate(main)
                binding, control = self.git_control(main)
                with self.assertRaisesRegex(ConfigurationError, "authoritative main"):
                    configuration_module._validated_authoritative_repository(main, binding=binding, control=control)

        def foreign_origin(main: Path) -> None:
            self.git(main, "remote", "set-url", "origin", "https://github.com/ythdelmar68/roundwright-alias.git")

        def aliased_origin(main: Path) -> None:
            self.git(main, "remote", "set-url", "origin", "https://github.com/ythdelmar68/roundwright.git/")

        def modified_source(main: Path) -> None:
            self.write(main / ".roundwright.toml", "[review]\nmax_rounds = 1\n")

        for label, mutation in (
            ("foreign-origin", foreign_origin),
            ("aliased-origin", aliased_origin),
            ("modified", modified_source),
        ):
            with self.subTest(case=label):
                assert_rejected(mutation)

    def test_authoritative_configuration_rejects_ignored_and_untracked_configurations(self) -> None:
        for label, ignored in (("ignored", True), ("untracked", False)):
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                main, _ = self.authoritative_worktrees(Path(temporary), configuration=None)
                if ignored:
                    self.write(main / ".gitignore", ".roundwright.toml\n")
                self.write(main / ".roundwright.toml", "[review]\nmax_rounds = 1\n")
                binding, control = self.git_control(main)
                with self.assertRaisesRegex(ConfigurationError, "authoritative main"):
                    configuration_module._validated_authoritative_repository(main, binding=binding, control=control)

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

    def test_dispatch_configuration_requires_and_pins_typed_trusted_review_floor(self) -> None:
        snapshot = TrustedPolicySnapshot(
            TrustedControlSource("a" * 64, "b" * 64),
            PolicyDocument(1, frozenset({PolicyAction.ISSUE_COMMENT})),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = load_configuration(cwd=root, environment={}).review_policy
            accepted_floor = baseline.__class__(2, 9, 2, baseline.on_final_findings)
            def authority_inputs(floor):
                authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
                anchor = load_configuration(cwd=root, environment={}, trusted_review_floor=floor).resolved_digest
                store_root = root / authority.receipt_digest.removeprefix("sha256:")
                expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, FileReviewAuthorityStore.identity_for_root(store_root), authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, anchor, 10, 20)
                store = FileReviewAuthorityStore(store_root, expectation=expectation)
                evidence = store.persist(authority, candidate_sha="c" * 40, configuration_anchor_digest=anchor, ready_at=10, freshness_until=20)
                return authority, expectation, store, evidence
            authority, expectation, store, evidence = authority_inputs(accepted_floor)
            resolved = resolve_dispatch_configuration(
                cwd=root,
                environment={},
                trusted_policy_snapshot=snapshot,
                trusted_review_floor=accepted_floor,
                trusted_review_authority_receipt=authority,
                review_authority_expectation=expectation,
                review_authority_store=store,
                review_authority_evidence=evidence,
                candidate_sha="c" * 40,
                evidence_time=10,
            )
            self.assertEqual(resolved.trusted_review_floor, accepted_floor)
            self.assertNotEqual(resolved.resolved_digest, load_configuration(cwd=root, environment={}).resolved_digest)
            changed_floor = baseline.__class__(1, 8, 1, baseline.on_final_findings)
            changed_authority, changed_expectation, changed_store, changed_evidence = authority_inputs(changed_floor)
            drifted = resolve_dispatch_configuration(
                cwd=root,
                environment={},
                trusted_policy_snapshot=snapshot,
                trusted_review_floor=changed_floor,
                trusted_review_authority_receipt=changed_authority,
                review_authority_expectation=changed_expectation,
                review_authority_store=changed_store,
                review_authority_evidence=changed_evidence,
                candidate_sha="c" * 40,
                evidence_time=10,
            )
            self.assertNotEqual(resolved.pin().digest, drifted.pin().digest)
            with self.assertRaisesRegex(ConfigurationError, "authority receipt"):
                resolve_dispatch_configuration(
                    cwd=root,
                    environment={},
                    trusted_policy_snapshot=snapshot,
                    trusted_review_floor=accepted_floor,
                    trusted_review_authority_receipt=changed_authority,
                    review_authority_expectation=expectation,
                    review_authority_store=store,
                    review_authority_evidence=evidence,
                    candidate_sha="c" * 40,
                    evidence_time=10,
                )
            with self.assertRaisesRegex(ConfigurationError, "trusted review policy evidence"):
                resolve_dispatch_configuration(cwd=root, environment={}, trusted_policy_snapshot=None, trusted_review_floor=accepted_floor, trusted_review_authority_receipt=None)
            with self.assertRaisesRegex(ConfigurationError, "trusted review policy evidence"):
                resolve_dispatch_configuration(cwd=root, environment={}, trusted_policy_snapshot=snapshot, trusted_review_floor=None, trusted_review_authority_receipt=None)
            with self.assertRaisesRegex(ConfigurationError, "independent review authority evidence"):
                resolve_dispatch_configuration(
                    cwd=root,
                    environment={},
                    trusted_policy_snapshot=snapshot,
                    trusted_review_floor=baseline.__class__(4, 10, 3, baseline.on_final_findings),
                    trusted_review_authority_receipt=TrustedReviewAuthorityReceipt.from_snapshot(snapshot, baseline.__class__(4, 10, 3, baseline.on_final_findings)),
                )

    def test_file_review_authority_store_rehydrates_and_rejects_tamper(self) -> None:
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authority"
            expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, FileReviewAuthorityStore.identity_for_root(root), authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, "sha256:" + "d" * 64, 10, 20)
            store = FileReviewAuthorityStore(root, expectation=expectation)
            receipt = store.persist(authority, candidate_sha="c" * 40, configuration_anchor_digest="sha256:" + "d" * 64, ready_at=10, freshness_until=20)
            self.assertEqual(FileReviewAuthorityStore(root, expectation=expectation).read(receipt, evidence_time=10), receipt)
            self.assertIsNot(FileReviewAuthorityStore(root, expectation=expectation).read(receipt, evidence_time=11), receipt)
            path = store._path(receipt.record_identity)
            path.write_text('{"tampered":true}\n', encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                store.read(receipt, evidence_time=10)

    def test_file_review_authority_store_rejects_same_expectation_clone_root(self) -> None:
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "pinned-authority"
            expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, FileReviewAuthorityStore.identity_for_root(root), authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, "sha256:" + "d" * 64, 10, 20)
            store = FileReviewAuthorityStore(root, expectation=expectation)
            receipt = store.persist(authority, candidate_sha="c" * 40, configuration_anchor_digest="sha256:" + "d" * 64, ready_at=10, freshness_until=20)
            self.assertEqual(store.read(receipt, evidence_time=10), receipt)
            with self.assertRaises(ConfigurationError):
                FileReviewAuthorityStore(Path(temporary) / "candidate-clone", expectation=expectation)

    def test_file_review_authority_store_uses_canonical_root_after_platform_normalization(self) -> None:
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        with tempfile.TemporaryDirectory() as temporary:
            raw_root = Path(temporary) / "var-spelling" / "authority"
            # Build the canonical spelling from the host-resolved temporary
            # root.  On macOS, re-resolving a lexical /var spelling yields
            # /private/var; the mock must therefore return that same real
            # canonical object both for the raw spelling and a later
            # identity_for_root(canonical_root) call.
            resolved_temporary = Path(temporary).resolve(strict=True)
            canonical_root = resolved_temporary / "private-var" / "authority"
            raw_root.parent.mkdir()
            canonical_root.mkdir(parents=True)
            original_resolve = Path.resolve
            def normalized_resolve(path: Path, strict: bool = False) -> Path:
                try:
                    relative = path.relative_to(raw_root.parent)
                except ValueError:
                    relative = None
                if relative is not None:
                    return original_resolve(canonical_root.parent / relative, strict=strict)
                return original_resolve(path, strict=strict)
            with mock.patch.object(Path, "resolve", autospec=True, side_effect=normalized_resolve):
                identity = FileReviewAuthorityStore.identity_for_root(raw_root)
                expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, identity, authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, "sha256:" + "d" * 64, 10, 20)
                store = FileReviewAuthorityStore(raw_root, expectation=expectation)
                self.assertEqual(store._root, canonical_root)
                self.assertEqual(store.authority_store_identity, FileReviewAuthorityStore.identity_for_root(canonical_root))

    def test_file_review_authority_store_rejects_reparse_leaf_but_not_normalized_ancestor(self) -> None:
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        with tempfile.TemporaryDirectory() as temporary:
            ancestor = Path(temporary) / "normalized-ancestor"; ancestor.mkdir()
            root = ancestor / "authority"
            with mock.patch.object(configuration_module, "_reparse", side_effect=lambda path: path == ancestor):
                identity = FileReviewAuthorityStore.identity_for_root(root)
                expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, identity, authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, "sha256:" + "d" * 64, 10, 20)
                self.assertEqual(FileReviewAuthorityStore(root, expectation=expectation).authority_store_identity, identity)
            with mock.patch.object(configuration_module, "_reparse", side_effect=lambda path: path == root):
                with self.assertRaises(ConfigurationError):
                    FileReviewAuthorityStore.identity_for_root(root)

    @unittest.skipUnless(os.name == "nt" and hasattr(Path(), "is_junction") and shutil.which("cmd.exe"), "Windows cmd.exe junction creation is unavailable")
    def test_file_review_authority_store_accepts_junction_ancestor_but_rejects_junction_leaf(self) -> None:
        floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
        snapshot = TrustedPolicySnapshot(TrustedControlSource("a" * 64, "b" * 64), PolicyDocument(1, frozenset()))
        authority = TrustedReviewAuthorityReceipt.from_snapshot(snapshot, floor)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); target = root / "target"; target.mkdir(); ancestor = root / "junction-ancestor"
            if subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(ancestor), str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
                self.skipTest("host cannot create a Windows junction")
            ordinary_leaf = ancestor / "authority"
            identity = FileReviewAuthorityStore.identity_for_root(ordinary_leaf)
            expectation = ReviewAuthorityExpectation(authority.source_identity, authority.authority_identity, authority.runtime_store_source_identity, identity, authority.receipt_digest, authority.policy_snapshot_digest, floor, "c" * 40, "sha256:" + "d" * 64, 10, 20)
            self.assertEqual(FileReviewAuthorityStore(ordinary_leaf, expectation=expectation).authority_store_identity, identity)
            leaf_target = root / "leaf-target"; leaf_target.mkdir(); leaf = root / "junction-leaf"
            if subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(leaf), str(leaf_target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode != 0:
                self.skipTest("host cannot create a Windows leaf junction")
            with self.assertRaises(ConfigurationError):
                FileReviewAuthorityStore.identity_for_root(leaf)


if __name__ == "__main__":
    unittest.main()
