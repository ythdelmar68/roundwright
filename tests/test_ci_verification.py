"""Regression coverage for the workflow's package-tool and pipx boundaries."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import zlib

ROOT = Path(__file__).resolve().parents[1]


def load_install_verifier() -> object:
    location = ROOT / "ci" / "verify_installs.py"
    specification = importlib.util.spec_from_file_location("verify_installs", location)
    if specification is None or specification.loader is None:
        raise AssertionError("install verifier is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_validation_resolver() -> object:
    location = ROOT / "ci" / "resolve_validation_toolchain.py"
    specification = importlib.util.spec_from_file_location("resolve_validation_toolchain", location)
    if specification is None or specification.loader is None:
        raise AssertionError("validation toolchain resolver is unavailable")
    module = importlib.util.module_from_spec(specification)
    with mock.patch.object(sys, "path", [str(location.parent), *sys.path]):
        specification.loader.exec_module(module)
    return module


def load_docker_qualification() -> object:
    location = ROOT / "ci" / "docker_consumer_qualification.py"
    specification = importlib.util.spec_from_file_location("docker_consumer_qualification", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Docker qualification helper is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_git_commit_materializer() -> object:
    location = ROOT / "ci" / "materialize_git_commit.py"
    specification = importlib.util.spec_from_file_location("materialize_git_commit", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Git commit materializer is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_docker_fixture_writer() -> object:
    location = ROOT / "ci" / "write_docker_consumer_fixture.py"
    specification = importlib.util.spec_from_file_location("write_docker_consumer_fixture", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Docker fixture writer is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_docker_negative_scenarios() -> object:
    location = ROOT / "ci" / "docker_negative_scenarios.py"
    specification = importlib.util.spec_from_file_location("docker_negative_scenarios", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Docker negative scenarios are unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def load_ci_read_only_handoff() -> object:
    location = ROOT / "ci" / "verify_ci_read_only_handoff.py"
    specification = importlib.util.spec_from_file_location("verify_ci_read_only_handoff", location)
    if specification is None or specification.loader is None:
        raise AssertionError("CI read-only handoff verifier is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def load_docker_consumer_test_helpers() -> object:
    location = ROOT / "tests" / "test_docker_consumer.py"
    specification = importlib.util.spec_from_file_location("docker_consumer_test_helpers", location)
    if specification is None or specification.loader is None:
        raise AssertionError("Docker consumer test helpers are unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class CiVerificationTests(unittest.TestCase):
    def test_ci_defaults_to_read_only_and_proves_complete_handoff_teardown(self) -> None:
        verifier = load_ci_read_only_handoff()
        candidate = "a" * 40
        receipt = verifier.qualify(
            candidate, candidate, "b" * 64, "c" * 64, "d" * 64,
            expected_policy="c" * 64, expected_verifier="d" * 64, workflow_mode="read-only",
        )
        self.assertEqual(receipt["schema"], "roundwright-ci-read-only-handoff/v1")
        self.assertEqual(receipt["candidate_sha"], candidate)
        self.assertEqual(receipt["checked_out_sha"], candidate)
        self.assertEqual(receipt["default_dispatch"], "denied")
        self.assertEqual(receipt["selected_handoff"], ["stop", "reconcile", "revoke-old", "issue-new", "bounded-work", "read-back"])
        self.assertEqual(receipt["action_budget"], 1)
        self.assertEqual(receipt["action_read_back"], "completed")
        self.assertEqual(receipt["teardown"], ["stop", "reconcile", "revoke-selected", "verify-cleanup", "clear-handoff", "no-active-authority"])
        self.assertEqual(receipt["result"], "passed")

    def test_ci_read_only_handoff_rejects_stale_candidate_and_dispatch_mode(self) -> None:
        verifier = load_ci_read_only_handoff()
        with self.assertRaisesRegex(ValueError, "checked-out SHA"):
            verifier.qualify("a" * 40, "b" * 40, "c" * 64, "d" * 64, "e" * 64, expected_policy="d" * 64, expected_verifier="e" * 64, workflow_mode="read-only")
        with self.assertRaisesRegex(ValueError, "read-only"):
            verifier.qualify("a" * 40, "a" * 40, "c" * 64, "d" * 64, "e" * 64, expected_policy="d" * 64, expected_verifier="e" * 64, workflow_mode="authoritative")

    def test_ci_read_only_handoff_rejects_policy_verifier_and_action_readback_substitution(self) -> None:
        verifier = load_ci_read_only_handoff()
        arguments = ("a" * 40, "a" * 40, "b" * 64, "c" * 64, "d" * 64)
        with self.assertRaisesRegex(ValueError, "candidate policy"):
            verifier.qualify(*arguments, expected_policy="e" * 64, expected_verifier="d" * 64, workflow_mode="read-only")
        with self.assertRaisesRegex(ValueError, "candidate policy"):
            verifier.qualify(*arguments, expected_policy="c" * 64, expected_verifier="e" * 64, workflow_mode="read-only")
        action = verifier.SyntheticAction("f" * 64, "a" * 64, "a" * 40, 1)
        for readback in (
            None,
            verifier.SyntheticActionReadback("e" * 64, "a" * 64, "a" * 40, 1, 1, "completed"),
            verifier.SyntheticActionReadback("f" * 64, "a" * 64, "a" * 40, 2, 1, "completed"),
            verifier.SyntheticActionReadback("f" * 64, "a" * 64, "a" * 40, 1, 2, "completed"),
        ):
            with self.subTest(readback=readback):
                with self.assertRaises(ValueError):
                    verifier.verify_action_readback(action, readback)

    def test_ci_read_only_handoff_binds_one_uploaded_wheel_digest(self) -> None:
        verifier = load_ci_read_only_handoff()
        with tempfile.TemporaryDirectory() as temporary:
            dist = Path(temporary)
            wheel = dist / "roundwright-0.0.0-py3-none-any.whl"
            wheel.write_bytes(b"candidate wheel")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            (dist / "package-digest.json").write_text(
                json.dumps({"wheel": wheel.name, "sha256": digest}), encoding="utf-8"
            )
            self.assertEqual(verifier.package_digest(dist), digest)
            wheel.write_bytes(b"substituted wheel")
            with self.assertRaisesRegex(ValueError, "does not match"):
                verifier.package_digest(dist)

    def test_ci_workflow_runs_the_read_only_handoff_fixture_on_the_exact_artifact(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        command = "ci/verify_ci_read_only_handoff.py --candidate \"$CANDIDATE_SHA\" --checked-out-sha \"$checked_out_sha\" --dist dist --policy .github/workflows/ci.yml --expected-policy-sha256 \"$candidate_policy_sha\" --expected-verifier-sha256 \"$candidate_verifier_sha\" --workflow-mode read-only --output dist/ci-read-only-handoff.json"
        self.assertIn(command, workflow)
        self.assertIn('test "$checked_out_sha" = "$CANDIDATE_SHA"', workflow)
        self.assertIn('git rev-parse "$CANDIDATE_SHA:.github/workflows/ci.yml"', workflow)
        self.assertIn('git hash-object --path=.github/workflows/ci.yml .github/workflows/ci.yml', workflow)
        self.assertIn('git rev-parse "$CANDIDATE_SHA:ci/verify_ci_read_only_handoff.py"', workflow)
        self.assertIn('git hash-object --path=ci/verify_ci_read_only_handoff.py ci/verify_ci_read_only_handoff.py', workflow)
        self.assertIn('git diff --exit-code "$CANDIDATE_SHA" -- .github/workflows/ci.yml ci/verify_ci_read_only_handoff.py', workflow)
        self.assertIn("roundwright-ci-read-only-handoff-${{ matrix.os }}-${{ env.CANDIDATE_SHA }}", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        guide = (ROOT / "docs" / "operations" / "ci-read-only-handoff.md").read_text(encoding="utf-8")
        self.assertIn("no dispatch trigger", guide)
        self.assertIn("no receipt or handoff remains active", guide)

    def test_docker_consumer_matrix_helpers_load_without_module_registration(self) -> None:
        """The fixture writer's dynamic helper loader need not register modules."""

        helpers = load_docker_consumer_test_helpers()
        expected = tuple((mode, diagnostic) for _, mode, diagnostic in helpers._HOSTED_NEGATIVE_CASES)
        self.assertEqual(helpers.hosted_workflow_expectations(), expected)
        self.assertEqual(len(expected), 27)

    def test_docker_negative_scenarios_cover_every_workflow_invocation(self) -> None:
        """Hosted assertions consume one complete, reviewed projection each."""

        scenarios = load_docker_negative_scenarios()
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        import re
        calls = re.findall(r'expect_blocked (authoritative|read-only|test-only) "([^"]+)"', workflow)
        self.assertGreaterEqual(len(calls), 20)
        for mode, expected in calls:
            rendered = scenarios.scenario(mode, expected).render()
            self.assertEqual(rendered.count("\n"), 11)
            self.assertIn(f"mode: {mode}\n", rendered)
            self.assertIn(f"result: blocked ({scenarios.scenario(mode, expected).reason})", rendered)
        authority_missing = scenarios.scenario("authoritative", "authority-receipt mount: missing").render()
        self.assertIn("authority-receipt mount: missing", authority_missing)
        self.assertIn("authority receipt: missing", authority_missing)
        self.assertIn("result: blocked (authority-receipt mount is missing)", authority_missing)
        repository_drift = scenarios.scenario("test-only", "repository mount: evidence-mismatch").render()
        self.assertIn("repository mount: evidence-mismatch", repository_drift)
        self.assertIn("candidate: missing", repository_drift)
        authority_mismatch = scenarios.scenario("authoritative", "authority receipt: mismatch").render()
        self.assertIn("authority receipt: mismatch", authority_mismatch)
        self.assertNotIn("authority receipt: missing", authority_mismatch)
        self.assertIn('ci/docker_negative_scenarios.py "$mode" "$expected"', workflow)
        self.assertNotIn('canonical="$(printf', workflow)

    def test_docker_workflow_runs_correlated_typed_substitution_in_each_mode(self) -> None:
        """The hosted image invokes, rather than merely lists, this attack."""

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('sudo cp -a "$fixtures/state" "$fixtures/state-correlated"', workflow)
        correlated_writer = 'python ci/resolve_validation_toolchain.py exec-python -- ci/write_docker_consumer_fixture.py --candidate "$CANDIDATE_SHA" --state "$fixtures/state-correlated" --configuration "$fixtures/etc/config-correlated.toml" --authentication "$fixtures/run/auth-correlated.toml" --correlated-substitution'
        self.assertIn(correlated_writer, workflow)
        self.assertNotIn('from roundwright.docker_authority import canonical_fixture_envelope', workflow)
        host_owner = 'sudo chown -R "$USER" "$fixtures/state-correlated"'
        image_owner = 'sudo chown -R 65532:65532 "$fixtures/state-correlated"'
        self.assertIn(host_owner, workflow)
        self.assertLess(workflow.index(host_owner), workflow.index(correlated_writer))
        self.assertLess(workflow.index(correlated_writer), workflow.index(image_owner))
        self.assertLess(workflow.index(image_owner), workflow.index('sudo find "$fixtures/state-correlated" -type d -exec chmod 0750 {} +'))
        for mode, expected, state_access in (
            ("authoritative", "configuration mount: evidence-mismatch", "rw"),
            ("read-only", "state mount: evidence-mismatch", "ro"),
            ("test-only", "state mount: evidence-mismatch", "ro"),
        ):
            invocation = f'expect_blocked {mode} "{expected}" docker run --rm'
            self.assertIn(invocation, workflow)
            start = workflow.index(invocation)
            command = workflow[start:workflow.index("\n", start)]
            self.assertIn('config-correlated.toml:/etc/roundwright/config.toml:ro', command)
            self.assertIn('auth-correlated.toml:/run/roundwright/auth.toml:ro', command)
            self.assertIn(f'state-correlated:/var/lib/roundwright:{state_access}', command)
            self.assertTrue(command.endswith('"$image" doctor'))

    def test_docker_fixture_writer_records_the_serialized_native_host_installation(self) -> None:
        """The positive image fixture must persist exactly the mounted typed state evidence."""

        writer = load_docker_fixture_writer()
        helpers = load_docker_consumer_test_helpers()
        from roundwright.docker_consumer import DockerMountName, DockerOperationMode
        from roundwright.docker_entrypoint import preflight
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            (repository / ".git").mkdir(parents=True)
            candidate = helpers.write_self_contained_checkout(repository)
            output = root / "run" / "authority-receipt.json"
            state = root / "state"
            configuration = root / "etc" / "config.toml"
            authentication = root / "run" / "auth.toml"
            arguments = [
                "write_docker_consumer_fixture.py", "--candidate", candidate,
                "--output", str(output), "--state", str(state),
                "--configuration", str(configuration), "--authentication", str(authentication),
            ]
            with mock.patch.object(sys, "argv", arguments):
                self.assertEqual(writer.main(), 0)

            authority = writer.load_mounted_authority(output, candidate_sha=candidate)
            observed = writer.NativeHostControlStore(state / "native-host.sqlite3").observe()
            self.assertEqual(observed.candidate_sha, candidate)
            self.assertEqual(observed.installation_fingerprint, authority.native_host_installation.installation_fingerprint)
            self.assertEqual(observed.receipt_fingerprint, authority.native_host_installation.receipt.receipt_fingerprint)
            self.assertTrue(
                writer.NativeHostControlStore(state / "native-host.sqlite3").verify(
                    authority.native_host_installation
                ).accepted
            )
            connection = sqlite3.connect(state / "native-host.sqlite3")
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            finally:
                connection.close()
            self.assertFalse((state / "native-host.sqlite3-wal").exists())
            self.assertFalse((state / "native-host.sqlite3-shm").exists())

            identity = root / "consumer-identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate,
                "package_digest": "sha256:" + "b" * 64,
                "base_image_digest": "sha256:" + "c" * 64,
            }), encoding="utf-8")
            receipt_sha = hashlib.sha256(output.read_bytes()).hexdigest()
            base_environment = {
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": "sha256:" + "c" * 64,
                "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
                "XDG_CONFIG_HOME": "/etc",
                "XDG_STATE_HOME": "/var/lib",
            }
            for mode in DockerOperationMode:
                paths = {
                    DockerMountName.REPOSITORY: repository,
                    DockerMountName.STATE: state,
                    DockerMountName.CONFIGURATION: configuration,
                    DockerMountName.AUTHENTICATION: authentication,
                    DockerMountName.AUTHORITY_RECEIPT: output if mode is DockerOperationMode.AUTHORITATIVE else root / "unmounted-authority.json",
                }
                environment = {**base_environment, "ROUNDWRIGHT_DOCKER_MODE": mode.value}
                if mode is DockerOperationMode.AUTHORITATIVE:
                    environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_sha

                def mounted_access(path: Path, access_mode: int) -> bool:
                    return access_mode == os.R_OK or (
                        path == state and mode is DockerOperationMode.AUTHORITATIVE
                    )

                with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access):
                    report = preflight(environment, paths=paths, identity_path=identity)
                self.assertTrue(report.ready, f"{mode.value}: {report.reason}")

    def test_candidate_route_uses_candidate_lock_and_explicit_shared_cache(self) -> None:
        resolver = load_validation_resolver()
        candidate_lock = Path("candidate") / "ci" / "validation-toolchain.lock.toml"
        authoritative_cache = Path("authoritative") / ".roundlet" / "validation-tools"
        arguments = [
            "resolve_validation_toolchain.py",
            "--lock",
            str(candidate_lock),
            "--cache-root",
            str(authoritative_cache),
            "verify",
        ]
        with mock.patch.object(sys, "argv", arguments):
            parsed = resolver.parse_arguments()
        self.assertEqual(parsed.lock, candidate_lock)
        self.assertEqual(parsed.cache_root, authoritative_cache)
        self.assertEqual(parsed.operation, "verify")

        guide = (ROOT / "docs" / "operations" / "validation-toolchain.md").read_text(encoding="utf-8")
        self.assertIn("run the candidate's resolver and candidate lock", guide)
        self.assertIn("--cache-root <authoritative-checkout>/.roundlet/validation-tools", guide)
        instructions = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("isolated candidate Worker must execute the resolver and lock", instructions)
        self.assertIn("never validation evidence", instructions)

    def test_workflow_provisions_locked_toolchain_before_no_isolation_build(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        provision = "python ci/resolve_validation_toolchain.py provision"
        build = "python ci/resolve_validation_toolchain.py exec-python -- -m pip wheel --no-build-isolation"
        self.assertIn(provision, workflow)
        self.assertIn(build, workflow)
        self.assertLess(workflow.index(provision), workflow.index(build))
        self.assertNotIn('setuptools>=69" pipx uv', workflow)

    def test_platform_matrix_qualifies_one_uploaded_content_addressed_package(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("build-package:", workflow)
        self.assertIn("needs: build-package", workflow)
        self.assertIn("roundwright-package-${{ env.CANDIDATE_SHA }}", workflow)
        self.assertIn("actions/download-artifact@v4", workflow)
        self.assertIn("ci/verify_package_digest.py verify dist", workflow)
        self.assertIn("ci/verify_package_digest.py qualify dist", workflow)

    def test_docker_consumer_workflow_qualifies_the_uploaded_wheel_without_publication(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("docker-consumer-qualification:", workflow)
        self.assertIn("needs: build-package", workflow)
        self.assertIn("roundwright-package-${{ env.CANDIDATE_SHA }}", workflow)
        self.assertIn("ci/docker_consumer_qualification.py inputs dist --candidate", workflow)
        self.assertIn("docker pull \"${{ steps.docker-inputs.outputs.base_image }}\"", workflow)
        self.assertIn("docker build --network=none --file docker/Dockerfile", workflow)
        self.assertIn("ROUNDWRIGHT_WHEEL_SHA256=${{ steps.docker-inputs.outputs.wheel_sha256 }}", workflow)
        self.assertIn("CANDIDATE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn('ref: ${{ env.CANDIDATE_SHA }}', workflow)
        self.assertIn('ROUNDWRIGHT_DOCKER_CANDIDATE_SHA=$CANDIDATE_SHA', workflow)
        self.assertIn("docker image inspect --format '{{.Id}}'", workflow)
        self.assertIn("/workspace:ro", workflow)
        self.assertIn("/var/lib/roundwright:rw", workflow)
        self.assertIn('sudo chown -R 65532:65532 "$fixtures/state"', workflow)
        self.assertIn('sudo find "$fixtures/state" -type d -exec chmod 0750 {} +', workflow)
        self.assertIn('sudo find "$fixtures/state" -type f -exec chmod 0640 {} +', workflow)
        self.assertIn('common=(--network=none --read-only --tmpfs /tmp', workflow)
        self.assertIn('ROUNDWRIGHT_REPOSITORY_ROOT=/workspace', workflow)
        self.assertIn('XDG_CONFIG_HOME=/etc', workflow)
        self.assertIn('XDG_STATE_HOME=/var/lib', workflow)
        self.assertIn('docker run --rm "${common[@]}"', workflow)
        self.assertIn("ROUNDWRIGHT_DOCKER_MODE=authoritative", workflow)
        self.assertIn("ROUNDWRIGHT_DOCKER_MODE=read-only", workflow)
        self.assertIn("ROUNDWRIGHT_DOCKER_MODE=test-only", workflow)
        self.assertIn('"$image" status', workflow)
        self.assertIn('expect_status() {', workflow)
        for status in ("candidate: match", "worktree: match", "sqlite: ready", "native-host: match", "runtime-binding: match", "active-lock: held", "restart: observed", "cancellation: observed", "stale-recovery: observed"):
            self.assertIn(f'grep -F "{status}"', workflow)
        self.assertIn('"$image" run-once', workflow)
        self.assertIn('test "$exit_code" -eq 3', workflow)
        self.assertIn('git clone --no-local --no-checkout "$GITHUB_WORKSPACE" "$fixtures/repository"', workflow)
        self.assertIn('git -C "$fixtures/repository" checkout --detach "$CANDIDATE_SHA"', workflow)
        self.assertIn('test -d "$fixtures/repository/.git"', workflow)
        self.assertIn('test ! -e "$fixtures/repository/.git/objects/info/alternates"', workflow)
        self.assertNotIn('worktree add --detach "$fixtures/repository"', workflow)
        self.assertIn('git -C "$fixtures/repository" rev-parse HEAD', workflow)
        materialize = 'python ci/resolve_validation_toolchain.py exec-python -- ci/materialize_git_commit.py --repository "$fixtures/repository" --candidate "$CANDIDATE_SHA"'
        self.assertIn(materialize, workflow)
        self.assertIn('test -f "$fixtures/repository/.git/objects/${CANDIDATE_SHA:0:2}/${CANDIDATE_SHA:2}"', workflow)
        self.assertIn('test -f "$fixtures/repository/.git/roundwright-checkout.json"', workflow)
        repository_owner = 'sudo chown -R 65532:65532 "$fixtures/repository"'
        self.assertIn(repository_owner, workflow)
        self.assertIn('test "$(stat -c \'%u:%g\' "$fixtures/repository")" = "65532:65532"', workflow)
        self.assertIn('test "$(stat -c \'%u:%g\' "$fixtures/repository/.git")" = "65532:65532"', workflow)
        self.assertLess(workflow.index('git -C "$fixtures/repository" checkout --detach "$CANDIDATE_SHA"'), workflow.index(repository_owner))
        self.assertLess(workflow.index(repository_owner), workflow.index('common=(--network=none --read-only --tmpfs /tmp'))
        self.assertIn('python ci/resolve_validation_toolchain.py exec-python -- ci/write_docker_consumer_fixture.py --candidate "$CANDIDATE_SHA" --state "$fixtures/state"', workflow)
        self.assertIn('--configuration "$fixtures/etc/config.toml" --authentication "$fixtures/run/auth.toml"', workflow)
        fixture_writer = workflow.index('python ci/resolve_validation_toolchain.py exec-python -- ci/write_docker_consumer_fixture.py --candidate "$CANDIDATE_SHA"')
        recursive_owner = 'sudo chown -R 65532:65532 "$fixtures/state"'
        self.assertLess(fixture_writer, workflow.index(recursive_owner))
        self.assertIn('sudo find "$fixtures/state" -type d -exec chmod 0750 {} +', workflow)
        self.assertIn('sudo find "$fixtures/state" -type f -exec chmod 0640 {} +', workflow)
        self.assertIn('expect_blocked test-only "state mount: missing"', workflow)
        self.assertIn('No state bind also prevents typed configuration/authentication', workflow)
        self.assertIn('expect_blocked read-only "state mount: permission-mismatch"', workflow)
        self.assertIn('expect_blocked authoritative "authority-receipt mount: missing"', workflow)
        self.assertIn('expect_blocked test-only "authority-receipt mount: permission-mismatch"', workflow)
        self.assertIn('expect_blocked authoritative "state mount: ownership-mismatch"', workflow)
        self.assertIn('repository-dirty', workflow)
        self.assertIn('mounted-tree-drift', workflow)
        self.assertIn('sudo cp -a "$fixtures/repository" "$fixtures/repository-dirty"', workflow)
        self.assertNotIn('          cp -a "$fixtures/repository" "$fixtures/repository-dirty"', workflow)
        self.assertLess(
            workflow.index('sudo cp -a "$fixtures/repository" "$fixtures/repository-dirty"'),
            workflow.index('sudo chown -R 65532:65532 "$fixtures/repository-dirty"'),
        )
        self.assertIn('config-drift.toml', workflow)
        self.assertIn('auth-drift.toml', workflow)
        self.assertIn('state-drift/docker-runtime-evidence.json', workflow)
        self.assertIn('sudo cp -a "$fixtures/state" "$fixtures/state-drift"', workflow)
        self.assertNotIn('          cp -a "$fixtures/state" "$fixtures/state-drift"', workflow)
        self.assertLess(
            workflow.index('sudo cp -a "$fixtures/state" "$fixtures/state-drift"'),
            workflow.index('sudo chown -R 65532:65532 "$fixtures/state-drift"'),
        )
        for diagnostic in (
            "repository mount: evidence-mismatch", "configuration mount: missing", "authentication mount: missing",
            "repository mount: permission-mismatch", "configuration mount: permission-mismatch",
            "authentication mount: permission-mismatch", "authority-receipt mount: permission-mismatch",
            "authority receipt: mismatch",
        ):
            self.assertIn(f'"{diagnostic}"', workflow)
        self.assertIn('expect_blocked read-only "configuration mount: evidence-mismatch"', workflow)
        self.assertIn('expect_blocked test-only "authentication mount: evidence-mismatch"', workflow)
        self.assertIn('expect_blocked authoritative "state mount: evidence-mismatch"', workflow)
        self.assertNotIn('expect_blocked authoritative "authority receipt: missing"', workflow)
        self.assertNotIn('"repository mount: missing" docker', workflow)
        self.assertIn('if [ "$exit_code" -ne 2 ]; then', workflow)
        self.assertIn('canonical="$(python ci/resolve_validation_toolchain.py exec-python -- ci/docker_negative_scenarios.py', workflow)
        self.assertIn('if [ "$output" != "$canonical" ]; then', workflow)
        self.assertIn('docker consumer negative assertion failed: $mode/$expected diagnostic', workflow)
        self.assertNotIn("printf '%s\\n' \"$output\" >&2", workflow)
        self.assertNotIn("grep -F \"$expected\"", workflow)
        self.assertIn("for status in expired copied conflicting revoked", workflow)
        self.assertIn("authority-wrong-candidate.json", workflow)
        self.assertIn('cp "$fixtures/run/authority-receipt.json" "$fixtures/run/authority-writable.json"', workflow)
        self.assertIn('sudo chown 65532:65532 "$fixtures/run/authority-writable.json"', workflow)
        self.assertIn('sudo chmod 0660 "$fixtures/run/authority-writable.json"', workflow)
        self.assertIn('-v "$fixtures/run/authority-writable.json:/run/roundwright/authority-receipt.json:rw"', workflow)
        self.assertNotIn('test "$exit_code" -eq 2', workflow)
        self.assertNotIn("case \"$mode:$expected\" in", workflow)
        self.assertIn('docker_negative_scenarios.py "$mode" "$expected"', workflow)
        self.assertIn("roundwright-docker-fixtures", workflow)
        self.assertNotIn("| python ci/materialize_git_commit.py", workflow)
        self.assertNotIn("\n            python -c", workflow)
        self.assertIn('docker compose -f docker/compose.yaml run --rm roundwright-authoritative doctor', workflow)
        self.assertIn('docker compose -f docker/compose.yaml run --rm roundwright-read-only status', workflow)
        self.assertIn('docker compose -f docker/compose.yaml run --rm roundwright-test-only status', workflow)
        self.assertIn('export ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256="$receipt_sha"', workflow)
        self.assertNotIn('export ROUNDWRIGHT_AUTHORITY_RECEIPT_SHA256="$receipt_sha"', workflow)
        self.assertIn("roundwright-docker-consumer-qualification-${{ env.CANDIDATE_SHA }}", workflow)
        self.assertNotIn("docker push", workflow)

    def test_workflow_runs_pinned_reference_cli_against_every_devcontainer_path(self) -> None:
        """The public receipt exists only after real default and mode execution."""

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn('DEVCONTAINER_CLI_VERSION: "0.82.0"', workflow)
        self.assertIn('npm install --no-save --no-package-lock --prefix "$cli_root" "@devcontainers/cli@$DEVCONTAINER_CLI_VERSION"', workflow)
        self.assertIn('"$cli_root/node_modules/.bin/devcontainer" --version | grep -Fx "$DEVCONTAINER_CLI_VERSION"', workflow)
        command = 'ci/devcontainer_consumer_qualification.py --devcontainer "$devcontainer" --workspace "$fixtures/repository" --configuration-root "$GITHUB_WORKSPACE" --candidate "$CANDIDATE_SHA" --wheel-sha256 "${{ steps.docker-inputs.outputs.wheel_sha256 }}" --base-image-digest "${{ steps.docker-inputs.outputs.base_image_digest }}" --reference-cli-version "$DEVCONTAINER_CLI_VERSION" --output dist/devcontainer-consumer-qualification.json'
        self.assertIn(command, workflow)
        self.assertNotIn("--no-lockfile", workflow)
        self.assertNotIn("--noLockfile", workflow)
        self.assertIn('test -f dist/devcontainer-consumer-qualification.json', workflow)
        self.assertGreaterEqual(workflow.count("git diff --exit-code"), 2)
        self.assertIn('test -z "$(git status --porcelain --untracked-files=no)"', workflow)
        self.assertIn('roundwright-devcontainer-consumer-qualification-${{ env.CANDIDATE_SHA }}', workflow)
        self.assertIn('path: dist/devcontainer-consumer-qualification.json', workflow)
        self.assertLess(workflow.index('Install pinned Dev Container reference CLI'), workflow.index('Qualify the exact Dev Container consumer paths'))
        self.assertLess(workflow.index('Qualify the exact Dev Container consumer paths'), workflow.index('Record public-safe Docker qualification'))

    def test_docker_qualification_routes_every_python_helper_through_the_resolver(self) -> None:
        """Hosted Docker setup may bootstrap the resolver, never bypass its receipt."""

        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        docker_job = workflow[workflow.index("  docker-consumer-qualification:"):]
        for line in docker_job.splitlines():
            stripped = line.lstrip()
            if "python" not in line or stripped.startswith("#") or "uses:" in stripped or "python-version:" in stripped:
                continue
            self.assertIn("python ci/resolve_validation_toolchain.py", line)
        self.assertNotIn("python -c", docker_job)
        self.assertNotIn("| python", docker_job)

    def test_git_commit_materializer_writes_exact_loose_object_from_packed_start(self) -> None:
        materializer = load_git_commit_materializer()
        payload = b"tree " + b"0" * 40 + b"\nauthor Docker <docker@example.invalid> 0 +0000\n\nfixture\n"
        raw_object = b"commit " + str(len(payload)).encode("ascii") + b"\0" + payload
        candidate = hashlib.sha1(raw_object).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            git_directory = repository / ".git"
            packed = git_directory / "objects" / "pack"
            packed.mkdir(parents=True)
            (packed / "pack-fixture.pack").write_bytes(b"packed candidate already available")
            (git_directory / "HEAD").write_bytes(candidate.encode("ascii") + b"\n")

            target = materializer.materialize_loose_commit(repository, candidate, payload)

            self.assertEqual(target, git_directory / "objects" / candidate[:2] / candidate[2:])
            self.assertTrue(target.is_file())
            self.assertEqual(zlib.decompress(target.read_bytes()), raw_object)
            self.assertTrue((packed / "pack-fixture.pack").is_file())
            self.assertEqual(materializer.materialize_loose_commit(repository, candidate, payload), target)
            with self.assertRaises(ValueError):
                materializer.materialize_loose_commit(repository, candidate, b"copied payload")
            (git_directory / "HEAD").write_bytes(candidate.encode("ascii") + b"\\n")
            with self.assertRaises(ValueError):
                materializer.materialize_loose_commit(repository, candidate, payload)

    def test_git_commit_materializer_uses_real_detached_head_and_nul_object_header(self) -> None:
        materializer = load_git_commit_materializer()
        from roundwright.docker_entrypoint import _checkout_candidate
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            repository = Path(temporary) / "repository"
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "Docker fixture"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "docker@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "core.autocrlf", "false"], check=True)
            (source / "nested").mkdir()
            (source / "fixture.txt").write_text("fixture\n", encoding="utf-8")
            (source / "nested" / "tracked.txt").write_text("nested\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "fixture.txt", "nested/tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
            candidate = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "--no-local", "--no-checkout", str(source), str(repository)], check=True)
            subprocess.run(["git", "-C", str(repository), "checkout", "--detach", candidate], check=True, capture_output=True)
            payload = subprocess.run(["git", "-C", str(repository), "cat-file", "commit", candidate], check=True, capture_output=True).stdout

            self.assertEqual((repository / ".git" / "HEAD").read_bytes(), candidate.encode("ascii") + b"\n")
            raw_object = materializer._canonical_commit(payload)
            self.assertEqual(raw_object, b"commit " + str(len(payload)).encode("ascii") + b"\0" + payload)
            self.assertNotEqual(raw_object, b"commit " + str(len(payload)).encode("ascii") + b"\\0" + payload)
            manifest = materializer.materialize_checkout_evidence(repository, candidate)
            self.assertEqual(manifest, repository / ".git" / "roundwright-checkout.json")
            evidence = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(evidence["candidate_sha"], candidate)
            self.assertEqual(evidence["entries"], [
                {"path": "fixture.txt", "sha1": subprocess.run(
                    ["git", "-C", str(repository), "rev-parse", f"{candidate}:fixture.txt"], check=True, capture_output=True, text=True,
                ).stdout.strip()},
                {"path": "nested/tracked.txt", "sha1": subprocess.run(
                    ["git", "-C", str(repository), "rev-parse", f"{candidate}:nested/tracked.txt"], check=True, capture_output=True, text=True,
                ).stdout.strip()},
            ])
            self.assertEqual(_checkout_candidate(repository), candidate)
            (repository / "nested" / "tracked.txt").write_text("substituted\n", encoding="utf-8")
            self.assertIsNone(_checkout_candidate(repository))

    def test_docker_qualification_binds_artifact_base_and_dockerfile_without_paths(self) -> None:
        qualification = load_docker_qualification()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            wheel = dist / "roundwright-0.0.0-py3-none-any.whl"
            wheel.write_bytes(b"candidate wheel")
            digest = qualification.hashlib.sha256(wheel.read_bytes()).hexdigest()
            (dist / "package-digest.json").write_text(
                qualification.json.dumps({"wheel": wheel.name, "sha256": digest}) + "\n", encoding="utf-8"
            )
            dockerfile = root / "Dockerfile"
            dockerfile.write_text(
                "FROM python:3.12.13-slim-bookworm@sha256:" + "a" * 64
                + "\nCOPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL} /tmp/${ROUNDWRIGHT_WHEEL}\n"
                + "RUN python -m pip install --no-index --no-deps /tmp/${ROUNDWRIGHT_WHEEL}\nconsumer-identity.json\n",
                encoding="utf-8",
            )
            values = qualification.docker_inputs(dist, "b" * 40, dockerfile=dockerfile)
            self.assertEqual(values["wheel_sha256"], digest)
            self.assertEqual(values["base_image_digest"], "sha256:" + "a" * 64)
            self.assertNotIn(str(root), qualification.json.dumps(values, sort_keys=True))
            receipt = root / "receipt.json"
            with mock.patch.object(qualification, "_DOCKERFILE", dockerfile):
                qualification.record_qualification(
                    dist, "b" * 40, values["base_image"], "sha256:" + "c" * 64,
                    {name: "passed" for name in qualification._CHECKS}, receipt,
                )
            recorded = qualification.json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(recorded["candidate_sha"], "b" * 40)
            self.assertEqual(recorded["wheel_sha256"], digest)
            self.assertEqual(recorded["checks"]["offline_build"], "passed")
            self.assertEqual(recorded["built_image_id"], "sha256:" + "c" * 64)

    def test_workflow_does_not_restore_nonportable_windows_junctions(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        cache_step = """- name: Restore portable validation toolchain cache
        if: runner.os != 'Windows'
        uses: actions/cache@v4"""
        self.assertIn(cache_step, workflow)
        self.assertIn("path: .roundlet/validation-tools", workflow)

    def test_pipx_route_forces_pip_and_uses_one_offline_no_dependency_pair(self) -> None:
        verifier = load_install_verifier()
        environment = verifier.pipx_environment({"PIP_NO_INDEX": "1", "PIP_NO_DEPS": "1"})
        command = verifier.pipx_install_command(Path("tools/pipx"), Path("python"), Path("candidate.whl"))
        self.assertNotIn("PIPX_USE_UV", environment)
        self.assertNotIn("PIP_NO_INDEX", environment)
        self.assertNotIn("PIP_NO_DEPS", environment)
        self.assertEqual(command[2:4], ["--backend", "pip"])
        self.assertEqual(command[4:6], ["--python", str(Path("python"))])
        self.assertIn("--skip-maintenance", command)
        self.assertEqual(command.count("--pip-args=--no-index --no-deps"), 1)
        self.assertEqual(command[-1], "candidate.whl")

    def test_uv_route_uses_receipt_bound_tools_without_discovery_or_download(self) -> None:
        verifier = load_install_verifier()
        command = verifier.uv_tool_install_command(Path("tools/uv"), Path("python"), Path("candidate.whl"))
        self.assertEqual(command[:5], [str(Path("tools/uv")), "tool", "install", "--python", str(Path("python"))])
        self.assertIn("--no-python-downloads", command)
        self.assertIn("--no-config", command)
        self.assertIn("--offline", command)
        self.assertEqual(command[-2:], ["candidate.whl", "roundwright"])

    def test_installed_command_environment_precedes_the_inherited_path(self) -> None:
        verifier = load_install_verifier()
        environment = verifier.command_environment({"PATH": "parent"}, Path("isolated-bin"))
        self.assertEqual(environment["PATH"], f"isolated-bin{verifier.os.pathsep}parent")

    def test_pipx_validates_the_exposed_and_managed_launchers(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "pipx-home"
            exposed_directory = root / "pipx-bin"
            scripts = home / "venvs" / "roundwright" / ("Scripts" if verifier.os.name == "nt" else "bin")
            scripts.mkdir(parents=True)
            exposed_directory.mkdir()
            managed = verifier.executable(scripts, "roundwright")
            exposed = verifier.executable(exposed_directory, "roundwright")
            managed.write_bytes(b"managed")
            exposed.write_bytes(b"exposed")
            exposed_command, managed_command = verifier.pipx_commands(home, exposed_directory)
            self.assertEqual(exposed_command, exposed.resolve())
            self.assertEqual(managed_command, managed.resolve())
            self.assertEqual(
                verifier.command_environment({"PATH": "parent"}, managed_command.parent)["PATH"],
                f"{managed_command.parent}{verifier.os.pathsep}parent",
            )

    def test_pipx_managed_command_rejects_absent_and_traversal_paths(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "pipx-home"
            home.mkdir()
            with self.assertRaisesRegex(ValueError, "managed command is unavailable"):
                verifier.pipx_managed_command(home)
            with self.assertRaisesRegex(ValueError, "application path is invalid"):
                verifier.pipx_managed_command(home, "../outside")

    def test_pipx_default_environment_clears_overrides_for_a_temporary_profile(self) -> None:
        verifier = load_install_verifier()
        profile = Path("temporary-profile")
        environment = verifier.pipx_default_environment(
            {
                "PIPX_HOME": "override-home",
                "PIPX_BIN_DIR": "override-bin",
                "XDG_BIN_HOME": "override-xdg-bin",
                "XDG_CACHE_HOME": "override-xdg-cache",
                "XDG_DATA_HOME": "override-xdg-data",
            },
            profile,
        )
        home, bin_directory = verifier.pipx_default_paths(profile)
        self.assertNotIn("PIPX_HOME", environment)
        self.assertNotIn("PIPX_BIN_DIR", environment)
        self.assertFalse({"XDG_BIN_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"} & set(environment))
        self.assertEqual(environment["HOME"], str(profile))
        if verifier.os.name == "nt":
            self.assertEqual(home, profile / "AppData" / "Local" / "pipx" / "pipx")
        self.assertEqual(bin_directory, profile / ".local" / "bin")
        self.assertNotEqual(home, Path("override-home"))

    def test_pipx_smoke_runs_every_command_through_the_exposed_launcher(self) -> None:
        verifier = load_install_verifier()
        exposed = Path("pipx-bin") / verifier.executable(Path(), "roundwright").name
        commands: list[list[str]] = []

        def record(command: list[str], **_kwargs: object) -> None:
            commands.append(command)

        with mock.patch.object(verifier, "run", side_effect=record):
            verifier.pipx_smoke(exposed, cwd=Path("isolated"), environment={})
        self.assertEqual(
            commands,
            [
                [str(exposed), "--help"],
                [str(exposed), "doctor"],
                [str(exposed), "status"],
                [str(exposed), "db", "check"],
            ],
        )

    def test_relative_distribution_path_selects_one_absolute_wheel_before_cwd_changes(self) -> None:
        verifier = load_install_verifier()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dist = root / "dist"
            dist.mkdir()
            wheel = dist / "roundwright-0.0.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            original = Path.cwd()
            try:
                os.chdir(root)
                self.assertEqual(verifier.select_wheel(Path("dist")), wheel.resolve())
            finally:
                os.chdir(original)
            (dist / "roundwright-extra.whl").write_bytes(b"wheel")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                verifier.select_wheel(dist)
            with self.assertRaisesRegex(ValueError, "distribution directory is unavailable"):
                verifier.select_wheel(root / "missing")
