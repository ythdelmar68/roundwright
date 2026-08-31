"""Hermetic checks for the minimal Docker deployment consumer contract."""

from __future__ import annotations

import io
import contextlib
import os
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import zlib
import re

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ci.docker_negative_scenarios import _SCENARIOS, scenario
from roundwright.docker_consumer import (
    DockerConsumerContract,
    DockerIdentityStatus,
    DockerMountCheck,
    DockerMountName,
    DockerMountStatus,
    DockerOperationMode,
    evaluate_docker_consumer,
    render_docker_consumer_diagnostics,
)
from roundwright.docker_entrypoint import _checkout_candidate, _render_mounted_status, main as docker_entrypoint_main, preflight
from roundwright.docker_authority import DockerAuthorityAdapterError, canonical_fixture_envelope, evaluate_mounted_authority, runtime_environment_fingerprint
from roundwright.docker_authority import canonical_native_host_installation
from roundwright.native_host import InvocationSource, NativeHostControlStore, NativeHostMountedRuntimeEvidence
from roundwright.cli import main


def digest(character: str) -> str:
    return "sha256:" + character * 64


def mounted_runtime_environment() -> dict[str, str]:
    return {
        "ROUNDWRIGHT_REPOSITORY_ROOT": "/workspace",
        "XDG_CONFIG_HOME": "/etc",
        "XDG_STATE_HOME": "/var/lib",
    }


def mounts(status: DockerMountStatus = DockerMountStatus.READY, *, authority: DockerMountStatus | None = None) -> tuple[DockerMountCheck, ...]:
    return tuple(DockerMountCheck(name, authority if name is DockerMountName.AUTHORITY_RECEIPT and authority is not None else status) for name in DockerMountName)


def write_self_contained_checkout(
    repository: Path,
    *,
    body: bytes | None = None,
    tracked_file: tuple[str, bytes] | None = None,
) -> str:
    """Create only the detached Git evidence available to the minimal image."""

    git_directory = repository / ".git"
    entries: list[dict[str, str]] = []
    tree_body = b""
    if tracked_file is not None:
        name, content = tracked_file
        raw_blob = b"blob " + str(len(content)).encode("ascii") + b"\0" + content
        blob_sha = hashlib.sha1(raw_blob).hexdigest()
        blob_path = git_directory / "objects" / blob_sha[:2] / blob_sha[2:]
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        blob_path.write_bytes(zlib.compress(raw_blob))
        (repository / name).write_bytes(content)
        tree_body = b"100644 " + name.encode("utf-8") + b"\0" + bytes.fromhex(blob_sha)
        entries.append({"path": name, "sha1": blob_sha})
    tree_raw = b"tree " + str(len(tree_body)).encode("ascii") + b"\0" + tree_body
    tree_sha = hashlib.sha1(tree_raw).hexdigest()
    body = body or (
        b"tree " + tree_sha.encode("ascii") + b"\nauthor Fixture <fixture@example.invalid> 0 +0000"
        b"\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nfixture\n"
    )
    raw = f"commit {len(body)}".encode("ascii") + b"\0" + body
    candidate = hashlib.sha1(raw).hexdigest()
    object_path = git_directory / "objects" / candidate[:2] / candidate[2:]
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(zlib.compress(raw))
    tree_path = git_directory / "objects" / tree_sha[:2] / tree_sha[2:]
    tree_path.parent.mkdir(parents=True, exist_ok=True)
    tree_path.write_bytes(zlib.compress(tree_raw))
    (git_directory / "HEAD").write_text(candidate + "\n", encoding="ascii")
    (git_directory / "roundwright-checkout.json").write_text(
        json.dumps({"candidate_sha": candidate, "entries": entries, "tree_sha": tree_sha}, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return candidate


def write_typed_mounted_evidence(paths: dict[DockerMountName, Path], candidate: str, *, now: datetime) -> dict[str, object]:
    """Create disposable typed inputs; production must only parse them."""

    material = canonical_fixture_envelope(candidate, now=now)
    paths[DockerMountName.CONFIGURATION].write_text(
        "[runtime]\n"
        f"candidate_sha = {json.dumps(candidate)}\n"
        f"binding = {json.dumps(material['identity']['runtime_binding'])}\n",
        encoding="utf-8",
    )
    paths[DockerMountName.AUTHENTICATION].write_text(
        "[operator]\n"
        f"candidate_sha = {json.dumps(candidate)}\n"
        f"identity = {json.dumps(material['mounts']['authentication_identity'])}\n",
        encoding="utf-8",
    )
    paths[DockerMountName.AUTHORITY_RECEIPT].write_text(
        json.dumps(material, sort_keys=True, separators=(",", ":")), encoding="utf-8",
    )
    store = NativeHostControlStore(paths[DockerMountName.STATE] / "native-host.sqlite3")
    assert store.install(canonical_native_host_installation(candidate, now=now)).accepted
    installation = canonical_native_host_installation(candidate, now=now)
    assert store.record_mounted_runtime_evidence(NativeHostMountedRuntimeEvidence(
        installation.installation_fingerprint,
        installation.receipt.receipt_fingerprint,
        candidate,
        installation.identity.runtime_binding,
        material["mounts"]["authentication_identity"],
        runtime_environment_fingerprint(candidate, material["mounts"]["runtime_environment"]),
    )).accepted
    (paths[DockerMountName.STATE] / "docker-runtime-evidence.json").write_text(
        json.dumps(
            {
                "authentication_identity": material["mounts"]["authentication_identity"],
                "candidate_sha": candidate,
                "installation_fingerprint": installation.installation_fingerprint,
                "receipt_fingerprint": installation.receipt.receipt_fingerprint,
                "runtime_binding": material["identity"]["runtime_binding"],
                "runtime_environment": material["mounts"]["runtime_environment"],
            },
            sort_keys=True, separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return material


_HOSTED_NEGATIVE_CASES = (
    ("state-missing", "test-only", "state mount: missing"),
    ("state-writable-read-only", "read-only", "state mount: permission-mismatch"),
    ("authority-mount-missing", "authoritative", "authority-receipt mount: missing"),
    ("authority-present-nonauthoritative", "test-only", "authority-receipt mount: permission-mismatch"),
    ("state-ownership", "authoritative", "state mount: ownership-mismatch"),
    ("repository-dirty", "test-only", "repository mount: evidence-mismatch"),
    ("configuration-drift", "read-only", "configuration mount: evidence-mismatch"),
    ("authentication-drift", "test-only", "authentication mount: evidence-mismatch"),
    ("state-drift", "authoritative", "state mount: evidence-mismatch"),
    ("repository-omitted", "test-only", "repository mount: evidence-mismatch"),
    ("configuration-missing", "read-only", "configuration mount: missing"),
    ("authentication-missing", "test-only", "authentication mount: missing"),
    ("state-read-only-authoritative", "authoritative", "state mount: permission-mismatch"),
    ("repository-writable", "test-only", "repository mount: permission-mismatch"),
    ("configuration-writable", "read-only", "configuration mount: permission-mismatch"),
    ("authentication-writable", "test-only", "authentication mount: permission-mismatch"),
    ("authority-writable", "authoritative", "authority-receipt mount: permission-mismatch"),
    ("authority-malformed", "authoritative", "authority receipt: mismatch"),
    ("authority-digest-mismatch", "authoritative", "authority receipt: mismatch"),
    ("authority-expired", "authoritative", "authority receipt: mismatch"),
    ("authority-copied", "authoritative", "authority receipt: mismatch"),
    ("authority-conflicting", "authoritative", "authority receipt: mismatch"),
    ("authority-revoked", "authoritative", "authority receipt: mismatch"),
    ("authority-wrong-candidate", "authoritative", "authority receipt: mismatch"),
)


def hosted_workflow_expectations() -> tuple[tuple[str, str], ...]:
    """Expand the workflow's literal status loop into hosted invocations."""

    cases: list[tuple[str, str]] = []
    statuses: tuple[str, ...] | None = None
    call = re.compile(r'^\s*expect_blocked\s+(\S+)\s+"([^"]+)"')
    status_loop = re.compile(r"^\s*for status in ([a-z ]+); do\s*$")
    for line in (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").splitlines():
        loop_match = status_loop.match(line)
        if loop_match:
            statuses = tuple(loop_match.group(1).split())
            continue
        call_match = call.match(line)
        if call_match:
            cases.extend((call_match.group(1), call_match.group(2)) for _ in (statuses or ("one",)))
        if statuses is not None and line.strip() == "done":
            statuses = None
    return tuple(cases)


class DockerConsumerTests(unittest.TestCase):
    def test_entrypoint_reads_head_from_self_contained_git_metadata_without_git(self) -> None:
        """A mounted repository must not depend on a Git executable or outside metadata."""

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            (repository / ".git").mkdir(parents=True)
            expected = write_self_contained_checkout(repository)
            with mock.patch.dict(os.environ, {"PATH": ""}, clear=False):
                self.assertEqual(_checkout_candidate(repository), expected)

            linked = Path(temporary) / "linked-worktree"
            linked.mkdir()
            (linked / ".git").write_text("gitdir: /outside/mounted-boundary\n", encoding="utf-8")
            self.assertIsNone(_checkout_candidate(linked))

    def test_entrypoint_rejects_symbolic_malformed_and_copied_git_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbolic = root / "symbolic"
            (symbolic / ".git").mkdir(parents=True)
            (symbolic / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
            self.assertIsNone(_checkout_candidate(symbolic))

            malformed = root / "malformed"
            (malformed / ".git").mkdir(parents=True)
            (malformed / ".git" / "HEAD").write_text("not-a-candidate\n", encoding="ascii")
            self.assertIsNone(_checkout_candidate(malformed))

            copied = root / "copied"
            (copied / ".git").mkdir(parents=True)
            candidate = write_self_contained_checkout(copied)
            object_path = copied / ".git" / "objects" / candidate[:2] / candidate[2:]
            wrong = b"commit 5\0wrong"
            object_path.write_bytes(zlib.compress(wrong))
            self.assertIsNone(_checkout_candidate(copied))

    def test_entrypoint_rejects_substituted_tree_or_dirty_tracked_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repository"
            git_directory = repository / ".git"
            tracked_path = repository / "tracked.txt"
            git_directory.mkdir(parents=True)
            tracked_path.write_bytes(b"expected\n")
            blob = b"expected\n"
            blob_raw = b"blob " + str(len(blob)).encode("ascii") + b"\0" + blob
            blob_sha = hashlib.sha1(blob_raw).hexdigest()
            tree_body = b"100644 tracked.txt\0" + bytes.fromhex(blob_sha)
            tree_raw = b"tree " + str(len(tree_body)).encode("ascii") + b"\0" + tree_body
            tree_sha = hashlib.sha1(tree_raw).hexdigest()
            commit_body = b"tree " + tree_sha.encode("ascii") + b"\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nfixture\n"
            commit_raw = b"commit " + str(len(commit_body)).encode("ascii") + b"\0" + commit_body
            candidate = hashlib.sha1(commit_raw).hexdigest()
            for object_sha, raw in ((blob_sha, blob_raw), (tree_sha, tree_raw), (candidate, commit_raw)):
                object_path = git_directory / "objects" / object_sha[:2] / object_sha[2:]
                object_path.parent.mkdir(parents=True, exist_ok=True)
                object_path.write_bytes(zlib.compress(raw))
            (git_directory / "HEAD").write_text(candidate + "\n", encoding="ascii")
            manifest = {"candidate_sha": candidate, "entries": [{"path": "tracked.txt", "sha1": blob_sha}], "tree_sha": tree_sha}
            (git_directory / "roundwright-checkout.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            self.assertEqual(_checkout_candidate(repository), candidate)
            tracked_path.write_bytes(b"substituted\n")
            self.assertIsNone(_checkout_candidate(repository))
            tracked_path.write_bytes(b"expected\n")
            manifest["tree_sha"] = "0" * 40
            (git_directory / "roundwright-checkout.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            self.assertIsNone(_checkout_candidate(repository))

    def test_typed_native_host_fixture_initializes_sqlite_and_enforces_one_active_lock(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            control_store = NativeHostControlStore(Path(temporary) / "native-host.sqlite3")
            installation = canonical_native_host_installation("a" * 40, now=now)
            self.assertTrue(control_store.install(installation).accepted)
            self.assertTrue(control_store.verify(installation).accepted)
            self.assertTrue(control_store.admit(installation, "fixture-one", InvocationSource.ONE_SHOT, now=now).accepted)
            self.assertFalse(control_store.admit(installation, "fixture-two", InvocationSource.SCHEDULER_WAKE, now=now).accepted)
            self.assertTrue(control_store.finish(installation, "fixture-one", "completed", now=now).accepted)
            self.assertTrue(control_store.admit(installation, "fixture-two", InvocationSource.SCHEDULER_WAKE, now=now).accepted)

    def test_mounted_status_observes_persisted_lifecycle_without_dispatch(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            installation = canonical_native_host_installation("a" * 40, now=now)
            store = NativeHostControlStore(state / "native-host.sqlite3")
            self.assertTrue(store.install(installation).accepted)
            self.assertTrue(store.admit(installation, "restart", InvocationSource.ONE_SHOT, now=now).accepted)
            self.assertTrue(store.finish(installation, "restart", "completed", now=now).accepted)
            self.assertTrue(store.admit(installation, "cancel", InvocationSource.ONE_SHOT, now=now).accepted)
            self.assertTrue(store.finish(installation, "cancel", "cancelled", now=now).accepted)
            stale_at = now - timedelta(hours=1)
            self.assertTrue(store.admit(installation, "stale", InvocationSource.SCHEDULER_WAKE, now=stale_at, lease_for=timedelta(seconds=1)).accepted)
            self.assertTrue(store.recover_stale(installation, "stale", now=now, stale_after=timedelta(minutes=1)).accepted)
            self.assertTrue(store.admit(installation, "active", InvocationSource.ONE_SHOT, now=now).accepted)
            paths = {name: state for name in DockerMountName}
            paths[DockerMountName.STATE] = state
            output = io.StringIO()
            self.assertEqual(_render_mounted_status(output, paths=paths, candidate="a" * 40, authoritative=True), 0)
            rendered = output.getvalue()
            for value in ("candidate: match", "worktree: match", "sqlite: ready", "native-host: match", "runtime-binding: match", "receipt: match", "active-lock: held", "restart: observed", "cancellation: observed", "stale-recovery: observed", "result: ready"):
                self.assertIn(value, rendered)
            self.assertNotIn(str(state), rendered)

            connection = sqlite3.connect(state / "native-host.sqlite3")
            try:
                with connection:
                    connection.execute("UPDATE native_host_metadata SET value = ? WHERE key = 'candidate_sha'", ("b" * 40,))
            finally:
                connection.close()
            output = io.StringIO()
            self.assertEqual(_render_mounted_status(output, paths=paths, candidate="a" * 40, authoritative=True), 2)
            self.assertEqual(output.getvalue(), "roundwright docker status\nresult: blocked\n")
    def test_mounted_authority_adapter_accepts_typed_canonical_fixture(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authority.json"
            path.write_text(json.dumps(canonical_fixture_envelope("a" * 40, now=now), sort_keys=True, separators=(",", ":")), encoding="utf-8")
            decision = evaluate_mounted_authority(path, candidate_sha="a" * 40, now=now)
        self.assertTrue(decision.authorized)

    def test_mounted_authority_adapter_rejects_missing_or_malformed_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authority.json"
            with self.assertRaises(DockerAuthorityAdapterError):
                evaluate_mounted_authority(path, candidate_sha="a" * 40, now=datetime.now(timezone.utc))

    def test_mounted_authority_adapter_blocks_typed_receipt_and_identity_drift(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "authority.json"
            def decision_for(mutator: object):
                envelope = canonical_fixture_envelope("a" * 40, now=now)
                mutator(envelope)  # type: ignore[operator]
                path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                return evaluate_mounted_authority(path, candidate_sha="a" * 40, now=now)

            for status in ("expired", "copied", "conflicting", "revoked"):
                self.assertFalse(decision_for(lambda envelope, status=status: envelope["verification"].update({"status": status})).authorized)  # type: ignore[index]
            self.assertFalse(decision_for(lambda envelope: envelope["verification"].update({"state_id": "12345678-1234-5678-1234-567812345678"})).authorized)  # type: ignore[index]
            def runtime_drift(envelope: dict[str, object]) -> None:
                binding = json.loads(envelope["identity"]["runtime_binding"])  # type: ignore[index]
                binding["resolved_digest"] = digest("f")
                envelope["identity"]["runtime_binding"] = json.dumps(binding, sort_keys=True, separators=(",", ":"))  # type: ignore[index]
            self.assertFalse(decision_for(runtime_drift).authorized)
            envelope = canonical_fixture_envelope("a" * 40, now=now)
            envelope["candidate_sha"] = "b" * 40
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(DockerAuthorityAdapterError):
                evaluate_mounted_authority(path, candidate_sha="a" * 40, now=now)
            envelope = canonical_fixture_envelope("a" * 40, now=now)
            envelope["mounts"]["runtime_environment"]["XDG_STATE_HOME"] = "/unexpected"  # type: ignore[index]
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(DockerAuthorityAdapterError):
                evaluate_mounted_authority(path, candidate_sha="a" * 40, now=now)
            with self.assertRaises(DockerAuthorityAdapterError):
                evaluate_mounted_authority(path, candidate_sha="not-a-candidate", now=datetime.now(timezone.utc))
            path.write_text("{}", encoding="utf-8")
            with self.assertRaises(DockerAuthorityAdapterError):
                evaluate_mounted_authority(path, candidate_sha="a" * 40, now=datetime.now(timezone.utc))
    def contract(self, **changes: object) -> DockerConsumerContract:
        values: dict[str, object] = {
            "mode": DockerOperationMode.AUTHORITATIVE,
            "candidate_sha": "a" * 40,
            "observed_candidate_sha": "a" * 40,
            "package_digest": digest("b"),
            "observed_package_digest": digest("b"),
            "base_image_digest": digest("c"),
            "observed_base_image_digest": digest("c"),
            "mounts": mounts(),
            "authority_receipt_digest": digest("d"),
            "observed_authority_receipt_digest": digest("d"),
            "observed_authority_receipt_candidate_sha": "a" * 40,
        }
        values.update(changes)
        return DockerConsumerContract(**values)  # type: ignore[arg-type]

    def test_authoritative_mode_requires_complete_candidate_bound_inputs(self) -> None:
        self.assertTrue(evaluate_docker_consumer(self.contract()).ready)
        self.assertFalse(evaluate_docker_consumer(self.contract(authority_receipt_digest=None)).ready)
        self.assertFalse(evaluate_docker_consumer(self.contract(observed_authority_receipt_candidate_sha="e" * 40)).ready)
        self.assertFalse(evaluate_docker_consumer(self.contract(authority_inputs_conflict=True)).ready)

    def test_read_only_and_test_only_reject_authority_ambiguity(self) -> None:
        for mode in (DockerOperationMode.READ_ONLY, DockerOperationMode.TEST_ONLY):
            clean = self.contract(mode=mode, mounts=mounts(authority=DockerMountStatus.NOT_APPLICABLE), authority_receipt_digest=None, observed_authority_receipt_digest=None, observed_authority_receipt_candidate_sha=None)
            self.assertTrue(evaluate_docker_consumer(clean).ready)
            self.assertFalse(evaluate_docker_consumer(self.contract(mode=mode)).ready)

    def test_mount_mismatch_blocks_before_authority_use(self) -> None:
        for status in (
            DockerMountStatus.MISSING,
            DockerMountStatus.OWNERSHIP_MISMATCH,
            DockerMountStatus.PERMISSION_MISMATCH,
        ):
            report = evaluate_docker_consumer(self.contract(mounts=mounts(status)))
            self.assertFalse(report.ready)
            self.assertIn(status.value, report.reason)

    def test_doctor_report_is_path_and_secret_free(self) -> None:
        report = evaluate_docker_consumer(self.contract(mounts=mounts(DockerMountStatus.PERMISSION_MISMATCH)))
        output = io.StringIO()
        render_docker_consumer_diagnostics(report, output)
        rendered = output.getvalue().lower()
        self.assertIn("repository mount: permission-mismatch", rendered)
        self.assertIn("candidate: match", rendered)
        self.assertIn("authority receipt: match", rendered)
        self.assertIn("result: blocked", rendered)
        self.assertFalse(any(value in rendered for value in ("/workspace", "token", "credential", "sha256:")))

    def test_cli_doctor_accepts_a_path_free_contract(self) -> None:
        arguments = [
            "doctor", "--docker-mode", "authoritative", "--docker-candidate-sha", "a" * 40,
            "--docker-observed-candidate-sha", "a" * 40, "--docker-package-digest", digest("b"), "--docker-observed-package-digest", digest("b"),
            "--docker-base-image-digest", digest("c"), "--docker-observed-base-image-digest", digest("c"),
            "--docker-authority-receipt-digest", digest("d"), "--docker-observed-authority-receipt-digest", digest("d"), "--docker-observed-authority-receipt-candidate-sha", "a" * 40,
        ]
        arguments.extend(f"--docker-mount={name.value}=ready" for name in DockerMountName)
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [sys.executable]), contextlib.redirect_stdout(output):
            # The test invokes the module interpreter rather than an installed
            # console launcher, so ordinary entrypoint diagnostics remain 2.
            self.assertEqual(main(arguments), 2)
        rendered = output.getvalue().lower()
        self.assertIn("roundwright docker consumer preflight", rendered)
        self.assertIn("authority receipt: match", rendered)
        self.assertNotIn("sha256:", rendered)

    def test_dockerfile_uses_a_pinned_base_and_one_offline_wheel(self) -> None:
        dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12.13-slim-bookworm@sha256:", dockerfile)
        self.assertIn("COPY --chown=65532:65532 dist/${ROUNDWRIGHT_WHEEL} /tmp/${ROUNDWRIGHT_WHEEL}", dockerfile)
        self.assertIn("sha256sum --check --strict", dockerfile)
        self.assertIn("pip install --no-index --no-deps", dockerfile)
        self.assertNotIn("COPY src", dockerfile)
        self.assertNotIn("COPY .", dockerfile)
        self.assertIn("roundwright.docker_entrypoint", dockerfile)

    def test_compose_documents_only_host_owned_explicit_mounts(self) -> None:
        compose = (ROOT / "docker" / "compose.yaml").read_text(encoding="utf-8")
        for target in (
            "/workspace:ro",
            "/var/lib/roundwright:rw",
            "/var/lib/roundwright:ro",
            "/etc/roundwright/config.toml:ro",
            "/run/roundwright/auth.toml:ro",
            "/run/roundwright/authority-receipt.json:ro",
        ):
            self.assertIn(target, compose)
        self.assertIn('user: "65532:65532"', compose)
        self.assertIn("read_only: true", compose)
        self.assertNotIn("image: ghcr.io", compose)
        self.assertIn("roundwright-authoritative:", compose)
        self.assertIn("roundwright-read-only:", compose)
        self.assertIn("roundwright-test-only:", compose)
        self.assertIn("ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256:", compose)
        self.assertNotIn("/dev/null", compose)
        # Service-level environments replace the extension mapping in Compose,
        # so every mode must restate the mounted runtime paths explicitly.
        self.assertEqual(compose.count("ROUNDWRIGHT_REPOSITORY_ROOT: /workspace"), 3)
        self.assertEqual(compose.count("XDG_CONFIG_HOME: /etc"), 3)
        self.assertEqual(compose.count("XDG_STATE_HOME: /var/lib"), 3)

    def test_operator_documentation_matches_current_docker_contract(self) -> None:
        documentation = (ROOT / "docs" / "operations" / "docker-consumer.md").read_text(encoding="utf-8")
        for value in (
            "--build-arg ROUNDWRIGHT_CANDIDATE_SHA=<40-lowercase-hex>",
            "--build-arg ROUNDWRIGHT_BASE_IMAGE_DIGEST=sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2",
            "ci/write_docker_consumer_fixture.py --candidate",
            "roundwright-authoritative doctor",
            "roundwright-read-only status",
            "roundwright-test-only status",
            "roundwright-test-only run-once",
            "ROUNDWRIGHT_AUTHORITY_RECEIPT=<authority-receipt.json>",
            "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256=<64-lowercase-hex>",
            "returns exit code 3",
        ):
            self.assertIn(value, documentation)
        self.assertNotIn("\nROUNDWRIGHT_AUTHORITY_RECEIPT_SHA256=", documentation)
        self.assertEqual(documentation.count("ROUNDWRIGHT_WHEEL=<exact-wheel-name>"), 4)
        self.assertEqual(documentation.count("ROUNDWRIGHT_REPOSITORY=<repository>"), 4)
        self.assertEqual(documentation.count("ROUNDWRIGHT_AUTHORITY_RECEIPT=<authority-receipt.json>"), 1)
        self.assertNotIn("--docker-authority-receipt-matches-candidate", documentation)

    def test_entrypoint_observes_real_mounts_and_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir(); paths[DockerMountName.STATE].mkdir()
            paths[DockerMountName.CONFIGURATION].write_text("[runtime]\nschema_version = 1\n", encoding="utf-8")
            paths[DockerMountName.AUTHENTICATION].write_text("# fixture\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text(json.dumps({"candidate_sha": "a" * 40}), encoding="utf-8")
            identity = root / "identity.json"
            identity.write_text(json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}), encoding="utf-8")
            receipt = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment = {"ROUNDWRIGHT_DOCKER_MODE": "authoritative", "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64, "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"), "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256": receipt, **mounted_runtime_environment()}
            # A digest-matching JSON fragment is not authority: mounted typed
            # canonical evidence must pass the existing deployment evaluator.
            with mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                self.assertFalse(preflight(environment, paths=paths, identity_path=identity).ready)
                environment["ROUNDWRIGHT_DOCKER_CANDIDATE_SHA"] = "e" * 40
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(report.ready)
            self.assertEqual(report.candidate, DockerIdentityStatus.MISMATCH)

    def test_entrypoint_accepts_typed_authoritative_mounted_evidence(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            paths[DockerMountName.CONFIGURATION].write_text("[runtime]\nschema_version = 1\n", encoding="utf-8")
            paths[DockerMountName.AUTHENTICATION].write_text("# fixture\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text(
                json.dumps(canonical_fixture_envelope("a" * 40, now=now), sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            identity = root / "identity.json"
            identity.write_text(
                json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}),
                encoding="utf-8",
            )
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            self.assertTrue(NativeHostControlStore(paths[DockerMountName.STATE] / "native-host.sqlite3").install(canonical_native_host_installation("a" * 40, now=now)).accepted)
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "authoritative",
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256": receipt_sha,
                **mounted_runtime_environment(),
            }
            def mounted_access(path: Path, mode: int) -> bool:
                if mode == os.R_OK:
                    return True
                return path is paths[DockerMountName.STATE]

            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK or path == paths[DockerMountName.STATE]), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
                self.assertTrue(report.ready, report.reason)
            def writable_authority(path: Path, mode: int) -> bool:
                return mode == os.R_OK or path in {
                    paths[DockerMountName.STATE], paths[DockerMountName.AUTHORITY_RECEIPT]
                }
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=writable_authority), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertEqual(report.exit_code, 2)
            self.assertIn("authority-receipt mount is permission-mismatch", report.reason)
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="b" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(report.ready)
            self.assertIn("repository mount is evidence-mismatch", report.reason)

            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_sha
            paths[DockerMountName.CONFIGURATION].write_text(
                "[runtime]\ncandidate_sha = \"a\"\nbinding = \"malformed\"\n", encoding="utf-8",
            )
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK or path == paths[DockerMountName.STATE]), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertEqual(report.exit_code, 2)
            self.assertIn("configuration mount is evidence-mismatch", report.reason)

    def test_entrypoint_reports_complete_no_state_bind_diagnostic(self) -> None:
        """An absent state bind makes dependent typed identities unverifiable."""

        now = datetime.now(timezone.utc)
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            write_typed_mounted_evidence(paths, candidate, now=now)
            identity = root / "identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate,
                "package_digest": digest("b"),
                "base_image_digest": digest("c"),
            }), encoding="utf-8")
            missing_state = root / "state-unmounted"
            paths[DockerMountName.STATE] = missing_state
            # The hosted no-state scenario also supplies no authority bind in
            # test-only mode; preserve the image-bound absent-path shape.
            paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-unmounted.json"
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "test-only",
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                **mounted_runtime_environment(),
            }
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda _path, mode: mode == os.R_OK), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            rendered = io.StringIO()
            render_docker_consumer_diagnostics(report, rendered)
            self.assertEqual(report.exit_code, 2)
            self.assertEqual(report.reason, "state mount is missing")
            self.assertEqual(
                rendered.getvalue(),
                "roundwright Docker consumer preflight\n"
                "mode: test-only\n"
                "authentication mount: evidence-mismatch\n"
                "authority-receipt mount: not-applicable\n"
                "configuration mount: evidence-mismatch\n"
                "repository mount: ready\n"
                "state mount: missing\n"
                "candidate: match\npackage: match\nbase image: match\n"
                "authority receipt: not required\n"
                "result: blocked (state mount is missing)\n",
            )

    def test_entrypoint_reports_complete_missing_authority_diagnostic(self) -> None:
        """An authoritative absent receipt is mount-missing and identity-missing."""

        now = datetime.now(timezone.utc)
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            write_typed_mounted_evidence(paths, candidate, now=now)
            paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-unmounted.json"
            identity = root / "identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate,
                "package_digest": digest("b"),
                "base_image_digest": digest("c"),
            }), encoding="utf-8")
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "authoritative",
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                **mounted_runtime_environment(),
            }
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda _path, mode: mode == os.R_OK or _path is paths[DockerMountName.STATE]), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            rendered = io.StringIO()
            render_docker_consumer_diagnostics(report, rendered)
            self.assertEqual(report.exit_code, 2)
            self.assertEqual(report.reason, "authority-receipt mount is missing")
            self.assertIn("authority-receipt mount: missing\n", rendered.getvalue())
            self.assertIn("authority receipt: missing\n", rendered.getvalue())

    def test_entrypoint_reports_candidate_missing_for_dirty_or_empty_checkout(self) -> None:
        """Repository evidence failures cannot claim an observed candidate."""

        now = datetime.now(timezone.utc)
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            write_typed_mounted_evidence(paths, candidate, now=now)
            identity = root / "identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate, "package_digest": digest("b"), "base_image_digest": digest("c"),
            }), encoding="utf-8")
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "test-only", "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64, "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                **mounted_runtime_environment(),
            }
            paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-unmounted.json"
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=None,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            rendered = io.StringIO()
            render_docker_consumer_diagnostics(report, rendered)
            self.assertEqual(report.exit_code, 2)
            self.assertEqual(report.reason, "repository mount is evidence-mismatch")
            self.assertEqual(report.candidate, DockerIdentityStatus.MISSING)
            self.assertIn("repository mount: evidence-mismatch\n", rendered.getvalue())
            self.assertIn("candidate: missing\n", rendered.getvalue())

    def test_entrypoint_reconciles_typed_runtime_identity_drift_in_every_mode(self) -> None:
        """Every mode consumes the same mounted identity evidence before ready."""

        now = datetime.now(timezone.utc)
        candidate = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            identity = root / "identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate, "package_digest": digest("b"), "base_image_digest": digest("c"),
            }), encoding="utf-8")
            environment = {
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                **mounted_runtime_environment(),
            }

            def mounted_access(path: Path, access_mode: int) -> bool:
                return access_mode == os.R_OK

            def report_for(mode: DockerOperationMode) -> object:
                paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-receipt"
                write_typed_mounted_evidence(paths, candidate, now=now)
                paths[DockerMountName.REPOSITORY].mkdir(exist_ok=True)
                environment["ROUNDWRIGHT_DOCKER_MODE"] = mode.value
                if mode is DockerOperationMode.AUTHORITATIVE:
                    environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = hashlib.sha256(
                        paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()
                    ).hexdigest()
                    access = lambda path, access_mode: access_mode == os.R_OK or path == paths[DockerMountName.STATE]
                else:
                    environment.pop("ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256", None)
                    paths[DockerMountName.AUTHORITY_RECEIPT] = root / "unmounted-authority.json"
                    access = mounted_access
                with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=access), mock.patch(
                    "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
                ):
                    return preflight(environment, paths=paths, identity_path=identity)

            paths[DockerMountName.CONFIGURATION] = root / "configuration"
            paths[DockerMountName.AUTHENTICATION] = root / "authentication"
            paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-receipt"
            report = report_for(DockerOperationMode.TEST_ONLY)
            self.assertTrue(report.ready, report.reason)
            material = canonical_fixture_envelope("b" * 40, now=now)
            paths[DockerMountName.CONFIGURATION].write_text(
                "[runtime]\n"
                f"candidate_sha = {json.dumps(candidate)}\n"
                f"binding = {json.dumps(material['identity']['runtime_binding'])}\n",
                encoding="utf-8",
            )
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertIn("configuration mount is evidence-mismatch", report.reason)

            report = report_for(DockerOperationMode.READ_ONLY)
            self.assertTrue(report.ready, report.reason)
            paths[DockerMountName.AUTHENTICATION].write_text(
                "[operator]\n"
                f"candidate_sha = {json.dumps(candidate)}\nidentity = {json.dumps('0' * 64)}\n",
                encoding="utf-8",
            )
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertIn("authentication mount is evidence-mismatch", report.reason)

            report = report_for(DockerOperationMode.AUTHORITATIVE)
            self.assertTrue(report.ready, report.reason)
            runtime = json.loads((paths[DockerMountName.STATE] / "docker-runtime-evidence.json").read_text(encoding="utf-8"))
            runtime["candidate_sha"] = "b" * 40
            (paths[DockerMountName.STATE] / "docker-runtime-evidence.json").write_text(
                json.dumps(runtime, sort_keys=True, separators=(",", ":")), encoding="utf-8",
            )
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_sha
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK or path == paths[DockerMountName.STATE]), mock.patch(
                "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
            ):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertIn("state mount is evidence-mismatch", report.reason)

            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_sha
            paths[DockerMountName.AUTHENTICATION].write_text(
                "[operator]\ncandidate_sha = \"a\"\nidentity = \"b" + "b" * 63 + "\"\n", encoding="utf-8",
            )
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK or path == paths[DockerMountName.STATE]), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertEqual(report.exit_code, 2)
            self.assertIn("authentication mount is evidence-mismatch", report.reason)

            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_sha
            connection = sqlite3.connect(paths[DockerMountName.STATE] / "native-host.sqlite3")
            try:
                with connection:
                    connection.execute("UPDATE native_host_metadata SET value = ? WHERE key = 'candidate_sha'", ("b" * 40,))
            finally:
                connection.close()
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda path, mode: mode == os.R_OK or path == paths[DockerMountName.STATE]), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertEqual(report.exit_code, 2)
            self.assertIn("state mount is evidence-mismatch", report.reason)

    def test_entrypoint_rejects_correlated_runtime_and_authentication_substitution_in_every_mode(self) -> None:
        """SQLite-native host evidence is independent of substitutable mounts."""

        now = datetime.now(timezone.utc)
        candidate = "a" * 40
        substituted = canonical_fixture_envelope("b" * 40, now=now)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            identity = root / "identity.json"
            identity.write_text(json.dumps({
                "candidate_sha": candidate, "package_digest": digest("b"), "base_image_digest": digest("c"),
            }), encoding="utf-8")

            for mode in DockerOperationMode:
                paths[DockerMountName.AUTHORITY_RECEIPT] = root / "authority-receipt"
                write_typed_mounted_evidence(paths, candidate, now=now)
                runtime = json.loads((paths[DockerMountName.STATE] / "docker-runtime-evidence.json").read_text(encoding="utf-8"))
                runtime["runtime_binding"] = substituted["identity"]["runtime_binding"]
                runtime["authentication_identity"] = substituted["mounts"]["authentication_identity"]
                (paths[DockerMountName.STATE] / "docker-runtime-evidence.json").write_text(
                    json.dumps(runtime, sort_keys=True, separators=(",", ":")), encoding="utf-8",
                )
                paths[DockerMountName.CONFIGURATION].write_text(
                    "[runtime]\n"
                    f"candidate_sha = {json.dumps(candidate)}\n"
                    f"binding = {json.dumps(substituted['identity']['runtime_binding'])}\n",
                    encoding="utf-8",
                )
                paths[DockerMountName.AUTHENTICATION].write_text(
                    "[operator]\n"
                    f"candidate_sha = {json.dumps(candidate)}\n"
                    f"identity = {json.dumps(substituted['mounts']['authentication_identity'])}\n",
                    encoding="utf-8",
                )
                environment = {
                    "ROUNDWRIGHT_DOCKER_MODE": mode.value,
                    "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                    "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                    "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                    **mounted_runtime_environment(),
                }
                if mode is DockerOperationMode.AUTHORITATIVE:
                    environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = hashlib.sha256(
                        paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()
                    ).hexdigest()
                    access = lambda path, access_mode: access_mode == os.R_OK or path is paths[DockerMountName.STATE]
                else:
                    paths[DockerMountName.AUTHORITY_RECEIPT] = root / "unmounted-authority"
                    access = lambda _path, access_mode: access_mode == os.R_OK
                with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=access), mock.patch(
                    "roundwright.docker_entrypoint._checkout_candidate", return_value=candidate,
                ):
                    report = preflight(environment, paths=paths, identity_path=identity)
                self.assertEqual(report.exit_code, 2, mode.value)
                expected = "configuration mount is evidence-mismatch" if mode is DockerOperationMode.AUTHORITATIVE else "state mount is evidence-mismatch"
                self.assertIn(expected, report.reason, mode.value)

    def test_entrypoint_renders_every_present_invalid_authority_variant_as_mismatch(self) -> None:
        """Every hosted negative reaches production preflight and its projection."""

        self.assertEqual(
            hosted_workflow_expectations(),
            tuple((mode, expected) for _, mode, expected in _HOSTED_NEGATIVE_CASES),
        )
        self.assertEqual(set(hosted_workflow_expectations()), set(_SCENARIOS))

        def mutate_payload(receipt_path: Path, update) -> None:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            update(payload)
            receipt_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")

        for case_name, mode, expected in _HOSTED_NEGATIVE_CASES:
            with self.subTest(case=case_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                paths = {name: root / name.value for name in DockerMountName}
                paths[DockerMountName.REPOSITORY].mkdir()
                paths[DockerMountName.STATE].mkdir()
                candidate = write_self_contained_checkout(
                    paths[DockerMountName.REPOSITORY],
                    tracked_file=("README.md", b"candidate-bound\n"),
                )
                now = datetime.now(timezone.utc)
                write_typed_mounted_evidence(paths, candidate, now=now)
                identity = root / "identity.json"
                identity.write_text(
                    json.dumps({"candidate_sha": candidate, "package_digest": digest("b"), "base_image_digest": digest("c")}),
                    encoding="utf-8",
                )
                writable_paths: set[Path] = set()
                state_writable = mode == DockerOperationMode.AUTHORITATIVE.value
                effective_uid = (paths[DockerMountName.STATE] / "native-host.sqlite3").stat().st_uid

                if mode != DockerOperationMode.AUTHORITATIVE.value and case_name != "authority-present-nonauthoritative":
                    paths[DockerMountName.AUTHORITY_RECEIPT] = root / "unmounted-authority.json"

                if case_name == "state-missing":
                    paths[DockerMountName.STATE] = root / "unmounted-state"
                elif case_name == "state-writable-read-only":
                    state_writable = True
                elif case_name == "authority-mount-missing":
                    paths[DockerMountName.AUTHORITY_RECEIPT] = root / "unmounted-authority.json"
                elif case_name == "authority-present-nonauthoritative":
                    writable_paths.add(paths[DockerMountName.AUTHORITY_RECEIPT])
                elif case_name == "state-ownership":
                    effective_uid += 1
                elif case_name == "repository-dirty":
                    (paths[DockerMountName.REPOSITORY] / "README.md").write_bytes(b"mounted-tree-drift\n")
                elif case_name == "configuration-drift":
                    paths[DockerMountName.CONFIGURATION].write_text("[runtime]\ncandidate_sha = \"0\"\nbinding = \"{}\"\n", encoding="utf-8")
                elif case_name == "authentication-drift":
                    paths[DockerMountName.AUTHENTICATION].write_text("[operator]\ncandidate_sha = \"0\"\nidentity = \"0\"\n", encoding="utf-8")
                elif case_name == "state-drift":
                    runtime = json.loads((paths[DockerMountName.STATE] / "docker-runtime-evidence.json").read_text(encoding="utf-8"))
                    runtime["candidate_sha"] = "0" * 40
                    (paths[DockerMountName.STATE] / "docker-runtime-evidence.json").write_text(json.dumps(runtime, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                elif case_name == "repository-omitted":
                    paths[DockerMountName.REPOSITORY] = root / "image-workspace"
                    paths[DockerMountName.REPOSITORY].mkdir()
                elif case_name == "configuration-missing":
                    paths[DockerMountName.CONFIGURATION] = root / "unmounted-config.toml"
                elif case_name == "authentication-missing":
                    paths[DockerMountName.AUTHENTICATION] = root / "unmounted-auth.toml"
                elif case_name == "state-read-only-authoritative":
                    state_writable = False
                elif case_name == "repository-writable":
                    writable_paths.add(paths[DockerMountName.REPOSITORY])
                elif case_name == "configuration-writable":
                    writable_paths.add(paths[DockerMountName.CONFIGURATION])
                elif case_name == "authentication-writable":
                    writable_paths.add(paths[DockerMountName.AUTHENTICATION])
                elif case_name == "authority-writable":
                    writable_paths.add(paths[DockerMountName.AUTHORITY_RECEIPT])
                elif case_name == "authority-malformed":
                    paths[DockerMountName.AUTHORITY_RECEIPT].write_text("{}\n", encoding="utf-8")
                elif case_name == "authority-digest-mismatch":
                    pass
                elif case_name.startswith("authority-"):
                    status = case_name.removeprefix("authority-")
                    if status == "wrong-candidate":
                        mutate_payload(paths[DockerMountName.AUTHORITY_RECEIPT], lambda payload: payload.update({"candidate_sha": "0" * 40}))
                    else:
                        mutate_payload(paths[DockerMountName.AUTHORITY_RECEIPT], lambda payload: payload["verification"].update({"status": status}))
                else:
                    self.fail(f"unhandled hosted negative case: {case_name}")

                environment = {
                    "ROUNDWRIGHT_DOCKER_MODE": mode,
                    "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                    "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                    "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                    **mounted_runtime_environment(),
                }
                receipt_path = paths[DockerMountName.AUTHORITY_RECEIPT]
                if (
                    mode == DockerOperationMode.AUTHORITATIVE.value
                    and case_name != "authority-mount-missing"
                ) or case_name == "authority-present-nonauthoritative":
                    receipt_digest = "0" * 64 if case_name == "authority-digest-mismatch" else hashlib.sha256(receipt_path.read_bytes()).hexdigest()
                    environment["ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256"] = receipt_digest

                def mounted_access(path: Path, mode: int) -> bool:
                    if mode == os.R_OK:
                        return True
                    if path == paths[DockerMountName.STATE]:
                        return state_writable
                    return path in writable_paths

                with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch(
                    "roundwright.docker_entrypoint.os.geteuid", return_value=effective_uid, create=True,
                ):
                    report = preflight(environment, paths=paths, identity_path=identity)
                output = io.StringIO()
                render_docker_consumer_diagnostics(report, output)
                self.assertEqual(report.exit_code, 2)
                self.assertFalse(report.ready)
                self.assertEqual(output.getvalue(), scenario(mode, expected).render() + "\n")

    def test_entrypoint_treats_unbound_image_workspace_as_repository_evidence_drift(self) -> None:
        """The image's declared workspace is not proof of a host checkout mount."""

        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            candidate = write_self_contained_checkout(paths[DockerMountName.REPOSITORY])
            write_typed_mounted_evidence(paths, candidate, now=now)
            paths[DockerMountName.AUTHORITY_RECEIPT].unlink()
            identity = root / "identity.json"
            identity.write_text(
                json.dumps({"candidate_sha": candidate, "package_digest": digest("b"), "base_image_digest": digest("c")} ),
                encoding="utf-8",
            )
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": DockerOperationMode.TEST_ONLY.value,
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": candidate,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                **mounted_runtime_environment(),
            }
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=lambda _path, access_mode: access_mode == os.R_OK):
                self.assertTrue(preflight(environment, paths=paths, identity_path=identity).ready)
                image_workspace = root / "image-workspace"
                image_workspace.mkdir()
                paths[DockerMountName.REPOSITORY] = image_workspace
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(report.ready)
            self.assertEqual(report.exit_code, 2)
            self.assertIn("repository mount is evidence-mismatch", report.reason)

    def test_entrypoint_blocks_state_ownership_before_database_access(self) -> None:
        """An inaccessible authoritative database must never escape preflight."""

        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir()
            paths[DockerMountName.STATE].mkdir()
            paths[DockerMountName.CONFIGURATION].write_text("[runtime]\nschema_version = 1\n", encoding="utf-8")
            paths[DockerMountName.AUTHENTICATION].write_text("# fixture\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text(
                json.dumps(canonical_fixture_envelope("a" * 40, now=now), sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            database = paths[DockerMountName.STATE] / "native-host.sqlite3"
            self.assertTrue(NativeHostControlStore(database).install(canonical_native_host_installation("a" * 40, now=now)).accepted)
            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            identity = root / "identity.json"
            identity.write_text(
                json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}),
                encoding="utf-8",
            )
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "authoritative",
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
                "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256": hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest(),
                **mounted_runtime_environment(),
            }

            def mounted_access(path: Path, mode: int) -> bool:
                return mode == os.R_OK or path is paths[DockerMountName.STATE]

            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40), mock.patch("roundwright.docker_entrypoint.os.geteuid", return_value=database.stat().st_uid + 1, create=True), mock.patch("roundwright.docker_entrypoint.NativeHostControlStore.verify") as verify:
                ownership_report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(ownership_report.ready)
            self.assertIn("state mount is ownership-mismatch", ownership_report.reason)
            self.assertEqual(ownership_report.exit_code, 2)
            verify.assert_not_called()

            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40), mock.patch("roundwright.docker_entrypoint.os.geteuid", return_value=database.stat().st_uid, create=True), mock.patch("roundwright.docker_entrypoint.NativeHostControlStore.verify", side_effect=OSError("database unavailable")):
                access_report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(access_report.ready)
            self.assertIn("state mount is evidence-mismatch", access_report.reason)
            self.assertEqual(access_report.exit_code, 2)

    def test_entrypoint_requires_mounted_runtime_evidence_and_environment(self) -> None:
        now = datetime.now(timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir(); paths[DockerMountName.STATE].mkdir()
            paths[DockerMountName.CONFIGURATION].write_text("[runtime]\nschema_version = 1\n", encoding="utf-8")
            paths[DockerMountName.AUTHENTICATION].write_text("# fixture\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text(json.dumps(canonical_fixture_envelope("a" * 40, now=now)), encoding="utf-8")
            self.assertTrue(NativeHostControlStore(paths[DockerMountName.STATE] / "native-host.sqlite3").install(canonical_native_host_installation("a" * 40, now=now)).accepted)
            write_typed_mounted_evidence(paths, "a" * 40, now=now)
            identity = root / "identity.json"
            identity.write_text(json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}), encoding="utf-8")
            receipt_sha = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment = {"ROUNDWRIGHT_DOCKER_MODE": "authoritative", "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64, "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"), "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256": receipt_sha, **mounted_runtime_environment()}
            def mounted_access(path: Path, mode: int) -> bool:
                return mode == os.R_OK or path is paths[DockerMountName.STATE]
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=mounted_access), mock.patch("roundwright.docker_entrypoint._checkout_candidate", return_value="a" * 40):
                self.assertTrue(preflight(environment, paths=paths, identity_path=identity).ready)
                environment.pop("XDG_STATE_HOME")
                report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(report.ready)
            self.assertIn("repository mount is evidence-mismatch", report.reason)

    def test_entrypoint_blocks_writable_host_owned_mounts_and_dispatches_cli_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir(); paths[DockerMountName.STATE].mkdir()
            for name in (DockerMountName.CONFIGURATION, DockerMountName.AUTHENTICATION):
                paths[name].write_text("fixture\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text("fixture\n", encoding="utf-8")
            environment = {
                "ROUNDWRIGHT_DOCKER_MODE": "test-only",
                "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40,
                "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64,
                "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"),
            }
            identity = root / "identity.json"
            identity.write_text(json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}), encoding="utf-8")
            def writable_configuration(path: Path, mode: int) -> bool:
                return mode == os.R_OK or path is paths[DockerMountName.CONFIGURATION]
            with mock.patch("roundwright.docker_entrypoint.os.access", side_effect=writable_configuration):
                self.assertFalse(preflight(environment, paths=paths, identity_path=identity).ready)
        original_environment = {name: os.environ.get(name) for name in ("ROUNDWRIGHT_REPOSITORY_ROOT", "XDG_CONFIG_HOME", "XDG_STATE_HOME")}
        with mock.patch("roundwright.docker_entrypoint.preflight", return_value=mock.Mock(ready=True)), mock.patch("roundwright.docker_entrypoint.render_docker_consumer_diagnostics"), mock.patch("roundwright.docker_entrypoint.os.chdir"), mock.patch("roundwright.docker_entrypoint.cli_main", return_value=3) as cli:
            self.assertEqual(docker_entrypoint_main(["run-once"]), 3)
            cli.assert_called_once_with(["run-once"])
        self.assertEqual({name: os.environ.get(name) for name in original_environment}, original_environment)
