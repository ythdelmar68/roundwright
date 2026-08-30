"""Hermetic checks for the minimal Docker deployment consumer contract."""

from __future__ import annotations

import io
import contextlib
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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
from roundwright.docker_entrypoint import preflight
from roundwright.cli import main


def digest(character: str) -> str:
    return "sha256:" + character * 64


def mounts(status: DockerMountStatus = DockerMountStatus.READY, *, authority: DockerMountStatus | None = None) -> tuple[DockerMountCheck, ...]:
    return tuple(DockerMountCheck(name, authority if name is DockerMountName.AUTHORITY_RECEIPT and authority is not None else status) for name in DockerMountName)


class DockerConsumerTests(unittest.TestCase):
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
            "/etc/roundwright/config.toml:ro",
            "/run/roundwright/auth.toml:ro",
            "/run/roundwright/authority-receipt.json:ro",
        ):
            self.assertIn(target, compose)
        self.assertIn('user: "65532:65532"', compose)
        self.assertIn("read_only: true", compose)
        self.assertNotIn("image: ghcr.io", compose)
        self.assertIn("ROUNDWRIGHT_DOCKER_MODE", compose)

    def test_entrypoint_observes_real_mounts_and_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {name: root / name.value for name in DockerMountName}
            paths[DockerMountName.REPOSITORY].mkdir(); paths[DockerMountName.STATE].mkdir()
            for name in (DockerMountName.CONFIGURATION, DockerMountName.AUTHENTICATION):
                paths[name].write_text("{}\n", encoding="utf-8")
            paths[DockerMountName.AUTHORITY_RECEIPT].write_text(json.dumps({"candidate_sha": "a" * 40}), encoding="utf-8")
            identity = root / "identity.json"
            identity.write_text(json.dumps({"candidate_sha": "a" * 40, "package_digest": digest("b"), "base_image_digest": digest("c")}), encoding="utf-8")
            receipt = hashlib.sha256(paths[DockerMountName.AUTHORITY_RECEIPT].read_bytes()).hexdigest()
            environment = {"ROUNDWRIGHT_DOCKER_MODE": "authoritative", "ROUNDWRIGHT_DOCKER_CANDIDATE_SHA": "a" * 40, "ROUNDWRIGHT_DOCKER_PACKAGE_SHA256": "b" * 64, "ROUNDWRIGHT_DOCKER_BASE_IMAGE_DIGEST": digest("c"), "ROUNDWRIGHT_DOCKER_AUTHORITY_RECEIPT_SHA256": receipt}
            self.assertTrue(preflight(environment, paths=paths, identity_path=identity).ready)
            environment["ROUNDWRIGHT_DOCKER_CANDIDATE_SHA"] = "e" * 40
            report = preflight(environment, paths=paths, identity_path=identity)
            self.assertFalse(report.ready)
            self.assertEqual(report.candidate, DockerIdentityStatus.MISMATCH)
