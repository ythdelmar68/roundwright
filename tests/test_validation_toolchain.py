"""Hermetic totality and fail-closed coverage for validation-toolchain receipts."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "ci"
if str(CI) not in sys.path:
    sys.path.insert(0, str(CI))

import resolve_validation_toolchain as resolver
import validation_toolchain as toolchain


class ValidationToolchainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = toolchain.load_lock(CI / "validation-toolchain.lock.toml")
        self.identity = toolchain.current_platform(self.lock)

    def copied_lock(self, root: Path) -> Path:
        ci = root / "ci"
        ci.mkdir()
        for name in (
            "validation-toolchain.lock.toml",
            "validation-build.requirements.txt",
            "validation-toolchain.requirements.txt",
        ):
            shutil.copy2(CI / name, ci / name)
        return ci / "validation-toolchain.lock.toml"

    def fake_receipt(self, cache: Path) -> tuple[Path, dict[str, object]]:
        root = toolchain.toolchain_root(cache, self.lock, self.identity)
        uv = root / "uv" / ("uv.exe" if sys.platform == "win32" else "uv")
        managed = root / "python" / ("python.exe" if sys.platform == "win32" else "python")
        python = root / "build-env" / ("python.exe" if sys.platform == "win32" else "python")
        pipx = root / "uv-tools" / "pipx" / ("pipx.exe" if sys.platform == "win32" else "pipx")
        for index, path in enumerate((uv, managed, python, pipx), 1):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"tool-{index}".encode("ascii"))
        document = toolchain.create_receipt(
            root,
            self.lock,
            self.identity,
            uv=uv,
            managed_python=managed,
            python=python,
            pipx=pipx,
            managed_python_environment=managed.parent,
            build_environment=python.parent,
            pipx_environment=pipx.parent,
        )
        receipt = root / "receipt.json"
        receipt.write_text(json.dumps(document, sort_keys=True), encoding="ascii")
        return receipt, document

    @staticmethod
    def rewrite_receipt(receipt: Path, document: dict[str, object]) -> None:
        document["receipt_digest"] = "sha256:" + toolchain.hashlib.sha256(
            toolchain._canonical_receipt(document)
        ).hexdigest()
        receipt.write_text(json.dumps(document, sort_keys=True), encoding="ascii")

    def test_tracked_lock_pins_every_supported_platform_and_hashed_input(self) -> None:
        self.assertEqual(self.lock.resolver_revision, 1)
        self.assertEqual(self.lock.uv_version, "0.12.3")
        self.assertEqual(self.lock.python_version, "3.12.13")
        self.assertEqual(self.lock.pip_version, "26.1.2")
        self.assertEqual(self.lock.setuptools_version, "83.0.0")
        self.assertEqual(self.lock.pipx_version, "1.16.6")
        self.assertEqual(set(self.lock.uv_artifacts), set(toolchain.SUPPORTED_PLATFORMS))
        self.assertTrue(self.lock.digest.startswith("sha256:"))

    def test_lock_rejects_missing_extra_and_drifted_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self.copied_lock(root)
            original = lock.read_text(encoding="utf-8")
            lock.write_text(original.replace('schema = "', 'extra = "no"\nschema = "', 1), encoding="utf-8")
            with self.assertRaisesRegex(toolchain.ToolchainError, "fields are invalid"):
                toolchain.load_lock(lock)
            lock.write_text(original, encoding="utf-8")
            (root / "ci" / "validation-toolchain.requirements.txt").write_text("drift\n", encoding="utf-8")
            with self.assertRaisesRegex(toolchain.ToolchainError, "digest does not match"):
                toolchain.load_lock(lock)

    def test_receipt_accepts_exact_layout_and_rejects_missing_or_extra_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, document = self.fake_receipt(Path(temporary))
            resolved = toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)
            self.assertEqual(resolved.receipt, receipt.resolve())

            for mutate in (
                lambda value: value.pop("requirements"),
                lambda value: value.__setitem__("extra", True),
            ):
                changed = json.loads(json.dumps(document))
                mutate(changed)
                receipt.write_text(json.dumps(changed), encoding="ascii")
                with self.assertRaisesRegex(toolchain.ToolchainError, "fields are invalid"):
                    toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

    def test_receipt_rejects_stale_lock_platform_requirements_and_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, document = self.fake_receipt(Path(temporary))
            changed = json.loads(json.dumps(document))
            changed["lock_digest"] = "sha256:" + "0" * 64
            self.rewrite_receipt(receipt, changed)
            with self.assertRaisesRegex(toolchain.ToolchainError, "receipt is stale"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

            receipt, document = self.fake_receipt(Path(temporary) / "second")
            changed = json.loads(json.dumps(document))
            changed["platform"]["architecture"] = "aarch64" if self.identity.architecture == "x86_64" else "x86_64"
            self.rewrite_receipt(receipt, changed)
            with self.assertRaisesRegex(toolchain.ToolchainError, "platform is stale"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

            receipt, document = self.fake_receipt(Path(temporary) / "third")
            changed = json.loads(json.dumps(document))
            changed["requirements"]["pipx"] = "sha256:" + "1" * 64
            self.rewrite_receipt(receipt, changed)
            with self.assertRaisesRegex(toolchain.ToolchainError, "requirements are stale"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

            wrong = receipt.parent.parent / "wrong-candidate" / "receipt.json"
            wrong.parent.mkdir()
            shutil.copy2(receipt, wrong)
            with self.assertRaisesRegex(toolchain.ToolchainError, "location is stale"):
                toolchain.verify_receipt(wrong, self.lock, self.identity, read_back=False)

    def test_receipt_rejects_tool_and_environment_drift_or_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, document = self.fake_receipt(Path(temporary))
            root = receipt.parent
            (root / Path(document["tools"]["uv"]["path"])).write_bytes(b"tampered")
            with self.assertRaisesRegex(toolchain.ToolchainError, "digest does not match"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

            receipt, document = self.fake_receipt(Path(temporary) / "second")
            root = receipt.parent
            (root / Path(document["environments"]["pipx"]["path"]) / "dependency.py").write_text("drift", encoding="utf-8")
            with self.assertRaisesRegex(toolchain.ToolchainError, "environment digest does not match"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

            receipt, document = self.fake_receipt(Path(temporary) / "third")
            changed = json.loads(json.dumps(document))
            changed["tools"]["uv"]["path"] = "../outside"
            self.rewrite_receipt(receipt, changed)
            with self.assertRaisesRegex(toolchain.ToolchainError, "path is invalid"):
                toolchain.verify_receipt(receipt, self.lock, self.identity, read_back=False)

    def test_read_back_requires_every_locked_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt, _ = self.fake_receipt(Path(temporary))
            expected = [
                f"uv {self.lock.uv_version}",
                f"CPython {self.lock.python_version}",
                f"CPython {self.lock.python_version}",
                self.lock.pipx_version,
                f"{self.lock.pip_version} {self.lock.setuptools_version}",
            ]
            with mock.patch.object(toolchain, "_read_back", side_effect=expected):
                toolchain.verify_receipt(receipt, self.lock, self.identity)
            stale = list(expected)
            stale[3] = "0.0.0"
            with mock.patch.object(toolchain, "_read_back", side_effect=stale):
                with self.assertRaisesRegex(toolchain.ToolchainError, "pipx read-back version is stale"):
                    toolchain.verify_receipt(receipt, self.lock, self.identity)

    def test_incomplete_cache_requires_explicit_rebuild_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            expected = toolchain.toolchain_root(cache, self.lock, self.identity)
            expected.mkdir(parents=True)
            with self.assertRaisesRegex(toolchain.ToolchainError, "explicit --rebuild"):
                resolver.provision(self.lock.path, cache)

    def test_incomplete_cache_removal_is_bounded_to_the_exact_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "exact-cache"
            sibling = parent / "keep"
            (target / "nested").mkdir(parents=True)
            (target / "nested" / "partial").write_text("incomplete", encoding="utf-8")
            sibling.write_text("preserve", encoding="utf-8")
            resolver._remove_incomplete_cache(target)
            self.assertFalse(target.exists())
            self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve")

    def test_resolver_source_has_no_path_discovery_fallback(self) -> None:
        source = (CI / "resolve_validation_toolchain.py").read_text(encoding="utf-8")
        verifier = (CI / "verify_installs.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.which", source + verifier)
        self.assertNotIn('["pipx", "install"]', verifier)
        self.assertNotIn('["uv", "tool"]', verifier)


if __name__ == "__main__":
    unittest.main()
