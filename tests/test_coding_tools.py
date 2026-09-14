"""Real local-effect coverage for the bounded coding tool capability."""
from __future__ import annotations

import sys
import tempfile
import unittest
import os
import subprocess
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools, CodingToolError
from roundwright.role_capability_policy import RoleCapability, RoleCapabilityError, RoleScope, ScopeKind, ScopedDescriptor


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class BoundedCodingToolsTests(unittest.TestCase):
    def capability(self, root: Path, readable: tuple[str, ...], writable: tuple[str, ...], commands: tuple[tuple[str, ...], ...], **kwargs) -> BoundedCodingCapability:
        """Create an effectful fixture with its full exact role scope."""
        root_identity = kwargs.pop("scope_root_identity", digest("scope:" + str(root.resolve())))
        supplied_scope = kwargs.pop("role_scope", None)
        descriptors = [
            *(ScopedDescriptor(ScopeKind.PATH, root_identity, value) for value in sorted(set(readable + writable))),
            *(ScopedDescriptor(ScopeKind.PROCESS, root_identity, digest(json.dumps({"command": command}, sort_keys=True, separators=(",", ":")))[7:]) for command in commands),
        ]
        return BoundedCodingCapability(
            root, readable, writable, commands, role_scope=supplied_scope or RoleScope(
                frozenset({RoleCapability.BOUNDED_CODING}), tuple(descriptors),
            ), scope_root_identity=root_identity, **kwargs,
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Path(self.temporary.name)
        self.root = self.fixture / "workspace"
        self.foreign = self.fixture / "foreign-worktree"
        self.foreign.mkdir()
        (self.root / "src").mkdir(parents=True)
        (self.root / "src" / "allowed.txt").write_text("before", encoding="utf-8")
        self.tools = BoundedCodingTools(self.capability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",),
            ((sys.executable, "-c", "import sys; sys.exit(0)"),),
        ))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_allowlisted_read_write_and_validation_have_real_local_effects(self) -> None:
        value, read = self.tools.read("src/allowed.txt")
        write = self.tools.write("src/allowed.txt", "after")
        validation = self.tools.validate((sys.executable, "-c", "import sys; sys.exit(0)"))
        self.assertEqual(value, "before")
        self.assertEqual((self.root / "src" / "allowed.txt").read_text(encoding="utf-8"), "after")
        self.assertEqual((read.tool, write.tool, validation.tool, validation.exit_code), ("workspace-read", "workspace-write", "validation-execute", 0))
        self.assertNotEqual(write.before_digest, write.after_digest)

    def test_escape_unlisted_path_and_shell_are_denied(self) -> None:
        for path in ("../secret", "src/other.txt", "C:/secret", "src\\allowed.txt"):
            with self.subTest(path=path), self.assertRaises(CodingToolError):
                self.tools.read(path)
        with self.assertRaises(CodingToolError):
            self.tools.validate(("cmd.exe", "/c", "whoami"))

    def test_win32_aliases_are_rejected_before_any_path_effect(self) -> None:
        command = (sys.executable, "-c", "import sys; sys.exit(0)")
        for alias in (
            "src/aux.txt", "src/COM1", "src/allowed.txt:stream",
            "src/allowed.txt.", "src/allowed.txt ", "src/ａｕｘ.txt",
        ):
            with self.subTest(alias=alias), self.assertRaises((CodingToolError, RoleCapabilityError)):
                self.capability(
                    self.root, (alias,), ("src/allowed.txt",), (command,),
                )

    def test_symlink_escape_is_denied_when_supported(self) -> None:
        target = self.foreign / "coding-tools-secret.txt"
        target.write_text("secret", encoding="utf-8")
        link = self.root / "src" / "allowed.txt"
        link.unlink()
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation is unavailable to this test identity")
        with self.assertRaises(CodingToolError):
            self.tools.read("src/allowed.txt")

    def test_junction_escape_is_denied_when_supported(self) -> None:
        if os.name != "nt":
            self.skipTest("junctions are a Windows-only reparse-point fixture")
        target = self.foreign / "secret.txt"
        target.write_text("secret", encoding="utf-8")
        junction = self.root / "src" / "foreign"
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(self.foreign)],
            stdin=subprocess.DEVNULL, capture_output=True, check=False,
        )
        if completed.returncode != 0:
            self.skipTest("junction creation is unavailable to this test identity")
        tools = BoundedCodingTools(self.capability(
            self.root, ("src/foreign/secret.txt",), ("src/allowed.txt",),
            ((sys.executable, "-c", "import sys; sys.exit(0)"),),
        ))
        with self.assertRaises(CodingToolError):
            tools.read("src/foreign/secret.txt")

    def test_foreign_worktree_path_is_not_a_capability(self) -> None:
        (self.foreign / "secret.txt").write_text("secret", encoding="utf-8")
        with self.assertRaises(CodingToolError):
            self.tools.read("../foreign-worktree/secret.txt")

    def test_admitted_role_scope_enforces_exact_paths_before_local_effects(self) -> None:
        (self.root / "src" / "other.txt").write_text("other", encoding="utf-8")
        root_identity = digest("fixture-worktree")
        scope = RoleScope(
            frozenset({RoleCapability.BOUNDED_CODING}),
            (ScopedDescriptor(ScopeKind.PATH, root_identity, "src/allowed.txt"),),
        )
        tools = BoundedCodingTools(self.capability(
            self.root, ("src/allowed.txt", "src/other.txt"), ("src/allowed.txt",),
            ((sys.executable, "-c", "import sys; sys.exit(0)"),),
            role_scope=scope, scope_root_identity=root_identity,
        ))
        self.assertEqual(tools.read("src/allowed.txt")[0], "before")
        with self.assertRaisesRegex(CodingToolError, "admitted role scope"):
            tools.read("src/other.txt")

    def test_effectful_capability_requires_a_role_scope(self) -> None:
        with self.assertRaisesRegex(CodingToolError, "capability is invalid"):
            BoundedCodingCapability(
                self.root, ("src/allowed.txt",), ("src/allowed.txt",),
                ((sys.executable, "-c", "pass"),),
            )

    def test_validation_output_budget_is_enforced_while_the_process_runs(self) -> None:
        command = (sys.executable, "-c", "import sys; sys.stdout.write('x' * 4097)")
        tools = BoundedCodingTools(self.capability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), output_limit=4096,
        ))
        with self.assertRaisesRegex(CodingToolError, "output budget"):
            tools.validate(command)

    def test_validation_timeout_terminates_the_owned_process(self) -> None:
        command = (sys.executable, "-c", "import time; time.sleep(5)")
        tools = BoundedCodingTools(self.capability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), timeout_seconds=1,
        ))
        with self.assertRaisesRegex(CodingToolError, "timed out"):
            tools.validate(command)

    def test_verified_timeout_cleanup_is_not_recorded_as_uncertain(self) -> None:
        command = (sys.executable, "-c", "import time; time.sleep(5)")
        tools = BoundedCodingTools(self.capability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), timeout_seconds=1,
        ))
        with self.assertRaises(CodingToolError) as captured:
            tools.validate(command)
        self.assertEqual((captured.exception.outcome, captured.exception.cancellation_state, captured.exception.ambiguity_state), ("timed-out", "confirmed", "clear"))


if __name__ == "__main__":
    unittest.main()
