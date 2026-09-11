"""Real local-effect coverage for the bounded coding tool capability."""
from __future__ import annotations

import sys
import tempfile
import unittest
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roundwright.coding_tools import BoundedCodingCapability, BoundedCodingTools, CodingToolError


class BoundedCodingToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Path(self.temporary.name)
        self.root = self.fixture / "workspace"
        self.foreign = self.fixture / "foreign-worktree"
        self.foreign.mkdir()
        (self.root / "src").mkdir(parents=True)
        (self.root / "src" / "allowed.txt").write_text("before", encoding="utf-8")
        self.tools = BoundedCodingTools(BoundedCodingCapability(
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
        tools = BoundedCodingTools(BoundedCodingCapability(
            self.root, ("src/foreign/secret.txt",), ("src/allowed.txt",),
            ((sys.executable, "-c", "import sys; sys.exit(0)"),),
        ))
        with self.assertRaises(CodingToolError):
            tools.read("src/foreign/secret.txt")

    def test_foreign_worktree_path_is_not_a_capability(self) -> None:
        (self.foreign / "secret.txt").write_text("secret", encoding="utf-8")
        with self.assertRaises(CodingToolError):
            self.tools.read("../foreign-worktree/secret.txt")

    def test_validation_output_budget_is_enforced_while_the_process_runs(self) -> None:
        command = (sys.executable, "-c", "import sys; sys.stdout.write('x' * 4097)")
        tools = BoundedCodingTools(BoundedCodingCapability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), output_limit=4096,
        ))
        with self.assertRaisesRegex(CodingToolError, "output budget"):
            tools.validate(command)

    def test_validation_timeout_terminates_the_owned_process(self) -> None:
        command = (sys.executable, "-c", "import time; time.sleep(5)")
        tools = BoundedCodingTools(BoundedCodingCapability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), timeout_seconds=1,
        ))
        with self.assertRaisesRegex(CodingToolError, "timed out"):
            tools.validate(command)

    def test_verified_timeout_cleanup_is_not_recorded_as_uncertain(self) -> None:
        command = (sys.executable, "-c", "import time; time.sleep(5)")
        tools = BoundedCodingTools(BoundedCodingCapability(
            self.root, ("src/allowed.txt",), ("src/allowed.txt",), (command,), timeout_seconds=1,
        ))
        with self.assertRaises(CodingToolError) as captured:
            tools.validate(command)
        self.assertEqual((captured.exception.outcome, captured.exception.cancellation_state, captured.exception.ambiguity_state), ("timed-out", "confirmed", "clear"))


if __name__ == "__main__":
    unittest.main()
