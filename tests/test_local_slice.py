"""Installed-package proof for the hermetic Phase 2 local run-once slice."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LocalSliceTests(unittest.TestCase):
    def git(self, directory: Path, *arguments: str) -> str:
        result = subprocess.run(["git", "-C", str(directory), *arguments], check=True, text=True, capture_output=True)
        return result.stdout.strip()

    def repository(self, root: Path) -> Path:
        remote = root.parent / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, text=True, capture_output=True)
        subprocess.run(["git", "init", "-b", "main", str(root)], check=True, text=True, capture_output=True)
        self.git(root, "config", "user.email", "fixture@example.invalid")
        self.git(root, "config", "user.name", "Local Slice Fixture")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self.git(root, "add", "README.md")
        self.git(root, "commit", "-m", "test: local slice base")
        self.git(root, "remote", "add", "origin", str(remote))
        self.git(root, "push", "-u", "origin", "main")
        return root

    def test_installed_package_runs_one_local_task_without_external_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            wheel_directory = temporary_root / "wheel"
            installed = temporary_root / "installed"
            fixture = self.repository(temporary_root / "repository")
            subprocess.run(
                [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheel_directory), str(ROOT)],
                check=True, text=True, capture_output=True,
            )
            wheel = next(wheel_directory.glob("roundwright-*.whl"))
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(installed), str(wheel)],
                check=True, text=True, capture_output=True,
            )
            script = """
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, r'''%s''')
from roundwright.configuration import RepositoryIdentity
from roundwright.local_slice import LocalSliceFixture, render_local_slice_status, run_once_local_slice

root = Path(r'''%s''')
fixture = LocalSliceFixture('local-task', 'local-source', 'local/repository', 'codex/local-slice', root.parent / 'worker', 'implemented locally\\n')
repository = RepositoryIdentity.from_root(root)
first = run_once_local_slice(repository, fixture, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
second = run_once_local_slice(repository, fixture, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
print(json.dumps({
    'state': first.task.state,
    'base': first.candidate.base_sha,
    'candidate': first.candidate.candidate_sha,
    'same_candidate': first.candidate == second.candidate,
    'same_status': render_local_slice_status(first) == render_local_slice_status(second),
    'sessions': [first.plan_session, first.diff_session],
    'next_action': first.task.next_action,
    'artifacts': [item.kind for item in first.task.artifacts],
    'blockers': first.task.blockers,
}))
""" % (str(installed), str(fixture))
            environment = {"PATH": os.environ["PATH"]}
            completed = subprocess.run([sys.executable, "-I", "-c", script], cwd=temporary_root, env=environment, check=False, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result["state"], "ready-for-owner")
            self.assertRegex(result["base"], r"^[0-9a-f]{40}$")
            self.assertRegex(result["candidate"], r"^[0-9a-f]{40}$")
            self.assertNotEqual(result["base"], result["candidate"])
            self.assertTrue(result["same_candidate"])
            self.assertTrue(result["same_status"])
            self.assertEqual(result["sessions"], ["local-plan-supervisor-session", "local-diff-supervisor-session"])
            self.assertEqual(result["next_action"], "owner-review")
            self.assertEqual(result["artifacts"], ["diff", "plan", "review", "status"])
            self.assertEqual(result["blockers"], [])


if __name__ == "__main__":
    unittest.main()
