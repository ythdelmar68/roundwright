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
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, r'''%s''')
from roundwright.configuration import RepositoryIdentity
from roundwright.local_slice import LocalSliceFixture, render_local_slice_status, run_once_local_slice
from roundwright.state import database_path
import roundwright.local_slice as local_slice
import roundwright.state as state_module

root = Path(r'''%s''')
fixture = LocalSliceFixture('local-task', 'local-source', 'local/repository', 'codex/local-slice', root.parent / 'worker', 'implemented locally\\n')
commands = []
original_run = subprocess.run
allowed_environment = {'PATH', 'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP'}
forbidden_operations = {'push', 'fetch', 'pull', 'ls-remote', 'reset', 'clean', 'checkout', 'switch', 'restore', 'clone', 'init', 'remote', 'config', 'tag', 'gc', 'prune', 'repack', 'fsck', 'update-ref', 'worktree remove', 'branch -d', 'branch -D'}
def local_git_only(command, *args, **kwargs):
    executable = Path(command[0]).name.casefold() if isinstance(command, (list, tuple)) else ''
    values = tuple(str(value).casefold() for value in command) if isinstance(command, (list, tuple)) else ()
    arguments = values[3:] if len(values) >= 4 and values[1] == '-c' else ()
    environment = kwargs.get('env')
    operation = ' '.join(arguments[:2])
    allowed_shape = (
        arguments[:2] == ('rev-parse', '--is-inside-work-tree')
        or (arguments[:2] == ('rev-parse', '--verify') and len(arguments) == 3)
        or arguments[:2] in {('rev-parse', '--git-common-dir'), ('rev-parse', '--absolute-git-dir')}
        or arguments == ('symbolic-ref', '--quiet', '--short', 'head')
        or arguments == ('status', '--porcelain=v1', '--untracked-files=all')
        or arguments == ('worktree', 'list', '--porcelain', '-z')
        or (arguments[:3] == ('worktree', 'add', '-b') and len(arguments) == 6 and arguments[3] == 'codex/local-slice')
        or arguments == ('add', 'implementation.txt')
        or arguments == ('commit', '-m', 'feat(local-slice): record hermetic implementation')
        or (arguments[:2] == ('merge-base', '--is-ancestor') and len(arguments) == 4)
    )
    if (
        executable not in ('git', 'git.exe') or not allowed_shape or operation in forbidden_operations
        or any(value in forbidden_operations for value in arguments) or kwargs.get('timeout') not in {5, 10}
        or not isinstance(environment, dict) or set(environment) - allowed_environment
        or 'ROUNDWRIGHT_TEST_CREDENTIAL' in environment
    ):
        raise AssertionError('external command attempted')
    commands.append(values)
    return original_run(command, *args, **kwargs)
subprocess.run = local_git_only
def no_network(*args, **kwargs):
    raise AssertionError('network attempted')
socket.create_connection = no_network
original_getenv = os.getenv
os.environ['ROUNDWRIGHT_TEST_CREDENTIAL'] = 'must-not-be-read'
def no_credential(name, *args, **kwargs):
    if name == 'ROUNDWRIGHT_TEST_CREDENTIAL':
        raise AssertionError('credential attempted')
    return original_getenv(name, *args, **kwargs)
os.getenv = no_credential
repository = RepositoryIdentity.from_root(root)
before_first = len(commands)
first = run_once_local_slice(repository, fixture, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
first_pass_commands = len(commands) - before_first
connection = sqlite3.connect(database_path(repository))
try:
    leases_after_first = connection.execute("SELECT COUNT(*) FROM transition_leases").fetchone()[0]
finally:
    connection.close()
def writes_denied(*args, **kwargs):
    raise AssertionError('SQLite write attempted during completion replay')
local_slice.initialize = writes_denied
original_writable_connection = state_module._open_writable_connection
state_module._open_writable_connection = writes_denied
before_replay = len(commands)
second = run_once_local_slice(repository, fixture, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
replay_commands = len(commands) - before_replay
before_changed_source = len(commands)
try:
    run_once_local_slice(repository, LocalSliceFixture('local-task', 'local-source', 'local/repository', 'codex/local-slice', root.parent / 'worker', 'changed source\\n'), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
except Exception:
    changed_source_rejected = True
else:
    changed_source_rejected = False
changed_source_commands = len(commands) - before_changed_source
state_module._open_writable_connection = original_writable_connection
try:
    run_once_local_slice(repository, LocalSliceFixture('failed-task', 'failed-source', 'local/repository', 'codex/failed-slice', root / 'unsafe-worktree', 'failed source\\n'), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
except Exception:
    failure_released_lease = True
else:
    failure_released_lease = False
connection = sqlite3.connect(database_path(repository))
try:
    transitions = connection.execute('SELECT from_state, to_state FROM transition_events WHERE task_id = ? ORDER BY sequence', ('local-task',)).fetchall()
    attempts = connection.execute('SELECT provider_role, session_identity, state, accepted_review_identity FROM provider_attempts WHERE task_id = ? ORDER BY provider_role, attempt_id', ('local-task',)).fetchall()
    accepted = connection.execute('SELECT accepted_review_identity FROM accepted_provider_reviews WHERE task_id = ? ORDER BY accepted_review_identity', ('local-task',)).fetchall()
    plan_review = connection.execute('SELECT supervisor_session_identity, state FROM plan_review_attempts WHERE review_attempt_id = ?', ('local-plan-review',)).fetchone()
    diff_review = connection.execute('SELECT supervisor_session_identity, state, base_sha, candidate_sha, accepted_review_identity FROM diff_review_attempts WHERE diff_review_attempt_id = ?', ('local-diff-review',)).fetchone()
    gate_context = connection.execute('SELECT source_count, isolated_local_task FROM gate_contexts WHERE task_id = ? AND candidate_sha = ?', ('local-task', first.candidate.candidate_sha)).fetchone()
    gate_rows = connection.execute('SELECT gate_key, outcome, changed_boundary, reason, follow_ups FROM gate_evidence WHERE task_id = ? AND candidate_sha = ? ORDER BY gate_key', ('local-task', first.candidate.candidate_sha)).fetchall()
    verifications = connection.execute('SELECT verification_kind, outcome FROM candidate_verifications WHERE task_id = ? AND candidate_sha = ? ORDER BY verification_kind', ('local-task', first.candidate.candidate_sha)).fetchall()
    source = connection.execute('SELECT source_digest FROM source_snapshots WHERE source_id = ?', ('local-source',)).fetchone()
    seal = connection.execute('SELECT base_sha, candidate_sha FROM candidate_seals WHERE task_id = ?', ('local-task',)).fetchone()
    state = connection.execute('SELECT state FROM tasks WHERE task_id = ?', ('local-task',)).fetchone()[0]
    blockers = [row[0] for row in connection.execute('SELECT blocker_class FROM blockers WHERE task_id = ? AND resolution_fingerprint IS NULL ORDER BY blocker_class', ('local-task',))]
    next_action = connection.execute('SELECT action_kind FROM next_actions WHERE task_id = ? AND resolution_fingerprint IS NULL', ('local-task',)).fetchone()[0]
    leases_after_replay_and_failure = connection.execute("SELECT COUNT(*) FROM transition_leases").fetchone()[0]
finally:
    connection.close()
worktree_clean = original_run(['git', '-C', str(root.parent / 'worker'), 'status', '--porcelain=v1', '--untracked-files=all'], check=True, text=True, capture_output=True).stdout == ''
implementation_commits = original_run(['git', '-C', str(root.parent / 'worker'), 'rev-list', '--count', f'{first.candidate.base_sha}..{first.candidate.candidate_sha}'], check=True, text=True, capture_output=True).stdout.strip()
status = render_local_slice_status(first)
gate_outcome = 'PASS' if len(gate_rows) == 13 and all(row[1] in ('PASS', 'NOT_APPLICABLE') for row in gate_rows) else 'BLOCKED'
expected_status = '\\n'.join((
    'roundwright local-slice', 'task=local-task', f'state={state}', f'base={seal[0]}', f'candidate={seal[1]}',
    f'gates={gate_outcome}', f'plan_session={plan_review[0]}', f'diff_session={diff_review[0]}',
    f'next_action={next_action}', f"blockers={','.join(blockers) if blockers else 'none'}",
))
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
    'changed_source_rejected': changed_source_rejected,
    'transitions': transitions,
    'attempts': attempts,
    'accepted': accepted,
    'plan_review': plan_review,
    'diff_review': diff_review,
    'gate_context': gate_context,
    'gates': gate_rows,
    'verifications': verifications,
    'source_matches': source == (hashlib.sha256(b'source\\x00implemented locally\\n').hexdigest(),),
    'worktree_clean': worktree_clean,
    'implementation_commits': implementation_commits,
    'status': status,
    'commands': commands,
    'command_profile': [first_pass_commands, replay_commands, changed_source_commands],
    'replay_shapes': [list(command[3:]) for command in commands[before_replay:before_changed_source]],
    'status_matches_sqlite': status == expected_status,
    'leases': [leases_after_first, leases_after_replay_and_failure],
    'failure_released_lease': failure_released_lease,
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
            self.assertTrue(result["changed_source_rejected"])
            self.assertEqual(result["transitions"], [
                ["queued", "planning"], ["planning", "plan-review"], ["plan-review", "implementing"],
                ["implementing", "diff-review"], ["diff-review", "ready-for-owner"],
            ])
            self.assertEqual(result["attempts"], [
                ["planning", "local-worker-thread", "completed", None],
                ["supervisor", "local-diff-supervisor-session", "accepted", "local-diff-review"],
                ["supervisor", "local-plan-supervisor-session", "accepted", "local-plan-review"],
                ["worker", "local-worker-thread", "completed", None],
            ])
            self.assertEqual(result["accepted"], [["local-diff-review"], ["local-plan-review"]])
            self.assertEqual(result["plan_review"], ["local-plan-supervisor-session", "recorded"])
            self.assertEqual(result["diff_review"], ["local-diff-supervisor-session", "accepted", result["base"], result["candidate"], "local-diff-review"])
            self.assertEqual(result["gate_context"], [1, 1])
            self.assertEqual(result["verifications"], [["build", "pass"], ["test", "pass"]])
            self.assertTrue(result["source_matches"])
            self.assertTrue(result["worktree_clean"])
            self.assertEqual(result["implementation_commits"], "1")
            self.assertTrue(result["status_matches_sqlite"])
            self.assertTrue(result["commands"])
            self.assertTrue(all(command[0] in {"git", "git.exe"} and "push" not in command for command in result["commands"]))
            self.assertGreater(result["command_profile"][0], 1)
            self.assertLessEqual(result["command_profile"][0], 300)
            self.assertEqual(result["command_profile"][1:], [1, 1])
            self.assertEqual(result["replay_shapes"], [
                ["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
            ])
            self.assertEqual(result["leases"], [0, 0])
            self.assertTrue(result["failure_released_lease"])
            expected_na = {"dependency-graph", "github-trace", "public-identifier", "live-proof", "external-ci"}
            self.assertEqual({row[0] for row in result["gates"]}, {
                "plan-review", "candidate-seal", "supervisor-diff-review", "targeted-tests", "full-tests", "build",
                "policy", "deployment-authority", *expected_na,
            })
            for gate, outcome, boundary, reason, follow_ups in result["gates"]:
                self.assertEqual(follow_ups, "[]")
                if gate in expected_na:
                    self.assertEqual((outcome, boundary, reason), ("NOT_APPLICABLE", "isolated single-source local fixture", "external adapter is outside this isolated local proof"))
                else:
                    self.assertEqual((outcome, boundary, reason), ("PASS", None, None))


if __name__ == "__main__":
    unittest.main()
