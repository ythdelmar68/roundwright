"""Installed-package proof for the hermetic Phase 2 local run-once slice."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
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
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, r'''%s''')
from roundwright.configuration import FinalFindingsPolicy, RepositoryIdentity, ReviewPolicy
from roundwright.dependency_policy import BootstrapPolicyReceipt, CandidateBinding, ComponentPolicy, DependencyComponent, DependencyExecutionControl, DependencyPolicy, DependencyStage, ObservedDependency, PolicyTransition, PolicyTransitionKind, TrustedDependencyAdmission, VersionRange
from roundwright.git_identity import GitEntrypointControl
from roundwright.local_slice import LocalSliceFixture, render_local_slice_status, run_once_local_slice
from roundwright.policy import PolicyAction, PolicyDocument, TrustedControlSource, TrustedPolicySnapshot
from roundwright.state import database_path
import roundwright.local_slice as local_slice
import roundwright.state as state_module

root = Path(r'''%s''')
fixture = LocalSliceFixture('local-task', 'local-source', 'local/repository', 'codex/local-slice', root.parent / 'worker', 'implemented locally\\n')
trusted_policy_snapshot = TrustedPolicySnapshot(
    TrustedControlSource('a' * 64, 'b' * 64),
    PolicyDocument(1, frozenset({PolicyAction.ISSUE_COMMENT})),
)
trusted_review_floor = ReviewPolicy(3, 10, 3, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
drifted_review_floor = ReviewPolicy(2, 9, 2, FinalFindingsPolicy.WORKER_FINAL_REPAIR_THEN_MERGE)
def dependency_digest(value):
    return 'sha256:' + value * 64
dependency_callbacks = []
def trusted_dependency_policy(binding):
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, 'roundwright', VersionRange('0.0.0', '1.0.0'), 'pypi/roundwright', dependency_digest('1'), dependency_digest('2')),
        ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME, 'codex-sdk', VersionRange('1.0.0', '2.0.0'), 'registry/codex-sdk', dependency_digest('3'), dependency_digest('4')),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, 'gh', VersionRange('2.0.0', '3.0.0'), 'github/gh', dependency_digest('5'), dependency_digest('6')),
        ComponentPolicy(DependencyComponent.BUILD_BACKEND, 'setuptools', VersionRange('69.0.0', '70.0.0'), 'pypi/setuptools', dependency_digest('7'), dependency_digest('8')),
    )
    policy = DependencyPolicy(binding, dependency_digest('9'), 1893456000, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, BootstrapPolicyReceipt.create(policy, reviewer_identity=dependency_digest('a'), authority_digest=dependency_digest('b'))))
    return policy
def candidate_dependency_evidence(binding):
    dependency_callbacks.append(('evidence', binding.candidate_sha))
    policy = trusted_dependency_policy(binding)
    observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 1893456000, policy.policy_digest) for item in policy.components)
    return policy, observations
def trusted_dependency_admission(binding):
    dependency_callbacks.append(('admission', binding.candidate_sha))
    policy = trusted_dependency_policy(binding)
    receipt = policy.transition.review
    return TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, dependency_digest('a'), dependency_digest('b'))
def candidate_validation(binding, kind):
    return dependency_digest(kind.value[0])
def run_slice(value):
    return run_once_local_slice(
        repository, value,
        git_entrypoint_control=git_entrypoint_control(value),
        trusted_policy_snapshot=trusted_policy_snapshot,
        trusted_review_floor=trusted_review_floor,
        candidate_dependency_evidence=candidate_dependency_evidence,
        trusted_dependency_admission=trusted_dependency_admission,
        candidate_validation=candidate_validation,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
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
sealed_base = original_run(['git', '-C', str(root), 'rev-parse', 'refs/remotes/origin/main'], check=True, text=True, capture_output=True).stdout.strip()
def git_entrypoint_control(value):
    binding = CandidateBinding(value.repository_id, value.task_id, sealed_base)
    components = (
        ComponentPolicy(DependencyComponent.PACKAGE, 'roundwright', VersionRange('0.0.0', '1.0.0'), 'pypi/roundwright', dependency_digest('c'), dependency_digest('d')),
        ComponentPolicy(DependencyComponent.PROVIDER_RUNTIME, 'codex-sdk', VersionRange('1.0.0', '2.0.0'), 'registry/codex-sdk', dependency_digest('1'), dependency_digest('2')),
        ComponentPolicy(DependencyComponent.GITHUB_CLI, 'gh', VersionRange('2.0.0', '3.0.0'), 'github/gh', dependency_digest('3'), dependency_digest('4')),
        ComponentPolicy(DependencyComponent.BUILD_BACKEND, 'setuptools', VersionRange('69.0.0', '70.0.0'), 'pypi/setuptools', dependency_digest('5'), dependency_digest('6')),
        ComponentPolicy(DependencyComponent.GIT_EXECUTABLE, 'git', VersionRange('2.0.0', '3.0.0'), 'git-scm/git', dependency_digest('e'), dependency_digest('f')),
    )
    policy = DependencyPolicy(binding, dependency_digest('0'), 1893456000, 60, components, PolicyTransition(PolicyTransitionKind.BOOTSTRAP))
    receipt = BootstrapPolicyReceipt.create(policy, reviewer_identity=dependency_digest('a'), authority_digest=dependency_digest('b'))
    policy = replace(policy, transition=PolicyTransition(PolicyTransitionKind.BOOTSTRAP, receipt))
    observations = tuple(ObservedDependency(binding, item.component, item.identifier, item.versions.minimum, item.source_identity, item.artifact_digest, item.executable_digest, 1893456000, policy.policy_digest) for item in components)
    admission = TrustedDependencyAdmission(binding, policy.core_fingerprint, receipt.receipt_digest, dependency_digest('a'), dependency_digest('b'))
    return GitEntrypointControl(binding, DependencyExecutionControl(policy, observations, admission), 1893456000)
database_before_missing_admission = database_path(repository).exists()
entrypoint_callbacks = []
valid_entrypoint_control = git_entrypoint_control(fixture)
def forged_entrypoint_control(binding, dependency_control):
    value = object.__new__(GitEntrypointControl)
    object.__setattr__(value, 'binding', binding)
    object.__setattr__(value, 'dependency_control', dependency_control)
    object.__setattr__(value, 'now', 1893456000)
    return value
stale_observations = tuple(replace(item, observed_at=1893455939) for item in valid_entrypoint_control.dependency_control.observations)
stale_entrypoint_control = forged_entrypoint_control(valid_entrypoint_control.binding, DependencyExecutionControl(valid_entrypoint_control.dependency_control.policy, stale_observations, valid_entrypoint_control.dependency_control.admission))
invalid_entrypoint_controls = (
    None,
    object(),
    stale_entrypoint_control,
    forged_entrypoint_control(CandidateBinding('other/repository', fixture.task_id, sealed_base), valid_entrypoint_control.dependency_control),
    forged_entrypoint_control(CandidateBinding(fixture.repository_id, 'other-task', sealed_base), valid_entrypoint_control.dependency_control),
    forged_entrypoint_control(CandidateBinding(fixture.repository_id, fixture.task_id, 'f' * 40), valid_entrypoint_control.dependency_control),
)
before_invalid_entrypoints = len(commands)
for invalid_control in invalid_entrypoint_controls:
    try:
        kwargs = dict(
            trusted_policy_snapshot=trusted_policy_snapshot,
            trusted_review_floor=trusted_review_floor,
            candidate_dependency_evidence=lambda binding: entrypoint_callbacks.append(('evidence', binding)) or candidate_dependency_evidence(binding),
            trusted_dependency_admission=lambda binding: entrypoint_callbacks.append(('admission', binding)) or trusted_dependency_admission(binding),
            candidate_validation=candidate_validation,
            now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        if invalid_control is None:
            run_once_local_slice(repository, fixture, **kwargs)
        else:
            run_once_local_slice(repository, fixture, git_entrypoint_control=invalid_control, **kwargs)
    except Exception:
        pass
    else:
        raise AssertionError('invalid Git entrypoint control was accepted')
invalid_entrypoints_leave_no_action = not entrypoint_callbacks and len(commands) == before_invalid_entrypoints and not database_path(repository).exists()
blocked_binding = CandidateBinding('local/repository', 'blocked-task', 'c' * 40)
blocked_policy, blocked_observations = candidate_dependency_evidence(blocked_binding)
blocked_action = []
for stage in DependencyStage:
    try:
        local_slice._execute_candidate_helper_from_factory(lambda binding: (blocked_policy, blocked_observations), lambda binding: TrustedDependencyAdmission(binding, blocked_policy.core_fingerprint, dependency_digest('0'), dependency_digest('a'), dependency_digest('b')), blocked_policy.binding, stage, lambda stage=stage: blocked_action.append(stage.value), 1893456000)
    except Exception:
        pass
blocked_candidate_helper = not blocked_action
try:
    run_once_local_slice(repository, fixture, git_entrypoint_control=git_entrypoint_control(fixture), now=datetime(2030, 1, 1, tzinfo=timezone.utc))
except Exception:
    missing_trusted_floor_rejected = True
else:
    missing_trusted_floor_rejected = False
database_after_missing_admission = database_path(repository).exists()
before_first = len(commands)
callbacks_before_first = len(dependency_callbacks)
first = run_slice(fixture)
first_pass_commands = len(commands) - before_first
first_candidate_callback_counts = [
    sum(1 for kind, candidate_sha in dependency_callbacks[callbacks_before_first:] if kind == expected_kind and candidate_sha == first.candidate.candidate_sha)
    for expected_kind in ('admission', 'evidence')
]
connection = sqlite3.connect(database_path(repository))
try:
    leases_after_first = connection.execute("SELECT COUNT(*) FROM transition_leases").fetchone()[0]
    database_snapshot_before_replay = hashlib.sha256('\\n'.join(connection.iterdump()).encode('utf-8')).hexdigest()
finally:
    connection.close()
def writes_denied(*args, **kwargs):
    raise AssertionError('SQLite write attempted during completion replay')
local_slice.initialize = writes_denied
original_writable_connection = state_module._open_writable_connection
state_module._open_writable_connection = writes_denied
before_replay = len(commands)
second = run_slice(fixture)
replay_commands = len(commands) - before_replay
before_changed_source = len(commands)
try:
    run_slice(LocalSliceFixture('local-task', 'local-source', 'local/repository', 'codex/local-slice', root.parent / 'worker', 'changed source\\n'))
except Exception:
    changed_source_rejected = True
else:
    changed_source_rejected = False
changed_source_commands = len(commands) - before_changed_source
state_module._open_writable_connection = original_writable_connection
try:
    run_once_local_slice(
        repository, fixture,
        git_entrypoint_control=git_entrypoint_control(fixture),
        trusted_policy_snapshot=trusted_policy_snapshot,
        trusted_review_floor=drifted_review_floor,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
except Exception:
    drifted_trusted_floor_rejected = True
else:
    drifted_trusted_floor_rejected = False
connection = sqlite3.connect(database_path(repository))
try:
    database_snapshot_after_replay = hashlib.sha256('\\n'.join(connection.iterdump()).encode('utf-8')).hexdigest()
finally:
    connection.close()
try:
    run_slice(LocalSliceFixture('failed-task', 'failed-source', 'local/repository', 'codex/failed-slice', root / 'unsafe-worktree', 'failed source\\n'))
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
def normalize_command(command):
    def path_key(value):
        return value.replace('\\\\', '/').casefold().rstrip('/')
    replacements = {
        **{path_key(str(path)): '<root>' for path in (root, root.resolve())},
        **{path_key(str(path)): '<worktree>' for path in (root.parent / 'worker', (root.parent / 'worker').resolve())},
        first.candidate.base_sha: '<base>',
        first.candidate.candidate_sha: '<candidate>',
    }
    normalized = []
    for index, value in enumerate(command):
        if index == 0:
            normalized.append('<git>')
        else:
            normalized.append(replacements.get(path_key(value), replacements.get(value, value)))
    return normalized
command_sequences = [
    [normalize_command(command) for command in commands[before_first:before_replay]],
    [normalize_command(command) for command in commands[before_replay:before_changed_source]],
    [normalize_command(command) for command in commands[before_changed_source:before_changed_source + changed_source_commands]],
]
command_sequence_digest = hashlib.sha256(json.dumps(command_sequences, separators=(',', ':')).encode('utf-8')).hexdigest()
platform_normalization_matches = (
    normalize_command(('git.exe', '-C', str(root.resolve()).replace('/', '\\\\'), 'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}'))
    == normalize_command(('/usr/bin/git', '-C', str(root), 'rev-parse', '--verify', 'refs/remotes/origin/main^{commit}'))
)
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
    'missing_trusted_floor_rejected': missing_trusted_floor_rejected,
    'missing_admission_has_no_domain_state': not database_before_missing_admission and not database_after_missing_admission,
    'drifted_trusted_floor_rejected': drifted_trusted_floor_rejected,
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
    'database_snapshot_unchanged': database_snapshot_before_replay == database_snapshot_after_replay,
    'command_sequence_digest': command_sequence_digest,
    'platform_normalization_matches': platform_normalization_matches,
    'leases': [leases_after_first, leases_after_replay_and_failure],
    'failure_released_lease': failure_released_lease,
    'blocked_candidate_helper': blocked_candidate_helper,
    'invalid_entrypoints_leave_no_action': invalid_entrypoints_leave_no_action,
    'first_candidate_callback_counts': first_candidate_callback_counts,
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
            self.assertTrue(result["missing_trusted_floor_rejected"])
            self.assertTrue(result["missing_admission_has_no_domain_state"])
            self.assertTrue(result["drifted_trusted_floor_rejected"])
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
            self.assertTrue(result["database_snapshot_unchanged"])
            self.assertEqual(result["command_sequence_digest"], "123028bb167b1b195d799b79bae30c2bece03234753c562a67301383da2dfd6e")
            self.assertTrue(result["platform_normalization_matches"])
            self.assertEqual(result["leases"], [0, 0])
            self.assertTrue(result["failure_released_lease"])
            self.assertTrue(result["blocked_candidate_helper"])
            self.assertTrue(result["invalid_entrypoints_leave_no_action"])
            self.assertEqual(result["first_candidate_callback_counts"], [3, 3])
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
