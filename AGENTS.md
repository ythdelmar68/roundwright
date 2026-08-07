# VERSION CONTROL GUIDELINES

## GIT
- Read and use [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/) to create meaningful commit messages in format: `<type>(<scope>): <description>`
  - Write meaningful commit messages that explain why changes were made, not just what.
  - Keep commits atomic and focused on single logical changes to facilitate code review and bisection.
- Read and use [Conventional Branch](https://conventional-branch.github.io/) to create descriptive branch names.
- Update `.gitignore` for new build artifacts or dependencies.

## External validation routing

Before a task or gate that may require external credentials, cross-environment
execution, or remote GitHub lifecycle testing, read
[`docs/operations/qualification-test-infrastructure.md`](docs/operations/qualification-test-infrastructure.md).
That document is routing and evidence guidance only: it does not grant
Roundwright authority or activate its disabled runtime surface.

<!-- roundlet-bootstrap-policy:start -->
## ACTIVE Roundlet Authority

Until Roundwright completes its Phase 2 vertical slice, passes shadow/read-only comparison, and is externally promoted as the active immutable runtime, Roundlet is this repository's sole mutation-capable development orchestrator.

The authority block below is standing, repository-scoped owner authorization for Roundlet only. It authorizes the enumerated Roundlet actions without separate per-pull-request approval. It grants no runtime activation, self-promotion, release, or publication authority to Roundwright N, Roundwright N+1, task candidates, Workers, or Supervisors.

A candidate branch may propose changes to this policy, but those changes have no effect until they are reviewed, merged to authoritative `origin/main`, and explicitly acknowledged by the allowlisted owner.

Before an immutable Roundwright N becomes mutation-capable, a separate owner-reviewed policy transition must stop and reconcile Roundlet, disable its active authority, and establish the external promotion boundary. After that transition, Roundlet may remain installed only as a dormant Stage 0 and recovery tool; it must never dispatch concurrently with Roundwright.

Release, tag, publish, version bump, repository visibility changes, force push, reset, rebase, and destruction of unique unmerged work remain prohibited.

GitHub trace text must be curated and public-safe. Never post raw run artifacts, private evidence, credentials, internal owner reasoning, confidential source context, or private migration provenance. Missing, stale, conflicting, or unverifiable identity, authority, review, check, or read-back evidence fails closed.

Roundlet runtime state remains local-only under `.roundlet/` in the authoritative checkout and must be excluded through local `.git/info/exclude`, not committed or added to repository-wide ignore rules.

# roundlet:repository-authority
roundlet:
  enabled: true
  allow_mark_pr_ready: true
  allow_merge_pr: true
  allow_close_leaf_issue: true
  allow_delete_remote_branch: true
  allow_delete_local_branch: true
  allow_remove_worktree: true
# roundlet:end-repository-authority
<!-- roundlet-bootstrap-policy:end -->

<!-- roundwright-proposed-authority:start -->
## INACTIVE Roundwright Proposed Authority

This is a machine-readable, disabled-by-default proposal for a later,
owner-reviewed transition. It grants no current authority. The active Roundlet
bootstrap policy above remains the only effective repository mutation policy.

Unknown, missing, malformed, stale, conflicting, or candidate-authored values
fail closed. A candidate cannot make this block effective or use it to widen
standing authority. An effective policy may only narrow reviewed standing
authority. Activation requires an allowlisted owner's separate, external,
candidate-bound decision after the Phase gate; this block is not that decision.
The Roundlet parser consumes only the exact `roundlet:` marker pair, and the
Roundwright parser consumes only the exact `roundwright:` marker pair. Neither
parser may fall back to, merge, infer, or borrow values from the other block.

# roundwright:repository-authority
roundwright:
  schema_version: 2
  enabled: false
  allow_issue_comment: false
  allow_create_remote_branch: false
  allow_update_remote_branch: false
  allow_delete_remote_branch: false
  allow_create_draft_pr: false
  allow_request_review: false
  allow_mark_pr_ready: false
  allow_merge_pr: false
  allow_close_leaf_issue: false
  allow_delete_local_branch: false
  allow_remove_worktree: false
# roundwright:end-repository-authority
<!-- roundwright-proposed-authority:end -->
