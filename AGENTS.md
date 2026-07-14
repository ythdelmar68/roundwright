# VERSION CONTROL GUIDELINES

## GIT
- Read and use [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/) to create meaningful commit messages in format: `<type>(<scope>): <description>`
  - Write meaningful commit messages that explain why changes were made, not just what.
  - Keep commits atomic and focused on single logical changes to facilitate code review and bisection.
- Read and use [Conventional Branch](https://conventional-branch.github.io/) to create descriptive branch names.
- Update `.gitignore` for new build artifacts or dependencies.

<!-- phase0-automation-policy:start -->
## Repository Automation Policy

- Draft PR creation is allowed only after deterministic identity, coverage, privacy, and independent-review gates pass.
- Ready-for-review transition additionally requires an owner receipt bound to the reviewed owner-bundle digest and exact candidate commit SHA.
- Merge, release, tag, publish, version bump, visibility changes, destructive cleanup, branch deletion, force push, reset, and rebase require explicit owner approval.
- Model-backed workers and reviewers are advisory, read-only, credential-isolated, and cannot bypass the repository-scoped Orchestrator.
- GitHub trace text must be curated and public-safe. Never post raw run artifacts, private evidence, credentials, internal owner reasoning, or confidential source context.
- Missing, stale, conflicting, or unverifiable evidence fails closed.
<!-- phase0-automation-policy:end -->
