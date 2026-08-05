# Typed GitHub adapter boundary

`roundwright.github` defines the Phase 3 environment-neutral GitHub contract.
It has no network client and imports neither `gh` nor MCP. The future default
live adapter is `gh`; an MCP adapter is optional and is never a runtime
requirement.

Core logic sends immutable `GitHubReadRequest` values and receives immutable,
public-safe snapshots. The supported reads cover repository identity, issues
and parent/sub-issue relationships, comments, branches, pull requests,
reviews, checks, workflow runs, mergeability, closing references, and exact
remote heads. Snapshots retain exact identifiers and commit identities, while
comment bodies are reduced to stable digests. Unknown, missing, mismatched, or
incomplete response fields are classified as `malformed-response`, not guessed.

Mutation is deliberately described as `GitHubMutationIntent`; it is not
executed by this Phase 3 core boundary. Outcomes distinguish unavailable
capability, permission denial, authentication failure, transport failure,
malformed response, stale response, and policy denial. A later `gh` adapter
must bind its semantic read-back receipt to the full intent identity.

`FakeGitHubAdapter` is test-only and fully deterministic. Fixtures specify
normal responses, each failure class, stale responses, and duplicate semantic
receipts. It records every attempted adapter call. Mutation intents are denied
unless a fixture explicitly supplies a receipt, and a duplicate returns the
same semantic identity as `ALREADY_APPLIED`; it never represents a second
external action. This makes shadow fixtures capable of proving both the
requested operation and an adapter-call count of zero.
