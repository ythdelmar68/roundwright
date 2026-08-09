# Typed GitHub adapter boundary

`roundwright.github` defines the Phase 3 environment-neutral GitHub contract.
It has no network client and imports neither `gh` nor MCP. The future default
live adapter is `gh`; an MCP adapter is optional and is never a runtime
requirement.

Core logic sends immutable `GitHubReadRequest` values and receives immutable,
public-safe snapshots. Every response must supply—and match—the requested
repository plus its operation-specific issue, pull-request, branch, or ref
identity. Each operation admits one exact response shape, including nested
records; unknown, missing, and inapplicable fields fail closed. The supported reads cover repository identity, issues
and parent/sub-issue relationships, comments, branches, pull requests,
reviews, checks, workflow runs, mergeability, closing references, and exact
remote heads. Snapshots retain exact identifiers and commit identities, while
comment bodies are reduced to stable digests. Unknown, missing, mismatched, or
incomplete response fields are classified as `malformed-response`, not guessed.

Mutation is deliberately described as `GitHubMutationIntent`; it is not
executed by this Phase 3 core boundary. Its canonical, operation-specific
payload carries public references and content digests only, and is bound into
the intent and receipt identity. Outcomes distinguish unavailable
capability, permission denial, authentication failure, transport failure,
malformed response, stale response, and policy denial. A later `gh` adapter
must bind its semantic read-back receipt to the full intent identity. A
successful receipt is invalid without a semantic read-back digest.

The Python `RepositoryMutationOperation` vocabulary and schema v2 Boolean
names are canonical. Every `GitHubMutationOperation` has one immutable,
one-to-one mapping to it; every repository operation has one Boolean switch.
The mapping is validated for totality at import and in CI, so missing, extra,
duplicate, or `None` entries fail before a mutation can be considered.
Remote branch creation, non-force update, and deletion are distinct actions.
An update binds both the previously observed SHA and the desired exact SHA;
request-review binds the exact pull-request head SHA and reviewers digest.

## `gh` runtime seam and semantic receipts

`roundwright.github_runtime` supplies that narrow `gh` seam. `gh` is the
documented default live adapter; MCP remains optional. The subprocess runner
accepts only the literal `gh` executable, uses no shell or token argument,
discards stderr, and returns no raw output beyond the adapter's immediate
normalization step. It never calls `gh auth status`, discovers credentials, or
places credentials, raw output, paths, or payload text in a typed result,
diagnostic, or receipt.

Every declared read and mutation operation requires its own
`OperationHealth` observation in `GitHubCapabilityHealth`. A missing row is
invalid; an unavailable row fails before a command is run. The default matrix
marks every operation unavailable, so constructing the adapter does not create
authority. Direct `submit` calls are denied even when health is available:
only `GitHubMutationBroker` can consider a typed intent. The adapter's separate
broker-only execution seam maps every declared mutation operation to one fixed
`gh` command shape. It accepts an ephemeral, digest-bound
`GhMutationPayload` from the credential-owning Orchestrator, rejects a missing
or mismatched payload before starting a process, and discards command output.
It does not accept a shell string, executable override, token, or arbitrary
command line. An unforgeable in-process capability is issued only to the
broker, so invoking the execution seam without the broker is denied too.

The broker requires an already-authorized exact Boolean repository-policy
decision, an authoritative deployment decision, a matching candidate, a gate
identity, configuration/base/candidate identities, and a pre-state read before
it invokes an adapter. A success exit code is insufficient: it requires an
operation-specific post-state read and produces a `SemanticMutationReceipt`
only if the exact semantic condition matches. The receipt binds repository,
operation, idempotency key, public payload digest, policy/configuration/
deployment/task/base/candidate/gate identities, pre- and post-state digests,
affected identity, and disposition. A repeat returns the retained receipt
without another mutation; an interrupted or mismatched post-state is marked
for reconciliation and is never reported as success.

The active repository policy keeps Roundwright disabled. Therefore the Phase 3
Shadow path evaluates these requirements counterfactually and denies before
broker execution. Live use is limited to separately approved read-only
observations; mutation fixtures remain hermetic and prove zero live mutation.

`FakeGitHubAdapter` is test-only and fully deterministic. Fixtures specify
normal responses, each failure class, stale responses, and duplicate semantic
receipts. It records every attempted adapter call. Mutation intents are denied
unless a fixture explicitly supplies a receipt, and a duplicate returns the
same semantic identity as `ALREADY_APPLIED`; it never represents a second
external action. An accepted fixture must explicitly supply its semantic
read-back digest. This makes shadow fixtures capable of proving both the
requested operation and an adapter-call count of zero.
