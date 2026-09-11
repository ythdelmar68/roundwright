# Bounded coding Worker execution contract

Schema: `roundwright-coding-dispatch-receipt/v1`.

The PLANNING route remains `no-tools-self-contained/v1`.  IMPLEMENTATION and
REPAIR require `executable-bounded-coding/v1`, a sealed dispatch receipt, and
a `CodingToolEventStore`; labels or an injected `BoundedCodingTools` object are
not authority by themselves.

Before dispatch and before every local effect, the runtime compares task,
attempt, candidate SHA and fingerprint, worktree, policy, configuration, and
toolchain identities to the receipt.  It also recomputes the sealed capability
digest: root identity, readable/writable allowlists, command tuples, time and
feedback budgets, resolved executable digests, and reviewed-sandbox receipt.
A candidate or capability mismatch fails before the effect.  Session and every
actual SDK turn identity are checkpointed before their stream is consumed.  An
effect-intent reservation is durably written before the filesystem or process
effect; a recovered matching reservation is typed `ambiguous` and is never
re-run.  The closed result projection is appended after execution and before
submission to that SDK turn.  Conflicting payloads fail closed.

SDK feedback is transient and capped at the capability output limit.  File text
and validation diagnostics may be sent only to the active SDK turn.  Durable
events contain the tool, outcome, digests, exit code, process/cancellation/
ambiguity state, and no text or absolute path.

Production validation requires a `ReviewedValidationSandbox` whose identity and
reviewed receipt digest are bound into the dispatch receipt.  Its issuer must
pin the reviewed OS sandbox infrastructure revision and seal the selected
worktree, executable/toolchain resources, network and ambient-credential denial,
output/time limits, child containment, cancellation request/confirmation, and
cleanup receipt.  The required host integration is the reviewed Harness sandbox
implementation at commit `0154817a6fba345b78af25017eb312a1b2349cd6`; until that
implementation emits the sealed receipt, this repository deliberately has no
live coding-runtime activation.  The direct launcher in `coding_tools.py`
exists only for disposable hermetic test fixtures and cannot satisfy a
production receipt.

This contract is implementation evidence only.  The versioned downstream
contracts are `roundwright-worker-shadow-capture-readiness/v1`,
`roundwright-worker-qualification-binding/v1`, and
`roundwright-worker-qualification-result/v1`; their digest identities, capture
plan, recorder/exporter/comparator binding, and retention are enforced by the
existing `worker_shadow` qualification boundary.  Coding activation additionally
requires qualification coverage for candidate movement, restart after an effect
intent, result replay, timeout/cancellation, cleanup, and terminal ambiguity.
Live coding qualification remains owned by #128; no external-validation route
or lifecycle observation is selected here.
