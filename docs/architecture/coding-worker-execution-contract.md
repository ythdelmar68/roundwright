# Bounded coding Worker execution contract

Schema: `roundwright-coding-dispatch-receipt/v1`.

The PLANNING route remains `no-tools-self-contained/v1`.  IMPLEMENTATION and
REPAIR require `executable-bounded-coding/v1`, a sealed dispatch receipt, and
a `CodingToolEventStore`; labels or an injected `BoundedCodingTools` object are
not authority by themselves.

Before dispatch and before every local effect, the runtime compares task,
attempt, candidate SHA and fingerprint, worktree, policy, configuration, and
toolchain identities to the receipt.  A candidate probe mismatch fails before
the effect.  Session and turn identities are checkpointed before the tool loop,
and the closed request/result projection is appended before submission to the
SDK turn.  Replays return only an equivalent stored event; conflicting payloads
fail closed.

SDK feedback is transient and capped at the capability output limit.  File text
and validation diagnostics may be sent only to the active SDK turn.  Durable
events contain the tool, outcome, digests, exit code, process/cancellation/
ambiguity state, and no text or absolute path.

Production validation requires a `ReviewedValidationSandbox` whose identity is
bound into the dispatch receipt.  That reviewed operational implementation must
seal the selected worktree and runtime resources, deny network and ambient
credentials, bind the exact executable/toolchain, apply output/time limits, and
own and clean up children.  The direct launcher in `coding_tools.py` exists only
for disposable hermetic test fixtures and cannot satisfy a production receipt.

This contract is implementation evidence only.  Live coding qualification,
capture/readiness, exporter/comparator, and retention proof remain owned by
#128; no external-validation route or lifecycle observation is selected here.
