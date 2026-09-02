# CI read-only handoff qualification

The CI workflow is a verifier, not a deployment authority. Its repository-wide
permission is `contents: read`; it has no dispatch trigger, deployment
environment, authority secret, or persistent authority receipt. Normal jobs
build one candidate-bound package, run deterministic tests and installed
diagnostics, and emit only public-safe qualification artifacts.

`ci/verify_ci_read_only_handoff.py` is the separately selected hermetic
handoff fixture. Before it can record a receipt it verifies all of the
following against the exact checked-out candidate:

- the selected SHA equals `git rev-parse HEAD`;
- `package-digest.json` matches exactly one uploaded wheel;
- the workflow policy bytes are represented by a SHA-256 digest; and
- the policy and verifier Git blob identities equal the exact candidate-tree
  blobs (independent of platform line-ending materialization); and
- the workflow mode is exactly `read-only`.

It then exercises the pure, in-memory deployment handoff coordinator. The
fixture stops the synthetic old authority, records complete dispatcher/child/
lease reconciliation, revokes the old receipt, issues one exact selected
receipt, records one budget-one fixture action and independently reads back its
exact completed result, then repeats stop, reconciliation, and revocation for
teardown. The terminal teardown verifies cleanup, clears the revoked handoff,
and asserts after restart that no receipt or handoff remains active. Missing state, a stale candidate, copied receipt,
partial reconciliation, ambiguous read-back, or failed teardown is a
fail-closed qualification error.

This is coverage of ordering and receipt binding only. It cannot inspect or
issue a real authority receipt, invoke a scheduler or provider, mutate a
deployment target, or turn CI into a second dispatcher.
