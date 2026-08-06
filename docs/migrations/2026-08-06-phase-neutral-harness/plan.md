# Transition plan

1. Keep root `AGENTS.md` authoritative and add only a short mandatory routing
   pointer outside both authority blocks.
2. Add the canonical operations document and the compact leaf-issue template.
3. Link roadmap, Shadow, authority, and operator-facing README documentation
   without copying the canonical contract or changing Phase 2 promotion limits.
4. Inspect affected public issue bodies read-only and record only material,
   deterministic patches in `issue-proposals.md`.
5. The Orchestrator may apply at most one reviewed proposal transition at a
   time, read it back, and retain its exact resulting issue revision identity.
6. A future leaf selects exact commits at dispatch, reconciles them at every
   gate, and stores owner-safe evidence; it never upgrades a pin to `main`.

No step runs the native fixture, logs the owner in, creates a remote mutation,
or changes repository authority.
