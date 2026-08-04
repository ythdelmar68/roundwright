# Shadow validation protocol

## Scope

Shadow is the permanent read-only regression layer for Roundwright. It replays
immutable inputs through a declared candidate and compares the result with a
declared reference outcome. It does not dispatch work, call a mutation broker,
write GitHub state, create branches or pull requests, merge, close issues,
release, publish, activate a runtime, or retire Roundlet.

This protocol owns Shadow input handling, deterministic comparison, mismatch
classification, retention, and curated reporting. It is consumed by later
qualification work; this document itself is not execution or promotion
evidence.

## Immutable replay inputs

Before a replay, the validator records an immutable input manifest containing:

- a public-safe source identifier and a content digest for every replay input;
- the exact reference-result identity and the exact candidate/base identities;
- the protocol version, declared comparison rules, and deterministic fixture
  environment identity; and
- the capture time and retention class without private paths, credentials, raw
  prompts, or confidential source content.

The replay consumes only the frozen manifest and its referenced immutable
contents. It must reject an absent manifest, duplicate or malformed identifier,
digest mismatch, changed source, undeclared dependency, unverifiable reference,
or candidate-provided replacement. A replay cannot update its own inputs or
reference result.

## Deterministic comparison

Comparison normalizes only protocol-declared, non-semantic variation before
comparison. It records the normalization version, compares the normalized
result byte-for-byte or with an explicitly versioned deterministic comparator,
and produces one of `MATCH`, `MISMATCH`, or `INVALID`.

`MATCH` means only that the declared candidate agrees with the declared
reference for the frozen input. It is not authorization, approval, canary
readiness, promotion, or evidence of a live external mutation. `INVALID`
denies the result when identity, determinism, privacy, or comparator integrity
cannot be established.

## Mismatch classification

Every `MISMATCH` must be classified without overwriting the original result:

| Class | Meaning | Required disposition |
| --- | --- | --- |
| `INPUT_DRIFT` | The replay input or reference identity differs from the frozen manifest. | Mark invalid, preserve the observation, and recapture only through the trusted process. |
| `NORMALIZATION_DEFECT` | The versioned normalizer is incomplete or inconsistent. | Block qualification until a reviewed protocol revision and fresh replay are available. |
| `DETERMINISM_DEFECT` | Repeated declared runs disagree. | Block qualification and preserve all run identities. |
| `SEMANTIC_REGRESSION` | Stable compared outcomes differ in a meaningful field. | Block promotion; create a bounded repair/decision record. |
| `EXPECTED_CHANGE` | A separately approved reference update explains the stable difference. | Require the owner-approved reference identity; never silently accept it. |
| `ENVIRONMENT_LIMITATION` | A declared environment cannot run the fixture comparably. | Record as incomplete, not pass or waiver; owner decides whether to narrow or stop the scope. |

Unknown, multiple, missing, or candidate-authored classifications fail closed
as `INVALID` or a blocked qualification result. Shadow does not repair a
mismatch and cannot declare its own exception.

## Retention and curated reporting

Retain the immutable manifest, input and reference digests, candidate/base
identity, comparator and normalization versions, result identity,
classification, disposition, and public-safe report digest for the period
required by the consuming qualification issue or later owner decision. Preserve
the original comparison even if a later run supersedes it. Do not retain or
publish credentials, private paths, raw prompts, confidential sources, or raw
run artifacts in a public report.

Curated reports state the scope, exact public-safe identities, result,
classification, disposition, and whether the replay was read-only. They must
not imply a mutation, activation, promotion, or approval. A report with missing
or unverifiable retention references is incomplete and cannot support a phase
exit.

## Relationship to authority

Shadow is independent of the dispatcher and never competes with it. During
Phase 3–5, Roundlet remains the Roundwright repository's mutation-capable
Orchestrator unless an external owner-approved transition changes the active
authority. Shadow remains read-only both before and after any transition. See
the [dogfood promotion roadmap](../operations/dogfood-promotion-roadmap.md)
for phase gates, repository authority, rollback, and owner-only decisions.
