# Conflict register

| ID | Previous ambiguity | Resolution | Status |
| --- | --- | --- | --- |
| PHI-1 | A controlled forward-test source was described as private in issue #49. | The owner-approved source is public `ythdelmar68/roundlet-forward-test`, disposable, and never production or unique work. | Proposed issue patch required. |
| PHI-2 | A harness `main` ref could be mistaken for this qualification run's content pin. | Record historical `681c7e9359a3767892a615ffa032d42b51e7be15` as non-qualifying; record selected content `52b1ad81ca2e13b40f4244f431fad9c231ab4c28` separately from canonical merge `2d412311d8ddbeb1db538111126a6e5dd62297b1`, and require fresh explicit selection after candidate movement. | Resolved in canonical document. |
| PHI-6 | Exact selected content could be conflated with its merge commit or superseded PR #2 heads. | Bind selected content, main merge, both parent identities, shared tree, selected factory, owner comment, and exact Roundwright candidate together. Superseded PR #2 heads remain unselected. | Resolved in canonical document and execution/audit record. |
| PHI-3 | External tests could imply provider or mutation authority. | Routing, evidence, and owner login are explicitly non-authoritative; product and root authority remain separate. | Resolved in canonical document. |
| PHI-4 | Phase documents could duplicate and diverge from infrastructure terms. | Phase 3-6 documentation links to the single canonical document; the template carries only a compact declaration. | Resolved locally; remote proposals pending. |
| PHI-5 | Global package installation could make host state an implicit dependency. | `uv` is global/per-user only; Python and packages are inside harness repo-local `.venv`. | Resolved in canonical document. |
