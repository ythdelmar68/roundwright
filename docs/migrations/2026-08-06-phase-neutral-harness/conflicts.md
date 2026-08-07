# Conflict register

| ID | Previous ambiguity | Resolution | Status |
| --- | --- | --- | --- |
| PHI-1 | A controlled forward-test source was described as private in issue #49. | The owner-approved source is public `ythdelmar68/roundlet-forward-test`, disposable, and never production or unique work. | Proposed issue patch required. |
| PHI-2 | A harness `main` ref could be mistaken for current invocation authority. | Record historical non-qualifying `681c7e9359a3767892a615ffa032d42b51e7be15` and historical prior selection `52b1ad81ca2e13b40f4244f431fad9c231ab4c28`/`2d412311d8ddbeb1db538111126a6e5dd62297b1`; require fresh authenticated selection after candidate or harness movement. | Resolved in canonical document. |
| PHI-6 | Repaired content could be conflated with either its merge or an owner selection. | Bind PR #3 content `e5ec738c67130b17a8e723b89a4b567e1873838d`, main merge `42830db90acbba499989cd434cdc46b4627042e2`, parent pair, shared tree, CI, and review trace as reviewed pending evidence only. | Resolved in canonical document and execution/audit record. |
| PHI-7 | A filesystem sandbox child-execution denial could be mistaken for administrator elevation or a package-install requirement. | Use ordinary low-privilege user, global/per-user `uv`, repo-local `.venv`/Python/packages, and only a separately authorized live host process for hermetic Git/pinned-runtime child execution outside the filesystem sandbox. | Resolved; no authority or package policy change. |
| PHI-3 | External tests could imply provider or mutation authority. | Routing, evidence, and owner login are explicitly non-authoritative; product and root authority remain separate. | Resolved in canonical document. |
| PHI-4 | Phase documents could duplicate and diverge from infrastructure terms. | Phase 3-6 documentation links to the single canonical document; the template carries only a compact declaration. | Resolved locally; remote proposals pending. |
| PHI-5 | Global package installation could make host state an implicit dependency. | `uv` is global/per-user only; Python and packages are inside harness repo-local `.venv`. | Resolved in canonical document. |
