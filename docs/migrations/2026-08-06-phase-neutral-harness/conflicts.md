# Conflict register

| ID | Previous ambiguity | Resolution | Status |
| --- | --- | --- | --- |
| PHI-1 | A controlled forward-test source was described as private in issue #49. | The owner-approved source is public `ythdelmar68/roundlet-forward-test`, disposable, and never production or unique work. | Proposed issue patch required. |
| PHI-2 | A harness `main` ref could be mistaken for this qualification run's content pin. | Preserve `681c7e9359a3767892a615ffa032d42b51e7be15` for the current run; record canonical main separately and require future explicit selection. | Resolved in canonical document. |
| PHI-3 | External tests could imply provider or mutation authority. | Routing, evidence, and owner login are explicitly non-authoritative; product and root authority remain separate. | Resolved in canonical document. |
| PHI-4 | Phase documents could duplicate and diverge from infrastructure terms. | Phase 3-6 documentation links to the single canonical document; the template carries only a compact declaration. | Resolved locally; remote proposals pending. |
| PHI-5 | Global package installation could make host state an implicit dependency. | `uv` is global/per-user only; Python and packages are inside harness repo-local `.venv`. | Resolved in canonical document. |
