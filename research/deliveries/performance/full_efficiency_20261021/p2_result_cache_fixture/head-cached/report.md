# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/incremental-cache`
- Pinned commit: `eff6ef56d9161173dd3d43b72f4d727f9eb16ccb`
- Git tree: `2b9a1aed7a5d7342856327076a8adb52596aaa17`
- Snapshot SHA-256: `743793cbbbeddd978e3dbc90f4d8436a917f0f3fa79303a6dfb8972ef8ef0874`
- Source files indexed: 2
- Parsing coverage: `{"complete": 2}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | failed | 0 | 0 | 0 | 2 | 0 | failed |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.example.cpp.copy-calls`: failed, 0/2 applicable files examined; unexamined=2

## Limitations

## Incremental planning

- Base commit: `9cff3eac63e7946329b1a1401a95e0f08e308309`; changed paths: 1
- Execution: `full_source_index_with_verified_per_file_result_reuse`; fallback reason: `cross_file_dependency_reuse_unproven; declared_source_blob_results_reused`
- Reused source files: 1; reused detector results: 1; cache-eligible recomputations/bypasses: 1. Full head source inventory and uncacheable detectors still ran.

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Incremental mode preserves full source indexing. Only explicitly opted-in single-Blob detector results may be reused; cross-file dependency reuse remains disabled.
- `ohscanner.example.cpp.copy-calls`: Detector failed: ValueError
- `ohscanner.example.cpp.copy-calls`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.example.cpp.copy-calls`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.example.cpp.copy-calls`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.example.cpp.copy-calls`: Detector failed; unexamined scope is unknown.
