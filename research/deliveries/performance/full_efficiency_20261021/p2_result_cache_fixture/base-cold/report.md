# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/incremental-cache`
- Pinned commit: `9cff3eac63e7946329b1a1401a95e0f08e308309`
- Git tree: `897b7d2624f285d3924ca89cf3c3f5f25dd61b00`
- Snapshot SHA-256: `3c06b91c79556eb8943b32d62185bc7031788bd36e3e7f9a773fcbf41571266d`
- Source files indexed: 2
- Parsing coverage: `{"complete": 2}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 2 | 2 | 0 | 0 | 2 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.example.cpp.copy-calls` | `ohscanner.example.cpp.copy-calls:f3d0e11d975eff43` | `changed.cpp:1` | `example.cpp.copy-call-inventory` | resolved_callee=unknown; bounds_proof=unknown; reachability=unknown |
| `ohscanner.example.cpp.copy-calls` | `ohscanner.example.cpp.copy-calls:8c7e6ce6907f53e2` | `unchanged.cpp:1` | `example.cpp.copy-call-inventory` | resolved_callee=unknown; bounds_proof=unknown; reachability=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.example.cpp.copy-calls`: complete, 2/2 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.example.cpp.copy-calls`: EXAMPLE ONLY: inventories selected syntax call expressions; it is not vulnerability detection.
- `ohscanner.example.cpp.copy-calls`: No control flow, call resolution, macro expansion, object size or taint analysis.
- `ohscanner.example.cpp.copy-calls`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.example.cpp.copy-calls`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.example.cpp.copy-calls`: Diagnostic does not establish vulnerability, reachability or security impact.
