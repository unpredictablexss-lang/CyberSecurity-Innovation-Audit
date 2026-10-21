# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `19b3ebe60071dcd899f433b750951c8eabfc528eed178a9c16cdc16d941ef9d3`
- Source files indexed: 257
- Parsing coverage: `{"complete": 204, "partial": 53}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 204 | 204 | 0 | 53 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.example.cpp.copy-calls`: partial, 204/257 applicable files examined; unexamined=53

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 53 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
