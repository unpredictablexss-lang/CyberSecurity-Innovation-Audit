# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/telephony_call_manager`
- Pinned commit: `6638d1b37f278d7ed380d907674820e7467cedf8`
- Git tree: `3eb7742bdcd1507ad75cfe9c580ff7fefe4f9d41`
- Snapshot SHA-256: `e00fdbf14cf18529b5855d2bf572958c518f10da0b18aee0228e2b08d2ca9793`
- Source files indexed: 513
- Parsing coverage: `{"complete": 383, "partial": 130}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 381 | 381 | 0 | 130 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 2
- `frameworks/js/napi/src/call.js`
- `interfaces/kits/js/@ohos.telephony.call.d.ts`
- `ohscanner.example.cpp.copy-calls`: partial, 381/511 applicable files examined; unexamined=130

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.example.cpp.copy-calls`: EXAMPLE ONLY: inventories selected syntax call expressions; it is not vulnerability detection.
- `ohscanner.example.cpp.copy-calls`: No control flow, call resolution, macro expansion, object size or taint analysis.
- `ohscanner.example.cpp.copy-calls`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.example.cpp.copy-calls`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.example.cpp.copy-calls`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 130 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
