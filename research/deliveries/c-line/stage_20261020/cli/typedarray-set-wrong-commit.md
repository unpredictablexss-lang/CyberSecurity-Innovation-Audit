# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `830e85b40240677039719fcbf14f721ad3b19050`
- Git tree: `579712c1ebbb703d17cea422b1572023bed5d8a4`
- Snapshot SHA-256: `f0860ca9f0d73b4f2a20aa39aa478354448d312742bfcd1af6eebeabf5712106`
- Source files indexed: 3
- Parsing coverage: `{"complete": 2, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 0 | 0 | 0 | 3 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: blocked, 0/3 applicable files examined; unexamined=3

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_arraybuffer.cpp: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_typedarray.cpp: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_typedarray.h: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `a2da20b1926c7a5b2d76840043f72350665d60803f0c22e0da66daae2db40bfc`
- Language matching plans attempts; actual coverage remains in the results above.
