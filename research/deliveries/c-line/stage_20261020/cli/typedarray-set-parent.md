# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `a65a2853ccae13da167d9aa4720ab8b11ec16656`
- Git tree: `8781f036a3e7e04d8e0b34970d5f623b42875016`
- Snapshot SHA-256: `4feb17e700c09316248bd882c6c8c807b58979baf88193bd9ae33162535bb558`
- Source files indexed: 3
- Parsing coverage: `{"complete": 2, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 2 | 1 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:e4eff216814da1ab` | `ecmascript/builtins/builtins_typedarray.cpp:1227` | `ark.runtime.typedarray-arraylike-set-offset-wrap` | integer_wrap_dispatch=unknown; cross_view_write=unknown; source_side_effects=unknown; product_binding=unknown; isolated_runtime_validation=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: partial, 0/3 applicable files examined; unexamined=3

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_arraybuffer.cpp: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_typedarray.cpp: arraylike_set_bounds_declaration_header_partial
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_typedarray.h: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `ceb778c9d61d037d89d368f6d7689a5ed40d444b02a6b672d5dbdfa3de333cbf`
- Language matching plans attempts; actual coverage remains in the results above.
