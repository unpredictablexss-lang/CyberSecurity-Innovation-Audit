# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `c758818dbfd0b146a908d43d21f6ca1706c33783`
- Git tree: `5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a`
- Snapshot SHA-256: `bbdfdae0b975efbf7e91518f9ff8c029dc7bc5f9b085da8b282598b19d9108d1`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 0 | 2 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:3d62ef945e91f1c2` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1487` | `ark.runtime.typedarray-allocation-exception-guard` | exception_path_semantics=unknown; runtime_impact=unknown; product_binding=unknown; isolated_validation=unknown; parse_completeness_impact=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:3a7114309068fd5c` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2656` | `ark.runtime.typedarray-allocation-exception-guard` | exception_path_semantics=unknown; runtime_impact=unknown; product_binding=unknown; isolated_validation=unknown; parse_completeness_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `c111f1fc361355c5c5cd0218b8b566ca1a5bb934657c8cae5967ef734ff9f943`
- Language matching plans attempts; actual coverage remains in the results above.
