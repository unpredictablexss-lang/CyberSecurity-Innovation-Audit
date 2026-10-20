# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `a65a2853ccae13da167d9aa4720ab8b11ec16656`
- Git tree: `8781f036a3e7e04d8e0b34970d5f623b42875016`
- Snapshot SHA-256: `6270bb99670c65dcca88a79a186041d5db3cddcc9d88c82a7a3fbe43b33174bd`
- Source files indexed: 2
- Parsing coverage: `{"complete": 1, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 1 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: partial, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: experimental_partial_function_scope
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: parse_dependency_contamination_unknown
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: partial_scope_routed_through_semantic_selector
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: unresolved_local_observations
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/new_object_stub_builder.cpp: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `6d8877bae43c9bd5644c0b5a4e30e8d02bbb8a782e6c64133c60389375702db6`
- Language matching plans attempts; actual coverage remains in the results above.
