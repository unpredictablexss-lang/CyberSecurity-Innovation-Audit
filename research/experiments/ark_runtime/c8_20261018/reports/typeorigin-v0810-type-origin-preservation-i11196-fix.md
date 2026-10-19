# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `919e4fbb011f610427e788889083fa8e28d2f951`
- Git tree: `82af11ced4297818410ccf61906b703d25b69165`
- Snapshot SHA-256: `45951ebe149386befe03a7dcfe28f1ce3fc1b91c8a9947745a692a4186e148dc`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 0 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Semantic applicability is bounded to declared Ark Runtime owner/method/signature profiles; no preprocessor, whole-program, product-build, or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: exception_path_not_fully_modeled
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: experimental_partial_function_scope
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: load_hclass_signature_or_binding_mismatch
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: parse_dependency_contamination_unknown
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: partial_scope_routed_through_semantic_selector
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `7a632e01ef61426fc1a84c637e245655dd2ea0553680420be21fab4f8001841f`
- Language matching plans attempts; actual coverage remains in the results above.
