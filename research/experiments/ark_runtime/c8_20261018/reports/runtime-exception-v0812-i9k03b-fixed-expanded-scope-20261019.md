# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `df668db447d7b19ee38fe7925638feffdd2c9bd6`
- Git tree: `7ad1bcd12c8f35982d04fdab329a43555039cff1`
- Snapshot SHA-256: `4fba819d7d896f270e26dc966e7250b4f9a498e7e297cd3ac3b34066260f9c11`
- Source files indexed: 5
- Parsing coverage: `{"complete": 3, "partial": 2}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 0 | 1 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:0819150c3e5ad858` | `ecmascript/compiler/builtins/builtins_array_stub_builder.cpp:2292` | `ark.runtime.callback-exception-before-result-conversion` | exception_effect_semantics=unknown; control_flow_dominance=unknown; runtime_impact=unknown; product_binding=unknown |

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
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::Every
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::Filter
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::FindLast
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::FindLastIndex
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::Some
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `c5aeb2701f5de08e824c54c8887c619b328d3f45c36e11cc2f309477c78a8e81`
- Language matching plans attempts; actual coverage remains in the results above.
