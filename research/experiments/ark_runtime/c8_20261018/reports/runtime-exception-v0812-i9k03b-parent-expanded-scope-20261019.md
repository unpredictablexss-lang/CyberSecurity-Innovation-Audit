# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `a3bbeab9883c7c22d4bdc0e65b3b516215d39e0d`
- Git tree: `af0321fb130de3e69613d61323cc337f0a4836a7`
- Snapshot SHA-256: `37f6ac7bdd4ae81bffdc08ce7ae1330aae8c6aa66238339557ce7aee5a97d105`
- Source files indexed: 5
- Parsing coverage: `{"complete": 3, "partial": 2}`
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
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:7b9f4946c0d0d542` | `ecmascript/compiler/builtins/builtins_array_stub_builder.cpp:2234` | `ark.runtime.callback-exception-before-result-conversion` | exception_effect_semantics=unknown; control_flow_dominance=unknown; runtime_impact=unknown; product_binding=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:751c857d52606d5a` | `ecmascript/compiler/builtins/builtins_array_stub_builder.cpp:2292` | `ark.runtime.callback-exception-before-result-conversion` | exception_effect_semantics=unknown; control_flow_dominance=unknown; runtime_impact=unknown; product_binding=unknown |

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
- Plan SHA-256: `2a8f46cb765d56e6febcef1b7efff586ab37478f9314efddd134cb4d4ec6fbb2`
- Language matching plans attempts; actual coverage remains in the results above.
