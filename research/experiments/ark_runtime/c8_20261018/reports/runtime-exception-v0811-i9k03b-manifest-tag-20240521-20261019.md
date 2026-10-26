# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `3ad6d4c17d24fd4e1bb9a42067b36cc498d0979f`
- Git tree: `0ca739eb7b7063ea8b7de950011917effcfc3656`
- Snapshot SHA-256: `2bf573addab6c4f2b8866f67f9f080524addba47862aa67500bb6138f7493669`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
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
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::Filter
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::Find
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_array_stub_builder.cpp: unmodeled_generated_callback_exception_path:panda::ecmascript::kungfu::BuiltinsArrayStubBuilder::FindIndex
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `ac3be733e341db3f74c857ce0777b887ed19773f65e96b7da5da2bd0462a8a86`
- Language matching plans attempts; actual coverage remains in the results above.
