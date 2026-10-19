# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `1eea202527c76b4ee171efe7597ebccecb1ee027`
- Git tree: `bc32ff368b44ed95d44be2ae0c52c4ae39bc50af`
- Snapshot SHA-256: `f2f7124f085bb5810cdb5e96310154e04c2025aa7a5fd2f0448fac360ce6946f`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 4
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | completed | 1 | 1 | 0 | 0 | 4 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:a1904abc6a26ace1` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1537` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:a9be2c2ed5d9c3a7` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1801` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:2cbb8bcfbfa17bdc` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2698` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:68e02531d1486bf6` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2755` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Semantic applicability is bounded to declared Ark Runtime owner/method/signature profiles; no preprocessor, whole-program, product-build, or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `8590971f462324ab2325200b0e7198b5c79e4d9eb26413920d16f88f391e7672`
- Language matching plans attempts; actual coverage remains in the results above.
