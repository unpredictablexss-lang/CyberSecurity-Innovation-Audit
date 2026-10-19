# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `acb7197ca9ce52248f3842012cb8c483158655a8`
- Git tree: `808fa19c831c1b61d9b75b96b642bd90c31d55be`
- Snapshot SHA-256: `3a3befafa1b966020d11f95b8fd2324a0532033b4fe45552c3726e4a001e4b6a`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 3
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 1 | 0 | 1 | 0 | 3 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:af4ce30550cc2d0b` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1537` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:7eba1fdd76eeba76` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1801` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:46b97adcb92344cb` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2756` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |

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
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: load_hclass_signature_or_binding_mismatch
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: unresolved_local_observations
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `c1080207960ce81d299b7ea90b4800913536a0f73c6b3f83d51cb74fbe700ff7`
- Language matching plans attempts; actual coverage remains in the results above.
