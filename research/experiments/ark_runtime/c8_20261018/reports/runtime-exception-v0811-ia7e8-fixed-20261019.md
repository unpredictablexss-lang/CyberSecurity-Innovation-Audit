# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `2a70904be0e21a37a666eb00cab49d02068260ea`
- Git tree: `8e5503ee7eebbb8e72bc6d5ca0cb88d5775301ef`
- Snapshot SHA-256: `8bd228ca6280e8ad4b26c688aa87f2fe5ff5a4d503685856d608124b64fc7c75`
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
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:e1b4aae93fed8a59` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:1525` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:483fa1660266119f` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2686` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |
| `ohscanner.ark.runtime.type_safety` | `ohscanner.ark.runtime.type_safety:8581f6d2673b81c8` | `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp:2743` | `ark.runtime.typedarray-store-type-origin` | model_applicability=unknown; runtime_path_feasibility=unknown; security_impact=unknown; isolated_validation=unknown |

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
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: receiver_guard_caller_parse_or_signature_unknown
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: receiver_type_guard_not_resolved
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: unresolved_local_observations
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `535cc3338fed37ef14277a975462330d6c8e5157da23e771ef8c85f26cb6023b`
- Language matching plans attempts; actual coverage remains in the results above.
