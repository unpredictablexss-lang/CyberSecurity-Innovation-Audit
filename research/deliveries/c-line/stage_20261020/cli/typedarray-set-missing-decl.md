# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `a65a2853ccae13da167d9aa4720ab8b11ec16656`
- Git tree: `8781f036a3e7e04d8e0b34970d5f623b42875016`
- Snapshot SHA-256: `f5e0f9ba2b88fe11102da35ab163fe2a2b0cfc7f7305dce11f0c7730f0cc1a25`
- Source files indexed: 2
- Parsing coverage: `{"complete": 2}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 0 | 0 | 0 | 2 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: blocked, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_arraybuffer.cpp: exact upstream repository/commit/path is not in the reviewed model
- `ohscanner.ark.runtime.type_safety`: ecmascript/builtins/builtins_typedarray.cpp: arraylike_set_bounds_missing_target_declaration
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `04b356e1118c290c7bad2d794ef5fa67b3ec2aeea5edab40f52b641ec2597a28`
- Language matching plans attempts; actual coverage remains in the results above.
