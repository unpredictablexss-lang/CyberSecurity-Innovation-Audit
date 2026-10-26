# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `a65a2853ccae13da167d9aa4720ab8b11ec16656`
- Git tree: `8781f036a3e7e04d8e0b34970d5f623b42875016`
- Snapshot SHA-256: `7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.ark.runtime.type_safety` | blocked | 0 | 0 | 0 | 1 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.ark.runtime.type_safety`: blocked, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.ark.runtime.type_safety`: Narrow local syntax/IR model; no whole-program type or exploitability proof.
- `ohscanner.ark.runtime.type_safety`: ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp: model dependency snapshot is blocked pending semantic review tree=8781f036a3e7e04d8e0b34970d5f623b42875016 snapshot_sha256=7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2 comparison_manifest_sha256=c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d model_sha256=79e69842146939fd1d278b10165bc4b1c468cf26676b56c04eaf09bf9c7f82e6 (unknown_unreviewed_semantics)
- `ohscanner.ark.runtime.type_safety`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.ark.runtime.type_safety`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.ark.runtime.type_safety`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.ark.runtime.type_safety`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.ark.runtime.type_safety`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `a64dd69e3d098f86e72344ab8ae3125ef68b9816e74b02291868a6b3cef35d50`
- Language matching plans attempts; actual coverage remains in the results above.
