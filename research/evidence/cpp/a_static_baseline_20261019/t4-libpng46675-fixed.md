# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `pnggroup/libpng`
- Pinned commit: `e283ed5d3a74c0112f092ddb1003c97e0e9a4717`
- Git tree: `c78da20c3ffe37b09653eaa3b49c5213745ac4bd`
- Snapshot SHA-256: `0e27e208e7bb29cbb2a95d76ed7e1ee53959fac13eb529fe6ee6bced724179c1`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 0 | 0 | 0 | 1 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: blocked, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: fixed/pngrutil.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `d51db4df42c3827ce1f469a4be8816e50438ca8f7c548292af4b442a385b91f5`
- Language matching plans attempts; actual coverage remains in the results above.
