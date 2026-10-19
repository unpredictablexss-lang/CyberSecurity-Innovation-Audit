# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `pnggroup/libpng`
- Pinned commit: `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`
- Git tree: `e01f5780f93eaa6d74cca003bb39b427c8f1e910`
- Snapshot SHA-256: `26cba27aa9b6619c776d99932a94336d6127934a63297f8ace50830772c86dbb`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 1 | 0 | 1 | 0 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: pngrutil.c: parse_status=partial; only bounded local complexity patterns are retained, semantic coverage remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `ed1859dc50724382ba85291fff955fed968097eb5ccc46c12be5bd1c85351a4f`
- Language matching plans attempts; actual coverage remains in the results above.
