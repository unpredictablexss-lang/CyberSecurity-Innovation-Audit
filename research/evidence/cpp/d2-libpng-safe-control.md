# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/d2-safe-controls`
- Pinned commit: `68ef7bc95dcc3dda62cb612e872fcd389377fc4e`
- Git tree: `d69f7520ee2475f5132fdf291e36a457873eb4f9`
- Snapshot SHA-256: `35dfc3f62308458d5020ddb2a3be516faf0a41195cc7cd4c72756817795ada80`
- Source files indexed: 3
- Parsing coverage: `{"complete": 3}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | completed | 3 | 3 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: complete, 3/3 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `5715d934f29331bd74cd5b14129bb6b7837772dd6c62ff1d15cbdd36a2bde02f`
- Language matching plans attempts; actual coverage remains in the results above.
