# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `curl/curl`
- Pinned commit: `01346829096c61b372692f6dc43ffa778c6caccd`
- Git tree: `6ae23d9333713707a02588b44ed238a50e8b3bde`
- Snapshot SHA-256: `c0ca047682dce16d7aec8a1607b06f7a0420602a6a0ae13b8195f6629a1ac730`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | completed | 1 | 1 | 0 | 0 | 1 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:057e29253b6f4573` | `lib/mime.c:1118` | `ohcpp-resource-lifetime-recursive-cleanup-candidate-003` | callback_binding=unknown; recursive_cleanup_path=unknown; input_depth_control=missing; entry_or_privilege_boundary=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: lib/mime.c:cleanup_part_content: unresolved allocation/release alias state remains unknown.
- `ohscanner.cpp.resource_lifetime`: lib/mime.c:mimesetstate: unresolved allocation/release alias state remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `81380b390093bb736f58039d94c59cb90f96932528e5ac3f796acffaf33a2839`
- Language matching plans attempts; actual coverage remains in the results above.
