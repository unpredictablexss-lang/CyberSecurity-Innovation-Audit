# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `pnggroup/libpng`
- Pinned commit: `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`
- Git tree: `e01f5780f93eaa6d74cca003bb39b427c8f1e910`
- Snapshot SHA-256: `f80ae78bc09612fd5b8c5a925f858b41e15711319d0a794cafeb4764f7ec73d9`
- Source files indexed: 4
- Parsing coverage: `{"partial": 4}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 4 | 0 | 4 | 0 | 2 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0f4a7c238e4ca5ff` | `pngrtran.c:1187` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0a2fa5fe1ecec1bd` | `pngrtran.c:1228` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: partial, 0/4 applicable files examined; unexamined=4

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: png.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngread.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngrtran.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngset.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `0ceb501728d8d6d5effcfe154590ac7191c943e31dba6755a35d10925db32add`
- Language matching plans attempts; actual coverage remains in the results above.
