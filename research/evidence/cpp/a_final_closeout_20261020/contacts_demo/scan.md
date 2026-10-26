# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/contacts_data`
- Pinned commit: `b02aadfc2d801ee30573fcb2d13490298e146fea`
- Git tree: `ef183625ccbc842f47b076eb75e68b665d7c21c6`
- Snapshot SHA-256: `05e048668b58a1778da649164cf2fffaff84677eafeee7d4c87fbf967c3588a2`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 3
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.path_traversal` | completed | 1 | 1 | 0 | 0 | 3 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.path_traversal` | `ohscanner.cpp.path_traversal:04e3ef65d0e6ed6b` | `dataBusiness/contacts/src/contacts_data_ability.cpp:789` | `ohcpp-path-traversal-source-to-file-sink-candidate-001` | source_binding=unknown; path_semantics=unknown; containment_dominance=unknown; entry_privilege_and_impact=missing |
| `ohscanner.cpp.path_traversal` | `ohscanner.cpp.path_traversal:42213d591d92fb56` | `dataBusiness/contacts/src/contacts_data_ability.cpp:790` | `ohcpp-path-traversal-source-to-file-sink-candidate-001` | source_binding=unknown; path_semantics=unknown; containment_dominance=unknown; entry_privilege_and_impact=missing |
| `ohscanner.cpp.path_traversal` | `ohscanner.cpp.path_traversal:b48a64b2266545fb` | `dataBusiness/contacts/src/contacts_data_ability.cpp:794` | `ohcpp-path-traversal-source-to-file-sink-candidate-001` | source_binding=unknown; path_semantics=unknown; containment_dominance=unknown; entry_privilege_and_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.path_traversal`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.path_traversal`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.path_traversal`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.path_traversal`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `3a770cf3dd2fc24c0feb0816f092d7da93e076b8c330b3f3bae417e26bdde1fe`
- Language matching plans attempts; actual coverage remains in the results above.
