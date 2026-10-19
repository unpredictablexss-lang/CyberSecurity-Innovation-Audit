# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11`
- Git tree: `0eea26c9eb6846f4d19926be83092c06f0d98692`
- Snapshot SHA-256: `ac7ff6e9a7a289e6fbcfe8c0599b15557d63ff2ce0184499dd547d1615998af8`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 5
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | completed | 1 | 1 | 0 | 0 | 5 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:76371c5c797e34b8` | `ecmascript/js_array.cpp:650` | `ohcpp-memory-bounds-element-access-candidate-003` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:dae378a343b89219` | `ecmascript/js_array.cpp:653` | `ohcpp-memory-bounds-element-access-candidate-003` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:c565fc9e460b73ba` | `ecmascript/js_array.cpp:665` | `ohcpp-memory-bounds-element-access-candidate-003` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:ca06d2c16dbf65df` | `ecmascript/js_array.cpp:666` | `ohcpp-memory-bounds-element-access-candidate-003` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:c80e695b638c64f8` | `ecmascript/js_array.cpp:668` | `ohcpp-memory-bounds-element-access-candidate-003` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `29acdca9b82c4641ba249710dda20f69f2cdb4e4cd81c380452507c6f7261aa9`
- Language matching plans attempts; actual coverage remains in the results above.
