# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/web_webview`
- Pinned commit: `87a7f7442c548ec8b46db6f73338e28983af9996`
- Git tree: `e1f6be0ebadba17b3cf94fb5b4202498e0c41a03`
- Snapshot SHA-256: `c59d3b70eca423e6abe7e46f12a1b6f45980d91c861601e1ee463e310c03be77`
- Source files indexed: 5
- Parsing coverage: `{"complete": 4, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 13
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 4 | 0 | 4 | 1 | 13 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:f8f40ffedd5159c9` | `renamed.cpp:3` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:c4de4e8866288753` | `vulnerable_flowbuffer_functions.cc:85` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:7ed2239a60ebc650` | `vulnerable_flowbuffer_functions.cc:87` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:a97ae57258c783e5` | `vulnerable_flowbuffer_functions.cc:96` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:6c6edcccaaa5d093` | `vulnerable_flowbuffer_functions.cc:98` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:d32cdbe7997de5ad` | `vulnerable_flowbuffer_functions.cc:116` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:f5ad15f052979d90` | `vulnerable_flowbuffer_functions.cc:118` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:172156543ec3df41` | `vulnerable_flowbuffer_functions.cc:126` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:c5fc6ac2b81f7b79` | `vulnerable_flowbuffer_functions.cc:127` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:cf0b626517d75dc3` | `vulnerable_flowbuffer_functions.cc:131` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:0a3d142204b6736f` | `vulnerable_flowbuffer_functions.cc:133` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:1544c9f90f90bacb` | `vulnerable_flowbuffer_functions.cc:140` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:77e336b578a55a1b` | `vulnerable_flowbuffer_functions.cc:142` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: partial, 0/5 applicable files examined; unexamined=5

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: partial.cpp: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `0cb959d90a8d98ae165d644242a17386a6a8bf408f5930c9b7c4969d9b030a44`
- Language matching plans attempts; actual coverage remains in the results above.
