# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `OpenHarmony-TPC/chromium_src`
- Pinned commit: `769110ddf1c14355c89f34b974ab9e6cf58c0c6c`
- Git tree: `a8d7d7f9fd5d81a7cc37128ab59ce88118397890`
- Snapshot SHA-256: `d1c3f958bb100dd931fbc0efd3482319bd47098305c8d255f94b73dbce4e844d`
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
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:4e4ea601fb75a7a6` | `flowbuffer_functions.cc:85` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:1d977ab6190e1549` | `flowbuffer_functions.cc:87` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:07b35b54f518b6b9` | `flowbuffer_functions.cc:96` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:e5c4a9ca253f14f3` | `flowbuffer_functions.cc:98` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:5258dfd42b1c4766` | `flowbuffer_functions.cc:116` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:a82fc62500604670` | `flowbuffer_functions.cc:118` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:dbdc086241adadf4` | `flowbuffer_functions.cc:126` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:c26d4de68cbf8373` | `flowbuffer_functions.cc:127` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:aafd31acab0df2ce` | `flowbuffer_functions.cc:131` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:ebe58ff788212238` | `flowbuffer_functions.cc:133` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:b19b7a32b422c257` | `flowbuffer_functions.cc:140` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:3d2fda6b6ffbc924` | `flowbuffer_functions.cc:142` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:f8f40ffedd5159c9` | `renamed.cpp:3` | `ohcpp-memory-bounds-vector-index-candidate-005` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

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
- Plan SHA-256: `9aafb79dbb0c48139aaa46b1824cab0d287cf8d9002a3319e3ae40d6ff542dde`
- Language matching plans attempts; actual coverage remains in the results above.
