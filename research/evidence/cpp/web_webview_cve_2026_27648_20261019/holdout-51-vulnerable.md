# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `OpenHarmony-TPC/chromium_src`
- Pinned commit: `17859babfa4450c9921a54918865907ed545482a`
- Git tree: `266ca9ca7f3705478afecb41b8156ff5c2d05cba`
- Snapshot SHA-256: `0ac9e96585564a63874630aa76b053e9fe1535831e7fcf83f9b97e9c9440fd71`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 12
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | completed | 1 | 1 | 0 | 0 | 12 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:70fce2d8e55ce6c3` | `flowbuf_functions.cc:78` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:fba8dc213f95e328` | `flowbuf_functions.cc:79` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:0518752ebae010f7` | `flowbuf_functions.cc:88` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:3fffbf3b3fb174d7` | `flowbuf_functions.cc:89` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:4dab437430e2d539` | `flowbuf_functions.cc:107` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:368817b7e101cc0a` | `flowbuf_functions.cc:108` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:f157e719dfeefde2` | `flowbuf_functions.cc:116` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:a8064115953eaa01` | `flowbuf_functions.cc:117` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:a663a14dd3b4c7f7` | `flowbuf_functions.cc:121` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:86a0391a42c3a227` | `flowbuf_functions.cc:122` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:4b92d6762f873ac2` | `flowbuf_functions.cc:129` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:53f77a63361854e7` | `flowbuf_functions.cc:130` | `ohcpp-memory-bounds-vector-index-candidate-004` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

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
- `ohscanner.cpp.bounds`: Only direct one-hop copy wrappers are summarized; deeper wrappers, function pointers, aliases, macros, templates and full C++ CFG semantics remain unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `6d839528ba43587b78a79e5b3f4489832e8bc2b950824db192247454903c5b96`
- Language matching plans attempts; actual coverage remains in the results above.
