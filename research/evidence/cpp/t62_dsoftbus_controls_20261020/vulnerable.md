# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/communication_dsoftbus`
- Pinned commit: `258662cd9840b55a31546a72d91027f6368cea84`
- Git tree: `366a4ced9400653c9628c0b677e4ae657c0e7bd8`
- Snapshot SHA-256: `25102a7c1fde5d072f082828ed60bbc586309724014d42d6df042845a977b8db`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 5
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.null_dereference` | blocked | 1 | 0 | 1 | 0 | 5 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:4f098613beea8c48` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:71` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:21444af94d04b671` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:82` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:426dc69869a63142` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:97` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:d8e462815217d8b7` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:108` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:63a48ed4f78b7b99` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:123` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.null_dereference`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.null_dereference`: Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.
- `ohscanner.cpp.null_dereference`: unknown_reason: guard_dominance_unknown_without_compile_context
- `ohscanner.cpp.null_dereference`: Zero findings under this bounded rule are not a safe verdict.
- `ohscanner.cpp.null_dereference`: Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.null_dereference`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `5190351326ef00ef62be4f031510dd4ee0cd1efdbfba86dcbe2b3ad57932b609`
- Language matching plans attempts; actual coverage remains in the results above.
