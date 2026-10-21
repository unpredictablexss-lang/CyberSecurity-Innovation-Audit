# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/communication_dsoftbus`
- Pinned commit: `9f922677e147b939d6db899bde181d609d64711b`
- Git tree: `4b114179868d96c69eedc4520037552ddc3d65dd`
- Snapshot SHA-256: `dbb4af85b71dd60e987cc91a77d183be02a6fb037117554ab75670e3c0b1c23c`
- Source files indexed: 3
- Parsing coverage: `{"complete": 2, "partial": 1}`
- Detector runs: 11
- Total unverified diagnostics: 30
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 2 | 0 | 2 | 1 | 0 | partial |
| `ohscanner.cpp.integer_bounds` | blocked | 3 | 0 | 3 | 0 | 0 | partial |
| `ohscanner.cpp.lifetime` | completed | 2 | 2 | 0 | 1 | 0 | partial |
| `ohscanner.cpp.null_dereference` | blocked | 3 | 1 | 2 | 0 | 30 | partial |
| `ohscanner.cpp.resource_lifetime` | blocked | 2 | 0 | 2 | 1 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | completed | 2 | 2 | 0 | 1 | 0 | partial |
| `ohscanner.cpp.unsafe_memory_call` | blocked | 3 | 2 | 1 | 0 | 0 | partial |
| `ohscanner.data.sensitive_exposure` | blocked | 2 | 0 | 2 | 1 | 0 | partial |
| `ohscanner.interface.ipc` | completed | 3 | 2 | 1 | 0 | 0 | partial |
| `ohscanner.known_disclosed_cves` | blocked | 3 | 0 | 3 | 0 | 0 | partial |
| `ohscanner.oh.arkts_js` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:13ed896248409944` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:288` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:6a3d17c927d481c3` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:293` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:f0844f05b0b5ae12` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:303` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:5b22d7c8849713fe` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:308` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:dbe933d09385253b` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:318` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:6dcd5c217156b27d` | `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:323` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:c3a41a1517c9e3bb` | `core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp:658` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:afeec0b32f0b63ca` | `core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp:659` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:46c6cb7115be4709` | `core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp:891` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:f51cffe9ad65409c` | `core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp:895` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:2d7257237b3fb015` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:189` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:43fa60856c4ecc9a` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:519` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:de8289206647bc4e` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:524` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:27da96f705a3c94f` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:525` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:25b5dbd90d27815c` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:558` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:afab2ba82c3f3ae8` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:560` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:f07e6c21143cf3ad` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:562` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:a8166cde7164a66c` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:571` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:4ab433f5496bd5c8` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1093` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:b6e17caaa417fc9f` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1097` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:27c17031a9235953` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1109` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:9c80884006fb9b1d` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1110` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:fbab8d7651844ac5` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1122` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:dcf98cd9d1951316` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1123` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:8400786dd75d1f0c` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1143` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:cab55c09c7526aef` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1144` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:c0ce23969a7c7bff` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1150` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:ca99fb1a5b121d55` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1151` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:f0248fb4007c0e51` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1170` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:10543faf7a326333` | `core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp:1171` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.cpp.integer_bounds`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.cpp.lifetime`: partial, 2/3 applicable files examined; unexamined=1
- `ohscanner.cpp.null_dereference`: partial, 1/3 applicable files examined; unexamined=2
- `ohscanner.cpp.resource_lifetime`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.cpp.shared_ptr_race`: partial, 2/3 applicable files examined; unexamined=1
- `ohscanner.cpp.unsafe_memory_call`: partial, 2/3 applicable files examined; unexamined=1
- `ohscanner.data.sensitive_exposure`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.interface.ipc`: partial, 2/3 applicable files examined; unexamined=1
- `ohscanner.known_disclosed_cves`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.oh.arkts_js`: not_applicable, 0/0 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.integer_bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.lifetime`: Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.
- `ohscanner.cpp.lifetime`: Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.
- `ohscanner.cpp.lifetime`: Empty findings are not proof of safety and are never benchmark misses.
- `ohscanner.cpp.lifetime`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.lifetime`: Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.
- `ohscanner.cpp.lifetime`: Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.
- `ohscanner.cpp.lifetime`: Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 1 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.null_dereference`: Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.
- `ohscanner.cpp.null_dereference`: unknown_reason: guard_dominance_unknown_without_compile_context
- `ohscanner.cpp.null_dereference`: unknown_reason: destructor_order_unknown
- `ohscanner.cpp.null_dereference`: unknown_reason: cross_function_alias
- `ohscanner.cpp.null_dereference`: unknown_reason: unresolved_function_return_nullability
- `ohscanner.cpp.null_dereference`: unknown_reason: function_return_nullability_unknown
- `ohscanner.cpp.null_dereference`: unknown_reason: parse_status_partial
- `ohscanner.cpp.null_dereference`: Zero findings under this bounded rule are not a safe verdict.
- `ohscanner.cpp.null_dereference`: Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.null_dereference`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp: core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 1 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.unsafe_memory_call`: Absence of a finding is not a safe verdict.
- `ohscanner.cpp.unsafe_memory_call`: Candidate only: lexical unsafe-call recognition does not prove exploitability.
- `ohscanner.cpp.unsafe_memory_call`: Wrappers, macros, varargs, destination aliases, compile context and attacker control remain unknown.
- `ohscanner.cpp.unsafe_memory_call`: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.unsafe_memory_call`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.unsafe_memory_call`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.data.sensitive_exposure`: Candidate only: runtime log readers, production enablement and impact require independent review.
- `ohscanner.data.sensitive_exposure`: Detailed private Tree-sitter statements pending owner-approved shared expression facts; no new global frontend.
- `ohscanner.data.sensitive_exposure`: Function-local syntax dependencies, not CFG/alias/full-program proof; no secret values recorded.
- `ohscanner.data.sensitive_exposure`: Model scope is exact repository/commit; receiver/typedef identity and include binding remain obligations.
- `ohscanner.data.sensitive_exposure`: Private/default-private sensitive operands retained as conditional candidates; runtime privacy configuration and reader exposure remain obligations.
- `ohscanner.data.sensitive_exposure`: Unsupported control-flow subtrees are scanned for may-flow call effects; branch feasibility remains unresolved.
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: bounded same-file helper expansion; compiler type identity remains unknown
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: branch merge is may-flow; no path feasibility proof
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: preprocessor/build context not expanded
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: short-circuit effects are may-flow; no path feasibility proof
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 105; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 120; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 135; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 156; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 71; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp: unsupported statement for_range_loop at line 86; nested call effects inspected as may-flow
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp: branch merge is may-flow; no path feasibility proof
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp: preprocessor/build context not expanded
- `ohscanner.data.sensitive_exposure`: core/bus_center/ipc/standard/src/bus_center_client_proxy_standard.cpp: short-circuit effects are may-flow; no path feasibility proof
- `ohscanner.data.sensitive_exposure`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.data.sensitive_exposure`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.data.sensitive_exposure`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.data.sensitive_exposure`: INCOMPLETE COVERAGE: 1 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.data.sensitive_exposure`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.data.sensitive_exposure`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v32; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: IPC roots require a source-indexed class dispatcher with code, request Parcel and reply Parcel; explicit service/transport roots and Stub inner helpers are separate allowlisted entry kinds. Test/fuzz/mock path roots are excluded from product candidate analysis and counted in limitations. Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 0 dispatcher(s) (0 in stub classes, 0 with a recognizable guard before dispatch), 0 binding(s) by grade {}, transactions {}, unresolved dispatch {}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.known_disclosed_cves`: core/bus_center/ipc/standard/src/lnn_bus_center_ipc.cpp: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.known_disclosed_cves`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.oh.arkts_js`: not_applicable: no source with supported language.
- `ohscanner.oh.arkts_js`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.oh.arkts_js`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.oh.arkts_js`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.oh.arkts_js`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `8600d9c192ddaa6e2fbe78562aeca2bae2887847a64f8400e05dfd65b2f04ccc`
- Language matching plans attempts; actual coverage remains in the results above.
