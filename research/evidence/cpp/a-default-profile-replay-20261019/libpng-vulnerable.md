# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `pnggroup/libpng`
- Pinned commit: `afad740f043acd9bee412677d0a5ff1e046aaa24`
- Git tree: `5d18312a3b10c4aa1a488b91ac41d010606640ef`
- Snapshot SHA-256: `f80ae78bc09612fd5b8c5a925f858b41e15711319d0a794cafeb4764f7ec73d9`
- Source files indexed: 4
- Parsing coverage: `{"partial": 4}`
- Detector runs: 8
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 0 | 0 | 0 | 4 | 0 | blocked |
| `ohscanner.cpp.integer_bounds` | blocked | 4 | 0 | 4 | 0 | 0 | partial |
| `ohscanner.cpp.lifetime` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.resource_lifetime` | blocked | 4 | 0 | 4 | 0 | 2 | partial |
| `ohscanner.cpp.shared_ptr_race` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.unsafe_memory_call` | blocked | 0 | 0 | 0 | 4 | 0 | blocked |
| `ohscanner.interface.ipc` | completed | 4 | 0 | 4 | 0 | 0 | partial |
| `ohscanner.oh.arkts_js` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0f4a7c238e4ca5ff` | `pngrtran.c:1187` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0a2fa5fe1ecec1bd` | `pngrtran.c:1228` | `ohcpp-resource-lifetime-cross-member-alias-uaf-candidate-003` | allocation_release_alias_state=unknown; control_flow_dominance=unknown; cross_function_and_container_transfer=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: blocked, 0/4 applicable files examined; unexamined=4
- `ohscanner.cpp.integer_bounds`: partial, 0/4 applicable files examined; unexamined=4
- `ohscanner.cpp.lifetime`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.resource_lifetime`: partial, 0/4 applicable files examined; unexamined=4
- `ohscanner.cpp.shared_ptr_race`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.unsafe_memory_call`: blocked, 0/4 applicable files examined; unexamined=4
- `ohscanner.interface.ipc`: partial, 0/4 applicable files examined; unexamined=4
- `ohscanner.oh.arkts_js`: not_applicable, 0/0 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: png.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: pngread.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: pngrtran.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: pngset.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: png.c: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: pngread.c: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: pngrtran.c: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: pngset.c: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.integer_bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.lifetime`: not_applicable: no source with supported language.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: png.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngread.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngrtran.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngset.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.shared_ptr_race`: not_applicable: no source with supported language.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.unsafe_memory_call`: png.c: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: pngread.c: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: pngrtran.c: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: pngset.c: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.unsafe_memory_call`: Coverage incomplete or unsupported; do not infer safety.
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
- `ohscanner.interface.ipc`: Macro expansion: 0 invocation(s) expanded in 0 file(s), 0 of them carrying control flow; 3 file(s) left unexpanded (source_local_undef_not_supported=3). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in png.c
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in pngread.c
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in pngrtran.c
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in pngset.c
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.oh.arkts_js`: not_applicable: no source with supported language.
- `ohscanner.oh.arkts_js`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.oh.arkts_js`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.oh.arkts_js`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.oh.arkts_js`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `5d9d83ffee8321d2bba2c85e17496f3e09982a531ee8378029423a5a94c95350`
- Language matching plans attempts; actual coverage remains in the results above.
