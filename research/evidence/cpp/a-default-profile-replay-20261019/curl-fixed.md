# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `curl/curl`
- Pinned commit: `d7546809d5bd548b69ec49fca26565c8f6f0d344`
- Git tree: `52a8416729366487cdd3b6012071f5f8370e769f`
- Snapshot SHA-256: `cbc4bf484c7dacefd8869f7917b00983569e8d012470e88f278fc6104744c2f6`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 8
- Total unverified diagnostics: 15
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | completed | 1 | 1 | 0 | 0 | 13 | complete |
| `ohscanner.cpp.integer_bounds` | completed | 1 | 1 | 0 | 0 | 2 | complete |
| `ohscanner.cpp.lifetime` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.resource_lifetime` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.shared_ptr_race` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.unsafe_memory_call` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.interface.ipc` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.oh.arkts_js` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:1bd9a1bb4138aca2` | `lib/mime.c:306` | `ohcpp-memory-bounds-copy-candidate-001` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:155a4ccdd925f4e9` | `lib/mime.c:333` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:224f84e6d925b0cc` | `lib/mime.c:377` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:060effbffee8d855` | `lib/mime.c:378` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:a2560d6a105b771f` | `lib/mime.c:379` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:4847c091d1c4d0d9` | `lib/mime.c:404` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:e3db19967b6c9d36` | `lib/mime.c:406` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:001690f58f754340` | `lib/mime.c:457` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:7b0fa55d30f84490` | `lib/mime.c:458` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:850e85901f90f967` | `lib/mime.c:480` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:063badf54888b1fc` | `lib/mime.c:485` | `ohcpp-memory-bounds-index-candidate-002` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:affa4721152dfe8b` | `lib/mime.c:588` | `ohcpp-memory-bounds-copy-candidate-001` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.bounds` | `ohscanner.cpp.bounds:4b891162e2db4933` | `lib/mime.c:696` | `ohcpp-memory-bounds-copy-candidate-001` | capacity_and_alias_identity=unknown; guard_dominance=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.integer_bounds` | `ohscanner.cpp.integer_bounds:8167afcf85ad663e` | `lib/mime.c:682` | `ohcpp-integer-bounds-arithmetic-candidate-001` | integer_range_and_signedness=unknown; overflow_guard_dominance=unknown; allocation_or_memory_consequence=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; cia_impact=missing |
| `ohscanner.cpp.integer_bounds` | `ohscanner.cpp.integer_bounds:6d079213c3cf9221` | `lib/mime.c:686` | `ohcpp-integer-bounds-arithmetic-candidate-001` | integer_range_and_signedness=unknown; overflow_guard_dominance=unknown; allocation_or_memory_consequence=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.integer_bounds`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.lifetime`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.resource_lifetime`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.shared_ptr_race`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.unsafe_memory_call`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.interface.ipc`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.oh.arkts_js`: not_applicable, 0/0 applicable files examined; unexamined=0

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
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: not_applicable: no source with supported language.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: lib/mime.c:cleanup_part_content: unresolved allocation/release alias state remains unknown.
- `ohscanner.cpp.resource_lifetime`: lib/mime.c:curl_mime_free: unresolved allocation/release alias state remains unknown.
- `ohscanner.cpp.resource_lifetime`: lib/mime.c:mimesetstate: unresolved allocation/release alias state remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: not_applicable: no source with supported language.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.unsafe_memory_call`: Absence of a finding is not a safe verdict.
- `ohscanner.cpp.unsafe_memory_call`: Candidate only: lexical unsafe-call recognition does not prove exploitability.
- `ohscanner.cpp.unsafe_memory_call`: Wrappers, macros, varargs, destination aliases, compile context and attacker control remain unknown.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
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
- `ohscanner.interface.ipc`: Macro expansion: 0 invocation(s) expanded in 0 file(s), 0 of them carrying control flow; 0 file(s) left unexpanded (conditional_definition_requires_build_profile=139). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.oh.arkts_js`: not_applicable: no source with supported language.
- `ohscanner.oh.arkts_js`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.oh.arkts_js`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.oh.arkts_js`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.oh.arkts_js`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `58eb6b0b464b21e80db901b9f51fd1a3cf97717617c6683c1e03f90baea5901c`
- Language matching plans attempts; actual coverage remains in the results above.
