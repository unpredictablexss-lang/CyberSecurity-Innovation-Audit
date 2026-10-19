# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `local/d48-d43-positive-control`
- Pinned commit: `052f5c0acf5654204b3512d470ee5f4f278d5b69`
- Git tree: `b439c20314be3f8cd3a0d2c0eaa2fbfa42feef6e`
- Snapshot SHA-256: `ceeded7747ef8d7bb5e7f6e306ab0b4168376c1e35bbb6d0b6e9ffc994e4cbe2`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 9
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.integer_bounds` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.lifetime` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.resource_lifetime` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.shared_ptr_race` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.unsafe_memory_call` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.data.sensitive_exposure` | blocked | 1 | 0 | 1 | 0 | 1 | partial |
| `ohscanner.interface.ipc` | completed | 1 | 1 | 0 | 0 | 0 | complete |
| `ohscanner.oh.arkts_js` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.data.sensitive_exposure` | `ohscanner.data.sensitive_exposure:309e65ccec54d8e5` | `fixture.cpp:1` | `data.log.sensitive-value` | local_flow=unknown; source_semantics=unknown; type_identity=unknown; sink_privacy=unknown; runtime_log_visibility=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.integer_bounds`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.lifetime`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.resource_lifetime`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.shared_ptr_race`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.cpp.unsafe_memory_call`: complete, 1/1 applicable files examined; unexamined=0
- `ohscanner.data.sensitive_exposure`: partial, 0/1 applicable files examined; unexamined=1
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
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: fixture.cpp: fixture.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.unsafe_memory_call`: Absence of a finding is not a safe verdict.
- `ohscanner.cpp.unsafe_memory_call`: Candidate only: lexical unsafe-call recognition does not prove exploitability.
- `ohscanner.cpp.unsafe_memory_call`: Wrappers, macros, varargs, destination aliases, compile context and attacker control remain unknown.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.data.sensitive_exposure`: Candidate only: runtime log readers, production enablement and impact require independent review.
- `ohscanner.data.sensitive_exposure`: Detailed private Tree-sitter statements pending owner-approved shared expression facts; no new global frontend.
- `ohscanner.data.sensitive_exposure`: Function-local syntax dependencies, not CFG/alias/full-program proof; no secret values recorded.
- `ohscanner.data.sensitive_exposure`: Model scope is exact repository/commit; receiver/typedef identity and include binding remain obligations.
- `ohscanner.data.sensitive_exposure`: No reviewed sensitive-source model for this repository/commit; heuristic candidates are incomplete and the scan is blocked.
- `ohscanner.data.sensitive_exposure`: Private/default-private sensitive operands retained as conditional candidates; runtime privacy configuration and reader exposure remain obligations.
- `ohscanner.data.sensitive_exposure`: Unsupported control-flow subtrees are scanned for may-flow call effects; branch feasibility remains unresolved.
- `ohscanner.data.sensitive_exposure`: fixture.cpp: private operand requires runtime privacy-configuration review; conditional candidate retained
- `ohscanner.data.sensitive_exposure`: fixture.cpp: unreviewed sensitive-name heuristic source; semantics unknown
- `ohscanner.data.sensitive_exposure`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.data.sensitive_exposure`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.data.sensitive_exposure`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.data.sensitive_exposure`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.data.sensitive_exposure`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v12; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: FD backing rule skipped: MessageParcelWarp::ReadRawData body is absent or ambiguous.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: Entry roots come from the name allowlist plus source-derived dispatch bindings (function-pointer tables, switch/if code dispatch, and source-declared virtual overrides). Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 0 dispatcher(s) (0 in stub classes, 0 with a recognizable guard before dispatch), 0 binding(s) by grade {}, transactions {}, unresolved dispatch {}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
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
- Plan SHA-256: `d958aa031e1721fbfef17c367abfb63aa92db95452a0ad70e625f4028842621e`
- Language matching plans attempts; actual coverage remains in the results above.
