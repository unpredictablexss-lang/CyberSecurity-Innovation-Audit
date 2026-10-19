# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/systemabilitymgr_samgr`
- Pinned commit: `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`
- Git tree: `b7a89e95be788f2f2372258e341f7be842c7826d`
- Snapshot SHA-256: `5c9865cdc8290f75825679a4c334ed2fdc40cb074539462573760cad7a01beec`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 10
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.interface.ipc` | completed | 1 | 0 | 1 | 0 | 10 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:b360d1d29c25e580` | `services/samgr/native/source/system_ability_manager_stub.cpp:298` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:6136103fc662c4a6` | `services/samgr/native/source/system_ability_manager_stub.cpp:302` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:2af8fbf91642cbbf` | `services/samgr/native/source/system_ability_manager_stub.cpp:464` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:e6305216fc6e7a94` | `services/samgr/native/source/system_ability_manager_stub.cpp:551` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:b810e0670174d80e` | `services/samgr/native/source/system_ability_manager_stub.cpp:668` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:c50c9e08852ab64f` | `services/samgr/native/source/system_ability_manager_stub.cpp:706` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:d21108b21819c7b8` | `services/samgr/native/source/system_ability_manager_stub.cpp:1485` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:cfca2b2cdef00a5b` | `services/samgr/native/source/system_ability_manager_stub.cpp:1692` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:2ffa938ee632d9d4` | `services/samgr/native/source/system_ability_manager_stub.cpp:1735` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:5f76290f7adec957` | `services/samgr/native/source/system_ability_manager_stub.cpp:1784` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.interface.ipc`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v32; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: IPC roots require a source-indexed class dispatcher with code, request Parcel and reply Parcel; explicit service/transport roots and Stub inner helpers are separate allowlisted entry kinds. Test/fuzz/mock path roots are excluded from product candidate analysis and counted in limitations. Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 1 dispatcher(s) (0 in stub classes, 0 with a recognizable guard before dispatch), 1 binding(s) by grade {'unresolved_handler': 1}, transactions {'unresolved': 1}, unresolved dispatch {'map_found_but_never_dispatched': 1}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Loops are conservatively explored zero/one iterations; no induction or termination proof.
- `ohscanner.interface.ipc`: Macro expansion: 0 invocation(s) expanded in 0 file(s), 0 of them carrying control flow; 0 file(s) left unexpanded (conditional_definition_requires_build_profile=5). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: Preprocessor conditional inside a function body: arms are explored as alternatives because the build variant is unknown. A guard written inside an arm is credited only on that arm's paths, the no-arm-taken path is kept when the chain has no #else, and facts proved before the conditional still hold in every arm.
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/samgr/native/source/system_ability_manager_stub.cpp
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: SystemAbilityManagerStub::LoadRemoteSACheck
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: SystemAbilityManagerStub::LoadSACheck
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: SystemAbilityManagerStub::SetIpcPrior
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: SystemAbilityManagerStub::UnmarshalingSaExtraProp
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `c60b1f12b3da99d216acd9cf0807b75eb8295960d263d95efbf70adcd320e453`
- Language matching plans attempts; actual coverage remains in the results above.
