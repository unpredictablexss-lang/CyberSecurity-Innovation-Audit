# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/distributeddatamgr_data_share`
- Pinned commit: `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`
- Git tree: `f731230c116c94d7619f5514c828b33ffac69924`
- Snapshot SHA-256: `162723a8b65a7900a04b8fe6bf19ec862d19c83ff35bdbe3217f6797dd384122`
- Source files indexed: 5
- Parsing coverage: `{"complete": 4, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.interface.ipc` | completed | 5 | 4 | 1 | 0 | 1 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:ad8ff7e568ba904b` | `frameworks/native/proxy/src/data_proxy_observer_stub.cpp:222` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; descriptor_identity_mismatch=unknown; consequence=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.interface.ipc`: partial, 4/5 applicable files examined; unexamined=1

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
- `ohscanner.interface.ipc`: Call depth/recursion budget reached at RdbObserverStub::DeserializeDataFromAshmem
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 3 dispatcher(s) (3 in stub classes, 0 with a recognizable guard before dispatch), 0 binding(s) by grade {}, transactions {}, unresolved dispatch {}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in frameworks/native/proxy/include/data_proxy_observer.h
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: ProxyDataObserverStub::OnChangeFromProxyData
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PublishedDataObserverStub::OnChangeFromPublishedData
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: RdbObserverStub::OnChangeFromRdb
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: RdbObserverStub::RecoverRdbChangeNodeData
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `0085e1f384f6648592e4743cbf810772d91c914f60f3f5d7b9d1c9e0f9fa2b3f`
- Language matching plans attempts; actual coverage remains in the results above.
