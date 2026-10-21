# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/miscservices_pasteboard`
- Pinned commit: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`
- Git tree: `e374a0d61c9ec664ddd29fc17002797828c480ee`
- Snapshot SHA-256: `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`
- Source files indexed: 68
- Parsing coverage: `{"complete": 59, "not_run": 1, "partial": 8}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.interface.ipc` | completed | 67 | 59 | 8 | 0 | 2 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:5b54938c4ec4d184` | `services/zidl/src/pasteboard_service_stub.cpp:77` | `ipc.auth.missing` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; dispatch_binding=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:0fc129db7dc16ae6` | `services/zidl/src/pasteboard_service_stub.cpp:107` | `ipc.auth.missing` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; dispatch_binding=unknown; consequence=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 1
- `interfaces/declaration/api/@ohos.pasteboard.d.ts`
- `ohscanner.interface.ipc`: partial, 59/67 applicable files examined; unexamined=8

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v32; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: IPC roots require a source-indexed class dispatcher with code, request Parcel and reply Parcel; explicit service/transport roots and Stub inner helpers are separate allowlisted entry kinds. Test/fuzz/mock path roots are excluded from product candidate analysis and counted in limitations. Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Cross-service boundary coverage: 0 call(s) on a handle built by iface_cast<> in the scanned sources, 0 carrying the original caller's identity (SetCallingIdentity with a calling-token value active), 0 executing as the service. Each boundary is recorded with the identity that crossed it; no candidate is emitted from the boundary itself, and a downstream service's own guards are not read from this corpus.
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 2 dispatcher(s) (2 in stub classes, 0 with a recognizable guard before dispatch), 16 binding(s) by grade {'source_dispatch': 16}, transactions {'dynamic': 16}, unresolved dispatch {}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Macro expansion: 0 invocation(s) expanded in 0 file(s), 0 of them carrying control flow; 0 file(s) left unexpanded (variadic_stringify_or_token_paste=363). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: One-hop callee is not unique (3 definitions) for PasteboardObserverStub::OnPasteboardChanged; the callee body was not read. The call site therefore stays a candidate.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in interfaces/kits/napi/src/napi_init.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/core/include/i_pasteboard_observer.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/core/include/i_pasteboard_service.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/core/include/pasteboard_service.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/core/src/pasteboard_storage.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/test/unittest/src/paste_service_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/zidl/include/pasteboard_observer_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/zidl/include/pasteboard_service_stub.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/zidl/src/pasteboard_observer_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/zidl/src/pasteboard_service_stub.cpp
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
