# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/multimedia_player_framework`
- Pinned commit: `71ab1e0881e0a79f2b9528742677467e7bb8dde5`
- Git tree: `9cc6c53506a70424485885c4c10b29dfbfaa8d1b`
- Snapshot SHA-256: `4d5a45d61644f0b98f1666e27ff17f0055c3fb73e1a41504751007a6791f28f8`
- Source files indexed: 22
- Parsing coverage: `{"complete": 6, "partial": 16}`
- Detector runs: 1
- Total unverified diagnostics: 24
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.interface.ipc` | completed | 22 | 6 | 16 | 0 | 24 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:69862a19b285f208` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:55` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:0a18d344f489fdb7` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:69` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:f4a4d04093c25644` | `services/services/avmetadatahelper/ipc/helper_listener_stub.cpp:75` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:43e8a27f1a7e651f` | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp:48` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:8ceef15520c9e709` | `services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp:59` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:e0c83313013ccb3a` | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp:48` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:1a9ffa86a5eac23f` | `services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp:59` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:2e6de3ec8ffac2ad` | `services/services/media_source/ipc/media_source_loader_stub.cpp:61` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:102652a18e89ee97` | `services/services/media_source/ipc/media_source_loader_stub.cpp:75` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:0e0126085ac28c6a` | `services/services/media_source/ipc/media_source_loader_stub.cpp:82` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:3424715ce64ebb61` | `services/services/media_source/ipc/media_source_loader_stub.cpp:86` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:c373dccca3e20e34` | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp:46` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:fc5957497aa904dc` | `services/services/pcm_output/ipc/pcm_output_callback_stub.cpp:56` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:e7bc1e6ffa196304` | `services/services/player/ipc/player_listener_stub.cpp:50` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:2554eaead15d2b8f` | `services/services/player/ipc/player_listener_stub.cpp:61` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:21b90abae1437824` | `services/services/player/ipc/player_listener_stub.cpp:67` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:fcbf595a7d61885c` | `services/services/player/ipc/player_listener_stub.cpp:124` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:59ec084f0a008f99` | `services/services/player/ipc/player_service_stub.cpp:376` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:08c6ca5648a924bf` | `services/services/recorder/ipc/recorder_service_stub.cpp:215` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:4234f4766d6495bb` | `services/services/recorder/ipc/recorder_service_stub.cpp:218` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:c19cba72a935afd6` | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp:92` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:fe6d4c1e8570773c` | `services/services/transcoder/ipc/transcoder_listener_stub.cpp:47` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:7c9a7ed28819d20d` | `services/services/transcoder/ipc/transcoder_listener_stub.cpp:53` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:81789eae6b5ac2b7` | `services/services/transcoder/ipc/transcoder_service_stub.cpp:128` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown; parse_completeness_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.interface.ipc`: partial, 6/22 applicable files examined; unexamined=16

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
- `ohscanner.interface.ipc`: Entry/dispatch coverage: 11 dispatcher(s) (11 in stub classes, 1 with a recognizable guard before dispatch), 171 binding(s) by grade {'source_dispatch': 152, 'source_dispatch_case_call': 18, 'unresolved_handler': 1}, transactions {'dynamic': 170, 'unresolved': 1}, unresolved dispatch {'map_found_but_never_dispatched': 1}, 0 binding(s) under a preprocessor condition. A binding is not reachability; a refused binding is unknown, not safe.
- `ohscanner.interface.ipc`: Loops are conservatively explored zero/one iterations; no induction or termination proof.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/avmetadatahelper/ipc/helper_listener_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/player/ipc/player_listener_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/services/transcoder/ipc/transcoder_service_stub.h
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/avmetadatahelper/ipc/helper_listener_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/media_source/ipc/media_source_loader_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/player/ipc/player_listener_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/player/ipc/player_service_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/recorder/ipc/recorder_service_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/transcoder/ipc/transcoder_listener_stub.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: services/services/transcoder/ipc/transcoder_service_stub.cpp
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: HelperListenerStub::OnInfo
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: HelperListenerStub::OnPixelComplete
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: LppAudioStreamerListenerStub::OnError
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: LppAudioStreamerListenerStub::OnInfo
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: LppVideoStreamerListenerStub::OnError
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: LppVideoStreamerListenerStub::OnInfo
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PCMOutputCallbackStub::OnPCMOutput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PCMOutputCallbackStub::OnPCMProcessor
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PlayerListenerStub::OnInfo
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PlayerListenerStub::OnMonitor
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: RecorderServiceStub::CheckPermission
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: TransCoderListenerStub::OnError
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: TransCoderListenerStub::OnInfo
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `5eb074b59d66cc92a9b2591b4a4e7d51725009a2e63887f882aabd244dbcab7b`
- Language matching plans attempts; actual coverage remains in the results above.
