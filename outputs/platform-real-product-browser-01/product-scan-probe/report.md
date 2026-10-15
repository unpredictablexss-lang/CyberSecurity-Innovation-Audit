# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/inputmethod_imf`
- Pinned commit: `e663b47013d534a56165ab7467fbb3e14bf7172b`
- Git tree: `5037e995cb4f3f29d54307b6e0fbf352cc9d6252`
- Snapshot SHA-256: `4e713499a9f001324947a9073fc7f959d54cb0ea683e5271eaec0bf3d761b8fa`
- Source files indexed: 75
- Parsing coverage: `{"complete": 62, "not_run": 1, "partial": 12}`
- Detector runs: 1
- Total unverified diagnostics: 10
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.interface.ipc` | completed | 74 | 62 | 12 | 0 | 10 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:b82952e7df0067cc` | `frameworks/inputmethod_ability/src/input_method_core_stub.cpp:136` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:356ee7ee908ea090` | `frameworks/inputmethod_ability/src/input_method_core_stub.cpp:153` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:549e5068c8703ca5` | `frameworks/inputmethod_controller/src/input_client_stub.cpp:45` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:2c81bd289609837f` | `services/src/input_method_system_ability_stub.cpp:185` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:bd657a34455cbc88` | `services/src/input_method_system_ability_stub.cpp:186` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:0d80648a72eba189` | `services/src/input_method_system_ability_stub.cpp:206` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:a2dee5c97997f30d` | `services/src/input_method_system_ability_stub.cpp:225` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:0e3ea0d2c3d523e5` | `services/src/input_method_system_ability_stub.cpp:243` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:ecb14b704116cf72` | `services/src/input_method_system_ability_stub.cpp:262` | `ipc.capability.export` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |
| `ohscanner.interface.ipc` | `ohscanner.interface.ipc:c590c70a85c68412` | `services/src/platform_callback_stub.cpp:46` | `ipc.relay.descriptor-boundary` | entry_reachability=unknown; callee_and_policy=unknown; security_impact=unknown; consequence=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 1
- `interfaces/kits/js/declaration/api/@ohos.inputmethodengine.d.ts`
- `ohscanner.interface.ipc`: partial, 62/74 applicable files examined; unexamined=12

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.interface.ipc`: Model=oh-ipc-2026.10-v3; first-party bounded structured syntax interpretation, no external scanner execution.
- `ohscanner.interface.ipc`: Private branch pass reconstructs Tree-sitter nodes; public shared facts/schema are unchanged.
- `ohscanner.interface.ipc`: No compiler CFG, arbitrary virtual dispatch, alias analysis or full-program authorization proof. Macros are expanded only from the scan's own sources and only when unambiguous; the catalogue is never an #include resolution, and what the expander refused is counted in the macro-expansion limitation rather than assumed away.
- `ohscanner.interface.ipc`: Unmodeled callees/authorization remain evidence obligations; no findings does not establish safety.
- `ohscanner.interface.ipc`: Interface-descriptor identity is read from the class's own base clause: a comparison is counted as this transaction's guard only when the source names the interface the class implements. A comparison against another interface, or one whose identity the analysed sources do not state, is reported with that reason instead of counting as a guard or as a proven mismatch.
- `ohscanner.interface.ipc`: Descriptor consistency is separate from caller authorization; relay candidates are not exploit proofs.
- `ohscanner.interface.ipc`: Entry roots come from the name allowlist plus source-derived dispatch bindings (function-pointer tables, switch/if code dispatch, and source-declared virtual overrides). Entry discovery is not reachability: dispatcher-level guards and macro-conditional reachability remain obligations, not conclusions.
- `ohscanner.interface.ipc`: Entry-coverage measurements are published in the interface research report, not in this result.
- `ohscanner.interface.ipc`: Loops are conservatively explored zero/one iterations; no induction or termination proof.
- `ohscanner.interface.ipc`: Macro expansion: 3 invocation(s) expanded in 1 file(s), 0 of them carrying control flow; 0 file(s) left unexpanded (conditional_definition_requires_build_profile=2,variadic_stringify_or_token_paste=348). The catalogue is the scan's own sources, never #include; where a macro was expanded, quoted conditions come from the expanded form while a finding's line is mapped back to the original file.
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in frameworks/inputmethod_ability/include/i_input_method_agent.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in frameworks/inputmethod_ability/include/i_input_method_core.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in frameworks/inputmethod_controller/include/i_input_client.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in frameworks/inputmethod_controller/include/i_input_data_channel.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/global.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/i_input_control_channel.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/i_input_method_proxy.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/i_input_method_system_ability.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/i_platform_api.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in services/include/i_platform_callback.h
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in unitest/src/input_method_ability_test.cpp
- `ohscanner.interface.ipc`: Partial source: only error-free functions can be inspected in unitest/src/input_method_controller_test.cpp
- `ohscanner.interface.ipc`: Private syntax models format-string macros/unresolved member-pointer dispatch; original public parse status retained: frameworks/inputmethod_ability/src/event_target.cpp
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputControlChannelStub::hideKeyboardSelf
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputControlChannelStub::onAgentCreated
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputControlChannelStub::onKeyboardShowed
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputControlChannelStub::setDisplayMode
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputDataChannelStub::Close
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputDataChannelStub::DeleteBackward
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputDataChannelStub::InsertText
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodAgentStub::DispatchKey
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::getKeyboardWindowHeight
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::hideKeyboard
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::initializeInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::setKeyboardType
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::showKeyboard
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::startInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodCoreStub::stopInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbility::GetUserSession
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbility::GetUserSetting
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbilityStub::prepareInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbilityStub::releaseInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbilityStub::setInputMethodCoreFromHap
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbilityStub::startInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: InputMethodSystemAbilityStub::stopInput
- `ohscanner.interface.ipc`: Unresolved multi-outcome helper return: PlatformCallbackStub::notifyEvent
- `ohscanner.interface.ipc`: Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.
- `ohscanner.interface.ipc`: Unavailable AST units: 0; cross-file context from these units is unknown.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
