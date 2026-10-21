# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `a39d1aa9d56a743ac4a366b573cec8508feacb62e3d5cb53ed6397541725df48`
- Source files indexed: 234
- Parsing coverage: `{"complete": 106, "partial": 128}`
- Detector runs: 2
- Total unverified diagnostics: 6
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | blocked | 106 | 105 | 1 | 128 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | completed | 106 | 106 | 0 | 128 | 6 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e0988e36b1d1ed76` | `wm/include/picture_in_picture_controller.h:50` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c9dbb305ed1d5069` | `wm/include/picture_in_picture_controller.h:54` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:19908386bd67b661` | `wm/include/picture_in_picture_controller_ani.h:53` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9f58e49e5f26499d` | `wm/include/picture_in_picture_controller_ani.h:57` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c54ae7bc61f63923` | `wm/include/picture_in_picture_controller_base.h:141` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:393d246c582a31b2` | `wm/include/picture_in_picture_controller_base.h:145` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.lifetime`: partial, 105/234 applicable files examined; unexamined=129
- `ohscanner.cpp.shared_ptr_race`: partial, 106/234 applicable files examined; unexamined=128

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.lifetime`: Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.
- `ohscanner.cpp.lifetime`: Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.
- `ohscanner.cpp.lifetime`: Empty findings are not proof of safety and are never benchmark misses.
- `ohscanner.cpp.lifetime`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.lifetime`: Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.
- `ohscanner.cpp.lifetime`: Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.
- `ohscanner.cpp.lifetime`: Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.
- `ohscanner.cpp.lifetime`: wm/src/gtx_input_event_sender.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: wm/src/gtx_input_event_sender.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 128 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/extension_window_impl.h: wm/include/extension_window_impl.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/float_view_interface.h: wm/include/float_view_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/float_view_manager.h: wm/include/float_view_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/float_view_model.h: wm/include/float_view_model.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/floating_ball_interface.h: wm/include/floating_ball_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/floating_ball_manager.h: wm/include/floating_ball_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/future_callback.h: wm/include/future_callback.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/lifecycle_future_callback.h: wm/include/lifecycle_future_callback.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/native_pip_window_listener.h: wm/include/native_pip_window_listener.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/pattern_detach_callback.h: wm/include/pattern_detach_callback.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/picture_in_picture_controller.h: pairwise analysis of 'wm/include/picture_in_picture_controller.h::OHOS::PictureInPictureController::mainWindowXComponentController_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: wm/include/picture_in_picture_controller_ani.h: pairwise analysis of 'wm/include/picture_in_picture_controller_ani.h::OHOS::PictureInPictureControllerAni::mainWindowXComponentController_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: wm/include/picture_in_picture_controller_base.h: pairwise analysis of 'wm/include/picture_in_picture_controller_base.h::OHOS::PictureInPictureControllerBase::pipXComponentController_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: wm/include/picture_in_picture_interface.h: wm/include/picture_in_picture_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/picture_in_picture_option_ani.h: wm/include/picture_in_picture_option_ani.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/ressched_report.h: wm/include/ressched_report.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/ui_extension/provider_data_handler.h: wm/include/ui_extension/provider_data_handler.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/window_display_change_adapter.h: wm/include/window_display_change_adapter.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/window_inspector.h: wm/include/window_inspector.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/window_manager_agent.h: wm/include/window_manager_agent.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/window_manager_agent_lite.h: wm/include/window_manager_agent_lite.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/window_prepare_terminate.h: wm/include/window_prepare_terminate.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/get_snapshot_callback_stub.h: wm/include/zidl/get_snapshot_callback_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/pattern_detach_callback_proxy.h: wm/include/zidl/pattern_detach_callback_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/pattern_detach_callback_stub.h: wm/include/zidl/pattern_detach_callback_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/window_manager_agent_proxy.h: wm/include/zidl/window_manager_agent_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/window_manager_agent_stub.h: wm/include/zidl/window_manager_agent_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/include/zidl/window_stub.h: wm/include/zidl/window_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/all_users_window_manager.cpp: wm/src/all_users_window_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/all_users_window_manager_lite.cpp: wm/src/all_users_window_manager_lite.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/extension_window.cpp: wm/src/extension_window.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/extension_window_impl.cpp: wm/src/extension_window_impl.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/float_view_manager.cpp: wm/src/float_view_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/floating_ball_manager.cpp: wm/src/floating_ball_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/future_callback.cpp: wm/src/future_callback.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/lifecycle_future_callback.cpp: wm/src/lifecycle_future_callback.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/oh_window_event_filter.cpp: wm/src/oh_window_event_filter.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/oh_window_pip.cpp: wm/src/oh_window_pip.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/pattern_detach_callback.cpp: wm/src/pattern_detach_callback.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/picture_in_picture_controller_base.cpp: wm/src/picture_in_picture_controller_base.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/picture_in_picture_option_ani.cpp: wm/src/picture_in_picture_option_ani.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/ui_extension/provider_data_handler.cpp: wm/src/ui_extension/provider_data_handler.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/web_picture_in_picture_controller_interface.cpp: wm/src/web_picture_in_picture_controller_interface.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/window_inspector.cpp: wm/src/window_inspector.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/window_manager_agent.cpp: wm/src/window_manager_agent.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/window_manager_agent_lite.cpp: wm/src/window_manager_agent_lite.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/window_option.cpp: wm/src/window_option.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/window_prepare_terminate.cpp: wm/src/window_prepare_terminate.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/zidl/pattern_detach_callback_proxy.cpp: wm/src/zidl/pattern_detach_callback_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/zidl/pattern_detach_callback_stub.cpp: wm/src/zidl/pattern_detach_callback_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/zidl/window_manager_agent_proxy.cpp: wm/src/zidl/window_manager_agent_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/src/zidl/window_manager_agent_stub.cpp: wm/src/zidl/window_manager_agent_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/test/mock/mock_data_handler.h: wm/test/mock/mock_data_handler.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/test/unittest/pattern/window_scene_session_impl_pattern_test.cpp: wm/test/unittest/pattern/window_scene_session_impl_pattern_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wm/test/unittest/ui_extension/provider_data_handler_test.cpp: wm/test/unittest/ui_extension/provider_data_handler_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 128 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `d312280b489f7a03fa6ff7a0aeb30f5b533862184235c5218276543d4c12a54f`
- Language matching plans attempts; actual coverage remains in the results above.
