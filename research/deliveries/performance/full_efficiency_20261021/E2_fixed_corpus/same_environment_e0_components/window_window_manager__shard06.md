# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `1559b69209eb0ab7a17609a9f351bc49b586e78bfbe74cda6b487d5c0d9645ca`
- Source files indexed: 181
- Parsing coverage: `{"complete": 105, "partial": 76}`
- Detector runs: 2
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | completed | 105 | 105 | 0 | 76 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | blocked | 105 | 104 | 1 | 76 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.lifetime`: partial, 105/181 applicable files examined; unexamined=76
- `ohscanner.cpp.shared_ptr_race`: partial, 104/181 applicable files examined; unexamined=77

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
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 76 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/include/display_manager_agent_default.h: dm/include/display_manager_agent_default.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/include/zidl/display_manager_agent_proxy.h: dm/include/zidl/display_manager_agent_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/include/zidl/display_manager_agent_stub.h: dm/include/zidl/display_manager_agent_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/src/display.cpp: not_applicable: global shared_ptr declaration 'g_eventHandler' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: dm/src/oh_display_manager_inner.h: dm/src/oh_display_manager_inner.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/src/screen.cpp: dm/src/screen.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/src/screen_group.cpp: dm/src/screen_group.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/src/zidl/display_manager_agent_proxy.cpp: dm/src/zidl/display_manager_agent_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm/src/zidl/display_manager_agent_stub.cpp: dm/src/zidl/display_manager_agent_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm_lite/src/display_lite.cpp: dm_lite/src/display_lite.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm_lite/src/display_manager_lite_proxy_idl.cpp: dm_lite/src/display_manager_lite_proxy_idl.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm_lite/test/unittest/mock/mock_message_parcel.cpp: dm_lite/test/unittest/mock/mock_message_parcel.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dm_lite/test/unittest/mock/mock_message_parcel.h: dm_lite/test/unittest/mock/mock_message_parcel.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/abstract_display.h: dmserver/include/abstract_display.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/display_cutout_controller.h: dmserver/include/display_cutout_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/display_dumper.h: dmserver/include/display_dumper.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/display_manager_config.h: dmserver/include/display_manager_config.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/display_manager_interface_code.h: dmserver/include/display_manager_interface_code.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/display_power_controller.h: dmserver/include/display_power_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/screen_rotation_controller.h: dmserver/include/screen_rotation_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/sensor_connector.h: dmserver/include/sensor_connector.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/include/sensor_plugin.h: dmserver/include/sensor_plugin.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/display_cutout_controller.cpp: dmserver/src/display_cutout_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/display_dumper.cpp: dmserver/src/display_dumper.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/display_manager_config.cpp: dmserver/src/display_manager_config.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/display_power_controller.cpp: dmserver/src/display_power_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/screen_rotation_controller.cpp: dmserver/src/screen_rotation_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/sensor_connector.cpp: dmserver/src/sensor_connector.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: dmserver/src/sensor_plugin.cpp: dmserver/src/sensor_plugin.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: edidparse/edidparse.cpp: edidparse/edidparse.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/extension_connection/include/zidl/window_extension_client_stub.h: extension/extension_connection/include/zidl/window_extension_client_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/extension_connection/src/window_extension_connection.cpp: extension/extension_connection/src/window_extension_connection.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/modal_system_ui_extension/src/modal_system_ui_extension.cpp: extension/modal_system_ui_extension/src/modal_system_ui_extension.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/include/window_extension_context.h: extension/window_extension/include/window_extension_context.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/include/window_extension_module_loader.h: extension/window_extension/include/window_extension_module_loader.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/include/zidl/window_extension_proxy.h: extension/window_extension/include/zidl/window_extension_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/include/zidl/window_extension_stub.h: extension/window_extension/include/zidl/window_extension_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/src/js_window_extension_context.cpp: not_applicable: global shared_ptr declaration 'handler_' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/src/window_extension_context.cpp: extension/window_extension/src/window_extension_context.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/src/window_extension_module_loader.cpp: extension/window_extension/src/window_extension_module_loader.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/src/zidl/window_extension_proxy.cpp: extension/window_extension/src/zidl/window_extension_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: extension/window_extension/src/zidl/window_extension_stub.cpp: extension/window_extension/src/zidl/window_extension_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/display.h: previewer/include/display.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/window_display.h: previewer/include/window_display.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::StartAnimationSystemOptions::animationConfig' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::WindowCreateParams::animationParams' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::WindowCreateParams::animationSystemParams' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::WindowCreateParams::excludeFromDock' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::WindowCreateParams::excludeFromRecent' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: modeled accesses to 'previewer/include/wm_animation_common.h::OHOS::WindowCreateParams::needAnimation' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'animationConfig' occurrence at line 229 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'animationParams' occurrence at line 298 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'animationSystemParams' occurrence at line 300 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'excludeFromDock' occurrence at line 328 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'excludeFromRecent' occurrence at line 331 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_animation_common.h: previewer/include/wm_animation_common.h: shared_ptr member 'needAnimation' occurrence at line 319 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: previewer/include/wm_type.h: previewer/include/wm_type.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/accesstoken_kit.h: previewer/mock/accesstoken_kit.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/ipc_skeleton.h: previewer/mock/ipc_skeleton.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/js_err_utils.h: previewer/mock/js_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/js_window_listener.cpp: previewer/mock/js_window_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/napi_common_want.h: previewer/mock/napi_common_want.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/napi_remote_object.h: previewer/mock/napi_remote_object.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/permission.cpp: previewer/mock/permission.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/permission.h: previewer/mock/permission.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/pixel_map.h: previewer/mock/pixel_map.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/tokenid_kit.h: previewer/mock/tokenid_kit.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/want_params.h: previewer/mock/want_params.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/window_info.h: previewer/mock/window_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/window_manager.h: previewer/mock/window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/window_manager_napi/js_window_manager.h: previewer/mock/window_manager_napi/js_window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/mock/window_manager_napi/window_manager_module.cpp: previewer/mock/window_manager_napi/window_manager_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/src/window_display.cpp: previewer/src/window_display.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/src/window_model.cpp: previewer/src/window_model.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: previewer/src/window_option.cpp: previewer/src/window_option.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: setresolution/include/setresolution_utils.h: setresolution/include/setresolution_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: setresolution/src/setresolution_screen.cpp: setresolution/src/setresolution_screen.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: setresolution/src/setresolution_utils.cpp: setresolution/src/setresolution_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: snapshot/include/snapshot_utils.h: snapshot/include/snapshot_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: snapshot/src/snapshot_utils.cpp: snapshot/src/snapshot_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/include/ohos_window_command.h: tools/ohos-window/include/ohos_window_command.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/include/shell_command.h: tools/ohos-window/include/shell_command.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/src/main.cpp: tools/ohos-window/src/main.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/src/ohos_window_command.cpp: tools/ohos-window/src/ohos_window_command.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/src/shell_command.cpp: tools/ohos-window/src/shell_command.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/ohos-window/tests/ohos_window_command_util_test.cpp: tools/ohos-window/tests/ohos_window_command_util_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 76 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `f756df6613a1170a51008996d3591846dd9ffed8545b0e25715558e2b60c31b0`
- Language matching plans attempts; actual coverage remains in the results above.
