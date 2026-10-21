# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `7ca0a3be4ee960f028baa55af6d797c06397e40d75f74337d288cf5c3f834c33`
- Source files indexed: 274
- Parsing coverage: `{"complete": 200, "partial": 74}`
- Detector runs: 2
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | blocked | 186 | 181 | 5 | 63 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | blocked | 186 | 184 | 2 | 63 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 25
- `interfaces/kits/ani/display_runtime/display_ani/ets/@ohos.display.ets`
- `interfaces/kits/ani/embeddable_window_stage/ets/@ohos.arkui.uiExtension.ets`
- `interfaces/kits/ani/embeddable_window_stage/ets/@ohos.uiExtensionHost.ets`
- `interfaces/kits/ani/embeddable_window_stage/ets/uiExtensionHost_entry.ets`
- `interfaces/kits/ani/embeddable_window_stage/ets/uiExtension_entry.ets`
- `interfaces/kits/ani/environmental/ets/@ohos.windowenv.ets`
- `interfaces/kits/ani/float_view/float_view_ani/ets/@ohos.window.floatView.ets`
- `interfaces/kits/ani/floating_ball/floating_ball_ani/ets/@ohos.window.floatingBall.ets`
- `interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/ets/@ohos.PiPWindow.ets`
- `interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/ets/PiPContent.ets`
- `interfaces/kits/ani/screen_runtime/screen_ani/ets/@ohos.screen.ets`
- `interfaces/kits/ani/screenshot_runtime/screenshot_ani/ets/@ohos.screenshot.ets`
- `interfaces/kits/ani/window_runtime/window_stage_ani/ets/@ohos.window.ets`
- `interfaces/kits/ani/window_runtime/window_stage_ani/ets/window_entry.ets`
- `interfaces/kits/napi/embeddable_window_stage/embeddable_window_stage.js`
- `interfaces/kits/napi/environmental/src/DisplayIdEnv.ts`
- `interfaces/kits/napi/environmental/src/SystemDensityEnv.ts`
- `interfaces/kits/napi/environmental/src/WindowAvoidAreaEnv.ts`
- `interfaces/kits/napi/environmental/src/WindowFocusEnv.ts`
- `interfaces/kits/napi/environmental/src/WindowSizeEnv.ts`
- `interfaces/kits/napi/environmental/src/common.d.ts`
- `interfaces/kits/napi/extension_window/extension_window.js`
- `interfaces/kits/napi/window_extension_ability/window_extension_ability.js`
- `interfaces/kits/napi/window_extension_context/window_extension_context.js`
- `interfaces/kits/napi/window_runtime/window_stage_napi/window_stage.js`
- `ohscanner.cpp.lifetime`: partial, 181/249 applicable files examined; unexamined=68
- `ohscanner.cpp.shared_ptr_race`: partial, 184/249 applicable files examined; unexamined=65

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.cpp.lifetime`: Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.
- `ohscanner.cpp.lifetime`: Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.
- `ohscanner.cpp.lifetime`: Empty findings are not proof of safety and are never benchmark misses.
- `ohscanner.cpp.lifetime`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.lifetime`: Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.
- `ohscanner.cpp.lifetime`: Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.
- `ohscanner.cpp.lifetime`: Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.
- `ohscanner.cpp.lifetime`: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_utils.h: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_utils.h: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/extension_window/js_extension_window.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/extension_window/js_extension_window.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/float_view_napi/js_float_view_controller.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/float_view_napi/js_float_view_controller.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/picture_in_picture_napi/js_pip_controller.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/picture_in_picture_napi/js_pip_controller.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/window_runtime/window_napi/js_window_utils.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: interfaces/kits/napi/window_runtime/window_napi/js_window_utils.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 63 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm/display.h: interfaces/innerkits/dm/display.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm/display_property.h: interfaces/innerkits/dm/display_property.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm/screen.h: interfaces/innerkits/dm/screen.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm/screen_group.h: interfaces/innerkits/dm/screen_group.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm_lite/display_lite.h: interfaces/innerkits/dm_lite/display_lite.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm_lite/display_manager_lite.h: interfaces/innerkits/dm_lite/display_manager_lite.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/dm_lite/screen_manager_lite.h: interfaces/innerkits/dm_lite/screen_manager_lite.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/edidparse/edidparse.h: interfaces/innerkits/edidparse/edidparse.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/extension/extension_business_info.h: interfaces/innerkits/extension/extension_business_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/all_users_window_manager.h: interfaces/innerkits/wm/all_users_window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/all_users_window_manager_lite.h: interfaces/innerkits/wm/all_users_window_manager_lite.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/data_handler_interface.h: interfaces/innerkits/wm/data_handler_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/extension_window.h: interfaces/innerkits/wm/extension_window.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/float_view_template_info.h: interfaces/innerkits/wm/float_view_template_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/floating_ball_template_base_info.h: interfaces/innerkits/wm/floating_ball_template_base_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/occupied_area_change_info.h: interfaces/innerkits/wm/occupied_area_change_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/web_picture_in_picture_controller_interface.h: interfaces/innerkits/wm/web_picture_in_picture_controller_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/window_accessibility_controller.h: interfaces/innerkits/wm/window_accessibility_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/window_option.h: interfaces/innerkits/wm/window_option.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'animationConfig' occurrence at line 236 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'animationParams' occurrence at line 307 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'animationSystemParams' occurrence at line 309 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'excludeFromDock' occurrence at line 337 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'excludeFromRecent' occurrence at line 340 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: interfaces/innerkits/wm/wm_animation_common.h: shared_ptr member 'needAnimation' occurrence at line 328 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::StartAnimationSystemOptions::animationConfig' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::WindowCreateParams::animationParams' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::WindowCreateParams::animationSystemParams' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::WindowCreateParams::excludeFromDock' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::WindowCreateParams::excludeFromRecent' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: modeled accesses to 'interfaces/innerkits/wm/wm_animation_common.h::OHOS::WindowCreateParams::needAnimation' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_animation_common.h: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_layout_common.h: interfaces/innerkits/wm/wm_layout_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/innerkits/wm/wm_type.h: interfaces/innerkits/wm/wm_type.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/display_runtime/display_ani/include/ani_err_utils.h: interfaces/kits/ani/display_runtime/display_ani/include/ani_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/display_runtime/display_ani/include/display_ani.h: interfaces/kits/ani/display_runtime/display_ani/include/display_ani.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/display_runtime/display_ani/include/display_ani_manager.h: interfaces/kits/ani/display_runtime/display_ani/include/display_ani_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/display_runtime/display_ani/src/ani_err_utils.cpp: interfaces/kits/ani/display_runtime/display_ani/src/ani_err_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/embeddable_window_stage/include/ani_embeddable_window_stage.h: interfaces/kits/ani/embeddable_window_stage/include/ani_embeddable_window_stage.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/embeddable_window_stage/include/ani_extension_window_register_manager.h: interfaces/kits/ani/embeddable_window_stage/include/ani_extension_window_register_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/embeddable_window_stage/src/ani_embeddable_window_stage.cpp: interfaces/kits/ani/embeddable_window_stage/src/ani_embeddable_window_stage.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/embeddable_window_stage/src/ani_extension_window_register_manager.cpp: interfaces/kits/ani/embeddable_window_stage/src/ani_extension_window_register_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/float_view/float_view_ani/include/ani_fv_window.h: interfaces/kits/ani/float_view/float_view_ani/include/ani_fv_window.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/float_view/float_view_ani/include/ani_fv_window_controller.h: interfaces/kits/ani/float_view/float_view_ani/include/ani_fv_window_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/float_view/float_view_ani/src/ani_fv_window_listener.cpp: interfaces/kits/ani/float_view/float_view_ani/src/ani_fv_window_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window.h: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window_controller.h: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window_utils.h: interfaces/kits/ani/floating_ball/floating_ball_ani/include/ani_fb_window_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_listener.cpp: interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_utils.cpp: interfaces/kits/ani/floating_ball/floating_ball_ani/src/ani_fb_window_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/include/ani_pip_manager.h: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/include/ani_pip_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/include/ani_pip_window.h: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/include/ani_pip_window.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_controller.cpp: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_listener.cpp: interfaces/kits/ani/picture_in_picture_runtime/pipwindow_ani/src/ani_pip_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/include/ani_err_utils.h: interfaces/kits/ani/screen_runtime/screen_ani/include/ani_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani.h: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani_manager.h: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani_utils.h: interfaces/kits/ani/screen_runtime/screen_ani/include/screen_ani_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/src/ani_err_utils.cpp: interfaces/kits/ani/screen_runtime/screen_ani/src/ani_err_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screen_runtime/screen_ani/src/screen_ani.cpp: interfaces/kits/ani/screen_runtime/screen_ani/src/screen_ani.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screenshot_runtime/screenshot_ani/include/ani_err_utils.h: interfaces/kits/ani/screenshot_runtime/screenshot_ani/include/ani_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/screenshot_runtime/screenshot_ani/src/ani_err_utils.cpp: interfaces/kits/ani/screenshot_runtime/screenshot_ani/src/ani_err_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_err_utils.h: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_manager.h: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_register_manager.h: interfaces/kits/ani/window_runtime/window_stage_ani/include/ani_window_register_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/include/idl_window_common.h: interfaces/kits/ani/window_runtime/window_stage_ani/include/idl_window_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/src/ani_err_utils.cpp: interfaces/kits/ani/window_runtime/window_stage_ani/src/ani_err_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/src/ani_transition_controller.cpp: interfaces/kits/ani/window_runtime/window_stage_ani/src/ani_transition_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/ani/window_runtime/window_stage_ani/src/idl_window_common.cpp: interfaces/kits/ani/window_runtime/window_stage_ani/src/idl_window_common.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/display_runtime/cj_display_listener.cpp: interfaces/kits/cj/display_runtime/cj_display_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/display_runtime/cj_display_listener.h: interfaces/kits/cj/display_runtime/cj_display_listener.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/display_runtime/cj_display_manager.h: interfaces/kits/cj/display_runtime/cj_display_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/display_runtime/display_utils.h: interfaces/kits/cj/display_runtime/display_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 142 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 143 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 157 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 165 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 168 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 178 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 181 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 184 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 187 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 202 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 203 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: shared_ptr member 'image' occurrence at line 82 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.cpp: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/cj_screenshot_module.h: interfaces/kits/cj/screenshot/cj_screenshot_module.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/screenshot_ffi.cpp: interfaces/kits/cj/screenshot/screenshot_ffi.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/screenshot/screenshot_utils.h: interfaces/kits/cj/screenshot/screenshot_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/window_runtime/window_manager_impl.cpp: interfaces/kits/cj/window_runtime/window_manager_impl.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/window_runtime/window_manager_impl.h: interfaces/kits/cj/window_runtime/window_manager_impl.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/window_runtime/window_register_manager.h: interfaces/kits/cj/window_runtime/window_register_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/cj/window_runtime/window_utils.h: interfaces/kits/cj/window_runtime/window_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/common/dm_napi_common.cpp: interfaces/kits/napi/common/dm_napi_common.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/common/dm_napi_common.h: interfaces/kits/napi/common/dm_napi_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/common/js_err_utils.cpp: interfaces/kits/napi/common/js_err_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/common/js_err_utils.h: interfaces/kits/napi/common/js_err_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/display_runtime/js_display_listener.cpp: interfaces/kits/napi/display_runtime/js_display_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/display_runtime/js_display_listener.h: interfaces/kits/napi/display_runtime/js_display_listener.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/display_runtime/js_display_manager.h: interfaces/kits/napi/display_runtime/js_display_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/display_runtime/js_display_module.cpp: interfaces/kits/napi/display_runtime/js_display_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/embeddable_window_stage/embeddable_window_stage_module.cpp: interfaces/kits/napi/embeddable_window_stage/embeddable_window_stage_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/embeddable_window_stage/js_embeddable_window_stage.h: interfaces/kits/napi/embeddable_window_stage/js_embeddable_window_stage.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/environmental/inner/js_windowenv_manager.cpp: interfaces/kits/napi/environmental/inner/js_windowenv_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/environmental/inner/js_windowenv_manager.h: interfaces/kits/napi/environmental/inner/js_windowenv_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/environmental/inner/js_windowenv_module.cpp: interfaces/kits/napi/environmental/inner/js_windowenv_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension/extension_manager.cpp: interfaces/kits/napi/extension/extension_manager.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension/extension_manager.h: interfaces/kits/napi/extension/extension_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension/extension_module.cpp: interfaces/kits/napi/extension/extension_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension_window/extension_window_module.cpp: interfaces/kits/napi/extension_window/extension_window_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension_window/js_extension_window.cpp: not_applicable: global shared_ptr declaration 'g_jsExtensionWindowMap' is outside the class-member race rule and is not analyzed.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension_window/js_extension_window_utils.cpp: interfaces/kits/napi/extension_window/js_extension_window_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/extension_window/js_extension_window_utils.h: interfaces/kits/napi/extension_window/js_extension_window_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/float_view_napi/js_float_view_listener.h: modeled accesses to 'interfaces/kits/napi/float_view_napi/js_float_view_listener.h::OHOS::JsFloatViewListener::jsCallBack_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/float_view_napi/js_float_view_manager.h: interfaces/kits/napi/float_view_napi/js_float_view_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/float_view_napi/js_float_view_module.cpp: interfaces/kits/napi/float_view_napi/js_float_view_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fb_utils.cpp: interfaces/kits/napi/floating_ball_napi/js_fb_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fb_utils.h: interfaces/kits/napi/floating_ball_napi/js_fb_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fb_window_controller.h: interfaces/kits/napi/floating_ball_napi/js_fb_window_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h: modeled accesses to 'interfaces/kits/napi/floating_ball_napi/js_fb_window_listener.h::OHOS::JsFbWindowListener::jsCallBack_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fb_window_manager.h: interfaces/kits/napi/floating_ball_napi/js_fb_window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/floating_ball_napi/js_fbwindow_module.cpp: interfaces/kits/napi/floating_ball_napi/js_fbwindow_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/inner/js_pip_manager.h: interfaces/kits/napi/picture_in_picture_napi/inner/js_pip_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pip_controller.h: interfaces/kits/napi/picture_in_picture_napi/js_pip_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pip_utils.cpp: interfaces/kits/napi/picture_in_picture_napi/js_pip_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pip_utils.h: interfaces/kits/napi/picture_in_picture_napi/js_pip_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h: modeled accesses to 'interfaces/kits/napi/picture_in_picture_napi/js_pip_window_listener.h::OHOS::JsPiPWindowListener::jsCallBack_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pip_window_manager.h: interfaces/kits/napi/picture_in_picture_napi/js_pip_window_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/picture_in_picture_napi/js_pipwindow_module.cpp: interfaces/kits/napi/picture_in_picture_napi/js_pipwindow_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screen_runtime/napi/js_screen.h: interfaces/kits/napi/screen_runtime/napi/js_screen.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screen_runtime/napi/js_screen_listener.cpp: interfaces/kits/napi/screen_runtime/napi/js_screen_listener.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screen_runtime/napi/js_screen_listener.h: interfaces/kits/napi/screen_runtime/napi/js_screen_listener.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screen_runtime/napi/js_screen_manager.h: interfaces/kits/napi/screen_runtime/napi/js_screen_manager.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screen_runtime/napi/screen_manager_module.cpp: interfaces/kits/napi/screen_runtime/napi/screen_manager_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/screenshot/native_screenshot_module.h: interfaces/kits/napi/screenshot/native_screenshot_module.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/window_extension_ability/window_extension_ability_module.cpp: interfaces/kits/napi/window_extension_ability/window_extension_ability_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/window_extension_context/window_extension_context_module.cpp: interfaces/kits/napi/window_extension_context/window_extension_context_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/window_runtime/window_manager_napi/window_manager_module.cpp: interfaces/kits/napi/window_runtime/window_manager_napi/window_manager_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/window_runtime/window_napi/js_ui_effect_controller.h: interfaces/kits/napi/window_runtime/window_napi/js_ui_effect_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: interfaces/kits/napi/window_runtime/window_stage_napi/window_stage_module.cpp: interfaces/kits/napi/window_runtime/window_stage_napi/window_stage_module.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 63 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `25d0471eedfa57bbe8e0e18b4b55a939c6584a18d394944fe3fa18f03ed15fd5`
- Language matching plans attempts; actual coverage remains in the results above.
