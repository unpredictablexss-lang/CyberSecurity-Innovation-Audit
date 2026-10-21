# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `7ca0a3be4ee960f028baa55af6d797c06397e40d75f74337d288cf5c3f834c33`
- Source files indexed: 274
- Parsing coverage: `{"complete": 200, "partial": 74}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 186 | 186 | 0 | 63 | 0 | partial |

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
- `ohscanner.example.cpp.copy-calls`: partial, 186/249 applicable files examined; unexamined=63

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.example.cpp.copy-calls`: EXAMPLE ONLY: inventories selected syntax call expressions; it is not vulnerability detection.
- `ohscanner.example.cpp.copy-calls`: No control flow, call resolution, macro expansion, object size or taint analysis.
- `ohscanner.example.cpp.copy-calls`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.example.cpp.copy-calls`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.example.cpp.copy-calls`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 63 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
