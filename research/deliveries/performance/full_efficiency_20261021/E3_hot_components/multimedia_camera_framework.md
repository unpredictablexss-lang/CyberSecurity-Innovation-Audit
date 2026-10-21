# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/multimedia_camera_framework`
- Pinned commit: `085a5d0e2dc1c90a4b676bad55675a1cf12a6380`
- Git tree: `daef3c4c6bc50ead50610846a958c29ae669f0f3`
- Snapshot SHA-256: `72fdccb6afffbdcc9eb19cc7bebf483ba96142899886da0e17092198e2f7cba1`
- Source files indexed: 1696
- Parsing coverage: `{"complete": 1335, "partial": 361}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 1291 | 1291 | 0 | 320 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 85
- `frameworks/js/camera_napi/cameraAnimSample/entry/hvigorfile.ts`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/common/Constants.ts`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/common/utils/BlurAnimateUtil.ts`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/common/utils/DateTimeUtil.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/common/utils/GlobalContext.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/common/utils/Logger.ts`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/entryability/EntryAbility.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/mode/CameraService.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/pages/EditPage.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/pages/Index.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/views/FlashingLightComponent.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/views/FocusAreaComponent.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/views/FocusComponent.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/views/ModeComponent.ets`
- `frameworks/js/camera_napi/cameraAnimSample/entry/src/main/ets/views/SlideComponent.ets`
- `frameworks/js/camera_napi/cameraAnimSample/hvigorfile.ts`
- `frameworks/js/camera_napi/demo/entry/hvigorfile.js`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/Application/MyAbilityStage.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/Dialog/MultiCameraDialog.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/Dialog/MultiCameraHelpDialog.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/Dialog/RecodeStopDialog.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/Dialog/SettingDialog.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/EntryAbility/EntryAbility.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/MainAbility/MainAbility.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/CameraConfig.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/Constants.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/DisplayCalculator.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/GlobalContext.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/SettingItem.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/SettingList.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/SettingPublicLayout.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/common/SettingRightLayout.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/model/CameraService.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/model/DateTimeUtil.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/model/Logger.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/model/Setting.ts`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/pages/Index.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/ColorEffectComponent.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/CountdownPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/DeferredPhotoComponent.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/DividerPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/FlashingLightPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/FocusAreaPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/FocusPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/ModeSwitchPage.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/MoonCaptureBoostComponent.ets`
- `frameworks/js/camera_napi/demo/entry/src/main/ets/views/SlidePage.ets`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/Application/TestAbilityStage.ts`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/TestAbility/TestAbility.ets`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/TestAbility/pages/index.ets`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/TestRunner/OpenHarmonyTestRunner.ts`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/test/Ability.test.ets`
- `frameworks/js/camera_napi/demo/entry/src/ohosTest/ets/test/List.test.ets`
- `frameworks/js/camera_napi/demo/hvigor/hvigor-wrapper.js`
- `frameworks/js/camera_napi/demo/hvigorfile.js`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/hvigorfile.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/cpp/types/libentry/index.d.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/Dialog/mainDialog.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/Dialog/settingDialog.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/MainAbility/MainAbility.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/common/Constants.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/common/DisplayCalculator.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/common/settingItem.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/common/settingPublicLayout.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/common/settingRightLayout.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/entryability/EntryAbility.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/model/DateTimeUtil.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/model/Logger.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/model/MediaUtils.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/pages/tableIndex.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/CountdownPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/FlashingLightPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/SlidePage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/dividerPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/focusAreaPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/focusPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/main/ets/views/modeSwitchPage.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/ohosTest/ets/test/Ability.test.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/ohosTest/ets/test/List.test.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/ohosTest/ets/testability/TestAbility.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/ohosTest/ets/testability/pages/Index.ets`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/entry/src/ohosTest/ets/testrunner/OpenHarmonyTestRunner.ts`
- `frameworks/native/camera/test/ndktest/camera_ndk_demo/hvigorfile.ts`
- `interfaces/kits/js/camera_napi/@ohos.multimedia.camera.d.ts`
- `interfaces/kits/js/camera_napi/@ohos.multimedia.cameraPicker.d.ts`
- `ohscanner.example.cpp.copy-calls`: partial, 1291/1611 applicable files examined; unexamined=320

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 320 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
