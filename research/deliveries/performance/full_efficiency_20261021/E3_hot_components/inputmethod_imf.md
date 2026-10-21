# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/inputmethod_imf`
- Pinned commit: `7777cba9eb19085af8e7b90088531028d2937460`
- Git tree: `3edaf7b3825158e13177a8ed61fa1689905229ba`
- Snapshot SHA-256: `d8c053e7575238e68bc045081c23ffdd43a8555777571c001e9b9d610df1f0e5`
- Source files indexed: 698
- Parsing coverage: `{"complete": 539, "partial": 159}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 522 | 522 | 0 | 152 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 24
- `frameworks/ets/extension/ets/@ohos.InputMethodExtensionAbility.ets`
- `frameworks/ets/extension/ets/@ohos.InputMethodExtensionContext.ets`
- `frameworks/ets/inputmethodlist/@ohos.inputMethodList.ets`
- `frameworks/js/napi/inputmethod_extension_ability/inputmethod_extension_ability.js`
- `frameworks/js/napi/inputmethod_extension_context/inputmethod_extension_context.js`
- `frameworks/js/napi/inputmethodlist/inputmethodlist.js`
- `frameworks/js/napi/inputmethodlist/source/inputmethodlist.ets`
- `services/dialog/entry/src/main/ets/Application/MyAbilityStage.ts`
- `services/dialog/entry/src/main/ets/ServiceExtAbility/ServiceExtAbility.ts`
- `services/dialog/entry/src/main/ets/pages/index.ets`
- `test/unittest/napi_test/src/InputMethodTest.js`
- `test/unittest/napi_test/src/InputMethodWithAttachTest.js`
- `test/unittest/resource/bundle_dependencies/editorBox/entry/src/main/ets/entryability/EntryAbility.ts`
- `test/unittest/resource/bundle_dependencies/editorBox/entry/src/main/ets/pages/Index.ets`
- `test/unittest/resource/bundle_dependencies/extImfBundle/entry/src/main/ets/Application/MyAbilityStage.ts`
- `test/unittest/resource/bundle_dependencies/extImfBundle/entry/src/main/ets/InputMethodExtAbility/InputMethodExtAbility.ts`
- `test/unittest/resource/bundle_dependencies/extImfBundle/entry/src/main/ets/InputMethodExtAbility/model/KeyboardController.ts`
- `test/unittest/resource/bundle_dependencies/extImfBundle/entry/src/main/ets/MainAbility/MainAbility.ts`
- `test/unittest/resource/bundle_dependencies/extImfBundle/entry/src/main/ets/pages/Index.ets`
- `test/unittest/resource/bundle_dependencies/newTestIme/entry/src/main/ets/Application/MyAbilityStage.ts`
- `test/unittest/resource/bundle_dependencies/newTestIme/entry/src/main/ets/InputMethodExtAbility/InputMethodExtAbility.ts`
- `test/unittest/resource/bundle_dependencies/newTestIme/entry/src/main/ets/InputMethodExtAbility/model/KeyboardController.ts`
- `test/unittest/resource/bundle_dependencies/newTestIme/entry/src/main/ets/MainAbility/MainAbility.ts`
- `test/unittest/resource/bundle_dependencies/newTestIme/entry/src/main/ets/pages/index.ets`
- `ohscanner.example.cpp.copy-calls`: partial, 522/674 applicable files examined; unexamined=152

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 152 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
