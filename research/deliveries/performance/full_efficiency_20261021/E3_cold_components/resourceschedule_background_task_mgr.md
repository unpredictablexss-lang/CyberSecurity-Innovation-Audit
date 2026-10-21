# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/resourceschedule_background_task_mgr`
- Pinned commit: `cff2ff475e3885ee814651f6a13d7f8a5782efdd`
- Git tree: `0a18669abd454ae51f19adcf445eeb57888d2f3e`
- Snapshot SHA-256: `51dd0c184f0d54b7e3fcd09ac30104767ae7b12ce27bb7678494c3583f3a0722`
- Source files indexed: 284
- Parsing coverage: `{"complete": 237, "partial": 47}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 229 | 229 | 0 | 44 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 11
- `interfaces/test/unittest/continuous_task_jsunittest/continuous_task_jsunit.test.js`
- `interfaces/test/unittest/efficiency_resources_jsunittest/efficiency_resources_jsunit.test.js`
- `interfaces/test/unittest/transient_task_jsunittest/transient_task_jsunit.test.js`
- `resources/entry/src/main/ets/Application/AbilityStage.ts`
- `resources/entry/src/main/ets/ServiceExtAbility/NotificationServiceExtAbility.ts`
- `resources/entry/src/main/ets/common/constant.ets`
- `resources/entry/src/main/ets/common/displayUtils.ets`
- `resources/entry/src/main/ets/common/utils.ets`
- `resources/entry/src/main/ets/pages/emptyPage.ets`
- `resources/entry/src/main/ets/pages/notificationDialog.ets`
- `resources/entry/src/main/ets/pages/pcNotificationDialog.ets`
- `ohscanner.example.cpp.copy-calls`: partial, 229/273 applicable files examined; unexamined=44

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 44 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
