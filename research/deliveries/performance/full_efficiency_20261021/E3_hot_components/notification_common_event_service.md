# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/notification_common_event_service`
- Pinned commit: `aaaaf6d10aa8e1f6bd28673f10d5791d7e9c9e3f`
- Git tree: `bca5f636d88a314c82f52a564b7dbf3b5d4aa1cc`
- Snapshot SHA-256: `d6eae8aee637abb98d75f8643e97c5a826edd88fcbe2966367b2431da18fd929`
- Source files indexed: 293
- Parsing coverage: `{"complete": 221, "partial": 72}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 215 | 215 | 0 | 69 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 9
- `interfaces/kits/ani/common_event/ets/@ohos.application.StaticSubscriberExtensionAbility.ets`
- `interfaces/kits/ani/common_event/ets/@ohos.application.StaticSubscriberExtensionContext.ets`
- `interfaces/kits/ani/common_event/ets/@ohos.commonEventManager.ets`
- `interfaces/kits/ani/common_event/ets/commonEvent/commonEventData.ets`
- `interfaces/kits/ani/common_event/ets/commonEvent/commonEventPublishData.ets`
- `interfaces/kits/ani/common_event/ets/commonEvent/commonEventSubscribeInfo.ets`
- `interfaces/kits/ani/common_event/ets/commonEvent/commonEventSubscriber.ets`
- `interfaces/kits/napi/static_subscriber_extension/static_subscriber_extension_ability.js`
- `interfaces/kits/napi/static_subscriber_extension_context/static_subscriber_extension_context.js`
- `ohscanner.example.cpp.copy-calls`: partial, 215/284 applicable files examined; unexamined=69

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 69 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
