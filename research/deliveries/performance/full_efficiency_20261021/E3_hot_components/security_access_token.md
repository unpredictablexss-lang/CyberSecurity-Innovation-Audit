# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/security_access_token`
- Pinned commit: `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`
- Git tree: `4621b3e40b31a958a4bbe9be87690afb6cec44b0`
- Snapshot SHA-256: `8cf960ea497f845842666ba3240c642c76fa590a46ede6d4c36b783a2a34daae`
- Source files indexed: 1249
- Parsing coverage: `{"complete": 1048, "partial": 201}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 1046 | 1046 | 0 | 198 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 5
- `frameworks/ets/ani/accesstoken/ets/@ohos.abilityAccessCtrl.ets`
- `frameworks/ets/ani/common/ets/permissions.ets`
- `frameworks/ets/ani/common/ets/security/PermissionRequestResult.ets`
- `frameworks/ets/ani/el5filekeymanager/ets/@ohos.ability.screenLockFileManager.ets`
- `frameworks/ets/ani/privacy/ets/@ohos.privacyManager.ets`
- `ohscanner.example.cpp.copy-calls`: partial, 1046/1244 applicable files examined; unexamined=198

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 198 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
