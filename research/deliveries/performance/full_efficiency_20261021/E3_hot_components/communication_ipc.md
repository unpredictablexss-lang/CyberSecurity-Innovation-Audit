# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/communication_ipc`
- Pinned commit: `bbb92dbb2f52aca54ab268307c9476ac1802f3ff`
- Git tree: `125ecbfa21f430f2f977f0026ab97b70cd27a726`
- Snapshot SHA-256: `56c7666d183a563f7897df79c4121d26a3c0d235d1d631b1d6bf41c826666931`
- Source files indexed: 697
- Parsing coverage: `{"complete": 453, "partial": 244}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.example.cpp.copy-calls` | completed | 442 | 442 | 0 | 218 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 37
- `ipc/native/src/ani/rpc/ets/@ohos.rpc.ets`
- `ipc/native/src/taihe/test/test_main.ets`
- `test/unittest/js/NapiIRemoteProxy.js`
- `test/unittest/js/NapiRemoteObjectTest.js`
- `test/unittest/js/ipcActsObject.js`
- `test/unittest/js/ipcActsRemoteObject.js`
- `test/unittest/js/ipcActsTaihe01.js`
- `test/unittest/js/ipcActsTaihe02.js`
- `test/unittest/js/ipcActsTaihe03.js`
- `test/unittest/js/ipcActsTaihe04.js`
- `test/unittest/js/ipcActsTaihe05.js`
- `test/unittest/js/ipcActsTest01.js`
- `test/unittest/js/ipcActsTest02.js`
- `test/unittest/js/ipcActsTest03.js`
- `test/unittest/js/ipcActsTest04.js`
- `test/unittest/js/ipcActsTestA.js`
- `test/unittest/js/ipcActsTestB.js`
- `test/unittest/js/ipcActsTestC.js`
- `test/unittest/js/ipcActsTestD.js`
- `test/unittest/js/ipcActsTestE.js`
- `test/unittest/js/ipcActsTestF.js`
- `test/unittest/js/ipcActsTestG.js`
- `test/unittest/js/ipcActstaihe06.js`
- `test/unittest/js/ipcApiStageMessageSequence_001_030.js`
- `test/unittest/js/ipcApiStageMessageSequence_0310_0600.js`
- `test/unittest/js/ipcApiStageMessageSequence_1810_2100.js`
- `test/unittest/js/ipcCapiTest.js`
- `test/unittest/js/ipcMessageSequence0760_1050.js`
- `test/unittest/js/ipcMessageSequenceTest.js`
- `test/unittest/js/module/adddeathrecipientTest.ts`
- `test/unittest/js/module/appendTest.ts`
- `test/unittest/js/module/bindTest.ts`
- `test/unittest/js/module/binderconnectorTest.ts`
- `test/unittest/js/module/binderinvokerTest.ts`
- `test/unittest/js/module/binderinvokerdTest.ts`
- `test/unittest/js/module/bufferobjectTest.ts`
- `test/unittest/js/module/bufferobjectarrayTest.ts`
- `ohscanner.example.cpp.copy-calls`: partial, 442/660 applicable files examined; unexamined=218

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
- `ohscanner.example.cpp.copy-calls`: INCOMPLETE COVERAGE: 218 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
