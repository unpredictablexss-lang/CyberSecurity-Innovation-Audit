# D53 — camera framework shared_ptr A0 source-bound assessment

## Scope and result

Reviewed A0 candidates CR-0261–CR-0290 against the exact `openharmony/multimedia_camera_framework` source object, commit `35445b57d739a41cb916330935e61f1e83d982ca`, tree `2907d1748b46897c49c8f8c253c49384294a6a7a`. The 30 rows point to 13 unique C++ headers. Each blob ID and SHA-256 is recorded in the replay JSON and checked against the frozen 345-row A0 queue.

The current `ohscanner.cpp.shared_ptr_race` 0.5.1 was run directly on each exact source file. All 13 files parse syntactically completely; there are 13 diagnostics. Ten A0 locations are reproduced at their exact source lines: CR-0261, CR-0276–CR-0278, CR-0280–CR-0283, and CR-0286–CR-0287. None of the other 20 rows demonstrates a concrete generalized detector gap after reviewing the associated member operation and in-file context. This is a **no-change assessment**, not a safety determination.

## Unmatched locations and source context

- CR-0262–CR-0264 and CR-0267–CR-0269 refer to `eventListenerMap_` shared_ptr values. Their helpers are named `NoLock`, but the two caller methods hold `eventListenerMapMutex_` over map reads and writes. Both Taihe and N-API headers follow this pattern. The AST detector does not emit these container-element accesses as shared_ptr member accesses; the observed same-object access is protected in these caller scopes, so this is not a reproduced missed unsafe read/write pair.
- CR-0265 (`asyncCtx_`) is initialized in the constructor and then returned by an accessor. CR-0266 (`metadataResultProcessor_`) is read by the header accessor; observed assignments are in implementation/session constructors. CR-0271–CR-0275 (`asyncFunction_`) is constructor-initialized and then read by the parser constructor body. CR-0279 (`configureParameter_`) and CR-0288–CR-0290 (`videoProcessor_`, `repository_`, `postProcessor_`) are accessor reads; their writes are outside the reported header and arise from initialization/constructor wiring in the component. These rows do not establish an unsynchronized post-construction same-member write/read pair in the scanned scope.
- CR-0270 is `ptrHolder_.emplace_back(ptr)`: the reported operation mutates a list of `shared_ptr<void>` values, rather than reading/writing one shared_ptr member. The source also has a destructor implementation that clears the holder. This scoped evidence does not establish concurrent calls on the same `CameraNapiObjectTypes` instance or a detector omission with a validated race.
- CR-0284–CR-0285 are constructor initializers for callback `wrapPtr_` holders. Their reported lines do not show a concurrent mutation.
- Existing emitted candidates also need context: CR-0276 is destructor reset paired with accessors; CR-0277/0278 are setter/getter; CR-0280–0283 read `audioCapturer_`; and CR-0286/0287 are constructor/destructor writes to `curNode_`. The lexical hits do not independently prove concurrent execution or vulnerability.

The repository source object was searched for the relevant helper/member references and nearby component/build files. This replay did not lock an actual device/product build profile, macro set, target selection, cross-component runtime schedule, or attacker-reachable security impact. Parser status `complete` means syntax parsing of the selected files only. Preserve the assessment as **PARTIAL/BLOCK**.

## A0 preservation and artifacts

All selected A0 rows remain `not_testable / paused_pending_evidence`; no queue status or detector code was changed. The replay uses the scanner's current detector implementation on exact source bytes; no positive/fixed/security-control fixture matrix is warranted because no rule change is proposed.

- [Machine assessment](d53_camera_sharedptr_assessment_20261030.json)
- [Exact-source CLI replay](d53_camera_sharedptr_cli_20261030.json)
- [Replay and source-binding verifier](verify_d53_camera_sharedptr_20261030.py)

## Reproduction

```powershell
python research/evidence/cpp/d53_camera_sharedptr_assessment_20261030.py `
  --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\multimedia_camera_framework.git `
  --output research/evidence/cpp/d53_camera_sharedptr_cli_20261030.json
python research/evidence/cpp/verify_d53_camera_sharedptr_20261030.py `
  --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\multimedia_camera_framework.git
```
