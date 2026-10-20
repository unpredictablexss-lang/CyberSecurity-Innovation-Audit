# D47 — Camera shared_ptr race candidates CR-0257–CR-0260

## Result

No detector change. The old A0 review is a syntax-level `shared_ptr_race` candidate set, not a labeled vulnerability. Replaying the exact A0 source commit with the current C++ scanner (0.5.1) produced four candidates in two files. Three map to A0 IDs CR-0258–CR-0260; CR-0257 is quiet. The extra result is the getter return on line 52. Both files parse syntactically complete, but detector coverage is still partial because its synchronization/thread/build model is incomplete for `camera_auto_ref_taihe.h`.

Source identity is `openharmony/multimedia_camera_framework`, commit `35445b57d739a41cb916330935e61f1e83d982ca`, tree `2907d1748b46897c49c8f8c253c49384294a6a7a`. The target `frameworks/taihe/include/camera_auto_ref_taihe.h` is blob `7696d21cf0dff92e54416f7f6131644c6d2e5a48`, SHA-256 `d43b2035615f59cfd6307730ae8e247f6f89153597b954d1a02dc6b6b42005ba`. The other target `common/utils/watch_dog.h` is blob `3bc969ff348e39cc55387502ddfaf0b64d0ad1eb`, SHA-256 `2b9eda5f6c23c895c033f1aa5514244e588ace74a3a5b81d8ffbeff43083c6ca`.

## Replay

Command:

```powershell
python -m src.cli ohscan-run --repo-dir <multimedia_camera_framework.git> --repository openharmony/multimedia_camera_framework --commit 35445b57d739a41cb916330935e61f1e83d982ca --include common/utils/watch_dog.h --include frameworks/taihe/include/camera_auto_ref_taihe.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d47_camera_sharedptr_cli_20261027.json --md-out research/evidence/cpp/d47_camera_sharedptr_cli_20261027.md
```

| A0 ID | Location | Current 0.5.1 replay |
| --- | --- | --- |
| CR-0257 | `common/utils/watch_dog.h:34` | No finding |
| CR-0258 | `frameworks/taihe/include/camera_auto_ref_taihe.h:27` | Candidate at same line |
| CR-0259 | `frameworks/taihe/include/camera_auto_ref_taihe.h:43` | Candidate at same line |
| CR-0260 | `frameworks/taihe/include/camera_auto_ref_taihe.h:48` | Candidate at same line |
| — | `frameworks/taihe/include/camera_auto_ref_taihe.h:52` | One extra getter-return candidate |

Run coverage is 2 files / 156 LOC, parser status complete 2/2, detector status `partial` (one file fully modeled and one `detector_model_incomplete`), four candidate diagnostics, about 0.0091 seconds. A complete syntax parse does not resolve synchronization or feasible interleavings.

## Source context and decision

- `AutoRef::callbackRef_` is initialized before the new wrapper is inserted into `ListenerBase::CallbackList`. The list owns a `listMutex`; `SaveCallbackReference`, all three callback execution templates, callback removal, clearing, and `IsEmpty` take that lock. The executed-callback paths call `GetCallbackFunction()` under the lock; removal/clear also destroy wrappers under it. The same source commit's `frameworks/taihe/BUILD.gn` builds `listener_base_taihe.cpp` into `camera_taihe`.
- In the visible exact-repository callers, the A0 assignment, destruction/reset, null test, and returned shared pointer are therefore protected by the callback-list lock or happen before publication. This is source-level evidence against calling these lines an established unsynchronized race. External use of the public wrapper, all product configurations, callback reentrancy and actual runtime interleavings are not proven here.
- `Watchdog::timeBroker_` is initialized once in its constructor; `Watchdog` copy operations are deleted, and `StartMonitor`, `StopMonitor`, and `DoTimeout` lock the same `mutex_`. No post-publication assignment/reset appears in this class, so CR-0257's constructor line alone does not establish conflicting concurrent access.
- No trusted fixed source or target-derived concurrency harness is available. Preserve the four A0 rows as `not_testable / paused_pending_evidence` and the current candidate evidence as PARTIAL. Do not label this family a confirmed flaw or a false-positive rate measurement. No rules, A0 statuses, shared APIs, or Catalog files changed.

Next evidence needed: resolve externally callable wrapper uses and shipped target configuration, then exercise a target-derived same-instance concurrent callback/remove scenario under a race detector if a feasible overlap remains. Until that is available, keep the family paused; do not broaden the detector to flag one-time shared pointer initialization or reads.

## Verification

`verify_d47_camera_sharedptr_20261027.py` binds the A0 rows to commit/tree/blob/SHA, checks the CLI version and finding map, verifies listener/build lock evidence, and asserts the original queue status remains unchanged. The A0 queue remains 345 rows. CPP scope check against PR #30 base returned no violations.
