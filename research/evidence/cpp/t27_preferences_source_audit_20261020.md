# T27 — Preferences CR-0020–CR-0024 independent source audit

## Result

All five IDs bind to the frozen A0 source rows and exact Preferences commit/tree/blob/SHA. Their original states remain `not_testable / paused_pending_evidence`. This source-only pass does not establish a confirmed race or safety.

## Detector replay

Independent production M2 CLI replay: `ohscanner.cpp.shared_ptr_race` 0.5.1, scope `js_proxy.h` plus `dbpreferences_fuzzer.cpp`, parsing `{'complete': 2}`. It emitted 21 syntax candidates: two in the shared header and nineteen in the fuzz file. Fuzz-file hits are not product findings.

## Product/test boundary

CR-0022–CR-0024 point to `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp`; its GN target is `ohos_fuzztest("DBPreferencesFuzzTest")`, with a `testonly = true` fuzztest group and `LLVMFuzzerTestOneInput`. It calls `PreferencesHelper` and `Preferences` APIs, but remains a test harness. The production N-API implementation contains a concrete setup/use/destruction path: `NewInstance` calls `SetInstance(value)`, `GetSelfInstance` unwraps the N-API object and calls `GetInstance()`, and the non-sendable proxy destructor calls `SetInstance(nullptr)`. Async work stores a `weak_ptr<Preferences>` in context. The reviewed source does not show a reassignment to an already-published proxy; it also does not establish whether finalization overlaps native calls, N-API environment/thread affinity, or sendable proxy cross-thread scheduling. Target build, runtime schedule, reachability and impact remain unverified, so source alone proves neither a race nor safety.

## Queue

Frozen original A0 queue CSV/JSON agree on 345 rows and 345 unique IDs. Original status counts: `{'not_reproduced': 9, 'not_testable': 336}`; queue status counts: `{'queued_not_reproduced': 9, 'queued_first_batch': 5, 'paused_pending_evidence': 331}`. The five rows retain exact source keys and states.

Per-ID reports and raw CLI output are next to this file. Run `python research/evidence/cpp/verify_t27_preferences_source_audit.py` to check object identities, both queue exports, CLI finding locations, and unchanged states.
