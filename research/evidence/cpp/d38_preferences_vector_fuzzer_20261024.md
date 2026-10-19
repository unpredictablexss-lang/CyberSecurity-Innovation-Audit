# D38 — Preferences vector fuzzer CR-0091–CR-0096

## Exact-source replay

All six A0 records point to `openharmony/distributeddatamgr_preferences` commit `bff9efd79afc0d7d1ed22a63ff355f1600404596`, tree `7761d9e273ae7007046ae115797f255e554523ae`. The source `test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp` is blob `3de64e85dcba575ed35b6bc7f3e5b2fbcf223e2c`, SHA-256 `4b4f6e8e9f7f8e4d06887b93f67352ba9c5e9cf9b697c7814cc713573c0b7dfe`. Its BUILD file is blob `56471b31f18f3184a79badfacf35a6fa8ab03552`, SHA-256 `54a176a31ab5e5d768d1f4408ec86e1b85c6a47880088936c23a528ba5d59770`.

Current CLI command:

```powershell
python -m src.cli.main ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d37-preferences-source-20261024 --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesvector_fuzzer/dbpreferencesvector_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d38_preferences_vector_fuzzer_20261024.json
```

Result: `ohscanner.cpp.shared_ptr_race` 0.5.1, one source file / 93 LOC, parse complete, 6 candidates in 0.0058 seconds. The findings map exactly to A0 lines:

| A0 ID | Source line | Finding ID |
|---|---:|---|
| CR-0091 | 45 | `ohscanner.cpp.shared_ptr_race:07d9e0bcac5b3c28` |
| CR-0092 | 50 | `ohscanner.cpp.shared_ptr_race:99b4bea93cf5d266` |
| CR-0093 | 52 | `ohscanner.cpp.shared_ptr_race:9ff4745d9094a32e` |
| CR-0094 | 68 | `ohscanner.cpp.shared_ptr_race:ae7a984b69ab110b` |
| CR-0095 | 77 | `ohscanner.cpp.shared_ptr_race:653de71495ef3908` |
| CR-0096 | 78 | `ohscanner.cpp.shared_ptr_race:eb9d0be0d85827d7` |

The source declares `DBPreferencesVectorFuzzTest::preferences_`, sets up one Preferences instance, then calls `PutVectorFuzz` and `GetVectorFuzz` in sequence from `LLVMFuzzerTestOneInput`, before teardown. The `DBPreferencesVectorFuzzTest` GN target is an `ohos_fuzztest`; the surrounding `fuzztest` group sets `testonly = true`. It invokes production APIs but provides no proof of product build inclusion, production entry reachability, overlapping concurrent accesses to the same object, or security impact. All findings are therefore syntax candidates. No real detector miss was demonstrated, so no detector change is warranted.

Keep CR-0091–CR-0096 as `not_testable / paused_pending_evidence`, disposition PARTIAL. The A0 queue was not modified. Raw CLI JSON, source-bound per-ID mapping, and verifier are `d38_preferences_vector_fuzzer_20261024.json`, `d38_preferences_vector_fuzzer_replay_20261024.json`, and `verify_d38_preferences_vector_fuzzer_20261024.py`.

## Structured vibe-coding prompt

- **Role:** A-line Preferences `shared_ptr_race` development lead.
- **Sustained goal:** Distinguish test-harness syntax candidates from production-reachable, genuinely overlapping same-object access roots while preserving exact source identities and A0 states.
- **Inputs:** D38 exact source/build bindings, raw CLI output, and CR-0091–CR-0096 locations.
- **Steps:**
  1. Trace production BUILD inclusion and reachable call paths; do not infer shipping from fuzz-target dependencies.
  2. Verify concurrent reads/writes to the same `shared_ptr`, task lifetimes, and mutex/atomic/join synchronization.
  3. Change the detector only after reproducing a concrete production-source miss; add positive, fixed, safe, unrelated, renamed, and partial controls.
  4. Record commit/tree/blob/SHA, scope, profile, rule version, coverage, elapsed time, and replay command for every run.
- **Completion gate:** Independently verify product build/reachability and overlapping unsynchronized access to the same object. Otherwise retain PARTIAL/BLOCK and state the missing evidence.
- **Boundaries:** No CVE/repository/function/hash hardcoding; do not promote harness candidates to product vulnerabilities; do not alter A0 state, shared APIs, Catalog, or diagnostic schema.
