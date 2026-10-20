# T39 — Preferences fuzzer independent audit (CR-0097–CR-0115)

## Result

T39 independently ran the current first-party `ohscan-run` CLI on the exact A0 source object. The one-file scope parsed completely; `ohscanner.cpp.shared_ptr_race` 0.5.1 emitted 19 syntax candidates, matching every A0 source line in this family. This establishes detector output only. The source is an `LLVMFuzzerTestOneInput` harness, and its GN file declares an `ohos_fuzztest("PreferencesFuzzTest")` target under a `group("fuzztest")` with `testonly = true`. This source and build declaration do not prove product inclusion, production reachability, or a concurrent race.

All 19 IDs remain `not_testable / paused_pending_evidence` and PARTIAL. A0 row count and states were not changed. No detector, tests, or fixtures were modified.

## Immutable source identity and replay

- Repository: `openharmony/distributeddatamgr_preferences`
- Commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Source: `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp`
- Source blob: `fad8bdb1b87a8566b355b0ea4dbd5020c42c405c`
- Source SHA-256: `140266d2693d7a0028767c80670d01682c2e7deca2634412028a59504a976e29`
- Source size: 4,668 bytes
- BUILD: `test/native/fuzztest/preferences_fuzzer/BUILD.gn`
- BUILD blob: `8506a0917b7fbff48a6d14ccb4c1f931db5db251`
- BUILD SHA-256: `d10327b19d3006cc1f0c9ad52d858a009cd0c90d8d4c0e14be6e2d870c132488`
- Current CLI command:

```powershell
python -m src.cli.main ohscan-run `
  --repo-dir D:\openHarmonyScanner\tmp\t39-preferences-source-20261024 `
  --repository openharmony/distributeddatamgr_preferences `
  --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 `
  --include test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp `
  --detector ohscanner.cpp.shared_ptr_race `
  --json-out research/evidence/cpp/t39_preferences_fuzzer_cli_20261024.json `
  --md-out research/evidence/cpp/t39_preferences_fuzzer_cli_20261024.md
```

Result: detector run `completed`, parse `complete: 1`, scope 1 file / 147 LOC, 19 findings, elapsed 0.02239 seconds. No finding count or candidate should be interpreted as a vulnerability count.

## Per-ID source/finding mapping

| A0 ID | Source line | Source operation | Current CLI finding |
| --- | ---: | --- | --- |
| CR-0097 | 46 | `SetUpTestCase`: assign result of `GetPreferences` to static `Preferences_` | `ohscanner.cpp.shared_ptr_race:c8d862df309bc6e8` |
| CR-0098 | 51 | `TearDownTestCase`: call `Clear` through `Preferences_` | `ohscanner.cpp.shared_ptr_race:e06970342e1589e5` |
| CR-0099 | 53 | `TearDownTestCase`: remove path from Preferences cache | `ohscanner.cpp.shared_ptr_race:d45a2ab1ccd87b57` |
| CR-0100 | 68 | `GetAllFuzz`: `PutInt` | `ohscanner.cpp.shared_ptr_race:04d7f855cf838e0b` |
| CR-0101 | 69 | `GetAllFuzz`: `GetAll` | `ohscanner.cpp.shared_ptr_race:cb9638502cb08b2f` |
| CR-0102 | 77 | `GetAllDataFuzz`: `PutInt` | `ohscanner.cpp.shared_ptr_race:a70e637212a6b076` |
| CR-0103 | 78 | `GetAllDataFuzz`: `GetAllData` | `ohscanner.cpp.shared_ptr_race:e5f12e89e2779b69` |
| CR-0104 | 86 | `GetAllDatasFuzz`: `PutInt` | `ohscanner.cpp.shared_ptr_race:3a308d9708b0802e` |
| CR-0105 | 87 | `GetAllDatasFuzz`: `GetAllDatas` | `ohscanner.cpp.shared_ptr_race:3fe8ca30d4133ecb` |
| CR-0106 | 95 | `DeleteFuzz`: `PutLong` | `ohscanner.cpp.shared_ptr_race:9f5b14f9a7844537` |
| CR-0107 | 96 | `DeleteFuzz`: `Delete` | `ohscanner.cpp.shared_ptr_race:6258aa5e23a470ef` |
| CR-0108 | 104 | `ClearFuzz`: `PutLong` | `ohscanner.cpp.shared_ptr_race:18aee91f72dc1998` |
| CR-0109 | 105 | `ClearFuzz`: `Clear` | `ohscanner.cpp.shared_ptr_race:8918a41536d3f1ca` |
| CR-0110 | 113 | `FlushFuzz`: `PutLong` | `ohscanner.cpp.shared_ptr_race:ee90232ed4af5aa3` |
| CR-0111 | 114 | `FlushFuzz`: `Flush` | `ohscanner.cpp.shared_ptr_race:68cf0b81f60deac9` |
| CR-0112 | 115 | `FlushFuzz`: `GetLong` | `ohscanner.cpp.shared_ptr_race:c09682270995ec1c` |
| CR-0113 | 124 | `FlushSyncFuzz`: `PutLong` | `ohscanner.cpp.shared_ptr_race:5028826f569067e8` |
| CR-0114 | 125 | `FlushSyncFuzz`: `FlushSync` | `ohscanner.cpp.shared_ptr_race:a88fb238c64aa7e3` |
| CR-0115 | 126 | `FlushSyncFuzz`: `GetLong` | `ohscanner.cpp.shared_ptr_race:4bacb2ad7ca38c0b` |

All findings use rule `ohcpp-shared-ptr-race-candidate-001` and are bound to the source SHA above. The 19 rows map to 19 distinct candidate IDs/lines in this file; this is a queue-to-finding reconciliation, not evidence of 19 separate concurrency defects.

## Build and security boundary review

The translation unit defines a static `std::shared_ptr<Preferences> Preferences_`. `LLVMFuzzerTestOneInput` calls `SetUpTestCase`, then the seven fuzz helper functions in order, then `TearDownTestCase`. Each helper performs its visible Put/Get/Delete/Clear/Flush calls inline. The file contains no thread creation, task dispatch, or explicit parallel calls. This does not establish that the fuzz runtime can never invoke callbacks concurrently, and it says nothing about other production call paths.

The exact BUILD file defines `ohos_fuzztest("PreferencesFuzzTest")`; the `fuzztest` aggregation group sets `testonly = true` and depends on that target. This identifies the checked-in entry as a fuzz/test target. No product build manifest/configuration was supplied to prove whether this target is excluded from a particular product or whether production code reaches the same object access.

Still unknown: effective product build selection, production caller/reachability, whether two threads can access the same `Preferences` object concurrently, synchronization/ownership guarantees in the implementation and callers, attacker control and trigger conditions, and security impact. Keep this family PARTIAL. The observed syntax candidates are not confirmed vulnerabilities and are not labeled confirmed false positives.

## Verification

- Independent source replay and per-ID mapping: [machine record](t39_preferences_fuzzer_audit_20261024.json)
- Raw current CLI output: [JSON](t39_preferences_fuzzer_cli_20261024.json) and [Markdown](t39_preferences_fuzzer_cli_20261024.md)
- Reproduction/record builder: [script](t39_preferences_fuzzer_audit_20261024.py)
- Independent consistency verifier: [verifier](verify_t39_preferences_fuzzer_audit_20261024.py)
- A0 queue CSV SHA-256: `a174c0a74986e8410c53f173b84bb446c59000c3867add612a14e8aab4396d27`
- A0 remains 345 unique rows; all 19 audited IDs retain `not_testable / paused_pending_evidence`.
