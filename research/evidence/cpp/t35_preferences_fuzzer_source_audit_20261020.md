# T35 — Preferences fuzzer family CR-0025–CR-0040 independent audit

## Result

All 16 A0 rows bind to one frozen source object and source-family key. The independently executed production M2 `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI parsed the exact fuzzer file completely and emitted 19 syntax candidates; all 16 row locations map to a current finding. T27 already mapped the other three rows in this same source family (CR-0022–CR-0024), so the 19 source-family queue IDs now map to 19 diagnostics without treating duplicate family evidence as independent validation.

The target is fuzz-only: the pinned `BUILD.gn` declares `ohos_fuzztest("DBPreferencesFuzzTest")`, and its `fuzztest` group is `testonly = true`. The harness entry `LLVMFuzzerTestOneInput` invokes `SetUpTestCase`, seven input-driven wrappers, and teardown. Those wrappers call real Preferences APIs through the fuzz target's dependency, but the reported `preferences_` accesses occur in the fuzz harness static member and wrapper functions. No production function using this harness member, shipped product configuration, product-reachable concurrent schedule, or impact is established. Fuzz-only classification is not evidence that a race is absent.

All CR-0025–CR-0040 rows remain `not_testable / paused_pending_evidence`, with case disposition **PARTIAL**. No row was promoted to safe or to a confirmed product vulnerability.

## Provenance and replay

- Repository: `openharmony/distributeddatamgr_preferences`
- Commit/tree: `bff9efd79afc0d7d1ed22a63ff355f1600404596` / `7761d9e273ae7007046ae115797f255e554523ae`
- Source: `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp`
- Source blob/SHA-256: `4cf33a525d98b18bda1f36d7ec0cf27cdb4a41b6` / `39d4429ccf1ef4cacf946597de5f5b789bb826427b7901e820d97e3859ec6bbf`
- Build descriptor: `test/native/fuzztest/dbpreferences_fuzzer/BUILD.gn`; exact blob and SHA-256 are in the machine record.
- CLI: selected only the pinned fuzzer source; `complete: 1`, 19 diagnostics, build profile `none`.
- T27's CR-0022–CR-0024 identities and states were used only to de-duplicate this source family; the A0 CSV/JSON were read-only inputs.

| A0 ID | Source line | Current candidate |
|---|---:|---|
| CR-0025 | 65 | `preferences_` |
| CR-0026 | 66 | `preferences_` |
| CR-0027 | 74 | `preferences_` |
| CR-0028 | 75 | `preferences_` |
| CR-0029 | 83 | `preferences_` |
| CR-0030 | 84 | `preferences_` |
| CR-0031 | 92 | `preferences_` |
| CR-0032 | 93 | `preferences_` |
| CR-0033 | 101 | `preferences_` |
| CR-0034 | 102 | `preferences_` |
| CR-0035 | 110 | `preferences_` |
| CR-0036 | 111 | `preferences_` |
| CR-0037 | 112 | `preferences_` |
| CR-0038 | 121 | `preferences_` |
| CR-0039 | 122 | `preferences_` |
| CR-0040 | 123 | `preferences_` |

Run `python research/evidence/cpp/verify_t35_preferences_fuzzer_audit.py` to check CSV/JSON parity, every target row's ID/source key/state and source hashes, current CLI locations, fuzz-only build markers, and unchanged A0 state counts.
