# D35 — Preferences fuzz candidates CR-0022–CR-0040

## Source and replay

The 19 A0 rows bind to `openharmony/distributeddatamgr_preferences` commit `bff9efd79afc0d7d1ed22a63ff355f1600404596`, tree `7761d9e273ae7007046ae115797f255e554523ae`, and the same source file blob `4cf33a525d98b18bda1f36d7ec0cf27cdb4a41b6` / SHA-256 `39d4429ccf1ef4cacf946597de5f5b789bb826427b7901e820d97e3859ec6bbf`.

Current `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI replayed the entire `dbpreferences_fuzzer.cpp` source file. Parsing is complete (1/1 file); all 19 syntax candidates reproduce at the queue-bound lines for CR-0022–0040. Each observation has a diagnostic ID and rule ID, while stable and occurrence finding identities are unknown. The 19 positions cover setup/teardown and fuzzed API calls; their location match is source correspondence, not evidence of a data race.

The exact `BUILD.gn` blob is `b9a2eacecbc180514c963e59d3f9365068ae20e5` (SHA-256 `2f3268757bbe0e66f9cb1eac4b6fc5c6f2be0a1f063931052969bd840b3c217e`). It declares `ohos_fuzztest("DBPreferencesFuzzTest")`; the `fuzztest` group is `testonly = true`, and the C++ entry point is `LLVMFuzzerTestOneInput`. Thus these are test-harness source candidates, not production vulnerability evidence. Runtime thread overlap, product inclusion, production reachability and impact have not been established. This source review does not label them false positives or infer safety.

## Disposition and queue

CR-0022–0040 retain original A0 state `not_testable / paused_pending_evidence`. All remain `PARTIAL`; no detector change was justified. T27 previously audited CR-0022–0024; D35 replays the complete file and records the same source binding and findings in one per-ID machine report.

Run `python research/evidence/cpp/verify_d35_preferences_fuzz_replay.py` to verify source Git objects, both queue exports, all 19 line-to-finding matches, finding identity quality, parser coverage and unchanged queue status counts. Machine report: `d35_preferences_source_replay_20261024.json`; raw CLI: `d35_preferences_fuzz_20261024.json`.
