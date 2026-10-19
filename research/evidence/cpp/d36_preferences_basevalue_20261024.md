# D36 — Preferences base-value fuzz candidates CR-0041–CR-0065

## Exact source and CLI replay

The 25 A0 rows bind to `openharmony/distributeddatamgr_preferences` commit `bff9efd79afc0d7d1ed22a63ff355f1600404596`, tree `7761d9e273ae7007046ae115797f255e554523ae`. The source is `test/native/fuzztest/dbpreferencesbasevalue_fuzzer/dbpreferencesbasevalue_fuzzer.cpp`, blob `37345f46187665a0a0de293ba31a446acb1616d3`, SHA-256 `2351f76128395a0da41b96719836465505060cf46949ac89677deae5dc316651` (6,273 bytes). Its `BUILD.gn` is blob `73d07d85f4e438fcc125f2661b645d11cfc6a2d1`, SHA-256 `82db6683a383051fd7c6c61e2be5db028254162d3e140d678545227e448a3435`.

The current `ohscanner.cpp.shared_ptr_race` 0.5.1 CLI scanned only this source file. Parsing completed (1/1; 197 LOC); 25 syntax findings reproduce all CR-0041–CR-0065 queue lines. Each finding is retained as a candidate, not a confirmed race.

The exact build target is `ohos_fuzztest("DBPreferencesBaseValueFuzzTest")`; its `fuzztest` group sets `testonly = true`. `LLVMFuzzerTestOneInput` invokes setup, sequential fuzz helper calls against one static `shared_ptr<Preferences>`, then teardown. This establishes a fuzz harness, not that the calls overlap concurrently, that the target ships in a product build, or that production code is attacker-reachable. No same-object unsynchronized production race or CIA impact is established. The evidence is therefore PARTIAL, and does not label the findings confirmed false positives or imply safety.

## Disposition and follow-up

All 25 rows remain `not_testable / paused_pending_evidence`. The detector was not changed because the replay exposes syntax-level fuzz harness candidates, not a demonstrated production-source miss. Next evidence needed: production target inclusion, caller/reachability chain, and concrete thread/task overlap with same-object synchronization analysis. Keep those proof obligations distinct from the fuzz target.

Run `python research/evidence/cpp/verify_d36_preferences_basevalue_20261024.py` to re-run source binding checks, validate raw CLI findings and line mapping, and assert the 345-row A0 counts and unchanged statuses. Raw CLI output: `d36_preferences_basevalue_20261024.json`; per-ID report: `d36_preferences_basevalue_replay_20261024.json`.

## Structured vibe-coding prompt for follow-up

- **Role:** A-line Preferences `shared_ptr_race` development lead.
- **Sustained goal:** Distinguish test-only fuzz syntax candidates from production-reachable concurrency root causes; keep each result reproducible and avoid counting duplicate lines as separate vulnerabilities.
- **Inputs:** Exact D36 source identity and CLI replay; CR-0022–CR-0065 family evidence.
- **Work:** Trace production build inclusion and callers separately from fuzz targets; identify same-object copies, reads/writes, locks/atomics, and task/thread creation, dispatch, join, and teardown; test every proposed rule change with vulnerable, fixed, safe, unrelated, renamed, and partial controls.
- **Completion gate:** An independent replay binds to exact commit/tree/blob/SHA; product inclusion/reachability and an overlapping unsynchronized same-object access are established before calling a product vulnerability. Otherwise keep PARTIAL/BLOCK and name the missing evidence.
- **Boundaries:** No CVE/repository/name/hash hardcoding; no promotion of syntax candidates to vulnerabilities; do not edit A0 states, shared API, or Catalog.
