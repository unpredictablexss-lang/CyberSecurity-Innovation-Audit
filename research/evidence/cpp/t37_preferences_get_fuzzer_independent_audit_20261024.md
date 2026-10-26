# T37 — Preferences get-fuzzer independent audit (CR-0066–CR-0090)

## Result

T37 independently ran the current production `ohscan-run` CLI on the exact A0 source object for `dbpreferencesget_fuzzer.cpp`. The one-file scope parsed completely (197 LOC); `ohscanner.cpp.shared_ptr_race` 0.5.1 completed and reported 25 syntax candidates. All 25 A0 locations reproduce. This is a replay of syntax candidates, not evidence of product vulnerabilities or false positives.

The exact GN target is `ohos_fuzztest("DBPreferencesGetFuzzTest")`, grouped under `group("fuzztest")` with `testonly = true`. The fuzzer entry calls setup, sequentially invokes Get/Put helpers on the static `preferences_` shared pointer, then tears down. The target source contains no thread creation or parallel dispatch. It calls production Preferences APIs, which alone does not establish that this fuzz target ships or that production code reaches the same object concurrently.

## Immutable source identity and CLI

- Repository: `openharmony/distributeddatamgr_preferences`
- Commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Source: `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp`
- Source blob: `7a5c8a263fa4142579a3f4c6161c7d28b3350f50`
- Source SHA-256: `3e72c80d962f8dc9df6573328198c37072f4dddcd88dbc004ed2f72128d176b9`
- BUILD: `test/native/fuzztest/dbpreferencesget_fuzzer/BUILD.gn`; exact blob and SHA-256 are recorded in the machine replay.
- CLI: `python -m src.cli.main ohscan-run --repo-dir <pinned-source-checkout> --repository openharmony/distributeddatamgr_preferences --commit bff9efd79afc0d7d1ed22a63ff355f1600404596 --include test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp --detector ohscanner.cpp.shared_ptr_race`
- Result: completed; parser `complete: 1`; detector `ohscanner.cpp.shared_ptr_race` 0.5.1; 25 diagnostics at the 25 queue locations.

## A0 row mapping

All candidates use the same source identity, detector/rule family and A0 state (`not_testable / paused_pending_evidence`). The exact line and diagnostic ID for each are machine-recorded in `t37_preferences_get_fuzzer_replay_20261024.json`.

| A0 IDs | Source lines | Candidate |
| --- | --- | --- |
| CR-0066–CR-0073 | 43, 48, 50, 65, 66, 74, 75, 83 | `ohscanner.cpp.shared_ptr_race:ea649f7693617f0e` |
| CR-0074–CR-0081 | 91, 92, 100, 108, 109, 117, 125, 126 | same |
| CR-0082–CR-0090 | 134, 142, 143, 151, 159, 160, 168, 176, 177 | same |

## Assessment and outstanding evidence

Keep all 25 records `PARTIAL`, with frozen A0 states unchanged. The replay confirms the detector emits syntax candidates at the recorded locations on a complete parse. The test-only harness and sequential calls do not establish overlapping concurrent accesses. Remaining evidence must come from the exact product build and production call graph: whether this target is shipped, whether production paths share this Preferences instance, the object/thread ownership and synchronization protocol, an attacker-reachable trigger, and security impact. Until then, do not call these findings product vulnerabilities or confirmed false positives. No detector, tests, fixtures, or queue states were changed.

## Continuous objective / structured Vibe Coding prompt

**Role:** A-line Preferences `shared_ptr_race` independent audit and development lead.

**Sustained goal:** Distinguish fuzz-harness syntax candidates from product-reachable unsynchronized accesses to the same object, while preserving exact source identity and all unresolved evidence gaps.

**Input:** T37's pinned source/BUILD identities and 25-row replay; the related CR-0022–CR-0090 Preferences candidate family.

**Work sequence:** Bind the product BUILD and version; trace production callers and the same `Preferences` instance through reads, writes, locks/atomics, thread creation, dispatch, and destruction; only propose a generic detector change after reproducing a missed production root cause; add positive, fixed, safe, unrelated, renamed and partial controls; bind every run to commit/tree/blob/SHA, CLI version, scope and parser coverage.

**Completion gate:** An independent replay reproduces the candidate and the product target, reachable path, and unsynchronized concurrent access are evidenced. Otherwise preserve `PARTIAL/BLOCK` and identify the precise missing evidence.

**Boundaries:** Never label test-only harness findings as product vulnerabilities or false positives; do not edit frozen A0 states; do not hardcode by repository/CVE/function/hash; partial parses and zero findings are not safety evidence.
