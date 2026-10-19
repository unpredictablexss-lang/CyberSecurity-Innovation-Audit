# D38 — Preferences vector fuzzer CR-0091–CR-0096

**Status:** Exact A0 source and BUILD identities bound; current `shared_ptr_race` CLI replay completed with complete parsing and 6/6 queue-line candidates. The exact `DBPreferencesVectorFuzzTest` is inside a `testonly = true` fuzz group. The harness invokes production APIs sequentially; it does not establish product inclusion, reachability, overlapping concurrency, or impact. No production detector miss was demonstrated and no detector change was made. All six A0 rows remain `not_testable / paused_pending_evidence`, disposition PARTIAL.

**Artifacts:** [D38 report](d38_preferences_vector_fuzzer_20261024.md), [source-bound per-ID JSON](d38_preferences_vector_fuzzer_replay_20261024.json), [raw CLI output](d38_preferences_vector_fuzzer_20261024.json), [replay script](d38_preferences_vector_fuzzer_replay_20261024.py), [verifier](verify_d38_preferences_vector_fuzzer_20261024.py).

**Sustained objective and structured prompt:** Continue investigating production BUILD inclusion and reachable same-object concurrency; change the detector only for a concrete production-source miss with regression controls. The full structured prompt is in the D38 report.
