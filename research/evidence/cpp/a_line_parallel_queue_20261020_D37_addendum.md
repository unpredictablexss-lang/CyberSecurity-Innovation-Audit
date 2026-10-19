# D37 — Preferences get-fuzzer CR-0066–CR-0090

**Status:** Exact source/build identities bound; current `shared_ptr_race` CLI replay completed with full parse and 25/25 queue-line candidates. The exact target is a `testonly` fuzz target. Harness calls are sequential and do not demonstrate production concurrency, shipping or reachability. No detector change is justified. All A0 records remain `not_testable / paused_pending_evidence`; disposition PARTIAL.

**Artifacts:** [D37 report](d37_preferences_get_fuzzer_20261024.md), [source-bound per-ID JSON](d37_preferences_get_fuzzer_replay_20261024.json), [raw CLI output](d37_preferences_get_fuzzer_20261024.json), [replay script](d37_preferences_get_fuzzer_replay_20261024.py), [verifier](verify_d37_preferences_get_fuzzer_20261024.py).

**Reusable structured prompt:** See the D37 report. Next evidence should establish production build inclusion and a reachable, overlapping, unsynchronized same-object access before changing the detector or promoting a product-level result.
