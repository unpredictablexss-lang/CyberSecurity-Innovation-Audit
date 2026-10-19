# T27 — Preferences CR-0020–CR-0024 independent acceptance

T27 bound all five rows to the original 345-row A0 CSV/JSON and exact Preferences commit/tree/blob/SHA. The current M2 `shared_ptr_race` CLI parsed both selected files completely and emitted two header candidates plus nineteen fuzz-harness syntax candidates. `dbpreferences_fuzzer.cpp` is the `ohos_fuzztest("DBPreferencesFuzzTest")` test target and its hits are not production vulnerability evidence; it invokes Preferences APIs from a fuzz harness. Source review does not establish same-object unordered overlap for the N-API accesses, runtime thread/finalizer semantics, shipped build, reachability or impact.

All five queue rows remain `not_testable / paused_pending_evidence`, and each case is **PARTIAL**. See [overall report](t27_preferences_source_audit_20261020.md), [raw CLI JSON](t27_preferences_header_and_fuzzer_20261020.json), and [read-only verifier](verify_t27_preferences_source_audit.py).
