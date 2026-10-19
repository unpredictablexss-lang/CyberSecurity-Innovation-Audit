# T36 addendum — Preferences BaseValue fuzz family

- Independent test line audited A0 CR-0041–CR-0065 from the exact pinned source commit/tree/blob/SHA.
- Current production shared_ptr race CLI v0.5.1: complete one-file parsing, 25 syntax candidates; all 25 original source lines map one-to-one.
- The exact GN target is `ohos_fuzztest("DBPreferencesBaseValueFuzzTest")`, under `group("fuzztest")` with `testonly = true`. Harness calls invoke Preferences APIs sequentially; product-image inclusion, production path/reachability, actual concurrency, attacker control and impact remain unknown.
- Keep all IDs at `not_testable / paused_pending_evidence` and PARTIAL. Do not classify the fuzz harness candidates as confirmed vulnerabilities or confirmed false positives.
- A0 remains 345/345 with original IDs and statuses unchanged. No detector/test/fixture changes.
- Evidence: [T36 audit](t36_preferences_basevalue_audit_20261024.md), [JSON](t36_preferences_basevalue_audit_20261024.json), [raw CLI run](t36_preferences_basevalue_cli_20261024.json), [verifier](t36_preferences_basevalue_audit.py).
