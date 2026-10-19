# C13 per-candidate product gate audit

- Source review: `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`
- Pinned blob: `dbedea677c8dc70c1b0066c7bc52df27bcff06ea` / `732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240`
- Reviewed dispositions: 28; candidate/explicit-unknown rows: 26
- Ark parent/fix product candidates: 16
- Gate decision: `NOT_ADMITTED`

## Ark product candidates

| Case | Source | Build | Entry | Permission | Trigger | Sensitive op | CIA | PoC | Fix retest |
|---|---|---|---|---|---|---|---|---|---|
| OH-I7E0FM-TYPEDARRAY-FILTER-ABRUPT-COMPLETION | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-ARRAY-CALLBACK-ABRUPT-COMPLETION-HISTORY-VARIANT | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-ARRAY-EVERY-WRAPPED-CALLBACK-EXCEPTION-I5XZRO | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-ARRAY-FINDINDEX-STABLE-ABRUPT-RETURN-C333 | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-RUNTIME-CALLINFO-CONSTRUCTION-PENDING-EXCEPTION-I7K7L6 | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-RUNTIME-NEWCALLINFO-EXCEPTION-GUARD-IB40SU | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-RUNTIME-INSTANCEOF-EXCEPTION-RETURN-VALUE-I7SDBG | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-SHAREDARRAY-FINDINDEX-EXCEPTION-PROPAGATION-PARTIAL-2A9BCFB | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-COMPILER-REFLECT-APPLY-PENDING-EXCEPTION-IAO7GO | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-MAP-STORE-TYPE-ORIGIN-CVE-2025-24304 | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-MAP-NEWARRAY-PENDING-EXCEPTION-IC7B8Q | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-CREATEFROMTYPEDARRAY-BYTE-LENGTH-OVERFLOW-I7KZJ7 | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-CONSTRUCTOR-LENGTH-NARROWING-I7W51D | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-DATAVIEW-INDEX-WIDTH-AND-BOUNDS-IB8BCA | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-FILTER-RESULT-TYPE-ORIGIN-IBS5YG | recorded_complete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |
| ARK-TYPEDARRAY-FILTER-RECEIVER-TYPE-GUARD-IAO7E8 | recorded_incomplete | unknown | unknown | unknown | unknown | unknown | unknown | not_run | not_run |

## Reviewed disposition rows

| # | Identity | Disposition | Source identity | Product gate |
|---:|---|---|---|---|
| 1 | CVE-2026-46675 | candidate-component-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 2 | CVE-2025-9900 | candidate-component-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 3 | CVE-2026-92391 | candidate-component-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 4 | CVE-2026-67216 | candidate-component-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 5 | CVE-2026-67215 | candidate-component-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 6 | CVE-2026-27648 | explicit-unknown-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 7 | CVE-2025-25212 | candidate-historical-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 8 | CVE-2022-45877 | explicit-unknown-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 9 | CVE-2026-58313 | candidate-static-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 10 | CVE-2026-28733 | candidate-static-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 11 | CVE-2026-25850 | candidate-static-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 12 | CVE-2026-28751 | explicit-unknown-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 13 | CVE-2025-27247 | candidate-historical-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 14 | CVE-2025-57052 | candidate-fixed-shape-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 15 | CVE-2026-33636 | candidate-fixed-patch-present-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 16 | CVE-2026-92392 | not-applicable-version-bound | not_applicable | NOT_APPLICABLE |
| 17 | CVE-2026-9079 | explicit-unknown-fixed-not-locally-verified | explicit_unknown | NOT_ADMITTED |
| 18 | LOCAL-GROUP-DELETE | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 19 | LOCAL-REQUEST-PATH | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 20 | LOCAL-REQUEST-FD | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 21 | LOCAL-DEVICEAUTH-NEGATIVE-LENGTH | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 22 | LOCAL-PASTEBOARD-HISTORICAL-READ | candidate-historical-overlap-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 23 | MANUAL-UPDATE-DEV-SIGNING | explicit-unknown-bounded-artifact-p12-json5-no-cpp-coverage | explicit_unknown | NOT_ADMITTED |
| 24 | MANUAL-APPDOMAIN-PRIORITY | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 25 | MANUAL-STORAGE-STATISTICS | candidate-control-synthetic-replay-only-source-unavailable | explicit_unknown | NOT_ADMITTED |
| 26 | MANUAL-SECURITY-ASSET-CROSS-ACCOUNT | explicit-unknown-bounded-language-rust-no-cpp-coverage | explicit_unknown | NOT_ADMITTED |
| 27 | EXCLUDED-CVE-2026-33416 | not-applicable-no-independent-source-case | not_applicable | NOT_APPLICABLE |
| 28 | EXCLUDED-CVE-2026-34757 | not-applicable-no-independent-source-case | not_applicable | NOT_APPLICABLE |

All missing product evidence remains explicit unknown/not-run. Source-shape candidates and fixed controls are not product vulnerability confirmation.
