# A-line original 13-row current-CLI replay inventory (2026-10-20)

Scope: source-linked status reconciliation against `a_static_baseline_20261019/matrix.json`, T12, T2, T4 and T5 materials. “Current CLI” means a pinned-source replay through the production `ohscan-run` CLI on the integrated scanner code; a direct detector/fragment call is labeled separately. This inventory does not upgrade PARTIAL/BLOCK to a vulnerability confirmation.

| Original row | Source binding / latest replay evidence | Fresh CLI evidence status | Current disposition / gap |
|---|---|---|---|
| libtiff CVE-2025-9900 | Exact upstream pair in baseline matrix; current evidence in the 2026-10-20 webview/libtiff test package | Fresh current-CLI two-file vulnerable/fixed replay is 0/0 with both files partial; bounded complete function probe is 1/0 on the vulnerable/fixed slices | PARTIAL/BLOCK: full-file zero is inconclusive; bounded probe uses a documented type shim and does not establish capacity, build, reachability or impact |
| libpng CVE-2026-46675 (GHSA-qvg3-h654-xq3j) | Exact upstream `pngrutil.c` identities in T11/T12; T61/D54 source and CLI evidence | Source-bound current CLI evidence exists in T61/D54, but whole-file parsing is partial | PARTIAL/BLOCK: zero findings on both incomplete sides is inconclusive |
| libpng CVE-2026-33416 (GHSA-m4pc-p4q3-4c7j) | T12 exact fragment/source pairs; T61/D54 replay package | T12 direct fragment detector replay and T61/D54 source-bound CLI evidence; whole-file parsing partial | PARTIAL/BLOCK: no successful vulnerable/fixed differential |
| curl CVE-2026-92391 | Exact vulnerable/fixed upstream commits and `lib/mime.c` in baseline matrix; T2 links D32/T32 | Existing pinned CLI differential; current paired run is complete parse (see linked evidence) | T12 PASS for static pair differential; keep product/build scope limits |
| cJSON CVE-2026-67216 compare cost | Exact OpenHarmony source commit in baseline matrix; T60 pins current source/CLI and controls; T2 fresh replay package binds the current run | Fresh current-CLI replay at scanner `81dd4aea9bb51522ac912b33504ef0d2ddb79089`; exact root scope, 1 candidate at `cJSON.c:3161`, parser partial, detector coverage partial/run blocked | PARTIAL/BLOCK: this replay resolves date provenance for this run only; no trusted fixed source or same-scope safe/unrelated comparison, and parser/detector coverage remain partial |
| cJSON CVE-2026-67215 tree amplification | Exact OpenHarmony source commit in baseline matrix; T60 pins current source/CLI and controls; T2 fresh replay package binds the current run | Fresh current-CLI replay at scanner `81dd4aea9bb51522ac912b33504ef0d2ddb79089`; exact root scope, candidates at `cJSON_Utils.c:932,950`, parser complete but detector coverage partial/run blocked | PARTIAL/BLOCK: this replay resolves date provenance for this run only; no trusted fixed source or same-scope safe/unrelated comparison, and detector coverage remains partial |
| OpenHarmony web_webview CVE-2026-27648 | Baseline row pins `openharmony/web_webview` commits `a15cbf4…`/`fa0d92c…`; exact full-file CLI and exact-A0-derived fragment replays are in `webview_exact_a0_20261020/` and `webview_exact_a0_fragments_20261020/` | Exact full-file pair remains partial/blocked with zero findings. Source-byte-bound function fragments parse complete and reproduce six patched-root candidates versus zero, plus six ordinary residuals on both sides; renamed positive 1/1, safe/unrelated 0/0. Partial control keeps aggregate blocked | PARTIAL/BLOCK: function-level root candidate coverage is demonstrated on exact A0 source bytes, but full target TU parsing remains blocked; fragments do not establish product reachability/impact, and blocked aggregates are not a safety/fixed verdict |
| OpenHarmony CVE-2025-26690 dSoftBus | T62 pins exact vulnerable/fixed objects and A0 row; T62 follow-up binds four local guard-before-use controls in the vulnerable source blob | Current pinned CLI replay verified by T62; 5/0, syntax complete, semantic coverage 0/1 and run blocked | PARTIAL/BLOCK: the source controls are manually reviewed but not scanner-validated while semantic coverage is blocked; no product/reachability/impact evidence |
| OpenHarmony CVE-2025-0587 | Baseline exact pair rerun in this package; exact vulnerable-source DataView adjacent control is in `t_source_test_file_scans_20261020/` | Fresh current CLI vulnerable/fixed pair and source-bound adjacent control, all full parse | 1/0 vulnerable/fixed differential; reviewed DataView guarded access is quiet but is not the same TypedArray atomic API. PARTIAL pending root-specific control and product reachability/impact |
| OpenHarmony CVE-2025-23420 | Baseline exact pair rerun in this package; exact vulnerable-source `SortElementsByInsertionSort` method-local control is in `t_source_test_file_scans_20261020/` | Fresh current CLI vulnerable/fixed pair and same-file control review, full parse | 5/0 vulnerable/fixed differential; all five findings remain in vulnerable `SortElementsByObject`, none in lines 603–636 control method. PARTIAL pending further root-specific controls and product reachability/impact |
| OpenHarmony CVE-2025-20042 | A0 row has no source identities; baseline records explicit N/A | Not scanned by design | N/A, not a safety conclusion |
| OpenHarmony CVE-2025-21098 | A0 row has no source identities; baseline records explicit N/A | Not scanned by design | N/A, not a safety conclusion |
| Contacts PortraitFileName path traversal | T20 exact OpenHarmony Git object/source SHA and CLI replay | Current source-bound detector replay exists in T20 | PARTIAL/BLOCK: no trusted fixed source; parser/aggregate limitations remain |

## Freshly replayed historical pairs

| Case / side | Commit | Tree | File blob | File SHA-256 | Detector/version | Parse / findings |
|---|---|---|---|---|---|---|
| CVE-2025-0587 vulnerable | `cae11f121c030a90ba41d8e4d866f91292f25892` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `7fd67717571c6d8fe7b10bf294998e952dc61e36` | `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541` | `ohscanner.cpp.integer_bounds` 0.2.0 | complete; 1 candidate at `atomic_helper.cpp:71`, `ohcpp-integer-bounds-narrow-index-candidate-003` |
| CVE-2025-0587 fixed | `5aa9c035e98911ec7ed28065a2138c2709792a42` | `05ac3902979e37ae08efa2d1e3ed32472a69d0cc` | `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` | `39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b` | `ohscanner.cpp.integer_bounds` 0.2.0 | complete; 0 findings |
| CVE-2025-23420 vulnerable | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` | `ohscanner.cpp.bounds` 0.3.0 | complete; 5 candidates at `js_array.cpp:650,653,665,666,668`, `ohcpp-memory-bounds-element-access-candidate-003` |
| CVE-2025-23420 fixed | `1b23531531e768398682582969c2a9f17e72cafe` | `52f27683e2f6e1ba8272aee7d5202c73059e10b4` | `58266855967e3dc4af97721d3a2fc5417cb887b6` | `f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6` | `ohscanner.cpp.bounds` 0.3.0 | complete; 0 findings |

Exact commands for all four inputs:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/a_matrix_history_20261020/cve2025-0587-vulnerable.json --md-out research/evidence/cpp/a_matrix_history_20261020/cve2025-0587-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/a_matrix_history_20261020/cve2025-0587-fixed.json --md-out research/evidence/cpp/a_matrix_history_20261020/cve2025-0587-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/a_matrix_history_20261020/cve2025-23420-vulnerable.json --md-out research/evidence/cpp/a_matrix_history_20261020/cve2025-23420-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 1b23531531e768398682582969c2a9f17e72cafe --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/a_matrix_history_20261020/cve2025-23420-fixed.json --md-out research/evidence/cpp/a_matrix_history_20261020/cve2025-23420-fixed.md
```

The machine verifier recomputes Git tree/blob and SHA-256 identities, then checks each CLI report’s commit, declared scope, rule/version, parse status, diagnostic count and locations:

```powershell
python research/evidence/cpp/verify_a_matrix_history_20261020.py --source-git-dir D:\openHarmonyScanner\arkruntime-holdout-history --evidence-dir research/evidence/cpp/a_matrix_history_20261020
```

Result: `PASS_SOURCE_BOUND_STATIC_DIFFERENTIAL`, errors `[]`. The machine-readable summary is `a_matrix_history_20261020/matrix_history_replay_20261020.json`. Existing safe/unrelated controls were not rerun in this task; the two historical rows therefore remain PARTIAL overall despite the complete parsing and source-pair differentials.

## Focused integer/bounds detector controls (2026-10-20)

Command:

```powershell
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v
```

Result: 20 tests passed. Coverage includes integer/bounds positive shapes, checked/fixed and safe shapes, unrelated accessors/operators, deterministic output, partial-parse and budget fail-closed behavior, and hash-bound fixture control classes. This validates the detector control suite on the integrated checkout; it does not replace the source-bound safe/unrelated controls or product reachability evidence missing from CVE-2025-0587 and CVE-2025-23420. Those rows remain PARTIAL.

## Webview detector-gap audit (2026-10-20)

An independent development review found no supported `bounds` rule change: the exact source-derived Chromium Flowbuffer function fragments retain the D11 patched-root differential (six vulnerable-root candidates versus zero in the fixed fragment) with safe/unrelated controls quiet. The six ordinary-argument residuals are not proven safe or vulnerable and remain unresolved. The exact A0 `openharmony/web_webview` full-file CLI pair remains partial/blocked with zero diagnostics on both sides, so it does not establish a miss or a safe/fixed differential. See `d15_webview_residuals_20261020/review.md` and `webview_exact_a0_20261020/README.md`.

Next development action: request a parser-owner assessment of localized recovery for the Flowbuffer region in `nweb_handler_delegate.cc`, keeping this separate from bounds-rule changes. Reuse the exact A0 pair and D11 safe/unrelated/renamed/partial controls; require target-region coverage before judging findings. No parser, detector, Catalog, API, or fixture change was made in this audit.

## Source-bound upstream test-file observations (2026-10-20)

The independent test line scanned the unmodified upstream `atomic_helper_test.cpp` at the CVE-2025-0587 vulnerable-source commit and `js_array_test.cpp` at the CVE-2025-23420 vulnerable-source commit. Both files parsed completely with zero diagnostics. Semantic review found neither file to be a directly relevant safe/unrelated control for its reported root cause; the 0587 test covers legal indices, while the 23420 test does not establish safe `SortElementsByObject` behavior. Keep both rows PARTIAL. Raw CLI outputs, exact identities, commands, and verifier are in `t_source_test_file_scans_20261020/README.md`.

## Historical integer/bounds closeout follow-up (2026-10-30)

D23 replayed exact CVE-2025-0587 vulnerable/fixed sources with `integer_bounds@0.2.0` (1/0) and CVE-2025-23420 with `bounds@0.3.0` (5/0); all four selected source files parsed completely. T3 independently bound a same-commit `SortIndexedProperties` comparator-snapshot control for 23420; the file parsed completely and produced zero bounds candidates. These results support existing root-positive/fixed differentials and a narrow same-semantic control observation, but do not establish product reachability/impact or a root-specific 0587 safe control. No detector change was made; both rows remain PARTIAL/BLOCK. See [D23](d23_integer_bounds_gap_20261030/README.md) and [T3](t3_integer_source_controls_20261020/README.md).

## Additional A0 fresh replay (2026-10-20)

T5 independently refreshed the current-CLI replay for D51 HUKS CR-0341 and D52 global_i18n CR-0255/CR-0256. The exact queue-bound source identities were reverified; all three scopes parsed completely and `shared_ptr_race@0.5.1` returned zero findings. This does not validate or clear the original findings: retain all three A0 rows as `not_testable`, PARTIAL/BLOCK, and retain BLOCK on the earlier future-dated run artifacts. See [T5 report](t5_d51_d52_fresh_replay_20261020/README.md).
