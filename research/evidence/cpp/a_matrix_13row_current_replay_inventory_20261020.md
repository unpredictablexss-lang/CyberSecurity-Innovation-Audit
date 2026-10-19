# A-line original 13-row current-CLI replay inventory (2026-10-20)

Scope: source-linked status reconciliation against `a_static_baseline_20261019/matrix.json`, T12, T2, T4 and T5 materials. “Current CLI” means a pinned-source replay through the production `ohscan-run` CLI on the integrated scanner code; a direct detector/fragment call is labeled separately. This inventory does not upgrade PARTIAL/BLOCK to a vulnerability confirmation.

| Original row | Source binding / latest replay evidence | Fresh CLI evidence status | Current disposition / gap |
|---|---|---|---|
| libtiff CVE-2025-9900 | Exact upstream pair in baseline matrix; T-libtiff independent package exists | Existing pinned CLI evidence; separate follow-up assigned elsewhere, so this inventory does not re-adjudicate it | PARTIAL: source files parse partial; retain caller/build/profile limits |
| libpng CVE-2026-46675 (GHSA-qvg3-h654-xq3j) | Exact upstream `pngrutil.c` identities in T11/T12; T61/D54 source and CLI evidence | Source-bound current CLI evidence exists in T61/D54, but whole-file parsing is partial | PARTIAL/BLOCK: zero findings on both incomplete sides is inconclusive |
| libpng CVE-2026-33416 (GHSA-m4pc-p4q3-4c7j) | T12 exact fragment/source pairs; T61/D54 replay package | T12 direct fragment detector replay and T61/D54 source-bound CLI evidence; whole-file parsing partial | PARTIAL/BLOCK: no successful vulnerable/fixed differential |
| curl CVE-2026-92391 | Exact vulnerable/fixed upstream commits and `lib/mime.c` in baseline matrix; T2 links D32/T32 | Existing pinned CLI differential; current paired run is complete parse (see linked evidence) | T12 PASS for static pair differential; keep product/build scope limits |
| cJSON CVE-2026-67216 compare cost | Exact OpenHarmony source commit in baseline matrix; T60 pins current source/CLI and controls | Current CLI replay exists, but evidence date is unconfirmed by T3/T5 | PARTIAL/BLOCK: candidate at `cJSON.c:3161`; no trusted fixed source; date provenance BLOCK |
| cJSON CVE-2026-67215 tree amplification | Exact OpenHarmony source commit in baseline matrix; T60 pins current source/CLI and controls | Current CLI replay exists, but evidence date is unconfirmed by T3/T5 | PARTIAL/BLOCK: candidates at `cJSON_Utils.c:932,950`; no trusted fixed source; date provenance BLOCK |
| OpenHarmony web_webview CVE-2026-27648 | Baseline row pins `openharmony/web_webview` commits `a15cbf4…`/`fa0d92c…`; T12 also tested a distinct `OpenHarmony-TPC/chromium_src` source pair | No verified replay bound to the baseline row’s exact repository/commit pair in the accepted T12/T2 packages; the T12 chromium_src replay is related evidence, not a substitute | PARTIAL: exact-original-row fresh replay remains outstanding; T12’s alternate source pair had fragment differential and partial full-file parse |
| OpenHarmony CVE-2025-26690 dSoftBus | T62 pins exact vulnerable/fixed objects and A0 row | Current pinned CLI replay verified by T62 | PARTIAL/BLOCK: five candidates vs zero same-rule; semantic coverage partial and source-bound safe/unrelated controls absent |
| OpenHarmony CVE-2025-0587 | Baseline exact pair rerun in this package; identities below | Fresh current CLI vulnerable/fixed pair, full parse | 1/0 static candidate differential; keep PARTIAL pending safe/unrelated controls and product reachability |
| OpenHarmony CVE-2025-23420 | Baseline exact pair rerun in this package; identities below | Fresh current CLI vulnerable/fixed pair, full parse | 5/0 static candidate differential; keep PARTIAL pending safe/unrelated controls and product reachability |
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
