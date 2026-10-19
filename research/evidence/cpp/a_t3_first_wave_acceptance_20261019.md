# A-line first-wave independent acceptance (T3)

Date: 2026-10-19 (Asia/Shanghai)

## Checkout and frozen inputs

- Independent validation checkout started at PR #30 base `8ec5f56a12e90bba56953b39eb17faa20e154da9`.
- Frozen commits replayed without conflict, in order: D1 `d556cb079dcc97d39947b661120c4510c044abae`, D2 `e3e8507f47dd6030a32c5c529679ad915662ffa1`, T1 `a4b819419d7e38cd973ba0f4ce93ed05a485bef1`.
- Validation checkout HEAD after cherry-pick: `90d8260` (local cherry-pick IDs differ; the frozen commit contents were not edited).
- The original dirty A-line checkout was not accessed for writing.

## Independent checks

1. `python -m unittest tests.detectors.test_cpp_path_traversal_detector tests.detectors.test_cpp_memory_safety_detectors -v`: **23/23 passed**.
2. Re-ran D1 direct replay against `D:\openHarmonyScanner\openharmony\applications\standard\contacts_data\dataBusiness\contacts\src\contacts_data_ability.cpp`, explicitly passing `--parse-status partial`. It reproduced three path-to-file-sink candidates at lines 792, 793 and 797, detector/rule `ohscanner.cpp.path_traversal` / `ohcpp-path-traversal-source-to-file-sink-candidate-001` version `0.1.0`; run was `blocked`, file outcome `partial`, source hash `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`.
3. Independently reran D2 production CLI on exact local Ark Runtime objects in `D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git`, writing only under `%TEMP%\t3-ark`. Results matched D2's recorded semantic outcome and source identities: CVE-2025-0587 vulnerable/fixed **1/0**, complete parsing, candidate line 71, detector `integer_bounds` 0.2.0; CVE-2025-23420 vulnerable/fixed **5/0**, complete parsing, candidates lines 650, 653, 665, 666, 668, detector `bounds` 0.2.0. Both fixed versions had zero diagnostics. Raw JSON file hashes differ because execution timestamps/run IDs are regenerated; counts, commits, trees, source hashes, diagnostics and coverage were verified from the new outputs.
4. `python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp --repo .`: exit 0, no violations across all committed paths. Initial attempt with `--lane A` returned `unknown lane`; the base policy defines the A-line C/C++ owner lane as `cpp`.

## Case dispositions

| Work | Disposition | Independent evidence and remaining limit |
|---|---|---|
| D1 Contacts `PortraitFileName` path traversal | **PARTIAL / BLOCK** | Detector unit controls pass and the available checkout replay produces three candidates. The checkout bytes hash `c9d1f03d…` does not equal the pinned A0 Git object SHA-256 `70bb1da2…`; exact source object was unavailable. Parsing was explicitly set to partial, so this does not validate the exact vulnerable object or a safe negative. No trusted fixed Contacts source is bound, and Catalog remains owner-controlled; production CLI integration has not been demonstrated. Line 793's `DeleteFile(filePath)` candidate also depends on unverified bucket-field validation semantics. |
| D2 CVE-2025-0587 | **PARTIAL** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 1/0. Candidate aligns with the narrowing operation. A separately bound safe/unrelated control is absent, so not PASS. |
| D2 CVE-2025-23420 | **PARTIAL** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 5/0. Candidate locations align with the changed element accesses. Separately bound safe/unrelated controls are absent, so not PASS. |
| D2 libtiff CVE-2025-9900 | **PARTIAL** | Frozen evidence reports exact commits and scope but 0/0 with both files partial. This remains unknown, not a safe result. |
| D2 web_webview CVE-2026-27648 | **BLOCK** | Frozen evidence has only a fixed-source replay; vulnerable full translation unit is unavailable and prior full-TU parsing was partial. No differential acceptance is possible. |
| T1 13-row baseline matrix | **PASS as a status/evidence inventory; case outcomes remain mixed** | 13 rows reconcile 12 ledger cases plus Contacts. Distribution is 3 BLOCK, 8 PARTIAL, 2 N/A. Missing exact objects, parser partial, absent fixes and N/A exclusions are explicitly retained; curl's complete-parse baseline miss remains BLOCK, not silently called a detector success. Historical 0587/23420 rows correctly remain PARTIAL due to missing separately bound controls. |

## Overall first-wave decision

**PARTIAL.** The branch-scope check and focused tests pass. D2's two complete vulnerable/fixed historical pairs independently reproduce. The first wave does not establish end-to-end production coverage for Contacts, and the matrix intentionally retains blocked and partial cases. Do not describe these results as product vulnerability validation, scanner precision/recall, or a completed A-line coverage goal.

## Minimal follow-up items

1. Provide and hash-verify the exact Contacts commit/tree/blob bytes; rerun the candidate rule on those bytes with an independently established parser result. Obtain a trusted fixed source or keep fixed comparison BLOCK.
2. Owner review and, if accepted, Catalog registration for the Contacts rule; then run the production `ohscan-run` path and recheck scope.
3. Bind safe/unrelated controls to the D2 historical cases before upgrading their status from PARTIAL.
4. Recover the vulnerable full web_webview translation unit and establish adequate parsing before a differential verdict.
5. Keep T1's missing dsoftbus object pair and all partial/N/A cases in the validation queue; do not translate zero findings under partial coverage into safe.

## D3 incremental audit queue

D3 has not been frozen at the time of this report. When root supplies its frozen SHA, independently replay only the D3 delta in a separate validation checkout: curl CVE-2026-92391 vulnerable/fixed pair, libpng 33416 and 46675 with their exact source/fix-parent identities and parser statuses, and cJSON 67215/67216 with safe/unrelated controls where no trusted fix exists. Reconfirm rule identity, finding locations, source hashes, parse coverage, candidate status semantics, and C++ scope. Keep unavailable source, incomplete parsing, or absent fixed objects as BLOCK/PARTIAL.
