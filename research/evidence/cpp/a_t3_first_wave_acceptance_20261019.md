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

## Second-wave independent acceptance (D3 and T2)

Date: 2026-10-19 (Asia/Shanghai). The following commits were introduced into this independent checkout from PR #30 base without conflict:

- D3 `d8c7a49860cb5635632f76be7319cf38e2129179` (local cherry-pick `3e76360`).
- T2 `75df609f7f76f11dd31faa695eb3d6e549d02729` (local cherry-pick `b87e2d4`).

### D3 replay and fixture results

- Independently reran production `ohscan-run` on local pinned curl objects from `D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git`, explicit `light-ast` default profile and one-file scope `lib/mime.c`, detector `ohscanner.cpp.resource_lifetime` 0.2.0. Vulnerable commit/tree `01346829096c61b372692f6dc43ffa778c6caccd` / `6ae23d9333713707a02588b44ed238a50e8b3bde`: complete parse, 1 candidate at `lib/mime.c:1118`, rule `ohcpp-resource-lifetime-recursive-cleanup-candidate-003`, source SHA-256 `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d`. Fixed commit/tree `d7546809d5bd548b69ec49fca26565c8f6f0d344` / `52a8416729366487cdd3b6012071f5f8370e769f`: complete parse, 0 findings. Run reports were written under `%TEMP%\t3-curl`, not over the committed evidence.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: **5/5 passed**. This independently exercised the hash-bound recursive callback-cycle positive, detached-callback fixed control, unrelated recursive-cleanup control, existing lifetime controls, partial input and budget behavior.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py'`: **148/148 passed**.
- **D3 curl: PASS for the static source-level differential only.** Complete parsing and vulnerable/fixed results reproduce. This is not product-build, call-path, attacker reachability, or impact confirmation.
- **libpng CVE-2026-46675: PARTIAL.** Frozen D3 evidence leaves the selected vulnerable/fix-parent/fixed/OH targets partial; the cited archive/fix identity does not establish a complete parser target here.
- **libpng CVE-2026-33416: PARTIAL.** The selected source units remain parser partial and have no rule candidate; no safe conclusion follows.
- **cJSON CVE-2026-67215: PARTIAL/BLOCK.** Exact OH commit/tree is recorded, but the two-file run has a partial `cJSON.c`, zero findings and no trusted fixed source. The JSON Patch amplification then recursive-delete root cause is distinct from the D3 callback-cycle rule.
- **cJSON CVE-2026-67216: PARTIAL/BLOCK.** Exact OH commit/tree is recorded, but `cJSON.c` parses partial, there is no trusted fixed source, and exponential compare cost is outside this rule's root cause.

### T2 inventory integrity and scope

Independently ran `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: exit 0 and `overall_ok=true`. All 97 source-manifest files (4,364,747 bytes) were present and matched; all 345 IDs/source keys reconcile; JSON and CSV each contain 345 unique rows; original statuses remain 9 `not_reproduced` and 336 `not_testable`; queue counts are 9 `queued_not_reproduced`, 5 `queued_first_batch`, and 331 `paused_pending_evidence`; no missing next-action/ranking fields; all 14 verifier assertions passed. A separate check confirmed the 7 files named in `artifact_hashes.json` have matching sizes and SHA-256 values. The verifier's generated outputs were byte-for-byte unchanged after rerun.

**T2 disposition: PASS for reproducible queue and source-package reconciliation.** This verifies preservation and sorting of A0 evidence, not the truth of 345 candidate conclusions or current availability of every upstream source object.

`python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` and `git diff --check` both pass with no violations. The T1 matrix, D1 replay record, D2 replay record and this report's first-wave section are unchanged from first-wave acceptance commit `333ba323dccb9d9c507b39227a37ec6f86b5731`.

## Consolidated first + second wave decision

**PARTIAL overall.** First-wave results remain: D1 Contacts PARTIAL/BLOCK; D2 CVE-2025-0587 and CVE-2025-23420 PARTIAL (complete vulnerable/fixed differentials, but no separately bound safe/unrelated controls); libtiff PARTIAL; web_webview BLOCK; and T1's 13-row matrix PASS as an evidence/status inventory (3 BLOCK, 8 PARTIAL, 2 N/A). Second wave adds a passing static curl differential and a passing T2 queue-integrity audit. The remaining libpng and cJSON cases stay PARTIAL/BLOCK. All source-only results remain candidate evidence, not product vulnerability or safety determinations.

## Minimum remaining work

1. Contacts: retrieve exact pinned A0 commit/tree/blob bytes, establish parser status, review the `DeleteFile(filePath)` bucket inputs, and obtain a trusted fixed source or retain BLOCK; owner review/Catalog admission and production CLI replay remain separate.
2. D2 historical cases: bind safe/unrelated controls; keep both PARTIAL until then.
3. libtiff/web_webview: address the required parse/context blockers; recover the vulnerable full web_webview source before any differential judgment.
4. libpng 46675/33416: establish adequate parser coverage and source-to-product provenance before claiming more than PARTIAL.
5. cJSON 67215/67216: model their distinct root causes with separate rule identities and positive plus safe/unrelated controls; do not use the callback-cycle rule as coverage.
6. Keep dsoftbus exact-object absence, N/A exclusions, and all 345 A0 queue entries in the task tree with their current status semantics.
