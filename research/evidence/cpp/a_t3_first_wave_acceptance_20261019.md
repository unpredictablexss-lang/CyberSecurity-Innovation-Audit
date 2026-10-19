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
| D1 Contacts `PortraitFileName` path traversal | **PARTIAL** | Initial first-wave replay used a checkout copy, not the exact pinned source. A subsequent T3 follow-up retrieved the specified A0 blob, verified commit/tree/blob/SHA-256, independently established complete parser coverage (0 issues; 57 functions, 525 calls), and reproduced three candidates on those exact bytes. The detector's finding identity remains `partial`; no trusted fixed source is bound; Catalog is not registered and production CLI integration has not been demonstrated. The candidate at `DeleteFile(filePath)` also depends on bucket-field validation semantics. |
| D2 CVE-2025-0587 | **PARTIAL** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 1/0. Candidate aligns with the narrowing operation. A separately bound safe/unrelated control is absent, so not PASS. |
| D2 CVE-2025-23420 | **PARTIAL** | Exact pinned vulnerable/fixed commits and complete parsing independently replayed at 5/0. Candidate locations align with the changed element accesses. Separately bound safe/unrelated controls are absent, so not PASS. |
| D2 libtiff CVE-2025-9900 | **PARTIAL** | Frozen evidence reports exact commits and scope but 0/0 with both files partial. This remains unknown, not a safe result. |
| D2 web_webview CVE-2026-27648 | **BLOCK** | Frozen evidence has only a fixed-source replay; vulnerable full translation unit is unavailable and prior full-TU parsing was partial. No differential acceptance is possible. |
| T1 13-row baseline matrix | **PASS as a status/evidence inventory; case outcomes remain mixed** | 13 rows reconcile 12 ledger cases plus Contacts. Distribution is 3 BLOCK, 8 PARTIAL, 2 N/A. Missing exact objects, parser partial, absent fixes and N/A exclusions are explicitly retained; curl's complete-parse baseline miss remains BLOCK, not silently called a detector success. Historical 0587/23420 rows correctly remain PARTIAL due to missing separately bound controls. |

## Overall first-wave decision

**PARTIAL.** The branch-scope check and focused tests pass. D2's two complete vulnerable/fixed historical pairs independently reproduce. The first wave does not establish end-to-end production coverage for Contacts, and the matrix intentionally retains blocked and partial cases. Do not describe these results as product vulnerability validation, scanner precision/recall, or a completed A-line coverage goal.

## Minimal follow-up items

1. Review the `DeleteFile(filePath)` bucket inputs and obtain a trusted fixed source or retain BLOCK for the fixed comparison.
2. Owner review and, if accepted, Catalog registration for the Contacts rule; then run the production `ohscan-run` path and recheck scope.
3. Bind safe/unrelated controls to the D2 historical cases before upgrading their status from PARTIAL.
4. Recover the vulnerable full web_webview translation unit and establish adequate parsing before a differential verdict.
5. Keep T1's missing dsoftbus object pair and all partial/N/A cases in the validation queue; do not translate zero findings under partial coverage into safe.

## D3 incremental audit queue (completed)

This was the first-wave handoff checklist. D3 and T2 were independently replayed below after their frozen commits were provided. Remaining partial/blocked cases and their minimum follow-up actions are listed in the consolidated section.

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

**PARTIAL overall.** First-wave results remain: D1 Contacts PARTIAL (exact A0 source and complete parser coverage confirmed; detector finding identity is partial, and fixed source/Catalog/production CLI integration remain); D2 CVE-2025-0587 and CVE-2025-23420 PARTIAL (complete vulnerable/fixed differentials, but no separately bound safe/unrelated controls); libtiff PARTIAL; web_webview BLOCK; and T1's 13-row matrix PASS as an evidence/status inventory (3 BLOCK, 8 PARTIAL, 2 N/A). Second wave adds a passing static curl differential and a passing T2 queue-integrity audit. The remaining libpng and cJSON cases stay PARTIAL/BLOCK. All source-only results remain candidate evidence, not product vulnerability or safety determinations.

## Minimum remaining work

1. Contacts: retrieve exact pinned A0 commit/tree/blob bytes, establish parser status, review the `DeleteFile(filePath)` bucket inputs, and obtain a trusted fixed source or retain BLOCK; owner review/Catalog admission and production CLI replay remain separate.
2. D2 historical cases: bind safe/unrelated controls; keep both PARTIAL until then.
3. libtiff/web_webview: address the required parse/context blockers; recover the vulnerable full web_webview source before any differential judgment.
4. libpng 46675/33416: establish adequate parser coverage and source-to-product provenance before claiming more than PARTIAL.
5. cJSON 67215/67216: model their distinct root causes with separate rule identities and positive plus safe/unrelated controls; do not use the callback-cycle rule as coverage.
6. Keep dsoftbus exact-object absence, N/A exclusions, and all 345 A0 queue entries in the task tree with their current status semantics.

## Contacts exact-source identity follow-up

Root supplied the read-only project-object archive `D:\openHarmonyScanner\openharmony\.repo\project-objects\applications_contacts_data.git` for a follow-up to D1. From that archive, T3 independently verified:

- Commit `b02aadfc2d801ee30573fcb2d13490298e146fea` tree is `ef183625ccbc842f47b076eb75e68b665d7c21c6`.
- `dataBusiness/contacts/src/contacts_data_ability.cpp` at that commit is blob `32c6a26a9a6c1f4ec3172f45bc3dbe4d3668abe6`, 80,944 bytes, SHA-256 `70bb1da2cb107649dd2bb39358aeb56983f613ee0bdd6216d805bbd39c8df383`.
- Independently extracted the blob byte-for-byte to a temporary file. The earlier replay used `--parse-status partial` and returned blocked; the follow-up independently parsed the same bytes as complete and reran `direct_replay.py <temp-file> --parse-status complete`. Detector `ohscanner.cpp.path_traversal` 0.1.0 returned `completed`/`complete` and three candidates at lines 789, 790 and 794 under rule `ohcpp-path-traversal-source-to-file-sink-candidate-001`; all diagnostics carry the exact source hash above and `identity_quality=partial`.
- The older cited commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` resolves to tree `2054824c04bb403eeea128a9262edfb3001efa4f` and this path resolves to blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, which is different from A0's specified blob. Thus the exact A0 source identity is now **confirmed against b02aadf**, and the earlier `341cc3` identity should not be used as that A0 binding.

**Updated D1 disposition: PARTIAL, not identity-blocked.** Exact vulnerable source binding and candidate reproduction pass. On that exact 80,944-byte blob, an independent `src.parser.ast.parse_source(text, language='cpp')` run returned parse status `complete`, 0 parse issues, 57 functions, and 525 calls. The direct harness was then run with `--parse-status complete`; it returned `completed`/`complete`, three findings at lines 789, 790 and 794, and no parser limitation. These findings still carry `identity_quality=partial`, so complete syntax/parser coverage does not upgrade finding identity or establish the source-to-sink security conclusion. This is a direct detector harness, **not production `ohscan-run`**, because Catalog registration is absent. No independently verified fixed Contacts source is available; the fixed comparison and production integration remain BLOCK. The T1 13-row artifact remains an unchanged *before* baseline at PR #30 base: its original Contacts row saying that the baseline had no registered detector and could not run the intended production path remains historically accurate.
