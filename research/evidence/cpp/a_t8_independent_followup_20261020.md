# T8 independent A-line follow-up audit

Date: 2026-10-20 (Asia/Shanghai)

Checkout: `D:\openHarmonyScanner\worktrees\a-t8-followup-20261020`

Branch: `codex/a-t8-followup-20261020`

Base: `983afb846ceaa34daf690c39e4918703c4ac99a7`

Role: independent evidence review. No detector, test, fixture, or development source was edited.

## Results

| Case | T8 status | Independent evidence and limits |
|---|---|---|
| libtiff CVE-2025-9900 / D9 | **PARTIAL** | Exact vulnerable and fixed commits, trees, blobs, and file SHA-256 values match the local Git object store. D9 CLI JSON reports both two-file scopes `partial: 2`, detector `blocked`, 0 findings. D7's positive control does not upgrade this full-source result. |
| web_webview CVE-2026-27648 / D9 and T7 | **PARTIAL** | T8 independently resolved vulnerable-parent and fixed-merge commit/tree/blob IDs and SHA-256 values from the read-only audit mirror. Full translation units remain partial/blocked with 0 findings. Historical v0.3.6 source-derived function-fragment differential is 6 vulnerable root findings vs 0 fixed root findings; 6 distinct ordinary-loop findings remain on each side. Fragment results do not establish a full-source or current-version PASS. |
| cJSON CVE-2026-67216 compare cost / D10 | **PARTIAL**, fixed comparison **BLOCK** | Exact commit/tree/blob/bytes/SHA-256 verified from local Git objects. Candidate at `cJSON.c:3161`; that file and paired detector analysis are partial. No trusted fixed source is bound. |
| cJSON CVE-2026-67215 tree amplification / D10 | **PARTIAL**, fixed comparison **BLOCK** | Exact commit/tree/blob/bytes/SHA-256 verified from local Git objects. Candidate at `cJSON_Utils.c:861`, file parse complete but paired run partial because `cJSON.c` is partial. No trusted fixed source is bound. |
| libpng CVE-2026-46675 / D10 | **PARTIAL** | Vulnerable commit/tree/blob/SHA verified. Fixed bytes match the claimed blob OID and SHA-256 from a local snapshot, but the claimed fixed commit-to-tree link was not available in the checked Git object store. Both files were partial, blocked, and 0-finding. |
| libpng CVE-2026-33416 | **PARTIAL** | T4/T6 source ledger binds vulnerable v1.6.55 and fixed v1.6.56 identities. Historical 2/0 belongs to detector 0.1.9; the later four-file replay is 0/0 with all four partial, so no same-version full-source differential is established. |
| A0 CR-0219–CR-0223 | **PARTIAL** (availability review only) | All five original IDs and `not_reproduced` / `queued_not_reproduced` states remain intact. The exact source file is now present in the workspace; its 78,212 bytes match the claimed SHA-256 and Git blob OID. The claimed commit/tree relation is still unverified because the examined source directory is not a Git checkout. All 15 referenced report/result/run-metadata files exist and match their recorded hashes. No candidate status was changed. |

For the reviewed source cases, a partial parse or blocked detector result with zero findings is inconclusive. No finding count here is a precision/recall estimate or a product-security verdict.

## T7 correction and superseded statements

T7's source-ledger correction is confirmed against the local read-only Chromium audit mirror: the vulnerable 6.0 parent and fixed merge, their trees, target blobs, and full-file SHA-256 values resolve. This supersedes the earlier T3/D9 broad statement that the vulnerable web_webview object is unavailable. D9's narrower record that the object was missing in its particular fixed-only replay checkout remains accurate. D9's overall `BLOCK` is superseded by T7's fragment differential and corrected to **PARTIAL**; T1's frozen original matrix is not rewritten.

T7's `3 PASS / 8 PARTIAL / 0 BLOCK / 2 N/A` is the current 13-case disposition after applying that evidence. T6's `3 / 7 / 1 / 2` remains the dated historical snapshot and must not be silently edited.

The web fragment evidence is bound to source-derived synthetic snapshots and detector v0.3.6. It indicates the patched Flowbuffer root loops differ by 6/0 candidates, but six separate ordinary-loop candidates remain on both versions, and full translation units still parse partial. The full-file CLI outputs therefore do not establish a quiet fixed source.

## CR-0219–CR-0223 source availability

Each queue row retains the same source key: repository `openharmony/systemabilitymgr_samgr`, claimed commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`, tree `b7a89e95be788f2f2372258e341f7be842c7826d`, blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`, and SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`.

The present file at `D:\openHarmonyScanner\openharmony\foundation\systemabilitymgr\samgr\services\samgr\native\source\system_ability_manager_stub.cpp` is 78,212 bytes and matches both the declared source SHA-256 and Git blob OID. The row lines 464, 551, 668, 706, and 1485 exist and contain `WriteRemoteObject` calls. This verifies availability and content identity for the file bytes; without a Git object chain it does not independently prove that the claimed commit/tree contains that blob. Keep all five queue states unchanged. The minimum next input is the pinned commit/tree object chain or a verifiable source export that binds those identities; only then proceed to per-entry caller, permission, and sensitive-operation review.

## Independent checks

- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: `overall_ok=true`, 345 unique IDs; original counts 9 `not_reproduced` and 336 `not_testable`; queue counts 9 / 5 / 331.
- Verified 15 CR-0219–CR-0223 report/result/run-metadata artifacts against the SHA-256 values in the queue.
- Recomputed Git tree/blob IDs and SHA-256 values for libtiff, web_webview, cJSON, and vulnerable libpng objects; independently checked fixed libpng snapshot bytes and blob hash while retaining the missing commit/tree-link limitation.
- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors tests.detectors.test_cpp_resource_lifetime_detector -v`: 27/27 passed.
- `python -m scripts.check_change_scope --base 983afb846ceaa34daf690c39e4918703c4ac99a7 --lane cpp`: must pass before handoff.
- `git diff --check`: must pass before handoff.

## Next work split

### Development line

1. **Bounds / libtiff:** expose target function parser context under a relevant profile; only amend the detector after a reproducible full-source miss.
2. **Bounds / web_webview:** use verified upstream objects to address full-file parser coverage and separately review the six ordinary-loop residual candidates.
3. **Resources / cJSON:** locate trusted root-matched fixes and complete paired analysis; keep compare-cost and tree-amplification rules distinct.
4. **Resources / libpng:** provide parser-visible zstream ownership and cross-function caller context; bind the fixed commit/tree chain before making a source differential claim.
5. **A0 Samgr:** restore or obtain the pinned Git object chain for the already available exact file bytes; preserve all five IDs and states while assessing IPC reachability/permissions.

### Independent test line

1. Re-run each frozen change in a clean checkout with exact source identity, rule version, finding location, parser coverage, detector coverage, and safe/unrelated/partial controls.
2. Keep full-source and source-derived fragment evidence as separate scopes. A fragment result cannot upgrade a partial full-file result.
3. Re-run the queue verifier and source hash reconciliation after evidence changes. Change CR statuses only when new evidence meets their documented obligations.

Overall A-line goal remains **PARTIAL**. This audit does not close product reachability, selected build profile, remaining parser coverage, or the fixed-source blocks.
