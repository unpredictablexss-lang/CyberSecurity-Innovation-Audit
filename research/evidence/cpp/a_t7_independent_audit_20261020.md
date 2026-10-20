# T7 independent A-line audit

- Date: 2026-10-20 (Asia/Shanghai)
- Checkout: `D:/openHarmonyScanner/worktrees/a-t7-independent-audit-20261020`
- Branch: `codex/a-t7-independent-audit-20261020`
- Frozen base: `7e8083314f854780a0f606ecc6382208e8a02e8a`
- Role: independent static-regression/provenance audit. No detector, test, fixture, or development files were changed.

## Results

| Case / gate | T7 disposition | Evidence and boundary |
|---|---|---|
| D7 libtiff CVE-2025-9900 | **PARTIAL** | The exact vulnerable/fixed commit, tree, target blob, and target file SHA-256 were independently checked in the local upstream object store. Current `ohscan-run` replay of both two-file scopes returns 0 findings, parse coverage `partial: 2`, detector coverage `blocked`, and `completed_with_limitations`. This is not a differential pass. The two D7 focused control tests pass, including positive unsigned-dimension pointer-offset and guarded/signed/unrelated shapes. Full-source candidate detection remains blocked by parser coverage. |
| D8 cJSON CVE-2026-67216 compare-cost | **PARTIAL** | Exact component commit/tree/blob/source SHA identities match the T4 ledger. Current `ohscan-run` v0.4.0 emits `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` at `third_party/cjson/cJSON.c:3161`; that translation unit is partial and overall detector coverage is partial. No trusted fixed source is bound, so the fixed differential is BLOCK. |
| D8 cJSON CVE-2026-67215 tree-amplification | **PARTIAL** | Same exact component source identity. Current `ohscan-run` emits `ohcpp-resource-exhaustion-tree-amplification-candidate-004` at `third_party/cjson/cJSON_Utils.c:861`; this file parses complete, but the two-file detector run is `completed_with_limitations` because `cJSON.c` is partial. No trusted root-matching fixed source is bound, so fixed comparison is BLOCK. |
| D7/web_webview CVE-2026-27648 | **PARTIAL** | The 6.0 upstream vulnerable-parent and fixed-merge commits are now available in the local read-only chromium_src audit mirror. T7 independently verified commit/tree/blob, byte count, and full-file SHA-256 against `source-identities.json`. Current CLI reruns against the byte-identical synthetic full-TU snapshots are both `blocked`, parse `partial`, 0 findings; a direct CLI run against the large upstream mirror timed out while recursively enumerating the repository tree, not because the two target objects were missing. Existing v0.3.6 production CLI reports on exact source-derived function fragments parse complete and return 12/6 diagnostics for 6.0 and held-out 5.1. Root-specific findings are 6/0 at the patched Flowbuffer loops, while 6 ordinary-argument-loop candidates remain on each side. Thus the disclosed loop-root differential is evidenced at function scope; full-TU coverage and the separate residual candidates still prevent an overall PASS. |
| D7/D8 focused tests | **PASS (regression tests only)** | D7 unsigned-pointer-offset controls: 2/2. D8 resource lifetime/compare controls: 8/8. Complete C++ detector suite: 159/159. These tests do not upgrade the source-bound case statuses above. |
| A0 queue integrity | **PASS (inventory integrity only)** | The queue verifier reports `overall_ok: true`, 345 unique IDs retained, original status counts `not_reproduced=9` and `not_testable=336`, queue states `queued_not_reproduced=9`, `queued_first_batch=5`, `paused_pending_evidence=331`; no ID or state was edited. This does not complete candidate triage. |

## web_webview discrepancy reconciliation

The earlier descriptions referred to different evidence scopes and object stores:

1. T1 `matrix.json` records its original full-translation-unit baseline with the synthetic byte-bound vulnerable/fixed snapshots. Both inputs are the exact registered full-file blobs, both parse `partial` with 23 issues, both return 0 findings, and both detector runs are `blocked`. These 0/0 results are unknown, not safe.
2. T3 first-wave wording that the vulnerable file/object was unavailable was stale by the later T4/T6 source-acquisition records. T7 found the official 6.0 vulnerable parent `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8` and fixed merge `4cf313408de7b6d807465ea2bb22e434269b7c5e` in `D:/openHarmonyScanner/tmp/chromium-src-cve-2026-27648-audit.git`; target tree/blob/hash identities match the ledger. T7's attempt to scan this entire mirror directly timed out during recursive `git ls-tree`, so it is not a completed direct upstream CLI run.
3. The later v0.3.6 CLI fragment records are production CLI runs over complete, source-derived function ranges packaged as synthetic snapshots. They are not whole-file runs or upstream commits. The reports and identity maps are available in the read-only source-review checkout under `CyberSecurity-Innovation-Audit/research/evidence/cpp/web_webview_cve_2026_27648_20261019/`. They show 12 total findings in each vulnerable fragment and 6 in each fixed fragment. The diagnostic map attributes 6 vulnerable findings and 0 fixed findings to the three patched Flowbuffer loops; the other 6 fixed findings are separate ordinary-argument-loop writes that remain unresolved. The 5.1 branch was held out before evaluation and is now consumed evidence.
4. T7 reran the full-TU CLI on the local synthetic snapshots `a15cbf4...` and `fa0d92...`, whose target blobs and full-file hashes match the upstream objects. Both parse `partial`, are `blocked`, and return 0 findings under the current checkout. The current CLI metadata reports bounds detector version `0.2.0`; the v0.3.6 fragment reports are historical, separately version-bound evidence and are not represented as current-version full-file results.

Suggested correction to the stale T3 sentence:

> “The official 6.0 vulnerable-parent and fixed-merge commits and target blobs are now verified in the local audit mirror. Exact source-derived function-fragment CLI evidence shows 6 vulnerable versus 0 fixed candidates at the three patched Flowbuffer loops, with six separate ordinary-argument-loop candidates remaining on both sides. Full translation units parse partial and current full-TU CLI runs are blocked with zero findings; the case remains PARTIAL, not a whole-file pass or safe verdict.”

This reconciles the historical BLOCK wording without silently rewriting the frozen T1 matrix or claiming whole-file coverage.

## D7/D8 exact identities and T7 replays

- libtiff vulnerable: commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, tree `986499c84247e9a1f49560128bbe7580d8ebea1a`, `tif_getimage.c` blob `6c7b5031a1937bb48cc79808a59618d8a4f6237e`, SHA-256 `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`.
- libtiff fixed: commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, tree `77361ef7262189e16a2010b5c333f6b275d17f09`, `tif_getimage.c` blob `2774caa0eef24bce2a619d2686a23d59fb5ef9db`, SHA-256 `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`.
- cJSON component: commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`; `cJSON.c` blob/SHA-256 `152b2caa479c9f448001652913c980a6dafb82e0` / `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`; `cJSON_Utils.c` blob/SHA-256 `8fa24f8e9bf452cf1ba49d1325c85423ce742c74` / `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`.
- Commands independently run: D7 focused unittest command (2/2); `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v` (8/8); `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v` (159/159); current CLI pinned-source replays for libtiff vulnerable/fixed and cJSON scoped files; queue verifier. Full outputs were written under the user temp directory and not committed.

## Next five actionable A0 queue entries: evidence availability only

Entries CR-0219 through CR-0223 all point to the same Samgr source family and the same source key: repository `openharmony/systemabilitymgr_samgr`, commit `08e2a552b839ea7727251cb9b749a5c1dd9cfeff`, tree `b7a89e95be788f2f2372258e341f7be842c7826d`, blob `ae84d998c4d90c8c08d692b9020404593b58a0cc`, source SHA-256 `e82aa966b6c70278c64683b3bc4c0b236cf7550da3e65aeafc12acfa5f718433`. Their source report, result JSON, and run metadata are available and each matches its recorded SHA-256. The A0 package does not contain the raw source tree at the recorded project path, and the examined local Samgr clone does not have the pinned commit object. This is availability evidence only; the five entries remain queued `not_reproduced`, and no candidate conclusion is inferred.

Minimum next action: obtain the exact pinned Samgr source object or an independently verifiable file export; verify tree/blob/SHA and line context; then map each of the five IDs to its transaction, caller permission, data/FD flow, and protected operation. Because these IDs share one source family, handle them as one grouped evidence pass while retaining all five IDs/states.

## Responsibility split

### Development line

- libtiff: reproduce complete target-function parsing with a source-bound product-compatible profile or narrow parser/model change; do not treat current 0/0 partial runs as success.
- cJSON: obtain root-matching trusted fixed sources for both distinct cases; improve cross-file analysis only after a reproducible coverage limitation is isolated. Keep residual/unknown cases separate.
- web_webview: use the verified upstream objects for a fresh controlled extraction; investigate the remaining six ordinary-loop candidates with exact arithmetic/type bounds. Preserve the full-TU parser blocker unless it is solved with evidence.

### Independent test line

- Re-run any frozen developer commit against its bound source objects; verify per-root locations, rule versions, parser and detector coverage, plus controls before changing case status.
- Retain the 345 original queue IDs and statuses. For CR-0219–CR-0223, add evidence only after the exact source is obtained and hash-verified; do not use source report presence as source availability.
- Keep product reachability, build profile, attacker control, and impact separate from static candidate regression.

## Scope and formatting checks

- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: passed, `overall_ok=true`.
- `python -m scripts.check_change_scope --base 7e8083314f854780a0f606ecc6382208e8a02e8a --lane cpp`: run before commit; evidence-only additions are within this lane's research scope.
- `git diff --check`: run before commit.
