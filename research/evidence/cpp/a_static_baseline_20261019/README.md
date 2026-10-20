# A-line PR #30 independent static baseline

Date: 2026-10-19 (Asia/Shanghai)

## Scope and method

This is T1's independent **before** matrix on scanner base `8ec5f56a12e90bba56953b39eb17faa20e154da9` (PR #30 head). The worktree started clean. The source of the case inventory is the read-only ledger `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\nesearch\deliveries\cpp\coverage_ledger_20261019.json` (SHA-256 `e991abd2c020e5157278779374ed2f029ac6aacfddef4887adbcd160b58f8812`) plus the A0 Contacts manifest and T1 source review. The matrix has **13 rows**: all 12 ledger case IDs, plus the separate A0 Contacts `PortraitFileName` path traversal candidate.

All executed scans used the production pinned-source CLI `python -m src.cli ohscan-run`, profile `light-ast`, and explicit detector selection. The input commit/tree/blob, snapshot digest, per-file source hashes, parse state, selected detector/rule version, finding locations, run status, and elapsed time are retained in `matrix.json` and each raw M2 JSON report. Synthetic source snapshots use their synthetic commit/tree identity in the run report and retain upstream/OH provenance in the ledger; they are not represented as original upstream commits.

`PASS` is not assigned to any row in this before matrix. `PARTIAL` means analysis is incomplete or the root-cause/control checks are incomplete. `BLOCK` means the PR #30 baseline has a complete-parse miss, or the required immutable source object/detector is unavailable. `N/A` preserves explicit historical exclusions. These statuses do not determine product vulnerability or safety.

## Thirteen-row reconciliation

| Case | Before status | PR #30 replay result | Evidence / limitation |
|---|---|---|---|
| libtiff CVE-2025-9900 | PARTIAL | vulnerable/fixed 0/0; integer_bounds 0.2.0; 2/2 files partial | Exact upstream commits and two-file scope; raw `libtiff-*.json`. No safe conclusion. |
| libpng CVE-2026-46675 | PARTIAL | vulnerable, fix-parent, fixed, OH-generated: all 0; resource_lifetime 0.1.0; each target file partial | Four exact-byte sources in synthetic source snapshot; upstream tree IDs were unavailable locally. |
| libpng CVE-2026-33416 | PARTIAL | upstream v1.6.55/v1.6.56 0/0; resource_lifetime 0.1.0; all 4/4 partial | Also replayed the exact-byte OH snapshot. No complete parse. |
| curl CVE-2026-92391 | BLOCK | upstream 8.22.0/fix 0/0; resource_lifetime 0.1.0; both complete | Valid baseline miss on vulnerable source under complete parsing. |
| cJSON CVE-2026-67216 | PARTIAL | OH `cJSON.c` 0; resource_lifetime 0.1.0; `cJSON.c` partial | No trusted fix source; PR #30 has no exponential-compare root rule. |
| cJSON CVE-2026-67215 | PARTIAL | OH two-file snapshot 0; `cJSON.c` partial, `cJSON_Utils.c` complete | No trusted fix source; no rule models tree amplification followed by recursive deletion. |
| web_webview CVE-2026-27648 | PARTIAL | vulnerable/fixed 0/0; bounds 0.2.0; full translation unit partial | Synthetic byte-bound pair; hashes map to source identities in the ledger. |
| CVE-2025-26690 dsoftbus | BLOCK | Not run | Local Git object stores lack the exact vulnerable/fixed commits. Exact minimum missing objects are listed below. |
| CVE-2025-0587 Ark runtime | PARTIAL | vulnerable/fixed 1/0; integer_bounds 0.2.0; both complete; vulnerable at `atomic_helper.cpp:71` | Fix diff changes the signed 32-bit length/index narrowing. Safe/unrelated controls are not bound. |
| CVE-2025-23420 Ark runtime | PARTIAL | vulnerable/fixed 5/0; bounds 0.2.0; both complete; vulnerable at lines 650, 653, 665, 666, 668 | Fix diff replaces the corresponding element accesses with stable-array guarded operations. Safe/unrelated controls are not bound. |
| CVE-2025-20042 kernel_liteos_a | N/A | Not run | Retained as not applicable under the historical lexical-bounds rule. |
| CVE-2025-21098 kernel_liteos_a | N/A | Not run | Retained as not applicable under current historical A rules. |
| Contacts `PortraitFileName` path traversal | BLOCK | Not run | A0 binds Contacts commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`, tree `2054824c04bb403eeea128a9262edfb3001efa4f`, file blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`, SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`; that commit's Git object store is missing here. PR #30 has no source-to-file-sink rule, so the production CLI cannot exercise the intended rule yet. |

The machine-readable per-run table is [`matrix.json`](matrix.json). Each per-run object includes the complete M2 command with an explicit placeholder for the local object-store path; no command fetches objects or uses a branch/tag ref.

## Reproduction commands

Run from `D:\openHarmonyScanner\worktrees\a-t1-audit-pr30-20261019` at scanner HEAD `8ec5f56a12e90bba56953b39eb17faa20e154da9`. The source stores listed here are read-only inputs.

```powershell
$e = 'research/evidence/cpp/a_static_baseline_20261019'
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out "$e/libtiff-vuln.json" --md-out "$e/libtiff-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out "$e/libtiff-fixed.json" --md-out "$e/libtiff-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-cve-2026-33416-production-baseline-20261019 --repository libpng/libpng --commit f3ef808f45af32fabed16e1796ee82598c17e9f7 --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/libpng33416-vuln.json" --md-out "$e/libpng33416-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-gitlab-mirror-pins-20261019.git --repository libpng/libpng --commit c3e304954a9cfd154bc0dfbfea2b01cd61d6546d --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/libpng33416-upstream-vuln.json" --md-out "$e/libpng33416-upstream-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-gitlab-mirror-pins-20261019.git --repository libpng/libpng --commit d5515b5b8be3901aac04e5bd8bd5c89f287bcd33 --include pngset.c --include png.c --include pngread.c --include pngrtran.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/libpng33416-upstream-fixed.json" --md-out "$e/libpng33416-upstream-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit 01346829096c61b372692f6dc43ffa778c6caccd --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/curl-vuln.json" --md-out "$e/curl-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git --repository curl/curl --commit d7546809d5bd548b69ec49fca26565c8f6f0d344 --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/curl-fixed.json" --md-out "$e/curl-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\web-webview-flowbuf-full-tu-m2-20261019 --repository openharmony/web_webview --commit a15cbf4ef20673cfcf1856bf40a723b3ce026564 --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out "$e/web27648-vuln.json" --md-out "$e/web27648-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\web-webview-flowbuf-full-tu-m2-20261019 --repository openharmony/web_webview --commit fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out "$e/web27648-fixed.json" --md-out "$e/web27648-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cjson-cve67215-current-replay-20261019 --repository openharmony/third_party_cjson --commit 105eaddbf0d0110b07d16bdefc81ffc796e1444a --include third_party/cjson/cJSON.c --include third_party/cjson/cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/cjson-openharmony.json" --md-out "$e/cjson-openharmony.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository libpng/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include vulnerable-1.6.55/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/libpng46675-vuln.json" --md-out "$e/libpng46675-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-scan-20261019 --repository libpng/libpng --commit e283ed5d3a74c0112f092ddb1003c97e0e9a4717 --include fixed/pngrutil.c --detector ohscanner.cpp.resource_lifetime --json-out "$e/libpng46675-fixed.json" --md-out "$e/libpng46675-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out "$e/cve2025-0587-vuln.json" --md-out "$e/cve2025-0587-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out "$e/cve2025-0587-fixed.json" --md-out "$e/cve2025-0587-fixed.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out "$e/cve2025-23420-vuln.json" --md-out "$e/cve2025-23420-vuln.md"
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\arkruntime-holdout-history --repository openharmony/arkcompiler_ets_runtime --commit 1b23531531e768398682582969c2a9f17e72cafe --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out "$e/cve2025-23420-fixed.json" --md-out "$e/cve2025-23420-fixed.md"
```

The omitted runs were not retried because the minimum source input is unavailable or the historical rule explicitly excludes them:

- CVE-2025-26690 needs a local Git object store containing commits `258662cd9840b55a31546a72d91027f6368cea84` and `192f3e11d74beeaa3d879333471deb8a24a7e1c5`, with `core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp` blobs/trees verifiable.
- Contacts needs the local Git object store for `applications/standard/contacts_data` commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` (tree and file identity are above) and a source-to-file-sink detector admitted to PR30. The unbound local checkout and extracted PoC adapter are not substitute source identities or safe/fixed controls.
- CVE-2026-46675 upstream full commit trees were not available; the byte-bound four-file variants used in the earlier investigation remain the available replay unit. CVE-2026-67215/67216 have no confirmed fixed source. No safe/unrelated source controls have been silently inferred.

## Follow-up after development freeze

T1 should rerun these exact cases against the frozen D1/D2 detector commits from a fresh independent checkout, preserve the baseline outputs, then compare same-root findings and parsing coverage. Add explicit safe/unrelated controls only after each control is source-bound. The curl complete-parse zero/zero row requires attention as a baseline miss. Partial parser results remain partial even when the diagnostic count is zero.

## Dated source replay update

research/evidence/cpp/a_static_baseline_20261019/cve2025-26690-replay-update-20261019.md adds an official-fetch/synthetic-package replay for CVE-2025-26690. The original BLOCK in the before matrix is retained; current case status is PARTIAL because vulnerable/fixed source blobs now replay as 5/0 candidates, but upstream tree IDs, exact controls, and complete detector analysis are unavailable.
