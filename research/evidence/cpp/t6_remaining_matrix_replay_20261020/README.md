# T6 remaining original-matrix CLI replay

Date: 2026-10-20 (Asia/Shanghai)  
Independent scanner checkout: `81dd4aea9bb51522ac912b33504ef0d2ddb79089`  
Role: independent source-bound CLI replay; this package adds evidence only and does not change detector code, tests, fixtures, Catalog, API, A0, or owner documentation.

## Scope selection

Reviewed the original 13-row matrix in `t12_a_line_wave_acceptance_20261020.md`, the current T2 report, and the current matrix replay inventory. The cases explicitly excluded from this task because they already have fresh/current evidence are curl, both cJSON cases, CVE-2025-0587, CVE-2025-23420, Contacts, both libpng cases, and dSoftBus. The two N/A rows remain excluded as not applicable. Among the remaining eligible rows, this package replayed the locally available exact-source pairs for libtiff CVE-2025-9900 and web_webview CVE-2026-27648.

All CLI runs used the frozen scanner checkout at `81dd4aea9bb51522ac912b33504ef0d2ddb79089` and detector `ohscanner.cpp.bounds` 0.3.0. Raw JSON and Markdown outputs are in this directory. `source-identities.json` records commit/tree/blob/SHA-256 and exact scope; the verifier independently checks the Git objects and report projections.

## Results

| Matrix row | Vulnerable / fixed | Findings and locations | Parsing / detector coverage | Disposition |
|---|---|---|---|---|
| libtiff CVE-2025-9900 | `9dff73be` / `3e0dcf0e`; same two-file scope `libtiff/tif_getimage.c`, `libtiff/tiffio.h` | 0 / 0 under `ohcpp-integer-bounds-pointer-offset-underflow-candidate-004` (no root finding on either side) | Both files partial on both variants; `bounds` blocked and no files analyzed | **PARTIAL/BLOCK**. Zero results are unknown coverage and provide no fixed/safe differential. |
| web_webview CVE-2026-27648 | `769110dd` / `f550e8e5`; same five-file bounded snapshot scope | 13 / 7 under `ohcpp-memory-bounds-vector-index-candidate-005`; vulnerable root lines 85, 87, 96, 98, 116, 118; fixed-side ordinary residual lines 122, 124, 132, 133, 137, 139; renamed positive at `renamed.cpp:3` on each side | Four files complete, `partial.cpp` partial on both; aggregate blocked. `safe.cpp`, `unrelated.cpp`, and `partial.cpp` quiet. | **PARTIAL**. Root-specific six-to-zero differential reproduces in the bounded fragment, while ordinary-loop residuals persist and the partial control blocks full aggregate coverage. This is not a full translation-unit or product-safety result. |

The webview snapshots are synthetic commits containing the bounded function extraction and controls. Their vulnerable/fixed function bytes are bound to the exact upstream source commits, trees, blobs, and full-file SHA-256 in `webview-source-identities.json`; the included identity check records the extraction-to-source match. The upstream full source is 185,698 / 185,982 bytes; the analyzed function fragments are 4,684 / 4,968 bytes. These function-scope observations must not be presented as complete translation-unit results.

## Reproduction

From the scanner checkout at the pinned commit:

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/libtiff-vuln.json --md-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/libtiff-vuln.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/libtiff-fixed.json --md-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/libtiff-fixed.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/webview-vuln.json --md-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/webview-vuln.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/webview-fixed.json --md-out research/evidence/cpp/t6_remaining_matrix_replay_20261020/webview-fixed.md
python research/evidence/cpp/verify_t6_remaining_matrix_replay_20261020.py
```

The verifier requires the frozen scanner commit to be an ancestor and verifies that `src/` is unchanged from it. It checks libtiff source commit/tree/blob/SHA-256 and both CLI report projections; webview upstream source and synthetic-fragment commit/tree/blob/SHA bindings, all scoped file hashes, exact rule/version, finding locations, parse state, and retained limitations.

## Interpretation

These fresh runs do not upgrade either matrix row. The libtiff zero-finding full scope is blocked by partial parsing; its separate bounded function probe is not repeated here because this task requested full-row fresh CLI replay. The webview run remains bounded to source-derived functions plus four controls, with a deliberately partial file. Product build association, runtime reachability, attacker control, and impact remain unverified. Missing complete parsing is not treated as safe, and this evidence does not assert a product vulnerability.
