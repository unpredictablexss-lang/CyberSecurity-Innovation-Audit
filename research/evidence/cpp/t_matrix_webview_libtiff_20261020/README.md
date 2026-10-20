# T matrix follow-up: web_webview and libtiff

Execution date: 2026-10-20 (Asia/Shanghai).
Independent checkout: based on integrated PR #35 head `0e5a899043804fae5024ca315e4a6d441030fbb5`. The source object dates and upstream commits in this report are distinct from the execution date.
Disposition: both named cases remain **PARTIAL/BLOCK**. This replay did not change detectors, tests, fixtures, or A0.

## Current CLI replay

The current checkout reports `ohscanner.cpp.bounds` **0.3.0**. Fresh current-CLI runs were made for the pinned five-file webview function/control snapshots and the two-file libtiff scopes. Raw JSON is checked in beside this report. The existing D21 bounded function probe was rerun from this checkout and its fresh JSON is included.

### OpenHarmony-TPC/chromium_src web_webview CVE-2026-27648

The upstream full-file source identity remains bound by `webview-source-identities.json` and independently checked in `webview-source-identity-check.json`: vulnerable commit/tree/blob `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8` / `4ed3b46721fbfe04059af4ddb18bcd5272ce4762` / `78e83fea67a2db3297cc59f07566a0c0b6153e7a`, file SHA-256 `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920`; fixed commit/tree/blob `4cf313408de7b6d807465ea2bb22e434269b7c5e` / `a7769bf612be457e6e368f14ee355f3ea8ed2935` / `27e93e338ced03aeed6e7d892e29d4d0740f3653`, file SHA-256 `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`.

Current CLI was rerun on the source-derived function snapshots (synthetic snapshot commits `769110ddf1c14355c89f34b974ab9e6cf58c0c6c` vulnerable and `f550e8e59c57afe4e02b130ec3373b1011843617` fixed). Both use the same five files: `flowbuffer_functions.cc`, `safe.cpp`, `unrelated.cpp`, `renamed.cpp`, and deliberately partial `partial.cpp`. Four parse complete and the partial control remains partial on both sides. The detector therefore reports blocked/limited aggregate coverage, despite findings.

| Variant | Total findings | Patched Flowbuffer root | Ordinary-loop residuals | Renamed positive | Safe/unrelated |
|---|---:|---:|---:|---:|---:|
| Vulnerable | 13 | 6 | 6 | 1 | 0 |
| Fixed | 7 | 0 | 6 | 1 | 0 |

The root-specific six-to-zero differential reproduces. Six ordinary-loop residual candidates persist on each side; they are unresolved, neither suppressed nor asserted exploitable. Safe and unrelated controls remain quiet. Because the selected source is a function snapshot with a partial control, this is a bounded regression observation; the exact full translation units remain `PARTIAL/BLOCK` per the prior T9/T12 full-file replay, which had partial parse, blocked detector status and zero findings on both variants. A zero full-file result under partial parsing is not a safe/fixed conclusion. Product build, entry reachability, attacker control, and impact remain unverified.

### libtiff/libtiff CVE-2025-9900

Fresh current CLI full-scope runs use the exact commits and two-file scope (`libtiff/tif_getimage.c`, `libtiff/tiffio.h`). Vulnerable commit/tree/file blob/SHA-256: `9dff73bebc5661f2dace6f16e14cf9e857172f4e` / `986499c84247e9a1f49560128bbe7580d8ebea1a` / `6c7b5031a1937bb48cc79808a59618d8a4f6237e` / `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`. Fixed: `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` / `77361ef7262189e16a2010b5c333f6b275d17f09` / `2774caa0eef24bce2a619d2686a23d59fb5ef9db` / `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`.

| Variant | Parser | Detector | Findings | Interpretation |
|---|---|---|---:|---|
| Vulnerable | 2 files partial | blocked | 0 | Unknown coverage |
| Fixed | 2 files partial | blocked | 0 | Unknown coverage |

The fresh bounded probe uses the exact `TIFFReadRGBAImageOriented` function and `_TIFFRGBAImage` declaration; both bounded parses complete. Vulnerable emits `ohcpp-memory-bounds-pointer-offset-candidate-004` v0.1.0 at original `tif_getimage.c:621` (`raster`); fixed is quiet. This slice uses the documented `uint32_t` underlying-type shim and is not a full-TU result. No capacity/build/reachability/impact claim follows. Case remains PARTIAL/BLOCK.

## Matrix reconciliation

The T2/T12 13-case matrix still records **3 PASS / 8 PARTIAL / 2 N/A**. The two cases replayed here remain in the PARTIAL set; the PASS labels elsewhere are bounded static regressions and do not mean product security is proven. The two N/A cases remain exclusions. This package does not claim to freshly replay all remaining historic rows. Original A0 IDs/statuses are untouched.

## Reproduction

Run from this checkout; replace `<tmp>` with a fresh writable output directory:

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <tmp>/libtiff-vuln.json --md-out <tmp>/libtiff-vuln.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <tmp>/libtiff-fixed.json --md-out <tmp>/libtiff-fixed.md
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --output-dir <tmp>/libtiff-fragment
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out <tmp>/webview-vuln.json --md-out <tmp>/webview-vuln.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out <tmp>/webview-fixed.json --md-out <tmp>/webview-fixed.md
python research/evidence/cpp/verify_t_matrix_webview_libtiff_20261020.py
```

Verification: run `python research/evidence/cpp/verify_t_matrix_webview_libtiff_20261020.py`. It checks the committed raw replay projections, pinned source identities, detector versions, expected locations/counts, partial coverage and unchanged matrix disposition. It does not authenticate upstream repository ownership or establish product impact.
