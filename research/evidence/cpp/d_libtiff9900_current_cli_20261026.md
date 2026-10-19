# libtiff CVE-2025-9900 current production CLI recheck

Date: 2026-10-26 (Asia/Shanghai)

## Decision

No detector change. The current production CLI whole-file replay remains blocked on both exact vulnerable and fixed source commits because both translation units parse partially. A bounded function-plus-exact-struct probe still reports the existing pointer-offset candidate only on the vulnerable function. This confirms no new rule gap and does not establish a whole-file fixed differential or safety conclusion. Case status remains **PARTIAL/BLOCK**.

## Bound inputs and execution

| Role | Component commit | Tree | `tif_getimage.c` blob | SHA-256 |
|---|---|---|---|---|
| Vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| Fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

Each whole-file run used the current checkout's `ohscan-run`, detector `ohscanner.cpp.bounds` version `0.3.0`, and the same two-file scope: `libtiff/tif_getimage.c`, `libtiff/tiffio.h`.

| Role | Whole-file parse | Detector status | Findings | Run coverage |
|---|---|---|---:|---|
| Vulnerable | both files partial | blocked | 0 | completed_with_limitations |
| Fixed | both files partial | blocked | 0 | completed_with_limitations |

The earlier bounded probe was rerun from the current checkout using the exact vulnerable/fixed function and `_TIFFRGBAImage` field declaration. The vulnerable `TIFFReadRGBAImageOriented` slice reports `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621; the fixed slice reports zero. The probe uses a standalone `uint32_t` underlying-type shim and is not a full translation unit analysis.

## Reproduction

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <out>/vulnerable.json --md-out <out>/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <out>/fixed.json --md-out <out>/fixed.md
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --output-dir <out>/fragment
```

The temporary run JSON files were retained outside the repository at `D:/openHarmonyScanner/tmp/d-libtiff9900-recheck-{vuln,fixed}.json`; the fragment JSON is at `D:/openHarmonyScanner/tmp/d-libtiff9900-recheck-fragment/replay.json`. The A0 queue is unchanged. Product inclusion, input reachability, raster capacity semantics and impact remain unverified.
