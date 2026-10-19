# D21 libtiff CVE-2025-9900 bounds gap assessment

Date: 2026-10-20 (Asia/Shanghai)

## Decision

No-change: current D7 pointer-offset rule already detects the exact vulnerable root on a complete local function plus exact TIFFRGBAImage field declaration; the exact fixed function is quiet. Whole translation units remain partial, so case remains PARTIAL.

Case disposition remains **PARTIAL**. Full-file CLI results are blocked by incomplete parsing and must not be read as safe or as a fixed differential.

## Exact source identity

| Role | Commit | Tree | File blob | File SHA-256 |
|---|---|---|---|---|
| vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

## Coverage and replay

- Whole-file scope: `libtiff/tif_getimage.c`, `libtiff/tiffio.h`; both parse `partial` on vulnerable and fixed versions; current detector `0.3.0` is `blocked`, 0 diagnostics on both.
- Vulnerable `TIFFReadRGBAImageOriented`: source lines 610–631; exact local function plus `_TIFFRGBAImage` field declaration parses complete and emits `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621 (`raster + (rheight - img.height) * rwidth`).
- Fixed `TIFFReadRGBAImageOriented`: source lines 626–645; same exact field declaration and local unit parse complete, 0 findings.
- Local unit materializes `uint32_t` as `unsigned int` to model the standard-header typedef. The struct field declaration itself is copied from the exact pinned `tiffio.h` object.
- Finding is a source-level candidate only. No capacity, product build, reachability or impact proof.

## Commands

```powershell
python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds
python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir <repo> --output-dir <output-dir>
```

## Validation

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 20 passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v`: 160 passed.
- `python -m scripts.check_change_scope --base b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e --lane cpp`: 0 violations.
- `git diff --check`: clean.

No detector edit is made because the existing narrow rule already handles the complete local source fragment.
