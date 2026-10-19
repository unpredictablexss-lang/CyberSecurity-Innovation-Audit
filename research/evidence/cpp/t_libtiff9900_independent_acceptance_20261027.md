# T libtiff CVE-2025-9900 independent acceptance

Date: 2026-10-27 (Asia/Shanghai)
Independent checkout: clean detached worktree at `febc34f7757b5cb58bee6af77e053ba6bdb1a21c`.
Frozen development evidence: D commit `9904375320e3f136f199f286751f44dbce8d6013`.
Disposition: **PARTIAL/BLOCK**.

## Reproduction

Re-ran the current checkout's production `ohscan-run` CLI against the exact vulnerable and fixed source commits, selecting `libtiff/tif_getimage.c` and `libtiff/tiffio.h` with `ohscanner.cpp.bounds` 0.3.0. Both runs returned `completed_with_limitations`, both selected files parsed `partial`, detector status was `blocked`, and each had zero diagnostics. These zero results are unknown due to incomplete parsing; they are not a fixed differential or safety conclusion.

Re-ran `research/evidence/cpp/d21_libtiff_9900_20261020/replay.py` for the exact function plus `_TIFFRGBAImage` declaration. Both bounded inputs parsed `complete`. The vulnerable function emitted `ohcpp-memory-bounds-pointer-offset-candidate-004` (rule 0.1.0) at original `tif_getimage.c:621`; the fixed function emitted no finding. This is a bounded source-slice result and does not upgrade the whole-file case.

The vulnerable/fixed commit, tree, file blob, and SHA-256 values reproduced exactly as recorded in the attached JSON. The probe has a standalone `uint32_t` underlying-type shim. Product build, caller reachability, raster capacity, and impact remain unknown.

## Integrity and scope checks

- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: PASS; 345 unique IDs, original counts preserved (`not_reproduced=9`, `not_testable=336`), queue counts preserved (`paused_pending_evidence=331`, `queued_first_batch=5`, `queued_not_reproduced=9`), `overall_ok=true`.
- `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py`: PASS; all 345 IDs/status pairs preserved, `overall_ok=true`.
- `python -m scripts.check_change_scope --base 5e9f8f52b2c0fd53c71667ef2255493843ac1321 --lane cpp`: PASS; two reviewed evidence paths, zero violations.
- `git diff --check 5e9f8f52b2c0fd53c71667ef2255493843ac1321..febc34f7757b5cb58bee6af77e053ba6bdb1a21c`: PASS.

## Commands

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <tmp>/t-libtiff-vuln.json --md-out <tmp>/t-libtiff-vuln.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds --json-out <tmp>/t-libtiff-fixed.json --md-out <tmp>/t-libtiff-fixed.md
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --output-dir <tmp>/t-libtiff-fragment
```

See `t_libtiff9900_independent_acceptance_20261027.json` for machine-readable results.
