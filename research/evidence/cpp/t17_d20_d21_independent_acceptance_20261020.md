# T17 independent acceptance: D20 / D21

Date: 2026-10-20 (Asia/Shanghai)
Independent checkout base: `60c758812`
Scope: evidence-only; no detector, tests, or fixtures changed.

## Rule regression

### D20 — libpng resource-lifetime slices

Replayed `d20_libpng33416_replay_20261020.py` under `ohscanner.cpp.resource_lifetime` 0.4.2. The vulnerable and fixed libpng commits/trees were verified against the local Git object mirror. For all four requested slices (`png_set_PLTE`, `png_set_tRNS`, `png_free_data`, `png_do_expand_palette`), the three underlying file blob IDs and SHA-256 values matched the exact commit objects. All four vulnerable slices and all four fixed slices reproduced `partial` fragment and translation-unit parse statuses with zero findings.

This does not establish the root-cause candidate and does not establish a fixed differential. Partial parser coverage remains the limiting result.

### D21 — libtiff pointer-offset bounds rule

Replayed `d21_libtiff_9900_20261020/replay.py` from the exact libtiff object mirror. Commit, tree, blobs and SHA-256 values for `tif_getimage.c` and `tiffio.h` match both pinned versions. The bounded `TIFFReadRGBAImageOriented` function plus its exact `_TIFFRGBAImage` declaration parses complete on both sides. Vulnerable source emits existing rule `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621; the fixed function is quiet.

The whole two-file CLI was also rerun independently for both pinned commits: each returned `completed_with_limitations`, two partial files, detector `blocked`, and zero diagnostics. The function-fragment result is a bounded rule regression only; the local `uint32_t` alias shim and absent build/reachability/capacity evidence limit its interpretation.

## Case status

| Case | Independent result | Disposition |
|---|---|---|
| libpng CVE-2026-33416 | 4/4 vulnerable and 4/4 fixed slices partial, 0 findings; parent TUs partial | **PARTIAL/BLOCK** |
| libtiff CVE-2025-9900 | Exact vulnerable function candidate, exact fixed function quiet; both full two-file scopes partial and blocked | **PARTIAL/BLOCK** |

No case status changed from the T1/T3 full-source conclusions. In particular, the local libtiff fragment candidate does not make the full source case PASS, and zero findings in partial libpng slices is not evidence of safety.

## Independent validation

- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: 8 passed.
- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 20 passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v`: 160 passed.
- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: overall OK; 345 unique IDs, original status counts preserved (`not_reproduced=9`, `not_testable=336`), 97 source-hash manifest entries / 4,364,747 bytes verified.
- `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py`: overall OK; all 345 IDs/status pairs and selected source objects reconciled.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: 0 violations.
- `git diff --check`: clean.

Full JSON evidence, including source identities, is in [`t17_d20_d21_independent_acceptance_20261020.json`](t17_d20_d21_independent_acceptance_20261020.json).
