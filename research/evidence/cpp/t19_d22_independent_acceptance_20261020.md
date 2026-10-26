# T19 independent acceptance of D22 libtiff review

Date: 2026-10-20 (Asia/Shanghai)
Checkout: `codex/a-t17-independent-d20-d21-20261020`, HEAD `d3ebf4c1ccabdba0be674294a438472bbaed37af`.
Reviewed D22 commit: `ccce5279d2ca53a97443d0fed0c48c0b068947b8` (read by pinned Git object; not checked out or cherry-picked).

## Dispositions

| Item | Result | Rationale |
|---|---|---|
| D21 bounds-rule regression | **PASS (bounded modeled regression only)** | Re-running the exact-function + exact-struct-field replay gives one candidate at vulnerable source line 621 and none on the fixed function. Memory-safety controls pass. The standalone `unsigned int` shim is the arithmetic model; it is not proof of the target compiler's concrete `uint32_t` typedef/rank. |
| CVE-2025-9900 case | **PARTIAL/BLOCK** | A concrete fixture caller allocates 16×1 entries and passes them for a 16×16 TIFF, and the documented contract permits smaller raster dimensions/cropping. The source relation and upstream repair are supported, but both full translation-unit analyses remain partial/blocked. No product-specific inclusion, build, or reachable production caller is established. |
| D22 report's type-semantics claim | **PARTIAL** | `uint32_t` is sourced through `<stdint.h>` and denotes an exact-width unsigned type when available. That alone does not prove integer promotions preserve unsigned 32-bit arithmetic on every conforming implementation. The fragment replay's `typedef unsigned int uint32_t` explicitly models the common case. |
| D22 report's capacity statement | **PASS as API contract; PARTIAL as case evidence** | The pinned documentation describes caller-supplied `width × height` 32-bit entries, cropping when smaller, and permits raster height greater than image height. The local fixture is a concrete reproducer caller/allocation, but not a product caller or evidence of a shipped call path. |

## Independent source checks

- D22 commit `ccce5279d2ca53a97443d0fed0c48c0b068947b8` contains only `report.md` and `report.json`; both state `PARTIAL` and preserve the full-file parse limitation.
- Pinned repository objects verified locally in `D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream`: vulnerable commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, tree `986499c84247e9a1f49560128bbe7580d8ebea1a`; fixed commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, tree `77361ef7262189e16a2010b5c333f6b275d17f09`. The vulnerable commit is an ancestor of official fix commit `14da830be4bf4d6d3daafcbd892426aa6c164242` (`git merge-base --is-ancestor` exit 0). Fixed tree is the later descendant whose `tif_getimage.c` was replayed.
- Vulnerable `libtiff/tif_getimage.c` blob `6c7b5031a1937bb48cc79808a59618d8a4f6237e`, SHA-256 `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`; fixed blob `2774caa0eef24bce2a619d2686a23d59fb5ef9db`, SHA-256 `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`.
- The vulnerable `TIFFReadRGBAImageOriented(TIFF*, uint32_t rwidth, uint32_t rheight, uint32_t *raster, ...)` contains `raster + (rheight - img.height) * rwidth` at source line 621. The exact `_TIFFRGBAImage.height` field in the pinned `tiffio.h` is `uint32_t`. `tiffconf.h.in` includes `<stdint.h>`; `tiff.h` documents the format's intrinsic fixed-width types and aliases deprecated `uint32` to `uint32_t`.
- Official fix commit `14da830be4bf4d6d3daafcbd892426aa6c164242` is on the vulnerable history. The fixed descendant removes the offset expression and calls `TIFFRGBAImageGet(&img, raster, rwidth, rheight)`. The repair prevents base-pointer adjustment by the negative logical difference; it is consistent with the documented crop semantics.
- Fixed-tree `doc/functions/TIFFReadRGBAImage.rst` says raster storage is assumed to contain `width × height` 32-bit entries; smaller dimensions crop image data; raster height may be greater than image height. The source fixture `tests/fixtures/data_sensitive/cve_2025_9900_read_small_raster.c` (1,944 bytes; SHA-256 `6d907f94c1e100936fb4b714d6ee6fea9d6e1f96ecf2a8b04252db5d076337e1`) creates a 16×16 palette TIFF, uses `raster_height = 1`, allocates `calloc(16 * 1, sizeof(*raster))`, then calls `TIFFReadRGBAImageOriented` with 16×1. Its `safe` mode uses height 16. This establishes a concrete fixture caller and intended capacity; it does not establish any external/product caller.
- The replay diagnostic hashes the synthesized fragment (shim + exact field + function), not the full pinned source file. Source binding therefore relies on commit/tree/blob/SHA, function boundaries and field provenance together; do not treat the diagnostic hash as a full-file identity.

## Replays and controls

Command:

```powershell
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --output-dir D:\openHarmonyScanner\tmp\t19-d21-replay-20261020
```

Result: exit 0. Vulnerable function and exact field parse complete; `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621. Fixed function parses complete and has zero findings. Both complete translation units remain `partial`, six parse issues each, whole-file detector `blocked`, zero findings each. The latter is unknown coverage, not a safe/fixed result.

Commands:

```powershell
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v
python -m unittest tests.detectors.test_cpp_unsafe_memory_call_detector -v
```

Results: 20 memory-safety tests passed and 12 unsafe-memory-call control tests passed. Relevant bounds controls include candidate on unsigned dimension underflow in a pointer offset; quiet guarded unsigned offset, signed offset, unrelated unsigned subtraction, fixed guard/exact capacity; partial parse fails closed. These are detector controls, not whole-source libtiff coverage.

## Queue, scope, and limits

- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: `overall_ok=true`; 345 queue rows / 345 unique IDs, original statuses preserved (`not_reproduced=9`, `not_testable=336`), queue statuses preserved (`queued_not_reproduced=9`, `queued_first_batch=5`, `paused_pending_evidence=331`); 97 source-manifest entries / 4,364,747 bytes verified.
- `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py`: `overall_ok=true`; 345 IDs/status pairs preserved and source objects checked.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: 0 violations. The checker includes the checkout's pre-existing parallel evidence and detector/test changes; both newly authored T19 files are within the `cpp` evidence lane.
- The D22 claim that the source independently establishes modulo-2^32 subtraction/multiplication is stronger than the pinned headers alone support without resolving the target implementation's integer promotions. The standalone `unsigned int` typedef makes the replay model explicit; full TU remains partial. This uncertainty does not invalidate the observed detector shape replay but prevents promoting the CVE case.

No detector, test, or fixture was edited by T19. The 345-row queue remains unchanged. `git diff --check` completed cleanly (exit 0).
