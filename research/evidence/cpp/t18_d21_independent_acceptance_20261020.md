# T18 independent D21 acceptance note

Date: 2026-10-20 (Asia/Shanghai)  
Scope: independent evidence review; no detector, test, or fixture edits. This note supplements T17 and does not replace its conclusions.

## Results

| Dimension | Result | Disposition |
|---|---|---|
| D21 bounds-rule regression | Vulnerable `TIFFReadRGBAImageOriented` fragment plus exact `_TIFFRGBAImage` declaration parses complete and emits candidate rule `ohcpp-memory-bounds-pointer-offset-candidate-004`; fixed fragment parses complete and is quiet. | **PASS (bounded rule regression only)** |
| CVE-2025-9900 case | The complete selected translation units remain partial and detector-blocked on both commits. The slice does not establish build inclusion, callers, attacker control, raster allocation capacity, or impact. | **PARTIAL/BLOCK** |
| D20 / CVE-2026-33416 | T17's four vulnerable and four fixed function slices remained partial with zero findings; no new evidence in this audit changes that. | **PARTIAL/BLOCK** |

## Independent checks

- Replayed `python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream --output-dir D:/openHarmonyScanner/tmp/t18-d21-replay-output`.
- Replay source identity agrees with exact Git objects: vulnerable commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, tree `986499c84247e9a1f49560128bbe7580d8ebea1a`; fixed commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, tree `77361ef7262189e16a2010b5c333f6b275d17f09`. File and header blob IDs and SHA-256 values are recorded in the companion JSON.
- Function extraction is bounded by the parser's `TIFFReadRGBAImageOriented` start/end lines: vulnerable lines 610–631, fixed lines 626–645. The field declaration is copied from the matching commit's `libtiff/tiffio.h` object and balanced through the exact struct closing brace. Both local fragments parse complete.
- Vulnerable local diagnostic line 50 maps to original `tif_getimage.c` line 621; the raw pinned source confirms the operation is `raster + (rheight - img.height) * rwidth`. Fixed fragment has no finding. The upstream fix diff removes this unchecked offset from the function and passes `raster, rwidth, rheight` to `TIFFRGBAImageGet`, where dimension handling is added.
- Important binding limit: diagnostic `source_sha256` is `6302a9c9f11f62a244fd3d765f39f1cac87855423cc59d01f51a5e3cc9ce1d06`, the hash of the synthetic local fragment (shim + exact field declaration + function), not the original source-file hash. The original vulnerable file hash is `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`; fixed is `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`. Function-slice hashes and object identities provide the source mapping. Do not treat the synthetic diagnostic hash as a full-file source binding.
- The `typedef unsigned int uint32_t` shim substitutes for the standard-header alias. It is plausible for the reviewed build, but the local probe does not independently resolve the project's target compiler typedef or reproduce the full include/build environment. This further bounds the result.
- Whole-scope replay retained partial parsing and blocked detector status with zero findings on both sides. This is unknown coverage, not a clean scan or a fixed differential pass.
- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 20 passed. These establish rule-control regression only; they do not upgrade the CVE case.
- `python research/evidence/cpp/t13_first_batch/verify_t13_queue.py`: `overall_ok=true`, all 345 queue IDs/statuses preserved; 9 `queued_not_reproduced`, 5 `queued_first_batch`, 331 `paused_pending_evidence`. Its 97-entry source hash manifest remains verified.
- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: `overall_ok=true`, 345 unique IDs and original counts preserved (9 `not_reproduced`, 336 `not_testable`). `git diff --check`: clean.

## Conclusion

Maintain **PASS** only for the bounded D21 vulnerable/fixed rule-fragment regression and **PARTIAL/BLOCK** for CVE-2025-9900. This audit found no evidence supporting promotion beyond PARTIAL. Maintain D20 at **PARTIAL/BLOCK**. No source, detector, test, or fixture files were changed.
