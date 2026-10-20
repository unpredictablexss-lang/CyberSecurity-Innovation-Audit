# D7 bounds follow-up: unsigned pointer offsets

Date: 2026-10-19 (Asia/Shanghai)
Base: T3 integration `50b2806a7df38cd1ad07f257873617fe9d6b8337`.

## Finding and source binding

The D2 baseline records libtiff CVE-2025-9900 as 0/0 because its vulnerable and fixed `tif_getimage.c` plus `tiffio.h` inputs all parse `partial`; the scanner marks all four detector/file combinations `not_analyzed`. The selected input identity remains:

| Version | Commit | Tree | `tif_getimage.c` blob | File SHA-256 |
|---|---|---|---|---|
| Vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| Fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

The upstream vulnerable line is in `TIFFReadRGBAImageOriented`: `raster + (rheight - img.height) * rwidth` is passed to the decoder. Both image dimensions are unsigned. If the requested raster height is smaller than `img.height`, the subtraction wraps before scaling and the pointer can move outside the caller's raster. The fixed commit removes that caller-side offset and makes `TIFFRGBAImageGet` validate/adapt `h` and `w` before computing an offset. The relevant upstream diff is between the two commits above, `libtiff/tif_getimage.c` around lines 600–640.

## Rule change and bounded controls

Added `ohcpp-memory-bounds-pointer-offset-candidate-004` (`0.1.0`) to the existing C/C++ bounds detector. It reports only a pointer addition whose displacement is a multiplication of a difference between known unsigned scalar dimensions, and it suppresses an explicit enclosing `left >= right` branch or a preceding reject-on-underflow return. It does not infer pointer capacity, aliases, reachability or impact. Existing incomplete-source behavior is unchanged: a `partial` unit remains blocked and produces no findings.

Focused controls exercise the exact vulnerable expression shape, an ordered guard containing the same expression, signed subtraction, unrelated unsigned subtraction, and partial parsing. The focused regression command is:

```powershell
python -m unittest tests.detectors.test_cpp_memory_safety_detectors.BoundsDetectorControlTests.test_unsigned_dimension_underflow_in_pointer_offset_is_candidate tests.detectors.test_cpp_memory_safety_detectors.BoundsDetectorControlTests.test_unsigned_dimension_offset_guard_and_unrelated_shapes_are_quiet -v
```

Result: 2/2 passed. An equivalent isolated C++ snippet parsed as `complete` with `src.parser.ast.parse_source`; its candidate is a bounded expression-level reproduction, not a full-file or production CLI result. The complete pinned libtiff translation units remain `partial`, so the exact CVE row remains `PARTIAL`; this change does not claim the current CLI can analyze those complete files.

Replayed pinned-source CLI against both libtiff commits with detector `ohscanner.cpp.bounds` after the rule change. Both runs remain `completed_with_limitations`, parse status is `partial` for both selected files, and each emits zero diagnostics. This is the expected fail-closed result, not a regression pass. `ohscanner.cpp.integer_bounds` D2 results remain unchanged.

The CLI replay used `light-ast` and these pinned object commands (reports were written outside the checkout under `%TEMP%\a-d7-bounds-followup-20261019`):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d2-webview-fixed-current-cli-20261019 --repository openharmony/web_webview --commit 7038439a38336e0f74de9e8cdd72bf7b7ce8371f --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds
```

## web_webview CVE-2026-27648

No detector change was made for this case. The source object store still lacks vulnerable commit `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8` and blob `78e83fea67a2db3297cc59f07566a0c0b6153e7a`. The available fixed full TU hash is `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`; it parses `partial`, and its one-sided replay is not a differential. The task remains `BLOCK`. Minimum missing evidence is the exact vulnerable blob/source (or a local object store resolving the cited commit) plus sufficient parser coverage of the target function on both versions.

## Scope and limits

- No shared parser, Catalog, API, or shared documentation changed.
- Candidate semantics remain source-level only; no product build or runtime reachability is established.
- Safe/fixed shape is a synthetic control for the rule, not a replacement for trusted upstream fixed-source validation.
- Required scope and diff checks are recorded with the development commit and must be independently rerun by T3.
