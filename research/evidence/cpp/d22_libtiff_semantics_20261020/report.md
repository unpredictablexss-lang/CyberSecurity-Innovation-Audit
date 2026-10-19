# D22 libtiff CVE-2025-9900 semantic and bounds review

Date: 2026-10-20 (Asia/Shanghai)

## Decision

No-change to `ohscanner.cpp.bounds` (0.3.0). The existing pointer-offset candidate is supported by the exact vulnerable function and is quiet on the fixed function. The checked controls did not demonstrate a false positive or missed unsigned-underflow candidate that warrants widening or narrowing this rule. Case disposition remains **PARTIAL** because both complete translation units parse partial; a bounded function fragment is not whole-file coverage.

## Fixed source identity and replay

The review used the pinned libtiff objects already recorded by D21:

| Role | Commit | Parent | Tree | `tif_getimage.c` blob | File SHA-256 |
|---|---|---|---|---|---|
| Vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `95911a1c2cb5f701e3d6678a95493d9692027ab6` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| Fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `14da830be4bf4d6d3daafcbd892426aa6c164242` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |

The vulnerable commit is an ancestor of the fixed commit's parent. The final fix commit is `14da830be4bf4d6d3daafcbd892426aa6c164242` (`tif_getimage.c: Fix buffer underflow crash for less raster rows at TIFFReadRGBAImageOriented()`). Its function-level hunk applies to the same vulnerable operation, although the full fix commit also contains other changes accumulated on that branch.

Replaying the D21 bounded fragment script against those exact Git objects reproduced one `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621 on vulnerable source and zero findings on fixed source. The local `uint32_t` shim remains a fragment-modeling limitation; the underlying source evidence below independently establishes unsigned 32-bit semantics.

## Type, arithmetic, and object relationship

- `libtiff/tif_getimage.c` includes `tiffiop.h`; that includes `tiffio.h`, which includes `tiff.h`.
- At the vulnerable commit, `libtiff/tiffconf.h.in:18` includes `<stdint.h>`. `tiff.h` documents its intrinsic types as `int32_t`/`uint32_t` and aliases deprecated `uint32` to `uint32_t`. This establishes `uint32_t` as an exact-width unsigned integer type, without assuming a platform-specific alias such as `unsigned int`.
- The vulnerable declaration has `rwidth` and `rheight` parameters of `uint32_t`; `_TIFFRGBAImage.height` is also declared `uint32_t` in the exact `tiffio.h` blob. Thus `rheight - img.height` is unsigned arithmetic. On `rheight < img.height`, subtraction wraps modulo the width of `uint32_t`; multiplication by `rwidth` also uses unsigned 32-bit arithmetic before the result is used as an element offset from `uint32_t *raster`.
- The function's decode call passes `rwidth` and `img.height` to `TIFFRGBAImageGet`, not the requested `rheight`. The pointer is first offset by `(rheight - img.height) * rwidth` at original line 621. The dangerous relation is therefore tied locally to the requested raster height, image height, and raster pointer.

## Capacity and repair semantics

The fixed source's `doc/functions/TIFFReadRGBAImage.rst` documents the caller-supplied raster as `width × height` 32-bit entries, says image data are cropped when raster dimensions are smaller, and permits a raster height greater than the image height. That is a caller-side capacity contract, not a proof of any particular caller's allocation. The fixture `tests/fixtures/data_sensitive/cve_2025_9900_read_small_raster.c` demonstrates the relation in source: it allocates `raster_width * raster_height` entries and passes a 16×1 raster while generating a 16×16 image. This source fixture was inspected but not executed for this D22 review.

The fixed function removes the underflow-prone pointer expression and calls `TIFFRGBAImageGet(&img, raster, rwidth, rheight)`. The fixed `TIFFRGBAImageGet` limits height to `img->height` when the requested raster is taller, and limits width to `img->width`; the resulting behavior matches the documented crop/pad contract without moving the base pointer using a negative logical difference.

## Controls and coverage

- Vulnerable exact function + exact `_TIFFRGBAImage` declaration: complete local parse; one candidate at line 621.
- Fixed exact function + exact field declaration: complete local parse; zero candidate.
- Existing detector controls: direct guarded unsigned dimension subtraction is quiet; signed pointer subtraction and unrelated unsigned subtraction are quiet; a partial unit is blocked and emits no finding. These are detector controls, not proof that partial source is safe.
- Whole-file vulnerable and fixed translation units: both partial; detector run blocked with zero findings. This result is unknown, not safe and not a fixed differential pass.
- Existing fixture and D21 evidence show a bounded static candidate relationship, not product reachability, a specific caller's buffer, or product impact.

## Smallest follow-up evidence

1. A complete parse of the exact vulnerable and fixed translation units, or a separately justified local-fragment admission contract showing all needed type and function facts are isolated from the six whole-file parse issues.
2. For caller-specific capacity, the exact caller allocation and its dataflow into `TIFFReadRGBAImageOriented`; do not infer a caller allocation from the library API alone.
3. If product applicability is assessed later, the exact product component revision/build configuration and reachable call path. This D22 review makes no product exploitability claim.

## Reproduction

```powershell
python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --output-dir D:\openHarmonyScanner\tmp\d22-libtiff-semantic-replay-20261020
git -C D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream show 9dff73bebc5661f2dace6f16e14cf9e857172f4e:libtiff/tiffconf.h.in
git -C D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream diff 9dff73bebc5661f2dace6f16e14cf9e857172f4e 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 -- libtiff/tif_getimage.c
```
