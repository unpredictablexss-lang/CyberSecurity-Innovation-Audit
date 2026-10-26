# libtiff CVE-2025-9900 replay and root-cause card

Verification date: 2026-10-19. Scanner checkout: `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit`, HEAD `f8e3a0ad7463f216db4be7502bd8a19eec545908`. OpenHarmony source is pinned to libtiff commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`; upstream vulnerable/fixed pair is v4.7.0 commit `9dff73bebc5661f2dace6f16e14cf9e857172f4e` and patch commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`.

## Evidence sources

- Disclosure and severity wording: [Red Hat CVE record](https://access.redhat.com/security/cve/cve-2025-9900).
- Root-cause report: [upstream issue #704](https://gitlab.com/libtiff/libtiff/-/issues/704).
- Patch and changed invariant: [upstream MR #732](https://gitlab.com/libtiff/libtiff/-/merge_requests/732).
- Fixed release: [libtiff v4.7.1 notes](https://libtiff.gitlab.io/libtiff/releases/v4.7.1.html).
- Caller/cropping impact caveat: [Openwall discussion](https://www.openwall.com/lists/oss-security/2025/09/26/3).

## Root-cause card

1. **Attacker control / unknowns.** A malformed TIFF can supply image dimensions, including image height. The caller supplies output raster and requested dimensions. ImageSource accepts stream/byte/path/FD input; trust/permissions are unknown. The image-framework caller and Dell backend were inspected and both pass output height equal to the TIFF height they set/read. No smaller-height condition is evidenced in those two paths; other product consumers and selected target linkage remain unknown.
2. **Flow.** `TIFFReadRGBAImageOriented` forms an output base by adding `(rheight - img.height) * rwidth` to the caller raster, then invokes the RGBA image reader. The dimensions are unsigned. A smaller requested height wraps the subtraction; multiplication magnifies the offset and pointer addition can move before the raster.
3. **Missing guarantee.** Vulnerable source did not establish `rheight >= img.height` before this unsigned subtraction or otherwise prevent the derived base from leaving the allocation.
4. **Patch invariant.** Patch removes the subtraction-derived pointer offset. It supplies the original raster and caller dimensions to the reader, whose dimension handling performs crop placement safely.
5. **Static proof / obligations.** Rule proves unsigned operands and source-level flow from subtraction into scaled pointer offset, plus a pointer-typed base. It cannot prove allocation extent, caller-controlled values, actual reachability, image dimensions at runtime, target build inclusion, or impact. Those are unknown obligations, not findings of fact.
6. **Safe lookalikes.** A dominating lower-bound return or clamp before the subtraction prevents the underflow; signed/scalar arithmetic without pointer flow is not this root cause. A generic `if` elsewhere is not enough to suppress.

## Replaying scans

The reports are reproducible with the production entry. Run from the scanner checkout; change only output destinations if needed. For the upstream repositories, use the pinned local Git mirrors (these commands do not fetch):

```powershell
$scanner = 'D:\openHarmonyScanner\CyberSecurity-Innovation-Audit'
$upstream = 'D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream'
$vuln = '9dff73bebc5661f2dace6f16e14cf9e857172f4e'
$fixed = '3e0dcf0ec651638b2bd849b2e6f3124b36890d99'
python -m src.cli ohscan-run --repo-dir $upstream --repository OSGeo/libtiff --commit $vuln --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/libtiff-vulnerable.json --md-out research/evidence/cpp/libtiff-vulnerable.md
python -m src.cli ohscan-run --repo-dir $upstream --repository OSGeo/libtiff --commit $fixed --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/libtiff-fixed.json --md-out research/evidence/cpp/libtiff-fixed.md
```

For the local OpenHarmony component, use the repository object store at `D:\openHarmonyScanner\openharmony\.repo\project-objects\third_party_libtiff.git` and commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`. Baseline was the pre-rule scanner snapshot `D:\openHarmonyScanner\tmp\ohscanner-pointer-underflow-baseline`; current scan used this checkout at detector version 0.2.4. The CLI options and exact scope are also serialized in each JSON report. Replay uses the same two-file scope (`libtiff/tif_getimage.c`, `libtiff/tiffio.h`):

- `baseline-openharmony-source.json`: pre-rule scanner, 0 findings; parser partial/blocked for both files.
- `vulnerable-v4.7.0.json`: 1 CWE-191/787 candidate at the unsigned dimension offset; parser partial.
- `fixed-commit-3e0dcf0.json`: 0 same-rule findings; parser partial.
- `current-openharmony-d4a0516.json`: 1 candidate at line 621; parser partial.
- `heldout-variant.json`: synthetic renamed-member variant, 1 candidate; complete parse. It is a post-freeze mechanism fixture, not an independent real CVE sample.

The detector is registered in the existing integer-bounds detector; it does not consume CVE metadata. The broad suite log is `detector-suite.log`: 143 tests, 136 passed, 4 failed, 3 errored. All seven failures/errors were unrelated pre-existing fixture hash/size or shared_ptr fixture input mismatches. Focused new tests passed 4/4.

## Current-checkout recheck (2026-10-19)

The previous report text records scanner HEAD `f8e3a0ad7463f216db4be7502bd8a19eec545908`; current checkout was revalidated at branch `codex/a-line-scanner-regression-20261018`, HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`, with pre-existing dirty changes preserved. Fresh current-CLI M2 runs used the same pinned local Git object store, `light-ast`, detector `ohscanner.cpp.integer_bounds` v0.2.4, and the exact two-file scope. No fetch occurred.

| Source | Full commit | Tree | Snapshot SHA-256 | Result | Parse |
|---|---|---|---|---:|---|
| Upstream v4.7.0 | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `dda2fe1af73132372d00a491714b80dcf51a6056a1acc0e60259fc4e922a748a` | 1 CWE-191/787 candidate, `tif_getimage.c:621` | partial, 2/2 |
| Fix commit | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` (parent `14da830be4bf4d6d3daafcbd892426aa6c164242`) | `77361ef7262189e16a2010b5c333f6b275d17f09` | `c7b380f2774adc947c493f919086e4a48cd4c0dfd1e6d6041e6e9ae2587817d5` | 0 same-rule candidates | partial, 2/2 |

The vulnerable and fixed results are both `blocked`/`completed_with_limitations`, not complete-coverage verdicts. The patch's relevant invariant was re-read: `TIFFReadRGBAImageOriented` now passes `raster, rwidth, rheight` directly; `TIFFRGBAImageGet` limits requested height to image height before computing any bottom placement and clamps width. The earlier unguarded unsigned subtraction feeding a pointer offset is gone. The fixed report is a meaningful same-rule negative for this source pair, but partial parsing remains an explicit limitation.

## Isolated component runtime reproduction (2026-10-19)

Both pinned source versions were exported by `git archive` from the existing local object database to new directories, configured with CMake 4.4.4 and built with GCC 13.3.0 in WSL2. CMake was installed only under workspace `tmp`; the source mirror/checkout was not altered. Optional tools/tests/codecs were disabled except the available zlib. Exact build logs and object identities are listed in `runtime-reproduction-20261019.json`.

`guard_page_repro.c` writes a 1x2 uncompressed RGB TIFF, then invokes `TIFFReadRGBAImageOriented` with output raster width 1. It maps two pages, leaves the first `PROT_NONE`, and places raster at the second page start. A one-row request makes the vulnerable `(rheight - img.height)` offset equal -1 pixel, directly entering the guard page. Core dumps are disabled and calls have a five-second timeout.

| Caller output height | v4.7.0 vulnerable build | exact fix build |
|---:|---|---|
| 1 (less than 2-row image) | SIGSEGV, exit 139 | returned pixel `ffcc8844`, exit 0 |
| 2 (safe equal-height control) | returned pixel `ffcc8844`, exit 0 | returned pixel `ffcc8844`, exit 0 |

This is a bounded component API reproduction of the unsafe caller-dimension condition, not evidence that an OpenHarmony product caller exposes an attacker-controlled output height. The input TIFF is generated by the harness; the caller height is explicitly selected by the harness. The two reviewed OpenHarmony callers use equal dimensions, and app-level input trust/permissions remain unknown. The OpenHarmony product build itself is not built: the existing `out/rk3568` contains only a build log reporting the configured Ninja binary missing; no args.gn, generated global_parts_info or Ninja graph is present.

The replay is verified by executing `replay-runtime.sh` from a new output directory; the successful run log is `replay-script-run-r2.log`. The first script run reached all four expected component results but failed only its final shell assertions because PowerShell had written CRLF; that attempt is retained as `replay-script-run.log`. The corrected LF script passed all assertions on the second run.

## Regression and build environment

- `python -m unittest tests.detectors.test_cpp_pointer_offset_underflow -v`: **4/4 passed**, covering the root arithmetic, a member/renamed-dimension variant, a lower-bound guard, unrelated arithmetic, and incomplete input.
- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: **18 passed, 1 failed**. The failure is the existing hash/length manifest check, not the detector: at the first mismatch `bounds_positive.cpp` is 116 bytes while the manifest records 111. A read-only manifest audit found additional fixture/hash mismatches; exact current/expected identities are in `regression-and-build-status-20261019.json`. No fixture or manifest was edited.
- Component build/dynamic reproduction was **not run**. Windows lacks CMake/Ninja/Clang/GCC; probed WSL environments expose GCC/Make but not CMake/Ninja/Autotools/pkg-config. No packages were installed and no upstream source tree was changed. This is a toolchain limitation, not a safe result.
The pinned temporary upstream checkout itself was already dirty when inspected (many tracked source files deleted and an untracked `.replay-vuln-tif_getimage.c`); its Git object database still served the pinned objects, but this turn did not modify or repair that checkout. Preserve it for owner review.

The local OpenHarmony file hash was independently rechecked: `tif_getimage.c` SHA-256 `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`, matching the prior current-OH candidate report. Its result remains 1 candidate at line 621 with both scoped files partial. Fresh current-CLI reports are `recheck-vulnerable-current-cli.json/.md` and `recheck-fixed-current-cli.json/.md` beside this note.

Exact upstream source identities verified from the local Git object database:

- v4.7.0 `tif_getimage.c`: blob `6c7b5031a1937bb48cc79808a59618d8a4f6237e`, SHA-256 `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3`; `tiffio.h`: blob `225f3c1bfeabae2b31a5f35fbfd12d14b570dcd8`, SHA-256 `70119b9db897a364821a108ff0adc09f26c20ad9b6d9e943eb376ee3edb6166f`.
- Fix commit `tif_getimage.c`: blob `2774caa0eef24bce2a619d2686a23d59fb5ef9db`, SHA-256 `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8`; `tiffio.h`: blob `6a7ab2f5b7f6697020dfbcac57f8c2617c4b1074`, SHA-256 `7923903a85c15c047a22bfe52ef1901939d6a7e656c75b814fcb86c6179b120c`.

## OpenHarmony caller and build-path review

Local source-wide search found a known image-framework TIFF decoder caller and a scanner backend caller outside the libtiff implementation. Source identities and evidence are in `openharmony-caller-analysis-20261019.md/.json`.

Public ImageSource constructors accept streams, byte buffers, paths and file descriptors, and the selected plugin receives that stream through `SetSource`. The image-framework decoder reads TIFF width/height tags into `tiffSize_`, allocates a buffer from that exact size pair, then passes the same width/height to `TIFFReadRGBAImageOriented`. The trust boundary/permissions of applications supplying those bytes remain unknown. The vulnerable condition `rheight < img.height` is therefore not evidenced on this known caller. The local `out/ohos_config.json` identifies rk3568 and its pinned `vendor/hihope/rk3568/config.json` lists both `image_framework` and `libtiff`. The plugin target is conditional on `has_libtiff`; `out/rk3568` contains only a failed build log; `args.gn`, generated `global_parts_info`, Ninja graph and final binary are absent, so final linkage remains unconfirmed.

The scanner backend caller sets TIFF tags from scanner `m_pixelWidth`/`m_pixelHeight` and passes those same values as output dimensions, also avoiding the reproduced mismatch. Its product inclusion and trust path were not established. TIFF command-line utilities are present in the source but are not in the libtiff GN library source list inspected here.

This narrows applicability for the two source-visible calls only. It does not prove all products/callers safe; retain product vulnerability confirmation as unknown.

## Result status and limits

Static results are **candidate / partial parse**. The upstream component API condition was reproduced on vulnerable and fixed builds, but that does not prove product exploitability. The local product source config names rk3568; final plugin linkage and app-level reachability remain unverified. The two source-visible callers reviewed pass equal image/output heights. Do not claim precision/recall or zero false positives/negatives from this sample set.

## Detector implementation

`src/ohscanner/detectors/cpp/integer_bounds_detector.py`, detector `ohcpp-integer-bounds-pointer-offset-underflow-candidate-004`, version 0.2.4. Focused regression: `tests/detectors/test_cpp_pointer_offset_underflow.py`.

### Strict positive-guard refinement (2026-10-19)

The fixed libtiff change uses a `rheight > img.height` branch before subtracting to position a crop. The pointer-offset detector's positive-branch guard recognizer previously accepted `left >= field` only. Added a focused safe regression using the same strict-positive form; it failed before the code change, then passed after the recognizer accepted `>` as a dominating lower-bound proof. Focused pointer-offset suite is now 5/5.

Replayed the production M2 CLI after this change on identical exact upstream commits and identical two-file scope. Vulnerable v4.7.0 still emits one candidate at `tif_getimage.c:621` (0.0778 s); exact fix commit still emits zero same-rule candidates (0.0790 s). Both parser results remain partial/blocked (2/2 files), so the zero fixed finding is not a full safe verdict. Reports are `post-guardfix-vulnerable.json/.md` and `post-guardfix-fixed.json/.md`. Peak memory is not reported. The refinement does not alter the vulnerable finding; it improves a bounded guard proof and keeps candidate status.

### Compound offset and exact fixed-shape refinement (2026-10-19)

A second inspection showed the patch-side code uses compound assignment and an explicit `size_t` cast. The rule now models `pointer += (size_t)(unsigned_left - unsigned_member) * scale` as well as direct pointer addition, so the root mechanism is not missed solely because of the write form. Added an unguarded compound/cast variant that must produce a candidate and changed the guarded safe control to use this same expression shape under `left > member`. Detector version is 0.2.6. Focused suite: 6/6 passed, including positive compound form, exact fixed-style strict guard, renamed/member variant, early-return guard, unrelated scalar arithmetic, and incomplete parse.

Fresh production M2 CLI replay at 0.2.6 on the same two-file pinned upstream scope: vulnerable commit still has 1 candidate at line 621 (0.0836 s); exact fixed commit has 0 same-rule candidates (0.0864 s). Both stay parse-partial/blocked. These times exclude no other run costs and peak memory is unavailable. Reports were regenerated as `post-guardfix-vulnerable.json/.md` and `post-guardfix-fixed.json/.md`.

### OpenHarmony source rescan at detector 0.2.6 (2026-10-19)

Ran the production M2 CLI on the local OpenHarmony third_party_libtiff Git object at pinned commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`, same selected files (`libtiff/tif_getimage.c`, `libtiff/tiffio.h`), current integer-bounds version 0.2.6. The selected `tif_getimage.c` blob output is 108,663 bytes with SHA-256 `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`, matching the prior bound OH source. CLI emits one candidate at line 621; both selected files remain parser-partial/blocked. Detector time 0.0946 s; memory not reported. Raw report: `post-guardfix-openharmony.json/.md`.

Final source-to-test reconciliation: upstream fixed `TIFFRGBAImageGet` uses `if (h > img->height)` around `raster += (size_t)(h - img->height) * w`; `test_strict_positive_guard_matches_fixed_source_expression` now uses the same expression and condition, while `test_compound_pointer_offset_with_cast_is_candidate_without_guard` removes only the guard and requires a candidate. The six-test focused suite passed after this exact-shape adjustment. This is a source-backed safe control, not a claim that the scanner parsed the entire upstream file.

### Current-checkout revalidation (2026-10-19, detector 0.2.6)

Replayed four pinned local snapshots through `python -m src.cli ohscan-run` from scanner HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`, identical detector and exact two-file scope for the three component sources:

- Vulnerable upstream v4.7.0 `9dff73bebc5661f2dace6f16e14cf9e857172f4e`: one candidate at `libtiff/tif_getimage.c:621`, symbol `rheight - img.height`; partial/blocked (2/2 files), 0.0866 s.
- Fixed commit `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`: no same-rule candidate; partial/blocked (2/2), 0.0907 s. This absence is consistent with the patch removing the vulnerable subtraction; it is not a whole-file safety result.
- OpenHarmony pin `d4a0516c477dfbaf1153ae295893ab75aadd63d4`: one same-root candidate at line 621; partial/blocked (2/2), 0.0882 s. This identifies the source expression in the pinned component, not a built product vulnerability.
- Post-freeze synthetic renamed/member/wrapper holdout `f6a34c25b8265d2af539159897b563d7adf51ae5`: one candidate at `src/crop_rows.c:4`; complete parse, 0.0019 s. It is a structural holdout fixture, not an independent real CVE sample.

All reports are `revalidation-v026-{vulnerable,fixed,openharmony,holdout}.{json,md}`. The six focused unit controls also pass: positive unsigned subtraction-to-pointer, renamed/member variant, strict fixed-source guard, early lower-bound guard/unrelated arithmetic, compound/cast variant, and partial-input blocking. Component guard-page runtime evidence remains as recorded above. Memory was not reported; product consumer/reachability remains unknown.


## Current-turn scope-dependency replay (2026-10-19)

The exact upstream vulnerable/fixed commits were rechecked in the local source repository with lazy fetch disabled and current production M2 detector `ohscanner.cpp.integer_bounds` v0.2.6. This time `tif_getimage.c` alone was scanned, then the prior scope with `tiffio.h` was restored:

| Version | Exact scope | Result | Parsing | Time |
|---|---|---|---|---:|
| Vulnerable `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `libtiff/tif_getimage.c` | 0 diagnostics | 1/1 partial, blocked | 0.0578 s |
| Fixed `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `libtiff/tif_getimage.c` | 0 diagnostics | 1/1 partial, blocked | 0.0715 s |
| Vulnerable, same commit | `libtiff/tif_getimage.c`, `libtiff/tiffio.h` | 1 CWE-191/787 candidate at line 621 | 2/2 partial, blocked | 0.0780 s |
| Fixed, same commit | same two files | 0 same-rule diagnostics | 2/2 partial, blocked | 0.0787 s |

This demonstrates that the candidate model consumes a fact available only with the header in scope; it also confirms why scope must be recorded. It does not distinguish semantic parse failure from all other dependency facts because none of these runs is complete. The single-file zeros are not negative or safe results. The two-file results remain candidate evidence only. All four reports bind exact commit/tree/snapshot identities in `turn-tif-getimage-vulnerable/fixed.json` and `turn-twofile-vulnerable/fixed.json`.

The focused pointer-offset-underflow regression file was rerun: 6/6 passed. It covers unsigned dimension-difference feeding pointer offset, renamed/member variant, fixed positive guard, unrelated arithmetic, and incomplete source. It does not replace the real-source partial parser limitation.
