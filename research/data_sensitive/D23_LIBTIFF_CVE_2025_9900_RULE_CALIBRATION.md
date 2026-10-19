# D23: libtiff CVE-2025-9900 rule calibration and fix review

Date: 2026-10-19  
Detector: `ohscanner.known_disclosed_cves` 0.4.0  
Status: component-source candidate; product status unknown

## What changed

The 0.3.0 rule searched for a shifted-raster expression anywhere in a C/C++ file, then suppressed it if dimension comparisons appeared in the preceding 1,500 characters. A check in an unrelated earlier function could therefore hide the candidate. The rule now binds the signature to the `TIFFReadRGBAImageOriented` function body and preserves the candidate whenever that old call shape exists. It does not infer that nearby comparisons prove the path safe.

The updated message states the narrow observed condition: the wrapper offsets the raster by `(rheight - img.height)`; when the caller-provided raster height is smaller than the image height, the pointer calculation can underflow. The claim is limited to source evidence and the upstream correction.

## Fixed-source comparison

The pinned G-drive source is repository `third_party_libtiff`, commit `d4a0516c477dfbaf1153ae295893ab75aadd63d4`, tree `33beab3b3b50fe6678b1a74ed48ac3b69084c6ec`. The source is `libtiff/tif_getimage.c`, Git blob `5121e85b9eb2bc734b557892c0968f629d370b82`, SHA-256 `4b664c80e2e208c2a9cd33042419f69e590ff088c1a3befe99581d1b1df5471a`. The code at line 621 calls `TIFFRGBAImageGet(&img, raster + (rheight - img.height) * rwidth, rwidth, img.height)`.

The upstream fix is [libtiff MR !732](https://gitlab.com/libtiff/libtiff/-/merge_requests/732), with the patch mirrored in [OpenEmbedded's CVE-2025-9900 patch](https://patchwork.yoctoproject.org/project/oe-core/patch/f4e5cdeccee02d3ea78db91d5dfdcfd017c40ee0.1759260542.git.steve%40sakoman.com/). It moves the adaptation into `TIFFRGBAImageGet`: if requested height or width exceeds the image dimensions, it adjusts the raster/dimensions, and the wrapper passes the original `raster, rwidth, rheight` instead of subtracting image height. The issue record describes the less-raster-rows crash condition; it does not establish that every affected call is exploitable.

Recommended remediation for code carrying the old shape is to take the upstream fix for the exact source baseline, or an equivalent reviewed backport, then run libtiff's regression suite and a constrained ASan reproduction using synthetic TIFF input. Do not hand-apply only the call-site change without checking the matching `TIFFRGBAImageGet` contract.

## Verification

- The first-party `run_reviewed_detectors` path scanned the exact pinned Git commit twice.
- Both runs returned the same candidate at `tif_getimage.c:621`, source SHA above, and the same `blocked`/partial coverage state.
- Detector unit tests: 10/10 passed, including the old call, fixed API call shape, unrelated prior dimension checks, fixed-version controls, and other CVE families.
- Full Python suite is running for this change; current-main CI compatibility remains to be checked.
- Reproduce the pinned scan with PYTHONPATH=. .venv-web/bin/python research/data_sensitive/d23_libtiff_rule_calibration.py from the repository root.
- The G-drive audit records a prior isolated ASan reproduction for this component, and the upstream issue publishes a crash harness. This D23 run did **not** re-run that PoC. A reproducible PoC artifact in this branch remains outstanding.
- `validated_vulnerability=0`. The candidate does not prove OpenHarmony product inclusion, caller reachability, actual affected product version, or product impact.

## Conclusion

The public component disclosure and the vulnerable source shape are supported, and the scanner now catches the exact pinned source without being suppressed by an unrelated nearby guard. Treat the detector result as a **candidate** with partial coverage. Keep product vulnerability confirmation, exploitability, and release impact **unknown** pending the required build and runtime evidence.
