# D2 integer and bounds replay

Date: 2026-10-19  
Scanner checkout: `8ec5f56a12e90bba56953b39eb17faa20e154da9`  
Profile: `light-ast`  
Rules: `ohscanner.cpp.integer_bounds` 0.2.0; `ohscanner.cpp.bounds` 0.2.0.

This replay uses current CLI output captured in the adjacent JSON/Markdown files. Source commit/tree/blob and SHA-256 are retained per case below. Detector elapsed time is from the CLI report; it excludes CLI setup and Git indexing. No detector changes were justified by this replay: the two historical pairs have complete parse and show the expected root-cause candidate/fixed difference; libtiff and web_webview remain blocked by parser coverage, so their zero findings are not passes or misses.

## Case results

| Case | Input and detector | Current result | Coverage | Detector time |
|---|---|---|---|---:|
| CVE-2025-9900 vulnerable | libtiff `9dff73bebc5661f2dace6f16e14cf9e857172f4e`, `ohscanner.cpp.integer_bounds` | 0 diagnostics; `BLOCK`, no candidate conclusion | `tif_getimage.c` and `tiffio.h` both partial and not analyzed | 0.000029 s |
| CVE-2025-9900 fixed | libtiff `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`, same detector/scope | 0 diagnostics; `BLOCK`, not a fixed pass | both files partial and not analyzed | 0.000024 s |
| CVE-2025-0587 vulnerable | arkcompiler `cae11f121c030a90ba41d8e4d866f91292f25892`, `ohscanner.cpp.integer_bounds` | 1 narrow-index root-cause candidate at `atomic_helper.cpp:71`; key `ohscanner.cpp.integer_bounds:b7b2f77b4f18fb3d` | 1/1 complete | 0.003868 s |
| CVE-2025-0587 fixed | arkcompiler `5aa9c035e98911ec7ed28065a2138c2709792a42`, same scope | 0 same-root findings | 1/1 complete | 0.003698 s |
| CVE-2025-23420 vulnerable | arkcompiler `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11`, `ohscanner.cpp.bounds` | 5 direct `ElementAccessor` root-cause candidates in `js_array.cpp` at lines 650, 653, 665, 666, 668 | 1/1 complete | 0.013611 s |
| CVE-2025-23420 fixed | arkcompiler `1b23531531e768398682582969c2a9f17e72cafe`, same scope | 0 same-root findings | 1/1 complete | 0.013014 s |
| CVE-2026-27648 fixed-only replay | exact fixed translation-unit bytes from blob `27e93e338ced03aeed6e7d892e29d4d0740f3653`, packaged in synthetic local commit `7038439a38336e0f74de9e8cdd72bf7b7ce8371f`, `ohscanner.cpp.bounds` | 0 diagnostics; `BLOCK`; fixed-only evidence cannot validate a vulnerable/fixed pair | 1 file partial and not analyzed | 0.000023 s |

For CVE-2026-27648, the read-only source identity record binds the vulnerable full TU to upstream commit `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8`, tree `4ed3b46721fbfe04059af4ddb18bcd5272ce4762`, blob `78e83fea67a2db3297cc59f07566a0c0b6153e7a`, SHA-256 `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920`. The full vulnerable TU bytes and reachable Git object were not present in the available local source mirror at replay time; only a function fragment and prior summaries were available. The fixed full TU was present and SHA-256 matched `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`. The synthetic commit is packaging only; it is not represented as the upstream commit. Minimum input to close this case: restore the exact vulnerable blob (or a local Git object containing the stated upstream commit/blob) and rerun the same current CLI scope with both exact vulnerable and fixed source identities. The parser must analyze the target function before either side can be called PASS.

For CVE-2025-9900, the exact commits and blobs were available in `D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream`, and the CLI replay ran on both sides. The target C file and paired header were both partial on both commits. Minimum input to close the static case: a parser-complete source view for the target function and relevant declarations/macros, or an independently reviewed bounded snippet analysis that preserves the whole-file `PARTIAL` status. Do not interpret these zero-result runs as fixed validation.

## Source identities

| Case | Commit | Tree | Path | Blob | Source SHA-256 |
|---|---|---|---|---|---|
| libtiff vulnerable | `9dff73bebc5661f2dace6f16e14cf9e857172f4e` | `986499c84247e9a1f49560128bbe7580d8ebea1a` | `libtiff/tif_getimage.c` | `6c7b5031a1937bb48cc79808a59618d8a4f6237e` | `cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3` |
| libtiff fixed | `3e0dcf0ec651638b2bd849b2e6f3124b36890d99` | `77361ef7262189e16a2010b5c333f6b275d17f09` | `libtiff/tif_getimage.c` | `2774caa0eef24bce2a619d2686a23d59fb5ef9db` | `de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8` |
| CVE-2025-0587 vulnerable | `cae11f121c030a90ba41d8e4d866f91292f25892` | `61ff01d9a06b4186125a04e2b790e07640f57198` | `ecmascript/base/atomic_helper.cpp` | `7fd67717571c6d8fe7b10bf294998e952dc61e36` | `f4890391896239c845bbcaee489d83c85eb5a64e37d563b91ed6e3908c62a541` |
| CVE-2025-0587 fixed | `5aa9c035e98911ec7ed28065a2138c2709792a42` | `05ac3902979e37ae08efa2d1e3ed32472a69d0cc` | `ecmascript/base/atomic_helper.cpp` | `80d7ad14e70825ef2daf7b3f2fc956a891bf8b2c` | `39521f4c6fa6b4b65d8b3daacd80f6e051b5a01c5aa814c9ac2ffc432529b36b` |
| CVE-2025-23420 vulnerable | `aeee3fd12c03193545edea4b8e0fdfa3d9a03d11` | `0eea26c9eb6846f4d19926be83092c06f0d98692` | `ecmascript/js_array.cpp` | `2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471` | `b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b` |
| CVE-2025-23420 fixed | `1b23531531e768398682582969c2a9f17e72cafe` | `52f27683e2f6e1ba8272aee7d5202c73059e10b4` | `ecmascript/js_array.cpp` | `58266855967e3dc4af97721d3a2fc5417cb887b6` | `f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6` |
| web_webview fixed | `4cf313408de7b6d807465ea2bb22e434269b7c5e` | `a7769bf612be457e6e368f14ee355f3ea8ed2935` | `arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc` | `27e93e338ced03aeed6e7d892e29d4d0740f3653` | `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483` |

The libtiff two-file scope also bound `tiffio.h`: vulnerable blob `225f3c1bfeabae2b31a5f35fbfd12d14b570dcd8`, SHA-256 `70119b9db897a364821a108ff0adc09f26c20ad9b6d9e943eb376ee3edb6166f`; fixed blob `6a7ab2f5b7f6697020dfbcac57f8c2617c4b1074`, SHA-256 `7923903a85c15c047a22bfe52ef1901939d6a7e656c75b814fcb86c6179b120c`.

## Reproduction commands

Run from repository root with Python and local Git objects available. `--include` scopes are explicit and the CLI does not fetch.

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/libtiff-vulnerable.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/libtiff-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\libtiff-cve-2025-9900-upstream --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/libtiff-fixed.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/libtiff-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git --repository openharmony/arkcompiler_ets_runtime --commit cae11f121c030a90ba41d8e4d866f91292f25892 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-0587-vulnerable.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-0587-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git --repository openharmony/arkcompiler_ets_runtime --commit 5aa9c035e98911ec7ed28065a2138c2709792a42 --include ecmascript/base/atomic_helper.cpp --detector ohscanner.cpp.integer_bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-0587-fixed.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-0587-fixed.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git --repository openharmony/arkcompiler_ets_runtime --commit aeee3fd12c03193545edea4b8e0fdfa3d9a03d11 --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-23420-vulnerable.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-23420-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\cve-2025-arkruntime-official.git --repository openharmony/arkcompiler_ets_runtime --commit 1b23531531e768398682582969c2a9f17e72cafe --include ecmascript/js_array.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-23420-fixed.json --md-out research/evidence/cpp/d2_bounds_replay_20261019/cve2025-23420-fixed.md
```

The fixed-only web_webview replay used the same production CLI against a temporary local repository containing the exact fixed source bytes. Its synthetic commit/tree are recorded in `webwebview-fixed-only.json`; source SHA-256 was checked against the supplied read-only identity record. The vulnerable full TU was unavailable, so this is `BLOCK`, not a fixed-pair pass.

## Regression check and disposition

`python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 17/17 passed. This covers detector-level positive, fixed, safe, unrelated, narrow integer promotion, rename-independent semantic shapes, and partial/failed/budget fail-closed controls. It does not substitute for the missing web_webview vulnerable TU or complete parsing of libtiff.

Disposition: no detector code changed. Keep CVE-2025-9900 and CVE-2026-27648 as `PARTIAL/BLOCK`. CVE-2025-0587 and CVE-2025-23420 replay as complete vulnerable/fixed differential capability checks on these fixed objects. Product build, entry, reachability and impact remain outside this static replay.
