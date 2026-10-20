# Exact A0 source replay: OpenHarmony web_webview CVE-2026-27648

Execution date: 2026-10-20 (Asia/Shanghai). Detector checkout: integrated PR #35 scanner at commit `1dcffebe50d7a260b8b58684b7f30ae34efcd80f` before this evidence-only package.

## Exact baseline inputs

Both rows match `research/evidence/cpp/a_static_baseline_20261019/matrix.json` and were scanned from the pinned local Git object store `D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019`.

| Side | Commit | Tree | File blob | File SHA-256 | Selected source | Current CLI result |
|---|---|---|---|---|---|---|
| Vulnerable | `a15cbf4ef20673cfcf1856bf40a723b3ce026564` | `03e16f6f4f2c33c2cd08e31c14e00be689230c39` | `78e83fea67a2db3297cc59f07566a0c0b6153e7a` | `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920` | `arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc` | `ohscanner.cpp.bounds` 0.3.0; 1 file partial, run blocked, 0 diagnostics |
| Fixed | `fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb` | `9873e4146e4a521b80f05a61c24d9c6047f696a7` | `27e93e338ced03aeed6e7d892e29d4d0740f3653` | `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483` | same file | `ohscanner.cpp.bounds` 0.3.0; 1 file partial, run blocked, 0 diagnostics |

The parser reports the same missing/error spans on both versions, beginning at lines 2807 and 3255 and continuing through the later Flowbuffer functions. `analysis_status` is `not_analyzed` with reason `blocked`. These zero-diagnostic outputs do not establish that the vulnerable code is safe or that the fix works.

The source-bound Chromium-derived function snapshots in [the T matrix follow-up](../t_matrix_webview_libtiff_20261020/README.md) do produce a patched-root 6/0 differential with controls. They use related, separately pinned `OpenHarmony-TPC/chromium_src` objects and cannot substitute for a complete parse of these exact `openharmony/web_webview` commits. The exact A0 replay now closes the source-identity/re-execution gap; parser coverage and root detection remain unresolved, so the CVE case stays **PARTIAL/BLOCK**.

## Reproduction

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019 --repository openharmony/web_webview --commit a15cbf4ef20673cfcf1856bf40a723b3ce026564 --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/webview_exact_a0_20261020/vulnerable.json --md-out research/evidence/cpp/webview_exact_a0_20261020/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019 --repository openharmony/web_webview --commit fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/webview_exact_a0_20261020/fixed.json --md-out research/evidence/cpp/webview_exact_a0_20261020/fixed.md
python research/evidence/cpp/verify_webview_exact_a0_20261020.py --source-git-dir D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019
```

The verifier checks both commit/tree/blob/SHA bindings and each CLI report's exact scope, detector version, blocked/partial status and zero-diagnostic result. It records this result as source replay only; no safety or fixed differential is inferred.
