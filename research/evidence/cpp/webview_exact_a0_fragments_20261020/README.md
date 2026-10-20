# Exact A0 webview Flowbuffer function-fragment replay

Date: 2026-10-20 (Asia/Shanghai). Detector checkout base: `4c484d82df34b79bb3c01323fb1e897c6c8a9eeb`.

This package extracts `FlowbufStrAtIndex` and `ProcessNativeProxyResultNewFlowbuf` directly from the exact A0 `openharmony/web_webview` source commits. The synthetic Git snapshots exist only to run the current CLI on the extracted bytes plus controls; they are not presented as original A0 commits. Exact A0 source identity and synthetic replay identity are separate fields in `source-identities.json`.

## Source and byte binding

| Variant | Exact A0 commit | Tree | Target blob | Full file SHA-256 | Function fragment SHA-256 | Function ranges (line / byte, half-open) |
|---|---|---|---|---|---|---|
| Vulnerable | `a15cbf4ef20673cfcf1856bf40a723b3ce026564` | `03e16f6f4f2c33c2cd08e31c14e00be689230c39` | `78e83fea67a2db3297cc59f07566a0c0b6153e7a` | `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920` | `70e2cf35f6b143a7fdbf2e6c9a571817545ef9c9efe0199aa1e7c5e6e4afb973` | 4428–4458 / 155734–156659; 4460–4586 / 156660–160418 |
| Fixed | `fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb` | `9873e4146e4a521b80f05a61c24d9c6047f696a7` | `27e93e338ced03aeed6e7d892e29d4d0740f3653` | `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483` | `6d8f1982dae51a633959ba7a7cdeb78c6f1f29d85571ed98e7ffc0c789556e74` | 4428–4463 / 155734–156817; 4465–4592 / 156818–160702 |

Each function's exact contiguous source byte range and SHA-256 is listed in the machine manifest. The two selected ranges are joined by one newline to form the CLI fragment. The current parser reports each combined fragment `complete` with no parse issues.

The earlier D11 source package names `OpenHarmony-TPC/chromium_src`, while this package names `openharmony/web_webview`. The verifier confirms that the old D11 and exact A0 full-file SHA-256, target blob SHA, and extracted fragment SHA are equal. This is a byte-equivalence check only; the Chromium repository's commit/tree is not used as the OpenHarmony A0 source identity.

## Current CLI results

Current `ohscanner.cpp.bounds` 0.3.0 (`ohcpp-memory-bounds-vector-index-candidate-005` 0.1.0), with identical five-file explicit scope on both snapshots:

| Variant | Flowbuffer root candidates | D15 ordinary-loop residuals | Renamed positive | Safe | Unrelated | Partial control | Aggregate |
|---|---:|---:|---:|---:|---:|---|---|
| Vulnerable | 6 | 6 | 1 | 0 | 0 | partial, no diagnostic | blocked |
| Fixed | 0 | 6 | 1 | 0 | 0 | partial, no diagnostic | blocked |

The six vulnerable root sites are fragment lines 85, 87, 96, 98, 140 and 142. Six ordinary argument-loop residuals remain on both sides. The renamed positive remains on both sides. Safe and unrelated controls are quiet. A deliberately incomplete control makes both aggregate runs `blocked`; it does not invalidate the per-file observations, and the blocked aggregates are not pass/safety results.

This demonstrates function-level candidate behavior only. The original exact A0 translation units remain parser-partial and blocked with zero findings as recorded in `webview_exact_a0_20261020/`; the fragment replay does not restore whole-TU coverage or prove vulnerability reachability/impact.

## Reproduction

From the detector worktree root, using the local exact-source checkout and an empty generated snapshot directory:

```powershell
python research/evidence/cpp/webview_exact_a0_fragments_20261020/build_fragments.py
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020 --repository openharmony/web_webview --commit 87a7f7442c548ec8b46db6f73338e28983af9996 --include vulnerable_flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/webview_exact_a0_fragments_20261020/vulnerable.json --md-out research/evidence/cpp/webview_exact_a0_fragments_20261020/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020 --repository openharmony/web_webview --commit 43406588f1ea2d67282fe3920411adcfc4a5c219 --include fixed_flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/webview_exact_a0_fragments_20261020/fixed.json --md-out research/evidence/cpp/webview_exact_a0_fragments_20261020/fixed.md
python research/evidence/cpp/verify_webview_exact_a0_fragments_20261020.py --source-repo D:\openHarmonyScanner\tmp\web-webview-flowbuf-full-tu-m2-20261019 --snapshot-repo D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020 --d11-identities research/evidence/cpp/d11_webview_fragment_20261020/source-identities.json
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q
python scripts/check_change_scope.py --base 349d3b570eafd35f05544ee5b90d32ea377ec5ee --lane cpp
git diff --check
```

The CLI reports are retained beside this README; the verifier rechecks exact source objects and byte slices, synthetic package bytes, D11 hash equivalence without repository conflation, detector identity/status, candidate/control counts and partial blocking.
