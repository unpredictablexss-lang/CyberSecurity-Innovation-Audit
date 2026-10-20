# D37 — web_webview ordinary-loop residual review

Date: 2026-10-20 (Asia/Shanghai)  
Scanner base: `73d5c356b1b1dbc081727948d89d6502c862f3af`  
Detector: `ohscanner.cpp.bounds` 0.3.0; rule `ohcpp-memory-bounds-vector-index-candidate-005` 0.1.0

## Decision

No bounds-rule change is justified by the currently available source facts. All six ordinary-loop sites remain **unknown candidates**: the code shape suggests a cursor/capacity relationship, but this review cannot prove every cursor increment is bounded or construct a concrete out-of-range execution. The findings remain enabled; this is not a safety conclusion.

The six sites form three paired writes in `ProcessNativeProxyResultNewFlowbuf`:

| Branch | Exact A0 vulnerable/fixed file lines | Extracted fragment line | Accesses | Classification | Missing fact for benign classification |
|---|---:|---:|---|---|---|
| String | 4549/4554, 4551/4556 | 122, 124 | `dataList[curIndex]`, `dataSize[curIndex]` | unknown | A bound ensuring `argsSize` and cursor increments fit the cursor type and allocated `size_t` capacity |
| Binary | 4559/4564, 4560/4565 | 132, 133 | `dataList[curIndex]`, `dataSize[curIndex]` | unknown | Same cursor/capacity bound and proof of the Flowbuffer count/order contract |
| Other/JSON | 4564/4569, 4566/4571 | 137, 139 | `dataList[curIndex]`, `dataSize[curIndex]` | unknown | Same cursor/capacity bound and proof of the Flowbuffer count/order contract |

Exact fixed A0 identity: `openharmony/web_webview`, commit `fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb`, tree `9873e4146e4a521b80f05a61c24d9c6047f696a7`, blob `27e93e338ced03aeed6e7d892e29d4d0740f3653`, full-file SHA-256 `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`. Exact vulnerable identity and byte ranges are preserved in the source identity manifest referenced below.

The vector capacity is `argsSize + static_cast<size_t>(flowbufSize)`. Ordinary arguments advance `curIndex` once per loop iteration; Flowbuffer records can also advance it. The safe-looking count relation is insufficient by itself: the source evidence reviewed here does not bind `argsSize` to an `int`-representable maximum, prove no overflow in capacity arithmetic, or establish a complete contract between `GetFlowbufCount`, indexed Flowbuffer consumption and `argIndex` ordering. The fixed version's `int dataListSize = argsSize + flowbufSize` is not used to guard the ordinary argument writes, and does not provide those missing proofs.

Classification for each individual access:

- **root**: not established; no concrete execution showing an ordinary-argument write out of range was found.
- **benign**: not established; the count/type and Flowbuffer ordering facts above are absent.
- **unknown**: applies to all six sites and preserves the scanner's candidate behavior.

This is a narrow source-semantics conclusion, not a claim that the issue is exploitable or that the accesses are safe. Whole translation-unit parsing remains partial/blocked.

## Replay

Replayed from this scanner checkout against the exact-A0-derived synthetic snapshots. The synthetic commit IDs identify the replay snapshots, not upstream source commits:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020 --repository openharmony/web_webview --commit 87a7f7442c548ec8b46db6f73338e28983af9996 --include vulnerable_flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d37_webview_residuals_20261020/vulnerable.json --md-out research/evidence/cpp/d37_webview_residuals_20261020/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\webview-exact-a0-fragments-20261020 --repository openharmony/web_webview --commit 43406588f1ea2d67282fe3920411adcfc4a5c219 --include fixed_flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d37_webview_residuals_20261020/fixed.json --md-out research/evidence/cpp/d37_webview_residuals_20261020/fixed.md
python research/evidence/cpp/d37_webview_residuals_20261020/verify.py
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q
```

Results: vulnerable/fixed totals are 13/7; patched-root sites are 6/0; ordinary residuals are 6/6; renamed positive is 1/1; safe and unrelated controls are 0/0. The partial control remains partial and both aggregates remain `completed_with_limitations`. The findings use the same rule and version listed above. Exact source and fragment hashes, control hashes, and line mappings are in `../webview_exact_a0_fragments_20261020/source-identities.json` and `../webview_exact_a0_fragments_20261020/README.md`.

The six accesses stay unresolved because the same evidence is compatible with both (a) a valid count invariant and (b) arithmetic/type/order cases not ruled out by this function fragment. A generic suppression or new capacity inference would be unsound without the missing semantic facts. No source-specific exception or hash/CVE special case was introduced.

## Verification

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q` — 20 passed.
- `python research/evidence/cpp/d37_webview_residuals_20261020/verify.py` — verifies exact observed locations, counts, rule versions, controls and partial aggregate state.
- `python -m scripts.check_change_scope --base 73d5c356b1b1dbc081727948d89d6502c862f3af --lane cpp` — zero violations.
- `git diff --check` — clean.
- Vulnerable and fixed CLI replay commands above completed at scanner base `73d5c356b1b1dbc081727948d89d6502c862f3af`.
- The exact-A0 fragment package's prior source identity verifier remains the binding reference; it requires the source checkout, snapshot checkout and D11 identity manifest paths supplied in that package README.
- Full translation-unit parse and product-level reachability/impact remain unknown.
