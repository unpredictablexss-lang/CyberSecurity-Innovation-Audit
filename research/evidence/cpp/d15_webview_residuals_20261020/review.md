# D15 web_webview Flowbuffer ordinary-loop residual review

Date: 2026-10-20 (Asia/Shanghai)  
Worktree: `D:/openHarmonyScanner/worktrees/a-d15-webview-residuals-20261020`  
Branch: `codex/a-d15-webview-residuals-20261020`  
Base: `a374fc81b3dc07d7e78471cea08bf34b87e2d01e`

## Result

No detector change is justified by the source evidence reviewed. The six residual findings are three ordinary argument branches, each with a paired `dataList[curIndex]` and `dataSize[curIndex]` write. They are distinct from the three Flowbuffer `while` loops patched by the upstream fix. I could not prove these six are false positives: vector capacities are initialized together from `argsSize + size_t(flowbufSize)`, while `curIndex` is advanced by both Flowbuffer and ordinary-argument processing. However, the total-count invariant and integer conversions are not established by this function alone. Keep all six as unresolved candidates; do not suppress them or call them confirmed vulnerabilities.

The D11 root-specific differential remains unchanged: 6 vulnerable candidates at the patched Flowbuffer loop sites and 0 at those sites in the fixed fragment. The six ordinary-argument candidates remain on both. The exact function fragments parse complete; the full translation-unit result remains partial/blocked with zero findings, and is not a safety result. Case status stays **PARTIAL**.

## Source and detector identity

- Repository: `OpenHarmony-TPC/chromium_src`
- Path: `arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc`
- Vulnerable source: commit `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8`, tree `4ed3b46721fbfe04059af4ddb18bcd5272ce4762`, blob `78e83fea67a2db3297cc59f07566a0c0b6153e7a`, file SHA-256 `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920`.
- Fixed source: commit `4cf313408de7b6d807465ea2bb22e434269b7c5e`, tree `a7769bf612be457e6e368f14ee355f3ea8ed2935`, blob `27e93e338ced03aeed6e7d892e29d4d0740f3653`, file SHA-256 `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483`.
- Detector: `ohscanner.cpp.bounds` 0.3.0; rule `ohcpp-memory-bounds-vector-index-candidate-005` 0.1.0.
- Source-derived fragment SHA-256: vulnerable `70e2cf35f6b143a7fdbf2e6c9a571817545ef9c9efe0199aa1e7c5e6e4afb973`; fixed `6d8f1982dae51a633959ba7a7cdeb78c6f1f29d85571ed98e7ffc0c789556e74`.

## Six residual locations

Line numbers below are in the extracted complete function fragment, matching the scanner reports. Each pair indexes the same two vectors at the same cursor.

| Type branch | `dataList` write | paired `dataSize` write | Source relation | Assessment |
|---|---:|---:|---|---|
| String | 122 | 124 | `argString` bytes and `argString.size()` | Unresolved candidate; not proven safe or erroneous |
| Binary | 132 | 133 | moved `data` constructed with `argBinary->GetSize()` and the same `size` | Unresolved candidate; not proven safe or erroneous |
| Other / JSON | 137 | 139 | `jsonString` bytes and `jsonString.size()` | Unresolved candidate; not proven safe or erroneous |

At all six sites, `curIndex` is consumed by the surrounding argument loop; it advances once after the selected branch. `argsSize` is a `size_t`. `flowbufSize` is returned by `GetFlowbufCount`, whose loop can count at most `MAX_ENTRIES`. Both vectors use `argsSize + static_cast<size_t>(flowbufSize)` as their constructor count. The separate guard count is `int dataListSize = argsSize + flowbufSize`; the addition and narrowing to `int` need a proven range before the cursor guard can establish a complete bound. The ordinary-argument loop itself is controlled by `i < argsSize`, and is not directly guarded by `curIndex < dataListSize` at the three branch writes. Flowbuffer entries can also advance `curIndex` before and between ordinary arguments. This source does not provide the CEF argument-count limit or a complete invariant tying every cursor advance to the vector count.

The missing proof is therefore specific: a bound on `argsSize` and a no-overflow proof for the sum, `dataListSize`, and all `curIndex` increments, together with the ordering/count contract for Flowbuffer entries. Without those, suppressing the candidates risks treating a narrowing/overflow path as safe. Conversely, the source alone does not establish that such an input is reachable or that a practical out-of-range access occurs.

## Replays and controls

Replayed from this worktree at the pinned synthetic source snapshots with the same explicit scope:

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d15_webview_residuals_20261020/current-vulnerable.json --md-out research/evidence/cpp/d15_webview_residuals_20261020/current-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d15_webview_residuals_20261020/current-fixed.json --md-out research/evidence/cpp/d15_webview_residuals_20261020/current-fixed.md
```

Results: vulnerable has 13 diagnostics total, including 6 patched-root and 6 ordinary residual findings; fixed has 7 total, including 0 patched-root and the same 6 ordinary residuals. The renamed positive reports and the safe/unrelated controls are quiet on both. The partial control has partial parse and keeps the aggregate run blocked/limited. The extracted `flowbuffer_functions.cc` parses complete on both. Machine-readable output and markdown are adjacent to this report.

The exact full translation units were already replayed in D11/T7 and remained partial/blocked with zero findings. This review does not upgrade that coverage. Product build, entry reachability, attacker control, and impact remain unverified.

## Validation

- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q` — 20 passed.
- The two exact-scope CLI replays above completed and retained the D11 6/0 patched-root differential.
- `git diff --check` and C++ change-scope check are recorded with the D15 commit.
