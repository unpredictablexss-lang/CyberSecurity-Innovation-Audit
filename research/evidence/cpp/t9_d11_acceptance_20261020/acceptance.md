# T9 independent acceptance: D11 / D12

Date: 2026-10-20 (Asia/Shanghai)  
Worktree: `D:/openHarmonyScanner/worktrees/a-t9-d11-acceptance-20261020`  
Branch: `codex/a-t9-d11-acceptance-20261020`  
Frozen base: `c0a80cc630450f499ea4d04adee20619b5c2c4e9`

## D11 — web_webview CVE-2026-27648

**Function-fragment regression: PASS. Whole translation-unit case: PARTIAL/BLOCK.** No precision or recall conclusion is made.

Independently read the exact vulnerable and fixed source blobs from the local bare Chromium mirror `D:/openHarmonyScanner/tmp/chromium-src-cve-2026-27648-audit.git`. Commit, tree, blob, full-file SHA-256, byte count, extracted function ranges, fragment SHA-256, and complete fragment parser status all matched `source-identities.json`; details are in `source-identity-check.json`. The exact functions are `FlowbufStrAtIndex` and `ProcessNativeProxyResultNewFlowbuf`.

Replayed the current frozen bounds CLI against both fragment snapshots with the same explicit five-file scope. Detector `ohscanner.cpp.bounds` 0.3.0 / rule `ohcpp-memory-bounds-vector-index-candidate-005` 0.1.0 produced:

| Variant | Patched Flowbuffer root sites | Ordinary argument-loop residuals | Renamed positive | Safe | Unrelated |
|---|---:|---:|---:|---:|---:|
| Vulnerable | 6 | 6 | 1 | 0 | 0 |
| Fixed | 0 | 6 | 1 | 0 | 0 |

The fragment snapshot has four complete files and one partial control. The partial control has no diagnostic and keeps each aggregate run blocked. The six ordinary residuals remain candidate findings; they are not a confirmed vulnerability conclusion. The positive/fixed comparison is limited to the six Flowbuffer loop sites.

The exact full translation units were separately replayed from their local synthetic snapshots. Both parser results are `partial`; both detector runs are `blocked` with zero findings. This is unknown coverage, not a safe result. Product build association, runtime reachability, attacker control, and impact are not established.

Rule and assertion review: candidate generation is restricted to parsed dynamic `std::vector` subscripts with a same-function local loop/branch condition; quieting requires modeled nonnegative index, matching vector capacity or `.size()`, supported increment, and no recognized mutation/index rewrite before the access. The regression asserts vulnerable/fixed, same-vector safe guards, unrelated fixed-array access, renamed symbols, mutation controls, and partial blocking. Lexical control-flow and symbol modeling still leave aliases, constructor arithmetic, complete CFG/dominance, macros/templates, and cross-loop count/cursor relationships unknown.

## D12 — libpng fragment status verification

Independently reran the D12 fragment replay script against the source roots and wrote fresh output to `d12-independent.json`. Every supplied source file matched the script's recorded SHA-256. The outcomes match D12's report:

- CVE-2026-33416: 4 functions per version; both translation units and all eight isolated fragments parse `partial`; zero findings. Status remains **PARTIAL/BLOCK**. The experiment does not support root-cause detection or fixed/safe inference.
- CVE-2026-46675: 7 function fragments per version; both translation units parse `partial`, and six fragments parse complete while `png_handle_iCCP` remains partial on each version; zero findings. Status remains **PARTIAL/BLOCK**. The interprocedural zstream state transition and later IDAT consumption are not modeled, so the zero result is inconclusive.

The replay did not alter detector/tests/fixtures and did not add controls or rules. Product build and call-path evidence also remain absent.

## Validation and reproduction

Commands run from this worktree:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t9_d11_acceptance_20261020/vulnerable.json --md-out research/evidence/cpp/t9_d11_acceptance_20261020/vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/t9_d11_acceptance_20261020/fixed.json --md-out research/evidence/cpp/t9_d11_acceptance_20261020/fixed.md
python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q
python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -q
python -m scripts.check_change_scope --base c0a80cc630450f499ea4d04adee20619b5c2c4e9 --lane cpp
git diff --check
```

Results: bounds tests 20/20 passed; C++ detector tests 160/160 passed; change scope checked 12 evidence paths with zero violations; `git diff --check` clean. D12 replay invocation and exact input roots are present in the run provenance in `d12-independent.json`.

Full-TU replays used the same file scope against the local source snapshots and commits recorded in the resulting JSON. The first invocation using upstream commit IDs against a synthetic snapshot repo failed before scanning; it was corrected to the snapshot commits (`a15cbf4...` and `fa0d92...`) and the accepted outputs are `full-vulnerable.json` / `full-fixed.json`. The corrected runs both report partial parsing and blocked detector coverage.

D12 replay command:

```powershell
python D:\openHarmonyScanner\worktrees\a-d12-libpng-fragment-20261020\research\evidence\cpp\d12_libpng_function_fragments_20261020.py --33416-vulnerable D:\openHarmonyScanner\tmp\libpng-runtime-cve-2026-33416-20261019\vulnerable --33416-fixed D:\openHarmonyScanner\tmp\libpng-runtime-cve-2026-33416-20261019\fixed --46675-vulnerable D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-source-20261019\vulnerable-1.6.55 --46675-fixed D:\openHarmonyScanner\tmp\libpng-ghsa-qvg3-source-20261019\fixed --output research/evidence/cpp/t9_d11_acceptance_20261020/d12-independent.json
```
