# D11 web_webview CVE-2026-27648 function-fragment replay

Date: 2026-10-20 (Asia/Shanghai)  
Worktree: `D:/openHarmonyScanner/worktrees/a-d11-webview-fragment-20261020`  
Branch: `codex/a-d11-webview-fragment-20261020`  
Base: `983afb846ceaa34daf690c39e4918703c4ac99a7`

## Outcome

The integration base actually contained `ohscanner.cpp.bounds` 0.2.0 and no dynamic `std::vector` subscript rule. A separate detached worktree at the exact base reran M2 on the extracted vulnerable and fixed function fragments: both returned 0 findings and `blocked` coverage due to the partial control. This baseline confirms that the current pre-D11 integration code could not reproduce T7's root-specific result. D11 adds `ohcpp-memory-bounds-vector-index-candidate-005` (rule 0.1.0), and advances the bounds detector to 0.3.0. Baseline JSON/Markdown reports are retained beside the current reports.

The current production CLI replay over source-derived function fragments yields:

| Source slice | Flowbuffer patched-loop root candidates | Ordinary argument-loop candidates | Renamed positive control | Safe / unrelated controls |
|---|---:|---:|---:|---:|
| 6.0 vulnerable parent | 6 | 6 | 1 | 0 |
| 6.0 fixed merge | 0 | 6 | 1 | 0 |

Each run also includes a deliberately incomplete C++ control: it parses `partial`, receives no finding, and causes the aggregate detector run to stay `blocked`. The `flowbuffer_functions.cc` source fragment itself parses complete. Therefore the root-specific fragment differential is a static regression result, while each aggregate CLI run is blocked due to the partial control. It is not a whole-component pass.

T7's v0.3.6 result (12 vulnerable / 6 fixed) separates into the same two categories: six candidates at the three patched Flowbuffer `while` loops on the vulnerable source, zero at those sites after the patch, and six ordinary argument-loop candidates on both versions. D11 reproduces that structural separation with its own v0.3.0 detector / rule-005 evidence. The six ordinary-loop candidates remain unresolved: the rule does not model the count/capacity relation, all integer conversions, and the cross-loop cursor invariant, so it does not suppress them.

The exact full translation units were also replayed with current D11 code. Vulnerable and fixed each remain `parse partial`, detector `blocked`, and 0 findings. No full-file negative or safe result is claimed. Overall case status remains **PARTIAL**.

## Source identity and extraction

`source-identities.json` is produced by `build_fragments.py`. The script reads directly from the local bare upstream object database with `git --git-dir ... show`; it does not use the old synthetic fragment bytes. It verifies commit, tree, target blob, source byte count and SHA-256 before extracting the complete enclosing functions `FlowbufStrAtIndex` and `ProcessNativeProxyResultNewFlowbuf` using the local parser. Both fragments parse `complete` with zero parse issues.

| Revision | Commit | Tree | Target blob | File SHA-256 | Function lines | Fragment SHA-256 |
|---|---|---|---|---|---|---|
| Vulnerable parent | `5ab1905a8fba8d07e9ab4a9453a7787ec274a1a8` | `4ed3b46721fbfe04059af4ddb18bcd5272ce4762` | `78e83fea67a2db3297cc59f07566a0c0b6153e7a` | `aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920` | 4428–4458; 4460–4586 | `70e2cf35f6b143a7fdbf2e6c9a571817545ef9c9efe0199aa1e7c5e6e4afb973` |
| Fixed merge | `4cf313408de7b6d807465ea2bb22e434269b7c5e` | `a7769bf612be457e6e368f14ee355f3ea8ed2935` | `27e93e338ced03aeed6e7d892e29d4d0740f3653` | `332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483` | 4428–4463; 4465–4592 | `6d8f1982dae51a633959ba7a7cdeb78c6f1f29d85571ed98e7ffc0c789556e74` |

The local snapshot commits package those exact fragments plus identical controls. They are synthetic scan inputs, not upstream commits. Their exact tree and commit identities are in the JSON manifest.

## Rule behavior and controls

The new rule emits a candidate only for a dynamic `std::vector` subscript without a recognized same-loop bound. It suppresses a candidate only when a local nonnegative index fact and an exact bound for the indexed vector's `size()` or constructor-size expression are present in the same loop/branch. It does not infer a bound from a different index, infer the ordinary argument count from the Flowbuffer count, or suppress the six remaining writes.

- Positive: all six subscript writes in the vulnerable Flowbuffer loops; renamed dynamic-vector control also reports.
- Fixed: those six root-specific locations are quiet; six ordinary argument-loop writes remain candidates.
- Safe: an unsigned zero-start `for` loop bounded by the same vector's `.size()` is quiet.
- Unrelated: a fixed array guarded by a local nonnegative and literal upper bound is quiet.
- Renamed: a dynamic-vector unbounded subscript using renamed symbols reports, showing the rule is not keyed to CVE names or application symbols.
- Partial: incomplete source has no finding and keeps `blocked` coverage.

The root-specific separation is source-location / enclosing-loop classification, not a claim that every vector index candidate is exploitable. Full function/source ranges are hash-bound; product build, execution reachability, attacker control and impact remain unknown.

## Commands

Rebuild the source-derived slices and snapshot commits:

```powershell
python research/evidence/cpp/d11_webview_fragment_20261020/build_fragments.py
```

Current detector replay (same explicit scope on both versions):

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-vulnerable.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-fixed.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-fixed.md
```

The baseline runs used the same scope and were executed from a detached worktree at base `983afb846ceaa34daf690c39e4918703c4ac99a7`:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out D:\openHarmonyScanner\worktrees\a-d11-webview-fragment-20261020\research\evidence\cpp\d11_webview_fragment_20261020\baseline-vulnerable.json --md-out D:\openHarmonyScanner\worktrees\a-d11-webview-fragment-20261020\research\evidence\cpp\d11_webview_fragment_20261020\baseline-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out D:\openHarmonyScanner\worktrees\a-d11-webview-fragment-20261020\research\evidence\cpp\d11_webview_fragment_20261020\baseline-fixed.json --md-out D:\openHarmonyScanner\worktrees\a-d11-webview-fragment-20261020\research\evidence\cpp\d11_webview_fragment_20261020\baseline-fixed.md
```

Full translation-unit replays and outputs are recorded in `replay.json` and `current-full-*.json/.md`. Fragment detector elapsed times were 0.01249 s vulnerable and 0.01236 s fixed in the recorded runs. These are local wall measurements for the small explicit scope, not product-scale performance measurements.

## Validation and limits

- Focused bounds regression: `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -q` — 20/20 passed.
- Full C++ detector regression: `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -q` — 160/160 passed.
- Change scope: `python -m scripts.check_change_scope --base 983afb846ceaa34daf690c39e4918703c4ac99a7 --lane cpp` — 19 paths checked, 0 violations.
- `git diff --check` — clean.
- No parser, Catalog, public API, shared documentation or product source was changed.
- The source-fragment result does not upgrade full translation-unit coverage from partial/blocked, and the case remains PARTIAL.
