# CVE-2026-27648 Flowbuffer bounds root-cause card (2026-10-19)

## Disclosure and patch verification

OpenHarmony's official April 2026 security notice lists CVE-2026-27648 as a web_webview out-of-bounds write with remote arbitrary-code-execution impact, CVSS 8.8, affecting OpenHarmony 5.0.3, 5.1.0 and 6.0 release lines. It links three merged fixes in OpenHarmony-TPC/chromium_src: PR #7093 for 6.0 (`4cf313408de7b6d807465ea2bb22e434269b7c5e`), PR #7110 for 5.1 (`9082c13cea0f423b99ba0dc7ca105515e7373d44`), and PR #7108 for 5.0.3 (`ffdf319542b161da7211dc33cbf3d4dc565f370f`). Each official merge changes `NWebHandlerDelegate::FlowbufStrAtIndex` and `ProcessNativeProxyResultNewFlowbuf` with the same data-range check and three vector-index guards. Exact identities are in `source-identities.json`.

The vulnerable sources are the first parents of those merges, not arbitrary older tags. Official merge commits and branch names were checked on GitCode and exact commits were fetched explicitly into isolated workspace bare repo `D:\openHarmonyScanner\tmp\chromium-src-cve-2026-27648-audit.git`. Fetching and scanning were separate. This repository is a temporary source mirror, not a product checkout.

## Root-cause card

1. **Potential attacker control / unknowns:** the official notice classifies this as remotely triggerable. The affected code maps read-only Ashmem supplied through a flowbuffer adapter and consumes a header containing entry indexes and lengths. Which web content, renderer/native bridge, IPC permissions and product build expose attacker-controlled header fields is not established here.
2. **Flow to dangerous operations:** `FlowbufStrAtIndex` reads per-entry length values from the mapped header, sums preceding lengths into `offset`, reads the current entry length into `strLen`, then returns `dataSegment + offset`. `ProcessNativeProxyResultNewFlowbuf` constructs `dataList` with `argsSize + flowbufSize` entries and uses header-derived `argIndex`/`curIndex` to write `dataList[curIndex]` and copy the returned memory range into vectors/strings.
3. **Missing guarantees in the vulnerable release branches:** no check established `offset + strLen <= MAX_FLOWBUF_DATA_SIZE` before returning a pointer into the data segment; three `while (argIndex == curIndex)` loops wrote `dataList[curIndex]` without checking `curIndex < dataListSize`.
4. **Patch invariant:** reject flowbuffer ranges extending beyond the mapped data region (set `argIndex=-1`, return null) and perform each dynamic-vector write only while `curIndex < dataListSize`. This reflects two related bounds obligations: backing mapped-buffer extent and dynamic container extent. Arithmetic conversions/overflow and null propagation still require review; do not infer the patch proves every input safe.
5. **Static proof obligations:** bind `offset` and `strLen` to untrusted header reads; prove their sum and units relative to mapped extent; bind `dataList` capacity to its constructor expression; prove all `curIndex` values and guard dominance; retain signedness and conversion unknowns. Entry reachability, attacker control and impact remain separate obligations.
6. **Safe lookalikes:** `dataList[curIndex]` is safe when a dominating path proves `curIndex < dataList.size()` (or a valid exact capacity alias); pointer addition is safe when the complete interval is within the mapped region. A generic `if`, unrelated index bound or same-named variable is not proof.

## Current production baseline

Scanner HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`. Exact same source file and profile, 6.0 vulnerable parent vs fixed merge:

- `ohscanner.cpp.integer_bounds` 0.2.6: 0 diagnostics on both; each run is blocked because this 185 KiB file parses partial.
- `ohscanner.cpp.bounds` 0.3.2: 0 diagnostics on both; blocked/partial.
- `ohscanner.cpp.unsafe_memory_call` 0.1.3: 0 diagnostics on both; blocked/partial.

These are not a valid detector miss or fixed/safe result. Direct parser probe reports unrelated syntax issues at lines 2807, 3255-3259 and pointer-to-member call expressions around lines 5011-5059; the affected functions are still present in the partial AST, but production detectors fail closed for the whole SourceUnit. All raw M2 reports are in this folder. No component build, runtime exploit reproduction, safe/unrelated production control, or holdout was run for this case.

## Vector-index rule experiment (2026-10-19)

The baseline exact function-fragment probe found zero findings on both sides and on unguarded/guarded vector controls. Added registered rule `ohcpp-memory-bounds-vector-index-candidate-004` to `ohscanner.cpp.bounds` (v0.3.5). It reports local and reference-parameter `std::vector` symbolic indexes without a recognized same-loop upper bound. It recognizes direct `.size()` bounds and simple constructor-capacity aliases when the index is known nonnegative. Signed conversions, alias mutation, `if` dominance and complete CFG remain unknown. Backing mapped-byte extents are not modeled.

Focused regression: local and parameter unguarded vector indexes are candidates; same-loop `.size()` bounds with nonnegative indexes, matching constructor-capacity aliases, and unrelated fixed-array controls are quiet; incomplete input is blocked. A signed index without a lower-bound proof remains a candidate. Same-branch `if (index >= 0 && static_cast<size_t>(index) < v.size())` is quiet; positive-only bounds remain candidates. Focused bounds tests passed 8/8. Exact vulnerable Flowbuffer fragments produce 12 candidates; fixed fragments produce 6 at lines 122, 124, 132, 133, 137 and 139. These are actual `dataList[curIndex]`/`dataSize[curIndex]` subscripts in the ordinary `for (i < argsSize)` argument-processing branch. The patch bounds three Flowbuffer `while` loops; it does not add a direct bound to these ordinary-argument writes. Their safety depends on a cross-loop count invariant relating `curIndex`, `argsSize`, consumed flowbuffers and vector sizes. The detector does not prove that invariant, so the six fixed candidates remain unresolved.

Current-checkout M2 v0.3.5 replay used the same exact one-file scope for vulnerable parent and fixed merge. Both report zero diagnostics and remain partial/blocked because unrelated parser errors occur elsewhere in the file. This is neither a whole-file vulnerable detection nor a fixed-safe verdict. Function fragments are research probes, not production M2 scans. No component runtime, build or mapped-span rule was implemented.

Evidence: `function-fragment-probe.json` records exact source lines for each finding and contains unguarded parameter, same-loop safe, positive-only guard, and incomplete controls. Production reports: `post-v035-parent-bounds.json/.md`, `post-v035-fixed-bounds.json/.md`. Next exact operation: obtain the exact pinned official object/source by successful explicit acquisition, inspect `GetFlowbufCount`, and prove the cross-loop index invariant including signed overflow and size conversion. The local promisor source object was missing and its attempted automatic fetch failed; no scanner/source files were modified by that lookup. Suppress fixed residuals only if source evidence and a structural regression prove safety; otherwise retain them as unknown and switch family.


## Production CLI fragment replay (2026-10-19)

To distinguish per-file parser blocking from detector registration, the exact two complete function ranges above were packaged into a local synthetic Git snapshot pair. Source identities, upstream commit, ranges, fragment hashes and synthetic tree/commit IDs are in `fragment-m2-source-identities.json`; `create_fragment_m2_snapshots.py` shows the extraction procedure. The synthetic commits contain these extracted function bytes plus identical controls; they are not upstream commits.

Using scanner HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`, registered production CLI `ohscan-run`, `ohscanner.cpp.bounds` v0.3.5 and `light-ast`: vulnerable exact fragments parse complete and report 12 candidates (0.0092 s); fixed exact fragments parse complete and report 6 candidates (0.0099 s). Reports: `fragment-m2-vulnerable.json/.md` and `fragment-m2-fixed.json/.md`. This demonstrates that the registered rule executes on the real-source-derived functions. It does not satisfy the fixed-version gate: six ordinary-argument vector writes remain unresolved. Full original-file CLI scans are still partial/blocked and cannot be interpreted as negative or fixed-safe.

Separate production CLI controls: guarded vector `.size()` loop and same-if signed lower bound plus size_t-cast upper bound report 0 (`fragment-m2-safe-vector-controls.json/.md`). A guarded fixed-array control reports one existing `ohcpp-memory-bounds-index-candidate-002` finding (`fragment-m2-unrelated-array.json/.md`); retain this as a failed safe/unrelated gate, not as evidence of a clean result. The unguarded vector plus safe controls combined produced three findings because of the fixed-array candidate and a control-name collision; the isolated reruns identify the vector-safe shapes as quiet and preserve the array issue. No independent held-out variant was evaluated.

Replay command pattern (use the recorded synthetic snapshot commit IDs):

```powershell
python -m src.cli ohscan-run --repo-dir D:\\openHarmonyScanner\\tmp\\web-webview-flowbuf-fragment-m2-20261019 --repository OpenHarmony-TPC/chromium_src --commit d5ab663b730bbda87452a31782aecb804139a23c --include flowbuf_functions.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/web_webview_cve_2026_27648_20261019/fragment-m2-vulnerable.json --md-out research/evidence/cpp/web_webview_cve_2026_27648_20261019/fragment-m2-vulnerable.md
python -m src.cli ohscan-run --repo-dir D:\\openHarmonyScanner\\tmp\\web-webview-flowbuf-fragment-m2-20261019 --repository OpenHarmony-TPC/chromium_src --commit 9116238d44dbf6c5e89f85d4ab073f3afae2ae21 --include flowbuf_functions.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/web_webview_cve_2026_27648_20261019/fragment-m2-fixed.json --md-out research/evidence/cpp/web_webview_cve_2026_27648_20261019/fragment-m2-fixed.md
```


## Guarded fixed-array control and v0.3.6 replay (2026-10-19)

The v0.3.5 M2 control surfaced a false candidate for a fixed array inside `if (index >= 0 && index < 8)`. Added a narrow same-function, same-positive-branch recognizer requiring a conjunction and a literal upper bound no greater than the declared array capacity. The focused regression keeps one-sided and disjunctive guards as candidates. This raises the registered detector to v0.3.6. Bounds are indexed once per source unit; no public API or runner changes were made.

Focused regression: `python -m unittest tests.detectors.test_cpp_memory_safety_detectors.BoundsDetectorControlTests -v` — 9/9 passed. Full detector suite after the new regression: 150 tests, 4 failures and 3 errors from existing dirty fixture/manifest hash and byte-length mismatches; this was not cleaned up or rewritten.

Current-code production CLI replay (v0.3.6): the exact 6.0 source fragments remain 12 vulnerable / 6 fixed residual candidates (complete parse; about 0.01 s per run). Guarded vector and guarded fixed-array controls each return 0. Reports are `post-v036-fragment-vulnerable.json/.md`, `post-v036-fragment-fixed.json/.md`, `post-v036-safe-vector.json/.md` and `post-v036-unrelated-array.json/.md`.

An untrained 5.1 release-branch variant was held out before evaluation. Its exact hash-bound fragments parse completely and production M2 reports 12 candidates on the vulnerable parent and 6 on the official fixed merge (`holdout-51-vulnerable.json/.md`, `holdout-51-fixed.json/.md`). This verifies a cross-branch vulnerable hit but **fails** the fixed gate. It is now consumed evidence; future tuning must add a fresh holdout. Source commits, paths, blobs, whole-source hashes, fragment hashes/ranges, and synthetic IDs are in `holdout-51-source-identities.json`.

The v0.3.6 full vulnerable translation-unit report is `post-v036-full-vulnerable.json`: parser partial, detector blocked, zero findings. A full fixed translation-unit v0.3.6 replay did not complete and produced no report; do not infer safety. Earlier v0.3.5 full-file results also remain partial/blocked. One exact fixed full-source CLI attempt stalled against a promisor-backed local mirror; it was interrupted. Do not repeat with implicit fetch. The next action is a no-lazy-fetch local object search for `GetFlowbufCount` and its callers; only explicitly acquire source if that exact blob is absent, then prove/disprove the ordinary-argument index invariant before changing candidate behavior.


Final production CLI replay after v0.3.6 guard indexing optimization is preserved as `final-v036-6.0-vulnerable.json/.md`, `final-v036-6.0-fixed.json/.md`, and `final-v036-5.1-vulnerable.json/.md`, `final-v036-5.1-fixed.json/.md`. On complete function fragments: 6.0 12/6, 5.1 12/6; each run completed in about 0.01 seconds with source binding. Guarded safe vector and unrelated fixed-array controls are `post-v036-safe-vector.json/.md` and `post-v036-unrelated-array.json/.md`, both 0.


## Fixed-fragment count-source analysis (2026-10-19)

With `GIT_NO_LAZY_FETCH=1`, bounded `git grep` found `GetFlowbufCount` in each exact 6.0 and 5.1 source file. The helper bodies are byte-bound in `get_flowbuf_count_source.txt` and `get_flowbuf_count_source_identities.json`. Each body counts the consecutive nonzero-length header entries in a loop with `i < MAX_ENTRIES`, so its return range is `0..MAX_ENTRIES`. The helper is identical in each vulnerable/fixed pair. The source search also emitted errors for unrelated absent CAPI blobs, so no full component object closure is claimed.

This proves the external-entry count bound only. It does not establish the complete fixed-write safety invariant: the vector constructor uses size_t addition of `argsSize` and the count, `dataListSize` stores the sum in `int`, and `curIndex` is also `int`. The ordinary loop increments once on the null path and after each regular argument, while flowbuffer loops advance the cursor separately. Keep the six fixed candidates until the additions, conversions and cursor range are proven for the actual type/build profile; the upstream patch does not justify blanket suppression. `get_flowbuf_count_no_lazy_search.json` preserves the no-lazy-fetch search and its missing unrelated blob diagnostics.

The final full A-line suite log is `full-suite-v036.log`: 150 tests, 4 fixture/manifest failures and 3 errors. These are existing dirty evidence integrity problems (null dereference, shared_ptr guard lifetime, memory safety, resource lifetime, null-signal, unsafe-call controls); fixtures and manifests remain untouched. The focused bounds control class passes 9/9.


## Root-specific diagnostic delta (2026-10-19)

Mapped every v0.3.6 production CLI finding to source lines in `root-cause-diagnostic-map-v036.json`. On both 6.0 and 5.1, the vulnerable source has six candidates in the three Flowbuffer `while` loops: one `dataList[curIndex]` and one matching `dataSize[curIndex]` per loop. The official fix adds `curIndex < dataListSize` to those loops; the fixed fragments have zero findings at those six root sites. The 5.1 side was held out before evaluation. This is a root-specific vulnerable→fixed differential.

Each fixed version still reports six `dataList`/`dataSize` writes in the ordinary `for (i < argsSize)` loop. The same six sites also occur in the vulnerable version and are not the disclosed missing while-loop bound. They remain unresolved candidate obligations: capacity uses size_t addition, `dataListSize` is stored in `int`, and `curIndex` is `int`. Do not suppress them until those ranges are proven. Thus the root-specific patch gate passes at function scope, while the broader vector-index rule retains separate unknowns.

The exact full 6.0 translation units were replayed through M2 v0.3.6 using one-file synthetic snapshots from the byte-identical pinned upstream blobs (`full-tu-m2-source-identities.json`, `create_full_tu_m2_snapshots.py`). Both source files parse partial and the detector is blocked with zero diagnostics: `final-v036-full-6.0-vulnerable.json/.md` and `final-v036-full-6.0-fixed.json/.md`. These are blocked coverage results, not whole-file miss/safe evidence.


## Cursor and capacity arithmetic disposition (2026-10-19)

`cursor-arithmetic-analysis.json` records the bounded proof and remaining obligations. In both release branches, `MAX_ENTRIES` is 10 and the exact helper counts a consecutive nonzero-length prefix, giving `0 <= flowbufSize <= 10`. Every accepted flowbuffer insertion advances `curIndex` and `flowbufIndex`; every ordinary argument iteration advances `curIndex` once, including the null-value path. If arithmetic does not wrap and source/helper semantics match, the mathematical cursor before argument `i` is at most `i + flowbufSize < argsSize + flowbufSize`.

That conditional proof is not enough to suppress the six ordinary-loop candidates: the allocation adds in `size_t`, `dataListSize` and `curIndex` are `int`, and no pinned CEF API header or product input bound was found to establish the required range limits. The six ordinary writes occur in both vulnerable and fixed branches, away from the three Flowbuffer `while` loops patched by the advisory. They are therefore retained as separate unresolved capacity/integer-range candidates, not described as persistence of the disclosed loop-guard defect.
