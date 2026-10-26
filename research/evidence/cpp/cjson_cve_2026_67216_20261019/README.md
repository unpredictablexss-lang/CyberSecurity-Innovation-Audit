# cJSON CVE-2026-67216 source precheck

Verification date: 2026-10-19. Lane: A_CPP. This is an investigation card, not a static finding or product verdict.

## Root-cause card

- **Public disclosure:** Red Hat describes excessive CPU time in `cJSON_Compare()` on crafted deeply nested JSON objects. The host application must explicitly compare attacker-influenced data with a structurally matching reference object; parsing/validation/serialization alone does not trigger the reported path. Red Hat’s record is authoritative for that disclosed condition; it does not establish product reachability.
- **Attacker control / unknowns:** the attacker may control one or both compared structures only if the application passes them to `cJSON_Compare()`. Whether any OH application does so, which argument can be controlled, and whether object keys/values remain matching through the recursion are unknown.
- **Source flow:** in the local 1.7.19 source, object comparison walks each member and calls `get_object_item()` in the other object (a linked-list search), recursively compares matched values, then performs a reverse pass. The source itself comments that the per-object path is O(n²). The exact recurrence/input family underlying Red Hat’s reported exponential cost still needs independent reproduction; do not infer it solely from the TODO comment.
- **Missing invariant / patch:** no comparison work budget, memoization, or efficient key lookup appears in this source. Upstream PR #1078 is open and bounds recursive comparison depth using `CJSON_NESTING_LIMIT`; it describes stack exhaustion, not a demonstrated fix for the advisory’s CPU-complexity condition. Do not treat that PR as a fixed control until its exact patch and adversarial runtime behavior are checked.
- **Static proof obligations:** establish an application call to `cJSON_Compare`, attacker influence over the object pair, recursive matching structure, repeated per-level lookup/comparison cost, and an input-size-to-work bound. Current OHScanner parser gives `cJSON.c` partial coverage and cannot support a production finding. Product invocation and CIA impact remain unknown.
- **Safe lookalikes:** parsing or serializing deeply nested input without comparison; identity comparison where `a == b`; mismatching keys/values that short-circuit; small trusted structures; and depth-limited recursion are not by themselves this CPU DoS.

## Bound source and production coverage

- cJSON local component source: 1.7.19; `.git/HEAD` commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`; source tree and `cJSON.c` blob/SHA are in `../cjson_cve_2026_67215_20261019/README.md` and the A-line ledger.
- The production M2 scan that included this exact `cJSON.c` (same two-file source snapshot used for CVE-2026-67215) produced 0 diagnostics but was blocked/partial: `cJSON.c` is parser partial; `cJSON_Utils.c` complete. This is not a static miss or safe result.
- The resolved rk3568 source config points to the standard cJSON target that builds `cJSON.c`; the target has a public `cJSON_Compare` declaration. Application calls and final generated link remain unverified. See `../cjson_cve_2026_67215_20261019/rk3568-product-source-route.json`.
- No independent runtime complexity reproduction, fixed source, safe/unrelated pair, or detector regression has been run for this CVE.

## Verified references

- Red Hat: https://access.redhat.com/security/cve/cve-2026-67216
- GitHub Advisory Database: https://github.com/advisories/GHSA-ff2v-f99f-wm3f
- Upstream open PR #1078 (recursive depth guard): https://github.com/DaveGamble/cJSON/pull/1078
- PR #1078 addresses recursive stack depth; its open state and summarized patch do not establish a fix for CPU complexity.

## Bounded local cost probe (2026-10-19)

- Exact source: local OH `cJSON.c` from commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`; probe compiles that file directly, no fetch during build/run.
- Probe source: `compare_cost_probe.c`. It generates two equal binary object trees; mode 1 repeats key `x` at every level; mode 0 uses `x`/`y`. WSL GCC 16.2.0, `-O2`. Logs `compare-d{8,10,12,14,16}-m{0,1}.log`; per-process CPU limit 4 s, wall timeout 6 s, virtual memory limit 512 MiB, core dumps disabled.
- Duplicate-key timings at depths 8/10/12/14: 0.593/8.792/145.447/2266.684 ms. Unique-key timings: 0.629/10.571/171.904/2772.637 ms. Depth 16 both exit 137 on CPU limit; no claim of completion.
- Both controls are positive expensive matching structures; the unique-key case is not a safe negative. Early-mismatch, parser-depth boundary, fixed version, and independent structural variant remain untested. Runtime complexity is established for this bounded family on component source only; it does not establish attacker reachability or product impact.

## Upstream PR #1078 comparison (2026-10-19)

- Fetched PR #1078 head explicitly into isolated bare repo `D:\openHarmonyScanner\tmp\cjson-pr1078-20261019.git`; no product or OH checkout mutation. Latest observed head `d18fad4ae9c743ebe493135dc8576ac1e4521969`; its direct parent is `6b805f14d16d896f12da62221eb1940b37d0e077`. The original compare guard commit is `2ceb3abc1d9f9e37827c32caeee75dcdd0ed4802`, parent `fb16e5cf358798aabb049655975cde8427101056`.
- The PR’s original commit adds a recursion-depth guard to compare recursion; it does not change linked-list member lookup or introduce a comparison-work budget. The later PR head also includes merge-patch recursion changes and tests. It is an open proposal, not a confirmed upstream fixed version.
- Identical `-O2` harness/source family on original PR commit: depth-14 equal duplicate-key object took 2092.902 ms; depth 16 hit the 4 s CPU limit (exit 137). Latest PR head: depth 14 took 2294.072 ms; depth 16 hit the same limit. Local OH cJSON 1.7.19: depth 14 took 2266.684 ms; depth 16 also hit the limit. These similar values do not support a CPU-complexity fix; the PR comparison is only a depth/stack guard.
- Top-level type mismatch (`[]` versus the generated object) at depth 14 returned unequal in 0.000 ms on local OH, original PR commit, and latest PR head; it is a fast unrelated comparison control. A top-level key mismatch within a same-type large object was also tried earlier and still took about 1 s, so it is not considered a safe low-cost control.
- Logs: `pr1078-initial-d14.log`, `pr1078-initial-d16.log`, `pr1078-initial-mismatch.log`, `pr1078-compare-d12.log`, `pr1078-compare-d14.log`, `pr1078-compare-d16.log`, `early-mismatch-oh.log`, `early-mismatch-pr1078.log` (these last two are the fast type mismatch after harness update). PR source copies and executables are in workspace `tmp` and not part of repository delivery. No production detector scan, rule, or fixed-version regression exists for this CVE.

## Parser context gap narrowed (2026-10-19)

`parser_context_probe.py` checks the local `cJSON.c` and `cJSON.h` SHA-256 before transforming anything. Raw parser errors occur at `CJSON_CDECL` declarations (158/159/160/165/169/173) and missing loop nodes at `cJSON_ArrayForEach` calls (3152/3169). The exact header-defined macro expansions, with the explicitly selected non-Windows empty calling-convention branch, produce a complete research-only tree-sitter parse with line count preserved and recursive `cJSON_Compare` calls at 3131/3161/3177. The transformed SHA and full parse report are in `parser-context-probe.json`. This is not production parser coverage, has no product-bound compile profile and no byte/column map; production result stays blocked/partial.
