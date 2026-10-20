# T15 independent D18 acceptance: cJSON JSON Patch root-path binding

Date: 2026-10-20 (Asia/Shanghai)

## Result

The D18 rule regression **passes** for the bounded behavior requested: replaying the exact source produces tree-amplification candidates only at `cJSON_Utils.c:932` (COPY) and `:950` (ADD/REPLACE); the root-path replacement at `:861` stays quiet. Synthetic coverage also detects two candidates after renaming `apply_patch`, keeps unrelated tree-cleanup/name controls quiet, and preserves `blocked` for the partial control.

The cJSON vulnerability case remains **PARTIAL** (detector aggregate `blocked`). `cJSON_Utils.c` parsed completely, but `cJSON.c` is parser-partial and still emits the separate comparison-cost candidate at `:3161`. No trusted root-matched fixed source is bound, so the fixed differential is **BLOCK**. Neither the candidate nor the rule regression establishes product reachability, attacker control, exploitability, or security.

## Independent source identity check

From the OpenHarmony `third_party_cJSON` project-object Git repository, I independently resolved upstream commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748` and tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`. The source blobs and byte-stream SHA-256 values match the replay pins:

- `cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, 80,529 bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`, parser `partial`.
- `cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`, parser `complete`.

The replay runner packages the two exact upstream file contents under a synthetic transport commit/tree (`105eadd…` / `3c07134…`, snapshot SHA-256 `c0482c…`). Those packaging IDs are not presented as the upstream component identity.

## Rule mechanics assessment

D18 uses balanced lexical block spans, not a control-flow graph. For this source shape, the guard checks whether the duplicate's innermost block has a direct `goto cleanup` at that block's direct brace depth; if so, it excludes that duplicate before searching for a later attach. This explains the root-path early exit at line 861 and the general COPY/ADD-REPLACE positives at 932/950, and the renamed/unrelated fixture outcomes support that narrow behavior.

This is a bounded may-flow heuristic, not proof of branch feasibility, dominance, or ownership transfer. Nested cleanup exits and other control-flow layouts are not proven. Retain those limits when interpreting further sources.

## Independent verification

- Exact-source replay command: `python research/evidence/cpp/d16_cjson_tree_amplification_20261020/replay.py --source-root D:/openHarmonyScanner/tmp/cjson-cve67215-current-replay-20261019` — exit 0; only tree-amplification locations are 932/950; 861 absent; aggregate `blocked`.
- Resource lifetime tests: 8 passed.
- Full C++ detector suite: 160 passed.
- A0 queue verifier: `overall_ok=true`, all 345 IDs retained.
- `scripts.check_change_scope` against `8ec5f56a12e90bba56953b39eb17faa20e154da9`, lane `cpp`: 0 violations.
- `git diff --check`: passed.

The machine-readable record is in `t15_d18_independent_acceptance_20261020.json`. This acceptance checkout did not modify detector code, tests, or fixtures.
