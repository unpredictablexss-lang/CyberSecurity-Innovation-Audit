# D18 cJSON apply_patch root-path binding

Date: 2026-10-20 (Asia/Shanghai)

## Decision

Implemented bounded lexical block association in `ohscanner.cpp.resource_lifetime` (version 0.4.2). On the exact source, root replacement at `cJSON_Utils.c:861` is quiet because its innermost operation block exits to cleanup before the general attachment statements. General COPY duplicate at line 932 and ADD/REPLACE duplicate at line 950 each produce a candidate associated with the later attachment block (array attach at 985/997 or object attach at 1015). The rule remains a candidate, not a product vulnerability conclusion.

The association uses only complete function text and balanced brace boundaries already supplied by the parser. It rejects a duplicate when its own innermost lexical block contains a direct `goto cleanup` after the duplicate, then searches for an attach after that block. This is a bounded may-flow filter; it does not prove arbitrary branch feasibility, dominance, ownership transfer, or exploitability. No CFG was added. Full exact-source replay remains `blocked` because `cJSON.c` is parser-partial, and no trusted fixed source is bound.

## Exact source replay

The D16 identity-checking runner verified the same transport snapshot and source identities:

- Upstream component commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`, tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`.
- `third_party/cjson/cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`, parse complete.
- `third_party/cjson/cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`, parse partial.

Findings for tree amplification are at duplicate source lines 932 and 950; line 861 is absent. The recursive comparison candidate at `cJSON.c:3161` is unchanged. Aggregate status remains blocked due the partial `cJSON.c` translation unit. Machine-readable output is [d18-replay.json](d18-replay.json).

## Controls

- Added hash-bound fixture `positive_recursive_tree_json_patch.c`: finds both the COPY-like and ADD/REPLACE-like duplicate+attach paths, while the root-only duplicate followed by direct cleanup exit stays quiet.
- The same fixture passes after renaming `apply_patch` to `mutate_item` (two candidates), so the behavior does not depend on the reported function name.
- Existing positive recursive tree controls remain positive; unrelated tree cleanup and misleading `cJSON_Delete`-name controls remain quiet; the partial recursive-release control remains blocked with zero candidates.
- No fixed cJSON differential is claimed.

## Verification

- Resource detector tests: 8 passed.
- Full C++ detector suite: 160 passed.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: 0 violations.
- `git diff --check`: passed.
- Replay command: `python research/evidence/cpp/d16_cjson_tree_amplification_20261020/replay.py --source-root D:/openHarmonyScanner/tmp/cjson-cve67215-current-replay-20261019`.
