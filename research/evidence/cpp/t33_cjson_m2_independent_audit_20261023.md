# T33 — cJSON CVE-2026-67215/67216 independent M2 CLI replay

Date: 2026-10-23 (Asia/Shanghai)

## Baseline and source identity

This independent checkout started at acceptance commit `6f24b0ccae22446d76b4a993312ef37228ffd05e`. The current production M2 command was run against the OpenHarmony project-object Git repository `third_party_cJSON`, upstream component commit `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`, tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`. Both exact blob IDs, byte lengths, and SHA-256 hashes were independently recomputed from `git cat-file blob`; see the audit JSON.

The two-file scope is identical for both cases: `cJSON.c` (80,529 bytes, blob `152b2caa479c9f448001652913c980a6dafb82e0`, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`) and `cJSON_Utils.c` (40,736 bytes, blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`).

## Whole-source CLI result

`ohscan-run` used detector `ohscanner.cpp.resource_lifetime` version `0.4.2`, profile `light-ast`, and both files in one invocation. `cJSON.c` parses `partial`; `cJSON_Utils.c` parses `complete`. Current CLI emitted three candidates under two distinct rules: compare-cost at `cJSON.c:3161` (`ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005`) and JSON Patch tree-amplification at `cJSON_Utils.c:932` and `:950` (`ohcpp-resource-exhaustion-tree-amplification-candidate-004`). Aggregate run is `blocked`; detector coverage is `partial` (0/2 files fully analyzed). This preserves the candidate evidence without turning the blocked aggregate into a miss or pass.

## Case disposition

- CVE-2026-67215: root-specific candidate positions `cJSON_Utils.c:932` and `:950`; parser partial elsewhere in the same scope blocks whole-scope completion. Fixed-source comparison **BLOCK** because no trusted root-matched fix exists. See [case report](t33_cjson_cve_2026_67215_20261023.md).
- CVE-2026-67216: root-specific candidate at `cJSON.c:3161`; the source file is parser-partial and the aggregate is blocked. Fixed-source comparison **BLOCK** because no trusted merged/released root-matched fix exists; an upstream develop experiment is not a fixed control. See [case report](t33_cjson_cve_2026_67216_20261023.md).

## D18/T15 and D19/T16 evidence boundary

D18/T15 established bounded mechanism behavior and exact candidate locations. D19/T16 established direct detector rule behavior and explicitly marks parser/CLI coverage unevaluated. Those fragment/direct-detector regressions are useful mechanism evidence but cannot replace this current production M2 whole-source CLI replay. The replay above independently exercises parsing, same-scope aggregate state, detector coverage, and both distinct rules.

No trusted fixed source is available for either root; no safety inference is made. Product configuration/build, call path, attacker control, runtime trigger, and impact remain unverified. The frozen A0 queue was not edited.

## Reproduction

```powershell
python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/openharmony/.repo/project-objects/third_party_cJSON.git --repository openharmony/third_party_cJSON --commit 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 --include cJSON.c --include cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t33_cjson_m2_cli_20261023.json --md-out research/evidence/cpp/t33_cjson_m2_cli_20261023.md
python research/evidence/cpp/verify_t33_cjson_m2_replay.py
python research/deliveries/cpp/a0_triage_20261019/verify_triage.py
python scripts/check_change_scope.py --base 6f24b0ccae22446d76b4a993312ef37228ffd05e --lane cpp
git diff --check
```
