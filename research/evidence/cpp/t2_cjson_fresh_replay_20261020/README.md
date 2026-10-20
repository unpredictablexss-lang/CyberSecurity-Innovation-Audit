# T2 fresh cJSON replay on PR #35 frozen scanner

Date: 2026-10-20 (Asia/Shanghai)

## Result

Fresh production CLI replay on scanner commit `81dd4aea9bb51522ac912b33504ef0d2ddb79089` reproduced the existing source-bound candidates for both A-matrix cJSON rows. This resolves the T3 date-provenance gap for this replay only. Both cases remain `PARTIAL/BLOCK`: no trusted root-matched fixed source exists, `cJSON.c` parses partially, detector semantic coverage is partial for both files, and the scanner run is blocked. Candidate findings are not vulnerability confirmations.

## Bound input

- Repository: `openharmony/third_party_cJSON` (user-declared repository identity; local Git object store)
- Commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`
- Tree: `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`
- Profile: `light-ast`
- Scope: exactly `cJSON.c`, `cJSON_Utils.c` (2 files, 121265 bytes)
- `cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`, parse `partial`
- `cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`, parse `complete`

## Current CLI result

Detector `ohscanner.cpp.resource_lifetime` version `0.4.2`; profile `light-ast`; run status `blocked`; 3 unassessed candidates:

| Matrix case | Rule | Location | Parse / coverage |
|---|---|---|---|
| CVE-2026-67216, recursive compare cost | `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` | `cJSON.c:3161:22`, `cJSON_Compare` | source parse partial; detector coverage partial |
| CVE-2026-67215, patch tree amplification | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | `cJSON_Utils.c:932:13`, `apply_patch` | source parse complete; detector coverage partial |
| CVE-2026-67215, patch tree amplification | same | `cJSON_Utils.c:950:9`, `apply_patch` | source parse complete; detector coverage partial |

No fixed result is available. PR #1078 is an unmerged proposal for a different/depth-limited mitigation and is not treated as fixed evidence. Existing controls are mechanism-level only, not same-scope CLI differentials. Preserve both rows as `PARTIAL/BLOCK`.

## Reproduction

From the scanner checkout at the frozen scanner commit:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\third_party_cJSON.git --repository openharmony/third_party_cJSON --commit 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 --include cJSON.c --include cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out research/evidence/cpp/t2_cjson_fresh_replay_20261020/cli.json --md-out research/evidence/cpp/t2_cjson_fresh_replay_20261020/cli.md
python research/evidence/cpp/t2_cjson_fresh_replay_20261020/verify.py --source-git-dir D:\openHarmonyScanner\openharmony\.repo\project-objects\third_party_cJSON.git
```

The checked-in `cli.json` and `cli.md` are outputs of this run. The verifier checks the frozen scanner HEAD, source commit/tree/blob/SHA-256, exact declared scope, rule/version, candidate locations, parse states, coverage, and blocked disposition. It does not assert a fixed/safe result.

## Remaining minimum inputs

- For either CVE: a trusted upstream merged/released root-matched fixed commit with exact source objects, then a same-scope current CLI replay.
- For CVE-67216: complete parser/model coverage for `cJSON_Compare` and a same-scope safe/unrelated comparison control.
- For CVE-67215: detector semantic coverage for the patch-to-tree-growth-to-recursive-delete relation and a same-scope safe/unrelated patch control.
- Product/build selection, attacker input path, and bounded isolated impact evidence remain outside this static replay.

