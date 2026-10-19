# D33 — cJSON production M2 CLI source replay

Date: 2026-10-23 (Asia/Shanghai)  
Integration baseline: `6f24b0ccae22446d76b4a993312ef37228ffd05e`  
Disposition: **candidate coverage reproduced; overall case remains PARTIAL/BLOCK**.

## Source identity and execution

The pinned local Git object is `openharmony/third_party_cjson@0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`, tree `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`. The CLI scanned exactly the declared two-file scope:

| File | Git blob | Blob source SHA-256 | Bytes | Parse |
|---|---|---|---:|---|
| `cJSON.c` | `152b2caa479c9f448001652913c980a6dafb82e0` | `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb` | 80,529 | partial |
| `cJSON_Utils.c` | `8fa24f8e9bf452cf1ba49d1325c85423ce742c74` | `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9` | 40,736 | complete |

Command:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d33-cjson-0c2c9dff-20261023 --repository openharmony/third_party_cjson --commit 0c2c9dff82cc85539c8362132d7a5f6bf7d1e748 --include cJSON.c --include cJSON_Utils.c --detector ohscanner.cpp.resource_lifetime --json-out research\evidence\cpp\d33_cjson_current_cli_20261023.json --md-out research\evidence\cpp\d33_cjson_current_cli_20261023.md
```

Production detector `ohscanner.cpp.resource_lifetime` version/rule version `0.4.2`; profile `light-ast`; snapshot SHA-256 `84452a40925b94a82d038150157e5a3514289d21ea9562bc58d1e202b98b537e`. Total CLI wall time reported by the rule run: `0.179887 s`. Runner `completed_with_limitations`; detector `blocked`; 3 unverified diagnostics; 0 validated vulnerabilities. Parser coverage is 1 complete / 1 partial. `cJSON.c` has parser errors at lines 158–173 and missing nodes at 3152/3169; the detector explicitly limits semantic coverage. `cJSON_Utils.c` parser status is complete, although detector analysis is partial under its model.

## Findings and case mapping

| Case | Candidate | Location | Interpretation |
|---|---|---|---|
| CVE-2026-67216 recursive comparison cost | `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` | `cJSON.c:3161:22`, `cJSON_Compare` | The production CLI retains the recursive sibling-loop / lookup candidate despite partial parsing. This is not runtime complexity or attacker-control proof. |
| CVE-2026-67215 JSON Patch tree amplification | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | `cJSON_Utils.c:932:13`, `apply_patch` | COPY-like duplicate followed by attachment candidate. |
| CVE-2026-67215 JSON Patch tree amplification | same rule | `cJSON_Utils.c:950:9`, `apply_patch` | ADD/REPLACE duplicate followed by attachment candidate. |

The exact production replay therefore does **not** reproduce a root-candidate miss for either case. It corroborates D18's two duplicate-plus-attachment paths and quiet root-replacement early-exit branch (line 861), and D19's recursive-compare rule candidate on the same source blob. D18's rule controls and D19's direct-detector renamed/develop/safe controls remain separate mechanism evidence; they do not replace this CLI replay or establish a fixed-source differential.

## Limits and disposition

No trusted root-matched fixed/released source is bound for either CVE. The D17 develop experiment is not an accepted fix. No product build/profile, full semantic analysis of `cJSON.c`, runtime impact, or attacker control is proved here. Consequently both cases remain **PARTIAL/BLOCK**; the fixed comparison remains **BLOCK**. No detector change is justified by this replay. Do not treat parser-partial zero results on `cJSON.c` as safety evidence.

Machine-readable CLI output: [d33_cjson_current_cli_20261023.json](d33_cjson_current_cli_20261023.json). Verification helper: [verify_d33_cjson_current_cli.py](verify_d33_cjson_current_cli.py).
