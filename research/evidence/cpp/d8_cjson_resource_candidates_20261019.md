# D8 cJSON resource exhaustion candidate replay

Date: 2026-10-19 (Asia/Shanghai)

## Source identity and scope

The replay uses the A-line cJSON OpenHarmony source package recorded by T3/T4:

- Repository: `openharmony/third_party_cjson`
- Commit: `105eaddbf0d0110b07d16bdefc81ffc796e1444a`
- Tree: `3c07134d5a05aa546b15739e32503a2ca192d258`
- Snapshot SHA-256: `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`
- `third_party/cjson/cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`
- `third_party/cjson/cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`

Root-cause source is fixed to two distinct observations: JSON Patch copy/add repeatedly deep-copies and attaches nested values before cleanup can recursively delete the expanded tree (CVE-2026-67215); `cJSON_Compare` recursively compares both directions while each sibling loop performs key lookup (CVE-2026-67216). These roots have separate rule IDs. No trusted fixed source is bound for either case. The known PR #1078 is not treated as a matching fix for these roots.

## Detector change

The existing compare-cost candidate only required a lookup call inside each recursive sibling loop. That could match indexed/constant-time lookup implementations without visible linear sibling traversal. Version `0.4.0` now requires the lookup helper definition in the same translation unit and a visible `while`/`for` traversal advancing through `next`, or a `ForEach` traversal. Unresolved or cross-unit helper implementations do not produce this bounded candidate. This is a conservative syntax gate, not a complexity proof.

The tree-amplification rule remains separately identified as `ohcpp-resource-exhaustion-tree-amplification-candidate-004`; compare cost remains `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005`. Existing fixtures cover each positive shape, safe/unrelated controls, and partial input. A new indexed-lookup control preserves the recursive two-way comparison shape but stays quiet because its helper has no visible sibling loop.

## Exact-source replay

The current detector was run directly over the exact source bytes with the recorded source hashes, language `c`, and parser statuses from the T3/T4 replay (`cJSON.c` partial; `cJSON_Utils.c` complete). It returned `blocked`, retained both files as analyzed/inspected, and emitted:

| File:line | Rule | Symbol | Source SHA-256 |
|---|---|---|---|
| `third_party/cjson/cJSON.c:3161` | `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` | `cJSON_Compare` | `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb` |
| `third_party/cjson/cJSON_Utils.c:861` | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | `apply_patch` | `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9` |

This confirms the bounded candidate rules can identify the disclosed source shapes. It does not upgrade the parser result, establish complete detector coverage, attacker control, runtime impact, or product reachability. The run remains `PARTIAL/BLOCK`; no missing fixed comparison is fabricated.

## Verification

- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: 8/8 passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v`: 157/157 passed.
- `python -m scripts.check_change_scope --base 50b2806a7df38cd1ad07f257873617fe9d6b8337 --lane cpp`: passed; no violations.
- `git diff --check`: passed.

