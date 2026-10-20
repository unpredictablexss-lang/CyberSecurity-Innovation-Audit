# D10 resource-lifetime and resource-exhaustion replay

Date: 2026-10-20 (Asia/Shanghai)

## Scope and decision

Replayed the D8 cJSON compare-cost and JSON Patch tree-amplification candidates, then replayed the exact CVE-2026-46675 vulnerable/fixed libpng `pngrutil.c` bytes with the detector at this branch base (`ohscanner.cpp.resource_lifetime` 0.4.0). No detector change is justified in this slice: both cJSON roots already produce separate bounded candidates, while the libpng pair is parser-partial and its cross-call zstream state is outside the current local resource model. No candidate result on either libpng variant is a fixed/safe conclusion.

## cJSON replay

Source identity is inherited from the T3/T4 evidence and independently byte-checked in this replay:

- Repository: `openharmony/third_party_cjson`
- Commit: `105eaddbf0d0110b07d16bdefc81ffc796e1444a`
- Tree: `3c07134d5a05aa546b15739e32503a2ca192d258`
- Snapshot SHA-256: `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`
- `third_party/cjson/cJSON.c`: 80,529 bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`, parser status `partial`
- `third_party/cjson/cJSON_Utils.c`: 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`, parser status `complete`

Paired-scope replay at detector 0.4.0 returned `blocked`, with the two distinct candidates:

| File:line | Rule | Root | Result |
|---|---|---|---|
| `third_party/cjson/cJSON.c:3161` | `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` | recursive two-way compare with visible linear sibling lookup | candidate |
| `third_party/cjson/cJSON_Utils.c:861` | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | repeated JSON Patch deep copy/attachment reaching recursive cleanup | candidate |

The compare-cost and tree-amplification rules remain separate. D8's positive, safe, unrelated, indexed-lookup, and partial fixtures remain the controls. There is no trusted fixed source for either cJSON root; PR #1078 is not accepted as a root-matched fix. Therefore neither root has a fixed-difference pass.

## libpng CVE-2026-46675 replay

The exact upstream blob bytes were fetched by pinned commit and verified against the recorded blob OIDs:

- Vulnerable upstream commit `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d`, `pngrutil.c` blob `a4eda54c8cb3d36cf1651dba159067b65030e3aa`, 153,112 bytes, SHA-256 `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e`.
- Fixed upstream commit `aa77ef38c17ab2fc1b41bec09fb973c6a386641d`, `pngrutil.c` blob `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a`, 152,477 bytes, SHA-256 `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e`.
- The historical T4 experiment binds these as vulnerable/fixed byte snapshots under synthetic commit `e283ed5d3a74c0112f092ddb1003c97e0e9a4717`, tree `c78da20c3ffe37b09653eaa3b49c5213745ac4bd`; those synthetic Git IDs are not represented as the official upstream commit/tree. Upstream tree IDs were unavailable in T4.

At detector 0.4.0, both exact files were supplied with the recorded `partial` parse status. Both runs returned `blocked`, one file inspected, and zero findings. This is inconclusive. The vulnerable source has zstream releases where `zowner` is cleared while `next_in` / `avail_in` or other buffers can still reference transient storage; the upstream fix centralizes detachment of `next_in`, `avail_in`, `next_out`, and `avail_out` before relinquishing the stream in the affected paths. Demonstrating the later IDAT consumption sequence needs state and caller ordering beyond a partial single translation unit.

Do not call the fixed replay a quiet safe control: parser coverage is partial and the detector did not analyze the file completely. D4/T4 runtime component evidence and product reachability limitations remain as recorded there.

## Reproduction and verification

The in-memory direct replay used `SourceUnit(language="c", parse_status=...)` and `CppResourceLifetimeDetector()` from this checkout. The cJSON replay supplied both source units together because recursive cleanup discovery is scope-wide; replaying `cJSON_Utils.c` alone is not equivalent. Source SHA-256 values and output locations are recorded above and in `report.json`.

Minimum evidence before a libpng detector change: parser-visible zstream ownership transitions over the affected functions (or an explicitly reviewed local-candidate contract that isolates those functions from unrelated parse errors), plus source-bound vulnerable/fixed and safe/unrelated controls. Product-level claims also require the selected build and application call path. Missing trusted cJSON fixes remain a blocker for fixed comparisons.

Disposition: cJSON candidates confirmed with partial overall run; libpng CVE-2026-46675 remains `PARTIAL/BLOCK`; no code change made because current evidence does not distinguish a rules-model defect from incomplete parser/context coverage.
