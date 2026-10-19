# T16 independent acceptance — D19 cJSON compare-cost candidate

Date: 2026-10-20 (Asia/Shanghai)
Independent checkout: `codex/a-t16-d19-acceptance-20261020`
Checkout starting point: `2457c6658b2bf1b4887f91bb406537b150afd259`
Target development commit: `83b5bc1a5427a4a74c403547c4a2362f6060cfb1`

## Decision

**Candidate rule regression: PASS for direct detector behavior only. CVE-2026-67216 source-paired case: PARTIAL; fixed comparison: BLOCK.** The direct replay found the disclosed source shape and a renamed variant, while the indexed-lookup and unrelated positional-recursion controls were quiet. The upstream develop patch also stayed quiet, but it is unmerged and is not a fixed source. The production whole-source replay remains parser-partial/blocked, so this acceptance does not establish full-source coverage or a CVE fixed differential.

## Source identity and provenance

The A-line replay's `105eaddbf0d0110b07d16bdefc81ffc796e1444a` commit / `3c07134d5a05aa546b15739e32503a2ca192d258` tree are a synthetic two-file transport identity, not the upstream component repository identity. Using the local OpenHarmony project-object mirror `openharmony/.repo/project-objects/third_party_cJSON.git`, T16 independently verified:

- Upstream component commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`
- Tree: `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`
- `cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, 80,529 raw bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`

The unmerged develop experiment was independently checked in local Git objects: commit `bd307ec3b5f1c0555976c4b0118621e485367aa2`, parent `4e9154458dce824216820fd49bfe8bd97bc1e287`, tree `fa51cefb4d6f1f097d5cbfa842702a3c4e09bf3f`, `cJSON.c` blob `d8ea4d33a1546a3da052c3387319632b56818341`, 73,339 bytes, SHA-256 `2d13226af13a4f065862caf6f0c34f3ef7b43f83798ce37d28747d05612f097a`. It is an ancestor of local `remotes/d17/develop` and not an ancestor of `remotes/d17/master`. It remains an experimental comparison only.

## Candidate rule regression

The D19 exact-source/fragment helper was rerun in the independent checkout. The source hash guard passed. Rule version was `0.4.2`; the rule ID was `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005`.

| Input | Result | Meaning |
|---|---|---|
| Pinned OpenHarmony `cJSON.c` | Candidate at line 3161, `cJSON_Compare`; parse status supplied as partial | Positive direct-detector replay |
| Same source with `cJSON_Compare` renamed | Candidate at line 3161, renamed symbol | Name-independent shape regression |
| `bd307ec` develop experiment | No candidate | Experimental root-difference control, not fixed |
| Indexed lookup safe fixture | No candidate | Safe complexity control |
| Positional linear recursive comparison fixture | No candidate | Unrelated recursion control |

This is direct detector execution over supplied source units. The helper does not invoke parser or CLI; its `blocked` status for partial source does not alter the observed candidate result.

## CVE case disposition

The separate exact-source replay records `cJSON.c` as parser-partial and the aggregate CLI run as blocked. The candidate therefore remains a partial root-cause lead, not complete source coverage. No trusted merged/released fix is bound for this root. The `bd307ec` develop experiment changes the comparison algorithm but is unmerged, so it cannot satisfy the fixed-source gate. CVE-2026-67216 remains **PARTIAL**, with fixed-source comparison **BLOCK**.

## Verification

- `python research/evidence/cpp/d19_cjson_compare_precision_replay.py --vulnerable-source D:\openHarmonyScanner\openharmony\third_party\cJSON\cJSON.c --output research/evidence/cpp/t16_d19_independent_acceptance_20261020.json`: completed; source hash guard and five direct replay inputs passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v`: 160 passed.
- `python research/deliveries/cpp/a0_triage_20261019/verify_triage.py`: `overall_ok=true`; 345 IDs retained.
- `python -m scripts.check_change_scope --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: zero violations.
- `git diff --check`: passed.

See the adjacent JSON for source identities, replay findings, separate candidate/CVE dispositions, and verification results. This T16 change contains only independent acceptance evidence.
