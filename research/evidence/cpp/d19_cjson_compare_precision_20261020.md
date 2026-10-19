# D19 — cJSON recursive compare-cost root precision

Date: 2026-10-20 (Asia/Shanghai)
Development worktree: `codex/a-d19-cjson-compare-20261020`
Base integration commit: `252e842e7627dda3e261b2bac17cc855ef1d4ddb`
Disposition: **NO CHANGE** — no reproducible detector gap or over-report was found.

## Source and upstream patch provenance

The pinned OpenHarmony source identity carried forward from the D8/T3 source ledger is repository `openharmony/third_party_cjson`, commit `105eaddbf0d0110b07d16bdefc81ffc796e1444a`, tree `3c07134d5a05aa546b15739e32503a2ca192d258`. The recorded `third_party/cjson/cJSON.c` object is blob `152b2caa479c9f448001652913c980a6dafb82e0`; its local Git object bytes were independently read in this worktree and hash to SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb` (80,529 bytes). The exact commit/tree chain was not re-fetched from the OpenHarmony source remote in this task; commit/tree values above remain bound by the existing D8/T3 ledger, while this task independently verifies the source blob bytes and digest.

D17 provenance identifies official cJSON commit `bd307ec3b5f1c0555976c4b0118621e485367aa2`, parent `4e9154458dce824216820fd49bfe8bd97bc1e287`, tree `fa51cefb4d6f1f097d5cbfa842702a3c4e09bf3f`, and `cJSON.c` blob `d8ea4d33a1546a3da052c3387319632b56818341`, SHA-256 `2d13226af13a4f065862caf6f0c34f3ef7b43f83798ce37d28747d05612f097a` (73,339 bytes). Local ancestry checks confirm this commit is an ancestor of the fetched `d17/develop` ref (`1ac905d3b2359f48a0463afe8e16a080f0e1e03c`) and is not an ancestor of the D17-recorded current `master` commit `6d9f2443ab071f86e5d9b43025a40929ec41c46c`. The patch is therefore used only as an **unmerged develop experiment**, never as a trusted fixed release or a fixed PASS.

## Root and rule review

On the pinned vulnerable source, `cJSON_Compare` contains two object-member loops. Each walks one object's members, calls same-translation-unit `get_object_item` on the opposite object, and recursively compares the matched members. `get_object_item` visibly advances `current_element = current_element->next` inside a `while`, so each sibling lookup has a linear linked-list walk. The second direction is explicitly present to prevent a subset from comparing equal. The rule's existing gate in `resource_lifetime_detector.py` requires two recursive sibling-loop sites, distinct loop iterators, and visible same-unit linear lookup helpers; this matches the disclosed nested work shape without relying on the function name or CVE identifier.

The official develop experiment checks object sizes and removes the reverse second recursive traversal. It does not trigger the current candidate rule, as expected. That demonstrates the rule's root sensitivity for this source shape, but does not change the source-paired case disposition: the develop commit remains unmerged and the vulnerable file remains parser-partial.

## Replay results

The replay was run by `research/evidence/cpp/d19_cjson_compare_precision_replay.py`. It invokes the detector directly, not the parser or production CLI. Results are in `d19_cjson_compare_precision_replay.json`.

| Input | Parse state supplied to detector | Rule 0.4.2 result | Runtime |
|---|---|---|---:|
| Pinned vulnerable `cJSON.c` bytes | partial | Candidate at line 3161, column 22; symbol `cJSON_Compare` | 0.112 s |
| Same source with compare function renamed | partial | Candidate at line 3161, column 22; symbol `compare_json_nodes` | 0.105 s |
| D17 `bd307ec` develop source, experimental only | partial | No candidate | 0.084 s |
| Indexed-lookup synthetic safe control | complete | No candidate | 0.002 s |
| Unrelated recursive comparison control | complete | No candidate | 0.001 s |

The exact source CLI replay remains the D8 record: `cJSON.c` is partial and the run is blocked overall, even though the root candidate is present. D19 did not re-run or improve parser coverage. No trusted fixed/released source was identified, and no source-paired fixed differential is claimed. The CVE case stays **PARTIAL** with fixed-source comparison **BLOCK**.

## Verification and change scope

- `python research/evidence/cpp/d19_cjson_compare_precision_replay.py --vulnerable-source D:\\openHarmonyScanner\\openharmony\\third_party\\cJSON\\cJSON.c --output research/evidence/cpp/d19_cjson_compare_precision_replay.json`: completed; exact hash guard and all five inputs recorded.
- `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: 8 passed.
- `python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v`: 160 passed.
- `python -m scripts.check_change_scope --base 252e842e7627dda3e261b2bac17cc855ef1d4ddb --lane cpp`: passed; zero violations.
- `git diff --check`: passed.

Only this evidence report, its JSON replay output, and its bounded replay helper are added. No detector, fixture, parser, public API, or Catalog changes were justified.
