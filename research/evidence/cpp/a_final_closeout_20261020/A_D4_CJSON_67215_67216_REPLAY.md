# A-D4 cJSON CVE-2026-67215 / CVE-2026-67216 replay

Date: 2026-10-20
Scope: source-bound detector evidence only; no product claim.

## Pinned source objects

The local bare Git object store `D:/openHarmonyScanner/tmp/d3-cjson-upstream-review.git` contains the upstream cJSON history. The relevant commits are:

- `2ceb3abc1d9f9e37827c32caeee75dcdd0ed4802`: bounds recursive `cJSON_Compare` and `compare_json` depth (candidate 67216 fix shape).
- `713439d87e319152ad3ef5e90ceb985ca33050ee`: adds depth limits to `compare_json`, `merge_patch`, and `generate_merge_patch` (candidate 67215 tree/merge recursion fix shape).
- The parent of each commit is the vulnerable control for the corresponding source-diff review. The exact parent of both selected fixes resolves to `fb16e5cf358798aabb049655975cde8427101056`.

The source objects are read directly by the production `run_fixed_commit_scan` Runner; no checkout or source rewrite was used.

## Commands and results

Command environment: `D:/openHarmonyScanner/.venv-c-line/Scripts/python.exe`, repository worktree at the final A-line snapshot. The scan selected `cJSON.c` and `cJSON_Utils.c` and detector `ohscanner.known_disclosed_cves`.

Results:

| replay | commit | parse | candidates |
|---|---|---|---|
| 67216 vulnerable | `fb16e5cf358798aabb049655975cde8427101056` | 1 complete / 1 partial | 67216 `cJSON.c:3073`; 67215 `cJSON_Utils.c:808` |
| 67216 fixed | `2ceb3abc1d9f9e37827c32caeee75dcdd0ed4802` | 1 complete / 1 partial | 67215 `cJSON_Utils.c:813`; 67216 absent |
| 67215 vulnerable | `fb16e5cf358798aabb049655975cde8427101056` | 1 complete / 1 partial | 67216 `cJSON.c:3073`; 67215 `cJSON_Utils.c:808` |
| 67215 fixed | `713439d87e319152ad3ef5e90ceb985ca33050ee` | 1 complete / 1 partial | 67216 `cJSON.c:3073`; 67215 `cJSON_Utils.c:813` |

The 67216 pair is a useful source-bound positive/fixed differential: the recursive comparison detector candidate disappears after the depth guard. The 67215 candidate remains on the upstream fixed commit because the current detector signature inspects `apply_patch`/`cJSON_Duplicate` cleanup, while the reviewed upstream fix adds depth to `merge_patch`/`generate_merge_patch`; the source diff does not modify that `apply_patch` shape. This is an evidence mismatch, not proof that the fixed component remains vulnerable.

Existing control suite: `D:/openHarmonyScanner/.venv-c-line/Scripts/python.exe -m unittest tests.detectors.test_known_disclosed_cves -q` — 21 tests passed, including positive, fixed, safe and unrelated controls plus partial-source handling. The tests include synthetic controls; they are not substituted for the pinned source replay.

## Decision and limitation

No detector or contract change is made in A-D4. The 67216 result is already supported by a real vulnerable/fixed source pair. A 67215 rule change would require an authoritative CVE-to-upstream-fix mapping and a general semantic rule that distinguishes recursive merge-patch depth guards from unrelated JSON Patch cleanup; the available evidence does not justify changing the existing rule ID or its scope. Product inclusion, caller reachability, attacker control, build configuration, runtime impact and independent holdout evidence remain unknown.

## Reproduction outputs

Raw Runner reports are in `D:/openHarmonyScanner/tmp/cjson-a-d4-replay-20261020/` (six JSON/Markdown reports for the four selected pairs and the additional 713439d differential). They are generated evidence and are intentionally outside the source repository commit.
