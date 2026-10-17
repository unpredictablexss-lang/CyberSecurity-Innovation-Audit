# OpenHarmony Full Scan Summary

- Started: `2026-10-17T08:39:20.242211+00:00`
- Updated: `2026-10-17T08:40:22.557729+00:00`
- Manifest: `/mnt/d/openHarmonyScanner/openharmony-manifest-fixed.xml`
- Projects in manifest: `1`
- Projects processed: `1`
- Completed: `0`
- Unknown: `1`
- Failed: `0`
- Validated vulnerabilities: `0`
- Diagnostics (not validated vulnerabilities): `0`
- Remaining disk bytes: `278466895872`

## Interpretation

- `candidate` and `possible_hit` diagnostics are not vulnerabilities or true positives.
- `validated_vulnerability=0` does not prove a project is safe or has zero vulnerabilities.
- Missing, failed, insufficient-coverage, blocked, and not-run outcomes are classified as `unknown`.
- Results are offline and pinned to manifest commit, actual commit, Git tree, and scanner snapshot.

## Results

| Index | Repository | Project path | Manifest commit | Actual commit | Git tree | Snapshot | Status | Classification | Diagnostics | Validated | Duration s | Failure |
|---:|---|---|---|---|---|---|---|---|---:|---:|---:|---|
| 8 | openharmony/ability_idl_tool | foundation/ability/idl_tool | d45cc0a0cf24986b1c4f07a08dc7d6e3a3ee5c3b | d45cc0a0cf24986b1c4f07a08dc7d6e3a3ee5c3b | f87fe47cb066f528e64211dda421b86c7dcbd79f | e861f310955261b6433ca16314f49e49a7ed50144eb8e4c1a9bd955e93c04662 | completed_with_limitations | unknown | 0 | 0 | 62.238 |  |

## Detector Summary

| Repository | Detector | Status | Scope files | Scope LOC | Diagnostics |
|---|---|---|---:|---:|---:|
| openharmony/ability_idl_tool | ohscanner.cpp.lifetime | blocked | 371 | 59763 | 0 |
| openharmony/ability_idl_tool | ohscanner.cpp.shared_ptr_race | completed | 371 | 59763 | 0 |
| openharmony/ability_idl_tool | ohscanner.interface.ipc | completed | 379 | 62994 | 0 |
