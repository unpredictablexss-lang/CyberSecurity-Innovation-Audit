# C7 full snapshot tree and source inventory replay

Recorded 2026-10-18. This is a supplemental replay using full pinned source snapshots for the five already selected development cases. It does not change the frozen detector, profile, scope, or the prior `run_final/` record.

## Source object recovery

The missing subtree objects reported by `run_final/manifest.json` were obtained by fetching the five exact commits from the official `openharmony/arkcompiler_ets_runtime` GitHub repository into a new isolated bare object database. The fetch was depth-limited to those commits, with no checkout and no changes to the shared OpenHarmony source tree:

```powershell
$db = 'D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git'
git init --bare $db
git --git-dir=$db fetch --depth=1 --no-tags `
  https://github.com/openharmony/arkcompiler_ets_runtime.git `
  830e85b40240677039719fcbf14f721ad3b19050 `
  a0e30483ab3e4aead67ecfb5c708489915e447f9 `
  c758818dbfd0b146a908d43d21f6ca1706c33783 `
  81ca57487d04ea30cd11c271e86494a4e130f43e `
  95554c2ee75b35d556640eb6f2591d429796f60e
```

The object pack is 18,909 KiB. Each commit's tree and the full `git ls-tree -r --full-tree` traversal succeeded. Entry counts were 7,573; 7,577; 7,829; 7,832; and 10,218 respectively. The replay then independently rechecked each expected commit, tree, parent list, target path, blob OID, source SHA-256 and byte length.

## Replay

The runner used the previously frozen scanner archive and the same command/config as the scoped replay, with `PYTHONPATH` explicitly set:

```powershell
$env:PYTHONPATH = 'D:\openHarmonyScanner\tmp\arkruntime-detector-070-code-retry2'
D:\anaconda3\python.exe research\experiments\ark_runtime\c7_20261018\replay.py `
  --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git `
  --scanner-root D:\openHarmonyScanner\tmp\arkruntime-detector-070-code-retry2 `
  --output research\experiments\ark_runtime\c7_20261018\run_full_snapshot_20261018
```

The first invocation without `PYTHONPATH` exited before execution with `ModuleNotFoundError: src`; the documented invocation above succeeded. Manifest SHA-256: `8ec7dd1790b9b6245e132f0b9ca72580960ed66739da7bd85aa2c879c101628c`.

## Results and boundary

The full pinned Git source loader succeeded for all five commit snapshots; `source_inventory_blocker` is null for every row. Candidate counts and detector states match the earlier scoped run: vulnerable development parents have 1 and 2 candidates, fixed/unrelated controls have 0; all five parses remain `partial`, all runs remain `blocked`, and `holdout_eligible` is false. No result is interpreted as safe, a miss, a confirmed vulnerability, or a precision/recall observation.

This resolves the missing unrelated-subtree provenance blocker for these five snapshots and provides complete repository inventory input to the scanner's shared source loader. The detector analysis scope remains the single explicitly selected TypedArray source path. C1's product build/preprocessing profile, C2's 18 semantic drift judgments, and C4's trusted exact-snapshot dependency closure remain blocked/unknown. This is a development replay, not an independent holdout.
