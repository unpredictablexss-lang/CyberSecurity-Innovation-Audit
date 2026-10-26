# C7 full snapshot tree and source inventory replay

Recorded 2026-10-18. This is a supplemental replay using full pinned source snapshots for the five already selected development cases. It does not change the frozen detector, profile, scope, or the prior `run_final/` record.

## Source object recovery

The missing subtree objects reported by `run_final/manifest.json` were obtained by fetching the five exact commits from the official `openharmony/arkcompiler_ets_runtime` GitHub repository into a new isolated bare object database. The fetch was depth-limited to those commits, with no checkout and no changes to the shared OpenHarmony source tree:

```powershell
$db = 'D:/openHarmonyScanner/tmp/c-line-ark-history-full-snapshots-20261018.git'
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
  --repo-dir D:/openHarmonyScanner/tmp/c-line-ark-history-full-snapshots-20261018.git `
  --scanner-root D:\openHarmonyScanner\tmp\arkruntime-detector-070-code-retry2 `
  --output research\experiments\ark_runtime\c7_20261018\run_full_snapshot_20261018
```

The first invocation without `PYTHONPATH` exited before execution with `ModuleNotFoundError: src`; the documented invocation above succeeded. Manifest SHA-256: `8ec7dd1790b9b6245e132f0b9ca72580960ed66739da7bd85aa2c879c101628c`.

## Results and boundary

The full pinned Git source loader succeeded for all five commit snapshots; `source_inventory_blocker` is null for every row. Candidate counts and detector states match the earlier scoped run: vulnerable development parents have 1 and 2 candidates, fixed/unrelated controls have 0; all five parses remain `partial`, all runs remain `blocked`, and `holdout_eligible` is false. No result is interpreted as safe, a miss, a confirmed vulnerability, or a precision/recall observation.

This resolves the missing unrelated-subtree provenance blocker for these five snapshots and provides complete repository inventory input to the scanner's shared source loader. The detector analysis scope remains the single explicitly selected TypedArray source path. C1's product build/preprocessing profile, C2's 18 semantic drift judgments, and C4's trusted exact-snapshot dependency closure remain blocked/unknown. This is a development replay, not an independent holdout.

## Independent source-tree recheck — 2026-10-19

Using the existing isolated bare object database at `D:/openHarmonyScanner/tmp/c-line-ark-history-full-snapshots-20261018.git`, Git independently resolved each pinned commit's root tree and traversed the full recursive tree. The observed tree IDs and entry counts are:

| Commit | Root tree | Recursive entries |
|---|---|---:|
| `830e85b40240677039719fcbf14f721ad3b19050` | `579712c1ebbb703d17cea422b1572023bed5d8a4` | 7,573 |
| `a0e30483ab3e4aead67ecfb5c708489915e447f9` | `82af11ced4297818410ccf61906b703d25b69165` | 7,577 |
| `c758818dbfd0b146a908d43d21f6ca1706c33783` | `5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a` | 7,829 |
| `81ca57487d04ea30cd11c271e86494a4e130f43e` | `f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5` | 7,832 |
| `95554c2ee75b35d556640eb6f2591d429796f60e` | `65728158c365a0100db906bfca1cedf3ee3f5ebf` | 10,218 |

The recorded replay manifest remains byte-identical at SHA-256 `8ec7dd1790b9b6245e132f0b9ca72580960ed66739da7bd85aa2c879c101628c`. This recheck confirms the five commit trees remain available and fully traversable in the local object database. It does not upgrade the replay outcomes: all five cases remain `partial`/`blocked`, and no whole-repository detector coverage or security conclusion is claimed.

## Object-closure, gitlink, and LFS audit — 2026-10-19

The reproducible verifier `../verify_source_tree_closure.py` checked each manifest commit against its expected root tree, recursively enumerated tree and leaf entries, and batch-checked every referenced tree/blob object in the local bare object database. It also searched tracked text blobs for the standard Git LFS pointer header and enumerated gitlinks, `.gitmodules`, and `.gitattributes` paths. Run it from the repository root with:

```powershell
python research/experiments/ark_runtime/c7_20261018/verify_source_tree_closure.py `
  --object-db D:/openHarmonyScanner/tmp/c-line-ark-history-full-snapshots-20261018.git
```

The saved machine-readable report is [source_tree_closure_20261019.json](../source_tree_closure_20261019.json), SHA-256 `54657970afc43fdefd00297809bf6ae8286e17cb90091cf1a9209d52d1618e3b`. For all five commits, the expected and observed root trees match; recursive leaf counts match the replay inventory (7,573; 7,577; 7,829; 7,832; 10,218); every referenced tree/blob object is present, targeted `git fsck --full --no-reflogs --connectivity-only` exited 0 without missing/corrupt-object errors (dangling-object notices remain expected for this ref-less bare database), and no gitlinks, `.gitmodules`, `.gitattributes`, or standard LFS pointer blobs were found. The five-snapshot object database remains shallow (18 boundaries); this tree-closure pass alone does not establish complete ancestry/history. A separate upstream parent-history recovery and cross-evidence verifier are documented below. The bare object database has no checkout, so its dirty state is not applicable; the separate shared source worktree may be dirty and is not represented by this C7 database.

This closes the full recursive Git tree-object completeness claim for these five pinned snapshots only. It does not prove external build inputs, the current product build profile, preprocessing completeness, or whole-repository detector analysis; all five replay outcomes remain partial/blocked and holdout-ineligible. Parent-history evidence is separately recovered and cross-checked below.

## Parent-history recovery from upstream refs and object IDs — 2026-10-19

The five-snapshot object database remains shallow; its full-tree proof and the independent ancestry proof use distinct databases. A separate scratch bare database was created at `D:/openHarmonyScanner/tmp/c7-upstream-ancestry-20261019.git`; the prior object database and all frozen replay outputs were left untouched. The source is the same HTTPS upstream recorded above: `https://github.com/openharmony/arkcompiler_ets_runtime.git`.

At observation time, `git ls-remote --refs` returned 431 refs: 361 heads, 56 tags, seven `refs/pull/*/head`, and seven `refs/pull/*/merge` (raw output: [upstream_refs_20261019.txt](../upstream_refs_20261019.txt), SHA-256 `d7fa0f2ca21e9a617798e41070c2e64375b382db290cd5ca94806ea682402b14`). The filtered, non-shallow fetch covered all 361 heads and 56 tags (417 refs total). Each exact commit is an ancestor of 26 to 152 of those fetched head/tag refs. The separate pull-head query returned seven refs; pull refs were not fetched into this scratch DB, and are not needed to establish the selected ancestry because head/tag refs already contain every target. Direct exact-OID fetch also succeeded for all five commits.

For the five exact commits, `git rev-list --parents <commit>` traversed 15,326; 15,327; 15,742; 15,743; and 19,061 commits, respectively. Every walk exited 0, had no missing parent edge, and reached the same root commit `ac58bbe578f0eb61e985a450c6ceab03bd9ad2ec`. Root tree IDs match the independently verified full-tree report. The ancestry fetch used `--filter=tree:0`; it proves parent-commit graph closure only and deliberately does not supply or claim tree/blob closure. The separately recorded [source-tree closure report](../source_tree_closure_20261019.json), SHA-256 `54657970afc43fdefd00297809bf6ae8286e17cb90091cf1a9209d52d1618e3b`, remains the evidence for complete recursive trees.

Auditable commands, outputs, and hashes are indexed in [upstream_parent_history_20261019.json](../upstream_parent_history_20261019.json), SHA-256 `397c4b08f673f88aea3459433e5d69e5142ef8360fd89a50929a3769726ab544`. The complete per-target parent walks are in [upstream_target_ancestry_20261019.txt](../upstream_target_ancestry_20261019.txt), SHA-256 `f20ff13c64a2b3738971ad7398ad357a1abee3e5d595ee8465e98683832acb3e`; the complete advertised-ref walk is in [upstream_advertised_ref_walk_20261019.txt](../upstream_advertised_ref_walk_20261019.txt), SHA-256 `8ff9e2f63b960c7d5e3c198d0c1cac3336596d6bb178b866035d66f7729bab26`. Exact fetch logs are preserved in [upstream_fetch_exact_oids_20261019.txt](../upstream_fetch_exact_oids_20261019.txt) (SHA-256 `e42d8f2d7c76e8b157d65030821568561e10508ac8ecc81a34e457be51f7f660`) and the all-refs refresh log in [upstream_fetch_all_refs_20261019.txt](../upstream_fetch_all_refs_20261019.txt) (SHA-256 `cd076d292e2d6bb70316967a556ef4264c6a2c61e60e5a000fcb2fdfeb6b97a9`).

This proves complete parent ancestry for these five selected commits as traversed from the captured upstream heads/tags; it does not prove arbitrary unreachable objects or other repository history. It does not upgrade detector results, build/profile evidence, semantic completeness, or holdout status.


The read-only [combined provenance verifier](../verify_combined_source_provenance.py) cross-checks all five selected commit IDs, manifest roots, verified tree roots, complete parent walks, and captured advertised-ref ancestry. The verified result is complete_for_five_selected_commits; it is limited to these five snapshots and does not change replay or evaluation status.
