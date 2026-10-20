# D16 cJSON JSON Patch tree-amplification replay

Date: 2026-10-20 (Asia/Shanghai)

## Decision

Detector `ohscanner.cpp.resource_lifetime` changed from `0.4.0` to `0.4.1` in a narrow resource-sink classification fix. The exact CVE-2026-67215 source remains a root-specific candidate after the change. No fixed-source differential is claimed: a trusted root-matched cJSON fix is still unavailable. The exact two-file source run remains `blocked` because `cJSON.c` is parser-partial.

## Bound source and independent replay

The local Git source checkout was independently verified at:

- Repository: `openharmony/third_party_cjson`
- Commit: `105eaddbf0d0110b07d16bdefc81ffc796e1444a`
- Tree: `3c07134d5a05aa546b15739e32503a2ca192d258`
- `third_party/cjson/cJSON.c`: blob `152b2caa479c9f448001652913c980a6dafb82e0`, 80,529 bytes, SHA-256 `427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb`, parser status `partial`.
- `third_party/cjson/cJSON_Utils.c`: blob `8fa24f8e9bf452cf1ba49d1325c85423ce742c74`, 40,736 bytes, SHA-256 `bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9`, parser status `complete`.
- Paired snapshot SHA-256: `c0482c314ead7b9131426e7aa74f1073f734341c2ac56fb9a2578efecb51b3e7`.

After the change, the exact-source replay still emits `ohcpp-resource-exhaustion-tree-amplification-candidate-004` at `cJSON_Utils.c:861`, symbol `apply_patch`, bound to the Utils file SHA above. The separate compare-cost candidate remains at `cJSON.c:3161`; its TU and overall run stay partial/blocked. Machine-readable output is in [replay.json](replay.json); the identity-checking runner is [replay.py](replay.py).

## Root flow and model issue

The source flow is visible across the two selected translation units:

1. `cJSONUtils_ApplyPatches` iterates `current_patch` through `current_patch->next` and calls `apply_patch` for each operation (`cJSON_Utils.c`, around lines 1053–1061).
2. `apply_patch` performs recursive `cJSON_Duplicate(value, 1)` for ADD and COPY operations, then attaches the duplicate with array/object add helpers and transfers ownership by setting `value = NULL` (around lines 846–1008).
3. The core `cJSON_Delete` walks siblings and recursively invokes itself on `item->child`; it releases node/string storage through `global_hooks.deallocate` (`cJSON.c`, around lines 253–280).

The prior recursive-destructor check accepted a self-recursive function whose name ended in `Delete` as proof of a release sink. A hash-bound synthetic unrelated fixture made that weakness reproducible: a function named `cJSON_Delete` that only traversed children, combined with copy/attach-shaped code, emitted the tree-amplification candidate despite having no release operation. D16 now requires a distinct free/release/deallocator call or the C++ `delete` operator; the recursive function's own name cannot satisfy that condition. This recognizes the actual `global_hooks.deallocate` sink in cJSON and keeps the unrelated fixture quiet.

The remaining rule is deliberately a candidate model. It does not prove patch-list attacker control, aggregate node growth bounds, reachability of a later full-object deletion, or stack exhaustion. It must not be read as vulnerability confirmation.

## Controls and limits

- Existing synthetic tree-amplification positives still hit; the recursive delete-name-only negative is new and hash-bound in the fixture manifest.
- Existing unrelated tree cleanup and safe/unrelated controls stay quiet; the partial control stays blocked. There is no trusted fixed cJSON source, so a real fixed control is not fabricated.
- The vulnerable source candidate is reproducible, but aggregate parser/detector coverage remains partial. A zero result in any future partial run is not a safe result.
- No public API, parser, Catalog, or shared status document changed.

## Reproduction and verification

From the repository worktree on branch `codex/a-d16-cjson-tree-20261020`, base integration HEAD `8e79a238c3689ec6ffc2d98559a801e1620042ed`:

```powershell
python research/evidence/cpp/d16_cjson_tree_amplification_20261020/replay.py --source-root D:/openHarmonyScanner/tmp/cjson-cve67215-current-replay-20261019
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v
python -m unittest discover -s tests/detectors -p 'test_cpp_*.py' -v
python -m scripts.check_change_scope --base 8e79a238c3689ec6ffc2d98559a801e1620042ed --lane cpp
git diff --check
```

The source-root argument must point to the pinned upstream component checkout; the replay refuses a commit/tree/blob/hash mismatch. The pinned local copy is machine-local evidence input, not bundled third-party source.
