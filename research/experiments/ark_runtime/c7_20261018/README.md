# C7 — Ark Runtime 0.7.0 historical replay

Recorded 2026-10-18 (Asia/Shanghai). This is a development replay of the already exposed C1/C2 history and one previously inspected unrelated patch control. It is not a holdout and supports no precision/recall claim.

## Frozen inputs

- Detector/rules: `ohscanner.ark.runtime.type_safety` 0.7.0; model digest `548996ced072b847e2a01d17c4f56de11b6fe4e42e3657f1434c7b8fbc9f3aca`.
- Freeze: scanner commit `a2fce96f98ffbb968c04ac69e19a7da24032d368`, tree `a9eba411bcbb0e9dc940f2abe4f4e96f454007c4`.
- Parser/toolchain: CPython 3.13.9, Git for Windows 2.46.2, Tree-sitter 0.26.0, tree-sitter-c 0.24.2, tree-sitter-cpp 0.23.4.
- Profile/scope: `light-ast`, one path: `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`.
- Preprocessing: none; macro expansion disabled. Build profile remains the unverified assumption `NDEBUG=1;ENABLE_ASM_ASSERT=0`.
- The original scoped replay is [run_final/manifest.json](run_final/manifest.json); verified recovered target commit/tree/blob identities are in [source_objects_manifest.json](source_objects_manifest.json). It records exact target commit/tree/path/blob/source bindings, parse status, candidate counts, coverage and obligations. A supplemental replay using complete pinned snapshots is now recorded in [run_full_snapshot_20261018/README.md](run_full_snapshot_20261018/README.md) and [run_full_snapshot_20261018/manifest.json](run_full_snapshot_20261018/manifest.json); the full source loader succeeded for all five snapshots and the missing subtree blocker is resolved for this selected set. The SHA-256 index for the original scoped result, scripts, freeze records and C1/C2 review inputs remains [run_final/integrity.json](run_final/integrity.json).

## Reproduce on this workstation

The source packet contains exact source bytes and reconstructed Git commit/tree objects from the earlier GitHub API recovery. The packet is outside this repository to keep upstream source out of commits. Restore only the required objects into an isolated bare object database, extract the clean scanner archive, run the frozen regression, then replay:

```powershell
$repo = 'D:\openHarmonyScanner\CyberSecurity-Innovation-Audit-c4'
$packet = 'C:\Users\DeepSleep\Documents\Codex\2026-10-18\c-agents-md-research-experiments-ark\work'
$sourceObjects = 'D:\openHarmonyScanner\tmp\c-line-ark-history-0.7-recovered2.git'
$scannerArchive = 'D:\openHarmonyScanner\tmp\arkruntime-detector-070-code-retry2'
$scannerTar = 'D:\openHarmonyScanner\tmp\arkruntime-detector-070-code-retry2.tar'
$runOut = Join-Path $repo 'research\experiments\ark_runtime\c7_20261018\run_reproduction'
$objectManifest = Join-Path $repo 'research\experiments\ark_runtime\c7_20261018\source_objects_reproduction.json'

git -C $repo archive --format=tar --output=$scannerTar `
  a2fce96f98ffbb968c04ac69e19a7da24032d368 src tests requirements.txt
New-Item -ItemType Directory -Path $scannerArchive
tar -xf $scannerTar -C $scannerArchive

D:\anaconda3\python.exe "$repo\research\experiments\ark_runtime\c7_20261018\restore_object_subset.py" `
  --packet $packet --output-repo $sourceObjects `
  --manifest $objectManifest

$env:PYTHONPATH = $scannerArchive
D:\anaconda3\python.exe -m pytest `
  "$scannerArchive\tests\detectors\ark_runtime\test_unseen_detector.py" -q

D:\anaconda3\python.exe "$repo\research\experiments\ark_runtime\c7_20261018\replay.py" `
  --repo-dir $sourceObjects --scanner-root $scannerArchive --output $runOut
```

The recorded clean archive was produced from the freeze commit with `git archive --format=tar <freeze-commit> src tests requirements.txt`; all 14 frozen implementation/dependency/test hashes are checked by `replay.py` before execution. The source packet is explicit input; the replay script itself performs no fetch and never reads current checkout source as a substitute.

## Results and limits

| Sample | Expected role | Result | Interpretation |
|---|---|---|---|
| C1 parent `830e85b` | Development vulnerable parent | 1 type-origin candidate; partial/blocked | Candidate has five unknown obligations. |
| C1 fix `a0e3048` | Development fixed control | 0 candidates; partial/blocked | Specific fix control only; not a broad safe label. |
| C2 parent `c758818` | Development vulnerable parent | 2 exception-guard candidates; partial/blocked | Each has five unknown obligations. |
| C2 fix `81ca574` | Development fixed control | 0 candidates; partial/blocked | Specific fix control only; not a broad safe label. |
| Unrelated spelling patch `95554c2` | Previously exposed unrelated control | 0 candidates; partial/blocked | Label stays unknown; excluded from holdout. |

The C1 patch derives a destination type token from `newArray` and uses it for the store, replacing the source array's `arrayType`. The C2 patch moves the Filter allocation header read after pending-exception handling and adds pending-exception exits in Map (and ToReversed, outside this detector's declared methods). These source-level differences match the C1/C2 development expectations; they do not prove product runtime behavior.

No separately sourced, independently reviewed safe historical version was found in the delivered C1/C2 materials. C04/C08 and other developer fixtures were not used. The fixed endpoints remain fixed controls, not independent safe examples. No sample is scored as a holdout.

All five target files parse as `partial`; all runs are `blocked`. The original `run_final/` replay could not load the full snapshot because unrelated subtree objects were missing, so it used a verified one-file `git_object` context. The supplemental `run_full_snapshot_20261018/` replay fetched the exact five commits into a new isolated depth-1 bare database, where complete tree traversal and the normal pinned-source loader succeeded. It retains the same detector/model/parser/profile/scope and the same candidate counts. The detector still analyzes only the selected one-file scope; full source inventory is not a whole-repository detector coverage claim. The full C3 evidence gate remains blocked on product build/preprocessing context and dependency semantics.

The 0.7.0 applicability contract freezes source-identity-independent selection. Its own limitations say the operation semantics originated in development work and were not independently checked against changed helper implementations; no preprocessing, complete header/type context, or verified product build profile is available. Those obligations remain unknown. Zero findings do not establish safe or miss.


`run_001/manifest.json` is the preliminary attempt and is superseded by `run_final/manifest.json`; use only the latter for this recorded result.
