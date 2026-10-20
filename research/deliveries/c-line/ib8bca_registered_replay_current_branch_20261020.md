# IB8BCA exact registered replay on the current C-line planning branch

Date: 2026-10-20  
Planning branch HEAD at replay: `85eb0948515e777d53996caf8f7ecb4b87897c90`  
Reproduction script: `ib8bca_registered_replay_20261020.py`  
Machine-readable output: `ib8bca_registered_replay_20261020.json`

## Method

The replay read the pinned Git blobs from the local Ark Runtime object store, verified commit tree/blob/SHA-256, parsed each source with the repository's C++ parser, and built a `ScanContext` with repository `openharmony/arkcompiler_ets_runtime`, the exact source commit, `git_object` provenance, `light-ast` profile, the source blob OID, and complete AST facts. It then registered `ArkRuntimeTypeSafetyDetector` and called the repository's `run_all_with_coverage` runner. This exercises the registered `ark.runtime.dataview-index-width-bounds` binding in the current planning branch.

Reproduce from the repository root:

```powershell
python research/deliveries/c-line/ib8bca_registered_replay_20261020.py --git-dir D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git
```

## Results

| Revision | Parse | Applicable | Rule diagnostics | Diagnostic line | Coverage / detector status |
|---|---|---:|---:|---:|---|
| Parent `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | complete, 0 issues | 1 | 1 candidate | 75 | partial / blocked; `detector_model_incomplete` |
| Fixed `48fcec3686e45175f95b4600b579026a65149966` | complete, 0 issues | 1 | 0 | — | partial / blocked; `detector_model_incomplete` |

Both exact blobs match the task pins. The parent candidate is preserved despite the aggregate blocked status. The fixed result has no same-rule diagnostic, but remains partial/unknown; zero findings do not establish safety. The diagnostic is explicitly candidate-only and says it does not establish vulnerability, reachability, or impact.

## Worktree-scope reconciliation

The developer branch at `6d97874a` and tester branch at `420a71e` did not contain the index-width rule or these exact bindings, so their branch-local `not_run` conclusions were correct for those checkouts. The planning branch at `85eb094` does contain the rule and exact bindings. An independent tester reran the registered path on that planning worktree and reproduced the results above. These statements refer to different code bases; the old-base `not_run` result must not be generalized to the current planning branch.

The replay is still a static source/model result. The detector reports `bounded_index_width_model_no_general_bounds_proof` on the parent and `index_width_bounds_arithmetic_not_fully_proven:BuiltinsDataViewStubBuilder::SetTypedValue` on the fixed source. The task's second-layer review separately finds a plausible parent source-level bounds-check bypass, but compiled IR behavior, trigger reachability, runtime effect, backing allocation feasibility, and product impact remain unknown. No vulnerability or safety conclusion follows.

