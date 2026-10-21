# TypedArray.set offset closeout package

**Case status:** `COMPLETED_WITH_BUILD_BLOCKER`. Source and component-model review plus the 11-test detector regression are complete. Ark Runtime execution is `not_run`; product impact is `unknown`; severity is unscored.

The a65 candidate source is `openharmony/arkcompiler_ets_runtime` commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. The independently reviewed d1a58 source is commit `d1a58d59166777e16574ceed64c15f0b2f44a76c`, tree `2cd854aa7d9f987de89d31a6a512e735779e75b6`. The relevant offset/conversion/write path was unchanged. The witness supports only a **target-view cross-boundary write hypothesis**: its calculated interval crosses the target view by 2,048 bytes but remains within the 8,192-byte backing allocation. It does not support backing-store OOB.

## Evidence index

| Artifact | What it establishes |
|---|---|
| [`../typedarray_set_d1a58_source_component_report_20261021.md`](../typedarray_set_d1a58_source_component_report_20261021.md) | Source binding, model/harness limits, regression result, build attempts and final limitations |
| [`independent_source_delta_review.md`](independent_source_delta_review.md) | Independent a65 → d1a58 object/hash/path review; explicitly says runtime not run and no backing-buffer OOB shown |
| [`../typedarray_set_d1a58_source_replay.py`](../typedarray_set_d1a58_source_replay.py), [`../typedarray_set_d1a58_source_replay_20261021.json`](../typedarray_set_d1a58_source_replay_20261021.json) | Recomputable d1a58 source-object/hash/AST replay; runtime remains `not_run` |
| [`../typedarray_set_boundary_harness_20261021.js`](../typedarray_set_boundary_harness_20261021.js), [`../typedarray_set_boundary_harness_20261021.json`](../typedarray_set_boundary_harness_20261021.json), [`component_harness.log`](component_harness.log) | Source arithmetic model and Node/V8 control only; not Ark Runtime execution |
| [`detector_regression_11.log`](detector_regression_11.log), [`detector_regression_11.exit`](detector_regression_11.exit), [`detector_regression_11.command.txt`](detector_regression_11.command.txt) | Exact a65-bound production detector regression: 11 passed, exit 0. Test code is pinned to C-line commit `45c2694dbcb9851dfd42f3663ba63e1b4d6d924a` (tree `34473d7ed1f9e582ceb5ce4a85750ca70ee8712a`); d1a58 was not added to production CLI |
| [`typedarray_set_offset_task_tree_20261021.json`](../typedarray_set_offset_task_tree_20261021.json) | Case-specific terminal state and limits |
| [`SHA256SUMS.txt`](SHA256SUMS.txt) | SHA-256 for the closeout artifacts and updated status entry (manifest excludes itself) |

## Reproduction commands

Run the source replay and component-model harness from the C-line worktree root. For source replay, use a local clone of the Ark Runtime repository checked out at the pinned d1a58 commit:

```powershell
$ArkRuntime = Join-Path $env:TEMP 'arkcompiler_ets_runtime-d1a58'
git clone https://gitee.com/openharmony/arkcompiler_ets_runtime.git $ArkRuntime
git -C $ArkRuntime checkout --detach d1a58d59166777e16574ceed64c15f0b2f44a76c
python research/deliveries/c-line/typedarray_set_d1a58_source_replay.py `
  --source-repo $ArkRuntime `
  --json-out research/deliveries/c-line/typedarray_set_d1a58_source_replay_20261021.json
node research/deliveries/c-line/typedarray_set_boundary_harness_20261021.js
```

Run the detector regression against its exact scanner source revision. The mainline evidence-only proposal does not contain this feature test module, so check out the C-line source commit explicitly:

```powershell
$Scanner = Join-Path $env:TEMP 'ohscanner-c-line-regression'
git clone https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git $Scanner
git -C $Scanner fetch origin codex/c-line-parallel-plan-20261020
git -C $Scanner checkout --detach 45c2694dbcb9851dfd42f3663ba63e1b4d6d924a
git -C $Scanner show -s --format="%H %T"
Set-Location $Scanner
python -m unittest tests.detectors.ark_runtime.test_arraylike_set_bounds -v
```

The expected checkout identity is commit `45c2694dbcb9851dfd42f3663ba63e1b4d6d924a`, tree `34473d7ed1f9e582ceb5ce4a85750ca70ee8712a`; the checked output is 11 tests passed, zero failed. This is scanner regression evidence, not an Ark VM run. The nested worktree name is not required for reproduction.

## Natural build blockers

### RK3568 profile

The isolated native Linux/ext4 snapshot reached GN product dependency resolution. HB/GN exited naturally with **255** because `weex-loader` was absent at `//base/global/system_resources/systemres/BUILD.gn:28`. See the complete [`rk3568_hb_build.log`](rk3568_hb_build.log), [`rk3568_gn_error.log`](rk3568_gn_error.log), [`rk3568_args.gn`](rk3568_args.gn), and [`rk3568_shell_exit.txt`](rk3568_shell_exit.txt). `args.gn` exists, but `build.ninja` was not generated.

### Host profile selection

The attempt to select/prepare `host_product@ohemu` stopped before profile selection and GN. The HB `set` module failed importing `run_application` from `prompt_toolkit.shortcuts`; HB reported code `0000`, and the script wrapper naturally exited **255**. See [`host_selection_hb_set.log`](host_selection_hb_set.log) and [`host_selection_shell_exit.txt`](host_selection_shell_exit.txt).

Neither attempt produced `ark_js_vm` or `es2abc`; no Ark Runtime candidate or safe-control execution occurred. No second build attempt is part of this closeout. The component arithmetic model and Node/V8 behavior are not described as Ark Runtime PoCs.

## Integrity and reference check

From this directory, verify included artifact hashes and Markdown references with:

```powershell
python validate_closeout_package.py
```
