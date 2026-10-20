# C-line type_safety registered CLI baseline（2026-10-20）

## 范围与选择

- 测试工作树：`D:\openHarmonyScanner\worktrees\worktrees\c-static-replay-test-20261020`
- 工作开始时分支干净，HEAD `39afcc6faef68a68ae281cf277215143e2e29805`；随后仅 cherry-pick 已授权的开发基线 `a6b1cf699781c6c74ff3fca4559a1b7c9a9cb501`（本地 `a01ffa873`），没有编辑生产代码。
- 输入索引：规划工作树 `research/experiments/ark_runtime/c10_ark_gap_rules_20261019/production-adapter-replay.json`（历史记录的 model version `0.8.10`）。本复核选择的是当前注册 `c_line_static_model()` 中可本地取源的精确 C1 target binding：commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`。当前模型版本为 `0.8.14`；该条 target binding 的 path/blob/SHA 均与 CLI 输入一致。这样可以区分模型绑定、creator scope、parser/internal coverage，不把旧 JSON 的模型版本当作当前 CLI 配置。
- 固定 Git 对象库：`D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`。
- 没有改写模型、适用范围或规则，没有把空结果解释成安全结论。

## 精确源码身份

| 输入 | Git blob | SHA-256 | 解析状态 |
|---|---|---|---|
| target `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `68fb3b0adc4f9062889a861be51b7be90362e37a` | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` | `partial` |
| creator dependency `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | `complete` |
| unrelated same-language control `ecmascript/compiler/builtins/builtins_array_stub_builder.cpp` | `147cce946ad94aa7da8775cd975f251808762089` | `240777c02a62e43899ec769dada8ff954a6804dae4aec790ebb22c4daa0b0a7f` | `partial` |

Target commit tree: `8781f036a3e7e04d8e0b34970d5f623b42875016`. Model expectation for the creator dependency is Git blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, which matches the source object passed to the CLI.

## CLI reproductions and actual output

All runs use the public registered path `python -m src.cli ohscan-run`, repository `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, and detector `ohscanner.ark.runtime.type_safety`. Artifacts are outside the worktree under `D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\`.

Target-only command:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1.json --md-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1.md
```

Actual result: aggregate `completed_with_limitations`; detector `blocked`; `applicable_files=1`; target file parse `partial`, analysis `not_analyzed`; coverage `not_analyzed: 1`; diagnostics `0`. The explicit limitation is `creator dependency is outside the scanned source scope: ecmascript/compiler/new_object_stub_builder.cpp`.

Target plus creator dependency:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1-with-dependency.json --md-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1-with-dependency.md
```

Actual result: aggregate `completed_with_limitations`; detector `blocked`; `applicable_files=2`; diagnostics `0`; coverage `partial: 1, not_analyzed: 1`. The target source remains `partial` and analysis is `partial` with `analysis_reason=detector_model_incomplete`; the dependency source is `complete` and `not_analyzed`. Target parser issues are at lines 148, 151, 154, 155, 166, 2862, 2873, 2952, 2953, 3041, 3286, 3611 and 3629. Reported target limitations include `experimental_partial_function_scope`, `parse_dependency_contamination_unknown`, `partial_scope_routed_through_semantic_selector` and `unresolved_local_observations`. The dependency is present with the expected blob/SHA, but its file record is `not_analyzed` and the run lists `new_object_stub_builder.cpp: exact upstream repository/commit/path is not in the reviewed model`.

Target plus creator dependency plus one unrelated same-language file:

```powershell
python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git --repository openharmony/arkcompiler_ets_runtime --commit a65a2853ccae13da167d9aa4720ab8b11ec16656 --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp --include ecmascript/compiler/new_object_stub_builder.cpp --include ecmascript/compiler/builtins/builtins_array_stub_builder.cpp --detector ohscanner.ark.runtime.type_safety --json-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1-with-unrelated.json --md-out D:\openHarmonyScanner\tmp\c-static-replay-type-safety-20261020\c1-with-unrelated.md
```

Actual result: aggregate `completed_with_limitations`; detector `blocked`; `applicable_files=3`; diagnostics `0`; coverage `partial: 1, not_analyzed: 2`. The target remains `partial / detector_model_incomplete`; the creator dependency is `complete / not_analyzed`; the unrelated array stub file is `partial / not_analyzed` with limitation `exact upstream repository/commit/path is not in the reviewed model`. Adding the unrelated path does not produce a finding or complete analysis. Its zero findings are not a safe verdict.

As an additional fixed-path control, the exact exception-guard fixed revision `81ca57487d04ea30cd11c271e86494a4e130f43e` still yields zero findings with `partial / blocked` coverage. This is only a fixed-source control for the registered detector and does not prove the broader source is safe.

## Root-cause boundary

Observed evidence separates the stages:

1. **Target model binding and source mapping:** the C1 target commit/path/blob/SHA match the registered binding; the target passes identity validation. No target `source blob/SHA does not match` limitation appears.
2. **Creator scope:** target-only scope is rejected for analysis because the model-required creator source is outside scope. Including the exact expected creator blob removes that specific scope limitation.
3. **Parser/internal analysis:** after adding the creator, the target remains parser `partial` and internal analysis `partial / detector_model_incomplete`, with the enumerated parser and partial-scope limitations. The rule does not produce a complete positive or negative result in these runs.
4. **Rule behavior:** no run reaches a complete analysis for this target, so this baseline provides no evidence that the type-safety rule itself should or should not emit a candidate.
5. **Runner/coverage counts:** `applicable_files` follows the scoped path count in these runs (1, 2, 3), while coverage separates one partially inspected target from unanalysed dependency/control files. This is recorded as observed output for development review; it is not by itself a security or safe/unsafe conclusion.

Thus the empty finding set is explained by explicit scope and incomplete parser/internal-analysis states, not by a demonstrated rule-level miss. The report does not claim a vulnerability, safety, or product impact. The correct expected contract for follow-up is to preserve exact target/dependency identity, represent dependency and unrelated files without treating them as target analyses, and keep the target `partial/blocked` until complete evidence exists.

## 验证与交付

在此基线代码下，无固定 Ark 环境变量运行完整 Ark Runtime 包：

```powershell
$env:OHSCANNER_ARK_REPO=$null
$modules=Get-ChildItem tests/detectors/ark_runtime -Filter 'test_*.py' | ForEach-Object { 'tests.detectors.ark_runtime.' + $_.BaseName }
python -m unittest $modules
```

实际结果：155 tests，3 skipped，全部其余测试通过。每个 CLI run 均退出成功，聚合状态 `completed_with_limitations`；`git diff --check` 通过。未新增或改动生产代码。
