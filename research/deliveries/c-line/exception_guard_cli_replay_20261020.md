# Ark exception guard：CLI 历史样本基线复核（2026-10-20）

## 检查范围

- 工作树：`D:\openHarmonyScanner\worktrees\worktrees\c-static-replay-test-20261020`
- 分支/基线：`codex/c-static-replay-test-20261020`，HEAD `71950e65f46e204e6aec21210c8de73fa4f2a1a9`
- 固定源码对象库：`D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`
- detector：`ohscanner.ark.runtime.type_safety`
- 源路径：`ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`
- 本轮只检查现有 CLI 与模型接线；没有修改生产代码或模型。

## 单元测试对照

使用固定对象库运行：

```powershell
$env:OHSCANNER_ARK_REPO='D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git'
python -m unittest tests.detectors.ark_runtime.test_exception_guard.ExceptionGuardHistoricalTests -v
```

实际结果：`test_exact_parent_and_fixed_source_through_registered_adapter ... ok`，1 项通过。该测试直接构建 `RuntimeTypeModel()`，再手动注册 `ArkRuntimeTypeSafetyDetector(model=model)`；同一条测试确认 parent `c758...` 有两条 exception-guard candidate，fixed `81ca...` 没有该规则 finding。两者的 detector run 都保持 `blocked`、覆盖 `partial`，所以单元对照没有宣称完整或安全。

## 公开 CLI 基线

通过生产 `ohscan-run` 入口分别扫描 parent 与 fixed 的精确目标文件。命令模板（将 `<commit>`、`<name>` 替换为下表值）：

```powershell
python -m src.cli ohscan-run `
  --repo-dir D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git `
  --repository openharmony/arkcompiler_ets_runtime `
  --commit <commit> `
  --include ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp `
  --detector ohscanner.ark.runtime.type_safety `
  --json-out D:\openHarmonyScanner\tmp\c-static-replay-baseline-20261020\<name>.json `
  --md-out D:\openHarmonyScanner\tmp\c-static-replay-baseline-20261020\<name>.md
```

CLI 两次均退出成功，stdout 的扫描覆盖为 `completed_with_limitations`，diagnostic 数为 0。JSON 中各项实际值：

| 字段 | parent | fixed |
|---|---|---|
| commit | `c758818dbfd0b146a908d43d21f6ca1706c33783` | `81ca57487d04ea30cd11c271e86494a4e130f43e` |
| tree | `5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a` | `f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5` |
| source blob | `857ad416bc102fcd5d462e9702d2ba7c51f29b6d` | `3b9de9d915d767d7a67316145451da2446162884` |
| source SHA-256 | `984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9` | `4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0` |
| parse status | `partial` | `partial` |
| parser missing-line issues | 3373, 3686 | 3391, 3704 |
| detector analysis | `not_analyzed` | `not_analyzed` |
| detector-run status | `blocked` | `blocked` |
| detector diagnostics | 0 | 0 |
| coverage counts | `not_analyzed: 1` | `not_analyzed: 1` |

Both reports explicitly carry the limitations “exact upstream repository/commit/path is not in the reviewed model”, “INCOMPLETE COVERAGE”, and “Coverage incomplete or unsupported; do not infer safety.” Thus the absence of diagnostics is not a fixed/safe verdict. The partial source is not reported as complete.

The CLI registered catalog model identifies the detector admission as `explicit_selection_required: exact C1 repository/commit/target/creator blob profile only; partial or unsupported source remains unknown`. In the current `c_line_static_model()`, `exception_guard_bindings` is restricted to `base.exception_guard_bindings[-1]`, the later C1-bound source. Consequently neither parent nor fixed historical row is available to the public CLI model. The manual unit test and public CLI therefore exercise different model construction paths, explaining why the former can reproduce the pair while the latter blocks both before analysis.

## Baseline finding and remaining verification

At this baseline, the parent candidate disappears from the public CLI because the historical binding is absent; the fixed case also has no finding, but only because it is equally unbound and unanalyzed. The CLI currently blocks correctly and does not label either partial source complete or safe. This establishes a profile/replay gap, not a detector miss after analysis and not a claim that the underlying source is a confirmed vulnerability.

JSON and Markdown CLI outputs are preserved outside the worktree at `D:\openHarmonyScanner\tmp\c-static-replay-baseline-20261020\parent.{json,md}` and `fixed.{json,md}`. Further after-change conclusions are intentionally pending the development-line commit.
