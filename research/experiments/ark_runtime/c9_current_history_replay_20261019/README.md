# AC-REPLAY-03B: Ark current-rule historical replay

本目录是 `AC-REPLAY-03B` 的唯一新增输出目录。输入目标是本地 partial clone Git 对象库：

`E:\网安\_oh_targets\arkcompiler_ets_runtime`

执行边界：

- 不 fetch、不 checkout、不 reset、不 push。
- 不恢复目标工作树。
- 不覆盖 `c8_known_vulnerability_replay_20261019/` 或其他既有证据。
- 读取目标对象时强制 `GIT_NO_LAZY_FETCH=1`、`GIT_ALLOW_PROTOCOL=`、`GIT_NO_REPLACE_OBJECTS=1`。
- 使用 Ark Runtime 0.7.0 当前 Detector/model，不消费历史 verdict。
- 所有输出保持 `candidate/unassessed`；`validated_vulnerability=0`。

## Replay matrix

| Case | Rule | Parent/fix | 0.7.0 current result | Expected | Meaning |
|---|---|---|---|---|---|
| C9-TO-POS-001 | type-origin | 830e85b parent | `unknown` | `hit` | scanner gap |
| C9-TO-FIX-001 | type-origin | a0e3048 fix | `unknown` | `miss` | no candidate, but not a clean fixed miss |
| C9-EG-POS-001 | exception-guard | c758818 parent | `hit` | `hit` | 2 candidates: Filter, Map |
| C9-EG-FIX-001 | exception-guard | 81ca574 fix | `miss` | `miss` | 2 matched guard controls, no candidate |

`hit/miss/unknown/not_analyzed` 是本轮 replay 分类。`miss` 只表示规则分析后无 candidate，不证明安全。

## Main conclusion

- C4 exception-guard 已由当前 0.7.0 规则闭合 parent/fix 行为。
- C3 type-origin 的已知 vulnerable parent 当前不命中；已最小化为 `type_fact_invalidated_by_call`。
- 直接原因是在 `StoreTypedArrayElement` 之前执行的 `GetTaggedValueWithElementsKind(glue, kept, *i)` 尚无受限 effect summary，旧 type token 被 fail-closed 置为 stale。
- 不能在缺少 effect source 的情况下把该调用声明为 pure/type-stable。因此本线未修改 Detector/model，也未把 unknown 伪装成 hit 或 miss。
- C4 replay 的 creator dependency blob `05dda56de74949f07a241942be6465beaf94b52a` 在本地对象库缺失，因此整体 `replay_gate=blocked`，即使局部 C4 rule replay 有 hit/miss。

## Evidence files

- `replay-manifest.json`：source-bound manifest、rule/model/profile、exact argv/env、gate。
- `raw-results.json`：逐 case raw analyzer/Runner 结果和 source identity。
- `source-excerpts.json`：parent/fix 精确源码摘录。
- `type-origin-parent-fix.diff`、`exception-guard-parent-fix.diff`：由 exact blobs 在内存中生成的差异。
- `scanner-gap.md`：type-origin 不命中的最小复现和原因。
- `limitations.md`：依赖、环境、范围和禁止结论。
- `continuation-plan.md`：下一算法切片和结构化 vibe coding prompt。
- `test-results.txt`、`measurement.json`：exact tests、wall、peak RSS。
- `hashes.json`：本目录证据哈希。

## Commands

```powershell
$env:PYTHONPATH='.;E:\网安\CyberSecurity-Innovation-Audit\.venv\windows-audit-deps'
$env:PYTHONDONTWRITEBYTECODE='1'
$env:PYTHONHASHSEED='0'
$env:GIT_NO_LAZY_FETCH='1'
$env:GIT_ALLOW_PROTOCOL=''
$env:GIT_TERMINAL_PROMPT='0'
$env:GIT_NO_REPLACE_OBJECTS='1'
$env:OHSCANNER_ARK_REPO='E:\网安\_oh_targets\arkcompiler_ets_runtime'
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe research\experiments\ark_runtime\c9_current_history_replay_20261019\measure.py
```

## Claim boundary

本轮没有产品漏洞、CWE/CVE、Precision/Recall、FP/FN 或安全证明。当前候选仍是 `candidate/unassessed`，产品入口、权限边界、触发条件、CIA impact 和 PoC 均未闭合。
