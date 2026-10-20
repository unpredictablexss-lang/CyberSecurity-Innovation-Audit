# C 线快速收尾：最新 Mainline 并行任务（2026-10-20）

## 当前快照

- 已执行 `git fetch origin`。最新 `origin/main`：`c380a474718e8ec4497aff55b18a1dd38bafa13f`（D 线主线状态同步）。
- C 线主线集成 worktree 的已验收代码树基于 `4b0e16576a45a111b4fad7e8f82819a47ed472f5`；开发提交 `eb43f462769b315e87f7716f237c58b66f058acd`，Catalog 兼容修复 `764f7698f6babdcccb2cd68eba75ed1b0afefc9e`。C 集成尚未接到最新 `origin/main`。
- 独立测试已在旧基线复验该集成树：Ark Runtime 212 项通过、3 项跳过；Runner/source-binding 相关 97 项通过、1 项跳过。该结果不能替代最新 main 上的复验。
- 执行树 `C_LINE_EXECUTION_TREE_20261020.json` 的已有切片均完成或以明确限制收尾，树状态为 `CLOSEOUT_READY_WITH_LIMITATIONS`。本轮只重开“最新 mainline 兼容整合”这一具体差异，不重开已完成的候选审查。
- C 线静态候选仍显式 opt-in、default-off、精确源绑定。运行时、产品配置、可达性和影响继续按现有证据记为 `not_run`/`unknown`。

## 并行任务与结构化 Vibe Coding 提示词

### C-DEV-MAINLINE-SYNC-20261020 — 开发/整合线

```yaml
role: C 线 Ark Runtime 开发与主线整合负责人
workspace: D:\openHarmonyScanner\worktrees\c-mainline-dev-closeout-20261020
base: origin/main@c380a474718e8ec4497aff55b18a1dd38bafa13f
input: 已验收 C 集成分支，包含 eb43f462769b315e87f7716f237c58b66f058acd 与 764f7698f6babdcccb2cd68eba75ed1b0afefc9e
objective: 在最新 main 上保留 C 线已验收的精确源绑定、default-off 和研究候选限制，修复由基线漂移引入的具体兼容问题。
steps:
  - 核验分支、HEAD、remote、dirty 状态和 main/C 变更范围
  - 将 C 集成接到 origin/main，逐项审查冲突和共享文件差异
  - 对具体冲突做最小修复，不改动无关 D/owner 变更
  - 运行 Ark Runtime、Catalog、Runner 与 source-binding 受影响回归
  - 提交本地代码和报告，提供最终完整 SHA 与复验命令
feedback: 独立测试线按最终 SHA 检查；发现缺陷后修复并再次交给测试线同 SHA 复验
deliverable: 最终 commit/tree SHA、差异摘要、命令/结果、已知限制
stop: 不推送、不发布 PR、不把静态候选升级为产品漏洞；没有可复现缺陷时不扩大改动
```

### C-TEST-MAINLINE-SYNC-20261020 — 独立测试/反馈线

```yaml
role: C 线独立回归与反例测试负责人
workspace: D:\openHarmonyScanner\worktrees\c-mainline-test-closeout-20261020
base: origin/main@c380a474718e8ec4497aff55b18a1dd38bafa13f
objective: 独立核验最新 main 上 C 集成的兼容性，并在独立 checkout 上复验开发线最终 SHA。
steps:
  - 保存当前基线身份与已有测试状态
  - 检查 default-off、显式选择、精确 source identity、Runner applicability 和状态保真
  - 开发线提交后 checkout 完全相同的代码 SHA，独立执行 Ark Runtime 和相关回归
  - 检查 parent/fixed、错误 repo/commit/blob、缺依赖、partial/blocked/unknown 控制
  - 将具体失败、精确命令和日志回传开发线；修复后重复同 SHA 验收
deliverable: 独立测试报告、精确代码 SHA、逐项命令/计数、反馈与限制
stop: 不改生产实现，不用 0 findings 声称安全，不在缺少标签时计算 Precision/Recall
```

### C-INTEGRATE-TREE-20261020 — 任务树/收尾整合线

```yaml
role: C 线收尾协调者
workspace: worktrees/c-line-task-tree-20261020
objective: 让任务树、最新主线、开发提交、独立测试和收尾报告引用同一代码树与证据。
steps:
  - 记录 fetch 后 main SHA 和开发/测试 worktree 身份
  - 开发/测试来回反馈时维持 in_progress，禁止预填通过结果
  - 两线闭环后更新 execution tree 和本轮结果表，保留已完成历史
  - 运行 JSON parse、diff whitespace 检查并列出后续可执行事项与 not_run/unknown
deliverable: 更新的 JSON 任务树、并行结果/命令/完整 SHA、收尾状态
stop: 不重跑无新证据的历史审查，不等待产品或人工前置条件
```

## 持续目标与相互反馈

持续目标：每次 C 线代码交付都以最新 main 的完整 SHA 为基线，开发、独立测试和任务树使用同一代码树；任何测试反例都回到开发线，修复后由测试线针对修复 SHA 重放。每个结果分开记录源码身份、解析/internal coverage、规则候选、组件运行和产品影响。没有实际运行的项目记 `not_run`，缺失信息记 `unknown`；不得把豁免、跳过或零候选写成通过/安全结论。

快速完成条件：开发整合提交存在；独立测试在线程隔离 checkout 对该完整 SHA 复验通过，或所有失败完成开发—测试往返；任务树引用同一 SHA、命令、计数和限制。完成后状态可为 `CLOSEOUT_READY_WITH_LIMITATIONS`，无需等产品 profile 或正式准确率。

## 本轮启动状态

| 任务 | 状态 | 执行位置 | 反馈方向 |
|---|---|---|---|
| C-DEV-MAINLINE-SYNC-20261020 | in_progress | `worktrees/c-mainline-dev-closeout-20261020` | 接收测试反例并修复 |
| C-TEST-MAINLINE-SYNC-20261020 | in_progress | `worktrees/c-mainline-test-closeout-20261020` | 独立复验开发最终 SHA，失败回传开发线 |
| C-INTEGRATE-TREE-20261020 | in_progress | `worktrees/c-line-task-tree-20261020` | 汇总闭环，不提前认定通过 |
