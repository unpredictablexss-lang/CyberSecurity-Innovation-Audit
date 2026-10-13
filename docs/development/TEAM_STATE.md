# 团队状态与集成决策单

日期：2026-10-13。来自本次 git fetch 与 GitHub PR 元数据。
这份文件是当前入口；PROGRAM_STATUS 的历史试验章节保留，不用一长篇历史代替当前任务板。

## 当前固定版本

| 线 | head | 状态 |
|---|---|---|
| main | 1446e49 | 正式主线，尚无 Core/面板完整新能力 |
| Core | e365465 | Draft PR #5 → main |
| 负责人覆盖/IPC 平台 | 86fbf99 | Draft PR #8 → Core |
| 工作台 | fe85edd | Draft PR #9 → 负责人平台；CI Run 38195475780 success |
| A 最新静态模块 | e9563f9 | 本次取到的远端快照，整条线未复测/未集成 |
| B 最新接口模块 | 48bce9e | 本次取到的远端快照，整条线未复测/未集成 |
| 本轮工作区整理 | chore/workspace-standardization | 基于 fe85edd，只做本地入口/协作规范 |

完整 SHA、脏文件状态和源码库清单见本机 records/2026-10-13/before.json。
上述是取证时点，不会自动跟随远端变化。A/B 文档中的 391/451 是各自记录，
不是本轮负责人验收数，不能相加或拿来要求集成分支凑同一总数。

## 先解决的冲突

1. B 新树 ToolRunResult 支持 v2/逐 diagnostic 来源字段，负责人和工作台基于 v1。
   B runner 与负责人 runner 的 covered/partial/blocked 计数策略也不同。
   不以覆盖整文件方式集成；先单开契约迁移决策，明确旧报告读取与新的序列化。
2. B 的 M1/M2 修复值得优先审查，但应从 interface 包与正反例开始，依负责人平台回归。
   不把 B 的双遍 audit、v2 runner 和临时平台副本默认装进产品。
3. A 新增 RevisionAnalysis/AnalysisRunContext、差异 sidecar 等，不能因此宣称面板
   已支持提交区间/跨版本模式。先确定版本解析/比较服务的公共所有权和兼容边界。
4. A 记录将 shared_ptr PoC 移交 B 的 src/ohscanner/poc。本轮只核对记录，未搬文件。
   统一验证任务/证据 schema 应由负责人维护；A/B 分别负责各自家族的 Harness 与语义，
   不因代码暂存在谁的分支就把整个验证平台归给该线。

建议短期保持现有产品 v1 与 Sidecar，选取 A/B 检测修复；若 v2 有必须的语义价值，
单独迁移 PR 并提供 v1 输入读取、v2 输出、CLI/Web/报告/未知义务保留的兼容回归。
“建议”不是已经否决或撤销 B 的既有约定，最终接口决策由队长冻结后通知两线。

## 模块与协作规则

- 负责人：公共 contracts/runner/catalog、Git/版本解析、Web/Worker/存储、CI、
  统一验证编排与最终报告。公共 API/schema 变更必须先有兼容说明。
- A：C/C++ 检测器、对应正例/修复/安全对照、方法卡、受控 Harness 和根因解释。
- B：IPC/接口检测器、对应对照、方法卡、权限边界和受控 Harness。
- 队友可以提出公共层改动，但独立提交，不混在检测器修复里。
- 新工作从队长发布的固定 integration-base 完整 SHA 起分支；分支名不是固定版本。
  已在开发的旧分支不强行重置，先交一个可审查的固定 head/patch。
- 每轮只交一个可验收单元。禁止复制整个仓库目录作为“交付包”再覆盖集成目录。
- 本轮模块历史为 foundation → jobs-api → UI → evidence-review 的累积节点，
  工作台 fe85edd 已包含，不要逐条重复 merge。
- 不让团队三人同时编辑 PROGRAM_STATUS 的同一末尾段落；各线详细日志保存在
  docs/research 对应文件，交付摘要由负责人更新本文件/PROGRAM_STATUS。
- Git worktree 共享对象但有独立分支和文件；B 现有独立 clone 仍是同一远端项目，
  不必为了统一外观重新 clone 或移动。每个活动分支一个工作目录。

## 合并顺序

PR #5 公共 Core → PR #8 覆盖/义务与 IPC 注册 → PR #9 工作台。
每个依赖合入后再 retarget 下一级并检查差异/CI，不能现在全标 Ready。
A/B 修复可在独立集成分支先做选择性迁入测试，但 main 合并仍走上述依赖。
本轮未执行上述合并，也不修改现有 PR 的 base/Ready 状态。

新任务建议命名：feat/source-sync、feat/revision-range、feat/validation-jobs、
feat/version-impact、feat/agent-investigation。只在实际开工时创建分支，不建空壳。

## 单次交付模板

复制 handoff_template.md，填 branch + 完整 head + base SHA、变更路径、
exact argv/环境/产物 hash、通过/失败/跳过、候选/确认数、覆盖/unknown、
协议是否改变、依赖和未完成。没有独立证据的候选不提升为确认。
负责人在独立 worktree 审查，必要时迁移指定提交/文件，跑旧回归和真实组件对照后收口。
