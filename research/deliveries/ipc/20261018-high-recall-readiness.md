# B 线高召回静态候选与 Agent 复核：首轮落地记录

日期：2026-10-18
工作线：`work/ipc-20261017`
检测器源码基线：`04201e708538706a8bfb633ff5e22c50d643fb6a`
共同开发基线：`6a41dc9b1aa030158e09be6241e2b14341f9256d`

## 本轮已落地

- 增加 IPC M2 适配器回归：当同一文件包含可解析的候选函数与语法错误时，适配器仍保留该候选，文件覆盖明确为 `partial`，并在候选上附加状态为 `unknown` 的解析完整性义务。此项锁定“已观察候选不能因整体部分解析而丢失”，不声称部分 AST 之外已分析。
- 建立机器可读的真实正例 holdout 准入清单，覆盖当前 IPC 家族和 ArkTS/JS 规则。清单将所有规则标为 `unmeasured`、数据集标为 `not_established`，并禁止把没有独立正例的家族写成通过。原因是当前只有合成控制和未裁定组件候选；没有已独立裁定、源码绑定并冻结的真实漏洞正例。合成夹具、Harness、候选数变化都不计作 holdout。
- 增加契约测试，确保家族注册表与 holdout 清单一致，ArkTS/JS 规则均显式保持未测。新增规则若没有同时更新此清单和真实样本，将不能被误报为已通过召回门槛。

## Agent/平台接口复核

负责人共享工作区 `/home/audit/ohscanner/worktrees/b-high-recall-review-20261018` 有未提交的 owner-owned 文件改动，本轮只读检查，没有改写或提交这些改动。该差异将扫描报告的全部唯一 Candidate ID 与 report SHA-256 写入追加式 `candidate_review_batch`；批次幂等，不按 Top-K 截断；旧的 count-only 批次保留为身份未知。零候选不会触发第二遍 LLM 扫描。批次消费保持关闭，等待批次范围的源码披露授权；单候选仍须走现有预览/授权。Agent 复核使用追加记录和固定源码引用，不能写入 `confirmed/reportable`。

在共享工作区所用隔离依赖环境中，Agent workflow、队列、零候选、固定引用、不可自我确认与取消保留测试共 51 项通过。这只验证了当前未提交改动的测试表现，不代表其已提交、已集成或面板浏览器验收通过。

## 验收

- B IPC 全部定向测试：224 项运行，192 通过，32 跳过，0 失败。
- 仓库根 Python 全量回归：649 项运行，613 通过，36 跳过，0 失败。
- 变更范围检查：以完整基线 `6a41dc9b1aa030158e09be6241e2b14341f9256d`、lane `ipc` 运行，`violations=[]`。
- 所有静态结果仍是候选/未评估。当前未由本轮建立 `entry_controlled`、产品影响或 `validated_vulnerability`。

## 仍未达成的计划验收

1. 真正的冻结 holdout 尚未建立；所有规则家族召回状态都是未测。需要独立审阅者从有明确修复前源代码的真实漏洞中选样，按根因/补丁谱系隔离调参数据，并记录仓库、commit/tree/blob、源文件哈希、范围、规则版本和裁定依据。没有这组样本前，不能宣称 B 已达到“每个支持家族全命中”。
2. Agent 批量消费仍关闭；没有以适当的批次级源码披露授权运行真实模型，也没有 timeout、引用失效和预算排队的端到端实际消费记录。候选已排队/阻塞并不等于 Agent 已复核。
3. 负责人工作区的队列/API/面板差异仍未提交；未在浏览器复验 API→Worker→报告→队列展示，且当前还没有可用的模型 token/费用使用量记录。按所有权约束，本线不编辑 `src/workbench`、公共契约、Catalog 或全局 UI。
4. ArkTS/JS 检测器当前为 `ohscanner.oh.arkts_js@0.3.0`，但尚未注册进公共 Catalog，语法依赖也未进入 CI，因此还不能由 CLI/API 正式选择并入队；已有 owner-only 注册提案 `research/methods/interface/ARKTS_JS_CATALOG_REGISTRATION.md`。
5. 新规则须继续按独立根因加入正例、修复、安全和无关控制；当前回归数不能用作准确率或召回率。

本记录与实现仍只在本地 IPC 工作线；未推送、未合并、未更改 Draft 状态。

## 2026-10-18 复验补记

- 执行测试时 IPC 工作树 `work/ipc-20261017@1ff4cc09e415534959a1aaa5e20f3a8898601859` 干净；本补记是当前唯一未提交文件。IPC 全量定向测试 `224` 项通过、`32` 项跳过，仓库根测试 `649` 项通过、`36` 项跳过。
- 以共同基线 `6a41dc9b1aa030158e09be6241e2b14341f9256d` 执行 lane `ipc` 变更范围检查，`violations=[]`。`git diff --check` 对整条历史差异返回非零，定位到既有动态 Harness/精度探针/copy-range 证据文件的行尾空白；本轮未改这些历史产物。
- 另一个平台工作树 `/home/audit/ohscanner/worktrees/high-recall-platform-implementation-20261018` 位于 `work/high-recall-agent-queue-20261018@53db1f0e83d5c97bc7a84ce1f331324ae59e3421`，有 5 个 owner-owned 文件未提交。其队列/API/Worker 差异测试 `tests.test_workbench_operations` 与 `tests.test_workbench` 共 `64` 项通过。变更把全部唯一 ID 按字典序写入批次（不是按报告顺序），并暴露排队/运行 ID；这只是该未提交快照的测试结果，没有消费真实模型，也没有 API→Worker→报告→面板浏览器验收。本线未修改该工作树。
- 本次没有推送或合并。holdout 仍是 `not_established`，所有规则家族均为 `unmeasured`；Agent 仍未实际消费候选，漏洞确认数量仍为 `0`。
