# T82 — D82 独立验收：D55 本地 M2 准备度盘点

- 结论：**ACCEPTED_WITH_LIMITATIONS**。
- 被审材料：D82 commit `659f5cd743adb093f948a9654440dabc8bd7e133`，worktree `D:/openHarmonyScanner/worktrees/d82-local-m2-readiness-20261020`。
- 独立重放：脚本退出码 0；输出 JSON 与冻结 JSON 逐字段相同，唯一差异为 `scope.base_commit`。冻结报告记录生成前父提交 `92ccbd488c0dc4b5b98285659f2b9dd35ceb130e`；在包含冻结文件的 D82 commit 上重放时脚本自然记录 `659f5cd743adb093f948a9654440dabc8bd7e133`。这是运行时 checkout 变化，不是盘点结论或输入内容差异。
- 严格 JSON：用 `object_pairs_hook` 对冻结 D82 JSON、重放 JSON及脚本读取的协议、清单、D41/D48、T54/T55 接受记录递归拒绝 duplicate keys；全部通过。
- 范围检查：`git diff --check 92ccbd488c0dc4b5b98285659f2b9dd35ceb130e..659f5cd743adb093f948a9654440dabc8bd7e133` 通过；独立验收提交 diff-check 通过。

## 独立核验结果

1. **D55 / T54**：D55 协议标为 `preregistered_protocol_only`，`accuracy_evaluation_started=false`、`labels_created=false`、`metrics_computed=false`。T54 审阅的确切 commit 是 `c86e0b0321eb38b0ff403e98b8597622c7cd556c`，协议设计 `READY_FOR_EXECUTION_PREREQUISITES`，执行 `NOT_READY`，M2 `NOT_MET`。D82 没有把设计可执行前置条件误读成执行已就绪。
2. **D41 状态与结果**：manifest 中的 `preregistered_not_run` 与结果报告首行“replayed; independent labels pending”不一致；JSON 结果记录两轮复放。把 manifest 视为预注册状态、把结果/报告视为实际执行记录，且显式说明此 reconciliation，处理恰当。6 仓库、3,820 eligible files、201 candidate observations、complete=0、partial=2,787、not analyzed=1,033、failed=0、各类独立标签=0 与结果一致。99-case packet 确为扫描后分层审查材料；协议排除 D41，因此不能把它当总体抽样或准确率样本。
3. **D48**：README 与 summary 固定 `distributed_screen` commit/tree、97 tracked files；97 个均 partial，complete=0、scan blocked、candidate=0，未记录独立标签。材料明确是 convenience sample，不能从零候选推导安全性或准确率。D82 按协议排除该材料，结论正确。
4. **D55 advisory 覆盖**：目标目录含 17 个 catalog IDs，A/B 两批 9+8，ID 并集 17、缺少/额外 ID 均为 0；脚本校验 15 份响应正文 SHA-256。CVE-2026-33636 与 CVE-2026-46675 仍缺可校验的主 GHSA 原始响应正文，因此 package 仍为 `PARTIAL_NOT_READY` / `NOT_READY`。T55 revision 的 scope 限制也保留，没有把哈希完整误写成范围审查完成。
5. **M2 blockers**：协议 11 个 `current_missing_inputs` 都由 10 个 gate 覆盖；其中多个输入组合在同一个 gate（例如 matcher 与 coverage/unknown aggregation，reviewer 与 adjudicator）。阈值审批、独立 cohort/frame 与 provenance、overlap、可复现选择/seed、设计仿真、scanner/scope freeze、advisory、matcher/coverage、独立标签/裁决、预测密钥保管均有明确状态和外部责任方。未把缺少的治理准入、来源独立性、人工标签或 custody 伪装成扫描器代码修复，也未自行生成样本、标签或指标。

## 限制

- 此验收证明的是 D82 本地材料盘点与其边界处理可信；不证明 M2 达成，也不形成精确率/召回率估计。
- 两个 GHSA 主响应正文仍未捕获；advisory 版本适用范围也保留各自未决事项。
- `base_commit` 单字段差异由重放发生在包含 D82 文件的 commit 上造成；复放其它输出字段、输入哈希与结论均一致。
- D82 文件自述 inspection limit 为有限材料集；本报告针对任务指定的 D41/D48/D55/T54/T55 核验范围，不把它扩张成整个仓库或 M3 产品证据审计。

## 机器可读复核

配套 `T82_D82_INDEPENDENT_ACCEPTANCE_20261020.json` 记录审阅 commit、检查、对比差异和限制。复放临时输出位于系统临时目录，不写回 D82 冻结 worktree。
