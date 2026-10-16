# Agent 方案与可复核对照实验

更新：2026-10-16。产品核心仍是模型缺席可运行的固定只读调查；A-EXP-01 研究 harness 已执行受控模型/工具实验，R0 人工组仍 pending。

## 何时读取

设计 LLM/Agent、R0/R1/R2、D0/D1/D2、prompt、工具适配器、真值或准确率实验时读取。普通扫描任务不应加载本文件。

## Agent 边界

Agent 输入固定候选、来源证据和义务，只能建议调查步骤并通过授权工具层执行。当前工具为固定源码摘录、义务查询、固定提交 Git 历史和 Detector 记录的符号/parse 摘要。尚未实现通用符号搜索、历史补丁检索、模型选择器、多 Agent 或 arbitrary shell。

每次实验记录 model/provider/version、prompt/tool version、参数/采样、输入 hash、工具 evidence ID、Token/费用/耗时、失败/重试和最终假设。模型输出是 untrusted content，不能改扫描结果、Git 对象、review 或确认状态，也不能自证。向第三方发送源码前必须确定数据处理约束。

## 实验源码来源与复现边界

已有真实组件实验使用 OHScanner 仓库外的预固定 checkout，不从 `/download` 下载，也不现场 `repo sync`。五组件仓库、full commit/tree、GitCode `refs/keep-around` 来源及本地路径见《开发、协作、复现与最终打包》的“既有实验来源”。R0/R1/R2 和消融读取冻结候选包、源码摘录和 Git identity。A-NULL-02 是独立 vulnerable/fixed `communication_dsoftbus` 快照；RC-JSPROXY 绑定 `distributeddatamgr_kv_store` 的固定 commit。synthetic fixture 和 Harness 控制来自本仓库测试资产。新 `repo sync` 只能作为新 acquisition run，不能回填旧实验 provenance。

## 主实验

| 组 | 方法 | 问题 |
|---|---|---|
| R0 | OHScanner + 同标准人工 | 基础根因区分与人工成本 |
| R1 | 同候选 + 单轮 LLM review | 解释收益、幻觉与成本 |
| R2 | 同候选 + 有界工具 Agent | 多轮取证是否补齐事实、降低人工 |

三组固定 target/commit/scope/Detector、`fact_bundle_sha256`、义务、工具口径和判定标准。R2 额外预算单列。人工用时单独测、盲化；失败、超预算、unknown 全计入，报告所有 repetition，不挑最佳。

补充 D0 自研静态、D1 定向 LLM 探索、D2 混合发现。D 实验与 R 实验分母分开，显式报告可见文件、字节、上下文覆盖、Token、工具和迭代预算。

## 数据集与真值

开发、调参、冻结 holdout 按根因/补丁家族隔离。样本至少覆盖 vulnerable/fixed/safe/unrelated，固定 repo/parent/fix/tree/blob/source hash、profile、入口/条件和 ground truth 来源。公开 CVE 可能有训练污染，应补未见变体。

真值由独立源码复核或受控运行建立。补丁绑定不等于产品级漏洞。缺 include/解析失败为 unknown，不强判 miss。Semgrep、CodeQL、Joern、Clang、Infer 只作离线基线，不是生产 Detector 依赖。

## 指标与报告

按独立根因统计 TP/FP/FN/TN，只有 reliable non-model truth 和完整 prediction 才发布 Precision/Recall。单列 coverage、partial/failed/unknown、义务、独立新事实、引用错误、人工时间、wall/RSS/Token/费用/工具失败。冻结 repetitions、seed 和采样，报告全部运行和区间。

0 findings 不证明安全，模型同意不证明漏洞。最终包包含 manifest、exact argv、模型/配置/prompt、原始日志、hash、结果表和限制。A-EXP-01 的 R1/R2 与三项消融已执行全部 repetition；R0 仍待独立人工，不能声称完整三组方法效果。

## 2026-10-16 A-EXP-01 execution update

R1/R2 使用同一 45 review items、同一 `fact_bundle_sha256`、同一六项 EvidenceObligation 合同和同一判定标准。R1 为 135/135 记录、128 completed、7 failed；R2 为 135/135 记录、123 completed、12 failed。R2 使用 270 次 provider turns 和 540 次只读工具调用，额外预算在 `r2_extra_budget.json` 单列。

去 AST、去历史补丁、只允许一轮三项消融均为 135/135 记录。所有失败、非法/缺失引用、unknown 和输出不稳定均保留。独立新增事实只按持久化 tool-result evidence ID 的引用统计；模型自评、历史 review 和 sealed truth 均未作为真值。R0 的 135 个盲化人工评审任务已排队，但没有人工评审员执行，人工用时保持 unknown。完整原始请求/响应、工具轨迹、hash、Token、参考费用、耗时、repetition variance 和限制位于 `research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/`。
