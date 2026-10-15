# A-EXP-01 统计方法（冻结，未运行）

## 数据边界与统计口径
本包固定 **45 个 review item / 45 个 scope occurrence / 44 个唯一 workbench candidate**。
45 个 review item 由唯一 `experiment_item_id` 标识，是 planned run 和主要聚合单位。
scope occurrence 的键是 `workbench_candidate_id + review_scope`；唯一 candidate 的键是
`workbench_candidate_id`。因此同一 candidate 出现在两个 scope 时仍是 2 个 review item、
2 个 scope occurrence，但只贡献 1 个 unique candidate。

candidate `1fee3a1da2302de95846358305a7b7e0c64b2241d2e1a0e831a2f58c08167cd7`
分别出现在 `plausible_unproven` 和 `holdout`。两条记录、两个 `experiment_item_id`、
两个 `review_item_id` 和两个 scope 都原样保留；不删除、不合并、不改写。
同 scope 内重复 occurrence 是 conflict；跨 scope 重复是已披露的 overlap。
必须同时报告 45 review item 和 44 unique candidate，不能把 45 写成 44 个独立候选，
也不能宣称 unique-candidate 级独立性。

真值集来自 `truth_set_manifest.json`，其 `eligible_for_metrics=false`、
`metrics=not_computed`。当前 product-level truth 只有 safe/unrelated/unknown，且仍有产品入口、
触发、同步和 CIA unknown。本实验不计算 Precision/Recall、FPR/FNR、零误报/零漏报，
也不把 controlled mechanism label 当产品真值。synthetic controls 不是独立 holdout。

## 设计
- R0：OHScanner 固定事实包 + 同标准人工审查；3 次 repetition。
- R1：同一批 review item + 单轮 LLM review；3 次 repetition，temperature=0，
  seeds 20261015/20261016/20261017，tool_calls=0。
- R2：同一批 review item + 有界只读工具 Agent；3 次 repetition，同一 seeds。
- 每组 planned run = 45 × 3 = 135；三组合计 405。retry 留在同一 run/repetition 内，
  不增加 repetition 数，也不替换失败 repetition。
- 所有运行、失败、超时、超预算、unknown、retry 和全部 repetition 都保留，不选最佳一次。

## 主要预注册描述量
1. 合法引用率：有合法 fact_id/evidence_id 的 claims / 全部 claims；非法/缺失引用单列并使
   completed run 失败或保持 unknown。
2. 证据门完整度：六个门项的 met/partial/not_met/unknown 计数和比例。
3. 机制标签与冻结 controlled_mechanism_label 的一致性：只作 descriptive agreement。
4. unknown 保持率：产品级/机制级 unknown 是否保持 unknown，不被强行判 safe/miss。
5. 人工 active time、provider token、实际费用、wall、工具调用/失败/retry、输出字节。
6. 可复现性：同 `experiment_item_id` 三次 repetition 的标签、输出 hash、引用集合稳定性。

## 聚合与区间
先按 `experiment_item_id` 聚合三次 repetition（保留每次原始记录），再以 45 个 review item
为单位汇总；另披露 44 个 unique candidate 的聚类。比例给 Wilson 95% 区间；
均值/中位数给 bootstrap 95% 区间（10,000 次，seed=20261015）。失败运行按失败/unknown
计入分母，不删除；缺失 provider usage/cost 记 unknown，不估算。
