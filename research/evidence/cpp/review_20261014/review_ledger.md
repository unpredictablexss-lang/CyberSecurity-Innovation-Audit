# 208 条 shared_ptr 候选人工复核台账

- Reviewer: `teammate-A / static review`
- 逐条状态已写入工作台 append-only review；不是 confirmed/reportable。
- 候选：208；历史基线：229。
- 根因组：9 个分析假设组，不等同于已证明根因。

## 状态统计

- `likely_false_positive`: 194
- `plausible_unproven`: 11
- `refuted`: 3

## 证据边界

- `likely_false_positive` 是对候选机制的静态复核判断，不是组件安全证明。
- `plausible_unproven` 保留并发、发布、入口、权限和 CIA 影响 unknown。
- 旧 229 条原始候选 ID 不可恢复，`baseline_229_identity.json` 只保留聚合身份和哈希。
- 没有独立真值前不计算 Precision/Recall。
