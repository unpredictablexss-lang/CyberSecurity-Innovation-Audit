# A 线 R0/R1/R2 预检模板

状态：`P5-A independent signoff not completed`。本目录只保存输入清单模板、标签签字状态、
样本量模板、人工成本模板和实验预算模板，不包含已冻结的 development / tuning / holdout，
也不包含 R0/R1/R2 真实输入集。

## 当前门禁

现有 `review_supplement.json` 明确记录 `independent_review=false`、`blind_review=false`，
45 个 review item 均为 `pending_independent_reviewer`。`technical_suggestion` 只是范围受限的
技术建议，不是独立真值。必须由未参与首轮候选裁定的 reviewer 完成 P5-A 签字后，才能按独立
根因和补丁家族冻结 development、调参集和 holdout。

## 文件

- `preflight_manifest.json`：本阶段边界、checkout、输入哈希和模板哈希。
- `sample_manifest.template.json`：逐样本绑定与字段规则。
- `label_signoff_status.json`：45 个盲审 review item 的待签字状态与已知源码/Detector 身份。
- `sample_size.template.json`：已观察样本池计数和待填的真值/拆分计数。
- `human_cost.template.csv`：人工成本记录模板。
- `experiment_budget.template.json`：R0/R1/R2 预算占位，不填真实模型、盲评或工具预算。

## 保留规则

所有 `unknown`、解析失败、partial、failed、unexecuted 和缺构建上下文项必须保留。
synthetic/fixture control 不能替代独立真值；模型输出和模型自评不能作为真值。当前阶段不调用模型、
不计算 Precision/Recall、不选择最佳运行。真实模型配置、盲评、工具预算和最终统计由项目负责人统一安排。
