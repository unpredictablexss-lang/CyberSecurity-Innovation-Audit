# A-NULL 四类计数报告接口申请（2026-10-19）

## 请求状态

**待 owner 评审。** 这是跨 Runner/报告/API/UI 的公共报告扩展请求，不授权 A 线直接修改公共输出契约。本地研究抽样 manifest 已有独立 JSON Schema 与校验器；产品报告接线尚未实现。

## 背景

扫描报告当前用 `diagnostic_count` 表示原始候选诊断行数。它没有把同仓库根因、跨仓相同源码和人工复核结果作为独立维度呈现。抽样研究工件已证明这些口径不能互相替代：9,323 条 provisional 原始观察仍保留为 9,323 行；根因身份未建立时 count 为 null；跨仓源码簇单独计数；人工标签当前 0/160。

此处不请求自动推导漏洞真值，也不请求将四数相加或从候选文本/文件行推断根因。

## 建议接口语义

建议在下一兼容报告 schema 中增加可选的 `report_count_dimensions` 对象，保留现有 `diagnostic_count`、diagnostic IDs、source location、source hash、v1 历史读取行为。字段命名和版本迁移由 owner 决定。

| 维度 | 建议字段 | 计数门与未知状态 |
|---|---|---|
| 原始观察行 | `raw_observation_rows` | 必须等于当前报告范围中保留的 diagnostic 行数及 `diagnostic_count`；不得因聚类去重而减少。 |
| 同仓库根因簇 | `within_repository_root_cause_clusters` | 仅由已验证的 root-cause identity 计数；身份未建立时 `count: null`、`status: not_established` 并说明原因。不能用文件/行、消息或相似源码替代。 |
| 跨仓相同源码簇 | `cross_repository_identical_source_clusters` | 只在多仓聚合有稳定 repository identity 和精确 source/rule 身份时计数；不足时 count 为 null/`not_established`，单仓时由 owner 选择 `not_applicable`。保存 cluster 数与覆盖的原始行数。 |
| 人工复核结论 | `human_review_outcomes` | 只从独立复核事件生成 `reviewed`、`pending`、按 disposition 分类的数量及状态；模型判断、开发者预期或扫描结果不得自动填标签。 |

每个维度应携带 `count`、`status` 和适用的来源/理由字段。四类数字是互相独立的视图，不可求和；未知必须用 null 与原因表达，不以 0 冒充。

## 兼容与验收建议

1. 新旧报告均可读取；没有新字段的 v1 历史报告继续保持原意，不回写历史文件。
2. 原始行计数与 diagnostic 行数强一致；grouping 不删诊断 ID、源码位置或证据。
3. root-cause 未验证时必须是 null/unknown；仅有文本或路径相同不能计簇。
4. 跨仓计数需要多个实际 repository identity 和可复算的源码键；同仓重复不得误计为跨仓簇。
5. 人工计数可追溯到复核事件、blind queue/source hash 和冻结标签；未审仍显示 pending，not-testable/unknown 不计作 FP。
6. 汇总 API、报告下载和 Web 展示的 scope 与计数一致；single-repo 报告不伪造跨仓数字。

## A 线交付与边界

A 线仅提供上述语义、研究 manifest/schema、可复现样例及计数差异说明。Runner、storage、API、下载报告、Web 类型/展示和兼容迁移由 owner 评估并负责；批准后再按 owner 的契约和变更范围提供 A-owned 数据或适配。未批准前，研究 manifest 不宣称已经成为产品报告接口。

相关样例与校验：`research/evidence/cpp/a_unsafe_memory_review_20261018/sampling_manifest.json`、`research/schemas/a_unsafe_memory_review_manifest_v1.schema.json`、`research/tests/a_null_03_unsafe_memory_review/validate_review_manifest.py`。该样例使用的是 9,323 provisional frame，不能代表目标 8,994 总体。
