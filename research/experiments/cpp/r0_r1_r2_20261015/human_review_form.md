# A-EXP-01 同标准人工评审表（冻结）

本表用于 R0；R1/R2 的模型输出由盲化人工复核员按同一证据门和同一字段验收。不得把模型自评当真值。

## 运行绑定
- experiment_item_id：________________
- group / repetition / reviewer_id：________________
- input_bundle_sha256：________________
- fact/evidence IDs visible：________________
- 开始/结束时间、active_seconds、paused_seconds：________________
- 工具调用数、失败数、超时/超预算：________________

## 程序事实（每项引用 fact_id 或 evidence_id）
1. 同对象 owner read/write pair：________________
2. thread/event-queue ownership：________________
3. shared_ptr publication/lifecycle order：________________
4. synchronization protocol / happens-before：________________
5. trigger window：________________
6. entry/privilege boundary：________________
7. reachable sensitive operation：________________
8. concrete CIA impact：________________

## 证据门
| 门项 | met / partial / not_met / unknown | evidence IDs | 解释与缺口 |
|---|---|---|---|
| fixed target identity | | | |
| realistic entry/privilege boundary | | | |
| reachable sensitive operation | | | |
| trigger conditions | | | |
| concrete CIA impact | | | |
| auditable evidence | | | |

## 结论（不得改历史状态）
- mechanism_label：vulnerable / fixed / safe / unrelated / unknown
- product_assessment：reportable_vulnerability / not_reportable / unknown
- evidence_gate_status：met / partial / not_met / unknown
- claims（每条必须有 evidence_refs）：________________
- missing_evidence / unknown_reason：________________
- recommended_probe（只能建议，不得执行）：________________
- limitations：________________

## 盲化与追加性
- 未查看独立真值、历史 review label、R1/R2 输出或其他评审员答案：是 / 否
- 未修改历史报告、candidate ID、review、case、confirmed/reportable 状态：是 / 否
- 本表和运行记录按 append-only 保存；失败/超时/unknown 均保留。
