# 请求共享平台增加规则级覆盖 sidecar

日期：2026-10-19。提出方：B / IPC lane。目的：让组件扫描中的零命中规则能显示实际评估范围和语法限制，而不是把 detector 全局解析率冒充成逐规则覆盖。根据 `config/collaboration/ownership.json`，`src/ohscanner/contracts.py` 与 `src/ohscanner/runner.py` 由集成人维护；本文件是接口申请，不包含越界实现。

## 当前已验证缺口

- 固定八仓、`ohscanner.interface.ipc 0.12.12` 共注册 19 条规则：命中 3 条、16 条零候选。
- 八仓 C/C++ applicable 文件 6,035 个：complete 4,341、partial 1,694；detector 级 complete 比例为 71.9%。这不能说明任一具体规则评估了哪些文件或语法形状。
- 当前 fixture 已将 19/19 positive 与 19/19 fixed-negative 控制精确关联到规则，另有 13/19 条规则具备精确 safe-negative 控制；这是设计回归，不是独立 holdout。
- 当前 `DetectorRun` 和 `detector_coverage` 只有 detector/file 级结果，没有 rule-specific applicable/evaluated/unexamined 计数。零候选规则必须留为 coverage-unknown。
- 可复核数据：`20261019-eight-component-rule-coverage-audit/manifest.json`、`rule_coverage.csv`、`README.md`。

## 建议接口

由 shared contract 为 DetectorRun 增加可选、结构化的规则覆盖观察；旧 detector 可以不提供，旧报告读取语义不变。Runner 将其复制到 detector coverage sidecar 的可选 `rules` 子对象，并在 Markdown 展示摘要。建议每条记录至少包含：

```json
{
  "rule_id": "ipc.auth.object-owner",
  "basis": "rule-defined syntactic evaluation population",
  "status": "partial",
  "applicable_files": ["path/to/file.cpp"],
  "evaluated_complete_files": [],
  "evaluated_partial_files": ["path/to/file.cpp"],
  "not_evaluated_files": [],
  "unsupported_construct_count": 0,
  "budget_skipped_count": 0,
  "candidate_count": 0,
  "limitations": ["..."],
  "controls": {"positive": 1, "fixed": 1, "safe": 0, "kind": "design_fixture"}
}
```

示例仅表示建议形状，不是当前已实现或已测量的数值。每个 detector 必须自己定义 `basis` 和 applicable/evaluated 事件；Runner 不得默认“凡是 C/C++ 文件都适用于全部 IPC 规则”。来源文件列表需与本次 ScanRequest scope 相交校验，并带 source hash 绑定；计数由 runner 从去重后的路径列表重算，拒绝矛盾计数。

## 展示规则

- `evaluated_complete_files > 0` 且没有规则级缺口时，允许展示“在明确适用语法范围内评估，0 candidate”；这仍不是组件安全结论。
- 有 partial、unsupported、budget-skipped 或 unexamined 文件时展示“0 candidate，覆盖不完整/unknown”，并列出原因。
- 没有可证明的适用单元时是 `not_evaluated`，不是“已扫描 0 命中”。
- positive/fixed/safe controls 单列 fixture 结果，不纳入真实仓覆盖分母；缺一种控制不能由其它控制推断替代。
- 不增加 DetectorRun 的执行状态种类；执行结果与规则覆盖是独立维度。

## 兼容与验收

1. 给公共协议添加新字段前列清所有 DetectorRun 构造、规范化/序列化和 CLI/API/Web 消费点；旧 detector 无该字段时旧报告与现有输出保持一致。
2. 加一条 IPC 规则对照，包含正例、fixed、safe、无适用文件、partial、unsupported 和 not-run 输入；不把 fixture 控制混入真实组件文件数。
3. 固定八仓原 commit/tree/scope 重跑，检查每条规则的 file 列表、状态、计数闭合及 SHA 来源绑定。16 条零候选规则中只把有实际完整评估证据的规则从 unknown 提升到“已评估无命中”。
4. 原始 30 条候选身份必须逐条比较；任何增加/消失都单独解释。未变候选也要检查 partial 义务是否保留。
5. 回归 v1 历史报告读取与 v2 新报告输出；不得改写已归档 JSON、finding ID、人工复核或已生成 hash。

## 决策边界

这个改动需要 shared owner 先接受接口并实现 Runner/sidecar 部分，B 再按规则逐步上报覆盖事件。B 线不应私自修改 shared contracts/runner，也不能通过在 `limitations` 拼机器 JSON 或伪造零候选诊断绕过所有权与 schema 边界。
