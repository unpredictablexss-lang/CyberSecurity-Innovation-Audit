# Contract Change Request: a machine-readable consequence on a finding

- 状态：`proposed / not implemented`
- 适用接口：`src/ohscanner/contracts.py` 的 `DetectorFinding`，以及 `src/benchmark/tool_result.py` 的 `ToolDiagnostic`
- 关联 detector：`ohscanner.interface.ipc`
- 处理原则：本文只提出变更，**不修改公共 contracts**，也不把 proposed 字段写成已实现 API。

## 1. 问题

赛题把「CWE 准确性」和「完整性」分开计分。一个候选同时有两个不同的问题要回答：

1. **机制**：信任边界是怎么失守的？这是现有 `DetectorFinding.candidate_cwe` 表达的东西
   （`ipc.auth.missing` → CWE-862，`ipc.parcel.copy-range` → CWE-20）。
2. **后果**：失守之后可能暴露什么？这对同一个机制是不同的答案，而且不随家族走。

本仓库 39 条公告里有 **15 条**的官方影响就是信息泄露/越界读，分布在 AUTH-02（10）、
DATA-01（6）、AUTH-03（5）、AUTH-04（1）；12 组已核 S2 修复对里有 **4 组**是这一类。
实测（`research/experiments/interface/ipc/measure_consequences.py`，10 个真实组件生产代码）：
88 条候选中 `information_disclosure` 出现在 **2 个不同规则**上
（`ipc.auth.missing` 3 条、`ipc.relay.descriptor-boundary` 2 条）。

**但 `DetectorFinding` 只有一个 CWE 字段**，所以后果目前只能写进 `message` 字符串和
`EvidenceObligation`。后果因此不可机读：下游要做统计、去重、按影响排序，只能对消息做正则。

## 2. 当前的 workaround（本分支已实现）

不改契约的前提下：

- `models.py` 新增**已审查的后果目录**（`DISCLOSURE_CALLS` / `IMPACT_BY_RULE` / `IMPACT_CWE` /
  `IMPACT_DESCRIPTION`），与机制规则分开；`consequence_for(rule, calls)` 给出
  `(impact, consequence_cwe, basis)`。读类 API 把后果提升为 `information_disclosure`，
  与机制无关；否则取规则基线。**只有目录能给出理由的后果才带 CWE**——`boundary_bypass`
  这类后果的 CWE 取决于路径到底够到什么，硬编一个号就是过度声称。
- `analysis.py` 的 `Observation` 带上 `impact` / `impact_cwe` / `impact_basis`。
- `detector.py` 把后果写进 message（`[<impact> <CWE>]`，并在有根据时给出驱动它的调用名），
  并新增 `consequence` 义务。
- **机制 CWE 不变**：`candidate_cwe` 仍是机制，后果是第二个、不同的答案，不是替换。

代价：后果靠消息格式承载，解析器一变就失效。实测脚本已经用「取不到后果的候选数必须为 0」
把这一点变成硬失败，而不是静默归零。

## 3. 请求的接口能力

在 `DetectorFinding` 增加**可选**字段：

```python
consequence_impact: Optional[str] = None   # e.g. "information_disclosure"
consequence_cwe: Optional[str] = None      # e.g. "CWE-200", None 表示目录给不出根据
```

并原样映射到 `ToolDiagnostic`。要求：

1. 两个字段都可为 `None`；既有 detector 不填也能通过（纯增量，不破坏 v1 payload）。
2. Runner 不得因为这两个字段改变状态语义：finding 仍是 `candidate/unassessed`。
3. 若填写，`consequence_impact` 必须来自一个**显式、版本化的目录**，不是由消息或名字启发式推断。
4. `consequence_cwe` 与 `candidate_cwe` 并存且**不得互相覆盖**；报告要能分别列。

## 4. 状态语义必须同步固定

- 后果是**可能性**，不是已证实的暴露：调用一个读类 API 不证明真的把数据返回给了未授权调用者。
- 只有 `Evidence gate` 通过后，后果才能从「可能」升级为「已证实的 CIA 影响」。
- 不给 CWE 的后果（`boundary_bypass` 等）不得在报告里被补一个号码。
- `consequence_*` 的存在不改变 `validated_vulnerability`。

## 5. 需要的回归测试

- 不填新字段的既有 payload 仍能规范化（向后兼容）。
- `consequence_cwe` 与 `candidate_cwe` 同时存在时不互相覆盖。
- 空字符串与 `None` 的区别必须明确（`None` = 未分类；目录判断「给不出根据」也用 `None`）。
- 未知 `consequence_impact` 不得被下游静默当成某个已知类别。
- 混入未审查后果类别的 payload 必须被拒绝。

## 6. 不在本请求范围

不请求 CFG、数据流、污点、可达性证明、运行时触发或状态提升；也不请求把后果目录本身放进公共 schema
（目录属于 detector 的模型，应各自版本化）。
