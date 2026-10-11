# OHScanner 自研 Detector Plugin Contract v2

> 状态：**已实现**（代码 + 回归测试落地后本行才成立；见 §7 的测试清单与 §8 的实现位置）。
> 基线：`ohscanner_detector_contract_v1.md`（未删除，作为 v1 语义的历史记录保留）。
> 本文件按 v1 §7 的规定提出：「之后任何破坏性变更必须提出 contract-v2（含迁移说明），
> 不可悄悄改公共 schema」。v1 §7 未改动，v1 其余章节仍有效。

## 0. 为什么是 v2 而不是 v1.1

两处变更被判定为**破坏性**，因此按 v1 §7 走 v2：

1. `DetectorFinding` 新增**必填**的 source 绑定（v1 的 finding 只有 file/line/rule/message，
   无法在 schema 层证明它对应哪一版源码）；
2. `diagnostic_id` 的**取值发生变化**（identity 纳入 `source_sha256`）。任何按 ID 存储、
   去重或比对的既有消费者，其键值不再与 v1 相同。

第 2 条是关键：它使 v1 payload 与 v2 payload 的同一 finding 具有不同 ID，所以这不是纯增量。

## 1. 本版吸收的三份 CCR

| CCR | 请求 | 本版处置 |
|---|---|---|
| `..._cpp_lifetime_source_binding_ccr.md` | `DetectorFinding` 必填 `source_sha256` 并映射到 `ToolDiagnostic` | **接受**，见 §2 |
| `..._cpp_shared_ptr_race_ccr.md` | 同上；另要求固定「机制 CWE vs 可能后果 CWE」的语义 | **接受**，见 §2 与 §3 |
| `..._consequence_ccr.md`（接口线） | 可选的机器可读后果字段 | **接受**，见 §3 |

两份 source-binding CCR 是同一个请求（内容逐段重合），合并为一条实现。
`research/corpus/native/contract_change_proposal.md` 早于本版，其请求已被上面三条覆盖，
不再单列。

## 2. source 绑定（必填）

`DetectorFinding` 新增：

```python
source_sha256: str = ""     # dataclass 层可为空，schema 层必填
```

**为什么构造函数允许空、而 schema 层必填。** 「必填」要落在**产出物**上，不是落在
每个 detector 的调用点上：Runner 已经从 selected units 拿到了 `SourceUnit.sha256`，
让 detector 自己再抄一遍只会多一处可以抄错的地方。

Runner 在构造 `ToolDiagnostic` 之前必须：

1. `finding.file` 必须存在于 selected units（v1 已有，保留）；
2. `finding.source_sha256` 为空时**由 Runner 绑定**为该 unit 的 `SourceUnit.sha256`；
3. `finding.source_sha256` 非空且**不等于** unit 的 `sha256` 时**直接失败**——
   既不改写它，也不降级为 unbound（伪造或纠正 hash 都是伪造证据）；
4. `finding.line` 必须落在该 source text 的行数内（v1 已有，保留）；
5. `diagnostic_id` 的输入**包含** `source_sha256`，源码版本变化后旧 ID 不得复用。

`ToolDiagnostic` 新增 `source_sha256: str = ""` 并原样映射。序列化**总是**输出该字段，
并额外输出派生的 `source_binding`：

- `bound` —— 有非空 hash；
- `unbound` —— 空 hash，表示**未知**绑定，**不是**「已核对通过」。v1 迁移过来的 payload
  一律落在这里，且**不得**被补一个 hash（见 §5）。

`SourceUnit.sha256` 已由 v1 的 `SourceUnit.__post_init__` 与文本内容校验一致
（`source content hash mismatch`），因此这一条绑定的是**真实源码文本**，不是声称的 hash。

## 3. 机制 CWE 与后果 CWE 并存（可选）

`DetectorFinding` / `ToolDiagnostic` 新增两个**可选**字段：

```python
consequence_impact: Optional[str] = None   # e.g. "information_disclosure"
consequence_cwe:    Optional[str] = None   # e.g. "CWE-200"；None = 目录给不出根据
```

语义分工是本版要固定下来的东西：

- `candidate_cwe` = **机制**（信任边界/根因怎么失守），必填语义不变；
- `consequence_*` = **后果**（失守之后可能暴露或破坏什么），可选；
- 两者**并存且不得互相覆盖**；报告必须能分别列出。

这同时兑现了 shared_ptr_race CCR 的 §4：该 detector 的机制是 `CWE-362`（并发 race 根因），
`CWE-416` 只作为**可能后果**记录在 `consequence_cwe`，不得写成已证明的 UAF。

约束：

1. 两个字段都可为 `None`；既有 detector 不填也能通过（**纯增量**）。
2. Runner **不得**因这两个字段改变状态语义；finding 仍是 `candidate/unassessed`。
3. 若填写，`consequence_impact` 必须来自一个**显式、版本化的目录**，不得由消息文本或名字
   启发式推断。目录属于各 detector 的模型，各自版本化，**不进公共 schema**。
4. `consequence_cwe` 与 `candidate_cwe` 同时存在时报错之外的任何「合并」都禁止——它们是两个
   不同的答案。若二者取值相同，视为调用方把机制写成了后果，**允许**但由测试要求调用方说明。
5. 未知 `consequence_impact` 值不得被下游静默当作某个已知类别。

## 4. 状态语义（本版**不**改变，逐条重申）

- `completed` 只表示 selected scope 已执行，**不是** safe；
- `partial/failed/blocked/not_run` 表示未知或覆盖不足，**不是** miss；
- unsupported language 可记 `not_applicable`，**不是** miss；
- empty findings **不是**安全证明；
- rule hit、syntax shape、symbol overlap 只能是 `candidate/unassessed`；
- `source_sha256` 只证明**文本绑定**，不证明 parse、reachability、guard dominance、
  concurrent interleaving、attacker control、impact 或 runtime validation；
- 后果是**可能性**，只有 `AGENTS.md` 的 Evidence gate 通过后才能升级为已证实的 CIA 影响；
- 新增字段不改变 `validated_vulnerability`。

## 5. 迁移说明（v1 → v2）

| 情况 | 处置 |
|---|---|
| **产出 v2** | `src/ohscanner/runner.py` 产出的自研 detector 结果，`schema_version=2`；`source_sha256` 必填。 |
| **外部工具 Adapter 保持 v1** | `src/providers/*`（semgrep/codeql/cppcheck/clang_sa/joern）继续产出 `schema_version=1`：第三方工具的原生输出不能被我们声称已绑定到某版源码。 |
| **读取 v1 payload** | 仍可加载。`source_sha256` 缺失 ⇒ `""` ⇒ `source_binding="unbound"`，**显式标记未知**，不得伪造 hash，不得被当作已核对。 |
| **读取 v2 payload** | 必须带 `source_sha256`；空值不得出现在 v2 产出中（由测试钉死）。 |
| **跨版本比较** | `src/benchmark/compare.py` 接受 1 与 2，但**不得**把两个版本的 transcript 静默当同构；版本不同必须在输出里点名。 |
| **旧 ID 复用** | 禁止。v2 的 `diagnostic_id` 含 source hash，与 v1 的同 finding ID 不同，属预期变化。 |

## 6. 不在本版范围

不请求 CFG、污点、类型系统、锁语义证明、runtime trigger、漏洞状态提升、Precision/Recall；
不请求在 M0 实现 Git commit/tree 证明；不请求把后果目录放进公共 schema；
不改变 `ScanRequest` / `SourceUnit` / `ScanContext` / `EvidenceObligation` / `DetectorRun`
的既有字段与校验。

## 7. 必须的回归测试

source 绑定：

- finding 的 hash 与 `SourceUnit.sha256` 一致时可规范化（且 ID 含该 hash）；
- stale / mismatched hash 必须**拒绝**，不得改写、不得降级；
- 源码内容变化后 `diagnostic_id` 必须变化；
- line 越界必须拒绝；
- 未填 hash 的 finding 由 Runner 绑定，结果 `source_binding="bound"`；
- v1 payload（无 hash）加载后 `source_binding="unbound"`，且 **hash 仍为空**（未伪造）；
- `completed/blocked/failed/not_run/not_applicable` 映射保持现状；
- safe/fixed/vulnerable/unrelated 证据组不得静默合并。

后果字段：

- 不填新字段的既有 payload 仍能规范化（向后兼容）；
- `consequence_cwe` 与 `candidate_cwe` 同时存在时不互相覆盖；
- `None` 与空字符串的区别明确（`None` = 未分类；目录判断「给不出根据」也用 `None`）；
- 未知 `consequence_impact` 不被下游静默归入已知类别；
- 混入未审查后果类别的 payload 必须被拒绝（由目录校验，不在公共 schema 硬编名单）。

## 8. 实现位置

- `src/ohscanner/contracts.py` —— `DetectorFinding` 新字段与校验；
- `src/ohscanner/runner.py` —— 绑定/校验 hash、ID 纳入 hash、后果字段透传、`schema_version=2`；
- `src/benchmark/tool_result.py` —— `ToolDiagnostic` 新字段、`schema_version in (1, 2)`、
  `to_dict()` 输出 `source_sha256` 与派生的 `source_binding`；
- `src/benchmark/compare.py` / `src/benchmark/report_inputs.py` —— 接受两个版本并点名差异；
- `tests/test_contract_v2_source_binding.py` —— §7 的逐条测试。

**本文件在代码与测试落地后才可称为已实现；在此之前它是请求，不是能力。**
