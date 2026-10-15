# A-CCR-04 Contract Change Request：ReadOnlyFactView 最小共享语义事实接口

状态：`proposed`，等待项目负责人批准。
范围：只读语义事实查询契约、兼容性约束、contract tests 与有限分析预算测试。
实施边界：本 CCR 不修改公共 IR、`contracts.py`、`runner.py`、`frontend.py`、`catalog.py`、
`ToolRunResult v1`、schema v2、检测器规则或任何历史报告。

## 1. 提交身份与实际基线

- 工作目录：`E:\网安\CyberSecurity-Innovation-Audit`
- 实际分支：`codex/full-runtime-performance-audit-20261014`
- 基线 HEAD：`38b93d30ed4be71af4a8245ed18198d999c3ee18`
- 基线 tree：`5be00bf65cd330e7a0309567a51be3a67c066c8c`
- 远端：`origin/codex/full-runtime-performance-audit-20261014`
- 远端指向同一 HEAD；未以 branch claim 代替对象核验。
- 原有 dirty worktree 和生成证据保留，不覆盖、不 reset、不迁移队友改动。
- 机器可读契约：`research/contracts/a_ccr_04/contract.json`
- 可执行一致性规则：`research/contracts/a_ccr_04/conformance.py`

## 2. 问题与目标

现有 `ReadOnlyFactView` 只能读取源码上下文、syntax facts、Detector 结果、解析覆盖和已有
`EvidenceObligation`。下一阶段 NULL Detector 和更深的 C/C++ 语义分析需要共享、只读、
可审计的 CFG、dataflow、guard、lock 和 build-context 查询，但不能由 Detector 各自猜测
这些事实，也不能把 AST/pattern 匹配升级成语义证明。

本 CCR 申请一个最小 `ReadOnlyFactView` 增量层：

1. 只读访问固定源对象和既有分析结果；
2. 每个响应明确 `observed / proven / unknown / failed`；
3. 每个响应绑定 `proof_ref`、分析范围、有限预算和失败/未知原因；
4. 缺少语义输入时 fail-closed 为 `unknown`；
5. 与现有 Detector contract、schema v2、partial coverage、EvidenceObligation 完全兼容。

## 3. 共同响应契约

所有方法均返回同一 envelope。接口简称保留原要求，实际请求还必须携带 `scope` 和 `budget`：

```text
get_symbol(path, position, scope, budget)
get_cfg_path(function, source_node, sink_node, scope, budget)
get_dataflow(source, sink, budget)             # budget 内含 scope
get_guard_proof(node, guard, scope, budget)
get_lock_state(function, location, scope, budget)
get_build_context(commit, file, scope, budget)
get_source_context(path, range, scope, budget)
get_detector_results(candidate_id, scope, budget)
get_coverage(detector_id, path, scope, budget)
```

### 3.1 状态语义

| status | 含义 | 允许的 facts | 必须避免的误读 |
|---|---|---|---|
| `observed` | 读到了绑定到 source/evidence 的直接记录 | 原始源码、syntax/coverage/detector record | 不等于 CFG、类型、guard、lock 或漏洞证明 |
| `proven` | 在声明范围内有完整、可复核证明的语义主张 | 主张、witness/certificate、proof_ref | 只证明该范围和该主张，不外推产品安全 |
| `unknown` | 能力、输入、覆盖、身份或预算不足 | `null` | 不得用最近节点、空路径、邻近 if 或默认锁状态填空 |
| `failed` | 查询、输入或完整性执行失败 | `null` | 不得解释为不存在、safe 或 miss |

状态优先级：

1. 无效请求、非法预算、hash/integrity mismatch、provider exception → `failed`；
2. 缺 CFG/dataflow/guard/lock/build context、partial analysis、unresolved identity、预算耗尽 → `unknown`；
3. 只有直接绑定记录 → `observed`；
4. 只有完整且可复核语义证明 → `proven`。

### 3.2 必填 envelope 字段

```text
schema_version
change_request_id
method
request_id
status
proof_ref[]
analysis_scope
budget
failure_reason
facts
coverage
limitations
unknown_reason       # status=unknown 时必填
```

- `proof_ref` 永远存在。`observed` 非空；`proven` 非空且 `verified=true`；
  `unknown/failed` 可为空数组，但不能省略。
- `analysis_scope` 至少包含 repository、full commit、Git tree、snapshot SHA-256、profile、
  文件/path/blob/source SHA、函数集合、detector ID/version、build context ID。
- `budget` 同时包含 requested、used、exhausted、reason。上限字段为
  `wall_time_ms / memory_mb / files / source_bytes / call_depth / cfg_nodes / paths /
  dataflow_steps / macro_rounds`。
- `failure_reason` 字段永远存在，只有 `failed` 时为非 null；必须有 code、message、retryable。
- `unknown_reason` 必须有 code、message、missing_facts。预算耗尽固定为
  `code=budget_exhausted`。
- `facts` 在 `unknown/failed` 必须为 `null`，禁止把截断路径或部分流包装成结果。

## 4. 九个接口的逐项评估

| 接口 | observed 可提供 | proven 才能提供 | 缺失/有限分析时 | v0 建议 |
|---|---|---|---|---|
| `get_symbol` | 精确 source hash 下 token/语法位置和候选符号记录 | 经 build context、声明/定义、链接/类型解析的稳定符号 identity | `unknown(identity_unresolved)`，不返回最近同名符号 | 纳入 v0；NULL Detector 先用它绑定指针/解引用符号 |
| `get_cfg_path` | 已保存的 node/function/edge 记录 | 一个可行 source→sink 路径，或完整 CFG 搜索后的 no-path | 缺 CFG、节点 identity、路径搜索不完整或预算耗尽均为 `unknown`；`facts=null` | 纳入 v0；不允许启发式“看起来可达” |
| `get_dataflow` | 已保存 def/use、alias observation | 一条带变换/别名/调用上下文的 source→sink witness，或完整 no-flow | 缺 dataflow graph、alias model 或预算耗尽为 `unknown`；不生成合成路径 | 纳入 v0；NULL 值流、返回值和对象生命周期后续共用 |
| `get_guard_proof` | 语法 guard 表达式和节点 identity | guard dominance、分支结果、提前返回和 sink 被保护的证明 | 缺 CFG/dominance/early-exit 语义为 `unknown`；附近 `if` 不是证明 | 纳入 v0；NULL Detector 必须使用它做 deref 前检查 |
| `get_lock_state` | 词法 lock/RAII 线索 | resolved lock alias、RAII/try-lock、线程上下文下的 held/not-held | 缺 lock model、alias、thread/RAII 语义为 `unknown` | 纳入 v0；`shared_ptr` 同步和 NULL 并发扩展复用 |
| `get_build_context` | 已保存 compile DB/GN/Ninja/宏/include 片段 | 与 commit/file 精确绑定的 TU、宏、include、target、生成输入 | 缺产品构建上下文为 `unknown(build_context_unavailable)`，不得套用 host 默认 | 纳入 v0；没有 build context 就不能声称 complete semantic analysis |
| `get_source_context` | 绑定 blob/source SHA 的精确 source range | 不适用；源码是证据，不是语义证明 | 范围外或预算不足为 `unknown`；hash mismatch 为 `failed` | 纳入 v0；保持历史源证据只读 |
| `get_detector_results` | schema v2 诊断、limitations、obligation，或显式 unbound 的 v1 记录 | 不适用于漏洞真值；可证明 record identity，但 finding 仍为 candidate | candidate 不存在为 `unknown`；检索/完整性失败为 `failed` | 纳入 v0；禁止自动晋升或删除 |
| `get_coverage` | file_outcomes、parse_status、complete/partial/not_analyzed/failed sidecar | 只有 sidecar 精确闭合声明范围时，才可证明该范围 coverage complete | 未记录、partial、failed 或 task completed 推不出 complete，返回 `unknown` | 纳入 v0；partial 必须保留给候选和 obligation |

### 4.1 不提供的语义

v0 不承诺跨仓库/产品级真值、攻击者控制、CIA 影响、完整调用图、跨 TU 宏展开、模板全实例化、
真实并发交错或动态可达性。它们仍是后续 EvidenceObligation/验证服务的责任。

## 5. 与现有公共契约的兼容方式

### 5.1 Detector contract

- `Detector.detect(context, units) -> DetectorRun` 不改签名、不改字段、不要求 Detector 立即依赖新接口。
- `ReadOnlyFactView` 是旁路的只读 provider；是否提供 semantic fact 由 provider 记录，
  不把 `required_facts` 缺失改成 Detector 失败。
- Detector 可以继续输出 `EvidenceObligation(kind, description, status)`；查询只读取，不写回、
  不把 `unknown/missing` 改成 `satisfied`。
- 失败隔离、`analyzed_files`、`file_outcomes` 和 `limitations` 原样保留。

### 5.2 schema v2 / v1

- 第一方 v2 继续逐诊断绑定 `source_sha256`，ID、历史 JSON、报告 hash、review 不重写。
- v1 结果继续读取，缺 source binding 标记为 `unbound/unknown`，不得补写 hash 或升级为 proven。
- `get_detector_results` 返回记录原貌及 source binding，不把 diagnostic 转成漏洞结论。

### 5.3 partial coverage 与 evidence obligations

- `complete/partial/not_analyzed/failed` 与 parse status 分离。
- partial 文件的候选和义务独立保留；整体 blocked 不会抹掉局部候选。
- `get_coverage` 可以 `observed` 返回 partial 记录；任何跨 partial 范围的 CFG/dataflow/guard/lock
  semantic claim 必须 `unknown`，除非有完整 proof。
- proof_ref 必须能回到 repository/commit/tree/blob/source/report/detector/rule/profile 或
  build artifact，不可只写模型文本、第三方 warning 或历史 verdict。

## 6. 失败与未知策略

以下情况必须 `unknown`，且 `facts=null`：

- 没有 CFG 或 node identity；
- 没有 dataflow graph、alias model 或 source/sink identity；
- 没有 guard dominance/early-return proof；
- 没有 lock alias、RAII、try-lock、thread context；
- 没有与 commit/file 绑定的 build context；
- parse/analysis 为 partial；
- symbol/call target 无法解析；
- 有限预算耗尽。

以下情况必须 `failed`：

- method/参数/路径不合法；
- requested budget 为 0、负数、缺失或 used > requested；
- source/blob/report hash 不匹配；
- provider 内部错误。

`unknown` 不是 safe、miss 或 empty result；`failed` 也不证明目标不存在。未知/失败响应必须保留
`analysis_scope`、budget usage、proof_ref（若有）和 limitations。

## 7. 有限分析预算

- 每个请求和响应都必须带 requested/used budget；不得只返回 wall time。
- `get_cfg_path` 至少限制 `cfg_nodes`、`paths`、`call_depth`、`wall_time_ms`。
- `get_dataflow` 至少限制 `dataflow_steps`、`files`、`source_bytes`、`call_depth`、`wall_time_ms`。
- `get_source_context` 的 range 必须受 `source_bytes` 限制；不能截断后声称完整。
- 达到任意上限时，整体语义查询为 `unknown(budget_exhausted)`，`facts=null`，
  `budget.exhausted` 列出触发项；可以保留已观测的原始 evidence ref，但不能返回半条路径。
- provider 不得偷偷增加预算、扫描范围外文件、隐式 fetch 或调用外部 scanner。

## 8. Contract tests 与预算测试

可执行测试位于：

```text
tests/test_a_ccr_04_contract.py
tests/test_a_ccr_04_budget.py
research/contracts/a_ccr_04/conformance.py
```

覆盖要求：

1. 九个方法名称、签名、状态枚举和 envelope 字段完整；
2. `observed/proven/unknown/failed` 语义和 facts/proof_ref 约束；
3. 缺 CFG/dataflow/guard/lock/build context 强制 `unknown` 且不返回猜测结果；
4. schema v2 source binding、v1 unbound、candidate/diagnostic identity、partial coverage、
   EvidenceObligation 只读兼容；
5. proof_ref、analysis_scope、budget、failure_reason/unknown_reason 必填；
6. zero/negative/missing/contradictory budget 明确 `failed`；
7. cfg path、dataflow、source range 的有限预算耗尽明确 `unknown(budget_exhausted)`；
8. budget exhaustion 不暴露 partial facts 或半截 path；
9. invalid request、hash mismatch、provider error 与 unknown 分离。

建议验收命令：

```text
python -m unittest tests.test_a_ccr_04_contract tests.test_a_ccr_04_budget -q
python -m unittest discover -s tests -q
git diff --check
```

## 9. 决策请求

请负责人决定是否批准 `ohscanner.readonly-fact-view-v0` 作为独立 CCR：

1. 批准共同 envelope、四态语义、proof_ref/scope/budget/failure 字段；
2. 批准九个只读查询的 v0 能力边界和 unknown fallback；
3. 批准与 Detector/schema v2/partial coverage/EvidenceObligation 的兼容测试；
4. 指定公共 provider、IR、runner、stable Finding identity 的后续实施归属；
5. 在批准前不合并公共实现、不改 IR/runner、不改历史报告。

批准前状态保持 `candidate/unknown`；批准后才进入公共接口实现和兼容性迁移。
