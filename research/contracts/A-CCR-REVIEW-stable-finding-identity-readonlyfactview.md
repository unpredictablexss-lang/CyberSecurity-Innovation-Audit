# A-CCR-REVIEW：Stable Finding Identity 与 ReadOnlyFactView 负责人审批准备

状态：`awaiting_owner_approval`。本文仅整理负责人审批材料；不修改公共实现、不合并 main、不标记 PR ready、不写 production registration。
日期：2026-10-15（Asia/Shanghai）。

## 0. 审批对象与实际 checkout

| 项目 | 实际观察 |
|---|---|
| 工作目录 | `E:\网安\CyberSecurity-Innovation-Audit` |
| 当前分支 | `codex/full-runtime-performance-audit-20261014` |
| 当前 HEAD | `0e94ceafab1b2d79547bdf71c86e26e8b42a6b48` |
| 当前 HEAD tree | `cee6b4609e65f2954114b368761614d5f745d6a6` |
| 远端 | `origin https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git` |
| 本地相对远端 | `ahead 1`；远端分支当前指向 `38b93d30ed4be71af4a8245ed18198d999c3ee18` |
| 工作树 | 既有 dirty/untracked 文件和证据保留；未 reset、未覆盖、未迁移队友改动 |
| CCR 文档记录的基线 | A-CCR-03 / A-CCR-04 均记录 `38b93d30ed4be71af4a8245ed18198d999c3ee18`；A-CCR-04 提案当前在本地 HEAD 提交中 |

审批判断应以当前实际对象和本材料中的验证记录为准；branch claim、文档中的旧基线和 teammate 分支都不构成实现或批准证明。

### 明确只读边界

本次不修改以下公共文件，且写入审批材料前后已核对 SHA-256 未变：

| 文件 | SHA-256 |
|---|---|
| `src/ohscanner/contracts.py` | `6FEC225967A191F32C9238AA34952511BF248EA6FBC93346BBF309DBC5EFB9CE` |
| `src/ohscanner/runner.py` | `8E4C85E3B8992879F7C9EFFCF139377F426410A3D3373BE274DCE8CADEE8C7C5` |
| `src/ohscanner/detectors/catalog.py` | `F680959BC8F977114519C20308BDE07E7AA841156CE2A341F47BC2332AF8FC0E` |
| `src/ohscanner/detectors/interface/analysis.py` | `AE42F130D91D4FE6168C5571C52EAFB84C3781618780FC1520868B500602677F` |

## 1. A-CCR-03：Stable Finding Identity 摘要

### 1.1 当前 diagnostic identity 的问题

当前第一方 v2 的诊断 ID 由 `src/ohscanner/runner.py:40-43` 生成：

```text
diagnostic_id = detector_id + ":" +
  sha256(source_sha256 | file | line | rule_id | message)[:16]
```

它是单次输出中的 occurrence key，不是跨源码修订稳定的 Finding identity：

- 注释插入改变 `source_sha256`、行号和 byte range，ID 会变。
- message 改写直接改变 ID；说明文字不应决定语义身份。
- Detector/rule 版本变化时，当前 ID 不能表达“同一语义 finding 的新观察”。
- 16 位截断哈希存在碰撞风险；runner 对同 run 重复 ID 直接拒绝，不能表达重复语义 anchor。
- `file:line:rule_id` 无法区分同名成员跨 class/namespace，也不能证明移动后的表达式是同一节点。
- 现有比较的 heuristic key 为 `component|provider|rule_id|file|line|column|symbol|source_sha256`；它只能说明观察对应，不等于漏洞消失、修复或安全。

已有固定范围复扫投影：old 208、new 182、added 0、disappeared 26、changed 182、unchanged 0；182 条只改变 `diagnostic_id,message`，26 条是旧 heuristic key unmatched，不是 security-truth disappearance。对应输入和结果 hash 已核对一致：

- `outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/comparison/comparison.json`：`c7da13895f4ed08abf19eadefdea871c1633bf9a3f15833567034129a69d62e4`
- `outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/artifact_manifest.json`：`483464735cab65c69e54a1cd3c42822d5a8acbc0c9fa88a5d96791af7034c60c`

### 1.2 identity / occurrence / relation 三层设计

1. **`finding_identity_id`（语义稳定身份）**
   `ohfi:v1:sha256(canonical_json(schema, repository, rule_lineage_id, symbol_identity, ast_fingerprint))`。
   不包含 message、line、column、byte range、detector version、rule version。规则改名必须有显式 `rule_lineage_id`/alias，不能从 message 推断。

2. **`occurrence_id`（精确观察身份）**
   `ohocc:v1:sha256(canonical_json(schema, repository, legacy_diagnostic_id, detector_id, detector_version, rule_id, rule_version, file, line, message, source_blob_oid, source_sha256, byte_start, byte_end))`。
   message、line、source blob 变化产生新 occurrence；这不必产生新的 stable identity。v1/v2 legacy ID 原样保留，不重算。

3. **`relation`（跨 run 对应关系）**
   由 stable identity、occurrence、覆盖和版本兼容证据共同产生。关键关系包括：
   - `persistent_unchanged`：identity 和 occurrence 均相同；
   - `persistent_changed_metadata`：stable identity 相同，但 message/ID/version 等元数据变化；
   - `persistent_moved_or_changed`：stable identity 相同，且 patch-region 明确 mapped；
   - `observation_absent_comparable` / `observation_added_comparable`：仅在两侧覆盖 complete、lineage 兼容时表达“未观察/新观察”；
   - `unknown_identity`、`unknown_identity_ambiguous`、`unknown_version_boundary`、`unknown_not_comparable`：缺字段、partial/failed/unknown、重复 anchor 或版本边界无证据时 fail-closed。
   所有 relation 的 `vulnerability_effect` 固定 `unknown`；观察缺失不能推导 safe、miss、fixed 或漏洞真正消失。

### 1.3 兼容结果

| 场景 | stable identity | occurrence | relation / 结果 |
|---|---|---|---|
| 插入注释 | 不变 | 变（line/byte range/source hash） | `persistent_moved_or_changed`；不是新 finding |
| message 变化 | 不变 | 变 | `persistent_changed_metadata`；`diagnostic_id,message` 变化，legacy ID 保留 alias |
| 表达式移动但 AST fingerprint 不变、patch-region `mapped` | 不变 | 变 | `persistent_moved_or_changed` |
| 同名成员跨 class/namespace | `ns::A::handle` 与 `ns::B::handle` 不同 | 各自保留 | 不合并 |
| duplicate semantic anchor | 多实例同一 stable basis | 各 occurrence 保留 | `unknown_identity_ambiguous`；禁止按 line/ordinal 强制一对一 |
| partial / failed / unknown | 不能生成完整 identity | 不补猜 | `unknown_identity`，不得成为 added/disappeared |
| historical v1 | 不生成伪 stable identity | 仅保留 legacy ID | source binding `unbound/unknown` |
| Detector/rule version | 只有 lineage 兼容才可跨版本对应 | 各版本 observation 保留 | compatible -> `persistent_changed_metadata`；无兼容证据 -> `unknown_version_boundary` |
| observation absence | 不宣称漏洞变化 | 旧 occurrence 保留 | `observation_absent_comparable`，`vulnerability_effect=unknown` |

### 1.4 不能从旧产物重建 stable identity 的限制

现有比较记录缺少 `rule_lineage_id`、AST node/expression fingerprint、Git blob + byte range、patch-region mapping。因此不能从旧 JSON 或 heuristic key 重建 `finding_identity_id`，不能补写推测值。后续只能对新的固定 source blob、parser/normalizer version、rule manifest 和 source range 生成 identity；旧报告、候选 ID、review、fact_id、evidence ID、report hash 均不重写，alias 只能追加。

## 2. A-CCR-04：ReadOnlyFactView 摘要

### 2.1 九个只读语义接口

共同 envelope：`schema_version, change_request_id, method, request_id, status, proof_ref[], analysis_scope, budget, failure_reason, facts, coverage, limitations`，`unknown_reason` 在 `status=unknown` 时必填。所有方法必须带显式 `scope` 与 `budget`：

1. `get_symbol(path, position, scope, budget)`
2. `get_cfg_path(function, source_node, sink_node, scope, budget)`
3. `get_dataflow(source, sink, budget)`
4. `get_guard_proof(node, guard, scope, budget)`
5. `get_lock_state(function, location, scope, budget)`
6. `get_build_context(commit, file, scope, budget)`
7. `get_source_context(path, range, scope, budget)`
8. `get_detector_results(candidate_id, scope, budget)`
9. `get_coverage(detector_id, path, scope, budget)`

能力边界：接口只读既有固定源对象、syntax/coverage/detector records 和有界 semantic provider 输出；不改 IR、runner、catalog、schema v2、历史报告、review 或 EvidenceObligation。AST/pattern match 不能升级为 CFG、type、guard、lock 或漏洞证明。

### 2.2 observed / proven / unknown / failed

| status | 允许内容 | 强制语义 |
|---|---|---|
| `observed` | 绑定 source/evidence 的直接原始记录 | 不等于语义证明 |
| `proven` | 声明 scope 内完整、可复核的语义主张 + witness/certificate | 不外推产品安全 |
| `unknown` | `facts=null`；`unknown_reason{code,message,missing_facts}` | 缺 CFG、identity、alias、guard、lock、build context、partial 或预算耗尽时不得猜测 |
| `failed` | `facts=null`；`failure_reason{code,message,retryable}` | 非法请求、预算、hash mismatch、provider error；不等于不存在、safe 或 miss |

状态优先级：invalid request / illegal budget / integrity mismatch / provider exception -> `failed`；缺输入、partial、unresolved identity、预算耗尽 -> `unknown`；直接绑定记录 -> `observed`；完整可复核语义证明 -> `proven`。

### 2.3 proof_ref、scope、budget、unknown_reason

- `proof_ref` 字段永远存在。`observed` 非空；`proven` 非空且每项 `verified=true`；`unknown/failed` 可为空数组。authority/kind 必须回到 Git object、source blob、detector report、build artifact、analysis output、runtime 或 human evidence，不能只写模型文本或历史 verdict。
- `analysis_scope` 至少绑定 repository、full commit、Git tree、snapshot SHA-256、profile、path/blob/source SHA、functions、detector ID/version、build context ID。scope 不得超出 pinned ScanContext。
- `budget` 必须同时有 `requested / used / exhausted / reason`，上限字段包括 `wall_time_ms, memory_mb, files, source_bytes, call_depth, cfg_nodes, paths, dataflow_steps, macro_rounds`。非法预算为 `failed`；任一预算耗尽为 `unknown(budget_exhausted)` 且 `facts=null`，不得返回半条 path/flow 或截断 source。
- `unknown_reason` 在 `status=unknown` 时必填，至少 `code, message, missing_facts`；预算耗尽固定 `code=budget_exhausted`。`failure_reason` 仅在 `status=failed` 非 null。

### 2.4 partial coverage 与 EvidenceObligation 兼容策略

- `complete/partial/not_analyzed/failed` 与 parse status 分离；partial 文件中的候选和义务独立保留，整体 blocked 不抹掉局部候选。
- `get_coverage` 可以 `observed` 返回 partial 记录；任何跨 partial 范围的 CFG/dataflow/guard/lock claim 除非有完整 proof，否则必须 `unknown`。
- `get_detector_results` 返回 candidate/diagnostic 原貌及 source binding；v1 缺 source hash 标 `unbound/unknown`，不补写、不升级。
- `EvidenceObligation` 是 immutable read-only record；查询不把 `unknown/missing` 改成 `satisfied`，不改变 candidate、review、finding 或 vulnerability 状态。
- proof_ref 必须回到 repository/commit/tree/blob/source/report/detector/rule/profile 或 build artifact；模型文本、第三方 warning、历史 verdict 不能单独作为 proof。

## 3. 需要负责人决定的事项

以下项目均需负责人明确勾选和签名；本材料不代替批准。

### D1. 是否批准公共 schema

- [ ] 批准 `ohscanner.readonly-fact-view-contract-v0` 共同 envelope、四态语义、`proof_ref/scope/budget/failure_reason/unknown_reason` 约束。
- [ ] 批准 A-CCR-03 的可选 additive identity schema / sidecar：`ohscanner.finding-identity.v1`、`ohscanner.finding-occurrence.v1`、`finding_identity_id`、`occurrence_id`、`rule_lineage_id`、`symbol_identity`、`ast_fingerprint`、`source_blob_oid`、byte range、`patch_region`、`identity_status`、`historical_ids`。
- [ ] 有条件批准（条件：________________________________________________）
- [ ] 退回修改

### D2. 是否批准 stable Finding identity

- [ ] 批准 identity / occurrence / relation 三层设计及 collision/unknown 语义。
- [ ] 批准保留现有 v2 `diagnostic_id`，只追加 identity sidecar / optional fields，不重写历史。
- [ ] 批准 duplicate anchor 进入 ambiguity group，禁止 line/message/ordinal 猜配。
- [ ] 有条件批准（条件：________________________________________________）
- [ ] 退回修改

### D3. 公共 provider、IR、runner、catalog 责任归属

建议按公共边界原则由项目负责人统筹并签字确认；A/B 只提供 Detector 侧证据，不直接改公共边界：

| 公共对象 | 建议责任人 | A/B 支持范围 | 负责人确认 |
|---|---|---|---|
| ReadOnlyFactView provider / semantic fact provider | 项目负责人（公共边界 owner） | A 提供 C/C++ rule lineage、symbol/AST/source-range evidence；B 提供 IPC/interface 侧事实 | [ ] 确认 |
| 公共 IR / schema / compatibility tests | 项目负责人 | A/B 提交契约测试和证据，不改公共 IR | [ ] 确认 |
| runner 集成、source binding、budget/coverage 适配 | 项目负责人 | A/B 提供 Detector observation | [ ] 确认 |
| catalog / production registration | 项目负责人 | A/B 提交注册建议和 provenance/license 材料 | [ ] 确认 |

负责人指定其他分配时，请填写：________________________________________________

### D4. 是否允许进入生产注册

- [ ] 暂不允许；保持 proposal / research-only，等 schema、provider、IR、runner、catalog 实现和兼容测试完成后另行申请。
- [ ] 允许进入生产注册（必须同时填写版本、注册 detector/provider ID、测试门和回滚方案）：________________________________________________
- [ ] 有条件允许（条件：________________________________________________）

在 D1-D4 未批准前：不合并 main、不标 PR ready、不写 production registration、不修改公共 contracts/runner/catalog/analysis、不重写历史报告或 review。

## 4. 审批 checklist

### 4.1 已验证

- [x] 实际 checkout、full SHA、tree、remote、dirty/untracked 状态已核对；未把 branch claim 当实现证明。
- [x] 当前 `_diagnostic_id` 公式已从 `src/ohscanner/runner.py` 核对：包含 `source_sha256,file,line,rule_id,message`，并截断为 16 位。
- [x] A-CCR-03 合成 compatibility matrix 9/9：注释、message、移动表达式、同名成员、partial/failed/unknown、historical v1、version boundary、duplicate anchors、observation absence。
- [x] A-CCR-03 真实复扫投影 208 -> 182；182 条只改变 `diagnostic_id,message`；26 条为 heuristic unmatched，不能解释成漏洞消失。
- [x] A-CCR-03 `comparison.json`、artifact manifest、reference model、results 的 SHA-256 与 manifest 记录一致。
- [x] A-CCR-04 `contract.json` 可解析，schema 为 `ohscanner.readonly-fact-view-contract-v0`，方法数为 9，状态枚举为 `observed/proven/unknown/failed`。
- [x] 四个禁止修改的公共文件在核对时 SHA-256 与 CCR 记录一致。
- [x] `git diff --check` 无空白错误；仅报告既有 LF/CRLF warning。
- [x] 当前 catalog 只注册既有 example/C++/IPC detectors；未写入 Stable Finding Identity 或 ReadOnlyFactView production registration。

### 4.2 已有测试

- [x] `research/tests/a_ccr_03_stable_finding_identity/test_stable_finding_identity_compatibility.py`：9 tests；本次用 WSL `.venv-web/bin/python` 实跑 9 passed / 0 failed / 0 skipped。
- [x] `tests/test_a_ccr_04_contract.py`：contract/envelope/status/proof/source binding/partial coverage/EvidenceObligation 测试。
- [x] `tests/test_a_ccr_04_budget.py`：budget validation、exhaustion、invalid/missing/contradictory budget、partial fact suppression 测试。
- [x] A-CCR-04 两模块本次实跑 22 passed / 0 failed / 0 skipped。
- [x] `research/contracts/a_ccr_04/verification.json` 记录过完整 `unittest discover` 619 passed / 8 skipped（该次验证基线为 `38b93d3`，不是本次重新执行结论）。
- [x] 同一 verification 记录说明 clean `git archive` 历史 PoC 测试受 ignored/generated evidence 缺失限制，不能把 archive 的 3 failures / 8 errors 解释成 CCR 契约失败；A-CCR-04 targeted tests 在 clean archive 中通过。

### 4.3 待负责人决定

- [ ] D1 公共 ReadOnlyFactView schema 与 additive identity schema 是否批准。
- [ ] D2 stable Finding identity 三层设计、legacy ID append-only、ambiguous/unknown 语义是否批准。
- [ ] D3 公共 provider、IR、runner、catalog 的最终责任人和 A/B 支持边界。
- [ ] D4 是否允许进入生产注册，以及若允许的版本、测试门和回滚方案。
- [ ] 是否接受本材料中的“旧产物不能重建 stable identity”为不可绕过限制。

### 4.4 尚未实现

- [ ] `src/ohscanner/contracts.py` 中 stable identity / occurrence / relation 公共字段。
- [ ] `src/ohscanner/runner.py` 中 identity 生成、alias 追加、cross-run relation 和 legacy ID 保留。
- [ ] 公共 ReadOnlyFactView provider、semantic IR、CFG/dataflow/guard/lock/build-context provider。
- [ ] runner/catalog 对 ReadOnlyFactView 的公共适配和失败隔离。
- [ ] 生产 detector/provider registration。
- [ ] 旧报告/候选/review/fact/evidence 的 identity 迁移或回填（明确禁止伪造、默认不做）。
- [ ] 以真实 Detector、固定 Git source、生产 build context 的端到端验证。

### 4.5 明确 unknown

- [x] 旧产物缺少 rule lineage、AST fingerprint、Git blob byte range、patch-region mapping，无法重建 `finding_identity_id`。
- [x] AST fingerprint v1 不覆盖宏、模板实例化、跨文件类型、CFG、alias、编译配置；这些仍需独立证据。
- [x] patch-region mapping 只支持可审计对应，不证明漏洞因果、修复或安全。
- [x] `observation_absent_comparable` 的 `vulnerability_effect` 为 `unknown`；0 findings 不证明安全。
- [x] partial/failed/unknown、unresolved identity、预算耗尽都不能变成 safe、miss 或 empty result。
- [x] 本任务未运行真实 Detector、未联网、未攻击生产服务、未计算 Precision/Recall。
- [x] 完整 `unittest discover` 619/8 是历史 verification 记录；本次只重跑 A-CCR-03 9 项和 A-CCR-04 22 项定向测试。

## 5. 负责人签字区

- 决策人：____________________
- 日期：____________________
- D1 结论：____________________
- D2 结论：____________________
- D3 责任分配：____________________
- D4 结论：____________________
- 后续公共实现 issue / PR / commit：____________________
- 备注与限制：________________________________________________
