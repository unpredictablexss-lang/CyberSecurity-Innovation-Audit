# exact snapshot/build-profile/source identity 与 partial AST evidence admission RFC

日期：2026-10-19
状态：待负责人审批；不授予生产 partial 默认准入、漏洞确认、合入或发布权限。
范围：为后续独立的公共 contracts/Runner/Catalog 协议变更提供可执行定义；本轮不改实现。

## 1. 目标与非目标

### 1.1 目标

1. 为第一方 source-bound schema v2 结果补齐可审计的 exact repository/commit/tree/blob/source identity。
2. 明确 build profile、工具链、编译参数与依赖闭包的 identity 和 hash。
3. 定义函数/区域级 AST scope，以及 parse contamination、dependency contamination、valid/unknown/not_analyzed 的准入语义。
4. 定义 partial、mixed、over-budget 的局部候选保留、文件覆盖和聚合状态。
5. 保持 legacy v1 只读，保持旧 diagnostic/candidate ID、review、EvidenceObligation 字节与语义不重写。
6. 给出 positive/fixed/safe/unrelated/unknown 兼容控制和 fail-closed 验收，作为后续兼容测试输入。

### 1.2 非目标

- 不证明漏洞、真实入口、权限边界、可达敏感操作、触发条件、ownership、dominance、并发、attacker control 或 CIA impact。
- 不产生 CVE/CWE 确认，不计算或声称 precision、recall、FP/FN、零漏报、性能提升或其他指标。
- 不允许 AST/pattern/局部符号路径替代产品级证据。
- 不把 `light-ast`、函数无 ERROR 或局部候选升级为翻译单元完整、构建完整或依赖无污染。
- 不设计 PoC、不运行动态验证、不攻击服务、不运行外部扫描器。
- 不改变任何 Detector 算法；公共协议变更与算法修复必须分开提交。

## 2. 当前契约缺口

| 能力 | 当前实际行为 | 缺口 | RFC 处理 |
|---|---|---|---|
| repository | `ScanRequest.repository` 是声明的 `<namespace>/<name>` | 无 remote/ownership 证明 | 绑定声明身份；remote 可选且 ownership 始终 unknown |
| commit | `ScanRequest.commit` 要求 full 40/64 hex（Git 输入） | 只有 request 级 commit | 每条 admission 同时携带 full commit OID |
| tree/blob | `shared_facts["source_blob_oid"]` 可进入 identity observation | 无 tree；blob 缺项可为 null | v2 admission 必须显式完整或记 unknown，并阻止升级 |
| source hash | `SourceUnit.sha256`、finding `source_sha256` 已校验 | 有 source hash，但缺 identity 联合验证 | 作为 exact source tuple 的必选成员 |
| snapshot | `snapshot_digest(units)` 与 `ScanRequest.snapshot_sha256` 一致 | digest 未表达 path/blob/build/dependency manifest | 增加 exact snapshot manifest hash；保留现有 digest |
| build profile | `profile_id`，Git 输入要求 `light-ast` | 单字符串不能表达 toolchain/flags/defines/includes | 增加不可折叠的 BuildProfileIdentity 与 canonical hash |
| dependency identity | `ScanContext.shared_facts` 是开放 mapping | 无统一 dependency closure/hash | 增加逐依赖 OID/hash/role 与 closure hash |
| region scope | finding 有 line、可选 symbol/AST fingerprint | 无统一 byte region 与事实范围 | 增加 RegionScope 与 admitted fact set |
| contamination | `parse_status/issues`，finding obligations | parse 和依赖污染未结构化 | 增加独立 contamination records |
| file outcome | `complete/partial/not_analyzed/failed` | 只到文件级 | 保留文件状态并增加 region status |
| mixed/budget | Runner 有 blocked、partial、skipped | 无显式 mixed/over-budget 聚合语义 | 与执行 status 分离，增加 coverage aggregate |
| 局部候选 | blocked run 可保留 finding/obligation | partial region 的准入条件不统一 | 仅 valid region 的局部候选可保留，仍为 candidate/unassessed |

## 3. 规范性术语

- **exact**：所有规定字段存在、类型正确、canonical serialization 稳定、hash/OID 可重算，且相互一致。不是“看起来相同”或“缩写匹配”。
- **unknown**：信息缺失、冲突、不可验证或无法排除相关污染。unknown 不是 safe、miss、complete 或 not_analyzed。
- **not_analyzed**：该范围没有执行分析。它可以与同一次运行中的 valid 局部范围并存。
- **valid**：仅表示一个局部范围通过本 RFC 的 identity、parse、dependency、budget 准入，可保留有限事实和 `candidate/unassessed` 候选；不表示安全或漏洞结论。
- **partial**：覆盖深度或解析/分析完整度，不是独立安全真值。
- **mixed**：同一次报告同时存在不同区域/文件的 valid、unknown、not_analyzed 或 failed 状态，或 complete 与 partial 文件混合。
- **over-budget**：达到文件/字节/节点/时间/内存/调用深度等已声明预算，未闭合范围被拒绝准入；不是安全状态。

## 4. Exact identity 协议

### 4.1 通用规则

1. OID 必须是 full Git object ID：40 位 SHA-1 或 64 位 SHA-256，并带 `oid_algorithm`；禁止缩写。
2. SHA-256 值必须是 64 位小写十六进制。
3. 路径必须是 canonical relative POSIX path，复用 `safe_relative_path` 语义。
4. 所有 canonical hash 都基于 UTF-8、key 按 Unicode code point 排序的 JSON object；数组保持声明顺序；禁止浮点；null 只能表示显式 unknown。
5. unknown 值不得由 message、line、symbol name、旧 ID、文件名或默认 profile 推导。
6. 任何 identity 成员变化都产生新的 admission identity；禁止复用旧 candidate/diagnostic ID 字节。

### 4.2 RepositoryIdentity

必选：

- `repository_name`：现有 `<namespace>/<name>` 形式。
- `repository_identity_quality`：`exact` 或 `unknown`。
- `ownership`：固定为 `unknown`，除非另有独立、可审计的 owner 证明协议；本 RFC 不提供该证明。

可选：

- `remote_origin_normalized`：本地 remote 的规范化 URL。
- `remote_identity_sha256`：规范化 remote 字符串的 SHA-256。

仅配置 remote 不证明 ownership。repository 名、remote 或工作目录不匹配时拒绝 admission，不自动换仓。

### 4.3 CommitTreeIdentity

必选：

- `repository`：完整 RepositoryIdentity 引用。
- `commit_oid`：full commit OID。
- `commit_oid_algorithm`：`sha1` 或 `sha256`。
- `tree_oid`：该 commit 下实际 scope 根或文件所属 tree OID，必须 full。
- `tree_path`：tree 相对路径；根为 `.`。
- `snapshot_manifest_sha256`：见 4.5。
- `provenance`：`git_object`。
- `verification`：逐项 `verified/unknown/failed`。

`commit -> tree -> blob -> source bytes` 必须在本地 pinned Git objects 中逐级核验。缺级为 unknown 并 fail closed。禁止 fetch、checkout 或隐式解析其他 revision。

### 4.4 SourceIdentity

每个 admitted region 必须绑定一个 SourceIdentity：

- `file`
- `blob_oid` + `blob_oid_algorithm`
- `source_sha256`：精确文件字节的 SHA-256
- `commit_oid` + `tree_oid`
- `byte_length`
- `language`
- `parser_identity`：实现/版本/构建配置或代码 blob OID
- `source_identity_sha256`：上述 canonical record 的 SHA-256

`source_sha256` 必须可由 blob 字节重算；`SourceUnit.text` 也必须匹配。任何一项不一致时，region 为 unknown/not_analyzed，已有候选不得从旧报告复制到新 identity。

### 4.5 ExactSnapshotManifest

snapshot manifest 按 `file` 排序，每项至少包含：

- `file`
- `blob_oid`
- `source_sha256`
- `byte_length`
- `language`
- `tree_oid`
- `commit_oid`

`snapshot_manifest_sha256` 是该完整数组 canonical JSON 的 SHA-256。它补充而非替换当前 `ScanRequest.snapshot_sha256`。scope 必须显式列全，不能以“目录大概相同”代替。混合 tree/commit 的产品版本必须分别绑定，禁止套用一个 product commit。

## 5. Build profile 与 dependency identity

### 5.1 BuildProfileIdentity

必选：

- `profile_id`：例如 `light-ast`，仅作稳定标签。
- `profile_schema_version`
- `language_standard`
- `compiler_identity`：family、version、target triple、binary/source identity；缺项记 unknown。
- `flags`：有序、去 shell 的原始参数数组。
- `defines`：规范化 name/value 列表。
- `include_roots`：有序 canonical path 与 identity 引用。
- `generated_sources`：生成文件的 blob/source identity；无则空数组，未知则 unknown。
- `dependency_closure_sha256`
- `build_profile_sha256`

`build_profile_sha256` 覆盖所有上述字段，不只 hash `profile_id`。相同 `profile_id` 但 flags/defines/includes/toolchain 不同必须视为不同 profile。产品构建身份未验证时记 unknown，不借用研究 fixture profile。

### 5.2 DependencyIdentity 与 contamination

每项 dependency 至少包含：

- `dependency_id`
- `role`：`include/type/base/signature/macro/generated/build_flag/summary/other`
- `resolved_path` 或 `external_identity`
- `blob_oid`/`source_sha256` 或 `content_sha256`
- `resolution_status`：`verified/unknown/failed`
- `used_by_region_ids`
- `affects_fact_ids`

依赖闭包必须覆盖实际 admitted facts 所引用的：

1. 类型、基类、别名和成员声明；
2. 被调用符号签名及 overload 集；
3. 宏定义、展开与重定义；
4. include、生成源和跨 TU 摘要；
5. 编译 flags、defines、target 和模板/内建模型。

摘要必须绑定实际 blob OID、签名和 build profile。缺失、同名歧义、可写引用/指针、未审查构造、宏重定义、错误 include/TU 或未知生成边均使相关 facts 为 unknown。

## 6. Region scope

### 6.1 RegionScope

必选：

- `region_id`：由 source identity、symbol identity、byte range、rule/model identity 派生的新稳定 ID。
- `source_identity_sha256`
- `symbol_identity`：限定命名空间、类、函数、完整参数类型；禁止仅同名。
- `byte_start`/`byte_end`：精确 UTF-8 byte half-open interval `[start,end)`。
- `line_start`/`line_end`、可选 column：派生定位，不参与唯一性回退。
- `ast_fingerprint`：绑定 parser identity/config 的子树 token/结构 fingerprint。
- `declared_fact_ids`：本次允许使用的有限程序事实。
- `dependency_ids`
- `parse_state`：`valid/unknown/not_analyzed`
- `dependency_state`：`valid/unknown/not_analyzed`
- `budget_state`：`closed/over_budget/not_run`
- `admission_state`：`valid/unknown/not_analyzed`

范围可以是完整函数、显式 statement/block 或其他可重算 AST 区间。目标函数内部 ERROR、未知宿主分支、lambda、宏条件、未知生成图控制或 byte/AST fingerprint 不一致时，相关 region 不得 valid。

### 6.2 parse contamination

`ParseContamination`：

- `state`：`uncontaminated_for_declared_fact_set/known/unknown/not_analyzed`
- `error_node_ids`
- `affected_fact_ids`
- `affected_region_ids`
- `reason`

`uncontaminated_for_declared_fact_set` 只表示错误与缺失未触及本次声明事实所需 token/子树/依赖；绝不等于文件或翻译单元完整。无法证明“错误远离目标就不影响依赖”时必须为 unknown。

### 6.3 dependency contamination

`DependencyContamination`：

- `state`：`uncontaminated_for_declared_fact_set/known/unknown/not_analyzed`
- `affected_dependency_ids`
- `affected_fact_ids`
- `reason`

只有完整列出相关依赖并逐项验证 exact identity/build profile，且不存在未解析宏、include、overload、alias、跨 TU 或生成图污染时，才可对声明事实使用 `uncontaminated_for_declared_fact_set`。这仍不证明全局无污染。

## 7. 状态模型

### 7.1 三个正交轴

1. **执行 status**：`completed/blocked/failed`；保持现有 DetectorRun 语义。
2. **覆盖深度**：region `valid/unknown/not_analyzed`，文件 `complete/partial/not_analyzed/failed`。
3. **安全结论**：固定 `candidate/unassessed` 或 EvidenceObligation 的 `unknown/missing/satisfied/not_applicable`；本准入协议不授予 confirmed/reportable。

partial、mixed、over-budget、unknown、failed、not_analyzed 都不是 safe 或 miss。

### 7.2 Region admission 决策

region 只有同时满足以下条件才是 `valid`：

1. exact repository/commit/tree/blob/source identity 全部 verified；
2. exact snapshot manifest 匹配；
3. build profile 与 dependency closure hash 全部 verified；
4. region byte/AST/symbol identity 可重算；
5. parse contamination 对 `declared_fact_ids` 为 `uncontaminated_for_declared_fact_set`；
6. dependency contamination 对 `declared_fact_ids` 为 `uncontaminated_for_declared_fact_set`；
7. 预算已闭合，且不是 `over_budget`；
8. Detector 实际执行并产生可审计 observation。

任一条件缺失或冲突，region 为 `unknown`。没有执行分析则为 `not_analyzed`。`failed` 是 file/run 执行结果，不覆盖 region truth；失败前已完整闭合的独立 region 可以保留，未闭合 region 必须 unknown/not_analyzed。

### 7.3 partial

- 文件 `partial`：文件整体存在 parse/analysis 缺口。
- region `valid` 可以位于文件 `partial` 中，但必须明确列出 valid、unknown、not_analyzed region。
- 禁止从“目标函数无 ERROR”推导文件 complete。
- region 级 valid 不改变 SourceUnit.parse_status，也不改变 file_outcomes。

### 7.4 mixed

当报告含多个文件或 region，且 admission/coverage 状态不同，coverage aggregate 必须为 `mixed`。典型情形：

- complete 文件候选 + partial 文件；
- valid region + unknown region；
- 已闭合函数 + 未分析函数；
- 一个 detector 适用而另一个 not_applicable。

mixed 不丢弃已通过门的局部证据，也不把局部分析量转换为整文件/组件安全证明。

### 7.5 over-budget

预算必须先声明并绑定到 run manifest：文件数、总字节、blob 字节、AST 节点、region 数、wall time、RSS、递归/调用深度、依赖展开数等。

达到预算时：

1. 当前未完成 observation 不发布；
2. 未闭合 region 标记 `over_budget`，admission 为 unknown 或 not_analyzed；
3. 此前已独立闭合的 region/candidate/obligation 可以保留；
4. aggregate 标记 `partial` 或 `mixed`，并带 `over_budget` reason；
5. 不发布“完整扫描结果”，不把剩余 scope 记 safe/miss；
6. 部分候选集合必须标 `exhaustive_for_scope=false`。

## 8. 局部候选保留与聚合

### 8.1 CandidateRecord

局部候选必须绑定：

- 新 `candidate_id` 与 `occurrence_id`，不复用旧 ID；
- schema version；
- repository/commit/tree/blob/source/snapshot identity；
- build_profile_sha256 与 dependency_closure_sha256；
- region_id、symbol_identity、ast_fingerprint、byte/line range；
- detector ID/version、model version、rule ID/version/lineage；
- `declared_fact_ids` 与 dependency IDs；
- parse/dependency contamination record；
- `admission_state=valid`；
- `security_state=candidate/unassessed`；
- EvidenceObligations；
- `exhaustive_for_scope` 与 budget manifest；
- `limitations`。

候选只表达有限事实形成的局部观察。不得添加或暗示已验证 consequence、CIA、CVE、真实入口或产品影响。

### 8.2 保留规则

- valid region 的候选可在 detector run `blocked` 时保留。
- 同一 run 的 unknown/not_analyzed region 不删除 valid region 的候选。
- mixed/over-budget 不清空已闭合候选。
- identity、rule/model、scope 或 dependency closure 改变时，旧候选不能复制；只能作为只读历史记录。
- 无效、越界、混合 identity 或依赖污染明确触及 facts 的 observation 必须拒绝，不得保留为 valid。
- 没有达到 valid 的局部观察不得进入 source-bound v2 admitted candidate 集；可以留在明确标记的研究附件中，状态为 unknown。

### 8.3 聚合状态

增加独立 `coverage.aggregate_state`，不要改写 `DetectorRun.status`：

- `complete`：声明 scope 的所有 region 均 valid 且预算闭合。
- `partial`：存在已检查但未完整闭合的 region，且没有可区分的 complete/valid 混合；附 reason。
- `mixed`：valid、unknown、not_analyzed、failed、complete、partial 或多个文件状态并存。
- `not_analyzed`：声明 scope 全部未分析。
- `unknown`：存在身份/依赖冲突，无法可靠分类。
- `failed`：执行失败且没有可保留的已闭合 region。

同时输出：

- `aggregate_state`
- `reasons`：`parse_partial/dependency_unknown/over_budget/identity_mismatch/mixed_files/...`
- `region_counts`：valid/unknown/not_analyzed
- `file_counts`：complete/partial/not_analyzed/failed
- `retained_candidate_ids`
- `exhaustive_for_scope`
- `safety_inference_allowed=false`

聚合层必须保证有效局部候选和义务不因整体 blocked 消失。

## 9. source-bound schema v2 与 legacy v1

### 9.1 v2 附加而非重写

建议新增独立 `admission_record` sidecar，并在 v2 finding identity/coverage obligation 中追加稳定引用：

- `admission_record_id`
- `source_identity_sha256`
- `snapshot_manifest_sha256`
- `build_profile_sha256`
- `dependency_closure_sha256`
- `region_id`
- `region_admission_state`
- `aggregate_state`

不修改历史 JSON 字节、report hash、diagnostic/candidate ID、review、EvidenceObligation 内容或状态历史。需要稳定映射时追加新 ID/映射表，不伪造旧 ID。

### 9.2 legacy v1

legacy v1 只读兼容：

- 不把 v1 外部结果提升为 source-bound admission；
- 不从 v1 message/line/rule 推导 blob/tree/build/dependency identity；
- 不重写 v1 ToolDiagnostic/ToolRunResult；
- 不把 v1 的 partial/unknown 解释为 safe 或 miss。

## 10. 建议逻辑结构

以下结构是协议草案，不是本轮公共代码修改：

- `SourceIdentity`
- `RepositoryIdentity`
- `CommitTreeIdentity`
- `BuildProfileIdentity`
- `DependencyIdentity`
- `ExactSnapshotManifest`
- `RegionScope`
- `ParseContamination`
- `DependencyContamination`
- `RegionAdmission`
- `CandidateRecord`
- `CoverageAggregate`

字段缺失、未知和不一致必须在构造/验证边界拒绝升级。开放 `shared_facts` 不能被 Detector ID 特判绕过 `required_facts`；partial capability 必须是显式、审计过的编排能力，不是注册某个 detector 的隐含效果。

## 11. 兼容性原则

1. 公共契约/协议变更独立提交，只增加可选 sidecar/新版本读取能力并带兼容测试。
2. Runner/Catalog 接入是第二个提交切片；仍可单独回滚。
3. Detector 算法修复、模型/规则更新、研究 replay 修复均不得混入上述提交。
4. `run_all(context, registry)` 返回结构保持不变。
5. `run_all_with_coverage` 在未显式启用 admission 时保持现有行为。
6. 默认 Catalog 不启用 partial admission；显式选择也不等于漏洞确认。
7. 旧 ID、review、EvidenceObligation 和历史报告只读。
8. 任何新增能力在验证失败时 fail closed，并保留 unknown/not_analyzed 与已验证局部证据。

## 12. 结论

本 RFC 将 partial AST 准入限制为“exact identity + exact build/dependency closure + bounded region + contamination-controlled facts + closed budget”的局部证据门。它允许保留 valid region 的 `candidate/unassessed` 观察，同时诚实表达 partial/mixed/over-budget/unknown。它不提供漏洞、CIA、CVE、影响版本、PoC、修复有效性或性能指标证明。