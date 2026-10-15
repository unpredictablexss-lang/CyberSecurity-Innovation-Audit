# A-CCR-03：Stable Finding Identity 公共变更提案

状态：Proposal / compatibility tests and experiment only。本文档不构成公共实现变更、生产注册或合并授权。

## 1. 目标与边界

本提案针对 A 线同一固定范围复扫中出现的 diagnostic ID 变化和 `disappeared/changed` 误读风险，提出分层的 Finding identity。目标是让同一语义 finding 在注释、message、行号和兼容 Detector 版本变化后仍可对应，同时不伪造历史身份、不把扫描观察差异推导成漏洞修复或安全结论。

### 本次 checkout 身份

- branch：`codex/full-runtime-performance-audit-20261014`（仅作定位，不作为实现证明）
- HEAD：`38b93d30ed4be71af4a8245ed18198d999c3ee18`
- HEAD tree：`5be00bf65cd330e7a0309567a51be3a67c066c8c`
- remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`
- 工作树存在既有 dirty/untracked 证据和队友文件；本次不覆盖、不回退、不把 branch 名称当作实现证明。

### 明确禁止修改的公共边界

| 路径 | 本任务状态 |
|---|---|
| `src/ohscanner/contracts.py` | 只读；SHA-256 `6FEC225967A191F32C9238AA34952511BF248EA6FBC93346BBF309DBC5EFB9CE` |
| `src/ohscanner/analysis.py` | 当前 checkout 中该精确路径不存在；不创建、不替换 |
| `src/ohscanner/runner.py` | 只读；SHA-256 `8E4C85E3B8992879F7C9EFFCF139377F426410A3D3373BE274DCE8CADEE8C7C5` |
| `src/ohscanner/catalog.py` | 当前 checkout 中该精确路径不存在；不创建、不替换 |
| `src/ohscanner/detectors/catalog.py` | 当前实际 Catalog 入口；只读；SHA-256 `F680959BC8F977114519C20308BDE07E7AA841156CE2A341F47BC2332AF8FC0E` |
| `src/ohscanner/detectors/interface/analysis.py` | 当前实际 analysis 模块；只读；SHA-256 `AE42F130D91D4FE6168C5571C52EAFB84C3781618780FC1520868B500602677F` |

本任务只产出 CCR、研究测试草案和实验结果；不创建 production registration，不修改公共 contracts/runner/catalog/analysis，不合并 main。

## 2. 现状与问题

### 2.1 当前 v2 diagnostic ID

当前 `src/ohscanner/runner.py:40-43` 的第一方 v2 生成方式是：

```text
diagnostic_id = detector_id + ":" +
  sha256(source_sha256 | file | line | rule_id | message)[:16]
```

它适合作为一次输出中的 occurrence key，但不是跨源码修订的稳定 Finding identity：

- 注释插入会改变 `source_sha256`、行号和 byte range，导致 ID 改变。
- message 改写会直接改变 ID；Detector 说明文字不应决定 finding 身份。
- 同一源码位置在 Detector 版本升级后，若 message 或版本边界变化，当前 ID 不能表达“同一语义 finding 的新观察”。
- 16 位截断哈希是输出 key 的碰撞风险；重复 finding 在同一 run 中会被拒绝，不能把重复语义锚点强行配对。
- `file:line:rule_id` 也不能区分同名成员跨 class/namespace，更不能证明移动后的表达式是同一节点。

### 2.2 已有同范围复扫数据

输入证据：`outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/comparison/comparison.json`，SHA-256 `c7da13895f4ed08abf19eadefdea871c1633bf9a3f15833567034129a69d62e4`。

固定 commit/tree/逐文件 scope/snapshot/profile 均不变；`shared_ptr` 0.4.0 -> 0.5.0，`lifetime` 0.3.0 -> 0.4.0。当前比较结果为：

| 指标 | 数值 |
|---|---:|
| old | 208 |
| new | 182 |
| added | 0 |
| disappeared | 26 |
| changed | 182 |
| unchanged | 0 |
| changed fields | `diagnostic_id,message` 182 条 |
| historical ID rows observed | 208 |

这 182 条对应关系在现有启发式 key `component|provider|rule_id|file|line|column|symbol|source_sha256` 下保持不变，但 v2 diagnostic ID 因 message 增补而全部改变。26 条 `disappeared` 只表示旧启发式 key 在新 run 中未匹配，不表示漏洞消失、修复或安全。

现有比较记录没有 `rule_lineage_id`、AST node/expression fingerprint、Git blob + byte range 或 patch-region mapping，因此不能从旧产物直接重建本提案的 `finding_identity_id`。该缺口是本次实验的明确限制，不应补写推测值。

## 3. 提案模型：identity、occurrence、relation 三层

保留现有 `diagnostic_id`，新增身份层，禁止把 legacy ID 重新计算或覆盖。

### 3.1 `finding_identity_id`：语义稳定身份

```text
stable_basis = canonical_json({
  "schema": "ohscanner.finding-identity.v1",
  "repository": repository,
  "rule_lineage_id": rule_lineage_id,
  "symbol_identity": symbol_identity,
  "ast_fingerprint": ast_fingerprint
})
finding_identity_id = "ohfi:v1:" + sha256(stable_basis)
```

设计取舍：

- **不包含** message、line、column、byte range、detector version、rule version。这些是观察元数据或漂移维度。
- **包含** repository、规则 lineage、完整 symbol scope、AST/expression fingerprint，以区分同名成员并支持移动代码。
- 不以 `rule_id` 的显示字符串作为跨版本 lineage；rule 改名必须有显式 `rule_lineage_id`/alias 映射。
- 若同一 run 中多个 finding 得到同一 `finding_identity_id`，不强行按行号配对。该组标为 `ambiguous`，保留各 occurrence，关系只能是集合级或 unknown。

### 3.2 `occurrence_id`：精确观察身份

```text
occurrence_basis = canonical_json({
  "schema": "ohscanner.finding-occurrence.v1",
  "repository", "legacy_diagnostic_id", "detector_id", "detector_version",
  "rule_id", "rule_version", "file", "line", "message",
  "source_blob_oid", "source_sha256", "byte_start", "byte_end"
})
occurrence_id = "ohocc:v1:" + sha256(occurrence_basis)
```

它精确保留某次 detector 输出、源码 blob 和 byte range。message、line、source blob 变化应产生新的 occurrence，而不必产生新的 finding identity。

### 3.3 `relation`：跨 run 对应关系

关系由 identity 和证据状态共同产生，不能从 ID 相等直接推导漏洞状态：

| relation | 产生条件 | 含义 |
|---|---|---|
| `persistent_unchanged` | stable identity 和 occurrence 均相同 | 同一观察 |
| `persistent_changed_metadata` | stable identity 相同，message/ID/version 等元数据改变 | 同一语义 finding 的新观察 |
| `persistent_moved_or_changed` | stable identity 相同，patch-region 明确 mapped，位置/byte range 改变 | 移动或局部变化后对应 |
| `observation_absent_comparable` | 旧项无新项；两侧覆盖 complete；rule lineage 兼容 | 新 run 未观察到该候选 |
| `observation_added_comparable` | 新项无旧项；两侧覆盖 complete；rule lineage 兼容 | 新 run 观察到新候选 |
| `unknown_identity` | identity 字段缺失、partial/failed/unknown | 不配对、不判消失 |
| `unknown_identity_ambiguous` | 同一 stable identity 在单侧多于一个实例 | 集合对应，禁止强制一对一 |
| `unknown_version_boundary` | Detector/rule 版本没有可审计兼容声明 | 跨版本关系 unknown |
| `unknown_not_comparable` | 覆盖或执行不可比 | 不判 added/disappeared |

所有 relation 的 `vulnerability_effect` 固定为 `unknown`。`observation_absent_comparable` 不是 safe、miss、fixed 或漏洞真正消失；只有独立证据门才可能支持安全/修复判断。

## 4. Identity 字段定义

| 字段 | 生成方式 | 稳定性 | 冲突处理 | unknown 情况 | 向后兼容 |
|---|---|---|---|---|---|
| `legacy_diagnostic_id` | 原样保存 v1 provider ID 或当前 v2 `diagnostic_id` | 历史不可变 | 同一历史 ID 只保留原对象；不重算 | 缺失则 `unknown`，不得用新 ID 代替 | v1/v2 均只读保留 |
| `finding_identity_id` | 上述 canonical stable basis 的 SHA-256 | 注释、message、行号、byte range 漂移不变 | 同 basis 多实例标 `ambiguous`，不按 line 硬配 | 任一 basis 字段缺失或 identity quality 非 complete 即 `unknown` | v2 可选字段；缺失不拒绝旧报告 |
| `occurrence_id` | source blob、byte range、detector/rule version、message、location 的 canonical SHA-256 | 只对同一精确观察稳定 | 同 occurrence ID 重复时保留原始重复并拒绝合并 | source blob/range 缺失时 `unknown` | v1 无 source range 时只保留 legacy ID |
| `repository` | 登记仓库全名；Git provenance 由固定对象验证 | 同仓库跨版本稳定 | 仓库不一致禁止匹配 | 未登记或 user-declared-only 记 provenance unknown | v1 可读但不补写 |
| `rule_id` | Detector 当前输出的显示 rule ID | 同 rule lineage 内可随版本改变 | rule ID rename 需 alias；同 ID 语义变化需版本断开 | 缺失为 unknown | 原字段不变 |
| `rule_version` | rule catalog/manifest 的显式版本 | 版本升级可追踪 | 不同版本不能默认等价 | 无 manifest 为 unknown | v1 可空 |
| `rule_lineage_id` | 规则所有者显式分配的语义 lineage；不得从 message 推断 | 只在声明兼容的 rule 版本间稳定 | lineage 不同即不匹配 | 缺失即 unknown | 新增字段；旧记录不回填 |
| `detector_id` | 现有 `Detector.detector_id` | 同 Detector 家族稳定 | 不同 Detector 默认不合并 | 缺失为 unknown | 原字段不变 |
| `detector_version` | 现有 `Detector.version` | 记录观察来源，不作为 stable key | 版本变化需 rule compatibility 证据 | 缺失为 unknown | 原字段不变 |
| `model_version` | Detector/adapter 显式模型或规则模型版本 | 记录 provenance | 不进入 stable key | 无模型时 `null/unknown` | v1 可空 |
| `symbol_identity` | AST 解析出的 `language + fully-qualified scope + member + signature fingerprint + anonymous-scope ID` | 注释、行号、文件移动后可稳定 | `A::f` 与 `B::f` 必须不同；同名同 scope 重复仍 ambiguous | partial/failed parse、未解析签名或宏展开不完整为 unknown | 可作为 v2 sidecar；v1 不补写 |
| `function_identity` | symbol_identity 中的 enclosing callable：language、qualified function/member、signature fingerprint；成员字段同时记录 enclosing function | 函数移动、注释插入后可稳定；重命名/签名变化需显式 alias/新 identity | 同名函数跨 namespace/class 不合并；同签名重复实例仍 ambiguous | 无 enclosing function、partial/failed parse 或签名未解析为 unknown | 可选 v2 sidecar；不替换 legacy symbol/display 字段 |
| `ast_fingerprint` | 固定 parser/normalizer 版本生成 node kind + normalized expression/subtree hash；剥离注释、空白、行列位置，保留 v1 的标识符拼写、操作符和 literal | 表达式移动可稳定；算法版本固定 | 同一 fingerprint 多实例进入 ambiguity group | parse partial/failed、unsupported language、parser version 不兼容为 unknown | 新增字段，算法版本必须绑定 |
| `source_blob_oid` | 从固定 Git object 读取 blob SHA-1 | 同 blob 精确稳定 | blob 不同即 occurrence 不同 | 非 Git/v1 为 unknown | v2 侧带；v1 不伪造 |
| `source_sha256` | 从 blob bytes 计算 SHA-256 | 同 bytes 精确稳定 | 与 blob/range 不一致即拒绝 | 未提供保持 `unbound` | v1 保持 unbound |
| `byte_start`,`byte_end` | 固定 blob 的半开 byte range `[start,end)` | 同 occurrence 精确稳定 | range 重叠/越界拒绝 | 无 range 为 unknown | 新增字段 |
| `file`,`line`,`column` | Detector 当前显示位置 | 仅显示和检索稳定 | 不作为 stable identity tie-breaker | line 越界拒绝；column 可空 | v1/v2 原字段不变 |
| `patch_region` | 显式 patch hunk/移动映射：base/new blob、range、方法、状态 `exact/mapped/ambiguous/removed/unknown` | 只作为跨 revision relation 证据 | 多映射为 ambiguous，禁止选“最像” | 无 patch 或启发式不足为 unknown | 可选 sidecar；缺失不阻断 legacy |
| `identity_status` | `stable/ambiguous/unknown` | 由字段质量决定 | ambiguous 不合并 | partial/failed/unexecuted 一律 unknown | v2 新增；缺失按 unknown |
| `historical_ids` | 追加保存所有 v1/v2 ID alias | append-only | alias 冲突保留冲突证据，不覆盖 | 空列表合法 | 历史 ID、report hash、review 不改写 |

## 5. v1 / schema v2 兼容策略

1. **v1 外部工具结果**：保留 provider 的原始 `diagnostic_id`、原始 message、原始 report hash。缺 source SHA 时 `source_binding=unbound`，不得根据行号或文件内容补写 verified source identity。
2. **当前 schema v2**：保留现有 `diagnostic_id` 算法和值；建议增加可选 `finding_identity` sidecar 或可选字段 `identity_schema_version`、`finding_identity_id`、`occurrence_id`、`rule_lineage_id`、`symbol_identity`、`function_identity`、`ast_fingerprint`、`source_blob_oid`、`byte_start`、`byte_end`、`patch_region`、`identity_status`、`historical_ids`。旧 v2 payload 缺字段时按 `unknown` 读取，不报损坏。
3. **不重写历史**：不回写历史 report、candidate ID、review、fact_id 或 evidence ID。新增 alias 关系只能追加。
4. **schema 变更独立提交**：契约测试、兼容性测试先独立提交，检测器算法修复不得混入该提交。
5. **算法版本化**：`fingerprint_algorithm`、parser/normalizer 版本进入 provenance；算法改变必须产生新 identity namespace 或显式映射，不静默改变旧 ID。

## 6. Compatibility tests 草案

文件：`research/tests/a_ccr_03_stable_finding_identity/test_stable_finding_identity_compatibility.py`

覆盖项：

- 插入注释：stable identity 不变，occurrence ID/line/byte range 改变。
- 修改 message：stable identity 不变，legacy diagnostic ID 保留 alias，changed fields 为 `diagnostic_id,message`。
- 移动代码但保持表达式：symbol identity + AST fingerprint 不变，patch-region mapped 后 relation 为 `persistent_moved_or_changed`。
- 同名成员跨 class/namespace：`ns::A::handle` 与 `ns::B::handle` 不合并。
- partial / failed / unknown：关系为 `unknown_identity`，不得成为 disappeared/added。
- historical ID 保留：v1 `semgrep:historical-42` 原样保留，source binding 为 `unbound`，不生成伪 stable identity。
- Detector/rule 版本：compatible lineage 允许 `persistent_changed_metadata`，无 lineage 证据时为 `unknown_version_boundary`。
- duplicate semantic anchors：同 stable identity 多实例为 `unknown_identity_ambiguous`，不强制一对一。
- observation absence：只得到 `observation_absent_comparable`，`vulnerability_effect=unknown`。

执行命令：

```text
wsl.exe -e bash -lc "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest discover -s research/tests/a_ccr_03_stable_finding_identity -v"
```

结果：9 tests executed，9 passed，0 failed，0 skipped。该测试针对研究 reference model，不导入或修改 `src/ohscanner` 公共实现。

## 7. 实验结果

目录：`research/experiments/cpp/a_ccr_03_stable_finding_identity_20261015/`

- `results.json`：机器可读结果。
- `results.md`：人类可读摘要。
- `manifest.json`：输入/输出 SHA-256。
- `identity_reference.py`：仅研究 reference model。
- `run_experiment.py`：研究实验入口。

合成兼容矩阵 9/9 通过；包括注释、message、移动表达式、同名成员、partial/failed/unknown、historical v1、Detector/rule version、duplicate anchors、observation absence。

真实固定范围复扫投影：

- old 208 -> new 182；
- added 0、disappeared 26、changed 182、unchanged 0；
- 182 条全部只改变 `diagnostic_id,message`；
- 26 条只在旧启发式稳定 key 下 unmatched，不能解释成真实消失；
- 旧比较缺少 proposed identity 所需的 rule lineage、AST fingerprint、Git blob byte range、patch-region mapping，因此不能用旧产物伪造新 identity。

## 8. 验收与后续实施顺序

1. 负责人先审阅本 CCR 的字段语义、collision/unknown 语义和 v1/v2 兼容矩阵。
2. 公共 contracts/runner/catalog/analysis 由负责人单独实现；A 线只提供 Detector 侧 `rule_lineage_id`、symbol/AST evidence 和 source range 生成能力。
3. 先提交协议兼容测试，再提交可选 sidecar 读写；旧 report/ID/review 保持 append-only。
4. 用固定 source blob、parser/normalizer version、Detector/rule manifest 生成 identity；partial/failed/unknown fail-closed。
5. 对 duplicate/ambiguous 使用集合关系和人工复核，不用 line、message 或 ordinal 猜配。
6. 只有在真实入口/权限边界、可达敏感操作、触发条件和 CIA impact 证据门满足后，才讨论 vulnerability promotion；identity 关系本身永不升级漏洞状态。

## 9. 限制

- AST fingerprint v1 只保证声明的规范化范围；宏、模板实例化、跨文件类型、CFG、alias 和编译配置仍需独立证据。
- patch-region mapping 是可审计对应证据，不是漏洞因果或修复证明。
- 本任务未运行真实 Detector、未联网、未攻击生产服务、未计算 Precision/Recall。
- 本次没有修改公共 contracts、runner、catalog 或 analysis，也没有 production registration 或 main 合并。



