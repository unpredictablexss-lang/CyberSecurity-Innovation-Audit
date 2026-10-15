# A-CCR-03 Finding Identity implementation / migration / compatibility plan

状态：implementation under separate public CCR；不改 Detector 算法、不推送、不合并、不标 ready。
日期：2026-10-15（Asia/Shanghai）。

## 1. Approval and checkout audit

批准记录先于代码实施写入并提交为 `research/contracts/A-CCR-03-approval.json`：

- 状态 `approved`；批准人 `项目负责人`；日期 `2026-10-15`；时区 `Asia/Shanghai`。
- 批准对象：`research/contracts/A-CCR-03-stable-finding-identity.md`。
- 批准对象 SHA-256：`261a9918f1d220da8218dd19a57545cb2d4b2a041bb119f1fe7d238d3b7d906c`（批准时 untracked）。
- 提案记录的批准 commit：`38b93d30ed4be71af4a8245ed18198d999c3ee18`。
- 批准记录提交：`9583db63b772d35ee6c27aeaf494d30a5726123a`，tree `7f0ec1e8faf7511bf0eeb7740f6acc709919d5ed`。
- 审批准备材料 SHA-256：`053282ff6697029c24b82e9d38af8f8e2fccc797d271d0e6a299486cb110403d`；其历史状态 `awaiting_owner_approval` 未改写。
- 批准记录 SHA-256：`f374081a1828e8d3638d0b87e763c638e8c42bb328c663311f43b839ca7ee0cc`。
- 实施基线分支 `codex/full-runtime-performance-audit-20261014`，远端 `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`；既有 dirty/untracked 文件保留，未 reset、覆盖或删除。

## 2. Public additive contract

新增 `src/ohscanner/identity.py`，并以独立公共变更提交，包含：

- `finding_identity_id`：`ohfi:v1:sha256(canonical_json(schema, repository, rule_lineage_id, symbol_identity, ast_fingerprint))`。
- `occurrence_id`：`ohocc:v1:sha256(canonical_json(schema, repository, legacy_diagnostic_id, detector_id, detector_version, rule_id, rule_version, file, line, message, source_blob_oid, source_sha256, byte_start, byte_end))`。
- relation sidecar：stable identity、occurrence、coverage、显式版本兼容证据联合产生。

稳定身份不进入 message、line、column、byte range、detector version 或 rule version。任一 stable basis 字段缺失，或 `identity_quality` 不是 `complete`，返回 `unknown`，不回退到 `file:line`、message 或 legacy ID。

`src/ohscanner/contracts.py` 的 `DetectorFinding` 新增可选 `rule_version`、`rule_lineage_id`、`symbol_identity`、`ast_fingerprint`、`identity_quality`。这些是 detector 边界的显式输入；本 CCR 不修改任何 detector 实现。`src/benchmark/tool_result.py` 的 `ToolDiagnostic` 新增可选 `finding_identity_id`、`occurrence_id`、`finding_identity`；无 identity 时 `to_dict()` 删除这些键，保持旧 payload 形状。

`src/ohscanner/indexing.py` 在 Git object context 中记录 `source_blob_oid` map；fixture/非 Git 输入没有该绑定时 occurrence 保持 unknown。runner 从固定 SourceUnit 计算 UTF-8 行级半开 byte range，并把 exact observation/source binding 放入 append-only identity record；该 byte range 是观察行范围，不是 AST 语义节点范围。

## 3. Cross-run relation semantics

实现公开以下关系；所有关系的 `vulnerability_effect` 固定为 `unknown`：

| relation | 必要条件 | 禁止解释 |
|---|---|---|
| `persistent_unchanged` | stable identity 与 occurrence 都相同 | 不等于安全或确认 |
| `persistent_changed_metadata` | stable 相同，message/legacy ID/版本等 occurrence 元数据变化 | 不等于修复 |
| `persistent_moved_or_changed` | stable 相同、patch-region `mapped` 且位置/source range 变化 | 不证明漏洞因果 |
| `observation_absent_comparable` | 旧项无新项、两侧 coverage `complete`、lineage/版本显式 compatible | 不等于 disappeared/fix/safe |
| `observation_added_comparable` | 新项无旧项、两侧 coverage `complete`、显式 compatible | 不等于新增漏洞 |
| `unknown_identity` | identity 缺失或 partial/failed/unknown | 不判 absent、safe 或 miss |
| `unknown_identity_ambiguous` | 同一 stable identity 在任一侧多于一个实例 | 禁止按行强制一对一 |
| `unknown_version_boundary` | Detector/rule 版本无可审计兼容声明 | 跨版本关系 unknown |
| `unknown_not_comparable` | coverage 或执行不可比 | 不判 added/disappeared |

重复 anchor 保留各 occurrence 并进入 ambiguity group；disappeared 只能作为旧比较产物的描述字段，不能出现在 relation 解释中。

## 4. v1 / v2 migration and compatibility

1. v1 provider payload 保留原始 `diagnostic_id`、message、report hash；缺 source hash 时 reader 返回 `source_binding=unbound`，不补写 identity。
2. 已存在的 schema v2 payload 没有 identity sidecar 时，reader 返回 `stable/occurrence=unknown`、`backfilled=false`；不根据行号、文件或 Git 当前内容重算。
3. 新 v2 emission 才写 optional identity sidecar；`diagnostic_id` 继续使用既有 runner 公式和值，历史 ID、candidate ID、review、诊断 ID 均 append-only。
4. schema version 仍为既有 v1/v2 读写范围；不创建竞争 scanner，不改变 catalog 注册，不把 identity 生成混入 detector 修复。
5. 迁移只允许未来显式提供完整 lineage/symbol/AST/source binding 的新观察；旧报告默认不迁移。需要跨 revision mapping 时必须另存 patch-region 证据，不能启发式补写。

## 5. Tests and same-scope regression

公开测试：`tests/test_a_ccr_03_finding_identity.py`，覆盖注释插入、message 修改、代码移动、同名成员、partial/failed/unknown、重复 anchor、absent/added、coverage 不可比、version boundary、v1/v2 无回填、ID 篡改检测、legacy payload 形状和稳定身份禁用字段。

同范围复扫输入：

- `outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015/comparison/comparison.json`
  SHA-256 `c7da13895f4ed08abf19eadefdea871c1633bf9a3f15833567034129a69d62e4`。
- `artifact_manifest.json` SHA-256 `483464735cab65c69e54a1cd3c42822d5a8acbc0c9fa88a5d96791af7034c60c`。
- 回归断言：old 208、new 182、added 0、disappeared 26、changed 182、unchanged 0；182 条 changed fields 仅 `diagnostic_id,message`；旧行没有 `finding_identity_id`；`precision_recall=not_computed`，`candidate_decrease_is_not_safety=true`，`version_difference_is_not_fix_or_accuracy=true`。candidate 数量变化不解释为准确率变化。

## 6. Exact implementation hashes at plan time

- `src/ohscanner/contracts.py` `75e5a02170f6e592c28c8a81040de803e326d6b340ca007936f9b7c35a633726`
- `src/ohscanner/runner.py` `fc313f3ddde265b994ffa7ce585bb87c63421249a2afeaa71994d56cdceba7d8`
- `src/ohscanner/identity.py` `8a5303ec0bc5e2e1addeed7185010ede5194510574e02aff8b53ee1acff9421b`
- `src/ohscanner/indexing.py` `3a2d100f8e4999094f8c658a77c44ecc74b6eaa9926aea246e3e044281b9aeb6`
- `src/benchmark/tool_result.py` `24667cb0c7cd013c8e836e2b60bc60d1789898d8dd5367eddee972fb650683ed`
- `tests/test_a_ccr_03_finding_identity.py` `f7ba74c301568cb78b64d1f9692db60e8b9c15a550d18e87481d7e2781456024`

提交后应重新计算并报告完整 SHA-256、commit、tree、测试命令/结果。

## 7. Unknowns and limitations

- 现有复扫 comparison 没有 `rule_lineage_id`、AST fingerprint、Git byte range 或 patch-region mapping，不能从历史产物重建 stable identity；测试因此只验证“无回填”和计数，不伪造 relation。
- 当前注册 detector 尚未提供新增 identity 输入；其新 emission 的 stable/occurrence 通常保持 `unknown`，直到独立 detector CCR 显式提供 lineage、symbol scope、AST fingerprint、rule version。
- fixture/非 Git 输入没有 source blob OID；occurrence/source binding 保持 unbound/unknown。
- AST fingerprint 不覆盖宏、模板实例化、跨文件类型、CFG、alias 或完整编译上下文；这些仍是 unknown。
- `observation_absent_comparable` 不是修复、安全、miss 或漏洞消失；0 findings 不证明安全。
- 本 CCR 不调用真实模型、不联网、不推送、不合并、不标 ready，不计算 Precision/Recall，不改变历史报告/review/candidate ID。