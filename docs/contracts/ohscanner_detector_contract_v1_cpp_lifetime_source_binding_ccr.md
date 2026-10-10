# Contract Change Request: source-hash-bound detector findings

- 状态：`proposed / not implemented`
- 适用接口：`src/ohscanner/contracts.py` 的 M0 `DetectorFinding` / `DetectorRun`
  及 `src/benchmark/tool_result.py` 的 `ToolDiagnostic`
- 关联 detector：`ohscanner.cpp.lifetime` `0.1.0-proposed`
- 接口基线：PR #5 head `108494bfe392ae62394ea82cd44d28cc03ebb163`
- 处理原则：本文件只提出变更，不修改公共 contracts，也不把 proposed 字段写成已实现 API。

## 1. 问题

当前 `SourceUnit` 已绑定 `path/language/text/sha256/parse_status/parse_issues`，
但 `DetectorFinding` 只有 `file/line/column/rule_id/message/evidence_type` 等字段；
规范化后的 `ToolDiagnostic` 也没有 `source_sha256`。因此公共 finding identity
只能由文件、行、规则和消息计算，无法在 schema 层证明该 finding 对应哪一版源码。

这不满足证据评审要求中的“finding 必须绑定真实文件、行号、rule_id、
evidence_type 和 source hash”。源文件在扫描后被修改时，旧 finding 仍可能与
新路径/行号看起来相同。

## 2. 当前安全 workaround

本分支新增 detector 专用本地 review sidecar：

- `src/ohscanner/detectors/cpp/lifetime_review.py`
- `tests/detectors/test_cpp_lifetime_review_evidence.py`

sidecar 为每个 candidate 记录：

- `file/line/column`
- `rule_id/evidence_type/symbol/message`
- 对应 `SourceUnit.sha256`
- 由上述字段计算的 `finding_binding_id`
- request repository/commit/revision/target/profile/provenance/snapshot
- tool id/version、analyzed scope 和 fixture manifest SHA-256

sidecar 明确保持 `assessment=candidate`、`review_status=unassessed`，并拒绝
stale source hash、混合 vulnerable/fixed/unrelated/safe/unknown 证据组及被篡改的
finding binding。它不是公共 API，也不替代 Git object verification。

## 3. 请求的接口能力

优先方案：在 `DetectorFinding` 增加必填 `source_sha256`，并原样映射到
`ToolDiagnostic.source_sha256`。Runner 在构造 diagnostic 前验证：

1. `finding.file` 必须存在于 selected units；
2. `finding.source_sha256 == SourceUnit.sha256`；
3. line/column 必须落在该 source text；
4. diagnostic identity 必须包含 `source_sha256`，源码版本变化后不得复用旧 ID。

兼容方案：增加不可变 `source_binding_id`，由公共 evidence registry 将该 ID
解析到 `(repository, commit, path, blob/source sha256)`。无论采用哪一方案，
`ToolRunResult.parsing` 或独立 normalized evidence 都必须能回查同一 source hash。

## 4. 状态语义必须同步固定

接口变更不得改变现有语义：

- `completed` 只表示 selected scope 已执行，不是 safe；
- `partial/failed/blocked/not_run` 表示未知或覆盖不足，不是 miss；
- unsupported language 可记录 `not_applicable`，但不是 miss；
- empty findings 不是安全证明；
- rule hit、syntax shape、symbol overlap 只能是 `candidate/unassessed`；
- source hash 只证明文本绑定，不证明 parse、reachability、impact 或 runtime validation。

## 5. 需要的回归测试

- finding source hash 与 `SourceUnit.sha256` 一致时可规范化；
- stale/mismatched source hash 必须拒绝；
- 修改源码后 diagnostic identity 必须变化；
- line/column 越界必须拒绝；
- `completed/blocked/failed/not_run/not_applicable` 映射保持现状；
- safe/fixed/vulnerable/unrelated evidence group 不得静默合并；
- 旧无 hash payload 的迁移策略必须显式标记 `unknown/unbound`，不得伪造 hash。

## 6. 不在本请求范围

不请求 CFG、污点、类型系统、runtime trigger、漏洞状态提升、Precision/Recall，
也不请求在 M0 中实现 Git commit/tree 证明。真实 Git provenance 仍由后续
M1+ 能力按 `PROGRAM_STATUS.md` 的实际实现状态描述。
