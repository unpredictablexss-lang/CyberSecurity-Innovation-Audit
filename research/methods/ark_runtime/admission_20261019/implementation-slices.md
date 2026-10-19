# 后续真实实现与兼容测试切片

本轮只交付协议与切片，不修改公共实现。后续必须逐切片评审、独立提交、运行验证并报告限制；不得把整套变更压成一个混合 diff。

## 切片依赖图

1. RFC/兼容矩阵/验收清单（本轮，完成）
2. S1 纯 identity/value objects 与 canonical hash（公共协议，不改运行行为）
3. S2 admission validator 与 sidecar schema（公共协议，可单测，不接入默认 Runner）
4. S3 Runner opt-in coverage/admission bridge（公共 Runner，保持默认输出）
5. S4 Catalog/capability gate（公共 Catalog，默认关闭）
6. S5 Ark runtime adapter 对接（Detector/算法提交，和 S1-S4 分开）
7. S6 兼容、回归、预算与历史不变性加固（独立测试/修复提交）

S5 只能在 S1-S4 合入并验证后进行。任何算法修复不得倒灌进 S1-S4。

## S1：exact identity 与 canonical value objects

### 交付范围

在公共 contracts 侧增加纯数据/验证能力，或由负责人选择独立 identity 模块：

- `RepositoryIdentity`
- `CommitTreeIdentity`
- `SourceIdentity`
- `BuildProfileIdentity`
- `DependencyIdentity`
- `ExactSnapshotManifest`
- `RegionScope`
- `ParseContamination`
- `DependencyContamination`

实现 canonical JSON/hash、full OID 校验、safe relative path、byte range、symbol identity 和显式 unknown。不得创建 Detector、不改 Catalog、不改 `run_all` 结果。

### 必须测试

- positive/fixed/unknown identity 构造与 canonical hash golden。
- 40/64 位 full OID；缩写、algorithm 混用、大小写错误拒绝。
- path/byte range/symbol identity 的 fixed change 测试。
- build flags/defines/includes/dependency array 顺序稳定性。
- 缺项无法从默认值/旧 ID/message 推导。

### 提交边界

一个公共协议提交，包含上述 value objects、文档注释和兼容测试。不得包含 Runner bridge、Catalog 注册或算法修复。

### 验证

运行 contracts/identity 对应 pytest；运行仓库测试入口中与 contracts/identity 相关的既有测试；执行 `git diff --check`。报告实际命令、通过/失败和限制。

## S2：admission validator 与 sidecar schema

### 交付范围

增加 `admission_record_version=1` 的验证器和序列化：

- 校验 exact identity 联合一致性。
- 校验 `commit -> tree -> blob -> bytes` 的 supplied proof；不自行 fetch/checkout。
- 计算/验证 `snapshot_manifest_sha256`、`build_profile_sha256`、`dependency_closure_sha256`。
- 产生 region `valid/unknown/not_analyzed`。
- 记录 parse/dependency contamination、budget state 和 declared facts。
- 产出 CandidateRecord 引用与 CoverageAggregate，不改变 security state。
- v1 输入永远不升级；v2 无 sidecar 时保持旧语义。

### 必须测试

- 任一 identity 成员冲突 fail closed。
- 完整 profile/dependency closure 才能 valid。
- parse/dependency contamination 只对 declared facts 判定；无法排除即 unknown。
- region valid 可位于 file partial；file outcome 不被修改。
- invalid/mixed/out-of-bounds observation 被拒绝。
- 旧 IDs/reviews/obligations 不重写。

### 提交边界

公共协议/验证器提交，仍不改默认 Runner 行为。schema golden 与兼容测试同提交；算法 fixture 只做输入，不改 Detector。

### 验证

单测 + schema JSON round-trip + legacy/v2 golden 对比。任何 golden 变化必须解释为新增字段而非旧字节重写。

## S3：Runner opt-in admission bridge

### 交付范围

在 `run_all_with_coverage` 增加显式 opt-in 参数或 capability record；未启用时返回值和现有 sidecar 不变。启用时：

- 执行前验证 snapshot manifest、build profile、dependency closure。
- 为 selected units 生成 region records。
- 合并 DetectorRun findings 到 admitted candidates；拒绝 scope/hash 越界。
- 保持 `DetectorRun.status` 为 completed/failed/blocked。
- coverage 输出 `aggregate_state/reasons/counts/retained_candidate_ids/exhaustive_for_scope/safety_inference_allowed=false`。
- valid 局部候选在 mixed/blocked/over-budget 中保留。
- selector/admission 异常只 fail closed 当前 detector。
- `run_all` 仍返回原列表结构。

### 必须测试

- admission disabled byte/shape-compatible golden。
- complete+partial mixed：完整文件候选保留，aggregate=mixed。
- valid+unknown region：valid candidate 保留，unknown 列出。
- over-budget：旧闭合 region 保留，未完成 region 不发布。
- identity mismatch：仅目标 detector blocked/failed closed，其他 detector 仍运行。
- missing required facts 不因 detector ID 放行。
- legacy v1 只读不进入 admission。

### 提交边界

公共 Runner 提交，包含兼容测试。不得修改 Ark runtime 算法、模型、规则或历史 report fixture。

### 验证

运行 Runner/coverage 全套既有测试、新兼容测试和 mixed/budget/identity 回归。对未启用路径做 golden 对比。

## S4：Catalog 与显式 capability gate

### 交付范围

- 默认 detector IDs 保持现状。
- Ark runtime detector 保持 `research_candidate`、default disabled。
- 新增 admission capability 选择，不使用 detector-ID 特判。
- 显式选择 detector 不隐式开启 partial。
- 明确日志/元数据说明 exact-bound、local candidate、no safety inference。
- pending/unknown detector 继续 fail closed。

### 必须测试

- 默认 IDs 不变。
- explicit detector without capability 不准入 partial。
- explicit detector + approved capability 只允许 exact-bound region。
- selector/admission bug 不放开其他 detector。
- example/pending/unknown 注册规则不回退。

### 提交边界

公共 Catalog 提交，独立于 Runner 和算法。若 Catalog 只需暴露 metadata/capability，不导入研究 replay。

### 验证

Catalog resolution/build_registry 测试 + 默认快照 + fail-closed 测试。

## S5：Ark runtime adapter 迁移

### 交付范围

这是 Detector/算法边界提交，不得和 S1-S4 混合：

- 将 C2/C3/C4 的 exact source、model/digest、region、macro/type/signature/summary 约束映射到新 admission record。
- 保持研究 replay 数据只读；不改历史 ID/review。
- partial production path 只有在负责人批准 S1-S4 后显式启用。
- 保留 `required_facts=('ast',)`、`ast_scope='per_file'`，除非有独立负责人协议决定。
- 未知 build profile、依赖污染、同名模型/宏/类型、跨 TU 摘要 mismatch 全部 unknown/not_analyzed。
- 目标 region 候选仍为 `candidate/unassessed`。

### 必须测试

- C2 错误在目标函数/宏/声明/跨文件依赖时 fail closed。
- C3 source/model/summary/blob tamper 拒绝。
- C4 exact upstream snapshots 的 selector/admission 绑定。
- positive/fixed/safe/unrelated/unknown 控制。
- mixed scope 与 over-budget 保留规则。

### 提交边界

Detector/adapter 提交，可再拆 model/data 与算法逻辑；不得改变公共协议 golden。

## S6：兼容、历史与预算加固

### 交付范围

- legacy v1、v2、旧 ID/review/EvidenceObligation 的只读 golden。
- canonical hash 稳定性与跨 Python 版本测试。
- 大 scope 的 batch/region 分片和 aggregate invariance；只测正确性/资源限制行为，不先宣称性能指标。
- 超时/RSS/节点/依赖展开预算的 bounded harness。
- 所有 fail-closed 错误信息包含 identity/region/reason，但不泄漏或推断安全结论。

### 提交边界

测试/稳定性修复独立提交；若发现 Detector 算法问题，另开算法修复提交。

## 每切片交付模板

每个真实实现切片完成后必须在聊天中说明：

1. 实际 checkout、HEAD、branch 和 commits；不自动 push/merge。
2. 修改文件与 dirty worktree 状态。
3. 公共协议与算法修复的提交边界。
4. 实际执行的验证命令、结果和未执行项。
5. positive/fixed/safe/unrelated/unknown 控制覆盖。
6. 兼容风险、失败关闭点和遗留 unknown。
7. 未声明漏洞、CIA、CVE、PoC 或指标结论。
8. 下一切片。

## 当前完成定义

本轮完成定义仅为：

- 五份 RFC/矩阵/验收/切片文件存在；
- JSON 可解析；
- 只改 `research/methods/ark_runtime/admission_20261019/`；
- 未改公共代码/docs/其他目录；
- 未 commit/fetch/checkout/push/merge；
- 未运行外部扫描器或动态验证；
- 最终消息列出产物、关键决定、兼容风险、验证命令和 S1。