# Admission fail-closed 验收清单

状态：待实现测试；勾选只表示对应控制有可重复证据，不表示漏洞、CIA、CVE 或指标结论。任何必选项未满足，partial region 不得为 `valid`，安全状态仍为 `candidate/unassessed` 或 unknown。

## A. 固定输入与提交边界

- [ ] 测试和实现引用固定 checkout/HEAD，不以分支名、提交消息、README 或注释作为实现证明。
- [ ] 公共协议新增/兼容测试是独立提交。
- [ ] Runner/Catalog 接入是独立提交。
- [ ] Detector 算法、模型、规则修复不混入上述提交。
- [ ] 不重写历史 JSON/report hash/candidate ID/diagnostic ID/review/EvidenceObligation。
- [ ] `docs` 保持六份 Markdown；本 RFC 不进入公共 docs。

## B. Exact repository/commit/tree/blob/source identity

### positive

- [ ] 固定 repository name、full commit、tree、blob、source bytes、byte length、snapshot manifest 可重算并一致。
- [ ] 同一输入重复构建得到相同 `source_identity_sha256` 和 `snapshot_manifest_sha256`。
- [ ] v2 finding 引用的 source SHA 与 SourceUnit、blob 字节一致。

### fixed

- [ ] 改 commit、tree、blob、path、source bytes、byte length 或 snapshot member 任一项都产生新 identity。
- [ ] 把旧 finding/candidate 复制到新 identity 被拒绝。
- [ ] 缩写 OID、大小写不一致或错误 algorithm 被拒绝。

### safe

- [ ] identity 完整且局部事实成立时仍只产生 `candidate/unassessed`。
- [ ] 没有 finding 不标 safe/miss；证据门继续保留必要 obligations。

### unrelated

- [ ] unrelated path/tree/blob/finding 不并入目标 region identity。
- [ ] 同文件无关 region 不共享 target region ID。

### unknown

- [ ] repository remote/ownership 缺失时 ownership 为 unknown，不影响已有本地对象核验但不得声明归属。
- [ ] tree/blob/source/snapshot 任一缺失或冲突时 region 不得 valid。
- [ ] 禁止由 file name、line、message、旧 ID 或 profile 推导缺失 identity。

## C. Build profile 与 dependency hash

### positive

- [ ] toolchain/target/language standard/flags/defines/includes/generated sources/dependency closure 全部 canonical 且 hash 可重算。
- [ ] 相同完整 profile 和依赖闭包得到相同 `build_profile_sha256`。

### fixed

- [ ] 改一个 flag、define、include root、compiler target、generated source、dependency blob 或摘要 OID 都改变 profile/closure hash。
- [ ] `profile_id=light-ast` 相同但构建参数不同不会复用 admission。

### safe

- [ ] build identity 完整仍不产生安全结论。
- [ ] 产品 build-profile 假设未验证时不得借用 fixture profile 升级。

### unrelated

- [ ] unrelated dependency 不进入目标 closure；无关 file/region 不因共享 include 被合并成同一 finding。
- [ ] 同名 model type/alias/creator 不得替换已绑定 dependency identity。

### unknown

- [ ] 缺 toolchain/flags/defines/includes/generated source/dependency OID 时 fail closed。
- [ ] 未解析 include、宏、overload、type/base/signature、跨 TU 摘要或生成边时相关 facts 为 unknown。
- [ ] 可写引用、指针、未审查构造或宏重定义无法排除污染时不得 valid。

## D. Region scope、parse 与 dependency contamination

### positive

- [ ] symbol 身份含限定命名空间、类、函数和完整参数类型。
- [ ] byte half-open range、line/column、AST fingerprint 和 parser identity/config 可重算。
- [ ] declared facts 与 region/dependency IDs 一一可追踪。
- [ ] 目标 region 的 parse/dependency contamination 对 declared facts 均为 `uncontaminated_for_declared_fact_set`。

### fixed

- [ ] 目标函数 body、参数、返回类型、symbol identity 或 byte range 改变时 region ID 改变。
- [ ] parser/config/AST fingerprint 改变时不复用旧 region。
- [ ] 目标函数内部 ERROR、未知宿主分支、lambda、宏条件或未知生成图控制使相关 region 非 valid。

### safe

- [ ] “函数子树无 ERROR”不升级为翻译单元 complete。
- [ ] region valid 不改变文件 `partial` 或总体安全状态。
- [ ] AST/pattern 不被解释为 ownership、dominance、并发、attacker control 或 CIA impact。

### unrelated

- [ ] 远离 region 的 unrelated parse error 只污染实际相关 facts；不得无依据删除有效完整文件候选。
- [ ] 无关 rule/model/source region 不共享 candidate ID。

### unknown

- [ ] 无法排除错误节点、宏、include、声明、overload 或跨 TU 污染时保持 unknown。
- [ ] `uncontaminated_for_declared_fact_set` 不输出为“全局无污染”。
- [ ] not_run/failed/partial parser 状态不能重写为 complete。

## E. valid/unknown/not_analyzed、partial/mixed/over-budget

### positive

- [ ] exact identity、scope、facts、dependencies 和 closed budget 全部满足时 region 为 valid。
- [ ] valid region 的局部 candidate 和 obligations 在 detector aggregate blocked 时仍可见。
- [ ] 文件状态与 region 状态独立输出。

### fixed

- [ ] complete 文件候选在 mixed scope 中保持原 source-bound identity。
- [ ] partial 文件不计入 complete；未检查 region 不计为 miss。
- [ ] fixed source/region/rule/model change 后候选 ID 不复用。

### safe

- [ ] partial/mixed/over-budget/unknown/not_analyzed/failed 均带 no-safety-inference 语义。
- [ ] `complete` aggregate 只覆盖声明 scope，不表示产品安全。
- [ ] `exhaustive_for_scope=true` 不等于 exhaustive product analysis。

### unrelated

- [ ] mixed 文件/检测器保持逐文件、逐 region 独立计数。
- [ ] 一个 detector 的 selector/admission 失败不删除另一个 detector 的有效结果。

### unknown

- [ ] 缺项、冲突、无效或越界 evidence 拒绝升级。
- [ ] 未执行分析使用 not_analyzed；信息不足使用 unknown，两者不互换。
- [ ] failed run 前未闭合 region 不保留为 valid。

### over-budget

- [ ] budget manifest 在执行前声明并绑定 run。
- [ ] 超预算时未完成 observation 不发布。
- [ ] 此前已闭合 region 的候选保留，未闭合 region 为 unknown/not_analyzed。
- [ ] aggregate 为 partial 或 mixed，reason 含 `over_budget`。
- [ ] `exhaustive_for_scope=false`；不发布截断的“完整候选集合”。

## F. 兼容控制矩阵

- [ ] **positive**：现有 source-bound v2 fixture 在未启用 admission 时输出不变。
- [ ] **fixed**：tampered source/blob/build/region/rule/model identity 全部 fail closed。
- [ ] **safe**：safe-like fixture 仍为 `candidate/unassessed` 或无 finding，不输出 safe/miss。
- [ ] **unrelated**：unrelated file/finding/dependency 不污染目标，也不丢失自己的记录。
- [ ] **unknown**：所有缺失/冲突状态显式输出，不能默认 complete/valid。

## G. schema 与历史兼容

- [ ] legacy v1 只读测试通过，字节/hash 不变。
- [ ] v2 现有字段和 `run_all(context, registry)` 返回结构不变。
- [ ] `run_all_with_coverage` 默认行为与启用 admission 前一致。
- [ ] 新 admission sidecar 只追加稳定引用，不重算旧 diagnostic/candidate ID。
- [ ] 旧 review 仍绑定原 ID/source；新 identity 产生新记录和 append-only mapping。
- [ ] EvidenceObligation 原 kind/description/status 不改写；admission 不伪造 satisfied。
- [ ] Catalog 默认 detector IDs 不变；Ark runtime 仍 default disabled/research candidate。
- [ ] 显式 detector 选择不隐式授予 partial admission capability。
- [ ] required_facts 缺失仍 blocked；禁止 detector-ID 特判绕过。
- [ ] selector/admission 异常只 fail closed 当前 detector，不中止其他 detector。

## H. 建议兼容测试切片

### contracts

- [ ] `test_exact_identity_missing_or_conflicting_member_fails_closed`
- [ ] `test_build_profile_same_label_different_flags_has_different_hash`
- [ ] `test_dependency_closure_missing_macro_include_or_overload_is_unknown`
- [ ] `test_region_symbol_byte_ast_identity_rejects_fixed_change`
- [ ] `test_parse_dependency_contamination_is_fact_scoped_not_global_complete`

### runner

- [ ] `test_v2_admission_disabled_output_shape_unchanged`
- [ ] `test_valid_local_candidate_survives_blocked_and_mixed_scope`
- [ ] `test_partial_file_never_claims_complete_analysis`
- [ ] `test_over_budget_keeps_closed_regions_and_rejects_unfinished_region`
- [ ] `test_identity_mismatch_fails_only_target_detector_closed`
- [ ] `test_aggregate_mixed_never_allows_safety_inference`

### catalog

- [ ] `test_default_detector_ids_unchanged`
- [ ] `test_explicit_detector_selection_does_not_enable_partial_admission`
- [ ] `test_unknown_or_pending_detector_admission_fails_closed`

### history

- [ ] `test_legacy_v1_fixture_bytes_and_hash_unchanged`
- [ ] `test_old_ids_reviews_and_evidence_obligations_not_rewritten`
- [ ] `test_new_identity_uses_append_only_stable_mapping`

## I. 本轮文档验证

- [ ] `Get-Content -Raw research/methods/ark_runtime/admission_20261019/compatibility-matrix.json | ConvertFrom-Json` 成功（无 Python 依赖）。
- [ ] 五份交付物存在且只位于 `research/methods/ark_runtime/admission_20261019/`。
- [ ] `git diff --check` 无 whitespace error。
- [ ] `git status --short --untracked-files=all` 中本线五份文件均只在目标目录；其他并行/teammate dirty paths 必须原样保留，不计为本线修改，也不得清理。
- [ ] 文档未声称漏洞、CIA、CVE、PoC、影响版本、修复有效性、precision/recall、FP/FN 或性能指标。
- [ ] 不执行 fetch/checkout/push/merge、外部扫描器或动态验证。