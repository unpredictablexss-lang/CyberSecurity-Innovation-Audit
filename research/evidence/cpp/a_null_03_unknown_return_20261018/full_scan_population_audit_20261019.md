# NULL 全扫描数量身份核验（2026-10-19）

## 结论

只对本地可复核的 final run 作出计数结论：NULL detector 原始观察 **403,360 行**，唯一 diagnostic ID **403,359 个**，有 **1 行重复 ID**。该重复 ID 的两行都指向 `openharmony/ability_ability_base`、同一 commit、同一规则及 `test/unittest/want/want_test.cpp:1097`；两行引用同一个 `result.json`，该文件中该 diagnostic ID 仅出现一次。CSV 与 compact summary 的 CWE/detector 小计为原始行数 403,360；`检测器能力.csv` 的 `candidate_count` 为 403,359，与唯一 ID 数一致。任务描述中的 **546,559** 没有对应的 run signature、scanner commit、manifest 或输入 CSV；两者不能作为同一总体，也不能将 143,199 的算术差视为已解释差额。报告面板间的一行差已定位到重复 diagnostic ID，不解释 546,559 与本地 run 的总体差异。

本地 run identity：

- Run signature：`1696df82f39e2564e0821c0ad2e837a00c6d83f9276bf5e0c38a3bd1f511700b`
- Scanner commit：`0d9357ea22224b72c9756864dbd14b71a4723924`
- Manifest SHA-256：`52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55`
- Scope：报告 manifest 中 525 个项目均已处理；报告注明“807 个库”不能由该 manifest 证实。

## 复核内容

标准库脚本流式读取固定 `candidate_results.csv`，按 `detector=ohscanner.cpp.null_dereference` 统计原始行、rule ID 与 diagnostic ID；同时检查 `run_config.json`、报告 `compact-summary.json`、`checksums.json` 和检测器汇总 CSV 的身份/计数一致性。CSV 共 416,577 行；目标 NULL 行与 compact summary 的 CWE/detector 小计一致为 403,360；唯一 ID 数 403,359 与 `检测器能力.csv` 的 `candidate_count` 一致。脚本还核对重复 ID 的 CSV 行和被引用结果 JSON：重复 CSV 行只对应一个 JSON diagnostic。所有核验条件通过。

此项核验只证明固定扫描工件间的数量和 run 身份一致，不确认候选是真实漏洞，不重放检测器，也不绑定 546,559 对应的那轮运行。

## 输出形状与盲审 pilot（2026-10-19）

对同一固定 CSV 的 detector message 做分层前置统计：NULL 来源中 `parameter_may_be_null` 为 280,127（69.45%），`function_return_value_unknown_nullability` 为 63,637（15.78%），smart-pointer unknown 为 27,354（6.78%）；sink 以 member dereference 266,381、method dereference 67,962、subscript 37,100、unary dereference 28,135 为主。guard 为 none 377,514、not-dominating 14,347、unknown 11,499；输出状态 partial 365,109、analyzed 38,251。这些是 detector 输出形状，不能当作真/假阳性标签，也表明高数量不只来自 unknown-return；参数来源占多数，不能据此自动降权。

基于 `null_source × sink × repository selected_source_files quartile` 构建 160 条分层盲审 pilot，覆盖 108 个非空 strata；抽样单位是 CSV 原始行，保留唯一重复 ID 的其中一行作为可独立追溯的行。抽中 160/160 的源码 SHA-256 与诊断记录匹配，CSV 与 result JSON 的仓库、提交、规则、文件及行号字段 160/160 一致。人工审阅仍为 0/160，状态 pending；该 pilot 只针对上述 403,360 行的 provisional run，不代表未绑定的 546,559 总体。

Pilot manifest：`real_candidate_pilot_20261019_verified/sampling_manifest.json`，SHA-256 `3bc204a84227df8b5c6f6ee0afa473ae9cbfdcea74bb721f83ec40c035f87229`。盲审队列位于 `real_candidate_pilot_20261019_verified/reviewer/blind_review_queue.csv`，SHA-256 `14ac157d5fa3421853841fa6c10d42d818ce23c6b953e62ac3278013591c63fd`；标签定义见 `reviewer/review_protocol.md`。冻结后由 `research/tests/a_null_03_unknown_return/merge_null_candidate_review.py` 校验样本完整性、证据字段不变、标签和解盲 key 一一对应，再将合并结果写入 coordinator 子目录。解盲映射在标签冻结前不得交给审阅者。原始全扫描审计 JSON SHA-256：`2a3e9f0bf869e56f5bd2dfd97890cabbc839c18826e8edd1aaef43f9b7de6aa2`。

注意：同级 `real_candidate_pilot_20261019/` 是脚本修正前的初步产物，manifest 的 CSV/result 元数据交叉核对数为 0；它已被 `_verified/` 产物取代，不得用于盲审或报告。只使用本节明确列出的 `_verified/` 队列和 manifest。

## 可重放

从仓库根目录运行：

```powershell
python research/tests/a_null_03_unknown_return/audit_full_scan_population.py --output research/evidence/cpp/a_null_03_unknown_return_20261018/full_scan_population_audit_20261019.json
```

审计脚本使用 Python 标准库，可通过 `--scan-root`、`--report-root` 和 `--reported-count` 指定其他输入。冻结 JSON 结果的 SHA-256：`3c5ffbd8c1caeee8e3617d48ad983c9830f476dca83040f853b36878baacea8e`。
