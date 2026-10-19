# C13 HOLDOUT-PRODUCT-GATE minimal sustainable slice

日期：2026-10-19（Asia/Shanghai）
分支：`codex/c13-holdout-product-gate-20261019`
基线：`842948084660207fd64399cfd598ed93e5593dcc`

## 已完成

- 真实 holdout 输入/真值协议保持 `FROZEN_NOT_EXECUTED`，协议文件 SHA-256 为 `cb85cfbfe05a6a6e32197783670b427a8bedd38acf48508fbd826542199ef89c`。
- 补齐 development leakage ledger 实例、schema 和确定性生成脚本；本地开发根目录共登记 72 个排除 case ID、120 个排除 artifact。该账本只证明已列本地开发 artifact 的排除关系，不证明外部零泄漏。
- freeze/score 绑定 development leakage ledger 文件 SHA-256 与 canonical payload SHA-256；case ID/source SHA 与开发账本重叠会被拒绝。
- 双人独立提交要求独立性 attestation、confidence、rationale、evidence；分歧进入第三裁决。任一 reviewer 为 `unknown` 时裁决必须保持 `unknown`，不能升级。
- product evidence gate 使用 `candidate/unassessed`、`not-applicable` 与 `confirmed/reportable` 的显式边界；本次 `promoted_to_confirmed_reportable=[]`。
- 16 个 Ark parent/fix 产品候选均保持 `candidate/unassessed`、`NOT_ADMITTED`；入口、权限、触发、敏感操作、CIA、PoC、修复产品重验缺项保持 unknown/not-run。

## Exact tests

```text
python -m unittest -v research.evaluation.ark_runtime_holdout_20261019.test_holdout_pipeline
```

结果：7 tests，`OK`。覆盖协议哈希/语义、schema 契约、development leakage 绑定、开发重叠拒绝、双人分歧和 unknown 保留、product evidence gate 不升级。

```text
python -m unittest -v tests.detectors.ark_runtime.test_c12_deep_semantics tests.detectors.ark_runtime.test_c11_alias_cross_helper tests.detectors.test_known_case_corpus
```

结果：31 tests，`OK`。覆盖既有 C12 helper/effect/numeric/loop、C11 alias/cast/helper 控制，以及 28-way known-case positive/fixed/safe/unrelated/unknown 控制。

## Schema and generators

- `development_leakage_ledger.schema.json` 对生成实例校验：`PASS`。
- `product_evidence_gate.schema.json` 对生成门审计校验：`PASS`。
- `generate_c13_product_gate.py`：28 条 disposition、16 条 Ark 产品候选，生成成功。
- `generate_development_leakage_ledger.py`：72 个排除 case ID、120 个排除 artifact，生成成功。
- `holdout_pipeline.py self-test`：3 cases、2 agreements、1 disagreement、第三裁决，`PASS`。
- synthetic score：`NOT_RUN`，exit 3；Precision/Recall/F1 均为 null。
- JSON parse、`git diff --check`、self-test secret ignore check 均通过。

完整输出见 `C13_validation_raw.txt`，摘要见 `C13_validation.txt`。

## Blocked / unknown

1. 真实 holdout 未执行：缺预注册 sampling frame、family split、真实无泄漏样本、真实 custodian secret 和 reliable independent human adjudicated truth。
2. 双盲流程目前只有 pipeline self-test，不能当作两名真实独立人工 reviewer/一名独立 adjudicator 的执行证据。
3. 产品 build/source identity 未闭合：缺 exact product manifest/version/branch、binary/source mapping、GN target、args.gn、compile database、include closure、preprocessed TU 和 product toolchain identity。
4. 产品适用性未闭合：16 个候选均缺真实入口、权限/信任边界、攻击者触发、可达敏感操作和具体 CIA 影响。
5. PoC/fix revalidation 均 `NOT_RUN`；静态 fixture、Python 子进程和组件 harness 不是产品 PoC 沙箱。
6. 未计算独立 Precision/Recall/FP/FN，未声称零误报/漏报。
7. 未运行产品动态验证，未标记 Draft Ready，未 merge，未 push。

产品准入保持 `BLOCKED / NOT_ADMITTED`。
