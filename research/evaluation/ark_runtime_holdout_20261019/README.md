# Ark Runtime independent holdout pipeline

日期：2026-10-19（Asia/Shanghai）。本目录只实现并自测独立 holdout 的冻结、双盲评审锁和分歧裁决机制。没有把开发控制、C11 known-case corpus 或 D48 便利抽样当独立真值，没有计算 Precision/Recall。

## 当前状态

- 管线实现：`holdout_pipeline.py`。
- 机制自测：PASS；3 个纯合成 case，2 个一致、1 个分歧，第三评审完成。
- 真实独立 holdout：`NOT RUN`。缺少独立抽样框、无泄漏样本、两名独立人工评审和一名分歧裁决人。
- 真实标签：`BLOCKED`。任何模型输出、开发 fixture、scanner verdict 或历史 review 都不是真值。
- Precision/Recall：未计算；自测 truth 明确为 `pipeline_self_test_not_reliable`，score 命令返回 `NOT_RUN`。

## 双盲与隔离职责

1. 数据保管人执行 freeze，持有 secret，不参与评审或裁决。
2. Reviewer A/B 只收到去路径、去 case id、去 parent/fixed 配对、去 scanner verdict 的源码文本和伪匿名 ID。
3. 两名评审独立提交 `vulnerable_shape / not_vulnerable_shape / unknown`、理由和源码证据位置。
4. lock-review 对 packet hash、case set、标签枚举和理由完整性 fail-closed。
5. 一致项接受；不一致项生成匿名第三评审包，由独立裁决人给出决定。
6. 只有 truth custodian 声明 `reliable_independent_human_adjudicated` 且 `model_generated=false` 后，score 才允许输出 TP/FP/FN/TN/unknown。

## 可复现命令

```powershell
$python = "C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$root = "E:\网安\CyberSecurity-Innovation-Audit-c12-product-admission-20261019"
$script = "$root\research\evaluation\ark_runtime_holdout_20261019\holdout_pipeline.py"
$work = "$root\research\evaluation\ark_runtime_holdout_20261019\selftest"
& $python $script self-test --work-dir $work
& $python $script score --truth "$work\truth.json" --final-labels "$work\frozen\final_labels.json" --secret-file "$work\selftest-secret.txt" --output "$work\score-attempt.json"
```

self-test 退出码为 0；score 对非可靠 truth 返回退出码 3 和 `NOT_RUN`。

## 真实 holdout 最小补救

1. 预注册抽样框、家族拆分规则、排除规则、样本量和分歧裁决规则，冻结后再看标签。
2. 从开发规则、fixture、known-case、benchmark 和人工审查使用过的 source hash 中建立泄漏账本并去重。
3. 每个 case 绑定 repo/commit/tree/blob/source hash/parser/config/toolchain。
4. 两名独立人工评审和一名独立裁决人均不得查看 truth、对方意见、scanner 输出或 parent/fixed 配对。
5. 保留 unknown；只有可靠标签完成后计算 family-level confusion matrix，不声称零 FP/FN。