# A0 候选后续分诊队列（2026-10-19 核验）

本目录保留 A0 的 345 个候选原始 ID、source key、原始状态和逐条记录，并提供按最小补证动作排序的 JSON/CSV 队列。分诊不改变 A0 的结论，也不把 `not_testable` 当误报、把 `not_reproduced` 当安全。

## 核验结果

核验脚本只读原工作树 `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit` 中的 A0 包：

```powershell
python research\deliveries\cpp\a0_triage_20261019\verify_triage.py
```

2026-10-19 核验结果：A0 哈希清单中的 97 个文件、4,364,747 字节全部存在且 SHA-256/大小匹配；候选评审 345 条、队列 345 行、345 个唯一 ID；repo/commit/tree/blob/source SHA/Detector/rule/status/profile 来源键无差异；原始状态为 `not_reproduced=9`、`not_testable=336`。全量检查结果写入 `reconciliation_20261019.json`。直接输入文件的 SHA-256 和长度见 `input_identity_20261019.json`。

这项包内核验不等于 345 份上游仓库源码当前仍可 checkout。候选的 commit/tree/blob/source SHA 是从 A0 的 provenance 原样继承；未取得或未验证的上游对象仍需按队列中的 `minimum_next_evidence_action` 补齐。不得将 provenance 字段当作本轮重新读取了每份源码。

## 优先队列

| 顺序 | 原始记录 | 条数 | 最小下一步 |
|---|---|---:|---|
| 1 | CR-0219–CR-0226，samgr IPC 导出 | 8 | 对照原始 request/run_meta 与同 commit 源码，完成 8 个导出点的 transaction、调用者权限、输入及 FD/敏感操作矩阵；先证明外部可达再建目标 harness。共用同一源码家族，按一次边界分诊处理，不算 8 个独立缺陷。 |
| 2 | CR-0335，Wi‑Fi copy-range | 1 | 把 reduced model 的输入/长度约束映射到同 commit 的真实 IPC stub 与目标 buffer，并取得目标构建配置后再重放。模型控制不等于目标复现。 |
| 3 | CR-0016–CR-0018，DataShare 授权/FD capability | 3 | 取得同 commit IPC 注册、调用端和访问控制策略，追踪授权 guard、FD 创建及 reply 传输；确认外部主体可达后才做授权对照。 |
| 4 | CR-0336，Wi‑Fi remote-object capability | 1 | 追踪 remote object 的创建、owner、访问控制、导出、接收端敏感操作，再决定是否能做双主体对照。 |
| 5 | CR-0342，HUKS async shared_ptr | 1 | 梳理 `cancelled_` 全部读写、回调/任务生命周期、锁或原子及线程模型；只在证实存在未同步并发路径后建立目标 TSan harness。 |

除上述 9 条 `not_reproduced` 和 5 条首批高风险可行动 `not_testable` 外，其余 331 条 `not_testable` 保留在队列中，等候候选自身的入口、权限、线程/同步、目标构建或解析证据。具体 owner、dependency、阻塞类别、边界敏感度、证据完整度、补证成本、可重放性、priority rationale 都逐条保存在 JSON/CSV。评分只用于队列排序，不表示漏洞严重性或置信度。

## 解析与泄漏限制

- 56 条候选文件记录为 detector coverage partial（其中 9 条 `not_reproduced`、47 条 `not_testable`）；这是 detector model coverage，不应改写成语法 parser 失败或安全结论。
- 家族审计包含 345 条记录。重复 family key 聚合验证安排，但不合并/丢弃原 ID；source/commit 二级碰撞索引不完整的家族泄漏标为 `unknown`，不宣称独立 holdout。
- 队列状态为排序和后续工作状态，不是 A0 判定。状态变更需追加新证据、来源哈希、环境、执行记录和独立复核；缺证继续 `BLOCK/PARTIAL`。
- 样本只覆盖固定 seed 20261018 的 30 份报告；不能外推到 378 份报告总体，也不据此计算 Precision/Recall。
