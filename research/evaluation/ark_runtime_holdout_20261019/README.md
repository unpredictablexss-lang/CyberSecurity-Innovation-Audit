# G13-HP real independent holdout input protocol

日期：2026-10-19（Asia/Shanghai）。本目录已冻结真实独立 holdout 的**输入协议**，但没有冻结或执行真实样本，也没有生成真实 truth。开发 fixture、C11/C12 known-case、scanner verdict、模型输出和 parent/fixed 配对均不得作为真值或 reviewer 上下文。

## Frozen protocol

- 协议：`real_holdout_input_protocol.v1.json`
- 文件 SHA-256：`real_holdout_input_protocol.v1.sha256`
- Intake schema：`real_holdout_intake.schema.json`
- Truth schema：`real_holdout_truth.schema.json`
- 泄漏账本：`development_leakage_ledger.local-development-20261019.json`；schema：`development_leakage_ledger.schema.json`；生成脚本：`generate_development_leakage_ledger.py`
- freeze/score 现在绑定泄漏账本文件 SHA-256 与 canonical payload SHA-256，并拒绝开发 case/source hash 重叠。
- 执行管线：`holdout_pipeline.py`

`real_holdout` 输入必须绑定 repo/commit/tree/blob/source SHA/parser/snapshot，并绑定预注册抽样框、家族 split 和开发泄漏账本。任一身份缺失、开发重叠或来源文本泄漏 case id、路径、URL、CVE、issue/PR、scanner rule/verdict 时，freeze fail-closed。

## Double-blind packet boundary

Reviewer packet 只允许伪匿名 ID、去身份源码文本、分类问题、标签枚举和提交要求。禁止包含真实 case id、路径、repo/commit/source hash、parent/fixed 配对、scanner verdict 或模型输出。Reviewer 提交必须包含独立性 attestation、confidence、至少 20 字符 rationale 和非空源码 evidence。

Reviewer A/B 的顺序独立反转，但标签集合一致。分歧必须由第三名独立裁决人处理；裁决人不得见 truth、scanner/model output 或 parent/fixed 配对。unknown 必须保留，不能为了计算指标而强制改判。

## Truth commitment and metric gate

Truth custodian 不参与评审或裁决，secret 只保存在 Git 外。Commitment 使用 `hmac-sha256-custodian-secret-v1`，覆盖 schema、execution mode、truth status、model_generated 和 labels。Score 必须同时校验协议文件哈希、freeze manifest、truth commitment、final labels、完整 case set 和 reviewer/adjudicator attestation。

只有真实独立人工裁决完成、开发重叠为 false、身份完整、分歧裁决闭合且没有 unknown 时，才输出 family-level Precision/Recall/F1。否则 confusion counts 最多作为 non-release diagnostics，Precision/Recall/F1 保持 null。

## Real execution still blocked

当前缺少：

1. 经预注册的独立抽样框和 family split；
2. 覆盖开发 fixture、known-case、benchmark、人工审查源 hash 的完整泄漏账本；
3. 真实无泄漏 case 集及完整 Git/source identity；
4. 两名独立人工评审和一名独立裁决人；
5. 真实 truth custodian commitment 与揭示流程。

因此状态是 `FROZEN_NOT_EXECUTED`。本目录 `selftest*` 只验证机制，truth 明确为 synthetic/self-test，不计算指标。
