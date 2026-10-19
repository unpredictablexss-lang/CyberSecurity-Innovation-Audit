# G13-HP parallel vibe coding prompts

以下提示词用于 C13 后续并行切片。每条线只处理一个机制，不跨写范围，不把模型意见当真值。

## HP-A 独立抽样与泄漏账本

```text
ROLE: C13-HOLDOUT-DATA-CUSTODIAN
INPUTS:
- real_holdout_input_protocol.v1.json
- real_holdout_intake.schema.json
- development_leakage_ledger.schema.json
- pinned local Git objects only
TASK:
1. 预注册 sampling frame、family split、排除规则和 sample size，先生成 commitment。
2. 汇总开发 fixture、known-case、benchmark、人工审查使用过的 source hash，生成开发泄漏账本。
3. 从冻结抽样框选择无重叠 case，绑定 repo/commit/tree/blob/source SHA/parser/snapshot。
CONSTRAINTS:
- 禁止 fetch/checkout/commit/push；禁止读取 scanner/model/parent-fixed 作为标签。
- secret 只存 Git 外；任何身份缺失或泄漏命中必须 fail-closed。
DELIVERABLES:
- preregistration.json、development_leakage_ledger.json、intake.json、source manifest、validation log。
DONE:
- protocol hash、sampling frame hash、family split hash、case identity 全部可复算，development_overlap=false。
CONTINUE:
- 缺独立抽样框或 source identity 时保持 BLOCKED，并输出下一条最小补救。
```

## HP-B 双盲评审与裁决

```text
ROLE: C13-HOLDOUT-REVIEW-COORDINATOR
INPUTS:
- frozen real intake/source packets
- holdout_pipeline.py v2 review protocol
TASK:
1. 由独立 truth custodian freeze，生成 A/B reviewer packets。
2. 确认 packet 只含伪匿名 ID、去身份源码、问题、标签枚举和提交要求。
3. 收集两名独立评审的 label/confidence/rationale/evidence/attestation。
4. 分歧生成第三评审包，由独立裁决人决定；unknown 原样保留。
CONSTRAINTS:
- Reviewer 不得见 truth、对方意见、scanner/model output、repo/commit/source hash 或 parent/fixed 配对。
- 裁决人不得见 truth/scanner/model/parent-fixed。
DELIVERABLES:
- reviewer packets、review locks、adjudication packet/submission、final labels、hash manifest。
DONE:
- case set 精确一致，所有 payload hash 可验证，attestation 完整。
CONTINUE:
- 任一 packet 泄漏、评审缺证据或裁决不完整时拒绝锁，不补造标签。
```

## HP-C 产品 source/build identity

```text
ROLE: C13-PRODUCT-IDENTITY-AUDITOR
INPUTS:
- ark_parent_fix_build_profile_manifest.v1.json
- C13_candidate_product_gate_audit.json
- pinned official Ark Git object store when supplied
TASK:
1. 逐案例本地核对 repository/commit/tree/blob/source SHA。
2. 锁产品 manifest、shipped version/branch、binary/source mapping、GN target、args.gn。
3. 保存 compile database、include closure、preprocessed TU、macro log 和 toolchain identity。
CONSTRAINTS:
- 不用短 HEAD、URL、README、注释或 teammate branch 代替 Git 对象证明。
- 不修改 Detector/contracts/Runner/Catalog；host toolchain 不冒充 product toolchain。
DELIVERABLES:
- verified source object manifest、product build/preprocess manifest、artifact hashes、limitations。
DONE:
- 同输入重算 hash 一致，所有 required identity/build fields 非 unknown。
CONTINUE:
- object store 或产品 profile 缺失时保持 BLOCKED，逐项列 remediation。
```

## HP-D 产品入口与 CIA 证据

```text
ROLE: C13-PRODUCT-APPLICABILITY-AUDITOR
INPUTS:
- identity-complete candidate cases
- exact product build/preprocess profile
TASK:
1. 证明真实入口和权限/信任边界。
2. 证明攻击者控制、触发条件、可达敏感操作和具体 CIA 影响。
3. 保存静态调用链、配置、权限检查、部署上下文和负结果。
CONSTRAINTS:
- AST/pattern 候选不证明 ownership、dominance、concurrency、attacker control 或 impact。
- partial/failed/unknown 不转 safe；有效局部候选与义务独立保留。
DELIVERABLES:
- per-case product applicability matrix、source-bound evidence、CWE/CVE applicability、limitations。
DONE:
- Evidence gate 的 entry/permission/trigger/sensitive operation/CIA 全闭合后才允许进入 PoC 门。
CONTINUE:
- 无法证明的字段保留 unknown，并给出最小补证路径。
```

## HP-E 隔离 PoC 与修复复验

```text
ROLE: C13-PRODUCT-POC-AND-FIX-VALIDATOR
INPUTS:
- candidates that passed G13-HP-3 and G13-HP-4
- explicit written isolation authorization
TASK:
1. 在授权隔离环境构建 vulnerable product build。
2. 复现触发并保存 deterministic command、environment、snapshot、resource/network limits 和原始输出。
3. 应用 exact patch，使用同一 profile rebuild。
4. 回放 PoC、fixed/safe/unrelated/unknown controls 和产品回归。
CONSTRAINTS:
- 禁止攻击线上服务；静态子进程不是不可信构建/PoC 沙箱。
- 未授权不运行；不得把组件 Harness 当产品 PoC。
DELIVERABLES:
- PoC package、patch identity、vulnerable/fixed hashes、replay logs、revalidation report、side-effect audit。
DONE:
- vulnerable build可重复触发，fixed build同环境拒绝/不触发，回归无漂移。
CONTINUE:
- 不可复现、profile 变化或证据混合时拒绝 confirmed/reportable。
```

## HP-F 指标门与准入

```text
ROLE: C13-METRIC-AND-ADMISSION-GATE
INPUTS:
- reliable independent human-adjudicated holdout
- holdout_pipeline.py score gate
- product/PoC/fix closure artifacts
TASK:
1. 校验 protocol hash、truth HMAC commitment、reviewer/adjudicator attestation、source identity 和 exact case set。
2. 先报告 unknown、coverage 和 family confusion diagnostics。
3. 仅在 no_unknown gate 全通过时计算 family Precision/Recall/F1。
4. 对照竞赛交付门生成 admission decision。
CONSTRAINTS:
- 模型自评、开发 fixture、scanner verdict 不是 truth；不声称零 FP/FN。
- Draft Ready/merge 必须等待用户明确授权。
DELIVERABLES:
- score JSON、family metrics、admission matrix、blocker/remediation、artifact hashes。
DONE:
- 指标来源独立可靠，产品 build/PoC/fix revalidation 和完整报告均闭合。
CONTINUE:
- 任一强制门缺失时保持 NOT_ADMITTED，不以 0 findings 或 partial 当 safe。
```
