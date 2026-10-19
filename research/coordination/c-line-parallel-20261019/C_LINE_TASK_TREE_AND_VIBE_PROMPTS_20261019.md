# C 线最新任务树、并行 Vibe Coding 提示词与持续目标

更新：2026-10-19（Asia/Shanghai）。
适用基线：显式 fetch 后 `origin/codex/c-line-ark-runtime-20261018` = `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`。
审查原文：`research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`，位于上述 pinned Git tree；此前“原文缺失”判断已被最新远端对象推翻。
原则：公开披露、组件复现、静态候选和产品漏洞分层；candidate/unassessed 不升级为 confirmed，0 findings 不等于 safe，skip/blocked 不计通过。

## 1. 当前任务树

```text
C-line Ark Runtime type safety
├── C0 语义合同：0.7.0/0.8.x 开发控制已冻结
├── C1 exact snapshot 产品构建/预处理 profile：当前阻塞
├── C2 18 项模型依赖漂移：待逐项 changed/unaffected/unknown
├── C3/C7 历史 replay：scoped parent/fix 观察已有，full tree/产品 profile 仍 blocked
├── C4 exact dependency manifest：部分完成，缺完整宏/工具链/include closure
├── C5 独立 holdout：阻塞，现有 41 行标签为空，不是可靠真值
├── C6 动态/产品闭环：无候选通过入口、权限、触发、CIA、产品构建门
├── C7 admission/delivery：RFC 已有，公共实现需独立提交
└── C9 当前执行
    ├── C9-TYPE-ORIGIN：闭合 6 个 origin invalidation 反例
    ├── C9-EXCEPTION-GUARD：闭合 abrupt completion / allocation exception / effect order
    ├── C9-PARTIAL-OWNER：partial owner fail-closed 与审查记录对账
    └── C9-INTEGRATION：远端 e4e 与本地优化分支差异、回归、schema/Runner 门
```

## 2. 已知案例覆盖目标

以下均是“扫描器必须给出正确候选/未知语义”的验收输入，不是产品漏洞确认：

| 案例 | 当前扫描器目标 | 最低验收 |
|---|---|---|
| CVE-2025-24304 / Map type-origin | 父/修复 root-specific candidate 1→0 | 正例命中、修复不命中、fixed/safe/unrelated/unknown 分开 |
| IBS5YG / Filter type-origin | species-sensitive result token 来源错误可检出 | 父 1、修复 0，partial 不冒充完整通过 |
| I7KZJ7 / byte-length overflow | 32-bit element-size×length 溢出进入 allocation 可检出 | 正/修复/溢出边界/安全控制 |
| IC7B8Q / allocation pending exception | NewTypedArray 后读 HClass 前缺 guard 可检出 | 父 2→修复 0，异常顺序 unknown 保留 |
| I7E0FM / Filter abrupt completion | callback 后 ToBoolean 前缺 exception guard 可检出 | 父 1→修复 0，跨 helper 未知保留 |
| IAO7GO / Reflect.apply exception propagation | `native_inline_lowering.cpp` 不得因 selector 0 applicable 漏掉 | 至少给出适用/unknown，不得静默 0 |
| I7W51D / length narrowing | int32 narrowing→allocation 作为 candidate 规则或明确 security gate 未满足 | 不把 RangeError 修复当安全；正/修复控制 |
| IB8BCA / DataView index width | 32-bit index/bounds arithmetic 缺模型必须显式 unknown/limitation | 不以 0 findings 宣称安全 |
| IAO7E8 / receiver type guard | `IsFastTypeArray` 必须支配 `GetViewedArrayBuffer` | 父 1→修复 0，邻近 safe sibling 不当盲测 |

## 3. 当前并行执行线

### C9-TYPE-ORIGIN

- 角色：Ark Runtime type-origin/dataflow 语义工程师。
- 持续目标：让旧 token 在 assignment、compound declaration、increment、branch condition、unknown/global effect 后正确失效；只在可见语法和 source-bound graph 上推理。
- 唯一写范围：`type_origin.py`、对应 type-origin tests/fixtures、本线 `c9_type_origin_acceptance_20261019/`。
- Vibe Coding Prompt：
  > 你是 type-origin 语义修复 Agent。先只读核验 pinned commit、审查原文中的 CVE-2025-24304/IBS5YG 及 6 个 C3 反例。为每个反例写最小 source-bound test，断言 candidate/unknown 应有语义；再做最小算法修复。正/固定/安全/非相关/未知五类控制必须齐全。禁止用历史 verdict、名称相似或外部扫描器补语义；partial/unknown 不得转 safe。持续下一片：跨 callback、loop backedge、alias、跨函数 summary。完成门：最新远端测试不再出现旧 token 误传播，exact argv、patch、hash、限制、下一最小切片齐全。
- 持续执行目标：G-TO-1 固化反例 → G-TO-2 修复 origin invalidation → G-TO-3 正/固定/安全/非相关/未知回归 → G-TO-4 真实父/修复 replay → G-TO-5 未触碰同机制 holdout。

### C9-EXCEPTION-GUARD

- 角色：Ark Runtime abrupt completion/effect-order 语义工程师。
- 持续目标：覆盖 callback result、helper return、NewTypedArray allocation、pending exception guard 与 copy/store effect order；IAO7GO selector 漏覆盖必须显式暴露。
- 唯一写范围：`exception_guard.py`、`runtime_exception.py`、对应 tests/fixtures、本线 `c9_exception_guard_acceptance_20261019/`。
- Vibe Coding Prompt：
  > 你是 exception propagation Agent。读取 I7E0FM、IC7B8Q、IAO7GO、I5XZRO、FindIndex/C333 的精确 parent/fix source identity。区分 guard-before-effect、guard-after-effect、missing guard、unknown effect；实现最小直接调用和可证明 helper summary，缺 body/宏/CFG 保持 unknown。对每个案例生成 positive/fixed/safe/unrelated/unknown 矩阵。禁止把 source order、0 findings 或组件回归当产品安全。持续下一片：跨函数 exception summary、macro expansion、callback alias、并发/所有权。完成门：已知 abrupt-completion 正例可被扫描器捕获，fixed 不报同一根因，selector 不静默跳过。
- 持续执行目标：G-EG-1 审计 exception effect → G-EG-2 修复 guard/order → G-EG-3 selector applicability → G-EG-4 exact replay → G-EG-5 独立变体评估。

### C9-PARTIAL-OWNER

- 角色：partial AST、namespace identity、fail-closed 证据工程师。
- 持续目标：缺 include/宏/跨 TU/歧义 owner 时输出 unknown/limitation，不抛未分类 FileNotFoundError，不按名称猜 owner；同时把审查原文 finding 映射到 Detector/rule/control。
- 唯一写范围：`syntax.py`、parser-owner tests/fixtures、`c9_partial_owner_acceptance_20261019/`，可复用独立 `c8_source_audit_reconciliation_20261019/` 但不覆盖其 dirty 证据。
- Vibe Coding Prompt：
  > 你是 partial-owner 与 audit reconciliation Agent。原文位于 pinned Git tree 而非 checkout 根目录；用 git show 读取并绑定 blob/source hash。建立 owner 恢复正/歧义/缺源/parse-error 控制，缺证据必须 unknown。对审查记录中的 C 线条目做 finding→detector/rule/control/source identity 对账，substitute evidence 永不冒充原文。持续下一片：宏展开、模板限定名、include closure、跨 TU owner、build profile。完成门：外部目标源缺失可审计地 fail-closed，已知 finding 有稳定映射和回归入口。
- 持续执行目标：G-PO-1 输入身份 → G-PO-2 partial owner → G-PO-3 fail-closed → G-PO-4 audit mapping → G-PO-5 profile/dependency closure。

### C9-INTEGRATION

- 角色：Runner/Catalog/schema/回归集成验收员。
- 持续目标：比较本地 `715e298` 优化分支与远端 `e4e0761` C 线实现，建立可迁移 patch 和合流门；公共 contracts/Runner/Catalog 变更必须独立提交。
- 唯一写范围：`research/evidence/ark_runtime/c9_integration_20261019/` 与独立 worktree，不直接改算法或公共协议。
- Vibe Coding Prompt：
  > 你是集成验收 Agent。固定本地优化 commit、远端 e4e commit、review blob 与所有 source hashes。运行 Ark focused/full、Runner applicability、schema/legacy compatibility、compileall/JSON/diff check；把每个 pass/fail/skip/block 的 exact argv/env 和根因分开。生成 known-case coverage matrix，明确 IAO7GO/I7W51D/IB8BCA 等漏覆盖不是安全。持续下一片：选择性迁入、公共契约兼容测试、独立 holdout gate、最终打包。完成门：三条实现线可安全合流，算法修复与公共协议分提交，阻塞项有最小补救任务。
- 持续执行目标：G-INT-1 基线 → G-INT-2 known-case coverage → G-INT-3 兼容性 → G-INT-4 选择性迁入 → G-INT-5 交付审计。

## 4. 后续并行任务

### C9-BUILD-PROFILE

- 持续目标：补齐 exact Ark Runtime parent/fix 的 rk3568 compile action、宏、include closure、工具链和生成输入 manifest；重算摘要，缺项 fail-closed。
- Prompt：只读固定 Git/source 产物，生成可复算 dependency manifest 与 negative mutation tests；不得把 a65 profile 套到 !11196/历史 pair；完成门是同一 parent/fix 可用同一 profile 预处理并绑定 tree/blob/source SHA。

### C9-HOLDOUT

- 持续目标：冻结 Detector/model/parser/config 后，从开发家族之外抽取真实规则适用样本，双人盲标、第三方裁决，只有独立可靠真值才计算指标。
- Prompt：样本不足就报告不可评估；不复用调参样本，不泄露预测，不让模型自评；完成门是 applicability、labels、adjudication、family leakage 和 score gate 全部审计通过。

### C9-DYNAMIC-PRODUCT-CLOSURE

- 持续目标：仅对满足入口/权限/触发/敏感操作/CIA 门槛的候选做本地隔离 PoC、修复和重验，绑定产品构建、影响版本/分支、CWE/CVE。
- Prompt：授权隔离、无网络、只读根、资源限制；组件 PoC 不等于产品漏洞；无法证明就保留 unknown；完成门是可复现 PoC、修复版失效、合法控制通过、完整报告。

### C9-DELIVERY-ADMISSION

- 持续目标：按竞赛交付清单独立复审准确/完整分析、CWE/CVE、PoC、受影响版本、修复重验、性能/创新证据和完整报告；未获用户授权不标 Draft Ready、不合并。
- Prompt：逐项核对 pinned source identity、partial/unknown、可靠标注、性能边界和公开材料；输出准入决策与最小补救，不用候选数或工作量替代安全证据。

## 5. 统一持续执行规则

1. 每轮只推进一个可验证切片，结束必须有 exact commands、commit/tree/blob/source hashes、patch、控制矩阵、pass/fail/skip/block、限制和下一最小切片。
2. 缺对象、缺原文、缺依赖、partial、failed、unexecuted、unknown 都不得转成 safe/miss/throughput success。
3. 正例、fixed、safe、unrelated、unknown 五类控制不可省略；安全/修复控制只证明边界，不证明产品安全。
4. 不 fetch/checkout/reset/push/merge/PR，不攻击线上服务，不在普通测试子进程执行不可信构建或 PoC。
5. Detector/算法修复与 contracts/Runner/Catalog 公共变更分提交，legacy v1 只读，不重写历史 ID/review/EvidenceObligation。
6. 只有独立真值可计算 Precision/Recall；当前不声称零 FP/FN、产品漏洞或新 0day。
