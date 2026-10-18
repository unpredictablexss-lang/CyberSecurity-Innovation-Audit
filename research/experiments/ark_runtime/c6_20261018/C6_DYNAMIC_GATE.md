# C6 动态验证门审：无达门候选

日期：2026-10-18（Asia/Shanghai）
范围：C 线 Ark Runtime `ohscanner.ark.runtime.type_safety` 候选动态验证准入。该记录只判定是否有案例可进入隔离 PoC；不评价其他线或组件。

## 决定

本轮没有候选通过动态验证门。未构建目标、未执行 PoC、未制作漏洞修复 patch，也未运行产物复验。原因是现存材料不能同时证明现实入口、攻击者控制路径、可达敏感操作、触发条件和可检验 CIA 影响。候选维持 candidate/unknown；未将 blocked、partial、0 findings 或缺少运行结果解释为 safe、fixed 或 miss。

## 逐项证据门

| 门 | 现有证据 | 结论 |
|---|---|---|
| 精确源码身份 | C3 本地对象绑定 `openharmony/arkcompiler_ets_runtime` commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`、tree `8781f036a3e7e04d8e0b34970d5f623b42875016`、path `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`、blob `68fb3b0adc4f9062889a861be51b7be90362e37a`、source SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`。 | 来源身份对该单文件已绑定。 |
| 当前候选 | `current-run.json` 的解析状态为 partial，Runner 为 blocked、not_analyzed=1、diagnostic_count=0、validated_vulnerability=0。零诊断是未分析结果，不是安全结论。 | 没有当前可供 PoC 验证的检测候选。 |
| 历史父/修复 | C3 记载 C4 历史 type-origin parent/fix 为 1/0、exception-guard 为 2/0，但四项均 partial/blocked；精确历史提交对象不在当前组件对象库，不能从同一固定环境重放。 | 不能当成已确认漏洞或完整 vulnerable/fixed 对照。 |
| 构建上下文 | C3 run 的 `build_profile=none`、`product_manifest_locked=false`、`macro_expansion=false`。没有匹配产品的工具链、构建配置、依赖清单及二进制产物。 | 缺产品构建/依赖 manifest；不可安全、可重复地生成目标版本。 |
| 入口与攻击者控制 | 当前候选没有已证实的 VM/产品入口、外部或低权限输入到目标函数的来源链及边界条件。单个 C++ builder 函数及语法模式不构成可达性证明。 | unknown，不能据此构造真实利用输入。 |
| 敏感操作与影响 | 没有运行时状态损坏、越权、信息披露、拒绝服务或其他 CIA 结果的观测；没有可检验触发条件。 | 影响未证明。 |
| 独立评估 0.7.0 | v3 冻结检测器 commit `a2fce96f98ffbb968c04ac69e19a7da24032d368` / tree `a9eba411bcbb0e9dc940f2abe4f4e96f454007c4`，model digest `548996ced072b847e2a01d17c4f56de11b6fe4e42e3657f1434c7b8fbc9f3aca`；评估在选样前停止，无新样本、无 reviewer declarations、无标签或预测。冻结状态本身不提供动态候选。 | 不存在已审阅并可供动态验证的 holdout/案例。 |

## 精确来源与证据文件

以下路径相对 C 线 checkout `CyberSecurity-Innovation-Audit-c4`。SHA-256 用于把本门审结论绑定到本次读取的材料：

- `research/experiments/ark_runtime/c3_20261018/current-run.json` — `d66a52203e2de2359047dca7255d2aad29003f8c89df1894a2f8960033334182`
- `research/experiments/ark_runtime/c3_20261018/current-run.md` — `3bc849da8de9221c7467254da97a412c691a879ab1ad919a3f2faff3f2bf935b`
- `research/experiments/ark_runtime/c3_20261018/model_dependency_comparison.json` — `c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d`
- `research/evidence/ark_runtime/ark-runtime-c-independent-holdout-20261018-v3/README.md` — `97c0df9bfd12431150a40e8355e1e3f97c5b949b266e040c035e918a08514e2f`
- `research/evidence/ark_runtime/ark-runtime-c-independent-holdout-20261018-v3/admin/assessment_status.json` — `f3ce4ab533ed7dfcfa3589330cc1e234c53c03ca5579c16015870bf71f39ac0c`
- `research/evidence/ark_runtime/ark-runtime-c-independent-holdout-20261018-v3/admin/final_gate_audit.json` — `42f654e2eabba5982b4d6ef449611f73ebb52eab632e64acd4299d76c8da287a`

V3 中源码样本清单为 0 行（选样前停止），不能作为源码输入或产品构建 manifest。C3 精确目标源身份如上，但其构建 profile 明确为 `none`；故本记录不声称已冻结 C6 构建产物、工具链或依赖。

## 安全与重启条件

没有访问或触碰在线生产服务；没有运行来源构建脚本；没有在宿主执行不可信构建步骤；没有创建可执行 PoC。后续只有在候选证据补齐现实入口、攻击者控制、敏感操作、触发条件和具体影响，并有精确产品源码/构建 manifest 后，才进入一次新的隔离验证。届时须绑定 vulnerable/fixed/safe/unrelated 源码身份和产物哈希，记录重复运行及失败条件，并复验最小修复和合法行为。

剩余 unknown：18 个模型依赖漂移的语义影响仍未判定；产品构建 flags/macros/preprocessing 未绑定；完整产品入口、权限边界、输入控制、触发条件、CIA 影响、可用 PoC、修复及复验均未证实。C6 状态为 `blocked_before_dynamic_validation`，不是漏洞已确认或已排除。
