# G12-PC sustained goals

持续原则：每轮只闭合一个可审计缺口；缺输入就保持 blocked/unknown，不以规则数量、0 findings、模型意见或组件 Harness 代替产品证据。目标状态为 active，直到产品闭环与准入重审完成。

## G12-PC-1 Build/preprocess profile

- 本轮：已生成 16 个 Ark parent/fix 案例的可复算 manifest；6 个 source identity 字段完整，0 个产品 profile 完整。
- 下一轮：只绑定 official Ark Git object store，逐项本地核对 commit/tree/blob/source SHA。
- 后续：依次锁产品 manifest/branch/version、GN target/args.gn、compile database、include closure、compiler/linker/sysroot、preprocessed TU/macro log。
- 完成条件：同一输入重算 payload hash 一致，所有 required identity/build inputs 非 unknown。

## G12-PC-2 Independent holdout

- 本轮：freeze、双盲 packet、review lock、分歧裁决、final labels 和 score gate 已实现并完成合成自测；未使用开发控制作真值。
- 下一轮：先冻结抽样框、家族 split、泄漏账本和预注册协议，不读取标签。
- 后续：由数据保管人冻结真实 case；两名独立人工评审；一名独立裁决人；分歧和 unknown 全保留。
- 完成条件：truth_status=reliable_independent_human_adjudicated、model_generated=false、评审/裁决 hash 完整，之后才计算 family confusion matrix。

## G12-PC-3 Product applicability

- 本轮：16 个案例均输出 entry/permission/trigger/attacker/CIA/product build/PoC/fix-retest 义务矩阵，全部缺项显式 unknown。
- 下一轮：按 source identity 完整度选 6 个案例，只调查产品 manifest、版本/分支、入口和调用链，不先做 PoC。
- 完成条件：每案例有真实入口/权限边界、攻击者控制、触发条件、可达敏感操作和具体 CIA 影响证据。

## G12-PC-4 Authorized isolated PoC

- 本轮：未执行。定义了授权、隔离、资源、网络、快照和证据记录门。
- 下一轮：仅对满足 G12-PC-1+3 的候选申请隔离授权。
- 完成条件：vulnerable build 可重复触发、fixed build 同环境拒绝/不触发，保留命令、环境、patch、artifact hash 和完整输出。

## G12-PC-5 Fix/revalidation

- 本轮：未执行。
- 下一轮：对已通过 PoC 的案例绑定精确 patch、fixed source/tree/blob、产品 rebuild profile。
- 完成条件：同 profile 修复构建、PoC 重放、回归控制和副作用检查全部通过。

## G12-PC-6 Admission

- 本轮：NOT_ADMITTED。
- 重审触发：上述 1-5 全部闭环，且竞赛交付的准确分析、CWE/CVE、PoC、受影响版本/分支、修复重验、性能/创新和完整报告均支持。
- 禁止：未获用户授权标 Draft Ready、merge 或把模型自评/历史 verdict 当真值。