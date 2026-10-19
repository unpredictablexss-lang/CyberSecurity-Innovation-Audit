# G12-PC sustained goals

持续原则：每轮只闭合一个可审计缺口；缺输入就保持 blocked/unknown，不以规则数量、0 findings、模型意见或组件 Harness 代替产品证据。目标状态为 active，直到产品闭环与准入重审完成。

## G12-PC-1 Build/preprocess profile

- 本轮：已生成 16 个 Ark parent/fix 案例的可复算 manifest；6 个 source identity 字段完整，0 个产品 profile 完整。
- 当前 IBS5YG 单案例 intake 与 16 案例 portfolio 必须分别记账：D5/T5 通过最多闭合 IBS5YG 的 case profile，不能把 G12-PC-1 从 `IN_PROGRESS_BLOCKED` 更新为完成。单案必须核对 locked manifest digest、Ark Runtime component revision、同一 build 的 GN/config/toolchain/include/generated-input closure、preprocessed TU/macro log 和 shipped binary/image 映射。
- 下一轮：只绑定 official Ark Git object store，逐项本地核对 commit/tree/blob/source SHA；收到 IBS5YG 六项最小目标标识后执行单案画像 D5/T5。
- 后续：依次锁产品 manifest/branch/version、GN target/args.gn、compile database、include closure、compiler/linker/sysroot、preprocessed TU/macro log。
- 完成条件：同一输入重算 payload hash 一致，所有 required identity/build inputs 非 unknown。

## G12-PC-2 Independent holdout

- 本轮：freeze、双盲 packet、review lock、分歧裁决、final labels 和 score gate 已实现并完成合成自测；未使用开发控制作真值。
- 当前可先做的准备：D2/T2 完善空白抽样框、family split、泄漏账本和预注册模板，并用缺字段、身份漂移、标签泄漏等合成负例检查治理门 fail closed；这是模板/合成审查，不是真实 freeze、无泄漏证明或真实 holdout 结果。
- 下一轮：取得独立 source set、custodian 与评审人员后，才冻结真实抽样框和协议，不读取标签。
- 后续：由数据保管人冻结真实 case；两名独立人工评审；一名独立裁决人；分歧和 unknown 全保留。
- 完成条件：truth_status=reliable_independent_human_adjudicated、model_generated=false、评审/裁决 hash 完整，之后才计算 family confusion matrix。

## G12-PC-3 Product applicability

- 本轮：16 个案例均输出 entry/permission/trigger/attacker/CIA/product build/PoC/fix-retest 义务矩阵，全部缺项显式 unknown。
- 当前可先做的准备：按每个候选列出源码入口、调用链、权限边界、attacker-controlled input、trigger 和 CIA 证据定位点；尚无产品构建绑定的字段一律 `unknown`，不得把上游 JS API 可达性当作产品攻击面。
- 下一轮：目标产品输入到位后，按 source identity 完整度选 6 个案例调查同一产品 manifest、版本/分支、入口和调用链，不先执行 PoC。
- 完成条件：每案例有真实入口/权限边界、攻击者控制、触发条件、可达敏感操作和具体 CIA 影响证据。

## G12-PC-4 Authorized isolated PoC

- 本轮：未执行。定义了授权、隔离、资源、网络、快照和证据记录门。
- 测试矩阵和受控 harness 设计可提前完成；运行目标产品 PoC 仅对满足对应 case 的 PC-1 profile、PC-3 入口/影响证据并取得 PC-4 明确授权后进行。
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

## 本轮持续目标检查点（2026-10-20）

D3/T2/T6 并行交付已完成：D3 完成 source-side PC-3 定位但产品入口/权限/CIA 仍未知；T2 保留反例优先的窄候选；T6 仅完成运行时验证设计。下一轮优先级仍由准入门决定：先取得六项 IBS5YG 目标身份并绑定同一 build profile，再补产品入口/攻击面证据；随后才考虑 PC-4 授权执行。没有目标身份时，保持 G12-PC-1/3 blocked，允许继续做受限的源码证据整理与治理模板审查。

## 本轮增量（2026-10-20）

- **PC-1:** D2 对 7 个仍有提交锚点的案例补充本地 Gitee bare-store 身份复算（14 commit/tree、24 个存在的 path blob、7/7 parent→fix ancestry）；3 个无可靠锚点案例仍 `UNKNOWN`。T4 已独立复算并指出 verifier 对缺失/错误类型对象和 ancestry 异常的 gate 缺口；D2 按反馈修复，T4 对修复后的同一 commit 注入负例复核通过（报告 commit `a297e791908be725abfb39be75991d3813911dae`，SHA-256 `1e73b08d00d1a447157048fc9cde1c11e44f452847351f80b8054cb51e119939`）。上述内容不证明 acquisition custody、产品关联或产品构建画像；PC-1 portfolio 仍 0/16。
- **PC-2:** T2 将非合成 leakage evidence 绑定到 evidence-root 下的安全相对路径及原始字节 SHA；22 项合成单测和 pipeline self-test 通过，`metrics_computed=false`。真实独立 source set、custodian 与评审人员尚无，真实 PC-2 继续 `NOT_RUN`。
- **持续反馈:** 每个 D2 source verifier 更新由 T4 复算对象统计和错误门；每个 T2 pipeline 更新先用合成负例验证，再由 owner/T2 独立复跑。获得产品 owner 或独立 holdout owner 的真实材料前，维持所有对应 blocked/unknown 状态。

- D2 按 T4 反馈把缺失/错误类型 commit、缺 tree、expected-path blocker 和 ancestry 非 PASS 纳入 verifier failure gate；owner 重跑 self-test 和 build-profile 16 项 suite 通过。T4 独立验收通过；接下来仍须保持未记录字段和无锚点案例 UNKNOWN，等待 source owner 提供三案锚点。
- **D5/T5 intake gate:** T5 在 D5 初版发现 manifest URI 摘要未绑定证据字节，D5 修复后 T5 对精确新 SHA 的 21 项黑盒复测通过；正例仍返回 `admission_ready=false`。此 gate 只校验结构和本地字节摘要，不验证 issuer、证据内容、URL 可达、custody 或产品构建关系。六项产品身份仍全为 null，PC-1 维持 0/16 blocked；真实 build profile 收集等待产品 owner 提供唯一目标身份。
