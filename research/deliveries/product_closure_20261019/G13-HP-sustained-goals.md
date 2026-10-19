# G13-HP sustained goals

持续原则：每轮只闭合一个可审计缺口；缺输入保持 blocked/unknown/not-run。模型输出、开发 fixture、known-case、scanner verdict 和历史 review 都不是独立真值。目标保持 active，直到真实 holdout 指标门和产品准入全部闭环。

## G13-HP-1 Real holdout input

- 本轮：冻结 `real_holdout_input_protocol.v1.json`、intake/truth/leakage schema，管线强制完整 Git/source identity。
- 下一轮：预注册 sampling frame、family split、排除规则、样本量；从所有开发源 hash 生成泄漏账本。
- 完成条件：真实 case 只来自冻结抽样框，development overlap=false，所有身份字段完整，协议文件哈希一致。

## G13-HP-2 Double-blind review

- 本轮：reviewer packet 移除 source hash/repo/commit/path/parent-fixed/scanner/model 上下文；新增 reviewer/adjudicator attestation、confidence、evidence。
- 下一轮：数据保管人冻结真实 case；两名独立评审；分歧由第三名独立裁决；unknown 原样保留。
- 完成条件：review lock、adjudication、final labels 的 payload hash 和 case set 全闭合，truth 只由 custodian 揭示。

## G13-HP-3 Product identity/build

- 本轮：28 条 disposition 与 16 个 Ark 产品候选逐条产品门审计；6 条 source identity 记录完整但产品 profile 仍 0。
- 下一轮：绑定 official Ark Git object store，并锁产品 manifest/branch/version、GN target、args.gn、compile database。
- 完成条件：产品 source/binary mapping、include closure、preprocessed TU、compiler/linker/sysroot 和 hash 全部非 unknown。

## G13-HP-4 Product applicability

- 本轮：所有候选逐项记录 entry、permission、trigger、sensitive operation、CIA，缺项显式 unknown。
- 下一轮：优先调查 identity-complete 的六个案例，不先运行 PoC。
- 完成条件：真实入口/权限边界、攻击者控制、触发条件、可达敏感操作和具体 CIA 影响均有可审计证据。

## G13-HP-5 Authorized isolated PoC

- 本轮：NOT_RUN。静态 Python、fixture、组件 Harness 不是产品 PoC 沙箱。
- 下一轮：仅对 G13-HP-3/4 闭合的候选申请隔离授权。
- 完成条件：vulnerable product build 可重复触发，固定环境、命令、快照、资源、网络、输出和 artifact hash 完整。

## G13-HP-6 Fix/revalidation

- 本轮：NOT_RUN。
- 下一轮：绑定 exact patch 和 fixed product identity，同 profile rebuild。
- 完成条件：PoC 回放失败/不触发，fixed/safe/unrelated/unknown 控制与产品回归通过，无副作用漂移。

## G13-HP-7 Metrics

- 本轮：synthetic self-test 为 2 agreement + 1 adjudication；score 对 synthetic truth 返回 NOT_RUN，Precision/Recall/F1=null。
- 下一轮：真实可靠人工裁决后先报告 unknown 和 family coverage；只有 no_unknown metric gate 全通过才计算 family confusion matrix/Precision/Recall/F1。
- 完成条件：truth commitment、protocol hash、reviewer independence、adjudication、source identity 和 case set 全验证。

## G13-HP-8 Admission

- 本轮：NOT_ADMITTED。
- 重审触发：真实 holdout 指标门、产品 build/source identity、产品适用性、隔离 PoC、修复产品重验、CWE/CVE、性能/创新和完整报告全部闭合。
- 禁止：未获用户授权标 Draft Ready、merge，或用 0 findings/partial/unknown 解释为 safe。
