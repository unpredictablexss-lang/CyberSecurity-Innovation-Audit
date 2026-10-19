# OHScanner B/D 与 Agent 实验成果证据包

**评审材料｜截至 2026-10-19**
**远端代码基线：** `main@db77164fdc2af0da02e4d3efc056d84694fd68e8`

## 项目做了什么

OHScanner 将结果分成两层：B 线在 IPC/接口等静态规则上产出绑定源码的候选；D 线在多个真实 OpenHarmony 组件快照上做历史问题回放；Agent 原型对候选绑定固定源码取证、检查反证和未决义务，并输出结构化复核意见。三者的实验说明了检测与复核链路的工程进展，也记录了当前覆盖边界。

| 工作线 | 可核验成果 | 本轮证据能支持的结论 |
|---|---|---|
| B：IPC/接口候选检测 | 检测器版本 0.8.11；发布提交包含 48 份回放 JSON、18 份 SHA256SUMS 清单（共核验 59 个文件）；仓库测试 564 项通过。 | 回归样例、候选与证据绑定机制可复现；不等同于独立盲测召回率或产品漏洞确认。 |
| D：真实组件回放 | 固定三个 OpenHarmony 仓库 commit/tree，合计 1,113 个文件；pasteboard 产生 2 个候选，另两个仓库 0 条诊断。 | 展示真实快照扫描与 partial/blocked 覆盖的报告能力；0 条诊断不代表安全，2 条候选也未确认。 |
| Agent：候选复核原型 | 固定源码 Fake Provider 对照：单提示 1 次模型替身调用；Taskflow 4 次替身调用及 3 次只读源码工具调用，4 项义务均保留未决，结果为 needs_more_evidence。 | 证明原型能在固定源码上下文中运行并在证据不足时保守返回；不证明真实模型准确率。另有旧版真实 DeepSeek 兼容性实验，见下文。 |

## 评委应如何理解结果

- **candidate** 表示待人工/动态/产品构建证据复核的静态候选；**unknown/partial/blocked** 表示证据或覆盖不足。
- 本包未把组件级回放、扫描器测试、Fake Provider 输出或模型自述称为 OpenHarmony 产品漏洞确认。当前证据中没有经既有验证门批准的 `validated_vulnerability`。
- B 的测试和回放证明工程回归能力；它们不是冻结独立 holdout。D 的扫描使用 light-AST，没有产品构建、宏展开或产品锁定 manifest。Agent 评估含 Fake Provider，不能据此评价推理质量。
- 需要继续补齐独立标注的修复前后/安全样本、产品配置与入口确认、动态验证、跨版本影响和性能/资源数据，才能对召回、误报、影响范围作量化结论。

## 证据导航

- [B/D/Agent 核心实验矩阵](./实验矩阵.csv)：可用 Excel 打开。
- [Agent 固定源码与 Taskflow 实验说明](./AGENT_EXPERIMENTS.md)
- B 检测器源码与回放记录：[/feat/interface-ipc-detector @ 7579a16](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/tree/feat/interface-ipc-detector)
- B 发布提交：[7579a16344fa3164bfbea3e26db783854a1793b6](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/commit/7579a16344fa3164bfbea3e26db783854a1793b6)
- D50 组件回放报告（已在主线）：[D50_COMPONENT_CVE_REPLAY/README.md](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/blob/main/research/data_sensitive/D50_COMPONENT_CVE_REPLAY/README.md)
- Agent 原型的实验来源为本地工作区 `work/agent-llm-20261018@1c21ac60890fca0ce6be5d50d82e4757dd5e4623` 的未提交研究产物；为保护实验工作区，本分支仅发布经整理的评委说明，不声称该 Agent 实现已并入 main。

## 复现建议

1. 检查 B 发布分支及 `research/deliveries/ipc/` 下的回放记录和校验清单。
2. 打开 D50 报告，按记录的组件 commit/tree 对照结果；候选均应回到源码和真实产品配置复核。
3. 阅读 Agent 实验说明，区分 Fake Provider 流程烟测与旧版真实 Provider 调用实验。
4. 仅在有权限和明确固定输入时重跑；报告候选量、覆盖、partial、耗时和 RSS，不以 0 告警作为安全结论。
