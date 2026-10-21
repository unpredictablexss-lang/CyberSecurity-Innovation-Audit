# OHScanner：Agent 工作流选型与实测报告
**评委阅读版｜2026 年 10 月 19 日**

## 结论先行

建议采用候选驱动、固定阶段、只读工具的 Taskflow：静态扫描后，单个 Agent 针对候选绑定的提交和源码依次取证、主动审查反证、检查义务并输出结构化结论；服务端校验引用和状态，面板展示结论及处置入口。人工在结果之后处置，不要求预先填写 R0。

本轮已实现工作流原型并完成整仓回归及固定源码烟测。烟测证明流程接线可运行、源码范围受限、证据不足时会保守返回“需更多证据”；没有证明模型准确率，也没有确认产品漏洞。扫描完成后的自动派发和持续外发授权尚未完成，因此还不是生产闭环；结果页已显示 Agent 源码范围判定，并可追加人工分诊/误报处置审计记录，但不改变产品漏洞状态。

## 一、开源方案对比与选择

| 参考 | 可借鉴点 | 本项目取舍 |
|---|---|---|
| [GitHub Security Lab Taskflow Agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent) 及[分诊实践](https://github.blog/security/ai-supported-vulnerability-triage-with-the-github-security-lab-taskflow-agent/) | 将取证、误报条件审查、报告生成、完整性检查串成有序任务；最贴近静态告警后复核。GitHub Security Lab 报告其 CodeQL 告警工作流发现约 30 个真实漏洞，这是项目作者的结果陈述，不是 OHScanner 或本实验的独立验证。 | 采用固定步骤、可审计输出；沿用 OHScanner 固定提交绑定、只读源码工具和服务端 schema/引用校验，不照搬 GitHub Actions 执行环境。 |
| [阿里巴巴 OpenCodeReview](https://github.com/alibaba/open-code-review) | 通用 AI 代码审查，提供确定性规则与 Agent 分工、按文件/规则派发、按需取上下文和输出检查。 | 借鉴确定性输入范围与报告质检；不引入整套审查/扫描引擎，以免和 OHScanner 检测器重复，也不把其自有基准当作本项目效果证据。 |
| [阿里巴巴 CodeFuse-Query](https://github.com/codefuse-ai/CodeFuse-Query) | 静态语义查询引擎，可作为未来补充 AST、控制/数据流证据的候选。 | 它是分析引擎而非 Agent 工作流；替换 OHScanner 成本高，本轮目标是可靠复核既有候选，暂不纳入运行时。 |
| [vuln-scanner-agent](https://github.com/gitmehdii/vuln-scanner-agent) | 多 Agent 扫描与汇总的职责组织示例。 | README 的工具比较未启用 LLM、覆盖范围有限，不能证明多 Agent 更准。当前不采用自由多 Agent 群聊，避免增加调用、成本、分歧与复现难度。 |

**选型：**以 Taskflow 为主干，借鉴 OpenCodeReview 的确定性派发和报告验证，使用 OHScanner 固定源码工具。R1 单提示仅作离线对照，不作为产品主流程。

## 二、选定工作流

1. **绑定输入：**固定仓库、提交、Git tree、报告、候选行和源码哈希；扫描器元数据不能作为代码事实引文。
2. **受限取证：**白名单只读工具查询符号、读取候选函数和有限源码范围；不允许修改文件、执行任意命令或读取未绑定源码。
3. **审查假设和反证：**逐项检查可由源码回答的义务，主动寻找权限检查、早退、校验和清理等反向证据。产品可达性、攻击者控制、实际构建配置和影响等仍不能由源码片段解决的事项必须保持未决。
4. **结构化结论：**产出支持主张、反证、未决项、根因、影响边界和下一步验证，引用只能指向固定源码工具返回的证据。
5. **服务端质检：**检查 schema、义务覆盖、证据 ID、文件/行范围、引句原文及状态一致性；校验失败时丢弃不可信结论、重试有限次数或失败关闭。
6. **结果后处置：**面板显示 Agent 判断和限制；人工可标记误报、接受风险、继续调查、补证或确认。审计记录追加保存，不篡改原始扫描或模型结果。

本轮原型记录流程版本 `ohscanner-security-triage-taskflow@0.1.0` 和三个阶段：`collect_fixed_source_evidence`、`audit_hypothesis_and_counterevidence`、`validate_report`。 这些步骤由同一个受限模型会话按提示顺序执行，并由服务端把运行记录归并成三个审计阶段；当前不是多个独立 LLM 任务，也没有第二个审查模型。

## 三、结论与幻觉边界

`agent_verdict` 表达固定源码范围内的 Agent 判断；`vulnerability_state` 保持 `candidate`，`validated_vulnerability=0)，`product_status=unknown)。高置信源码确认必须满足结构答复通过校验、存在支持主张、所有 Agent 可审查的源码义务均有支持证据、没有未支持主张、没有必须交人工/运行时的未决门槛。误报确认须对所有源码义务提供引用反证。否则保留可能、未决、未知或分析失败状态。

这是一套可审计的规则原型，不是校准过的概率阈值。“源码确认”不等于产品可达、可利用或已影响 OpenHarmony 产品；需要独立产品构建、入口和影响证据。真实样本不足时不得声称误报率或召回率达标。

## 四、本轮真实源码烟测

脚本 `experiment_real_source_fake_agent.py` 使用只读固定源码和 Fake Provider，没有发起真实模型/API 请求。

- 仓库 `openharmony/security_access_token`，commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`，tree `4621b3e40b31a958a4bbe9be87690afb6cec44b0`。
- 固定扫描 550 个源码文件、8 个检测器、16 条诊断；5 个检测器 blocked，扫描状态 `completed_with_limitations`。
- 所选 IPC 候选在 `accesstoken_callback_stubs.cpp:103`，仍只是静态候选。

| 对照臂 | 观察结果 | 结论范围 |
|---|---|---|
| R1 单提示 Fake | 1 次替身调用，无源码工具调用。 | 仅作为流程对照，不测试真实 LLM。 |
| R2 Taskflow Fake | 4 次替身调用，3 次受限只读源码工具调用（符号查找、所在函数、8 行源码范围）；结构检查通过；4 项义务全部未决；verdict 为 `needs_more_evidence`。 | 证明绑定、白名单、阶段、操作 API 和保守结果可端到端运行；没有支持主张或引文，不证明推理质量、引用语义或漏洞存在。 |

两臂均保持 `vulnerability_state=candidate`、`validated_vulnerability=0`。产物：[selected-taskflow-offline-smoke-20261019.json](selected-taskflow-offline-smoke-20261019.json)。整仓 Python 回归 932 项通过、5 项跳过；Agent 模块 107 项通过。测试通过不等于模型准确率或漏洞确认。

另有 2026-10-18 的真实 DeepSeek R0/R1/R2 旧版配对记录：R1 一次调用，2,818 输入/800 输出 token，接受一条源码引用主张，但四项义务三项未决；R2 三次调用，12,169 输入/317 输出 token，最终答复和修复答复 JSON 校验失败，服务端丢弃主张并失败关闭。该实验早于本轮 Taskflow 版本，只能说明旧版 Provider schema 兼容和调用成本风险，不能作为本轮流程的效果评估。详见[原始记录](deepseek-r0-r1-r2-live-results-20261018.md)。

## 五、创新点和交付计划

创新点是让静态候选进入可追溯的 Agent 复核：结论绑定报告、提交、源码和行范围；扫描器与模型证据分开；未决项、工具调用、预算、校验失败都可审计；Agent 可给源码范围结论，但不冒充产品确认。项目应以人工处置数据盲测并持续校准，而不是以模型自评证明效果。

目前已有 Provider 设置、单候选/批次操作、固定源码只读工具、外发预览、结构/引用校验和操作记录。尚未完成静态扫描后的自动派发和项目级可撤销 Provider 外发授权。Agent verdict 与人工处置入口已落地；人工处置只追加审计记录，不把 candidate 自动改成产品确认或误报。源码外发必须由明确持久授权控制，不能自动推定同意。

建议交付顺序：①完成带暂停/撤销、预算和幂等保护的自动派发；②面板展示 Agent 状态、证据、反证、未决、覆盖和失败，并提供误报/风险接受/继续调查/确认等事后处置；③构造独立标注、去重的公开漏洞/修复前后/安全对照集合做盲测，统计误确认、语义支持、失败、费用和延迟；④仅对明确授权的小批候选进行真实 Provider 试运行，再逐步扩大。

## 参考资料

- [GitHub Security Lab Taskflow Agent](https://github.com/GitHubSecurityLab/seclab-taskflow-agent)
- [GitHub Security Lab：AI-supported vulnerability triage](https://github.blog/security/ai-supported-vulnerability-triage-with-the-github-security-lab-taskflow-agent/)
- [Alibaba OpenCodeReview](https://github.com/alibaba/open-code-review)
- [Alibaba CodeFuse-Query](https://github.com/codefuse-ai/CodeFuse-Query)
- [vuln-scanner-agent](https://github.com/gitmehdii/vuln-scanner-agent)

**给评委的一句话：**OHScanner 已验证“静态候选 → 固定源码取证 → 结构化 Agent 工作流 → 服务端校验”的离线原型；下一步接通有授权的自动派发和结果后处置，并用盲测评估真实 Provider。当前数据不支持宣称 Agent 提高了准确率，也不支持把该候选确认成 OpenHarmony 产品漏洞。
