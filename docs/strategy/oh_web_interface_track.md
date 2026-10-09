# 队友 B：OpenHarmony Web / ArkTS / IPC 接口安全研究与自研检测器任务书

> 状态：**计划**；并非已发现 Web 漏洞或现有 Web/IPC detector 已实现。
> 负责人负责引擎底座、插件契约、公共语义；B 负责真实攻击面定位、离线实验、OpenHarmony 专用检测算法、独立测试与接入包。无需自建 CLI、报告服务或重新实现整个 AST。
> 必须遵守 \`docs/contracts/ohscanner_detector_contract_v1.md\` 与 \`docs/strategy/vulnerability_corpus_bakeoff_protocol.md\`。

## 1. 为什么本方向不能直接叫“Web 漏洞扫描器”

OpenHarmony 含多语言、多进程和设备权限模型。传统网页 SQLi/XSS/SSRF 的通用规则不能自动成为 OpenHarmony 漏洞检测能力；关键问题是**是否存在实际用户可控入口和敏感调用路径**。

建议把 B 的方向定义为：**“OpenHarmony 跨语言与接口信任边界的静态安全分析”**，范围包括 WebView、JS/ArkTS、Native Bridge、IPC/RPC、调用者身份与权限、URL/文件/网络敏感操作。在其中选择一个能找到真实源码/修复证据的垂直切片作为首个 detector。

若某组件没有浏览器/JS 桥或网络服务接口，应标记该类攻击面不适用，而不是为了演示产生伪造结果。

## 2. 调研优先级（可以调整）

| 优先级 | 攻击面 / 分析对象 | 关键研究问题 | 拟提炼的检测方法 |
|---|---|---|---|
| P0 | IPC/RPC 与调用者身份 | 接口暴露给谁，传入参数如何解析，敏感方法调用前是否存在身份/权限检查 | Entry → caller identity → guard → privileged sink 的静态关系 |
| P1 | JS/ArkTS 与 Native Bridge | JS/ArkTS 可控输入如何进入 native 方法，是否跨越能力边界 | 多语言入口索引 + 可控参数传播 + bridge sink |
| P1 | WebView / 页面交互 | URL、导航、消息处理是否受来源、白名单、权限约束 | 来源约束与 guard 配对检查 |
| P2 | 文件/路径/命令/网络 | 上述真实入口的输入是否传播至敏感文件、命令和 URL 调用 | 限定的 source→sink + sanitizer/guard |
| P3 | 传统 SQLi/XSS/SSRF 等 | 是否确有服务端代码与入口且存在公开修复证据 | 有案例再建针对性规则，不先做通用漏洞清单 |

第一轮建议只做**一个**足够清晰的类别：优先 IPC 权限检查或 JS/ArkTS→Native Bridge。不与 C++ 队友争夺同一个 lifetime/bounds 检测器；共享的是入口、函数、调用关系和证据格式。

## 3. B 的资料与实验路线

**任务 B0：真实资产索引**

- 先定位 OpenHarmony 官方仓库中确实存在的目标 API、模块和语言，固定 commit、分支、文件、公开文档、接口参数类型；
- 逐条辨认用户可控来源、跨进程/跨语言边界、调用者身份、权限/白名单 guard、敏感 sink；
- 出具 \`attack_surface_inventory.md\`，同时列出目前**无法证实**输入可控或有无权限检查的情况。

**任务 B1：公开案例与对照**

- 从 S0 公告库中筛出 IPC/权限/JS/ArkTS/WebView 相关真实根因；
- 找不到官方漏洞修复对时，先做**synthetic fixture**（自建可信/不可信路径、已保护/未保护路径）测试算法，但不能把该 fixture 写成已知 OpenHarmony 漏洞案例，也不能算真实检出率；
- 至少有一个带 Guard 的安全对照和一个仅外观相似但本质不构成风险的对照。

**任务 B2：工具方法对比**

适合研究的候选工具按实际支持的源码语言选择，比如对 JS/TS 用 Semgrep/CodeQL 对照，在 C++ IPC 实现使用 Clang、CodeQL 等作为交叉参考；它们的安装成功和查询命中不能替代完整解析/构建覆盖。对每个候选报告记录 rule/query、构建上下文、入口/guard/sink 的证据是否具体存在。将对照工具的长处整理进 MethodCard（而非把它们编排为正式扫描主逻辑）。

**任务 B3：自主检测器**

提议首个 detector：
\`ohscanner.interface.permission\` 或 \`ohscanner.interface.bridge\`（最终名称以 v1 contract 登记为准）。

算法分层：
1. 在 AST/符号索引中标识真实入口（IPC transaction / JS bridge exposed function 等）；
2. 对关键参数建立有限 source/provenance 追踪；
3. 在目标函数/有限跨函数路径上查找身份、权限、URL/来源约束等 guard；
4. 识别敏感操作 sink，与入口及 guard 关联；
5. 输出 candidate + evidence + missing obligations，而不是直接标注“权限绕过”。

优先做函数内和**一跳**调用关系的有限分析；解析/类型/guard 支配信息不足时降级成 \`syntax\` 或 \`unknown\`，不要伪造 dataflow/control_flow 证据。可编写 OpenHarmony 专用的入口和能力 API 目录，但每项 API 需来源和版本证据，不能靠猜测字段名。

## 4. 需要交给负责人接入的清单

建议局部目录（尚未创建，属于规划）：

~~~text
research/corpus/interface/               # 公开公告元数据与 S0-S3 引用
research/experiments/interface/          # 对照实验脚本/结果清单/覆盖证明
research/methods/interface/              # MethodCard、误报与消融
src/ohscanner/models/openharmony_web/    # 入口、guard、权限/sink 语义模型
src/ohscanner/detectors/interface/       # B 自研检测器逻辑
tests/detectors/interface/               # synthetic+真实正/修复后/安全样例
docs/reviews/interface_attack_surface/   # 固定版本攻击面综述
~~~

每个 detector 的交付包必须包含：

1. 一张 MethodCard：漏洞家族/输入/敏感目标/历史参考/工具实验与失败/自主改进/许可证；
2. 可重放的固定源码索引与 positive/fixed/safe fixtures（如是 synthetic，明确标记）；
3. 一个符合 v1 Contract 的 Detector，不发明新的全局 Finding 或 CLI；
4. 明确要求主线提供哪些 \`required_facts\`、缺失时返回何种受限覆盖状态；
5. 单测（真实运行、失败/路径异常、guard 正例与负例、跨仓库/版本隔离）；
6. 最小演示命令在负责人提供的统一 orchestrator 中运行，而不是独立 Web 服务或网络爬虫。

结果通过 main 已存在的 \`ToolRunResult\` Bridge 保存；\`candidate_cwe\` 仅表示初步分类，\`validated_vulnerability=0\` 除非后续受控验证阶段有独立证据。

## 5. A 与 B 如何共享而不互相阻塞

| 共用能力 | 负责人提供 | A 需要 | B 需要 |
|---|---|---|---|
| SourceUnit 与 commit/hash | 固定文件、路径、语言和完整性校验 | C/C++ 包含/宏上下文 | JS/ArkTS/IPC 入口上下文 |
| shared facts | 统一符号、函数、调用、guard 的**可选**表示 | 生命周期、类型、guard | 入口、权限、数据传播 |
| Detector v1 | 注册、异常隔离、Bridge | C++ detector | Interface detector |
| benchmark lab | 执行记录模板、公共 hash/覆盖验证 | 内存安全基准 | 授权/接口安全基准 |
| Review & Report | 候选关联合规、状态与输出 | 生命周期审查义务 | 权限与信任边界审查义务 |

需要跨语言桥边时，B 应先提出可选边模型，例如 \`source_symbol → bridge_export → native_target_symbol\`，但**不要未经批准强制所有检测器升级统一 IR**。没有确定映射关系则输出 unknown；主线负责人批准后再扩公共事实结构。

## 6. 迭代建议与失败止损

**迭代 0：1 个真实接口审计示例**。固定仓库及一个 commit，画出入口/权限检查/敏感调用的源码级结构，区分静态已证明事实与推测。

**迭代 1：1 个 detector + 3 类 fixture**。至少未保护候选、完整 guard 对照、相似但安全的反例；还要覆盖 AST 缺失/partial、无真实入口场景。

**迭代 2：历史修复对（如有）+ 独立 holdout**。用离线扫描工具作对照，说明自主算法相对基础模式的检出/误报与覆盖变化；没有真实修复对时只称原型测试。

**迭代 3：接入 main 当前组件**。与 A 的 C++ detector 用一个 ScanRequest、一个 Runner、同一报告输出；在确有桥/IPC 的当前 OpenHarmony 组件试运行，保留不适用或无候选的真实结果。

止损条件：若无法确认真实的信任边界或缺少可分析源码，不在这个接口上硬写漏洞规则，切换到公开可核验的另一组件；如果 Web 方向与赛题 OpenHarmony 源码关联弱，应优先做 IPC/权限而非扩大传统 Web 攻击面。

## 7. 权限、安全与评审规则

- 只审计明确授权的源码、固定本地代码快照；本阶段不调用在线目标、不主动请求服务或进行漏洞触发。
- 队友默认只在本地开发与保留原生研究数据，整理 patch/报告给负责人；由负责人决定远端分支、PR 和合并。
- 模块不独自引入新的 schema、修改公共 providers、批量复制外部工具实现或上传未经核对许可的第三方源码。
- 已知漏洞样本、人工标注、安全对照和测试集分割须明确；不能把修复后的代码无限外推为安全。
- 输出只说明能由源码和可追溯 Evidence 支撑的静态结论；如需更高安全结论，应在后续隔离的验证阶段完成。

## 8. B 每次交付的标准报告模板

~~~markdown
# Interface track handoff
目标仓库 / 固定 commit / profile：
真实入口 / source / guard / sink：
根因家族和 CWE（若仅候选，标注 provisional）：
公开公告与修复对（如无，明确 none）：
对照工具/规则/原生报告 hash：
自研检测算法与 OpenHarmony 专用建模：
已通过正例、修复后、相似安全对照测试：
独立 holdout 的真实结果：
失败/partial/缺失构建上下文：
单模块耗时与实际文件范围：
程序目录与 Detector v1 接口输出：
许可证及第三方来源：
下一次需要负责人提供的 shared fact：
~~~

**本方向的成功标准不是“找到 Web 漏洞数量”，而是产生可在 OpenHarmony 当前源码上独立运行、可解释、能接入统一引擎的专用接口安全检测模块。**
