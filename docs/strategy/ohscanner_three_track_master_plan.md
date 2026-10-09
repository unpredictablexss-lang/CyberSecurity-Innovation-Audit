# OpenHarmony 专用自研扫描器：三线并行研发总方案（2026）

> 文档性质：**下一阶段技术设计与团队执行约定**，不是已实现功能清单。
> 基线：PR #4 historical benchmark 已合并到 main；具体代码实现与现状以 \`PROGRAM_STATUS.md\` 和当前 GitHub 提交为准。
> 技术主张：**离线多工具实验 → 提炼算法与语义 → 自主实现 OpenHarmony 专用检测器 → 统一候选证据接口 → 当前源码扫描与评估**。
> 本项目限于授权安全研究、静态审计和竞赛评估；漏洞候选不能自动升级为已确认漏洞。

## 0. 决策结论

三个人可以并行，但不是“三人各写一套扫描系统”。采用 **平台主线（负责人）+ C/C++ 检测研究线（队友 A）+ Web/ArkTS/IPC 接口安全研究线（队友 B）**。在开发第一批算法之前，负责人先锁定输入、结果、版本、覆盖和测试协议，让两位队友交付“可装入同一引擎的检测模块”。

成熟工具（Semgrep/Cppcheck/Clang Static Analyzer/CodeQL/Joern）在 **research 实验环境**中用于比较能力、分析机制和检验改进；自研扫描器的正式运行路径默认**不按漏洞类型调用这些外部扫描器**。借鉴算法思想不等于直接复制实现，任何代码/规则复用须单独核对许可证、出处和赛题原创性要求。可复用 Tree-sitter/Clang 等基础解析能力，但检测策略、OpenHarmony 语义模型、归因、候选关联和报告由团队自主实现。

**第一阶段成果不是论文式工具排行榜；最终交付是可运行、可扩展、可解释的 \`OHScanner\` 自研检测引擎。**

## 1. 当前基础与未完成工作

已合并主线包括：四条固定 OpenHarmony 历史样本、own text/AST scanner、人工审查持久化、历史 benchmark、外部工具结果适配、ToolRunResult/ToolDiagnostic、root-cause hit matrix、summary report；这些是基础设施，不是对某工具最优的结论。

\`codex/cutils-component-pilot\` 是**尚未作为独立工程能力合入 main 的试点**：固定 \`openharmony/commonlibrary_c_utils\` 的一个当前版本（\`b807d3d...\`），轻量扫描范围 123 C/C++ 文件；另有 21 个 Linux host TU 的 Clang/CodeQL 试验。该配置不等于真实 OpenHarmony 产品构建；记录中的告警是候选而不是漏洞。**不将此分支整体 merge 入 main**，仅由负责人审查并迁移有价值的实现、测试与实验说明。

尚未完成：高质量跨漏洞家族实验集、安全对照、可复现且真实可比的工具能力评价、OHScanner 检测器插件契约和自主检测算法、当前组件上的候选复核和受控验证。上述均为计划，不得写入“已完成”一栏。

## 2. 最终系统与研究系统分离

~~~text
                          研究实验线（不属于生产运行依赖）
官方漏洞公告/补丁/源码 ---> S0-S3 漏洞修复对+安全对照
                                     |
                          可比范围的多工具 bake-off
                        Semgrep/Cppcheck/Clang/CodeQL/Joern
                                     |
                        根因命中/修复区分/误报/覆盖/成本
                                     |
                        方法卡与规则设计决策、保留测试集
                                     |
                                     v
+------------------------- OHScanner 自研运行时 -------------------------+
| L0 资产/版本固定 -> L1 AST/类型/编译上下文/语义索引                  |
|                          |                                          |
|            +-------------+----------------+                          |
|            v                              v                          |
| L2/3 自研 C/C++ 检测器        L2/3 自研 Web/ArkTS/IPC 检测器       |
| ownership/guard/bounds       entry/bridge/permission/source-sink     |
|            +-------------+----------------+                          |
|                          v                                          |
|  L4 统一候选 -> 覆盖状态 -> 根因关联/去重 -> 人工复核与证据包         |
|                          v                                          |
|  L8 JSON / Markdown / 可视化 / 性能与对照报告                       |
+---------------------------------------------------------------------+
                          |
               L5-L7 后续版本：受控验证、版本影响、修复重验
~~~

注意：不必一次完成全程序 CFG、跨语言污点分析或自动修复。所有能力需要用独立测试证据声明覆盖边界。

### 2.1 拟新增工程组织（不是已存在目录）

~~~text
research/
  corpus/                  # 公告清单、漏洞/修复对清单、来源与标注；不复制全量第三方源码
  experiments/             # 离线工具执行配置、对照、性能、能力矩阵
  methods/                 # 漏洞家族方法卡、算法假设、消融记录

src/
  ohscanner/
    frontend/              # SourceUnit/语言、AST/类型、编译上下文适配
    ir/                    # 版本化的语法/符号/调用/守卫等共享事实
    models/
      openharmony_cpp/     # 智能指针/Parcel/API/异步模型
      openharmony_web/     # ArkTS/JS、WebView/Native Bridge、IPC/权限
    detectors/
      cpp/                 # 队友 A 自研：null/lifetime/bounds 等
      interface/           # 队友 B 自研：JS-Bridge、IPC/permission 等
    integration/           # 插件注册、兼容 ToolRunResult 的适配
    analysis/              # 复用的有限数据流/guard/函数关系
    triage/                # 候选关联、人工审查、证据
    reporting/             # 当前组件审计报告
scripts/                  # 可复现研究任务和当前组件扫描入口
tests/
  contracts/              # 所有成员共用的契约测试
  detectors/              # 各模块正/负/保留测试
~~~

不要复制已有 \`src/parser\`、\`src/providers\`、\`src/benchmark\` 的全部代码。先写薄适配层，复用 main 现有实现；确有必要再按单独 PR 重构。已有 \`src/providers\` 仅负责**外部工具格式转换**，不能直接等同于拟建的**自研检测器插件**。

## 3. 三人职责、代码所有权和接口权限

| 角色 | 独占/主要负责 | 必须交付 | 不得私自改变 |
|---|---|---|---|
| 负责人 / 主线 | \`src/ohscanner/frontend,ir,integration,triage,reporting\`、CLI、通用测试、文档、main、性能预算 | 运行时底座、接口冻结、Mock Detector、覆盖状态、集成/CI、当前 c_utils 验收 | 自研检测器逻辑的实验结论不得替队友宣布；不能静默修改已冻结契约 |
| A / C/C++ 线 | \`research/corpus\` 中 native 子集、\`research/experiments/cpp\`、\`research/methods/cpp\`、\`src/ohscanner/detectors/cpp\`、对应测试 | 历史漏洞清单/修复对、安全对照、工具能力矩阵、方法卡、至少一个独立 C++ 检测器、可导入接口和回归测试 | 不改 CLI/全局 schema/providers 公共语义；不把工具警告判成确认漏洞 |
| B / Web/接口线 | \`research/corpus\` 中 interface 子集、\`research/experiments/interface\`、\`research/methods/interface\`、\`src/ohscanner/detectors/interface\`、对应测试 | 真实 OpenHarmony WebView/JS/ArkTS/IPC/权限攻击面清单、数据/安全对照、工具比较、至少一个自主接口安全检测器 | 不把通用 XSS/SQLi 规则直接宣称适用 OpenHarmony；不修改全局插件接口 |

共享文件由**负责人统一维护**；队友遇到通用字段缺口，提 \`contract-change proposal\`（用途、向后兼容、迁移、失败样例），而不是自行改 \`ToolRunResult\`。双方实验可复用相同脚手架和数据字典，但不能合并未经复核的标注，也不得互相覆盖实验资产。

### 3.1 队友 B 的真实适用范围

Web 线不是“对 OpenHarmony 全仓跑 Web 漏洞大全”。先证实实际存在的语言和信任边界，再选择适合静态检测的对象：

- JS/ArkTS 与 Native/JS-Bridge 的外部输入到敏感操作传播；
- WebView 的可控 URL、导航、页面暴露和消息处理；
- IPC/RPC 参数来源、调用者身份、权限检查到敏感系统操作；
- 文件/路径、命令、日志、网络调用中与上述入口实际可达的风险。

若目标仓库不存在某种攻击面，该漏洞类型标记 \`not_applicable\`，不得为了检测种类数杜撰目标。动态 Web 探测、主动攻击和未授权服务测试均不属于这个静态扫描分支。

### 3.2 队友 A 的第一批目标

优先选 **对象生命周期/同步** 与 **边界/长度/Parcel**，但检出方法仍由实验确定。现有 \`.reset()\` OH 规则过宽，不能作为 UAF 证明；Clang 在 \`parcel.cpp\` 的某条未初始化路径告警存在约束疑问，也不能直接升格为越界漏洞。提炼方向包括类型/所有权绑定、guard/同步上下文、长度范围及有限路径事实。

## 4. 接口先行：负责人先实现的公共契约

正式开发前冻结 \`docs/contracts/ohscanner_detector_contract_v1.md\`。拟定调用链：

~~~text
ScanRequest(target repo/commit/profile/scope)
  -> SourceUnit + shared facts (AST/符号/有限语义) + ScanContext
  -> Detector.detect(context, source_units) -> DetectorRun
  -> validate/provenance/status adapter -> existing ToolRunResult(v1)
  -> Evidence / triage / dedup -> report
~~~

**契约分两层**：当前存在的 \`ToolRunResult/ToolDiagnostic\` 是描述性报告 v1；\`ScanRequest/Detector/SourceUnit/DetectorRun\` 是需要新增的**内部插件 v1**。不允许仅凭新增文档宣称这些 Python 类已经实现。主线应先提供一个只对固定测试样例生成候选的 \`ExampleDetector\`，队友在未获得真实工程底座前可用同构 fixture 开发。

最低约定：

1. 输入固定 \`repository + commit + scope + scan_profile + source_hash\`；相对路径，不接受越界和指向未固定来源的文件。
2. 输出 \`candidate\`、\`evidence_type\`、\`rule_id\`、源码位置、可选 symbol、解释、证据来源与局限，不自动生成 \`validated_vulnerability\`。
3. 执行状态 \`completed/failed/blocked\` 与评估格状态 \`possible_hit/miss/unknown/not_applicable\` **绝对不是同一个字段**。未覆盖、解析失败、缺构建信息不能计为安全或扫描漏报。
4. 已归一化结果使用 \`ToolRunResult\` 的现有 schema_version=1，避免让 A/B 自己设计新 JSON 格式。新增定位信息等先放**自研插件内部对象或旁路证据包**，经统一 adapter 映射；不要擅自给既有 dataclass 传未知键。
5. detector 输出必须是确定性的、可单测、可重放的；扫描失败不阻断其它检测器，但必须在报告中保留失败原因。

## 5. 同一漏洞家族实验如何指导算法开发

详见 [漏洞数据集与工具实验协议](vulnerability_corpus_bakeoff_protocol.md)。总原则：

- 按官方公告/原始修复证据收集 2021–2026 年档案；**全量索引**不等于全量都可跑实验。
- 每个可用案例要固定 \`affected_repo + vulnerable/fixed commit + affected symbol + evidence/source\`，并设未参与规则开发的相似安全对照。
- 试验同时记录 **修复前命中、修复后是否消失、未见漏洞的对照上有多少误报、解析/编译覆盖、资源成本**。
- 同一引擎套不同规则不得假装是完全独立检测器。各工具声明 query/ruleset 版本；只有在根因覆盖可信的单元才能解释 \`miss\`。
- 按 root-cause family 总结“适合提炼什么”，不凭个别案例宣布某工具整体最优；正例少或标签不完整时报告原始事实，不伪造 Precision/Recall。
- 训练/设计、验证、保留测试按根因实例及项目/时间隔离，同一 CVE 的 backport/重复修复不得泄漏到测试组。

成果不是“排名表”本身，而是带论据的**方法卡**：参考技术机制、有效样本、失败/误报模式、OpenHarmony 专有语义差异、提出的自研算法、复杂度与实现成本、消融测试、许可证声明。

## 6. 五个开发里程碑与合并门槛

| 阶段 | 主线负责人 | A：C/C++ | B：Web/接口 | 阶段闸门 |
|---|---|---|---|---|
| M0 契约冻结 | 插件协议 v1、ExampleDetector、统一候选/覆盖测试 | 选 2 个根因家族，首批样本核验 | 选 1 个实际桥接或 IPC 攻击面、首批样本核验 | 两个 Mock 插件无需运行外部工具，即可生成同 schema 报告 |
| M1 数据与底座 | repo/commit/snapshot、scan profiles、frontend/IR 薄接口 | 公告索引、S2 修复对、安全对照、baseline 命中矩阵 | 攻击面清单、原始入口证据、相关样本及对照 | 固定来源可重跑；失败/不适用如实记录 |
| M2 首版检测器 | 注册器、单模块超时与错误隔离、报告/测试 | 1 个自研 C++ detector，正负对照测试 | 1 个自研 Interface detector，正负对照测试 | 不改共享接口即可独立挂载两个 detector |
| M3 改进验证 | 去重、审查、性能/消融报告、保留集评估 | 增强类型/guard/生命周期或边界语义 | 增强入口/权限/数据传播关系 | 有保留集和消融实验；不拿规则设计样本当成绩 |
| M4 当前组件集成 | c_utils 当前版本与第二组件试点、统一 CI、文档/演示 | 高价值生产候选上下文审查 | 选一个确实有 JS/IPC/Bridge 表面的现行组件 | 自研扫描结果可独立运行、可解释、可追溯；外部工具不作为运行依赖 |

建议将 M0/M1 作为第一个迭代；周期按真实依赖与团队进度确定，不预设“每周一定发现漏洞”。**先有一个可集成的精简 detector，再扩类型**，不要两位队友分别完成大而全的扫描器后才首次集成。

### 6.1 主线负责人今天即可做的工作

1. 将插件契约文档作为三人唯一共享真源（schema、路径、错误语义、回归测试、演示命令）；落实 ExampleDetector 和一份 \`fake\` 输入 fixture。
2. 从新 \`main\` 建自己的 \`feat/ohscanner-core\`，只实现 SourceUnit、插件注册、报告桥接、scan profile、公共单测；保留之前 \`feat/cutils-current-scan\` 的组件试点工作为独立小 PR，避免将平台/实验/组件三项塞进同一 PR。
3. 建立工程测试：输入提交不匹配、路径越界、宏/AST partial、缺 symbol、detector crash/timeout、重复候选、报告来源绑定与排序稳定。
4. 先把 A/B 的 Mock 实现接入同一 CI；第 2 次迭代再把真实检测逻辑替换进去。
5. 统一输出 \`JSON/Markdown\` 和候选审查模板，默认 \`validation_status=not_run\`，不生成未经验证的漏洞报告。

### 6.2 A / B 今天即可做的工作

- 在**本地**独立工作分支准备：目标清单 → fixed pair → 基准工具原始结果 → 标注/排除表 → 方法卡 → detector 单元测试。
- 至少提交一组“能命中开发集正例 + 不误报指定安全对照”的契约 fixture，另列出完整保留测试方案；不得用单组演示宣称准确率。
- 需要通用 IR 新字段时先申请；尚未冻结前采用 \`SourceUnit\` 样例与规范中的 bridge fixture，不自行写全新的 CLI。
- 报告若使用第三方规则/实现，记录具体 commit、许可证、保留必要署名以及修改范围。

## 7. 工程协作与 Git 权限约定

**只有负责人决定何时将队友代码上传到公共远端、何时创建 PR、何时合入 main。** 队友默认在本地开发，提交本地 commit / \`git format-patch\` / 代码包与实验报告给负责人审查；未经负责人确认不主动 push 到仓库（即使拥有写权限）。已存在的 \`codex/cutils-component-pilot\` 保留作参考，不代表认可全部实现。

推荐分支（负责人创建正式远端分支；队友可在本地用同名或 personal 名称工作）：

- \`feat/ohscanner-core\`：负责人，核心接口/引擎与报告。
- \`feat/oh-vuln-corpus\`：A 主持的历史公告与修复对（可将原始大文件放本地/制品库）。
- \`feat/cpp-detectors\`：A 的 C/C++ 检测器。
- \`feat/oh-interface-detectors\`：B 的 Web/ArkTS/IPC 专用检测器。
- \`feat/cutils-current-scan\`：负责人，对固定当前组件的集成验证。

一个 PR 只做一个垂直、可回滚改动；不因成员身份绕过负责人复核。队友交付必须附：基线 SHA、改动文件、算法与局限、编译/运行命令、通过/失败测试、实验/来源 hash、例子和负例、许可证说明。**负责人从 main 挑选代码迁移或 cherry-pick，避免直接并入另一个包含旧历史提交的巨大分支。**

共享接口调整用 \`contract-v2 proposal\` 单独审查；已有 v1 能兼容时不新增公共字段。任何自研 detector 默认不得访问网络、不得修改受检源码、不得对第三方服务开展主动攻击或漏洞触发。

## 8. PR 和验收一票否决条件

- 无固定提交或来源哈希；修复前/后证据混淆；不同扫描范围的数值被直接当成工具优劣；
- 输出把工具 warning、possible_hit、弱结构匹配解释为确认漏洞；
- 解析/工具失败却报告为 \`miss\`、\`safe\`、\`zero vulnerabilities\`；
- 未经批准改变 \`ToolRunResult\` v1、共用 IR、CLI 或公共规则文件；
- detector 不能通过接口单测，需强制拉起外部大扫描器才能跑正式路径；
- 用开发集本身当独立测试成绩，或未审查第三方代码/规则许可证；
- 提交第三方 OpenHarmony 全量源码、数据库、临时编译产物、密钥或未经批准的运行时触发脚本。

合并通过后的演示：同一主线 \`ScanRequest\`，加载独立的 C++ + Interface 两个自研插件，在带来源哈希的代码快照上返回规范化候选和完整覆盖状态；至少包含一组独立测试、负例和审查证据。**零个确认漏洞仍可以是合格的工程阶段交付，但不能宣称达成发现真实漏洞的最终比赛目标。**

## 9. 与旧文档的关系

- \`docs/architecture_2026.md\`：L0–L8 最终系统目标；本文件明确下一阶段自研检测器的研发与组织路径。
- \`docs/strategy/team_parallel_multi_scanner_plan.md\`：前一阶段多工具基础设施/分工历史，不再把外部工具 adapter 作为最终核心产品。
- \`docs/contracts/ohscanner_detector_contract_v1.md\`：下一阶段最先冻结的插件协议。
- \`docs/strategy/vulnerability_corpus_bakeoff_protocol.md\`：如何构造漏洞与安全对照数据，并公平评价。
- \`docs/strategy/oh_web_interface_track.md\`：队友 B 的 Web/IPC 研究范围、交付样例与排除条件。

**状态声明：本文件只是项目决策和计划；未写出的算法、接口及样本数量均不得视为已开发或已验证。**
