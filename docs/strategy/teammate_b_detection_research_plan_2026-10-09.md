# 队友 B：面向高检出率的 OpenHarmony 接口安全研究与开发方案

> 日期：2026-10-09（Asia/Shanghai）。性质：源码与官方公告调研、算法设计和待执行实验计划。
> 工作分支：`feat/oh-a-interface-detectors`；阅读基线：`dcd9629f50a34545d75abc92c0a16c79723197db`。
> 本轮没有实现检测器、运行漏洞对比实验或验证新漏洞。`validated_vulnerability=0`。

## 1. 先确定方向：两类主攻，一类扩展，首版只完成一个检测器

建议 B 的方向定为：**OpenHarmony 外部接口到敏感能力的信任边界分析**。

| 顺序 | 家族 | 具体子问题 | 为什么选 | 交付节奏 |
|---|---|---|---|---|
| P0 | IPC/服务接口授权缺陷 | 缺少检查、检查结果未执行、检查错主体/对象、分支绕过检查 | 多年官方案例，鸿蒙语义明显，可复用同一授权状态分析 | 第一个完整 detector |
| P1 | 路径穿越与越权文件访问 | 外部路径到文件能力、规范化与目录约束错配、对象归属缺失 | 有 appspawn/nwebspawn、request_request 历史公告；适合污点与约束传播 | 第二个 detector，建立在首个闭环之后 |
| P2 | WebView/JS/ArkTS 桥接信任边界 | 不可信页面调用敏感桥方法、来源校验不足、导航后权限残留 | 符合 Web 特长，与前两类共享入口/身份/资源模型 | 有真实源码、语言前端和案例后扩展 |

**首版收敛到“一个服务、一组 transaction、一类授权义务”**，例如服务端接口是否对真实调用者执行已知所需权限检查。第二轮再扩展对象归属、路径与桥接。这不是把三类完整检测器同时开工。

命令注入、SSRF、XSS、SQLi、TLS 错配、敏感日志暂列候选池。只有找到真实入口、代码和对应安全语义才升级为主攻。`fileAccess(true)`、缺 HTTP 安全头、使用 `loadUrl` 都不能单独等同漏洞。UAF/边界/Parcel 长度分析仍由 A 主攻；B 追踪 Parcel 中的身份、对象 ID、路径等信任属性，不重复写内存检测器。

高检出率来自**缩小适用范围、补齐真实 API 模型和路径关系、逐个解释漏检**，没有一种通用算法能事先保证所有鸿蒙漏洞都高召回。

## 2. 阅读队长代码后的判断

已阅读根 `AGENTS.md`、`PROGRAM_STATUS.md`、架构、三线总方案、B 任务书、Detector v1 设计、漏洞库与 bake-off 协议，以及 `src/parser/ast.py`、`src/core/ast_scanner.py`、`src/providers/base.py`、`src/benchmark/tool_result.py`、`src/benchmark/root_cause_matrix.py`、`src/evidence/from_tool_result.py` 和工具对比 README。

| 目前代码事实 | 对 B 的影响 |
|---|---|
| 当前分支等于 main；已有 Tree-sitter C/C++ 函数/调用/变量索引 | 可以先选 C++ 实现的 IPC 接口；Web 背景不等于只能检查 JS 文件 |
| 当前 AST scanner 主要枚举危险调用；没有 CFG、符号绑定、污点传播和 guard 支配证明 | 不能把“同一函数出现 Verify… / open”解释成权限或路径安全 |
| providers 是保存结果的格式适配器 | 实验 runner 和正式 detector 分开；adapter 不负责真正检测 |
| root_cause_matrix 按文件/符号区域产生 possible_hit | 现有矩阵适合第一层对照，不能直接证明抓到了授权错误或计算真阳性 |
| ToolDiagnostic 没有 source/guard/sink/path 字段 | 证据链放旁路 trace，映射到既有字段；不擅自改公共 dataclass |
| 本分支没有 `src/ohscanner` 的运行时代码 | 本轮文档不能给出可 import 的新 detector 或虚构运行命令 |

另行只读检查了 `origin/feat/ohscanner-core` 的 `3b437e46c218093d5405b3928f10ed4e88966b95`：已存在 contracts、runner、frontend、facts 和显式 detector catalog。其 C/C++ facts 仍主要是语法摘要，`guards=[]`、调用目标未解析；JS/TS/ArkTS 仍按 text-only / not_run 索引。**“核心分支有代码”不等于“本分支已有完整语义前端”。** 本轮没有合并或复制这些公共文件。

也阅读了 `origin/codex/vulnerability-dataset-survey-20261009` 的数据集调研报告。通用 C/C++ 漏洞集可补充算法性质测试，但不能取代本方向的 OpenHarmony 授权/桥接标签；告警修复任务不能直接当确认漏洞。

因此第一轮要向负责人提出最小事实需求：AST 节点引用/稳定符号 ID、条件与分支边、提前返回、实参位置、一跳调用映射；由负责人提供或批准兼容扩展。缺这些时先交攻击面清单和语法候选原型，不用正则伪装完整 CFG。

## 3. 历史案例：已有官方依据，但尚未组成可跑的漏洞基准

本轮克隆并读取官方 `openharmony/security`，固定公告快照为 `ceaf1b4fbe38e46cd18bfcffd7353516bdc34227`。下列来源均是**公告级 S0 线索**，PR 是公告提供的修复入口；尚未核验其固定修复前后 SHA、受影响函数和完整构建条件。没有凭标题猜补丁根因。

| 官方记录 | 组件/方向 | 能支持什么选题判断 |
|---|---|---|
| CVE-2022-38081 | security_access_token / tokensync | 真实分布式调用者权限边界；公告另有前置权限条件，不能假设普通应用直接可用 |
| CVE-2022-38064 | window_window_manager | 服务端调用者权限检查是历史问题 |
| CVE-2022-38700 | multimedia_camera_framework | 相机服务调用权限值得纳入建模 |
| CVE-2022-42488 | startup_init_lite / param 服务 | 缺少权限校验；具体权限和路径仍需补丁核验 |
| CVE-2024-38382、CVE-2024-12082 | ability_ability_runtime | 能力服务授权问题有多个历史记录 |
| CVE-2024-21816、CVE-2024-39612 | resourceschedule_background_task_mgr | 两条公告指向同一 PR #470，可能相关，必须先去重，不能当两个独立测试事件 |
| CVE-2024-39775 | communication_netmanager_base | 网络管理的授权与信息访问边界 |
| CVE-2025-26693、CVE-2025-27563 | security_access_token | 新一些的授权案例，适合作为后续样本池 |
| CVE-2025-26691、CVE-2025-27247 | telephony_call_manager、distributeddatamgr_pasteboard | 授权与敏感数据返回相关，但不预设都是同一种“漏写 VerifyPermission” |
| CVE-2025-6969 | ability_ability_runtime | 权限绕过导致 DoS；权限缺陷不一定表现为数据泄露 |
| CVE-2026-50001 | communication_bluetooth | 近期权限绕过记录，可候选作时间保留集；本轮已读公告，不能再称完全未见测试数据 |
| CVE-2022-43451 | startup_appspawn / appspawn、nwebspawn | 路径穿越与沙箱边界的明确历史依据 |
| CVE-2022-43449 | request_request / download_server | 任意文件读取的历史依据；具体是路径规范化还是授权根因需看补丁 |

来源按月份：[2022-09](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2022/2022-09.md)、[2022-10](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2022/2022-10.md)、[2022-11](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2022/2022-11.md)、[2024-03](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2024/2024-03.md)、[2024-09](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2024/2024-09.md)、[2024-12](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2024/2024-12.md)、[2025-06](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2025/2025-06.md)、[2025-09](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2025/2025-09.md)、[2026-08](https://github.com/openharmony/security/blob/ceaf1b4fbe38e46cd18bfcffd7353516bdc34227/zh/security-disclosure/2026/2026-08.md)。

随附 [S0 种子索引](../../research/corpus/interface/official_advisory_seeds_2026-10-09.json) 保存 17 条公告记录的来源、公告哈希和修复链接，全部明确标为不可用于准确率实验。17 条记录不是 17 个已核验独立根因，不是 17 个 S2 样本。

两点取舍：

1. 权限类已有跨年份、跨组件来源，最适合第一主线；但标题相同不表示检测机制相同，必须按补丁再拆子家族。
2. 路径类本轮只确认两条较早的明确公告，暂不足以声称该类高召回。WebView 公告常涉及上游 Chromium，不能把 V8/Chromium 内存安全修复拿来给 JS 桥 detector 凑命中数。官方 [web_webview README](https://github.com/openharmony/web_webview) 也说明了其 Chromium/CEF 关系。

## 4. 第一类：IPC/服务接口授权缺陷怎样检测

### 4.1 建模的是“谁对哪个对象做什么”，不是找一个函数名字

为每个入口建立：

```text
真实暴露入口/transaction
  → 可信调用身份（token / UID / PID，含身份来源）
  → 请求对象（taskId / userId / resourceId，含外部可控来源）
  → 授权策略与返回值检查
  → 敏感操作（读数据、改资源、启动能力、注册回调等）
```

待核验的 OpenHarmony 模型项包括 `OnRemoteRequest` 分发、`IPCSkeleton::GetCallingTokenID/GetCallingUid`、`AccessTokenKit::VerifyAccessToken`、各服务自定义校验包装器等。这里是检索入口，**不是声称所有版本具有同一签名、返回值或相同权限规则**。每个实际 model 条目必须绑定仓库、版本、精确符号、参数索引、返回值语义和源码依据。

`ReadInterfaceToken`/descriptor 匹配通常用于协议接口识别，不能自动等价调用者授权；客户端 proxy 有权限检查也不能替代可被直接调用的服务端检查。进程隔离、服务注册 ACL 或内核策略可能提供其他保护，缺此上下文时必须列为未知。

敏感操作的策略来源必须是文档、服务规范、核验后的历史补丁或人工审核。只因邻近函数有检查，不能确定本函数也必须同样检查。

### 4.2 推荐算法：局部 CFG + 授权状态传播 + 一跳摘要

抽象状态可表示为：

```text
(entry_id, caller_identity, resource_identity,
 checked_predicates, branch_constraints, unresolved_edges)
```

一个授权事实是 `Authorized(subject, action, object, context)`，不能只存 `has_permission=True`。

步骤：

1. 从已核验的 transaction 映射或服务注册表定位 handler；仅看函数名时标 `entry_unverified`。
2. 用 AST 绑定变量、实参和分支，建立局部 CFG；先支持 if/else、switch、return、直接调用，其他语法列覆盖不足。
3. 检查函数调用只产生“检查已发生”事实；必须验证返回值，并只在成功分支增加授权事实。
4. 检查失败后继续执行、只打日志、不返回、条件写反，均不能作为安全屏障。
5. 到敏感 sink 时核对授权主体、权限种类、对象归属以及操作类型；检查别人 token 不能授权当前 caller。
6. 对直接可解析的一跳包装器生成摘要：返回值语义、授权前置条件、是否终止、身份改变、敏感副作用。调用摘要需绑定实参；不在全仓无限展开。
7. 若在建模图中存在缺少所需授权的路径，输出候选及路径；静态路径可能不可行，不能直接当真实可利用路径。

可先使用 worklist 有限状态数据流。合流点的“必然已检查”事实取交集；不同分支使用不同但都合法的授权方案时，简单交集会丢信息，应保存有界析取状态/策略公式。`permission_A OR trusted_UID` 与 `permission_A AND owner_match` 的逻辑不能混用。

初版路径状态和调用展开必须有预算；预算耗尽、递归、虚调用未解析、宏缺失、跨异步回调等返回 `unknown/partial` 语义覆盖，不能判安全。循环使用单调有限格求不动点；丢失精度不能反过来成为“已保护”的证据。

### 4.3 必须处理的易错例

以下 `CheckP`、`Sensitive` 仅为合成伪代码，不是真实 OpenHarmony API：

```cpp
// 无效：检查失败也继续做敏感操作
if (!CheckP(caller)) { LogDenied(); }
Sensitive(resource);

// 受限安全对照：前提是 CheckP 检查了正确主体及所需策略
if (!CheckP(caller)) { return DENIED; }
Sensitive(resource);

// 检查了错误的主体：requestToken 来源于客户端
if (!CheckP(requestToken)) { return DENIED; }
Sensitive(resource);
```

还需覆盖：忽略返回值、检查在 sink 后、switch 的默认分支漏检查、fall-through、同名变量遮蔽、身份 reset/restore、检查后对象 ID 被重赋值、已授权调用者访问别人的 task、同一入口部分分支豁免。

身份变化、对象重绑定后，应失效相关授权事实；跨异步上下文没有可信身份传递证据时保留未知。系统 UID/系统应用判断不自动替代对象归属和具体操作权限。

### 4.4 提高检出率最值得做的事

优先补齐服务端 transaction→handler 映射和校验包装器摘要，再做有限跨函数；否则漏掉入口或 wrapper，再复杂的求解器也找不到根因。授权分析还必须追踪**控制依赖**：敏感无参操作也可能需要权限，不能要求外部数据一定作为参数传到 sink 才产生候选。

## 5. 第二类：路径穿越与越权文件访问怎样检测

### 5.1 两种义务要分开

- **路径约束**：最终访问对象是否位于允许目录/命名空间。
- **授权约束**：当前调用者是否有权访问该文件、任务、FD 或 URI 对应对象。

路径经过规范化不代表调用者有权限；目录内的其他用户文件也可能越权。任意文件读取公告不应未经补丁核验就全部贴 CWE-22。

入口可包括已核验的 IPC 路径参数、下载任务配置、URI、JS 桥参数、请求拦截器输入；sink 可包括确实执行文件访问的 open/fopen、文件复制/删除、解压目的地、沙箱挂载等。每个 sink 解析真实参数位置和读/写/创建模式，不用整行字符串搜索代替实参分析。

### 5.2 推荐算法：来源污点 + 路径属性抽象解释

对路径值保存属性，而不是一次 `sanitize()` 就清除所有污点：

```text
origin / decoding_stage / normalized_value_id
allowed_root / confinement_proof / object_owner
symlink_policy / checked_value_id / used_value_id
```

步骤：

1. 追踪输入经过赋值、拼接、decode、URI 解析、包装器、返回值及一跳参数传递的关系。
2. 标记规范化函数的输出值和失败语义；规范化只减少路径歧义，不自动证明目录限制。
3. 识别基于最终值的目录边界校验。字符串前缀 `/data/app` 不能单独证明位于 `/data/app/`，要考虑同名前缀目录。
4. 校验失败必须退出危险路径；校验的路径必须与实际使用值相同。检查后再次解码、拼接或重赋值会使原证明失效。
5. 对实际目标检查授权：caller、任务所有者、URI/FD 的授予来源；已有授权 FD 不应自动当作任意路径读漏洞。
6. 符号链接、创建时尚不存在的最终文件、检查与访问间的目录变化，超出纯词法分析能力时保留专门未知项。不能把 lexical normalize 或 realpath 单独当万能屏障。

descriptor 锚定且限制解析逃逸的访问可作为更强防护模型，但必须检查目标平台真正支持的 API/flag 和全部路径组件；只出现 `openat` 名字不算证明。

必备对照：常量文件；外部输入只是日志；合法目录内文件；错误前缀判断；检查原值、使用解码后值；归一化成功但未限定目录；只打日志的检查；经过审核的固定资源映射；符号链接未知；不同租户/用户同目录对象。

针对高检出率，主要突破是：**不把“看起来像 sanitizer 的调用”错误当成安全、不断开包装器上的污点、区分检查值与使用值**。路径竞争和完整文件系统状态留到后续受控验证，首版不承诺静态证明。

## 6. 第三类：WebView/JS/ArkTS 桥接怎样扩展

这一类先做攻击面索引，满足条件再写 detector。官方 [Web 组件跨域资源说明](https://raw.githubusercontent.com/openharmony/docs/master/zh-cn/application-dev/web/web-cross-origin.md) 展示了请求拦截、固定资源映射以及 `setPathAllowingUniversalAccess` 的约束；这证明有值得建模的 API 和边界，不证明其示例存在漏洞。

推荐算法：**桥注册/路由关系图 + 来源约束 + 有限污点传播**。

```text
页面/消息来源
 → 所属 WebView/controller 实例
 → bridge 注册的对象、方法和生效条件
 → ArkTS/JS handler
 → 可核验的 native 映射（若存在）
 → 文件/网络/系统能力 sink
```

需要按目标版本核验 `javaScriptProxy/registerJavaScriptProxy`、消息回调、`loadUrl`、导航事件、请求拦截、删除代理等实际 API，索引暴露的方法列表。只扫描全局 `loadUrl` 和全局 proxy 的共现会把不同实例串起来。

来源策略应基于规范 URL 的 scheme/host/port 等目标允许项；包含子串不是可信 origin 证明。页面 JSON 自称的 origin/token 不是引擎提供的可信来源。主页面可信也不能自动证明所有 frame、后续导航和消息来源可信，具体语义需版本文档/实现核验。

候选分三种解释：

1. 不可信来源是否能到达暴露的敏感方法；
2. 来源检查是否覆盖对应 handler 到 sink 的路径；
3. 页面/实例状态变化后是否仍使用旧的授权事实。

JS→ArkTS→native 只有注册表、路由或精确绑定证据时连边；不能靠同名函数猜跨语言映射。没有前端时只报告 text inventory，不能标完整 AST 或 dataflow。无敏感能力的桥、可信固定本地资源映射等必须作为负例。

这一家族目前缺少本轮核验的第一方历史 S2 样本和可用 ArkTS 语义前端，故不与 IPC 主线争第一轮资源。其页面 XSS、桥能力暴露、URL 请求权限是不同命题，不能混成一个“WebView 漏洞”。

## 7. 历史库怎么建设：从索引变成可验证样本

按队长协议走 S0→S1→S2→S3，不从 CVE 标题直接生成真值：

1. **S0 公告索引**：记录原始来源、公告发布日期/更新日期、CVE、组件、版本、修复入口；区分第一方与上游依赖。随附 JSON 是这一级。
2. **S1 修复调查**：打开真实 PR/diff，找实际合并/修复提交；解决链接迁移和多次补丁，保留失败原因。
3. **S2 根因核验**：固定受影响版本与修复 SHA、文件、符号、入口、保护义务、实际修改的性质；核对受影响代码而非机械用 `fix^1`。
4. **S3 分析环境**：补依赖、宏、构建/解析范围与原生日志；记录工具实际覆盖，不能用无头文件的成功退出代表分析完整。

建议首批预算是 6–10 个可核验接口授权实例和 2 个路径实例，达不到就按实际数量报告。每例至少配：目标修复后版本、一个结构相似且经过指定性质审查的安全对照。修复后只标“该目标性质已修复”，不标整个函数/项目安全。

每个实例建立义务表：`entry / subject / action / object / policy / guard / sink / patch_change / unresolved`。权限绕过若实质来自生命周期/反序列化内存错误，交 A 或标本 detector 不适用，不强行用缺授权模型解释。

按 CVE/补丁事件/近克隆/回移修复分组，修复前后同组，相关公告同组。建议开发/验证/保留按根因事件划分并辅以跨服务、时间切分，不能随机拆同源函数。已看过的本轮公告不能冒充完全盲样本；若留作 holdout，须明确“已见公告、未见源码/补丁”，更严格的测试由其他成员封存新实例。冻结后再揭示源码并执行；不要根据保留集结果反复调规则。

## 8. 多工具实验：借鉴机制，正式扫描自主实现

### 8.1 第一轮只选两个有效基线，第三个用于解释路径

| 工具/profile | 适合比较的机制 | 本方向必须补的内容 | 使用限制 |
|---|---|---|---|
| Semgrep CE / 固定通用规则 | API 模式/简单局部污点 | 真实入口、guard、sink、参数位置 | 记录 CE/Pro；不能把 Pro 跨函数结果说成 CE 能力 |
| Semgrep CE / OH 模型规则 | 专用 wrapper 和源/汇识别 | 与自研同源的设计集知识 | 与通用规则分列，同一引擎不是独立投票 |
| CodeQL C++ / 固定查询 + OH model | 跨函数数据流、身份/对象数据来源、guard 条件 | 真实构建、权限策略、包装器摘要 | 没有相关查询不代表“工具漏掉权限漏洞” |
| Joern / 对应的 CPG 查询（可选） | 入口—调用—敏感能力关系及控制依赖 | 专项查询与准确解析覆盖 | 不能复用现有 nothrow 查询来评价权限/路径能力 |
| ClangSA / Cppcheck（辅助） | C++ 路径、基础质量问题 | 可适用的具体 checker | 通用内存 checker 不是授权 oracle；无专项能力不硬排召回 |
| ZAP/Nuclei/RESTler/Schemathesis | 有真实 HTTP/OpenAPI 目标时的动态补充 | 运行服务、协议与状态上下文 | 不能扫描 IPC 源码并声称覆盖权限；不属于本轮静态主线 |

方法参考：[CodeQL C/C++ 数据流](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-cpp/)、[CodeQL guard 分析](https://codeql.github.com/docs/codeql-language-guides/using-the-guards-library-in-cpp/)、[Semgrep 分析术语](https://semgrep.dev/docs/writing-rules/terminology)。工具能力和具体许可/版本以实验时的官方文档及锁定版本为准；本轮没有安装运行上述专项配置。

### 8.2 单个实例的实验顺序

```text
固定修复对 + 指定性质负例 + 同范围清单
 → 固定工具/规则/query/模型/配置/资源预算
 → 原生输出、退出码、解析/构建覆盖、耗时/RSS、哈希
 → 既有 adapter → ToolRunResult
 → 原矩阵 possible_hit/miss/unknown/NA
 → 人工核对是否真的关联到目标主体/对象/guard/sink
 → 修复区分与负例分析 → MethodCard → 自主实现 → 保留集
```

先完成 1 个真实修复对的端到端实验，再扩样本。某工具“报了很多”不能决定采用它。对每个漏检标原因：入口未识别、wrapper 不透明、对象身份丢失、guard 极性误判、调用目标未知、配置缺失、根因不适用、算法确实无能力。

借鉴模式：Semgrep 的高效候选定位、CodeQL 的 source/sink/额外传播边/屏障思想、路径分析的分支与摘要。自研部分重点在 OpenHarmony 主体—能力—对象模型、检查有效性和补丁义务迁移，不复制成熟工具内核。复用任何代码/规则前逐项审查许可证和赛题原创性；参考算法思想不等于规则代码可随意复制。

## 9. “缝合”怎样成为有证据的改进

建议创新假设是：**历史补丁提炼安全义务，再用鸿蒙语义模型与有限程序分析检查这些义务是否满足。**

例如补丁增加检查，不能只抽象成“多了一个 Verify 调用”，应记录：

```text
在敏感 action 前，调用主体必须满足 policy；
检查必须针对当前 subject / object；
失败路径不能到达 sink；
检查后 subject / object / path 不得变化使证明失效。
```

自研检查其他位置的是这组性质，而不是相似 token。候选产生可以并联保留：已知模型、历史义务相似候选、同服务策略不一致候选；后两类只增加调查入口，不凭相似度判漏洞。

必须做以下消融，且共享同一冻结样本/知识预算：

| 组 | 包含内容 | 检验的假设 |
|---|---|---|
| B0 | API/语法模式 | 仅按名称能做到哪里 |
| B1 | B0 + OH 入口/权限/对象模型 | 漏检是否主要来自领域模型缺失 |
| B2 | B1 + 有效 guard / CFG / 有限状态 | 能否减少伪 guard 造成的漏检和安全对照误报 |
| B3 | B2 + 一跳摘要 | 能否抓到 wrapper 隐藏的关系，成本增加多少 |
| B4 | B3 + 历史补丁义务迁移 | 在不同服务/重构/等价防护上是否真正增加有效根因 |

还需与“成熟工具 + 相同 OH model”的强基线比较，避免只打赢缺知识的默认规则。若没有优势，应报告模型贡献或工程可解释性，不能预写算法胜出。

## 10. 针对“检出率非常高”，具体用什么算法

优先组合是：**AST/符号绑定 + 局部 CFG + 有限抽象解释 + 一跳函数摘要 + 鸿蒙专用模型**。

| 技术 | 建议阶段 | 解决的问题 | 不应期待 |
|---|---|---|---|
| AST 模式/索引 | 起步 | 定位真实 API 与实参、暴露入口 | 单独证明授权/路径安全 |
| CFG + must/may facts | 第一 detector | 分支、检查失败退出、检查顺序 | 自动理解所有策略与系统边界 |
| 有限抽象解释 | 第一/第二 detector | 授权事实、主体/对象/路径属性的传播与失效 | 完整文件系统、所有别名/并发状态 |
| 调用摘要、受限上下文敏感分析 | 局部闭环后 | wrapper 和一跳跨函数 | 无限全程序跨语言分析 |
| IFDS/IDE 思想 | 稳定模型后的可选升级 | 适合有限、可分配的数据流事实传播 | 自动解决所有非分配授权逻辑和别名 |
| SMT 可行性检查 | 后期少量热点 | 排除可表达条件下的不可能候选路径 | 对未建模外部调用给出可靠安全结论 |
| GNN/Transformer/LLM | 非首版核心 | 补丁阅读、候选说明、模型建议或后期排序 | 小样本训练就证明域内高召回 |

IFDS 要求适用的问题满足有限事实集合、流函数对合流运算的分配律等条件，不能仅因名称高级就强行套在全部授权策略上；参见 [Reps、Horwitz、Sagiv 的原始论文摘要](https://research.cs.wisc.edu/wpis/abstracts/popl95.abs.html)。SMT 的 `unknown/timeout` 不能作为反证；未建模调用也不能被约束成“不会出错”。

从投入收益看，最先做模型和局部 guard，其次摘要，最后再考虑求解器。当前最大的瓶颈是**真实样本、入口覆盖、共享事实缺口**，不是缺深度学习模型。

候选排序可以降低审核成本，但不要直接截断低分候选后声称扫描高召回。保留全量候选，单列 Top-K；抽查低优先级结果以检查筛选损失。模型版本、缓存键应包含源码/构建 profile/摘要依赖，防止复用旧事实。

## 11. 怎样证明高检出率，而不是用漂亮百分比误导

现有 `possible_hit` 仅代表区域重合，继续保留原语义。另用审核记录确认是否实际指出目标的错误主体、缺授权路径或错误路径约束；没有这步不赋 TP/FN。

对未来合格的独立标注集，预先定义统计单位为独立根因事件：

```text
N = 冻结的合格阳性实例数
C = 完成相关语义分析的阳性实例数
D = 其中经审核真正指出目标根因的实例数
U = 未覆盖/失败/未决实例数

覆盖 = C / N
条件检出率 = D / C
全计划检出产出 = D / N（未知项没有偷偷从分母消失）
```

审核完成时，已覆盖但未指出目标根因才可成为 FN；`unknown` 单列，不冒充 FN/TN。若 U 包括全部未决项，可补描述性检出区间 `[D/N, (D+U)/N]`，但这不是统计置信区间。未来正式 Recall 须满足明确标签和覆盖资格，不能将本轮 S0 索引直接作分母。

安全对照 FPR 用指定性质的可信负例计算 `FP/(FP+TN)`；修复前后区分只检查对应根因告警，不能要求 fixed 所有告警清零。当前真实代码无完整标签，只报候选、覆盖、人工审核有效率/时间和未知项。

可先设**内部目标而非成绩**：在充足独立保留集上，重点子家族条件检出率 ≥90%，指定性质负例 FPR ≤10%，同时相关语义覆盖 ≥90%；分别报告每类及宏平均，不能让大量简单授权样本遮盖路径类差表现。冻结前约定阈值，未达标就缩小能力声明或修正方法。

样本少时只报原始计数和失败分析。即使 30/30 命中，95% Wilson 区间下界约 88.6%；100/100 才约 96.3%。这些只是统计示例，不是项目结果，也不是建议通过重复变体凑样本。所有 CVE backport、近克隆和合成变体必须防止伪独立。

## 12. 本地开发框架与阶段验收

建议新增文件仅位于 B 范围，以下均为待开发路径：

```text
research/corpus/interface/                 # S0-S3、分组与保留清单
research/experiments/interface/            # 离线 runner / 原生报告引用
research/methods/interface/                # 每类方法卡、消融和漏检分析
src/ohscanner/models/openharmony_web/       # 固定来源的入口/主体/策略模型
src/ohscanner/detectors/interface/          # permission / path / bridge
tests/detectors/interface/                 # 正例、fixed、安全、unknown
docs/reviews/interface_attack_surface/     # 固定版本入口证据
```

先对接负责人认可的核心版本，不整体合并 A 分支，不复制 contracts/runner/frontend/CLI。不因为本分支缺核心就另写全套扫描框架。需要公共语义扩展时给出最小事实提案和反例，由负责人维护。

### 第一迭代：一个真实权限修复对

1. 从 ability_ability_runtime、security_access_token、后台任务服务中筛一例公开可取的修复；优先根因简单、源码和依赖完整的实例，不仅按严重度挑选。
2. 固定入口—主体—策略—敏感操作的源码位置；把公告升级为 S2。两个工作日仍取不到可信修复对就切换候选服务。
3. 固定 Semgrep 模式/OH profile 与 CodeQL 专项查询，先跑该修复对和安全对照，保存原生证据；没有相关 query 就记录能力缺口。
4. 写 MethodCard，明确现有工具漏了什么、为何需要自主改进。没有实验之前不宣称已找出盲点。
5. 在 owner 的共享事实下实现局部授权检测器，先覆盖分支和返回语义，再加一跳摘要。
6. 通过合成反例与真实修复对后，冻结版本，进入独立保留测试。

### 第二迭代：扩大服务与路径家族

扩展不同服务的 wrapper/对象归属模型，保留真实失败；路径例若可升级 S2，再共享传播与 guard 设施，实现路径属性 detector。路径真值不足时只称原型，不拿合成样例宣传真实高检出率。

### 第三迭代：桥接条件成熟再进入

负责人提供可验证的 JS/ArkTS 语法与桥边事实后，完成一个 controller/一组 proxy 方法的攻击面图；有可信案例和负例再集成。若底座仍 text-only，就继续 IPC/路径，避免把一周用在不具备解析条件的方向。

### 每次交付必须有

- 基线 SHA、模型/检测器版本、实际文件范围、复现命令；
- 真实正例/fixed/相似安全对照与来源；合成样例明确分开；
- 原生输出与配置哈希、unknown/NA/失败日志；
- 方法卡、局限、覆盖需求、保留集与消融计划或实际结果；
- 单模块耗时、候选去重、`ToolRunResult` 兼容接入包；
- 默认 candidate/unassessed、runtime not_run，不自动提升漏洞状态。

## 13. 方案仍待解决的问题

1. 本轮 17 条 S0 记录尚未升级 S2，具体根因子家族可能调整；部分 PR 页面在网页读取时失败，源码调查必须重试官方镜像/迁移入口并固定提交。
2. 授权策略的真值不是纯 AST 能推出的，要补文档/补丁/人工审核；缺检查也可能由上层策略保证。
3. 共享 CFG/符号/一跳摘要在当前分支尚不可用；核心分支只有部分基础事实，不能先许诺完整算法已能接入。
4. ArkTS 前端和跨语言边暂缺，桥接方向条件最弱；目标应与第一方 OpenHarmony 源码关联，商业 HarmonyOS/生态 App 问题需另分组。
5. 尚无专项多工具执行、准确率、运行时或实际漏洞结果；本文件提出的是可检验路线。

当前最值得马上执行的动作是：**核验一个真实服务授权补丁，建立一个真实修复对和相似安全对照，跑两个相关工具 profile，围绕它完成第一个有效 guard 的自主 detector。** 能把这一步做成独立可复现证据，才有基础逐步实现你希望的重点类型高检出率。
