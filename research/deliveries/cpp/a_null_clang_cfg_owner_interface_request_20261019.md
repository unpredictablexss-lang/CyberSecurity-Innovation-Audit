# A-NULL Clang CFG 公共接口申请（2026-10-19）

## 请求状态

- 请求方：A 线 C/C++（NULL detector）
- immutable base：`4593a7c9b6977eb81172d01b46cc59daf46f5d45`
- detector：`ohscanner.cpp.null_dereference` 0.4.0
- 状态：**待 owner 评审；尚未实现/批准**
- 范围：仅申请公共 build-context provider 到 Detector 的数据接口；本申请不授权 A 线修改 contracts、indexing、runner、execution、catalog、API、Worker 或报告 schema。

## 现状与缺口

`ScanContext` 当前含 `request`、固定的 `SourceUnit` 和通用 `shared_facts`。生产 `prepare_git_context` 生成 `ast`、`source_blob_oid`、`facts_v1`、`coverage`，环境指纹记为 `build_profile=none`。A-NULL 需要真实编译参数、Clang 版本和 CFG 才能判断 source-to-sink reachability、guard dominance 与部分别名关系；detector 目前只有有界词法/Tree-sitter 事实。

源码 checkout 没有匹配的 `compile_commands.json` 或产品 `build.ninja`。Standalone Clang 控制实验不是产品构建上下文。本申请因此只定义将来上下文可用时的接线要求，不声称当前已有 CFG 分析。

## 需要的最小能力

由**公共引擎的受信任 build-context provider**读取经批准的编译数据库和构建配置，输出版本化、只读的 per-source CFG fact；A detector 只消费 fact，不执行 Clang 子进程、不解析任意 shell command、不自行读取浏览器/请求提供的本机路径。

建议由 owner 定义一个可选 fact，例如 `clang_cfg_v1`，至少包含：

- 输入身份：repository、full commit/tree、snapshot、规范相对路径、source/blob SHA-256；
- 构建身份：build-profile ID、compile database SHA-256、匹配 entry 数、规范化 argv/工作目录摘要、defines/includes/language standard、Clang binary/version；
- 结果状态：`complete`、`partial`、`failed`、`not_available`、`ambiguous`；
- 支持范围：每个函数/CFG 的节点与边、source range、terminator/branch predicate 可追溯位置，以及 alias/异常/宏/模板等能力标记；
- 失败与覆盖：诊断、未分析原因、未支持语义 obligations；无 fact 时 detector 的行为不变并保持相关结论 `unknown/partial`。

实际字段/存储形式由 owner 决定；不能为了方便把未验证的 CFG/alias 结论标成 complete。若一源文件匹配多个构建变体，provider 必须逐变体分析或显式返回 `ambiguous/partial`，不能静默挑一项。

## 安全与兼容要求

1. build profile 必须经受信任配置绑定固定 repo/commit/tree/snapshot；拒绝 source hash 不符、compile DB 来自其他源码对象、路径越界或配置漂移。
2. 编译参数按 argv 处理，不经 shell 求值；Clang 工具、资源限额、超时、宏/生成头文件依赖和产物缓存均由 owner/provider 管理。
3. 该 fact 为可选增量；无配置时保持当前 detector 行为与历史报告/ID 不变，不把缺失提升为 safe/miss。
4. facts 必须可供 CLI 与 Worker 共用，任务计划/执行指纹需固定 build-profile 和数据库摘要，避免预览后构建上下文漂移。
5. v1 历史报告仍可读取；新结果按当前 v2 source-bound evidence 输出。公共 schema 扩展须有兼容性测试与 scope/ownership 更新。

## A detector 消费规则

- 仅 `complete` 且身份/配置与本次输入匹配的 CFG fact 可支持局部 CFG 关系判断；每个判断需回指 CFG 节点/边/source range。
- 早返回、短路、错误分支只在 CFG 边与支配关系证据完整时形成结论；词法形状只作提示。
- 未覆盖的跨函数/跨 TU alias、动态 dispatch、异常、模板实例、宏配置等继续单独列为 unknown obligations；CFG 存在不自动证明攻击者控制或敏感操作影响。
- 缺失、歧义、partial、解析失败、超时、限额耗尽均不产生负向安全结论；有效局部候选可保留并标 coverage partial。

## 调用方与最小变更

| 调用方/组件 | 现状 | 所需变更 |
|---|---|---|
| `src/ohscanner/contracts.py:ScanContext` | 通用 `shared_facts`，无 build-profile 类型 | owner 决定是否版本化可选 fact 或增加受验证的 build context 子对象 |
| `src/ohscanner/indexing.py:prepare_git_context` | `build_profile=none`，仅轻量 AST 和源码 facts | owner/build provider 装载固定数据库并填充 CFG facts；不能直接把环境中随意发现的数据库作为产品配置 |
| `src/ohscanner/runner.py` | 把通用上下文传给 detector | 确认可选 facts 透传及覆盖/obligation 报告兼容性 |
| `src/ohscanner/detectors/cpp/null_dereference_detector.py` | 无 CFG consumer；`detect` 当前不使用 context | A 在接口批准后仅新增 `clang_cfg_v1` consumer 和 A-owned 回归 |
| planning/API/Worker/报告 | 当前指纹没有 build-context identity | 若支持真实任务入队，owner 单独定义配置来源、指纹和报告绑定；不得从 UI 接受任意编译命令 |

## owner 验收门与 A 后续

**Owner 侧：** 明确 build profile 的受信任配置入口、路径/版本/哈希验证、可选 facts schema、CLI/Worker 一致性、资源预算、历史兼容测试及允许修改文件范围。若当前不支持 build context，应明确记录接口 blocker，而非由 A 私接 subprocess。

**A 侧（批准后）：** 提交只修改 A-owned detector 与专属测试的消费实现，验证 CFG branch/dominance/early-return/short-circuit/alias reassignment/错误路径及无 context/partial/多配置控制；使用固定产品 compile DB 和源码对象做 pinned before/after，并交独立测试线复跑。

当前没有产品 compile DB，不能执行最后一门，也不能宣称 D3 完成。该申请与测试计划的 8,994 条 unsafe-memory 抽样、盲审独立推进。
