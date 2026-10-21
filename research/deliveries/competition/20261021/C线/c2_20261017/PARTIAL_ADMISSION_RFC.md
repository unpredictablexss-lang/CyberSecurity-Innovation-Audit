# C 线 partial 文件准入 RFC

日期：2026-10-17。状态：待负责人审批；本 RFC 未改变公共 Runner、Catalog、contracts、数据库或 UI。

## 现状与复现

`ohscanner.ark.runtime.type_safety 0.1.0` 保留 `required_facts=('ast',)` 和 `ast_scope='per_file'`。默认 Catalog 不注册本检测器。完整 AST 的自编 fixture 可在本线显式 Registry 中验证契约；真实历史源文件的生产路径继续 blocked。

固定目标为 `BuiltinsTypedArrayStubBuilder::Filter` 的快路径生成逻辑。父提交 `830e85b40240677039719fcbf14f721ad3b19050` 的 missing 节点在 3362、3675 行，目标函数在 1372–1511 行；修复提交 `a0e30483ab3e4aead67ecfb5c708489915e447f9` 的 missing 节点在 3363、3676 行，目标函数在 1372–1512 行。两者函数子树无 ERROR，但整文件仍为 partial。上述行号是固定版本的研究记录，不是检测条件。

复现命令为本目录 `replay.py --repo-dir <固定本地对象库> --output <新结果目录>`。它复用公共 Git/index/Registry/Runner，并分开保存研究执行和生产 Runner 执行；不会 fetch、改写 SourceUnit、构建上游或运行 PoC。

## C2 已实施的研究边界

- 独立 `analyze_unit(..., research_partial=True)` 只用于明确标记的研究实验。生产适配器没有 partial 开关，直接调用适配器也拒绝 partial。
- 对所有输入重新验 source SHA；目标 caller 使用限定命名空间、类、函数和完整参数类型。sink 依照来源模型核对实参语义，存在可见不兼容定义、局部遮蔽或相关宏重定义时回退 unknown。
- 仅分析目标无错子树；宏条件包围目标、函数本身损坏、含未知宿主分支、lambda 或未知生成图控制时回退。不能因为错误远离目标就认定依赖无污染。
- 对象/类型定义身份、简单局部别名、token 复制、重新赋值失效和受限 IR 边单独记录。生成图路径是符号路径，不是产品触发证明。循环只做有界状态探索，不声称一般 phi、数值范围或完整 CFG 可满足性。
- 研究输出保留 `parse_dependency_contamination_unknown` 和 `production_runner_not_admitted`。局部候选不得转换成已获公共层准入的 v2 生产报告。

## 请求负责人评审的最小准入条件

建议若将来允许局部证据，必须同时绑定固定 SourceUnit/blob、函数范围、模型/规则版本、错误节点清单与依赖清单。依赖包括类型与基类声明、被调用符号签名、宏、构建配置，以及 `NewTypedArray` 的 species 摘要。无法排除相关错误、宏或跨 TU 污染时，维持研究模式/unknown，而不是升级完整覆盖。

建议在负责人维护的编排层显式表达“仅允许局部研究证据”的能力与权限，避免按检测器 ID 特判、重写 parser 状态、删除 required facts 或让注册本检测器隐式放开全局规则。具体公共协议如需新增，应由负责人另行设计、独立提交兼容测试；本线不自行增加字段。

文件覆盖仍为 partial；未检查范围保留 not_analyzed。即使聚合 blocked，也应保留已通过来源与范围核验的局部候选及义务。多个文件混合时逐文件闭合 complete/partial/not_analyzed/failed，不将局部分析量当整文件安全证明。

## 审批前后应验证的场景

1. 当前行为：真实 partial 文件在生产 Runner 中无执行、无候选、not_analyzed；独立研究能区别历史修复前后，且仍标 partial。
2. 错误落在目标函数、宏/声明依赖、跨文件依赖缺失、多个同名定义、相关宏改写时不继续证明。
3. 一个完整文件和一个 partial 文件混合时，完整文件的有效候选不丢失；总体覆盖不升级。
4. 未知 IR 边与已分析路径并存时保留有效局部证据，并独立列出 unknown；预算/超时中断不发布截断候选集合。
5. source hash、blob、snapshot、模型版本或输入范围改变时拒绝混用；历史报告及复核不重写。

本 RFC 不申请默认启用、不申请合入 main，也不申请漏洞确认权限。PoC、真实入口、CIA 影响、影响版本与修复重验仍须独立完成。
