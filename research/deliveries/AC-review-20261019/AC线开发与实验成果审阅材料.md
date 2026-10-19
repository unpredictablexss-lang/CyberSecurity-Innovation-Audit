# A/C 线开发与测试成果审阅材料

**整理日期：** 2026-10-19（中国标准时间）  
**范围：** OHScanner A 线 C/C++ 静态分析与源码机制 PoC；C 线 Ark Runtime TypedArray 静态分析。数据来自固定提交、固定源码对象、第一方 Runner 输出及已有回归报告。

## 审阅摘要

A/C 两线把扫描能力从局部语法告警推进到带来源绑定、覆盖状态和安全/修复对照的候选分析。A 线包含空指针、数组边界、整数/长度计算、资源生命周期/释放、非安全内存调用、共享指针竞态以及路径穿越等机制；C 线针对 Ark Runtime TypedArray 对象创建者与方法/签名关系开展显式启用的静态候选识别。成果重点是可重复的固定源码分析、修复前后差分、负例控制和可审计的证据链。

本材料区分三类结论：**已披露 CVE 的历史/当前源码回放**、**真实源码机制或组件级候选**、**产品级确认**。目前 A 线 Contacts 路径穿越已在固定源码和隔离 Harness 中复现为源码机制；尚未确认特定产品构建、完整调用者权限与具体产品影响边界。所有本次列出的产品级 `validated_vulnerability` 均为 0。不得把候选数作为漏洞数，也不得由修复前后命中差异推导全局准确率或召回率。

## 开发成果与能力提升

### A 线：C/C++ 静态分析

- 形成并迭代第一方 C/C++ 检测器：`ohscanner.cpp.null_dereference`、`bounds`、`integer_bounds`、`resource_lifetime`、`unsafe_memory_call`、`shared_ptr_race`、`lifetime`；已披露 CVE 扫描 profile 另包含窄范围已知源码形态映射。检测输出以 `candidate/unassessed` 为主，并保存源码位置与证据义务。
- 从简单模式匹配扩展到局部 guard/error-path、整数区间/截断、资源分配/释放/别名、跨成员别名、递归 cleanup、共享状态访问配对等分析。已加入安全路径、固定版本、无关样本及解析不完整控制；未知/partial 继续标 unknown/blocked，不把零命中当安全。
- 针对真实 OpenHarmony 组件固定对象进行扫描，并对已披露漏洞的漏洞版/修复版进行第一方 CLI 回放。A 历史三项 CVE 当前 M2 回放均能在漏洞源码产生候选，修复源码为 0；这证明该小型回归集中对应规则可区分样本，不代表一般化召回率。
- 路径穿越审计发现 `ContactsDataAbility::BatchInsert` 中 `PortraitFileName` 参与文件路径构造/清理的机制问题。隔离 Harness 的 attack/fixed/safe/fixed-safe 对照各 3/3 稳定；权限边界及可访问 victim 文件影响在 Harness 观测。该发现没有分配 CVE，报告为源码机制确认/产品适用性待核验，不能写成已确认产品漏洞。

### C 线：Ark Runtime TypedArray

- Detector `ohscanner.ark.runtime.type_safety` 0.6.2，model 0.8.13；面向 TypedArray 对象创建者与目标 owner/method/signature 的精确关系，校验目标与 creator 依赖的 Git blob、源码 SHA-256 和 AST 完整性。
- 第一方 catalog 显式接入但默认关闭，需用户显式选择。当前 C1 两文件 Runner 回放中目标源码解析为 partial、creator 依赖 complete，任务 blocked、0 diagnostics。该结果界定了解析/源绑定边界，既不是漏洞命中，也不是安全结论。
- C 专项单测 146 passed、3 skipped；覆盖副作用和同名接收者控制。独立留出集、宏/产品构建、真实入口、攻击者控制和运行时影响仍待验证。

## 测试与实验结果解释

| 实验 | 结果 | 能支持的结论 | 边界 |
|---|---|---|---|
| A 历史 CVE 当前 CLI 回放 | CVE-2025-0587：漏洞版 1、修复版 0；CVE-2025-23420：5、0；CVE-2025-26690：历史组件 replay 5、0 | 当前固定基线对应 detector 对这些源差分有候选区分能力 | 小型历史集合，不是独立 holdout 或全局 Precision/Recall；组件/产品适用性另行证明 |
| A D2 对照回放 | CVE-2025-9900 libtiff：1/0（漏洞/修复），safe 0；CVE-2026-92391 libcurl：1/0，safe 0；CVE-2026-33416 libpng：2/0，safe 0 | integer bounds、recursive resource cleanup、cross-member lifetime 机制开始覆盖更多真实修复差分，并保留安全对照 | libtiff/libpng 覆盖 partial/blocked；只有 curl run 完整。全部 `validated_vulnerability=0` |
| A 解析边界 | CVE-2026-46675 libpng 回放 blocked/partial、0 diagnostic | 明确暴露跨函数 zlib 输入生命周期规则缺口 | 不是 detector miss、safe 或修复判断 |
| A Contacts 隔离 PoC | attack/fixed/safe/fixed-safe 各 3/3 稳定 | 源码路径穿越机制可在受控环境复现，修复对照阻断目标行为且安全路径工作 | 不是完整产品构建；产品型号/版本、真实调用权限、策略与受影响文件边界待证；ASan/UBSan 探针退出 139 不作为 sanitizer 成功 |
| C TypedArray 两文件 Runner | 目标 partial、creator 依赖 complete、blocked、0 diagnostic | 精确 source binding 和 partial fail-closed 能保留证据状态 | 不支持 safe/miss 或能力召回结论 |
| 2026-10-18 全量扫描基准 | 525 个 manifest 项目：37 completed、350 partial、138 failed；A 416,232 candidates，C 0；A/C 都无 confirmed | 覆盖大规模固定任务编排，观察到 C 全量 profile 无命中及 A 候选噪声/解析局限 | C 的检测准入当时为 `research_unadmitted`；A 候选尤其 NULL 告警多且噪声显著。候选量不等于漏洞数；无 ground truth，禁止算准确率 |
| A/C 单测 | A 历史完整回归 709 项（701 pass/8 skip）；C 专项 146 pass/3 skip | 代码级回归和控制样例通过 | 不等价于产品级验证或独立盲测；不同分支/日期的测试数量不可相加 |

## CVE 与 PoC 索引

### A 线 CVE 源码回放

- **CVE-2025-0587**（Ark Runtime `atomic_helper.cpp` 整数转换/边界）：`ohscanner.cpp.integer_bounds` 0.2.0，漏洞源码 1 条候选，固定源码 0。
- **CVE-2025-23420**（Ark Runtime JSArray sort 越界/UAF 相关）：`ohscanner.cpp.bounds` 0.2.0，漏洞源码 5 条候选，固定源码 0。
- **CVE-2025-26690**（DSoftBus 空指针）：历史 A 交付记录为漏洞源码 5 条、修复源码 0 条。2026-10-19 的最新 Ark Runtime CLI 重放不包含该项；不得将历史报告日期误写成当前重跑。
- **CVE-2025-9900**（libtiff 光栅偏移/指针下溢）：D2 固定源码候选 1、官方修复源码 0、安全控制 0；其中 libtiff 与 libpng D2 运行受 partial 解析限制。
- **CVE-2026-92391**（libcurl 嵌套 MIME 递归清理资源耗尽）：漏洞版 1、修复版 0、安全控制 0；此组完整解析，但产品调用与攻击影响未建立。
- **CVE-2026-33416**（libpng 跨结构体别名 UAF）：漏洞版 2、修复版 0、安全控制 0；解析 partial/blocked。此项不计入早期 17 项独立发现清单。
- **CVE-2026-46675**（libpng 解压输入生命周期 UAF）：A 当前 lexical detector 回放 blocked/partial、0 findings，明确属于规则与解析边界未知；不报告为 miss/safe。

这些是公开 CVE 的历史源码/规则回归，不是新挖出的 CVE。Contacts 路径穿越目前没有 CVE 编号。CVE 编号、源码样本匹配或组件 Harness 都不能单独证明 OpenHarmony 某产品版本受影响。

### 已实现 PoC / 扫描器类型和参数

| 类别 | 实现与参数 | 用途与边界 |
|---|---|---|
| A Bounds / Integer | `ohscanner.cpp.bounds` 0.2.0；`ohscanner.cpp.integer_bounds` 0.2.0 | 数组/拷贝/索引边界和整数/size 计算候选；CVE-2025-23420、0587 与 D2 libtiff 回归 |
| A Resource lifetime | `ohscanner.cpp.resource_lifetime` 0.3.0；旧交付 `ohscanner.cpp.lifetime` 0.4.0 | 分配/释放/别名、跨成员 owner alias、递归 cleanup 候选；CVE-2026-33416/92391、UAF/double-free 机制回归 |
| A NULL / unsafe call / shared_ptr race | `null_dereference` 0.2.0、`unsafe_memory_call` 0.1.0、`shared_ptr_race` 0.5.0 | 局部空值来源/守卫、危险内存 API/格式串、静态 shared_ptr 访问配对；均是窄范围 source-bound 静态候选 |
| A Path traversal | 路径穿越 detector 工作项与 Docker 隔离 PoC；attack/fixed/safe/fixed-safe 3/3 | Contacts 路径构造/清理机制验证；受限 Docker，无网络/只读根目录/丢弃 capabilities；产品授权入口和完整产品策略未覆盖 |
| A Memory PoC | bounds、整数溢出、UAF/double-free、stable sort 索引机制 Harness；ASan/UBSan 控制 | 在自编 workload/组件机制范围观察崩溃或行为；不是完整产品 exploit。整数样例仅观察到 `UINT32_MAX+1→0`，不声称 allocator crash |
| C Ark Runtime | `ohscanner.ark.runtime.type_safety` 0.6.2 / model 0.8.13，显式 opt-in | TypedArray owner/method/signature 与 creator 依赖校验，source blob/SHA/AST 完整性；C1 实验 partial/blocked |

## 规模与性能

A 线早期五个固定 OpenHarmony 组件实验共 4,983 个文件、51,551,827 bytes、33 条候选（22 个词法组），累计 wall 67.107 秒、峰值 RSS 282,972 KiB。候选组只是词法去重，不是根因或漏洞数。另一个平台吞吐基准使用非安全示例 detector，11 组件 9,508 文件耗时 113.64 秒，84 files/s，峰值 265.7 MB；它测量固定 Git 对象读取、Tree-sitter parse 与调度成本，不是漏洞检测性能或准确率。

2026-10-18 全量扫描报告的 525 项目/A 416,232 候选/C 0 候选与上面的小样本实验口径不同，不能相加。全量报告中 C detector 是 `research_unadmitted`；大量 partial/failed 也不能写成安全结果。后续应对分层标注的独立 holdout 评估，并对 parser 覆盖、候选归并与产品调用链分别补证。

## 评委复核路径

1. 先读配套 Excel 的「总览」「实验结果」「CVE与PoC」页；本 Markdown 给出方法和适用边界。
2. A 线来源：`sources/A_MEMORY_SAFETY_DELIVERY_20261017.md`、`sources/d2-disclosed-vulnerability-regression.md`、`sources/A_ARK_RUNTIME_CVE_REPLAY_STATUS_20261019.md`、Contacts 30 份抽样交付（见 `docs/项目现状与下一步.md` 的 2026-10-18 当前章节）。
3. C 线来源：`docs/项目现状与下一步.md` 的 2026-10-19 C 线状态、`src/ohscanner/detectors/ark_runtime/model.py` 与相关专项测试。
4. 全量扫描来源：`sources/full-scan-overview-20261018.md`、`sources/full-scan-detector-capability-20261018.md`、`sources/full-scan-testing-limitations-20261018.md`（原始报告在工作区扫描结果目录，不与本分支混为一次新的扫描）。

**审阅结论：** 当前材料支持“静态候选规则已覆盖更多边界/生命周期机制、固定源码回归可区分若干修复差分、受控 PoC 可复现若干组件机制”这一结论；不支持“AC 线已证明产品整体安全/漏洞识别率/新增 CVE 数量/所有候选均可利用”。

