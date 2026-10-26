# A 线后续开发任务树与并行设计（2026-10-18）

## 基线与进行中工作

- 仓库：`unpredictablexss-lang/CyberSecurity-Innovation-Audit`。
- 本轮已执行 `git fetch origin --prune`；更新后的 `origin/main` 为 `1c21ac60890fca0ce6be5d50d82e4757dd5e4623`（2026-10-18，集成 PR #18）。本地 A 线分支 `codex/a-line-scanner-regression-20261018` 为 `f8e3a0ad7463f216db4be7502bd8a19eec545908`，相对 `origin/main` ahead 6 / behind 0，且 `origin/main` 是当前 HEAD 的祖先。工作树有 655 个脏路径，禁止在其上 pull、reset、checkout、清理或覆盖文件。开始后续实施时，优先在保留该树的情况下从 `origin/main` 建立干净隔离工作树，或由集成人明确提供基线与环境。
- OpenHarmony 仓库上次 repo sync 于 2026-10-18 完成，绝大多数 project head 与 manifest revision 相同；`third_party_pulseaudio` 的 GitCode HTTPS 请求失败，不能声称该子仓库已更新。后续复现应记录每个使用的仓库和精确 SHA，不使用隐式 fetch。
- 当前 A 阶段（A0）为 30 份扫描报告抽查及隔离 PoC 交付，状态：报告/样本/PoC 已交付，产品影响闭环仍部分完成。30 个样本覆盖 345 条扫描候选：0 条直接扫描候选满足完整 confirmed/reportable 门，9 条 not_reproduced、336 条 not_testable。样本 2 的相邻上下文审计另发现 1 个独立确认的 Contacts `PortraitFileName` 路径穿越问题（CWE-22/CWE-73）；隔离机制 PoC attack/fixed/safe/fixed-safe 各 3/3。产品镜像、真实 SELinux 策略、上游修复验收、受影响版本范围仍未完成。ASan/UBSan 探针退出 139 是限制，不算 sanitizer 成功。
- A 线边界：C/C++ detector、规则、测试及本线证据；不得改公共 Runner/Catalog/API/合同、B IPC、UI 或平台集成。若要改公共接口，先提交独立接口申请。报告候选数不作为真值；没有合格独立标签集不计算 Precision/Recall。

## 任务树：开发线与测试线分离

```text
A0  30 份报告抽查与沙箱交付（已交付；继续作为只读基线）
├─ 开发线 D
│  └─ D1  C/C++ 路径处理检测器漏检根因与规则改进（只读盘点已完成；实现待开始）
│     ├─ D1a 固定漏洞/修复来源，重放基线并定位漏检环节
│     ├─ D1b 设计 source/transform/sink 与路径约束语义
│     └─ D1c 实现最小规则并维护开发者回归矩阵
└─ 测试线 T
   ├─ T1  Contacts 产品入口、权限、影响、版本与修复验证（P0；进行中，静态复核 partial）
   │  ├─ T1a 核验精确来源、真实调用入口与 WRITE_CONTACTS 边界
   │  ├─ T1b 查明上游修复及受影响版本/分支
   │  └─ T1c 产品级或最贴近产品的隔离重放、fixed/safe 复验
   ├─ T2  345 条候选的优先级复核与可验证性提升（可与 T1 并行）
   │  ├─ T2a 优先审 9 条 not_reproduced 和高风险 not_testable
   │  ├─ T2b 分类缺依赖、入口/权限、PoC、源码或解析证据阻塞
   │  └─ T2c 建下一轮可执行测试队列，不将 not_testable 当作误报
   └─ T3  独立验收 D1 与整线证据（依赖 D1/T1/T2）
```

### 当前开发/测试边界观察

- 开发线 D1 的初步基线事实：本分支 `src/ohscanner/detectors/cpp/` 与显式 catalog 中登记的是 bounds、integer bounds、null dereference、resource lifetime、unsafe memory call、unique_ptr lifetime、shared_ptr race 等 C/C++ 检测，没有文件路径穿越/source-to-file-sink 检测器。这是当前 C/C++ detector family 的覆盖缺口，与 A0 未直接命中 ADJ-001 相符；在确认 A0 run 的 Detector set/profile 前，不把它单独宣称为 A0 未命中的完整因果解释。零直接扫描候选不构成安全证据。
- D1 可在 A 的 `src/ohscanner/detectors/cpp/**` 设计/实现受限、source-bound 的路径安全 candidate 分析器，并在其自有 fixtures 中维护开发回归。Catalog 属于 shared owner-only 范围；D1 不自行注册或改默认 detector。若要面向生产 Runner 暴露，另交由 owner 做 catalog review/准入。
- 测试线 T1 与 D1 分开：T1 复核真实组件的调用/权限/源码分支，并独立验证产品配置；T1 不使用 D1 的新 fixture 作为产品证据。T2 对 345 个既有候选做证据分诊，不读取/重写 scanner 的原始分类来“美化”检测结果。

## 执行顺序、依赖与完成门

| ID | 优先级/状态 | 依赖 | 完成门 |
|---|---|---|---|
| D1 开发 | P1，根因盘点完成、实现待开始 | A0 固定源码与 T1 已核验的漏洞对象身份；不得依赖 T1 的产品验证结论 | 漏检原因可复现；仅改 A 线 C/C++ detector；positive/fixed/safe/unrelated/partial 回归齐全；同 scope 基线性能/coverage 有记录。开发者单测只验实现，不作独立产品验证。 |
| T1 测试 | P0，进行中（partial） | A0 精确来源材料 | 精确 repo/commit/tree/blob/source hash；现实入口、权限、攻击者输入、触发条件、CIA 影响、版本/修复范围分别有证据；PoC 与 fixed/safe 重放可重复。当前 8 个源码对象及权限门已核；6.1-LTS、7.0 Release/master refs 有危险实现，若干旧 release snapshot 未找到该字段链。产品 build/SELinux/版本映射/官方补丁未核，保持 unknown。 |
| T2 测试 | P1，待开始 | A0 抽样表、候选与日志 | 每项保留原来源键/结论并分类阻塞、补证动作和优先级；not_testable/not_reproduced 不被误改；输出可对账队列。 |
| T3 独立验收 | P2，排队 | D1、T1、T2 交付 | 独立复跑 D1 控制和 T1/T2 证据；文档/JSON/表格/PDF/PoC/hash 统计一致；依赖/限制明确；基线指向最新 main；scope check 零越界。 |

### 并行边界

- **开发线 D1** 只写 A 所有权下的 C/C++ detector、其开发回归 tests/fixtures 和独立研究记录；不编辑公共 Runner/Catalog/协议，也不写产品影响或版本结论。
- **测试线 T1** 只写 Contacts 路径穿越的来源、权限、产品/构建验证、修复复验与报告证据；不改生产 detector。已存在的机制 PoC 和 D1 新增单测不能替代产品级测试证据。
- **测试线 T2** 只写抽样复核矩阵、证据阻塞分类及候选优先队列；不修改 detector，不覆盖原始交付记录。
- **测试线 T3** 由未实现 D1 的独立审查者执行；独立复跑控制，不以 D1 作者自测代替验收。
- D1 与 T1/T2 使用独立 worktree、目录和环境；共同基线采用集成人给定的完整 immutable SHA。不要在现有 655 脏路径的 A 工作树里并行施工。交付前执行 `scripts.check_change_scope`，不得放宽 ownership policy。

## 并行 Vibe Coding 提示词

### 测试线 T1 — Contacts 路径穿越产品影响、版本与修复闭环

```text
角色：你是 OpenHarmony Scanner A 线独立安全测试负责人。任务只处理已报告的 Contacts PortraitFileName 路径穿越案例，不把机制 PoC 自动等同于产品级漏洞结论；不修改 detector 代码或采用开发线自测作为验证结论。

基线：先阅读 AGENTS.md 要求的六份当前文档、A 线任务说明及 `research/deliveries/a-line-sample30/20261018/`。使用集成人提供的 immutable base SHA 和独立工作树；现有 A 线工作树含大量未提交文件，禁止覆盖、清理或重置。逐一核对目标仓库、commit、tree、path、blob、source SHA-256、PoC 镜像 digest 和现有日志。

目标：完成 `ohscanner-contacts-path-traversal-001` 的产品证据链：从可触发的真实调用入口追踪到 `ContactsDataAbility::BatchInsert`/`PortraitFileName` 的文件操作，说明攻击者可控字段、`WRITE_CONTACTS` 权限边界、路径处理、受影响文件范围及可证明的完整性/可用性影响；查证受影响 OpenHarmony commit/版本/分支和上游修复对象；在安全隔离环境中对 vulnerable/fixed 与 safe/fixed-safe 版本复验。

步骤：
1. 先对照当前报告、源清单和 PoC；重新核验对象存在且字节 hash 相符。任何仓库取不到或镜像/工具不一致都记录为 blocked，不用近似版本代替。
2. 静态追踪调用入口、调用者权限检查、数据字段到路径 API 的传播、规范化/目录约束及删除/覆盖操作。区分已证明事实、推断和未知；只引用精确源码行与对象身份。
3. 检查上游提交历史/补丁，确认 fix 的具体代码行为与适用版本，不根据日期或分支名字猜版本范围。若无法获得官方构建/策略，明确说明与产品配置的差距。
4. 优先复用现有 Docker 隔离配置；维持无网络、只读根、降权和资源限制。只执行本地 PoC，不触碰真实用户数据、设备或线上服务。记录镜像 digest、编译命令、退出状态、输入、文件系统前后状态和日志哈希。ASan/UBSan 退出 139 应继续标记为探针失败/限制。
5. 对 vulnerable 复现攻击效果，对 fixed 验证同输入不再删除越界目标；safe/fixed-safe 必须证明正常图片/联系人流程仍可用。重复运行并保留全部结果，不删失败样本。

完成门：现实入口、权限、攻击者输入、触发条件、CIA 影响、版本/修复范围分别有可审计证据；PoC 和 fixed/safe 控制可按文档重复；交付包含来源 OID/hash、构建和环境、失败与限制。证据不足时维持 candidate/unknown/partial，不作 confirmed 升级。只更新日期化 A 线交付材料；不改公共接口、不 push/merge、不更改 PR 状态。

交付格式：摘要；证据表（claim、source object、artifact/hash、结论、限制）；版本/补丁矩阵；复现命令与结果；剩余 unknown；建议的最小后续事项。
```

### 开发线 D1 — 漏检根因与 C/C++ 检测器改进

```text
角色：你是 OpenHarmony Scanner A 线 C/C++ detector 工程师。目标是为当前缺失的文件路径 source-to-sink 检测能力设计范围受控的研究 candidate 分析器；你负责实现及开发者回归测试，但不负责独立验收或判定真实漏洞是否可利用。

基线：先读 AGENTS.md、六份当前文档、`research/coordination/parallel-20261017/A_CPP.md`、A0 样本与 PoC 来源记录。使用集成人给定 immutable base SHA 的隔离工作树。检查 ownership.json；仅修改 A 线 C/C++ detector、其专属测试/fixtures 和研究交付。不要编辑 Runner/Catalog、公共协议、B IPC、UI、平台代码或 A1 工件。

目标：当前 A C/C++ detector family 以内存安全为主，不含路径穿越/source-to-file-sink analyzer。先确认 A0 run 的 Detector set/profile，再以精确 Contacts 源码作为研究控制，探明适用于多个文件操作场景的最小通用语义：外部 DataShare 字段/string accessor → 路径构造/变换 → 文件读写/删除 sink；证明安全 containment/白名单与 unknown 情况如何区分。不要只为 `PortraitFileName`、单一仓库、方法名或 hash 堆砌特例，也不要扩大成所有路径拼接告警。

步骤：
1. 绑定 repo/full commit/tree/path/blob/source SHA、scope、detector/rule 版本与运行配置；确认漏洞版和修复版对象字节，读取 A0 run manifest 确认实际执行的 Detector set/profile。
2. 在不修改规则前重放基线，记录 diagnostics、coverage、解析状态和运行资源；归因到具体规则/数据流缺口。
3. 设计并实现最小 C/C++ detector 类。source 需由可审计的输入/字段提取 model 界定，sink 需限定到文件 API；路径 concat 本身不能触发 candidate。要求 source-to-sink 有 bounded dataflow 证据且缺少可验证的 root containment/basename allowlist/安全转换。跨函数、外部函数、宏和 partial parse 无法证明时保留 unknown/partial。
4. 加入漏洞正例、修复版/显式 canonical-containment fixed、普通安全 basename、受限目录安全路径、无关同名 API、没有 file sink 的相同路径、跨函数与解析不完整控制；覆盖 false positive 风险和异常/预算耗尽行为。所有 fixtures 只属于 detector 开发测试，不代表产品复现或独立标签。
5. 与基线按相同 scope/profile 比较候选身份数、coverage、耗时、内存及原因；候选减少不代表准确率提升。没有独立真值标签，不报告 Precision/Recall。
6. 运行专属 detector 回归及必要的 A 线全套验证，执行 scope check 与 diff check，记录确切命令和结果。

完成门：缺少 path traversal analyzer 的基线事实可复核；规则边界、适用条件和保守降级明确；positive/fixed/safe/unrelated/unknown 控制通过；仅改 A ownership 的 detector/tests/fixtures/研究材料，不改 shared catalog；若需暴露 detector，提供单独 owner review request。结果绑定精确源码和规则版本。不得把 detector candidate 当成 confirmed vulnerability，不 push/merge/改 PR 状态。

交付格式：问题陈述；基线来源/配置；漏检归因；算法设计与误报边界；变更文件和回归矩阵；基线对比；验证命令/结果；limitations 与后续建议。
```

### 测试线 T2 — 345 条候选复核队列与证据阻塞清理

```text
角色：你是 A 线独立测试与证据分诊负责人。你不改 detector，不重写历史报告；你要把 A0 的 345 条扫描候选转为有顺序、有证据路径的后续验证队列。

基线：先读 AGENTS.md、当前状态、A0 技术报告、样本清单、逐条判定、对账文件及交付 README。使用只读原始交付作为输入，在新的日期化目录写结果。保持原始 candidate ID、报告和结论不可变；先核验 JSON/Markdown/Excel/PDF 的总数和 hash 清单。

目标：优先复核 9 条 `not_reproduced` 和高风险 `not_testable` 中具有明确补证路径的案例；逐条识别阻塞是源码/构建缺失、parser partial、入口不可达、权限策略未知、PoC 缺失、环境限制、修复版对象缺失或报告证据不足。not_testable 不等同于 false positive，not_reproduced 也不在缺少复现条件时自动等同安全。

步骤：
1. 为每项保留原始样本/候选 ID、repo/commit/tree/path/blob/source SHA、Detector/rule/scope/profile 和当前 status。
2. 建立可行动评分列：潜在影响、边界敏感度、证据完整度、补证成本、可重放性；评分是队列优先级，不是漏洞严重性或置信度。
3. 对 9 条 not_reproduced 先检查原始运行环境、构建参数、输入和失败日志是否足以复现；列出一项最小补证动作。不要将“复现失败”改写成“漏洞不存在”。
4. 从 not_testable 中按风险和可补证性选定有限首批，写清继续/暂停的理由；不得为了凑数量扩大范围。
5. 检查样本与历史 benchmark/PoC/调参材料是否存在家族泄漏或重复；未知来源标明未知，不把同源样本当独立验证集。
6. 输出机器可读 JSON/CSV 与人工可读 Markdown，附统计校验脚本或明确复核步骤；保留失败、排除项与 unknown。

完成门：每条队列项都有来源键、原结论、阻塞原因、下一项最小证据动作、优先级理由、owner/dependency 和状态；数量可与原始 345 条对账；没有未经证据支持的状态升级，也不计算无效 Precision/Recall。

交付格式：分诊摘要；队列 schema；优先事项与暂停项；来源/家族泄漏说明；对账统计；明确的下一轮入口。不得修改 detector/公共服务，不 push/merge/更改 PR 状态。
```

### 测试线 T3 — 独立验收与集成前证据/范围审计

```text
角色：你是未参与 D1/T1/T2 实施的 A 线独立测试审计者。只对 D1/T1/T2 的交付做独立验收，不替代作者补写证据或假设缺失事实。

基线：核对各交付记录的 immutable base SHA、实际 commit/tree/blob/source SHA、worktree 状态和文件 ownership。检查 `scripts.check_change_scope` 对集成人给定 base 的结果。不要在已有脏树上 reset、checkout、清理或改变 PR 状态。

目标：判断 A 线交付是否可供 owner/mainline 审阅：来源可重放、状态语义准确、候选/确认/unknown 分离、PoC/修复配对、文档统计一致、测试结果可追溯、越界为零。

输出逐项 pass/partial/block 及证据；列出最小修复任务和责任线。只有 A1 达到产品证据门才建议 confirmed/reportable；否则明确保持状态。审计不授权 push、merge、Ready 或发布。
```

## 持续目标与每轮检查点

持续目标由本任务的 Codex Goal 管理：开发线 D1 与测试线 T1/T2 并行推进，由独立测试线 T3 收口。每轮继续前核对：最新远端基线、隔离工作树身份、未提交证据、当前进行项和依赖；每轮结束更新任务状态、已核实来源、实际命令/结果、unknown、下一步与 owner。测试线独立验证开发线结果；不得把 D1 单测、机制 PoC或零候选当作产品测试、真实漏洞判定或安全证明。遇到证据阻塞时保留原状态并把最小解阻动作写入任务树；不要用日期推断版本或用告警下降声称准确率提升。未收到明确授权时不 push、不 merge、不发布。
