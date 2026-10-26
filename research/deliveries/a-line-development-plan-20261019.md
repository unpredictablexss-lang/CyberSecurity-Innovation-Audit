# A 线开发任务树与并行执行提示（2026-10-19）

## 同步基线与当前现场

- 项目：`unpredictablexss-lang/CyberSecurity-Innovation-Audit`。本轮成功执行 `git fetch origin --prune`；最新 `origin/main` 为 `db77164fdc2af0da02e4d3efc056d84694fd68e8`（2026-10-19，PR #29）。
- 原 A 线主工作树 `D:\openHarmonyScanner\CyberSecurity-Innovation-Audit` 当前 `HEAD=9b99f10`，相对最新 `origin/main` ahead 7 / behind 93，工作树 718 个 dirty paths；另一 A 线副本 `CyberSecurity-Innovation-Audit-a-null-latest` 有 45 个 dirty paths。都保留原状；不得在其上 pull、reset、checkout、清理或覆盖。
- 四条隔离工作树已由最新 SHA 建立：`worktrees/a-path-d1-20261019`、`worktrees/a-memory-d2-20261019`、`worktrees/a-contacts-t1-20261019`、`worktrees/a-triage-t2-20261019`。D1/D2/T1/T2 本轮已交付，T3 独立预审已完成；当前并行续项为 D3（D2 worktree 中 generic libpng cross-function state/lifetime）、D4（同 worktree 独立 CJSON complexity prototype）与 H1（T1 worktree 中 Ark 历史源对重放）。D3/D4 编辑不同 A-owned detector 文件；所有开发工作树基线均为 `db77164…`，各 Agent 只编辑分配的 CPP 文件/新证据目录。
- 当前主线的 `docs/项目现状与下一步.md` 已更新到 2026-10-19，但旧 A 线任务树不在 `origin/main`；旧树保留在本地 `research/deliveries/a-line-development-plan-20261018.md`，本文件记录面向最新 main 的续行计划。
- 输入审查记录（用户本轮指定的权威 A 线清单）：`D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\cpp\源漏洞审查记录_20261018_A线整合版.md`，逐项机器台账为 `coverage_ledger_20261019.json`。本文件此前误指向另一份 C 线 G 盘报告，现已更正。A 线扫描/回放摘要列 12 项：7 项当前源码/组件或 M2 回放（CVE-2026-46675、CVE-2025-9900、CVE-2026-92391、CVE-2026-67216、CVE-2026-67215、CVE-2026-27648、CVE-2026-33416）；另有 3 项历史案例，其中 CVE-2025-0587 与 CVE-2025-23420 已于本轮完成当前 CLI vulnerable/fixed 配对，CVE-2025-26690 仍待回放；2 项明确 N/A（CVE-2025-20042、CVE-2025-21098）。用户指定文件全文另含其它披露编号；全量适用性见 A2 交叉表。所有候选/组件回放均不升级为产品漏洞结论。

## 任务树与状态

```text
A0  30 报告 / 345 候选抽查、隔离 PoC（已交付，只读基线）
└─ A1  依据漏洞审查记录提升扫描覆盖并完成证据闭环
   ├─ D1  路径 source-to-file-sink 检测器（独立审查 P1 已修，待完整 family 回归与 I1 接线）
   ├─ D2  已披露漏洞家族回归及规则缺口改进（A-owned 改进和默认集回放完成；待独立验收）
   ├─ D3  libpng CVE-2026-46675 精确源码缺口闭合（根因/parse blocker 已绑定；本轮记录 blocker 后收口）
   ├─ D4  cJSON CVE-2026-67216/67215 精确源/修复覆盖（generic prototype 与本地 snapshot Runner replay 完成；exact pair/admission 留后续）
   ├─ A2  全部已披露 CVE 的 A-line 适用性总映射（17 个独立披露编号；核验中）
   ├─ T1  Contacts 入口/权限/影响/版本/修复验证（本轮证据增量完成；产品状态仍 partial/candidate）
   ├─ T2  A0 的 345 条候选分诊与可验证队列（完成）
   ├─ I1  Owner-only Catalog/Runner 准入与 profile replay（D1/D2 后置；待 shared owner）
   └─ T3  独立验收（预审完成；最终验收依赖 D1/D2/T1/T2/I1）
```

| 任务 | 状态 / 优先级 | 交付门 |
|---|---|---|
| D1 路径检测 | 核心实现完成；独立审查 P1 已修 / P1，待完整 family 回归与 I1 | opt-in `ohscanner.cpp.path_source_file_sink` v0.1.0；Contacts 固定 source replay 3 条 partial candidate。独立审查发现 allowlist 条件误抑制危险 unlink，现已修复并增加正例/安全控制/partial 回归；14 个定向测试通过，`Logger::DeleteFile` 无关 sink 控制安静。完整 C++ family 回归与 source getter identity admission gate 仍待复核；此 detector 目前不在 Catalog/生产 profile。 |
| D2 CVE 回归 | A-owned 完成 / P1，待 T3/I1 | `integer_bounds` 0.2.1 与 `resource_lifetime` 0.3.0 覆盖 libtiff CVE-2025-9900、curl CVE-2026-92391、libpng CVE-2026-33416。漏洞版分别 1/1/2 个 candidate，修复版同规则为 0；安全控制为 0。curl 完整解析；libtiff 2/2、libpng 4/4 输入均 partial/blocked。已新增一键四-detector 显式 A profile：`research/deliveries/cpp/run_a_disclosed_cve_scan.ps1`；对三个 known-CVE source-shaped CLI controls 验证漏洞侧 3 条 candidate、fixed 侧 0，漏洞侧状态仍 `completed_with_limitations`。证据在 D2 worktree。CVE-2026-46675 精确 upstream 源回放仍为 partial/0 根因 candidate；known-CVE shape 不替代该差距。 |
| D3 libpng stale-input UAF | 本轮 gap audit 完成 / P1 后续 | 精确 affected/fix 身份与源哈希已核验；真实 CLI 仍 0/1 analyzed、partial/blocked、0 candidate。根因是跨函数 stream pointer/count lifetime state 建模不足；本轮不做 CVE 特判，记录为明确 parser/detector blocker，0 finding 不代表安全。详见 D2 worktree `research/evidence/cpp/d3-libpng-46675-gap.md`。 |
| D4 cJSON DoS | 本地 mechanism replay 完成、exact pair blocked / P1 后续 | generic detector 8 项正/负/partial/Runner 单测通过；本地 pinned cJSON snapshot replay 保留 3 个 partial/blocked 候选。不是 exact vulnerable/fixed pair，不证明对应披露根因；未注册 Catalog/Runner，不能算生产 CLI 覆盖。后续取得精确 affected/fixed 源与 safe controls 后再校准/admission。详见 D2 worktree `research/deliveries/cpp/D3_CJSON_GENERIC_COMPLEXITY_MECHANISM_REVIEW_20261019.md`。 |
| A2 全量披露适用性 | 已启动 / P1 | 仅根据用户指定的 A 线整合审查文件，逐项对照全部 17 个独立披露编号及其当前规则、默认/opt-in 可达性、精确源码/产品状态；把签名模式、generic root-cause replay、historical summary、N/A 和不受影响版本分开。 |
| H1 历史 Ark replay | 完成 / P1，待 T3 独立复验 | CVE-2025-0587 `integer_bounds` 当前 vulnerable/fixed 为 1/0；CVE-2025-23420 `bounds` 为 5/0；safe/unrelated 0，partial 为 blocked。source OID/tree/blob/file SHA 与当前 normalized CLI reports 已交付；旧 23420 patch digest 不一致仍单独记录，未沿用旧摘要作为根因结论。 |
| T1 Contacts | 本轮证据完成 / P0，产品 partial | 固定源码链和权限边界、精确 tag/历史、e92 预编译机制二进制补充重放及失败日志；没有真实产品版本/安装映射、文件权限域或官方修复证据。结论维持 candidate/partial。49 项日期化交付哈希清单已复核通过。 |
| T2 候选分诊 | 完成 / P1 | 345 条逐条 source-bound；9 条 not_reproduced=P0、274 条高风险 not_testable=P1、62 条普通 not_testable=P2。原 ID/结论不变，JSON/CSV 均为 345 行且 345 个 source SHA/行绑定匹配。 |
| I1 Scanner admission | 待接线 / P1，shared owner 负责 | D1/D2 的规则与 profile registration handoff 已写；owner 评审后决定 opt-in named profile/明确选择集，对多个 pinned vulnerable/fixed/safe/partial 控制做真实 CLI/Runner 回放。Catalog/Runner 为 shared owner-only，A lane 不自行改。 |
| T3 独立验收 | 预审完成、最终待 I1 / P2 | D1 10/10、D2 18/18 focused tests 独立复跑通过；14 个 exact vulnerable/fix 源文件 hashes 与 pinned Git objects、6 份 default-set report/snapshot hashes 匹配。libtiff/libpng 均 partial/blocked，fixed 0 仍不能作为安全证明。最终需 owner I1 profile 接线后复跑所有 controls、对账源 hash/覆盖/限制。 |

### T1 本轮证据更新（2026-10-19）

- 在最新 main 基线的 T1 worktree 核验 A0 manifest 97/97 文件、提取片段 manifest 11/11。
- 既有 `results-ubsan` 为 12/12 subprocess exit 0，适配器断言显示攻击用例删除测试 victim、fixed 保留、safe/fixed-safe 正常；另外 `results` / `results-final` 存在 exit 64/1/139，失败状态需分开保留，不能说所有历史运行成功。
- T1 dated report 核实 8/8 上游源对象、97/97 A0 artifact、11/11 函数片段；精确源历史显示 6.1-LTS 与 7.0 tag 仍含相关代码，未找到官方 fix。12/12 e92 预编译机制二进制补充重放通过，原 PoC 镜像不存在，脚本编译失败和 sanitizer exit 139 均单独保留。产品构建/HAP、真实授权 HAP、服务 UID/SELinux 文件范围和官方 fix 仍 unknown；不得升格为产品确认。交付报告与 49 项 SHA/size manifest 已复核。

### D2 漏洞族集成与 Runner 回放（2026-10-19）

- 固定 OSGeo/libtiff v4.7.0 初始 replay 触发 `analyzed_files` 归一化错误；原 JSON/MD/trace 已保留。D2 在 A-owned detector 修复 partial coverage 归属后，最终 Runner replay 保留候选且维持 blocked。
- libtiff CVE-2025-9900、curl CVE-2026-92391、libpng CVE-2026-33416 三个真实披露组件样本分别产生 1、1、2 条 vulnerable 候选；固定源同规则 0 条，safe controls 0 条。curl vulnerable/fixed 解析完整且目标规则 completed；libtiff 和 libpng vulnerable/fixed 都为 partial/blocked，固定版零候选不算安全证明。OH libtiff pin 是单独 source identity，也命中 1 条 candidate。
- 用 `catalog.default_detector_ids()` 的 8 个默认启用 ID 做了 6 次 CLI/Runner normalized vulnerable/fix 回放：三组目标 rule 漏洞版命中、修复版同规则为 0。证据、源 snapshot、报告 hash 在 `worktrees/a-memory-d2-20261019/research/evidence/cpp/a-default-profile-replay-20261019/`。`ohscanner.known_disclosed_cves` 与 D1 path detector 仍需显式 opt-in/owner admission。D2 18/18 focused tests 复核通过，A lane scope 检查零越界。

### D1 开发交付与接口复核（2026-10-19）

- D1 已实现 opt-in `ohscanner.cpp.path_source_file_sink` v0.1.0；A0 sample 2 实际 `light-ast` detector set 不含该规则，因此它补的是能力覆盖，不是对该 A0 run 的漏检归因。Contacts 精确字节回放保留 3 条 partial/blocked source-bound may-flow candidate。
- 初始专属测试暴露 partial finding 未计入 `DetectorRun.analyzed_files`，会被 Runner `_normalized` 拒绝。本轮已在 D1 隔离分支修正为“已检查”的 analyzed_files 与 `file_outcomes=partial` 并存，新增 Runner normalization 回归；10/10 D1 tests、141/141 C++ family tests 通过。全 detector suite 有一项已重现的 D5 本地对象临时文件错误，未归因于 D1。
- D1 仍未注册进 Catalog/Runner；实际生产 profile 1day/Nday 路径覆盖要等 I1 owner-only admission/replay。

### T3 独立预审结果（2026-10-19）

- 未参与 D1/D2 实现的审阅线在 T2 干净 latest-main worktree 复跑 D1 10/10、D2 18/18 focused tests；从 pinned Git objects 重算 14 个 CVE vulnerable/fix 源文件 SHA，全匹配 M2 JSON。六个 default-enabled replay JSON hash 和 source snapshot hash 与 manifest 全匹配。
- D1 模块和 partial Runner normalization 通过；三组 D2 目标 detector differential 在组件范围通过。curl 1/1 complete；libtiff 2/2 与 libpng 4/4 两侧 partial/blocked，不能把 fixed 0 当安全结论。safe fixtures 完整解析且同目标规则 0 candidate。
- 未见 D1/D2 新增通用 detector 的 CVE ID、CVE 名称或组件路径/函数名硬编码；`known_disclosed_cves` 是既有 CVE 专项 opt-in detector，其 synthetic source-shaped replay 与 exact upstream CVE coverage 分开计数。
- T3 预审报告和重放日志在 `worktrees/a-triage-t2-20261019/research/deliveries/a-line-independent-review/20261019/`。最终 T3 仍等待 I1 owner profile/CLI admission，之后还须 exact 46675/67215/67216 sources/fixes、D1 CLI controls 与所有 profile controls 的 independent replay。

## 并行边界与结构化 Vibe Coding 提示词

### D1 — 文件路径 source-to-sink 检测器

```text
角色：OHScanner A 线 C/C++ detector 工程师。
工作基线：独立 worktree `worktrees/a-path-d1-20261019`，起点完整 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`。先读本分支 AGENTS.md 要求的六份文档、ownership.json、旧 A 线任务树和 Contacts T1 证据；审查记录只作来源证据。
问题：C/C++ detector 缺少对外部输入流向文件路径操作的有界 source-to-sink 分析。Contacts PortraitFileName 是 candidate 控制，不预设产品结论。
目标：先绑定精确 repo/commit/tree/path/blob/source SHA 与 A0 detector profile，重放未修改基线并定位缺口；再实现能跨字段提取、路径构造/变换和限定文件读写/删除 sink 的最小通用规则。路径拼接不单独告警；只有可审计的数据流与缺少安全 containment/basename/allowlist 才出 candidate。
范围：仅本 worktree A-owned `src/ohscanner/detectors/cpp/**`、规则私有 tests/fixtures 与 research 交付。不得改 Runner/Catalog/API/协议、B IPC、UI/平台、产品源码、T1报告或历史 ID；不 push/merge。
验收：positive、fixed、safe、unrelated、partial controls；unknown 不洗成 safe；稳定源绑定、可重放命令、规则版本、覆盖及成本记录；对不确定跨函数/宏/解析失败明确限制。完成前每轮更新任务状态并向主 Agent 汇报。
```

### D2 — 已披露漏洞家族回放与覆盖缺口

```text
角色：OHScanner A 线漏洞回归与 C/C++ 检测器工程师。
工作基线：独立 worktree `worktrees/a-memory-d2-20261019`，起点 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`。先读 AGENTS/ownership/六份文档及 `OHScanner_G盘源码漏洞审查记录_20261018.md`。
目标：把近年真实披露的 1-day/N-day 案例集成进 A 线静态扫描器的 source-bound 回归；优先评估 libpng CVE-2026-46675 UAF、libtiff CVE-2025-9900 OOB write、curl CVE-2026-92391 递归栈耗尽，备选 cJSON CVE-2026-67216/67215 CPU/递归 DoS。至少选 3 个案例、覆盖至少 2 个机制家族。每例建立“公告事实—精确 vulnerable/fix 源码对象—现有规则—A 生产入口回放—组件/产品边界”证据链；先识别机制缺口，再做可泛化的 A-owned 检测器/回归接入。
范围：只改 D2 worktree 的 A-owned C/C++ detector、私有 tests/fixtures、research/evidence。不得改 D1 path analyzer 或共享 Catalog/Runner/API/协议、产品组件、旧报告结论；不以 CVE ID、目录/函数名或 hash 硬编码；第三方代码只保留必要、许可合规的小型 fixture/引用，不 vendoring 整个组件；不凭无命中说 safe，不算无独立集的 P/R，不 push/merge。
验收：至少 3 个近年 CVE 案例并跨至少 2 个机制家族；精确绑定 source repo/commit/tree/path/blob/source SHA、fixed commit、profile、rule version；vulnerable→candidate，fixed/safe/unrelated→不报同根因，partial→保留候选或 unknown/blocked；A 生产 detector 入口可重复运行；未证实产品适用性保持 unknown；保留命令、coverage、开销、许可证和限制。若精确来源不可得，用同等级证据替换并记录原因。持续推进并向主 Agent 汇报。
```

### D3 — libpng CVE-2026-46675 精确源码覆盖缺口

```text
角色：A 线 C/C++ 资源生命周期规则工程师。
工作基线：延续 `worktrees/a-memory-d2-20261019` 的 A-owned D2 detector 代码；先固定 official advisory、vulnerable tag/commit、exact fix commit/tree/blob 与实际 Scanner SourceUnit bytes。
问题：CVE-2026-46675 的精确 vulnerable `pngrutil.c` 当前 Runner parse partial/blocked，资源生命周期规则 0/1 inspected、0 findings；synthetic shape hit 不能替代 exact source coverage。
目标：在精确 vulnerable upstream source 上保留 source-bound UAF mechanism candidate，并在 exact fix 和 safe/unrelated controls 上对同 root cause 安静；partial 必须 blocked 且不能洗成 clean。优先改进通用跨函数状态/生命周期证据或有界 parser coverage；不得按 CVE ID、libpng 路径、函数名或 source hash 特判。
范围：只改 D2 worktree 的 A-owned `src/ohscanner/detectors/cpp/**`、私有测试/fixtures、research CPP evidence/deliveries。不得改 shared Catalog/Runner/contracts、D1 path analyzer、产品源码或 A0/T1 verdict；不得 vendoring 整个 libpng。
验收：官方 vulnerable/fix source identity 和每个 scanned file SHA 可独立复算；actual CLI/Runner vulnerable candidate、fixed/safe/unrelated same-root-cause zero、partial/failed controls 状态保持 blocked；focused regressions、预算/成本、scope check 全通过。若模型无法安全表达，保留失败产物、明确缺口，不声称覆盖。
持续执行：先重现 exact-source 0-candidate/partial，再做有界泛化实现和 counterexamples；每轮记录状态、hash、命令、成本、失败与下一动作，直至验收门或外部阻塞。
```

### D4 — cJSON CVE-2026-67216/67215 精确源码覆盖

```text
角色：独立 A 线算法/检测器工程师，聚焦 JSON parser 复杂度与递归 DoS。
工作基线：使用 `worktrees/a-triage-t2-20261019` 的 latest-main SHA；保留已有 T2/T3 交付，只在 A-owned C/C++ detector/tests 与 CPP research scope 新增 D4 内容。对照 D2、官方公告与上游 sources。
问题：`ohscanner.known_disclosed_cves` 的 source-shaped controls 不能证明 exact upstream CVE coverage；cJSON CVE-2026-67216/67215 的精确 vulnerable/fix identities 与扫描结果尚未闭合。
目标：绑定 affected/fixed upstream 对象和实际 source hashes，评估通用 complexity/lifetime 规则与 opt-in CVE rule pack。新规则匹配结构性算法形状（例如递归树遍历加重复线性查找、深拷贝加递归释放且缺少有效深度界），不按 CVE ID、cJSON 路径、函数名或 hash 特判。
范围：仅改该 worktree A-owned C/C++ detector/tests/fixtures 和新 D4 research/evidence；不得改 T2/T3 原交付、D2 worktree、Catalog/Runner/public contracts 或产品代码，不 vendoring 完整第三方组件。
验收：每个 CVE 独立提交 exact vulnerable/fix/safe/unrelated/partial 矩阵、公告与修复版本/commit、source commit/tree/blob/SHA、normalized CLI/Runner reports；漏洞版 candidate，修复/安全版同 root cause quiet，partial 继续 blocked；focused tests 与 scope check 通过。无 exact fixed source 时不得把 synthetic control 冒充修复版。
持续执行：证据不足时保留源报告和失败结果，继续查 upstream patch/tag 或公开 release archive；未闭合 gap 排入后续 A 线 P0/P1 队列，不能只停在一次静态审阅。
```

### T1 — Contacts 产品证据与修复闭环

```text
角色：A 线独立安全测试负责人；当前任务树 P0/partial。
工作基线：独立 worktree `worktrees/a-contacts-t1-20261019`，起点 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`。对照 A0 原始交付、8 个已 pin 源对象和旧 T1 复核。
目标：逐项证明真实入口→WRITE_CONTACTS/调用者权限→攻击者可控 PortraitFileName→路径操作及文件范围→可证 CIA；精确查修复提交和受影响版本；在无网络、降权、资源受限隔离环境重复 vulnerable/fixed/safe/fixed-safe。
范围：只写 T1 日期化证据；不改 detector/原始报告/历史结论，不攻击设备/线上服务；ASan/UBSan exit139 保留为失败限制。
验收：repo/commit/tree/path/blob/SHA、构建/镜像 digest、权限、版本/修复和全部实验可审计。证据缺失就逐项标 unknown/partial 并说明解阻动作，不升级产品结论；持续推进并汇报。
```

### T2 — 345 条候选分诊和验证队列（已完成）

```text
角色：A 线独立测试与证据分诊负责人。
工作基线：独立 worktree `worktrees/a-triage-t2-20261019`，起点 SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8`；输入仅用 A0 原始报告/样本/日志/对账产物。
目标：保留 345 条候选的原 ID/来源/结论，逐条归类阻塞原因（依赖、入口/权限、PoC、源码/对象、解析/覆盖、修复版本），排序补证优先级并产出下一轮可执行队列；当前主要家族是 shared_ptr race 263 条、IPC relay descriptor 62 条、capability export 14 条、IPC auth missing 4 条、其他规则各 1 条。优先复核 9 条 not_reproduced 和高风险 not_testable。
范围：只写新日期化 triage 交付，不改 detector、扫描器原始分类、历史报告和候选 ID；not_testable/not_reproduced 不等于误报；不计算不合格数据集的 Precision/Recall。
验收：逐项总数对账、来源键不变、理由有证据指针、行动有 owner/依赖/验收条件；旧产物只读。完成后由 shared owner 处理 I1 生产接线，再供 T3 独立验收。
```

### I1 — 共享 Catalog/Runner 准入与可复用 A profile（owner-only）

```text
角色：OHScanner shared Catalog/Runner owner；A 线提供需求与证据，不能代替你修改共享接口。
工作基线：最新 main `db77164fdc2af0da02e4d3efc056d84694fd68e8`；审阅 D1、D2 的 detector contract、registration/profile handoff 和可重放证据目录。
目标：定义并实现一个明确的 A-line disclosed-CVE 扫描 profile，使 A-owned 默认启用 detector 与经独立审查批准的 opt-in detector 可复用；让 CLI/Runner 记录准确 detector/version/profile/coverage。
优先候选：默认集已有 `integer_bounds` 0.2.1 与 `resource_lifetime` 0.3.0；待评估 `known_disclosed_cves` 0.16.0 和 D1 `path_source_file_sink` 0.1.0。保留 candidate-only/admission 限制；不得因已知 CVE 名称或产品未知而自动升级结论。
范围：共享 Catalog/Runner owner 负责 shared-file 修改、默认/opt-in 策略和 CLI contract；不得给研究规则做漏洞硬编码例外。若要改公开 API，先拆契约兼容方案。
验收：干净最新基线通过 catalog/planner/Runner/CLI checks；profile enumeration 显示准确 detector IDs/版本；对 D2 三组 vulnerable/fix/safe 与 partial 对照、D1 Contacts source 与 fixed/safe controls 做真实 CLI/Runner replay；candidate 保留、fixed/safe 不报同根因、partial 仍 blocked；报告含复现命令、source SHA、配置 hash 和失败输出。T3 独立复验通过前保持 opt-in。
持续执行：每轮先核对 shared ownership/dirty paths，保存完整 diff；修失败后重跑针对性检查；不得 push/merge。遇到无标签 holdout 或解析 unknown，记录审批门和责任人，继续完成其他工作。
```

### T3 — 独立验收与下一轮漏洞覆盖矩阵

```text
角色：未参与 D1/D2 实现的 A 线独立 detector 验收工程师。
工作基线：确认 D1/D2/T1/T2 隔离工作树的基线、状态与 handoff；I1 完成后使用其 profile 定义，不修改原始报告或 detector 实现。
目标：独立复跑候选检测和否定控制，审查披露公告、精确 vulnerable/fix/safe 源 pin、CLI/Runner normalized report、coverage/partial 语义及 source hash，逐项标通过/不通过/证据不足。
范围：只增加独立验收报告、重放产物及下一轮队列；发现 detector 问题转给对应 owner。产品 reachability/权限/构建保持单独证据项。
验收：复跑 D1 positive/fixed/safe/unrelated/partial；D2 libtiff、curl、libpng vulnerable/fix/safe，覆盖默认与 opt-in profile；独立核验 CVE-2026-46675 和 known-CVE holdout；确认 partial finding 经过 Runner 后仍存在且状态 blocked；保留 miss、误报、源身份不符和失败原始输出。不得用 detector 单测代替 CLI replay。
持续执行：逐 blocker 复核至 complete 或明确外部解阻动作；生成候选级缺口账本，按 P0/P1 排入后续 A 线并行 Agent；未经独立复核不宣称相关 N-day 已完整覆盖。
```

### D3 — libpng CVE-2026-46675 跨函数生命周期缺口（后续队列）

```text
角色：OHScanner A 线 C/C++ source parser 与资源生命周期 detector 工程师。
工作基线：最新 main SHA `db77164fdc2af0da02e4d3efc056d84694fd68e8` 的独立 worktree；启动前核验所有权并避开 D4 的 detector 文件。
目标：在精确 libpng vulnerable/fix 源上定位 png_read_info/png_read_end、zstream 输入缓冲 owner/free/read 的跨函数状态传播缺口；改进通用 parser/detector，而非用 CVE、路径、函数名或哈希特判。
范围：只改 A-owned parser/detector 私有目录、模块 tests/fixtures 和日期化 evidence；不得改 known-CVE signature、shared Catalog/Runner/API 或产品源码。
验收：精确源身份（repo/commit/tree/path/blob/source SHA）对账；vulnerable 根因 candidate、upstream fix/safe/unrelated 对同根因安静、解析 partial 时保留 candidate 或 blocked/unknown；真实 CLI/Runner 报告含 detector/rule version 与覆盖状态；组件 Harness 不等于产品结论。
持续执行：每次运行保存完整失败输出；修复到全部定向 controls 通过，或者明确列出 parser/上游固定源不可得 blocker、责任人和解阻动作；持续更新任务报告，不推送/合并。
```

### D4 — cJSON 复杂度/递归资源耗尽机制（进行中，Agent `/root/a_cve_coverage`）

```text
角色：OHScanner A 线 C/C++ complexity 与 resource-exhaustion detector 工程师。
工作基线：`worktrees/a-memory-d2-20261019`，HEAD `db77164fdc2af0da02e4d3efc056d84694fd68e8`；只编辑新 A-owned detector/test/evidence，先读 ownership 与 detector contract。
目标：分别评估并检测 CVE-2026-67216 的递归树比较叠加重复线性键查找，以及 CVE-2026-67215 的递归复制/树增长再递归清理。把编号/符号名只用作回归映射，生产 rule 不绑定 CVE、cJSON 路径或专有函数名。
范围：仅新的 A-owned C/C++ detector、私有 tests/fixtures、research/evidence/deliveries。禁止改 `known_cves.py`、D1 path detector、Catalog/Runner/API/协议、cJSON 产品源码。
验收：机制 positive、fixed/safe、unrelated、partial controls；优先精确核验 vulnerable/fixed Git 源身份与实际 CLI/Runner；source-shaped signature 只能作为 smoke control。按复杂度声明预算、解析限制和 candidate obligations；所有未知调用方/版本/产品 reachability 保持 unknown。
持续执行：先做规则可行性和源身份审计，再实现最小泛化规则并迭代针对性回归；若规则无法在有界 AST 中可靠区分，交付明确 blocker 和下一种可审计分析方案，不允许以命中 CVE signature 作为关闭任务依据。
```

### H1 — Ark 历史 CVE-2025-0587/23420 当前 CLI 重放（进行中，Agent `/root/a_t1_followup`）

```text
角色：A 线独立 source-bound regression 工程师。
工作基线：最新 main 基线的隔离工作树；输入仅为整合版报告、历史 A memory-safety 摘要与当前 detector 实现。
目标：恢复并核验 `atomic_helper.cpp` 的 CVE-2025-0587 vulnerable/fix commits，以及 `JSArray::SortElementsByObject` 的 CVE-2025-23420 vulnerable/fix commits；当前生产 CLI 对应使用 `integer_bounds` 和 `bounds`。
范围：只新增日期化研究交付/证据；不改 detector、原始审查记录、Catalog/Runner、历史候选 ID 和旧结论。
验收：核实 commit/tree/path/blob/source SHA 与 patch SHA；vulnerable/fixed/safe/unrelated/partial 配对；历史 1/0 与 5/0 只作为待验证线索，不要求复现旧候选数；完整保存 normalized reports、命令、scope/parser state 和失败输出。来源无法恢复时准确标记 unknown/blocker。
持续执行：逐案例完成证据绑定与当前 CLI/Runner replay；每轮登记剩余步骤、依赖和 owner，直到各项 complete 或达到可审计外部 blocker；不推送/合并。
```

### A2 — 全部已披露编号适用性与 scanner reachability（进行中，Agent `/root/full_cve_crosswalk`）

```text
角色：A 线 detector 覆盖审计负责人。
工作基线：最新 scanner HEAD `db77164fdc2af0da02e4d3efc056d84694fd68e8` 加当前 D2 evidence；唯一审查来源为用户指定文件 `research/deliveries/cpp/源漏洞审查记录_20261018_A线整合版.md`。
目标：对报告中的全部独立披露 CVE 做逐项 applicability mapping，回答 A-line C/C++ 静态分析是否应扫描、是否已有通用 root-cause detector、是否仅有 opt-in CVE signature、是否 default reachable、是否 historical/N/A/current-version-not-affected。
范围：只新增日期化交付；不得修改源码、Catalog/Runner/API、原始报告或 detector findings。其他报告只能作线索，不能替代权威输入。
验收：每行有精确源报告位置、规则 ID/version/default status、真实 source/CLI evidence 与 parse status、产品/组件边界、下一动作和 owner；签名存在不等于根因验证，partial 0 不等于安全，N/A/不受影响不等于漏报。
持续执行：逐条追到证据完成或明确列出 blocker 与 owner；跑文档 diff/scope checks；将 P1/P2 缺口并入 A-line 任务树和候选并行队列。
```

## 持续执行与收口

每条线以当前 Goal 为持续目标：每轮先核对基线、worktree、dirty paths 与最新远端；按依赖持续执行到完成门或明确外部阻塞；更新交付中的状态、来源、命令/结果、未知项、owner 与下一动作。D1/D2 开发者回归不替代 T3 独立验收；PoC、CVE 公告、候选数下降、零命中和 partial/blocked 都不构成产品安全证明。`AGENTS.md` 将 Catalog/Runner 列为 shared owner-only；若 I1 未完成，新增 detector 仅算研究模块，不声称最终 N-day scanner 已接线。T3 在 D1/D2/T1/T2/I1 齐备后由未参与实现者执行。未获明确授权不 push、merge、发布。
