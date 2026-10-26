# A 线开发续航计划与并行任务树（2026-10-19）

## 基线与仓库状态

- 远端已执行 `git fetch origin --prune`；最新 `origin/main` = `db77164fdc2af0da02e4d3efc056d84694fd68e8`（PR #29 合并后的 main）。
- 原 A 线工作树 `codex/a-line-scanner-regression-20261018` 有大量未提交改动，保留原样；没有在其上执行 pull/reset/checkout/clean。
- 本轮代码工作树：`worktrees/a-path-traversal-detector-20261019`，分支 `codex/a-path-traversal-detector-20261019`，起点正是上述 main SHA。
- 证据输入：`research/deliveries/a-line-sample30/20261018/`；A0 抽查 30 份、345 条扫描候选的原始交付继续只读保留。Contacts 路径穿越 `ohscanner-contacts-path-traversal-001` 是相邻上下文审查发现，不是 OHScanner 直接发现；产品可删范围、具体产品构建/版本仍待闭环。
- 公开 CVE 记录来自 `CyberSecurity-Innovation-Audit-c4/research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`。最新 main 的 `KnownDisclosedCveDetector` 对其中大多数机制已有独立候选规则，但 catalog 默认关闭，只有显式选择时运行；存在三个需先清理归因的对象：CVE-2026-58313、CVE-2026-28733、CVE-2026-28751。报告未建立这些规则对应根因的源码映射，当前不得称其为 CVE 漏洞命中或产品漏洞。

## 当前开发进度

- D1 根因已证实：当前 main 的 A C/C++ detector family 无路径穿越/source-to-file-sink 规则。既有 `known_cves.py` 虽有显式漏洞模式检测，但默认关闭，且不覆盖本次 Contacts `PortraitFileName` source-to-sink 机制。
- A0 的原始 run manifest 显示 sample 2 实际只运行 IPC、C++ lifetime 和 shared_ptr race 三个 detector；原扫描 scope 是 `foundation/distributeddatamgr/data_share`，相邻审查漏洞的实现位于另一个 Contacts 仓库。因此这属于 detector family 缺口与仓库/scope 边界同时存在，不能称为 A0 同一 scope 下的直接扫描漏报；要扫到机制须显式纳入 Contacts 源码及适当 profile。
- 从旧隔离 A 线 worktree 选择性迁入了 `path_traversal_detector.py` 原型与对应专属 fixtures 到最新 main；为准确覆盖 Contacts 的删除影响，新增了 `FileUtils::DeleteFile` 带 receiver 类型约束的 sink model 和精确源码片段回归。
- 已运行：`python -m unittest tests.detectors.test_cpp_path_traversal_detector -v`，9/9 通过。精确 Contacts excerpt 当前输出 `DeleteFile` 23/24/28 行及 `open` 42/53 行的 CWE-22 source-bound candidate；整体 status 为 `blocked`，因为 `GetPixelMap...`/`SavePixelMap...` 等其他外部 wrapper 仍未建模。规则为研究级 detector，未接共享 catalog，因此普通默认扫描尚不能运行此新规则。
- 又以本机 OpenHarmony checkout 中的完整 `contacts_data_ability.cpp` 做了 detector-level 重放：85,339 bytes，SHA-256 与既有 T1 manifest 相同（`c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`）；输出 `DeleteFile` 792/793/797 与 `open` 811/822 共 5 条候选、coverage `blocked`。这是直接 detector API 源码重放，不是 CLI/生产 profile 扫描；request provenance 保持 fixture，Git 对象身份仍按 T1 原始来源表，未从 Windows 子仓库读取 Git 元数据。
- 完整来源边界与 detector replay 结果见 [源码重放 JSON](../../evidence/cpp/path_traversal/contacts_full_source_replay_20261019.json)；最新 CVE 对照审查见 [Known CVE coverage review](A_KNOWN_CVE_COVERAGE_REVIEW_20261019.md)，T1/T2 摘要分别见 [T1 产品证据状态](A_T1_PRODUCT_EVIDENCE_STATUS_20261019.md) 与 [T2 候选分诊状态](A_T2_CANDIDATE_TRIAGE_STATUS_20261019.md)。
- 已知限制：检测器是 bounded lexical same-translation-unit dataflow，不证明 C++ AST 类型/控制流/调用者权限/产品构建可达性；目录 containment 只能抑制模型识别出的 basename、字面允许清单及有限 canonical-relative 防护。候选不等于产品漏洞确认。
- `DeleteFile` 是基于 T1 精确源材料的显式 `Contacts::FileUtils::DeleteFile` API 模型，单文件 fixture 不含其跨文件实现；后续应绑定 `FileUtils::DeleteFile` 的真实定义与内部 `unlink`，再决定是否提升为由方法体自动导出的 sink summary。调用方法名自身不能作为任意工程代码的通用 sink 证据。
- T1 独立复核没有新产品证据：产品 build/SHA 映射、真实 HAP 权限调用、服务 UID/SELinux 和路径影响边界、完整发布线/修复对象、产品级 fixed/safe 重放仍未知；ADJ-001 的 confirmed 只针对源码机制/Harness 范围。

## 任务树与并行依赖

```text
A1 扫描器/证据闭环
├─ D1（P0，本轮执行中）：路径穿越 source-to-file-sink detector
│  ├─ D1a：精确 Contacts 源码绑定与 A0 run profile/默认 detector 覆盖证据
│  ├─ D1b：positive/fixed/safe/unrelated/partial 回归及保守 blocked 语义
│  ├─ D1c：公开 CVE 检测面逐项核验；不可信 CVE 归因先移出 CVE claim
│  └─ D1d：申请 owner 将 detector 接入显式 security profile；等待共享 catalog 审核
├─ T1（P0，Agent 并行）：Contacts 产品入口/权限/服务 UID/SELinux/版本/修复映射
├─ T2（P1，Agent 并行）：345 条原始候选中的 9 not_reproduced 与高优先级 not_testable 分诊
├─ D2（P1，依赖 T1/source records）：已披露 CVE 检测模式的根因归因与真实源码前后对照
│  ├─ D2a：58313/28733/28751 精确归因复核
│  ├─ D2b：优先补 9900/92391/67215/67216/25212/27247/27648/45877 的官方源码前后控制
│  └─ D2c：为默认关闭的 KnownDisclosedCveDetector 提交显式 profile 接入建议（不改 catalog）
└─ T3（P2，D1/T1/T2/D2 后）：独立验收 source binding、候选状态、测试对照、变更范围和统一交付
```

| 线 | 本轮 Agent / owner | 输入 | 完成门 | 状态 |
|---|---|---|---|---|
| D1 Scanner | 主开发负责人 | A0 Contacts excerpt、最新 main detector 架构 | 精确源码候选可复现；fixed/safe/unrelated/unknown 控制；测试通过；scope 无越界；共享 catalog 请求独立提出 | 实施中 |
| T1 Product evidence | `a_t1_followup` | A0/T1 静态复核、PoC 与精确 Git 对象 | 入口/权限/数据/可删范围/产品构建与版本/补丁分别以来源证明；unknown 独立列出；不使用开发 fixtures 作产品证据 | 进行中 |
| T2 Candidate triage | `a_t2_candidate_triage` | 原始 345 ID/判定/扫描产物 | 9 not_reproduced 全部有最小补证动作；高优先级 not_testable 有阻塞分类与有限队列；可对账且不改旧状态 | 已复核并写本轮摘要；原始 2026-10-18 队列保持未改 |
| D2 CVE source mapping | `a_cve_coverage` 审查，后续需 A/CVE owner 修正规则 | 审查报告、规则源码及公告/上游 exact objects | CVE 根因→受影响源码→修复源码逐项绑定；无依据的 CVE 标签先隔离，不损失可用通用候选 | 覆盖审计已交付；三项误归因修正及真实源码配对仍待执行 |
| T3 Independent review | 未参与上述实现的 agent | D1/T1/T2/D2 固定交付 | 独立复跑、来源/hash/范围/状态/报告一致性逐项 pass/partial/block | 排队 |

## 结构化并行 Vibe Coding 提示词

### D1 — A 线 C/C++ 路径安全检测

```text
角色：你是 OHScanner A 线 C/C++ detector 工程师，对 detector 与专属 fixtures 负责，不负责产品漏洞确认。
目标：用严格 source-to-file-sink 语义发现 A0 的 Contacts `PortraitFileName` 路径穿越机制，同时避免把路径拼接本身当漏洞。
基线：origin/main `db77164fdc2af0da02e4d3efc056d84694fd68e8`；完整来源 `openharmony/applications_contacts_data@341cc3bf41b48e9a5f278dd088f40a2041d2f1c9`，tree `2054824c04bb403eeea128a9262edfb3001efa4f`，path `dataBusiness/contacts/src/contacts_data_ability.cpp`，blob `c93e950725adc93276916b3c96c5ac7a5bb5b6b7`，SHA-256 `c9d1f03da5994f32b6af7254ba505eb616713209222f48f1f91117c4827201b6`。
边界：只改 `src/ohscanner/detectors/cpp/**`、`tests/detectors/test_cpp_*.py`、`tests/detectors/fixtures/cpp_*/**`、`research/deliveries/cpp/**`；不要改 runner/catalog/contracts/API、默认 detector 列表、UI、历史 A0 原件。公共接入另提 owner request。
步骤：固定来源/profile → 记录 baseline detector coverage → 实现 typed DataShare string source、path transforms、同 TU bounded flow、直接文件 sinks 与有明确接收者类型的显式 wrapper sinks → 加 vulnerable/fixed/safe/unrelated/partial/macro/预算控制 → 运行专属测试和 scope check → 保留失败/blocked 与限制。
完成门：精确 Contacts excerpt 至少在 `DeleteFile(srcFilePath)` 产生 source-bound CWE-22 candidate；路径拼接无 file sink 不报；canonical containment/basename/allowlist 负例不报；无关同名 API 不报；跨函数、宏、外部 wrapper、partial 不能证明时 blocked/unknown；测试记录可复现。不得以此声称产品漏洞已扫描确认。
交付：改动清单、规则边界、对照矩阵、命令/结果、A0 scan profile 缺口、未完成的公共 catalog request。
```

### T1 — Contacts 产品证据与修复闭环

```text
角色：你是独立安全验证负责人，不改 detector，不用机制 harness 代替产品入口证据。
目标：闭环 `ohscanner-contacts-path-traversal-001` 的真实入口、`WRITE_CONTACTS` 边界、攻击输入、文件影响、产品 build/SELinux/版本和官方修复对象。
输入：只读 `research/deliveries/a-line-sample30/20261018/`；精确 Contacts/DataShare Git 对象；已存在 PoC 的 attack/fixed/safe/fixed-safe 原始日志及 Docker digest。
步骤：复核源 commit/tree/blob/hash；追踪 BatchInsert 到 PortraitFileName 到 filesystem sink；验证权限检查和服务身份/SELinux policy；确认产品构建是否包含精确仓库版本；查 exact fix commit 和受影响 refs；在授权隔离环境复跑现有机制 PoC，并区分 adapter 与产品配置差异。
完成门：入口/权限/攻击者输入/触发/可证明 CIA/版本与修复范围逐项有可审计证据；缺少设备或 build 证据时明确 unknown/partial，不用版本日期推断。
交付：source binding 表、入口/权限图、build/version/fix 矩阵、复现命令与原始结果、限制和最小后续动作；仅新增日期化 `research/deliveries/cpp/**` 报告，不改旧候选。
```

### T2 — A0 的 345 项候选优先级分诊

```text
角色：你是 A 线独立证据分诊负责人，不改 detector、不改写历史报告。
目标：让 9 条 not_reproduced 与有明确补证路径的高优先级 not_testable 成为有限、可执行、可复核的队列。
输入：`research/deliveries/a-line-sample30/20261018/` 原始 ID、报告、逐项结论、scope/profile、源码/hash、日志与对账材料；全部原始 status 保持不变。
步骤：校验源材料统计/hash；逐项分类源码/构建/parser/权限/入口/PoC/环境/修复对象等阻塞；记录最小补证动作、潜在影响、补证成本、可重放性、owner/dependency；识别重复根因或家族泄漏；不把 not_testable/not_reproduced 当作安全，也不为凑量扩范围。
完成门：队列能回对原 345 条；9 条 not_reproduced 全有可执行下一步；首批 testable 选择理由明确；保留未选项及原因；无无效 precision/recall。
交付：新日期化 Markdown+机器可读 JSON/CSV、对账方法、优先/暂停队列、hash；不覆盖原记录。
```

### D2 — 已披露 CVE 规则归因与覆盖验证

```text
角色：你是 A 线检测规则与来源映射审查者。规则命中是源码候选，不自动证明受影响产品漏洞。
目标：逐项对照 `OHScanner_G盘源码漏洞审查记录_20261018.md` 和 `src/ohscanner/detectors/known_cves.py`，判定检测器是否匹配公告根因、当前源码、修复源码、构建/入口边界。
优先：先审 CVE-2026-58313、CVE-2026-28733、CVE-2026-28751 的根因归因；再补 9900/92391/67215/67216/25212/27247/27648/45877 等仅有合成测试的真实源码前后配对。对 92392/9079、46675/33636 和 cJSON 现态保留版本/产品状态边界。
边界：不编辑 `known_cves.py`、catalog、默认配置或产品结论；缺精确提交/树/blob/修复 hunk 就标 unknown/unattributed；通用机制保留为 candidate，但不强贴 CVE。
完成门：每项有公告根因→affected source→fix source→detector condition→regression fixture 的可审计映射；无证据的 CVE tag 被列入待修正清单；显式关闭的 detector 不能称普通默认扫描覆盖。
交付：来源/规则矩阵、漏洞/修复 before-after hash、测试缺口、owner scope request。
```

### T3 — 独立收口审计

```text
角色：你是未参与 D1/T1/T2/D2 的独立审查者。
目标：复跑代码回归并审核 A 线交付的来源、权限/产品边界、候选状态、报告统计和改动 scope。
步骤：核验 immutable base 与当前 head；独立 hash exact source/fixtures；重跑 detector controls；核验漏洞/fixed/safe/unrelated/unknown 对照；检查 T1 产品证据与 T2 原 ID 对账；运行 `scripts.check_change_scope`，确认越界为零。
完成门：逐项 pass/partial/block 有证据；不得把作者自测当独立产品验证；不得自动 push/merge/发布。
交付：独立验收表与未完成的最小修复列表；不直接改作者成果。
```

## 持续执行目标

主 Goal 保持 active，直至 D1/T1/T2/D2 的交付可独立复核并由 T3 完成审计。每个续航回合：先核 `origin/main`、分支/HEAD/worktree/status 与当前精确 source binding；继续 owner/dependency 已满足的队列；结束时记实际命令、通过/失败/blocked、更新来源/限制与下一项。T1/T2 可并行；D2 的三项 attribution 要优先完成；T3 等 D1/T1/T2/D2 输出后启动。任何缺失证据都作为最小解阻任务，不用人工判断填补。
