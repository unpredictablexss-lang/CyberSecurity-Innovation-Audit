# C 线后续并行任务、结构化 Vibe Coding 提示词与持续目标

更新：2026-10-19（Asia/Shanghai）。

## 0. 固定输入与结论边界

- 最新主线：`origin/main` @ `db77164`；最新 C 线静态集成分支：`origin/codex/c-line-static-20261019` @ `09ba5aba03c7c7d6787bace349b8fc0a6b0a5457`。C 线算法补丁基线 `codex/c-line-scanner-optimization-20261019` @ `7af25f5ced471e5d6acc8cf5efd4c696275ce940`（算法提交 `715e29884a845a2daa80016f332c70b3db84ca45`）现在只作为选择性迁入源。
- 审查原文所在 pinned C 线远端：`origin/codex/c-line-ark-runtime-20261018` @ `e4e0761501a83ac25cc67d04c527eefe9f4a1b50`。最新主线已有 `src/ohscanner/detectors/known_cves.py` 0.16.0 和对应 17 项公开 CVE 回归；规则存在不等于分支可运行或产品漏洞成立。
- 审查原文 Git blob：`dbedea677c8dc70c1b0066c7bc52df27bcff06ea`，tree `307ac8237263db793028e0bf34a82a85f60821a5`，29553 bytes，SHA-256 `732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240`。
- 原文已按 blob 字节迁入 `research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`；导入身份见 `research/deliveries/c-line/source-audit-import-manifest-20261018.json`。
- 公开披露、组件复现、静态 candidate 和产品 confirmed/reportable 必须分层。扫描器对已知输入的最低保证是产生正确 candidate、显式 unknown/limitation 或可审计 not-applicable，不能静默 0，更不能把 0 findings 写 safe。

## 1. 已启动的 C9 并行线

| 线 | 子 Agent | 隔离工作树 | 当前最小交付 |
|---|---|---|---|
| C9-TYPE-ORIGIN | Halley (`01a15311-208b-70d3-9f7a-217dedc42329`) | `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/type-origin` | 已完成 old-baseline 30/30 与六个 C3 反例；latest 架构移植并入 C10 semantics |
| C9-EXCEPTION-GUARD | Euclid (`01a15311-21d7-7161-bd39-d7fea7acaf97`) | `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard` | 已完成 IC7B8Q/I7E0FM 五类控制；old Ark 153 pass/8 skip，latest patch 已产出 |
| C9-PARTIAL-OWNER | Ohm (`01a15311-232a-7792-bd05-42eb8ac5ae32`) | `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/partial-owner` | 已完成 36 条对账、owner 14 tests/1 skip、mapping 9/9、fail-closed 5/5 |
| C9-INTEGRATION | Cicero (`01a15311-247a-74a0-9085-9a8aa13b7060`) | `E:\网安\CyberSecurity-Innovation-Audit-c-line-static-20261019`（09ba5ab） | 已完成最小完整性修复并恢复可运行基线；后续算法/source identity/gap rules 已合入 dirty state 并通过最终复验 |

当前四条线不得 commit/push/merge/reset/fetch，不覆盖彼此 dirty 证据；算法修复、公共 contracts/Runner/Catalog 变更和最终合流必须分开。

## 2. “已有漏洞可扫描”验收口径

2026-10-19 最终验证：09ba5ab 原始树缺失/损坏已由 pinned `e4e0761` blob 选择性修复。latest C 线 Windows 复验为 Ark discover 170 pass/3 historical skip、gap focused 19/19、known CVE 21/21、compileall 与 git diff --check 通过。IAO7GO/I7W51D/IB8BCA 生产适配器复放分别为 `1→0`、`1→0`、`3→0`。这证明已知回归形状可被扫描为 candidate/显式 unknown，不证明产品漏洞、全项目 Recall 或安全。


| 输入组 | 最低扫描器行为 | 禁止误读 |
|---|---|---|
| Ark 9 案例：CVE-2025-24304、IBS5YG、I7KZJ7、IC7B8Q、I7E0FM、IAO7GO、I7W51D、IB8BCA、IAO7E8 | 父输入 candidate/显式 unknown，修复或安全控制不产生同根因 candidate；不适用必须给出原因 | 不代表产品漏洞或完整 TU 安全 |
| 本地组件 5 项：CVE-2026-46675、CVE-2025-9900、CVE-2026-92391、CVE-2026-67216、CVE-2026-67215 | 已知危险形状至少产生 source-bound candidate 或明确 limitation；fixed/safe/unrelated 分开 | 组件 Harness/静态命中不证明产品可达 |
| OpenHarmony 公告 10 项 | 源对象存在时映射现有/新 candidate；源对象缺失时给出 source unavailable/unknown | 历史公告不证明当前 master 或当前产品受影响 |
| 排除 2 项：CVE-2026-92392、CVE-2026-9079 | 生成版本/机制反证或 not-applicable 记录 | 不是 safe，也不计漏洞命中 |
| 4 个人工 candidate | 检测形状与 proof obligations 分开；并发、签名、跨账号副作用保留 candidate | 不因规则命中升级 confirmed |

## 3. C10-ARK-GAP-RULES

> 执行结果：C10-ARK-GAP-RULES 已完成。IAO7GO 使用 `ark.runtime.native-inline-pending-exception-propagation` v1.0.0，I7W51D 使用 `ark.runtime.typedarray-length-signed-to-unsigned-narrowing` v1.0.0，IB8BCA 使用 `ark.runtime.dataview-index-width-bounds` v1.0.0；全部保持 candidate/unassessed。

### 任务

补齐 `IAO7GO` selector/applicability、`I7W51D` signed-length narrowing、`IB8BCA` DataView/Atomics index-width/bounds 三个显式缺口。先保证“不静默漏掉”，再做有限语义增强。

### 结构化 Vibe Coding Prompt

```yaml
role: Ark Runtime missing-coverage rule engineer
objective: >
  为 IAO7GO、I7W51D、IB8BCA 建立稳定 Detector/rule 身份和保守语义，
  使已知父源码产生 candidate 或 explicit unknown，修复/安全控制不产生同根因候选。
inputs:
  - review blob dbedea677c8dc70c1b0066c7bc52df27bcff06ea
  - pinned C commit e4e0761501a83ac25cc67d04c527eefe9f4a1b50
  - local optimization commit 715e29884a845a2daa80016f332c70b3db84ca45
write_scope:
  - 新 isolated worktree 中的 Ark model/detector 规则实现
  - 对应 positive/fixed/safe/unrelated/unknown fixtures 和 tests
  - research/experiments/ark_runtime/c10_ark_gap_rules_20261019/
constraints:
  - 不使用外部扫描器、历史 verdict、名称相似性或模型自评
  - partial/blocked/0 findings 不得转 safe
  - 不改公共 contracts/Runner/Catalog；若确需变更另立提交
acceptance:
  - 三个 known parent 均命中 candidate 或显式 unknown
  - fixed/safe/unrelated 不产生同根因 candidate
  - source-bound ID/version/scope/profile 完整
  - focused/full tests 的 pass/fail/skip/block 可复现
continuation:
  - G10-AR-1 规则合同
  - G10-AR-2 三个父/修复控制
  - G10-AR-3 alias/cast/helper 扩展
  - G10-AR-4 真实 replay 与 profile closure
deliverables:
  - minimal patch
  - control matrix
  - exact commands and outputs
  - limitations and next slice
```

### 持续执行目标

每轮只推进一个机制；下一轮依次处理跨 helper、alias、cast、loop backedge、编译 profile 和历史 replay。目标未闭合时持续追加最小切片，不用任务量替代证据。

## 4. C10-KNOWN-CVE-COVERAGE

> 执行结果：origin/main 与 latest C 线的 `known_disclosed_cves` 0.16.0 已覆盖 17 个公开 CVE 形态；source identity 测试修复后 21/21 通过，Detector blob 未改变。

### 任务

为审查记录中 17 项公开漏洞和 4 项人工 candidate 建立 known-case 回归包。优先覆盖本地组件 5 项，并把其余项目映射到现有 bounds、integer、lifetime、resource、shared_ptr、IPC 规则或建立新 research candidate 规则。

### 结构化 Vibe Coding Prompt

```yaml
role: known-vulnerability regression and bounded rule engineer
objective: >
  把审查记录中的公开漏洞和人工 candidate 转成 source-bound known-case corpus，
  确保每个输入产生正确 candidate、explicit unknown、not-applicable 或可审计 limitation，禁止静默漏报。
inputs:
  - 审查原文和 import manifest
  - 公告/上游固定 commit、blob、版本和已记录 fixture
  - current C/C++ 与 interface Detector
write_scope:
  - 新 isolated worktree 中的 research_candidate Detectors 或规则
  - tests/fixtures/known_cases/*
  - research/experiments/known_vulnerability_coverage_20261019/
constraints:
  - 不把 CVE 名称当规则语义，不依赖外部扫描器
  - 不把组件 PoC、ASan、公告或静态 candidate 升级产品漏洞
  - 无固定源对象的项目记录 source unavailable，不伪造 replay
acceptance:
  - 本地 5 项危险代码形状至少 candidate/limitation
  - OpenHarmony 10 项逐条有 source/coverage disposition
  - 排除 2 项有具体反证
  - 4 项人工 candidate 保持 candidate/unassessed
  - positive/fixed/safe/unrelated/unknown 全覆盖
continuation:
  - G10-CV-1 audit-to-finding ledger
  - G10-CV-2 本地组件规则与控制
  - G10-CV-3 OpenHarmony family mapping
  - G10-CV-4 cross-file/profile generalization
  - G10-CV-5 独立 holdout
deliverables:
  - known-case manifest
  - rule/control matrix
  - patches and tests
  - exact verification and residual gaps
```

### 持续执行目标

所有已知条目必须有最终 disposition；不能把“当前没源码”写成“扫描通过”。每轮补齐一个漏洞家族，并保持 evidence gate 不变。

## 5. C10-BUILD-PROFILE

### 任务

补齐 Ark parent/fix 的 rk3568 compile action、宏、include closure、工具链、生成输入和 dependency manifest，解决 full-file partial/blocked。

### 结构化 Vibe Coding Prompt

```yaml
role: build-profile and dependency-closure engineer
objective: >
  为每个真实 parent/fix pair 生成同一可复算预处理 profile，
  使 source selection、宏、include、生成文件和工具链都绑定固定 identity。
write_scope:
  - research/methods/ark_runtime/build_profile_20261019/
  - profile/dependency manifest generators and negative mutation tests
constraints:
  - 不把 a65 或当前 master profile 套到历史 pair
  - 缺 include/宏/生成输入必须 fail-closed
acceptance:
  - parent/fix 使用等价 profile 可预处理
  - manifest 含 commit/tree/blob/source/parser/config/toolchain hashes
  - negative mutation 会稳定失败
continuation: G10-BP-1 inventory -> G10-BP-2 preprocess closure -> G10-BP-3 mutation tests -> G10-BP-4 replay
```

## 6. C10-HOLDOUT

### 任务

冻结规则后建立独立、双盲、可裁决 holdout；当前 41 行空标签不能用于 Precision/Recall。

### 结构化 Vibe Coding Prompt

```yaml
role: independent evaluation and adjudication engineer
objective: >
  从开发家族外抽取真实适用样本，完成双人盲标和第三方分歧裁决，
  只有 reliable truth 通过后才计算指标。
write_scope:
  - research/evaluation/ark_runtime_holdout_20261019/
constraints:
  - 不复用调参样本、不泄露预测、不让模型自评
  - 样本不足或标注不完整就报告 not evaluable
acceptance:
  - family leakage、reviewer identity、confidence、timing、disagreement、adjudication 全审计
  - score gate 独立于 Detector output
continuation: G10-HO-1 freeze -> G10-HO-2 sampling -> G10-HO-3 blind labels -> G10-HO-4 adjudication -> G10-HO-5 metrics
```

## 7. C10-DYNAMIC-PRODUCT-CLOSURE

### 任务

仅对满足入口/权限/触发/敏感操作/CIA 门槛的候选执行本地隔离 PoC、修复和重验，并闭合版本、分支、CWE/CVE。

### 结构化 Vibe Coding Prompt

```yaml
role: authorized isolated product-closure engineer
objective: >
  对证据门已满足的候选取真实产品入口、权限边界、触发条件、敏感操作和 CIA 影响，
  生成可复现 PoC、修复版失效和合法控制通过证据。
write_scope:
  - research/deliveries/product_closure_20261019/
constraints:
  - 只使用授权隔离环境、无网络、只读根、去 capabilities、资源限制
  - 静态资源受限子进程不是不可信构建/PoC 沙箱
  - 组件 PoC 不等于产品漏洞
acceptance:
  - source/build identity、入口、权限、trigger、sink、CIA、PoC、fixed rerun、affected versions、CWE/CVE 全绑定
continuation: G10-PC-1 admission -> G10-PC-2 product mapping -> G10-PC-3 isolated PoC -> G10-PC-4 fix/retest -> G10-PC-5 report
```

## 8. C10-SCALING-PERFORMANCE

### 任务

在不改变覆盖语义的前提下验证 2000 文件、32MiB 总源码、1MiB blob 限制下的 batch、分片/聚合、缓存和 wall/RSS。

### 结构化 Vibe Coding Prompt

```yaml
role: scanner scaling and performance engineer
objective: >
  对 batch、shard/aggregate、AST cache 和 resource limit 做覆盖不变性实验，
  记录 wall time、RSS、partial/unknown 变化和失败边界。
write_scope:
  - research/experiments/performance_20261019/
  - 独立性能脚本与报告
constraints:
  - 不以吞吐量替代正确性
  - 不扩大默认限制，除非兼容与回归实验通过
acceptance: same source identity and coverage before/after; exact env; median/tail wall and RSS; no verdict drift
continuation: G10-PF-1 baseline -> G10-PF-2 batching -> G10-PF-3 shard invariance -> G10-PF-4 cache -> G10-PF-5 limit policy
```

## 9. C10-DELIVERY-ADMISSION

### 任务

按竞赛交付清单独立复审准确/完整分析、CWE/CVE、PoC、受影响模块/版本/分支、修复重验、性能/创新证据和完整报告。

### 结构化 Vibe Coding Prompt

```yaml
role: competition delivery admission reviewer
objective: >
  基于 pinned evidence 逐项审计竞赛交付完整性并输出可执行补救清单，
  不以候选数、工作量或模型同意替代安全证据。
write_scope:
  - research/deliveries/admission_20261019/
constraints:
  - 未获用户授权不标 Draft Ready、不 merge
  - 缺失、partial、unknown 必须显式保留
acceptance: every deliverable has source identity, evidence status, owner, blocking condition and minimal remediation
continuation: G10-DA-1 inventory -> G10-DA-2 evidence audit -> G10-DA-3 gap closure -> G10-DA-4 package -> G10-DA-5 user authorization gate
```

## 10. 合流与提交策略

1. C9 三条算法线各自保存 minimal patch、五类控制和验证，不互相覆盖。
2. C9-INTEGRATION 先形成 known-case matrix 和合流门，再由负责人在独立 worktree 选择性迁入。
3. 算法修复、公共 contracts/Runner/Catalog、文档/证据分别提交。
4. 合流后运行 Ark focused/full、Runner applicability、owner integration、schema v2/legacy v1 compatibility、compileall、JSON 和 diff check。
5. push 前在聊天中说明变更、实际验证、限制、branch/full SHA/commits，并更新 `docs/项目现状与下一步.md`；不自动 push、merge 或标记 Ready。
