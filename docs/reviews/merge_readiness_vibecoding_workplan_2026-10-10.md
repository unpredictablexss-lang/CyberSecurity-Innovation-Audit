# 交付剩余工作与并行 Vibe Coding 任务包（2026-10-10）

## 0. 先统一口径

用户本次要的是：**离交付还差哪些工作，并按“能否合并到 main”组织成可并行执行的任务**。

因此本文拆成两套标准：

1. **M-gate：分支/PR 合并到 main 的工程门槛。**
   只要求当前改动范围内的代码、证据绑定、回归、文档和 CI 可复核；不要求一个检测器 PR 同时交付完整 PoC、跨版本报告和比赛材料。
2. **C-gate：比赛最终交付门槛。**
   要求至少一个真实 OpenHarmony 组件形成“候选 → 证据审查 → 本地动态验证 → CWE/CVE → 影响范围 → 修复/重验 → 性能 → 漏洞报告”的闭环。它是项目最终目标，不应被误读为每个 PR 的合并前置条件。

附加文档 `docs/reviews/local_delivery_review_2026-10-10.md` 是对特定历史 head 的审查记录。它指出的 R1/R2/R3 缺口仍应修复，但其中“完整比赛交付物未闭合”不能直接等同于“所有代码都不能合入 main”。如果 PR 只声称 `candidate/unassessed` 的检测器接入，就按 M-gate 验收；如果 PR 声称 `confirmed/reportable` 漏洞，必须额外满足 C-gate 的证据门槛。

## 1. 当前可核验基线

| 项目 | 当前事实 | 对合并的含义 |
|---|---|---|
| 工作分支 | `codex/teammate-a-shared-ptr-race-migration`，当前有未提交的迁移/收口文件 | 不能直接当作已完成 PR |
| 本地测试 | WSL Ubuntu 22.04 / Python 3.10.12，`python3 -m unittest discover -s tests -q`：242 tests，OK | 是本地回归证据，不替代最终 merge head 的远端 CI |
| 空白检查 | `git diff --check` 通过，仅有 LF/CRLF 转换提示 | 仍需最终检查生成物、第三方源码、绝对路径、密钥 |
| R1 来源绑定 | 已修复：native runner 绑定认可 origin + exact commit/tree/blob + 独立 binding manifest/hash | 本地 M-gate 已闭环 |
| R2 verifier | 已修复：从可信 context/run/manifest 重建并拒绝类别、范围、parse、artifact、finding 篡改 | 本地 M-gate 已闭环 |
| CI 触发 | 已扩展 `codex/**`、`feat/**`、`experiment/**` push 触发；PR 到 main 保持触发 | 远端最终 head CI 待 push 后核验 |
| Holdout | `research/methods/cpp/shared_ptr_race_holdout_plan.md` 为 `designed_not_executed` | 不阻塞候选检测器合并；阻塞任何准确率/零误报/零漏报声明 |
| PoC/动态 | 有历史 harness/记录，但当前交付不能声称本轮复现 | 不阻塞 scoped detector PR；阻塞 C-gate 和 `confirmed/reportable` |
| CWE/CVE/影响/修复/性能/报告 | 部分或缺失 | 不阻塞 scoped detector PR；阻塞最终比赛交付 |
| 证据状态 | 应保持 `candidate/unassessed`；`CWE-362` 是当前语法候选主类，`CWE-416` 只能写可能后果 | 不得在合并说明中写成已确认漏洞 |

## 2. M-gate：合并到 main 的硬门槛

每个 PR 只检查它声称的范围，但以下条件全部满足后才可 `ready` 或合并。**仍然遵守项目约定：不未经用户授权标 ready、不合并、不推送。**

### M1 范围与结论边界
- PR 描述明确是“候选检测器/基础设施/研究证据”，还是“已确认漏洞交付”。
- 未完成证据门槛的 finding 必须是 `candidate/unassessed/unknown`，不能由 warning、规则命中、`completed` 或 0 diagnostics 推成 `safe/confirmed/reportable`。
- 不把 `partial/failed/not_run` 写成 `miss`；只有有独立不兼容证明的分析单元才能写 `not_applicable`。

### M2 代码和数据契约
- 不破坏 `ToolRunResult v1`、既有 CLI、公共 IR；新增字段有版本和兼容测试。
- 自研 detector 的生产路径不调用 Semgrep/CodeQL/Clang/Cppcheck/Joern，也不访问网络或写受检源码。
- registry/Runner 对 crash、timeout、partial parse、duplicate diagnostic_id、跨仓库混用、路径逃逸有确定性处理。
- `completed` 仅表示合格子集执行完成；覆盖不足必须写入 limitations/sidecar。

### M3 证据与来源绑定（R1/R2 的合并阻断修复）
- `git_object` 必须来自校验过的本地 Git origin/commit/tree/blob，或绑定可信、独立固定的 repo/commit/path/blob SHA 清单；普通导出文件必须用准确的 `exported_file` 来源标记。
- verifier 必须校验：顶层 `evidence_class`、fixture category、artifact 唯一性/完整性、parse_issues、source hash、finding 文件属于 `analyzed_files`、finding 行列位于实际源码。
- 增加负向回归：错误 repo、错误 commit、替换内容、vulnerable/fixed 调换、伪造 evidence class、伪造 fixture category、清空 analyzed_files、finding 超范围、stale source hash。
- SHA-256 只能证明内容一致性，不得在文档中宣称为防伪认证。

### M4 测试和复现
- 正例、fixed、safe、unrelated、unknown、failed、partial、not_run、not_applicable 均有 fixture 和期望状态。
- 固定命令可在干净 checkout 重跑；测试输出记录 Python/OS/依赖和结果。
- 不把开发集当独立 holdout；holdout 未执行就只报 raw counts 和 limitation，不报 Precision/Recall。

### M5 CI、集成和仓库卫生
- 最终 merge head 通过远端 CI；当前 push 触发范围不足的问题必须解决（优先通过 PR 到 main 触发，或显式扩展 workflow）。
- 合并前 `git fetch` 后重新核对 main 的 merge-base、冲突和最新 head；不能沿用旧审查报告中的 commit 数字。
- 不提交第三方 OpenHarmony 全量源码、编译产物、临时实验输出、密钥、绝对个人路径或未批准 PoC 对线上目标的触发脚本。
- 方法卡、README、限制、许可证/来源、复现命令与当前测试数一致；`PROGRAM_STATUS.md` 只记录已复核事实。

### M6 授权
- 只有项目负责人可以决定 push、PR 创建、ready、merge。任务卡完成不等于授权合并。

**M-gate 当前判定：本地技术条件已满足，远端 CI 和负责人 push/PR/merge 授权仍待完成。**

## 3. C-gate：最终比赛交付门槛

只有以下闭环对至少一个真实 OpenHarmony 组件闭合，才可称“交付完成”：

1. 固定 repository/commit/scan scope，识别现实入口、攻击者控制或权限边界。
2. 找到可达敏感操作和 guard（或明确缺失），保留完整路径和必要条件。
3. 本地隔离构建/运行 PoC，记录 ASan/UBSan/TSan 或等效动态证据、命令、环境、观察结果和重放稳定性。
4. 记录 CWE；有公开编号才映射 CVE/公告，新发现走 OpenHarmony 漏洞奖励/披露流程。
5. 扫描 tagged manifests/branches，给出受影响模块、版本区间、vulnerable/fixed commit 边界。
6. 给出具体修复 diff/思路，基于 guard/effect 关系，并重放原 PoC、跑回归。
7. 在真实组件上记录文件数、LOC、墙钟、Peak Memory、解析覆盖率和 finding/confirmed 数。
8. 用 `src/report/vulnerability_report.py` 渲染漏洞报告，逐条满足 `docs/deliverables_checklist.md`。
9. 标签和分母足够时计算 Precision/Recall、per-subtype recall、safe-fixed FPR；否则明确 unknown/coverage，不宣称零误报/漏报。

## 4. 可并行 Vibe Coding 任务卡

下面每张卡都可直接派给独立 AI/队友。`[P]` 表示可并行，`[S]` 表示必须串行或最后集成。相同文件只能由一个任务修改；先改共享契约的任务优先。

### WP0 `[S]` 范围与状态冻结
**目标**：确定本批次是 scoped detector 还是 confirmed vulnerability。
**输入**：当前分支 diff、`PROGRAM_STATUS.md`、attached review。
**动作**：列出 PR 声明、finding 状态、证据等级、禁止声称；把“merge gate”和“competition gate”分开写入 PR 模板。
**验收**：没有把候选写成漏洞；没有把历史 TSan 日志当本轮复现；没有把 holdout 设计当已执行。
**依赖**：无；后续所有任务的口径基线。

### WP1 `[P]` R1 来源绑定修复
**目标**：让 `git_object` 真正绑定 Git 对象，或把普通文件输入降级为准确 provenance。
**输入**：`research/experiments/cpp/shared_ptr_race_native_evidence.py`、`src/ohscanner` 的 pinned Git reader、现有 Git integration tests。
**动作**：真实路径从校验 origin 的 exact commit/tree/blob 读取；导出文件路径必须校验可信 manifest（repo/commit/path/blob SHA）并标记 `exported_file`；禁止只凭调用者传入 SHA 宣称来源。
**测试**：错误 repo/commit、替换内容、vulnerable/fixed 调换、脏工作区、blob 不匹配、伪造 manifest 均拒绝。
**验收**：`build()` 不再接受任意本地内容冒充 Git object；方法卡明确 provenance 语义。
**可并行**：与 WP2 并行；WP3 可同时写测试，最后统一跑。

### WP2 `[P]` R2 verifier 语义完整性
**目标**：加载后的 review evidence 不能被外层字段替换后绕过。
**输入**：`src/ohscanner/detectors/cpp/shared_ptr_race_review.py`、review evidence fixtures/tests。
**动作**：核验顶层 `evidence_class` 与 manifest category；校验 artifact 唯一且完整、parse_issues、finding 文件在 `analyzed_files`、行列/哈希/身份；拒绝 mixed evidence class 和 stale scope。
**测试**：改顶层 class、改 fixture_category、清空 analyzed_files、伪造 parse_issues、把 finding 移出范围、重复/缺失 artifact、修改 source hash 后均失败。
**验收**：review verifier 的语义检查和生成器一致；文档不把 SHA-256 宣称为认证。
**可并行**：与 WP1 并行；最终集成测试由 WP3 执行。

### WP3 `[P]` 负向回归与证据隔离套件
**目标**：把 R1/R2 的可复现缺口变成永久回归。
**输入**：WP1/WP2 测试接口、`tests/detectors/`、fixture manifest。
**动作**：增加 evidence mixing、scope tamper、provenance forgery、stale hash、CRLF/LF、determinism、detector crash/partial/not_run 的表驱动测试。
**验收**：目标测试和全量测试在干净 checkout 通过；每个失败断言对应明确字段/来源语义。
**依赖**：WP1/WP2 的 API 形状；可先写测试骨架。

### WP4 `[P]` Runner/Contract/ToolRunResult 集成审计
**目标**：确认 detector 结果能稳定进入共享 Runner/ToolRunResult/Review/Report 桥接。
**输入**：`src/ohscanner/contracts.py`、runner、integration、catalog、`src/providers` 的 v1 schema。
**动作**：覆盖 crash/timeout/partial coverage/duplicate ID/跨 repo/排序稳定；确认生产路径不拉外部 scanner、不访问网络、不写源码。
**验收**：一个 ScanRequest 可加载 C++ 与 interface detector，输出规范结果和 coverage sidecar；0 diagnostics 不等于 safe。
**可并行**：与 WP1–WP3 并行，但不得同时改公共 schema；如需 schema 变更，单开 contract-v2。

### WP5 `[S]` CI 与 main 同步
**目标**：最终 merge head 有远端 CI 证据。
**输入**：`.github/workflows/ci.yml`、Git remote、最终分支 diff。
**动作**：优先用 PR 到 main 触发 `pull_request` 工作流；若需 push 触发，显式扩展开发分支白名单。`git fetch` 后 rebase/merge，解决冲突。
**验收**：远端 CI 在最终 head 通过；报告写明 run URL/commit；不得用本地 242 tests 代替远端 CI。
**依赖**：WP1–WP4 完成后执行。

### WP6 `[P]` 独立 holdout 数据与 raw-count 报告
**目标**：把 `designed_not_executed` 变成可复核实验，或诚实保持未执行。
**输入**：`shared_ptr_race_holdout_plan.md`、`src/ohscanner/holdout_manifest.py`、外部 pair/controls。
**动作**：独立数据管理员收集 pair/controls，冻结 detector hash，unlabeled prediction，封存 prediction hash，再 label reveal；分 evidence bundle，报告 raw counts/coverage/unknown。
**验收**：不混用 revision/evidence group；不把开发集当 holdout；无标签支持时不计算 Precision/Recall。
**可并行**：数据收集与 WP1–WP5 并行；指标/报告需在 detector freeze 后串行。

### WP7 `[P]` PoC 与动态验证
**目标**：对一个高价值候选建立本地隔离动态闭环。
**输入**：固定组件 commit、真实入口、现有 `src/validation`/harness、sanitizer 环境。
**动作**：实现 `src/ohscanner/poc/` family template；记录 build/run 命令、环境指纹、ASan/UBSan/TSan 观测、多次重放和 `dynamic_reproduced/stable_reproduced` 状态。
**验收**：PoC 可重跑且只攻击本地隔离目标；harness 人为并发不能冒充产品攻击路径。
**可并行**：与 WP8/WP9 并行，但只有证据审查通过后才能升级 finding。

### WP8 `[P]` Evidence gate、CWE/CVE 与真实入口审查
**目标**：把 candidate 的攻击面、guard、敏感操作、条件和 CIA 影响逐项落到证据。
**输入**：Finding、call path、权限/IPC/生命周期资料、公开 advisory/CVE。
**动作**：形成 EvidenceObligations 清单；主 CWE 与后果 CWE 分开；只在有公开可靠来源时映射 CVE。
**验收**：unsupported assumptions 保留为 obligations；没有入口/影响证据就不进 confirmed/reportable。
**可并行**：与 WP7/WP9 并行；最终 promotion 由负责人复核。

### WP9 `[P]` 影响版本/分支分析
**目标**：回答受影响模块、版本、tag/manifest、vulnerable/fixed 边界。
**输入**：目标 repo 的 tagged manifests、同一 detector、固定 profile。
**动作**：跨 tag 重扫同根因，保存每版本 source/tool/run binding；失败和 unknown 单列。
**验收**：不把单 commit pair 外推成全版本；报告首次引入/修复边界（能证明到哪里就写到哪里）。
**可并行**：与 WP7/WP8 并行。

### WP10 `[P]` 修复建议、Patch 与重验
**目标**：从 guard/effect 关系提出具体修复并验证。
**输入**：confirmed case、WP9 影响边界、WP7 PoC。
**动作**：生成最小 diff/补丁，解释为什么修复根因；修复后运行原 PoC、回归和 sanitizer。
**验收**：修复前后证据不混用；原 PoC 不再触发且有重复统计；不使用模板化空泛建议。
**依赖**：WP7/WP8/WP9 的事实；可先做历史 fixed pair 的方法研究。

### WP11 `[P]` 真实组件性能基准
**目标**：补齐工具性能交付。
**输入**：真实 OpenHarmony 组件、固定 commit/profile、detector/runner。
**动作**：记录 CPU/内存/OS/toolchain、文件数、LOC、扫描/解析覆盖率、墙钟、Peak Memory、files/s、LOC/s、candidate/confirmed 数。
**验收**：不用 TSan 编译耗时代替 detector 全组件成本；保留失败/unknown。
**可并行**：在 WP4 稳定后执行，可与 WP6–WP10 并行。

### WP12 `[S]` 漏洞报告与最终 checklist
**目标**：把通过 C-gate 的 finding 渲染为赛题报告。
**输入**：WP7–WP11 产物、`src/report/vulnerability_report.py`、`docs/deliverables_checklist.md`。
**动作**：逐项填基础信息、代码证据、攻击链、PoC、影响范围、修复、性能和限制；保留负结果和 unknown。
**验收**：报告中的 commit/行号/命令可复现；只包含达到相应证据等级的结论。
**依赖**：至少一个真实 case 通过 WP7–WP10；与 WP13 可并行但最后统一校对。

### WP13 `[P]` Web/ArkTS/IPC 接口线
**目标**：在独立模块中补真实接口/权限/IPC 候选，不重写整套 scanner。
**输入**：`docs/strategy/oh_web_interface_track.md`、interface fixtures、shared contract。
**动作**：提供 method card、positive/fixed/safe/unrelated/failed fixtures、coverage、contract-compatible result 和许可证/来源。
**验收**：不把 query 风格 CodeQL 输出偷偷当 dataflow；不把权限/IPC 结构命中直接升级 confirmed。
**可并行**：与 WP1–WP12 并行；共享接口变更须先过 WP4/contract review。

## 5. 推荐并行执行板

```text
并行第一批（互不改同一文件）：
  WP1 R1 provenance 修复
  WP2 R2 verifier 修复
  WP3 负向回归测试骨架
  WP4 Runner/contract 审计
  WP6 holdout 数据收集（只收集/冻结，不改 detector）
  WP13 interface detector 独立线

集成第二批：
  WP1 + WP2 + WP3 + WP4 → WP5 CI/main sync
  WP5 通过后 → 才允许负责人审查/合并 scoped detector PR

研究/交付第三批（可与第二批部分并行）：
  WP7 PoC + WP8 evidence gate + WP9 impact + WP11 performance
  WP10 remediation 依赖 WP7/WP8/WP9
  WP12 report 只依赖已经满足 C-gate 的 case
```

**不要并行修改的文件/决策**：`contracts.py`、`ToolRunResult` schema、`PROGRAM_STATUS.md`、PR ready/merge 状态、finding promotion。若需要改公共契约，单开 contract proposal，不在多个 detector 分支各自改。

## 6. 何时可以合入 main

只有在以下清单全部为“是”时，负责人才能考虑把 scoped detector PR 标 ready/合并：

- [x] R1 来源绑定已修复，且负向 provenance 测试通过。
- [x] R2 verifier 语义完整性已修复，且 mixed/scope/finding 负向测试通过。
- [x] 全量回归在最终 merge candidate 通过，测试数量/命令/环境已记录。
- [ ] CI 在最终 merge head 远端通过，或已明确记录等效的 PR CI 证据。
- [x] 已与最新 main 同步，冲突和 merge-base 已核对。
- [ ] finding 仍保持证据支持的状态；没有把 candidate/reporting gap 写成 confirmed。
- [x] 方法卡、README、限制、许可证、复现命令和 `PROGRAM_STATUS.md` 与当前实现一致。
- [ ] 没有第三方源码/生成实验产物/密钥/绝对个人路径/线上攻击脚本混入提交。
- [ ] 项目负责人已授权 push、PR ready 和 merge。

完整比赛交付还要继续满足 C-gate，但这些工作可以拆成后续独立 PR/实验批次，不应被一个 scoped detector PR 一次性阻塞。

## 7. 对原审查报告的修订结论

原报告的 **R1、R2、R3 事实仍然有效**，且应作为本批次的最高优先级整改；它的 fixture、holdout、PoC、版本、修复、性能和报告缺口也应保留在 C-gate backlog 中。

需要修订的是验收口径：

- **不能**把“完整比赛交付物尚未闭合”直接解释为“任何 scoped detector 都不能合入 main”。
- **可以**合入一个明确限定为 `candidate/unassessed`、具备 M-gate 证据和测试的 detector/基础设施 PR。
- **不能**在同一个 PR 中把研究候选升级为 `confirmed/reportable`，除非同时交付真实入口、动态证据、CWE/CVE、影响范围、修复重验和报告。
- **不能**沿用报告里的旧 head、旧测试数或旧 main SHA；最终验收必须针对实际 merge head 重新跑。
