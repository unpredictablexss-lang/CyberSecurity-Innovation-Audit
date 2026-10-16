> **2026-10-10 政策更新（优先于本文所有历史措辞）**：项目对齐赛题交付。本文 2026-10-08/10-09 各节为**历史记录**，其中"不做 PoC / 不做动态验证 / 不升级结论状态 / 不计算 Precision-Recall"等限制已于 2026-10-10 **废除**。当前生效政策见 `AGENTS.md` 的 **Competition deliverables — must produce** 章节：PoC、动态验证、CWE/CVE 映射、影响范围、修复建议、性能数据、漏洞报告均为**必须产出**的交付物；保留的只有"证据到哪一步、结论才到哪一步"的防误报纪律。目标对齐文档见 `docs/strategy/competition_deliverables_plan.md`。
>
> **2026-10-09 状态提醒**：本文件 2026-10-08 的细节章节按时间记录历史试验，可能保留当时的 draft/待验收措辞；主线真实状态是 PR #4 已合入 `main`。下一阶段文档见 [三线并行总方案](docs/strategy/ohscanner_three_track_master_plan.md)、[Detector Contract v1](docs/contracts/ohscanner_detector_contract_v1.md)、[漏洞库与工具实验协议](docs/strategy/vulnerability_corpus_bakeoff_protocol.md)、[Web/IPC 专项任务书](docs/strategy/oh_web_interface_track.md)。它们均属**拟开发方案而非已实现软件**。

# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-10（政策对齐赛题交付；旧阶段实测记录仍保留原日期）
> 工作分支：`feat/interface-ipc-detector`（接口/IPC 专项线，源自 `feat/ohscanner-core` 的 `830ef56`；原分支名 `feat/oh-a-interface-detectors`）
> PR：#4 `feat: historical benchmark, scanner evidence chain, and multi-tool adapters`（2026-10-09 已合并）
> 当前阶段：接口/IPC 检测线已实现 v0.1（六家族有界析取解释器 + 12 组 S2 历史修复对 + 四工具对照 + 218 项回归，见 `docs/research/ipc_scanner_v0_1_2026-10-10.md`）。真实漏洞算法、真实 c_utils Ubuntu 试跑及真实产品构建上下文仍未完成；PoC/动态验证/漏洞报告等待补交付。
> 交付目标：本项目以完成赛题为目标，必须产出 PoC、动态验证证据、CWE/CVE、影响范围、修复建议、性能数据与漏洞报告（见 `AGENTS.md` 的 Competition deliverables 章节）。`candidate` 是**默认起点**而非终点：证据满足门槛即升级为 `confirmed` / `reportable` 并记录证据等级。

---

## 0. 当前一句话状态

`feat/historical-vuln-benchmark` 已完成主要静态实验框架并持续补跑工具，尚未完成覆盖验收：当前已包含 4 条 OpenHarmony historical samples、text/AST scanner 对比、manual review 持久化、Tool Matrix、Evidence 生成层、VulnerabilityCase draft、Semgrep/CodeQL/ClangSA/Cppcheck/Joern adapter、`compare-tools`、root-cause hit matrix、`benchmark-report` 汇总命令，以及 OH 专用 Semgrep 规则的首轮验证。PR #4 已在 2026-10-09 合并到 `main`；本节其余内容为历史阶段实验记录，不代表新的 OHScanner 插件已完成。

已确认收口文档更新前代码 head `dd908f2` 的远端 CI Run #58：**149/149 通过**（Ubuntu 22.04 / Python 3.10）。文档更新产生新的 head 后必须重新核验 CI。
最近一次本地完整回归记录为 **149/149 通过**；`validated_vulnerability = 0`。
三个目标的固定提交/所需源码已补齐；四样本已有 16 次自身基线和 48 次外部工具/规则配置运行记录。
CodeQL、Joern 已补跑各 8 个版本单元。CodeQL 六单元缺 include、两单元 header-only 不适用；
Joern 四单元部分解析，dsoftbus 修复前 5 条结构诊断、修复后 0 条。
64 格汇总为 possible_hit=5、miss=29、unknown=20、not_applicable=10。
c_utils Clang 补充头文件实验两版本均成功、零诊断，但没有模板实例化；不替换原始基线。
Clang 其余目标缺依赖、kernel 部分解析、真实构建覆盖均未闭合；当前不能宣布分支完成。

2026-10-08 本地 WSL Python 3.10 回归 **129/129 通过**（113 个既有测试 + 16 个新增测试）；
该结果不是最新远端 CI。新增架构/规则审查与 `AGENTS.md` 开发约束，并接通保存结果到
按样本、修复前后版本隔离的汇总报告。未提供结果时所有格子为 `unknown`，不再预设 miss。

---

## 1. 当前 PR / CI 状态

| 项 | 状态 |
|---|---|
| PR | #4 |
| PR 状态 | merged / closed（2026-10-09） |
| mergeability | 已合并到 main，非待合并 PR |
| 当前分支 | `main`（前历史分支记录见原 PR #4） |
| 当前阶段 | 历史阶段完成合并；三线并行与自研 Detector 仍是计划 |
| 最近确认的 GitHub Actions | 原代码 head `dd908f2` / Run #58：149 tests passed |
| 当前本地回归 | 149 tests passed |
| 最新阶段核验 | 历史 PR #4 合并前 CI 已成功；后续自研运行时尚无功能测试结果 |
| validated vulnerability | 0 |

---

## 2. 已落地 historical samples

| sample_id | 组件 | root_cause_group | CWE / CVE | runtime |
|---|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `openharmony/commonlibrary_c_utils` | `lifetime_uaf` | CWE-416 | `not_run` |
| `kernel_liteos_a-getgroups-oob-2025-03` | `openharmony/kernel_liteos_a` | `concurrency_race` | CWE-125 / CVE-2025-20042 | `not_run` |
| `communication_dsoftbus_null_deref_001` | `openharmony/communication_dsoftbus` | `null_deref` | CWE-476 / CVE-2025-26690 | `not_run` |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `openharmony/arkcompiler_ets_runtime` | `oob_write` | CWE-787 / CVE-2025-23420 | `not_run` |

样本覆盖 4 个 root-cause group：`lifetime_uaf`、`concurrency_race`、`null_deref`、`oob_write`。样本量仍不足以计算正式 Precision / Recall，只能报告 raw hit / miss / unknown / not_applicable 和逐样本解释。

---

## 3. 已完成模块

### 3.1 Own scanner 主线

- `scan --engine text|ast`
- AST scanner：`src/core/ast_scanner.py`
- text-vs-AST 对比：`src/benchmark/scanner_compare.py`
- manual review 持久化：`src/triage/review_store.py`

### 3.2 多工具结果归一化

- 统一数据契约：`src/benchmark/tool_result.py`
- provider adapters：`src/providers/semgrep.py`、`codeql.py`、`clang_sa.py`、`cppcheck.py`、`joern.py`
- 统一入口：`normalize_tool_output(provider, payload, AdapterContext)`
- CLI：`normalize-tool-output`

Adapter 只做格式归一化，不执行扫描器，不自动判漏洞。

### 3.3 Evidence / Case draft

- tool / triage 到 Evidence：`src/evidence/from_tool_result.py`、`src/evidence/from_triage.py`
- draft case 组装器：`src/case/assembler.py`
- case 组装默认产出 `draft`；证据满足门槛（见 `AGENTS.md` 的 Evidence gate）时产出 `reportable`，并在 case 上记录证据等级。当前实现尚待补齐该升级路径。

### 3.4 Benchmark / Matrix / Report

- historical benchmark runner：`src/benchmark/historical.py`
- multi-tool matrix：`src/benchmark/tool_matrix.py`
- tool comparison orchestrator：`src/benchmark/compare.py` + CLI `compare-tools`
- root-cause hit matrix：`src/benchmark/root_cause_matrix.py`
- benchmark summary report：`src/report/benchmark_report.py`
- CLI 已确认存在：`benchmark-report`

`root_cause_matrix` 只使用 `possible_hit` / `miss` / `unknown` / `not_applicable`，明确不用 TP/FP/FN，也不把 possible_hit 当作漏洞命中。

---

## 4. benchmark-report CLI 确认

入口在 `src/cli/main.py`：

```bash
python -m src.cli benchmark-report \
  --samples-dir benchmarks/historical/ \
  --json-out outputs/reports/historical_benchmark_summary.json \
  --md-out outputs/reports/historical_benchmark_summary.md
```

输出标题为 `Historical Benchmark Summary Report`，汇总样本数量、root-cause / CWE 分布、runtime 状态、own scanner 状态与 root-cause matrix；面向赛题的漏洞报告由 `src/report/vulnerability_report.py` 单独产出。计算 Precision / Recall（及 per-subtype recall、safe-fixed false-positive rate）是交付目标：随标注样本积累持续报告，样本量不足时如实标注置信区间而非拒绝计算。

---

## 5. 外部工具与规则验证状态

已完成的实测与结论：

- Semgrep / Cppcheck 已在本机样本上实测，root-cause matrix 中相应列可从 `unknown` 填入 `possible_hit` / `miss`；
- `semgrep_oh` 已验证两条 OH 专用规则：`oh_shared_ptr_uaf.yaml`、`oh_nothrow_null_deref.yaml`；
- `deref-after-arrow` 这类本地通用规则噪音过高，已弃用；
- 免费 Semgrep registry 对 C++ 基本无可用公共覆盖，当前规则层依赖 vendor/raptor + OH 专用规则；
- CodeQL 当前 no-build 实验：header-only 两单元明确不适用；其余六单元因缺 include 为 unknown。不能把所有缺依赖运行一概归为 not_applicable；需补固定依赖和构建上下文。
- Clang Static Analyzer 已在本机实测（clang 14，`baseline-clang`）：4 样本 × 2 修订共 8 个文件**全部 `fatal error: '<header>' file not found`、0 诊断**，与 CodeQL 同一原因（无法形成翻译单元）→ 在单文件粒度同样记 `not_applicable`，不是 `miss`；
- `root_cause_matrix` 原先只能产出 `unknown` / `possible_hit` / `miss`，文档里定义的 `not_applicable` 无法表达；已补 `NOT_APPLICABLE` 标记，使"没跑（unknown）"与"跑了但不适用（not_applicable）"可区分；
- Joern adapter 与结构查询已落地并重跑：dsoftbus 为 vulnerable possible_hit(5) / fixed miss；ark 两版本 miss；c_utils/kernel 两版本均因解析问题 unknown。旧记录中“其余三样本均 miss”已被开启解析日志的实测修正。查询不分析 guard 支配关系，证据为 syntax，不代表零误报/漏报。
- Opengrep 与 Semgrep 在同一规则集上结果一致，可作为引擎平替候选，但不解决 C++ 规则缺口。

---

## 6. 仍然 unknown / not_run 的内容

1. 各 historical sample 的真实可利用性与系统入口可达性；
2. 运行时触发、TSan、PoC 或 exploitability 判断；
3. `communication_dsoftbus` 分配失败是否攻击者可控；
4. `arkcompiler_ets_runtime` 越界写样本的真实触发条件与受影响范围；
5. OH 专用规则在更大 OpenHarmony 代码面上的误报率；
6. `joern` 查询目前只覆盖 nothrow 判空模式，`oob_write` / `concurrency_race` 等根因家族尚无对应 CPG 查询；
7. `kernel_liteos_a` UAF（CVE-2025-24298 / CVE-2025-27128）仍在候选池，未进入本 PR。

---

## 7. 当前开发与实验 checklist

- [x] root-cause hit matrix 已完成；
- [x] benchmark summary report 已完成；
- [x] `benchmark-report` CLI 已确认存在；
- [ ] PR 描述与最新 64 格实验、Joern/CodeQL 覆盖限制、149 项 CI 记录一致性核对；
- [x] 文档中的旧状态需要从“待完成 / pending / first seed”改为当前 4 样本状态；
- [ ] 本轮收口文档提交后，核对 GitHub Actions 对 **最终 head** 的 CI，而不沿用 `dd908f2` 的成功结果；
- [x] Tool Capability Matrix API 与测试已实现，已补 target/commit/scope 和重复工具校验；
- [x] 四样本固定源码已可读取，text/AST 与 Semgrep/Cppcheck/Clang 本轮实验产物已保存；
- [x] CodeQL、Joern 各八个版本单元已执行，并检查原生覆盖日志；
- [ ] §18 第 5～6 步完整工具比较验收：kernel/Joern 部分解析、CodeQL 缺 include 和
  Clang 构建依赖限制尚未解决（最新实测见第 14 节）；
- [ ] 独立人工审查关键输入校验/源码映射/执行脚本、rule provenance 和保存证据的可复核性；确认后才考虑 ready。

---

## 8. 本阶段必须产出（2026-10-10 起，取代原「暂时不要做」）

```text
PoC                          —— 每个 confirmed 发现配可执行 PoC + 触发命令与观测结果
动态验证                     —— 本地隔离环境构建目标组件，ASan/UBSan/TSan 或等效 harness 复现
TSan 复现                    —— 并发类发现必须的运行时证据
exploitability 判定          —— 形成"可达输入/权限边界 → 敏感操作 → 现实后果"的结论
candidate → confirmed 升级   —— 证据满足 Evidence gate 即升级，并记录证据等级
Precision / Recall           —— 随标注样本积累持续计算并报告（含 per-subtype recall、safe-fixed FPR）
CWE/CVE 映射                 —— 每个发现标注 CWE；有公开编号的映射 CVE，新发现走 OH 漏洞披露流程
影响范围                     —— 受影响模块 + 版本/分支 + 漏洞/修复 commit 边界
修复建议                     —— 具名补丁或 diff，附 guard/effect 关系理由
性能数据                     —— 真实组件上的扫描耗时与规模
漏洞报告                     —— src/report/vulnerability_report.py 产出
```

**唯一边界**：不得攻击线上真实服务；动态验证只在本地隔离环境进行。保留防误报纪律：结论只上升到证据支撑的高度。

---

## 9. 统一表述底线

- `warning != vulnerability`
- `candidate != vulnerability`
- `crash != exploitable security issue`
- `possible_hit != true positive`
- `miss != false negative`
- `no warning != safe`
- `no CVE != 0-day`
- `historical fix parent != automatically ground truth`
- 真实代码必须固定 commit
- 实验必须保留失败结果
- 报告中的每一个结论必须能追溯到 Evidence
- 当前比较的是 root cause / analysis-unit coverage，不是 warning 数量

## 10. 2026-10-08 架构审查与报告链路修复

架构审查结论：保留 L0-L8 漏斗与 Candidate/Evidence 归一化边界。审查记录见
`docs/reviews/architecture_rules_review_2026-10-08.md`；后续开发约束和每次推送前
汇报要求写入根目录 `AGENTS.md`。

已完成：

- `benchmark-report --results <manifest>` 消费保存的归一化工具报告或已有 historical
  text replay；未指定结果时不执行工具，也不制造 miss。
- 每个结果绑定 sample_id、vulnerable/fixed、精确 commit 和 tool；拒绝错提交、
  错 target_id、重复实验和越出声明范围的诊断。缺失、失败、范围不完整或符号未解析
  结果保持 unknown；not_applicable 必须关联真实 failed/blocked 报告和明确原因。
- 汇总 JSON/Markdown 记录修复前后独立行、原始报告路径/SHA-256、run ID、
  工具版本、扫描范围、执行状态和工具局限；Joern 保留 symbol；样本数不再写死为 3。
- OH 规则仅修正候选表述和局限：reset 规则不验证 shared_ptr 类型、并发或锁，
  confidence 降为 LOW；nothrow/Joern 不证明 guard 支配关系。本轮未修改匹配模式。
- WSL 实跑完整测试 129/129 通过；git diff --check 通过。
- 实际导入本机保存的 `outputs/reports/bench_ark.json`，同时生成修复前后 text
  summary；其他未提供的实验保持 unknown。报告保存于 Git 忽略目录
  `outputs/reports/historical_benchmark_review.{json,md}`。另运行无 results 的 CLI
  生成 `historical_metadata_review.{json,md}`，验证无实验时全部 unknown。

仍未完成/边界：

- 本轮没有重新运行外部工具，也没有将文档中的历史结果伪造成输入数据。
- 本节截至 f6886be 时，normalized 诊断缺失 symbol 尚未自动从对应 commit 的 AST 映射符号；此时保留
  unknown，后续需基于固定源码快照补充映射，不能按行号猜测根因命中。
- 本节截至 f6886be 时，AST 解析失败/部分解析统计仍需后续专门接入，后续进展见第 11 节。
- 四个历史样本 runtime 仍为 not_run；validated vulnerability 仍为 0；PR 保持 draft。
- 远端 CI 需要在本轮推送后核验，不把本地测试结果当作远端成功。

## 11. 2026-10-08 AST 覆盖状态与固定源码符号映射

继续遵循 L1 解析索引 → benchmark 证据绑定 → L8 报告边界，没有增加新检测规则或动态触发。

- AstIndex 新增 complete/partial 及 ERROR/missing 节点行范围；AST 扫描报告记录每个
  已读取文件的 complete/partial/failed 状态，单文件解析失败不阻断其他文件。
- 修正 C++ 限定方法的函数名提取，避免将 OHOS 等作用域名称误作函数名。
- `benchmark-report` 输入支持可选 source_repo：校验 origin 仓库标识和精确 commit，
  从固定 Git blob 读取源码；不切换分支、不使用未提交文件。完整解析且诊断行仅属于
  一个已知函数时才补缺失 symbol，记录源码 SHA-256、commit、解析状态与错误范围。
- 部分解析、失败或缺失 own_ast 覆盖状态均保持 unknown，不把零诊断写成 miss；
  完整覆盖的空结果才可写成静态区域 miss。normalized parsing 可保留到最终报告。
- WSL 完整回归 140/140 通过（新增 11 个测试）；覆盖固定 blob 与脏工作区隔离、
  修复前后函数映射差异、错误仓库/提交、解析失败后继续、歧义范围，以及状态/哈希
  传播到矩阵和 Markdown。远端 CI 尚需推送后核验。
- AST CLI 样例扫描实跑：2 文件、28 行、1 个候选，两文件均 complete；报告保存到
  Git 忽略目录 `outputs/reports/samples_ast_coverage.{json,md}`，仅证明工程 smoke test。

限制：映射是文件级语法归属，尚不提供类型、宏展开、CFG、数据流或跨函数语义。
Tree-sitter partial 可能来自真实语法问题或宏/方言，不能据此判漏洞；本轮不重跑外部
分析器，不改变四个历史样本 runtime=not_run、validated vulnerability=0 和 draft 边界。

## 12. 2026-10-08 分支收尾审计与静态基线复跑

本节是 348945f 时的阶段记录；源码缺失项已在后续工作补齐，当前状态见第 13 节。

按本分支静态 benchmark 范围评估，不按完整比赛系统评估：

| 验收项 | 当前状态 | 证据/剩余工作 |
|---|---|---|
| 4 个历史样本元数据 | 已实现 | 固定修复前后提交、根因分类 |
| text/AST、人工 review、Evidence/Case draft | 已实现 | 单测与 CLI，仍为候选/草稿 |
| 5 类外部工具 adapter | 已实现 | 格式归一化测试；不代表实验完成 |
| 分样本/修订矩阵与汇总 | 已实现 | commit/scope/provenance/unknown 状态传递 |
| Tool Capability Matrix | 已实现 | 复用 compare-tools 可比性校验，输出 commit 和 scope |
| 本机全样本静态实验 | 部分完成 | 仅 arkcompiler 对象齐全；另三目标缺漏洞前提交 |
| 全样本外部工具实验产物 | 待验收 | 历史文字结论不能替代可读取、可溯源的输入 |
| 最新远端 CI、PR 描述复核 | 待验收 | GitHub 检查接口无法连接，不据此宣布 ready |

本轮实测与改动：

- 76c51a8 已成功推送，之前的网络失败已解除。
- 修复能力矩阵只校验 target 的缺口：拒绝混合 commit、文件数、LOC 和重复工具；
  commit/scope 输出到 JSON/Markdown，与 compare-tools 共用校验。
- 新命令 `python -m scripts.replay_static_baselines --target-root <repos>` 保存历史
  replay、text/AST 归一化报告、逐修订能力矩阵、inputs、summary 和 failures。
  默认输出目录 outputs/reports/static_baselines，已加入 Git 忽略。
- 本机 _oh_targets 实跑，并尝试 _wsl_targets_stage 作为 fallback：4 样本、64 格；arkcompiler 的 2 修订 × 2 引擎均为静态
  区域 miss（4 格），其余 60 格 unknown。另三目标 vulnerable commit 在本机
  不可读取；fallback 中部分 commit 已有但源码 blob 缺失，kernel fixed commit
  仍缺失。每个目录的尝试原因记录到 failures.json，不假造扫描完成。
- partial clone 的普通 Git 读取曾触发隐式补取并等待网络；本轮已停止该进程，
  为历史回放和固定源码映射添加 origin promisor 禁用、GIT_NO_LAZY_FETCH、
  空 GIT_ALLOW_PROTOCOL（禁止读取过程启动任何传输）和 20 秒超时。
- 完整回归 **142/142 通过**；新增测试覆盖矩阵可比性和基线复跑到汇总的真实链路。

实现层已接近完成，证据资产与远端验收未完成。补齐三目标对象、导入外部实验产物
并确认最新 CI 后再评估 ready。PoC、TSan、可利用性和新漏洞挖掘属于后续分支。

## 13. 2026-10-08 第一批固定源码补齐与工具实验（后续见第 14 节）

“最终验收阶段”的表述过早：实现完成度不等于实验完成度。当前属于静态实验推进，
不宣布分支完成、不将 draft 改为 ready。以下区分真实执行与未执行。

- c_utils/dsoftbus：备用仓库已有提交与树，GitHub raw 下载所需源码；按树中的
  Git blob SHA-1 验证完全一致后补入对象库。kernel 通过官方 Gitee 镜像拉取 manifest
  固定 SHA 与所需 blob；没有改变 manifest、目标 HEAD 或目标实现文件。
- 四样本 × 两修订的 text/AST 基线均执行，16 份归一化报告；kernel AST 为 partial，
  因而区域判断保持 unknown。源码准备及历史 replay 现在无缺对象失败。
- 执行 32 次外部工具/规则配置实验：Cppcheck 2.7、Clang 14、Semgrep CE 1.179.0
  vendor/raptor，以及相同 Semgrep 引擎的两条 OH 专用规则。原生输出、执行参数、
  归一化报告、48 个输入记录、8 份能力矩阵及修订隔离 summary 均留存在 Git 忽略目录。
- OH 规则：c_utils 修复前 possible_hit(1)、修复后 miss；dsoftbus 为 possible_hit(5)
  与 miss。是结构候选区分，不证明并发、可达性、可利用性或发现新漏洞。
- arkcompiler 的 Cppcheck 修复前后都 possible_hit(1)，不区分补丁；Semgrep vendor
  在已知根因区域没有命中。kernel vendor Semgrep 每修订有 41 条诊断但同时报告
  PartialParsing，保留 failed/unknown，不能以诊断数宣布漏洞发现。
- Clang 8 次均执行但缺依赖头文件，无法形成翻译单元，记 not_applicable；CodeQL
  和 Joern 本轮未运行，记 unknown，不能借历史文字记录假称已执行。
- 64 格 summary：possible_hit 4、miss 26、not_applicable 8、unknown 26。
  4 个 possible_hit 是格子数，不是 4 个漏洞；unknown 包括 16 格未运行工具、
  8 格 kernel 部分解析/映射和 2 格 c_utils Cppcheck 符号未定位。
- 完整回归 144/144 通过；新增原始源码恢复与 hash 不匹配拒绝测试。

详细条件、实验表和重跑命令见 docs/testing/static_experiments_2026-10-08.md。
剩余工作：CodeQL/Joern 本轮执行与环境准备、解析局限和真实构建范围方案、更多独立
样本/安全对照、当前远端 CI 和 PR 描述核验。动态验证尚未做，属于后续分支。

## 14. 2026-10-08 CodeQL / Joern 补跑与覆盖核验

- 各八单元重新执行；CodeQL 2.27.1 / cpp-queries 1.9.0，Joern 4.0.649。
  原生输出、固定源码 hash、命令、耗时、退出码、解析日志和查询 hash 均保存。
- CodeQL 不能凭成功退出判完整：SARIF 缺 include 的六单元均 unknown；
  c_utils 两单元日志明确 0 source / 1 header、No source files found，当前配置 not_applicable。
- Joern 默认 WARN 隐藏解析问题，已以 INFO / --log-problems 重跑。
  c_utils 的 CASTProblem、kernel 的解析问题保留 unknown；dsoftbus 为修复前
  possible_hit(5)、修复后 miss；ark 为两版本 miss，仅限当前 nothrow 查询。
- 当前 64 条绑定运行记录、64 格矩阵：possible_hit=5、miss=29、unknown=20、
  not_applicable=10。无未执行工具格，但不代表完整解析/构建覆盖或分支验收完成。
- c_utils Clang 补充实验固定 nocopyable.h blob 并显式 C++，两版本成功、零诊断。
  没有模板实例化，补充日志独立保存，不替换原始可比基线。
- 回归 149/149 通过；新增进程失败/超时、CodeQL include/文件覆盖和 Joern CPG
  日志覆盖测试。4fbfef2 的远端 CI 已核验成功，后续提交另验。PR #4 保持 draft。

下一步优先固定依赖/编译配置、kernel 宏解析与 Joern 部分解析，再扩大独立样本/安全对照。

## 15. 2026-10-09 第一阶段收口审查状态

本节是收口时点的最新说明；第 10–14 节记录了 2026-10-08 不同阶段的实验事实，旧计数和旧 pending 项不能代表当前状态。

- **第一阶段可交付范围**：四个固定历史修复对、text/AST 扫描、五类工具结果 adapter（含 Joern）、保存结果绑定/校验、按修复前后隔离的 root-cause matrix、benchmark summary report 与回归测试。
- **代码 CI**：文档同步之前的 `dd908f2` 在 GitHub Actions Run #58 通过 **149/149**；本次文档提交之后需重新核对新 head CI。
- **静态实验事实**：64 个修复前后/工具格：5 possible_hit、29 miss、20 unknown、10 not_applicable；均不代表新发现漏洞、TP/FP/FN 或形式化覆盖率。
- **待延续的实验限制**：CodeQL 六个分析单元缺 include、c_utils 两单元为 no-build header-only not_applicable；Joern/c_utils/kernel 的解析不完整；Clang 缺真实构建上下文；OH 规则尚未验证在宽代码面的误报率。不要将未覆盖误写为 miss。
- **审查边界**：已核对关键模块的状态语义、输入绑定和代码结构，并确认现有测试覆盖多种错误输入；尚未完成独立人工 Review、原生实验日志/忽略目录中的结果复跑与许可证逐项核对。请勿把单测通过写成实验已完整复现。
- **合并要求**：只接受第一阶段工程基线定位；新 head CI 成功、PR 文档同步和人工审查后由项目负责人决定 ready/merge，不自动执行。`validated_vulnerability = 0`，历史样本 runtime 为 `not_run`。


## 16. 2026-10-09 下一阶段文档落地（规划，不是功能交付）

- 已把三线并行 / 自研 OHScanner 策略写入 `docs/strategy/ohscanner_three_track_master_plan.md`；负责人负责平台与集成，A 负责 C/C++ 安全研究和自研 detector，B 负责 OpenHarmony WebView/JS/ArkTS/IPC/权限入口研究和自研 detector。
- 已提出 `docs/contracts/ohscanner_detector_contract_v1.md`：拟定 SourceUnit、ScanContext、Detector、DetectorRun 和通往主线 ToolRunResult v1 的桥接；**尚无可 import 的对应接口实现，也未跑 Mock 双插件 CI**。
- 已提出 `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`：官方历史漏洞 S0–S3 索引、固定源码/修复对、安全对照、覆盖与失败记录、独立保留测试、根因级工具评估；**尚未收集声明数量的新样本**。
- 已提出 `docs/strategy/oh_web_interface_track.md`：Web/ArkTS/IPC 优先真实攻击面、静态 guard/source-sink 研究，不把通用 Web 警告当 OpenHarmony 漏洞。
- 新阶段正式扫描引擎的核心检测算法将自主实现；成熟工具用于离线实验/基准，扫描阶段不自动依赖调用外部大扫描器。
- 下一步第一优先：负责人从当前 `main` 创建 `feat/ohscanner-core`，实现最小 Detector v1/Mock CPP+Interface 接入、异常隔离和 CI，然后队友按冻结接口独立开发本地模块。不得将该计划写成项目已经具有新漏洞检测能力。
- `codex/cutils-component-pilot` 目前仅用于选择性迁移的试点参考；不整体合并、不将当前 c_utils 试点告警称为漏洞。


## 17. 2026-10-09 OHScanner M0 代码原型（feat/ohscanner-core / PR #5）

- 本分支新增 `src/ohscanner/contracts.py`：ScanRequest、SourceUnit、ScanContext、Detector、DetectorFinding、DetectorRun 的最小代码协议；与主线外部工具 Adapter 分离。
- 已有 `src/ohscanner/runner.py`、`fixture.py`、`smoke.py` 和 `mocks.py`：两个合成 C/C++ / ArkTS 标记检测器使用同一注册器，桥接到已有 `ToolRunResult(schema_version=1)`；在命令行 `python -m src.cli ohscan --fixture-root tests/fixtures/ohscanner` 生成 JSON/Markdown。
- 来源严格为 `fixture/ohscanner-core`，`commit=synthetic-fixture-v1`；文件哈希和请求清单哈希校验、路径与符号链接限制、异常隔离已覆盖测试。**仅合成样例演示，不验证实际 OpenHarmony Git commit/tree，不代表真实漏洞检测。**
- PR #5 新代码最后一次核对：head `53aab448024569378080e3a8d522ef81971d2ba7`，GitHub Actions Run [#37897568236](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/actions/runs/37897568236) 通过，Python `unittest` **170/170 OK**（新增 19 项），包含新 CLI 端到端测试。
- 仍缺真实源码前端、C/C++ 和 Web/ArkTS/IPC 实际检测器、独立进程硬超时/资源沙箱、真实 Git 来源核验、工具研究样本扩展、保留测试集评估。
- 本分支保持 **Draft**，未经正式评审及负责人合并决策不切 Ready 或 Merge；上述 CI 结论在后续修改 head 时应重新验证。


## 18. 2026-10-09 OHScanner M1 固定 Git commit 源码索引（当前 Draft PR #5）

- 新增 `src/ohscanner/git_source.py`：读取本地 Git 仓库**完整 commit SHA** 的固定 tree/blob；不会 checkout 或 fetch。Git symlink/submodule 不跟随；非 UTF-8、超大源码记录为 skipped，全部 Git 条目与实际纳入分析的文件分别统计。
- 新增 `src/ohscanner/frontend.py`：复用原 `src/parser/ast.py` 的 Tree-sitter C/C++ 语法索引。JS/TS/ArkTS 仅做语言与文件登记、`parse_status=not_run`；没有冒充其 AST/语义分析。C/C++ 的 complete/partial/failed 如实保存。
- 新增 `src/ohscanner/indexing.py` 和 `python -m src.cli ohscan-index`：明确输出 `experiment_kind=current_component_source_index`、repo/commit/tree/manifest SHA-256、语言分布、语法覆盖、skip 原因及 JSON/Markdown，**无漏洞检测器执行**。
- `ScanRequest.provenance=git_object` 与 M0 fixture 分离；Runner 会阻断要求完整 AST 却遇到 partial/failed/not_run 文件的检测器；本阶段仍没有强隔离/硬超时/动态漏洞验证。
- 新增 `tests/test_ohscanner_m1.py`，CI 在临时本地 Git 仓库上覆盖真实 commit SHA 固定、工作树和 HEAD 漂移不影响索引、路径范围、symlink、non-UTF8/oversize 跳过、AST partial 和 CLI 端到端。回归结果以 Draft PR #5 最新 head 的 Actions 为准。
- **尚未实测**完整 OpenHarmony `commonlibrary_c_utils` 当前代码的该命令；需要负责人在 Ubuntu/WSL 运行 `docs/testing/ohscanner_m1_git_index.md` 中的固定源码实验后回传文件/AST 覆盖结果。不要把过去队友的当前组件扫描数据伪装为本次 M1 运行结果。
- M1 文档：`docs/testing/ohscanner_m1_git_index.md`；主线 `main` 尚未合并 PR #5，不改变 historical benchmark 正式基线。


## 19. 2026-10-09 M1.5 兼容性修复（feat/ohscanner-core / Draft PR #5）

- **Git 无隐式传输**：`src/ohscanner/git_source.py` 同时设置 `GIT_NO_LAZY_FETCH=1`、`GIT_ALLOW_PROTOCOL=""`、`remote.origin.promisor=false` 等限制；对 Git `ls-tree -l` 缺失 Blob 的 `-` / `BAD` 明确失败 `missing_local_git_object`。新增真实临时 `file://` partial-clone Git trace 回归：无 `fetch origin`、`upload-pack`。本项已在 GitHub Actions Git 2.55.0 下验证，Ubuntu Git 2.34.x 尚待用户本地复测。
- **AST 局部调度**：`run_all()` 仍返回旧的 `ToolRunResult` 列表；`run_all_with_coverage()` 增加逐文件侧车报告。AST 检测器默认 `ast_scope=per_file`，只检查 complete 文件，partial/failed/not_run 保留 `unexamined`，不冒充 miss；需要整体覆盖时显式选择 `ast_scope=whole_scope`。用 93 complete / 30 partial 的合成数据测试已过。
- **最小事实与未证实义务**：`src/ohscanner/facts.py` 提供函数、调用语法事实接口 `facts_v1`（不解析真实被调用目标，不证明 guard）。`EvidenceObligation` 可随自研 `DetectorFinding` 由 sidecar 输出“仍需证明的条件”；不修改历史 `ToolDiagnostic v1`。
- **环境指纹**：固定提交索引报告额外保存 Python/Git/Tree-sitter 版本和 `build_profile=none` 等保守配置。
- **兼容与测试**：从 185 项回归增加至 **192 项**（Github Actions CI 运行 `37933308609` 完成并成功；其后的文档提交仍以最终最新 head CI 为准）。M0 和 M1 命令保持可用；PR #5 仍 Draft、尚未合并 main。
- **待本地核验**：Ubuntu Git 2.34.x 的 partial-clone no-fetch 回归、真实 `commonlibrary_c_utils` 同一 SHA 的 93/30 文件级调度验证；这些不能用 synthetic CI 数据代替。
- **下一步**：先复测并确认使用者提交的证据，才考虑接口冻结及 Draft 收口；不自动进入完整 M2 或声称真实漏洞检测已实现。
- 使用说明：`docs/testing/ohscanner_m15_offline_and_coverage.md`。


## 20. 2026-10-09 M2 平台侧执行链（feat/ohscanner-core / Draft PR #5）

- 已新增 `src/ohscanner/detectors/catalog.py`：显式白名单，CLI 不能用任意 `module:Class` 导入不可信代码；未来真实 A/B Detector 需由负责人审核后注册。当前仅登记 `ohscanner.example.cpp.copy-calls`（`kind=example`），且 CLI 要求 `--allow-example-detectors` 明确确认其**不是漏洞检测器**。
- `src/ohscanner/detectors/example.py`：沿 M1 AST 函数调用概要枚举特定 C/C++ copy API 调用位置，输出 `syntax` 类型**未确认候选**和 `resolved_callee / bounds_proof / reachability` 待验证证据义务；未实现对象容量、攻击者控制或路径分析。
- `src/ohscanner/execution.py` 和 `python -m src.cli ohscan-run`：固定本地 Git 全 SHA 读取/二次核验，显式执行已登记第一方插件，桥接到既有 `ToolRunResult v1`，输出逐检测器覆盖、未解析文件和证据义务 Sidecar + JSON/Markdown。避免将 0 diagnostics 解读为 safe。
- `tests/test_ohscanner_m2.py` 使用 CI 临时 Git 仓库覆盖真实 commit 读取、调用候选、partial 未覆盖、语言不适用、未批准插件拒绝、CLI 显式允许、工作区漂移不影响固定版本结果。
- **平台功能明确限制**：目前没有把队友 A 的独立 `codex/teammate-a-cpp-detectors` 分支代码合入本核心分支，也没有集成 B 的 IPC/JS/ArkTS 真实语义算法；这不属于“全部 M2 算法完成”。原始 AST 不是完整 CFG/类型/所有权/权限检查证明。Runner 同进程，没有硬超时与独立沙箱。
- GitHub Actions 首轮 `ohscan-run` 回归 Run [37936944801](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/actions/runs/37936944801)：**201/201 OK**；后续文档提交的最新 head 结果应再次复核。
- **待本地真实组件试跑**：在 Ubuntu 22.04 Git 2.34.x 对固定 `openharmony/commonlibrary_c_utils` 提交 `b807d3dadb7dbb7639fe85b3a5f72da18d318da2` 执行示例插件运行，独立保留候选及范围统计。说明见 `docs/testing/ohscanner_m2_first_party_integration.md`。
- **Git 协作**：当前 Draft PR #5 暂不合并。建议核心底座经审查验收后做一次受控合并或拆分审查，队友算法各自 PR，**不建议将 M0–M4 所有提交堆成单个巨型 PR**；是否 Ready/Merge 以项目负责人授权为准。


## 21. 2026-10-09 高价值真实漏洞发现优先原则（文档决策）

- 负责人新增**项目级正式规范**：优先研究、展示有可达安全边界与具体危害的真实高价值漏洞（越权/权限提升、敏感泄露、代码执行、可触发内存安全与严重可用性问题等）；不以工具告警条数或单纯代码设计提醒代替漏洞发现。
- 对低价值的版本/普通公开资源/占位配置或未证实安全后果的提示，只保留研究级 `informational/candidate`；如果有证据形成实际攻击链，则重新评估。Web 示例仅用于说明危害严重性，**不代表 OpenHarmony 项目漏洞类别被限定为 Web**。
- 优先对照可靠的历史公开漏洞、真实修复补丁、修复前后和相似安全对照，寻找 OpenHarmony 同根因漏洞及变体；不把历史相似性、CVE 名称或 AI 猜想当作现行组件可利用证明，也不排除尚无 CVE 的新漏洞。
- 对可提交或可展示的实际漏洞结论，要求目标固定 commit、攻击前提、可达输入/权限边界、Guard/敏感操作、现实后果与可复核证据；缺失部分必须按 `EvidenceObligation` / `candidate` / `unknown` 处理。证据补齐到满足 Evidence gate 时**应当**升级为 `confirmed` / `reportable` 并记录证据等级（2026-10-10 政策，见 `AGENTS.md`）。
- 修改范围：`docs/strategy/ohscanner_three_track_master_plan.md` §0.1、`AGENTS.md`、`README.md` 和 `docs/strategy/vulnerability_corpus_bakeoff_protocol.md`。**只有文档与开发约束发生改变，未新增检测算法、告警分级代码或已确认漏洞；任何功能落地都需后续独立代码和测试。**
- 当前仍位于 `feat/ohscanner-core` / Draft PR #5；`main` 未合并，相关 CI 以最终当前提交最新记录为准。


## 22. 2026-10-10 接口线 v0.2：源码派生的入口/分发索引（实测）

- **动机（实测量出的短板）**：v0.1 的入口发现是硬编码名字白名单（`OnRemoteRequest` / `OnRemoteMessageRequest` / `*Inner` in `*Stub` / `models.py::service_entries`）。在 10 个真实组件的生产代码上，它只立起 **109** 个入口 root；其中 `*Inner` 命名假设在全语料几乎为空集。
- **改动**：新增 `src/ohscanner/detectors/interface/entry_index.py`；修改 `analysis.py`（入口来源、跨文件 handler root、受限服务委托边、私有语法规范化）与 `detector.py`（证据档与 `dispatch_binding` 义务）。**未改** `contracts.py` / `runner.py` / `execution.py` / `catalog.py` / `frontend.py` / `facts.py` / `parser/ast.py`，未新增 CLI，无公共 schema 变更。
- **入口发现**：按签名识别 dispatcher（含 `IPCObjectStub::SendRequest`——类名不含 `Stub`、函数名不叫 `OnRemoteRequest`，名字口径必然漏）；从成员函数指针表（构造函数内初始化）、`switch(code)`、`if (code==)` 恢复 code→handler 绑定；handler 可跨文件立为 root；服务委托边仅走**源码可证**的 `GetInstance()` 接收者且要求唯一定义。证据分档：`source_dispatch` / `source_dispatch_case_call` / `virtual_override` / `declaration_shape` / `unresolved_handler`；歧义与未解析事务一律显式记录，不猜。
- **实测（`perf-corpus` 10 组件生产代码，5,270 文件；提交号与数据集 §3 锚点逐字符一致）**：dispatcher **135**（旧名字口径 70），分发绑定 **592**，源码分发 root **690**（旧谓词 **109**），未解析事务 **72**。报告 `docs/research/ipc_scanner_v0_2_entry_coverage_2026-10-10.md`，脚本 `research/experiments/interface/ipc/measure_entry_coverage.py`。
- **历史 S2 修复对（按历史修订建索引，验收口径）**：58 条「样本×修订」记录中**未触达 0**，其中**源码派生 33**、**仅靠硬编码白名单 25**（43%）——即历史样本覆盖率有近一半靠手写名字支撑，且 `TraceServerReceieve` 等条目在现行代码里已不存在。**不把「触达」写成可利用性结论。**
- **端到端候选增量**：`update_updateservice` 0→2、`communication_ipc` 18→25、`telephony_call_manager` 2→3；`security_access_token` / `multimedia_camera_framework` 持平；`notification_common_event_service` 因组件内无 dispatcher 源码（IDL 生成）仍为 0。增量主要集中在「能看见」，不在「多报」。
- **顺带修掉的真缺陷**：① `required_facts=()` 使一个 `.ts` 声明文件令整组件 `blocked` 且 findings 为空（真实组件因此**从未**产出候选）；② `ENGINE_CHECK(cond, return ret, …)` 的宏实参含 `return` 导致函数解析失败（等长规范化救回 2662 个 partial 中的 281 个）；③ `(this->*(iter->second))(...)` 无法解析，连旧谓词都立不起 `UpdateServiceStub::OnRemoteRequest`（旧谓词 root 1→2）；④ `_ALIAS_PATTERNS` 的 `^::?` 锚定错误使对象宏别名表恒为空。
- **仍未做到**：3/10 组件的 dispatcher 是 IDL 生成物、不在仓库内；`multimedia_player_framework` 62 条事务码来自语料外枚举；成员函数指针目标无法从 AST 恢复（靠字节级 `->*` 确认）；无宏展开/重载解析/虚调用证明；服务委托边唯一绑定数百处但候选增量为 0。**本报告分母是入口数，不是漏洞数，不能反推召回率。**
- **回归**：`python -m unittest discover -s tests` **236 项 OK**（218 既有 + 18 新增 `tests/test_ipc_entry_index.py`）。本轮改动**未推送**，等负责人授权。


## 23. 2026-10-10 P0：PoC 模块与首个端到端触发（接口线）

- **交付件 #3 从空白到打通**。新模块 `src/ohscanner/poc/`：`states.py`（生命周期状态机 + 重放标签 + 证据阶梯）、`sources.py`（从本地 git 对象库按固定提交物化组件源码并逐文件校验 SHA-256）、`runner.py`（隔离构建/运行/判定/稳定性重放/环境指纹）、`records.py`（机器可读记录 + Markdown）、`harnesses/<family>/`（家族模板 + `manifest.json`）。驱动：`research/experiments/interface/poc/run_poc.py`。**未新增 CLI、未新增 Finding 类型、未改公共契约**——符合契约要求「PoC 由独立模块承载，不在检测器单次静态执行里完成」。执行范围仅限本地隔离临时构建目录，不触碰线上服务。
- **首个端到端触发：AUTH-01 SA 中继 / `cve-2023-0036`**（`openharmony/inputmethod_imf` PR !228，漏洞 `e663b470` → 修复 `5eaddcab`，S2）。两个修订的 `platform_callback_stub.cpp` **逐字节原样编译**，`Parcel` 用 **c_utils 真实实现**。结果：**不带任何接口 token 时，漏洞版 `messages_sent=1`（`msgId=5` MSG_ID_USER_LOCK、`userId=4242` 发送方自选），修复版 `ret=-74` 拒绝**；正确 token 的正对照在修复版仍正常投递（证明不是一律拒绝）。**状态 `stable_reproduced`（重放 3/3），证据 `stable_reproduced`。**
- **首个负结果：DATA-01 / `cve-2024-0285`**（`HitraceInvoker::TraceServerReceieve`）。用真实 `Parcel` 编译漏洞版与修复版，ASan+UBSan 扫 7×4 组输入 → **零 sanitizer 故障**：当代 `Parcel::RewindRead`/`SetDataSize` 会拒绝下溢位置，`MessageParcel` 未覆写这两个方法。漏洞版与修复版唯一差异是**返回值翻转**，`dataSize` 不被破坏。**该历史修复对在当前基线下已不可复现为内存安全缺陷**，不能作为 PoC 交付件——这条已写入测试文档，避免重复投入。
- **明确没有证明**：远端可达性（harness 直接调用 stub，仍是 `EvidenceObligation`）、影响范围（未跨版本扫描）、修复建议与「修复后原 PoC 失败」闭环（修复版能拒绝来自**上游既有补丁**，不是本模块产出的补丁）。故 `validated_vulnerability = 0`。
- **数据一致性问题（需队伍核对）**：`ipc-research/pairs/cve-2023-0036/lineage.json` 标 `verification_level: S1`，而 `research/corpus/interface/ipc/verified_pairs.jsonl` 标 `S2 / patch_root_cause_review`。
- **测试**：`python -m unittest discover -s tests` → **255 项 OK**（218 既有 + 18 入口索引 + 19 PoC，其中 2 项为真编译真运行的集成测试）。文档：`docs/testing/ipc_poc_auth01_descriptor_bypass.md`；harness 桩清单与来源：`src/ohscanner/poc/harnesses/auth01_descriptor_bypass/README.md`。已推送到 `origin/feat/interface-ipc-detector`（`f9e193b..07bcbb6`）。

## 24. 2026-10-11 接口线：给候选加「后果维度」（信息泄露不属某一个子类）

- **动机（实测）**：赛题把「CWE 准确性」与「完整性」分开计分，而一个候选要回答两个不同问题——**机制**（信任边界怎么失守，现有 `candidate_cwe`）与**后果**（失守后可能暴露什么）。后者不随家族走：39 条公告里 **15 条**官方影响是信息泄露/越界读，分布在 AUTH-02（10）、DATA-01（6）、AUTH-03（5）、AUTH-04（1）；**12 组已核 S2 修复对里有 4 组**属这一类。
- **改动**：`models.py` 新增版本化的**已审查后果目录**（`DISCLOSURE_CALLS` / `IMPACT_BY_RULE` / `IMPACT_CWE` / `IMPACT_DESCRIPTION`）与 `consequence_for(rule, calls)`；`analysis.py` 的 `Observation` 带 `impact`/`impact_cwe`/`impact_basis`；`detector.py` 把后果写进 message 并新增 `consequence` 义务。**机制 CWE 不变**——后果是第二个、不同的答案，不覆盖机制。**未改公共契约、schema 或 CLI。**
- **分类规则**：命中已审查的**读类 API** 就把后果提升为 `information_disclosure`（与机制无关）；否则取规则基线。**只有目录能给理由的后果才带 CWE**（CWE-200 / CWE-125 / CWE-668），其余只写后果名——硬编 CWE 属过度声称。驱动分类的调用名一并记录，供复核。
- **实测（10 个真实组件生产代码，5,270 文件）**：88 条候选，**0 条取不到后果**；`information_disclosure` 出现在**两个不同规则**上（`ipc.auth.missing` 3、`ipc.relay.descriptor-boundary` 2）——这是「信息泄露不属某一个子类」的实测形态。分布：`boundary_bypass` 59、`capability_exposure` 13、`unauthorized_effect` 9、`information_disclosure` 5、`cross_principal_effect` 2。脚本 `research/experiments/interface/ipc/measure_consequences.py`。
- **边界**：后果是**可能性**而非已证实暴露——调用读类 API 不证明真的把数据返回给了未授权调用者；只有 Evidence gate 通过才能升级。候选仍是 `candidate/unassessed`，`validated_vulnerability = 0`。
- **已知缺口，已提 CCR**：后果目前只能从 finding 消息里机读，因为公共 `DetectorFinding` 只有一个 CWE 字段；实测脚本把「取不到后果的候选数非 0」当硬失败而不是静默归零。见 `docs/contracts/ohscanner_detector_contract_v1_consequence_ccr.md`（`proposed / not implemented`，未擅自改契约）。
- **测试**：新增 `tests/test_ipc_disclosure_consequence.py`（11 项）：同一后果类跨两种机制的提升、非读类调用不冒充泄露、越界读保留自己的后果、未知规则不发明后果、机制 CWE 不被覆盖。全量 **266 项 OK**。

## 25. 2026-10-11 接口线：AUTH-01 PoC 的可达性证据（partial）

- **动机**：P0 的 harness 直接调用 stub，「远端能不能真的抵达」一直是 `EvidenceObligation`。WP7 的验收也要求「harness 人为并发不能冒充产品攻击路径」。所以把可达性的**已知部分固定下来、未知部分点名**，而不是留空。
- **改动**：新增 `src/ohscanner/poc/reachability.py`——harness 清单可声明 `reachability` 块，每条关系带 `kind / commit / path / sha256 / line / evidence / establishes / does_not_establish`；运行时**双重校验**（文件摘要对固定提交 + 该行原文是否仍在），文件被移动或引用过期会**直接失败**，不会静默换一段代码描述。`runner` 与 `records` 已接线，报告多一节「可达性证据」。
- **固定下来的关系链（`cve-2023-0036`，提交 `e663b470`）**：服务进程构造 stub（`services/src/platform.cpp:25`，sha256 `7ebe67fc…`）→ 把它作为 `IPlatformApi::registerCallback` 的实参传出（同文件 `:26`）；`registerCallback` 是 `IRemoteBroker` 接口上的纯虚方法（`services/include/i_platform_api.h:48`，sha256 `c2985b38…`），即 IPC 事务；proxy 侧 `data.WriteRemoteObject(cb->AsObject())`（`services/src/platform_api_proxy.cpp:47`，sha256 `8fc23c91…`）把它写进 Parcel。**结论：服务自己把 stub 导出到进程边界，持有该句柄的对端可向其发任意事务**——这正是接口描述符校验要约束的场景。
- **仍未被证明（逐条写在记录里，状态 `partial`）**：无特权或无关进程能否拿到该句柄；对端的身份与权限；对端是否会把句柄再转出去。`SetPlatform` 的调用者在仓库外，因此「谁触发这条链」也不在本仓库证据范围内。**`validated_vulnerability` 仍为 0。**
- **测试**：新增 6 项——`partial` 块必须对每条关系都写明「没有证明什么」、摘要/行号双重校验通过、无块即无声明、行号漂移必须失败、摘要不符必须失败、渲染结果必须出现「没有证明」。全量 **272 项 OK**。

## 26. 2026-10-11 接口线 v0.4：有界宏展开（移植 round1，两个预期收益实测只兑现一个）

- **动机**：round1 分支的 `cpp_macros.py` 是 v0.2 基线唯一没吸收的部分。移植它时预期同时改善两件事——① 补齐解析覆盖（宏实参含语句时 Tree-sitter 解析失败）；② 关掉「guard 藏在宏里」这个假阴性来源（`analysis.normalize_syntax` 能中和带语句的宏实参让文件解析过去，但**宏体内部**的 `return` 守卫仍然看不见，AUTH-02/AUTH-03 于是报告一条源码其实守住了的未授权路径——那是假阳性，赛题对误报负向扣分）。
- **改动**：新增 `src/ohscanner/detectors/interface/cpp_macros.py`（token 级、显式目录、逐字符行溯源、歧义即拒绝）；`models.py` 增 `expand_macros` / `max_macro_sources` / `max_macro_source_bytes` 三个开关（默认开）；`analysis.py` 在规范化前展开，并用 `line_map` 把报告行号译回原文；`detector.py` 把过期的那句限制串换成如实描述。**未改** `contracts.py` / `runner.py` / `execution.py` / `catalog.py` / `frontend.py` / `facts.py` / `parser/ast.py`，未新增 CLI，无公共 schema 变更。
- **与 round1 的两处刻意偏离**：① 整条调用（含实参表）替换——round1 只换宏名 token，于是 `#define CHECK(x) Allowed(x)` 被 `CHECK(c)` 调用时会变成 `Allowed(c)(c)`（对调用结果再调用）；② 拒绝拆成**致命**（无法分词或 `#undef` 使目录不可用，整个文件回退到未展开字节）与**拒绝**（单个宏原样保留）——round1 混为一类并封锁整个文件，一个歧义的 `LOG` 会赔掉该文件其余所有可展开的宏。
- **防倒退闸门（实测逼出来的）**：一个在 A 上下文成立的宏在 B 上下文可能是胡话，实测有 14 个文件展开后反而解析不动。因此**展开若把一个原本可解析的文件变成 partial，该次展开被丢弃**（`expansion_worsened_the_parse`，全语料 29 次）；私有解析覆盖因此单调不减。
- **实测（`perf-corpus` 10 组件生产代码，5,270 单元；脚本 `research/experiments/interface/ipc/measure_macro_expansion.py`，产物 `outputs/reports/macro_expansion.md`）**：
  - **展开活跃度**：791 个文件应用了展开，**12,716** 次调用被展开，其中 **3,645** 次把控制流（`return` / `if`）带进了函数体。
  - **解析覆盖确实改善，但幅度小**：完整解析 **4,384 → 4,467**（+83，+1.9%），0 个文件被拖坏。
  - **候选集增量：恰好为 0**。10 个组件逐个以 `expand_macros=False/True` 各跑一遍解释器：**88 → 88**，无一条规则计数变化。归因是可直接测的：`expansions_introducing_a_modelled_guard = 0`——12,716 次展开里**没有一次**引入策略建模为授权守卫的被调函数。
  - **这不是被我们自己的拒绝语义挡住的**：全语料 **314** 个被拒绝的宏定义中，**0 个**提到任何 modelled guard 被调函数（报告里 `refusal_cost` 一节单列）。即「宏里藏授权 guard」这个模式在语料里**确实不存在**，而不是藏在被拒绝的变参宏后面——OpenHarmony 的变参宏是日志与错误检查（`CHECK_AND_RETURN` 一类），其守卫条件是错误码而非权限。
  - **与入口索引正交（实测，不是推断）**：`analysis.py` 解析的是展开后文本、`entry_index.py` 解析的是原始文本，二者若对类名/owner 不一致就会静默丢 root。探针 `research/experiments/interface/ipc/probe_entry_index_expansion.py` 在 10 个组件上同时建两份索引比对：**root 与分发边 0 增 0 减**（含展开 186 个文件的 `security_access_token`、497 条 root 的 `window_window_manager`）。
- **结论（如实）**：移植的第二个预期收益在**本语料上落空**，第一个收益真实但只有 +1.9%。保留它的理由不是「找到了东西」，而是它把一个**会让源码已守住的路径被误报为未守卫**的假阳性类变成结构性不可能（测试证明机制在模式出现时有效：关闭时报、开启不报、去掉宏的对照组仍然报），并让解析覆盖单调不减。**`validated_vulnerability` 仍为 0；本轮没有产生任何新候选，也没有删掉任何旧候选。**
- **仍未做到**：`#include` 从不跟随，条件定义只记录不选择，变参 / 字符串化 / token 粘连 / 冲突定义变体一律拒绝（91,189 次拒绝中变参类占绝对多数）；目录预算 400 源 / 6 MB，3 个组件因此截断；宏体内部的守卫若调用不在 `IpcPolicy.boolean_permissions | result_permissions` 内（例如自定义 `IsCallerValid`），展开后依旧不构成授权事实——那部分不确定性走既有的 `dispatch_binding` 义务，不假装已解决。
- **测试**：新增 `tests/test_ipc_macros.py`（23 项：11 项扩展语义 + 5 项目录构建 + 6 项集成，含「控制组」与「展开不得发明 finding」）。全量 **295 项 OK**（272 既有 + 23 新增）。本轮改动**未推送**，等负责人授权。

## 27. 2026-10-11 契约 v2：source 绑定必填 + 后果字段转正（一次版本吸收三份 CCR）

- **动机**：三份 CCR 要的是同一件事的两半——A 的两份（`cpp_lifetime_source_binding` / `cpp_shared_ptr_race`，内容逐段重合）要求 finding 能机器证明「我对应哪一版源码」，并固定「机制 CWE vs 可能后果 CWE」的语义；接口线的 `..._consequence_ccr.md` 要求后果可机读。合并为**一次**版本变更，不分别破两次。
- **为什么是 v2 而不是 v1.1**：① `DetectorFinding` 新增**必填**（产出物层面）的 source 绑定；② `diagnostic_id` 的**取值变了**（identity 纳入 `source_sha256`）——按 ID 存储、去重或比对的既有消费者，其键值与 v1 不再相同。v1 §7 自己规定破坏性变更必须提 contract-v2，故照办；v1 文档未删，作为 v1 语义的历史记录保留。
- **必填落在产出物而不是调用点**：`DetectorFinding.source_sha256` 构造函数层可为空，由 Runner 从对应 `SourceUnit.sha256` 绑定（detector 不必自己抄一遍，少一处能抄错的地方）；**detector 自己填了且与 unit 不一致时直接失败**——不改写、也不降级为 unbound（纠正或伪造 hash 都是伪造证据）。`source_binding` 是派生字段：`bound` / `unbound`；`unbound` 表示**未知**，不是「已核对通过」，v1 迁移过来的 payload 一律落这一档且不得补 hash。
- **选择性吸收**：`consequence_impact` / `consequence_cwe` 保持**可选**，与 `candidate_cwe` 并存且互不覆盖（机制 = 怎么失守，后果 = 可能暴露什么）。不填新字段的既有 detector 与 payload 不受影响（纯增量）。
- **落地位置**：`src/ohscanner/contracts.py`（新字段与校验）、`src/ohscanner/runner.py`（绑定 / 拒绝 / ID 纳入 hash / 后果透传 / `schema_version=2`）、`src/benchmark/tool_result.py`（新字段、接受 v1 与 v2、`to_dict` 输出 `source_sha256` 与派生 `source_binding`、v2 缺 hash 直接拒绝）、`src/benchmark/compare.py`（两版都接受，**版本不同必须在输出里点名**：`schema_versions` + `CROSS-VERSION COMPARISON` 限制条目 + 汇总表多一列 Schema）、`models.py`（`reviewed_consequence()`——只放目录审查过的后果类，目录自己的 `unknown` 哨兵出口转 `None`；目录内部一致性在 import 时断言）。实测**无需改动**：`report_inputs.py`（按 `__dataclass_fields__` 过滤键，新键自动兼容）、`tool_matrix.py`（不读 ID）。
- **接口线 detector 版本 0.2.0 → 0.3.0**（输出多了机读字段，版本必须跟着动）。
- **未改状态语义（逐条重申，v2 §4）**：`completed` 不是 safe；空 findings 不是安全证明；`unbound` 不是已核对；hash 只证明**文本绑定**，不证明可达性、守卫支配、攻击者控制或影响；后果仍是**可能性**，只有过 Evidence gate 才升级。**`validated_vulnerability` 仍为 0。**
- **测试**：新增 `tests/test_contract_v2_source_binding.py`（25 项：绑定 / 拒绝 / ID 随源码变化 / 行越界 / v1 unbound 不补 hash / 状态映射不变 / 后果字段向后兼容 / 机制与后果不互相覆盖 / `None` 与空串区分 / 未审查后果类由目录拒绝 / 跨版本比较必须点名 / v2 存档可加载 / 修订组不合并）；`tests/test_ipc_disclosure_consequence.py` 增 3 项机读断言；`tests/test_ohscanner_contract.py` 的版本断言由 v1 改为 v2 并加验 hash 绑定。全量 **323 项 OK**。
- **仍未做到**：v1 payload 加载后仍然没有源码绑定（只能标 `unbound`，这是事实不是缺陷）；跨版本比较只**点名**差异，不阻断；`source_sha256` 绑定的是扫描时的文本，**不证明**该文本来自某个 upstream 提交（Git 侧证据在 M1 的 `git_source.py`，两条链尚未合并）。

## 28. 2026-10-11 远端分支删除的保全核对（以线上 10 个 head 为准重测）

- **背景**：远端有 9 个分支被删除（`codex/cutils-component-pilot`、`codex/reviewed-a-integration-20261009`、`codex/teammate-a-cpp-detectors`、`codex/teammate-a-lifetime-evidence-next`、`codex/teammate-a-oh-vuln-corpus`、`codex/teammate-a-oh-vuln-corpus-next`、`codex/teammate-a-shared-ptr-race-evidence`、`codex/vulnerability-dataset-survey-20261009`、`experiment/cutils-product-scan`）。核对要回答的是：有没有内容**只**存在于这些分支上，删了就没了。
- **判据（不用 ancestry）**：squash/rebase 会重写 patch-id，`git cherry` 与 merge-base 判定在这里都给不出有意义的答案。改用**逐文件 blob 比对**：拿每个被删分支 tip 的每个 `(path, blob)`，与线上全部 head 的并集比。
- **做法**：线上 head 列表以 `git ls-remote --heads origin` 为准——本地 remote-tracking 里还留着已删分支的陈旧引用，**不能**当线上用；被删分支的 tip 已备份在 `refs/backup-deleted/*`（主克隆）。
- **结果**：9 个分支各有 197–275 个文件与线上某个 head **逐字节相同**（这些分支多是同一棵树的旧快照）；**只有 4 个文件在线上任何 head 都不存在**：

  | 文件 | 载体分支数 |
  |---|---:|
  | `docs/reviews/branch_integration_review_2026-10-09.md` | 3 |
  | `tests/test_reviewed_integration.py` | 3 |
  | `research/corpus/native/lifetime_uaf_native_run_2026-10-10.json`（17 KB 原生运行证据记录） | 2 |
  | `docs/reviews/local_delivery_review_2026-10-10.md` | 1 |

  这四个在 `refs/backup-deleted/*` 里都在，随时可恢复。
- **更正本轮之前的一条结论**：先前一次核对（用的是陈旧的 remote-tracking 引用）称 `docs/testing/数据集调研报告.md` 的内容「在任何地方都不存在」。以线上 head 重测后：该文件 blob `973972f7de52` 与 `codex/teammate-a-fragment-consolidation-20261010`、`codex/teammate-a-shared-ptr-competition-loop-20261011` 上的**逐字节相同**，即已被吸收，**没有丢**。那个结论作废。
- **待定项**：另有每分支 10–42 个文件属「路径在线上、但这一版修订不在线上」——多为 main 自己继续演进造成的旧版本，需人工 diff 才能判断分支改动是否已被吸收，本轮**不下结论**。
- **动作**：是否重推这 9 个分支由负责人决定；本轮只提供核对结果，**未推任何分支**。

## 29. 2026-10-11 把 A 的 shared_ptr race PoC 摘进 B 仓库并真跑通（真 pinned 对象，3/3 触发）

- **任务来源**：负责人指示「A 出源码放我的 poc 里面跑」。目标是先把 A 的 PoC 落到 B 仓库、**在本机跑出真实结果**；等 A 最后一版推上来后再删重合部分。
- **摘取范围（只加不删，4 个文件，与 A 分支逐字节相同）**：`src/ohscanner/poc/cpp_shared_ptr_race.py`、`src/ohscanner/poc/templates/cpp_shared_ptr_race_harness.cpp`、`tests/test_shared_ptr_race_poc.py`，以及 `src/ohscanner/git_source.py` 上 A 的补丁（`import urllib.parse` + `verify_repository_identity`）。用 `git hash-object` 逐一比对四个路径：**四个都 IDENTICAL**。**没有**动 A 的 detector（`detectors/cpp/*`）、A 的实验脚本与其 fixtures——那条线归 A。
- **先把「重合部分」定义清楚**：A 的分支从早期 main 切出，它**删除**了接口线整套 PoC（`src/ohscanner/poc/{reachability,records,runner,sources,states}.py`、`harnesses/auth01_descriptor_bypass/*`、`research/experiments/interface/poc/run_poc.py`）与接口线 fixtures/tests。所以重合就是**同名 `poc/` 包与若干 tests**；本轮**一个都没删**，等 A 最后一版落地再按负责人指示裁。
- **blocker 与解除（本轮最关键的事实）**：A 的 PoC **拒绝任何替代源码**——`build_poc_binding()` 核对本地 repo 的 origin 身份、commit、tree、blob oid 与文件 sha256，任一不符即失败（这正是防伪造证据的设计，不该绕过）。而本机：唯一 c_utils 克隆是浅克隆，**两个 pinned commit 都不在**；`_research_sync/github_payload.json` 是仓库自身 198 个文件的快照（那两个 commit 只作为**文本**出现在 ground-truth JSON/MD 里，源码不在）；全盘扫描所有本地对象库，**那 4 个 oid 一个都没有**。github.com 不通（`git ls-remote` 超时、curl 无响应、宿主网关常见代理端口全关）。
  **实测解除：`gitcode.com` 通（HTTP 200）**——OpenHarmony 的镜像站，A 引用的 issue 也在那儿。git 对象内容寻址，从镜像取回的字节必然与 GitHub 一致，所以按 sha 取即可拿到与 A 的 pin **逐字节相同**的对象：`git init /tmp/cutils_pinned` + `git fetch --depth=1 <gitcode url> bdfafdaa… 9a3f2811…`。核对**全中**：
  - `bdfafdaa…` tree = `b3ec65d247c4ca1ff07318fa72c0daa368128563` ✓（= A 的 pin）
  - `9a3f2811…` tree = `69fbea434f22e2174a4dd79dff6ad25833e0ea49` ✓
  - `base/include/nocopyable.h` @ vuln sha256 = `388f5c50…` ✓
  - `base/include/singleton.h` @ vuln sha256 = `ce04ace5…` ✓；@ fixed sha256 = `9ed18694…` ✓
- **实跑**（clang++ 14，`-fsanitize=thread -O1 -g -pthread`，`setarch x86_64 -R`，`TSAN_OPTIONS=halt_on_error=0:exitcode=66:history_size=7`，`--repeats 3`）：

  | revision | 源码组成 | build | 3 次运行 | status |
  |---|---|---|---|---|
  | vulnerable | vuln 两文件 | success | **3/3 触发**（exit 66，data race + heap-use-after-free） | `stable_reproduced` |
  | fixed | fixed 两文件 | success | 3/3 clean（exit 0） | `patch_revalidation_passed` |
  | patched | vuln `nocopyable.h` + fixed `singleton.h` | success | 3/3 clean | `patch_revalidation_passed` |

  `poc_state = stable_reproduced`；`patch_revalidation = passed`；`binding_manifest_sha256 = a1523ff051720917b4ceada335d54dd518ae05b6d33c75a8d508787ee01fc199`；`harness_sha256 = 6af69e2d4c469be21ae04b3ee003ad31d1ef8de52f57fa23aef660466992e7db`。
- **栈顶就是被指认的那个符号**（不是「某处有竞争」这种泛泛之词）：race 栈为 `OHOS::DelayedSingleton<Payload>::DestroyInstance()` @ `singleton.h:141:19` → `__shared_ptr::reset()` → `__shared_ptr::swap()` 的 8 字节写，对读侧 `GetInstance()` 的读；同一次运行还报 `heap-use-after-free` @ `cpp_shared_ptr_race_harness.cpp:41`（读侧解引用 `ptr->value_`）。这同时坐实了 `rules/cpp/oh_shared_ptr_uaf.yaml` 注释里写的根因（`DestroyInstance()` 非原子 `reset()` vs `GetInstance()` 非原子读，修复改为 `atomic_store`/`atomic_load`）。
- **这套证据的边界（照抄 A 的条款，不改写）**：`binding_status = draft_unpinned`（绑定哈希需独立评估者 pin 才算定稿）；**API 级并发复现，不证明产品入口可达、不证明攻击者控制、不证明权限边界**；fixed/patched 干净是 patch 复核证据，**不是**普适安全证明。**`validated_vulnerability` 仍为 0**。
- **测试**：A 的 PoC 单测 7 项 OK（构建与运行全程 mock，不需 repo）；全量 **330 项 OK**（323 既有 + 7 新增）。
- **明确未做**：没有改 `benchmarks/historical/c_utils_singleton_uaf.json`（其 `runtime_replay_status` 仍是 `not_run`——要不要改成已复现由负责人决定，我不代填）；运行产物（JSON/MD/日志/二进制，vulnerable 日志每份约 95 KB）留在 `/tmp/poc_a_run`，**不入库**（AGENTS.md：生成产物与第三方源码不进提交）；`/tmp/cutils_pinned` 是临时对象库，不入库、不连接任何线上服务。
- **本轮改动未推送**，等负责人授权。

## 30. 2026-10-11 组件代码审计能力：把检测器指向任意组件跑一次可复核的审计

- **任务来源**：负责人「反正要做到能很好的对组件代码进行代码审计找出漏洞点」。目标是让接口线能对**任意一个组件**（给定 repo/commit/include）出一份可复核的审计报告，而不是只能跑既有 fixture。
- **先解决的核心 blocker（不是推演，是实测出来的）**：`ohscanner.interface.ipc` 在任一处 parse 不完整时返回 `blocked`，而共享 runner 对 `blocked` 的处理是**三件事同时发生**——`scope_files`/`scope_loc` 归 0、所有 applicable 文件记 `not_analyzed`、`evidence_obligations` 因 `report.status != "completed"` 而不生成。实测 `communication_dsoftbus`：检测器仍产出 **4 条候选**，但义务列表是**空的**。即一次「保守」的 run 同时**低报**了做过的工作、并**抹掉**了每条候选的证明义务（AGENTS.md 的证据门要求义务必须随候选存在）。
- **绕法（不改共享语义，共享 bridge/runner/CLI/报告归负责人）**：
  - 新增同解释、窄范围的 detector `ohscanner.interface.ipc.complete-ast`，只加一行 `required_facts = ("ast",)`；runner 于是只把 complete 文件交给它，其余记 `unexamined: incomplete_ast:<status>`。这次 run `completed`：`scope_files`/`scope_loc` 是真实数字且**义务被记录**。
    （过程中一个真实 bug：先只写了 docstring 忘了那个属性，导致 strict 那遍仍然是 `blocked`——测试与 scope 计数一起把它抓出来。）
  - 审计驱动对同一 shard **跑两遍**（`complete-ast` + `all-files`），按 `(file, line, rule_id, source_sha256)` 合并候选并记录 `passes`（哪几遍看见它）。blocked 那遍的候选在报告里显式写「义务未被 runner 记录，**不等于**没有义务」，并把那个 0 连同该遍真实的 `applicable/analyzed` 计数一起打印。
  - 把这条真实缺陷写成 **CCR 提案**（不改任何共享文件）：`docs/contracts/ohscanner_blocked_run_coverage_ccr.md`，建议 **(c) 增加第三个 run status + (b) 义务不再按 status 过滤**；本文明确列出该分支**没有**改 `contracts.py`/`runner.py`/`execution.py`/`catalog.py`/CLI。
- **新模块** `src/ohscanner/detectors/interface/audit.py`（**detector-agnostic**，只有 pass 表点了本线的两个 detector）：`plan_scope`（按 include 前缀 + 排除规则圈定 scope）、`plan_shards`（确定性分片，按排序后的路径贪心切分，附 sha256 分片摘要与 `plan_sha256`）、`run_audit`（逐 shard 跑两遍，单 shard 抛异常被捕获并进 `shard_errors`）、`merge_shard_runs`（按文件合并，parse 状态取两遍中较差者）、`coverage_depth`、`audit_component`、`render_markdown` 与 `main`（`--repo-dir/--repository/--commit/--include/--exclude/--include-tests/--max-files/--max-bytes/--passes/--json-out/--md-out/--plan-only`）。
- **生产代码排除按整路径段**（`PRODUCTION_EXCLUDED_SEGMENTS`：`test/tests/mock/sample/example/demo/benchmark/fuzz/third_party/...`）。此前一套**子串** SKIP 规则会漏掉 `/tests/`，这次改成整段匹配并加了回归测试钉死。
- **修掉一个真实报告缺口**：`files_selected` 可能大于 parse 映射（`window_window_manager` 1112 vs 1079），因为 `.js/.ts/.ets` 在 `SOURCE_LANGUAGES` 内但不在本检测器的 `("c","cpp")` 内。新增 `files_in_scope_without_a_claiming_detector` 计数 + 示例 + 说明：「这些文件在 scope 内、但没有任何被选中的 detector 声明它们，因此既不是漏检也不是已检查的干净文件」。五个组件的数字均由**最终代码**重跑得到。
- **五个真实组件端到端实测**（`validated_vulnerability` 全部 0；单 shard）：

  | 组件 | commit | 文件 / 字节 | parse complete/partial | 候选 | 其中仅 partial 文件可见 |
  |---|---|---:|---:|---:|---:|
  | update_updateservice | `e4942a33` | 219 / 851,345 | 187 / 31 | 2 | 2 |
  | security_access_token | `17d88bfb` | 550 / 3,484,891 | 489 / 56 | 20 | 0 |
  | distributeddatamgr_kv_store | `acfb22aa` | 1446 / 11,765,303 | 1134 / 310 | 0 | 0 |
  | window_window_manager | `8b0d8fe1` | 1112 / 20,206,691 | 811 / 268 | 15 | 11 |
  | communication_dsoftbus | `652f88e0` | 1656 / 15,243,597 | 729 / 927 | 4 | 2 |
  | **合计** | | **4983 / 51,531,827** | | **41** | **15** |

  候选构成：`ipc.relay.descriptor-boundary` 20、`ipc.capability.export` 15、`ipc.auth.missing` 4、`ipc.auth.guard-coverage` 2。**41 条中 26 条两遍都看见（义务已记录）、15 条只在 partial 文件里出现（义务未记录，报告里逐条标注）。**`window_window_manager` 磁盘上 51 MiB，经生产排除后为 20.2 MiB 生产源码，落在核心 `MAX_TOTAL_BYTES = 32 MiB` 内，故单 shard 即可跑完。
- **一个真实组件的一组分片配置下候选集合一致**（此前只有 fixture 级单测）：对 `window_window_manager` 用 `--max-files 600` 重跑 → **2 shard**，候选集合与 1 shard 时**逐条相同**（按 `file/line/rule_id/source_sha256` 比较：15 条，双向差集为 0），合并覆盖也相同（`files_selected` 1112 / 字节 / parse 811-268 / `files_analyzed` 811 / `candidate_files` 6），`plan_vs_load.mismatches == []`。只有 `plan_sha256` 与分片布局不同。**这只证明该配置下一致，不声称任意分片都不影响结果**；跨文件/组件全局规则的分片语义见 §31。
- **诚实性由构造与测试共同保证**：摘录 `_excerpt` 一律读 **pinned blob**（测试里把 worktree 改写并加标记 → 标记不出现在摘录里）；某个 shard 抛异常必须进 `shard_errors` 并**永不**被当成「无候选」；0 候选渲染为「不是安全的证明」；计划与实际读取数用 `plan_vs_load` 度量（非 UTF-8 blob 的丢弃可见）。
- **测试**：新增 `tests/test_component_audit.py` **33 项**；全量 **363 项 OK**（330 既有 + 33 新增）。既有 330 项无回归。
- **仍未做到 / 未做**：① `ohscanner.interface.ipc` 与 `complete-ast` 变体**没有**注册进 `catalog.py`，因此全局 CLI 目前**选不到**本线检测器——这是负责人的决定，我不代改；② 审计驱动**没有**做成 CLI 子命令，只能以模块方式调用；③ 真正「只在 partial 文件里」的 15 条候选，其义务仍只能靠人工（`complete-ast` 那遍看不见它们）；④ 两遍带来约一倍墙钟时间，且**一个解释对应两个 detector ID**（`diagnostic_id` 因 detector_id 不同而不同）；⑤ 根因相交一栏在组件审计里恒为 `not_measured`（无标注根因集绑定到该组件），既有 12 组历史对仍由 `measure_entry_coverage.py` 度量。
- **产物与动作**：审计 JSON/MD 全部留在 `/tmp/audit_*.json|.md`，**不入库**（AGENTS.md：生成产物与第三方源码不进提交）；**本轮未推送**，等负责人授权。本分支现领先 `origin/feat/interface-ipc-detector` 3 个提交（`4fda320`、`89401fb`、`3feb5bc`），本轮改动尚未提交。
- **本轮之后的修正**：负责人 2026-10-11 认可本轮为「真实组件审计实验成果」，但要求暂停扩规则、先修平台表达，并对本节的若干说法做了收紧（分片不变性口径、候选身份的完整绑定、partial 候选的空白义务、统计闭合、产物归档）。这些修正与随之落地的改动记在 **§31**，本节其余事实保留原样。

## 31. 2026-10-11 按负责人决定收紧审计链路：义务不再留空、身份绑定完整、统计闭合、产物归档

- **收到的决定**（负责人，2026-10-11）：① 接受本轮为**真实组件审计实验成果**，纳入待审交付，**不**认定检测器已正式集成；② **暂停扩规则**，下一步优先修平台对「部分分析结果」的表达，再接入正式入口；③ 负责人修公共执行结果的覆盖表达与义务保留，**队友 B 提供 partial 候选义务与对应回归测试**；④ 两遍方案**降为对照实验**，不作为长期正式执行路径；⑤ 测试数、候选数、确认漏洞数**分别报告**；⑥ 实验产物从 `/tmp` 转存**持久目录**并附提交/命令/环境/产物哈希；⑦ 分片口径收紧为「某真实组件的一组分片配置下集合一致」，不得宣称任意分片不变。
- **落地改动（全部属于 B 线，未动公共契约）**：
  1. **partial 候选不再留空白义务**：共享 runner 只为 `completed` 的 run 记录义务，blocked 那遍的候选义务为空。现在驱动对**没有** runner 义务的候选补 5 条**标准问题**——`entry_reachability` / `caller_identity_conditions` / `guard_effectiveness` / `parse_completeness_impact` / `configuration_path_existence`——状态一律 `unknown`，标 `origin: audit_driver`，并写明「空列表从来不代表无需验证」。**义务是问题不是断言**，因此 partial 文件也能带；驱动**不伪造任何 AST 事实**。
  2. **候选身份绑定完整**：身份键由 `(file, line, rule_id, source_sha256)` 扩为 **`(repository, 完整 commit, rule_id, 规则版本, file, line, source_sha256)`**，候选上同时记 `rule_version` / `model_version` / `observed_detector_versions` / `observed_detector_ids` / `sources`。新增 `merge_audit_reports()`：跨实验按该键合并，**按来源并集保留义务**（后一遍不再覆盖前一遍）。
  3. **修掉一处身份分裂**：把「规则版本」放进身份后，两个 pass 因 `detector_id` 不同（`…ipc` 与 `…ipc.complete-ast`）导致同一候选**裂成两行**（fixture 上候选 4 → 7）。角色归属应是**解释**而非**变体**，故引入 `interpretation_id`（两个变体都声明为 `ohscanner.interface.ipc`）：同一解释的不同作用域限制合并为一行，**算法不同的实现必须声明不同 `interpretation_id`** 才不会被混同。这正是负责人点出的「身份分裂」风险，实测被抓到并修正。
  4. **统计闭合**：新增 `bucket_closure`，把计划文件分入**六个桶**——`parse_complete` / `parse_partial` / `parse_failed` / `unclaimed_by_detector` / `dropped_by_loader` / `not_run_files`——残差进 `files_unaccounted` 并单独打印（不四舍五入进别的桶）。顺带修一个**真实归属 bug**：被共享 loader 丢弃的非 UTF-8 `.cpp` 原会被算成「无 detector 认领」（它其实是 `cpp`，有 detector 声明），现在按**声明语言**判定，该文件落进 `dropped_by_loader`。
  5. **报告 schema v2 + 三数分离**：报告顶层 `counts` 分开给 `source_files_audited` / `candidates` / `candidates_with_runner_obligations` / `candidates_with_driver_synthesized_obligations` / `confirmed_vulnerabilities` / `false_positives_reviewed`，控制台也分行打印。**测试数、候选数、确认漏洞数不混为一个数。**
  6. **产物归档**：默认写入 `outputs/reports/`（`.gitignore:226-227` 已忽略），并为每个组件写 `*.manifest.json`——提交 / git tree / snapshot / plan sha、`plansha`、命令 argv、cwd、环境（Python / platform / git 版本）、计数、闭合结果、以及 **JSON 与 MD 的 sha256**。清单与它描述的 JSON 写在同一目录，不会漂移。
  7. **口径收紧**：报告与限制里写明「**两遍都看见 = 同一解释在同一文件上跑两遍的重复，不是独立佐证**」；分片只声称「一组配置下一致」，并注明「组件全局规则需要整体求值，本链路不做」。
  8. **CCR 更新**：`docs/contracts/ohscanner_blocked_run_coverage_ccr.md` 增 §3.1/§3.2/§6——记录负责人已批准的语义（**先 sidecar 后 status**；执行 `completed` 而覆盖 `partial` 是允许的；已产出候选与义务**不得**因整体状态被丢弃；保留候选仍须**校验文件范围/源码哈希/位置/来源**；「已检查但分析未完成」与「完全未分析」分开记录），并列出 B 提供的**反例与回归测试清单**（平台修好后哪条断言该翻转）。反例本身：`communication_dsoftbus @ 652f88e0…` 4 条候选、义务为空。
- **五组件实数（最终代码，schema v2，1 shard/组件，`validated_vulnerability` 全部 0）**：

  | 组件 | commit | 文件 | parse 完/部分 | 未被认领 | 候选 | runner 义务 / 驱动补 |
  |---|---|---|---:|---:|---:|---:|---:|
  | update_updateservice | `e4942a33` | 219 | 187 / 31 | 1 | 2 | 0 / 2 |
  | security_access_token | `17d88bfb` | 550 | 489 / 56 | 5 | 20 | 20 / 0 |
  | distributeddatamgr_kv_store | `acfb22aa` | 1446 | 1134 / 310 | 2 | 0 | 0 / 0 |
  | window_window_manager | `8b0d8fe1` | 1112 | 811 / 268 | 33 | 15 | 4 / 11 |
  | communication_dsoftbus | `652f88e0` | 1656 | 729 / 927 | 0 | 4 | 2 / 2 |
  | **合计** | | **4983** | | | **41** | **26 / 15** |

  五个组件的文件账**全部闭合**（`files_unaccounted == 0`，`parse_failed` / `dropped_by_loader` / `not_run_files` 均为 0）；这三类桶目前为 0 是**实测**，不是「没统计」。
- **测试**：组件审计单测 **45 项**（本轮 +12：闭合 4、跨报告合并 2、身份/变体 2、清单 2、CLI 计数 1、清单落位 1），全量 **375 项 OK**。既有测试无回归。
- **仍未做到**：① 平台层的覆盖表达与义务保留**未改**（归负责人，B 只给反例与回归测试）；② 仍未注册 `catalog.py`、未做成 CLI 子命令（归负责人）；③ 15 条 partial-only 候选的义务是**驱动的标准问题**，不是跑出来的证据；④ 根因相交在组件审计里恒为 `not_measured`；⑤ 产物目录虽持久但**不入库**（按 AGENTS.md）。
- **下一步（B 线，按负责人指定优先级）**：从 41 条里挑 **5–8 条**代表性候选（覆盖 complete 与 partial-only），逐条记录：原始代码与关键上下文、是否误报及原因、是否有上层检查/调用前提/配置限制、当前能确认到哪一步、能否做构建或运行验证。**目标是用核查结果指导算法改进，而不是继续增加候选数量。**
- **动作**：本轮改动**未推送**（负责人未授权）；产物写入 `outputs/reports/*.json|*.md|*.manifest.json`（已忽略）。

## 32. 2026-10-11 首批候选核查：41 条逐条判定，五个误报机制定位到代码行

- **做了什么**：按 §31 的下一步，把五组件 41 条候选**逐条核查**（不是抽样），产出
  `docs/research/ipc_candidate_review_2026-10-11.md`，复核脚本入库到 `research/experiments/interface/ipc/review_*.py`。
- **三个数分开报**：**测试 375 项 OK**（组件审计 45 项）/ **候选 41 条** / **确认漏洞 0 条**。
  判定分布：**likely false positive 37 条、plausible but unproven 4 条、确认 0 条**。
- **41 条里没有一条能过证据门**（缺入口可达性、缺攻击者控制、缺 C/I/A 影响），全部仍是 `evidence_type=syntax`、
  `validated_vulnerability=0`。**本次核查不产生任何漏洞结论。**
- **五个误报机制（都已定位到 file:line，两个有对照实验）**：

  | 机制 | 位置 | 后果 |
  |---|---|---|
  | **M1** 描述符校验被限定条件挡掉 | `analysis.py:582-585`：`X::GetDescriptor()` 只在 `X == fn.owner` 时被认；真实 stub 实现的是接口 `I`，于是 `ITokenSyncCallback::GetDescriptor()` 判为 `UNKNOWN` | `security_access_token` 20 条 AUTH-01 的主因 |
  | **M2** 描述符校验被委托给内层入口 | `screen_session_manager_stub.cpp:42` 只是转调，校验在同文件 `:50` | WWM 1 条 AUTH-01 |
  | **M3** 授权谓词词表只认固定名字 | `models.py:130-135` + `analysis.py:596-601`；`IsRootCalling`/`IsNativeProcessCalling`/`IsCallerValid`/`IsSystemCalling`/`IsSACalling` 全不在表内 | AUTH-02/AUTH-04/CAP-01 多条；**反向**还把 guard 函数自己当 handler（`token_sync_manager_stub.cpp:83/110/127` 报的是 `IsRootCalling`） |
  | **M4** 权限函数用项目错误码判成败 | `CheckPermission` 在词表内，但调用点写 `!= SOFTBUS_OK`，而 `SOFTBUS_OK = 0` 是**另一文件**的枚举成员（`softbus_error_code.h:1788`） | dsoftbus 2 条 CAP-01 |
  | **M5** dispatcher 守卫支配性未证明 | `update_service_stub.cpp` 候选自述 `dispatcher-guard-observed` | 2 条 AUTH-04（**检测器自述诚实**，缺的是支配性证明，不是发现了缺失检查） |

  另有 **M6**：守卫在实现类、实现类在另一个翻译单元（`window_manager_stub.cpp:389` → `window_manager_service.cpp:1608` 等），
  属 file-local 分析的固有边界，不是 bug。
- **M1 的对照实验（本仓库可复现）**：只把 `GetDescriptor` 的限定判据放宽，别的都不动——
  `as shipped: candidates=6 / AUTH-01=6` → `qualifier relaxed: candidates=0 / AUTH-01=0`。
  量：`security_access_token` 12 处描述符比较中 **9 处是接口限定形式**；而 **28 个 fixture 全部写成非限定形式**，
  所以 29 个设计场景全绿、真实代码上的常见形式从未被测到——与 §22 入口发现的「命名假设在真实代码上接近空集」是同一类失效。
  接口身份**可从源码派生**（基类实参 `IRemoteStub<ITokenSyncCallback>` / `IRemoteStub<OnPermissionUsedRecordCallback>`），
  且**不能靠名字猜**（后者无 `I` 前缀）。
- **同一组件内的自证**：`accesstoken_callback_stubs.cpp` 用 `IsAccessTokenCalling()`（**在**词表内）→ 该文件没有 AUTH-02；
  `token_sync_manager_stub.cpp` 用 `IsRootCalling()`/`IsNativeProcessCalling()`（**不在**词表内）→ 同类位置出 3 条 AUTH-02。
  「有检查但没被识别」≠「没有检查」。
- **部分解析成因（实测，逐行 ERROR）**：不是 `#if` 嵌套，而是三类机械形状——格式宏字符串拼接（`PRIu64`/`PRIu32`/`SCNd64`）、
  成员函数指针调用 `(this->*f)(...)`、**把 `return` 当宏实参**（`ENGINE_CHECK(cond, return ret, ...)`，该文件 20 个 ERROR）。
  且这些 ERROR 行与本批候选行**不在同一处**：`update_service_stub.cpp` 的候选锚点是 `dispatch=map_member_ptr`，
  说明入口索引在部分解析下**仍然**恢复了分发绑定与 dispatcher 守卫——**partial 影响的是覆盖口径与义务来源，不是本批候选的成因**。
- **值得继续跟的 4 条（都不是漏洞结论）**：`screen_session_manager_stub.cpp:1778`（唯一一条导出前路径上找不到任何调用者检查的能力导出）、
  `session_stub.cpp:592`、dsoftbus 的 `bus_center_ex_obj_stub.cpp:56` / `trans_spec_object_stub.cpp:62`
  （stub 确实不校验描述符且绕过了 `IRemoteStub<T>` 默认校验，但强制点在**不在本仓库**的插件里）。
  四条都卡在同一件事：**跨仓或运行时才能确定能力面**。
- **没做**：**没有改任何检测器规则**（改规则会改变候选集合，须与它的正/反例一起单独落地并复跑五组件）；
  没有升级任何候选；没有跑构建/运行时验证（各组件可行性已列入报告 §7）。
- **动作**：本轮**未推送**。

## 33. 2026-10-11 M1 描述符身份修复（队友 B 单独提交，~~未推送~~ **该分支后已推送，见 §53**）

接口线 M1：把 IPC 描述符校验从「限定名必须是本类」的过滤器，改成**从类自己的基类子句读出的接口身份**，
并按三档给结论。只改这一处，**M2～M6 未动**。

- 提交：`3fe3537`（分支 `feat/interface-m1-descriptor-identity`，**基于负责人已本地验证并推送的
  `feat/owner-ipc-platform-integration` 顶端 `86fbf99`**）；同一份树改动在接口线为 `3d88ffc`。
  ~~**两者均未推送、未合并**~~，**（2026-10-16 更正，见 §53）两者均已推送，仍未合并**；
  是否开 PR/合并由负责人决定。
- 三档：身份一致（接受为守卫，报文注明来源）/ **明确不一致**（保留候选，同时列出比较的接口与类声明的接口
  各自的 file:line）/ 无法判定（保持 `unknown`，既不当作校验成立，也不当作明确不一致——别名基类、
  类声明不在本分片都属于这一档）。身份**永不从类名推断**：
  `IRemoteStub<OnPermissionUsedRecordCallback>`（接口无 `I` 前缀）与
  `TokenSyncCallbackStub : IRemoteStub<ITokenSyncCallback>`（类名与接口名不同）都被正确处理。
- 规则身份随之移动：detector `0.4.0`、model `oh-ipc-2026.10-v2`，新增两条按观测级别的义务
  `descriptor_identity_mismatch` / `descriptor_identity_unresolved`。
- **另加 4 个「有比较但不成守卫」的对照**：只取回没比较、不匹配分支只记日志、守卫在目标操作之后、
  只覆盖一个分支——四种情况下 AUTH-01 仍然产生，说明修复没有放宽路径语义。

### 已验证

- 按**正式执行路径**复跑五组件（`python -m src.cli ohscan-run --detector ohscanner.interface.ipc`，
  同一批显式 `--include` 路径、同一 commit、比较键与既有回归脚本一致）：
  `security_access_token` **20 → 3**（17 条 AUTH-01 消失、0 新增、0 理由变化），
  另四个组件 **15/4/2/0 逐条不变**；合计 **41 → 24**，`validated_vulnerability=0`，
  24 条候选全部带义务。
- **17 条消失逐条有依据**：每条都定位到入口函数体内的守卫行、两侧身份、以及候选被到达的调用链
  （如 `TokenSyncCallbackStub::OnRemoteRequest` 守卫 `:70` → 调用 `:78` → handler `:103`），
  并逐条验证文件的 sha256 等于该候选被绑定到的 `source_sha256`。注意一个文件可能有多个 stub 类、
  各带自己的守卫，取证必须取**候选所属入口**里的那一句。
- 测试：接口线分支 **391 项 OK**（修复前 375；新增 16 项描述符身份测试 + 11 个 fixture，
  manifest 29 → 40 行）；基于集成分支的分支 **350 项 OK**。
- 复现命令、环境、产物哈希：`docs/research/ipc_m1_descriptor_identity_2026-10-11.md`；
  产物在 ignored `outputs/reports/m1_descriptor_identity/`（不提交）；脚本入库到
  `research/experiments/interface/ipc/m1_*.py`。`.gitignore` 按既有惯例增加一行该产物目录。

### 未验证

- **`mismatch` 与 `unresolved` 两档只有 fixture 证据**：本次语料新增 0、理由变化 0，
  说明真实源码里没出现这两档。不能据此认为它们已在真实代码上验证过。
- **M3 的缺陷没有修**：17 条里有 3 条（`token_sync_manager_stub.cpp:83/110/127`，报的是授权谓词
  `IsRootCalling`）在核查文档里被判为 M3 机制；M1 让它们的 AUTH-01 观测消失，是因为入口守卫支配该路径，
  **不等于**「guard 被当成 handler」这件事被修好。
- 支配性只按同一套结构规则核对（守卫在入口体内、早于候选、不匹配分支 return）并逐条读过钉住 commit 的
  源码；守卫**语义**之外的前提仍在义务里（token 是否可能为空、调用方能否控制、是否存在别的入口绕过）。
- 五组件本次运行 `coverage status` 都是 **partial**，仍带解析完整性义务；
  「解析错误不在候选附近」不足以证明没有影响，只写「当前核查未发现直接关联」。
- 核查文档的 **37 条 likely false positive 不是正式误报率**：没有独立标注集就不存在 Precision，
  本项工作不给出该数字。
- M2（同文件一跳委托）、M5（有界支配性）、M3/M4、M6（定向跨文件/跨仓）**未开始**；
  存活候选的机制见 `docs/research/ipc_m1_descriptor_identity_2026-10-11.md` §6。

### unknown

- `dlsym`/函数指针表的间接分发、别名基类、跨仓能力面仍为 `unknown`，保留候选不臆断。
- M2～M6 修完后候选集合如何变化未知；本条不预测也不追求某个数字。

## 34. 2026-10-12 M2 一跳同文件委托：被委托方就是守卫时才不算边界（队友 B 单独提交，~~未推送~~ **该分支后已推送为 Draft PR #11，见 §53**）

### 已实现并复核

- **缺陷**：AUTH-01 的中继谓词问的是「**入口自己的状态**里有没有确立描述符校验」。入口只把请求
  原样转交给同文件另一个函数时，入口体内当然没有校验，于是**隔一次调用的守卫**被报成不存在。
  真实例：`window_window_manager` `window_scene/screen_session_manager/src/zidl/screen_session_manager_stub.cpp`
  候选 `:42`（`OnRemoteRequest` 转调 `OnRemoteRequestInner`），真守卫在其 `:50`。
- **修复**：新增 `relay_guard()`，五个条件同时满足才把这一跳读成守卫——①被委托方**同文件**；
  ②实参**逐字是入口自己的形参**（换成字面量即非转交）；③被委托方**顶层**存在
  `ReadInterfaceToken()` 与描述符的比较（嵌套不算）；④比较身份 ∈ M1 的 `_DESCRIPTOR_ACCEPTED`；
  ⑤不匹配分支**顶层 `return`/`throw`** 且该比较**早于 `switch`**。读到比较之前会**沿路绑定被委托方的
  `init_declarator`**（`token = data.ReadInterfaceToken();` 这种常见写法）。三档返回
  `guarded` / `seen`（保留候选，报文「present but not accepted」并列出两侧身份） / 不成立。
  `action()` 与 `value()` 的委托分支**两处调用点用同一判定**，避免同一行出现两种说法。
- **度量用正式执行路径**（`python -m src.cli ohscan-run --detector ohscanner.interface.ipc`），
  范围逐条取自 M1 平台产物自己记录的 `--include` 路径集合，键为 `(file, line, rule_id, source_sha256)`：
  `window_window_manager` **15 → 14**（1 条 AUTH-01 消失、0 新增、0 理由变化），
  其余四组件逐条不变（3→3、4→4、2→2、0→0），**合计 24 → 23**。
- **绑定未变**：前后两次运行 `commit` / `snapshot_sha256` / 该文件 `source_sha256` 完全相同，
  只有 `detector_version` 0.4.0 → 0.5.0。**拓扑已写入报告**：`catalog.py` 是负责人维护的注册表且其
  集成分支的 `interface/` 包是 M1 前快照，故 CLI 跑在该工作树的临时副本上并覆盖队友 B 的 `interface/` 包。
- **不丢信息**：`OnRemoteRequestInner` 本就是入口 root，其自身观测保留——同文件仍报 2 次
  （`:738` AUTH-02、`:1778` CAP-01）。
- **对照实验有区分度**：同一批 8 个 fixture 跑在 M2 之前的引擎上，恰好两个 `_fixed`
  与「另一个接口」的报文断言共 3 项失败，五个纯正例前后都通过。
- 测试：接口线分支 **401 项 OK**（修复前 391；新增 10 项 + 8 个 fixture，manifest 40 → 48 行）。
- 复现与产物：`docs/research/ipc_m2_relay_guard_2026-10-12.md`；
  脚本 `research/experiments/interface/ipc/m2_platform_delta.py`；
  产物在 ignored `outputs/reports/m2_relay_guard/`（不提交）。

### 未验证

- **`seen` 档与局部变量档只有 fixture 证据**：五组件里凡隔一次调用的守卫，比较身份都被接受，
  真实语料没有行使这两档。不能据此认为它们已在真实源码上验证过。
- **不做跨文件**：条件①硬性要求同文件；`DelayedSingleton<X>::GetInstance()->Method()` 那一跳
  与 M6 的范围没有改动。
- **不是支配性证明**：条件是结构规则（顶层 + 早于 switch + 不匹配分支离开），`goto`、异常、
  宏展开改变控制流的情形未被覆盖——支配性本身属 M5。
- **不校验被委托方的其它调用者**：判定按调用点逐处进行，不推断该函数是否还被别的入口调用。
- 五组件本次 `coverage status` 都是 **partial**，仍带解析完整性义务；
  只写「当前核查未发现直接关联」，不写「无影响」。
- 本报告不给 Precision：没有独立标注集就不存在正式误报率。
- **M2 未修 M3/M4/M5/M6**：授权谓词体未建模（M3）、常量域（M4）、有界支配性（M5）、
  定向跨文件/跨仓（M6）都原样保留。


## 35. 2026-10-11 M2-A 两个 C++ 自研候选检测器集成（GitHub CI 验证）

- **范围**：把队友 A 整合分支 `40c2c66e` 的 `lifetime_detector.py` 与 `shared_ptr_race_detector.py` 及合成开发样例原样迁入核心 Catalog；适配层提供固定 Git 输入、M1.5 资格检查、文件级执行状态、证据义务和 JSON/Markdown。
- 原始规则逻辑不改：`unique_ptr/raw alias/reset` 候选和 `shared_ptr` 非原子成员访问候选。前者对应待核实 CWE-416，后者首先是 CWE-362 候选；二者均不是确认漏洞。
- `DetectorRun.file_outcomes` 为向后兼容的可选文件级元数据；旧 `ToolRunResult v1` 不改。对 `blocked` 的局部已完成文件、部分检查和候选证据在 Sidecar 分别存储，不能把未完整检查当成安全。
- 新增 `tests/test_ohscanner_m2_a_integration.py` 的本地固定 Git 正负样例、跨文件 partial、工作区漂移和 Catalog 回归；旧 A 原算法测试一并携带。**GitHub Actions 已在 2026-10-11 最新功能提交 `f64c5b5d` 完成 250/250 项测试通过**（[Run 38073903714](https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit/actions/runs/38073903714)）；**Ubuntu 上对真实 c_utils 当前 commit 的两检测器执行仍未复测**，不得宣布真实新漏洞命中。
- 独立 holdout、当前组件攻击可达性、完整产品构建、PoC/TSan 自动关联、影响版本、修复重验和报告均不属于本次完成项。
- 文档：`docs/testing/ohscanner_m2_a_integration.md`。PR #5 保持 Draft，不合并 main。

- **CI 过程纠错**：首次开启 push CI 的 `d6943589` 运行 `38073772285` 为 249/250，通过日志定位为 M2-A 集成测试强求所有语义模型文件 `completed`；在 `f64c5b5d` 修正测试为承认真实 `blocked/partial`，没有放宽安全证据门槛或重写队友 A 原算法。后续 CI `38073903714` 全绿。


## 36. 2026-10-13 接口线并入 core，并按 blocked-run CCR §3.2 完成翻转（队友 B）

- **范围**：把 `origin/feat/ohscanner-core`（`e365465`，含 M2-A 集成 `022c022`）并入
  `feat/interface-ipc-detector`。冲突 2 处，均为取并集：`runner.py`（core 的 `file_outcomes`、
  sidecar 五档状态 + 接口线的契约 v2 身份、`_bind_source`、逐来源义务）与 `PROGRAM_STATUS.md`
  （接口线 §22–34 保留，core 的 §22 追加为 §35）。合并后的 `runner.py` 与 core 的差集**只有接口线
  自己那部分**，core 的义务门 `report.status in ("completed", "blocked")` 完整保留。
- **合并后 5 项红，全部是预先声明过的语义碰撞，不是合并缺陷**：4 项是
  `docs/contracts/ohscanner_blocked_run_coverage_ccr.md` §3.2 **预先点名**的接口线断言，1 项是
  core 的 v1 契约断言。逐条结果记在该文件 §3.3。**merge commit 单独看是红的**，翻转紧随其后。
- **驱动的逻辑未改，也不该改**：合成门本来就是 `if not entry["obligations"]`（只在 runner 确实
  没记录时才补 `origin: audit_driver` 的 standing questions）。本次只改描述旧平台行为的文字，
  并把该兜底路径的回归测试改成**对照测试**（`mock.patch` 抹掉 sidecar 的义务记录，断言驱动仍补）。
- **实测（合并后的树，fixture 组件）**：`all-files` 那遍 detector run 仍 `blocked`、`scope_files`
  仍 `0`，但 4 条候选全部 `obligations_source == shared_runner`，
  `candidates_with_driver_synthesized_obligations == 0`；整体 report 状态为
  `completed_with_limitations`。**候选集合与身份未变**——义务是元数据，翻转不改变报出哪些候选，
  因此不引入新的误报或漏报。
- **`scope_files` 仍是 0**（CCR (a)/(c) 未做）：报告继续把 0 与 `applicable/analyzed` 计数一起
  打印并附原因说明，不把 0 当覆盖，也不因义务修好而提升任何结论等级——候选仍是候选，
  `validated_vulnerability` 仍是 0。
- **跨线待办**：core 的 `tests/detectors/test_cpp_runner_integration.py` 在本分支已改为 v2；core
  线自身仍是 v1，由负责人决定何时重基线。core 的 §35 写着「旧 `ToolRunResult v1` 不改」，本分支
  按已批准的契约 v2（§27）取 `schema_version=2`，两者需要在合并进 main 前对齐。
- **测试**：合并后的树 `Ran 451 tests ... OK`（本次运行无跳过项）。合并前同一条线的基线为
  450 项（其中 5 项红），本轮净增 1 项（对照测试）。

## 37. 2026-10-15 推送已完成的 3 个提交 + window_window_manager 14 条候选逐条复核（队友 B）

### 已推送（负责人本轮授权；仍为 Draft PR，**未**标 Ready、**未**合并）

- 推送前的核对：当前分支 `feat/interface-ipc-detector`，HEAD `f245681`，工作树干净，
  领先 `origin/feat/interface-ipc-detector` **恰好 3 个提交**（`d586008` → `f2bd80b` → `f245681`），
  远端当时停在 `48bce9e` → 可安全快進。推送后远端为
  **`f2456815c8af17bc2edb5ecddcbc361ccb434d35`**（= 本地 HEAD），未做 force-push。
- 推送前那 3 个提交上跑的**全量测试 454 项 OK**（对应 HEAD `f245681`），
  `git diff --check` 干净，测试运行未改动 HEAD。

### 已修复的过期表述

- §22/§26/§29/§30/§31/§32/§33/§34 里的「未推送」是**写作当时**的事实；经
  `git merge-base --is-ancestor` 核对，`3d88ffc`、`4fda320`、`89401fb`、`3feb5bc`、`48bce9e`
  **都是当前 HEAD 的祖先**，已随本分支在远端 → 上述标记对这几个提交**已失效**。
  §33 提到的集成分支提交 `3fe3537` **不在**本分支（`NOT ancestor`），该行保持原样。

### 已完成：`openharmony/window_window_manager` @ `8b0d8fe1…` 的 14 条候选逐条复核

- **报告**：`docs/research/ipc_wwm_deep_review_2026-10-15.md`（本节的事实来源）。
- **版本绑定**：候选自带的 `source_sha256` 六个候选文件、pinned blob、本地 `perf-corpus` 工作树
  **三者一致**，且该 clone 的 HEAD 就是声明 commit — 本轮**没有** dsoftbus 式偏移；所有引文仍用
  `git show <commit>:<path>`，未以工作树为证据来源。
- **判定分布（四类互斥，不互相折算）**：likely false positive **6**（1/3/9/10/11/14）、
  unresolved external dependency **2**（12/13）、plausible but unproven **6**（2/4/5/6/7/8）、
  confirmed **0**。`validated_vulnerability` 仍为 **0**，未升级任何候选、未删改任何负结果。
- **FP 的守卫位置全部可复核**：`screen_session_manager.cpp:10918/:10933`（+ `CheckSavePermission`
  `:10894-10912`）、`wm/src/window_session_impl.cpp:5064`、`scene_session_manager.cpp:12969/:12984/:4779`、
  `window_manager_service.cpp:1608`（支配靠 `finishCallback` 保持 nullptr 传播到 stub 的空分支）。
- **两条重点候选**：候选 2（`screen_session_manager_stub.cpp:1778`）— 派发路径无守卫，`GetRenderSession`
  `:3200-3208` 无守卫，同文件有 `:2026` 先例；缺口在 foundation/graphics 的令牌能力语义与 SA 4607 可达性，
  且 WMS 本来就把同种令牌交给应用（`scene_session_manager.cpp:5421`），增量是「任意 `screenId`」。
  候选 4（`session_stub.cpp:592`）— `Connect` 全链**无所有权检查**，`identityToken` 仅主窗比较且空值即通过、
  失败还返回 `WS_OK`；`renderSession` 在 `scene_session.cpp:253` **无条件**赋值（失败也回写令牌）。
- **同一批候选里证据最强的一条**：候选 7/8（恢复路径）——`GetSceneSessionBySessionInfo:3756-3762`
  按调用者给定的 `persistentId_` 取回**任意活会话**且不比对属主；`CheckSessionPropertyOnRecovery`
  的守卫只查窗型（特定会话变体连 `IsNeedRecover` 都跳过）；`Session::Reconnect:1873-1875` 会接管
  stage/eventChannel 并**改写会话的 pid/uid**。仍判 `plausible but unproven`，**不写成漏洞**：
  可达性（第三方应用能否自备 property/事务）与影响均未证。候选集**不按严重度排序**这一点已记入报告 §7.3。
  ⚠️ 本bullet 里「按调用者 id 取回任意活会话」这一句**已被 §38 更正为不成立**（`GetSceneSessionBySessionInfo:3751`
  对恢复请求早退），原文保留以记录当时的判断。**注意口径**：被删掉的是这条**子假设**，
  候选 7/8 的**整体判定不变** —— 仍为 `plausible but unproven`（§38 判定表），
  不得把本行读成「候选 7/8 已降级 / 已判为误报」。

### 未验证 / unknown（本轮的诚实边界）

- 14 条中 **10 条的宿主文件 `file_parse_status=partial`**（1/2/4/5/6/7/8/9/10/11）；文件级 partial 268 /
  complete 811。判定只建立在**直接读到的**守卫上，不假设 partial 文件里的守卫都找到了。
- 外部依赖清单（报告 §6）：`RSUIDirector`/渲染令牌（foundation/graphics，本仓库只有 test mock）、
  `Ace::UIContent`、`RSIWindowAnimationFinishedCallback`、`WINDOW_MANAGER_SERVICE_ID` 的数值与归属
  （全树无定义）、`sa_profile` 的 `permission` 字段语义（4606/4607/scene_board 4607 **均无该字段**，
  但消费方在框架侧）。这些**既不判成漏洞也不判成安全**。
- **不给 Precision/准确率**：误报 6 与证据边界 2 分列计数，二者都不进准确率；独立 holdout 仍不存在。
- **未跑动态验证**：本轮全部为静态复核；7/8 若要推进，先钉 `isPersistentRecover_` 分支与可达性论证。
- 未修改任何检测器规则或契约；报告 §7.1 的 `object_ownership` 义务是**新契约建议**，须单独落地并带
  正例/反例/无关对照。

## 38. 2026-10-15 WWM 恢复路径可达性调查（候选 7/8，队友 B）

### 历史（上一轮，真实历史，保留）：提交 `b2d9885` 的推送

- 该提交的内容是 §37 的 14 条候选复核，**与本节的恢复路径调查不是同一件事**。
- 推送前核对：分支 `feat/interface-ipc-detector`，HEAD `b2d9885`，工作树干净，`git diff --check` 干净，
  领先远端**恰好 1 个提交**（`b2d9885`，改 `PROGRAM_STATUS.md` +54、新增
  `docs/research/ipc_wwm_deep_review_2026-10-15.md` 354 行），`merge-base --is-ancestor` 判定可快进、
  远端当时 `f2456815…`。推送后远端 = **`b2d98853c282e55c2079fef0579a27b99d03d8da`**，无 force-push，
  仍为 Draft PR，未标 Ready、未合并。

### 本轮推送记录（两段，勿与前一段的 `b2d9885` 混淆）

**第一段——已推送。** 本轮先形成本地提交 `6852b1c`（**仅文档**：`PROGRAM_STATUS.md` 与
`docs/research/ipc_wwm_recover_reachability_2026-10-15.md`），**从未推送**。按负责人 2026-10-15 的
判定修正文档结论后，`6852b1c` 于推送前被 **amend** 为 `ddcdb7d…`。在 `ddcdb7d` 上复跑通过
（`Ran 454 tests … OK`，见「本轮检查」），随后以 `git push origin feat/interface-ipc-detector`
**快进**推送 `b2d9885..ddcdb7d`（退出码 0，无 force）；推送后远端 = 本地 =
**`ddcdb7d5a2b82453b7cb2e85778676ce6643c7d7`**（ahead/behind 0/0），Draft PR **未标 Ready、未合并**。

**第二段——本次。** 按 B 线建议追加三处修正：(1) §7.A 子假设层**只用 `refuted`**，不并列
`likely false positive`（理由见报告 §7.A 脚注）；(2) §8.1 重评门槛改为 **(i)+(ii)**，(iii) 越权影响
降为**运行时阶段要产出的结果**而非进入前提；(3) §37 补口径注（子假设被删 ≠ 候选降级）。
本次提交即**本文件所在提交**，哈希以 `git rev-parse HEAD` 或推送后的远端
`origin/feat/interface-ipc-detector` 为准（不写自身哈希，以免自我指涉失效）。

**测试归属（勿误读）**：`6852b1c` 上**从未跑过** unittest，旧记的 `Ran 454 tests … OK` 是**父提交
`b2d9885`** 上的结果（改动只有 Markdown，不进入 Python 测试输入）；`ddcdb7d` 与本次提交上各复跑一次，
结果见「本轮检查」。

### 本轮已完成：回答「普通应用能否控制恢复请求并取回/接管其他会话」

- **报告**：`docs/research/ipc_wwm_recover_reachability_2026-10-15.md`（本节事实来源，含逐文件 blob+sha256）。
  固定对象 `openharmony/window_window_manager` @ `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
  （tree `24e60146ba2fe4af3aaef20b306a1e306df44617`），全部证据经 `git show <commit>:<path>` 读取。
- **输入可控性**：`persistentId` 随 `WindowSessionProperty` 序列化（`window_session_property.cpp:1676`），
  **调用者可控**；`isPersistentRecover_` **不是** property 字段（该文件全文无此标识符），
  且 `MarshallingSessionInfo:1338-1369` 不往返它 —— 它由服务端在 `RecoverSessionInfo:5963` **无条件置 true**。
- **更正前序线索**：`GetSceneSessionBySessionInfo:3751` 在 `isPersistentRecover_` 为真时**直接返回 nullptr**，
  而该位置在查表前已被置位 → 两条候选**都不会复用活会话**，必然走 `CreateSceneSession`；
  §37 那条「按调用者 id 取回任意活会话」对本组候选**不成立**。另：`GeneratePersistentId:5219` 只在
  id 未被 `g_persistentIdSet`（只增不删）占用时才采纳调用者的值 → **在用的 id 不可抢占**。
- **守卫缺口（本组候选真正的差异）**：`CheckSessionPropertyOnRecovery:6010-6026` 是唯一守卫 —
  候选 7（`:421`）连 `IsNeedRecover` 都跳过**且没有 `recoveringFinished_` 门**（`:6039` 只查回调非空），
  候选 8（`:462`）两者都有（`:6021` / `:6185`）；两条都不调用创建路径才有的
  `CheckModalSubWindowPermission:5818` 与 `CheckSubWindowCallingProcess:5918`（父进程 pid 比对 `:5937-5942`）。
- **实际效果**：`Session::Reconnect:1868-1875` 绑定调用者自己的 stage/eventChannel/abilityToken、
  整块覆盖 property、并把会话 pid/uid 改写为**调用者自己的真实 pid/uid**；该路径**不**做
  `CheckPidIfMatched` / `CheckIdentityTokenIfMatched`（只出现在 `scene_session.cpp:531/:634/:837`）。
  返回给调用者的对象是它自己刚建的那个会话，**不是**他人的会话。
- **可达性**：仓库内**找不到**任何限制普通应用发这两个事务的检查（`scene_session_manager_stub.cpp`
  全文无权限/uid/pid 检查，proxy 的两个方法无权限检查，`sa_profile/4606.json` 无 `permission` 字段）；
  但**也证不出**可达（需 SAMGR 取回 4606 对象 + 构造 property parcel，均在本仓之外）。
  应用侧入口是系统恢复通知驱动的单次回调（`window_scene_session_impl.cpp:1129-1167` →
  `window_adapter.cpp:615/690-714/887-896`），非应用可随时调用的 API；innerkit 的
  `Window::Recover()` 系列（`interfaces/innerkits/wm/window.h:3295` 等）经 `ExecuteRecover:5105`
  只做取消最小化，**不触达**这两个事务（负结果）。
- **JS/napi 面（本轮检索完毕）**：两个事务在 `interfaces/kits/napi/` 下**无任何绑定**；
  唯一相关 JS 面是 `notifySessionRecoverStatus`（绑定 `js_scene_session_manager.cpp:268-269`，
  实现 `:4400-4437`，**函数体内无权限检查**），它恰恰是候选 8 两道门
  （`IsNeedRecover(alivePersistentIds_)` `:6021`、`recoveringFinished_` `:6185`）的数据来源，
  且是 `alivePersistentIds_` 全仓唯一写入端；但 `git grep sceneSessionManager -- "*.d.ts" "*.ts"` **为空**
  → 该模块（`libscenesessionmanager_napi.so`）不在本仓声明式 API 清单内，调用方在仓外。
  应用侧 `window.recover`（`js_window.cpp:12338` → `OnRecover:2060` → `window_impl.cpp:2744-2766`）
  只取消最小化，**不触达**这两个事务（与 innerkit 结论互相印证）。

### 判定：两层，各有独立的对象与计数口径（按负责人 2026-10-15 判定）

| 层 | 结论对象 | 判定 | 计数口径 |
|---|---|---|---|
| 7.A | 「用调用者给的 `persistentId` **取回并接管已有会话**」这一**子假设** | **refuted** | 子假设被删项，**候选记录不减**（负结果保留） |
| 7.B | 候选 7/8 作为一条 finding 的**整体安全结论** | **未决（plausible but unproven）** | 仍是**同一条**共享机制记录，**不另立**新漏洞、**不重复计数** |

- **7.A —— 子假设已证伪（只能这样读，不得外推为候选整体误报）。** 三条**源码级确定性**事实
  各自独立否掉「取回/接管已有会话」：
  (1) `RecoverSessionInfo:5963` 在查表前置 `isPersistentRecover_=true` → 复用分支 `:3756-3762` 不可达，
  `GetSceneSessionBySessionInfo:3751` 必返 nullptr；
  (2) `GeneratePersistentId:5219` 只在 id 未被只增不删的 `g_persistentIdSet` 占用时才采纳调用者值 → 在用 id 不可抢占；
  (3) id 不一致时 `:6052-6061`/`:6202-6208` 擦除新建会话并返回 `SESSION_NOT_RECONNECT`。
  这是 in-repo 可证伪的**负结果**（带固定提交 `8b0d8fe1` 与行号），**不是**「本地没搜到限制」的推测；
  负结果与原始候选记录**保留、不删除**，**detector 规则不改**。
  **用词**：子假设层只用 `refuted`，**不并列** `likely false positive`——后者是本项目 **finding 级**判定词
  （§37 四类互斥分布的分母用的就是它），在子假设层并列会被读成对候选整体的判定；原始措辞与理由见报告 §7.A 脚注。
- **7.B —— 整体 finding 维持未决，承载尚未判定的 broader capability / ownership 风险。** 7.A 只删掉
  「接管已有会话」一条路径；这两条事务**仍然**能以调用者自备的 property 新建 sub/系统类型会话，
  `bundleName_`/`abilityName_`/`moduleName_` 任填且服务端不与调用者 UID 比对，且该路径**缺**
  创建路径才有的 `CheckModalSubWindowPermission:5818`、`CheckSubWindowCallingProcess:5918`
  （父进程比对 `:5937-5942`）与 sub-window 层级上限 `:5295-5300`；叠加 §3.5 的跨会话 DIALOG 绑定。
  判定它所需的两项证据都缺：(a) 普通应用能否取回 SA 4606 对象并发事务；(b) 冒名会话与跨会话
  DIALOG 绑定在 scene board/AMS 侧的具体 C/I/A 影响。缺证据的两项记为 **unresolved external
  dependency**（指向缺失的**外部证据**，**不是**一条已成立的新漏洞）。
  → **既不升 confirmed/reportable，也不因 7.A 定为 false positive，也不因本地未搜到限制就断言无限制。**
- **计数**：`:421` 与 `:462` 是**同一条共享机制**的两次触发点，按**一条**记录计，**不重复计为两个独立漏洞**；
  7.A 删的是子假设**不减候选计数**，7.B 的残余是**同一条记录**里未判定的部分、**不另立候选**
  → 本轮结论**不产出、也不折算进 Precision/准确率**。`confirmed` 仍为 **0**、
  `validated_vulnerability` 仍为 **0**。
- 跨会话 DIALOG 父子绑定（`UpdateParentSessionForDialog:2590-2613`，无属主校验）**同样存在于创建路径**
  （`RequestSceneSession:5396`），属 7.B 未判定的**同一机制**的一部分，不重复计数，仅作影响面待查项。

### 未验证 / unknown（本节的诚实边界）

- 缺外部证据：SAMGR 对 SA 4606 的取回策略；普通 app 能否加载 `libwindow_scene_common.so`
  （`innerapi_tags = ["platformsdk_indirect"]`）与 `libwm(z).so` 的 `WindowAdapter` 符号；
  描述符提取 + 手搓 parcel 的可行性；`libscenesessionmanager_napi.so`（`nm_modname = "sceneSessionManager"`）
  由哪个进程加载、是否要求系统身份；下游 scene board/AMS 对新建冒名会话与跨会话 DIALOG 绑定的处理。
  以上**既不判成漏洞也不判成安全**。
- **是否进入受控运行时验证：当前不建议**为 7/8 立项做 PoC。7.A 的三条证伪是源码级确定性结论，
  运行时只能重复同一负结果；7.B 缺的是宿主访问控制与下游影响证据（取证/跨仓审计问题，非 PoC 能补）。
  **重新评估门槛**：(i) 普通应用能取回 SA 4606 远程对象；(ii) 普通应用能调用这两个恢复事务。
  **二者有证据即重新评估是否进运行时；(iii) 具体越权影响不设为前提**——其消费者在 scene board/AMS，
  很可能只有运行时才能确立，它是运行时阶段要**产出**的结果而非进入条件（报告的 §8.1 附操作提示：
  一旦有可用设备，(i) 用几行的非系统 UID 应用几分钟即可定论，比跨仓读 samgr 策略更确定）。
  在此之前保持 unresolved/unknown。
- **下一步研究优先级**（只读、绑定固定仓库与 SHA）：① SAMGR 对 SA 4606 的访问控制；
  ② 普通应用可用的库/API 边界；③ 下游 scene board/AMS 对冒名会话与跨会话 DIALOG 绑定的处理。
  逐条记录所查仓库、commit/blob SHA 与源码位置；若仍不能证明可达性或具体影响，**保持 unresolved/unknown 并停止**。
- 运行时验证所需条件已列（完整 `out/` 构建、可运行 WMS/SCB 的设备或模拟器、普通应用样本、可复现恢复时序）；
  **本轮未做动态验证**，未扩大规则或结论，未新增检测能力，未改公共契约。

### 本轮检查（命令 / 结果 / HEAD）

- 一致性自查：`grep -n "false positive\|plausible\|unproven\|confirmed\|未决\|refuted\|不重复\|Precision"`
  同时扫报告与本 §38，确认「子假设 refuted」与「整体未决」两处表述一致（脚本
  `/home/audit/wtmp/w38_consistency.sh`，在仓库之外）。
- 证据读取：`git -C <perf-corpus/window_window_manager> show <commit>:<path>`，脚本
  `/home/audit/wtmp/w38_c1.sh … w38_c28.sh`、`w38_hashes.sh`（均在仓库之外，不入库）。
- `git diff --check`（工作区与暂存区）→ 均干净。
- 文档结构：`ipc_wwm_recover_reachability_2026-10-15.md` 行数/围栏/`## `/`### ` 标题计数自查，
  编号 §1–§9 连续，新增 §4.6 / §7.A–C / §8.1。
- 回归：`.venv/bin/python -m unittest discover -s tests` → **Ran 454 tests … OK**，在两处 HEAD 上各跑一次：
  ① **`ddcdb7d`**（第一段推送的提交，`Ran 454 tests in 53.111s`）；② **本次提交（即本文件所在提交，
  分支 HEAD，`git rev-parse HEAD` 可核）**。本轮改动**只有 Markdown**，不进入 Python 测试输入；
  **父提交 `b2d9885` 上的同名结果不构成「已在 `6852b1c` 验证」**（`6852b1c` 上从未跑过）。
- 顺带记录：`docs/research/` 与本文件之外**无**代码改动；`sa_profile/4606.json`、检测规则、
  公共契约均未触碰。

---

## 39. 2026-10-15 `security_access_token` 3 条 + `update_updateservice` 2 条深审：五组件复核覆盖率补齐到 23/23（队友 B）

承接 §38 的下一步：把当前检测器版本下**仅剩的 5 条未逐条复核的候选**判完。报告：
`docs/research/ipc_sat_update_deep_review_2026-10-15.md`。检测器 `ohscanner.interface.ipc` **0.5.0**，
模型 `oh-ipc-2026.10-v3`。**本轮不改任何规则、不改公共契约、不做动态验证。**

### 为何要做这一步：先前写下的「23」并不都是**当前版本**的复核结论

五组件 23 条候选（wwn 14 / dsoftbus 4 / sat 3 / update 2 / kv 0）此前只有 18 条
（WWM 14 见 §37、dsoftbus 4 见方法卡 v0.13）在当前版本下逐条判过。剩下 5 条最后一次
逐条判定是在 **0.3.0** 的 41 条全查里（`docs/research/ipc_candidate_review_2026-10-11.md`：
sat 20 条全 FP、update 2 条判 FP）。**规则已经从 0.3.0 走到 0.5.0（M1/M2），
把 0.3.0 的判定直接当作 0.5.0 的判定是没有依据的**，所以这 5 条必须重判。

### 已完成：5 条逐条复核，全部 likely false positive

| 组件 | 位置 | 规则 | 被报的效果调用 | 判定 |
|---|---|---|---|---|
| security_access_token | `token_sync_manager_stub.cpp:104` | `ipc.auth.missing` | `GetRemoteHapTokenInfo` | likely false positive（M3） |
| security_access_token | `token_sync_manager_stub.cpp:121` | `ipc.auth.missing` | `DeleteRemoteHapTokenInfo` | likely false positive（M3） |
| security_access_token | `token_sync_manager_stub.cpp:136` | `ipc.auth.missing` | `UpdateRemoteHapTokenInfo` | likely false positive（M3） |
| update_updateservice | `update_service_stub.cpp:228` | `ipc.auth.guard-coverage` | `service->Upgrade`（code 5） | likely false positive（M5） |
| update_updateservice | `update_service_stub.cpp:336` | `ipc.auth.guard-coverage` | `service->FactoryReset`（code 18） | likely false positive（M5） |

判据是**三件可复核的事**，不是"本地没搜到限制"：守卫**存在**、守卫的失败分支**返回**、
守卫**支配**那条被报告的效果调用。

- **sat 3 条**：`TokenSyncManagerStub::OnRemoteRequest` 的 `switch`（`:46`）是唯一派发点；
  三个 handler 的第一条语句都是 `if (!IsRootCalling() && !IsNativeProcessCalling()) { …; return; }`
  （`:83` / `:110` / `:127`），失败分支写 `ERR_IDENTITY_CHECK_FAILED` 后返回，效果调用在函数末尾
  （`:104` / `:121` / `:136`），中间无分支可绕过。`IsRootCalling()` = `GetCallingUid() == ROOT_UID`（`:70-79`）；
  `IsNativeProcessCalling()` = 调用者 token 类型 `TOKEN_NATIVE`（`:62-68`）。描述符门（`:42`）**已被检测器正确识别**
  （候选 1 的路径轨迹含 `(42, 'descriptor != ITokenSyncManager::GetDescriptor() => False')`）——**M1 在此文件上生效**。
- **update 2 条**：`:432` 是唯一派发点，`(this->*(iter->second))(...)`；到它之前 `:409` / `:416` / `:421` / `:425`
  四个分支各自 return，无旁路。`:421` 的 `IsCallerValid()`（TOKEN_HAP 要求 `IsSystemAppByFullTokenID`；
  TOKEN_NATIVE 要求 uid 为 `ROOT_UID(0)` 或 `EDM_UID(3057)`；其余 false）与 `:425` 的 `IsPermissionGranted(code)`
  （`AccessTokenKit::VerifyAccessToken`，`UPGRADE`→`ohos.permission.UPDATE_SYSTEM`，`FACTORY_RESET`→`ohos.permission.FACTORY_RESET`）
  **两级都支配**。code 绑定经枚举核验：`updater_sa_ipc_interface_code.h:22-43` 从 `CHECK_VERSION = 1` 顺序递增，
  故 `UPGRADE = 5`（`requestFuncMap_:48`）、`FACTORY_RESET = 18`（`:63`），与检测器 `codes=5/18` 一致。

### 机制归属（两条已在检测器自己的输出里写明）

- **M3（sat 3 条）**：授权谓词是本地 helper，其布尔取值未被解析成 auth 事实。**检测器自己的 `limitations`
  就记着守卫的名字**（`security_access_token` 共 249 条，其中 16 条 `Unresolved multi-outcome helper return:`）：
  `TokenSyncManagerStub::IsRootCalling`、以及三个 `…Inner`。同时引擎侧**已有**对应能力：
  `analysis.py:530-531` 对这三个调用名有专门分支（`state.auth` 非空 **或** `caller_class` 含 `TOKEN_NATIVE`），
  `analysis.py:881-882` 能把 `GetCallingUid()` 与 `trusted_uids` 的比较建模为 auth 事实。
  所以**不是"无法建模"，而是事实没走到路径上**——`IsRootCalling` 在 `#ifndef/#else` 下有两个 `return`
  （一个布尔表达式、一个字面 `false`），helper 摘要（`analysis.py:824-834`）要求 return 一致或恰为 true/false 字面量，
  于是给 `UNKNOWN` 并记 limitation。**M3 缺陷未修复**（修复需单独提交 + 正/固定/安全对照，本轮不做）。
- **M5（update 2 条）**：**检测器没有把「有守卫」说成「无守卫」**——它 `:421`/`:425` 两个调用都看见了，
  消息里写着 `dispatcher-guard-observed`，并如实说"支配性未建立"。对**候选**是 FP（支配成立）；
  对**规则** M5 未修复，维持 10-11 报告 §5 的处置（按派发形态证明支配性，把「支配」与「存在但支配未知」分开记录，
  **不是**删掉候选）。`limitations` 侧 92 条里有 2 条 `Unresolved multi-outcome helper return:`：
  `UpdateServiceStub::IsCallerValid`、`UpdateServiceStub::IsPermissionGranted`。

### 五组件复核覆盖率（本轮之后）

| 组件 | 候选 | 复核状态 |
|---|---:|---|
| window_window_manager | 14 | 2026-10-15 已复核（6 FP / 2 外部依赖 / 6 plausible / 0 confirmed） |
| communication_dsoftbus | 4 | 2026-10-14 已复核（2 FP / 2 外部依赖） |
| security_access_token | 3 | **本轮已复核**（3 likely false positive） |
| update_updateservice | 2 | **本轮已复核**（2 likely false positive） |
| distributeddatamgr_kv_store | 0 | 无候选 |
| **合计** | **23** | **23/23 有复核记录** |

合计候选级判定：likely false positive **13**、unresolved external dependency **6**、
plausible but unproven **6**、**confirmed 0**。**五组件合计候选数仍为 23**：
本轮 0 新增、0 删除、0 合并、0 升级。`validated_vulnerability` 仍为 **0**。

> **口径提醒**：上表是**候选级**判定，不得外推成「这两个组件是安全的」。`completed` 不是 safe、
> 空 findings 不是安全证明，本轮只覆盖被报告的那 5 条路径；sat 那道门的**策略是否充分**
> （native 进程粒度）本仓库内无可判定证据，**未判**。

### 本轮顺带查出的一条负结果（保留，不删）：`IPCSkeleton::IsLocalCalling()` 不是"同进程"判据

调查中我先把 sat `:37` 的 `if (!IPCSkeleton::IsLocalCalling())` 读成"跨进程调用一律拒绝"，
并准备据此写"远端调用者到不了这三个事务"。**按 pinned 源码更正**：
`ipc_skeleton.cpp:258-265` 转发给 invoker；`binder_invoker.cpp:1714-1717` 恒 `return true`；
`dbinder_databus_invoker.cpp:802-805` 恒 `return false`（`communication_ipc @ bbb92dbb`）。
即该函数真实语义是**"不是 dbinder/databus 跨设备调用"**，binder 路径上**恒为 true**，`const` 不构成门。
写出这条是因为该误读会**放大**结论（把一个没有源码支撑的更强断言写进报告）。
**记录为负结果并保留。**

### 未验证 / unknown（本节的诚实边界）

- sat 3 条：授权门**存在且支配**已证；但"native 进程"作为授权粒度的**策略充分性**未判——需策略评审，
  本仓库内无证据。以下两点记为**观察**、不写成 finding：① `IsNativeProcessCalling()` 只比对 token **类型**
  为 `TOKEN_NATIVE`，不比对**是哪一个** native 进程；② `ATM_BUILD_VARIANT_USER_ENABLE` 构建下
  `IsRootCalling()` 恒 `false`（`:76-78`），两种构建下都有检查，通过的集合不同。
- update 2 条：支配性已按源码证明，但**派发形态的支配性证明尚未成为规则**（M5），
  同类形态在别的组件上仍会照旧产出候选。
- 5 条全部 `evidence_type = syntax`；可达性、攻击者控制、具体影响三格均未填。
- **M3 的成因在本节只记录"limitations 里有这几条 / 引擎有那个分支 / `:881` 能建模 trusted-uid"这三件已验证事实**，
  不把"每条 limitation 的内部成因"当结论（例如 `IsPermissionGranted` 表面只有一个 `return` 却也被列入）。
- 独立 holdout 仍不存在（`research/corpus/interface/ipc/verified_pairs.jsonl` 12 条全 `split=design`，S3 = 0），
  **Precision/Recall 仍不可宣称**；本报告的 5 条**不折算**进任何精度指标。

### 固定版本与读取纪律

| 组件 | commit | 文件 | blob oid | sha256 |
|---|---|---|---|---|
| security_access_token | `17d88bfb36bea6c9370ba919ac41a22d16dd66b3` | `services/tokensyncmanager/src/service/token_sync_manager_stub.cpp` | `6b32d5dcc0e0b98c858a374d95640deb06ec94b0` | `c775adcc…636ae1` |
| update_updateservice | `e4942a33cc5ed29040e5c720bea3b2a8e4a79221` | `services/engine/src/update_service_stub.cpp` | `51ab923c63520965b13c95cab7c1674d799c93e9` | `9f0076ef…65768` |

两个 commit 与 `outputs/reports/*.manifest.json` 记录一致；两个 perf-corpus 克隆 `HEAD` 等于该 commit
且工作树干净。**本次全部内容从 `git show <commit>:<path>` 读出，未把工作树当证据**（v0.13 读法规则）；
行号一律是 pinned blob 行号。

### 本轮检查（命令 / 结果 / HEAD）

- 证据读取：`git -C ~/openharmony-audit/perf-corpus/{security_access_token,update_updateservice,communication_ipc} show <commit>:<path>`；
  脚本 `/home/audit/wtmp/w52.sh … w64.sh`（仓库之外，不入库）。
- 候选与 limitations 来源：`research/experiments/interface/ipc/measure_consequences.py`
  → `outputs/reports/consequence_dimension_v050.json`（10 组件 / 5,270 文件 / **72** 条 /
  `findings_without_a_consequence = 0` / `validated_vulnerability = 0`；产物 gitignored，未入库）。
  其中 `security_access_token` 3 条、`update_updateservice` 2 条、`window_window_manager` 14 条，
  与五组件集逐条一致。
- `git diff --check` → 干净。本轮改动**只有 Markdown**（本文件 + 新增 `docs/research/` 报告），
  不进入 Python 测试输入；检测规则、公共契约、`catalog.py`、Draft PR 均未触碰。
- 回归：`.venv/bin/python -m unittest discover -s tests` → **Ran 454 tests in 48.461s … OK**，
  HEAD 为 **`61cb12b`**（本轮 Markdown 改动尚未提交；本轮改动只有 Markdown，不进入 Python 测试输入）。
  **不把该结果写成「已在本轮提交上验证」**——提交哈希在提交后才存在，本轮提交的准确 HEAD 用
  `git rev-parse HEAD` 或推送后的远端核对。

## 40. 2026-10-15 打通 AUTH-01 修复重验闭环（自撰补丁）+ PoC 载体 spike 判定（队友 B）

**为什么做**：`AGENTS.md` 的证据门把 `reportable` 钉在三个条件上——六字段齐全、`poc_state == stable_reproduced`、
**`patch_revalidation == passed`**。前两项在 2026-10-10 已有（AUTH-01 `inputmethod_imf` / `cve-2023-0036`
端到端触发，3/3），第三项一直是「靠上游恰好有修复」间接说明，**本项目自己既没给出补丁、也没验证过补丁**。
本轮把它补上，顺带用一个小预算 spike 判定新 PoC 载体是否值得做。

### 一、载体 spike 判定（判负/半负，负结果保留）

方法照抄已跑通的 AUTH-01 harness（真实 TU + 真实头文件 + `commonlibrary_c_utils` 真实 `Parcel` +
最小 `poc_compat`），对每个探针跑自动 include 闭包发现。**预算 ≤20 轮，实耗 A 2 轮 / B 约 10 轮。**

| 探针 | 载体 | 判定 | 依据 |
|---|---|---|---|
| A | `window_window_manager` `screen_session_manager_stub.cpp`（CAP-01，2,088 行） | **本地不可行** | 第 2 层缺 `ui/rs_display_node.h`（`graphic_2d`），本机全树无该组件 |
| B | `communication_dsoftbus` `bus_center_ex_obj_stub.cpp`（AUTH-01，67 行） | **可编译，但不可用于闭环** | 8 个 `-I` + 一个补 `#include <mutex>`/`HILOG_IMPL` 的 compat shim 后 `clang++ -c` 退出码 0，产出 20,440 字节 `.o`，`BusCenterExObjStub::OnRemoteRequest` 为已定义符号 |

**探针 B 编得过不等于能当载体。** 这条候选在 §37 之前的 `ipc_dsoftbus_deep_review_2026-10-14` 里
**已经判过**，结论 `external gap / plausible but unproven`：真正的派发在 `libdsoftbus_server_plugin.z.so`，
本仓库无实现、无构建目标；给它建 PoC 只能观测到「桩不比对描述符就转交」这件**静态上早已确认**的事，
impact 一格填不了，还会踩「把非漏洞包装成交付件」的风险。
**⇒ 计划里「谁编过谁当载体」这条规则的前提不成立，本次不按它执行；载体切换为「闭已有 AUTH-01 的环」。**

### 二、自撰补丁 + 修复重验（本轮主要产出，全在 B 线自有面）

新增 `harnesses/auth01_descriptor_bypass/fix.diff`（18 行，`patch -p1` 可应用），
**从 guard/effect 关系推导**：效应是 `notifyEvent()` 走到 `MessageHandler::SendMessage()`，只能从 `switch`
的 `NOTIFY_EVENT` 分支到达；漏洞版在这条路径上**唯一前置条件**是 `code == NOTIFY_EVENT`，
「事务属于本接口」**整体缺席**而非被旁路。补丁在 `switch` 之前读接口 token、不等于 `GetDescriptor()`
即返回 `ERROR_STATUS_UNKNOWN_TRANSACTION`。**位置必须在最前**是正确性要求而非风格：
`ReadInterfaceToken()` 消费 parcel 字节，任何错位都会解析错误。上游 `5eaddcab` 在同一位置加了等价守卫，
本补丁**独立推导、独立验证**，该事实写在 manifest 的 `rationale` 里，不装作与上游无关。

| 项 | 值 |
|---|---|
| 补丁 id | `auth01-descriptor-guard-v1`，作用于 `vulnerable` |
| 应用 / 重新编译 | 成功 / 成功（`clang++`，ASan+UBSan，`returncode = 0`） |
| 补丁后源码 sha256 | `7b7660ab9973e27fa5a104b76f7c713aa95a210cf504d507d7a6c2778389dba9` |
| 状态 | **`passed`** |

| 用例 | 角色 | 打补丁后观测 | 判定 | 符合 fixed 预期 |
|---|---|---|---|---|
| `no_token` | attack | `messages_sent=0 ret=-74` | `no_trigger` | 是 |
| `foreign_token` | attack | `messages_sent=0 ret=-74` | `no_trigger` | 是 |
| `correct_token` | 正对照 | `messages_sent=1 msgId=5 userId=4242` | `trigger` | 是 |

**判据**（`runner.py:patch_revalidation_state`，纯逻辑 + 5 个单测）：`passed` 要求补丁应用成功、
重新编译成功、**每个**用例符合 `fixed` 修订预期。正对照在比对集里，所以**「一律拒绝」不会被误当成修复**；
其余状态命名为 `not_applied` / `build_failed` / `run_failed` / `failed`，不与 `passed` 混淆。

**改了哪些文件**（全在 `src/ohscanner/poc/`）：新增 `fix.diff`、`PatchRevalidation`、`apply_patch`、
`patch_revalidation_state`、`_revalidate_patch`；从 `build_revision` 拆出可复用的 `build_translation_unit`
（**旧签名保持兼容**）；`manifest.json` 增 `patch` 块；报告渲染增第 3 节。
**未触碰**检测规则、`models.py` 词表、公共契约、`catalog.py`、`src/case`、`src/benchmark`、`src/report`
（owner 共享面）、A 线代码、Draft PR。

### 三、这一步在证据门里的位置

`patch_revalidation` 从「无」变成「`passed`」，且是**本项目产出**的补丁。
**没有跟着变的**：`validated_vulnerability` 仍为 **0**；可达性仍 **`partial`**；
无特权/无关进程能否拿到句柄、对端身份与权限、对端是否转出句柄，**均未证明**。
**不因为有了补丁闭环就上调任何判定。**

### 四、未验证 / unknown（本节的诚实边界）

- 修复闭环证明的是「守卫有效」，**不是**「攻击者到得了这里」——可达性义务原样保留。
- **影响范围未做**：未跨 tag/分支扫描。（数据源已确认可用：`ipc-research/repos/inputmethod_imf`
  6,231 提交 / 57 tag / 19 条发布分支；`e663b470` 可达 `origin/OpenHarmony-3.0-LTS` 与 v3.0.5–v3.0.8，
  `5eaddcab` 可达同分支与 v3.0.6–v3.0.8。）
- **报告渲染未做**：`src/report/vulnerability_report.py` 在 B 仓库不存在，属 owner 共享面，移植需批准。
- **性能数据未做**：B 的 audit manifest 只记文件数与字节数，无墙钟/峰值 RSS。
- **数据一致性未核**（2026-10-10 已记，本轮仍未解）：`ipc-research/pairs/cve-2023-0036/lineage.json`
  标 `verification_level: S1`，`research/corpus/interface/ipc/verified_pairs.jsonl` 标
  `S2 / patch_root_cause_review`，两处不一致，需队伍核对哪一份准。
- spike 只证明了「本机缺 `graphic_2d` 时 A 编不过」「B 能编成 `.o`」，**不是**「A 永远不可行」「B 可提升」。

### 五、本轮检查（命令 / 结果 / HEAD）

- 证据读取：`git -C ~/openharmony-audit/ipc-research/repos/inputmethod_imf show <commit>:<path>`；
  spike 脚本 `/home/audit/wtmp/w78.sh … w83.sh`（仓库之外，不入库）。
- 端到端：`.venv/bin/python research/experiments/interface/poc/run_poc.py --json outputs/reports/poc_auth01_descriptor_bypass.json --md outputs/reports/poc_auth01_descriptor_bypass.md`
  → `patch_state = passed`（产物 gitignored，未入库）。
- `git diff --check` → 干净。
- 回归：`.venv/bin/python -m unittest discover -s tests` → **Ran 463 tests in 55.093s … OK**
  （此前基线 454；本轮 +9：状态机纯逻辑 5、manifest 形状 3、真编译集成 1）。
  集成用例已改为**类级共享一次运行**，避免每个用例重编三个修订——改前 79s、改后 24s。
- 归位：本节改动提交为 **`9f968c5`**（`feat(poc): close the AUTH-01 fix loop with a
  project-authored patch`），已推送到 `origin/feat/interface-ipc-detector`（`a646c59..9f968c5`）。
  上面那次 463 测试跑在提交之前；提交后未重跑全量（§41 会补跑并记录）。

## 41. 2026-10-15 AUTH-01 影响范围：`inputmethod_imf` 397 条 ref 逐条判定（队友 B）

交付件 **#4 影响范围**。新增工具
`research/experiments/interface/ipc/version_impact.py`（由 A 线
`shared_ptr_race_version_impact.py` **参数化移植**），新增单测 `tests/test_version_impact.py`
（19 项），记录写入 `docs/research/ipc_auth01_version_impact_2026-10-15.md`。
**`validated_vulnerability` 仍为 0**，本轮不提升任何候选。

### 一、结果（全量克隆，57 tag + 340 `origin` 分支 = 397 ref）

| 状态 | 条数 | tag / 分支 | 含义 |
|---|---|---|---|
| `affected` | **17** | 6 / 11 | 文件 blob **精确等于**漏洞版 `e90a4e77…` |
| `fixed` | **1** | 1 / 0 | 精确等于修复版 `0f9ed2f6…` |
| `not_present` | 317 | 36 / 281 | 该 ref 上**没有这个路径** |
| `unknown` | 62 | 14 / 48 | 有该路径，但两边界都不等（**非答案**） |

- `affected` 的 6 个 tag：`v3.0-LTS`、`v3.0.1-LTS`、`v3.0.2-LTS`、`v3.0.3-LTS`、`v3.0.5-LTS`、
  `v3.1-Beta`；11 条分支含 `OpenHarmony-3.1-Beta` 与 9 条 `weekly_2022xxxx`。
- `fixed` 唯一一条是 **`v3.0.6-LTS`**。这**不是**「唯一修好的版本」，只是「唯一与修复提交
  逐字节一致的 ref」；该线上更晚的 ref 因文件又被改动而落进 `unknown`。
- 记录摘要 `manifest_sha256 = 91f8b454b29944034c116d5138ece913d30f8e2110bb41a0faa042fe58991ea8`。

### 二、一条自洽性检验（本轮最有价值的单点）

17 条 `affected` 中 `fixed_commit_reachable` **全为 False（0/17）**：
不存在「已包含修复、却仍带着漏洞版文件」的 ref。这条检验把「判定是 blob 身份」
与「判定是版本区间推断」两种做法区分开了——后者给不出这条可证伪的断言。

### 三、`unknown` 的两种成因必须分开（62 条只涉及 6 个 blob）

1. **修复之后文件又被改动（3 条）**：`v3.0.7-LTS`、`v3.0.8-LTS`、`origin/OpenHarmony-3.0-LTS`
   （blob `022e5d44f76f`，`fixed_commit_reachable = True`）。含义只到「修复后又被改过」。
2. **从未拿到修复提交的两条线（59 条）**：3.1 线（`352b006d2405` / `7d45b1f09d98`）与
   3.2-Beta 线（`f34e8ff7d7a9` / `866c0b6a5825`）。**这是真实的研究线索**
   （look-alike variant），但本轮**未读内容**，因此既不算 `affected` 也不算 `fixed`。

### 四、`not_present` 不是缺数据

`services/` 目录在 3.2 之后被重构掉（`origin/OpenHarmony-3.2-Release` 顶层已是
`common/ frameworks/ interfaces/`），故 3.2+ 判 `not_present`。含义是「**这个路径**不存在」，
**不等于**「该版本没有这个接口」。

### 五、移植时修掉 A 线脚本的一处真实缺陷

A 线 `build_version_impact` 调 `classify_refs(repo, refs)` 时**没传 `source_path`**，
于是无论调用者指定哪个文件都按模块常量 `base/include/singleton.h` 判定。
本移植把 `source_path` 贯穿到 `_ref_blob` 与每条记录，并写了回归用例。
另把两个边界 blob 由常量改为**从 `--vulnerable-commit` / `--fixed-commit` 现场派生**，
推导不出**直接报错**而非猜；不传 `--fixed-commit` 时 `fixed` 在构造上不可达。

### 六、未验证 / unknown（本节的诚实边界）

- **`unknown` 不是安全**：62 条里 59 条的内容未读，不能声称已修复或受影响。
- **blob 身份不是可达性**：带漏洞版文件 ≠ 该 SA 可被非特权调用者触达；可达性仍 `partial`。
- **未扫 manifest XML**：没有把 ref 映射到产品版本；`product_manifest.py` 本地可用性未核
  （属 owner 共享面）。
- **未覆盖 `refs/heads/*` 本地分支**；ref 集 = tag + `refs/remotes/origin/*`。
- **内容摘要只有 56/397 条可取**：克隆是 `blob:none` **偏克隆**，
  `_git` 禁止惰性抓取，缺失 blob 的摘要留空（判定只用 blob OID，不受影响）。
  17 条 `affected` 的摘要 17/17 全部取到。
- 数据一致性仍未核（§40 已记）：`lineage.json` 标 S1 vs `verified_pairs.jsonl` 标 S2。

### 七、本节检查（命令 / 结果）

- 工具：`.venv/bin/python research/experiments/interface/ipc/version_impact.py --repo-root
  ~/openharmony-audit/ipc-research/repos/inputmethod_imf --repository openharmony/inputmethod_imf
  --kind ipc_auth01_version_impact --source-path services/src/platform_callback_stub.cpp
  --vulnerable-commit e663b470… --fixed-commit 5eaddcab… --tags --branches --json-out
  outputs/reports/version_impact_auth01_inputmethod_imf.json`
  → 397 ref，12.8 s，产物 161 KB（gitignored，**不入库**）。
- 单测：`.venv/bin/python -m unittest tests.test_version_impact` → **Ran 19 tests … OK**
  （含真仓库边界回归：两个边界提交必须分别判成 `affected` / `fixed`）。
- 克隆性质核实：`git config --get remote.origin.partialclonefilter` → `blob:none`；
  `rev-parse --is-shallow-repository` → `false`。

## 42. 2026-10-15 接口线组件审计的性能与规模实测（队友 B）

交付件 **#7 性能数据**。记录写入 `docs/testing/interface_audit_performance_2026-10-15.md`。
**`validated_vulnerability` 仍为 0**：这是成本测量，不是检出能力评测。

### 一、改动（全在 B 线自有面）

`src/ohscanner/detectors/interface/audit.py` 新增 `peak_rss_kb()` 与 `_rate()`；报告新增
`peak_rss_kb`；**manifest 新增 `performance` 块**（墙钟、峰值 RSS、files/s、bytes/s、口径说明）；
渲染首部与 CLI 输出新增成本行；`limitations` 新增一条写明墙钟/RSS 的口径。
`tests/test_component_audit.py` +3 用例。

**改动前的事实**：B 的 audit manifest **只记文件数与字节数，没有任何时间或内存字段**——
产物的规模可以被引用，而它的成本无处可查。现在两者写在同一个文档里。

### 二、实测（5 个真实组件，每个组件一个独立进程）

| 组件 | 固定提交 | 文件 | 源码字节 | 完整/部分 | 候选 | 墙钟 (s) | 峰值 RSS (MB) | files/s | MB/s |
|---|---|---:|---:|---|---:|---:|---:|---:|---:|
| `communication_ipc` | `bbb92dbb2f52` | 252 | 2,189,480 | 154/97 | 12 | 8.74 | 226.4 | 28.8 | 0.25 |
| `inputmethod_imf` | `7777cba9eb19` | 412 | 3,191,273 | 330/72 | 4 | 10.72 | 312.2 | 38.4 | 0.30 |
| `security_access_token` | `17d88bfb36be` | 550 | 3,484,891 | 489/56 | 3 | 16.05 | 307.0 | 34.3 | 0.22 |
| `update_updateservice` | `e4942a33cc5e` | 219 | 851,345 | 187/31 | 2 | 3.42 | 88.3 | 64.0 | 0.25 |
| `window_window_manager` | `8b0d8fe1b973` | 1112 | 20,206,691 | 811/268 | 14 | 98.46 | 1886.4 | 11.3 | 0.21 |

合计 **2,545 文件 / 29,923,680 字节 / 137.39 s**，单组件峰值最高 **1,886 MB**。
五个组件 `file accounting closed` 全 `True`（`files_unaccounted = 0`），
`confirmed_vulnerabilities` 全 0，候选合计 35 条（皆为未验证候选）；
`window_window_manager` 的 14 条与 2026-10-15 的逐条复核报告一致。

### 三、从数字里读出的三条事实

1. **吞吐是字节受限的**：files/s 区间 11.3–64.0（跨 5.7 倍），而 MB/s 稳定在 0.21–0.30。
   两个解析器都逐文件建 AST，决定成本的是源码字节。用 files/s 比较组件会得出错误结论，
   所以报告里两个都给，不让前者被单独引用。
2. **内存约为源码字节的 100 倍**：108× / 103× / 92× / 109× / 98×，稳定得反常（±10%），
   说明内存跟着源码总量走，而不是跟着候选数或组件类型走。
3. **`window_window_manager` 是当前的规模边界**：20.2 MB / 1,112 文件，单次单进程
   98.46 s、1,886 MB，且**在一个分片内跑完**（未触发 2000 文件 / 32 MiB 上限）——
   这 1.9 GB 是单次整树解析本身的占用，不是分片开销。

### 四、未验证 / unknown（本节的诚实边界）

- **不是检出能力评测**：候选数与 `confirmed_vulnerabilities: 0` 与任何耗时数字无关。
- **不是上界**：均为单次测量（未取中位数/最坏值），未测并行、增量缓存、硬超时或资源隔离。
- **未测整树规模**：最大被测组件 20.2 MB 源码；千万行整树未测，且分片上限使整树必须分片，
  分片成本未量化。
- **内存口径**：`ru_maxrss` 是进程高水位；同一进程内跑多个组件时它是运行最大值。
  本记录 5 个数字来自 5 次独立进程调用，**不能**用来解释「一个进程跑完 5 个组件」的内存。
- **与主线示例检测器实测不可相减**：主线 2026-10-10 在同一批克隆上测得 `wwm` 41.13 s /
  265.7 MB / 1,944 文件、`inputmethod_imf` 6.34 s / 101.3 MB / 698 文件，
  但那是**另一个检测器**且**文件选择口径不同**（主线按顶层目录分片，接口线按规则只取生产文件）。
  分母不同，不能说「接口线慢多少倍」。

### 五、本节检查（命令 / 结果）

- 单测：`.venv/bin/python -m unittest tests.test_component_audit` → **Ran 49 tests … OK**。
- 实测：5 个组件各一次
  `.venv/bin/python -m src.ohscanner.detectors.interface.audit --repo-dir perf-corpus/<c>
  --repository openharmony/<c> --commit <sha> --out-dir outputs/reports/interface_perf`。
- 产物 `outputs/reports/interface_perf/`（5 组件 × JSON/MD/manifest 三件 = 15 个文件）**不入库**；
  本文表格由其中的 JSON 直接渲染，未手抄。
- **该目录其实不被 `.gitignore` 覆盖**（第 226–227 行的 `outputs/reports/*.json` / `*.md` 不跨 `/`，
  只匹配顶层）；`git check-ignore` 对 15 个文件全部返回「未忽略」。它们只是**未跟踪**，
  不提交靠的是 `git add` 时的手工选择，不是规则兜底。

## 43. 2026-10-15 交付件 #6（报告渲染）的移植申请已提交，等 owner 决定

**状态：B 未动共享面任何一行。** 申请书写在
`docs/research/owner_request_vulnerability_report_port_2026-10-15.md`。

- **为何要批**：`src/report/`、`src/case/` 属 owner 共享面；而路径 `src/report/vulnerability_report.py`
  是 `AGENTS.md` 的 Competition deliverables **逐字点名**的交付要求，B 仓库里该文件**不存在**
  （`src/report/` 只有 `benchmark_report.py`，`src/case/` 只有 `assembler.py`）。
- **待移植对象已核实**：A 线该文件 249 行 / 9,514 字节，**只 import 标准库**（argparse/json/pathlib/typing），
  **零项目依赖** → 不会在 owner 的共享桥上新增耦合面。
- **必须改的一处已查实**：第 56–57 行硬断言 `root_cwe == "CWE-362" and consequence_cwe == "CWE-416"`，
  是 A 线竞态/UAF 家族专用。**AUTH-01 是 `CWE-441`，在该行会直接 raise** —— 不放开则渲染器对非 A 家族不可用。
- **适配层必要性的依据**：`src/core/case.py:VulnerabilityCase` 缺渲染器要的 8 个键
  （`consequence_cwe`、`evidence_gate`、`entry_point`、`attacker_control`、`impact`、
  `performance`、`patch_summary`、`why_it_fixes`）。B 用新增的
  `src/case/vulnerability_case_view.py` 做投影，**不改 owner 的 dataclass**。
- **诚实预期（申请里已写明）**：用 AUTH-01 现有证据跑，六门字段只有
  `target_bound` 与 `dynamic_reproduced` 为 True；`entry_controlled` 为 False 的直接依据是
  harness manifest 的 `reachability.status = "partial"` 与「whether an unprivileged process can
  obtain the handle ... **is NOT established here**」。故渲染状态是
  **`dynamic_reproduced_component_issue`，不是 `reportable`** —— 批准移植**不等于**把未定候选
  包装成已确认漏洞。
- **计划第 2 步（`patch_revalidation` 提到共享 PoC 层）已随 `9f968c5` 落地**，无需再申请：
  它现于 `src/ohscanner/poc/records.py` 的 `PatchRevalidation` / `patch_state` 与
  `runner.py` 的 `patch_revalidation_state()`，且 `src/ohscanner/poc/` 属 B 自有面。

## 44. 2026-10-16 AUTH-01：62 条 `unknown` ref 追查（38 结案 / 24 仍未知）（**剩下的 24 条当日已结案，见 §50；其中「逐字节相同」的表述已更正，见 §52**）

记录写入 `docs/research/ipc_auth01_unknown_refs_triage_2026-10-16.md`。
这是交付件 #4 遗留问题的收尾：**`version_impact.py` 一字未改**，改的是对那 62 条的解释。

- **方法**：全离线。所有 git 调用经 `src/ohscanner/git_source.py:_git`（promisor / lazy fetch /
  全部 transport 关闭），本次**没有任何 fetch**，也**没有**在共享研究克隆上做写操作。
  代价是 6 个 blob 里只有 1 个本地有内容 —— 如实记录，不假装读到了。
- **fixture 自检**：manifest 钉住的 vulnerable / fixed 两份源码 sha256 现场重算 **双双 MATCH**
  （vulnerable 103 行、fixed 108 行），确保后续比对是在正确对象上做的。
- **结果一**：`vulnerable → fixed` 的差异**只有 4 行**，就是描述符校验
  （`ReadInterfaceToken()` → 比对 `GetDescriptor()` → 否则 `ERROR_STATUS_UNKNOWN_TRANSACTION`）。
  即缺陷是**这个前置根本没写**，与 harness manifest 的 `defect`/`fix` 及 B 自撰补丁的 guard 论证一致。
- **结果二（结案 38 条）**：`fixed` 与 3.2 线 blob `f34e8ff7d7a9` 的差异**只有 4 行改动，
  且全在文件末尾的两个 namespace 注释**（`} // namespace MiscServices` / `// namespace OHOS`）。
  即这 38 个 ref 上的文件与修复版**内容等价、但并非同一 blob**（3639 B vs 3595 B；见 §52），第 34–43 行的校验在位
  → **不携带 AUTH-01 缺陷**。构成：3 tag + 3 Beta 分支 + 26 weekly + 3 monthly
  + 2 `filemanager_develop` + 1 `feature_IDL`（由 #4 产物统计，非估算）。
- **结果三（仍未知 24 条）**：`022e5d44f76f`(3)、`352b006d2405`(7)、`7d45b1f09d98`(4)、
  `866c0b6a5825`(7)、`14a849f73d0e`(3) —— 内容不在离线对象库，**维持 `unknown`**。
- **必须一起记的禁令**：后四个 blob 的 `fixed_commit_reachable = False` **不能读成「没有修」**。
  反例就在本次结果里：3.2 线带着校验，而修复提交本来就不在它的祖先链上。
  「修复提交不可达」既不是漏洞证据也不是安全证据。
- **未改四态**：`affected / fixed / not_present / unknown` 里没有「内容不同但前置在位」这一格，
  而本次那 38 条的最终判定**仍写 `unknown`**（判 `fixed` 会篡改判定语义、判 `affected` 是误报），
  只是把解释从「未读」升级为「已读且不含缺陷」。是否加第五态属 owner 的契约决定，B 未动。
- **顺带查实**：`ipc-research/repos/inputmethod_imf` 的 HEAD（`7777cba9eb19`，master）上
  `services/src/platform_callback_stub.cpp` **已不存在**（`rev-parse HEAD:<path>` 直接报不存在，
  `services/src/` 已换成 20 个完全不同的文件）。最新 ref 不在 `affected` 里**不是被修掉，
  是文件被重构掉了**。
- **本节检查**：全部命令在文档 §8 可复现；`git diff --cached --name-only` 自检共享面零命中。

## 45. 本日尚未闭环的事项（B 视角）

- 交付件 **#6 报告渲染**：等 owner 对 §43 申请的答复，B 未动共享面。
- **24 条 `unknown` ref**：要读内容必须显式取 blob（github 不通、gitcode 通）。
  在共享研究克隆上做显式 fetch 会改动别的会话依赖的对象库 → 由 owner 决定，B 不单方面做。
  **（本条已作废，见 §49：那 5 个 blob 已在 `~/openharmony-targets/inputmethod_imf` 盘上，无需取数。）**
- **S1 vs S2 数据不一致**（2026-10-10 起未解）：`ipc-research/pairs/cve-2023-0036/lineage.json`
  标 `verification_level: S1`，而 `research/corpus/interface/ipc/verified_pairs.jsonl` 标
  `S2 / patch_root_cause_review` —— 需队伍核对哪一份为准，B 不擅自改任一份。

## 46. 2026-10-16 CAP-01：版本影响扫描 + guard 链按原文读实（**一处事实错误当日已更正，见 §49**）

记录写入 `docs/research/ipc_cap01_guard_chain_2026-10-16.md`。
交付件 #4 的工具 `version_impact.py` **一字未改**，只是参数化后用到第二个候选上。
**CAP-01 状态仍是 `candidate`** —— 本节没有把它升级成已确认漏洞，理由见下。

- **影响范围**：`openharmony/window_window_manager` @ `8b0d8fe1b973`，
  **431 ref**（46 tag + 385 origin 分支）→ `affected 2 / fixed 0 / not_present 255 / unknown 174`，
  4.6 s，产物 `outputs/reports/version_impact_cap01_window_window_manager.json`
  （未跟踪、不入库），`manifest_sha256 = bfdf0a53d28353d61bf33592a88e1e27f244232ce5dde102506c4c8d43cb182f`。
- **`affected` 恰为两条**：`origin/master`（`8b0d8fe1b973`，2026-10-08）与
  `origin/weekly_20261005`（`2743766e03d0`，2026-09-30），两者 blob 均为
  `26df3196683976a9f175292fcbf54efef262eaa0`（sha256 `404969d1…de2ab`）。
- **`fixed = 0` 是如实留空**：本次不传 `--fixed-commit`，而工具的既有设计是「无 fixed blob
  则 `fixed` 永不可达」。不是「查了发现没有修复」，是这一格在该工具语义下取不到。
- **「克隆范围内不存在修复」是被验证的**：9 个 `unknown` tag 的 `%(committerdate)` 为空，
  用 `%(*committerdate)` 取 peeled 提交日期补齐后，最新的 `v7.0-Release` 为 2026-08-20；
  174 条 `unknown` 里最晚的 ref 是 `origin/OpenHarmony-6.1-LTS` 2026-09-29 ——
  **全部早于 master 2026-10-08**。即在该克隆的全部 ref 上，这个文件的最新状态就是脆弱状态。
- **guard 链三帧，全部有原文**（blob 与行号见文档 §3）：
  ① `screen_session_manager_stub.cpp:1775-1780` 事务臂内**无权限判断**，直调 `GetRenderSession`；
  ② `screen_session_manager.cpp:3200-3208` 定义体**只有 null 检查**，四个权限串一个都没有；
  ③ `screen_session.cpp:1006-1009` 是 `return renderSession_;` 纯 getter。
  （**行号差一，已更正为 `1007-1010`** —— 见 §49 末条；blob `2442c62f00c2` 复核过。）
  → `reply.WriteRemoteObject(renderSession)` 把内部对象交回给发起方，**全路径不问「谁在调」**。
- **同组件对照（本节最有力的证据）**：同一 impl 文件里 `SetScreenSkipProtectedWindow`
  （16347）与 `GetIsRealScreen`（16395）**都会**用 `SessionPermission::IsSystemCalling()` 拦截；
  该文件共 **132 处** 权限检查。不是「某个文件忘了写」，是「同一个类里 132 处都写了，
  唯独这条返回远程对象的路径没写」。
- **两处早先说法被更正**（写进文档 §5）：
  ①**CAP-01 不是描述符绕过** —— stub 第 50 行确实校验 `ReadInterfaceToken() != GetDescriptor()`，
  它在位的；CAP-01 与 AUTH-01 同属 SA relay 家族但机制不同（AUTH-01 是描述符校验完全缺失），
  两者在报告里必须分开写，否则会把 AUTH-01 的修复建议错套过来。
  ②「同模块 40+ 处 `IsSystemCalling`」数字不准：impl 里 **132 处**，
  而 **stub 文件里只有 1 处**（第 2028 行）—— 原说法容易让人以为 stub 里到处都有。
- **同时更正了本段我自己写错的三处数字**（先写文档、后回查产物发现，已改）：
  `not_present` 的 weekly 是 **137** 条、区间 2021-12-31 … **2024-09-10**（我原写「到 2024-09-10」
  但把总数写成 137 weekly 而全量区间是到 2025-09-02）；`unknown` 覆盖 **89** 个不同 blob（原写法正确）；
  9 个 `unknown` tag 的日期表逐条与产物吻合。另补一条**新交代**：255 条 `not_present` 里有
  **22 条晚于 2024-09-15**，它们是从模块创建之前的提交点分出去的分支，**不能**读成「上游删了文件」。
- **为什么仍是 `candidate`**（逐门见文档 §6）：`target_bound` 为真；`dynamic_reproduced` 为假
  （无 PoC）；**`entry_controlled` 未建立** —— 描述符校验不等于权限校验，
  「哪类调用者在什么权限下能发这个事务」拿不出证据，而
  ~~`sa_profile/4607.json`（`bb2aec03568e`）等 3 个 blob **不在本地**，离线核不到权限声明。~~
  **（错，见 §49：3 个 blob 都在 `perf-corpus/window_window_manager` 里，已读到；
  三份声明的共同点正是「没有任何权限字段」。）**
  `reachable_sensitive_operation` / `exploitation_conditions` 只到「半」，
  `security_impact` 未建立（拿到一个远程对象 ≠ 拿到某个能力）。
  → 与 AUTH-01 共享同一瓶颈：**不得**把「存在 `OnRemoteRequest` 分支」等同于「任意应用可达」。
- **CWE 出处坐实**：家族 `CAP-01` → `CWE-926`（`src/ohscanner/detectors/interface/detector.py:7`
  的 `_CWE`）；后果 `capability_exposure` → `CWE-668`（`src/ohscanner/detectors/interface/models.py:57`）。
- **本节检查**：全部命令在文档 §8 可复现；分析脚本在 `/home/audit/wtmp/`、产物在 `outputs/`，
  **均不入库**；`git diff --cached --name-only` 自检共享面（`src/report|src/case|src/evidence|src/benchmark`）
  零命中。

## 47. 2026-10-16 AUTH-01：`entry_controlled` 的证据清单（**本节结论当日已更正，见 §48**）

> **更正提示**：本节写于发现 `openharmony-targets/inputmethod_imf` 之前，其中
> 「34 个 blob，本地 0 个」与据此提出的取数申请**是错的**（只对 `ipc-research` 那份偏克隆成立）。
> 本节原文保留以便追溯；准确结论见 **§48**。

记录写入 `docs/research/ipc_auth01_entry_controlled_evidence_2026-10-16.md`。
起因是先把 `reportable` 的三个条件逐条对账，发现**只剩证据门**在挡：

| `reportable` 条件 | 现状 |
|---|---|
| `poc_state == "stable_reproduced"` | **已满足**（replay 3/3） |
| `patch_revalidation == "passed"` | **已满足**（`auth01-descriptor-guard-v1`，三例全对含正向对照） |
| 六个门字段全为 True | 不满足（只有 `target_bound` + `dynamic_reproduced`） |

→ 瓶颈是 `entry_controlled`。本节就是把这一格「到底缺什么」查实。

- **可达路径的第一个事实**：`services/src/platform.cpp:22` 的
  `Platform::SetPlatform(const sptr<IPlatformApi>& platformApi)` 是**外部注入**——
  `Platform` 不自己找 `IPlatformApi`，`:26` 把 `PlatformCallbackStub` 的句柄
  经 `registerCallback(cb)` **交给注入方**。所以「谁持有回调句柄」= 「谁调 `SetPlatform`」。
  `IPlatformApi` 的 proxy 在本仓库（`platform_api_proxy.cpp:42`），stub 实现不在。
- **可读性切分（必须说清，否则会误报）**：该提交 95 个文件、源码 74 个 →
  **可读 43 / 不可读 31**。在可读的 43 个里，`SetPlatform`/`registerCallback`
  合计只有 5 行（声明、定义、调用、纯虚、proxy），**没有调用方**。
  **但只能说「可读子集里没有调用方」，不能说「本仓库没有调用方」** —— 31 个读不到。
- **那 31 个不可读文件分布不是随机的**：`frameworks/inputmethod_controller/**` 13 个
  （**app 侧入口层**）+ `frameworks/inputmethod_ability/**` 14 个（注入 `IPlatformApi` 的一侧）
  + `unitest/**` 2 + `js_input_method_engine.cpp` 1。**要回答这一层的那层，恰好是偏克隆没有的那层。**
- **SA 暴露面也读不到**：`profile/3703.xml`（SA id 3703）、
  `etc/init/inputmethodservice.{cfg,rc}`、`bundle.json` —— **全部 not-local**。
- ~~**产出：一份按 blob 点名的取数清单**，共 **34 个 blob，本地 0 个**~~
  **（错，见 §48：那 34 个 blob 在 `~/openharmony-targets/inputmethod_imf` 里全部可读。）**
  清单本身仍然有用（它是对「要读哪些文件」的准确枚举），但「本地 0 个」这个前提是错的。
- **明确没有主张的事**：**没有**说这个 SA 不可达，也**没有**说它可达 ——「读不到」两个方向都不支持；
  **没有**把「可读子集无调用方」升格为「本仓库无调用方」；
  **没有**改任何 PoC 结论（`stable_reproduced` 与 `patch_revalidation = passed` 不变，
  `validated_vulnerability` 仍为 **0**，六个门字段**一个都没有**因本节置真）；
  **没有**推测 SA 3703 的权限语义；**没有**动 `version_impact.py` 或任何共享面。
- ~~**需要 owner 决定**：是否授权对这 34 个 blob 做一次显式取数~~
  **（撤回，见 §48：无需取数，已全部读到。真正的决定项换成了「实现 `IPlatformApi` 的组件是哪个」。）**
- **本节检查**：全部命令在文档 §7 可复现；脚本在 `/home/audit/wtmp/`，**不入库**；
  共享面 `git status` 零命中。

## 48. 2026-10-16 更正 §47：那 34 个 blob 就在盘上，而且答案不在本仓库

**这是一次对我自己已推送结论的更正。** §47（提交 `6d99e44`）说 AUTH-01 的入口证据
「34 个 blob，本地 0 个」，并据此请 owner 授权显式取数 —— **前提前提就错了**。
文档 `docs/research/ipc_auth01_entry_controlled_evidence_2026-10-16.md` 已整体修订。

- **错在哪**：§47 只在 `ipc-research/repos/inputmethod_imf`（`blob:none` 偏克隆）上统计。
  本机另有一份 **`/home/audit/openharmony-targets/inputmethod_imf`**：**浅克隆但非 blob 过滤**
  （`is-shallow=true`，无 `partialclonefilter`、无 `promisor`），对象库 54,344 对象，
  `cat-file -t e663b470…` 返回 `commit`。**那 34 个 blob 可读 34 / 缺失 0；全树源码 74/74 可读。**
- **教训（写下来以免再犯）**：§47 把「**这一份克隆**没有」写成了「**本地**没有」。
  差一步就让 owner 去授权取已经躺在盘上的对象。**判断「本地有没有」必须扫盘，不能只问一个对象库。**
  —— 同一条教训已同步到 CAP-01 那 3 个 `sa_profile` blob：**先扫盘，再谈取数。**
- **fixture 自检（读结论之前先做）**：在 targets 克隆上按 manifest 钉住的 sha256 重算，
  vulnerable `59c980bf…e043` **MATCH**、fixed `b6d7f66a…c444` **MATCH**；
  且该克隆的 vulnerable blob oid `e90a4e77e9be` 与 `ipc-research` 克隆**完全一致** →
  两个对象库同源，读到的是钉住版本的内容，不是近似版本。
- **读到了什么（正面证据）**：
  - `profile/3703.xml`（blob `d7736f4d42c9`）：SA 3703，`run-on-create=true`、`distributed=false`；
    **没有 `<permission>` 元素**。边界：OpenHarmony 的 SA profile 本来就不放调用者权限闸，
    所以这是「这条路取不到证据」，**不是**「该 SA 无权限控制」。
  - `etc/init/inputmethodservice.{cfg,rc}`：进程 **`uid system`**、`gid [system, shell]`、
    `caps SYS_TIME`、随 boot 启动。
  - `bundle.json`：subsystem `miscservices`，syscap `SystemCapability.MiscServices.InputMethod`。
- **关键结论升级（比 §47 更强，且这次站得住）**：74/74 全可读之后，§47 的
  「只能说可读子集里没有调用方」这个 caveat **被清除了** —— **`SetPlatform` 在钉住提交的整棵树里
  没有任何调用方**（只有 `platform.h:34` 声明与 `platform.cpp:22` 定义）；
  **`IPlatformApi` 在本仓库只有 proxy（`PlatformApiProxy`），没有 stub 实现。**
- **于是 `entry_controlled` 的形态变了**：不是「缺 34 个 blob」，而是
  **「答案不在这个仓库」——谁实现 `ohos.miscservices.inputmethod.IPlatformApi`。
  而该组件在本地不存在**（已扫 `~/openharmony-targets/` 与 `perf-corpus/`，
  既无实现者也无 `SetPlatform` 调用方）。
- **旁证（绑定的是另一个版本，不作钉住版本的证据）**：targets 克隆的 HEAD `09a9da45`（2025-09-13）上
  `services/src/platform.cpp` 与 `IPlatformApi`/`SetPlatform`/`PlatformCallback` 已全部消失
  （`services/src/` 换成完全不同的文件集），SA 声明改成 `profile/3703.json` ——
  而**新版 profile 同样没有权限字段**。即**两个版本的 SA profile 都不携带调用者权限闸**。
  本页**不**据此推断「该设计因缺陷被删」。
- **一个必须一起记的对照**：该 SA **自己的事务入口确实检查调用者** ——
  `input_method_system_ability.cpp`（208/227/251/279/307/335）与
  `input_method_system_ability_stub.cpp`（177/178/202/221/239/258）共 **11 处**
  `IPCSkeleton::GetCallingUid()`。而回调路径的句柄是被 `registerCallback` 交出去的，
  落到 `OnRemoteRequest` 的调用者不经过这些入口检查。
  **这是机制描述，不是可达性证明。**
- **门状态未移动**：`entry_controlled` **仍未建立**，`validated_vulnerability` 仍为 **0**，
  `poc_state = stable_reproduced` 与 `patch_revalidation = passed` 不变，
  **没有任何门字段**因本次置真。**没有**主张该 SA 可达或不可达。
- **决定项（替换 §47 的取数申请）**：不再需要取那 34 个 blob。
  需要的是**确定并取得实现 `IPlatformApi` 的组件**；现有线索（接口描述符
  `ohos.miscservices.inputmethod.IPlatformApi` + 调用点 `platform.cpp:26`）**不足以定位仓库**，
  **需要队伍判断或上游检索**。
- **本节检查**：命令在文档 §8 可复现；脚本 `/home/audit/wtmp/w170-172.py` **不入库**；
  共享面 `git status` 零命中；`version_impact.py` 与全部检测规则未改。

## 49. 2026-10-16 兑现 §48 的教训：CAP-01 的 `sa_profile` 本就在盘上，且该仓库全树可读（队友 B）

§48 记下的教训是「判断『本地有没有』**必须扫盘**」。本节立刻把它兑现到另外两处，
并顺手把 CAP-01 的 SA 暴露面补上。文档 `docs/research/ipc_cap01_guard_chain_2026-10-16.md`
新增 §10。**门字段一个都没移动，CAP-01 仍是 `candidate`。**

- **两处「待取数」全部作废**（`w173.py`，扫 `ipc-research/repos/`、`openharmony-targets/`、
  `perf-corpus/` 三处对象库）：
  - AUTH-01 §45 的 5 个 `unknown` blob（`022e5d44f76f` / `352b006d2405` / `7d45b1f09d98` /
    `866c0b6a5825` / `14a849f73d0e`）→ **全部在 `~/openharmony-targets/inputmethod_imf`**；
  - CAP-01 的 3 个 `sa_profile` blob（`bb2aec03568e` / `091a0ed22a33` / `58cd27ad45b2`）→
    **全部在 `~/openharmony-audit/perf-corpus/window_window_manager`**。

  → §45 那条「需 owner 决定是否显式取 blob」与 §47 的取数申请**都不成立**。
- **CAP-01 换数据源：全树可读**。`perf-corpus/window_window_manager` 是**浅克隆但非 blob 过滤**
  （无 `partialclonefilter`、无 `promisor`，读取不会触发惰性抓取；全部读取仍经
  `src/ohscanner/git_source.py:_git`），HEAD `8b0d8fe1b973`（= `origin/master`）：
  **全树 2450 路径、C/C++ 源码 1917 个，可读 1917 / 不可读 0**。
  于是 §46 的「impl 132 处 / stub 1 处」与同组件对照**不再受可读子集限制**
  （已全树重算复核，数值一致）。
- **三份 `sa_profile` 声明读到**（原文照录见文档 §10.2）：
  - `sa_profile/scene_board/4607.json` → SA **4607**，`libpath libscreen_session_manager.z.so`，
    `process foundation`，`run-on-create true`，`distributed false`，`bootphase CoreStartPhase`；
  - `sa_profile/4607.json` → SA **4607**，`libpath libwms.z.so`（其余字段同）；
  - `sa_profile/4606.json` → SA **4606**，`libpath libwms.z.so`（其余字段同）。

  三份**都只描述 SA 叫什么 / 加载哪个库 / 是否随创建启动 / 是否分布式 / boot 阶段 / dump 级别**，
  **没有任何权限字段**（无 `<permission>`、无 `exported`、无 `allow-update`）——与 AUTH-01 的
  `profile/3703.xml` **完全同形**。边界同样适用：**profile 无权限字段 ≠ 该 SA 无权限控制**；
  这是「这条路取不到 `entry_controlled` 的证据」，**不是**「没有控制」。
- **一处如实留白的未解决项**：`sa_profile/4607.json` 与 `sa_profile/scene_board/4607.json`
  **声明同一个 SA 号 4607 而 `libpath` 不同**。哪一份在 scene_board 构建下真正安装，
  **本仓库查不到** —— 全树 `.gn` / `.gni` / `.cfg` / `.json` 里 grep `sa_profile` **零命中**
  （`w177.py`），安装由 OpenHarmony 构建系统在本仓库之外完成。可说的只有：
  本候选所在模块是 `window_scene/screen_session_manager/`，**只有 `scene_board/4607.json`
  的 `libpath` 与它对应** —— 这是对应关系，**不是**安装证明。
- **补上 `renderSession_` 的来源（文档 §10.3）**：`screen_session.h:565`
  `sptr<IRemoteObject> renderSession_ = nullptr;`，在 `screen_session.cpp:72` 由构造参数
  `config.renderSession` 初始化，`screen_session.cpp:1007-1010` 是纯 getter。
  即这个事务交出去的**不是服务新建的对象，而是创建 ScreenSession 时随 config 注入的那个远程对象** ——
  与 AUTH-01 的注入式形态同类。因此 `security_impact` **依旧未建立**。
  （全树 `GetRenderSession` 53 处 / `SetRenderSession` 8 处 / `renderSession_` 14 处，调用方清单可枚举。）
- **门状态未移动**：`target_bound` 为真；`dynamic_reproduced` 为假（无 PoC）；
  **`entry_controlled` 仍未建立**；`reachable_sensitive_operation` / `exploitation_conditions`
  仍只到「半」；`security_impact` 未建立。**CAP-01 仍是 `candidate`**；
  **没有任何门字段**因本节置真。也**没有**主张该 SA 可达或不可达。
- **同时更正 §46 的另两处**：
  ① §46 写那 3 个 `sa_profile` blob「不在本地」——**错**，见上。
  更正方式与 §47 相同：**原文加删除线保留**、指向本节，**不删除记录**。
  ② 第 3 帧的行号写成 `1006-1009`，**差一行**。`w178.py` 在 blob `2442c62f00c2` 上复核，
  真实区间是 **`1007-1010`**（`screen_session.cpp:1007` 是函数定义行）。
  两个克隆给出的该 blob oid 完全一致（`2442c62f00c2`，3,795 行），所以这不是版本差异，是抄错。
  CAP-01 文档 §3 / §5.3 已同步更正。
  **这不是新证据，只是把引用改准** —— 三帧的结论一个字都没变。
- **本节检查**：命令在 CAP-01 文档 §8 可复现（`w173.py`–`w177.py`，均在 `/home/audit/wtmp/`，
  **不入库**）；`version_impact.py` 与全部检测规则未改；共享面
  （`src/report|src/case|src/evidence|src/benchmark`）零改动；回归见提交说明。

## 50. 2026-10-16 AUTH-01：#4 遗留的 62 条 `unknown` 全部结案（队友 B）

承接 §49 的教训（「本地有没有」**必须扫盘**），把 triage 文档 §5 剩下的那 24 条也读实。
记录写入 `docs/research/ipc_auth01_unknown_refs_triage_2026-10-16.md` 新增 §10，
该文档 §0 / §1 / §5 / §7 里「读不到」的说法已就地更正（原文加删除线保留）。
**`version_impact.py` 一字未改，#4 产物也一个字未改。**

- **那 5 个 blob 一直在盘上**：`022e5d44f76f` / `352b006d2405` / `7d45b1f09d98` /
  `866c0b6a5825` / `14a849f73d0e` 都在 `~/openharmony-targets/inputmethod_imf`
  （浅克隆、非 blob 过滤，读取不触网、全部经 `_git`）。
  triage 文档原写「没有去 fetch 那 24 条」—— 它隐含的前提「要读就得 fetch」**是错的**。
- **fixture 自检**：vulnerable `59c980bf…e043` **MATCH**、fixed `b6d7f66a…c444` **MATCH**
  （104 行 / 108 行）；`vulnerable → fixed` 的差异仍**只有描述符校验那 4 行**。
- **结果：5 个 blob 全部携带描述符校验** ——
  `ReadInterfaceToken` / `GetDescriptor` / `ERROR_STATUS_UNKNOWN_TRANSACTION` 三者全在。
  - ~~`352b006d2405`（7 条 ref）与 fixed **逐字节相同**~~ → **本条已更正，见 §52**：
    二者 108 行逐行相同、**但字节数不同**（`352b006d2405` 3594 B / fixed 3595 B，只差文件末尾
    那一个换行），所以「逐字节相同」**不成立**，只能说**内容等价**；
  - 其余 4 个在修复版之上**还多了边界校验**（`if (size < 0) … ERROR_STATUS_BAD_VALUE`
    与 `static_cast<size_t>(size) > data.GetReadableBytes() … ERROR_STATUS_BAD_VALUE`），
    是**比修复版更强**的加固。它们仍是不同的 blob，所以**不判 `fixed`**。
- **24 条 ref 已逐条点名**（由 #4 产物的 `records` 提取，非估算）：
  3.0-LTS 线 3 条（`origin/OpenHarmony-3.0-LTS`、`v3.0.7-LTS`、`v3.0.8-LTS`）、
  3.1 线 11 条（`3.1-API8-SDK-Public`、`3.1-API9-SDK-Canary`、`origin/OpenHarmony-3.1-Release`、
  `v3.1-Release`、`v3.1.1`–`v3.1.7`）、3.2-Beta4 + 2022-11 weekly 7 条、2022-10 weekly 3 条。
- **因此 62 条 `unknown` 全部结案**：38（§44）+ 24（本节）= **62**，
  **无一条携带 AUTH-01 缺陷**。判定状态按 triage 文档 §6 的原则**仍写 `unknown`**
  （blob 身份与 `fixed_blob` 不同，判 `fixed` 会篡改四态语义、判 `affected` 是误报）；
  是否需要第五态**属 owner 的契约决定，B 未动共享面**。
- **三条不越界的保留**：
  ① `unknown` 仍是 `unknown` —— 本节只把解释从「未读」升级为「已读且不含缺陷」；
  ② 这 24 条里 **21 条 `fixed_commit_reachable = False`**（只有 3.0-LTS 那 3 条为 True），
  「修复提交不可达」**既不是**漏洞证据**也不是**安全证据 —— 本节读的是**内容**，不是祖先关系；
  ③ 本节只覆盖 #4 扫描的 397 个 ref 里的这 62 条，**不构成「该缺陷已被完全清除」的结论**
  （未扫的 ref 与其它路径不在范围内）。
- **对 AUTH-01 状态的影响：没有。** `entry_controlled` 仍未建立、`validated_vulnerability` 仍为 **0**、
  `poc_state = stable_reproduced` 与 `patch_revalidation = passed` 不变，
  **没有任何门字段**因本节置真。交付件 #4 的解释更完整了，但**结论等级不变**。
- **本节检查**：命令在 triage 文档 §10.5 可复现（`w179.py`）；脚本在 `/home/audit/wtmp/`，
  **不入库**；共享面零改动；回归 485 tests OK（见提交说明）。

## 51. 2026-10-16 AUTH-01：被交出去的那个对象能做什么（队友 B）

记录写入 `docs/research/ipc_auth01_callback_capability_2026-10-16.md`。
**本文不解 `entry_controlled`** —— 它把 `reachable_sensitive_operation` 与 `security_impact`
这两格的**素材**读实，但**一个门字段都没有置真**。

- **两端的事务面（原文）**：`IPlatformApi` **9 个**事务
  （`registerCallback` / `bindInputMethodService` / `unbindInputMethodService` /
  `createWindowToken` / `destroyWindowToken` / `listInputMethod` / `getInputMethodProperty` /
  `getInputMethodSetting` / `setInputMethodSetting`，blob `1c7066c50728`）；
  `IPlatformCallback` **只有 1 个**（`NOTIFY_EVENT` → `notifyEvent(eventId, userId, eventContent)`，
  blob `e45548666deb`）。**交出去的那一侧是窄的。**
- **`PlatformCallbackStub::OnRemoteRequest`（blob `e90a4e77e9be`，104 行）三件事同时缺席**：
  ① 无 `ReadInterfaceToken()` / `GetDescriptor()` 比对（修复版加的正是这 4 行）；
  ② 无 `IPCSkeleton::GetCallingUid()` 之类的调用者检查（服务端**无法分辨**发消息的是谁）；
  ③ `size` 被直接当循环上界，**无边界校验**（独立于 ①②，见下）。
- **`notifyEvent` 能做的事（原文）**：把 `eventId` 映射成 7 种内部消息之一并投进
  `MessageHandler::Instance()`。消费者已定位到
  `services/src/input_method_system_ability.cpp:376-408` 的 `WorkThread()`：
  `MSG_ID_USER_START`→`OnUserStarted`、`USER_STOP`→`OnUserStopped`、`USER_UNLOCK`→`OnUserUnlocked`、
  `USER_LOCK`→`OnUserLocked`、`PACKAGE_ADDED`→`OnPackageAdded`、`PACKAGE_REMOVED`→`OnPackageRemoved`、
  `SETTING_CHANGED`→`OnSettingChanged`。
  即**用户生命周期 / 包安装卸载 / 输入法设置变更**三类事件，连同**调用方自选的 `userId` 与
  `eventContent`**，被投进 SA 的**串行工作线程**。
- **一处独立缺陷（静态分析，未动态验证）**：`platform_callback_stub.cpp:42-45`
  `int size = data.ReadInt32(); for (int i = 0; i < size; i++) eventContent.push_back(data.ReadString16());`
  —— parcel 读空后 `ReadString16()` 返回空串、**循环不停**，`size = INT_MAX` 时向量要装约 2³¹
  个空 `std::u16string`（量级几十 GiB）→ `std::bad_alloc` → **SA 进程终止（可用性）**。
  **钉住的 `fixed` 修订并没有修它**（`vulnerable → fixed` 只有那 4 行描述符校验）；
  反倒是 §50 读到的那 4 个变体 blob 带了 `size < 0` 与 `size > GetReadableBytes()` 两条校验。
  **按 `AGENTS.md`，「AI 推测不是验证」，所以这段不进任何门字段，只记为待验证线索。**
- **门状态：全部未变**。`entry_controlled` **仍未建立**；
  `reachable_sensitive_operation` **仍是「半」**，但「半在哪」变清楚了
  （敏感操作已具名，但仍未证 `On*` 内部的实际后果，且**仍需先持有句柄**）；
  `exploitation_conditions` 仍「半」；`security_impact` **仍未建立**
  —— **影响面写实与可达性未证是两件事**。
  `poc_state = stable_reproduced`、`patch_revalidation = passed` 不变，
  `validated_vulnerability` 仍为 **0**。
- **对定位实现者有一点帮助但不构成定位**：`IPlatformApi` 的 9 个方法给出了实现者的能力画像
  （绑定/解绑 IME 服务并返回 `IInputMethodCore`、创建/销毁 window token、列举/读写输入法属性与设置）
  —— *这**收窄**了候选范围，但盘上仍无实现者、也无 `SetPlatform` 调用方。*
  **决定项不变**：需要确定**实现 `ohos.miscservices.inputmethod.IPlatformApi` 的组件**。
- **没有证明的事**：没有读每个 `On*` 的内部（注入成功→状态被改之间还有一段未读）；
  没有追 `MessageHandler::Instance()` 与 `PerUserSession::msgHandler` 是否同一实例；
  没有做任何动态验证；没有改 `version_impact.py`、PoC harness、检测规则或任何共享面。
- **本节检查**：命令在该文档 §8 可复现（`w180`–`w183.py`）；脚本在 `/home/audit/wtmp/`，
  **不入库**；共享面零改动；回归 485 tests OK（见提交说明）。

## 52. 2026-10-16 AUTH-01：platform 层是怎么活着的、谁在用它、什么时候没的（队友 B）

记录写入 `docs/research/ipc_auth01_platform_layer_lifecycle_2026-10-16.md`。
起因是 §49/§51 反复撞上的那个决定项（「谁实现了 `IPlatformApi`」）。本轮**不追问实现者是谁**，
改问这个层**在历史上是怎么活着的** —— 结果同时给出了交付件 #4 的素材、一条**对 AUTH-01 不利**
的事实，以及一处**对我方旧记录的更正**。

- **它编进去了，不是死文件**：`e663b470:services/BUILD.gn:52-55` 把 `platform.cpp` /
  `platform_api_proxy.cpp` / `platform_callback_proxy.cpp` / `platform_callback_stub.cpp`
  四个源文件列进输入法 SA 的构建。
- **但全历史里没有调用方、也没有实现者**（pickaxe `-S` 扫 `--all`，看**命中路径集合**）：
  `SetPlatform` 只出现在 `platform.h` / `platform.cpp`；`IPlatformApi` 只出现在接口头 +
  `platform_api_proxy.cpp`；`PlatformApiStub` / `platform_api_stub` **零命中**。
  **这不是「没找到」，是「历史里就没有」。**
- **「没有调用方」≠「死代码」**：`platform.cpp`（blob `046a6a570cc1`，189 行）里**六个转发方法
  全都有 `platformApi == nullptr` 判空**（`:61`/`:74`/`:88`/`:101`/`:126`/`:150`），
  无注入方时统一返回 `ERROR_NULL_POINTER` / `nullptr`，**不崩**；`ListInputMethod`(`:114`) 与
  `GetInputMethodSetting`(`:140`) 更是**无条件 `return 0`**，根本不转发。
  **唯一不判空的是 `SetPlatform` 自己**（`:22-27`），也是全仓库**唯一** `new PlatformCallbackStub()`
  的地方。加上 `platform_api_proxy.cpp` 的存在，正确含义是：**注入方是仓库之外的、
  暴露 `IPlatformApi` stub 的 IPC 对端**。**不主张**产品上一定注入了 —— 那需要产品侧证据。
- **三个恒真函数不是漏洞（差点写成误报）**：`CheckPhysicalKeyboard`(`:160-163`)、
  `IsValidWindow`(`:169-175`)、`IsWindowFocused`(`:181-187`) 均**无条件 `return true`**，
  参数还是教科书式的 `(uid, pid, displayId)`。全树普查（74/74 可读）后：`CheckPhysicalKeyboard`
  **1 个调用方**（`peruser_session.cpp:490`，结果作为 `supportPhysicalKbd` 传给 `startInput`，
  **行为提示、不是安全闸**）；`IsValidWindow` / `IsWindowFocused` **零调用方**。
  → **不构成可达的鉴权绕过**；它们的意义是**设计证据**：钩子留了、没实现、也没接线。
- **影响范围（交付件 #4 素材，逐 ref 算）**：312 个 ref 逐一取 blob oid 并**逐个读内容**，
  分成 8 个 blob。**携带未修复 blob `e90a4e77e9be`（104 行）的是 18 个 ref**：
  `pinned-vulnerable`、`3.1-Beta`、`revert-merge-21-3.0-LTS`、`weekly_20220105`–`20220301`(9)、
  `v3.0-LTS`/`v3.0.1`/`v3.0.2`/`v3.0.3`/`v3.0.5`、`tags/OpenHarmony-3.1-Beta`。
  **边界**：`v3.0.4-LTS` 不在该对象库里；**230 个 ref 读不到**（多为 4.x/5.x/6.x），
  未纳入判定，**不能声称已穷尽全部 ref**。
- **时间线（必须一起记，因为它对 AUTH-01 不利）**：描述符校验是 **2022-03-05 `a6d13a2d`
  （master，zhouyongfei，「修复安全测试问题」）**加的 4 行；2022-03-09 `b61148e5` 进了 3.1；
  而钉住的 `e663b470`（2022-05-06，3.0-LTS，PR `!118`）**仍然没有校验**，
  直到 2022-08-23 `540daea7` → merge `5eaddcab`（PR `!228`「同步 master 安全问题修复」）才回移。
  → **主干 2022-03 就修了，3.0-LTS 是分支落后两个月**。**不能写成「OpenHarmony 到 2022-08 才修」**。
- **整层后来被当废弃代码删掉**：`98e421a2`(12-02「無用代碼刪除」)、`f2c9feb0`(12-03「删除代码」)、
  `3361ee76`(12-05「清理废弃代码」，含 `platform.cpp` −189 行)，作者均 `cy7717`。
  `3361ee76` 被 `3.2-Beta5` / `3.2-Release` 及其 tag 包含，`f2c9feb0` 被 `master` 与全部
  4.x/5.x/6.x release 包含；**`3.0-LTS` / `3.1-*` 不含**。即该层只活在 3.0/3.1/3.2-Beta4 及更早。
- **一处我方旧记录已更正**：§50 与 triage 文档 §10.2/§10.4 曾写 `352b006d2405` 与 fixed
  **「逐字节相同」—— 这是错的**。实测 `352b006d2405` 3594 B、fixed(`0f9ed2f6…ec68`) 3595 B，
  **108 行逐行相同、只差文件末尾一个换行**；同类的 `f34e8ff7d7a9`(38 ref) 是 3639 B，
  多两行 `// namespace` 注释（由 `5b5ef7d1 2022-03-25 fix warning` 引入）。
  三处表述已就地更正为「**内容等价，非同一 blob**」。**结论等级不变**（那 62 条仍不含缺陷）。
- **没有证明的事**：没有定位 `IPlatformApi` 的实现组件（`entry_controlled` 不动）；
  没有主张产品上一定注入了；没有读那 230 个不可读 ref；没有做任何动态验证。
- **公告归属当日补核（2026-10-16）**：团队原始材料
  `E:\读研\网络安全创新大赛\OpenHarmony_IPC近五年漏洞集.md`（第 58/125 行）把
  `OpenHarmony-SA-2023-0102 / CVE-2023-0036` 的修复线索记为
  `openharmony/inputmethod_imf` 的 **PR `!228`** —— 与本轮 git 事实
  `5eaddcab`（提交信息「同步master安全问题修复」，即 `!228`）**仓库与 PR 号双双吻合**，
  而 `e663b470`（`!118`）正是其回移前的快照。**因此**：本项目「vulnerable → fixed」这一对
  **可以绑定 `CVE-2023-0036 / OpenHarmony-SA-2023-0102` 编号**。**保留**：读的是团队整理的
  二次材料、**不是厂商公告原文**，所以口径是「编号 ↔ 提交对」的对应，不是「已核验公告文本」。
- **门状态**：**全部未变** —— `entry_controlled` 仍未建立、`validated_vulnerability` 仍为 **0**、
  `poc_state = stable_reproduced` 与 `patch_revalidation = passed` 不变。
- **本节检查**：命令在该文档 §9 可复现（`w184`–`w192.py`）；脚本在 `/home/audit/wtmp/`，
  **不入库**；共享面零改动；回归 485 tests OK（见提交说明）。

## 53. 2026-10-16 按独立审查反馈更正 B 线的推送/CI 表述（队友 B）

外部独立审查（`E:\读研\网络安全创新大赛\实验记录\OHScanner审查_2026-10-16\审查结论.md`，
2026-10-16）指出：**B 的交接/状态表述把「未推送」写成了现状，且不能称 M1/M2 分支的 CI 已通过**。
本轮**只改 B 自有文档的表述，不动代码、不动共享面、不动 A 与负责人目录**。

### 53.1 事实核对（本地 `git` 远端跟踪引用，未触网）

| 分支 | 远端 head | 含 B 的修复提交 | 状态 |
|---|---|---|---|
| `origin/feat/interface-m1-descriptor-identity` | `8464151` | `3fe3537`（**是它的祖先**） | 已推送，未合并 |
| `origin/feat/interface-m2-relay-guard` | `54a4d98` | `642ae1c` | 已推送，未合并（**Draft PR #11**，base = M1 分支） |
| `origin/feat/interface-ipc-detector` | `87e6ed0` | `3d88ffc`、`ffa27d7` 等 | 已推送，未合并（= 本地 HEAD） |

- 两条分支都不是 `feat/interface-ipc-detector` HEAD 的祖先（`git merge-base --is-ancestor` → NO），
  即它们是**独立的栈式分支**（M2 叠在 M1 上、M1 叠在负责人集成分支 `86fbf99` 上），
  不能按「同一分支已交付」理解。
- 本地分支与各自远端 head **一致**（`git branch -vv` 无 ahead/behind）。

### 53.2 已更正的表述（就地删除线 + 更正块）

- `docs/research/ipc_m1_descriptor_identity_2026-10-11.md` §头部第 6 行、§9「两条均未推送、未合并」。
- `docs/research/ipc_m2_relay_guard_2026-10-12.md` §头部第 7 行、§9「未推送、未合并」。
- 本文件 §33、§34 标题与正文里的「未推送」。

**没有删掉任何旧句**，全部保留并加删除线（`AGENTS.md`：不得删负结果；本项目一贯做法）。

### 53.3 一并记录的两条外部审查结论（**只记录，不据此行动**）

- **PR #11 的 head `54a4d98` 未返回 PR workflow run / status / review** —— 因此
  **不得称其 CI 已通过**。§6/§34 里的 401 项是**本地回归**结果，不是远端 CI 结果。
  （同类历史事实：B 从未在本线核对过 M1/M2 分支的远端 CI。）
- 审查同时记录：该 head **虽不是 `main` 祖先，但整个 interface 检测包、relay 测试及核对 fixture
  与 `main` 无差异**，故**无需再整支合并**。这是**负责人/main 侧**的判断，B **不据此行动**，
  也不改任何分支或 PR。

### 53.4 本条**没有**做的事

- 没有推送、没有开/改/合并 PR、没有把 Draft 标 Ready。
- 没有改 `tests/`、`web/`、`docs/项目现状与下一步.md`、`docs/面板功能与验收.md` 等负责人侧文件
  （审查的 R1/R2/R3 属负责人，由负责人自行处理）。
- 没有改 A 目录或 A 分支；没有重新联网查询远端（全部事实取自本地远端跟踪引用 + 审查记录）。
- **门状态、`validated_vulnerability`、候选数、`poc_state`、`patch_revalidation` 全部未变。**

## 54. 2026-10-16 P0-1（M3 授权谓词语义）关闭，并记录 entry_controlled 的上游追索结果（队友 B）

本轮按交接说明的优先级推进 **P0-1（M3）**，并同步追 `entry_controlled`。**只动 B 自有代码与 B 自有 fixture**；
未切分支、未碰 A 目录与负责人共享面、未 push/PR/merge、未做动态验证。

### 54.0 交接核对：两处与交接说明不符

- **HEAD 不符**：交接说明写 `87e6ed0a1849cd19b6170789b0ad3c53ddce4d42`，实测 HEAD =
  `818d3eb8d9760505a67eee7c2cca600ff783e152`（`docs(status): correct B's stale "not pushed"
  claims and record PR #11's CI state`）。二者是**父链关系**（`git log --oneline 87e6ed0a..HEAD` 只有
  `818d3eb` 一个提交），即交接说明**落后 §53 本身一个提交**，不是分叉。分支仍是
  `feat/interface-ipc-detector`。
- **未跟踪目录仍在**（交接要求核实）：`outputs/reports/interface_perf/` 存在，15 个文件（5 组件 ×
  `json`/`md`/`manifest.json`，2026-10-15 23:49–23:51 生成），`git ls-files` 为空 → **确认未跟踪、不入库**。

### 54.1 P0-1 是两处独立根因，不是一处

**(a) 函数体内的预处理条件使授权谓词不可判**（上一轮已修）。旧实现对函数体内的 `#if/#else` 整体报
`Unsupported control construct: preproc_ifdef` 并跳过，于是 `IsRootCalling()` 这类**返回值即授权判定**的
helper 被记为「多结果未解析」，其调用点因此拿不到授权事实。修法：有界预处理分支探索（把两条臂当备选，
因为构建变体未知）+ 帮助函数「返回 true 的路径」摘要。

**(b) `relay_guard` 的前瞻会为不可达路径发缺陷**（本轮新发现）。`relay_guard` 为了找回描述符比较，
从**处理器自身的守卫之前**的状态把处理器体读一遍；该读取会走到顶层声明初始化式里的值计算，从而在
`value()` 中触发 `action()`，为一条真实遍历不会走到的路径发出 `AUTH-02`/`AUTH-04`。
**调用栈证据**（插桩追踪，非推断）：
`analysis.py:609 action ← analysis.py:870 value ← analysis.py:777 relay_guard ← analysis.py:872 value
← analysis.py:1179 statement ← … ← detector.py:88 detect`。
修法：新增 `lookahead()` 上下文管理器，在前瞻期间把 `emit` / `limitations` / `seen_permissions`
换成惰性接收器——前瞻只需要它算出的值，不构成一次路径遍历，所以它期间看到的权限读取不能算作被分析路径的读取。

**因此上一轮「sat 3 → 0」的表述不完整**：只做 (a) 时真实测量是 12 → 11 条 finding、`auth.missing` 3 → 2；
(a)+(b) 都到位后才到 3 → 0。此处更正。

### 54.2 语料候选逐项差异（10 组件，每组件 5270 文件）

- **候选总数 72 → 69**，`detector_version` 由 `0.5.0` 记为 `0.6.0`。
- **消失 3 条**，全部是 `security_access_token` 的 `ipc.auth.missing`（AUTH-02），
  路径 `services/tokensyncmanager/src/service/token_sync_manager_stub.cpp` 第 **104 / 121 / 136** 行，
  符号 `TokenSyncManagerStub::{GetRemoteHapTokenInfoInner, DeleteRemoteHapTokenInfoInner,
  UpdateRemoteHapTokenInfoInner}`；其记录的 path 前缀均为
  `((37,'IPCSkeleton::IsLocalCalling() => True'), (42,'descriptor != ITokenSyncManager::Ge…`，
  即**授权事实此前由该 helper 供给、现在由预处理分支探索正确供给**，于是候选合法消失。
- **新增 0 条**。
- **7/10 组件候选集逐字节相同**；`security_access_token` 是唯一候选集变化的组件（3 → 0）。

### 54.3 限制文本的变化（按实列出，不写「减少了 N 条」）

- **移除**：`Unsupported control construct: preproc_ifdef; guards not proved through it.`
  （5 组件）；`Unresolved multi-outcome helper return: TokenSyncManagerStub::IsRootCalling`
  （`security_access_token`）。
- **新增**：`Path budget exceeded: conservative state join; path precision reduced.`
  （`communication_ipc`、`multimedia_camera_framework`）；
  `Preprocessor conditional inside a function body: arms are explored as alternatives …`
  （9 组件）——这是 54.1(a) 的代价：分支探索**声明**为限制，而不是假装构建变体已知。
- **只有 model 版本变化的组件**：`multimedia_player_framework`、`notification_common_event_service`、
  `update_updateservice`。

### 54.4 控制样例（正向 / 固定 / 无关）

`tests/fixtures/ipc/` 新增 7 个 fixture：6 条入 `manifest.json`（1 固定 + 5 正向，均属 AUTH-02 族、
`synthetic` 来源），第 7 个 `relay_lookahead_declaration_fixed.cpp` **刻意不入 manifest**（它合法保留中继候选，
不适合「`expected_rule: null` 即断言无 finding」的矩阵），改用独立测试
`test_relay_lookahead_does_not_report_a_call_it_could_not_reach`。
每个 fixture 都单独探过前后：`helper_preproc_guard_fixed` 1 → 0；4 个正向对照与 `no_else` 对照**保留**其候选；
lookahead fixture 在修复前 5 → 修复后 3（`ipc.auth.missing` 与 `ipc.auth.guard-coverage` 消失，中继候选保留）。
**已核实**：`manifest.json` 只被 `test_synthetic_semantic_matrix` 当清单遍历，**不存在**「每个 fixture 文件必须
出现在 manifest 里」的断言，故排除该 fixture 不会造成覆盖缺口。

### 54.5 版本提升

`IpcInterfaceDetector.version` `0.5.0` → `0.6.0`；`MODEL_VERSION` `oh-ipc-2026.10-v3` → `oh-ipc-2026.10-v4`；
`tests/test_component_audit.py` 中三处固定字面量同步。依据 `IPC_METHOD_CARD.md`：规则集变更必须使检测器身份移动。
**触及的共享面仅 `tests/test_component_audit.py` 的版本字面量**，已在此列明供负责人复核。

### 54.6 回归

`.venv/bin/python -m unittest discover -s tests`（**在仓库根执行；不能加 `-I`** —— 隔离模式把 cwd 从
`sys.path` 摘掉，`discover` 会以 `Start directory is not importable` 失败，这一点值得写下来免得下次再踩）
→ **Ran 486 tests in 44.751s … OK**（基线 485，本轮新增 1 项）。

**一个容易误引的坑**：测试输出里的 `[OK] manifest_sha256: …` 来自 `tests/test_version_impact.py` 调用
`version_impact.main()`，而该 hash 覆盖的是**测试自建的临时仓库**（提交 oid 含创建时间），**不是固定值**——
同一棵树两次运行分别是 `8ee73055…` 与 `3d8956f8…`。**不得**把它当作证据锚点或 fixture 清单指纹引用。

### 54.7 entry_controlled：从「找不到实现者」升级为「按设计不可能在本仓找到」

- **接口形态**（公共镜像 pinned SHA `8dac508bdc06caa03bd966890c40748a28a204bb` 的只读正文）：
  `IPlatformApi : public IRemoteBroker`，`DECLARE_INTERFACE_DESCRIPTOR(u"ohos.miscservices.inputmethod.IPlatformApi")`，
  9 个 transaction（`REGISTER_CALLBACK`…`SET_INPUT_METHOD_SETTING`）；`IPlatformCallback : public IRemoteBroker`
  （`…IPlatformCallback`）；本仓只有 `PlatformCallbackStub : public IRemoteStub<IPlatformCallback>`。
  → 这条依赖是**跨进程 broker**，框架侧只持有远端代理，**实现者按设计不在本仓**。
- **本仓可见的入站入口**：`PlatformCallbackStub::OnRemoteRequest` → `notifyEvent` → `MessageHandler::SendMessage`；
  从 parcel 读 `eventId`/`userId`/`eventContent` 后直接投递，**没有 `IPCSkeleton::GetCallingUid()` 一类调用方校验**。
  **可达性与影响未建立**（需先持有该 stub 的引用），等级仍是 **unknown**，不作为候选。
- **证据强度**：本仓无调用者这一点由两层独立事实支撑——(i) 磁盘扫描：`/home/audit` 下 37 个 git 对象存储 +
  全树 `grep`，`IPlatformApi`/`IPlatformCallback` 的实现者**磁盘上任何位置都不存在**；
  (ii) 本仓全 ref 历史（5356 提交，`3.0-LTS`…`6.0-Release`）：`SetPlatform` 在任何修订版中**都没有调用者**。
- **证据来源与限制**：上述 4 个头/源文件正文取自**公共镜像的只读 HTTP GET**（`raw.gitcode.com`，pinned SHA），
  **不是** `_git` 读取、**未**新建 clone、**未**写入任何对象存储、**未**入库；`xrefandroid.com`（OpenGrok）
  被 WebFetch 策略阻断，未能用作交叉引用。
- **结论**：`entry_controlled` **仍未建立**，`validated_vulnerability` **仍为 0**。本仓路径已穷尽，
  下一步只能依靠负责人/队伍判断是否认定上游实现组件在闭源或产品侧。

### 54.8 本节没有做的事

- 没有 push、没有开/改/合并 PR、没有把 Draft 标 Ready。
- 没有改 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/` 等共享面；
  没有改 A 目录或 A 分支。
- 没有做任何动态验证；没有把新生成的产物入库（`outputs/reports/interface_perf/` 与 `/home/audit/wtmp/` 脚本均不入库）。
- **门状态与候选等级全部未变**：AUTH-01、CAP-01 仍是 `candidate`；本轮只改检测算法与其控制样例。

## 55. 2026-10-16 P0-2（M6 跨 TU 一跳）落地：跨 TU 实现者守卫的读取、逐项差异清单与控制样例（队友 B）

本轮按交接优先级推进 **P0-2（M6）**。**只动 B 自有代码与 B 自有 fixture**；未切分支、未碰 A 目录与负责人共享面、
未 push/PR/merge、未做动态验证；`validated_vulnerability` 仍为 0。

### 55.1 M6 是什么，本轮改了哪四处

**机制**：OpenHarmony 的 stub 模式是 `class ScreenSessionManager : public SystemAbility,
public ScreenSessionManagerStub` —— 具体服务**派生自自己的 stub**，所以处理器里一句非限定的
`GetDisplaySnapshot(displayId, &errCode, …)` 是虚调用，函数体在**另一个 TU** 里。`EntryIndex.one_hop_definition(owner, name)`
沿 `_derived` 找**唯一**的覆盖定义；`analysis.one_hop_dispatch` 把那个体当成一跳的函数帧来读，`dispatch_guard`
判定它开头的门**是否真的在回答"调用方是谁"**。

**credit 的判定是双向的**（这是 M6 的实质，单看一例会写歪）：*离开*分支必须离开事务、且在**每条**路径上都不携带
调用方角色；*继续*分支必须可达、且**每一条**出口都携带角色。另有 `_modelled_before`（门只覆盖它之后的东西）与
`_decisive`（调用方自定的合取项，如 `&errorCode`）。

本轮四处修正：

- **(a) 出参的 const 判定是错的**（真实缺陷，非风格问题）：`ref_params` 只读 declarator 文本，而 tree-sitter 把
  `const sptr<T> &x` 的 `const` 放在 type 节点的**兄弟**位置（declarator 的文本只有 `&x`），于是 const 引用被当成
  非 const 出参，把**调用方自己的实参**标上"被写回"。修法：在整条参数声明上找 `const`；方向取保守（指向 const 的
  出参干脆不跟）。**语料影响为 0**（见 55.2 末尾的逐项比对），它改的是 `ref_params` 这个契约本身。
- **(b) 宿主类自己也定义同名方法时拒绝跳转**：`Base::Handle` 里的虚调用跑在 `this` 上，未覆盖的子类会跑 `Base` 的体；
  一个派生定义 + 宿主自身定义等于"不唯一"，两个体都不读，并把原因记下来。
- **(c) 一跳被拒的原因此前只写在 `EntryIndex.limitations` 上，而没有任何地方读它** —— 于是"拒绝了"与"从未尝试"在看输出
  的人眼里无法区分。现在只把 `One-hop callee is not unique…` 合并进 `DetectorRun.limitations`，并补一句"因此该调用点
  保持候选"。
- **(d) 0.7.1 追加**：被复审的 caller-role 谓词名如果在扫描源码里自带定义，就记录"替名的那份 body"。为什么需要，见 55.3。
  这一步第一次跑出来的是 `…at <file>:0 (…)` —— `Function.line` 只由一跳索引填充，从源码直接读出来的帧它是 0。
  引用一个不存在的行号等于没引用，改成用定义节点自己的行，并把"必须是非 0 行"写进测试。

### 55.2 语料逐项差异（10 组件；baseline = 0.6.0 的这次运行）

- 候选 **69 → 67 条原始记录**，`detector_version` `0.6.0` → `0.7.1`。**逐项比对按"唯一样本"**
  （`component`+`file`+`line`+`symbol`）做，两次运行都是 **67 → 65**：差的 2 条是同一身份上挂了两条规则的重复记录，
  两次运行**完全相同**、已核对——`communication_ipc` 的 `dbinder_callback_stub.cpp:139`（`ipc.auth.missing` +
  `ipc.relay.descriptor-boundary`）与 `multimedia_camera_framework` 的 `hcamera_service.cpp:1098`
  （`ipc.auth.guard-coverage` + `ipc.auth.missing`）。所以下面按组件判"集合是否移动"，不引原始记录数当结论。
- **消失 5 条**，全部在 `window_window_manager`，每条附上被 credit 的那一跳（stub 调用点 → 实现者 → 门的位置）：

| 消失的候选 | 一跳的源码依据（credit 原文） |
|---|---|
| `ScreenSessionManagerStub::OnRemoteRequestInner` AUTH-02，`screen_session_manager_stub.cpp:738` | 调用点 `:738` → `ScreenSessionManager::GetDisplaySnapshot` @ `screen_session_manager.cpp:10914`，门在 `:10918`，admits `<shell-caller>, <system-caller>` |
| `SessionStageStub::HandleGetUIContentRemoteObj` CAP-01，`session_stage_stub.cpp:1252` | 调用点 `:1251` → `WindowSessionImpl::GetUIContentRemoteObj` @ `wm/src/window_session_impl.cpp:5062`，门在 `:5064`，admits `<system-caller>` |
| `SceneSessionManagerStub::HandleGetUIContentRemoteObj` CAP-01，`scene_session_manager_stub.cpp:1208` | 调用点 `:1207` → `SceneSessionManager::GetUIContentRemoteObj` @ `scene_session_manager.cpp:12969`，门在 `:12971`，admits `<sa-caller>` |
| `SceneSessionManagerStub::HandleGetRootUIContentRemoteObj` CAP-01，`:1226` | 调用点 `:1221` → `SceneSessionManager::GetRootUIContentRemoteObj` @ `:12984`，门在 `:12986`，admits `<sa-caller>` |
| `SceneSessionManagerStub::HandleCreateUIEffectController` CAP-01，`:2944` | 调用点 `:2928` → `SceneSessionManager::CreateUIEffectController` @ `:4779`，门在 `:4782`，admits `<system-caller>` |

  逐一回原文核对（不是只看 credit 文本）：`screen_session_manager.cpp:10918` 是
  `if (!SessionPermission::IsSystemCalling() && !SessionPermission::IsShellCall() && errorCode) { *errorCode =
  DmErrorCode::DM_ERROR_NOT_SYSTEM_APP; return nullptr; }`，调用点传的 `&errCode` 是它自己的局部变量（`_decisive`）；
  `wm/src/window_session_impl.cpp:5064` 是 `if (!SessionPermission::IsSystemCalling()) { …; return
  WSError::WS_ERROR_NOT_SYSTEM_APP; }`；`session_stage_stub.cpp:1251` 调用的下一行就是
  `reply.WriteRemoteObject(uiContentRemoteObj)`（CAP-01 的锚点）。三处都在写回任何东西**之前**离开事务。
- **新增 3 条**，全在 `security_access_token`，全部是 `ipc.auth.missing`（AUTH-02）：
  `interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp` 第 **103 / 116 / 131** 行，
  符号 `TokenSyncCallbackStub::{GetRemoteHapTokenInfoInner, DeleteRemoteHapTokenInfoInner,
  UpdateRemoteHapTokenInfoInner}`，路径均为 `((70,'descriptor != ITokenSyncCallback::GetDescriptor() => False'),
  (77/80/83,'switch entry'), (94/109/122,'IsAccessTokenCalling() => True'))`。这三条的处置见 55.3。
- **其余 8/10 组件的候选集逐字节相同**（按"组件集合是否移动"判定，不按总数）。
- **本轮的两个修正对语料候选集的影响**：`ref_params` 的 const 修正 **0 条移动**（0.7.0 中间态 vs 0.7.0 末态逐项比对：
  65 → 65，无组件移动）；owner-body 守卫 **0 条移动**（5 条拒绝、涉及 4 个文件，两次运行的候选集在这 4 个文件上都是 0 条）。
- **一跳统计**：credited **90 条（全部在 wwm）**，refused **74 条**（wwm 60、sat 10、update 2、telephony 1、camera 1）。
  90 条 credit 里只有 5 条改变了候选 —— credit 只在调用点本来有候选时才有差别，这是"90"与"5"不相称的原因。
  **74 条拒绝既不新增也不消失**：0.6.0 根本没有一跳分析，拒绝等于维持原状；3 条新增的成因另由 55.3 的因果实验单独锁定，
  两者不重叠。

### 55.3 新增的 3 条为什么保留，而不是被 credit 掉

**源码依据**（全部来自 `accesstoken_callback_stubs.cpp`）：三个处理器开头都是
`:94/:109/:122 if (!IsAccessTokenCalling()) { LOGE(…); reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED); return; }`；
名字在本文件里**有定义**：`:136 bool TokenSyncCallbackStub::IsAccessTokenCalling() const { int callingUid =
IPCSkeleton::GetCallingUid(); return callingUid == ACCESSTOKEN_UID; }`，常量在 `:34 static const int32_t
ACCESSTOKEN_UID = 3020;`。

**因果实验**（`/home/audit/wtmp/b_exp_credit.py`，**只在内存里 patch** `Interpreter.resolve`，工作树不动）：
把复审名单里的名字改回"先按名字 credit"（0.6.0 的顺序）→ 该组件 3 → 0 条 finding，且**没有别的移动**。
所以差异的成因就是"名字在本文件里有定义，因此按 body 读、不按名字 credit"，不是别的东西。

**为什么不在本轮把它 credit 掉**：把 `GetCallingUid() == 3020` 当成授权事实，需要一条**被复审过的**声明"UID 3020 是特权
UID"。本语料能给的证据只有三处 `ACCESSTOKEN_UID = 3020`（`accesstoken_manager_service.h:240`、
`privacy_manager_service.h:103`、`accesstoken_callback_stubs.cpp:34`）的**命名与用法**，**没有 UID 分配表**——
未证实的假设不进策略。若要补，改动是 `models.py:135` 的 `trusted_uids` 加一处字符串，留给负责人判定。
本轮取"保守 + 有记录"：候选保留，同时把"是哪个 body 顶替了那个名字"写进 `DetectorRun.limitations`，
于是这条候选读起来是"这个 body 需要人看"，而不是"这里没有守卫"。

**全语料上一共命中 4 处**（同一份定义只记一次）：`TokenSyncCallbackStub::IsAccessTokenCalling`（sat，
就是新增的这 3 条的守卫）、`TokenSyncManagerStub::IsRootCalling` 与 `::IsNativeProcessCalling`（sat，
§54 里被抑制的 3 条正是靠这两份**自带 body** 建立的复审事实）、`CallManagerService::CheckCallerIsSystemApp`
（telephony）。也就是说这条记录既覆盖"body 建立了事实"的情形，也覆盖"没建立"的情形 —— 这不是缺陷，
而是这个规则本身的样子：它记录"名字没有按名单 credit"，不预判 body 的结论。

### 55.4 控制样例（正向 / 固定 / 无关）

- 新增 `tests/fixtures/ipc/role_predicate_shadowed_positive.cpp`（AUTH-02，入 manifest，
  `expected_rule: ipc.auth.missing`）：处理器用复审名单里的名字做门，而本文件自己定义了这个名字、答的是一个复审集合
  没有角色的 UID。配对的是已有的 `helper_preproc_guard_fixed`（同类同名 body、但**建立了**复审事实 → 抑制）。
  新增测试 `test_a_reviewed_role_name_defined_here_is_read_as_the_body_it_is` **同时断言两侧**，防止以后把
  "读本地 body"改成"按名字 credit"而不自知。
- M6 主体（六个 fixture：1 固定 + 5 正向）与三条测试在上一轮已落，本轮只补这一对；测试数 **494 → 495**。
- 已核实：owner-body 守卫在语料上**没有移动任何候选**（见 55.2），它的作用是"把'不唯一'写成记录"。

### 55.5 一跳 credit 的残留（已写进运行摘要的 limitation）

- 每个被 credit 的 stub 宿主在扫描集内**只有一个生产子类**（已核实）：`SceneSessionManagerStub` → `SceneSessionManager`
  (`scene_session_manager.h:236`)、`ScreenSessionManagerStub` → `ScreenSessionManager` (`screen_session_manager.h:64`)、
  `SessionStageStub` → `WindowSessionImpl` (`wm/include/window_session_impl.h:93`)；其余子类都在 `/test/` 下，被语料装载器跳过。
- 接口自己带**默认体**，而且就在扫描集里：`wmserver/include/zidl/window_manager_interface.h:213`
  (`GetUIContentRemoteObj` → `WSError::WS_OK`)、`:217` (`GetRootUIContentRemoteObj` → `WMError::WM_DO_NOTHING`)、
  `:442` (`CreateUIEffectController` → `WM_ERROR_DEVICE_NOT_SUPPORT`)。若存在第三个不覆盖的子类，调用会落到这些默认体
  （它们都不产出被写回的对象）。credit 陈述的是"为那次虚调用读到的实现者"，这条残留写进了运行摘要。
- 指向 const 的出参不跟：经出参写回的对象不会被追到产生它的那次调用。

### 55.6 版本与回归

- `IpcInterfaceDetector.version` `0.7.0` → `0.7.1`（0.7.0 是本轮 M6 的中间态）；`MODEL_VERSION` **未动**（规则集未变，
  只多了记录）。`tests/test_component_audit.py` 三处固定字面量同步 —— **触及的共享面仅此三处字面量**，列明供负责人复核。
- `.venv/bin/python -m unittest discover -s tests`（在仓库根执行；**不能加 `-I`**）→ **Ran 495 tests … OK**。
- 0.7.0 与 0.7.1 两次全语料运行的候选集**逐项比对 0 条移动**（不是只比总数）：0.7.1 只增加了 limitation 文本。
  55.1(d) 的行号修正补完后**再跑一次全语料**（`candidates_071b.json`）：仍是 67 条原始 / 65 条唯一样本、逐项 0 移动，
  4 条记录引用的定义行分别是 `accesstoken_callback_stubs.cpp:136`、`token_sync_manager_stub.cpp:62` / `:70`、
  `call_manager_service.cpp:2175` —— 与人工读到的定义行**逐一对上**（修正前这四处全是 `:0`）。

### 55.7 本节没有做的事

- 没有 push、没有开/改/合并 PR、没有把 Draft 标 Ready。
- 没有改 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/` 等共享面；没有改 A 目录或 A 分支。
- 没有做动态验证；新生成的产物不入库（`outputs/reports/interface_perf/` 与 `/home/audit/wtmp/` 下脚本均不入库）。
- **门状态与候选等级全部未变**：`entry_controlled` 仍未建立、`validated_vulnerability` 仍为 0，AUTH-01 与 CAP-01 仍是
  `candidate`。
- 未做 P1 的 M4/M5、独立留出集、WebView/ArkTS 检测器与只读 Agent 适配。

## 56. 2026-10-16 M8：UID 3020 的 source-bound 常量解析与限定账户角色，§55.3 的三条候选撤销，以及 5 棵未见树的通用性运行（队友 B）

本轮按负责人指定推进 **M8**：不给全局 `trusted_uids` 加白名单，而是把 §55.3 留下的"UID 3020 是不是特权 UID"变成一个
**只在源码能自证时才成立、且只对三个操作成立的账户角色**。**只动 B 自有代码与 B 自有 fixture**；未切分支、未碰 A 目录
与负责人共享面、未 push/PR/merge、未做动态验证；`validated_vulnerability` 仍为 0、`entry_controlled` 仍未建立。

### 56.1 为什么不是往白名单里加一行

`trusted_uids` 是一条**与源码无关的全局声明**：一旦加进去，任何地方出现 `GetCallingUid() == <那个 UID>` 都会被读成
"调用方是特权方"，与这个 UID 在该处**是否真的是**特权方、以及它**被允许做哪些操作**都无关。本轮改成三条同时成立的
**source-bound** 条件（`analysis.py:account_role`）：

1. 被比较的一侧必须是**调用方 UID**（`IPCSkeleton::GetCallingUid()`，且路径上身份未被重置）。调用方 **TokenID** 是另一个
   身份域，**请求报文里读出来的值**不是调用方 —— 两者都不得建立事实；
2. 另一侧必须是**复审记录点名的常量名**（`ACCESSTOKEN_UID`）。裸字面量 `3020` 没有可引用的复审绑定；
3. 该常量名必须**在本次扫描的源码里解析到记录的那个值**（`EntryIndex.define_constant`，同名同值优先），并且
   只有 `const` / `constexpr` 初始化器与对象式 `#define` 参与解析；同名但解析出**多个不同值**时返回 None 并记一条
   limitation（宁可不判也不猜）。

模型形状（`models.py`）：新增冻结数据类 `ServiceAccountRole(constant, uid, role, accepted_operations, origin)`，
策略字段 `service_account_roles`（当前只有一条：`ACCESSTOKEN_UID` / `3020` / `<caller-account:access-token-service>` /
三个操作 / 一条写明"值由源码确认、账户归属是**复审声明**"的 `origin`）。**`trusted_uids` 一行未动。**

角色只进入一个**新开的**事实通道 `State.service_account`（`bounded()` 的交集、`refine()` 的 kind→属性映射都已登记），
`authorized()` 里也只有 `GetRemoteHapTokenInfo / DeleteRemoteHapTokenInfo / UpdateRemoteHapTokenInfo` 三个操作会接受它。
**它不进 `state.auth`、不进 capability、不进 relay、不进跨 TU 一跳的 dispatch 判定** —— "账户不是权限"这句在这一轮是
代码结构上的事实，不是注释里的声明。

### 56.2 逐项语料差异（10 组件；baseline = `candidates_071b.json` 0.7.1 / 模型 v5）

runner 换成 `w_b_corpus_provenance.py`：每个组件按语料记录里的 `openharmony/<组件>` 与**固定提交**建 `ScanRequest`
（多数组件是性能文档记录的 12 位前缀，`security_access_token` / `update_updateservice` 用研究文档里的完整 40 位），
`snapshot_sha256` 改为按实际 unit 求 `snapshot_digest`。这样新笔记里的 `target` 字段指的是真正读过的那棵树，
而不是 `local/perf-corpus@0000…` 这种无法核对的占位。

- 候选 **67 → 64 条原始记录**（`detector_version` 0.7.1 → 0.8.0，模型 v5 → v6）。**逐项比对：消失 3 条、新增 0 条。**
- 消失的 3 条，全在 `security_access_token`，全部是 `ipc.auth.missing`，全部由同一条 credit 撤销：

| 消失的候选 | credit 的源码依据（运行输出原文） |
|---|---|
| `TokenSyncCallbackStub::GetRemoteHapTokenInfoInner`，`accesstoken_callback_stubs.cpp:103` | 守卫 `IsAccessTokenCalling` @ `:139`，常量绑定见文件自身 `:34` |
| `TokenSyncCallbackStub::DeleteRemoteHapTokenInfoInner`，`:116` | 同上 |
| `TokenSyncCallbackStub::UpdateRemoteHapTokenInfoInner`，`:131` | 同上 |

  运行输出原文（`candidates_m8.json`，`security_access_token` 的 limitations）：

  > Service-account role credited: caller-UID guard in `TokenSyncCallbackStub::IsAccessTokenCalling` at
  > `interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp:139` compares the calling UID with
  > `ACCESSTOKEN_UID`, which the scanned sources bind to `3020` at
  > `…/accesstoken_callback_stubs.cpp:34` (`OHOS::Security::AccessToken::ACCESSTOKEN_UID`,
  > `"static const int32_t ACCESSTOKEN_UID = 3020;"`). The role `<caller-account:access-token-service>` is accepted for
  > `GetRemoteHapTokenInfo, DeleteRemoteHapTokenInfo, UpdateRemoteHapTokenInfo` and for nothing else; target
  > `openharmony/security_access_token@17d88bfb36bea6c9370ba919ac41a22d16dd66b3`; policy origin: …
- **其余 9 组件的候选集逐字节相同**：`communication_ipc` 12、`inputmethod_imf` 4、`multimedia_camera_framework` 9、
  `multimedia_player_framework` 24、`notification_common_event_service` 0、`resourceschedule_background_task_mgr` 2、
  `telephony_call_manager` 2、`update_updateservice` 2、`window_window_manager` 9 —— 与 0.7.1 一致。
- 笔记层面的移动只有三类，逐条查明、无一条改变候选：**(a)** 10 个组件都有一条 `Model=…v5` → `…v6` 的模型版本行；
  **(b)** §55 的"被复审角色名在本文件有定义"那条笔记多了一句（说明该 body 若与复审账户比对会**另记一行**）；
  **(c)** sat 多出两行 —— 一条 `Service-account model:` 说明行，一条上面的 credit。**(a)(b)(c) 都不新增/不消失候选。**
- **全语料只有 1 条 credit**（就是 sat 的这条），没有任何别处的比较被读成账户事实：这是"没有给所有敏感 API 注入通用
  auth"在语料尺度上的对照组，不是只在 fixture 上成立。

### 56.3 那三条的复审结论：可以作为本条规则的误报撤销，撤销不等于组件安全

- **作为 `ipc.auth.missing` 的候选：撤销。** 该规则的陈述是"这个 IPC 操作上没有回答'调用方是谁'的守卫"。原文里
  三个处理器开头各有 `if (!IsAccessTokenCalling()) { …; reply.WriteInt32(ERR_IDENTITY_CHECK_FAILED); return; }`
  （`:94/:109/:122`，均在写回任何东西之前离开事务），而 `IsAccessTokenCalling` 读的是**调用方 UID**、比的是文件自身
  绑定的 `3020`。按本条规则的定义，这三条是该规则在本例上的**误报**，不是待复核的真候选。
- **撤销的边界**：credit 陈述的只是"这次比较建立了调用方是 access-token 服务账户这一事实，且该事实只覆盖记录里的三个
  操作"。它**没有**陈述 (i) `ACCESSTOKEN_UID = 3020` 这个**账户归属**本身正确 —— 那是复审带入的声明（`origin` 里写明
  "the account assignment is the reviewed claim it carries"），语料能自证的只有"值确实是 3020"；(ii) 这三个操作在
  这个账户下**应当**可达 —— 授权策略本身（谁该被允许调 TokenSync 的这三个操作）不在静态分析能回答的范围里。
- **因此审查台账上三条仍是 `candidate` / `unknown`，并注明"存在 UID 守卫，授权策略待复核"**：它们从检测器的 findings
  里退出，但没有从"待人工复核的授权问题"里退出。**撤销静态候选不等于证明整个组件安全** —— `security_access_token`
  的其余候选、`entry_controlled`、`validated_vulnerability=0` 全部未变。
- §55.3 与本轮的差别要写清：§55 的 3 条（sat 的 `IsRootCalling` / `IsNativeProcessCalling`，§54 抑制）靠的是
  **第一方角色谓词**；本轮这 3 条靠的是**新的账户通道**。两条规则都在，互不替代。
- 本轮**没有**为降低候选数加任何白名单：删掉的 3 条不是"豁免"，而是三个条件同时成立的推论；条件不成立时
  （见 56.4）候选照旧保留。

### 56.4 控制样例：一正四反 + 固定样例

新增 5 个 fixture（全部入 `tests/fixtures/ipc/manifest.json`，五个文件都带说明性头注释，用
`IRemoteStub<…>` + descriptor 检查 + switch 分发 + `this->Operation(…)` 的真实 stub 形状）：

| fixture | 构造 | 期望 |
|---|---|---|
| `account_role_authorized_fixed` | 三个 Inner 处理器都由 `GetCallingUid() == ACCESSTOKEN_UID`（本文件绑定 3020）把门，调用分别是记录里的三个操作 | **无 finding**，且 credit 笔记逐字断言（守卫函数与行、定义自己的 **`:11`** 行与声明原文、三个操作、`target fixture/ipc@synthetic-ipc-v1`、`policy origin`） |
| `account_role_wrong_value_positive` | 同名常量绑到 **4096** | 保留 `ipc.auth.missing`；笔记写 "bind to 4096 at sample.cpp:10"；**无 credit** |
| `account_role_tokenid_positive` | `GetCallingTokenID() == ACCESSTOKEN_UID` | 保留；笔记写 "against a caller TokenID"；**无 credit** |
| `account_role_request_value_positive` | `data.ReadUint32() == ACCESSTOKEN_UID` | 保留；笔记写 "against a request-derived value"；**无 credit** |
| `account_role_unrelated_call_positive` | 科目成立、命令不理：同一守卫后调 `SetPermission` | 保留；**有** credit，且 credit 只列那三个操作 —— 这是"账户不是权限"的对照组 |

两条新测试（`tests/test_ipc_detector.py`）：`test_service_account_role_is_credited_only_where_the_source_binds_it`
（同时断言"无 finding"与 credit 的可核对性），
`test_service_account_controls_that_must_not_supply_the_guard`（三条"不得建立事实"+ 一条"建立了也不覆盖"）。

**本轮另外发现并修掉一个真实文本缺陷**：credit 笔记**缺右括号**。原文写作 `… + definition.text + "\"")`，
末尾那个 `)` 是**闭 Python 分组**的，不是写进文本的字符，于是输出成了 `(ACCESSTOKEN_UID, "static const int32_t
ACCESSTOKEN_UID = 3020;". The role …`。它不影响任何判定（判定与文本构造无关），但引用一段没读完的原文同样是引用缺陷，
改成 `"\"")"` 并重跑确认三处引用（credit / 值不符 / 值无法解析）现在都闭合。**逐项语料差异对这条修正为 0**
（重跑全语料仍是 64 条、组件集合不动）。

### 56.5 未见过的 5 棵树：通用性运行（含一个被点名的覆盖缺口）

按负责人要求"多测试几个仓库"，从 `https://gitcode.com/openharmony/` 浅克隆 5 棵**从未参与调参**的树
（`usb_usb_manager` / `account_os_account` / `distributedhardware_device_manager` / `useriam_user_auth_framework` /
`sensors_sensor`，共 1,668 个源文件，均以**完整 commit SHA + `git_object` + `light-ast`** 建请求，脚本
`w_gitcode_scan.py`，产物 `b_runs/gitcode_5.json`）：

- **不崩、不空转、产出与语料同形的候选**：18 条候选 —— `distributedhardware_device_manager` 12 条、
  `usb_usb_manager` 6 条，其中 17 条是 `ipc.relay.descriptor-boundary`、1 条 `ipc.parcel.copy-range`。
  新出现的是 `3rd/interfaces/src/ipc/ipc_client_stub_3rd.cpp` 这类**第三方回调 stub**，以及
  `ipc_server_stub.cpp:309` 一个函数里 8 条（同一分发表连续 relay 的已知形状）。这些是**新线索**，等级仍是
  `candidate`，尚未逐条读原文。
- **`0 条候选` 不等于"安全"，本轮把它解释到了证据层**：三棵树 0 条（`account_os_account` /
  `useriam_user_auth_framework` / `sensors_sensor`）。用 `measure_entry_coverage.py --corpus <新目录>` 量入口：

| 树 | `.idl` 数 | 已提交 `*stub*.cpp` | 非测试分发器定义 | 识别到的 entry roots | 候选 |
|---|---:|---:|---:|---:|---:|
| `account_os_account` | 27 | 0 | 1 | 2 | 0 |
| `distributedhardware_device_manager` | 0 | 4 | 4 | 14 | 12 |
| `sensors_sensor` | 1 | 1 | 1 | 1 | 0 |
| `usb_usb_manager` | 2 | 1 | 2 | 4 | 6 |
| `useriam_user_auth_framework` | 18 | 1 | 0 | 0 | 0 |

  分发器定义数按"非测试、非调用（`return X::…` / `->`）、非声明"的 `X::OnRemoteRequest(…)` 定义行统计
  （`b_stub_generality3.sh`）。**定义数为 0 的那棵树 roots 也是 0，定义数不为 0 的树 roots 都不为 0**
  （1→2、4→14、1→1、2→4、0→0）—— 这 5 棵树上没有出现"仓库里有分发器、检测器却识别不到"的情形。
  反过来，`account_os_account` 450 个文件只识别出 2 个 root，
  原因是它的 IPC 面**由 IDL 生成**（27 个 `.idl`、**0 个已提交的 stub .cpp**；全树提到 `OnRemoteRequest` 的文件
  除一个回调 stub 外**全在 `/test/` 下**，被语料装载器按设计跳过）。`useriam` 同理（18 个 `.idl`、0 个定义）。
- **结论（写进 limitation 的形状）**：对"分发器由 IDL 生成、不随仓库提交"的组件，当前检测器看**不见**入口，
  于是 `0 条候选` 是**覆盖陈述**而非安全陈述。这是一条**被点名的缺口**，补法是二选一：把 `*.idl` 作为入口声明来源，
  或把生成产物纳入扫描集。本轮**未实现**，只是把它量化并记下来。
- **账户模型的跨树对照**：5 棵树里 `Service-account role credited` 与 `Service-account model:` 行**都是 0 条** ——
  新通道在这些树上什么都没建立、也什么都没抑制。加上 56.2 的"全语料只有 1 条 credit"，"不给所有敏感 API 注入通用
  auth"这条在 **5 棵新树 1,668 个文件 + 语料 10 组件 5,270 个文件 = 6,938 个文件**上有了对照组（其中 credit 恰好 1 次，
  且那 1 次的常量定义、比较点、目标提交都能逐字核对）。

### 56.6 版本与回归

- `IpcInterfaceDetector.version` `0.7.1` → `0.8.0`；`MODEL_VERSION` `oh-ipc-2026.10-v5` → `…-v6`。
  `tests/test_component_audit.py` 四处固定字面量同步（0.8.0 / v6 / `ohscanner.interface.ipc@0.8.0+oh-ipc-2026.10-v6`）
  —— **触及的共享面仅此四处字面量**，列明供负责人复核。
- `.venv/bin/python -m unittest discover -s tests`（仓库根执行，**不加 `-I`**）→ **Ran 497 tests … OK**（494 → 495（§55）
  → 497）。
- 全语料两次运行逐项比对见 56.2；本轮新增脚本与产物（`w_b_corpus_provenance.py` / `w_diff_candidates.py` /
  `w_gitcode_scan.py` / `w_dump_headers.py` / `w_show_notes.py` 与 `b_runs/*`）**全部在 `/home/audit/wtmp/` 下，不入库**。

### 56.7 本节没有做的事

- 没有 push、没有开/改/合并 PR、没有把 Draft 标 Ready。
- 没有改 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/` 等共享面；没有改 A 目录或 A 分支。
- **没有修改全局 `trusted_uids`**；没有为降低候选数加入任何白名单。
- 没有做动态验证；没有把 56.5 的 18 条新线索升级为任何更高等级（全部仍是 `candidate`）。
- **门状态与候选等级全部未变**：`entry_controlled` 仍未建立、`validated_vulnerability` 仍为 0；§56.3 撤销的三条在
  检测器输出里退出，但在审查台账上仍是 `candidate`/`unknown`（"存在 UID 守卫，授权策略待复核"）。

## 57. 2026-10-16 六 family 可插拔框架：family 自述其规则与策略片段，组合收在一个入口（队友 B）

为支撑"六条 family 线并行"，本轮把"哪个 family 负责哪些规则、持有哪条策略事实"从**两个所有线都会改的文件**
（`models.py` / `detector.py`）拆成**六个各自独立的模块**。**只动 B 自有代码与 B 自有测试**；未切分支、未碰 A 目录与
负责人共享面、未 push/PR/merge、未做动态验证；`validated_vulnerability` 仍为 0、`entry_controlled` 仍未建立。

### 57.1 为什么要有这一层

六条线各自要加的东西是同一类：一条新规则、一条复审过的调用方角色、一个敏感调用名、一个新入口名。改这些以前都必须
落在 `models.py` 与 `detector.py` 上 —— 六个会话改同一对文件就是天天解冲突，而且冲突的内容是**语义**（谁拥有哪条规则），
不是文本。现在每个 family 在自己的 `families/<family>.py` 里声明：

```
FAMILY   findings 上带的 family id（"AUTH-02"）
TITLE    一句话说清这条信任边界
CWE      该 family 报的机制 CWE
RULES    该 family 发出的规则 id
POLICY   可选：IpcPolicy 字段 -> 追加项（复审过的调用方角色、敏感调用名……）
```

`families/__init__.py` 自动发现本包内所有非私有模块，**没有手工注册表**，并在 **import 时**（不是首次扫描时）校验：

- 六个 family 的 `RULES` 合起来**恰好等于** `models.IMPACT_BY_RULE` 的键集 —— 少一条就是"没人认领的规则"，多一条就是
  "catalogue 里没有的规则"，两者都直接抛 `ValueError`，绝不会静默少跑一个 family；
- family id 唯一、CWE 形状为 `CWE-\d+`、`RULES` 非空、每条规则**只属一个** family；
- `POLICY` 只能追加到**元组/冻结集合**字段（标量是 catalogue 自己的值），且**两个 family 不得对同一字段追加同一个值**
  —— 这是编译器看不见的那一类跨线冲突（同一个调用方角色、同一个敏感调用名），必须由评审决定而不是由合并顺序决定。

`merge_policy(base)` 把各 family 的片段合到给定策略上，且是**幂等**的：任何进入接口内核的策略都会被合并一次
（`detector` / `Interpreter` / `EntryIndex` 三个入口），已经带过片段再合一次结果不变。这样"检测器跑"和"脚本自己跑"
读到的策略是同一个，不会出现"fixture 在检测器下干净、在 harness 里变脏"。`families/__main__.py` 提供一条自检命令：

```
.venv/bin/python -m src.ohscanner.detectors.interface.families
```

### 57.2 3020 账户角色从 `models.py` 搬到 `families/auth02.py`

§56 的 `ServiceAccountRole(ACCESSTOKEN_UID / 3020 / <caller-account:access-token-service> / 三个操作 / origin)`
是 **AUTH-02 那条线对它所 credit 的守卫的声明**，所以它随该 family 走：

- `IpcPolicy().service_account_roles` 的**默认值改为空元组**（`models.py` 不再含账号事实，只留类型 `ServiceAccountRole`）；
- 条目原文**逐字**移入 `families/auth02.py:POLICY`，`origin` 里"值由源码确认、账户归属是复审声明"这句照旧；
- **有效策略逐字节不变**：`merge_policy` 后 `service_account_roles` 仍是这一条，`trusted_uids` 一行未动；
- 因此 `detector.version` 保持 **0.8.0**、`MODEL_VERSION` 保持 **`oh-ipc-2026.10-v6`** —— 解释与判定能力没有变化，
  变的只是这条策略事实**存在哪个文件**，版本号不跟着文件搬家而变。

`detector._CWE` 也不再是手写字典，而是从注册表读（`families.cwes()`），并保留一条 import 断言要求它恰好是
AUTH-01/02/03/04、DATA-01、CAP-01 六个键。

### 57.3 回归证据（框架必须一条候选都不动）

- `.venv/bin/python -m unittest discover -s tests`（仓库根，**不加 `-I`**）→ **Ran 510 tests … OK**（497 → 510，
  新增 `tests/test_ipc_family_matrix.py` 13 条）。
- 新测试文件测的不是"框架能跑"，而是**框架的守卫本身**：规则集不构成划分 → 报错（两个方向都测）；同一规则被两个
  family 认领 → 报错；少一个 family 留下无人认领的规则 → 报错；两个 family 追加同一策略值 → 报错**且同一划分去掉冲突后
  能加载**（阳性对照）；family 模块缺声明、追加未知字段、追加标量字段、追加裸字符串 → 各自报错；`merge_policy` 幂等且
  保留调用方自己的收窄（`max_paths=4` 仍是 4 而角色仍在）；`IpcPolicy()` 不带账号、`default_policy()` 带 1 条、
  该条属于 AUTH-02。CWE 表在测试里是**写死的字面量**，family 改 CWE 必须同时改表。
- **10 组件语料：64 → 64 原始候选，逐项比对 `REMOVED 0 / ADDED 0`，10 个组件的 limitations 逐条无移动**
  （含 `security_access_token` 那条 §56.2 的 credit 原文，逐字未变）。
- **5 棵 gitcode 新树：18 → 18 候选，逐项比对 `REMOVED 0 / ADDED 0`，limitations 无移动。**
- 验收口径：**行为保持**——框架本身不新增、不撤销任何候选；新能力的入口是各 family 自己的 `POLICY` 与后续的内核请求，
  不是这一轮的重构。两次运行产物在 `/home/audit/wtmp/families_corpus.json` / `families_gitcode.json`，不入库。

### 57.4 六条 family 线的文件边界（相对 §56 的唯一变化）

- **可写**：`families/<family>.py`（自己的策略片段与规则声明）、`tests/fixtures/ipc/<fixture_dir>/`（`fixture_dir` = family id
  去掉连字符并小写，如 `AUTH-01` → `auth01/`）、`tests/test_ipc_<family>.py`、`docs/research/<family>_*.md`；
- **仍禁止改**：`models.py`、`analysis.py`、`entry_index.py`、`detector.py`、`families/__init__.py`、
  `tests/fixtures/ipc/manifest.json`、`tests/test_ipc_detector.py`、`PROGRAM_STATUS.md`，以及负责人共享面；
- 需要新 State 通道、新入口识别或新策略字段时，写 `docs/research/<family>_kernel_request.md` 交给 S0 合并；
- family 自己目录下的 `manifest.json` 会**自动**被 `tests/test_ipc_family_matrix.py` 按同一套断言读（目录名决定它属于哪个
  family，fixture 不得申报别的 family 的规则），因此新增 fixture 不需要任何人给共享 manifest 补一行。

### 57.5 本节没有做的事

- 没有 push、没有开/改/合并 PR；worktree/branch 说明写在仓库外的 `artifacts-2026-10-16/README-sessions.md`。
- 没有改 A 目录或 A 分支；没有改 `catalog.py`、`src/report/`、`src/case/`、`src/benchmark/`、`src/evidence/`。
- **没有修改全局 `trusted_uids`**；没有为降低候选数加入任何白名单；没有新增/撤销任何候选。
- 没有做动态验证；门状态与候选等级全部未变：`entry_controlled` 仍未建立、`validated_vulnerability` 仍为 0。
