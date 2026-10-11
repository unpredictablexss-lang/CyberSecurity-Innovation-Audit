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
