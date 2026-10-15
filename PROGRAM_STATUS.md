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

## 33. 2026-10-11 M1 描述符身份修复（队友 B 单独提交，未推送）

接口线 M1：把 IPC 描述符校验从「限定名必须是本类」的过滤器，改成**从类自己的基类子句读出的接口身份**，
并按三档给结论。只改这一处，**M2～M6 未动**。

- 提交：`3fe3537`（分支 `feat/interface-m1-descriptor-identity`，**基于负责人已本地验证并推送的
  `feat/owner-ipc-platform-integration` 顶端 `86fbf99`**）；同一份树改动在接口线为 `3d88ffc`。
  **两者均未推送、未合并**，是否推送/开 PR/合并由负责人决定。
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

## 34. 2026-10-12 M2 一跳同文件委托：被委托方就是守卫时才不算边界（队友 B 单独提交，未推送）

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
  对恢复请求早退），原文保留以记录当时的判断。

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

### 本轮推送状态（先记录，勿与前一段混淆）

- 本轮先形成本地提交 `6852b1c`（**仅文档**：`PROGRAM_STATUS.md` 与
  `docs/research/ipc_wwm_recover_reachability_2026-10-15.md`），**当前未推送**；
  分支 `feat/interface-ipc-detector` **领先 `origin/feat/interface-ipc-detector` 恰好 1 个提交**，
  远端仍为 `b2d98853c282e55c2079fef0579a27b99d03d8da`。
- **提交 `6852b1c` 上从未跑过 unittest。** 本文件旧版本记的 `Ran 454 tests … OK` 是
  **父提交 `b2d9885`** 上的结果（本轮改动只有 Markdown，不进入 Python 测试输入），
  不得读作「已在 `6852b1c` 验证」。重跑结果见「本轮检查」。
- 按负责人 2026-10-15 的判定修正文档结论后，`6852b1c` 于推送前被 **amend** 为分支当前 HEAD
  （该提交即**本文件所在提交**；哈希以 `git rev-parse HEAD` 或推送后的远端
  `origin/feat/interface-ipc-detector` 为准，本文件不写自身哈希以免自我指涉失效）；
  `6852b1c` 本身**从未推送**，远端历史不受影响。

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
| 7.A | 「用调用者给的 `persistentId` **取回并接管已有会话**」这一**子假设** | **refuted / likely false positive** | 子假设被删项，**候选记录不减**（负结果保留） |
| 7.B | 候选 7/8 作为一条 finding 的**整体安全结论** | **未决（plausible but unproven）** | 仍是**同一条**共享机制记录，**不另立**新漏洞、**不重复计数** |

- **7.A —— 子假设已证伪（只能这样读，不得外推为候选整体误报）。** 三条**源码级确定性**事实
  各自独立否掉「取回/接管已有会话」：
  (1) `RecoverSessionInfo:5963` 在查表前置 `isPersistentRecover_=true` → 复用分支 `:3756-3762` 不可达，
  `GetSceneSessionBySessionInfo:3751` 必返 nullptr；
  (2) `GeneratePersistentId:5219` 只在 id 未被只增不删的 `g_persistentIdSet` 占用时才采纳调用者值 → 在用 id 不可抢占；
  (3) id 不一致时 `:6052-6061`/`:6202-6208` 擦除新建会话并返回 `SESSION_NOT_RECONNECT`。
  这是 in-repo 可证伪的**负结果**（带固定提交 `8b0d8fe1` 与行号），**不是**「本地没搜到限制」的推测；
  负结果与原始候选记录**保留、不删除**，**detector 规则不改**。
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
  **重新评估门槛（三条同时有证据后再议）**：(i) 普通应用能取回 SA 4606 远程对象；
  (ii) 普通应用能调用这两个恢复事务；(iii) 由此造成**具体的越权影响**。在此之前保持 unresolved/unknown。
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
- 回归：`.venv/bin/python -m unittest discover -s tests` → **Ran 454 tests … OK**，
  运行于**本轮文档提交（分支 `feat/interface-ipc-detector` 的 HEAD，`git rev-parse HEAD` 可核）**。
  本轮改动**只有 Markdown**，不进入 Python 测试输入；**父提交 `b2d9885` 上的同名结果不构成
  「已在 `6852b1c` 验证」**，故按负责人要求在新判定落地后重跑。
- 顺带记录：`docs/research/` 与本文件之外**无**代码改动；`sa_profile/4606.json`、检测规则、
  公共契约均未触碰。
