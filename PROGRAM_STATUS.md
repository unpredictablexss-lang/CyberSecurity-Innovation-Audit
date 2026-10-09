> **2026-10-09 状态提醒**：本文件 2026-10-08 的细节章节按时间记录历史试验，可能保留当时的 draft/待验收措辞；主线真实状态是 PR #4 已合入 `main`。下一阶段文档见 [三线并行总方案](docs/strategy/ohscanner_three_track_master_plan.md)、[Detector Contract v1](docs/contracts/ohscanner_detector_contract_v1.md)、[漏洞库与工具实验协议](docs/strategy/vulnerability_corpus_bakeoff_protocol.md)、[Web/IPC 专项任务书](docs/strategy/oh_web_interface_track.md)。它们均属**拟开发方案而非已实现软件**。

# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-09（下一阶段规划；旧阶段实测记录仍保留原日期）
> 当前分支：`feat/ohscanner-core`（独立开发分支；main 不变）  
> PR：#4 `feat: historical benchmark, scanner evidence chain, and multi-tool adapters`（2026-10-09 已合并）  
> 当前阶段：历史基线已合并；OHScanner Core M0 Mock + M1 固定 Git 对象源码索引已在 PR #5 开发分支实现。真实漏洞算法、真实 c_utils Ubuntu 试跑及真实产品构建上下文仍未完成。
> 重要边界：本分支不声明新漏洞，不做 PoC，不做 exploitability 结论；所有结果仍为 `candidate / draft / benchmark`。

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
- 当前只生成 `draft`，不生成 `reportable`。

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

输出标题为 `Historical Benchmark Summary Report`，不是 vulnerability report。该命令用于汇总样本数量、root-cause / CWE 分布、runtime 状态、own scanner 状态与 root-cause matrix。当前仍不计算 Precision / Recall。

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

## 8. 暂时不要做

```text
PoC
TSan 复现
动态触发
exploitability 自动判断
将 candidate 升级为 validated vulnerability
基于 4 个正样本计算正式 Precision / Recall
```

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

## 19. 2026-10-09 Windows 测试环境可移植性修复（teammate A 分支）

- 已消除 Windows 上四类本地测试环境失败：Git loose-object 只读文件删除、无符号链接创建权限、伪 Clang 扩展名/执行方式、临时目录短路径解析导致的 snapshot root 误判。
- 测试改为权限无关的 symlink 拒绝模拟和真实 Git tree `120000` symlink 条目；伪 Clang 在 Windows 使用 `.cmd` + 当前 Python，在 POSIX 保留可执行脚本；源码准备测试在 unlink 前清除只读位；静态复跑先规范化临时根目录。
- Windows 实测使用 Codex bundled Python：`python -m unittest discover -s tests -v`，**Ran 205 tests, OK (skipped=2)**。Windows Store `python3.exe` 仅为 shim，不作为验证运行时。
- 这些是测试/路径可移植性修复，不改变 detector 语义、公共 schema、解析覆盖结论或安全/漏洞状态；v1 契约仍未冻结。


## 20. 2026-10-09 cpp.lifetime 词法绑定边界审查与修复（teammate A）

- 自由审查发现一个可复现的结构性误候选：同一函数的兄弟块或嵌套块复用相同 `owner`/`alias` 名称时，旧实现按名称和函数范围拼接了不同词法绑定实例，安全控制也会产生 candidate。
- 已用最内层花括号块近似 owner/alias 的词法绑定范围，并按最近声明实例配对 owner、alias、reset、use 和 rebind；兄弟块/嵌套 shadowing 不再跨范围组合。外层 alias 在嵌套块中的合法 use 仍保留正例回归。
- 新增自建 safe fixture `tests/detectors/fixtures/cpp_lifetime/safe_shadowed_scope_bindings.cpp`，manifest SHA-256 绑定；新增 nested outer alias 正例测试。没有修改公共 schema 或共享 Runner 语义。
- Codex bundled Python 全量验证：`Ran 206 tests in 19.986s`，`OK (skipped=2)`。消融真实运行保持 lifetime base=4、straight-line rebind=3、sync=3；bounds base vulnerable=1/fixed=1/safe=0，guard vulnerable=1/fixed=0/safe=0。
- 仍有限制：词法块只是近似，不处理宏、lambda capture、模板 wrapper 或完整 CFG；独立 holdout 仍未收集，v1 契约未冻结，hard timeout/进程/内存沙箱仍未实现。空 findings 和 `completed` 均不代表安全。

## 21. 2026-10-09 合成 fixture 证据绑定修复（teammate A）

- 自由审查发现 `cpp_lifetime` 与 `cpp_bounds_length_parcel` 的 manifest repository/snapshot 值未绑定实际 `ScanContext`，测试加载器也未强制核对 manifest 文件 SHA-256，存在跨 fixture 证据混用风险。现以 manifest 的 repository/commit/profile/snapshot 构造请求，并在 detector 运行前校验每个源文件哈希、fixture-set snapshot、重复路径及 fixture 目录边界。
- `fixture_category` 明确仅为开发控制标签；`expected_observation` 只记录 `candidate_shape` / `no_candidate_shape` / `unknown_incomplete_analysis`，其中 partial/failed 均为 unknown。空 findings、`completed` 或 `no_candidate_shape` 均不代表安全结论。
- 两个离线 research slice 的模块复现入口改为复用同一 hash 校验加载器，避免脚本运行与单测使用不同证据集合；没有修改公共 `contracts.py`、Runner、CLI、providers、frontend、IR 或报告 schema。
- Codex bundled Python 全量验证：`Ran 213 tests in 20.217s`，`OK (skipped=2)`；定向 research-slice 回归 `Ran 10 tests, OK`，并补充重复路径与 `..` 路径穿越拒绝测试。以 `python -m research.experiments.cpp.lifetime_sync_slice` 与 `python -m research.experiments.cpp.bounds_length_parcel_slice` 复现时，lifetime 保持 `blocked`/unknown 覆盖语义，bounds 保持形状观察而非漏洞结论。
- 仍有限制：这些仍是 self-authored synthetic fixtures，不是 OpenHarmony 真实提交或漏洞 ground truth；没有独立 holdout、CFG/宏/并发完整分析、硬超时或进程/内存沙箱。本节不改变候选/未评估默认状态，也不提供 Precision/Recall 或安全结论。

## 22. 2026-10-09 分支文档卫生修复（teammate A）

- 按 PR #5 head `108494bfe392ae62394ea82cd44d28cc03ebb163` 恢复必需的 `docs/strategy/ohscanner_teammate_development_guide.md` 及 README 入口；恢复后的 guide blob 为 `5ec375816c836cc838ea544b981c23ad90692aab`，与接口基线逐字一致。
- 恢复 `docs/contracts/ohscanner_detector_contract_v1.md` 的基线实现状态说明，避免把已经由 `src/ohscanner/contracts.py` 实现的 M0/M1 接口误写为不可导入；proposed 字段仍保持未实现语义。
- 从当前分支树移除 `PROMPT.md` 与 `START_PROMPT.md` 两个任务/生成式 prompt 产物。它们仍存在于历史提交中，但不再是当前交付树内容；没有删除或改写历史。
- Codex bundled Python 验证：契约定向回归 `Ran 20 tests, OK`；全量 `Ran 213 tests in 20.252s`，`OK (skipped=2)`。三个恢复文件与 PR #5 基线 blob hash 完全一致，未修改代码、CLI、Runner、providers、frontend、IR 或报告 schema。
- 仍有限制：v1 detector contract 仍是 proposed，独立 holdout、真实 OpenHarmony corpus、CFG/宏/并发完整分析及硬超时/进程/内存沙箱仍未实现；空 findings、`completed` 或 `no_candidate_shape` 均不代表安全。
