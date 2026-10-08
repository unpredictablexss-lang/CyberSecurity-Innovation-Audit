# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-08
> 当前分支：`feat/historical-vuln-benchmark`  
> PR：#4 `feat: historical benchmark, scanner evidence chain, and multi-tool adapters`  
> 当前阶段：PR #4 收尾检查；历史样本 benchmark、root-cause hit matrix、benchmark report、多扫描器证据归一化已落地。  
> 重要边界：本分支不声明新漏洞，不做 PoC，不做 exploitability 结论；所有结果仍为 `candidate / draft / benchmark`。

---

## 0. 当前一句话状态

`feat/historical-vuln-benchmark` 已从“搭框架”推进到“可收尾”：当前已包含 4 条 OpenHarmony historical samples、text/AST scanner 对比、manual review 持久化、Tool Matrix、Evidence 生成层、VulnerabilityCase draft、Semgrep/CodeQL/ClangSA/Cppcheck/Joern adapter、`compare-tools`、root-cause hit matrix、`benchmark-report` 汇总命令，以及 OH 专用 Semgrep 规则的首轮验证。PR #4 仍保持 **draft**，不要先 ready。

最近一次代码 CI 已通过：GitHub Actions `Ran 105 tests ... OK`。当前 `validated_vulnerability = 0`。

2026-10-08 本地 WSL Python 3.10 回归 **129/129 通过**（113 个既有测试 + 16 个新增测试）；
该结果不是最新远端 CI。新增架构/规则审查与 `AGENTS.md` 开发约束，并接通保存结果到
按样本、修复前后版本隔离的汇总报告。未提供结果时所有格子为 `unknown`，不再预设 miss。

---

## 1. 当前 PR / CI 状态

| 项 | 状态 |
|---|---|
| PR | #4 |
| PR 状态 | open / draft |
| mergeability | mergeable（以 PR 页面实时状态为准） |
| 当前分支 | `feat/historical-vuln-benchmark` |
| 当前阶段 | 文档与 PR 描述收尾，不切 ready |
| 最近一次 GitHub Actions | 105 tests passed |
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
- CodeQL 在单文件、缺头文件的样本粒度下不适用，应记为 `not_applicable`，如要使用需另立“全仓库 + 真实构建”工作流；
- Clang Static Analyzer 已在本机实测（clang 14，`baseline-clang`）：4 样本 × 2 修订共 8 个文件**全部 `fatal error: '<header>' file not found`、0 诊断**，与 CodeQL 同一原因（无法形成翻译单元）→ 在单文件粒度同样记 `not_applicable`，不是 `miss`；
- `root_cause_matrix` 原先只能产出 `unknown` / `possible_hit` / `miss`，文档里定义的 `not_applicable` 无法表达；已补 `NOT_APPLICABLE` 标记，使"没跑（unknown）"与"跑了但不适用（not_applicable）"可区分；
- Joern c2cpg 在单文件粒度表现为正结果，`joern` adapter / matrix 列**已落地**：`src/providers/joern.py`（provider `joern`，别名 `joern-cpg`，CLI `normalize-tool-output --provider joern`）+ `scripts/joern_nothrow_guard.sc`；历史本地实验记录 dsoftbus 为 vuln `possible_hit(5)` / fixed `miss(0)`（其余 3 样本均为 `miss`）。这只说明历史样本上的结构区分效果，不代表零误报/漏报；2026-10-08 审查确认其未分析 guard 支配关系，将脚本证据类型修正为 `syntax`，本轮未重跑 Joern。
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

## 7. 当前收尾 checklist

- [x] root-cause hit matrix 已完成；
- [x] benchmark summary report 已完成；
- [x] `benchmark-report` CLI 已确认存在；
- [x] PR 描述需要同步为“已完成 root-cause matrix / benchmark report”；
- [x] 文档中的旧状态需要从“待完成 / pending / first seed”改为当前 4 样本状态；
- [ ] 等本轮文档清理 commit 的 CI 跑完；
- [x] §18 第 5 步：四类外部工具的结构化结果已齐 —— Semgrep / Cppcheck 有实际诊断，CodeQL / Clang SA 在单文件粒度记 `not_applicable`（原因见第 5 节）；第 6 步（Tool Capability Matrix）尚未开始；
- [ ] 暂不切 ready。

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
