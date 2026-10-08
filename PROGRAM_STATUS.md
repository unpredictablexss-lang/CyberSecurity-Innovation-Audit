# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-06  
> 当前分支：`feat/historical-vuln-benchmark`  
> PR：#4 `feat: historical benchmark, scanner evidence chain, and multi-tool adapters`  
> 当前阶段：PR #4 收尾检查；历史样本 benchmark、root-cause hit matrix、benchmark report、多扫描器证据归一化已落地。  
> 重要边界：本分支不声明新漏洞，不做 PoC，不做 exploitability 结论；所有结果仍为 `candidate / draft / benchmark`。

---

## 0. 当前一句话状态

`feat/historical-vuln-benchmark` 已从“搭框架”推进到“可收尾”：当前已包含 4 条 OpenHarmony historical samples、text/AST scanner 对比、manual review 持久化、Tool Matrix、Evidence 生成层、VulnerabilityCase draft、Semgrep/CodeQL/ClangSA/Cppcheck/Joern adapter、`compare-tools`、root-cause hit matrix、`benchmark-report` 汇总命令，以及 OH 专用 Semgrep 规则的首轮验证。PR #4 仍保持 **draft**，不要先 ready。

最近一次代码 CI 已通过：GitHub Actions `Ran 105 tests ... OK`。当前 `validated_vulnerability = 0`。

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
- Joern c2cpg 在单文件粒度表现为正结果，`joern` adapter / matrix 列**已落地**：`src/providers/joern.py`（provider `joern`，别名 `joern-cpg`，CLI `normalize-tool-output --provider joern`）+ `scripts/joern_nothrow_guard.sc`；查询按分配变量做定向判空检查后，dsoftbus 样本为 vuln `possible_hit(5)` / fixed `miss(0)`，零误报零漏报（其余 3 样本均为 `miss`）；
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
