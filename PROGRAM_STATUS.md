# PROGRAM_STATUS.md

> 项目：CyberSecurity-Innovation-Audit  
> 赛题方向：2026 OpenHarmony 开源代码漏洞挖掘  
> 更新日期：2026-10-06  
> 当前分支：`feat/historical-vuln-benchmark`  
> PR：#4 `feat: historical ground-truth benchmark and multi-scanner evidence adapters`  
> 当前阶段：历史漏洞 benchmark、多扫描器证据归一化、AST scanner、Evidence/Case draft、root-cause 样本扩展。  
> 重要边界：本分支不声明新漏洞，不做 PoC，不做 exploitability 结论；所有结果仍为 `candidate / draft / benchmark`。

---

## 0. 当前一句话状态

`feat/historical-vuln-benchmark` 已完成历史漏洞 benchmark 主线、AST scanner、text-vs-AST 对比、manual review 持久化、Tool Matrix、Evidence 生成层、VulnerabilityCase draft、`normalize-tool-output`、Semgrep/CodeQL/ClangSA/Cppcheck adapter、`compare-tools` 静态对比入口，以及 3 条 historical sample 的初步样本集。GitHub Actions 已验证 **93 tests passed**。2026-10-05 本机 WSL（Ubuntu 22.04.5）首次实测 Semgrep 1.179.0 + Cppcheck 2.7 在 3 个 historical samples 上的真实命中：root-cause 矩阵中 semgrep/cppcheck 列已从 `unknown` 填为 `possible_hit` / `miss`（cutils、dsoftbus 两样本 possible_hit，liteos 全工具 miss）；期间修复 cppcheck adapter 对 `column="0"` 误判的边界 bug。2026-10-06 完成了 cutils 与 dsoftbus 全部 possible_hit 区域的逐行语义 review：dsoftbus 的 semgrep 5/6 命中为**语义命中**（正确捕获 new-nothrow→紧邻解引用 null-deref 模式），其余均为区域重叠；并落地首条 OpenHarmony 专用增强规则 `rules/cpp/oh_shared_ptr_uaf.yaml`（从 cutils 修复提交反推 shared_ptr 非原子 reset 模式），矩阵新增 `semgrep_oh` 列，在 cutils vulnerable 版本语义命中 1 条、fixed 版本静默、其他样本零误报。当前 `validated_vulnerability = 0`，不得把 warning、candidate、benchmark miss/hit 或 crash 写成漏洞。

---

## 1. 当前 historical samples

| sample_id | 组件 | root_cause_group | CWE / CVE | 当前用途 | runtime |
|---|---|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `openharmony/commonlibrary_c_utils` | `lifetime_uaf` | CWE-416 | 第一方历史 UAF ground truth；暴露危险 API 文本扫描器对生命周期/并发型漏洞的盲区 | `not_run` |
| `kernel_liteos_a-getgroups-oob-2025-03` | `openharmony/kernel_liteos_a` | `concurrency_race` | CWE-125 / CVE-2025-20042 | GetGroups 锁保护范围不足导致越界读；用于补充并发/越界读根因类型 | `not_run` |
| `communication_dsoftbus_null_deref_001` | `openharmony/communication_dsoftbus` | `null_deref` | CWE-476 / CVE-2025-26690 | 空指针解引用 historical sample；补充漏洞类型多样性 | `not_run` |

样本扩展目标已经从单一 UAF 扩展到 3 个不同根因组：`lifetime_uaf`、`concurrency_race`、`null_deref`。这仍不足以计算正式 Precision / Recall，只能报告原始 hit / miss / unknown。

---

## 2. communication_dsoftbus null deref benchmark 摘要

样本文件：`benchmarks/historical/communication_dsoftbus_null_deref.json`

关键字段：

```text
repository: openharmony/communication_dsoftbus
vulnerable_commit: 258662cd9840b55a31546a72d91027f6368cea84
fixed_commit: 192f3e11d74beeaa3d879333471deb8a24a7e1c5
affected_file: core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp
affected_symbols:
  - ClinetOnNodeOnlineStateChanged
  - ClinetOnNodeBasicInfoChanged
  - ClientOnNodeStatusChanged
  - ClinetOnLocalNetworkIdChanged
  - ClinetNotifyDeviceNotTrusted
weakness: CWE-476
cve: CVE-2025-26690
root_cause_group: null_deref
runtime_replay_status: not_run
```

当前 benchmark 结论边界：

- 文本 scanner 对该 `null_deref` historical sample 未命中，属于当前工具盲区记录，不是失败；
- 该 miss 只能说明危险 API 文本扫描器不能覆盖“new (std::nothrow) 后缺少空指针检查”这类根因；
- 尚未验证攻击者是否可控分配失败；
- 尚未验证真实 OpenHarmony 系统入口是否可达；
- `runtime_validation = not_run`；
- 未做 PoC；
- 未做 TSan；
- 未做 exploitability 判断；
- 不可写成 validated vulnerability。

需要后续补录或保持 unknown 的字段：

```text
vulnerable_commit_exists: 待本地 benchmark JSON 记录为准
fixed_commit_exists: 待本地 benchmark JSON 记录为准
direct_parent_match: 待本地 benchmark JSON 记录为准
affected_files_changed: 待本地 benchmark JSON 记录为准
vulnerable candidate count: 当前记录为 text miss / 0 文本候选
fixed candidate count: 当前记录为 text miss / 0 文本候选
text_candidate_overlap_in_vulnerable: false
text_candidate_overlap_in_fixed: false
runtime_validation: not_run
validated_vulnerability: 0
```

解释口径：`communication_dsoftbus` 样本用于 benchmark 类型多样性和盲区识别。它不是新漏洞发现，也不是 PoC 或运行时验证结果。

---

## 3. 当前 GitHub / CI 状态

- PR：#4
- PR 状态：open / draft
- 分支：`feat/historical-vuln-benchmark`
- 最新 GitHub Actions：**93 tests passed**
- 当前可合并性：以 GitHub PR 页面为准
- 当前 validated vulnerability：**0**

---

## 4. 当前已完成模块

### 4.1 Own scanner 主线

- `src/core/ast_scanner.py`
- `scan --engine text|ast`
- text vs AST 对比：`src/benchmark/scanner_compare.py`
- cJSON 核心两文件 26 条危险调用复现；AST 与 text 对齐；AST 排除宏定义场景中的文本误报。

### 4.2 Triage / Review

- `src/triage/review_store.py`
- review template export / merge
- 所有人工 review 字段只用于证据链，不自动升级为漏洞。

### 4.3 Tool result / providers

- `src/benchmark/tool_result.py`
- `src/providers/base.py`
- `src/providers/semgrep.py`
- `src/providers/codeql.py`
- `src/providers/clang_sa.py`
- `src/providers/cppcheck.py`
- `src/providers/registry.py`
- `normalize_tool_output(provider, payload, AdapterContext)`

当前 adapter 只做格式归一化，不执行外部工具，不做漏洞判定。

### 4.4 Evidence / Case draft

- `src/evidence/from_tool_result.py`
- `src/evidence/from_triage.py`
- `src/case/assembler.py`
- `VulnerabilityCase` 目前只生成 `draft`，不生成 `reportable`。

### 4.5 Benchmark / Matrix

- historical benchmark runner：`src/benchmark/historical.py`
- multi-tool matrix：`src/benchmark/tool_matrix.py`
- tool comparison orchestrator：`src/benchmark/compare.py`
- root-cause hit matrix：`src/benchmark/root_cause_matrix.py`（状态只含 `possible_hit` / `miss` / `unknown` / `not_applicable`，不用 TP/FP/FN）
- benchmark summary report：`src/report/benchmark_report.py` + CLI `benchmark-report`（标题为 Historical Benchmark Summary Report，非 Vulnerability Report）
- 当前不计算正式 Precision / Recall，最多报告 raw hit / miss / unknown 计数。

---

## 5. 当前 unknown 清单

以下内容仍为 unknown / not_run：

1. `communication_dsoftbus` 空指针样本的真实安全影响和可利用性；
2. 攻击者是否能实际触发分配失败；
3. OpenHarmony 系统服务入口是否可达；
4. ✅ Semgrep / Cppcheck 已在本机实测，root-cause 矩阵已从 unknown 填为实值（见第 6b 节）；
5. ✅ 外部工具真实命中情况已于 2026-10-05 完成，2026-10-06 完成语义 review（见第 6d 节）；
6. 样本量只有 3 条，不计算正式 Precision / Recall；
7. `kernel_liteos_a` UAF（CVE-2025-24298 / CVE-2025-27128）仍在候选池，未做；
8. validated vulnerability 仍为 0。

---

## 6b. 2026-10-05 外部工具（Semgrep / Cppcheck）在 3 个 historical samples 上的本机实测

验证环境：Ubuntu 22.04.5 WSL2（本机），分支 `feat/historical-vuln-benchmark`。样本仓库以懒克隆（blob:none, --no-checkout）拉取到 `/root/openharmony-targets/`，逐一确认 vulnerable/fixed commit 存在后，用 `git show <commit>:<file>` 提取受影响文件到临时扫描树。工具执行：

- Semgrep 1.179.0（`.venv` pip 安装，清华镜像）；因网络无法访问 semgrep.dev registry，使用本地通用规则（危险内存拷贝 API、nothrow new 未检查、单例 GetInstance/DestroyInstance、指针成员解引用），规则文件与报告留存在 WSL 本机。
- Cppcheck 2.7（apt 安装），`--xml --enable=all --inconclusive`，对 C++ 头文件强制 `--language=c++`。

各文件独立扫描后，用项目 `normalize-tool-output`（semgrep / cppcheck adapter）归一化为 ToolRunResult，再经桥接脚本把诊断映射到各样本的 affected file/symbol 区域，生成 root-cause 矩阵。结果：

| 样本（root_cause_group / CWE） | own_text | own_ast | semgrep | cppcheck | clang_sa / codeql |
|---|---|---|---|---|---|
| c_utils singleton UAF（lifetime_uaf / CWE-416） | miss | miss | possible_hit(6) | possible_hit(10) | unknown |
| communication_dsoftbus null_deref（null_deref / CWE-476） | miss | miss | possible_hit(44) | possible_hit(10) | unknown |
| kernel_liteos_a GetGroups（concurrency_race / CWE-125） | miss | miss | miss | miss | unknown |

要点与边界：

- `possible_hit` 表示工具诊断**触及了受影响文件/符号区域**（例如 dsoftbus 的 `new (std::nothrow)` 与紧邻解引用、cutils 的 `GetInstance/DestroyInstance` 调用），是区域重叠描述，**不是漏洞确认**，也不等于该根因被正确表达。
- 三样本根因均为非危险-API 型（生命周期/并发/空指针解引用），自研文本扫描器 0 命中符合既有盲区记录。
- kernel_liteos_a 所有工具均 miss：锁作用域竞争与越界读对应工具（Semgrep 通用规则、Cppcheck 2.7）在单文件粒度上未触及 `GetGroups` 符号。这是盲区记录，不是失败。
- 修复的边界 bug：`src/providers/cppcheck.py` 将 Cppcheck 输出的 `column="0"`（未知列）解析为 0，触发 `ToolDiagnostic` 的 `column >= 1` 校验失败，导致整个归一化中断；修复为把 0 归一化为 `None`。语义无其他变化，`package`/规则行为未改。
- 本轮未运行 CodeQL / ClangSA（环境未装）；未做 PoC、TSan、动态触发、exploitability 判断；`validated_vulnerability = 0`。
- 样本量仍只有 3，不计算正式 Precision / Recall；矩阵只报告 raw hit / miss / unknown。
- 复现材料：归一化产物 12 份 JSON（`/root/bench-scan/normalized/`）与汇总报告 `outputs/reports/historical_benchmark_summary.{json,md}`（Git 忽略目录，不入库）；Semgrep 本地规则与桥接脚本存于 WSL 本机 `/root/bench-scan/`。

---

## 6b.5 2026-10-06 possible_hit 语义 review：区域重叠 vs 语义命中

对 cutils（lifetime_uaf）与 dsoftbus（null_deref）全部 possible_hit 诊断做了逐行源码对照审查，判定"是触及了受影响函数区域"还是"确实表达了该样本的真实根因语义"。

**cutils singleton UAF（CWE-416）**：根因是 `GetInstance()` 与 `DestroyInstance()` 之间 std::shared_ptr 的非原子读写竞态。

- Semgrep 3 条（vuln）：`new-nothrow-unchecked` + `plain-new-expr` 触及 `GetInstance` 函数体，但命中的模式是"nothrow new 后未检查 null"（实际 safe：null shared_ptr 不会导致 UAF），另有 `DelayedRefSingleton` 模板类中的 `new` 完全无关。
  - **判断：区域重叠，非语义命中**
- Cppcheck 10 条：`identicalInnerCondition`（double-checked locking 条件相同）+ `unusedFunction`（`GetInstance`/`DestroyInstance`）。
  - `identicalInnerCondition` 与并发有关联但不是 UAF 根因的表述；`unusedFunction` 是对的符号错的诊断类型。
  - **判断：区域重叠，非语义命中**

**dsoftbus null_deref（CWE-476）**：根因是 5 个受影响函数中 `new (std::nothrow)` 后不检查 null 就直接 `->` 解引用。

- Semgrep 44 条命中（vuln 36）：5 个受影响函数中 `new-nothrow-unchecked` + `deref-after-arrow` 组合精准定位了分配后紧邻解引用的 null-deref 模式。逐一审查：
  - `ClinetOnNodeOnlineStateChanged`（L77-78）：new→proxy.second→紧邻解引用 ✅
  - `ClinetOnNodeBasicInfoChanged`（L88-89）：同上 ✅
  - `ClientOnNodeStatusChanged`（L103-104）：同上 ✅
  - `ClinetOnLocalNetworkIdChanged`（L114-115）：同上 ✅
  - `ClinetNotifyDeviceNotTrusted`（L129-130）：同上 ✅
  - `GetClientProxy`（L38）：安全封装（调用方检查 null），判定为误报 ❌
  - **判断：5/6 命中（83％）为语义命中**——Semgrep 的通用规则正确捕获了该样本的 null_deref 模式
- Cppcheck 10 条符号命中：全部为 `unusedFunction`，正确命中了 5 个 affected_symbols 的符号名，但与 null_deref 根因语义完全无关（诊断理由错误）。
  - **判断：区域重叠，非语义命中**

**结论**：dsoftbus 样本上 Semgrep 的 5/6 命中是**真实的语义命中**，证明了即使在通用规则层面，模式匹配工具对该类 null_deref 根因有效。其他 3 组 possible_hit 均为区域重叠——cutils 的 UAF 根因（并发 shared_ptr 竞态）本质上是生命周期/并发类漏洞，文本模式与轻量静态分析工具均只能触及代码区域，不能表达其真正根因语义。

---

## 6b.6 2026-10-06 OpenHarmony 专用增强规则：cutils UAF 语义命中

针对 6b.5 review 暴露的盲区（通用工具无法表达 cutils 的并发 UAF 根因），落地了架构文档第 17 节创新点 A 的第一步：从历史修复反推 vulnerable pattern，编写 OpenHarmony 专用 Semgrep 规则。

规则来源（ground truth 反推）：读取修复提交 `9a3f2811` 的 diff，确认官方修复把 `DelayedSingleton<T>::DestroyInstance()` 中的 `instance_.reset(); instance_ = nullptr;`（非原子写）替换为 `std::atomic_store(&instance_, ...)`，并把 `GetInstance()` 的非原子读改为 `std::atomic_load(&instance_)`。据此提取 vulnerable pattern = **对状态成员 std::shared_ptr 的非原子 `reset()`**。

落库规则：`rules/cpp/oh_shared_ptr_uaf.yaml`，规则 id `oh-shared-ptr-nonatomic-reset-uaf`，pattern `$PTR.reset()`，CWE-416，root_cause_group=lifetime_uaf。

区分度实测（固定 vulnerable/fixed pair，2026-10-06）：

| 样本 | 版本 | semgrep_oh 命中 | 说明 |
|---|---|---|---|
| cutils singleton UAF | vulnerable | **1**（singleton.h:141 `instance_.reset()`） | 正是官方修复替换的那一行 |
| cutils singleton UAF | fixed | 0 | 修复后 reset() 已被 atomic_store 取代 |
| dsoftbus null_deref | vulnerable / fixed | 0 / 0 | 非目标根因，零误报 |
| kernel_liteos_a GetGroups | vulnerable / fixed | 0 / 0 | 非目标根因，零误报 |

矩阵新增 `semgrep_oh` 列（与通用 `semgrep` 列隔离，量化增强层的独立贡献）：

| 样本（root_cause_group） | semgrep（通用） | semgrep_oh（OH 增强） |
|---|---|---|
| c_utils singleton UAF（lifetime_uaf） | possible_hit(6)，review 判定区域重叠 | **possible_hit(1)，语义命中** |
| communication_dsoftbus null_deref（null_deref） | possible_hit(44)，5/6 语义命中 | miss(0) |
| kernel_liteos_a GetGroups（concurrency_race） | miss(0) | miss(0) |

要点与边界：

- 这是**语义命中**：规则命中的 `reset()` 就是 UAF 根因的非原子写点，且只在 vulnerable 版本触发、fixed 版本静默、其他样本零误报——具备真实区分度，不是区域重叠。
- 但边界必须诚实：pattern 工具的命中只证明"存在对 shared_ptr 的非原子 reset"，**不证明**该 reset 在真实 OpenHarmony 调用面上会被并发读者触发，也未做 TSan / 运行时验证；`possible_hit` 仍是区域+语义描述，不是 validated vulnerability。
- 规则的 `$PTR.reset()` 是宽 pattern，在其他项目可能对"安全的单线程 reset"产生误报；本样本集内为零误报，但跨项目误报率未测。规则 metadata 的 confidence 标为 MEDIUM 而非 HIGH。
- 当前只落地了 1 条 OH 专用规则（lifetime_uaf 家族），concurrency_race 与 null_deref 家族的专用规则尚未编写。

---

## 6c. 下一步建议

优先做：

```text
1. 补 1~2 个 pattern 友好的历史样本（buffer overflow / integer overflow / use-of-uninitialized / command injection），
   扩充矩阵覆盖面，让"通用工具能命中什么类型"有更多证据行
2. 为 concurrency_race（liteos 锁竞态）与 null_deref 家族补 OH 专用规则，验证增强层在多根因家族上的可复制性
3. 把 Semgrep 规则集从本地通用规则升级到 registry（c/cpp 官方规则），扩大模式覆盖面后重跑矩阵
4. 在 WSL 安装并运行 Clang Static Analyzer（clang 已随 build-essential 可用），把 clang_sa 列从 unknown 填成实际 hit/miss
5. 再决定是否进入 c_utils 纵向验证分支（TSan 复现属 A 线，本分支不做）
```
```

暂时不要做：

```text
PoC
TSan 复现
动态触发
exploitability 自动判断
将 candidate 升级为 validated vulnerability
```

---

## 7. 统一表述底线

- `warning != vulnerability`
- `candidate != vulnerability`
- `crash != exploitable security issue`
- `no warning != safe`
- `no CVE != 0-day`
- `historical fix parent != automatically ground truth`
- 真实代码必须固定 commit
- 实验必须保留失败结果
- 报告中的每一个结论必须能追溯到 Evidence
- 当前比较的是 root cause，不是 warning 数量
