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

`feat/historical-vuln-benchmark` 已完成历史漏洞 benchmark 主线、AST scanner、text-vs-AST 对比、manual review 持久化、Tool Matrix、Evidence 生成层、VulnerabilityCase draft、`normalize-tool-output`、Semgrep/CodeQL/ClangSA/Cppcheck adapter、`compare-tools` 静态对比入口，以及 **4 条** historical sample 的样本集（root_cause_group 覆盖 `lifetime_uaf` / `concurrency_race` / `null_deref` / `oob_write`）。GitHub Actions 已验证 **93 tests passed**，本机 WSL 完整回归 **105 tests OK**。2026-10-05 本机 WSL（Ubuntu 22.04.5）首次实测 Semgrep 1.179.0 + Cppcheck 2.7 在 3 个 historical samples 上的真实命中：root-cause 矩阵中 semgrep/cppcheck 列已从 `unknown` 填为 `possible_hit` / `miss`；期间修复 cppcheck adapter 对 `column="0"` 误判的边界 bug。2026-10-06 三项进展：(1) 完成 cutils 与 dsoftbus 全部 possible_hit 区域的逐行语义 review——dsoftbus 的 semgrep 命中为语义命中（new-nothrow→紧邻解引用），cutils 均为区域重叠；(2) 落地首条 OpenHarmony 专用增强规则 `rules/cpp/oh_shared_ptr_uaf.yaml`（从 cutils 修复提交反推 shared_ptr 非原子 reset 模式），矩阵新增 `semgrep_oh` 列，vulnerable 命中 1 条、fixed 静默、其他样本零误报；(3) 新增 CVE-2025-23420 越界写样本（`arkcompiler_ets_runtime` JSArray sort，父提交已直接核验），**推翻了"缺失边界检查的越界写是 pattern 工具强项"这一假设**——semgrep/cppcheck 在该样本上精确命中已知漏洞行 **0 条**，`possible_hit` 纯属区域重叠；同时发现本地通用规则 `deref-after-arrow` 在 731 行文件上产生 144 条噪音（有效 0 条），需移除或收紧。新增行级"精确命中"统计后，4 样本 × 7 工具列中仅 2 个组合有精确命中（semgrep×dsoftbus 15 条、semgrep_oh×cutils 1 条）。当前 `validated_vulnerability = 0`，不得把 warning、candidate、benchmark miss/hit 或 crash 写成漏洞。

2026-10-06 追加（4）：semgrep.dev registry 网络已恢复可达（Windows/WSL 均 HTTP 200，`semgrep --config` 可在线拉取并执行），但**免费 registry 不含任何 C++ 规则**——154 条 `cpp.*` 全部是付费 `team_tier` pro 规则，`p/cpp` 为 404、`r/cpp` 为空，官方 `semgrep-rules` 仓库从无 `cpp/` 目录。因此已**弃用本地通用规则**（`deref-after-arrow` 噪音规则整体移除），改用 `0xdea/semgrep-rules`（MIT，49 条 c/cpp 规则，commit `dae50da6`）+ 官方 C 公共 registry 规则；同时新增第二条 OH 专用规则 `rules/cpp/oh_nothrow_null_deref.yaml`，把 dsoftbus 的「nothrow new 后未判空直接解引用」语义命中从旧通用规则手里恢复为专用规则命中（vulnerable 5 命中 / fixed 0 / 其他样本 0 误报）。详见第 6b.8 节。

---

## 1. 当前 historical samples

| sample_id | 组件 | root_cause_group | CWE / CVE | 当前用途 | runtime |
|---|---|---|---|---|---|
| `c_utils-singleton-uaf-2026-01` | `openharmony/commonlibrary_c_utils` | `lifetime_uaf` | CWE-416 | 第一方历史 UAF ground truth；暴露危险 API 文本扫描器对生命周期/并发型漏洞的盲区 | `not_run` |
| `kernel_liteos_a-getgroups-oob-2025-03` | `openharmony/kernel_liteos_a` | `concurrency_race` | CWE-125 / CVE-2025-20042 | GetGroups 锁保护范围不足导致越界读；用于补充并发/越界读根因类型 | `not_run` |
| `communication_dsoftbus_null_deref_001` | `openharmony/communication_dsoftbus` | `null_deref` | CWE-476 / CVE-2025-26690 | 空指针解引用 historical sample；补充漏洞类型多样性 | `not_run` |
| `arkcompiler_ets_runtime-jsarray-sort-oob-2025-02` | `openharmony/arkcompiler_ets_runtime` | `oob_write` | CWE-787 / CVE-2025-23420 | JSArray::SortElementsByObject 缺失边界检查的越界读写；**用于检验"缺失边界检查"是否真是 pattern 工具强项**（实测结论见 6b.7） | `not_run` |

样本扩展目标已经从单一 UAF 扩展到 4 个不同根因组：`lifetime_uaf`、`concurrency_race`、`null_deref`、`oob_write`。这仍不足以计算正式 Precision / Recall，只能报告原始 hit / miss / unknown。

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
5. ✅ 外部工具真实命中情况已于 2026-10-05 完成，2026-10-06 完成语义 review（见第 6b.5 节）；
6. 样本量为 4 条，仍不计算正式 Precision / Recall；
7. `kernel_liteos_a` UAF（CVE-2025-24298 / CVE-2025-27128）仍在候选池，未做；
8. validated vulnerability 仍为 0；
9. `arkcompiler_ets_runtime` 越界写样本（CVE-2025-23420）的真实可利用性、比较器触发条件与受影响版本范围均未验证；本轮只做静态 replay，`runtime_replay_status = not_run`；
10. ✅ 已确认（2026-10-06，见 6b.8）：`deref-after-arrow` 是纯噪音——在 `js_array.cpp` 上 144/144 条来自该规则、对已知漏洞行精确命中 0；本地通用规则已整体弃用，改为 0xdea raptor（MIT）+ 官方 C 公共规则 + OH 专用规则；
11. ✅ 已定性（2026-10-06，见 6b.9）：CodeQL（C++）已实测——工具可用，但在单文件样本粒度不可用（缺头文件→空 AST→0 结果）；`codeql` / `clang_sa` 两列应记 `not_applicable`（单文件粒度），要用须另立全仓库+真实构建工作流；ClangSA 本身仍未安装/未跑；
12. OH 专用规则的跨项目误报率未测（当前 4 样本内为零误报，不代表其他项目）。

---

## 6b. 2026-10-05 外部工具（Semgrep / Cppcheck）在 3 个 historical samples 上的本机实测

验证环境：Ubuntu 22.04.5 WSL2（本机），分支 `feat/historical-vuln-benchmark`。样本仓库以懒克隆（blob:none, --no-checkout）拉取到 `/root/openharmony-targets/`，逐一确认 vulnerable/fixed commit 存在后，用 `git show <commit>:<file>` 提取受影响文件到临时扫描树。工具执行：

- Semgrep 1.179.0（`.venv` pip 安装，清华镜像）；~~因网络无法访问 semgrep.dev registry~~，当时使用本地通用规则（危险内存拷贝 API、nothrow new 未检查、单例 GetInstance/DestroyInstance、指针成员解引用），规则文件与报告留存在 WSL 本机。**（2026-10-06 更新：registry 已恢复可达，本地通用规则已整体弃用，见 6b.8。）**
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

- Semgrep 44 条命中（vuln 36）：5 个受影响函数中 `new-nothrow-unchecked` + `deref-after-arrow` 组合精准定位了分配后紧邻解引用的 null-deref 模式。逐一审查（行号为 2026-10-06 直接从 `git show <vuln_commit>:<path>` 核实，修正了此前因 Windows 侧输出混入 stderr 导致的 7 行偏移）：
  - `ClinetOnNodeOnlineStateChanged`（L70 new → L71 解引用）：✅ 语义命中
  - `ClinetOnNodeBasicInfoChanged`（L81 new → L82 解引用）：✅
  - `ClientOnNodeStatusChanged`（L96 new → L97 解引用）：✅
  - `ClinetOnLocalNetworkIdChanged`（L107 new → L108 解引用）：✅
  - `ClinetNotifyDeviceNotTrusted`（L122 new → L123 解引用）：✅
  - `GetClientProxy`（L38）：安全封装（调用方检查 null），判定为误报 ❌
  - **判断：5/6 命中（83％）为语义命中**——Semgrep 的通用规则正确捕获了该样本的 null_deref 模式；精确行级证据见 6b.7
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
| arkcompiler_ets_runtime JSArray sort（oob_write） | possible_hit(4)，**精确命中 0**（见 6b.7） | miss(0) |

要点与边界：

- 这是**语义命中**：规则命中的 `reset()` 就是 UAF 根因的非原子写点，且只在 vulnerable 版本触发、fixed 版本静默、其他样本零误报——具备真实区分度，不是区域重叠。
- 但边界必须诚实：pattern 工具的命中只证明"存在对 shared_ptr 的非原子 reset"，**不证明**该 reset 在真实 OpenHarmony 调用面上会被并发读者触发，也未做 TSan / 运行时验证；`possible_hit` 仍是区域+语义描述，不是 validated vulnerability。
- 规则的 `$PTR.reset()` 是宽 pattern，在其他项目可能对"安全的单线程 reset"产生误报；本样本集内为零误报，但跨项目误报率未测。规则 metadata 的 confidence 标为 MEDIUM 而非 HIGH。
- 截至本条时只落地了 1 条 OH 专用规则（lifetime_uaf 家族）。**2026-10-06 更新：已补第 2 条 `oh_nothrow_null_deref`（null_deref 家族），见 6b.8；concurrency_race 家族仍待补。**

---

## 6b.7 2026-10-06 新增 oob_write 样本：一个被推翻的假设

### 样本核验（满足"父提交不得未经核验当作 ground truth"）

选取 CVE-2025-23420（官方 2025-03 公告：`arkcompiler_ets_runtime` 越界写，CVSS 3.8，修复 PR 11012）作为第 4 个样本，理由是越界写通常被认为是 pattern 工具的强项。核验链：

- fixed commit `1b235315`（cherry-pick of PR 10670 to 5.0.2）：新增 `JSArray::CheckStableArrayAndGet/Set`，在每处直接 `ElementAccessor::Get/Set` 前加 `IsStableJSArray && index < ElementAccessor::GetElementsLength()` 检查，否则回退 `ObjectFastOperator`。
- vulnerable commit `aeee3fd1`（直接父提交，`direct_parent_match = True`）：**已直接读取该提交内的 `js_array.cpp` 确认** `SortElementsByObject`（L638-671）仍含未加边界检查的 `ElementAccessor::Get(thisObjHandle, ...)`（L650/653/665）与 `ElementAccessor::Set(...)`（L666/668）。
- 父提交的 commit message 指向无关 PR 合并（!10959），因此它**只能因为漏洞代码被直接核验过**才算 ground truth，不能因为"它是修复的父提交"就自动采信。这一点已写入样本 JSON 的 notes。
- benchmark-historical 实跑：vulnerable/fixed commit 均存在，`affected-region overlap = False/False`，自研 text/AST 扫描器 0 候选（`ElementAccessor::Get/Set` 不在危险 API 名单内）。

### 假设被推翻：缺失边界检查的越界写并非 pattern 工具强项

原假设是"oob_write 属于 pattern 工具擅长类型，补进来能让矩阵出现更多语义命中"。实测结果相反：

| 工具 | 矩阵状态 | 精确命中已知漏洞行（L650/653/665/666/668） |
|---|---|---|
| semgrep（本地通用规则） | possible_hit(4) | **0** |
| cppcheck 2.7 | possible_hit(2) | **0** |
| semgrep_oh（UAF 专用规则） | miss(0) | 0（规则面向 shared_ptr，正确不适用） |
| own_text / own_ast | miss(0) | 0 |

- cppcheck 在该文件仅 3 条诊断（`duplicateConditionalAssign` L123/124、`unsignedPositive` L628/663），**没有一条指向未检查的索引访问**。`unsignedPositive`(L663) 虽落在同一循环，但讲的是 `endIndex` 的无符号比较冗余，与越界写根因无关。
- semgrep 通用规则报 144 条，全部来自 `deref-after-arrow`，落在漏洞行的为 **0 条**，函数体内仅 L641（`ASSERT(fn->IsUndefined()...)`）一条无关命中。
- 根因分析：要发现该漏洞必须理解"排序过程中比较器可执行任意 JS，从而改变数组后端存储，使先前取得的 index/length 失效"——这是**跨调用的数据流与时序推理**，不是单行语法模式。因此 `possible_hit(4)` / `possible_hit(2)` 只是区域重叠，**不能**当作工具"能发现越界写"的证据。

### 暴露的扫描器质量问题（需修复，非本轮结论）

本地通用规则里的 `deref-after-arrow`（pattern `$P->$FIELD`）在 731 行的 C++ 文件上产生 144 条诊断、有效 0 条。它把 C++ 里最常见的成员访问全部报警，属于**纯噪音规则**，会虚增 possible_hit 计数并掩盖真实信号。后续应从通用规则集中移除或大幅收紧，并重新评估 dsoftbus 的 44 条命中里有多少来自该噪音规则。

**（2026-10-06 已处理：整条本地通用规则集已弃用，改用 0xdea raptor 镜像 + 官方 C 公共规则 + OH 专用规则，ark 144→4，详见 6b.8。）**

### 精确命中统计（新增的行级语义证据）

为避免"区域重叠"被误读为"语义命中"，本轮在桥接脚本中增加了行级核验：只有诊断行号落在**已核实的漏洞行**上才计为精确命中。4 样本结果：

| 工具 | 样本 | 精确命中行 | 条数 |
|---|---|---|---|
| semgrep | dsoftbus null_deref | 70, 71, 81, 82, 96, 97, 107, 108, 122, 123 | 15 |
| semgrep_oh | c_utils singleton UAF | 141 | 1 |
| 其余全部组合 | — | （无） | 0 |

这是目前唯一可支撑"工具确实指向根因"的硬证据：**4 样本 × 7 工具列中，只有 2 个组合有精确命中**。

---

## 6b.8 2026-10-06 网络恢复：Semgrep registry 可达性与规则来源替换（弃用本地通用规则）

### 网络复测（结论：已恢复）

2026-10-06 在 Windows 与 WSL 两侧复测：`semgrep.dev`、registry API、清华 PyPI、GitHub 均返回 HTTP 200；`semgrep --config p/default --dryrun` 可在线拉取规则并执行。即**不再需要**"因网络无法访问 registry 而退化为本地通用规则"这一前提（该说明见 6b 节，已过时）。GitHub 在 WSL 侧仍不稳定（`git clone` 偶发 HTTP/2 framing error / 连接超时），但 registry 与 raw API 稳定。

### 关键发现：免费 registry 对 C++ 基本零覆盖

| 配置 | 规则数 | `languages: [c]` | `languages: [cpp]` |
|---|---|---|---|
| `p/default` | 1073 | 4 | **0** |
| `p/security-audit` | 225 | 9 | **0** |
| `p/ci` | 159 | 0 | 0 |
| `p/c` | 2 | 2 | 0 |
| `p/cpp` | — | — | HTTP 404 |
| `r/cpp` | — | — | `rules: []` |

registry API 共 6101 条规则：`cpp.*` 共 **154 条但全部为 `team_tier` 付费 pro 规则**（需登录且付费）；`c.*` 仅 **16 条 public**。官方 `semgrep/semgrep-rules` 仓库有 `c/`（16 条）但**从无 `cpp/` 目录**（git 历史亦未出现）。实测 `--config p/c` 的 C 规则不会作用于 `.cpp` 文件（语言隔离），在含 `gets()` 的 `.cpp` 上命中 0。

结论：**"把本地通用规则换成官方 registry 规则"这条路径对 C++ 不成立**——免费 registry 没有 C++ 规则可换。旧的"本地通用规则"问题（`deref-after-arrow` 噪音）不能靠换成 registry 规则解决，必须另找镜像源 + 专用规则。

### 替换方案（已落地）

| 目标 | 规则来源 | 位置 |
|---|---|---|
| C（`.c`/`.h`） | Semgrep 官方 registry（`p/security-audit` 等） | 运行时 `--config` |
| C++（`.cpp`/`.hpp`） | `0xdea/semgrep-rules`（MIT，875★，49 条 `raptor-*` c/cpp 规则，commit `dae50da6`） | `rules/cpp/vendor/raptor/`（已 vendor） |
| OpenHarmony 专用 | `oh_shared_ptr_uaf.yaml`、**新增** `oh_nothrow_null_deref.yaml` | `rules/cpp/` |

复用脚本：`scripts/semgrep_ruleset_scan.sh`。旧的 `/root/bench-scan/semgrep_rules.yaml`（本地通用规则，含 `deref-after-arrow`）**作废**。

### before / after（4 样本 × 2 修订，Semgrep 1.179.0，同机复测）

before —— 旧本地通用规则（2026-10-06 重跑，命令与配置一致）：

| 样本 | vuln 条数 | fixed 条数 | vuln 规则分布 |
|---|---|---|---|
| cutils singleton UAF | 3 | 3 | `new-nothrow-unchecked` 1、`plain-new-expr` 2 |
| kernel_liteos_a GetGroups | 0 | 0 | — |
| communication_dsoftbus null_deref | 36 | 36 | `get-instance-call` 7、`new-nothrow-unchecked` 7、`plain-new-expr` 7、**`deref-after-arrow` 15** |
| arkcompiler JSArray sort | 144 | 144 | **`deref-after-arrow` 144** |

after —— raptor + 官方 C 公共规则（通用层）：

| 样本 | vuln 条数 | fixed 条数 | 规则分布 |
|---|---|---|---|
| cutils singleton UAF | 0 | 0 | — |
| kernel_liteos_a GetGroups | 41 | 41 | `raptor-signed-unsigned-conversion` 20、`raptor-integer-truncation` 13、`raptor-interesting-api-calls` 8 |
| communication_dsoftbus null_deref | 0 | 0 | — |
| arkcompiler JSArray sort | 4 | 4 | `raptor-suspicious-assert` 2、`raptor-typos` 2 |

after —— OH 专用规则：

| 样本 | 规则 | vuln | fixed | 命中行 |
|---|---|---|---|---|
| cutils singleton UAF | `oh-shared-ptr-nonatomic-reset-uaf` | 1 | 0 | 141 |
| communication_dsoftbus null_deref | `oh-nothrow-alloc-unchecked-deref` | 5 | 0 | 70, 81, 96, 107, 122 |
| 其余样本 | 两条规则 | 0 | 0 | — |

要点与边界：

- `deref-after-arrow` 噪音彻底归零：ark 从 144 → 4（且这 4 条是 `suspicious-assert`/`typos`，与 `oob_write` 根因无关）。旧通用规则对 4 个样本已知漏洞行的**行级精确命中为 0**，与"纯噪音"判断一致。
- dsoftbus 的语义命中**没有丢失**：旧通用规则给出 36 条（vuln=fixed，无区分度）；新方案下通用层 0 条，而 OH 专用规则 `oh-nothrow-alloc-unchecked-deref` 精确命中 5 处分配点、fixed 静默——语义命中由**专用规则**承担，符合架构文档第 17 节创新点 A。
- liteos 的 41 条 raptor 命中在 vuln/fixed 上**完全相同**（signed/unsigned、整数截断、interesting-api-calls），属风格类噪音，**不构成** `concurrency_race` 根因命中。
- 新通用层的 4 个样本行级精确命中仍为 **0**（OH 专用层为 dsoftbus 5 行 + cutils 1 行）。
- **不能**据此宣称免费工具"能发现"这些漏洞；`validated_vulnerability` 仍为 0。

### 新增 OH 专用规则 `oh-nothrow-alloc-unchecked-deref`

- 来源（ground truth 反推）：dsoftbus 修复 `192f3e11` 在每个 `new (std::nothrow) ...` 之后插入 `if (x == nullptr) { ...; return ...; }`。规则把 vulnerable pattern 定义为"nothrow 分配结果被 `->` 解引用且中间无 null 检查"。
- 文件：`rules/cpp/oh_nothrow_null_deref.yaml`，CWE-476，`root_cause_group=null_deref`，confidence=MEDIUM。
- 判别力（实测）：vulnerable 5 命中 / fixed 0 / cutils·liteos·ark 全 0 误报。
- 边界：命中只证明"nothrow 分配结果被无守卫解引用"；**不证明**分配失败可被攻击者触发、也不证明可利用。仍非 validated vulnerability。

---

## 6b.9 2026-10-06 CodeQL（C++）可行性实测：工具可用，但不适用于单文件样本粒度

### 安装与"能跑起来"的部分

- CodeQL CLI **2.27.1**（`codeql-linux64.zip`，416 MB，sha256 与官方 checksum 一致），解压于 `/root/bench-scan/codeql/codeql`；查询包 `codeql/cpp-queries@1.9.0` + 库 `codeql/cpp-all@12.1.1`。
- 踩坑记录：用 `python3 -m zipfile` 解压**会丢失可执行位**，`extractor`/`java` 静默不可执行，症状是建库时报 `CodeQL detected code C/C++ but could not process any of it`。必须按 zip 的 `external_attr` 还原权限（本次还原 3052 个文件）。
- 对照组（证明工具本身可用）：一个自包含 `main.cpp`（`strcpy` + `malloc`）→ `cpp-security-and-quality` 套件正确报出 `cpp/unbounded-write`（L7），提取质量 303 funcs / 12 calls / 38 stmts。

### 样本实测（4 样本 × 2 修订，`--build-mode=none`，全套件 `cpp-security-and-quality.qls`）

| 样本 | 建库 | 提取质量（funcs / calls / stmts） | 套件结果 |
|---|---|---|---|
| cutils `singleton.h` | **失败**（DB 无 `db-cpp` 数据集） | — | — |
| liteos `process_syscall.c` | 成功 | 164 / 126 / 612 | **0** |
| dsoftbus `bus_center_client_proxy.cpp` | 成功 | **3 / 0 / 4** | **0** |
| ark `js_array.cpp` | 成功 | **2 / 0 / 0** | **0** |

即：**vuln 版本上一无所获**，且提取出的 AST 近乎为空。

### 根因（已验证，不是工具缺陷）

- C/C++ 分析必须以**可编译的翻译单元**为单位。样本是"从仓库里抠出来的单文件"，其 8 个 `#include "..."`（`bus_center_client_proxy.h`、`lnn_log.h`、`softbus_def.h` …）在样本树中都不存在——**但用 `git ls-tree` 核实，它们全部存在于仓库树中**。头文件缺失 → 提取退化为空 AST。
- `--build-mode=none` 不能替代构建：自包含文件能正常提取，一旦缺头文件就退化为空（对照实验可直接复现）。
- 显式 `--command "g++ -fsyntax-only ..."` 同样失败（`fatal error: bus_center_client_proxy.h: No such file or directory`）。

### 为什么没有继续走"全仓库 + 真实构建"

本机目标仓库是 `--filter=blob:none` 的 **partial clone**，checkout 需按需从 GitHub 拉 blob。实测：全量 checkout 跑 16 分钟仍未完成（网络对 GitHub 抖动），**仅头文件**的 checkout 也用了 6m41s，且中途把工作树清空导致源文件丢失。OpenHarmony 的真实构建还需要 gn/ninja 与生成头文件，成本远超单文件 benchmark 的收益。

### 结论与影响

- **CodeQL（以及同样依赖编译的 Clang Static Analyzer）在单文件样本粒度上不可用**。原因不是工具不行，而是 benchmark 的**分析单元与工具要求不匹配**。
- 矩阵中的 `codeql` / `clang_sa` 两列**不应继续记为"待补的 unknown"**；在单文件粒度下应标为 `not_applicable`，若要使用则必须另立"全仓库 + 真实构建"的独立工作流。
- 本轮为**保留失败结果**（见第 7 节底线"实验必须保留失败结果"），不写入任何 hit/miss 结论。
- 安装产物保留在 `/root/bench-scan/codeql/`（WSL 本机，未入库），后续如做全仓库分析可直接复用。

---

## 6c. 下一步建议

优先做：

```text
1. ✅ 已完成 2026-10-06：移除 deref-after-arrow 噪音规则，重跑 4 样本矩阵（ark 144→4），dsoftbus 旧 36 条被 OH 专用规则取代；详见 6b.8
2. 为 oob_write 家族写 OH 专用规则（针对 ElementAccessor::Get/Set 缺失 GetElementsLength 检查），
   验证"专用规则能否补上通用工具的 0 精确命中"
3. ✅ 已完成 2026-10-06（CodeQL 侧）：工具装好且可用（对照样本命中 `cpp/unbounded-write`），但**单文件样本粒度下不适用**——缺头文件导致 AST 近乎为空、4 样本 0 结果；`codeql` / `clang_sa` 两列在单文件粒度应记 `not_applicable`，详见 6b.9。若要用，需另立"全仓库 + 真实构建"工作流（含 ClangSA）
4. ✅ 已完成 2026-10-06：registry 可达性已复测；结论是免费 registry **没有** cpp 规则，改用 0xdea 镜像（MIT），差异见 6b.8
5. ⏳ 部分完成：null_deref 家族已补 `oh_nothrow_null_deref`（vuln 5 / fixed 0）；concurrency_race 家族仍待补
6. 为 concurrency_race 家族补 OH 专用规则（liteos GetGroups 锁作用域竞争），验证 raptor/官方 C 规则确无根因命中
7. （可选）若能取得 Semgrep 付费 pro 账号，用 154 条 `cpp.*` pro 规则对比 raptor + OH 专用层的覆盖面
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
