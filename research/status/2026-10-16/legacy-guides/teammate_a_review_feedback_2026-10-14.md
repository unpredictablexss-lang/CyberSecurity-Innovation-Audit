# 队友 A 静态扫描能力审查反馈与下一阶段任务计划

> 反馈日期：2026-10-14  
> 项目：`CyberSecurity-Innovation-Audit`  
> 角色：队友 A / C/C++ 静态检测线  
> 反馈对象：`OHScanner队友A静态扫描能力审查与LLMAgent准入建议.md`  
> 文档性质：基于本次独立实跑结果的审查反馈、任务拆解和负责人协作请求。  
> **证据边界**：本文严格区分“源码已实现”“本次独立实跑结果”“仓库历史记录”“审查推断”和“尚未证实”。未执行的扫描、未提供的外部语料、未建立的产品级入口和未完成的动态验证，不写成已完成能力。

## 1. 审查范围与代码基线

### 1.1 当前代码状态

本次核对的仓库状态：

| 项目 | 本次核对结果 |
|---|---|
| 当前分支 | `codex/teammate-a-static-module-20261013` |
| 当前 HEAD | `e27f744acb60d3c1bd45f6d3d9a4d07f9b2528cf` |
| 审查基线 | `460f212f372a11698c92ece89a820480e1bcb398` |
| 基线到当前 HEAD 的变化 | 仅 README 和技术文档新增，无检测器代码变化 |
| 工作区状态 | 无未提交的跟踪文件变更 |

因此，审查中指出的 `shared_ptr_race_detector.py` P0 边界不是已经被后续代码修复的问题。当前 HEAD 相比审查提交只有文档变化，算法代码仍需整改。

### 1.2 已阅读并纳入判断的项目约束

本次已阅读：

- `docs/architecture_2026.md`
- `PROGRAM_STATUS.md`
- `docs/strategy/ohscanner_three_track_master_plan.md`
- `docs/contracts/ohscanner_detector_contract_v1.md`
- `docs/contracts/ohscanner_detector_contract_v2.md`
- `docs/strategy/team_parallel_multi_scanner_plan.md`
- `docs/strategy/competition_deliverables_plan.md`
- 本次提供的《OHScanner 队友 A 静态扫描能力审查与 LLM / Agent 准入建议》

当前适用边界：

1. historical benchmark 是独立证据模块，不等于 OHScanner 自研 Detector 的主动漏洞覆盖。
2. 自研 Detector 的生产执行路径不能依赖外部大扫描器。
3. `candidate` 是默认起点，不是最终漏洞结论。
4. 只有满足 `AGENTS.md` 的 Evidence gate，才允许升级到 `confirmed` / `reportable`。
5. PoC、动态验证、CWE/CVE、影响范围、修复建议、性能和漏洞报告是赛题必须交付物。
6. 线上生产服务不攻击；动态验证只在本地隔离环境进行。

---

## 2. 对审查结论的逐项确认与修正

### 2.1 G1：扫描工程基础

**确认：基本达到，但不是完整语义审计能力。**

源码已经具备：

- 固定 Git 提交、tree/blob 和源码 SHA-256 绑定；
- C/C++ Tree-sitter 轻量解析和解析覆盖记录；
- `SourceUnit` / `ScanContext` / `DetectorRun` 等最小插件协议；
- 第一方 detector 显式 Catalog；
- `ToolRunResult` / `ToolDiagnostic` 桥接；
- detector 失败隔离和逐文件 coverage sidecar；
- historical benchmark、工具结果归一化和报告入口；
- `ReadOnlyFactView` 的只读事实访问。

但 G1 仍不能写成“全量真实产品构建已完成”：

- 完整 OpenHarmony 产品 GN 构建、完整宏/模板实例化和产品级 TU 语义尚未建立；
- `parse_status=complete` 只说明语法解析完成，不说明 CFG、类型、别名、guard 或 reachability 已完成；
- `completed` 只表示指定范围执行结束，不是安全判定；
- `candidate_count=0` 不是组件安全证明。

### 2.2 G2：漏洞检测能力

**确认：未通过。**

当前 A 线第一方主动检测主要覆盖：

| 检测器 | 当前能力 | 判断 |
|---|---|---|
| `ohscanner.cpp.lifetime` | `unique_ptr` owner/raw alias/reset/stale-use 的窄生命周期候选 | 仅为候选生成 |
| `ohscanner.cpp.shared_ptr_race` | `shared_ptr` 成员普通访问、atomic 形式和词法 mutex 的窄并发候选 | 仅为候选生成，且存在 P0 漏报边界 |
| `ohscanner.interface.ipc` | 接口/IPC/权限边界候选 | 接口线成果，不替代 C++ 程序分析 |
| `ohscanner.example.cpp.copy-calls` | 合成调用点枚举 | 非安全检测器 |

审查矩阵中关于 OOB、NULL、整数溢出、类型混淆、信息泄露、Double Free 的判断应保持：当前没有足够的 A 线第一方通用 Detector 证明这些家族已被主动覆盖。历史 CVE、Semgrep、CodeQL、Clang SA、Infer、Joern 的记录只能说明研究基线或历史证据存在，不能改写为 A 自研检测能力。

### 2.3 P0：`shared_ptr` mixed atomic/non-atomic 误抑制

**修正审查措辞：从“审查推断的风险”升级为“本次已独立复现的漏报边界”。**

审查原文说明该问题“尚未在本次审查中独立运行精确反例证明实际输出”。本次已经实际执行精确反例，当前实现确实返回 0 finding，详见第 4 节。

### 2.4 G3：LLM / Agent 准入

**确认：只读原型可以启动，自动误报排除和漏洞升级不能开放。**

`ReadOnlyFactView` 当前适合：

- 读取固定源码上下文；
- 读取 syntax facts；
- 读取 detector 结果；
- 读取解析 coverage；
- 读取已有 `EvidenceObligation`；
- 形成调查问题、缺失证据清单和人工复核建议。

当前不能让 Agent：

- 把 `candidate` 自动改为 `confirmed`；
- 把 `possible_hit` 当 true positive；
- 把 `completed` 或 0 findings 当 safe；
- 用模型生成的调用链、guard 或数据流替代可复核证据；
- 自动删除低分候选或把 `unknown` 改为安全。

### 2.5 历史 benchmark 与第三方工具

**确认：审查口径正确。**

历史样本、工具 warning 和 query 输出必须继续绑定 sample、repository、commit、revision、tool、scope 和 source artifact。第三方工具的：

- 无报警不能证明安全；
- `completed` 不能证明目标家族被完整分析；
- query-style CodeQL 输出不能自动改写为 dataflow；
- 诊断数量不能换算成漏洞数量；
- historical fix parent 不能未经核验自动当 ground truth。

---

## 3. 本次实际运行结果

### 3.1 运行环境

本次复核使用：

```text
WSL2: Linux 6.18.54.1-microsoft-standard-WSL2
Ubuntu: 22.04
Python: 3.10.12
Git: 2.34.1
```

以下结果均为本次在当前 HEAD `e27f744` 上执行的结果，不是从历史文档复制的状态。

### 3.2 shared_ptr 定向回归

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -q"
```

结果：

```text
Ran 28 tests in 17.513s

OK
```

结论边界：

- 这 28 项测试通过，只能证明当前已有测试断言全部通过；
- 不能证明 mixed atomic/non-atomic 的同步判断正确；
- 当前测试中已有 `test_mixed_atomic_and_mutex_paths_are_separately_limited`，它断言 mixed 情形 `finding_count=0`，该断言本身需要修正。

### 3.3 静态模块定向回归

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.test_static_module_contracts tests.detectors.test_cpp_shared_ptr_race_detector tests.detectors.test_cpp_lifetime_detector tests.detectors.test_cpp_shared_ptr_race_fixture_verify -q"
```

结果：

```text
Ran 65 tests in 25.380s

OK
```

这组结果覆盖：

- 静态模块契约；
- `shared_ptr` detector；
- `lifetime` detector；
- shared_ptr fixture evidence 验证。

仍然不能由该结果推出真实 OpenHarmony 漏洞检出率、Precision、Recall 或可利用性。

### 3.4 全量回归

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest discover -s tests -q"
```

结果：

```text
Ran 640 tests in 124.079s

FAILED (errors=1, skipped=10)
```

失败项：

```text
tests/test_ipc_entry_index.py::EntryIndexTests::test_corpus_ipc_object_stub_send_request_dispatch
FileNotFoundError:
/home/audit/openharmony-audit/perf-corpus/communication_ipc/interfaces/innerkits/ipc_core/include/ipc_object_stub.h
```

原因分析：

```python
@unittest.skipUnless(os.path.isdir(CORPUS), "perf-corpus/communication_ipc not present")
```

当前环境存在 `CORPUS` 目录，但缺少该测试所需的 header/source 文件，因此 skip 条件没有触发，测试进入执行后失败。

判断：

- 这是外部 corpus/测试夹具缺口；
- 不是 A 线 `shared_ptr` 或 `lifetime` 检测器回归失败；
- 本次无法复现历史文档中的“640 tests、11 skipped、OK”；
- 后续需由负责人/接口线补齐固定语料，或修正测试 skip 条件，或显式标记为 external-corpus integration test。

### 3.5 历史源码绑定验证

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m scripts.verify_historical_source_bindings"
```

结果：

```text
3/3 verified
```

已验证样本：

| sample_id | CVE | vulnerable commit | fixed commit | 状态 |
|---|---|---|---|---|
| `arkcompiler_ets_runtime-atomic-index-overflow-2025-03` | CVE-2025-0587 | `cae11f121c030a90ba41d8e4d866f91292f25892` | `5aa9c035e98911ec7ed28065a2138c2709792a42` | `verified` |
| `arkcompiler_ets_runtime-typedarray-filter-confusion-2025-09` | CVE-2025-27536 | `8299f560e7c51b2b988180fed44457dca63c4a54` | `0e2a01bba2345e5650e09bae36092237b010f254` | `verified` |
| `kernel_liteos_a-os-copy-user-param-bypass-2025-03` | CVE-2025-21098 | `f83c7205e7d685a999e5de360423c13db1886453` | `e6eb21f55e4768f6cfbf09cedb0b35259bafcb4b` | `verified` |

验证内容包括 vulnerable/fixed commit、blob SHA-1、source SHA-256、patch SHA-256。该结果证明历史来源绑定完整，不证明 A 线已经主动发现或检测这三个 CVE。

### 3.6 编译和差异检查

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m compileall -q src scripts tests"
```

结果：

```text
compileall: passed
```

命令：

```bash
git diff --check
```

结果：

```text
git diff --check: passed
```

### 3.7 M0 synthetic contract smoke

命令：

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m src.cli ohscan --fixture-root tests/fixtures/ohscanner"
```

结果：

```text
[OK] M0 synthetic contract smoke; NOT a real vulnerability scan
[OK] normalized first-party detector runs: 2
[OK] target provenance: fixture
[OK] json report: outputs/reports/ohscanner_m0.json
[OK] markdown report: outputs/reports/ohscanner_m0.md
```

该命令验证插件注册、统一运行和报告桥接，不是真实 OpenHarmony 漏洞扫描。

### 3.8 `ReadOnlyFactView` 实跑

实跑结果：

```json
{
  "call_path": {
    "status": "unknown",
    "source": "entry",
    "destination": "sink",
    "reason": "No validated cross-function call graph is available in ScanContext."
  },
  "guard_facts": {
    "status": "unknown",
    "reason": "syntax facts were not supplied"
  }
}
```

这验证了审查判断：

- Agent 可以读取已有事实；
- Agent 不能把 `unknown` 变成调用链、guard dominance 或数据流证明；
- 未实现的语义接口必须保持 `unknown`，不能返回猜测路径。

---

## 4. `shared_ptr` P0 独立复现结论

### 4.1 复现代码形状

本次使用审查中指出的 mixed atomic/non-atomic 形状：

```cpp
#include <atomic>
#include <memory>
#include <mutex>

class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;

    static std::shared_ptr<int> ReadAtomic() {
        return std::atomic_load(&instance_);
    }

    static void UpdateGuarded(std::shared_ptr<int> next) {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_ = std::move(next);
    }
};
```

关键语义：

- `ReadAtomic()` 使用 `std::atomic_load(&instance_)`；
- `UpdateGuarded()` 对同一 `instance_` 做普通写入；
- 普通写入只持有 `mutex_`；
- 原子读取线程没有持有同一 mutex。

因此，单独存在 `mutex_` 不能证明原子读取和普通写入之间不存在并发冲突。

### 4.2 当前 Detector 实跑输出

`SharedPtrRaceDetector` 当前返回：

```json
{
  "status": "completed",
  "finding_count": 0,
  "findings": [],
  "limitations": [
    "Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.",
    "No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.",
    "completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.",
    "all modeled non-atomic accesses to 'Holder::instance_' share reliable lexical mutex 'mutex_' in this translation unit; atomic_load/store and mutex paths are modeled separately, and this is a narrow suppression rather than a cross-function concurrency proof."
  ]
}
```

### 4.3 问题定位

当前 `_analyze_unit()` 的关键路径是：

```python
non_atomic = [access for access in accesses if not access.atomic]
common_mutex = _common_mutex(non_atomic)
if common_mutex is not None:
    continue
```

该条件只验证被识别出的普通访问之间是否有共同 mutex，然后抑制该成员的候选。它没有：

- 对 atomic access 与 non-atomic access 做冲突对分析；
- 证明所有访问线程遵循同一同步协议；
- 证明 atomic API 和 mutex 路径之间不存在并发交错；
- 处理跨函数、锁别名、不同锁或单侧锁的完整关系；
- 在同步关系不确定时保留 candidate/unknown。

### 4.4 对现有测试的修正要求

现有测试：

```python
def test_mixed_atomic_and_mutex_paths_are_separately_limited(self):
    ...
    self.assertEqual(run.findings, ())
```

当前断言把 mixed atomic/non-atomic 的 0 finding 当成了预期结果。下一阶段应改为：

- mixed 情形不得静默 suppress；
- 至少产生 candidate/unknown；
- finding 仍只能是 `candidate/unassessed`；
- `EvidenceObligation` 记录 `synchronization_proof` 等未证明项；
- 不得直接写 `confirmed`、`safe` 或 `validated`。

---

## 5. G1 / G2 / G3 当前判断

| Gate | 本次判断 | 现有证据 | 仍缺什么 |
|---|---|---|---|
| G1 扫描工程 | 基本达到 | 固定来源、解析、Catalog、M2、coverage、报告、只读事实、定向回归 | 产品构建 profile、完整宏/模板/跨 TU 语义 |
| G2 漏洞检测 | 未达到 | `lifetime`、`shared_ptr_race` 两个窄研究候选；历史样本和工具实验 | CFG、symbol identity、def-use、guard dominance、lock proof、NULL/OOB/Integer 第一方 Detector、独立 holdout |
| G3 可信智能审计 | 未达到 | `ReadOnlyFactView` 可读取已有事实 | 版本绑定的语义查询、确定性 evidence gate、动态重验、可追溯 Agent 操作记录 |

资源分配建议保持审查结论：

1. A 主线优先修 `shared_ptr` P0；
2. 负责人维护公共 IR、Contract、Runner、Catalog、Agent/PoC/报告平台；
3. 只读 Agent 原型可以并行，但没有候选状态升级权；
4. B 线的 IPC/接口能力不能替代 C++ 内存安全 G2 验收。

---

## 6. 下一阶段任务拆解

### A-P0-01：修复 `shared_ptr` mixed-access 抑制边界

负责人：队友 A。

代码范围：

- `src/ohscanner/detectors/cpp/shared_ptr_race_detector.py`
- `tests/detectors/test_cpp_shared_ptr_race_detector.py`
- 对应 method card / detector README / 适用边界说明

#### 实现原则

1. 建立访问记录：

```text
read/write × atomic/non-atomic × lock identity × function/location
```

2. 对潜在冲突访问对逐对分析，不再只对所有 `non_atomic` 访问求共同 mutex。
3. 以下情形不能直接 suppress：
   - atomic read/write 与普通 read/write 混合；
   - 不同 mutex；
   - 单侧锁；
   - `try_to_lock`；
   - `defer_lock`；
   - 锁身份不确定；
   - 跨函数访问；
   - atomic API 与 mutex 路径没有共同协议证明。
4. 上述情形返回 `candidate/unknown`，并增加 `EvidenceObligation("synchronization_proof", ...)`。
5. 只有所有潜在冲突访问均被可靠同步协议覆盖时，才允许窄范围抑制。
6. 保持原有安全负例：
   - atomic-only；
   - 所有普通访问处于同一可靠 mutex；
   - 非目标类型；
   - unrelated shape。

#### 首批回归矩阵

| 场景 | 预期 |
|---|---|
| atomic read + mutex-protected ordinary write | candidate/unknown |
| atomic write + mutex-protected ordinary read | candidate/unknown |
| mixed atomic/non-atomic + different mutex | candidate |
| one-sided mutex | 只报告未保护访问 |
| `try_to_lock` | blocked/unknown，不 suppress |
| `defer_lock` | blocked/unknown，不 suppress |
| all non-atomic + same reliable mutex | 无 finding，但保留窄同步限制 |
| atomic-only safe | 无 finding |
| local shadow | 不误绑定同名局部变量 |
| global/member same name | 只绑定目标成员 |
| namespace/class qualified member | 保持绑定正确 |

#### 交付要求

- 先写失败回归，再修改实现；
- 记录失败 -> 通过；
- 更新 detector version；
- 更新 method card 的同步适用边界；
- 记录仍为 unknown 的跨函数、锁别名、模板和真实构建限制；
- 不把 mixed 场景写成 safe；
- 不把候选写成 confirmed/reportable。

### A-P0-02：提交共享语义事实接口提案

负责人：项目主负责人；队友 A 提交 Contract Change Request，不直接修改共享实现。

拟议只读接口：

```text
get_symbol(path, position)
get_cfg_path(function, source_node, sink_node)
get_dataflow(source, sink, budget)
get_guard_proof(node, guard)
get_lock_state(function, location)
get_build_context(commit, file)
get_source_context(path, range)
get_detector_results(candidate_id)
get_coverage(detector_id, path)
```

接口要求：

- 状态至少区分 `observed / proven / unknown / failed`；
- 记录 `proof_ref`；
- 记录有限分析范围；
- 缺少 CFG、dataflow、guard 或 lock 证明时返回 `unknown`；
- 不能返回看似可信的猜测路径；
- 不修改 `contracts.py`、`runner.py`、`frontend.py`、`catalog.py` 或 `ToolRunResult v1`，除非负责人批准 CCR。

### A-P0-03：跨版本 Finding identity CCR

当前 `analysis.py` 使用：

```text
file:line:rule_id
```

在源代码上方插入注释后，同一根因的行号可能整体变化，造成：

```text
disappeared + new
```

应向负责人申请加入：

- symbol/function identity；
- syntax node / expression fingerprint；
- patch-region mapping；
- source binding。

在 CCR 批准前，A 线不直接修改公共 `analysis.py`。

### A-P1-03：NULL Detector v1

在 P0 和最小语义事实接口可用后，优先实现 NULL dereference v1：

- 指针可能为空；
- 检查是否在真实解引用之前；
- guard 是否支配 sink；
- 错误路径是否提前返回；
- 不能只看附近是否出现 `if`。

必须交付：

- method card；
- vulnerable/fixed/safe/unrelated fixture；
- 独立 holdout 设计；
- coverage/failed 状态；
- contract-compatible result；
- deterministic unit tests；
- 可复现命令；
- `EvidenceObligation`。

之后再扩展：

1. Bounds/OOB v1；
2. Integer -> allocation/copy/index v1。

### A-P1-04：外部工具保持研究基线

Clang SA、CodeQL、Infer、Joern 只用于：

- 离线实验；
- 能力矩阵；
- 方法卡依据；
- 交叉验证；
- 失败和 coverage 记录。

不得：

- 进入自研 Detector 的生产执行依赖；
- 把第三方 warning 当 A 自研覆盖；
- 把无报警当安全；
- 把 query 输出无依据地改写为 dataflow。

---

## 7. 公共接口与负责人协作事项

以下事项由负责人决定，A 线只提交提案、测试和证据：

1. `ReadOnlyFactView` 的 CFG/dataflow/guard/lock/build-context API；
2. 公共 IR 扩展；
3. stable Finding identity；
4. Detector Catalog production registration；
5. Contract v2 后续变更；
6. Agent workflow、任务队列、凭据和资源隔离；
7. PoC 执行沙箱和漏洞状态升级 Gate；
8. `src/report/vulnerability_report.py` 的正式报告集成；
9. main 合并、PR ready 和远程 push。

测试环境协作项：

`tests/test_ipc_entry_index.py` 需由负责人/接口线修复：

- 提供固定 `perf-corpus/communication_ipc`；
- 或把 skip 条件改为检查 header/source 具体文件；
- 或标记为显式 external-corpus integration test。

A 线不修改接口线测试，也不把该环境错误解释为 C++ 检测器失败。

---

## 8. 限制、unknown 与禁止表述

### 8.1 当前必须保持的 unknown

- 真实 OpenHarmony 产品构建和完整 TU/宏/模板语义；
- `shared_ptr` mixed atomic/non-atomic 的同步证明；
- 跨函数 alias、call graph、guard dominance、lock ownership；
- OOB/NULL/Integer 等家族的 A 线第一方主动 Detector 能力；
- 独立 holdout Precision / Recall；
- 产品级入口、攻击者控制和权限边界；
- 未运行的动态验证；
- 外部 corpus 缺失环境下的完整回归结果。

### 8.2 禁止表述

以下表述不得出现在后续报告或 PR 中：

- “该组件没有漏洞”；
- “0 findings 证明安全”；
- “completed 等于扫描完整”；
- “parse complete 等于语义分析完成”；
- “历史 CVE 绑定等于主动发现”；
- “CodeQL/Clang/Infer/Joern 命中等于 A 自研检出”；
- “warning 数量等于漏洞数量”；
- “mixed atomic/non-atomic 已被 mutex 正确保护”；
- “LLM 认为是漏洞”作为确认依据；
- “未运行工具等于 miss”。

### 8.3 允许表述

- “候选 / possible_hit / unassessed”；
- “本次执行范围已完成，但仍有 coverage limitation”；
- “历史来源绑定 verified”；
- “动态验证未运行，因此保持 unknown”；
- “满足 Evidence gate 后才可升级为 confirmed/reportable”；
- “本地隔离环境中的组件级复现，不等于产品级入口可利用”。

---

## 9. 后续复现命令

### 9.1 当前环境

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python --version && git --version && uname -sr"
```

### 9.2 shared_ptr 定向回归

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -q"
```

### 9.3 静态模块定向回归

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest tests.test_static_module_contracts tests.detectors.test_cpp_shared_ptr_race_detector tests.detectors.test_cpp_lifetime_detector tests.detectors.test_cpp_shared_ptr_race_fixture_verify -q"
```

### 9.4 全量回归

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest discover -s tests -q"
```

### 9.5 历史源码绑定

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m scripts.verify_historical_source_bindings"
```

### 9.6 编译和差异检查

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m compileall -q src scripts tests"

git diff --check
```

### 9.7 M0 synthetic smoke

```bash
wsl.exe -d Ubuntu-22.04 --exec /bin/bash -lc \
  "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m src.cli ohscan --fixture-root tests/fixtures/ohscanner"
```

---

## 10. 结论

本次反馈同意审查的主要结论：

1. A 线已经有真实的静态扫描工程基础；
2. 但主动漏洞检测仍集中在较窄的生命周期和并发所有权候选；
3. G2 尚未达到赛题所需的 C/C++ 语义审计能力；
4. 只读 LLM/Agent 原型可以启动；
5. 自动误报排除、漏洞确认和 `reportable` 升级暂不开放。

本次新增的最重要事实是：审查指出的 `shared_ptr` mixed atomic/non-atomic P0 已由实际代码形状独立复现，当前 Detector 会因为普通访问共享 mutex 而返回 0 finding。该问题必须先于新 Detector 扩展修复，并且现有 mixed 场景测试的断言必须同步纠正。

后续坚持：

```text
底层确定性证据先成立
    -> Agent 读取、解释和组织验证
    -> PoC / sanitizer / patch revalidation
    -> Evidence gate
    -> confirmed / reportable
```

本轮不推送、不建 PR、不标 ready、不合并 main。下一阶段代码改动需先由负责人确认共享接口和任务边界。
