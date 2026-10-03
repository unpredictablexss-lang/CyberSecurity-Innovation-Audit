# OpenHarmony 团队双线并行与多扫描器增强实施总方案

> 更新日期：2026-10-04  
> 适用项目：CyberSecurity-Innovation-Audit  
> 当前分支：feat/historical-vuln-benchmark  
> 文档性质：将《OpenHarmony 漏洞挖掘团队分工与双线并行实施方案》和《OpenHarmony 漏洞挖掘项目：多扫描器对比、融合与增强方案》整合为一份当前可执行的团队/技术总方案。  
> 当前实现状态以仓库根目录 PROGRAM_STATUS.md 为准；本文中的后续路线属于计划，不代表已经完成。

## 1. 总原则：纵向闭环不停止，横向工具研究并行

当前项目已经完成真实组件 onboarding 的第一条工程闭环，因此不应让全员停下主线、重新从零研究工具。

团队采用两条核心路线并行：

~~~text
纵向主线
Candidate
→ Context
→ Triage
→ Security Obligation
→ Static / Runtime Evidence
→ VulnerabilityCase

横向研究线
Semgrep / CodeQL / Clang SA / Cppcheck
→ 统一 Benchmark
→ 统一 Adapter
→ ToolRunResult / ToolDiagnostic
→ Evidence
→ 互补性分析
~~~

两条线最终通过统一数据协议汇合，而不是直接拼接各工具实现。

如果有第三位成员，可以单独承担动态与 Web/API/IPC 攻击面研究；但当前 historical-vuln-benchmark 分支的本轮工作只推进静态工具 benchmark 与结果归一化，不扩展漏洞触发或 PoC。

## 2. 当前项目基线

截至本方案整合时，项目已经具备：

- 固定 repo / commit / scan scope；
- 文本 Candidate；
- 函数上下文；
- Candidate Triage；
- Clang Static Analyzer baseline；
- 受控 Runtime Validation Gate；
- Evidence / VulnerabilityCase 基础模型；
- Tree-sitter AST 索引；
- historical ground-truth benchmark runner；
- 第一条 c_utils singleton.h UAF 历史样本；
- 多工具统一 ToolRunResult / ToolDiagnostic 数据协议。

因此下一阶段重点不是继续增加危险 API 名字，而是用真实历史样本回答：

1. 哪类真实根因当前工具能发现；
2. 哪类根因当前工具会漏掉；
3. 不同静态工具真正提供什么互补证据；
4. 哪些能力值得形成 OpenHarmony 专用增强层。

## 3. 最终作品目标

最终作品不应表述为：

> 我们用了很多扫描器。

更合适的系统叙事是：

> 基于真实 OpenHarmony 历史安全样本，对模式匹配、数据流、路径敏感分析和动态验证进行统一实验，将异构工具输出归一化为 Candidate / Evidence，在多阶段低误报漏斗中逐步完成上下文研判、语义确认和验证，最终形成可解释、可复现的 VulnerabilityCase。

推荐总架构：

~~~text
OpenHarmony
    ↓
TargetSnapshot / ScanScope
    ↓
┌──────────────┬──────────────┬──────────────┐
│ Fast Scan    │ Program      │ Optional Web │
│ Own/Semgrep  │ CodeQL/Clang │ /API/IPC     │
└──────┬───────┴──────┬───────┴──────┬───────┘
       ↓              ↓              ↓
             Candidate / Evidence
                    ↓
              Candidate Triage
                    ↓
             Security Obligations
                    ↓
       Static Deep Review / Validation
                    ↓
             VulnerabilityCase
                    ↓
       CWE / CVE / Version / Patch / Report
~~~

## 4. 统一数据契约

### 4.1 TargetSnapshot

回答“分析的是哪一份代码”。

核心字段：

~~~yaml
target_id:
project: OpenHarmony
component:
repo_url:
commit:
branch_or_tag:
source_paths:
exclude_paths:
build_command:
test_command:
toolchain:
build_profile:
~~~

正式实验不得只写“当前 master”。必须固定 commit 与 scan scope。

### 4.2 Candidate

回答“哪里值得调查”。

~~~yaml
candidate_id:
target_id:
provider:
rule_id:
file:
function:
line:
candidate_cwe:
candidate_type:
evidence:
context:
status: candidate
~~~

任何工具报警都只能先作为 Candidate。

### 4.3 Evidence

回答“什么证据支持或反驳候选”。

推荐 evidence_type：

- pattern
- syntax
- dataflow
- control_flow
- symbolic
- historical
- runtime
- permission
- web_dynamic
- human_review
- unknown

多工具同时命中不是投票机制，而是不同 Evidence 类型的补充。

### 4.4 CandidateReview

保存当前研判进度：

~~~yaml
candidate_id:
review_status:
input_control:
destination_capacity:
length_origin:
guard_evidence:
reachability:
security_impact:
runtime_validation:
reviewer:
notes:
next_action:
~~~

推荐状态：

~~~text
unreviewed
needs_context
likely_safe_static
interesting
runtime_worthy
refuted
inconclusive
validated_component
validated_target
reportable
~~~

### 4.5 RuntimeEvidence

动态证据与静态 Candidate 分离存储。当前分支不会新增漏洞触发或 PoC 实现；这里只保留接口边界。

### 4.6 VulnerabilityCase

只有根因去重且证据充分后建立。Candidate 数量不能直接等同于漏洞数量。

## 5. 多扫描器统一比较的四个核心工具

| 工具 | 主要角色 | 默认证据角色 |
|---|---|---|
| Semgrep | 快速规则候选 | Pattern Evidence |
| CodeQL | 数据流 / 污点 / 跨函数 | Dataflow Evidence |
| Clang Static Analyzer | 路径敏感 / 符号分析 | Symbolic / Path Evidence |
| Cppcheck | 轻量 C/C++ baseline | Lightweight Static Evidence |

工具角色是实验假设，最终能力矩阵必须由 benchmark 数据填写，不能拍脑袋。

## 6. 为什么不依赖单一扫描器

不同分析范式存在天然能力边界：

- 规则工具适合大规模快速筛选；
- 数据流工具适合 Source → Propagation → Sink；
- 路径敏感工具适合判断某条条件路径是否可达；
- 轻量工具适合作低成本 baseline；
- 动态验证提供运行事实，但不负责全仓覆盖。

因此采用：

~~~text
快速扫描负责广度
+
深度分析负责确认
+
动态证据负责验证
~~~

而不是让一个工具承担全部任务。

## 7. Benchmark 的统一实验口径

所有工具尽可能保持：

- 相同 commit；
- 相同源码范围；
- 相同硬件；
- 相同超时；
- 相同统计单位；
- 相同 historical ground-truth 样本。

统计单位优先使用 root cause，而不是 warning。

同一个根因出现在多个调用点或多个版本时，不应重复计成多个漏洞。

## 8. Historical Benchmark 规则

历史样本优先来自：

- OpenHarmony 历史安全修复；
- 官方安全公告；
- 公开 CVE；
- 明确 security fix commit。

Fix commit 的父提交不能未经核验自动标记为严格 ground truth。

样本应继续核对：

- 公告；
- 补丁；
- 版本；
- CWE / CVE；
- 实际根因；
- 是否 partial fix / backport。

当前 historical runner 的 replay_status 与 runtime_validation 边界继续保持，不因为 benchmark miss 而修改规则“刷通过率”。

## 9. 评价指标

在有充分标注的历史样本上，可以逐步统计：

- TP / FP / FN；
- Precision；
- Recall；
- CWE 覆盖；
- 扫描时间；
- Peak RSS；
- 跨函数能力；
- 路径解释；
- candidate_root_causes。

但当前未标注源码不能直接宣称全局 Recall。

当前源码更适合统计：

- Candidate 数量；
- Top-K 人工审核有效率；
- 唯一根因数量；
- 人工审核成本；
- failed / blocked 分析数；
- files / LOC 覆盖；
- 时间与内存。

## 10. 不做简单投票式融合

禁止第一版采用：

~~~text
Semgrep 报警 + Clang 报警
→ 两个工具都报
→ 判定漏洞
~~~

不同工具提供的是不同证据：

~~~text
Semgrep → Pattern
CodeQL → Dataflow
Clang → Path / Symbolic
Tree-sitter → Syntax
Historical Replay → Historical
Runtime → Runtime
~~~

Evidence Fusion 第一版应保存证据和状态迁移，不做无法解释的拍脑袋加权。

## 11. 当前统一多工具输出协议

当前分支使用：

- ToolRunResult：描述一次工具运行；
- ToolDiagnostic：描述一条归一化静态诊断；
- AdapterContext：提供 target / commit / scope / time / memory 等运行上下文；
- normalize_tool_output(provider, payload, context)：统一结果转换入口。

ToolRunResult 至少记录：

- tool / version；
- target_id / commit；
- scope_files / scope_loc；
- status；
- elapsed_seconds；
- peak_memory_mb；
- diagnostics；
- limitations。

ToolDiagnostic 至少记录：

- provider；
- evidence_type；
- file / line / column；
- rule_id；
- severity；
- message；
- candidate_cwe；
- confidence。

默认 confidence 为 unassessed。

## 12. 四个 Adapter 的职责边界

当前 adapter 只负责“格式转换”。

~~~text
Semgrep JSON
    ↓
SemgrepAdapter
    ↓
ToolRunResult

CodeQL SARIF
    ↓
CodeQLAdapter
    ↓
ToolRunResult

Clang baseline JSON
    ↓
ClangSAAdapter
    ↓
ToolRunResult

Cppcheck XML
    ↓
CppcheckAdapter
    ↓
ToolRunResult
~~~

Adapter 不负责：

- 运行外部扫描器；
- 生成 PoC；
- 触发漏洞；
- 判断 exploitability；
- 把 warning 升级成 validated vulnerability。

主线以后只需要读取统一结果，不需要了解每种原生格式。

## 13. 团队分工

### A：纵向真实问题闭环

职责：

- 真实目标固定；
- Candidate → Context → Review；
- 根因分析；
- Validation evidence；
- Case / Version / Report。

A 的目标不是“每天多写几条规则”，而是推动 Candidate 状态发生有证据的变化。

### B：多扫描器 Benchmark 与 OpenHarmony 增强

职责：

- historical benchmark；
- Semgrep / CodeQL / Clang / Cppcheck；
- provider adapter；
- 统一 ToolRunResult；
- Tool Capability Matrix；
- OpenHarmony 专用 Source/Sink/API 模型研究。

B 的成果不是“安装成功”，而是“同一 benchmark 上产生可复现、可归一化、可比较的数据”。

### C：动态 / Web/API / IPC（可选第三人）

职责可以包括：

- Fuzz / Sanitizer；
- WebView / HTTP / API；
- IPC / Permission；
- Attack Surface Map。

当前 historical-vuln-benchmark 分支不实现该线的漏洞触发内容。

## 14. 两人团队降级方案

如果只有两人：

- 人 1：Vertical + Runtime / Case；
- 人 2：Scanner Benchmark + Evidence Adapter；
- Web/API/Fuzz 只选择已有真实攻击面的一项，不同时铺满。

## 15. 目录协作建议

推荐边界：

~~~text
src/
├── providers/
│   ├── semgrep.py
│   ├── codeql.py
│   ├── clang_sa.py
│   ├── cppcheck.py
│   ├── base.py
│   └── registry.py
├── benchmark/
├── core/
├── parser/
├── triage/
└── validation/

benchmarks/
├── historical/
└── tool_comparison/

docs/
├── strategy/
├── testing/
├── reviews/
└── targets/
~~~

共同接口优先稳定，再各自扩工具。

## 16. Git 与 PR 规则

不同路线使用独立 feature branch。

每个 PR 必须回答：

1. 解决什么问题；
2. 输入是什么；
3. 输出是什么；
4. 怎样复现；
5. 跑了什么测试；
6. 哪些结论仍 unknown。

推荐 PR 描述：

> 将 Semgrep JSON 转换为 ToolDiagnostic v1，并在固定 fixture 上验证解析。

不推荐：

> 支持漏洞检测。

## 17. Stop-Loss

### 纵向线

- 真实组件长时间不可构建 → 换目标；
- 只有危险 API、没有真实输入路径 → 不进入动态验证；
- 只有普通健壮性崩溃 → 作为 quality issue，而不是硬包装安全漏洞。

### 多扫描器线

- CodeQL 环境长时间阻塞 → 暂时保留 Semgrep + Clang + Cppcheck；
- 工具安装成功但没有统一 benchmark → 不算成果；
- 结果无法归一化 → 先修 Adapter，不继续增加新工具。

### 动态/Web 线

只有真实攻击面存在时再使用对应动态工具，不为了展示工具而制造场景。

## 18. 当前分支的近期执行顺序

historical-vuln-benchmark 当前顺序：

~~~text
1. 扩充可信 historical ground truth
2. 固定 vulnerable / fixed pair
3. 运行现有 scanner / AST replay
4. 接入多工具 Adapter
5. 对同一历史样本收集 Semgrep / CodeQL / Clang / Cppcheck 结构化结果
6. 生成 Tool Capability Matrix
7. 识别真实 blind spot
8. 再决定 OpenHarmony 专用增强规则 / 数据流模型
~~~

当前不因为 benchmark miss 修改规则“刷分”。

## 19. 最终 Tool Capability Matrix

最终应由实验填表：

| 能力 | Own | Semgrep | CodeQL | Clang SA | Cppcheck |
|---|---:|---:|---:|---:|---:|
| Pattern | | | | | |
| Dataflow | | | | | |
| Cross-function | | | | | |
| Path | | | | | |
| C++ native | | | | | |
| OH custom model | | | | | |
| Speed | | | | | |
| Explainability | | | | | |

再建立 root-cause 互补矩阵：

| Root Cause | Own | Semgrep | CodeQL | Clang | Cppcheck | Dynamic |
|---|---|---|---|---|---|---|
| Case-001 | | | | | | |
| Case-002 | | | | | | |
| Case-003 | | | | | | |

## 20. 创新点收敛

整合两份方案后，优先保留以下可答辩创新点：

1. OpenHarmony 异构静态分析证据归一化；
2. Historical ground truth 驱动的工具能力评估；
3. Pattern / Syntax / Dataflow / Path / Runtime 的多证据模型；
4. 低误报的多阶段 Candidate 漏斗；
5. 历史安全补丁驱动的安全约束迁移；
6. 后续跨版本语义传播与修复重验闭环。

创新重点不是重新实现 Parser / CFG / Dataflow / Symbolic Executor，而是复用成熟底层能力，把创新集中在 OpenHarmony 场景适配、证据归一化、误报抑制、历史 benchmark 与验证闭环。

## 21. 团队统一底线

所有成员遵守：

1. warning != vulnerability；
2. candidate != vulnerability；
3. crash != exploitable security issue；
4. no warning != safe；
5. no CVE != 0-day；
6. historical fix parent != automatically ground truth；
7. 真实实验必须固定 commit；
8. 失败结果必须保留；
9. 报告结论必须可追溯到 Evidence；
10. 不为创新重复实现成熟底层分析器；
11. 不为了漏洞数量牺牲误报控制；
12. 重要结果必须可被另一成员复现；
13. 工具比较以 root cause 为单位，不以 warning 数量为单位；
14. 纵向真实问题主线优先于无边界工具扩张。

## 22. 本轮实现边界

本轮已经开始搭建：

~~~text
Semgrep Adapter
CodeQL Adapter
Clang SA Adapter
Cppcheck Adapter
→ normalize_tool_output(...)
→ ToolRunResult / ToolDiagnostic
~~~

这些 Adapter 只进行结果格式归一化。

本轮明确不做：

- 漏洞触发；
- PoC；
- exploitability 自动判定；
- 运行时攻击链；
- 以扫描器投票代替漏洞验证。

后续只有在 historical benchmark 与真实 Candidate Review 提供充分证据后，再决定下一层实现。
