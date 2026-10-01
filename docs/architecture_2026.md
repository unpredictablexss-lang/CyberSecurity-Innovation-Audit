# 2026 OpenHarmony 漏洞挖掘系统架构设计

> 本文是 2026 赛题的主架构文档。目标不是做一个“规则扫描器 + LLM”，而是实现一套面向 OpenHarmony 大规模源码的 **漏洞发现 → 深度确认 → PoC 验证 → 影响分析 → 修复 → 重验 → 报告** 闭环系统。
>
> 设计原则：比赛评分导向优先、真实漏洞优先、误报控制优先、可验证证据优先、全量扫描与深度分析分层。

---

## 1. 为什么今年必须重新设计架构

2025 年的核心对象是 Git Commit / Diff，重点是从“已经发生的安全修复”反推漏洞，并继续判断跨分支修复状态。

2026 年的核心对象变成 **当前源码本身**。系统必须主动回答：

1. 当前代码是否存在真实安全漏洞；
2. 外部输入能否到达危险点；
3. 安全检查是否真正覆盖危险路径；
4. 漏洞能否被稳定触发；
5. 哪些版本/分支受影响；
6. 如何修复，并证明修复后原 PoC 不再触发。

因此，今年的主链路必须从：

```text
规则命中 → LLM 判断 → 报告
```

升级为：

```text
大规模源码
   ↓
快速候选发现
   ↓
程序语义分析
   ↓
多证据风险排序
   ↓
PoC / 动态验证
   ↓
漏洞定级与 CWE/CVE
   ↓
跨版本影响
   ↓
修复建议 / Patch
   ↓
修复后重验
   ↓
结构化报告 + Benchmark
```

---

## 2. 总体架构：漏斗式九层体系

```text
┌──────────────────────────────────────────────┐
│ L0 代码资产与版本层                          │
│ Repo / Branch / Commit / Module / Language   │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│ L1 代码解析与索引层                          │
│ AST / Symbol / Function / Call / Include     │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│ L2 快速候选发现层                            │
│ Rules / Dangerous API / Patch Pattern / Risk │
└──────────────────────┬───────────────────────┘
                       ↓
             Candidate Findings（高召回）
                       ↓
┌──────────────────────────────────────────────┐
│ L3 深度程序分析层                            │
│ CFG / Data Flow / Taint / Lifecycle / Auth   │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│ L4 多证据融合与误报抑制层                    │
│ Reachability / Guards / Context / Evidence   │
└──────────────────────┬───────────────────────┘
                       ↓
              High-Value Candidates
                       ↓
┌──────────────────────────────────────────────┐
│ L5 漏洞验证与 PoC 层                         │
│ Harness / Build / Run / Sanitizer / Repro    │
└──────────────────────┬───────────────────────┘
                       ↓
              Validated Vulnerabilities
                       ↓
┌──────────────────────────────────────────────┐
│ L6 漏洞知识与分类层                          │
│ CWE / CVE / Severity / Dedup / Root Cause    │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│ L7 跨版本影响与修复闭环层                    │
│ Branch / Fingerprint / Patch / Re-validation │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│ L8 报告、可视化与性能层                      │
│ Report / Trace / Dashboard / Benchmark       │
└──────────────────────────────────────────────┘
```

核心思想不是“每层都对所有文件执行”，而是让候选逐层减少：

```text
100% 源码
  ↓ 快速扫描
5%~15% 候选
  ↓ 程序分析
1%~5% 高风险候选
  ↓ 深度验证
少量可报告真实漏洞
```

比例只表示架构目标，不是固定阈值，最终由实验数据决定。

---

## 3. L0：代码资产与版本层

### 目标

解决“大规模 OpenHarmony 到底扫描什么”的问题。

### 输入

- OpenHarmony 仓库
- master / Release 分支
- commit / tag
- 本地指定源码目录

### 需要实现

- 仓库元数据索引
- branch / commit / tag 管理
- 文件与语言识别
- 模块分类
- 安全敏感模块标签
- 增量变更检测
- 扫描范围与跳过原因记录

### 推荐目录

```text
src/
└── asset/
    ├── repository.py
    ├── version.py
    ├── module_index.py
    └── change_detector.py
```

### 关键设计

全量扫描不能每次从零开始。建议给每个文件建立：

```text
repo + commit + path + content_hash
```

作为缓存键。源码没有变化时，可以直接复用解析与部分分析结果。

---

## 4. L1：代码解析与索引层

### 目标

建立后续程序分析共同依赖的中间表示，而不是每个检测器重复解析代码。

### 最小索引

- 文件
- 函数 / 方法
- 类 / 结构体
- 变量
- include / import
- 函数调用
- 定义 / 引用
- source location

### C/C++ 优先路线

OpenHarmony 的底层代码使 C/C++ 分析必须成为主线之一。技术实现优先级建议：

1. **Tree-sitter**：快速文件级解析、统一 AST、适合首版；
2. **Clang AST / LibTooling**：用于需要类型、宏、精确 C/C++ 语义的深度分析；
3. 编译数据库可用时再接入 `compile_commands.json`，不要让“必须完整编译”成为第一版前置条件。

建议不要一开始强依赖整个 OpenHarmony 完整构建成功，而是：

```text
轻量解析成功 → 进入快筛
有编译信息 → 进入更精确分析
解析失败 → 标记降级，不中断全局扫描
```

---

## 5. L2：快速候选发现层

这是全量扫描的主力，目标是 **高覆盖 + 低成本**，不是直接宣布漏洞成立。

### 5.1 C/C++ 候选引擎

第一批规则优先覆盖：

- 危险内存复制/格式化 API
- 长度与分配尺寸不一致
- 下标/长度来自外部输入
- 整数运算结果进入分配、拷贝或索引
- free/delete 后潜在继续访问
- 重复释放
- NULL/状态检查缺失
- 权限敏感调用
- 文件/路径/命令执行类 sink
- 敏感数据输出/日志

### 5.2 Web / 服务接口候选引擎

Web 选手并不是没有用。OpenHarmony 中可以重点看：

- 外部参数 → system/popen/exec 类命令执行
- 外部路径 → 文件读写
- URL → 网络请求
- JS / WebView / Native Bridge
- IPC / RPC 参数 → 敏感系统能力
- 鉴权/权限检查缺失
- 序列化/解析输入 → 危险操作
- 日志/接口返回 → 敏感信息泄露

统一建模为：

```text
Source → Propagation → Sink
```

这样 Web 审计和 C++ 内存安全最终使用同一套 Finding / Trace 基础设施。

### 5.3 历史补丁知识驱动候选

这是今年很值得做成创新点的模块。

历史安全补丁可以抽象出：

```text
漏洞修复前模式 A → 安全模式 B
```

今年扫描时重点搜索：

> 其他模块里是否仍存在与 A 相似、但没有 B 保护的代码？

逐步从简单到复杂：

1. Token / API 模式
2. AST 结构
3. Guard 条件
4. Source-Sink 数据流
5. 调用链/语义图

历史补丁不再是最终检测对象，而是“漏洞知识来源”。

---

## 6. L3：深度程序分析层

只有 L2 中的高风险候选进入这一层。

### 6.1 CFG：判断危险点是否真的可达

重点回答：

- guard 是否支配 sink；
- 是否存在绕过检查的另一条路径；
- 错误路径是否遗漏释放；
- 权限检查是否覆盖所有敏感路径。

### 6.2 数据流与污点分析

统一抽象：

```text
Source
  ↓
Assignment / Argument / Return / Field / Arithmetic
  ↓
Sink
```

重点记录：

- Source 类型
- 传播步骤
- Sanitizer / Guard
- Sink
- 跨函数边
- 路径置信度

### 6.3 生命周期分析

对 UAF / Double Free 不能只靠危险函数规则，应建立对象状态：

```text
Created
  ↓
Initialized
  ↓
Referenced
  ↓
Released
  ↓
Forbidden-to-use
```

发现：

- release 后仍有访问；
- 不同分支释放状态不一致；
- 异步回调/事件队列持有旧引用；
- 多线程状态下生命周期竞争。

首版可先实现函数内/有限跨函数状态机，再逐步扩大范围。

### 6.4 权限与逻辑分析

重点建立：

```text
External Entry
    ↓
Caller Identity
    ↓
Permission Check
    ↓
Sensitive Operation
```

重点发现：

- 敏感路径未经过权限检查；
- 同类 API 权限检查不一致；
- 客户端可控字段被服务端信任；
- 状态切换后沿用旧授权；
- 检查与使用之间存在明显 TOCTOU 风险。

---

## 7. L4：多证据融合与误报抑制

不要使用一个“万能总分”解决所有问题。

建议每个 Finding 至少记录四个独立维度：

```text
static_confidence        静态结构像不像漏洞
reachability_confidence  Source 是否能到 Sink
security_impact          是否具有真实安全影响
validation_status        是否已经动态验证
```

### 证据分级

#### E1：模式证据
危险 API、危险状态、历史补丁模式等。

#### E2：语法证据
AST 参数关系、对象关系、类型信息。

#### E3：路径证据
CFG、数据流、污点路径、权限链。

#### E4：动态证据
ASan / UBSan / 崩溃栈 / 越权行为 / 非预期数据。

#### E5：稳定复现证据
同一 PoC 在目标环境多次成功。

最终只有高等级证据结果进入正式比赛漏洞报告。

---

## 8. L5：PoC 与动态验证必须提前建设

今年 PoC 不是最后“补一段代码”，而是核心判真模块。

### 8.1 PoC 生成过程

```text
Finding
  ↓
提取入口、参数、关键条件、环境
  ↓
选择漏洞类型模板
  ↓
生成 Harness / 输入
  ↓
Build
  ↓
Run
  ↓
捕获验证证据
  ↓
最小化 PoC
  ↓
重复执行
```

### 8.2 不同漏洞类型的验证方式

| 漏洞类型 | 主要验证证据 |
|---|---|
| OOB / Buffer Overflow | ASan、crash、越界报告 |
| Integer Overflow | UBSan + 后续内存/索引安全影响 |
| UAF / Double Free | ASan、heap-use-after-free、double-free |
| NULL Deref | crash + 可控触发路径 |
| Command Injection | 隔离环境内可观察命令副作用 |
| Path Traversal | 越权读取/写入测试文件 |
| Permission Bypass | 低权限身份完成本应禁止的操作 |
| Information Disclosure | 返回/读取未授权数据 |
| Logic Vulnerability | 状态机或权限边界被实际突破 |

### 8.3 Sandbox 原则

PoC Runner 必须使用隔离测试环境：

- Docker / VM / 专用测试机
- 超时
- CPU / 内存限制
- 网络默认受控
- 测试目录隔离
- 日志完整留存

系统设计目标是验证授权竞赛环境中的漏洞，而不是提供无约束攻击执行器。

### 8.4 PoC 状态机

```text
not_generated
generated
build_success
run_success
trigger_success
stable_reproduced
```

正式报告优先收录 `trigger_success` 及以上结果。

---

## 9. L6：CWE / CVE / 严重度 / 去重

### CWE

不要只通过“命中规则名”直接映射。输入应综合：

- root cause
- source
- sink
- memory / arithmetic / permission behavior
- validation evidence

### CVE

只在有足够证据时关联：

- 文件/函数
- 版本
- 历史补丁
- 安全公告
- 漏洞行为

不能因为“都是 UAF”就猜同一个 CVE。

### 去重与根因聚类

同一个根因可能在：

- 多个路径
- 多个调用点
- 多个版本

重复出现。建议生成：

```text
Vulnerability Case
├─ root_cause
├─ primary_location
├─ related_findings[]
├─ affected_versions[]
└─ evidence_bundle
```

而不是把几十条重复 Finding 当几十个漏洞。

---

## 10. L7：跨版本影响 + 修复 + 重验

### 跨版本五级证据

1. 相同位置/函数直接比对
2. AST 结构相似
3. Source-Sink / 调用链语义相似
4. 历史补丁 / 等价补丁
5. 关键漏洞在目标版本上重新运行 PoC

最终状态：

```text
affected
fixed
not_present
unknown
```

### Patch 闭环

```text
Validated Vulnerability
        ↓
Root Cause
        ↓
Patch Candidate
        ↓
Static Re-scan
        ↓
Original PoC Re-run
        ↓
Regression Test
        ↓
Patched / Needs Review
```

这比单纯给出“建议增加边界检查”更有竞争力。

---

## 11. LLM 应该放在哪里

LLM 不做全库首轮扫描器，优先放在它真正擅长的环节：

- 高风险代码上下文解释
- 跨文件语义摘要
- 复杂调用链辅助研判
- 历史安全补丁模式抽象
- PoC Harness 草案
- 修复 Patch 草案
- CWE 候选解释
- 漏洞报告生成
- 人工复核辅助

关键漏洞事实必须尽量由：

```text
Code Evidence + Program Analysis + Runtime Evidence
```

支撑，而不是“LLM 认为这是漏洞”。

建议 LLM 输出始终保存：

```text
model_output
supporting_evidence_ids
review_confidence
human_review_status
```

---

## 12. 核心数据结构：从 Finding 升级到 Vulnerability Case

### 12.1 Finding

表示某个分析器发现的一条候选证据。

```yaml
id:
rule_id:
file:
function:
line_range:
vulnerability_type:
candidate_cwe:
source:
sink:
trace:
guards:
evidence:
static_confidence:
reachability_confidence:
security_impact:
validation_status:
```

### 12.2 Vulnerability Case

表示去重、验证后的漏洞根因。

```yaml
case_id:
title:
root_cause:
cwe:
cve:
severity:
primary_location:
related_findings:
source_to_sink_trace:
trigger_conditions:
poc:
runtime_evidence:
affected_modules:
affected_versions:
patch:
patch_validation:
confidence:
report_status:
```

### 12.3 Evidence

所有结论必须能够追溯到 Evidence：

```yaml
evidence_id:
type: rule | ast | cfg | dataflow | taint | runtime | git | llm
source:
location:
content:
confidence:
```

这是后续可解释、去重、报告、答辩的基础。

---

## 13. 推荐代码目录调整

当前目录可以继续沿用，但建议逐步升级为：

```text
src/
├── asset/              # 仓库、分支、模块、增量扫描
├── parser/             # AST、符号、函数索引
├── rules/              # 高速候选规则
├── analyzer/
│   ├── callgraph/
│   ├── cfg/
│   ├── dataflow/
│   ├── taint/
│   ├── lifetime/
│   ├── permission/
│   └── constraints/
├── knowledge/
│   ├── cwe/
│   ├── cve/
│   └── patch_patterns/
├── validator/
│   ├── harness/
│   ├── builder/
│   ├── runner/
│   ├── sanitizer/
│   └── minimizer/
├── version/
│   ├── branch_analyzer/
│   ├── fingerprint/
│   └── patch_tracker/
├── remediation/
│   ├── patch_generator/
│   └── patch_validator/
├── llm/
├── report/
├── benchmark/
└── utils/
```

外部数据目录建议：

```text
data/
├── repo_index/
├── history_patches/
├── cve_cache/
└── benchmarks/

artifacts/
├── findings/
├── cases/
├── poc/
├── evidence/
├── patches/
└── reports/
```

---

## 14. Web + C++ 两人队伍的合理分工

### Web / 安全审计方向

重点负责：

- Source / Sink 模型
- Command Injection
- Path Traversal
- Arbitrary File Read/Write
- SSRF/URL 请求链
- JS / WebView / Native Bridge
- IPC 接口、鉴权、权限逻辑
- 敏感信息泄露
- 历史漏洞知识整理
- 漏洞报告与 Web 可视化

### C++ 方向

重点负责：

- C/C++ Parser / Clang 集成
- Buffer/OOB
- Integer Overflow
- UAF / Double Free
- 生命周期状态机
- CFG / 数据流基础设施
- Harness、编译、ASan/UBSan
- PoC 稳定复现
- Patch 编译与重验

### 两人共同

- Finding / Evidence 数据结构
- 候选排序
- Git / 分支影响
- Benchmark
- Demo
- 最终漏洞人工复核

这能让 Web 和 C++ 技能真正汇合，而不是各做一套互不相关的扫描器。

---

## 15. 开发优先级：PoC 要前移，LLM 要后移

建议顺序：

### P0：跑通“候选 → 验证 → 报告”最小闭环

先选少量自建/历史已知安全样例，实现：

```text
C/C++ 源码
 ↓
规则候选
 ↓
AST 上下文
 ↓
Harness
 ↓
ASan/UBSan
 ↓
Validated Finding
 ↓
Markdown Report
```

如果这一条跑不通，不应该急着做复杂 AI。

### P1：扩大候选类型

优先：

- Buffer/OOB
- Integer Overflow → memory impact
- UAF/Double Free
- Command Injection
- Path Traversal
- Permission / Sensitive Data

### P2：程序分析降误报

- CFG
- Source-Sink
- Taint
- Guard
- 有限跨函数

### P3：历史补丁知识与跨版本

这是很适合比赛创新展示的一块。

### P4：LLM 辅助

在已有证据基础上增强，而不是替代前面的确定性分析。

### P5：全量性能、可视化、答辩

---

## 16. 第一版真正应该做什么

第一版不要追求“自动挖所有 OpenHarmony 0-day”。

第一版只需要证明整个架构成立：

```text
1. 输入 C/C++ 项目
2. 扫描并发现 3~5 类候选
3. 至少 1~2 类能够进入 Source/Path 深度分析
4. 至少一种内存漏洞能够自动构造/运行验证 Harness
5. 保存 sanitizer 证据
6. 输出 CWE、触发条件、证据链、PoC、修复建议
7. 修复后重跑原 PoC，确认不再触发
8. 记录扫描耗时和内存
```

做到这里，项目才真正从“代码扫描框架”变成“2026 赛题原型”。

---

## 17. 当前最值得主打的三个创新点

### 创新点 A：历史安全补丁知识反向驱动未知漏洞发现

```text
历史 Fix
 ↓
提取 Vulnerable Pattern
 ↓
语义泛化
 ↓
扫描其他模块
 ↓
发现尚未修复同类风险
```

### 创新点 B：多层证据 + 动态验证反馈的误报抑制

不是单纯算分，而是：

```text
Rule
 + AST
 + CFG
 + Taint
 + Runtime
 + Reproducibility
```

逐层提升证据等级。

### 创新点 C：发现—PoC—Patch—重验闭环

最终向评委展示：

```text
系统找到漏洞
→ PoC 稳定触发
→ 自动/辅助产生 Patch
→ 原 PoC 无法再次触发
→ 回归测试通过
```

这个闭环比单纯“扫描出很多告警”更能证明作品价值。

---

## 18. 暂时不要做的事情

- 不要第一版就完整实现全程序符号执行；
- 不要一开始就全量编译整个 OpenHarmony；
- 不要把所有文件无差别发给 LLM；
- 不要把“危险 API 出现”直接算漏洞；
- 不要为了数量输出大量未验证 Finding；
- 不要把 PoC 放到项目最后才补；
- 不要同时平均投入 Web、Java、Python、C/C++ 四条语言线。

当前应以 **OpenHarmony 相关 C/C++ + 接口/权限/路径类漏洞** 为主，先做深，再逐步扩展。

---

## 19. 项目验收问题

每一个里程碑都用这些问题检查：

1. 系统扫了多少代码？覆盖率是多少？
2. 为什么这个候选被选中？
3. Source 在哪里？Sink 在哪里？
4. 哪条路径能够到达？
5. 哪个安全检查存在或缺失？
6. 这个问题为什么是安全漏洞而不是普通 Bug？
7. PoC 是否真的触发？
8. 动态证据是什么？
9. 哪些分支/版本受影响？
10. Patch 为什么能修？
11. 修复后原 PoC 是否失败？
12. 整个过程耗时和资源占用是多少？

只要这些问题能够被系统数据直接回答，架构就基本对准了今年的比赛目标。
