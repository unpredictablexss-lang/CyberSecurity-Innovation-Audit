# CyberSecurity-Innovation-Audit

面向网络安全创新大赛的自动化源代码安全审计系统。

> 本项目用于授权的安全测试、代码审计、漏洞研究与竞赛环境。请勿用于未经授权的攻击行为。

## 项目目标

结合传统静态分析、程序分析与大语言模型能力，对源码进行自动化安全审计，并输出结构化漏洞报告。

项目希望逐步实现：

- 多语言源码扫描与语言识别
- AST / 函数 / 变量 / 调用关系提取
- 基础漏洞规则匹配
- 数据流与污点传播分析
- 可疑代码片段自动提取
- LLM 辅助漏洞研判
- 漏洞风险评级与置信度评估
- 自动生成审计报告与修复建议
- 多文件、跨函数联合分析

## 2026 赛题架构文档

当前项目已经从通用源码审计骨架进一步收敛到 **OpenHarmony 开源代码漏洞挖掘** 赛题。

核心变化：不再把“规则命中”当成最终结果，而是采用 **漏斗式候选发现 → 程序分析 → 多证据误报抑制 → PoC/动态验证 → 跨版本影响 → Patch 重验** 的闭环架构。

**新增项目准则：高价值、真实危害、可复核证据优先。** 我们优先研究具有实际越权、敏感信息泄露、代码执行、内存安全、严重拒绝服务或信任边界突破后果的漏洞；对单纯版本信息、公开静态资源、无证据的配置提示等低价值告警只作研究线索，不包装成“已验证漏洞”。优先对照真实公开漏洞、官方修复前后与相似安全代码，查找根因变体；AI 猜测和规则命中永远不能代替可达性、攻击前提和实际影响的证明。完整门槛见 [三线并行总方案 §0.1 高价值漏洞原则](docs/strategy/ohscanner_three_track_master_plan.md#01-高价值真实危害与历史根因优先团队统一准则)。

- [2026 总体架构：docs/architecture_2026.md](docs/architecture_2026.md)
- [Teammate A 静态扫描技术指南](docs/teammate_a_static_scan_tech_guide.md)
- [技术文档索引](docs/technical_documentation_index.md)
- **[下一阶段三线并行总方案：自研 OHScanner 架构 / 分工 / 集成 / 验收](docs/strategy/ohscanner_three_track_master_plan.md)**（计划）
- **[自研检测器插件 Contract v1：队友必须遵守的输入/输出接口](docs/contracts/ohscanner_detector_contract_v1.md)**（拟实施、尚未在代码冻结）
- **[OHScanner 队友开发接入指南（M0/M1 实际可运行代码）](docs/strategy/ohscanner_teammate_development_guide.md)**（A/B 首先阅读）
- **[M2 第一方 Detector 真源码执行、Ubuntu 复测与队友接入规范](docs/testing/ohscanner_m2_first_party_integration.md)**（`ohscan-run` 统一执行入口）
- **[M2-A 队友 A C++ 检测器接入及 Ubuntu 复测指南](docs/testing/ohscanner_m2_a_integration.md)**（已登记 lifetime / shared_ptr race 两个自研研究候选，尚未确认为漏洞）
- [2021–2026 OpenHarmony 历史漏洞数据集与多扫描器实验协议](docs/strategy/vulnerability_corpus_bakeoff_protocol.md)（研究计划）
- [Web / ArkTS / IPC 方向专项开发任务书](docs/strategy/oh_web_interface_track.md)（队友 B）
- [系统设计：docs/design.md](docs/design.md)
- [开发路线：docs/roadmap.md](docs/roadmap.md)
- [赛题要求拆解：docs/competition_requirements.md](docs/competition_requirements.md)
- [评价指标：docs/evaluation_criteria.md](docs/evaluation_criteria.md)

## 当前建议的研发组织（规划）

正式核心产品以**自主实现的 OpenHarmony 专用检测器**为主：历史漏洞公开修复对用于离线评测成熟扫描器的根因识别、修复区分、误报与覆盖能力，并据此提炼、改造检测算法；正式扫描阶段不是根据漏洞类型自动调用 Semgrep/CodeQL 等外部工具。

由负责人建设统一的 SourceUnit/ScanContext/Detector 契约、引擎调度、证据链、Review/Report；队友 A 建 C/C++ 漏洞实验和检测器；队友 B 建 Web/ArkTS/IPC 权限与接口安全实验和检测器。**目前这套自研插件契约是设计稿，不代表 main 已具备该能力。** 已实现模块和待完成项仍以 [PROGRAM_STATUS.md](PROGRAM_STATUS.md) 为准。

## 总体技术路线

```text
源码输入
   ↓
语言识别与预处理
   ↓
代码解析 / AST
   ↓
规则扫描
   ↓
程序分析
   ├─ 调用图
   ├─ 控制流图
   ├─ 数据流分析
   └─ 污点分析
   ↓
可疑代码片段提取
   ↓
LLM 二次审计
   ↓
漏洞去重 / 风险评级
   ↓
结构化审计报告
```

## 系统分层

### 1. 代码解析层

负责文件遍历、语言识别、AST、函数、变量、import/include 与调用关系提取。

对应目录：`src/parser/`

### 2. 规则检测层

通过规则快速定位危险函数、不安全 API、输入校验缺失、路径操作、命令执行、数据库拼接、内存安全和 Web 风险。

对应目录：`src/rules/` 与 `rules/`

### 3. 程序分析层

逐步实现 CFG、调用图、数据流分析、污点分析以及 Source → Propagation → Sink 跨函数追踪。

对应目录：`src/analyzer/`

### 4. LLM 审计层

利用大语言模型对静态分析筛选出的高风险片段做二次研判，包括复杂上下文、业务逻辑、多文件分析、漏洞解释、修复建议和误报抑制。

对应目录：`src/llm/`

### 5. 报告层

单个漏洞至少输出：漏洞名称、CWE、风险等级、文件路径、行号、函数、Source、Sink、传播路径、证据代码、漏洞原因、触发条件、修复建议和置信度。

## 计划支持的漏洞类型

### Web / 服务端

- SQL Injection
- Command Injection
- Path Traversal
- Arbitrary File Read / Write
- File Upload
- SSRF
- XSS
- Template Injection
- Unsafe Deserialization
- Authentication / Authorization Logic Issues

### C / C++

- Buffer Overflow
- Out-of-Bounds Read / Write
- Use After Free
- Double Free
- Null Pointer Dereference
- Integer Overflow
- Format String
- Dangerous Memory Operations
- Resource Management Issues

### Python / Java 等

- 命令执行
- SQL 注入
- 路径操作
- 不安全反序列化
- 动态代码执行
- 弱加密 / 不安全随机数
- 敏感信息泄露
- 权限与业务逻辑问题

## MVP：第一版最小可行系统

```text
源码目录
  ↓
扫描文件
  ↓
语言识别
  ↓
基础规则检测
  ↓
可疑片段提取
  ↓
LLM 辅助分析
  ↓
JSON / Markdown 漏洞报告
```

第一版暂时不追求完整的全程序污点分析，优先保证：能运行、能扫描、能发现候选风险、能解释、能生成报告、后续容易扩展。

## 项目目录

```text
CyberSecurity-Innovation-Audit/
├── README.md
├── requirements.txt
├── docs/
│   ├── competition_requirements.md
│   ├── design.md
│   └── roadmap.md
├── src/
│   ├── parser/
│   ├── rules/
│   ├── analyzer/
│   ├── llm/
│   └── utils/
├── rules/
│   ├── cpp/
│   ├── java/
│   ├── python/
│   └── web/
├── samples/
│   ├── vulnerable/
│   └── safe/
├── tests/
├── scripts/
├── outputs/
│   ├── reports/
│   └── logs/
├── models/
└── config/
```

## 仓库结构与职责

当前仓库按“文档设计、分析引擎、规则库、样例与测试、运行产物、配置与依赖”进行组织，各目录职责如下：

1. `README.md`：项目目标、整体技术路线、五层架构、计划漏洞类型、MVP、开发阶段。
2. `docs/competition_requirements.md`：之后整理正式赛题要求。
3. `docs/design.md`：系统架构和 Finding 数据结构设计。
4. `docs/roadmap.md`：从 MVP 到比赛版本的开发路线。
5. `src/parser/`：源码解析。
6. `src/rules/`：规则引擎。
7. `src/analyzer/`：CFG、数据流、污点分析。
8. `src/llm/`：大模型辅助审计。
9. `src/utils/`：公共工具。
10. `rules/cpp/`、`rules/java/`、`rules/python/`、`rules/web/`：不同语言与漏洞方向的外部规则库。
11. `samples/vulnerable/` 和 `samples/safe/`：漏洞样例与安全对照样例。
12. `tests/`：单元测试、回归测试和分析准确性验证。
13. `scripts/`：环境初始化、批量扫描、Benchmark、数据准备等辅助脚本。
14. `outputs/reports/`：生成的漏洞分析报告。
15. `outputs/logs/`：扫描日志、调试日志、性能与执行记录。
16. `models/`：本地模型、模型配置或后续实验相关文件。
17. `config/`：扫描范围、规则开关、模型参数、运行参数等配置。
18. `requirements.txt`：Python 依赖列表。

对应目录结构：

```text
CyberSecurity-Innovation-Audit/
├── README.md
├── requirements.txt
├── docs/
│   ├── competition_requirements.md
│   ├── design.md
│   ├── roadmap.md
│   ├── architecture_2026.md
│   ├── evaluation_criteria.md
│   └── ...
├── src/
│   ├── parser/
│   ├── rules/
│   ├── analyzer/
│   ├── llm/
│   └── utils/
├── rules/
│   ├── cpp/
│   ├── java/
│   ├── python/
│   └── web/
├── samples/
│   ├── vulnerable/
│   └── safe/
├── tests/
├── scripts/
├── outputs/
│   ├── reports/
│   └── logs/
├── models/
└── config/
```

## 开发阶段

### Phase 1 — 基础扫描框架

- [ ] 文件递归扫描
- [ ] 语言识别
- [ ] 统一 Finding 数据结构
- [ ] 基础规则引擎
- [ ] Markdown / JSON 报告输出

### Phase 2 — 规则库

- [ ] Web 类漏洞
- [ ] Python 风险规则
- [ ] Java 风险规则
- [ ] C / C++ 内存安全规则
- [ ] 测试样例与回归测试

### Phase 3 — 程序分析

- [ ] AST
- [ ] 调用图
- [ ] CFG
- [ ] 数据流
- [ ] 污点分析
- [ ] 跨函数追踪

### Phase 4 — LLM 辅助审计

- [ ] 可疑片段上下文构造
- [ ] Prompt 模板
- [ ] 漏洞二次判断
- [ ] 修复建议生成
- [ ] 误报抑制

### Phase 5 — 比赛完善

- [ ] Web / CLI 操作界面
- [ ] 可视化调用链与污点路径
- [ ] 批量项目扫描
- [ ] Benchmark
- [ ] 准确率 / 召回率 / 误报率评估
- [ ] 比赛演示样例
- [ ] 技术文档与答辩材料

## 当前可运行的 MVP

当前实现是 **C/C++ 文本候选扫描器**，不是已确认漏洞检测器。命中危险调用后只生成 `status = candidate`；置信度、严重程度暂为 `unassessed`。CWE 只是候选分类，必须结合上下文和运行证据重新判断。它仍可能命中注释、声明或安全调用，也可能漏掉宏、别名和跨行写法；不要用两个自建样例宣称真实项目的准确率。

在仓库根目录运行（Python 3.10+，无需额外 Python 依赖）：

```bash
python -m src.cli scan samples \
  --json-out outputs/reports/samples_report.json \
  --md-out outputs/reports/samples_report.md
python -m unittest discover -s tests -v
```

预期扫描 2 个 C/C++ 文件、28 行，生成 1 个候选；两个报告位于 `outputs/reports/` 且已被 Git 忽略。旧的 `--out` 仍可作为 `--json-out` 的别名。扫描统计仅表示当前文本规则实际读取的文件和行数，不是代码解析覆盖率或安全覆盖率。

下一阶段优先选取**固定提交、可构建、可测试**的真实 OpenHarmony C/C++ 组件，记录构建配置与扫描范围，再做上下文分析和 ASan/UBSan 验证；只有验证证据充分时才升级为可报告漏洞。详细进度见 [PROGRAM_STATUS.md](PROGRAM_STATUS.md)。
