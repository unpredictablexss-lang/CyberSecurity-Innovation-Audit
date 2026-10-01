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

- [2026 总体架构：docs/architecture_2026.md](docs/architecture_2026.md)
- [系统设计：docs/design.md](docs/design.md)
- [开发路线：docs/roadmap.md](docs/roadmap.md)
- [赛题要求拆解：docs/competition_requirements.md](docs/competition_requirements.md)
- [评价指标：docs/evaluation_criteria.md](docs/evaluation_criteria.md)

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

## 当前状态

项目初始化阶段。

下一步优先完成：**C/C++ 小型验证原型：候选规则 → AST → Finding → ASan/UBSan 验证 → VulnerabilityCase → 报告 → Patch 重验**。跑通闭环后再扩大到 OpenHarmony 具体模块。
