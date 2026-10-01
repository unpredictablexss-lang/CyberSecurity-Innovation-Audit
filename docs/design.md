# System Design

## 1. 目标架构

系统采用“快速筛选 + 深度分析 + LLM 研判”的组合架构。

```text
Repository
   ↓
Scanner
   ↓
Parser
   ↓
Rule Engine
   ↓
Program Analyzer
   ↓
Candidate Findings
   ↓
LLM Reviewer
   ↓
Dedup / Severity / Confidence
   ↓
Report
```

## 2. 核心数据对象

建议后续统一定义 Finding：

- id
- rule_id
- vulnerability_type
- cwe
- severity
- confidence
- file
- start_line
- end_line
- function
- source
- sink
- trace
- evidence
- explanation
- remediation

统一数据结构可以避免规则引擎、污点分析和 LLM 输出互不兼容。

## 3. 分析策略

第一层采用规则扫描，速度快、结果稳定、易解释；第二层程序分析解决变量传播、跨函数调用和上下文依赖；第三层 LLM 聚焦高风险候选，而不是无差别读取整个大型仓库。

## 4. 设计原则

- 规则、分析器、模型解耦
- 所有漏洞结果使用统一结构
- 每条 Finding 必须保留证据
- 支持单独关闭某一分析模块
- 测试样例必须覆盖真阳性和真阴性
- 可重复运行
- 结果可解释
