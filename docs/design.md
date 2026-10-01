# System Design

## 1. 设计定位

2026 年项目不再定位为通用“规则扫描器 + LLM”，而是面向 OpenHarmony 的自动化漏洞发现与验证平台。

主流程：

```text
大规模源码
  ↓
快速候选发现
  ↓
AST / CFG / Data Flow / Taint / Lifecycle
  ↓
多证据误报抑制
  ↓
PoC / 动态验证
  ↓
CWE / CVE / Severity / Dedup
  ↓
跨版本影响
  ↓
Patch / 修复后重验
  ↓
报告与性能统计
```

详细架构见：[`architecture_2026.md`](./architecture_2026.md)。

## 2. 核心原则

- **漏斗式扫描**：全量代码做轻量分析，少量候选进入重分析。
- **Finding 不等于漏洞**：候选、疑似、已验证、可报告必须分级。
- **PoC 前移**：动态验证是判真的核心组件，不是比赛最后补的附件。
- **证据优先**：Rule / AST / CFG / Data Flow / Runtime 都形成可追溯 Evidence。
- **LLM 辅助而非裁判**：LLM 用于复杂上下文、解释、PoC/Patch 草案和报告，不替代确定性证据。
- **优雅降级**：完整编译/AST/深度分析失败时，局部失败不能拖垮全局扫描。
- **增量与缓存**：源码未变化时复用解析和分析结果。
- **修复闭环**：Patch 后必须重新静态扫描并重跑原 PoC。

## 3. 核心数据对象

### Finding

分析器产生的候选证据：

- id
- rule_id
- vulnerability_type
- candidate_cwe
- file / function / line_range
- source / sink / trace
- guards
- evidence_ids
- static_confidence
- reachability_confidence
- security_impact
- validation_status

### VulnerabilityCase

经过聚类、验证后的真实漏洞根因：

- case_id
- title
- root_cause
- cwe / cve
- severity
- primary_location
- related_findings
- trigger_conditions
- runtime_evidence
- poc
- affected_modules
- affected_versions
- patch
- patch_validation
- confidence
- report_status

### Evidence

所有关键结论都必须可追溯：

- evidence_id
- type
- source
- location
- content
- confidence

## 4. 当前实现优先级

第一版先打通：

```text
Scanner
 → C/C++ Candidate Rules
 → AST Context
 → Finding
 → Validation Harness
 → ASan/UBSan Evidence
 → VulnerabilityCase
 → Markdown/JSON Report
```

随后再加入 CFG、跨函数污点、历史补丁知识、跨版本和 LLM。

## 5. 两人分工

- Web/审计方向：Source-Sink、路径/命令/权限/接口/敏感信息、历史漏洞知识、报告和可视化。
- C++ 方向：Parser、内存安全、生命周期、CFG/Data Flow、Harness、Sanitizer、PoC 与 Patch 重验。
- 共同：Evidence 数据模型、候选排序、Git 版本影响、Benchmark、Demo。
