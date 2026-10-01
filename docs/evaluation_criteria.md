# 评价指标与比赛得分导向

本文将官方评价方式转换为项目开发时可直接执行的优化目标。

---

## 1. 官方评价维度总览

| 评价项 | 官方关注点 | 项目需要记录的指标 |
|---|---|---|
| 准确性 | 尽可能不误报 | Precision、确认漏洞数、误报数 |
| 完整性 | 尽可能不漏报 | Recall、覆盖率、漏报分析 |
| CVE 判断 | 已有漏洞匹配正确 | CVE Match Accuracy |
| CWE 分类 | CWE-ID 分类准确 | CWE Accuracy |
| PoC 质量 | 可执行、稳定、复现 | PoC Success Rate |
| 分支影响分析 | 版本/分支识别正确 | Version/Branch Accuracy |
| 修复建议 | 合理、可操作 | Patch Validation |
| 工具性能 | 快速、低资源占用 | Time、Memory、CPU、LOC/s |
| 技术创新 | 方法创新 | 创新模块、实验对比 |

---

## 2. 准确性：误报是明确扣分项

官方明确强调：

- 漏洞准确率
- 尽可能不误报
- 误报会产生负向扣分
- 普通 Bug 不能当作安全漏洞

因此项目应采用多级 Finding 状态：

```text
candidate
    ↓
suspected
    ↓
validated
    ↓
reportable
```

推荐字段：

```text
confidence
validation_status
validation_method
false_positive_reason
security_impact
```

### 开发原则

不要让：

```text
规则命中 == 最终漏洞
```

正确流程应该是：

```text
规则 / 数据流命中
      ↓
上下文判断
      ↓
漏洞可达性
      ↓
安全影响判断
      ↓
PoC / 验证
      ↓
最终报告
```

---

## 3. 完整性：不能为了低误报完全牺牲召回率

官方同时强调：

- 完整识别安全漏洞
- 尽可能不漏报
- 代码覆盖率
- 扫描粒度

因此项目需要记录：

- 总文件数
- 实际扫描文件数
- 跳过文件数
- 解析成功率
- 分析成功率
- LOC Coverage
- Module Coverage
- Rule Coverage

建议最终工具输出：

```text
Scan Coverage Summary
---------------------
Repositories:
Modules:
Files:
Parsed Files:
Skipped Files:
Total LOC:
Analyzed LOC:
Coverage:
```

---

## 4. CVE 获取或判断准确性

对于已有公开漏洞：

- 应正确关联 CVE
- 不应基于漏洞类型相似就直接猜测

建议证据至少包含：

- affected file
- vulnerable code
- commit / patch
- version
- module
- CWE
- public description

并给出：

```text
cve_match_confidence
cve_match_evidence
```

---

## 5. CWE 分类准确性

建议构建统一 CWE Mapper。

输入可以包括：

- source
- sink
- root cause
- vulnerability behavior
- memory / arithmetic / permission / validation 特征

输出：

```json
{
  "cwe_id": "CWE-XXX",
  "cwe_name": "...",
  "confidence": 0.0,
  "reason": "..."
}
```

---

## 6. PoC 质量

PoC 官方评分关注：

- 可执行性
- 稳定性
- 可复现性

建议将 PoC 状态划分：

```text
not_generated
generated
build_success
run_success
trigger_success
stable_reproduced
```

每个 PoC 需要保存：

- 环境
- 构建命令
- 运行命令
- 输入
- 预期输出
- 实际输出
- 触发证据
- 重复测试次数

---

## 7. 分支影响分析

官方单独评分不同 OpenHarmony 分支的影响范围。

需要逐步建设：

- commit history
- branch compare
- vulnerable code fingerprint
- fix commit identification
- backport detection
- affected version inference

最终应回答：

```text
master: affected
branch A: affected
branch B: fixed
branch C: code not present
```

---

## 8. 修复建议合理性

高质量修复不能只是：

> 请增加输入检查。

而应提供：

- 根因
- 修改点
- 修复代码
- Patch
- 为什么能够阻断漏洞
- 是否需要额外回归测试

可加入 Patch Validator：

```text
patch
 ↓
build
 ↓
original PoC
 ↓
should no longer trigger
 ↓
regression tests
```

---

## 9. 工具性能

官方评价：

- 扫描效率
- 资源占用
- 快速
- 准确
- 实时

建议 Benchmark 统一记录：

```text
repository
commit
files
loc
scan_time
parse_time
analysis_time
llm_time
peak_memory
avg_cpu
findings
validated_findings
```

推荐至少给出：

- files/s
- LOC/s
- Peak RSS
- 总耗时
- 各阶段耗时百分比

---

## 10. 技术创新性

可以考虑的创新方向：

### 方向 A：规则 + 程序分析 + LLM 融合

不是让 LLM 替代所有分析，而是：

```text
Static Candidate Generation
          ↓
Program Context Expansion
          ↓
LLM Security Reasoning
          ↓
Verification
```

### 方向 B：跨函数 / 跨文件污点追踪

针对大型系统代码的 source-to-sink 路径。

### 方向 C：自动 PoC 辅助生成与验证

从 Finding 自动构造：

- Harness
- Input
- Build
- Execution
- Crash / behavior validation

### 方向 D：版本影响自动分析

利用 Git 历史自动判断：

- 引入版本
- 修复版本
- Backport
- Affected branches

### 方向 E：误报抑制

基于：

- 可达性
- 上下文
- Sanitizer
- 生命周期
- 权限边界
- LLM 二次确认

对候选漏洞进行排序和筛选。

---

## 11. 额外加分导向

官方备注中特别强调：

### 真实高价值漏洞

真实、有价值的漏洞越多越有优势。

### 漏洞类型多样性

UAF、整数溢出、堆栈溢出、信息泄露、权限提升等不同漏洞类型会体现能力广度。

### 快速扫描

速度本身也是评价重点。

### 代码覆盖率和扫描粒度

不能只扫描少数高风险文件。

### 架构设计、可扩展性、易用性

因此工程质量本身会影响比赛表现。

---

## 12. 项目当前优先级建议

从评分导向看，开发优先级建议为：

### P0

- 稳定扫描框架
- Finding 统一结构
- 低误报基础规则
- 完整证据链
- 报告输出

### P1

- AST
- 数据流
- Source / Sink
- 基础污点分析
- CWE 分类

### P2

- PoC 生成/验证
- Git 分支影响分析
- 修复 Patch

### P3

- LLM 二次研判
- 自动误报抑制
- 多文件上下文

### P4

- 可视化
- Benchmark
- Demo
- 技术创新实验
