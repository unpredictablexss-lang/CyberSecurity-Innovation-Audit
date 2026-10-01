# Development Roadmap

> 2026 路线调整：PoC/动态验证前移，LLM 后移。先证明“发现 → 验证 → 报告”闭环真实可行，再扩大扫描范围与智能化程度。

## Milestone 0 — 赛题基线与测试资产

- [x] 建立 GitHub 仓库
- [x] 整理官方赛题要求
- [x] 整理评价指标与交付要求
- [x] 形成 2026 总体架构
- [ ] 建立第一批 vulnerable / safe 对照样例
- [ ] 收集可公开使用的历史 OpenHarmony 安全修复样例
- [ ] 定义 Finding / Evidence / VulnerabilityCase 数据结构
- [ ] 定义 Benchmark 指标格式

## Milestone 1 — 最小扫描器

目标：任何本地源码目录都能稳定跑完并输出候选结果。

- [ ] CLI 入口
- [ ] 目录递归扫描
- [ ] 语言识别
- [ ] 文件/LOC/耗时统计
- [ ] 增量 content hash
- [ ] 规则加载框架
- [ ] Finding JSON
- [ ] Markdown 报告
- [ ] 失败文件与跳过原因记录

## Milestone 2 — C/C++ 与接口安全候选引擎

目标：先覆盖比赛高价值漏洞类别，不追求语言大而全。

### C/C++

- [ ] Dangerous Memory API
- [ ] Buffer / OOB 候选
- [ ] Integer → allocation/copy/index 链
- [ ] UAF / Double Free 基础状态规则
- [ ] NULL / resource error path
- [ ] Sensitive information sink

### Web / 接口 / 权限

- [ ] Command execution sink
- [ ] Path traversal / file access
- [ ] URL / network request
- [ ] IPC/RPC external source
- [ ] Authentication / authorization check
- [ ] JS / WebView / Native Bridge 候选

## Milestone 3 — AST 与基础程序分析

目标：从“出现危险特征”升级成“证据链”。

- [ ] Tree-sitter AST
- [ ] Function / Symbol Index
- [ ] Call Graph
- [ ] CFG
- [ ] Intra-procedural Data Flow
- [ ] Source / Sink
- [ ] Guard / Sanitizer 识别
- [ ] 基础 Taint
- [ ] 有限跨函数追踪
- [ ] 生命周期状态机 v1

## Milestone 4 — PoC / 动态验证 MVP

目标：至少一种内存漏洞可以自动/半自动完成验证闭环。

- [ ] Validation Harness 数据模型
- [ ] Build Runner
- [ ] Sandbox Runner
- [ ] Timeout / Resource Limit
- [ ] ASan 结果解析
- [ ] UBSan 结果解析
- [ ] Crash / behavior evidence
- [ ] PoC 状态机
- [ ] 重复执行与稳定性统计
- [ ] PoC artifact 保存

验收：至少一个候选能够从 Finding 进入 stable_reproduced 或 trigger_success。

## Milestone 5 — 多证据误报抑制

- [ ] static_confidence
- [ ] reachability_confidence
- [ ] security_impact
- [ ] validation_status
- [ ] Evidence 统一存储
- [ ] candidate → suspected → validated → reportable
- [ ] 根因去重 / Finding 聚类
- [ ] 真阳性 / 真阴性回归集

## Milestone 6 — 历史补丁知识与跨版本

- [ ] Historical Patch Collector
- [ ] Vulnerable-before / Safe-after 模式抽取
- [ ] Token/API 模式迁移
- [ ] AST 模式迁移
- [ ] Source-Sink 模式迁移
- [ ] Branch Analyzer
- [ ] Vulnerable Code Fingerprint
- [ ] Backport / Equivalent Patch
- [ ] affected / fixed / not_present / unknown
- [ ] 关键漏洞跨版本 PoC 复验

## Milestone 7 — CWE / CVE / 修复闭环

- [ ] CWE Mapper
- [ ] CVE 证据关联
- [ ] Severity 事实化评估
- [ ] Patch Generator / Assistant
- [ ] Static Re-scan after Patch
- [ ] Original PoC Re-run
- [ ] Regression Test
- [ ] Patch Validation Report

## Milestone 8 — LLM 辅助分析

LLM 建立在确定性证据之上。

- [ ] 高风险上下文切片
- [ ] 调用链解释
- [ ] 历史补丁模式抽象
- [ ] 漏洞二次研判
- [ ] PoC Harness 草案
- [ ] Patch 草案
- [ ] CWE 候选解释
- [ ] 报告生成
- [ ] 人工复核状态

## Milestone 9 — 全量性能与比赛版本

- [ ] 多仓库批量扫描
- [ ] 并行任务调度
- [ ] AST / analysis cache
- [ ] Incremental Scan
- [ ] files/s
- [ ] LOC/s
- [ ] Peak RSS
- [ ] CPU
- [ ] 各阶段耗时
- [ ] Coverage
- [ ] Precision / Recall / FPR
- [ ] PoC Success Rate
- [ ] Web / CLI
- [ ] Trace 可视化
- [ ] Demo
- [ ] 技术说明书
- [ ] 使用说明书
- [ ] 答辩材料

## 当前最近一步

不要马上做全 OpenHarmony。

先完成一个小型验证原型：

```text
C/C++ 样例
 ↓
候选规则
 ↓
AST
 ↓
Finding
 ↓
ASan/UBSan Harness
 ↓
验证证据
 ↓
VulnerabilityCase
 ↓
报告
 ↓
Patch
 ↓
重跑 PoC
```

这条链跑通后，再把分析对象扩展到 OpenHarmony 的具体模块。
