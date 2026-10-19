# OHScanner：新 Agent 从这里开始

更新：2026-10-16。项目用于 OpenHarmony 开源代码漏洞挖掘竞赛，不是通用 Web 漏扫器。

## 何时读取

这是新人入门和边界说明，不进入默认 Agent 上下文。默认先读根目录 `AGENTS.md` 与《项目现状与下一步》，再按任务追加一份专项文档：

| 任务 | 专项文档 |
|---|---|
| 检测器、公共契约、Runner/Catalog | 架构与公共协议 |
| 安装、测试、协作和打包 | 开发协作与交付指南 |
| Workbench/Web/API | 面板功能与验收 |
| LLM/Agent/基准实验 | Agent方案与对照实验 |

## 项目边界

一条固定 Git 源码流水线：自研静态发现 → 程序事实/人工复核 → 受控 PoC/动态验证 → CWE/CVE 与影响版本 → 修复重验 → 完整报告和性能数据。

当前可运行快照扫描、版本/区间、证据复核、源码同步和只读调查。候选默认不是漏洞，0 findings 不是安全结论。Docker、产品入口、准确率和完整竞赛闭环仍需以当前状态文档为准。

## 仓库导航

- `src/ohscanner`：固定 Git、索引、契约、Registry、Runner 和统一执行。
- `src/ohscanner/detectors/cpp`、`interface`：A/B 自研检测器。
- `src/investigation`：确定性事实包和 draft-only 调查草案。
- `src/workbench`、`web`：API/Worker/storage 与 React 面板。
- `src/providers`、`src/benchmark`、`research`：历史研究/离线对照，不是生产隐藏依赖。
- `tests`、`samples`、`benchmarks`：回归与开发样本，不能自动当独立 holdout。

## 接手须知

不要把分支名、main 或 teammate 树当成已验收实现。保留 dirty files；未知保持 unknown；模型/规则输出默认 candidate。详细历史状态已迁往 `research/status/`，当前决策只看《项目现状与下一步》。
