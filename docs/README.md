# OHScanner：新 Agent 从这里开始

更新：2026-10-18。负责人本轮集成验收为 http://localhost:18778；18775、原入口与未提交工作保留，详见当前状态。项目是 OpenHarmony 开源代码漏洞挖掘竞赛工具，不是通用 Web 漏扫器。
本目录六份 Markdown 是当前权威方案；其中“目标”不是“已实现”。
历史教程、阶段路线图和长篇状态流水已从当前目录移除，证据可按 Git 固定提交追溯。

## 先读这三份，再动代码

1. [项目现状与下一步](项目现状与下一步.md)：当前分支、已验证结果、各模块进度、阻塞与下一项。
2. [架构与公共协议](架构与公共协议.md)：系统边界、v2 第一方输出与 v1 读取兼容、证据门。
3. [开发协作与交付指南](开发协作与交付指南.md)：本机目录、启动测试、团队职责、交付与打包。

产品和研究任务再读 [面板功能与验收](面板功能与验收.md)、[Agent方案与对照实验](Agent方案与对照实验.md)。
第一次使用面板可看 [面板操作手册](面板操作手册.md)；手册是使用说明，不是另一份状态表。
根目录 AGENTS.md 是执行约束；PROGRAM_STATUS.md 只指向项目现状文档，不再维护第二份状态表。

## 最终交付目标

固定 OpenHarmony 源码 → 自研静态发现 → 程序事实/人工复核 →
受控 PoC/动态验证 → CWE/CVE 与影响版本 → 修复重验 → 完整报告与性能数据。

准确性、完整性、CWE/CVE、可执行 PoC、影响模块/版本、修复、性能和创新均需有实际证据。
当前可运行快照扫描、证据复核、源码同步/区间/版本/只读调查操作；运营面支持按 committer 时间预览 first-parent 区间和直接比较两个 branch/tag 端点。标准 WSL Docker Worker 仍不可用；一次 Windows 暂存桥接 AUTH-01 组件 Harness 不证明标准 WSL Worker 可重复运行或产品入口可达。完整竞赛漏洞证据闭环尚未收口。

面板内嵌与工作区 HTML 原型相同的 MiSans VF 5.0.0 Web 字体，可离线加载；字体和许可文件随前端资源保留，不单独分发。使用声明与许可说明见“开发协作与交付指南”。
有价值的真实缺陷优先于告警数量、空菜单或把所有语言/工具列进能力清单。

## 两个容易混淆的维度

| 审计对象 | 发现/调查策略 |
|---|---|
| 仓库快照 / 提交区间 / 跨版本影响 | 静态 / 定向 LLM 探索 / 混合发现 |
| 决定哪些固定版本参与审计 | 决定如何提出和调查候选 |

Core-only / 单次 LLM review / 工具型 Agent 是另一个实验比较维度，
详见实验文档。三者不能混成同一个“模式”字段。

## 仓库导航

- src/ohscanner：固定 Git、索引、Detector 契约、Runner 和统一执行。
- src/ohscanner/detectors/cpp、interface：A/B 自研检测器。
- src/workbench + web：API/存储/Worker + React 面板；调用同一核心。
- src/benchmark、src/providers、research：历史研究/对照，不是生产检测依赖。
- tests、samples、benchmarks：回归/开发样本/实验定义，不能自动当独立 holdout。
- docs/integration/ipc_source_import_20261011.json：保留的来源审查清单，不是第七份方案。

## 接手须知

先确认 branch/full SHA/status/remote；不要把 main 或 A/B 最新树当成已验收工作台。
保留未提交改动；不整体覆盖 runner/catalog。未知保持 unknown，规则/模型输出默认 candidate。
本机入口 /home/audit/ohscanner/app；Windows 浏览器 http://localhost:8765。
历史基线 143fa63 保留旧文档；缺失实验细节用固定 Git 版本查，不重新恢复一套“旧权威方案”。
