# OHScanner · OpenHarmony 源码审计工作台

面向 2026 网络安全创新大赛 OpenHarmony 开源代码漏洞挖掘。
目标是自研静态检测、证据调查、受控动态验证、版本影响与修复重验的完整交付；
当前统一分支已接入固定 Git 快照、v2 诊断绑定、A/B 窄检测器、源码同步/区间/版本/只读调查入口和 Docker-only 验证框架；真实动态验证和漏洞影响闭环仍未验收。

**新 Agent / 新队友首先阅读 [docs/README.md](docs/README.md)。**

| 文档 | 内容 |
|---|---|
| [当前状态](docs/项目现状与下一步.md) | 分支、各模块完成度、实测与未知、下一步 |
| [架构与协议](docs/架构与公共协议.md) | 一套内核、模块职责、v2 第一方输出、v1 兼容与证据门 |
| [面板功能](docs/面板功能与验收.md) | 已有交互、三种审计对象与产品验收 |
| [Agent 与对照实验](docs/Agent方案与对照实验.md) | 单轮/Agent/主动发现、数据与指标 |
| [开发与交付](docs/开发协作与交付指南.md) | 安装、WSL目录、测试、协作、打包 |

## 运行

Python3.10+、Git、Node22/npm；从已合入统一工作台的 main 开始：
```bash
bash scripts/setup_workbench.sh
bash scripts/start_workbench.sh --port 8765
```
Windows 浏览器 http://localhost:8765。
本机负责人入口 /home/audit/ohscanner/app；已有环境可运行 ~/ohscanner/bin/oh start。

Web 与 CLI 共用 src/ohscanner；src/workbench 提供 API/存储/Worker，web 为 React。
A/B 代码是按模块选择性迁入；五组件候选变化与 229 条 A 诊断均不是漏洞真值。
候选、只读审查聚类、人工调查案例和确认漏洞分别记录；聚类不改原始身份、不推断根因，0 findings 不证明安全。
代码与生成报告/数据库/第三方源码分开，源代码交付从验收的 Git commit 导出。

历史路线图和阶段教程已从当前 docs 删除，历史证据通过固定 Git 提交追溯。
项目执行约束见 [AGENTS.md](AGENTS.md)。
