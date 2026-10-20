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

工作台运行于 Python 3.10+ 的 Linux 环境（Windows 可使用 WSL2），并需要 Git、Node 22/npm。运行数据目录和 OpenHarmony 目标源码根目录均从配置读取，不依赖 `/home/audit` 或某个盘符：
```bash
cp config/workbench.example.json config/workbench.local.json
# 编辑本机数据目录和已批准的源码根目录
bash scripts/setup_workbench.sh
bash scripts/start_workbench.sh --port 8765
```
本机浏览器访问 http://localhost:8765。`config/workbench.local.json` 已加入忽略规则，不会进入源码包；也可用 `OHSCANNER_CONFIG` 指定其他配置文件，并用 `OHSCANNER_DATA`、`OHSCANNER_TARGET_ROOTS` 覆盖单项设置。配置内相对路径以配置文件所在目录为基准，`~` 指当前用户主目录。

完整扫描与受限 Worker 目前面向 Linux/WSL；Windows 原生运行及 macOS 尚未验收。迁移到新机器时从 Git 验收提交重新安装 Python 与 npm 依赖，单独迁移已批准的目标源码；不要复制虚拟环境、`node_modules`、数据库或本机绝对路径配置。

本机负责人入口 `/home/audit/ohscanner/app` 和 `~/ohscanner/bin/oh start` 是这台电脑的管理入口，不是部署前提。

Web 与 CLI 共用 src/ohscanner；src/workbench 提供 API/存储/Worker，web 为 React。
A/B 代码是按模块选择性迁入；五组件候选变化与 229 条 A 诊断均不是漏洞真值。
候选、只读审查聚类、人工调查案例和确认漏洞分别记录；聚类不改原始身份、不推断根因，0 findings 不证明安全。
代码与生成报告/数据库/第三方源码分开，源代码交付从验收的 Git commit 导出。

当前 Catalog 已注册 C/C++ `bounds`、`integer_bounds`、`resource_lifetime` 和
`unsafe_memory_call` 候选规则；NULL dereference 与 Contacts path traversal 也已注册，
但普通扫描默认关闭，需显式选择。当前版本和范围见
[C/C++ detector catalog](src/ohscanner/detectors/cpp/README.md)。Catalog 可用性和源码命中
不代表产品可达性或漏洞影响已验证。

历史路线图和阶段教程已从当前 docs 删除，历史证据通过固定 Git 提交追溯。
项目执行约束见 [AGENTS.md](AGENTS.md)。
