# OHScanner · OpenHarmony 源码安全审计工作台

OHScanner 面向 OpenHarmony 源码审计，提供固定版本扫描、自研静态检测、模型辅助调查、人工复核、受控验证与报告导出。CLI 和 Web 共用同一扫描内核。

**项目评阅与演示从 [文档目录](docs/README.md) 开始。**

| 内容 | 文档 |
|---|---|
| 当前实现与验证边界 | [项目现状](docs/项目现状与下一步.md) |
| 系统组成与证据管理 | [架构与公共协议](docs/架构与公共协议.md) |
| 扫描、时间/版本比较及候选调查 | [面板操作手册](docs/面板操作手册.md) |
| 模型流程与对照实验 | [Agent方案与对照实验](docs/Agent方案与对照实验.md) |
| 部署、检查与打包 | [安装与交付指南](docs/开发协作与交付指南.md) |

## 运行

主要运行环境为 Python 3.10+ 的 Linux/WSL，需 Git、Node.js 22/npm：

```bash
cp config/workbench.example.json config/workbench.local.json
# 编辑本机数据目录与受允许的源码根目录
bash scripts/setup_workbench.sh
bash scripts/start_workbench.sh --port 8765
```

浏览器打开 `http://localhost:8765`。首次安装及更新步骤见[安装与交付指南](docs/开发协作与交付指南.md)。静态扫描无需模型；AI 调查需要配置可用 Provider 并明确授权源码发送范围。

## 源码导航

- `src/ohscanner/`：源码固定、索引、自研检测器与统一执行。
- `src/workbench/`、`web/`：任务、风险、调查、验证、报告及界面。
- `tests/`：回归测试；`benchmarks/`、`research/`：实验定义和证据材料。

扫描候选、模型判断、源码链可信与产品漏洞确认分别记录。任务完成或历史 CVE 命中不直接证明真实漏洞；未知、未分析和未验证范围保留在结果中。

开发执行约束见 [AGENTS.md](AGENTS.md)。过程文档可通过 Git 历史追溯，当前使用说明以 `docs/` 为入口。
