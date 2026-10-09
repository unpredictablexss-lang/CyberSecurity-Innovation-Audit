# Interface 分支改造与 Ubuntu 验证

正式本地仓库：`D:\ICP\CyberSecurity-Innovation-Audit`。
本地分支：`feat/oh-interface-detectors`；基线 main `dcd9629f50a34545d75abc92c0a16c79723197db`。
旧 `D:\ICP` 是研究包，原文件保留，不当成 Git 仓库或 Ubuntu 验证。

## 接口依赖

核心代码已在 `feat/ohscanner-core@8c5c9d9b77857d9ccf41d101be6068f287453e81` 实现，但未合入当前 main。
新增 `IpcPermissionDetector` 对接实际 `DetectorRun / DetectorFinding / EvidenceObligation`，ID 为
`ohscanner.interface.permission`，required_facts=`ast`，whole_scope 模式；不改变全局 CLI、catalog 或公共 schema。
真实核心 frontend、registry、runner、ToolRunResult bridge 和 coverage sidecar 已用于四项接入测试。
主线缺核心时这四项测试明确 skip；不提供冒充核心的本地类型或假接口。核心检验目录中四项实际通过。

候选只说明权限 helper 的否定条件分支没有源码结构上的 return，附政策、身份、控制流、宏/调用覆盖的未知义务。
调用图索引、宏和 helper 追踪仍属受限语法研究，完成不等于授权漏洞成立。详细 AST 分支节点尚未包含在核心 outline 中，因此局部算法继续使用 Tree-sitter 详细语法；该取舍需要负责人接入审查，不另建公共前端或 IR。
全局注册由负责人审查后完成，本分支不会自行加入全局批准 catalog。

## Ubuntu 迁移

当前 Codex 执行环境的 WSL 返回 `Wsl/E_ACCESSDENIED`；尚未在 Ubuntu 执行代码。
已准备不覆盖现有目录的迁移脚本，使用 Windows 本地 Git 对象和补丁，不需要把 GitHub 令牌复制到 Ubuntu。

在 Ubuntu 22.04 中：

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-pip
bash /mnt/d/ICP/CyberSecurity-Innovation-Audit/research/experiments/interface/setup_ubuntu.sh
```

默认建立 `~/projects/CyberSecurity-Innovation-Audit`；可将一个全新目录作为脚本参数。
脚本保留 `feat/oh-interface-detectors`，恢复 GitHub origin，应用 `.tmp/interface-main.patch`，
安装原项目依赖及解析器约束，运行全回归、可用缓存的 IPC inventory 和独立核心兼容测试。
代码放在 Linux 文件系统；Windows 虚拟环境不复制。脚本不 push、不 commit、不合并核心分支。
安装失败后检查日志再从失败步骤继续；不要为重跑删除已有项目。

## 开发纪律

只迁移 B 的模块、fixtures、方法卡、来源清单和测试；第三方源码、运行日志、虚拟环境均不进提交。
尚无独立 holdout 或已核验公开漏洞修复对，不宣称完成生产准确率验收或新漏洞发现。
Ubuntu 全回归和负责人审查仍是推送/集成前的待办，不将 Windows 部分通过写成 Ubuntu 通过。
远端原本没有该分支，本次未创建远端分支、未推送、未创建 PR。
