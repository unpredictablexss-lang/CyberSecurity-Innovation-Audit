# 一键部署验收（2026-10-22）

**后续发现：本页原 Windows 自测只证明 WSL 内部部署/扫描，未覆盖 Windows 宿主机浏览器访问。系统保留端口导致的实际失败、修复及补验以 [WINDOWS_HOST_FOLLOWUP.md](WINDOWS_HOST_FOLLOWUP.md) 为准。最终入口默认仍为 8765，不自动换端口。新增 start 入口和宿主机访问检查随新版源码包交付；以下 6.9 MB 初版包保留作历史结果。**

## 交付

- 获取并再次核对的远端 main：`bd28c931a0663399e69fcd1951502ef607899bdb`。
- 部署实现提交：`1107a11312907b60d9500d0b9215011ab0b7095d`，分支 `codex/one-click-deploy-20261022`。
- 精简源码包：工作区 `outputs/OHScanner-source-20261022.zip`，6,908,982 bytes；SHA-256 `01006026a3a923342160dd5e72b2df5c9ad2a2560d897cd1881f74dd89780e86`。
- 包内 943 个成员，包含 src、Web 源码/字体许可、配置示例、规则、部署/安装脚本、当前说明及约 2.18 MB curated local knowledge；不含 Git 历史、开发测试、大部分历史研究资料、venv、node_modules、dist、数据库、本机配置或密钥。ZIP CRC 和禁入文件检查通过。

## 使用

解压 ZIP 后进入 `OHScanner`：

```text
Windows：双击 deploy-windows.cmd
Windows 自测：powershell -ExecutionPolicy Bypass -File .\deploy-windows.ps1 -SmokeTest
Linux：bash deploy-linux.sh
Linux 自测：bash deploy-linux.sh --smoke-test
```

默认 `http://localhost:8765`，Ctrl+C 停止。首次需要联网；系统依赖安装可能要求 sudo。Windows 用 WSL2/Ubuntu，首次启用 WSL 可能需要管理员权限、虚拟化、重启及发行版初始化，随后重跑。Windows 可用 `-Distribution 名称 -Port 端口` 指定实例，Linux 可用 `--port 端口`。运行数据位置、配置覆盖与打包方法见根 README 和开发协作与交付指南。

## 实测范围

官方 Ubuntu Base 24.04.3 amd64 rootfs，SHA-256 `6bc2cde3930ad088b3bb46fa45279e96d25bc3810f209850ecbe4722711874f9`，来源 `https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/`。分别新建独立 WSL2 实例；初始 `python3/pip/node/npm/git/curl` 均不存在。没有挂载或复制其他 Python/Node 安装环境到实例内；安装从软件源下载。WSL 内核/网络由宿主共享，不能将其声称为独立物理机/完整虚拟机或不可信代码安全沙箱。

| 检查 | 结果 |
|---|---|
| Linux 完整源码，空 Ubuntu 实例，自动系统/应用依赖安装 | passed，端口 18867 |
| Linux 重复执行、正式前台启动、宿主访问健康接口 | passed，Worker running=true |
| Windows CMD → PowerShell → WSL，空 Ubuntu 实例，源码路径含空格 | passed，端口 18868 |
| 精简 ZIP 解压，Windows 入口，独立新 venv/Node/data | passed，端口 18870；复用已完成自动安装的系统依赖 |
| 精简 ZIP 解压，Linux 新空实例 | passed，端口 18869；首轮软件源索引同步错误，正常校验刷新索引后重试通过 |
| 前端测试 / TypeScript / 生产构建 | 190/190 / passed / passed |
| Python workbench/settings 定向回归 | 72 tests，0 failures，1 skipped（缺固定 communication_ipc 对象/T74_IPC_GIT） |

每次自测均实际启动已有 API、扫描/操作/验证 Worker；验证首页和 app.js 可读取，登记合成 Git 仓库，以固定完整 commit 请求正式扫描 API，由队列 Worker 生成报告。合成 strcpy 样例生成 1 条候选，任务 completed，报告 SHA 存入结果，服务退出码 0。合成样例不编译、不执行，不调用模型；候选数量不是精度评价或漏洞确认。原部署数据/正式服务未替换。

精简 ZIP 的额外 Linux 空实例安装首轮遭遇 Ubuntu security 软件源 Packages 与签名 Release 大小不一致，以及 archive 下载停滞。停止该次测试并保留日志；以正常签名/哈希校验、禁止 HTTP 缓存并设置有限超时/重试刷新索引后重新运行相同包/脚本；最终结果见 `validation.json`。没有跳过签名、允许不安全仓库或将失败记为通过。

## 修复与边界

1. main 原样在 Windows 文件系统构建失败：`InvestigationPriority.tsx` 和 `investigationPriority.js` 被 TypeScript 混淆（TS1149/TS2614）。组件改名为 `InvestigationPriorityPanel.tsx` 并更新引用后通过。
2. Windows 路径转义初测失败，改为 WSL 原生 `--cd` + `--exec` 参数传递；最终 CMD 测试覆盖带空格目录。
3. Windows 的锁、SQLite 与 Python 环境放入 WSL Linux 文件系统，按源码目录摘要隔离；不共享其他实例数据库。早期脚本迭代中的锁提示保留在工作区日志，最终通过以独立新实例的完整日志为准。
4. Docker Desktop 启动失败发生在自身 Inference manager socket 初始化阶段；未进行 factory reset 或数据删除。部署测试没有使用 Docker Desktop。可选 Docker PoC Worker 和真实模型 Provider 未验证；空模型配置允许启动/静态扫描。
5. 首次安装依赖外部网络，软件源同步/网络问题会导致失败，恢复后可重跑；本包不是离线安装器。未验证全新 Windows 首次开启 WSL/重启全过程、裸机 Linux、Debian 或 arm64。Windows 原生 Python Worker 仍未宣称支持。

完整测试结果、对应日志 SHA-256 及最终精简包 Linux 复测结果保存在 `validation.json` 和同目录日志中。源码包仅由上面的实现提交生成，后续验收文档提交不改变包中运行代码。
