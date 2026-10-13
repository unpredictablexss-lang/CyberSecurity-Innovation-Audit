# OHScanner 开发工作区与模块地图

2026-10-13 本机整理记录。保留一个 GitHub 项目；目录归类不代表新建另一套扫描系统。
入口是 /home/audit/ohscanner，真正 Git 工作目录是其 app/。
app 基于工作台 PR #9 的 fe85edd，当前整理分支 chore/workspace-standardization。
不在旧脏 Core 目录继续做负责人新功能，不整体合并 A/B 未完成研究树。

## 本机目录

| 入口 | 用途 | 是否新复制数据 |
|---|---|---|
| app/ | 后续负责人日常开发的真实 Git worktree | 新检出代码，共享原 Git 对象库 |
| worktrees/workbench-pr9 | 已推送的面板分支，PR #9 对照 | 链接旧 worktree |
| worktrees/owner-platform | PR #8 公共平台依赖 | 链接旧 worktree |
| worktrees/review-a-static | A 最新远端 e9563f9 的 detached 审查快照 | 固定检出，非 A 本人的开发目录 |
| worktrees/team-b | B 独立 clone，48bce9e | 链接；本轮不切分支、不编辑 |
| worktrees/legacy-* | 旧工作目录与实验对照 | 链接；不是日常主入口 |
| sources/components | 原 openharmony-targets：c_utils、cJSON 等 | 链接原源码库 |
| sources/performance-corpus | 十个性能/真实组件目录 | 链接原源码库 |
| sources/ipc-corpus | IPC 研究源码库 | 链接原源码库 |
| research/ | 研究数据、公告与工具；不属于产品运行必需项 | 链接既有研究目录 |
| data/runtime | 当前演示的 SQLite、artifacts 与复核记录 | 链接原 verification-data，未迁移数据库 |
| data/experiments | 最终组件验收与 CLI 对照报告 | 链接 final-verification-data |
| envs/web、envs/core | 可选工作台环境、原核心环境 | 复用 venv，未移动 venv |
| tools/node | 固定 Node 工具链 | 复用原安装 |
| config/local.json | 本机路径与端口，不存 Key | 新增本机配置，不入 Git |
| bin/oh | doctor / build / check / start 入口 | 本机 wrapper，核心脚本在 app/scripts |
| records/日期 | 本机盘点、前后保护核验、日志 | 机器路径/产物记录，不入 Git |

链接是兼容层：数据库仍引用原物理目录，历史命令仍可复现。不要手工删除链接指向的目录。
app 的 .git 指向原主 clone 的管理目录；删除原
/home/audit/openharmony-audit/CyberSecurity-Innovation-Audit/.git 会损坏所有共享 worktree。
这不是独立备份；未来物理迁移必须用 git worktree move 并检查路径绑定，不用 mv 直接搬。

## 日常四个命令

```bash
cd ~/ohscanner/app
~/ohscanner/bin/oh doctor
~/ohscanner/bin/oh build
~/ohscanner/bin/oh check
~/ohscanner/bin/oh start
```

Windows 浏览器：http://localhost:8765 。doctor 为只读检查，不联网 fetch。
build 安装锁定前端依赖并构建；check 是当前 app 的测试，不能代表 A/B 全分支通过。
start 使用原演示数据库。发现已有健康 API/Worker 时不重复启动；不自动杀其他服务。
新的独立部署应按 docs/workbench/README.md 重建 venv、依赖、前端，不能拷贝本机 venv。

## 仓库内模块

| 目录 | 职责 / 所有人 |
|---|---|
| src/ohscanner/git_source.py、indexing.py、frontend.py | 固定源码、索引与解析；负责人公共底座 |
| src/ohscanner/contracts.py、runner.py、execution.py、detectors/catalog.py | 统一输入、调度、覆盖、证据、注册；负责人 |
| src/ohscanner/detectors/cpp/ | A 的自研 C/C++ 检测模块；以独立变更接入 |
| src/ohscanner/detectors/interface/ | B 的 IPC/权限检测模块；以独立变更接入 |
| src/workbench/ | API、数据库、任务、Worker、源码/证据服务；负责人 |
| web/ | React/TypeScript/Monaco 面板；负责人 |
| src/benchmark/、src/providers/、research/ | 历史研究和外部工具对照；不替代生产检测器 |
| src/ohscanner/poc/、src/report/ | 已有研究/报告资产，不等于完整统一验证平台已实现 |
| tests/、samples/、benchmarks/ | 回归、开发样例、冻结实验定义；独立 holdout 要单列 |
| docs/ | 协议、方法卡、验证记录与路线；历史章节不能覆盖当前状态 |

不为追求目录好看，把已工作的 src/workbench 拆成 webapi/jobs/storage。
功能边界优先于文件夹命名，避免大规模重写与重复扫描器。
