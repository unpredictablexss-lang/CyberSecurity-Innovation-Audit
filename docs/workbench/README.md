# OHScanner 本地审计工作台：第一、二轮

本轮是负责人的产品与执行平台开发。保留原扫描引擎与 CLI，不修改 A/B 检测算法。
第一轮：快照审计、持久化任务、独立扫描进程与页面。
第二轮：固定源码阅读、追加式复核、人工案例关联、固定源码证据摘录与审计包导出。

## 运行

Ubuntu/WSL2；Python 3.10+，本轮实际使用 Node 22.23.3。前端依赖版本以 package-lock.json 为准。
新环境先安装 Node，再执行：

```bash
bash scripts/setup_workbench.sh
bash scripts/start_workbench.sh --port 8765
```

Windows 浏览器打开 http://localhost:8765 。演示态前后端同源，所有前端资源含 Monaco Worker 都本地打包。
扫描不需要模型服务、云服务器或开发板。

本机已准备独立环境（不是仓库必须依赖的硬编码路径）：

```bash
cd /home/audit/ohscanner-workbench/worktrees/integration
export OHSCANNER_VENV=/home/audit/ohscanner-workbench/venv
export OHSCANNER_DATA=/home/audit/ohscanner-workbench/verification-data
bash scripts/start_workbench.sh --port 8765
```

若服务已在运行，直接打开页面，不要启动第二个 Worker。
退出终端/按 Ctrl+C 会停止 API 与 Worker；重新运行上述命令恢复服务。
旧 running 任务标 interrupted，需明确重试，不冒充恢复到中间步骤。

## 配置

- OHSCANNER_DATA：SQLite 与 artifacts 的父目录；默认 ~/ohscanner-workbench/data。
- OHSCANNER_TARGET_ROOTS：允许登记仓库的父目录，以 Linux 冒号分隔；默认
  ~/openharmony-targets、~/oh-audit-targets、~/openharmony-audit/perf-corpus。
- OHSCANNER_VENV：启动脚本选择的 Python 环境，默认仓库 .venv-web。
- 服务仅监听 127.0.0.1；不是多人服务，不能直接改为公网部署。
- 浏览器 POST 必须带 X-OHScanner-Client: workbench-v1，并通过同源检查。
- 浏览器只能使用登记的 repository_id；不能提供任意命令或模块路径。
- 不在扫描中 fetch/clone，不执行目标仓库 hook、构建脚本或源码。

## 页面流程

1. 仓库与版本：登记已有本地 Git 仓库，可查看本地分支/Tag。
2. 新建审计：选择 ref/完整 SHA、纳入目录、Catalog 检测器、时间/内存预算。
3. 后端先固定 commit/tree，再排队；重试保持原 commit，不跟随移动分支。
4. 任务：展示实际执行阶段，不估算虚假的进度百分比；可取消/重试。
5. 候选：分页搜索、复核状态筛选、源码位置、原始证据义务。
6. 源码：固定 Git blob，校验与扫描清单的 blob/SHA-256；不读工作区修改。
7. 复核：追加记录，旧记录保留；expected_id 防止两个页面互相覆盖。
8. 补证：从本次扫描内的源码选取 1–100 行，服务器绑定原 commit、blob、
   source SHA-256、摘录 SHA-256 和原报告 hash。人工解释不自动成为路径证明。
9. 调查案例：人工声明关联依据，可以跨已完成任务追加候选；不自动去重判漏洞。
10. 报告：原始 JSON/Markdown、manifest、包含复核/摘录/案例的审计包。

API 文档：http://localhost:8765/docs 。请求/结果在应用层，不改 ToolRunResult v1。
GET /api/v1/health 返回实际 Worker 锁持有状态及能力开关。

## 执行与证据边界

- 单 Worker 独占锁；数据库事务领取任务；API 重启不丢任务与复核记录。
- 扫描子进程使用进程组，取消/硬截止时终止整组；Linux 父进程死亡信号防止
  直接扫描子进程遗留。CPU/地址空间/单文件写入上限在子进程设置。
- memory_mb 是进程地址空间上限，不是实测峰值 RSS；当前未提供峰值内存数据。
- 硬截止是整项扫描的边界，不是每个 Detector 独立硬超时。某插件卡死时整项任务
  timed_out；本轮不发布该任务的残缺候选包，缺失分析为 unknown。
- 这是静态扫描进程控制，**不是运行不可信构建/PoC 的安全沙箱**。
- 引擎源码指纹与算法版本在排队时固定；执行前后检查代码指纹，变更后旧任务失败，
  需新建/重试，不静默复用旧结论。
- JSON 报告 SHA-256 存数据库；Markdown hash 在该 JSON 内；源码查看核对报告内清单。
  manifest 下载根据已校验报告生成。数据库和主机被完全控制不在此完整性边界内。
- candidate、调查案例、确认漏洞分开。当前工作台没有运行时证据门实现，因此不提供
  手工一键 confirmed/reportable；以后接入真实验证门后应允许满足门槛的案例升级。
- 原始引擎仍有同步执行等说明；工作台额外提供任务级硬超时，不替换原始限制文本。

## 检查

```bash
python -m pip install -r requirements-web.txt
python -m unittest discover -s tests -q
cd web
npm ci
npm run build
```

真实组件独立复现（不要同时启动使用同一 data-dir 的 Worker）：

```bash
python -m scripts.verify_workbench \
  --repo-dir /home/audit/openharmony-targets/commonlibrary_c_utils \
  --repository openharmony/commonlibrary_c_utils \
  --commit b807d3dadb7dbb7639fe85b3a5f72da18d318da2 \
  --data-dir /tmp/ohscanner-workbench-cutils
```

它实际创建 API 任务、运行子进程 Worker、独立运行原 CLI 入口函数，并逐项比较
候选、覆盖、范围、解析统计和 snapshot。生成产物不入库。

## 未完成

Agent/模型接入、提交区间、多仓 Manifest、版本影响、隔离动态验证、修复重验、
自动证明漏洞成立、独立 holdout 准确率、全树自动分片与缓存均未包含在本轮。
队友新算法、验证器及历史样例仍需独立审查接入；不能把其分支自述复制成平台验证结果。
