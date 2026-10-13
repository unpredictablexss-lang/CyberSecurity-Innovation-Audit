# 工作台第一、二轮开发记录（2026-10-12）

## 开始时核对的远程状态

通过现有负责人 worktree git fetch origin 取得远程引用，未覆盖原开发目录的未提交修改。

| 线 | 固定 head |
|---|---|
| main | 1446e49b5b253bd1a65bdbd2d87976085d8d693f |
| core | e3654654d0b933a37bea8e0244c0755544950b76 |
| 负责人集成 | 86fbf9951967aaab879d24748a8231744d6977aa |
| B 接口线 | 742fc21（完整 SHA 见 upstream_refs_20261012.txt） |
| B M1 描述符身份 | 8464151（完整 SHA 见引用记录） |
| A 验证/报告线 | aa79d57（完整 SHA 见引用记录） |

已读取 B 最新 M1 工作记录和 A 验证/报告记录。它们包含各自实验边界，不能当作本轮复测。
本轮基于负责人集成 head：已有统一 A/B Catalog、部分覆盖与义务保留。
没有直接合并 A/B 未完成分支，没有修改检测算法；最新 M1 修复也未自动纳入。

## 模块提交顺序

- feat/workbench-foundation：数据、固定来源、应用服务。
- feat/workbench-jobs-api：持久化任务、API、独立 Worker、取消/截止与恢复。
- feat/workbench-ui：六类页面与本地源码阅读，前端按页面拆分。
- feat/workbench-evidence-review：源码摘录、案例扩展、报告清单与复核强化。
- feat/workbench-integration：经本地验证的组合版本。

本次由一个开发会话按依赖顺序实现，**不是宣称多个分支已被同时独立开发**。
这些分支用于审查与后续模块所有权；没有为未实现的 Agent 等创建空开发分支。
保留独立 foundation/ui 工作目录，另建最终 integration 工作目录。

## 第一轮与第二轮验收口径

第一轮：真实网页提交固定来源任务 → Worker 执行 → 覆盖/候选/报告 → 重启后保留。
第二轮：固定 Git blob 阅读 → 义务 → 追加复核/冲突检查 → 固定源码摘录 →
人工案例关联 → 带来源的审计包。没有把第三、四轮功能算作完成。

## 真实组件结果

| 组件 / 范围 | 固定 commit | 文件 | parse complete / partial / not_run | 候选 | 确认漏洞 |
|---|---|---:|---|---:|---:|
| c_utils / . | b807d3dadb7dbb7639fe85b3a5f72da18d318da2 | 123 | 93 / 30 / 0 | 0 | 0 |
| update_updateservice / services, interfaces, frameworks | e4942a33cc5ed29040e5c720bea3b2a8e4a79221 | 220 | 187 / 32 / 1 | 2 | 0 |

两组件均通过 API/Worker 与原 CLI 入口函数独立执行的候选、覆盖、范围、
解析统计、snapshot 一致性检查。update 两条候选源码 hash 均核验。
220 与此前 219 的生产范围数字不同：本次明确纳入上述三个路径前缀，
不是复用此前逐文件生产排除清单。没有修改预期凑旧数字。

初次真实运行记录：
- c_utils task a4eb6e1a203a4ae6834eb7797cfebf90，Worker 6.90 s。
- update task 59232be9012943d7994286718f26e134，Worker 4.06 s。
- 浏览器直接创建 c_utils task d36c780d0262441c834df4c0fe4723e2，Worker 6.09 s。
耗时仅为本机单次观测，非正式性能结论或跨工具比较。

## 浏览器实测

Windows 可访问 WSL2 localhost:8765；通过 computer-use 浏览器界面验证：
真实任务提交、运行中/完成状态、覆盖表、候选源码与 unknown 义务、
追加复核和人工案例分组。复核人与分组明确标为工作台交互验收，不是独立漏洞核查。

最终轮的测试数量、代码提交、源码摘录/下载/重启检查和产物位置，
以 PROGRAM_STATUS 最新工作台章节及本地 completion 记录为准。
GitHub CI 配置会随本轮提交准备，但没有 push 就不存在本轮远端 CI 结果。

## 未验证与 unknown

- Windows 睡眠、wsl --shutdown、断电与磁盘满等故障未实机演练；
  数据库恢复与 Worker 锁冲突有自动回归，不代表全部 OS 故障已验证。
- 地址空间限额不是容器/VM，未宣称恶意源码/PoC 隔离。
- 没有验证新漏洞或准确率；0/2 是 raw candidate。
- 任务超时不会返回已完成插件的检查点；逐 Detector 子进程隔离待后续设计。
- 核心输入限制仍为组件级；前端不提供虚假的全 OpenHarmony 一键完整扫描。
- 对 Agent/模型、跨版本、修复重验等能力页面明确显示未实现。

## 最终代码的独立复跑

第二轮代码收尾后，在独立 final-verification-data 数据目录再次运行同一复现脚本，
避免与演示服务的 Worker 竞争。两个组件结果保持上表一致；CLI parity 均为 true。

- c_utils task `6be1a2c1edae4d51a9bd6835d0f4df1d`，report SHA-256
  `b1990ad0ba152eb736d8349e94f3c05afe552fdef4f78e8b23cf4f6b71c0b9d8`。
- update task `efcb104723d844cb800fcac0ea6a71b6`，report SHA-256
  `d45e18c242f811422b819d2905f76797c4c19fdbe13b98805443b58d403eb867`。
- 引擎指纹 `161adf94be2b98475a6f86d6699b11457be77e1412799d8f8b45af3882a843eb`。
- verification.json、原报告、CLI 对照报告在
  `/home/audit/ohscanner-workbench/final-verification-data/` 下按 task ID 保存。
- 最终 unittest：web 环境 370 全通过；core-only 环境 334 通过、36 skipped。
  日志：`/home/audit/ohscanner-workbench/verification-logs/`。
- 浏览器下载的 review.json 已核对：2 candidates、1 review、1 source excerpt、
  1 investigation case / 2 links，validated_vulnerability 仍为 0。