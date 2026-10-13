# 当前状态、固定版本与下一步

更新：2026-10-13。只维护当前快照；历史流水查 Git。
证据分为本公共版本实测、其他分支自述、计划。不同分支测试数不能相加或强求一致。

## 当前公共基线

负责人日常目录 /home/audit/ohscanner/app；
本轮文档整理基于本地 143fa63，功能基线为工作台 fe85edd。
本轮将把整理提交推送到 feat/workbench-integration 并更新 Draft PR #9；
不改变 main，不代表依赖 PR 已合并。最终提交 SHA 用 git rev-parse HEAD 核对，
避免把文档中自引用的 SHA 当作版本冻结。

| 分支 | 固定 SHA | 核对状态 |
|---|---|---|
| main | 1446e49b5b253bd1a65bdbd2d87976085d8d693f | 正式主线，Core/面板依赖尚未合并 |
| feat/ohscanner-core | e3654654d0b933a37bea8e0244c0755544950b76 | Draft PR #5 → main |
| feat/owner-ipc-platform-integration | 86fbf9951967aaab879d24748a8231744d6977aa | Draft PR #8 → Core |
| feat/workbench-integration | fe85edd6431b09e01131608fa649286264ca2c2e | 整理前工作台 head，Draft PR #9 → 负责人平台 |
| A codex/teammate-a-static-module-20261013 | e27f744acb60d3c1bd45f6d3d9a4d07f9b2528cf | 最新已 fetch；整条树尚未由负责人验收 |
| B feat/interface-ipc-detector | 48bce9eab77fdf22acbb708cd9bf481ca32e7667 | 最新已 fetch；整条树尚未由负责人验收 |

PR #9 原 fe85edd 的 GitHub CI Run 38195475780 success。
新文档 head 的远端 CI 必须单独核对，不能复用旧成功。

## 各模块真实完成度

| 模块 | 公共版本已有 | 尚未完成 |
|---|---|---|
| 来源/索引 | 本地固定 SHA/tree/blob、范围、轻量 AST/覆盖 | 自动 Git 同步、多仓 Manifest、完整产品上下文 |
| Core | Catalog/Registry、v1 Bridge、文件覆盖、义务保留、CLI | v2 统一迁移、逐 Detector 隔离、全树分片/缓存 |
| A C/C++ | 既有 lifetime/shared_ptr_race 两个窄研究检测器已接入 | 最新精化/版本研究/验证资产的公共验收、独立 holdout |
| B IPC | 既有接口检测器正式入口、partial 候选义务 | M1/M2 新修复与 v2 的公共兼容集成、更深权限/跨文件事实 |
| Web | 快照任务、源码、候选、覆盖、复核、摘录、案例、导出 | 区间/版本/Agent/验证产品入口 |
| Worker/存储 | SQLite、单 Worker、取消/截止/重试/中断、报告完整性 | 不可信构建隔离、逐插件检查点、多用户部署 |
| 研究 | historical benchmark、工具适配、样本/方法卡 | 不应等同独立真实准确率或产品完整覆盖 |
| Agent | 实验设计 | 可运行单 Agent、预算/轨迹、消融结果 |
| 验证/影响/报告 | 研究分支有 Harness、静态/动态报告资产 | 公共任务接入、产品入口/影响/修复闭环与交付验收 |

## 本公共版本已验证

2026-10-13 规范工作区实测：370 tests 全通过；TypeScript/esbuild 构建通过；
doctor 配置路径有效，Windows HTTP health ok，Worker 运行。
7 个既有工作区的 head/status/diff hash 保持不变。
原演示 3 个任务保留；update 审计包有 2 候选、1 复核、1 摘录、1 案例，确认0。

2026-10-12 最终功能版真实组件实验：
| 组件 / scope | fixed commit | 文件 | parse complete/partial/not_run | candidate | confirmed |
|---|---|---:|---|---:|---:|
| c_utils / . | b807d3dadb7dbb7639fe85b3a5f72da18d318da2 | 123 | 93/30/0 | 0 | 0 |
| update / services,interfaces,frameworks | e4942a33cc5ed29040e5c720bea3b2a8e4a79221 | 220 | 187/32/1 | 2 | 0 |

API/Worker 与 CLI 入口函数独立执行的候选/范围/覆盖/parse/snapshot 一致。
update 2 条候选源码 hash 核验通过；220 与旧生产过滤范围的219不可混用。
产物保存在 /home/audit/ohscanner-workbench/final-verification-data：
c_utils task 6be1a2c1edae4d51a9bd6835d0f4df1d，
update task efcb104723d844cb800fcac0ea6a71b6。
未在本次纯文档整理中重新扫描组件；0 candidate 不证明安全。

## A/B 最新记录：不是本次公共验收

A e27f744 已合入接口线/工作台，源码支持 v1/v2；最新工作记录自述
640 tests / 11 skipped、Clang/CodeQL/Infer 实跑、Joern 覆盖不足维持 blocked、
3 条历史来源绑定 verified。以上没有在本轮复测，不能转述成已确认产品漏洞。
B 48bce9e 的记录自述451 tests OK、M1 描述符身份与 M2 同文件委托修复、
义务随 Finding 保留；覆盖和公共协议仍有集成差异。
两线版本不能直接覆盖公共 runner，A 最新也不再是“仍只有 v1”的旧状态。

## 当前决定与下一轮

1. v2 为最终目标，兼容读 v1；实现迁移未完成。负责人冻结 schema/覆盖/来源策略，
   复用 A/B 已有实现并做公共兼容测试，不能只改版本号。
2. 检测修复与协议迁移分开提交；优先 B M1/M2 正/反例与五组件差异复跑，
   并独立审查 A 最新静态模块、版本与 Harness 的可迁入单元。
3. 源码显式同步 + 两 SHA 端点区间入口；日期/多版本随后。
4. 高价值案例的入口、受控 PoC、patch 重验与报告与面板并行，不等 Agent 完成才做。
5. 最后扩到受约束 Agent 对照、多仓/性能/Ubuntu 部署。

## 未验证 / unknown

公共新协议兼容、A/B 最新实际准确率、独立 holdout、候选攻击可达性、
产品构建与影响范围未知。Windows睡眠/断电/磁盘满未实机演练；
资源限额不等于沙箱。当前公共版本 confirmed/reportable=0。
本轮文档删减不增加任何算法、漏洞或新性能结论。

## 本轮文档整理验收（2026-10-13）

- docs 当前仅6份方案 Markdown；移除45份旧文件，候选核查证据迁到 research/reviews，
  本机配置示例迁到 config，来源审查 JSON 保留。历史原文在 Git 143fa63 可恢复。
- README/AGENTS/PROGRAM_STATUS 已改为新入口；实验方法卡中的历史引用绑定固定 Git 版本，
  不把原研究证据重新写成当前实现结论。
- 删除后完整 unittest：Ran 370 tests in 20.244s / OK；14条当前入口相对链接有效。
  本轮没有改 Detector、runner 或结果协议，没有重新声明组件扫描结果。
- 推送包含原本地工作区整理提交143fa63和本轮文档提交，更新既有 Draft PR#9；
  main/A/B分支不改。新head的CI状态需看其对应运行，不预报成功。