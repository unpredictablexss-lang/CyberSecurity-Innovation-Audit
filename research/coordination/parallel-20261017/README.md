# 四线并行开发交付入口（2026-10-17）

继续使用现有 Git 仓库。分支、worktree、Python/Node 依赖、dist、DB/artifacts、端口分别隔离。
本轮只建立可交付的共同平台基线和任务边界，没有重写扫描器，也没有接入真实模型。

## 从哪里开始

1. 读 AGENTS.md 和 docs 三份核心文档。
2. 读本机 `/home/audit/ohscanner/records/parallel-20261017/workspace-manifest.json`；核对本线 path、branch、baseline 完整 SHA、env_file。不要凭短 SHA 猜基线。
3. 读下表自己的任务。只有共同平台基线已经验收；旧 A/B 最新代码仍需逐项迁入和复审。
4. `cd <本线 path>`，`source <本线 env_file>`；用 `.venv-web/bin/python`，不用正式服务的管理脚本。
5. 交付前运行：`.venv-web/bin/python -m scripts.check_change_scope --base "$OHSCANNER_BASELINE" --lane "$OHSCANNER_LANE"`。

| 线 | 分支 | 第一项任务 | 任务单 |
|---|---|---|---|
| A / cpp | work/cpp-20261017 | 从 A 原分支选择最小算法/证据改进，修复审查阻塞 | [A_CPP.md](A_CPP.md) |
| B / ipc | work/ipc-20261017 | 拆分交付现有 v0.8.0 家族实现，验证来源/授权建模 | [B_IPC.md](B_IPC.md) |
| UI | work/ui-20261017 | 审计新建与结果入口的模块化组件，先做现有运营表单 smoke | [UI.md](UI.md) |
| 平台 | work/platform-20261017 | 源码/规则规划纯服务，公共 API 接线由集成人完成 | [PLATFORM.md](PLATFORM.md) |

端口 18770 为集成验收，18771/18772/18773/18774 分别为 cpp/ipc/ui/platform。
这些端口分配仅用于本地开发，不是远端服务，不保证未来启动时仍空闲。
本轮环境准备完毕后不常驻启动四套 Worker；需要时用各线 start.sh。
一个数据目录内仍是现有单消费锁，未验收多个扫描 Worker 共享队列的并发。

## 公共文件归集成人

机器可读范围见 `config/collaboration/ownership.json`。各线只能修改自己的 allowlist；
contracts、runner、catalog、API 装配、SQLite、Worker、CI、全局路由/导航、全局依赖和权威状态文档由集成人写。
UI 可修改页面/独立 feature/component，但新的全局导航接线单独申请。
平台首项只写 sources/planning 新模块，不触碰现有 API/服务/存储。未被列出的文件默认越界。

需要公共改动：在 `research/deliveries/<lane>/` 写接口申请，列出现有调用者、最小 diff、兼容性与验证；
由集成人先落实公共契约，再给依赖它的线更新基线。不能私自放宽所有权表。
范围检查不是沙箱；集成人必须在可信代码中、以自己给定的基线重跑，不能采信队友自报检查通过。

## 需求的优先级与实现事实

三份新增材料已保存到 [产品参考](../../product/20261017/)，并记录原始/入库 SHA-256；Markdown 仅清理行尾空白，原件另存本机 records/product-originals。
PRD 用于产品流程；HTML 用于视觉参考；技术文档用于目标与方案讨论。
材料中的版本、菜单和能力描述不自动覆盖当前代码/测试结论。
共同基线已有：固定 Git、统一 Detector、CLI/API/Worker、覆盖/候选/报告、运营任务。
目标待开发：按语言与证据能力给出规则规划、审计 UI 重组、真实工具型模型 Agent、完整产品漏洞闭环。
不做空菜单、虚构成功任务、默认确认漏洞或多套独立引擎。

## 最小交付清单

按 [DELIVERY_TEMPLATE.md](DELIVERY_TEMPLATE.md) 填写，算法改动与公共协议变更分开。
提供 base/head 完整 SHA、精确文件、命令、真实通过/失败/skipped、源码绑定与局限。
提交到自己的本地分支后交集成人验收；此次授权不包括 push、merge main、Draft Ready 或发送队友消息。
集成顺序：平台契约（如需）→ 各线最小提交 → 全量/来源/旧报告/UI 验收 → 冻结下一基线。
原工作区不得 reset、clean、stash、自动 rebase 或覆盖；不得用整条 A/B 分支合并替代选择性验收。
