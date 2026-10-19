> 2026-10-19 最新刷新：本文件保留为本轮中间记录；最终任务树、并行 Vibe Coding 提示词与持续目标以 C_LINE_TASK_TREE_AND_VIBE_PROMPTS_20261019.md 为准。

# C 线扫描器优化持续执行目标

总目标：把已暴露的 type-origin、exception guard、partial owner 问题转成可重复的扫描器语义修复和正/固定/安全/非相关/未知控制；每轮只推进一个可验证切片，保留失败和 unknown，不伪造准确率或产品漏洞结论。

## 目标阶梯

1. G1 反例固化：每个已知机制至少有最小 source-bound 反例和 fixed/safe/unrelated/unknown 控制。
2. G2 语义修复：type-origin、exception guard、partial owner 三条线分别消除明确不健全行为。
3. G3 回归通过：聚焦套件和 detector cases 通过；skip/error 不计通过。
4. G4 集成验收：只在三条线合流后运行完整 Ark Runtime 套件、公共 Runner/Catalog 兼容性和 source-bound schema 检查。
5. G5 独立评估：冻结规则后建立双盲人工 holdout；只有独立可靠真值可计算指标。
6. G6 产品闭环：入口/权限、可达敏感操作、触发、CIA、产品构建、版本/分支、修复重验和 CVE 证据全部满足后才升级。

## 持续执行规则

- 每轮结束必须产生可复现命令、哈希/commit、控制结果、失败、限制和下一最小切片。
- 未完成任务继续沿目标阶梯推进，不停留在“初步分析”。
- 公共契约变更与算法修复分开提交。
- 网络、缺 Git 对象、optional dependency 或环境错误只能记阻塞，不写算法失败或安全结论。
- 不覆盖 dirty worktree、teammate 产物、历史报告 ID/review/EvidenceObligation。

## 本轮持续追加

- G7 C7-ADMISSION：完成 partial/exact evidence admission RFC 与公共兼容矩阵，之后再做独立公共代码实现提交。
- G8 AUDIT-RECONCILIATION：缺失审查记录必须 fail-closed；文件补齐后逐条抽取漏洞、绑定 source identity、映射 Detector/rule/control 并执行预期回归。
- G9 REMOTE-SYNC：网络恢复后显式 fetch，固定最新 commit/tree/blob，核对 C 线分支和审查记录来源，再决定是否合并优化分支。
