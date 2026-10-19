# B 线披露漏洞回归包（OHScanner 0.8.11）

日期：2026-10-19\
代码仓库：`CyberSecurity-Innovation-Audit-b`\
分支：`feat/interface-ipc-detector`\
代码 HEAD：`42c4d7140b67813105d6b8a9d3bea241f25a1209`\
检测器：`ohscanner.interface.ipc` 0.8.11；解释模型 `oh-ipc-2026.10-v17`

## 本轮基准回归

本包的六份 JSON 是此前 0.8.11 基准复验。候选差分用于验证规则对公开补丁代码变化的静态观察，不代表确认漏洞或组件完整覆盖。

| CVE | 修复前→修复后候选 | 解析/状态 | 说明 |
|---|---:|---|---|
| CVE-2022-42463 | 1→1 | partial / blocked | session 白名单候选在修复端仍存在，边界语义未决 |
| CVE-2023-25176 | 1→0 | partial / blocked | TLV 固定宽度长度候选随补丁消失；此处是已知回归，不新增唯一样本组 |
| CVE-2024-39775 | 2→0 | partial / blocked | 拒绝分支传输状态候选随补丁消失；未证明公告根因或影响 |
| CVE-2025-25212 | 3→2 | partial / blocked | 无界观察者候选 1→0，另外两条与此披露点不同 |
| CVE-2025-27247 | 4→3 | partial / blocked | privileged-app bypass 候选 1→0，另三条独立观察 |
| CVE-2025-27563 | 3→0 | partial / blocked | AUTH-03 caller-class 候选随修复消失 |

原始报告 JSON 直接保存在本目录。对应当前 B 分支更早的开发说明见 [PROGRAM_STATUS.md §72](../../../../PROGRAM_STATUS.md)；SHA256SUMS 覆盖本目录所有 JSON 与 README。

## 追加的披露复测

本轮在当前 0.8.11 版本复测四组公开修复对，四组都观察到与目标补丁相关的规则差分；另有一组反向差异未解决。结果独立保存于 [follow-up 复测包](../20261019-disclosure-expansion-followup-v0.8.11/README.md)：CVE-2023-0035（1→0，partial/blocked）、CVE-2023-0036（1→0，complete/completed）、CVE-2024-12082（8→4，partial/blocked）、CVE-2025-26693（4→1，partial/blocked）；CVE-2025-26691 为 7→9，尚未解释，不计匹配。0035/0036 曾在 0.8.9 复测，26693 曾在 0.8.8 复测，12082 曾在另一代码版本有 4→4 结果；不同版本结果不合并成唯一漏洞数量。

CVE-2024-12082 的跨文件 caller-class 契约有合成正/反例：正确 SA gate、无 gate、错误角色、检查晚于敏感查询、其他仓库边界。真实固定提交对也已在 follow-up JSON 中重放。CVE-2025-26691 需要先澄清公开修复提交与逐方法权限要求，不能删去修复端候选来造出预期差分。

## 判定边界与验证

公开披露修复对是有标签开发/回归集，不是独立 holdout。静态候选变化不证明普通应用可达性、产品构建条件、可利用影响或修复闭环；不能据此计算 Precision/Recall。六份基准扫描报告的 `validated_vulnerability` 均为 0；follow-up 原始 replay JSON 只记录静态候选，不含该验证字段。公开 CVE 的历史披露状态与本工具 finding 的验证状态应分开记录。本轮没有运行产品构建、设备 PoC、Harness 或 Agent。

本轮实际全量测试：`PYTHONPATH=. .venv/bin/python -m unittest discover -s tests -q`，**564 项通过，0 失败**；版本影响摘要通过。`git diff --check` 通过。尚未提交或推送。
