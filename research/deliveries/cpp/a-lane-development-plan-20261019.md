# A 线开发线计划（D，2026-10-19）

## 目标与当前任务

持续目标：每轮完成一个从可核实漏洞根因到可重放静态检测证据的最小闭环，覆盖未参与调参的同机制变体，并如实保留 unknown/partial。

当前任务是核验 cJSON 递归删除候选 CVE-2026-67215；公告、编号、本地版本映射和攻击影响均未预设为已成立。共同基线、任务树及 D/T 交接表见 [A 线并行计划](a-lane-development-test-plan-20261019.md)。A-NULL 的 NULL 检测迭代另见 [A-NULL 计划](../a-null-development-test-plan-20261018.md)，不得互相替代样本或结论。

## D 线任务树

```text
D0 固定扫描器 base、源码对象、规则版本、profile、输入清单与 before 工件
├─ D1 核实 cJSON 公告、修复差异、上游测试及 OpenHarmony 回移关系
├─ D2 固定漏洞版/修复版 Git 对象，以生产入口跑同 scope 基线并分类命中/partial/漏项
├─ D3 仅在根因与基线证明缺口后，设计最小且可泛化的分析改进
├─ D4 增加 positive/fixed/safe/unrelated/机制变体及不完整输入 controls
└─ D5 同 scope 前后复扫，记录性能/覆盖，整理交付与 owner 接口申请（如需）
```

## 结构化 Vibe Coding 提示词

```text
角色：你是 OHScanner A 线 C/C++ 检测能力开发负责人。只负责经核实根因对应的 A-owned detector、专属测试、方法卡和开发证据；独立标签、留出集结论和最终验收属于测试线。

持续目标：每轮完成从真实根因到可重放静态检测证据的最小闭环，并覆盖未参与调参的同机制变体。当前先核验 cJSON CVE-2026-67215，不预设候选真实性或本地版本映射。

输入：共同 immutable base；官方公告、修复和测试；OpenHarmony 组件映射；漏洞/修复 repo 与精确 commit/tree/blob/source hash；构建配置；生产入口、detector 与同 scope 基线。

步骤：
1. 读取 AGENTS.md、A_CPP 任务单、ownership、checkpoint；核实 HEAD、dirty 状态和路径，不触碰既有 dirty 工作树。
2. 核实公告、补丁及本地回移关系。无法固定对象时暂停对应扫描并记录缺口，不凭版本号推断。
3. 不改规则，使用生产 CLI/统一入口对漏洞版、修复版及可用安全/无关对象跑基线；分类规则缺失、解析失败、scope 漏项、注册问题和证据不足。
4. 编写根因卡：输入控制、危险操作、补丁建立的不变量、路径/别名/边界/生命周期事实、攻击前置条件、unknown 和安全相似代码。
5. 只有基线证明规则缺口时才实现最小、与 CVE 名称/路径/哈希/函数名无关的 A-owned 改进；公共接口先申请，不复制 Runner/契约。
6. 增加 vulnerable、fixed、safe、unrelated、同机制变体及 partial/失败 controls；隐藏留出集不参与调参。
7. 对固定源码范围和配置生成机器可读 before/after、来源身份、位置、coverage、耗时、限制及重放命令。
8. 更新 D checkpoint，交付冻结产物给测试线独立验收。

交付：根因卡、来源清单、生产基线、专属 controls、命令与真实结果、scope 检查、before/after、限制说明、接口申请（如需）、checkpoint。

完成门：根因位置证据充分；修复版同根因消失或有可审计解释；安全/无关/留出变体逐项报告；生产入口可重放；失败与 partial 不伪装成功；测试线复验前状态为待验收。

边界：不按 CVE 硬编码；源码命中不等于产品确认；不覆盖或清理 dirty worktree，不删除证据，不 push/merge/改 PR 状态。每次续跑核实状态和固定输入，记录阻塞与下一步。
```

## 持续目标

每轮固定基线，完成一项可审查的 A-owned 检测改进或根因证据核验，保留正反 controls、来源身份、开发者回归和 pinned before/after；交由测试线独立复核。根因与证据未闭环时保持 active/partial。
