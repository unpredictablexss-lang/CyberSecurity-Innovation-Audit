# A 线后续并行任务单（静态扫描）

基线：A 线披露漏洞整合提交 `24b4bef9f3aa58d513069db0613818a2bd363dbd`。比赛范围限定静态扫描；所有报告均为候选，不能表述为产品漏洞确认。各线在独立工作树开发，禁止修改他线工作树；共享 Catalog、Runner、contracts 需要 owner 审查。

## 当前任务树

```text
A 线披露漏洞静态覆盖
├── 已提交 PR：整数边界、资源生命周期、证据回放与 CVE 覆盖矩阵
├── D1：路径检测器（代码/回归已做；CLI 未注册不可达；参数模型审查阻止准入）
├── D3：libpng 46675 typedef/header-aware 静态解析（blocked：vulnerable/fixed 候选 8/7，未区分；上游 pin replay 受网络阻断）
└── D4：cJSON 67216/67215 精确源码回放（blocked：两个受影响版本均 partial，缺权威 fixed 源）
```

## 并行线 D3：libpng 跨函数共享状态

**结构化 Vibe Coding 提示词**

- **角色：** C/C++ 静态分析器开发者，聚焦保守的数据流分析。
- **上下文：** `shared_state_lifetime` 原型对 synthetic 解压样例有效，但精确 CVE-2026-46675 源码因 `png_structrp` typedef pointer 无法配对；不得把 synthetic 命中算成 CVE 覆盖。
- **目标：** 在不硬编码 CVE/函数名的前提下，最小支持 header typedef pointer 归一化并对固定 vulnerable/fixed 源码运行 CLI。
- **边界：** 不改 Catalog、Runner、contracts；不把 blocked/partial 的零 finding 解释为安全；固定仓库 commit、文件 SHA、扫描范围及 detector 版本。
- **步骤：** 固定源码对象 → 复现现状 → 写 failing regression → 加入最小 typedef/type facts → vulnerable/fixed/safe/unrelated/partial 配对 → 记录 CLI JSON/Markdown 与 scope 检查。
- **验收：** 精确 vulnerable 有候选、fixed 和 safe/unrelated 无候选、partial 保持 blocked；focused tests 通过，scope 零违规。达不到时交付可复现 blocked 原因，不做漏洞特定补丁。
- **持续目标：** 每次从 CVE 台账挑一个共享状态/生命周期漏洞，补齐精确版本正负对照；只在证据闭环后提 registry 请求。

## 并行线 D4：cJSON 算法复杂度

**结构化 Vibe Coding 提示词**

- **角色：** C/C++ 静态复杂度分析器开发者。
- **上下文：** `algorithmic_complexity_detector` 目前只有 synthetic 机制回归，尚未证明 CVE-2026-67216/67215 的真实源码区分能力。
- **目标：** 用 pinned vulnerable/fixed cJSON 源码校准现有原型，验证递归/重复遍历等机制是否在修复后消失。
- **边界：** 不使用 CVE 编号、函数名或 patch 文本作为 detector 触发器；不改共享 Registry/Runner/contracts；未知输入保留 partial/unknown。
- **步骤：** 验证 repo commit/tree/blob → 取得最小目标文件闭包 → vulnerable/fixed/safe/unrelated/partial 同范围 CLI replay → 检查候选证据与修复差异 → 仅在通用语义有依据时改实现。
- **验收：** exact vulnerable/fixed 有可解释差异且控制样本不误报；focused tests 与 scope check 通过。否则提交明确缺失的语义事实与 blocked 证据。
- **持续目标：** 按披露漏洞矩阵逐案建立复杂度漏洞 exact-source differential，不将形状样例计入实源覆盖。

## 并行线 D1 后续：路径检测器准入

**结构化 Vibe Coding 提示词**

- **角色：** 静态分析器 owner reviewer。
- **上下文：** `path_safety_detector` 已有 safe/unsafe/partial 回归，但没有 Catalog 注册，因此常规 profile 不会调度。
- **目标：** 核对 A 线所有权、Catalog 注册流程、CLI detector identity 与默认/显式 profile 预期，提出最小且可审查的准入变更。
- **边界：** 不越过 shared-file owner；未经 owner 批准不改 Catalog/Runner/contracts；不可把未调度模块称为生产覆盖。
- **步骤：** 固定 base → 阅读 ownership 与 Catalog contract → 核对 detector ID/schema/version → 跑精确 CLI 正负/partial 样本 → 准备 owner review diff 或记录阻塞。
- **验收：** 已注册时普通/显式选择行为清楚，safe/negative/partial 控制通过，scope 零违规；否则保留未注册状态并提供完整准入草案。
- **持续目标：** 每轮针对一个静态 source-to-sink 漏洞完成规则、回归、CLI 可达性与 owner review 证据。

## 全线持续目标与汇报节奏

每条线持续到其验收条件成立或证据证明被外部条件阻塞；每个迭代提交固定源码 pin、结果文件、focused tests、scope 检查和下一步。D3、D4 未闭环前不纳入本轮比赛 PR 的“已覆盖”统计；D1 在 Catalog 注册前只算研究候选实现。
