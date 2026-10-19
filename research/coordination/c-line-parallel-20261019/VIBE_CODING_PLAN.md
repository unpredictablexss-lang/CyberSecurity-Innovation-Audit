> 2026-10-19 最新刷新：本文件保留为本轮中间记录；最终任务树、并行 Vibe Coding 提示词与持续目标以 C_LINE_TASK_TREE_AND_VIBE_PROMPTS_20261019.md 为准。

# C 线并行开发任务树与 vibe coding 提示词

日期：2026-10-19（Asia/Shanghai）。本文件是本轮 C 线协调计划，不替代 `docs/项目现状与下一步.md`。

## 1. 固定事实

- 当前 checkout：`E:\网安\CyberSecurity-Innovation-Audit`。
- 当前 HEAD：`0f8e6403095ea0fd8d6c8ac41a4789299915d139`。
- 当前分支：`codex/full-runtime-performance-audit-20261014`。
- remote：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`。
- 工作树启动时干净；没有执行 checkout、reset、clean 或覆盖 teammate 工作。
- 显式 `git pull --ff-only origin codex/full-runtime-performance-audit-20261014` 因 `Recv failure: Connection was reset` 失败。现有 `FETCH_HEAD` 仍提供 pinned 远端对象；网络失败不写成“已同步最新”。
- C 线主工作对象：`origin/codex/c4-selective-integration-20261018` = `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df`。
- C 线独立分支：`origin/codex/c-line-ark-runtime-20261018` = `95ca71a446b089229aa67f50dcb06a90b88f6a63`。
- 两个 C 分支不是祖先关系；`95ca...` 独有 1 个提交，`b011...` 独有 4 个提交。禁止把提交消息或分支名当作实现证明。

## 2. 当前任务树

```text
C-line Ark Runtime type safety
├── C1 TypedArray type-origin research
│   ├── 完成：历史 parent/fix 来源与局部 parser probe
│   └── 未闭合：完整 Git 对象链交叉核验、产品构建与影响
├── C2 0.1.0 bounded detector/replay
│   ├── 完成：12 案例与局部 parent/fix 观察
│   └── 阻塞：5 个历史对象相关测试 skip，不能当历史验证通过
├── C3 generalization and holdout preparation
│   ├── 完成：24 项开发机制控制、局部来源/摘要/预算
│   ├── 未完成：16 样本独立人工标签与分歧裁决
│   └── 限制：开发控制不提供真实 Precision/Recall
├── C4 exception guard and selective integration
│   ├── 完成：model 0.6.1 两规则研究包、C4 资料选择性导入
│   ├── 接收代码：model 0.6.2、精确 source selection、默认关闭
│   └── 未闭合：产品入口、构建配置、CIA、动态验证、独立评估
├── C5 exact source binding
│   ├── 完成：commit/tree/blob/source SHA 双规则绑定
│   └── 未闭合：部署 revision 与 product build identity
├── C6 parser namespace recovery probe
│   ├── 完成：证明 Tree-sitter 恢复不能重建 namespace owner
│   └── 结论：不直接增加生产 parser 猜测或 owner whitelist
└── C7 current parallel execution
    ├── C7-DEP: 18 个模型依赖语义漂移复核
    ├── C7-REPLAY: 历史对象库存、parent/fix/safe/unrelated 重放
    ├── C7-HOLDOUT: 双盲独立 holdout 协议与评分门
    └── C7-ADMISSION: exact snapshot/build profile/partial AST 准入 RFC
```

## 3. 执行顺序与并行关系

- 立即并行：`C7-DEP`、`C7-REPLAY`、`C7-HOLDOUT`、`C7-ADMISSION`。
- `C7-DEP` 与 `C7-REPLAY` 共享输入事实但写目录不同；结论必须分别绑定对象哈希。
- `C7-HOLDOUT` 只建立新评估协议和抽样账本，不读取预测包做标签，不用模型自评当真值。
- `C7-ADMISSION` 只提出公共协议变更，不直接修改 contracts/Runner/Catalog。
- 后续串联门：依赖复核和历史对象补齐 -> 冻结新规则 -> 抽取真实目标规则适用 holdout -> 双人盲标/裁决 -> 只有独立真值可算指标。
- 动态验证只允许授权隔离环境；当前普通测试子进程不是不可信构建或 PoC 沙箱。

## 4. 持续执行原则

每个子 Agent 必须：

1. 从只读核验开始，只写自己的唯一目录。
2. 缺对象、partial、failed、unexecuted、unknown 均显式记录，不降格为 safe。
3. 保留 positive/fixed/safe/unrelated/unknown 控制和失败尝试。
4. 不 fetch、checkout、push、merge、建 PR 或调用外部扫描器。
5. 不声称新漏洞、产品 CIA、CVE、Precision/Recall 或零 FP/FN。
6. 在证据未闭合时继续完成离线可执行部分、补对象清单和下一实现切片，不停在“初步分析”。
7. 公共契约变更与算法修复分离，兼容性测试单独交付。

## 5. 并行 vibe coding 提示词

### C7-DEP

角色：C++/ArkCompiler Runtime 静态分析语义审查员。

持续目标：完成 18 个 Ark Runtime 模型依赖的语义漂移审查、版本化建议、可重放输入清单和 unknown 账本。

任务：
- 以 `b011ea0...` 的 C3/C4 manifests 与 model 0.6.2 为基线。
- 逐项核对 repo/commit/tree/blob/source SHA、函数/宏/类型/效果摘要。
- 将差异分类为 equivalent、semantic_drift、needs_re_review、unknown，禁止名称匹配推断。
- 为每项给出最小 replay fixture 与 positive/fixed/safe/unrelated 控制建议。
- 只写 `research/experiments/ark_runtime/c7_dependency_drift_20261019/`。
- 交付 `README.md`、`dependency_review.json`、`versioning_proposal.md`、`replay_plan.md`、命令/环境/哈希记录。

### C7-REPLAY

角色：固定 Git 对象与历史漏洞对照验证工程师。

持续目标：完成历史对象可用性审计、可复现 replay/控制脚手架和实际可执行部分。

任务：
- 扫描本地 pinned Git objects，不 fetch、不改上游对象库。
- 对 parent、fix、safe、unrelated、unknown 分别核对完整来源身份。
- 运行现有 replay/单测到独立输出目录；缺对象时交付 fail-closed 证据与最小补对象清单。
- 只写 `research/experiments/ark_runtime/c7_historical_replay_20261019/`。
- 交付 `README.md`、`object_inventory.json`、`replay_results.json`、`controls_matrix.json`、`next_object_manifest.json`。

### C7-HOLDOUT

角色：检测器独立评估与证据门工程师。

持续目标：产出可交给两名独立人工审查者的冻结 holdout 协议、抽样账本、双盲源码包、标签/裁决模板和 fail-closed 评分门。

任务：
- 不读取预测文件给审查包，不由模型自标。
- 按根因家族建立 inclusion/exclusion ledger。
- 设计新规则冻结后抽取 target-rule-applicable 的 vulnerable/fixed 与 safe/unrelated 样本。
- 生成 reviewer A/B 隔离包、既往暴露声明、admin 随机 ID 映射、双标和分歧裁决模板。
- 只写 `research/evidence/ark_runtime/independent-holdout-20261019/`。
- 人工标签未完成前，TP/FP/FN 与 Precision/Recall 均保持不可估计。

### C7-ADMISSION

角色：OHScanner 公共契约、Runner/Catalog 与证据门架构审查员。

持续目标：形成 exact snapshot/build-profile 来源身份与局部 partial AST 证据准入 RFC、兼容性测试矩阵、验收清单和实现边界。

任务：
- 定义区域范围、错误/依赖污染、summary signature、构建身份、valid/unknown/not_analyzed 区域、聚合状态和局部候选保留。
- 保持 v1 只读兼容、v2 source-bound，旧 ID/review/EvidenceObligation 不重写。
- 设计 partial/mixed/over-budget 等兼容性控制。
- 只写 `research/methods/ark_runtime/admission_20261019/`。
- 不直接改公共代码；将 contracts/Runner/Catalog 变更拆成后续独立实现任务。
