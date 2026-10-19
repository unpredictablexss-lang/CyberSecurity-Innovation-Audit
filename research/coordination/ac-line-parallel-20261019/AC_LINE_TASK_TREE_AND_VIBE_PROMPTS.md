# AC 线任务树、并行设计与 vibe coding 提示词

日期：2026-10-19（Asia/Shanghai）。
目标：在保留现有 dirty worktree 和本地证据的前提下，把 A 线已确认的源码漏洞转成可回归扫描能力，并继续推进 C 线 Ark Runtime 已知反例、历史 replay、审计导入与独立 holdout。

## 0. 已核验事实与边界

- 主 checkout：`codex/full-runtime-performance-audit-20261014` @ `0f8e6403095ea0fd8d6c8ac41a4789299915d139`，本地未跟踪 `research/coordination/`、`research/evidence/ark_runtime/`、`research/experiments/ark_runtime/` 保留。
- A 线固定输入：`origin/codex/a-line-scanner-regression-20261018` @ `758d22f354b4aede80d21f321761e4515ab86047`；其中 `research/deliveries/a-line-sample30/20261018/report/technical-report.md` 确认 `ohscanner-contacts-path-traversal-001`，但该发现来自相邻上下文审计，不是原扫描器直接命中。
- C 线固定输入：`codex/c-line-scanner-optimization-20261019` @ `7af25f5ced471e5d6acc8cf5efd4c696275ce940`，已有 Ark Runtime 0.7.0 的 type-origin、exception-guard、partial-owner 修复和 source-audit reconciliation scaffold。
- `源码漏洞审查记录_20261018.md` 在 checkout、本地全部提交树、父目录和本地 pinned objects 均未找到；显式 GitHub fetch 亦因 HTTPS/443 连接失败。不得声称已读取该文件。当前替代输入只能是 A 线 sample30 技术报告、C3 review counterexamples、C4 unknown cases、C7 replay fail-closed 记录和 C8 `known-source-findings.json`。
- 公共 contracts/Runner/Catalog、schema v2/v1、finding identity 和历史报告不得被并行算法线直接改写；公共变更必须单独集成提交并带兼容性测试。
- 所有新输出默认 `candidate/unassessed`，`validated_vulnerability=0`。partial/failed/skip/unknown 不是 safe 或 miss；没有独立真值不得计算 Precision/Recall 或声称零 FP/FN。

## 1. 当前任务树

```text
AC-line source-bound scanner assurance
├── AC-PATH-01 A 线路径穿越检测器
│   ├── 输入：sample30 `ohscanner-contacts-path-traversal-001`、target_adapter、fixed/safe controls
│   ├── 产出：局部 path composition -> delete/write sink 规则、五类控制、回归
│   └── 未闭合：产品 SELinux/构建/完整 IPC trace、CWE/CVE 上游确认
├── AC-REPLAY-02 C 线已知漏洞/反例 replay
│   ├── 输入：C3 six type-origin counterexamples、C4 guard/owner controls、C7 missing-object ledger
│   ├── 产出：scanner-to-control replay、vulnerable hit / fixed miss / safe/unrelated / unknown 映射
│   └── 未闭合：Ark 历史 parent/fix Git objects、独立真值
├── AC-AUDIT-03 源码审查导入与对账
│   ├── 输入：缺失的 `源码漏洞审查记录_20261018.md`、C8 audit schema、known-source-findings
│   ├── 产出：fail-closed import manifest、finding-to-rule/control 对账、可重跑脚本
│   └── 未闭合：缺失原文条目、repo/commit/tree/blob/source hash、产品影响
└── AC-HOLDOUT-04 规则冻结、holdout 与性能
    ├── 输入：Ark Runtime 0.7.0、A/C 控制矩阵、resource limits
    ├── 产出：rule freeze、独立人工标签包、coverage/partial/unknown/wall/RSS 记录
    └── 未闭合：独立盲化评审、可靠 truth、Precision/Recall
```

## 2. 并行执行规则

1. 三条实现线只写各自唯一文件范围；任何公共 contracts/Runner/Catalog 修改留给 `AC-INTEGRATION`。
2. 每条线先固定 base commit、输入 hash、命令和预期控制，再改代码；不覆盖 teammate 工作树、不 reset、不隐式 fetch/checkout、不调用外部扫描器。
3. 测试至少覆盖 positive、fixed、safe、unrelated、unknown；失败、skip 和外部 source unavailable 原样入账。
4. 只有真实入口/权限边界、可达敏感操作、触发条件、具体 CIA 影响和可审计证据同时满足，才允许 `confirmed/reportable`；本轮算法线不得自行升级。
5. 每条线输出：结构化 vibe prompt、最小 patch、控制矩阵、exact argv/env、前后行为、失败/限制、下一持续切片。

## 3. 结构化 vibe coding 提示词

### AC-PATH-01 — A 线路径穿越检测器

- 角色：OHScanner C++/数据流路径安全 Detector 工程师。
- 持续目标：让 sample30 已确认的 `PortraitFileName -> path join -> DeleteFile/unlink` 边界破坏成为可重复的 scanner positive regression，同时 fixed/safe/unrelated 不误报。
- 唯一写范围：A 线 worktree `research/experiments/ac_parallel_20261019/worktrees/path-traversal/` 内新增 `src/ohscanner/detectors/cpp/path_traversal_detector.py`、对应 `tests/detectors/cpp_path_traversal/` 和 fixture；本线不得改 `contracts.py`、`runner.py`、`catalog.py` 或历史报告。
- 输入：`research/deliveries/a-line-sample30/20261018/report/technical-report.md`、`poc/ohscanner-contacts-path-traversal/generated/*.inc`、`target_adapter.cpp`、`patched_target_adapter.cpp`、`evidence/reconciliation.json`。
- 算法边界：追踪不可信字段/调用者输入进入路径拼接，识别 `DeleteFile`/`unlink`/写入 sink；basename、canonical path、allowlist、数字 ID 校验作为 guard 事实。局部 AST/lexical fact 只产生 candidate，不证明权限支配、攻击者控制或 CIA。
- 任务：1) 固定 vulnerable/fixed/safe/unrelated/unknown fixture 和 source SHA；2) 实现最小 detector 与稳定 finding identity；3) 记录 attack 3/3、fixed 3/3、safe 3/3、fixed-safe 3/3 与 scanner 前后行为；4) 生成 rule/method/limitation 文档；5) 持续切片扩展到 IPC/UID/permission dominance 与跨文件 wrapper。
- 完成门：新 Detector 测试和既有 C++ regression 不回归；vulnerable 必须命中、fixed/safe/unrelated 不得新增 candidate、unknown fail-closed；输出 exact 命令、hash、wall/RSS、限制。禁止把 sample30 PoC 当产品完整镜像证明，禁止自算 Precision/Recall。

### AC-REPLAY-02 — C 线已知反例与历史 replay

- 角色：Ark Runtime source-bound replay 与控制矩阵工程师。
- 持续目标：把 C3/C4/C7 已知反例转成 scanner replay，使预期 vulnerable hit、fixed miss、safe/unrelated、unknown 均有机器可核验映射；缺 Git object 必须 blocked/unknown。
- 唯一写范围：C 线 worktree `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/type-origin/` 内 `research/experiments/ark_runtime/c8_known_vulnerability_replay_20261019/` 和相关 test fixture；不改公共 contracts/Runner/Catalog。
- 输入：`C3_REVIEW_COUNTEREXAMPLES.json`、`C4_EXCEPTION_GUARD.md`、`C4_UNKNOWN_CASES.md`、C7 `replay_results.json`/missing-object ledger、C8 `known-source-findings.json`。
- 任务：1) 建立 finding-to-rule/control/source hash 清单；2) 运行 0.7.0 Ark detector cases，保留 hit/miss/unknown；3) 对历史 parent/fix/current object inventory 做 fail-closed 检查；4) 对 positive/fixed/safe/unrelated/unknown 生成可重复脚本和 run manifest；5) 持续切片补 alias merge、跨函数 effect summary、宏/跨 TU。
- 完成门：已知本地控制可重现，历史缺对象明确 skip/error 不计通过；任何 0 findings 只记覆盖结果，不写 safe；输出 exact argv、source/tree/blob SHA、失败/unknown、wall/RSS 和下一依赖清单。

### AC-AUDIT-03 — 源码审查导入与漏洞对账

- 角色：源码漏洞审查导入、证据绑定和 scanner reconciliation 工程师。
- 持续目标：为 `源码漏洞审查记录_20261018.md` 建立 fail-closed 导入器；文件缺失时只输出 blocked/missing/unknown，文件补齐后可直接抽取条目并对账到规则/控制。
- 唯一写范围：C 线 worktree `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/partial-owner/` 内 `research/experiments/ark_runtime/c8_source_audit_reconciliation_20261019/`；不改 Detector 语义、公共契约或历史 ID。
- 输入：C8 `audit-schema.json`、`input-manifest.json`、`known-source-findings.json`、`expected-regressions.json`、A sample30 `technical-report.md` 的 confirmed finding 与 PoC manifest。
- 任务：1) 让 `reconcile.py` 在缺文件、存在但无条目、schema invalid、hash mismatch 时分别 fail-closed；2) 映射 entry -> detector/rule/control/source identity；3) 将 A 线 path-traversal confirmed finding 作为 substitute evidence 记录，不伪造缺失原文；4) 生成 expected-regressions、run-manifest、unknown ledger；5) 持续切片支持多文件/多 commit/source hash、稳定 finding identity 和 v2/v1 只读兼容。
- 完成门：`python reconcile.py --strict-input --write-run-manifest` 可重复运行并给出明确 blocked 状态；有输入时条目、source hash、控制映射可审计；不得生成 Precision/Recall、CWE/CVE 或产品 confirmed 结论。

### AC-HOLDOUT-04 — 规则冻结、独立 holdout 与性能

- 角色：Ark Runtime 规则冻结、独立标注包和性能覆盖工程师。
- 持续目标：冻结 0.7.0 语义，生成独立人工盲化 holdout，记录 coverage/partial/unknown/wall/RSS/Token/费用；未完成独立 truth 前不计算指标。
- 唯一写范围：C 线 worktree `research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard/` 内 `research/experiments/ark_runtime/c8_holdout_20261019/` 与 `research/methods/ark_runtime/rule_freeze_0.7.0/`；不调参、不删历史结果、不改公共 schema。
- 输入：0.7.0 Ark detector source、C3 holdout manifest、A/C control matrices、`docs/Agent方案与对照实验.md` 的真值/指标边界。
- 任务：1) 写 rule freeze manifest（source hash、rule version、profile、resource limits）；2) 生成 positive/fixed/safe/unrelated/unknown 与 parent/fix/safe holdout packet；3) 生成盲化 assignment/label template、分歧裁决和 active/paused timing 字段；4) 运行本地 tests、compileall、文档预算和 wall/RSS；5) 持续切片增加跨版本、多仓和独立 reviewer queue。
- 完成门：冻结后不调参；所有 prediction/coverage/unknown/性能字段可重放；缺独立 truth 时 `eligible_for_metrics=false`，不得发布 Precision/Recall 或零 FP/FN。

## 4. 集成与持续目标

- `AC-INTEGRATION`：三条实现线完成后，在独立干净 worktree 选择性迁入，单独处理 Catalog/Registry 公共变更，运行 Ark Runtime、C++、Runner applicability、schema v2/v1 compatibility、compileall、文档预算和 `git diff --check`；更新 `docs/项目现状与下一步.md` 后才谈 push/PR/Ready。
- 持续执行目标：每轮只推进一个可审计切片，保留 base/patch/test/evidence/unknown；网络失败不阻塞本地开发，连续三次失败后记录并五分钟后再同步；最终交付必须包含完整分析、受支持 CWE/CVE、可复现 PoC、影响版本/分支、修复与重验、性能和创新证据、完整报告。

## 5. 第三次显式同步后的任务树更新

2026-10-19，第三次 `git fetch --prune origin` 成功；当前主分支 tracking 仍与 `0f8e6403095ea0fd8d6c8ac41a4789299915d139` 一致，未覆盖 dirty/untracked 产物。最新本地 remote objects 显示：

- `origin/codex/a-path-source-sink-20261018` @ `bc27c2ca520223acec6ae6e44e1535e5e4e73404` 已包含 `ohscanner.cpp.path_traversal` 0.1.0-research、Contacts exact excerpt、positive/fixed/safe/unrelated/unknown controls 和 evidence；尚未注册 Catalog。
- `origin/codex/a-line-scanner-regression-20261018` 已推进到 `9b99f10`，新增 bounded chunk/ABCD scan 和 C-line replay review。
- `origin/codex/c-line-ark-runtime-replay-20261019` 已包含 frozen history replay、run-summary、hash-manifest、两个 blind holdout packet 和 coverage ledger；run-summary 仍 `blocked`，不能计为历史漏洞 replay 通过。
- `源码漏洞审查记录_20261018.md` 在同步后的全部本地对象中仍不存在。

据此，当前进行中任务调整为：

1. `AC-PATH-01`：不再重复实现；审查/选择性迁入远端 path detector，并验证 sample30 confirmed finding 能被 scanner candidate 回归命中。
2. `AC-REPLAY-02`：审查远端 history replay 与 C3/C4/C8 控制映射，补缺失对象账本和 known-vulnerability scanner replay。
3. `AC-AUDIT-03`：继续 fail-closed 导入缺失审查记录，将 A path delivery/sample30 finding 仅作为 substitute evidence。
4. `AC-HOLDOUT-04`：审查远端 blind holdout packets、freeze/coverage ledger，补独立标签与指标资格门。
5. `AC-INTEGRATION-05`：单独提交 Catalog/Runner 兼容性变更，将 `ohscanner.cpp.path_traversal` 显式注册为 research candidate；公共变更不得与算法修复混提交。

持续目标保持：每个切片都绑定完整 SHA/hash、exact argv/env、控制结果和 unknown；远端 blocked/missing/skip 不计通过，最终不擅自 push、merge 或标记 Ready。
