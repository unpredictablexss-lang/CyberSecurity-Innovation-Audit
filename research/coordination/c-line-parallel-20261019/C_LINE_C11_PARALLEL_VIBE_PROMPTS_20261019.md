# C 线 C11 并行任务、Vibe Coding 提示词与持续目标

更新：2026-10-19（Asia/Shanghai）。
执行基线：`codex/c-line-known-vuln-optimization-20261019` @ `ab30df6a01797af455d2abbbc9533ab15964ee68`。
固定输入：审查原文 blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`；已知 Ark 9 案例、公开 CVE 17 项、人工 candidate 4 项。
边界：静态命中只允许 `candidate/unassessed`、`explicit unknown`、`not-applicable` 或可审计 limitation；0 findings、partial、blocked、skip、组件 PoC 和模型自评都不能证明安全或产品漏洞。

## 当前任务树

```text
C11 known-vulnerability scan closure
├── C11-ALIAS-CROSS-HELPER：Ark gap rules 的 alias/cast/helper/loop 泛化
├── C11-KNOWN-CASE-CORPUS：审查记录到 known-case/规则/控制的全量 disposition
├── C11-PERFORMANCE-ADMISSION：覆盖不变的性能、资源边界和交付准入
└── C11-INTEGRATION：负责人合流、统一回归、schema/Runner 门与 push 审批
```

## C11-ALIAS-CROSS-HELPER

- 写范围：隔离 worktree 中 `src/ohscanner/detectors/ark_runtime/` 的语义模块、对应 Ark tests/fixtures、`research/experiments/ark_runtime/c11_alias_cross_helper_20261019/`。
- 结构化 Vibe Coding Prompt：

```yaml
role: Ark Runtime alias and cross-helper semantic engineer
objective: >
  在不放宽证据门的前提下，为已知 IAO7GO、I7W51D、IB8BCA、CVE-2025-24304、
  IBS5YG、I7KZJ7、IC7B8Q、I7E0FM、IAO7E8 增加 alias、cast、wrapper/helper、
  loop backedge 的有限泛化，确保父输入命中 candidate/显式 unknown，
  fixed/safe/unrelated 不产生同根因 candidate。
inputs:
  - ab30df6a01797af455d2abbbc9533ab15964ee68
  - dbedea677c8dc70c1b0066c7bc52df27bcff06ea
  - existing Ark fixtures and source-bound replay records
write_scope:
  - src/ohscanner/detectors/ark_runtime/*
  - tests/detectors/ark_runtime/*
  - research/experiments/ark_runtime/c11_alias_cross_helper_20261019/
constraints:
  - 不使用外部扫描器、历史 verdict、名称相似性或模型自评
  - 不改公共 contracts/Runner/Catalog；需要变更时停止并报告
  - partial/blocked/unknown 不转 safe，0 findings 不作安全结论
acceptance:
  - 既有 9 案例和 170 项 Ark 回归不退化
  - alias/cast/helper/loop 每类都有 positive/fixed/safe/unrelated/unknown
  - rule ID/version、commit/tree/blob/source hash、scope/profile 可审计
  - focused/full tests 的 pass/fail/skip/block 和限制可复现
continuation:
  - G11-AH-1 alias identity
  - G11-AH-2 cast/sign-width
  - G11-AH-3 wrapper/helper summaries
  - G11-AH-4 loop backedge invalidation
  - G11-AH-5 historical replay/profile closure
```

- 持续执行目标：每轮只闭合一个机制并保留最小 patch；若 alias/cast/helper/loop/profile/replay 任一项未闭合，下一轮继续该切片，不用新增规则数量替代证据。

## C11-KNOWN-CASE-CORPUS

- 写范围：隔离 worktree 中 `src/ohscanner/detectors/known_cves.py`、`tests/fixtures/known_cases/`、`tests/detectors/test_known_case_corpus.py`、`research/experiments/known_vulnerability_coverage_20261019/`。
- 结构化 Vibe Coding Prompt：

```yaml
role: known-vulnerability corpus and bounded rule engineer
objective: >
  将审查记录的 17 个公开漏洞、5 个本地危险形状、4 个人工 candidate
  和 2 个排除项转成 source-bound disposition/known-case corpus；
  保证已知危险输入产生 candidate、explicit unknown、not-applicable 或
  limitation，禁止静默 0、伪造 replay 或把候选升级为产品漏洞。
inputs:
  - source audit markdown and import manifest
  - pinned upstream/current Git objects already present locally
  - current C/C++/interface/data detector capabilities
write_scope:
  - src/ohscanner/detectors/known_cves.py
  - tests/fixtures/known_cases/*
  - tests/detectors/test_known_case_corpus.py
  - research/experiments/known_vulnerability_coverage_20261019/
constraints:
  - 不依赖外部扫描器或 CVE 名称相似性推语义
  - 没有固定源对象就写 source unavailable/unknown
  - 组件 PoC、ASan、公告、静态 candidate 不升级产品确认
acceptance:
  - 28 个审查条目逐一有 source identity 和 disposition
  - 本地 5 项至少 candidate/limitation，排除 2 项有具体反证
  - 4 项人工 candidate 保持 candidate/unassessed
  - positive/fixed/safe/unrelated/unknown 控制齐全且无同根因固定侧误命中
continuation:
  - G11-KC-1 complete audit ledger
  - G11-KC-2 local component rules
  - G11-KC-3 OpenHarmony source mapping
  - G11-KC-4 human candidate mappings
  - G11-KC-5 cross-file/profile generalization
```

- 持续执行目标：所有条目必须最终有 disposition；缺源码、缺权限链或缺 CIA 证据时持续保留 unknown/obligation，不得写“扫描通过”。

## C11-PERFORMANCE-ADMISSION

- 写范围：隔离 worktree 中 `research/experiments/performance_20261019/`、`research/deliveries/admission_20261019/` 和独立脚本；不改生产 Detector。
- 结构化 Vibe Coding Prompt：

```yaml
role: scanner scaling and competition admission engineer
objective: >
  在相同 source identity 与覆盖集合上验证 batch、shard/aggregate、cache、
  2000 文件、32MiB 总源码和 1MiB blob 限制；随后按竞赛交付清单审计
  分析、CWE/CVE、PoC、影响版本/分支、修复重验、性能创新和报告完整性。
inputs:
  - ab30df6a01797af455d2abbbc9533ab15964ee68
  - existing Ark/known CVE verification records
  - competition deliverables checklist
write_scope:
  - research/experiments/performance_20261019/
  - research/deliveries/admission_20261019/
  - independent scripts and reports only
constraints:
  - 不以吞吐量替代正确性，不扩大默认限制而无兼容实验
  - 不标 Draft Ready、不 merge、不把 candidate 数当安全证据
acceptance:
  - before/after source hashes、coverage、finding identities 和 verdict drift 可比
  - wall/RSS 的 median/tail、env、失败边界、partial/unknown 变化完整
  - 每个交付项有 evidence status、owner、blocking condition、minimal remediation
continuation:
  - G11-PA-1 baseline
  - G11-PA-2 batching
  - G11-PA-3 shard invariance
  - G11-PA-4 cache/limits
  - G11-PA-5 delivery audit/remediation
```

- 持续执行目标：性能线持续追求“覆盖不变且瓶颈可解释”；准入线持续维护缺口清单，只有真实证据闭合才减少 blocker，不以工作量或模型同意关闭。

## 合流规则

1. 三条线只在各自隔离 worktree 和写范围内修改，不 commit/push/merge 到公共分支。
2. 算法修复、公共契约/Runner/Catalog、证据/文档分别形成提交。
3. 负责人合流前运行 Ark focused/full、known-case corpus、Runner/Catalog、schema v2/legacy v1、compileall、JSON、docs budget 和 diff check。
4. push 前更新 `docs/项目现状与下一步.md`，并在聊天中说明变更、实际验证、限制、branch/full SHA/commits。
