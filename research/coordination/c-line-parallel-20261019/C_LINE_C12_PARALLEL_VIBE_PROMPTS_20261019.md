# C 线 C12 并行任务、Vibe Coding 提示词与持续目标

更新：2026-10-19（Asia/Shanghai）。
执行基线：`codex/c-line-known-vuln-optimization-20261019` @ `ddd8556768d679fcc09f1fcb37d10730f49b2c6c`。
对账基线：`origin/codex/c-line-static-20261019` @ `67631f35ea2b8064cffacef33c125b3c73ac0bba`。
固定审查输入：`research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`，blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`。
边界：candidate/unknown/not-applicable/limitation 分层；0 findings、partial、blocked、skip、组件 PoC 和模型自评不能证明安全或产品漏洞。

## C12 任务树

```text
C12 scanner known-vulnerability closure
├── C12-ARK-DEEP-SEMANTICS：effectful helper、numeric cast、CFG loop 的下一语义切片
├── C12-REAL-SOURCE-ADAPTERS：真实 parent/fix 对象、P12/JSON5/Rust 显式适配与 known-case replay
├── C12-PRODUCT-ADMISSION-CLOSURE：build profile、独立 holdout、产品 PoC/修复重验准入
└── C12-INTEGRATION：负责人对账 67631f3 与 ddd8556，合流、统一回归、push/merge 审批
```

## C12-ARK-DEEP-SEMANTICS

### 结构化 Vibe Coding Prompt

```yaml
role: Ark Runtime deep semantic engineer
objective: >
  继续闭合 effectful helper contract、numeric cast/sign-width、最小 CFG loop backedge，
  在既有九个已知案例不退化的情况下减少无依据 unknown，并保证未知语义仍 fail-closed。
inputs:
  - ddd8556768d679fcc09f1fcb37d10730f49b2c6c
  - audit blob dbedea677c8dc70c1b0066c7bc52df27bcff06ea
  - c10/c11 known-case matrices and replay identities
write_scope:
  - src/ohscanner/detectors/ark_runtime/*
  - tests/detectors/ark_runtime/*
  - research/experiments/ark_runtime/c12_ark_deep_semantics_20261019/
constraints:
  - 不使用外部扫描器、历史 verdict、名称相似性或模型自评
  - 不改公共 contracts/Runner/Catalog；需要公共变更立即停下报告
  - effectful、宏、递归、模板、多返回和不可证明 CFG 必须保留 unknown/partial
acceptance:
  - 九个已知父侧仍命中 candidate/显式 unknown，fixed/safe 无同根因候选
  - helper/cast/loop 每个机制有 positive/fixed/safe/unrelated/unknown
  - Ark full/focused、compileall、diff check 和 source identity 可复现
continuation:
  - G12-AS-1 effectful helper source contract
  - G12-AS-2 numeric cast/sign-width
  - G12-AS-3 minimal CFG loop invalidation
  - G12-AS-4 cross-function summary
  - G12-AS-5 official parent/fix replay
```

### 持续执行目标

每轮只推进一个语义机制并保留最小 patch；若官方对象、profile 或产品绑定缺失，持续记录 blocked/unknown，不用更多规则替代证据。

## C12-REAL-SOURCE-ADAPTERS

### 结构化 Vibe Coding Prompt

```yaml
role: real-source identity and artifact adapter engineer
objective: >
  为审查记录的本地危险形状、公开 CVE、P12、JSON5 和 Rust 条目补齐真实 Git/source identity、
  有界适配器和 known-case replay；缺对象必须显式 source unavailable/unknown。
inputs:
  - source audit and import manifest
  - existing local pinned Git objects and known-case manifest
  - current known_cves 0.17.0 and first-party detectors
write_scope:
  - src/ohscanner/detectors/known_cves.py
  - src/ohscanner/detectors/adapters/*（如需新增）
  - tests/fixtures/known_cases/*
  - tests/detectors/test_known_case_corpus.py
  - research/experiments/known_vulnerability_coverage_20261019/
constraints:
  - 不伪造 commit/tree/blob/source SHA，不把路径描述当真实 replay
  - P12/JSON5/Rust 只做有界输入识别和显式 disposition，不假装 C/C++ 语义完整
  - 不修改 Ark 模块或公共 contracts/Runner/Catalog
acceptance:
  - 28 条 disposition 更新为 exact-source、source-unavailable、language-limitation 或 exclusion
  - 本地5项和可固定的公开案例有 parent/fixed/safe/unrelated/unknown 控制
  - 无固定对象条目不计命中、不计通过、不计 safe
continuation:
  - G12-RS-1 object inventory
  - G12-RS-2 local five exact replay
  - G12-RS-3 P12/JSON5/Rust adapters
  - G12-RS-4 OpenHarmony source mapping
  - G12-RS-5 cross-file/profile generalization
```

### 持续执行目标

每个条目必须趋向明确 disposition；缺源对象时持续保留 obligation，只有完整 source identity 和控制闭合才移除 blocker。

## C12-PRODUCT-ADMISSION-CLOSURE

### 结构化 Vibe Coding Prompt

```yaml
role: build profile, independent evaluation and product closure engineer
objective: >
  建立可复算 build/preprocess profile 和独立 holdout 管线；只对满足证据门的候选规划
  授权隔离 PoC、修复与重验，并输出竞赛交付准入缺口。
inputs:
  - ddd8556768d679fcc09f1fcb37d10730f49b2c6c
  - current admission NOT ADMITTED report
  - source audit evidence obligations
write_scope:
  - research/methods/ark_runtime/build_profile_20261019/
  - research/evaluation/ark_runtime_holdout_20261019/
  - research/deliveries/product_closure_20261019/
  - research/deliveries/admission_20261019/
constraints:
  - 不把开发控制当真值，不让模型自评，不计算无可靠标注的 Precision/Recall
  - 动态验证只限授权隔离环境；静态资源受限子进程不是 PoC 沙箱
  - 不标 Draft Ready、不 merge、不升级 candidate 为 confirmed
acceptance:
  - profile manifest 绑定 commit/tree/blob/source/parser/config/toolchain hash
  - holdout 有 family leakage 防护、双盲标签、分歧裁决和审计记录
  - 产品闭环缺入口/权限/触发/CIA/PoC/修复重验时保持 NOT ADMITTED
continuation:
  - G12-PC-1 dependency/profile closure
  - G12-PC-2 holdout freeze
  - G12-PC-3 blind labels/adjudication
  - G12-PC-4 isolated product PoC
  - G12-PC-5 fix/retest and delivery admission
```

### 持续执行目标

持续维护可审计 blocker 清单；只有真实构建、入口、权限、触发、CIA、PoC 和修复重验逐项闭合才减少 blocker。

## 合流与提交

1. 三条线只修改各自隔离 worktree 和写范围，不执行 fetch/checkout/commit/push/merge/reset。
2. 算法、公共契约、证据/文档分别提交；C12-INTEGRATION 先对账 `67631f3` 与 `ddd8556`，禁止 force-update。
3. 合流后运行 Ark focused/full、known-case corpus、Runner/Catalog、schema v2/legacy v1、compileall、JSON、docs budget 和 diff check。
4. push 前更新 `docs/项目现状与下一步.md`，在聊天中说明变更、实际验证、限制、branch/full SHA/commits；未获用户授权不 merge/Ready。
