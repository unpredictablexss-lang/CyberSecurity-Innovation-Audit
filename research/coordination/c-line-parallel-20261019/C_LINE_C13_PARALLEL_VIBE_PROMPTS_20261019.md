# C 线 C13 并行任务、Vibe Coding 提示词与持续目标

更新：2026-10-19（Asia/Shanghai）。
执行基线：`codex/c-line-known-vuln-optimization-20261019` @ `842948084660207fd64399cfd598ed93e5593dcc`。
固定审查输入：`research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md`，blob `dbedea677c8dc70c1b0066c7bc52df27bcff06ea`。
本轮 fetch/pull 因 GitHub 443 失败，只使用本地 pinned refs/objects；不得隐式 fetch 或伪造远端新鲜度。

## C13 任务树

```text
C13 known-vulnerability evidence closure
├── C13-ARK-REAL-REPLAY：九案例真实 parent/fix 对象、selector/profile 和 replay
├── C13-CROSS-FILE-FACTS：权限、canonical path、FD ownership、锁身份等跨文件事实
├── C13-HOLDOUT-PRODUCT-GATE：真实 holdout、产品 PoC/修复重验和准入门
└── C13-INTEGRATION：对账远端 static/optimization，统一回归并提交
```

## C13-ARK-REAL-REPLAY

### 结构化 Vibe Coding Prompt

```yaml
role: Ark Runtime real-source replay and profile engineer
objective: >
  对 CVE-2025-24304、IBS5YG、I7KZJ7、IC7B8Q、I7E0FM、IAO7GO、I7W51D、IB8BCA、IAO7E8
  建立只读本地 Git 对象清单和 parent/fix source-bound replay；缺对象、缺 profile 或缺 selector 时显式 blocked/unknown。
inputs:
  - 842948084660207fd64399cfd598ed93e5593dcc
  - pinned Ark objects and source audit blob
  - existing c10/c12 control matrices
write_scope:
  - src/ohscanner/detectors/ark_runtime/*
  - tests/detectors/ark_runtime/*
  - research/experiments/ark_runtime/c13_ark_real_replay_20261019/
constraints:
  - 不隐式 fetch、不使用外部扫描器、不把短 SHA/URL/路径当对象身份
  - 不改公共 contracts/Runner/Catalog；缺 source/profile 时 fail-closed
acceptance:
  - 每案例记录 repository/commit/tree/blob/source SHA、selector、scope/profile
  - parent/fixed/safe/unrelated/unknown 五态结果可复算
  - 已知九案例不退化，缺失项明确 source unavailable/unknown
continuation:
  - G13-AR-1 object inventory
  - G13-AR-2 exact parent/fix replay
  - G13-AR-3 selector/profile closure
  - G13-AR-4 generated-source/creator dependencies
  - G13-AR-5 product build mapping
```

### 持续执行目标

每轮只闭合一个案例家族或一个 profile/selector 依赖；对象缺失就持续保留 obligation，不用 synthetic control 替代真实 replay。

## C13-CROSS-FILE-FACTS

### 结构化 Vibe Coding Prompt

```yaml
role: cross-file security fact and known-case engineer
objective: >
  为 group-delete membership、canonical app-base、raw FD ownership、共同锁身份、权限边界和跨账号副作用
  建立有界跨文件事实模型，保证已知危险输入产生 candidate/unknown，fixed/safe/unrelated 不产生同根因候选。
inputs:
  - source audit and known_case_manifest
  - local pinned source objects and existing adapter boundaries
  - known_cves 0.17.0 and first-party C/C++ detectors
write_scope:
  - src/ohscanner/detectors/known_cves.py
  - src/ohscanner/detectors/adapters/*
  - tests/fixtures/known_cases/*
  - tests/detectors/test_known_case_corpus.py
  - research/experiments/known_vulnerability_coverage_20261019/
constraints:
  - 不把语法近似当权限/ownership/锁证明，不升级候选为产品漏洞
  - P12/JSON5/Rust 仍只作显式 language/artifact limitation
  - 不修改 Ark 或公共 contracts/Runner/Catalog
acceptance:
  - 本地五项和人工候选的 parent/fixed/safe/unrelated/unknown 全覆盖
  - 每个跨文件结论带 source identity、supporting/unknown facts 和 limitation
  - 无完整对象的条目保持 source unavailable，不计通过
continuation:
  - G13-CF-1 canonical path/base
  - G13-CF-2 FD ownership/double-close
  - G13-CF-3 lock identity/scheduling
  - G13-CF-4 permission/entry boundaries
  - G13-CF-5 real-source generalization
```

### 持续执行目标

每轮只补一个事实维度和一组正/固定/安全/非相关/未知控制；缺真实跨文件证据就保留 unknown，不以规则数量替代证明。

## C13-HOLDOUT-PRODUCT-GATE

### 结构化 Vibe Coding Prompt

```yaml
role: independent holdout and product admission engineer
objective: >
  冻结真实独立 holdout，完成双盲评审/分歧裁决；只对满足入口、权限、触发、敏感操作和 CIA 门的候选规划授权隔离 PoC、修复和重验。
inputs:
  - C12 build-profile and holdout pipeline artifacts
  - NOT ADMITTED admission report and product closure matrix
  - source audit evidence obligations
write_scope:
  - research/evaluation/ark_runtime_holdout_20261019/
  - research/methods/ark_runtime/build_profile_20261019/
  - research/deliveries/product_closure_20261019/
  - research/deliveries/admission_20261019/
constraints:
  - 开发 fixture/known-case/模型输出不得当真值
  - 静态资源受限子进程不是 PoC 沙箱；无授权不执行动态验证
  - 不计算无 reliable truth 的 Precision/Recall，不标 Ready/merge
acceptance:
  - holdout leakage、reviewer identity、timing、disagreement、adjudication 全审计
  - product closure 每候选绑定 build/source identity、入口、权限、trigger、sink、CIA、PoC、fixed rerun
  - 强制门未闭合时保持 NOT ADMITTED
continuation:
  - G13-HP-1 official object/build identity
  - G13-HP-2 real holdout freeze
  - G13-HP-3 blind review/adjudication
  - G13-HP-4 isolated PoC
  - G13-HP-5 fix/retest and admission
```

### 持续执行目标

持续维护 blocker/remediation 清单；只有真实人工真值、产品构建、入口权限、CIA、PoC 和修复重验逐项闭合才减少 blocker。

## 合流规则

1. 三条线只在隔离 worktree 和写范围内修改，不执行 fetch/checkout/commit/push/merge/reset。
2. 算法、公共契约、证据/文档分别提交；C13-INTEGRATION 只选择性对账 `67631f3` 与 `8429480`。
3. 合流后运行 Ark focused/full、known-case corpus、Runner/Catalog、schema/legacy、compileall、JSON、docs budget、diff check。
4. push 前更新 `docs/项目现状与下一步.md`，并在聊天中说明变更、验证、限制、branch/full SHA/commits；未获用户授权不 merge/Ready。
