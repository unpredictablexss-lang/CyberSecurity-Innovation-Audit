> 2026-10-19 最新刷新：本文件保留为本轮中间记录；最终任务树、并行 Vibe Coding 提示词与持续目标以 C_LINE_TASK_TREE_AND_VIBE_PROMPTS_20261019.md 为准。

# C 线开发情况、任务树与后续并行设计

日期：2026-10-19（Asia/Shanghai）。

## 1. 已核验事实

- 主 checkout 保持 `codex/full-runtime-performance-audit-20261014` @ `0f8e6403095ea0fd8d6c8ac41a4789299915d139`，原有 `research/coordination/`、`research/evidence/ark_runtime/`、`research/experiments/ark_runtime/` 未跟踪产物未覆盖。
- C 线接收分支固定为 `origin/codex/c4-selective-integration-20261018` @ `b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df`；独立分支 `origin/codex/c-line-ark-runtime-20261018` @ `95ca71a446b089229aa67f50dcb06a90b88f6a63`。
- 显式 GitHub fetch/pull 三次均因 443 连接失败；因此“最新远端”未验证。只使用本地 pinned refs/objects。
- `源码漏洞审查记录_20261018.md` 未出现在 checkout、本地全部提交树、父目录或本地固定远端对象。当前采用 C3 review counterexamples、C4 unknown cases 和 C7 replay fail-closed 证据作为替代输入，并保留该缺口。

## 2. 当前任务树

```text
C-line Ark Runtime type safety
├── C1 TypedArray type-origin research
│   ├── 已有：历史 parent/fix 来源、parser probe、规则假设
│   └── 未闭合：完整 Git 对象链、产品构建、入口/权限/CIA
├── C2 bounded detector/replay
│   ├── 已有：12 案例、局部 parent/fix 观察、replay 脚手架
│   └── 阻塞：历史对象缺失，skip/error 不计通过
├── C3 generalization / holdout
│   ├── 已有：机制控制、review counterexamples、holdout 包
│   └── 未完成：独立人工标签、分歧裁决、可靠指标
├── C4 exception guard / selective integration
│   ├── 已有：0.6.2 双规则、source selection、默认关闭
│   └── 未闭合：产品入口、build profile、CIA、独立评估
├── C5 exact source binding
│   ├── 已有：commit/tree/blob/source SHA 绑定
│   └── 未闭合：部署 revision / product build identity
├── C6 parser namespace recovery
│   ├── 已有：partial parse owner recovery 与边界结论
│   └── 当前回归：外部目标源缺失导致测试环境错误
└── C7 parallel execution
    ├── C7-DEP：18 项依赖漂移账本，已产出但仍需逐项重审
    ├── C7-REPLAY：对象库存/控制/补对象清单，历史 replay fail-closed
    ├── C7-HOLDOUT：双盲包/标签模板，等待独立人工评审
    └── C7-ADMISSION：目录缺失，公共准入 RFC 尚未落地
```

## 3. 已暴露的扫描器优化点

1. type-origin 不健全传播：6 个反例在 `tag++`、`++tag`、赋值嵌入 `Int32Add`、`output=input`、复合声明和分支条件赋值后仍从旧 origin 得出 `matched`，预期应为 `unknown`。
2. exception/effect order：`NewTypedArray`/`NewTypedArraySameType` 后的 pending-exception guard、零长度路径、copy/store effect 顺序仍存在 unknown；不能把 source order 观察升级成安全或漏洞。
3. partial owner identity：外部目标仓库缺失时测试直接 FileNotFoundError；owner 恢复需要区分“代码逻辑失败”和“外部 source unavailable”，缺上下文必须 unknown。
4. evaluation gate：开发控制、历史 replay 和模型预测均不是独立真值；只有双盲人工标签完成且分歧裁决后才可评估。

## 4. 本轮并行实现线

- `C8-TYPE-ORIGIN`：修复 6 个反例的 origin invalidation。
- `C8-EXCEPTION-GUARD`：修复/补强异常守卫效果顺序模型。
- `C8-PARTIAL-OWNER`：修复 partial owner fail-closed 与外部源缺失测试边界。
- `C8-INTEGRATION`：三条线合流后统一运行 Ark Runtime 回归、source-bound schema、Runner/Catalog 兼容性；不得与三条实现线同时改同一文件。

## 5. 后续串联任务

1. 合并三条实现线前分别记录最小 patch、控制矩阵、测试输出。
2. 在独立工作树运行完整 `tests/detectors/ark_runtime`、Runner applicability、owner integration 和公共契约兼容测试。
3. 将缺失的 `research/methods/ark_runtime/admission_20261019/` 作为独立架构任务实现，公共 contracts/Runner/Catalog 变更单独提交。
4. 补齐 C7 historical object manifest 后再做 parent/fix/safe/unrelated replay；缺对象继续 fail-closed。
5. 冻结规则版本和 source hashes，再生成新 holdout；两名独立人工审查完成后才计算指标。
6. 只有产品入口、权限边界、可达敏感操作、触发条件、CIA、产品构建、影响版本/分支、修复重验和 CVE 检索均闭合，才允许升级 confirmed/reportable。
