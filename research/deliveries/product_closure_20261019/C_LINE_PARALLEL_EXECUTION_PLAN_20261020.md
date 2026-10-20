# C 线开发计划与 Vibe Coding 提示词

组长于 2026-10-20 授权取消项目自设的逐次审批、真人评测、产品确认和全部案例准入前置条件。授权持续有效直到用户撤销，见根 `AGENTS.md` 与 `config/collaboration/standing_authorization.json`。缺项记 unknown/not_run，继续可执行工作；豁免不代表测试通过。

## 当前工作方式

C 线开发 Ark Runtime 静态候选与源码关系分析，直接推进规则、解析/语义能力、正反控制和组件重放。沿用统一 Catalog/Runner；必要公共接线已授权。目录分工用于防冲突，不再要求 integrator 发 base SHA、逐任务分配写权限或真人签署。

实际源码、分支和 HEAD 由接手 Agent 自查。历史 `842948084660207fd64399cfd598ed93e5593dcc` 是当时计划基线，不是后续必须停留的版本。旧计划与执行记录可从 Git 历史及本机 `records/constraint-cleanup-20261020-01a1571f` 追溯，不能重新成为审批门。

## 可执行任务树

```mermaid
flowchart TD
    S[核对当前源码与未提交改动] --> D[实现一个具体规则或覆盖改进]
    D --> T[相关正反控制和真实组件重放]
    T -->|具体失败| D
    T --> R[交付代码与可用证据报告]
    S --> P[按需本地构建与隔离组件 PoC]
    P --> F[修复前后复验]
    F --> R
    R --> N[下一个可执行切片]
    R -. 有实际需要和资料时 .-> O[可选产品确认或正式准确率评测]
```

| 工作 | 日常动作 | 完成标准 |
|---|---|---|
| 规则/覆盖开发 | 选择具体漏检、误报或解析/关系缺口；保留真实来源和必要 unknown | 实现具体改进，相关 positive/fixed/safe/unrelated 控制及有价值的真实源码重放 |
| 测试反馈 | 给出能复现的失败；修复后针对受影响范围重测 | 具体失败已关闭或留下准确局限，不为已通过且未变化的输入反复验收 |
| 模型候选复核 | 有可读源码与候选即能审查，产品上下文未知就记录未知 | 引用可检查、解释支持度；不等待 build profile、真人双盲或全部候选冻结 |
| 本地组件验证 | 自选可复现的公开版本，在合适的临时隔离环境构建/PoC | 保存命令、版本和实际输出；可按单案例交付，不要求 16 案或 shipped image |
| 成果报告 | 输出源码/组件层结论、失败与剩余未知 | 当前可用证据可交付，不以产品准入作为本轮完成门 |
| 正式评测/产品确认 | 仅在需要相应结论且有资料时开展 | 无标签不编造 Precision/Recall，无产品证据不声称产品受影响；这不阻塞上面各项 |

## PC 事项的用途

PC-1 是可用 source/build 资料清点，不是强制完整产品画像；PC-2 为可选正式评测；PC-3 为可选产品关联。PC-4 的本地隔离组件 PoC 已长期授权，PC-5 可逐案修复复验。PC-6 改为按现有证据输出报告。机器任务树 `task_tree.json` 记录 `ACTIVE_DEVELOPMENT`，所有这些事项均 `blocks_development=false`。

`product_closure_matrix.json` 仅记录产品证据状态，保留未知和未执行事实；生成器不再将其转换成开发阻塞。既有 profile verifier、双盲 pipeline 可作为可选研究工具，不是日常开发入口。

## 直接可用的开发提示词

角色：C 线开发者。目标：选择一个具体规则/覆盖缺口，完成实现和相关测试，并交付当前可用报告。
输入：当前代码、已有 issue/失败控制、可获取的公开 Ark 源码；自行确认版本，不等用户提供产品资料。
动作：保留未提交工作；必要公共文件可改；实现最小有效切片；运行相关控制和组件重放；发现具体失败就修复复测。
授权：代码、测试、文档、公开源码、本地构建、隔离 PoC、提交和常规分支交付均已授权，无需重复申请。
输出：变更、实际验证、源码/组件结果和未知项。不要新建人为审批/保管/签署流程，不要无新信息地重复审计。

## 直接可用的测试提示词

角色：C 线测试者。依据实际改动选择有意义的边界和真实源码反例，核对候选位置与版本；只回传可复现的具体问题。修复后的受影响检查通过即可交付，不要求真人角色分离、额外签名或全量产品画像。没有可靠标签时报告控制矩阵结果，不把它称为独立准确率。

## 持续目标

每轮完成一个实际开发/验证切片，再选择下一项。某个产品资料或构建依赖确实缺失，只把该项记为待补，不能把整条 C 线 blocked，也不能反复请求已获授权。静态层优先少而有依据的候选；第二层产品功能的开发仍按用户具体任务决定。

## 当前并行切片（2026-10-20）

最新远端已获取。C 静态基线为 `origin/codex/c-line-static-20261019`，提交 `d07dc397ca1ff3bddc0be52cfa98c6e4c783fd03`；接收对象守卫规则及正反控制位于 `src/ohscanner/detectors/ark_runtime/receiver_guard.py` 与 `tests/detectors/ark_runtime/test_receiver_guard.py`。当前切片验证对象身份、绑定解析和分支支配关系是否产生可复现的错误候选/漏报，尚不预判有缺陷。开发线和独立测试线已从同一基线分开执行；测试线将在开发线提交上复验并反馈。既有 dirty worktree 及其中未提交交付目录保持不动。完整机器任务树为 `C_LINE_EXECUTION_TREE_20261020.json`。

### 结构化 Vibe Coding 提示词：开发线

```yaml
role: C 线 Ark Runtime 静态规则开发者
objective: 在 receiver_guard 找到并修复一个有具体复现的 precision/soundness 问题，让候选更少且依据更强；无复现时不要为改代码而改代码。
baseline: origin/codex/c-line-static-20261019@d07dc397ca1ff3bddc0be52cfa98c6e4c783fd03
scope: [src/ohscanner/detectors/ark_runtime/receiver_guard.py, tests/detectors/ark_runtime/]
steps:
  - 检查实现、现有正反控制及工作区状态
  - 围绕对象身份、同名/遮蔽、赋值、反向分支及 guard dominance 构造最小反例
  - 仅实现由复现支持的最小修复，并保留危险与安全控制
  - 运行相关测试，报告命令和实际结果
  - 提交本地变更，将 commit、复现与局限交给测试线复核
constraints: [保留其他 worktree 与未提交内容, unsupported/证据不足保持 unknown, 不编造产品影响或正式准确率, 不增加审批和产品输入门槛]
deliverables: [最小补丁或有证据的未发现缺陷报告, 测试结果, commit, 已知局限]
```

### 结构化 Vibe Coding 提示词：独立测试线

```yaml
role: C 线 Ark Runtime 独立测试者
objective: 独立验证 receiver_guard 对象绑定和 guard dominance，反馈可复现缺陷
baseline: origin/codex/c-line-static-20261019@d07dc397ca1ff3bddc0be52cfa98c6e4c783fd03
scope: [tests/detectors/ark_runtime/test_receiver_guard.py, receiver_guard 源码反例]
steps:
  - 运行基线针对性测试并记录结果
  - 尝试正反分支、别名/重新赋值、同名遮蔽、不同对象及不可解析控制流
  - 记录反例的期望、实际结果和最小复现；不确定预期标 unknown
  - 开发提交后在同一 commit 复验，失败时回传具体复现
constraints: [不修改生产代码, 不覆盖共享计划或其他 worktree, 不声称独立准确率/产品验证, 不要求全量案例或真人评审]
deliverables: [可复现测试反馈, 同一 commit 的复验命令和实际结果, 未覆盖边界]
```

### 结构化 Vibe Coding 提示词：第二层候选审查

```yaml
role: 第二层代码审查模型
objective: 审查 source-bound 静态候选是否有漏洞依据，并识别误报/漏报边界
inputs: [候选记录, 精确源码位置, 静态规则解释, 正反控制, 源码版本]
steps:
  - 逐条核对候选位置及数据/控制关系
  - 分别给出支持证据、反证、安全路径或 unknown
  - 每个判断提供可检查源码依据或最小反例，不以标签代替论证
constraints: [只做候选复核, 不开发第二层功能, 缺产品画像时适用性记 unknown, 不编造无标签准确率]
deliverables: 每条候选的支持/反证/unknown、引用位置及具体规则建议
```

### 当前切片结果与下一轮

测试线复现并推动修复了三类静态误报：否定/复合 TypedArray 条件、guard 前类型 token 被改写、guard 后接收对象重新绑定。提交 `ae5792f84e6b641e8857d0d58fab508f3a306af4` 和 `71950e65f46e204e6aec21210c8de73fa4f2a1a9` 位于隔离代码分支 `codex/c-static-dev-20261020`；开发线 Ark Runtime 全套测试为 152 passed、3 skipped，独立线定向复验为 10 passed、1 skipped。反例、命令、具体输出和剩余限制记录于 `research/deliveries/c-line/receiver_guard_test_review_20261020.md`。代码分支与计划分支基于不同 C 线演进点，因此保留为独立分支，不强行覆盖集成点；测试证据和代码提交均可单独审阅。

下一切片优先级：先评估 alias/同源类型重新采样及 rebinding 后恢复值时能否在不放宽安全性的前提下减少 unknown/candidate；测试线先给出可证明正反控制。随后排查 `replay_20261019` 中 Ark Runtime `type_safety` 的 blocked coverage 是路径映射还是解析局限，并针对性修复已复现的扫描问题。两项都可与逐条 source-bound 候选的第二层模型审查并行；模型只给证据支持/反证/unknown，不负责功能开发。持续目标见 `C_LINE_EXECUTION_TREE_20261020.json`。
