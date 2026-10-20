# C 线快速收尾并行计划（2026-10-20）

## 当前基线

- 最新 `origin/main`：`0f53af62283dbd0f249280805e8286a04b2d43b9`。
- C 线计划分支当前代码/证据基线：`6c71a7bfd`；该提交记录了 type_safety 的 no-change 根因复核。
- 已完成的 receiver_guard、exception_guard、alias、runner applicability、DataView/TypedArray 相关切片继续保留原报告和限制，不重复开发。
- C03 baseline 的独立复验：fixture 解析完整，但不在 reviewed model 的 exact upstream 绑定中，type_safety 保持 `blocked`、0 diagnostics、`not_analyzed=1`；partial 控制保持 candidate/unknown。

## 并行工作线

### C-DEV-TYPESAFETY-20261020：开发/根因线

```yaml
role: C线 Ark Runtime type_safety 开发者
objective: 对一个可重放 partial/blocked 案例拆分 model binding、source mapping、parser、internal coverage 和 detector 状态；只有 source-bound 正反控制证明了规则缺陷才修改代码
baseline: origin/main@0f53af62283dbd0f249280805e8286a04b2d43b9
inputs: production-adapter-replay.json; C03 fixture; exact Git object metadata
steps:
  - 运行 registered CLI 并保存完整 JSON/Markdown
  - 把 blocked 原因分类为绑定、路径、解析、依赖或规则逻辑
  - 若有具体缺陷，补 positive/fixed/safe/unrelated/partial 控制并做最小修复
  - 否则提交 no-change 根因报告，保留 partial/blocked/unknown
deliverable: 完整 SHA、命令、报告、测试结果、限制和可复验输入
stop: 不扩展新漏洞家族，不把 fixture 结果冒充产品证据
```

### C-TEST-TYPESAFETY-20261020：独立测试/反馈线

```yaml
role: C线独立测试负责人
objective: 在开发 SHA 上复验 type_safety 的正例、fixed/safe/unrelated/partial 和模型边界
baseline: origin/main@0f53af62283dbd0f249280805e8286a04b2d43b9
steps:
  - 先记录 baseline 的 repo/commit/tree/blob/source SHA、CLI argv 和 coverage
  - 开发提交后以同一 SHA 重跑，不改生产代码
  - 检查 partial/blocked/unknown 是否保持，0 diagnostics 不当作 safe
  - 将失败回传开发线，直到同提交结果和报告一致
deliverable: 独立测试报告、逐案状态、跳过原因和反馈记录
stop: 无可靠标签时不报 Precision/Recall，不修改公共 Catalog/Runner
```

### C-INTEGRATE-CLOSEOUT-20261020：整合/交付线

```yaml
role: C线收尾整合者
objective: 使任务树、交付报告、实际提交和测试证据一致
steps:
  - 核对开发/测试 SHA 是否相同或明确分离
  - 将 completed、no-change、partial、blocked、not_run 分开记录
  - 汇总候选/源码/组件/产品四层结论和剩余责任方
  - 运行 JSON 校验、git diff --check 和受影响测试
deliverable: 任务树增量、并行结果表、复验命令、未完成事项
stop: 不升级产品漏洞结论，不覆盖历史证据，不整体合并旧 C 分支
```

## 持续目标与反馈闭环

持续目标是：每个 C 线切片都能在固定源码身份上重放，并将解析完整性、模型覆盖、候选信号和运行/产品影响分开记录。开发线提交后，测试线必须在同一 SHA 反馈；整合线只有在命令、输出和限制齐全时更新任务树。当前 type_safety 已证明的结果是“绑定缺失/宏解析导致的 blocked/partial 根因”，不是漏洞确认，也不是安全结论。

## 快速收尾门

1. 开发线：完成最小代码修复，或提交 no-change 根因报告。
2. 测试线：同 SHA 完成正反/partial 回归，保留跳过和 unknown。
3. 整合线：更新 C 线任务树和状态报告，记录完整 SHA 与下一复验条件。
4. 仅在上述三项都有证据后，才创建后续发布 PR；不因缺少产品镜像而阻塞源码/组件交付。
