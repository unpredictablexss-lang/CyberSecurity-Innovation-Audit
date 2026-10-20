# TypedArray.set offset 转换可达性：开发/独立测试切片（2026-10-20）

## 触发依据与身份

当前 C 收尾代码基线：`4e1268a980fd103326c7dbaa6ca2e78d2ba43e69`，tree `0495b0db7d05f02e2ce4e48149f7571c8bdd8023`。Ark Runtime 输入源码：`openharmony/arkcompiler/ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`，tree `8781f036a3e7e04d8e0b34970d5f623b42875016`。

已有条件性 `TypedArray.set(arrayLike, offset)` 源码候选使用 `targetOffset = 2^64 - 2048` 计算 unsigned range-sum wrap。新发现的可核实边界是实际实现调用 `ToInteger` 并将 double 转 `uint64_t`；必须独立证明该输入可由 JS Number 表达、且转换处于合法范围。Ark Runtime 构建尝试在依赖检查处停止：当前 checkout 缺 Node.js 14.21.1、Linux Python 预置和 Hvigor；因此不记为 runtime 结果。

## C-DEV-SET-OFFSET-CONVERSION-20261020

```yaml
role: 精确源码转换路径开发/分析负责人
code_sha: 4e1268a980fd103326c7dbaa6ca2e78d2ba43e69
source_repo: openharmony/arkcompiler_ets_runtime
source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
objective: 证明或推翻候选 offset 经真实 JS Number → ToInteger → double→uint64_t 路径的可达性，并复核之后 unsigned 算术。
steps:
  - 绑定 BuiltinsTypedArray::Set 和 ToInteger 实现的完整源码对象身份
  - 分析 2^64-2048 的 binary64 可表示性与 uint64_t cast 范围
  - 跟踪负数、+Infinity、2^64 和邻近可表示值等边界控制
  - 用最小隔离计算复核 unsigned addition、byte index narrowing 和 range check
  - 写 source-only 报告，明确不等同于 Ark VM 执行
deliverable: research/deliveries/c-line/typedarray_set_offset_conversion_developer_20261020.md 和本地提交 SHA
feedback: 独立测试线挑战转换、舍入和边界结论；具体矛盾回到开发线更正报告
stop: 不修改生产 detector，不称为 runtime PoC 或产品影响
```

## C-TEST-SET-OFFSET-CONVERSION-20261020

```yaml
role: 独立转换可达性反证/测试负责人
code_sha: 4e1268a980fd103326c7dbaa6ca2e78d2ba43e69
source_commit: a65a2853ccae13da167d9aa4720ab8b11ec16656
objective: 独立复现/挑战开发报告中的 JS Number 可达性、binary64 邻值、uint64_t 转换和 unsigned wrap 计算。
steps:
  - 自行读取精确 pinned source 与 ToInteger 实现，不先复用开发推理
  - 在独立 temp 中用 Python/C++ 计算可复现的正例与边界控制
  - 审阅开发报告，逐项回传源码行、身份或算术差异
  - 若发现反例，要求开发线修订后再复核报告
deliverable: research/deliveries/c-line/typedarray_set_offset_conversion_independent_20261020.md 和本地提交 SHA
stop: 不改生产代码，不将微型计算称作 Ark Runtime 执行；runtime 保持 not_run，product 保持 unknown
```

## 持续目标

本切片仅回答 offset 转换可达性与源代码算术链。开发线先提交证据，独立测试线在同一 scanner/source SHA 上挑战；矛盾经开发修订后由测试线复查。只有新证据能够证明实际执行时才更新 runtime 状态。即使转换成立，候选仍是 source-level conditional candidate；组件写入、可观察性、产品纳入和安全影响分别保留为 `not_run`/`unknown`。

## 当前状态

| 任务 | 状态 | 结果 |
|---|---|---|
| C-DEV-SET-OFFSET-CONVERSION-20261020 | in_progress | 等待 exact-source 转换报告 |
| C-TEST-SET-OFFSET-CONVERSION-20261020 | in_progress | 等待独立复算并审阅开发报告 |
