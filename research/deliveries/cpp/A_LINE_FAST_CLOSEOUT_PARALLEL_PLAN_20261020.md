# A 线快速收尾并行计划（2026-10-20）

基线：远端 `origin/main` `0f53af62283dbd0f249280805e8286a04b2d43b9`；A 收尾分支 `70f59f5c07a72792ad9e7ed5f2424879b606ca20`。本计划只推进可复验的源码/组件证据，不扩大漏洞家族，不把产品资料缺失当开发阻塞。

## 任务树核对

```text
A 线快速收尾
├── 已完成：bounds/resource_lifetime/unsafe_memory_call 选择性接入与 73 项回归
├── 已完成：A0 345 条候选记录保全；CVE-2025-0587 精确修复差分复核
├── A-D3 开发：libpng typedef/header-aware 解析（仍 blocked，需最小 parser/control 复核）
├── A-D4 开发：cJSON compare/tree 精确源码差分（仍 blocked，需固定 source/fix 或明确 blocked）
├── C-C1 开发：Ark Runtime parser/model partial 根因调查（不把 partial 改绿）
├── C-Alias 测试：receiver_guard alias/rebinding 同提交独立复验
└── C-Profile 审查：registered source-bound profile 的 parent/fixed CLI 复验与证据报告
```

## 并行线 1：A-D3 libpng 开发

```yaml
role: A 线 C/C++ 解析器开发者
objective: 针对 png_structrp typedef/pointer 归一化的可复现解析缺口，完成最小通用修正或给出精确 blocked 报告
baseline: origin/main@0f53af62283dbd0f249280805e8286a04b2d43b9
scope: [detector/parser-owned C++ files, tests/detectors/fixtures/cpp_*, research/deliveries/cpp, research/evidence/cpp]
steps: [固定 vulnerable/fixed source identity, 复现 8/7 候选差异, 写 failing control, 只实现 typedef/type fact 最小修复, 跑 vulnerable/fixed/safe/unrelated/partial CLI]
constraints: [不硬编码 CVE/函数名, 不改 Catalog/Runner/contracts, partial 不当 safe, 保留 source/tree/blob/SHA]
deliverables: [最小补丁或 blocked 根因报告, focused tests, CLI JSON/Markdown, 下一解除条件]
feedback: 测试线先固定基线并在开发提交上复验；任何具体反例返回开发线修正
sustained_goal: 每轮只关闭一个共享状态/生命周期解析缺口；证据不足时交付可复验 blocked，不伪造覆盖
```

## 并行线 2：A-D4 cJSON 开发

```yaml
role: A 线 C/C++ 算法复杂度检测开发者
objective: 用 pinned cJSON vulnerable/fixed 源码验证 recursive compare/tree amplification 是否可被通用规则区分
baseline: origin/main@0f53af62283dbd0f249280805e8286a04b2d43b9
steps: [核对 commit/tree/blob, 建最小文件闭包, 运行 vulnerable/fixed/safe/unrelated/partial, 仅对可复现通用语义改规则]
constraints: [不以 CVE/函数名/patch 文本触发, 不改公共注册, 不把 partial 零 finding 当安全]
deliverables: [代码/测试或精确 blocked 报告, source-bound CLI 证据, 候选/根因/产品影响分层]
feedback: 测试线对 candidate locations 和 fixed disappearance 做独立复跑
sustained_goal: 按台账逐案建立 exact-source differential；没有可信 fixed source 就保留 partial/unknown
```

## 并行线 3：C-C1 parser/model 开发

```yaml
role: C 线 Ark Runtime parser/model 根因调查者
objective: 把 C1 的 13 个 parser issues、detector_model_incomplete、type_fact_invalidated_by_call 映射到具体分析阶段；只有最小反例证明缺陷才改代码
baseline: origin/codex/c-line-static-20261019@d07dc397ca1ff3bddc0be52cfa98c6e4c783fd03；runner 修复提交由任务树记录的 85a1f1e6f9...
steps: [固定 target+creator source identity, 逐 issue 对照 raw/expanded controls, 解释 Map callback unknown, 评估宏感知 PoC 是否能保留 source map, 跑 Ark suite]
constraints: [不把 partial 改 complete, 不用手写 build profile 冒充产品配置, 不改共享 runner 除非有独立接口需求]
deliverables: [最小修复或 root-cause/unsupported syntax 报告, focused regression, exact CLI evidence]
feedback: 独立测试线先给 raw/expanded/safe/fixed 期望，再复验开发提交
sustained_goal: 每轮关闭一个真实 parser/model 缺口；无缺陷则稳定记录 partial 边界并转下一 exact-bound case
```

## 并行线 4：C-Alias 独立测试

```yaml
role: C 线独立测试者
objective: 在 receiver_guard alias 开发提交上复验同源 alias、跨对象、重绑定恢复、opaque/reference 写入和 token resampling
baseline: codex/c-static-alias-test-20261020@71950e65f46e204e6aec21210c8de73fa4f2a19
steps: [运行 baseline focused suite, 复跑开发 SHA 2d79560c..., 核对候选/静默/unknown 和 source identity, 发现具体回归才反馈]
constraints: [不改生产代码, 不把零诊断当安全, 不报独立准确率]
deliverables: [同提交测试结果、最小反例、剩余边界和报告路径]
sustained_goal: 每个 alias slice 都必须有开发提交与独立复验；稳定后转 type_safety source-bound replay
```

## 并行线 5：C-Profile 证据测试

```yaml
role: C 线 source-bound profile 测试/证据审查者
objective: 复验 registered parent/fixed CLI 是否保持精确 source binding、候选差分和 partial/blocked 真实状态
baseline: codex/c-static-replay-test-20261020@71950e65f46e204e6aec21210c8de73fa4f2a1a9
steps: [核对 parent/fixed full commit/tree/blob/SHA, 复跑 parent/fixed, 验证非绑定版本拒绝, 检查 report obligations]
constraints: [不修改 profile 生产代码, 不把 candidate/blocked 变成 confirmed/safe]
deliverables: [逐案 CLI JSON/Markdown、命令、差异、未解决限制]
sustained_goal: 每次关闭一个 exact-bound profile replay；失败时记录绑定/解析/模型/规则的真实阶段
```

## 开发—测试反馈协议

开发线先提交最小变更或 blocked 根因；测试线只复跑同一提交和同一输入，返回具体实际/期望差异。反馈闭环后才更新 A 线矩阵；产品级证据仍单列 unknown/not_run。
