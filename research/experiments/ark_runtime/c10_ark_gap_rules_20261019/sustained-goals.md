# G10-AR-1..4 持续执行目标

- **G10-AR-1 固定身份与适用性：已完成。** 固定 IAO7GO/I7W51D/IB8BCA parent/fixed commit、tree-role blob/source hash，`native_inline_lowering.cpp` 必须被 selector 适用。
- **G10-AR-2 规则与五类控制：已完成。** 三个稳定 rule ID/v1.0.0 均有 positive/fixed/safe/unrelated/unknown；RangeError、fixed、0 findings 均不得转 safe。
- **G10-AR-3 语义增强：持续。** 下一片补跨函数 effect summary、精确 CFG dominance、alias/loop、整数区间与 DataView/Atomics 溢出证明；无法证明保持 unknown。
- **G10-AR-4 独立与产品闭环：持续。** 冻结版本后做独立盲 holdout；对满足入口/权限/触发/CIA 门槛的候选执行授权隔离 PoC、修复和重验，不攻击线上服务。

每轮只推进一个最小可验证切片，保留 exact commands、source identity、patch、controls、pass/fail/skip/block、限制和下一最小切片。
