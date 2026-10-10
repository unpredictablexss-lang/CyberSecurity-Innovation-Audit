# Research slice: bounds / length / Parcel

> 状态：最小离线研究切片，不是 production detector，也不是另一套扫描框架。没有注册入口、CLI、公共 Candidate schema 或外部工具依赖。

## 1. 研究问题

能否用一个极窄的语法事实回答：

`Parcel.ReadUint32()` 赋给 `length`，随后 `length` 出现在 `memcpy` 长度位置，并且之前是否出现 `if (length > capacity)` / `if (length >= capacity)` 的 upper-bound guard 形状？

## 2. 已实现事实

`research/experiments/cpp/bounds_length_parcel_slice.py` 只提取：

- `length_source`：整数长度变量由 `Parcel.ReadUint32()` 赋值；
- `upper_bound_guard_shape`：同文本中 guard 语法位于 sink 之前；
- `copy_size_sink`：共享 Tree-sitter AST 提取 `memcpy` / `std::memcpy` 第三实参，检查其中的长度变量；多行调用和嵌套参数不会混入第二实参。

输出是 `candidate_shapes`、事实位置和 limitations。没有 vulnerability verdict，也没有 benchmark 状态。

## 3. Fixtures

- vulnerable：`tests/detectors/fixtures/cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp`
- fixed：`tests/detectors/fixtures/cpp_bounds_length_parcel/fixed_guarded_parcel.cpp`
- safe control：`tests/detectors/fixtures/cpp_bounds_length_parcel/safe_constant_length.cpp`
- partial/unknown：`tests/detectors/fixtures/cpp_bounds_length_parcel/partial_parse_macro_guard.cpp`
- failed：`tests/detectors/fixtures/cpp_bounds_length_parcel/failed_parse_unbalanced.cpp`

逐文件 hash 与 parse 状态见 `tests/detectors/fixtures/cpp_bounds_length_parcel/manifest.json`。这些是自建 synthetic fixtures，不是历史漏洞样本。

## 4. 消融结果

| 模式 | vulnerable | fixed | safe | partial | failed |
|---|---:|---:|---:|---:|---:|
| base source→sink shape | 1 | 1 | 0 | 0（未知） | 0（失败） |
| + descriptive guard ordering | 1 | 1 | 0 | 0（未知） | 0（失败） |

2026-10-09 整合审查取消了 guard 文本排序对候选的抑制：比较后仅日志输出也会继续执行 memcpy，且当前没有 CFG 支配证明。两种模式均保留 fixed fixture 的候选，只额外记录 guard 形状；这不代表 fixed 版本不安全。源码实际解析非 complete 时保留 unknown。

## 5. 为什么不提升为本轮 detector

要形成可信 bounds detector 至少还需要：

- CFG/path dominance，处理 early return、循环、goto、异常和多入口；
- length/capacity/index 的符号关系、整数宽度、截断和溢出；
- allocation size 与 destination capacity 的类型事实；
- Parcel 字段边界、读写对称、返回值和剩余字节约束；
- partial parse/macro/build context 的真实降级；
- positive/fixed/safe 独立 holdout 与已知限制。

本轮按“窄而完整”要求选择 `cpp.lifetime`；bounds slice 作为下一轮方法输入，不宣称已具备 OOB/integer-overflow/Parcel 漏洞检测能力。
