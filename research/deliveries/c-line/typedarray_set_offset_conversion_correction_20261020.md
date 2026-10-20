# TypedArray.set 超大 offset 可达性报告更正

日期：2026-10-20（Asia/Shanghai）  
更正对象：[typedarray_set_offset_conversion_developer_20261020.md](typedarray_set_offset_conversion_developer_20261020.md)  
源码固定版本：`openharmony/arkcompiler_ets_runtime@a65a2853ccae13da167d9aa4720ab8b11ec16656`

## 更正结论

原报告正确判定 `2^64 - 2048` 可经 `ToInteger → TruncateDouble → uint64_t` 到达，但其“只有目标 byte capacity 足够覆盖窄化起点时才会循环，且循环索引已在目标 TypedArray 范围内”的推论不成立：它忽略了目标 TypedArray 的非零 `targetByteOffset`。

对 `TypedArray.set(arrayLike, offset)` array-like 分支，存在如下**源码级 view-boundary 越界写候选**：整数长度检查可以在 `uint64_t` 加法回绕后通过；之后 `targetByteIndex` 由超大 offset 与 `targetByteOffset` 相加并窄化到 32 位。该 index 可以落在目标 TypedArray view 的 byteOffset 之前，而 32 位 `limit` 仍大于它，故循环执行。示例写入位置全部在 backing ArrayBuffer 之内，因此当前证据支持的是越过目标 TypedArray view 边界，而非越过 backing buffer 的物理/逻辑边界。候选需独立测试线复核，不能标成 confirmed。

## 手工算术反例

令 `x = 2^64 - 2048 = 18446744073709549568`，目标为长度 8192 bytes 的 backing buffer 上偏移 4096、长度 4096 的 `Uint8Array` view；array-like source 的 `length = 4096`，并提供 4096 个可读元素。

对应的源码级输入形状（仅用于描述，不曾在 Ark Runtime 执行）：

```js
const backing = new ArrayBuffer(8192);
const target = new Uint8Array(backing, 4096, 4096);
const source = { length: 4096 /* 且提供索引 0..4095 */ };
target.set(source, 18446744073709549568);
```

逐步计算（均对应 `builtins_typedarray.cpp` array-like 路径）：

1. `ToInteger` 保持 `x`；`static_cast<uint64_t>` 得到 `x`。
2. `srcLen + targetOffset` 在无符号 64 位加法中回绕：`4096 + (2^64 - 2048) ≡ 2048 (mod 2^64)`。目标 `targetLength = 4096`，所以 `2048 > 4096` 为假，RangeError 检查不触发。
3. `targetByteIndex = uint32_t(x + targetByteOffset) = uint32_t((2^64 - 2048) + 4096) = 0x00000800`。
4. `limit = uint32_t(targetByteIndex + srcLen) = 0x00000800 + 0x1000 = 0x00001800`。
5. 循环条件 `targetByteIndex < limit` 为真，索引按 byte 递增，循环区间 `[0x0800, 0x1800)` 共 4096 次。
6. 目标 TypedArray view 覆盖 backing buffer 区间 `[0x1000, 0x2000)`。循环前半 `[0x0800, 0x1000)` 共 2048 bytes 位于 view 之前；所有 4096 个写入地址仍落在 8192-byte backing buffer `[0x0000, 0x2000)` 内。

这不需要 `ASSERT` 被关闭：源码中的两个断言表达式也在无符号算术回绕后得到 `2048 <= UINT32_MAX` 与 `6144 <= UINT32_MAX`。这只说明断言不能排除此算例，不证明编译配置、runtime 执行或具体写操作结果。

## 源码绑定与复验命令

精确源 commit、文件 blob OID 与 SHA-256 沿用原报告。关键位置为：

- `ecmascript/builtins/builtins_typedarray.cpp:1156-1179`：ToInteger、负值/正无穷拒绝、转换成 uint64。
- `ecmascript/builtins/builtins_typedarray.cpp:1223-1235`：ToLength/source length、uint64 长度检查、窄化 targetByteIndex。
- `ecmascript/builtins/builtins_typedarray.cpp:1237-1276`：32 位 limit、循环条件与每次 SetValueInBuffer。
- `ecmascript/js_tagged_value.cpp:204-210` 与 `ecmascript/base/number_helper.cpp:804-820`：ToInteger / TruncateDouble 语义。

用于核对源码位置：

```powershell
rg -n 'targetOffset|srcLen \+ targetOffset|targetByteIndex|uint32_t limit|while \(targetByteIndex < limit\)' ecmascript/builtins/builtins_typedarray.cpp
rg -n 'JSTaggedValue::ToInteger\(' ecmascript/js_tagged_value.cpp
rg -n -F 'TruncateDouble' ecmascript/base/number_helper.cpp
```

复算示例：`(2**64 - 2048 + 4096) % 2**32 == 0x800`，`(0x800 + 4096) % 2**32 == 0x1800`，循环区间为 `[2048,6144)`；view 起点为 4096，backing buffer 长度为 8192。

## 修订后的状态

- 超大 offset conversion：`reachable`，源码级。
- array-like 路径的目标 TypedArray view 前置写：`candidate`，本报告给出可复算的源码级算术见证；需独立测试复核实际 runtime 行为和目标构造可行性。
- backing ArrayBuffer 边界越界：此算例不支持该结论（所有算术写地址均在 buffer 内）；其他参数/路径未穷尽。
- Ark Runtime 执行、产品构建/配置、产品入口可达性和影响：`not_run / unknown`。
- 原报告的通用“循环时必在 TypedArray view 范围内”句子应由本更正替代。原提交保留在 Git 历史，便于追溯。
